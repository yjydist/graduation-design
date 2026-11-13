package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestDomainAuthorityCredentialSignVerifyAndChainConsistency(t *testing.T) {
	privT, pubT, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	depID := strings.Repeat("ab", 32)
	now := time.Now().UTC().Truncate(time.Second)
	nbf := now.Add(-time.Hour).Unix()
	exp := now.Add(24 * time.Hour).Unix()

	scopes := []IssuerScope{
		{
			ID:              "did:web:a.local:ia1",
			AppKeyVersion:   1,
			CredentialTypes: []string{CredentialTypeEnterpriseIdentity},
			ClaimNames:      []string{"domain", "role"},
		},
		{
			ID:              "did:web:a.local:ia2",
			AppKeyVersion:   1,
			CredentialTypes: []string{CredentialTypeEnterpriseIdentity},
			ClaimNames:      []string{"department", "domain", "role"},
		},
	}

	cred := DomainAuthorityCredential{
		Type:             []string{CredentialTypeVC, CredentialTypeDomainAuthority},
		ID:               "urn:grad:domain-certification:A-v1",
		DeploymentID:     depID,
		Issuer:           "did:web:t.local",
		Iss:              "did:web:t.local",
		Sub:              "did:web:a.local",
		IssuerKeyVersion: 1,
		ValidFrom:        time.Unix(nbf, 0).UTC().Format(time.RFC3339),
		ValidUntil:       time.Unix(exp, 0).UTC().Format(time.RFC3339),
		NBF:              nbf,
		EXP:              exp,
		CredentialStatus: CredentialStatus{
			ID:   "urn:grad:domain-certification:A-v1",
			Type: StatusTypeDomainCertification,
		},
		CredentialSubject: DomainAuthoritySubject{
			ID:              "did:web:a.local",
			DomainID:        "A",
			IdentityIssuers: scopes,
		},
	}

	jws, digest, err := SignDomainAuthorityCredential(privT, "did:web:t.local#key-1", &cred)
	if err != nil {
		t.Fatalf("SignDomainAuthorityCredential: %v", err)
	}
	sum := sha256.Sum256([]byte(jws))
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("anchor digest mismatch: got %s, want %x", digest, sum)
	}

	pubTKey, _, err := ParseAppPublicKey(pubT)
	if err != nil {
		t.Fatal(err)
	}
	verified, verifiedDigest, err := ParseAndVerifyDomainAuthorityCredential(jws, pubTKey, "did:web:t.local#key-1")
	if err != nil {
		t.Fatalf("ParseAndVerifyDomainAuthorityCredential: %v", err)
	}
	if verifiedDigest != digest {
		t.Fatalf("verified digest %s != %s", verifiedDigest, digest)
	}

	chainState := DomainAnchorState{
		RootDID:            "did:web:t.local",
		RootKeyVersion:     1,
		DomainID:           "A",
		DomainDID:          "did:web:a.local",
		DomainIssuers:      []string{"did:web:a.local:ia1", "did:web:a.local:ia2"},
		CertificationID:    cred.ID,
		CertificationNBF:   nbf,
		CertificationEXP:   exp,
		CertificationDig:   digest,
		CertificationScope: scopes,
	}
	if err := verified.VerifyAgainstChain(verifiedDigest, chainState); err != nil {
		t.Fatalf("VerifyAgainstChain: %v", err)
	}
	if _, err := verified.FindIssuerScope("did:web:a.local:ia1", 1, CredentialTypeEnterpriseIdentity, []string{"domain", "role"}); err != nil {
		t.Fatalf("FindIssuerScope ia1: %v", err)
	}

	// Negative 1: wrong signature key rejected
	_, wrongPubHex, _ := GenerateP256KeyPair()
	wrongPub, _, _ := ParseAppPublicKey(wrongPubHex)
	if _, _, err := ParseAndVerifyDomainAuthorityCredential(jws, wrongPub, "did:web:t.local#key-1"); !HasCode(err, ErrCodeSignatureInvalid) {
		t.Fatalf("expected SIGNATURE_INVALID for wrong T key, got %v", err)
	}

	// Negative 2: wrong JWS typ rejected
	payload, _ := MarshalJCS(&cred)
	wrongTypJWS, _, _ := SignCompactJWS(privT, TypGrantDelegation, "did:web:t.local#key-1", payload)
	if _, _, err := ParseAndVerifyDomainAuthorityCredential(wrongTypJWS, pubTKey, "did:web:t.local#key-1"); !HasCode(err, ErrCodeInvalidSchema) {
		t.Fatalf("expected INVALID_SCHEMA for wrong typ, got %v", err)
	}

	// Negative 3: unsorted identityIssuers rejected
	badCred := cred
	badCred.CredentialSubject.IdentityIssuers = []IssuerScope{scopes[1], scopes[0]}
	if _, _, err := SignDomainAuthorityCredential(privT, "did:web:t.local#key-1", &badCred); !HasCode(err, ErrCodeInvalidSchema) {
		t.Fatalf("expected INVALID_SCHEMA for unsorted identityIssuers, got %v", err)
	}

	// Negative 4: identityIssuers > 8 rejected
	tooMany := make([]IssuerScope, 9)
	for i := range tooMany {
		tooMany[i] = IssuerScope{
			ID:              "did:web:a.local:i" + string(rune('a'+i)),
			AppKeyVersion:   1,
			CredentialTypes: []string{CredentialTypeEnterpriseIdentity},
			ClaimNames:      []string{"domain", "role"},
		}
	}
	badCred.CredentialSubject.IdentityIssuers = tooMany
	if _, _, err := SignDomainAuthorityCredential(privT, "did:web:t.local#key-1", &badCred); !HasCode(err, ErrCodeInvalidSchema) {
		t.Fatalf("expected INVALID_SCHEMA for >8 identityIssuers, got %v", err)
	}

	// Negative 5: on-chain digest mismatch rejected
	badState := chainState
	badState.CertificationDig = strings.Repeat("c", 64)
	if err := verified.VerifyAgainstChain(verifiedDigest, badState); !HasCode(err, ErrCodeDomainCertificationInvalid) {
		t.Fatalf("expected DOMAIN_CERTIFICATION_INVALID, got %v", err)
	}
}

func TestEnterpriseIdentityCredentialSDJWTAndNegatives(t *testing.T) {
	privIA, _, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, pubUHex, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	holderJWK, err := AppPublicKeyToJWK(pubUHex)
	if err != nil {
		t.Fatal(err)
	}
	wantThumb, err := holderJWK.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}

	depID := strings.Repeat("12", 32)
	now := time.Now().UTC().Truncate(time.Second)
	nbf := now.Add(-time.Hour).Unix()
	exp := now.Add(24 * time.Hour).Unix()

	claims := EnterpriseIdentityCredential{
		Type:             []string{CredentialTypeVC, CredentialTypeEnterpriseIdentity},
		ID:               "urn:grad:credential:U-v1",
		DeploymentID:     depID,
		Issuer:           "did:web:a.local:ia",
		Iss:              "did:web:a.local:ia",
		Sub:              "did:web:a.local:u",
		IssuerKeyVersion: 1,
		AppKeyVersion:    1,
		ValidFrom:        time.Unix(nbf, 0).UTC().Format(time.RFC3339),
		ValidUntil:       time.Unix(exp, 0).UTC().Format(time.RFC3339),
		NBF:              nbf,
		EXP:              exp,
		CredentialStatus: CredentialStatus{
			ID:   "urn:grad:credential:U-v1",
			Type: StatusTypeCredential,
		},
		Cnf: ConfirmationKey{JWK: holderJWK},
		CredentialSubject: SDJWTCredentialSubject{
			ID: "did:web:a.local:u",
		},
	}

	signed, err := IssueEnterpriseIdentityCredential(
		privIA,
		"did:web:a.local:ia#key-1",
		claims,
		"A",
		"USER",
		map[string]string{"department": "procurement"},
	)
	if err != nil {
		t.Fatalf("IssueEnterpriseIdentityCredential: %v", err)
	}

	// Verify anchor digest covers ONLY issuer-signed JWT (independent of disclosures / KB-JWT).
	if strings.Contains(signed.IssuerSignedJWT, "~") {
		t.Fatalf("IssuerSignedJWT must not contain '~': %s", signed.IssuerSignedJWT)
	}
	wantAnchor := sha256.Sum256([]byte(signed.IssuerSignedJWT))
	if signed.AnchorDigest != hex.EncodeToString(wantAnchor[:]) {
		t.Fatalf("AnchorDigest mismatch: got %s, want %x", signed.AnchorDigest, wantAnchor)
	}

	// Verify full presentation (trailing '~', no KB-JWT)
	verified, err := VerifySDJWTCredential(signed.PresentationPrefix, &privIA.PublicKey, "did:web:a.local:ia#key-1", pubUHex, false)
	if err != nil {
		t.Fatalf("VerifySDJWTCredential full: %v", err)
	}
	if verified.Domain != "A" || verified.Role != "USER" || verified.Disclosed["department"] != "procurement" {
		t.Fatalf("unexpected disclosed claims: %+v", verified.Disclosed)
	}
	if verified.HolderThumb != wantThumb || verified.AnchorDigest != signed.AnchorDigest {
		t.Fatalf("holder thumb or anchor mismatch")
	}

	// Verify selective disclosure keeping only mandatory domain and role (hiding optional department)
	selective := signed.IssuerSignedJWT + "~" + signed.DisclosureByClaim["domain"] + "~" + signed.DisclosureByClaim["role"] + "~"
	verifiedSel, err := VerifySDJWTCredential(selective, &privIA.PublicKey, "did:web:a.local:ia#key-1", pubUHex, false)
	if err != nil {
		t.Fatalf("VerifySDJWTCredential selective: %v", err)
	}
	if verifiedSel.AnchorDigest != signed.AnchorDigest || len(verifiedSel.Disclosed) != 2 {
		t.Fatalf("selective disclosure mismatch: anchor=%s disclosed=%+v", verifiedSel.AnchorDigest, verifiedSel.Disclosed)
	}

	// Negative 1: missing mandatory role disclosure rejected
	missingRole := signed.IssuerSignedJWT + "~" + signed.DisclosureByClaim["domain"] + "~"
	if _, err := VerifySDJWTCredential(missingRole, &privIA.PublicKey, "did:web:a.local:ia#key-1", pubUHex, false); !HasCode(err, ErrCodeInvalidDisclosure) {
		t.Fatalf("expected INVALID_DISCLOSURE when role omitted, got %v", err)
	}

	// Negative 2: unreferenced extra disclosure rejected
	orphanBytes, _ := MarshalJCS([]string{"salt123456", "extra", "val"})
	orphanDisc := base64.RawURLEncoding.EncodeToString(orphanBytes)
	withOrphan := signed.PresentationPrefix + orphanDisc + "~"
	if _, err := VerifySDJWTCredential(withOrphan, &privIA.PublicKey, "did:web:a.local:ia#key-1", pubUHex, false); !HasCode(err, ErrCodeInvalidDisclosure) {
		t.Fatalf("expected INVALID_DISCLOSURE for unreferenced disclosure, got %v", err)
	}

	// Negative 3: duplicate disclosure rejected
	withDup := signed.IssuerSignedJWT + "~" + signed.DisclosureByClaim["domain"] + "~" + signed.DisclosureByClaim["domain"] + "~" + signed.DisclosureByClaim["role"] + "~"
	if _, err := VerifySDJWTCredential(withDup, &privIA.PublicKey, "did:web:a.local:ia#key-1", pubUHex, false); !HasCode(err, ErrCodeInvalidDisclosure) {
		t.Fatalf("expected INVALID_DISCLOSURE for duplicate disclosure, got %v", err)
	}

	// Negative 4: mismatched cnf.jwk holder key rejected
	_, otherPubHex, _ := GenerateP256KeyPair()
	if _, err := VerifySDJWTCredential(signed.PresentationPrefix, &privIA.PublicKey, "did:web:a.local:ia#key-1", otherPubHex, false); !HasCode(err, ErrCodeHolderMismatch) {
		t.Fatalf("expected HOLDER_MISMATCH for different cnf.jwk holder key, got %v", err)
	}
}
