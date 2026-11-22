package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalVCv2ContextAndValidation(t *testing.T) {
	raw, manifest, err := LocalVCv2Context()
	require.NoError(t, err)
	assert.Equal(t, PinnedVCv2ContextSHA256, manifest.SHA256)
	assert.Equal(t, len(raw), manifest.ByteLength)
	assert.Equal(t, VCv2ContextURL, manifest.URI)
	assert.Equal(t, GradAuthVocabURI, manifest.VocabURI)

	// Digest tamper on bundled context fails offline check.
	tampered := bytes.Clone(raw)
	tampered[0] = ' '
	_, _, err = verifyBundledContext(tampered, PinnedVCv2ContextSHA256)
	assert.True(t, HasCode(err, ErrCodeInvalidSchema), "got %v", err)

	// Default context validates cleanly.
	require.NoError(t, ValidateCredentialContext(DefaultCredentialContext()))

	badContexts := []struct {
		name string
		ctx  any
	}{
		{"wrong order", []any{map[string]string{"@vocab": GradAuthVocabURI}, VCv2ContextURL}},
		{"string only", VCv2ContextURL},
		{"v1 url", []any{"https://www.w3.org/2018/credentials/v1", map[string]string{"@vocab": GradAuthVocabURI}}},
		{"extra array element", []any{VCv2ContextURL, map[string]string{"@vocab": GradAuthVocabURI}, "https://other.example/ctx"}},
		{"extra key in vocab object", []any{VCv2ContextURL, map[string]string{"@vocab": GradAuthVocabURI, "foo": "bar"}}},
		{"tampered vocab URI", []any{VCv2ContextURL, map[string]string{"@vocab": "https://evil.example.test/vocab#"}}},
		{"missing vocab", []any{VCv2ContextURL}},
	}
	for _, tc := range badContexts {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCredentialContext(tc.ctx)
			assert.True(t, HasCode(err, ErrCodeInvalidSchema), "got %v", err)
		})
	}
}

func TestDomainAuthorityCredentialSignVerifyAndChainConsistency(t *testing.T) {
	privT, _ := mustGenKeyPair(t)
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
	require.NoError(t, err)
	sum := sha256.Sum256([]byte(jws))
	assert.Equal(t, hex.EncodeToString(sum[:]), digest)

	verified, verifiedDigest, err := ParseAndVerifyDomainAuthorityCredential(jws, &privT.PublicKey, "did:web:t.local#key-1")
	require.NoError(t, err)
	assert.Equal(t, digest, verifiedDigest)

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
	require.NoError(t, verified.VerifyAgainstChain(verifiedDigest, chainState))
	_, err = verified.FindIssuerScope("did:web:a.local:ia1", 1, CredentialTypeEnterpriseIdentity, []string{"domain", "role"})
	require.NoError(t, err)

	// Negative 1: wrong signature key rejected.
	wrongPriv, _ := mustGenKeyPair(t)
	_, _, err = ParseAndVerifyDomainAuthorityCredential(jws, &wrongPriv.PublicKey, "did:web:t.local#key-1")
	assert.True(t, HasCode(err, ErrCodeSignatureInvalid), "got %v", err)

	// Negative 2: wrong JWS typ rejected.
	payload, err := MarshalJCS(&cred)
	require.NoError(t, err)
	wrongTypJWS, err := SignCompactJWS(privT, TypeGrantJWS, "did:web:t.local#key-1", payload)
	require.NoError(t, err)
	_, _, err = ParseAndVerifyDomainAuthorityCredential(wrongTypJWS, &privT.PublicKey, "did:web:t.local#key-1")
	assert.True(t, HasCode(err, ErrCodeInvalidSchema), "got %v", err)

	// Negative 3: unsorted identityIssuers rejected.
	badCred := cred
	badCred.CredentialSubject.IdentityIssuers = []IssuerScope{scopes[1], scopes[0]}
	_, _, err = SignDomainAuthorityCredential(privT, "did:web:t.local#key-1", &badCred)
	assert.True(t, HasCode(err, ErrCodeInvalidSchema), "got %v", err)

	// Negative 4: identityIssuers > 8 rejected.
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
	_, _, err = SignDomainAuthorityCredential(privT, "did:web:t.local#key-1", &badCred)
	assert.True(t, HasCode(err, ErrCodeInvalidSchema), "got %v", err)

	// Negative 5: on-chain digest mismatch rejected.
	badState := chainState
	badState.CertificationDig = strings.Repeat("c", 64)
	err = verified.VerifyAgainstChain(verifiedDigest, badState)
	assert.True(t, HasCode(err, ErrCodeDomainCertificationInvalid), "got %v", err)
}

func TestEnterpriseIdentityCredentialSDJWTAndNegatives(t *testing.T) {
	privIA, _ := mustGenKeyPair(t)
	privU, pubUHex := mustGenKeyPair(t)
	holderJWK, err := JWKFromPublicKey(&privU.PublicKey)
	require.NoError(t, err)
	wantThumb, err := JWKThumbprint(holderJWK)
	require.NoError(t, err)

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
	require.NoError(t, err)

	// Anchor digest covers ONLY issuer-signed JWT (independent of disclosures / KB-JWT).
	assert.NotContains(t, signed.IssuerSignedJWT, "~")
	wantAnchor := sha256.Sum256([]byte(signed.IssuerSignedJWT))
	assert.Equal(t, hex.EncodeToString(wantAnchor[:]), signed.AnchorDigest)

	// Verify full presentation (trailing '~', no KB-JWT).
	verified, err := VerifySDJWTCredential(signed.PresentationPrefix, &privIA.PublicKey, "did:web:a.local:ia#key-1", pubUHex, false)
	require.NoError(t, err)
	assert.Equal(t, "A", verified.Domain)
	assert.Equal(t, "USER", verified.Role)
	assert.Equal(t, "procurement", verified.Disclosed["department"])
	assert.Equal(t, wantThumb, verified.HolderThumb)
	assert.Equal(t, signed.AnchorDigest, verified.AnchorDigest)

	// Selective disclosure keeping only mandatory domain and role (hiding optional department).
	selective := signed.IssuerSignedJWT + "~" + signed.DisclosureByClaim["domain"] + "~" + signed.DisclosureByClaim["role"] + "~"
	verifiedSel, err := VerifySDJWTCredential(selective, &privIA.PublicKey, "did:web:a.local:ia#key-1", pubUHex, false)
	require.NoError(t, err)
	assert.Equal(t, signed.AnchorDigest, verifiedSel.AnchorDigest)
	assert.Len(t, verifiedSel.Disclosed, 2)

	// Negative 1: missing mandatory role disclosure rejected.
	missingRole := signed.IssuerSignedJWT + "~" + signed.DisclosureByClaim["domain"] + "~"
	_, err = VerifySDJWTCredential(missingRole, &privIA.PublicKey, "did:web:a.local:ia#key-1", pubUHex, false)
	assert.True(t, HasCode(err, ErrCodeInvalidDisclosure), "got %v", err)

	// Negative 2: unreferenced extra disclosure rejected.
	orphanBytes, err := MarshalJCS([]string{"salt123456", "extra", "val"})
	require.NoError(t, err)
	orphanDisc := base64.RawURLEncoding.EncodeToString(orphanBytes)
	withOrphan := signed.PresentationPrefix + orphanDisc + "~"
	_, err = VerifySDJWTCredential(withOrphan, &privIA.PublicKey, "did:web:a.local:ia#key-1", pubUHex, false)
	assert.True(t, HasCode(err, ErrCodeInvalidDisclosure), "got %v", err)

	// Negative 3: duplicate disclosure rejected.
	withDup := signed.IssuerSignedJWT + "~" + signed.DisclosureByClaim["domain"] + "~" + signed.DisclosureByClaim["domain"] + "~" + signed.DisclosureByClaim["role"] + "~"
	_, err = VerifySDJWTCredential(withDup, &privIA.PublicKey, "did:web:a.local:ia#key-1", pubUHex, false)
	assert.True(t, HasCode(err, ErrCodeInvalidDisclosure), "got %v", err)

	// Negative 4: mismatched cnf.jwk holder key rejected.
	_, otherPubHex := mustGenKeyPair(t)
	_, err = VerifySDJWTCredential(signed.PresentationPrefix, &privIA.PublicKey, "did:web:a.local:ia#key-1", otherPubHex, false)
	assert.True(t, HasCode(err, ErrCodeHolderMismatch), "got %v", err)
}
