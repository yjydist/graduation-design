package fabric

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
)

func (a acceptance) protocolVectors() error {
	// 1. Strict JSON & RFC 8785 JCS UTF-16 sorting + negative checks
	canon, err := protocol.CanonicalizeJSON([]byte("{\"\\uE000\":1,\"\\ud800\\udc00\":2}"))
	if err != nil {
		return err
	}
	if string(canon) != "{\"\\ud800\\udc00\":2,\"\\uE000\":1}" && string(canon) != "{\"\U00010000\":2,\"\uE000\":1}" {
		return fmt.Errorf("unexpected JCS UTF-16 order: %s", string(canon))
	}
	for _, bad := range [][]byte{
		[]byte(`{"a":1,"a":2}`),
		[]byte(`{"n":9007199254740992}`),
	} {
		if _, err := protocol.ParseStrictJSON(bad); !protocol.HasCode(err, protocol.ErrCodeInvalidSchema) {
			return fmt.Errorf("expected INVALID_SCHEMA for %s, got %v", bad, err)
		}
	}

	// 2. DID Document + JWK + uncompressed point vector (Section 1.4)
	didRaw := []byte(`{"id":"did:web:example.test:subjects:vector","verificationMethod":[{"id":"did:web:example.test:subjects:vector#key-1","type":"JsonWebKey","controller":"did:web:example.test:subjects:vector","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}}],"authentication":["did:web:example.test:subjects:vector#key-1"],"assertionMethod":["did:web:example.test:subjects:vector#key-1"]}`)
	doc, didDig, err := protocol.ParseDIDDocument(didRaw)
	if err != nil {
		return err
	}
	_, pubHex, err := doc.VerificationMethod[0].PublicKeyJWK.Validate()
	if err != nil {
		return err
	}
	thumb, err := doc.VerificationMethod[0].PublicKeyJWK.Thumbprint()
	if err != nil {
		return err
	}
	if didDig != "e08e529fe445c3506b707a790adc556b93148015621303fb48a7ccd7f1b3e8e8" ||
		thumb != "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M" ||
		pubHex != "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5" {
		return fmt.Errorf("Section 1.4 vector mismatch: didDig=%s thumb=%s", didDig, thumb)
	}

	// 3. Challenge nonce vector & '8'->'9' trailing bit rejection (Section 2.1)
	const nonceVec = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	if _, err := protocol.ValidateNonce(nonceVec); err != nil {
		return err
	}
	if _, err := protocol.ValidateNonce(nonceVec[:42] + "9"); !protocol.HasCode(err, protocol.ErrCodeInvalidSchema) {
		return fmt.Errorf("expected INVALID_SCHEMA for trailing-bit mutated nonce")
	}

	// 4. taskSpec + requestHash static vectors (Section 1.3 & Section 3)
	spec, specDig, err := protocol.ParseTaskSpec([]byte(`{"supplierId":"urn:grad:supplier:C","productId":"urn:grad:product:P1","maxQuantity":1,"currency":"CNY","resources":["urn:grad:resource:C:orders","urn:grad:resource:C:quotes"],"actions":["order.create","quote.read"],"description":"P1 x 1"}`))
	if err != nil {
		return err
	}
	if specDig != "430541fe288ebcb3eaadbc6ba54765d45e4e56a1131148ff57a5e42c26e7c6ba" {
		return fmt.Errorf("taskSpecDigest vector mismatch: %s", specDig)
	}
	_ = spec

	req800, hash800, err := protocol.ParseAccessRequest([]byte(`{"schemaVersion":"grad-auth-v1","deploymentId":"0000000000000000000000000000000000000000000000000000000000000000","actor":"did:web:broker-b.example.test:agents:B1","principalDomain":"urn:grad:domain:A","authorizationMode":"RESOURCE_PREAUTHORIZED","taskId":"urn:grad:task:purchase-001","audience":"https://supplier-c.example.test","resource":"urn:grad:resource:C:orders","action":"order.create","supplierId":"urn:grad:supplier:C","quoteId":"urn:grad:quote:Q800","productId":"urn:grad:product:P1","quantity":1,"currency":"CNY","amountMinor":80000,"idempotencyKey":"purchase-001-order-001"}`), true)
	if err != nil {
		return err
	}
	if hash800 != "ebaa3f7977a96dc46851272c964b135256580b5f8dd0a6b4ca366e472ef668c5" {
		return fmt.Errorf("request 800 vector mismatch: %s", hash800)
	}
	req1200 := *req800
	req1200.AmountMinor = 120000
	hash1200, err := req1200.Hash(true)
	if err != nil || hash1200 != "9ed920b6a8055eb83ad5b3ff7ed91b852211f0975738b8b51f0def3693fe4444" {
		return fmt.Errorf("request 1200 vector mismatch: %s %v", hash1200, err)
	}
	reqQuote := *req800
	reqQuote.Resource = "urn:grad:resource:C:quotes"
	reqQuote.Action = "quote.read"
	reqQuote.QuoteID = nil
	reqQuote.AmountMinor = 0
	reqQuote.IdempotencyKey = "purchase-001-quote-001"
	hashQuote, err := reqQuote.Hash(true)
	if err != nil || hashQuote != "bb00c19deddca75a715791d25b3670d4679608ff5ad17c3d09c8fc9765d73863" {
		return fmt.Errorf("quote.read vector mismatch: %s %v", hashQuote, err)
	}

	// 5. Management dual proof static vector (Section 4)
	dualVecJSON := []byte(`{"appJwsProtected":"eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDp3ZWI6ZXhhbXBsZS50ZXN0OnZlY3RvciNrZXktMSIsInR5cCI6ImdyYWQtbWFuYWdlbWVudC1wcm9vZitqd3QifQ","appJwsSignature":"OTzI9unDzkeM2WwD4ItwlE3Pp1OVsrUClg1pgc6XZpaedyaCQbefspRZK_gZU82Y9rVYEVivhrXZ-k2m4dflsA","challenge":{"accountCommitment":"4444444444444444444444444444444444444444444444444444444444444444","appKeyId":"did:web:example.test:vector#key-1","appKeyVersion":1,"appPublicKey":"0431a61fada7406d291c75e0efe1469a2c2fe3e17d699bf9cb94c73546ffcf65af780ceae5c0cd184f810c097d306b6e0bced6b11757be7474111c1e7a3198ba17","challengeId":"registration-vector","deploymentId":"5fe902e96041547d334a9d7df5744e4587416513d7726a0ae71c98bd35423efa","didDocumentDigest":"3333333333333333333333333333333333333333333333333333333333333333","domainId":"A","expiresAt":1794270060,"issuedAt":1794270000,"managementIdentity":{"certificateSha256":"89388e455530a554a374ef021ad195adc74dfbe6f2b69b7b5300720f3d58c719","mspId":"AMsp"},"nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","purpose":"grad-identity-registration-v1","subjectId":"did:web:example.test:vector"},"challengeSha256":"29d51c5814bc4fd04ca389616d2be1d14560ded592a88c7c644101f0ec6939bc","deployment":{"channelId":"procurement","genesisHash":"1111111111111111111111111111111111111111111111111111111111111111","instanceId":"2222222222222222222222222222222222222222222222222222222222222222","purpose":"grad-fabric-deployment-v1","registryName":"authregistry","schemaVersion":"grad-auth-v1"},"deploymentId":"5fe902e96041547d334a9d7df5744e4587416513d7726a0ae71c98bd35423efa","managementCertificateDer":"MIIBSjCB8aADAgECAgEBMAoGCCqGSM49BAMCMCUxDzANBgNVBAsTBmNsaWVudDESMBAGA1UEAxMJRDAgdmVjdG9yMB4XDTI2MTEwOTIzMjAwMFoXDTI2MTExMDAxMjAwMFowJTEPMA0GA1UECxMGY2xpZW50MRIwEAYDVQQDEwlEMCB2ZWN0b3IwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQjhz6-jSlHcN8B92sGs-kYO9dDGvSzHrYUvHWCpX8T_DhRkmUNukfdVma25kz7RHDu5VK8iQ61MtZW7WLOegI1oxIwEDAOBgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDSAAwRQIhAPz6mpIUqsIvPC7S2gJbxUx2JUUbjVxUYZ12eM5vhBWLAiAl3WlhDLEk-A27ZyUHp7Ew4J3e2OktfkkUeNVjYJo_Mw","managementSignatureDer":"MEYCIQCMmhtMKHOZMzsesHjIK5fV4l2sG1Q8XjHeSL6-IKI73wIhANWR3n35NV94RujhEGZhZyTAuhihWpazSvTODJSKNbPx"}`)
	var dual protocol.ManagementDualProofBundle
	if err := protocol.DecodeStrictJSON(dualVecJSON, &dual); err != nil {
		return err
	}
	if err := dual.Verify(); err != nil {
		return err
	}
	dualBad := dual
	dualBad.Challenge.DeploymentID = strings.Repeat("a", 64)
	if err := dualBad.Verify(); err == nil {
		return fmt.Errorf("expected failure on mutated dual proof deploymentId")
	}

	a.log.event("protocol_vectors", map[string]any{
		"didDocumentDigest": didDig,
		"jwkThumbprint":     thumb,
		"taskSpecDigest":    specDig,
		"request800Hash":    hash800,
		"request1200Hash":   hash1200,
		"quoteReadHash":     hashQuote,
		"dualDeploymentId":  dual.DeploymentID,
		"dualChallengeHash": dual.ChallengeSha256,
	})
	return nil
}

func (a acceptance) protocolDIDAndContext() error {
	// 1. Validate local W3C VC v2 context copy and manifest offline.
	rawCtx, err := os.ReadFile(a.instance.registrySubPath("vc-v2.context.json"))
	if err != nil {
		return err
	}
	if protocol.DigestBytes(rawCtx) != protocol.PinnedVCv2ContextSHA256 {
		return fmt.Errorf("instance vc-v2.context.json SHA-256 mismatch")
	}
	var manifest protocol.ContextManifestEntry
	if b, err := os.ReadFile(a.instance.registrySubPath("context-manifest.json")); err != nil {
		return err
	} else if err := protocol.DecodeStrictJSON(b, &manifest); err != nil {
		return err
	}
	if manifest.SHA256 != protocol.PinnedVCv2ContextSHA256 || manifest.VocabURI != protocol.GradAuthVocabURI {
		return fmt.Errorf("unexpected context manifest: %+v", manifest)
	}
	if err := protocol.ValidateCredentialContext([]any{"https://evil.example/v2", map[string]string{"@vocab": protocol.GradAuthVocabURI}}); !protocol.HasCode(err, protocol.ErrCodeInvalidSchema) {
		return fmt.Errorf("expected INVALID_SCHEMA on non-pinned @context URL, got %v", err)
	}

	// 2. Start controlled local HTTPS did:web server backed solely by instance CA/TLS certs & DID docs.
	srv, resolver, err := a.instance.startControlledDIDResolver()
	if err != nil {
		return err
	}
	defer srv.Close()

	// Verify T root preseed offline against live ledger RootRecord.
	bootRaw, err := a.p.direct(a.ctx, api.Registry, "Read", api.BootstrapKey)
	if err != nil {
		return err
	}
	var liveBoot api.Bootstrap
	if err := json.Unmarshal(bootRaw, &liveBoot); err != nil {
		return err
	}
	tDocRaw, err := os.ReadFile(a.instance.registrySubPath(didRelPath(liveBoot.Root.DID)))
	if err != nil {
		return err
	}
	if _, err := resolver.RegisterPreseed(protocol.RootPreseed{
		DID:               liveBoot.Root.DID,
		KeyID:             liveBoot.Root.KeyID,
		KeyVersion:        liveBoot.Root.KeyVersion,
		PublicKeyHex:      liveBoot.Root.PublicKey,
		DIDDocumentDigest: liveBoot.Root.DocumentDigest,
		RawDocument:       tDocRaw,
	}); err != nil {
		return err
	}
	if _, _, _, err := resolver.ResolveDID(a.ctx, liveBoot.Root.DID, protocol.DIDResolutionExpectation{
		ExpectedDigest:       liveBoot.Root.DocumentDigest,
		ExpectedKeyID:        liveBoot.Root.KeyID,
		ExpectedKeyVersion:   liveBoot.Root.KeyVersion,
		ExpectedPublicKeyHex: liveBoot.Root.PublicKey,
		RequiredPurpose:      protocol.KeyPurposeAssertionMethod,
	}); err != nil {
		return err
	}

	// Resolve all seeded identities & issuers over controlled HTTPS did:web and verify against ledger state.
	resolvedCount := 1
	checkDID := func(did string, purpose string) error {
		idRec, err := ledgerRecord[api.Identity](a.ctx, a.p, "identity", did)
		if err != nil {
			return err
		}
		if _, _, _, err := resolver.ResolveDID(a.ctx, idRec.ID, protocol.DIDResolutionExpectation{
			ExpectedDigest:       idRec.DocumentDigest,
			ExpectedKeyID:        idRec.KeyID,
			ExpectedKeyVersion:   idRec.KeyVersion,
			ExpectedPublicKeyHex: idRec.PublicKey,
			RequiredPurpose:      purpose,
		}); err != nil {
			return err
		}
		resolvedCount++
		return nil
	}
	for _, dom := range []string{"A", "B", "C"} {
		domDID := a.f.Domains[dom].Identity.ID
		issDID := a.f.Domains[dom].Issuers[0].ID
		if err := checkDID(domDID, protocol.KeyPurposeAssertionMethod); err != nil {
			return err
		}
		if err := checkDID(issDID, protocol.KeyPurposeAssertionMethod); err != nil {
			return err
		}
	}
	for _, role := range []string{"U", "A1", "alt", "B1", "C"} {
		if err := checkDID(a.f.Identities[role].ID, protocol.KeyPurposeAuthentication); err != nil {
			return err
		}
	}

	// Negative probes on resolver: plaintext HTTP, untrusted CA, wrong digest, missing purpose on issuer
	if _, err := resolver.ResolveRawURL(a.ctx, "http://a.local/u/did.json"); !protocol.HasCode(err, protocol.ErrCodeDIDDocumentMismatch) {
		return fmt.Errorf("expected plaintext HTTP rejection, got %v", err)
	}
	untrustedCA, err := protocol.GenerateTestCA(time.Now().UTC())
	if err != nil {
		return err
	}
	untrustedPool, _ := protocol.ParseTestCAPublic(untrustedCA.CertPEM)
	untrustedRes, err := protocol.NewDIDWebResolver(untrustedPool, srv.Routes())
	if err != nil {
		return err
	}
	if _, _, _, err := untrustedRes.ResolveDID(a.ctx, a.f.Identities["U"].ID, protocol.DIDResolutionExpectation{}); !protocol.HasCode(err, protocol.ErrCodeDIDDocumentMismatch) {
		return fmt.Errorf("expected untrusted CA rejection, got %v", err)
	}
	if _, _, _, err := resolver.ResolveDID(a.ctx, a.f.Domains["A"].Issuers[0].ID, protocol.DIDResolutionExpectation{
		ExpectedDigest:       a.f.Domains["A"].Issuers[0].DocumentDigest,
		ExpectedKeyID:        a.f.Domains["A"].Issuers[0].KeyID,
		ExpectedKeyVersion:   1,
		ExpectedPublicKeyHex: a.f.Domains["A"].Issuers[0].PublicKey,
		RequiredPurpose:      protocol.KeyPurposeAuthentication,
	}); !protocol.HasCode(err, protocol.ErrCodeDIDKeyPurposeInvalid) {
		return fmt.Errorf("expected DID_KEY_PURPOSE_INVALID on assertion-only issuer, got %v", err)
	}

	// Confirm exported materials/run dir contain zero private keys
	scanned, err := scanDirForPrivateKeys(a.dir)
	if err != nil {
		return err
	}
	a.log.event("did_web_and_context_verified", map[string]any{
		"contextSha256":  manifest.SHA256,
		"resolvedDIDs":   resolvedCount,
		"scannedFiles":   len(scanned),
		"privateKeyLeak": false,
	})
	return nil
}

func (a acceptance) protocolEvidence() error {
	srv, resolver, err := a.instance.startControlledDIDResolver()
	if err != nil {
		return err
	}
	defer srv.Close()

	// Capture consistent fixed-height ledger state snapshot from peer.
	height, err := a.p.height(a.ctx)
	if err != nil {
		return err
	}
	bootRaw, err := a.p.direct(a.ctx, api.Registry, "Read", api.BootstrapKey)
	if err != nil {
		return err
	}
	var liveBoot api.Bootstrap
	if err := json.Unmarshal(bootRaw, &liveBoot); err != nil {
		return err
	}
	tDocRaw, err := os.ReadFile(a.instance.registrySubPath(didRelPath(liveBoot.Root.DID)))
	if err != nil {
		return err
	}
	if _, err := resolver.RegisterPreseed(protocol.RootPreseed{
		DID:               liveBoot.Root.DID,
		KeyID:             liveBoot.Root.KeyID,
		KeyVersion:        liveBoot.Root.KeyVersion,
		PublicKeyHex:      liveBoot.Root.PublicKey,
		DIDDocumentDigest: liveBoot.Root.DocumentDigest,
		RawDocument:       tDocRaw,
	}); err != nil {
		return err
	}

	now := time.Now().UTC().Truncate(time.Second)
	snap := &protocol.SnapshotView{
		Height:         height,
		Now:            now,
		ClockError:     api.ClockError,
		DeploymentID:   a.d.DeploymentID,
		Root:           liveBoot.Root,
		Domains:        make(map[string]api.Domain),
		Certifications: make(map[string]api.Certification),
		Identities:     make(map[string]api.Identity),
		Credentials:    make(map[string]api.Credential),
		Tasks:          make(map[string]api.Task),
		Grants:         make(map[string]api.Grant),
	}

	for _, domID := range []string{"A", "B", "C"} {
		domRec, err := ledgerRecord[api.Domain](a.ctx, a.p, "domain", domID)
		if err != nil {
			return err
		}
		snap.Domains[domID] = domRec
		certRec, err := ledgerRecord[api.Certification](a.ctx, a.p, "certification", domRec.Certification)
		if err != nil {
			return err
		}
		snap.Certifications[certRec.ID] = certRec

		domIdentity, err := ledgerRecord[api.Identity](a.ctx, a.p, "identity", domRec.DID)
		if err != nil {
			return err
		}
		snap.Identities[domIdentity.ID] = domIdentity
		for _, issDID := range domRec.Issuers {
			issID, err := ledgerRecord[api.Identity](a.ctx, a.p, "identity", issDID)
			if err != nil {
				return err
			}
			snap.Identities[issID.ID] = issID
		}
	}
	for _, role := range []string{"U", "A1", "alt", "B1", "C"} {
		idRec, err := ledgerRecord[api.Identity](a.ctx, a.p, "identity", a.f.Identities[role].ID)
		if err != nil {
			return err
		}
		snap.Identities[idRec.ID] = idRec
		credRec, err := ledgerRecord[api.Credential](a.ctx, a.p, "credential", a.f.Credentials[role].ID)
		if err != nil {
			return err
		}
		snap.Credentials[credRec.ID] = credRec
	}
	taskRec, err := ledgerRecord[api.Task](a.ctx, a.p, "task", a.f.Task.ID)
	if err != nil {
		return err
	}
	snap.Tasks[taskRec.ID] = taskRec
	for _, gID := range []string{a.f.G0.ID, a.f.G1.ID} {
		gRec, err := ledgerRecord[api.Grant](a.ctx, a.p, "grant", gID)
		if err != nil {
			return err
		}
		snap.Grants[gRec.ID] = gRec
	}

	// Verify all persisted domain certifications & SD-JWT credentials across A, B, C against live anchors.
	_, rootPub, err := resolver.ResolvePreseededKey(snap.Root.DID, snap.Root.KeyID, snap.Root.KeyVersion, protocol.KeyPurposeAssertionMethod, snap.Root.PublicKey)
	if err != nil {
		return err
	}
	for _, domID := range []string{"A", "B", "C"} {
		jwsBytes, err := os.ReadFile(a.instance.registrySubPath("certifications", domID+".jws"))
		if err != nil {
			return err
		}
		dom := snap.Domains[domID]
		certAnchor := snap.Certifications[dom.Certification]
		parsedCert, dig, err := protocol.ParseAndVerifyDomainAuthorityCredential(string(jwsBytes), rootPub, snap.Root.KeyID)
		if err != nil {
			return err
		}
		scopes := make([]protocol.IssuerScope, len(certAnchor.Scopes))
		for idx, s := range certAnchor.Scopes {
			scopes[idx] = protocol.IssuerScope{ID: s.ID, AppKeyVersion: s.KeyVersion, CredentialTypes: s.Types, ClaimNames: s.Claims}
		}
		if err := parsedCert.VerifyAgainstChain(dig, protocol.DomainAnchorState{
			RootDID:            snap.Root.DID,
			RootKeyVersion:     snap.Root.KeyVersion,
			DomainID:           dom.ID,
			DomainDID:          dom.DID,
			DomainIssuers:      dom.Issuers,
			CertificationID:    certAnchor.ID,
			CertificationNBF:   certAnchor.NBF,
			CertificationEXP:   certAnchor.EXP,
			CertificationDig:   certAnchor.Digest,
			CertificationScope: scopes,
		}); err != nil {
			return err
		}
	}
	for _, role := range []string{"U", "A1", "alt", "B1", "C"} {
		sdBytes, err := os.ReadFile(a.instance.registrySubPath("credentials", role+".sdjwt"))
		if err != nil {
			return err
		}
		credAnchor := snap.Credentials[a.f.Credentials[role].ID]
		issuerID := snap.Identities[credAnchor.Issuer]
		holderID := snap.Identities[credAnchor.Subject]
		_, issPub, _, err := resolver.ResolveDID(a.ctx, issuerID.ID, protocol.DIDResolutionExpectation{
			ExpectedDigest:       issuerID.DocumentDigest,
			ExpectedKeyID:        issuerID.KeyID,
			ExpectedKeyVersion:   issuerID.KeyVersion,
			ExpectedPublicKeyHex: issuerID.PublicKey,
			RequiredPurpose:      protocol.KeyPurposeAssertionMethod,
		})
		if err != nil {
			return err
		}
		vc, err := protocol.VerifySDJWTCredential(string(sdBytes), issPub, issuerID.KeyID, holderID.PublicKey, false)
		if err != nil {
			return err
		}
		if vc.AnchorDigest != credAnchor.Digest || vc.Domain != holderID.Domain || vc.Role != holderID.Kind {
			return fmt.Errorf("role %s SD-JWT anchor or claims mismatch", role)
		}
	}

	// Verify persisted evidence-sample.json using live fixed-height snapshot.
	sampleRaw, err := os.ReadFile(a.instance.registrySubPath("evidence-sample.json"))
	if err != nil {
		return err
	}
	var sample EvidenceSample
	if err := protocol.DecodeStrictJSON(sampleRaw, &sample); err != nil {
		return err
	}
	sampleRes, err := protocol.VerifyAccessEvidencePackage(a.ctx, &sample.Package, snap, resolver, protocol.ChallengeContext{
		ChallengeID: sample.ChallengeID,
		Nonce:       sample.Nonce,
		Audience:    sample.Audience,
		IssuedAt:    sample.IssuedAt,
		ExpiresAt:   sample.ExpiresAt,
	})
	if err != nil {
		return fmt.Errorf("persisted evidence-sample verification failed: %w", err)
	}

	// Issue fresh challenge nonce & KB-JWT using A1's persisted private key, verify positive + 8 single-field tampers.
	privA1, err := loadECPrivateKeyPEM(a.instance.privatePath("app", "A1.key.pem"))
	if err != nil {
		return err
	}
	sdA1Bytes, err := os.ReadFile(a.instance.registrySubPath("credentials", "A1.sdjwt"))
	if err != nil {
		return err
	}
	liveNonce, err := protocol.GenerateNonce()
	if err != nil {
		return err
	}
	liveChal := protocol.ChallengeContext{
		ChallengeID: "live-" + a.id,
		Nonce:       liveNonce,
		Audience:    "https://c.local",
		IssuedAt:    now.Unix(),
		ExpiresAt:   now.Add(10 * time.Minute).Unix(),
	}
	livePkg := sample.Package
	livePkg.Request.IdempotencyKey = "verify-live-" + a.id
	livePkg.AncestorCredentials = append([]protocol.AncestorCredential(nil), sample.Package.AncestorCredentials...)
	livePkg.Grants = append([]string(nil), sample.Package.Grants...)
	livePkg.TrustPaths = append([]protocol.TrustPathEntry(nil), sample.Package.TrustPaths...)
	_, _, err = protocol.AssembleAccessEvidencePackage(&livePkg, string(sdA1Bytes), a.f.Identities["A1"].KeyID, privA1, liveChal, now.Unix(), false)
	if err != nil {
		return err
	}
	liveRes, err := protocol.VerifyAccessEvidencePackage(a.ctx, &livePkg, snap, resolver, liveChal)
	if err != nil {
		return fmt.Errorf("live AccessEvidencePackage verification failed: %w", err)
	}

	// Negative tests across all 8 fields: request, taskSpec, challengeId, nonce, leafPresentation, ancestorCredentials, grants, trustPaths.
	cloneLive := func() protocol.AccessEvidencePackage {
		p := livePkg
		p.AncestorCredentials = append([]protocol.AncestorCredential(nil), livePkg.AncestorCredentials...)
		p.Grants = append([]string(nil), livePkg.Grants...)
		p.TrustPaths = append([]protocol.TrustPathEntry(nil), livePkg.TrustPaths...)
		p.TaskSpec.Resources = append([]string(nil), livePkg.TaskSpec.Resources...)
		p.TaskSpec.Actions = append([]string(nil), livePkg.TaskSpec.Actions...)
		if livePkg.Request.QuoteID != nil {
			q := *livePkg.Request.QuoteID
			p.Request.QuoteID = &q
		}
		return p
	}
	toggleTail := func(s string) string {
		if s[len(s)-1] == 'A' {
			return s[:len(s)-1] + "B"
		}
		return s[:len(s)-1] + "A"
	}

	tamperCases := []struct {
		name string
		test func() error
	}{
		{"request", func() error {
			p := cloneLive()
			p.Request.AmountMinor++
			_, err := protocol.VerifyAccessEvidencePackage(a.ctx, &p, snap, resolver, liveChal)
			return err
		}},
		{"taskSpec", func() error {
			p := cloneLive()
			p.TaskSpec.Description = "tampered-spec"
			_, err := protocol.VerifyAccessEvidencePackage(a.ctx, &p, snap, resolver, liveChal)
			return err
		}},
		{"challengeId", func() error {
			p := cloneLive()
			p.ChallengeID = "tampered-chal"
			_, err := protocol.VerifyAccessEvidencePackage(a.ctx, &p, snap, resolver, liveChal)
			return err
		}},
		{"nonce", func() error {
			badChal := liveChal
			otherNonce, _ := protocol.GenerateNonce()
			badChal.Nonce = otherNonce
			_, err := protocol.VerifyAccessEvidencePackage(a.ctx, &livePkg, snap, resolver, badChal)
			return err
		}},
		{"leafPresentation", func() error {
			p := cloneLive()
			p.LeafPresentation = toggleTail(p.LeafPresentation)
			_, err := protocol.VerifyAccessEvidencePackage(a.ctx, &p, snap, resolver, liveChal)
			return err
		}},
		{"ancestorCredentials", func() error {
			p := cloneLive()
			p.AncestorCredentials = p.AncestorCredentials[:1]
			_, err := protocol.VerifyAccessEvidencePackage(a.ctx, &p, snap, resolver, liveChal)
			return err
		}},
		{"grants", func() error {
			p := cloneLive()
			p.Grants[1] = toggleTail(p.Grants[1])
			_, err := protocol.VerifyAccessEvidencePackage(a.ctx, &p, snap, resolver, liveChal)
			return err
		}},
		{"trustPaths", func() error {
			p := cloneLive()
			p.TrustPaths[0].DomainCertification = toggleTail(p.TrustPaths[0].DomainCertification)
			_, err := protocol.VerifyAccessEvidencePackage(a.ctx, &p, snap, resolver, liveChal)
			return err
		}},
	}
	rejected := make([]string, 0, len(tamperCases))
	for _, tc := range tamperCases {
		if err := tc.test(); err == nil {
			return fmt.Errorf("tampered %s unexpectedly passed verification", tc.name)
		}
		rejected = append(rejected, tc.name)
	}

	a.log.event("verifiable_evidence_verified", map[string]any{
		"snapshotHeight":     snap.Height,
		"sampleRequestHash":  sampleRes.Bindings.RequestHash,
		"sampleEvidenceHash": sampleRes.Bindings.EvidenceHash,
		"liveChallengeId":    liveChal.ChallengeID,
		"liveRequestHash":    liveRes.Bindings.RequestHash,
		"liveEvidenceHash":   liveRes.Bindings.EvidenceHash,
		"tamperRejected":     rejected,
	})
	return nil
}
