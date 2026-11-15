package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

const vectorTaskSpecJSON = `{
  "supplierId": "urn:grad:supplier:C",
  "productId": "urn:grad:product:P1",
  "maxQuantity": 1,
  "currency": "CNY",
  "resources": ["urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"],
  "actions": ["order.create", "quote.read"],
  "description": "P1 x 1"
}`

const vectorOrder800JSON = `{
  "schemaVersion": "grad-auth-v1",
  "deploymentId": "0000000000000000000000000000000000000000000000000000000000000000",
  "actor": "did:web:broker-b.example.test:agents:B1",
  "principalDomain": "urn:grad:domain:A",
  "authorizationMode": "RESOURCE_PREAUTHORIZED",
  "taskId": "urn:grad:task:purchase-001",
  "audience": "https://supplier-c.example.test",
  "resource": "urn:grad:resource:C:orders",
  "action": "order.create",
  "supplierId": "urn:grad:supplier:C",
  "quoteId": "urn:grad:quote:Q800",
  "productId": "urn:grad:product:P1",
  "quantity": 1,
  "currency": "CNY",
  "amountMinor": 80000,
  "idempotencyKey": "purchase-001-order-001"
}`

const vectorManagementDualProofJSON = `{
  "appJwsProtected": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDp3ZWI6ZXhhbXBsZS50ZXN0OnZlY3RvciNrZXktMSIsInR5cCI6ImdyYWQtbWFuYWdlbWVudC1wcm9vZitqd3QifQ",
  "appJwsSignature": "OTzI9unDzkeM2WwD4ItwlE3Pp1OVsrUClg1pgc6XZpaedyaCQbefspRZK_gZU82Y9rVYEVivhrXZ-k2m4dflsA",
  "challenge": {
    "accountCommitment": "4444444444444444444444444444444444444444444444444444444444444444",
    "appKeyId": "did:web:example.test:vector#key-1",
    "appKeyVersion": 1,
    "appPublicKey": "0431a61fada7406d291c75e0efe1469a2c2fe3e17d699bf9cb94c73546ffcf65af780ceae5c0cd184f810c097d306b6e0bced6b11757be7474111c1e7a3198ba17",
    "challengeId": "registration-vector",
    "deploymentId": "5fe902e96041547d334a9d7df5744e4587416513d7726a0ae71c98bd35423efa",
    "didDocumentDigest": "3333333333333333333333333333333333333333333333333333333333333333",
    "domainId": "A",
    "expiresAt": 1794270060,
    "issuedAt": 1794270000,
    "managementIdentity": {
      "certificateSha256": "89388e455530a554a374ef021ad195adc74dfbe6f2b69b7b5300720f3d58c719",
      "mspId": "AMsp"
    },
    "nonce": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    "purpose": "grad-identity-registration-v1",
    "subjectId": "did:web:example.test:vector"
  },
  "challengeSha256": "29d51c5814bc4fd04ca389616d2be1d14560ded592a88c7c644101f0ec6939bc",
  "deployment": {
    "channelId": "procurement",
    "genesisHash": "1111111111111111111111111111111111111111111111111111111111111111",
    "instanceId": "2222222222222222222222222222222222222222222222222222222222222222",
    "purpose": "grad-fabric-deployment-v1",
    "registryName": "authregistry",
    "schemaVersion": "grad-auth-v1"
  },
  "deploymentId": "5fe902e96041547d334a9d7df5744e4587416513d7726a0ae71c98bd35423efa",
  "managementCertificateDer": "MIIBSjCB8aADAgECAgEBMAoGCCqGSM49BAMCMCUxDzANBgNVBAsTBmNsaWVudDESMBAGA1UEAxMJRDAgdmVjdG9yMB4XDTI2MTEwOTIzMjAwMFoXDTI2MTExMDAxMjAwMFowJTEPMA0GA1UECxMGY2xpZW50MRIwEAYDVQQDEwlEMCB2ZWN0b3IwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQjhz6-jSlHcN8B92sGs-kYO9dDGvSzHrYUvHWCpX8T_DhRkmUNukfdVma25kz7RHDu5VK8iQ61MtZW7WLOegI1oxIwEDAOBgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDSAAwRQIhAPz6mpIUqsIvPC7S2gJbxUx2JUUbjVxUYZ12eM5vhBWLAiAl3WlhDLEk-A27ZyUHp7Ew4J3e2OktfkkUeNVjYJo_Mw",
  "managementSignatureDer": "MEYCIQCMmhtMKHOZMzsesHjIK5fV4l2sG1Q8XjHeSL6-IKI73wIhANWR3n35NV94RujhEGZhZyTAuhihWpazSvTODJSKNbPx"
}`

const (
	wantTaskSpecDigest = "430541fe288ebcb3eaadbc6ba54765d45e4e56a1131148ff57a5e42c26e7c6ba"
	wantOrder800Hash   = "ebaa3f7977a96dc46851272c964b135256580b5f8dd0a6b4ca366e472ef668c5"
	wantOrder1200Hash  = "9ed920b6a8055eb83ad5b3ff7ed91b852211f0975738b8b51f0def3693fe4444"
	wantQuoteReadHash  = "bb00c19deddca75a715791d25b3670d4679608ff5ad17c3d09c8fc9765d73863"
	wantDeploymentID   = "5fe902e96041547d334a9d7df5744e4587416513d7726a0ae71c98bd35423efa"
	wantChallengeHash  = "29d51c5814bc4fd04ca389616d2be1d14560ded592a88c7c644101f0ec6939bc"
)

func TestTaskSpecAndRequestVectors(t *testing.T) {
	spec, specDigest, err := ParseTaskSpec([]byte(vectorTaskSpecJSON))
	if err != nil {
		t.Fatalf("ParseTaskSpec failed: %v", err)
	}
	if specDigest != wantTaskSpecDigest {
		t.Fatalf("taskSpecDigest mismatch: got %s, want %s", specDigest, wantTaskSpecDigest)
	}
	specDigest2, err := spec.Digest()
	if err != nil || specDigest2 != wantTaskSpecDigest {
		t.Fatalf("spec.Digest() mismatch: got %s err %v", specDigest2, err)
	}

	// Order 800
	req800, hash800, err := ParseAccessRequest([]byte(vectorOrder800JSON), true)
	if err != nil {
		t.Fatalf("ParseAccessRequest 800 failed: %v", err)
	}
	if hash800 != wantOrder800Hash {
		t.Fatalf("order 800 requestHash mismatch: got %s, want %s", hash800, wantOrder800Hash)
	}

	// Order 1200
	req1200 := *req800
	req1200.AmountMinor = 120000
	hash1200, err := req1200.Hash(true)
	if err != nil {
		t.Fatalf("req1200.Hash failed: %v", err)
	}
	if hash1200 != wantOrder1200Hash {
		t.Fatalf("order 1200 requestHash mismatch: got %s, want %s", hash1200, wantOrder1200Hash)
	}

	// Quote read
	reqQuote := *req800
	reqQuote.Resource = "urn:grad:resource:C:quotes"
	reqQuote.Action = "quote.read"
	reqQuote.QuoteID = nil
	reqQuote.AmountMinor = 0
	reqQuote.IdempotencyKey = "purchase-001-quote-001"
	hashQuote, err := reqQuote.Hash(true)
	if err != nil {
		t.Fatalf("reqQuote.Hash failed: %v", err)
	}
	if hashQuote != wantQuoteReadHash {
		t.Fatalf("quote.read requestHash mismatch: got %s, want %s", hashQuote, wantQuoteReadHash)
	}

	// Negative cases: unsorted taskSpec sets, bad quoteId on quote.read, missing amountMinor on order.create
	unsortedSpec := strings.Replace(vectorTaskSpecJSON, `["order.create", "quote.read"]`, `["quote.read", "order.create"]`, 1)
	if _, _, err := ParseTaskSpec([]byte(unsortedSpec)); !HasCode(err, ErrCodeInvalidSchema) {
		t.Fatalf("expected INVALID_SCHEMA for unsorted taskSpec.actions, got %v", err)
	}
	badQuote := reqQuote
	q := "urn:grad:quote:Q800"
	badQuote.QuoteID = &q
	if err := badQuote.Validate(true); !HasCode(err, ErrCodeInvalidSchema) {
		t.Fatalf("expected INVALID_SCHEMA for non-null quoteId in quote.read, got %v", err)
	}
	if err := req800.Validate(false); !HasCode(err, ErrCodeInvalidSchema) {
		t.Fatalf("expected INVALID_SCHEMA when all-zero deploymentId rejected at runtime, got %v", err)
	}
}

func TestManagementDualProofVectorAndTampering(t *testing.T) {
	var bundle ManagementDualProofBundle
	if err := DecodeStrictJSON([]byte(vectorManagementDualProofJSON), &bundle); err != nil {
		t.Fatalf("DecodeStrictJSON bundle failed: %v", err)
	}
	if err := bundle.Verify(); err != nil {
		t.Fatalf("ManagementDualProofBundle.Verify failed on fixed vector: %v", err)
	}

	depID, err := bundle.Deployment.ComputeID()
	if err != nil || depID != wantDeploymentID {
		t.Fatalf("deploymentId mismatch: got %s err %v", depID, err)
	}
	chalBytes, err := MarshalJCS(bundle.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if got := DigestBytes(chalBytes); got != wantChallengeHash {
		t.Fatalf("challengeSha256 mismatch: got %s, want %s", got, wantChallengeHash)
	}

	// Negative 1: mutate nonce with another valid 43-char canonical nonce
	tamperedNonce := bundle
	validOtherNonce, err := EncodeNonce(bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	tamperedNonce.Challenge.Nonce = validOtherNonce
	tamperedBytes, _ := MarshalJCS(tamperedNonce.Challenge)
	tamperedNonce.ChallengeSha256 = DigestBytes(tamperedBytes)
	if err := tamperedNonce.Verify(); !HasCode(err, ErrCodeSignatureInvalid) {
		t.Fatalf("expected SIGNATURE_INVALID after mutating nonce, got %v", err)
	}

	// Negative 2: mutate deploymentId
	tamperedDep := bundle
	tamperedDep.Challenge.DeploymentID = strings.Repeat("a", 64)
	if err := tamperedDep.Verify(); !HasCode(err, ErrCodeBindingMismatch) {
		t.Fatalf("expected BINDING_MISMATCH after mutating deploymentId, got %v", err)
	}

	// Negative 3: mutate management signature
	tamperedMgmt := bundle
	tamperedMgmt.ManagementSignatureDER = strings.Replace(tamperedMgmt.ManagementSignatureDER, "MEY", "MEZ", 1)
	if err := tamperedMgmt.Verify(); err == nil {
		t.Fatal("expected failure after corrupting management signature")
	}

	// Negative 4: mutate app signature
	tamperedApp := bundle
	tamperedApp.AppJWSSignature = "A" + tamperedApp.AppJWSSignature[1:]
	if err := tamperedApp.Verify(); !HasCode(err, ErrCodeSignatureInvalid) {
		t.Fatalf("expected SIGNATURE_INVALID after mutating appJwsSignature, got %v", err)
	}
}

func TestM3RecoveryDualProofAndDIDCanonicalVectors(t *testing.T) {
	now := time.Now().UTC()
	dep := DeploymentBinding{
		Purpose:       DeploymentPurpose,
		SchemaVersion: SchemaVersion,
		ChannelID:     "procurement",
		RegistryName:  "authregistry",
		GenesisHash:   strings.Repeat("1", 64),
		InstanceID:    strings.Repeat("2", 64),
	}
	depID, err := dep.ComputeID()
	if err != nil {
		t.Fatalf("ComputeID: %v", err)
	}

	// Verify DIDDocument digest invariance under JSON whitespace / key-order permutation (S98)
	_, pubHex, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := NewDIDDocument("did:web:a.local:u", "did:web:a.local:u#key-2", pubHex, KeyPurposeAssertionMethod, KeyPurposeAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	docDigest1, err := doc.Digest()
	if err != nil {
		t.Fatal(err)
	}
	canonicalDocBytes, err := MarshalJCS(doc)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(canonicalDocBytes, &generic); err != nil {
		t.Fatal(err)
	}
	indentedBytes, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if _, parsedDigest, err := ParseDIDDocument(indentedBytes); err != nil {
		t.Fatalf("ParseDIDDocument failed on indented doc: %v", err)
	} else if parsedDigest != docDigest1 {
		t.Fatalf("whitespace/key-order invariance broken: %s != %s", parsedDigest, docDigest1)
	}

	// Self-signed new management cert & app key for RecoveryDualProofBundle (S95, S96, S103)
	mgmtPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "u-recovered"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	mgmtDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &mgmtPriv.PublicKey, mgmtPriv)
	if err != nil {
		t.Fatal(err)
	}
	mgmtSum := sha256.Sum256(mgmtDER)
	newAppPriv, newAppPubHex, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != ChallengeNonceLen {
		t.Fatalf("expected canonical 43-char nonce, got %d", len(nonce))
	}

	chal := RecoveryChallenge{
		Purpose:               RecoveryChallengePurpose,
		ChallengeID:           "rec-chal-001",
		DeploymentID:          depID,
		DomainID:              "A",
		SubjectID:             "did:web:a.local:u",
		AccountCommitment:     strings.Repeat("4", 64),
		OldManagementIdentity: ManagementIdentity{MSPID: "AMsp", CertificateSha256: strings.Repeat("a", 64)},
		NewManagementIdentity: ManagementIdentity{MSPID: "AMsp", CertificateSha256: hex.EncodeToString(mgmtSum[:])},
		ExpectedRevision:      1,
		ExpectedKeyVersion:    1,
		NewAppKeyID:           "did:web:a.local:u#key-2",
		NewAppKeyVersion:      2,
		NewAppPublicKey:       newAppPubHex,
		DIDDocumentDigest:     docDigest1,
		Nonce:                 nonce,
		IssuedAt:              now.Unix(),
		ExpiresAt:             now.Unix() + 120,
	}

	bundle, err := SignRecoveryDualProofBundle(dep, chal, mgmtDER, mgmtPriv, newAppPriv)
	if err != nil {
		t.Fatalf("SignRecoveryDualProofBundle: %v", err)
	}
	if err := bundle.Verify(); err != nil {
		t.Fatalf("RecoveryDualProofBundle.Verify failed on valid bundle: %v", err)
	}

	// Negative 1: mutate new application key proof
	badApp := *bundle
	badApp.NewAppJWSSignature = "B" + badApp.NewAppJWSSignature[1:]
	if err := badApp.Verify(); !HasCode(err, ErrCodeRecoveryProofInvalid) {
		t.Fatalf("expected RECOVERY_PROOF_INVALID on mutated app signature, got %v", err)
	}

	// Negative 2: mutate challengeId -> BINDING_MISMATCH; mutate subjectId -> RECOVERY_PROOF_INVALID
	badSub := *bundle
	badSub.Challenge.SubjectID = "did:web:a.local:other"
	if err := badSub.Verify(); !HasCode(err, ErrCodeRecoveryProofInvalid) {
		t.Fatalf("expected RECOVERY_PROOF_INVALID on mutated subjectId, got %v", err)
	}
	badChalID := *bundle
	badChalID.Challenge.ChallengeID = "rec-chal-tampered"
	if err := badChalID.Verify(); !HasCode(err, ErrCodeChallengeMismatch) {
		t.Fatalf("expected CHALLENGE_MISMATCH on mutated challengeId, got %v", err)
	}

	// Negative 3: TTL > 300s rejected
	badTTL := chal
	badTTL.ExpiresAt = badTTL.IssuedAt + 301
	if _, err := SignRecoveryDualProofBundle(dep, badTTL, mgmtDER, mgmtPriv, newAppPriv); !HasCode(err, ErrCodeRecoveryProofInvalid) {
		t.Fatalf("expected RECOVERY_PROOF_INVALID for TTL > 300s, got %v", err)
	}
}
