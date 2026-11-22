package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)
	assert.Equal(t, wantTaskSpecDigest, specDigest)

	specDigest2, err := spec.Digest()
	require.NoError(t, err)
	assert.Equal(t, wantTaskSpecDigest, specDigest2)

	// Order 800
	req800, hash800, err := ParseAccessRequest([]byte(vectorOrder800JSON), true)
	require.NoError(t, err)
	assert.Equal(t, wantOrder800Hash, hash800)

	// Order 1200
	req1200 := *req800
	req1200.AmountMinor = 120000
	hash1200, err := req1200.Hash(true)
	require.NoError(t, err)
	assert.Equal(t, wantOrder1200Hash, hash1200)

	// Quote read (canonical URI urn:grad:resource:C:quotes)
	reqQuote := *req800
	reqQuote.Resource = ResourceQuotes
	reqQuote.Action = ActionQuoteRead
	reqQuote.QuoteID = nil
	reqQuote.AmountMinor = 0
	reqQuote.IdempotencyKey = "purchase-001-quote-001"
	hashQuote, err := reqQuote.Hash(true)
	require.NoError(t, err)
	assert.Equal(t, wantQuoteReadHash, hashQuote)

	// Negative cases: unsorted taskSpec sets, non-canonical resource aliases, mismatched action/resource,
	// bad quoteId on quote.read, all-zero deploymentId at runtime.
	unsortedSpec := strings.Replace(vectorTaskSpecJSON, `["order.create", "quote.read"]`, `["quote.read", "order.create"]`, 1)
	_, _, err = ParseTaskSpec([]byte(unsortedSpec))
	assert.True(t, HasCode(err, ErrCodeInvalidSchema), "got %v", err)

	legacySpec := strings.Replace(vectorTaskSpecJSON, ResourceQuotes, "urn:grad:resource:quotes", 1)
	_, _, err = ParseTaskSpec([]byte(legacySpec))
	assert.True(t, HasCode(err, ErrCodeInvalidSchema), "got %v", err)

	for _, alias := range []string{"quotes", "urn:grad:resource:quotes", ResourceOrders} {
		badAlias := reqQuote
		badAlias.Resource = alias
		assert.True(t, HasCode(badAlias.Validate(true), ErrCodeInvalidSchema), "quote.read alias=%q", alias)
	}
	for _, alias := range []string{"orders", "urn:grad:resource:orders", ResourceQuotes} {
		badAlias := *req800
		badAlias.Resource = alias
		assert.True(t, HasCode(badAlias.Validate(true), ErrCodeInvalidSchema), "order.create alias=%q", alias)
	}

	badQuote := reqQuote
	q := "urn:grad:quote:Q800"
	badQuote.QuoteID = &q
	assert.True(t, HasCode(badQuote.Validate(true), ErrCodeInvalidSchema))
	assert.True(t, HasCode(req800.Validate(false), ErrCodeInvalidSchema))
}

func TestManagementDualProofVectorAndTampering(t *testing.T) {
	var bundle ManagementDualProofBundle
	require.NoError(t, DecodeStrictJSON([]byte(vectorManagementDualProofJSON), &bundle))
	require.NoError(t, bundle.Verify())

	depID, err := ComputeDeploymentID(bundle.Deployment)
	require.NoError(t, err)
	assert.Equal(t, wantDeploymentID, depID)

	chalBytes, err := MarshalJCS(bundle.Challenge)
	require.NoError(t, err)
	assert.Equal(t, wantChallengeHash, DigestBytes(chalBytes))

	// Negative 1: mutate nonce with another valid 43-char canonical nonce.
	tamperedNonce := bundle
	validOtherNonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, ChallengeNonceBytes))
	require.NoError(t, ValidateNonce(validOtherNonce))
	tamperedNonce.Challenge.Nonce = validOtherNonce
	tamperedBytes, err := MarshalJCS(tamperedNonce.Challenge)
	require.NoError(t, err)
	tamperedNonce.ChallengeSha256 = DigestBytes(tamperedBytes)
	assert.True(t, HasCode(tamperedNonce.Verify(), ErrCodeSignatureInvalid))

	// Negative 2: mutate deploymentId.
	tamperedDep := bundle
	tamperedDep.Challenge.DeploymentID = strings.Repeat("a", 64)
	assert.True(t, HasCode(tamperedDep.Verify(), ErrCodeBindingMismatch))

	// Negative 3: mutate management signature.
	tamperedMgmt := bundle
	tamperedMgmt.ManagementSignatureDER = strings.Replace(tamperedMgmt.ManagementSignatureDER, "MEY", "MEZ", 1)
	assert.Error(t, tamperedMgmt.Verify())

	// Negative 4: mutate app signature.
	tamperedApp := bundle
	tamperedApp.AppJWSSignature = "A" + tamperedApp.AppJWSSignature[1:]
	assert.True(t, HasCode(tamperedApp.Verify(), ErrCodeSignatureInvalid))
}

func TestRecoveryDualProofAndDIDCanonicalVectors(t *testing.T) {
	now := time.Now().UTC()
	dep := DeploymentBinding{
		Purpose:       DeploymentPurpose,
		SchemaVersion: SchemaVersion,
		ChannelID:     "procurement",
		RegistryName:  "authregistry",
		GenesisHash:   strings.Repeat("1", 64),
		InstanceID:    strings.Repeat("2", 64),
	}
	depID, err := ComputeDeploymentID(dep)
	require.NoError(t, err)

	// Verify DIDDocument digest invariance under JSON whitespace / key-order permutation.
	privDoc, _ := mustGenKeyPair(t)
	doc, err := NewDIDDocument("did:web:a.local:u", "did:web:a.local:u#key-2", &privDoc.PublicKey, KeyPurposeAssertionMethod, KeyPurposeAuthentication)
	require.NoError(t, err)
	docDigest1, err := doc.Digest()
	require.NoError(t, err)
	canonicalDocBytes, err := MarshalJCS(doc)
	require.NoError(t, err)
	var generic map[string]any
	require.NoError(t, json.Unmarshal(canonicalDocBytes, &generic))
	indentedBytes, err := json.MarshalIndent(generic, "", "  ")
	require.NoError(t, err)
	_, parsedDigest, err := ParseDIDDocument(indentedBytes)
	require.NoError(t, err)
	assert.Equal(t, docDigest1, parsedDigest)

	// Self-signed new management cert & app key for RecoveryDualProofBundle.
	mgmtPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "u-recovered"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	mgmtDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &mgmtPriv.PublicKey, mgmtPriv)
	require.NoError(t, err)
	mgmtSum := sha256.Sum256(mgmtDER)
	newAppPriv, newAppPubHex := mustGenKeyPair(t)
	nonce, err := GenerateNonce()
	require.NoError(t, err)
	assert.Len(t, nonce, ChallengeNonceLen)

	chal := RecoveryChallenge{
		Purpose:               RecoveryChallengePurpose,
		ChallengeID:           "rec-chal-001",
		DeploymentID:          depID,
		DomainID:              "A",
		SubjectID:             "did:web:a.local:u",
		AccountCommitment:     strings.Repeat("4", 64),
		OldManagementIdentity: ManagementIdentity{MSPID: "AMsp", CertificateSHA256: strings.Repeat("a", 64)},
		NewManagementIdentity: ManagementIdentity{MSPID: "AMsp", CertificateSHA256: hex.EncodeToString(mgmtSum[:])},
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
	require.NoError(t, err)
	require.NoError(t, bundle.Verify())

	// Negative 1: mutate new application key proof.
	badApp := *bundle
	badApp.NewAppJWSSignature = "B" + badApp.NewAppJWSSignature[1:]
	assert.True(t, HasCode(badApp.Verify(), ErrCodeRecoveryProofInvalid))

	// Negative 2: mutate subjectId -> RECOVERY_PROOF_INVALID; mutate challengeId -> CHALLENGE_MISMATCH.
	badSub := *bundle
	badSub.Challenge.SubjectID = "did:web:a.local:other"
	assert.True(t, HasCode(badSub.Verify(), ErrCodeRecoveryProofInvalid))

	badChalID := *bundle
	badChalID.Challenge.ChallengeID = "rec-chal-tampered"
	assert.True(t, HasCode(badChalID.Verify(), ErrCodeChallengeMismatch))

	// Negative 3: TTL > 300s rejected.
	badTTL := chal
	badTTL.ExpiresAt = badTTL.IssuedAt + 301
	_, err = SignRecoveryDualProofBundle(dep, badTTL, mgmtDER, mgmtPriv, newAppPriv)
	assert.True(t, HasCode(err, ErrCodeRecoveryProofInvalid))
}

func TestIdentityLinkProofBundleSignVerifyAndTamper(t *testing.T) {
	srcPriv, _ := mustGenKeyPair(t)
	dstPriv, _ := mustGenKeyPair(t)
	now := time.Now().UTC().Unix()

	proposal := IdentityLinkProposal{
		DeploymentID:            strings.Repeat("5", 64),
		ID:                      "urn:grad:link:u-a-b-1",
		ProposedAt:              now,
		ExpiresAt:               now + 3600,
		SourceDomain:            "A",
		SourceSubject:           "did:web:a.local:u",
		SourceKeyID:             "did:web:a.local:u#key-1",
		SourceKeyVersion:        1,
		SourceAccountCommitment: strings.Repeat("6", 64),
		TargetDomain:            "B",
		TargetSubject:           "did:web:b.local:u-in-b",
		TargetKeyID:             "did:web:b.local:u-in-b#key-1",
		TargetKeyVersion:        1,
		TargetAccountCommitment: strings.Repeat("7", 64),
	}

	bundle, err := SignIdentityLinkProofBundle(proposal, srcPriv, dstPriv)
	require.NoError(t, err)
	require.NoError(t, bundle.Verify(&srcPriv.PublicKey, &dstPriv.PublicKey))

	// Wrong public key rejected.
	assert.True(t, HasCode(bundle.Verify(&dstPriv.PublicKey, &dstPriv.PublicKey), ErrCodeLinkProofInvalid))

	// Tampered proposalDigest rejected.
	badDig := *bundle
	badDig.ProposalDigest = strings.Repeat("9", 64)
	assert.True(t, HasCode(badDig.Verify(&srcPriv.PublicKey, &dstPriv.PublicKey), ErrCodeLinkProposalMismatch))
}
