package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

const (
	// SchemaVersion is the fixed grad-auth-v1 protocol schema identifier.
	SchemaVersion = "grad-auth-v1"
	// DeploymentPurpose is the fixed purpose for deploymentId derivation.
	DeploymentPurpose = "grad-fabric-deployment-v1"
	// RegistrationChallengePurpose is the fixed purpose for registration challenges.
	RegistrationChallengePurpose = "grad-identity-registration-v1"
	// ManagementProofTyp is the JOSE typ for application-key management proofs.
	ManagementProofTyp = "grad-management-proof+jwt"

	// ModeResourcePreauthorized matches fabricapi.RP.
	ModeResourcePreauthorized = "RESOURCE_PREAUTHORIZED"
	// ModeBuyerMandate is buyer-mandate authorization mode.
	ModeBuyerMandate = "BUYER_MANDATE"
)

// TaskSpec is the 7-field canonical task specification committed via taskSpecDigest.
type TaskSpec struct {
	SupplierID  string   `json:"supplierId"`
	ProductID   string   `json:"productId"`
	MaxQuantity int64    `json:"maxQuantity"`
	Currency    string   `json:"currency"`
	Resources   []string `json:"resources"`
	Actions     []string `json:"actions"`
	Description string   `json:"description"`
}

// ParseTaskSpec strictly decodes and validates a TaskSpec JSON payload.
func ParseTaskSpec(raw []byte) (*TaskSpec, string, error) {
	var spec TaskSpec
	if err := DecodeStrictJSON(raw, &spec); err != nil {
		return nil, "", err
	}
	if err := spec.Validate(); err != nil {
		return nil, "", err
	}
	digest, _, err := DigestJCS(raw)
	if err != nil {
		return nil, "", err
	}
	return &spec, digest, nil
}

// Validate enforces grad-auth-v1 TaskSpec schema, positive quantity, and sorted non-wildcard sets.
func (s *TaskSpec) Validate() error {
	if s == nil {
		return NewError(ErrCodeInvalidSchema, "nil TaskSpec")
	}
	if s.SupplierID == "" || s.ProductID == "" || s.Currency == "" || s.Description == "" {
		return NewError(ErrCodeInvalidSchema, "TaskSpec string fields must be non-empty")
	}
	if s.MaxQuantity <= 0 || s.MaxQuantity > MaxSafeInt {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("TaskSpec maxQuantity %d out of range", s.MaxQuantity))
	}
	if err := ValidateStringSet("TaskSpec.resources", s.Resources, 32, true); err != nil {
		return err
	}
	if err := ValidateStringSet("TaskSpec.actions", s.Actions, 32, true); err != nil {
		return err
	}
	return nil
}

// Digest computes H(J(TaskSpec)) = SHA-256(JCS(TaskSpec)) as 64-char lowercase hex.
func (s *TaskSpec) Digest() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	canon, err := MarshalJCS(s)
	if err != nil {
		return "", err
	}
	return DigestBytes(canon), nil
}

// AccessRequest is the 16-field canonical request covered by requestHash.
type AccessRequest struct {
	SchemaVersion     string  `json:"schemaVersion"`
	DeploymentID      string  `json:"deploymentId"`
	Actor             string  `json:"actor"`
	PrincipalDomain   string  `json:"principalDomain"`
	AuthorizationMode string  `json:"authorizationMode"`
	TaskID            string  `json:"taskId"`
	Audience          string  `json:"audience"`
	Resource          string  `json:"resource"`
	Action            string  `json:"action"`
	SupplierID        string  `json:"supplierId"`
	QuoteID           *string `json:"quoteId"`
	ProductID         string  `json:"productId"`
	Quantity          int64   `json:"quantity"`
	Currency          string  `json:"currency"`
	AmountMinor       int64   `json:"amountMinor"`
	IdempotencyKey    string  `json:"idempotencyKey"`
}

// ParseAccessRequest strictly decodes and validates an AccessRequest JSON payload.
func ParseAccessRequest(raw []byte, allowZeroDeploymentID bool) (*AccessRequest, string, error) {
	var req AccessRequest
	if err := DecodeStrictJSON(raw, &req); err != nil {
		return nil, "", err
	}
	if err := req.Validate(allowZeroDeploymentID); err != nil {
		return nil, "", err
	}
	digest, _, err := DigestJCS(raw)
	if err != nil {
		return nil, "", err
	}
	return &req, digest, nil
}

// Validate enforces strict schema and action-specific quoteId/amountMinor invariants on AccessRequest.
func (r *AccessRequest) Validate(allowZeroDeploymentID bool) error {
	if r == nil {
		return NewError(ErrCodeInvalidSchema, "nil AccessRequest")
	}
	if r.SchemaVersion != SchemaVersion {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("unexpected schemaVersion %q", r.SchemaVersion))
	}
	if !IsHexDigest(r.DeploymentID, allowZeroDeploymentID) {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid deploymentId %q", r.DeploymentID))
	}
	if r.AuthorizationMode != ModeResourcePreauthorized && r.AuthorizationMode != ModeBuyerMandate {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid authorizationMode %q", r.AuthorizationMode))
	}
	requiredStrings := []struct {
		name string
		val  string
	}{
		{"actor", r.Actor},
		{"principalDomain", r.PrincipalDomain},
		{"taskId", r.TaskID},
		{"audience", r.Audience},
		{"resource", r.Resource},
		{"action", r.Action},
		{"supplierId", r.SupplierID},
		{"productId", r.ProductID},
		{"currency", r.Currency},
		{"idempotencyKey", r.IdempotencyKey},
	}
	for _, f := range requiredStrings {
		if f.val == "" || strings.ContainsRune(f.val, '*') {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("AccessRequest.%s invalid or empty", f.name))
		}
	}
	if r.Quantity <= 0 || r.Quantity > MaxSafeInt {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("AccessRequest.quantity %d out of range", r.Quantity))
	}
	if r.AmountMinor < 0 || r.AmountMinor > MaxSafeInt {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("AccessRequest.amountMinor %d out of range", r.AmountMinor))
	}
	switch r.Action {
	case "quote.read":
		if r.QuoteID != nil {
			return NewError(ErrCodeInvalidSchema, "quote.read request must set quoteId to null")
		}
		if r.AmountMinor != 0 {
			return NewError(ErrCodeInvalidSchema, "quote.read request must set amountMinor to 0")
		}
	case "order.create":
		if r.QuoteID == nil || *r.QuoteID == "" {
			return NewError(ErrCodeInvalidSchema, "order.create request requires non-empty quoteId")
		}
		if r.AmountMinor <= 0 {
			return NewError(ErrCodeInvalidSchema, "order.create request requires positive amountMinor")
		}
	}
	return nil
}

// Hash computes requestHash = H(J(AccessRequest)).
func (r *AccessRequest) Hash(allowZeroDeploymentID bool) (string, error) {
	if err := r.Validate(allowZeroDeploymentID); err != nil {
		return "", err
	}
	canon, err := MarshalJCS(r)
	if err != nil {
		return "", err
	}
	return DigestBytes(canon), nil
}

// IsHexDigest reports whether s is 64 lowercase hex digits (optionally rejecting all zeros).
func IsHexDigest(s string, allowZero bool) bool {
	if len(s) != 64 {
		return false
	}
	nonZero := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '1' && c <= '9', c >= 'a' && c <= 'f':
			nonZero = true
		case c == '0':
		default:
			return false
		}
	}
	return allowZero || nonZero
}

// DeploymentBinding defines the 6 canonical fields whose JCS SHA-256 produces deploymentId.
type DeploymentBinding struct {
	ChannelID     string `json:"channelId"`
	GenesisHash   string `json:"genesisHash"`
	InstanceID    string `json:"instanceId"`
	Purpose       string `json:"purpose"`
	RegistryName  string `json:"registryName"`
	SchemaVersion string `json:"schemaVersion"`
}

// ComputeID computes deploymentId = SHA256(JCS(DeploymentBinding)).
func (b DeploymentBinding) ComputeID() (string, error) {
	if b.Purpose != DeploymentPurpose {
		return "", NewError(ErrCodeInvalidSchema, fmt.Sprintf("deployment purpose must be %q", DeploymentPurpose))
	}
	if b.SchemaVersion != SchemaVersion {
		return "", NewError(ErrCodeInvalidSchema, fmt.Sprintf("deployment schemaVersion must be %q", SchemaVersion))
	}
	if b.ChannelID == "" || b.RegistryName == "" || !IsHexDigest(b.GenesisHash, false) || !IsHexDigest(b.InstanceID, false) {
		return "", NewError(ErrCodeInvalidSchema, "invalid deployment binding fields")
	}
	canon, err := MarshalJCS(b)
	if err != nil {
		return "", err
	}
	return DigestBytes(canon), nil
}

// ManagementIdentity binds an X.509 client identity to an MSP and SHA-256 DER fingerprint.
type ManagementIdentity struct {
	CertificateSha256 string `json:"certificateSha256"`
	MSPID             string `json:"mspId"`
}

// RegistrationChallenge models the canonical dual-proof challenge object in Section 4.
type RegistrationChallenge struct {
	AccountCommitment  string             `json:"accountCommitment"`
	AppKeyID           string             `json:"appKeyId"`
	AppKeyVersion      int64              `json:"appKeyVersion"`
	AppPublicKey       string             `json:"appPublicKey"`
	ChallengeID        string             `json:"challengeId"`
	DeploymentID       string             `json:"deploymentId"`
	DIDDocumentDigest  string             `json:"didDocumentDigest"`
	DomainID           string             `json:"domainId"`
	ExpiresAt          int64              `json:"expiresAt"`
	IssuedAt           int64              `json:"issuedAt"`
	ManagementIdentity ManagementIdentity `json:"managementIdentity"`
	Nonce              string             `json:"nonce"`
	Purpose            string             `json:"purpose"`
	SubjectID          string             `json:"subjectId"`
}

// ManagementDualProofBundle captures the management and DID application proofs for verification.
type ManagementDualProofBundle struct {
	AppJWSProtected          string                `json:"appJwsProtected"`
	AppJWSSignature          string                `json:"appJwsSignature"`
	Challenge                RegistrationChallenge `json:"challenge"`
	ChallengeSha256          string                `json:"challengeSha256"`
	Deployment               DeploymentBinding     `json:"deployment"`
	DeploymentID             string                `json:"deploymentId"`
	ManagementCertificateDER string                `json:"managementCertificateDer"`
	ManagementSignatureDER   string                `json:"managementSignatureDer"`
}

type jwsProtectedHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Verify checks deploymentId derivation, challenge SHA-256, non-padded challenge nonce,
// management X.509 ASN.1 DER ECDSA signature, and ES256 application key compact JWS proof.
func (b *ManagementDualProofBundle) Verify() error {
	if b == nil {
		return NewError(ErrCodeInvalidSchema, "nil ManagementDualProofBundle")
	}
	derivedDepID, err := b.Deployment.ComputeID()
	if err != nil {
		return err
	}
	if b.DeploymentID != derivedDepID || b.Challenge.DeploymentID != derivedDepID {
		return NewError(ErrCodeBindingMismatch, fmt.Sprintf("deploymentId mismatch: computed %s", derivedDepID))
	}
	if b.Challenge.Purpose != RegistrationChallengePurpose {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("unexpected challenge purpose %q", b.Challenge.Purpose))
	}
	if _, err := ValidateNonce(b.Challenge.Nonce); err != nil {
		return err
	}
	if b.Challenge.AppKeyVersion <= 0 || !strings.HasPrefix(b.Challenge.AppKeyID, b.Challenge.SubjectID+"#") {
		return NewError(ErrCodeInvalidSchema, "invalid appKeyId or appKeyVersion in challenge")
	}
	if !IsHexDigest(b.Challenge.AccountCommitment, false) || !IsHexDigest(b.Challenge.DIDDocumentDigest, false) {
		return NewError(ErrCodeInvalidSchema, "invalid hex digest in challenge")
	}
	if !IsHexDigest(b.Challenge.ManagementIdentity.CertificateSha256, false) || b.Challenge.ManagementIdentity.MSPID == "" {
		return NewError(ErrCodeInvalidSchema, "invalid managementIdentity in challenge")
	}
	appPub, _, err := ParseAppPublicKey(b.Challenge.AppPublicKey)
	if err != nil {
		return err
	}

	challengeJCS, err := MarshalJCS(b.Challenge)
	if err != nil {
		return err
	}
	challengeSum := sha256.Sum256(challengeJCS)
	challengeHex := hex.EncodeToString(challengeSum[:])
	if b.ChallengeSha256 != challengeHex {
		return NewError(ErrCodeBindingMismatch, fmt.Sprintf("challengeSha256 mismatch: computed %s, got %s", challengeHex, b.ChallengeSha256))
	}

	// 1. Verify Fabric management X.509 certificate fingerprint and ASN.1 DER signature over challengeSha256.
	certDER, err := base64.RawURLEncoding.DecodeString(b.ManagementCertificateDER)
	if err != nil {
		return WrapError(ErrCodeInvalidSchema, "decode managementCertificateDer", err)
	}
	if DigestBytes(certDER) != b.Challenge.ManagementIdentity.CertificateSha256 {
		return NewError(ErrCodeBindingMismatch, "management certificate SHA-256 fingerprint mismatch")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return WrapError(ErrCodeInvalidSchema, "parse management X.509 certificate", err)
	}
	mgmtPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || mgmtPub.Curve != elliptic.P256() {
		return NewError(ErrCodeInvalidSchema, "management certificate must carry P-256 ECDSA public key")
	}
	mgmtSigDER, err := base64.RawURLEncoding.DecodeString(b.ManagementSignatureDER)
	if err != nil {
		return WrapError(ErrCodeInvalidSchema, "decode managementSignatureDer", err)
	}
	if !ecdsa.VerifyASN1(mgmtPub, challengeSum[:], mgmtSigDER) {
		return NewError(ErrCodeSignatureInvalid, "management ASN.1 DER signature verification failed")
	}

	// 2. Verify ES256 application JWS proof over JCS(challenge).
	if err := VerifyDetachedJWSES256(b.AppJWSProtected, challengeJCS, b.AppJWSSignature, appPub, ManagementProofTyp, b.Challenge.AppKeyID); err != nil {
		return err
	}
	return nil
}

// VerifyDetachedJWSES256 verifies a protected header, payload bytes, and raw 64-byte r||s signature
// using ECDSA P-256 SHA-256.
func VerifyDetachedJWSES256(protectedB64 string, payload []byte, sigB64 string, pub *ecdsa.PublicKey, wantTyp, wantKid string) error {
	hdrBytes, err := decodeStrictBase64URLAny(protectedB64)
	if err != nil {
		return WrapError(ErrCodeInvalidSchema, "decode JWS protected header", err)
	}
	var hdr jwsProtectedHeader
	if err := DecodeStrictJSON(hdrBytes, &hdr); err != nil {
		return WrapError(ErrCodeInvalidSchema, "parse JWS protected header", err)
	}
	if hdr.Alg != "ES256" {
		return NewError(ErrCodeSignatureInvalid, fmt.Sprintf("unsupported JWS alg %q", hdr.Alg))
	}
	if wantTyp != "" && hdr.Typ != wantTyp {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("unexpected JWS typ %q, want %q", hdr.Typ, wantTyp))
	}
	if wantKid != "" && hdr.Kid != wantKid {
		return NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("JWS kid %q mismatches expected %q", hdr.Kid, wantKid))
	}
	sigRaw, err := DecodeStrictBase64URLFixed(sigB64, 64)
	if err != nil {
		return WrapError(ErrCodeSignatureInvalid, "invalid ES256 signature encoding", err)
	}
	signingInput := protectedB64 + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signingInput))
	r := new(big.Int).SetBytes(sigRaw[:32])
	s := new(big.Int).SetBytes(sigRaw[32:64])
	if !ecdsa.Verify(pub, sum[:], r, s) {
		return NewError(ErrCodeSignatureInvalid, "ES256 signature verification failed")
	}
	return nil
}

func decodeStrictBase64URLAny(s string) ([]byte, error) {
	if s == "" || strings.ContainsAny(s, "=+/\r\n\t ") {
		return nil, NewError(ErrCodeInvalidSchema, "base64url string contains padding or invalid chars")
	}
	for i := 0; i < len(s); i++ {
		if !isBase64URLChar(s[i]) {
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid base64url char %q", s[i]))
		}
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, NewError(ErrCodeInvalidSchema, "non-canonical base64url encoding")
	}
	return b, nil
}
