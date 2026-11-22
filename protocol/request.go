package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"grad/protocol/registry"
)

const (
	// RegistrationChallengePurpose is the fixed purpose for registration challenges.
	RegistrationChallengePurpose = "grad-identity-registration-v1"
	// RecoveryChallengePurpose is the fixed purpose for ordinary management account recovery challenges.
	RecoveryChallengePurpose = "grad-identity-recovery-v1"
)

// ManagementIdentity aliases registry.Management (MSPID + DER certificate SHA-256).
type ManagementIdentity = registry.Management

// DeploymentBinding aliases registry.DeploymentFields (6 canonical deployment fields).
type DeploymentBinding = registry.DeploymentFields

// ComputeDeploymentID validates b and computes deploymentId = SHA256(JCS(DeploymentBinding)).
func ComputeDeploymentID(b DeploymentBinding) (string, error) {
	if b.Purpose != "" && b.Purpose != DeploymentPurpose {
		return "", NewError(ErrCodeInvalidSchema, fmt.Sprintf("deployment purpose must be %q", DeploymentPurpose))
	}
	if b.SchemaVersion != SchemaVersion {
		return "", NewError(ErrCodeInvalidSchema, fmt.Sprintf("deployment schemaVersion must be %q", SchemaVersion))
	}
	if b.ChannelID == "" || b.RegistryName == "" || !IsHexDigest(b.GenesisHash, false) || !IsHexDigest(b.InstanceID, false) {
		return "", NewError(ErrCodeInvalidSchema, "invalid deployment binding fields")
	}
	return b.DeploymentID(), nil
}

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
	digest, err := DigestJCS(raw)
	if err != nil {
		return nil, "", err
	}
	return &spec, digest, nil
}

// Validate enforces grad-auth-v1 TaskSpec schema, positive quantity, canonical resource URIs, and sorted non-wildcard sets.
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
	if err := ValidateStringSet(s.Resources, MaxGrantSetSize); err != nil {
		return err
	}
	for _, res := range s.Resources {
		if !IsCanonicalResource(res) {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("TaskSpec.resources contains non-canonical resource URI %q", res))
		}
	}
	if err := ValidateStringSet(s.Actions, MaxGrantSetSize); err != nil {
		return err
	}
	return nil
}

// Digest computes H(J(TaskSpec)) = SHA-256(JCS(TaskSpec)) as 64-char lowercase hex.
func (s *TaskSpec) Digest() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	return DigestValueJCS(s)
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
	digest, err := DigestJCS(raw)
	if err != nil {
		return nil, "", err
	}
	return &req, digest, nil
}

// Validate enforces strict schema, canonical action-to-resource URI mapping,
// and action-specific quoteId/amountMinor invariants on AccessRequest.
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
	if err := ValidateCanonicalResource(r.Action, r.Resource); err != nil {
		return err
	}
	if r.Quantity <= 0 || r.Quantity > MaxSafeInt {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("AccessRequest.quantity %d out of range", r.Quantity))
	}
	if r.AmountMinor < 0 || r.AmountMinor > MaxSafeInt {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("AccessRequest.amountMinor %d out of range", r.AmountMinor))
	}
	switch r.Action {
	case ActionQuoteRead:
		if r.QuoteID != nil {
			return NewError(ErrCodeInvalidSchema, "quote.read request must set quoteId to null")
		}
		if r.AmountMinor != 0 {
			return NewError(ErrCodeInvalidSchema, "quote.read request must set amountMinor to 0")
		}
	case ActionOrderCreate:
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
	return DigestValueJCS(r)
}

// RegistrationChallenge models the canonical dual-proof challenge object for identity registration.
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

// SignManagementDualProofBundle constructs and signs both proofs for a registration challenge:
// the Fabric management X.509 ECDSA ASN.1 DER signature and the application ES256 JWS proof.
func SignManagementDualProofBundle(
	dep DeploymentBinding,
	chal RegistrationChallenge,
	mgmtCertDER []byte,
	mgmtPriv *ecdsa.PrivateKey,
	appPriv *ecdsa.PrivateKey,
) (*ManagementDualProofBundle, error) {
	if mgmtPriv == nil || mgmtPriv.Curve != elliptic.P256() {
		return nil, NewError(ErrCodeInvalidSchema, "management private key must be ECDSA P-256")
	}
	if appPriv == nil || appPriv.Curve != elliptic.P256() {
		return nil, NewError(ErrCodeInvalidSchema, "application private key must be ECDSA P-256")
	}
	if dep.Purpose == "" {
		dep.Purpose = DeploymentPurpose
	}
	depID, err := ComputeDeploymentID(dep)
	if err != nil {
		return nil, err
	}
	chal.DeploymentID = depID
	chal.Purpose = RegistrationChallengePurpose
	chal.ManagementIdentity.CertificateSHA256 = DigestBytes(mgmtCertDER)

	chalJCS, err := MarshalJCS(chal)
	if err != nil {
		return nil, err
	}
	chalSum := sha256.Sum256(chalJCS)
	chalHex := hex.EncodeToString(chalSum[:])

	mgmtSigDER, err := ecdsa.SignASN1(rand.Reader, mgmtPriv, chalSum[:])
	if err != nil {
		return nil, err
	}
	protectedB64, sigB64, err := SignDetachedJWS(appPriv, TypeManagementProofJWS, chal.AppKeyID, chalJCS)
	if err != nil {
		return nil, err
	}
	bundle := &ManagementDualProofBundle{
		AppJWSProtected:          protectedB64,
		AppJWSSignature:          sigB64,
		Challenge:                chal,
		ChallengeSha256:          chalHex,
		Deployment:               dep,
		DeploymentID:             depID,
		ManagementCertificateDER: base64.RawURLEncoding.EncodeToString(mgmtCertDER),
		ManagementSignatureDER:   base64.RawURLEncoding.EncodeToString(mgmtSigDER),
	}
	if err := bundle.Verify(); err != nil {
		return nil, err
	}
	return bundle, nil
}

// Verify checks deploymentId derivation, challenge SHA-256, non-padded challenge nonce,
// management X.509 ASN.1 DER ECDSA signature, and ES256 application key detached JWS proof.
func (b *ManagementDualProofBundle) Verify() error {
	if b == nil {
		return NewError(ErrCodeInvalidSchema, "nil ManagementDualProofBundle")
	}
	derivedDepID, err := ComputeDeploymentID(b.Deployment)
	if err != nil {
		return err
	}
	if b.DeploymentID != derivedDepID || b.Challenge.DeploymentID != derivedDepID {
		return NewError(ErrCodeBindingMismatch, fmt.Sprintf("deploymentId mismatch: computed %s", derivedDepID))
	}
	if b.Challenge.Purpose != RegistrationChallengePurpose {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("unexpected challenge purpose %q", b.Challenge.Purpose))
	}
	if err := ValidateNonce(b.Challenge.Nonce); err != nil {
		return err
	}
	if b.Challenge.AppKeyVersion <= 0 || !strings.HasPrefix(b.Challenge.AppKeyID, b.Challenge.SubjectID+"#") {
		return NewError(ErrCodeInvalidSchema, "invalid appKeyId or appKeyVersion in challenge")
	}
	if !IsHexDigest(b.Challenge.AccountCommitment, false) || !IsHexDigest(b.Challenge.DIDDocumentDigest, false) {
		return NewError(ErrCodeInvalidSchema, "invalid hex digest in challenge")
	}
	if !b.Challenge.ManagementIdentity.Valid() {
		return NewError(ErrCodeInvalidSchema, "invalid managementIdentity in challenge")
	}
	appPub, err := ParseAppPublicKey(b.Challenge.AppPublicKey)
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
	certDER, err := DecodeStrictBase64URL(b.ManagementCertificateDER)
	if err != nil {
		return WrapError(ErrCodeInvalidSchema, "decode managementCertificateDer", err)
	}
	if DigestBytes(certDER) != b.Challenge.ManagementIdentity.CertificateSHA256 {
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
	mgmtSigDER, err := DecodeStrictBase64URL(b.ManagementSignatureDER)
	if err != nil {
		return WrapError(ErrCodeInvalidSchema, "decode managementSignatureDer", err)
	}
	if !ecdsa.VerifyASN1(mgmtPub, challengeSum[:], mgmtSigDER) {
		return NewError(ErrCodeSignatureInvalid, "management ASN.1 DER signature verification failed")
	}

	// 2. Verify ES256 application JWS proof over JCS(challenge).
	return VerifyDetachedJWS(b.AppJWSProtected, challengeJCS, b.AppJWSSignature, appPub, TypeManagementProofJWS, b.Challenge.AppKeyID)
}

// RecoveryChallenge models the canonical dual-proof challenge object for ordinary management recovery.
type RecoveryChallenge struct {
	AccountCommitment     string             `json:"accountCommitment"`
	ChallengeID           string             `json:"challengeId"`
	DeploymentID          string             `json:"deploymentId"`
	DIDDocumentDigest     string             `json:"didDocumentDigest"`
	DomainID              string             `json:"domainId"`
	ExpectedKeyVersion    uint64             `json:"expectedKeyVersion"`
	ExpectedRevision      uint64             `json:"expectedRevision"`
	ExpiresAt             int64              `json:"expiresAt"`
	IssuedAt              int64              `json:"issuedAt"`
	NewAppKeyID           string             `json:"newAppKeyId"`
	NewAppKeyVersion      uint64             `json:"newAppKeyVersion"`
	NewAppPublicKey       string             `json:"newAppPublicKey"`
	NewManagementIdentity ManagementIdentity `json:"newManagementIdentity"`
	Nonce                 string             `json:"nonce"`
	OldManagementIdentity ManagementIdentity `json:"oldManagementIdentity"`
	Purpose               string             `json:"purpose"`
	SubjectID             string             `json:"subjectId"`
}

// RecoveryDualProofBundle captures the new management certificate signature and new app-key JWS proof.
type RecoveryDualProofBundle struct {
	Challenge                   RecoveryChallenge `json:"challenge"`
	ChallengeSha256             string            `json:"challengeSha256"`
	Deployment                  DeploymentBinding `json:"deployment"`
	DeploymentID                string            `json:"deploymentId"`
	NewAppJWSProtected          string            `json:"newAppJwsProtected"`
	NewAppJWSSignature          string            `json:"newAppJwsSignature"`
	NewManagementCertificateDER string            `json:"newManagementCertificateDer"`
	NewManagementSignatureDER   string            `json:"newManagementSignatureDer"`
}

// SignRecoveryDualProofBundle signs both new management certificate and new application key proofs over JCS(challenge).
func SignRecoveryDualProofBundle(
	dep DeploymentBinding,
	chal RecoveryChallenge,
	newMgmtCertDER []byte,
	newMgmtPriv *ecdsa.PrivateKey,
	newAppPriv *ecdsa.PrivateKey,
) (*RecoveryDualProofBundle, error) {
	if newMgmtPriv == nil || newMgmtPriv.Curve != elliptic.P256() {
		return nil, NewError(ErrCodeRecoveryProofInvalid, "new management private key must be ECDSA P-256")
	}
	if newAppPriv == nil || newAppPriv.Curve != elliptic.P256() {
		return nil, NewError(ErrCodeRecoveryProofInvalid, "new application private key must be ECDSA P-256")
	}
	if dep.Purpose == "" {
		dep.Purpose = DeploymentPurpose
	}
	depID, err := ComputeDeploymentID(dep)
	if err != nil {
		return nil, err
	}
	chal.DeploymentID = depID
	chal.Purpose = RecoveryChallengePurpose
	chal.NewManagementIdentity.CertificateSHA256 = DigestBytes(newMgmtCertDER)

	chalJCS, err := MarshalJCS(chal)
	if err != nil {
		return nil, err
	}
	chalSum := sha256.Sum256(chalJCS)
	chalHex := hex.EncodeToString(chalSum[:])

	mgmtSigDER, err := ecdsa.SignASN1(rand.Reader, newMgmtPriv, chalSum[:])
	if err != nil {
		return nil, err
	}
	protectedB64, sigB64, err := SignDetachedJWS(newAppPriv, TypeManagementProofJWS, chal.NewAppKeyID, chalJCS)
	if err != nil {
		return nil, err
	}
	bundle := &RecoveryDualProofBundle{
		Challenge:                   chal,
		ChallengeSha256:             chalHex,
		Deployment:                  dep,
		DeploymentID:                depID,
		NewAppJWSProtected:          protectedB64,
		NewAppJWSSignature:          sigB64,
		NewManagementCertificateDER: base64.RawURLEncoding.EncodeToString(newMgmtCertDER),
		NewManagementSignatureDER:   base64.RawURLEncoding.EncodeToString(mgmtSigDER),
	}
	if err := bundle.Verify(); err != nil {
		return nil, err
	}
	return bundle, nil
}

// Verify checks deployment binding, challenge digest, canonical nonce, 300s TTL cap,
// and dual proofs for both the new management X.509 certificate and new application key.
func (b *RecoveryDualProofBundle) Verify() error {
	if b == nil {
		return NewError(ErrCodeInvalidSchema, "nil RecoveryDualProofBundle")
	}
	derivedDepID, err := ComputeDeploymentID(b.Deployment)
	if err != nil {
		return err
	}
	if b.DeploymentID != derivedDepID || b.Challenge.DeploymentID != derivedDepID {
		return NewError(ErrCodeBindingMismatch, fmt.Sprintf("deploymentId mismatch: computed %s", derivedDepID))
	}
	if b.Challenge.Purpose != RecoveryChallengePurpose {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("unexpected challenge purpose %q", b.Challenge.Purpose))
	}
	if err := ValidateNonce(b.Challenge.Nonce); err != nil {
		return err
	}
	if b.Challenge.ExpiresAt <= b.Challenge.IssuedAt || b.Challenge.ExpiresAt-b.Challenge.IssuedAt > 300 {
		return NewError(ErrCodeRecoveryProofInvalid, "recovery challenge TTL must be in (0, 300] seconds")
	}
	if b.Challenge.ExpectedRevision == 0 || b.Challenge.ExpectedKeyVersion == 0 ||
		b.Challenge.NewAppKeyVersion != b.Challenge.ExpectedKeyVersion+1 ||
		!strings.HasPrefix(b.Challenge.NewAppKeyID, b.Challenge.SubjectID+"#") {
		return NewError(ErrCodeRecoveryProofInvalid, "invalid expectedRevision, expectedKeyVersion, or newAppKeyId")
	}
	if !IsHexDigest(b.Challenge.AccountCommitment, false) || !IsHexDigest(b.Challenge.DIDDocumentDigest, false) {
		return NewError(ErrCodeRecoveryProofInvalid, "invalid hex digest in recovery challenge")
	}
	if !b.Challenge.OldManagementIdentity.Valid() || !b.Challenge.NewManagementIdentity.Valid() ||
		b.Challenge.NewManagementIdentity == b.Challenge.OldManagementIdentity {
		return NewError(ErrCodeRecoveryProofInvalid, "invalid old/new managementIdentity in recovery challenge")
	}
	appPub, err := ParseAppPublicKey(b.Challenge.NewAppPublicKey)
	if err != nil {
		return WrapError(ErrCodeRecoveryProofInvalid, "invalid newAppPublicKey", err)
	}

	chalJCS, err := MarshalJCS(b.Challenge)
	if err != nil {
		return err
	}
	chalSum := sha256.Sum256(chalJCS)
	chalHex := hex.EncodeToString(chalSum[:])
	if b.ChallengeSha256 != chalHex {
		return NewError(ErrCodeChallengeMismatch, fmt.Sprintf("recovery challengeSha256 mismatch: computed %s, got %s", chalHex, b.ChallengeSha256))
	}

	certDER, err := DecodeStrictBase64URL(b.NewManagementCertificateDER)
	if err != nil {
		return WrapError(ErrCodeRecoveryProofInvalid, "decode newManagementCertificateDer", err)
	}
	if DigestBytes(certDER) != b.Challenge.NewManagementIdentity.CertificateSHA256 {
		return NewError(ErrCodeBindingMismatch, "new management certificate SHA-256 fingerprint mismatch")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return WrapError(ErrCodeRecoveryProofInvalid, "parse new management certificate", err)
	}
	mgmtPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || mgmtPub.Curve != elliptic.P256() {
		return NewError(ErrCodeRecoveryProofInvalid, "new management certificate must carry P-256 ECDSA key")
	}
	mgmtSigDER, err := DecodeStrictBase64URL(b.NewManagementSignatureDER)
	if err != nil {
		return WrapError(ErrCodeRecoveryProofInvalid, "decode newManagementSignatureDer", err)
	}
	if !ecdsa.VerifyASN1(mgmtPub, chalSum[:], mgmtSigDER) {
		return NewError(ErrCodeRecoveryProofInvalid, "new management ASN.1 DER signature verification failed")
	}

	if err := VerifyDetachedJWS(b.NewAppJWSProtected, chalJCS, b.NewAppJWSSignature, appPub, TypeManagementProofJWS, b.Challenge.NewAppKeyID); err != nil {
		return WrapError(ErrCodeRecoveryProofInvalid, "verify new application key JWS proof", err)
	}
	return nil
}

// IdentityLinkProposal models the canonical cross-domain identity link proposal signed by both endpoints.
type IdentityLinkProposal struct {
	DeploymentID            string `json:"deploymentId"`
	ExpiresAt               int64  `json:"expiresAt"`
	ID                      string `json:"id"`
	ProposedAt              int64  `json:"proposedAt"`
	SourceAccountCommitment string `json:"sourceAccountCommitment"`
	SourceDomain            string `json:"sourceDomain"`
	SourceKeyID             string `json:"sourceKeyId"`
	SourceKeyVersion        uint64 `json:"sourceKeyVersion"`
	SourceSubject           string `json:"sourceSubject"`
	TargetAccountCommitment string `json:"targetAccountCommitment"`
	TargetDomain            string `json:"targetDomain"`
	TargetKeyID             string `json:"targetKeyId"`
	TargetKeyVersion        uint64 `json:"targetKeyVersion"`
	TargetSubject           string `json:"targetSubject"`
}

// Digest returns SHA-256(JCS(p)) as 64-char lowercase hex and its canonical bytes.
func (p IdentityLinkProposal) Digest() ([]byte, string, error) {
	if p.ID == "" || p.SourceDomain == "" || p.TargetDomain == "" || p.SourceDomain == p.TargetDomain ||
		p.SourceSubject == "" || p.TargetSubject == "" || p.SourceSubject == p.TargetSubject ||
		!IsHexDigest(p.DeploymentID, false) || !IsHexDigest(p.SourceAccountCommitment, false) ||
		!IsHexDigest(p.TargetAccountCommitment, false) || p.SourceKeyVersion == 0 || p.TargetKeyVersion == 0 ||
		p.ProposedAt <= 0 || p.ExpiresAt <= p.ProposedAt {
		return nil, "", NewError(ErrCodeLinkProofInvalid, "invalid IdentityLinkProposal fields")
	}
	raw, err := MarshalJCS(p)
	if err != nil {
		return nil, "", err
	}
	return raw, DigestBytes(raw), nil
}

// IdentityLinkProofBundle carries both endpoints' ES256 PoP signatures over an IdentityLinkProposal.
type IdentityLinkProofBundle struct {
	Proposal       IdentityLinkProposal `json:"proposal"`
	ProposalDigest string               `json:"proposalDigest"`
	SourceProofJWS string               `json:"sourceProofJws"`
	TargetProofJWS string               `json:"targetProofJws"`
}

// SignIdentityLinkProofBundle signs source and target application-key PoPs for a dual-domain identity link.
func SignIdentityLinkProofBundle(
	proposal IdentityLinkProposal,
	srcPriv *ecdsa.PrivateKey,
	dstPriv *ecdsa.PrivateKey,
) (*IdentityLinkProofBundle, error) {
	if srcPriv == nil || dstPriv == nil {
		return nil, NewError(ErrCodeLinkProofInvalid, "both source and target private keys are required")
	}
	raw, dig, err := proposal.Digest()
	if err != nil {
		return nil, err
	}
	srcJWS, err := SignCompactJWS(srcPriv, TypeLinkProofJWS, proposal.SourceKeyID, raw)
	if err != nil {
		return nil, err
	}
	dstJWS, err := SignCompactJWS(dstPriv, TypeLinkProofJWS, proposal.TargetKeyID, raw)
	if err != nil {
		return nil, err
	}
	return &IdentityLinkProofBundle{
		Proposal:       proposal,
		ProposalDigest: dig,
		SourceProofJWS: srcJWS,
		TargetProofJWS: dstJWS,
	}, nil
}

// Verify checks both endpoints' PoP signatures and proposal digest consistency.
func (b *IdentityLinkProofBundle) Verify(srcPub, dstPub *ecdsa.PublicKey) error {
	if b == nil {
		return NewError(ErrCodeLinkProofInvalid, "nil IdentityLinkProofBundle")
	}
	raw, dig, err := b.Proposal.Digest()
	if err != nil {
		return err
	}
	if b.ProposalDigest != dig {
		return NewError(ErrCodeLinkProposalMismatch, "proposalDigest mismatch")
	}
	for _, check := range []struct {
		jws string
		pub *ecdsa.PublicKey
		kid string
	}{
		{b.SourceProofJWS, srcPub, b.Proposal.SourceKeyID},
		{b.TargetProofJWS, dstPub, b.Proposal.TargetKeyID},
	} {
		parsed, err := ParseCompactJWS(check.jws, TypeLinkProofJWS)
		if err != nil {
			return WrapError(ErrCodeLinkProofInvalid, "parse link proof JWS", err)
		}
		if err := verifyJWSWithKid(parsed, check.pub, check.kid); err != nil {
			return WrapError(ErrCodeLinkProofInvalid, "verify link proof signature", err)
		}
		if !bytes.Equal(parsed.PayloadBytes, raw) {
			return NewError(ErrCodeLinkProofInvalid, "link proof payload mismatches canonical proposal")
		}
	}
	return nil
}
