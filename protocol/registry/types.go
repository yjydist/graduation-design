package registry

import (
	"bytes"
	"encoding/json"
	"time"
)

const (
	Channel           = "procurement"
	Registry          = "authregistry"
	Schema            = "grad-auth-v1"
	DeploymentPurpose = "grad-fabric-deployment-v1"
	RP                = "RESOURCE_PREAUTHORIZED"
	BM                = "BUYER_MANDATE"

	ResourceQuotes    = "urn:grad:resource:C:quotes"
	ResourceOrders    = "urn:grad:resource:C:orders"
	ActionQuoteRead   = "quote.read"
	ActionOrderCreate = "order.create"

	Active    = "ACTIVE"
	Pending   = "PENDING"
	Suspended = "SUSPENDED"
	Revoked   = "REVOKED"
	Cancelled = "CANCELLED"

	BootstrapKey   = "bootstrap"
	PeerTimeWindow = 2 * time.Second
	ClockError     = time.Second
	ProbeInterval  = time.Second
	ProbeLifetime  = 5 * time.Second

	MaxIdentityIssuers     = 8
	MaxIssuerTypesOrClaims = 64
	MaxUnixTimestamp       = 253402300799
)

// Key separates ledger object kinds and permits an arbitrary UTF-8 protocol identifier.
func Key(kind, id string) string { return kind + "/" + Digest([]byte(id)) }

// Management binds an X.509 client identity to an MSP and SHA-256 DER certificate fingerprint.
type Management struct {
	MSPID             string `json:"mspId"`
	CertificateSHA256 string `json:"certificateSha256"`
}

// String returns the canonical "<mspId>/<certificateSha256>" identifier.
func (m Management) String() string { return m.MSPID + "/" + m.CertificateSHA256 }

// DeploymentFields defines the 6 canonical fields whose JCS SHA-256 produces deploymentId.
type DeploymentFields struct {
	ChannelID     string `json:"channelId"`
	GenesisHash   string `json:"genesisHash"`
	InstanceID    string `json:"instanceId"`
	Purpose       string `json:"purpose,omitempty"`
	RegistryName  string `json:"registryName"`
	SchemaVersion string `json:"schemaVersion"`
}

// Canonical returns the RFC 8785 JCS UTF-8 JSON bytes for DeploymentFields.
func (d DeploymentFields) Canonical() []byte {
	purpose := d.Purpose
	if purpose == "" {
		purpose = DeploymentPurpose
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// Field names are fixed ASCII keys already ordered per RFC 8785.
	_ = enc.Encode(struct {
		ChannelID     string `json:"channelId"`
		GenesisHash   string `json:"genesisHash"`
		InstanceID    string `json:"instanceId"`
		Purpose       string `json:"purpose"`
		RegistryName  string `json:"registryName"`
		SchemaVersion string `json:"schemaVersion"`
	}{
		ChannelID:     d.ChannelID,
		GenesisHash:   d.GenesisHash,
		InstanceID:    d.InstanceID,
		Purpose:       purpose,
		RegistryName:  d.RegistryName,
		SchemaVersion: d.SchemaVersion,
	})
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// DeploymentID returns SHA256(Canonical()) as a 64-character lowercase hex digest.
func (d DeploymentFields) DeploymentID() string { return Digest(d.Canonical()) }

type RootRecord struct {
	DID            string     `json:"rootDid"`
	Management     Management `json:"managementIdentity"`
	DocumentDigest string     `json:"didDocumentDigest"`
	KeyID          string     `json:"appKeyId"`
	KeyVersion     uint64     `json:"appKeyVersion"`
	PublicKey      string     `json:"appPublicKey"`
}

type TaskAuthority struct {
	Domain     string     `json:"domainId"`
	Subject    string     `json:"subjectId"`
	Management Management `json:"managementIdentity"`
}

type Bootstrap struct {
	DeploymentFields
	Root               RootRecord    `json:"root"`
	Initializer        Management    `json:"initializer"`
	TaskCreator        TaskAuthority `json:"taskCreator"`
	ResourceID         string        `json:"resourceId"`
	ResourceOwner      string        `json:"resourceOwner"`
	ResourceManagement Management    `json:"resourceManagement"`
}

type Version struct {
	Status   string `json:"status"`
	Revision uint64 `json:"revision"`
}

type Interval struct {
	NBF int64 `json:"nbf"`
	EXP int64 `json:"exp"`
}

type Bound struct {
	DeploymentID string `json:"deploymentId"`
}

type Domain struct {
	Bound
	ID                  string     `json:"domainId"`
	DID                 string     `json:"domainDid"`
	Admin               Management `json:"administrator"`
	Registrar           Management `json:"registrar"`
	Issuers             []string   `json:"identityIssuers"`
	PurchasingAuthority string     `json:"purchasingAuthority,omitempty"`
	Certification       string     `json:"currentCertificationId"`
	Version
}

type PurchasingAuthorityUpdate struct {
	Bound
	DomainID            string `json:"domainId"`
	PurchasingAuthority string `json:"purchasingAuthority"`
	ExpectedRevision    uint64 `json:"expectedRevision"`
}

type IdentityLink struct {
	Bound
	ID                      string `json:"id"`
	SourceDomain            string `json:"sourceDomain"`
	SourceSubject           string `json:"sourceSubject"`
	SourceKeyVersion        uint64 `json:"sourceKeyVersion"`
	SourceAccountCommitment string `json:"sourceAccountCommitment"`
	TargetDomain            string `json:"targetDomain"`
	TargetSubject           string `json:"targetSubject"`
	TargetKeyVersion        uint64 `json:"targetKeyVersion"`
	TargetAccountCommitment string `json:"targetAccountCommitment"`
	ProposalDigest          string `json:"proposalDigest"`
	ProposedAt              int64  `json:"proposedAt"`
	ExpiresAt               int64  `json:"expiresAt"`
	ApprovedBy              string `json:"approvedBy,omitempty"`
	ApprovedAt              int64  `json:"approvedAt,omitempty"`
	RevokedBy               string `json:"revokedBy,omitempty"`
	RevokedAt               int64  `json:"revokedAt,omitempty"`
	Reason                  string `json:"reason,omitempty"`
	EffectiveActive         bool   `json:"effectiveActive"`
	Version
}

type IdentityLinkApproval struct {
	Bound
	ID               string `json:"id"`
	ProposalDigest   string `json:"proposalDigest"`
	ExpectedRevision uint64 `json:"expectedRevision"`
	ApprovedAt       int64  `json:"approvedAt"`
}

type Identity struct {
	Bound
	ID                string     `json:"subjectId"`
	Domain            string     `json:"domainId"`
	Kind              string     `json:"kind"`
	Management        Management `json:"managementIdentity"`
	DocumentDigest    string     `json:"didDocumentDigest"`
	KeyID             string     `json:"appKeyId"`
	KeyVersion        uint64     `json:"appKeyVersion"`
	PublicKey         string     `json:"appPublicKey"`
	AccountCommitment string     `json:"accountCommitment"`
	Version
}

type DomainBootstrap struct {
	Domain   Domain     `json:"domain"`
	Identity Identity   `json:"identity"`
	Issuers  []Identity `json:"issuers"`
}

// IssuerScope defines an authorized identity issuer entry in both ledger certifications and DomainAuthorityCredential.
type IssuerScope struct {
	ID              string   `json:"id"`
	AppKeyVersion   uint64   `json:"appKeyVersion"`
	CredentialTypes []string `json:"credentialTypes"`
	ClaimNames      []string `json:"claimNames"`
}

type Certification struct {
	Bound
	ID             string        `json:"certificationId"`
	Domain         string        `json:"domainId"`
	RootKeyVersion uint64        `json:"issuerKeyVersion"`
	Digest         string        `json:"digest"`
	Scopes         []IssuerScope `json:"identityIssuers"`
	Interval
	Version
}

type Certify struct {
	Certification         Certification `json:"certification"`
	ExpectedRevision      uint64        `json:"expectedRevision"`
	ExpectedCertification string        `json:"expectedCertificationId"`
}

type Credential struct {
	Bound
	ID                string   `json:"credentialId"`
	Issuer            string   `json:"issuer"`
	Subject           string   `json:"subject"`
	IssuerKeyVersion  uint64   `json:"issuerKeyVersion"`
	SubjectKeyVersion uint64   `json:"appKeyVersion"`
	Type              string   `json:"credentialType"`
	ClaimNames        []string `json:"claimNames"`
	Digest            string   `json:"digest"`
	Interval
	Version
}

type Task struct {
	Bound
	ID                string `json:"taskId"`
	Creator           string `json:"creator"`
	CreatorCredential string `json:"creatorCredentialId"`
	CreatorKeyVersion uint64 `json:"creatorKeyVersion"`
	Domain            string `json:"principalDomain"`
	Mode              string `json:"authorizationMode"`
	Resource          string `json:"resourceId"`
	Digest            string `json:"taskSpecDigest"`
	Interval
	Version
}

type Grant struct {
	Bound
	ID                string `json:"grantId"`
	Schema            string `json:"schemaVersion"`
	Parent            string `json:"parentId"`
	ParentDigest      string `json:"parentDigest"`
	Root              string `json:"rootId"`
	Task              string `json:"taskId"`
	Mode              string `json:"authorizationMode"`
	Domain            string `json:"principalDomain"`
	Resource          string `json:"resourceId"`
	Issuer            string `json:"issuer"`
	Grantee           string `json:"grantee"`
	IssuerKeyVersion  uint64 `json:"issuerKeyVersion"`
	GranteeKeyVersion uint64 `json:"granteeKeyVersion"`
	IssuerCredential  string `json:"issuerCredentialId"`
	GranteeCredential string `json:"granteeCredentialId"`
	Depth             uint8  `json:"remainingDepth"`
	Digest            string `json:"digest"`
	Interval
	Version
}

type Mutation struct {
	Bound
	ID               string `json:"id"`
	ExpectedRevision uint64 `json:"expectedRevision"`
	ExpectedDigest   string `json:"expectedDigest"`
	Reason           string `json:"reason,omitempty"`
}

type Replacement struct {
	Old Mutation `json:"old"`
	New Grant    `json:"new"`
}

type DomainStatus struct {
	Bound
	ID               string `json:"domainId"`
	ExpectedRevision uint64 `json:"expectedRevision"`
	Status           string `json:"status"`
}

type AuthorityIdentityUpdateInput struct {
	Bound
	ID                 string     `json:"id"`
	ExpectedRevision   uint64     `json:"expectedRevision"`
	ExpectedKeyVersion uint64     `json:"expectedKeyVersion"`
	Management         Management `json:"managementIdentity"`
	DocumentDigest     string     `json:"didDocumentDigest"`
	KeyID              string     `json:"appKeyId"`
	PublicKey          string     `json:"appPublicKey"`
}

type IdentityStatusInput struct {
	Bound
	ID               string `json:"id"`
	ExpectedRevision uint64 `json:"expectedRevision"`
	Status           string `json:"status"`
}

type RotateIdentityInput struct {
	Bound
	ID                 string `json:"id"`
	ExpectedRevision   uint64 `json:"expectedRevision"`
	ExpectedKeyVersion uint64 `json:"expectedKeyVersion"`
	DocumentDigest     string `json:"didDocumentDigest"`
	KeyID              string `json:"appKeyId"`
	PublicKey          string `json:"appPublicKey"`
}

type RecoverIdentityInput struct {
	Bound
	ID                 string     `json:"id"`
	ExpectedRevision   uint64     `json:"expectedRevision"`
	ExpectedKeyVersion uint64     `json:"expectedKeyVersion"`
	AccountCommitment  string     `json:"accountCommitment"`
	OldManagement      Management `json:"oldManagementIdentity"`
	NewManagement      Management `json:"newManagementIdentity"`
	DocumentDigest     string     `json:"didDocumentDigest"`
	KeyID              string     `json:"appKeyId"`
	PublicKey          string     `json:"appPublicKey"`
}

type Probe struct {
	TxID     string     `json:"txId"`
	Identity Management `json:"identity"`
}

// ProbeKey returns the ledger state key for a probe record bound to management identity m.
func ProbeKey(m Management) string { return Key("probe", m.String()) }
