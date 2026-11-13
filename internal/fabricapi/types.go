package fabricapi

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

const (
	Channel   = "procurement"
	Registry  = "authregistry"
	Schema    = "grad-auth-v1"
	RP        = "RESOURCE_PREAUTHORIZED"
	Active    = "ACTIVE"
	Pending   = "PENDING"
	Suspended = "SUSPENDED"
	Revoked   = "REVOKED"

	BootstrapKey   = "bootstrap"
	PeerTimeWindow = 2 * time.Second
	ClockError     = time.Second
	ProbeInterval  = time.Second
	ProbeLifetime  = 5 * time.Second
)

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func IsDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && s == strings.ToLower(s) && s != strings.Repeat("0", 64)
}

func ValidAppKey(id, keyID, public string, version uint64) bool {
	point, err := hex.DecodeString(public)
	x, _ := elliptic.Unmarshal(elliptic.P256(), point)
	return strings.HasPrefix(id, "did:web:") && strings.HasPrefix(keyID, id+"#") &&
		len(keyID) > len(id)+1 && version > 0 && err == nil && public == strings.ToLower(public) &&
		x != nil
}

// Key separates object kinds and permits an arbitrary UTF-8 protocol identifier.
func Key(kind, id string) string { return kind + "/" + Digest([]byte(id)) }

type Management struct {
	MSPID       string `json:"mspId"`
	Fingerprint string `json:"certificateSha256"`
}

func (m Management) String() string { return m.MSPID + "/" + m.Fingerprint }
func (m Management) Valid() bool {
	return m.MSPID != "" && IsDigest(m.Fingerprint)
}

type DeploymentFields struct {
	ChannelID     string `json:"channelId"`
	GenesisHash   string `json:"genesisHash"`
	InstanceID    string `json:"instanceId"`
	RegistryName  string `json:"registryName"`
	SchemaVersion string `json:"schemaVersion"`
}

func (d DeploymentFields) Canonical() []byte {
	// The fixed, ASCII field names are already in JCS order.
	b, _ := json.Marshal(struct {
		ChannelID     string `json:"channelId"`
		GenesisHash   string `json:"genesisHash"`
		InstanceID    string `json:"instanceId"`
		Purpose       string `json:"purpose"`
		RegistryName  string `json:"registryName"`
		SchemaVersion string `json:"schemaVersion"`
	}{d.ChannelID, d.GenesisHash, d.InstanceID, "grad-fabric-deployment-v1", d.RegistryName, d.SchemaVersion})
	return b
}

func (d DeploymentFields) ID() string { return Digest(d.Canonical()) }

func (d DeploymentFields) Valid() bool {
	return d.ChannelID == Channel && d.RegistryName == Registry && d.SchemaVersion == Schema &&
		IsDigest(d.GenesisHash) && IsDigest(d.InstanceID)
}

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

func (i Interval) Valid() bool                 { return i.NBF > 0 && i.NBF < i.EXP && i.EXP <= 253402300799 }
func (i Interval) Within(parent Interval) bool { return i.NBF >= parent.NBF && i.EXP <= parent.EXP }
func (i Interval) Current(t time.Time, margin time.Duration) bool {
	return i.Valid() && !t.Add(-margin).Before(time.Unix(i.NBF, 0)) && t.Add(margin).Before(time.Unix(i.EXP, 0))
}

type Bound struct {
	DeploymentID string `json:"deploymentId"`
}

type Domain struct {
	Bound
	ID            string     `json:"domainId"`
	DID           string     `json:"domainDid"`
	Admin         Management `json:"administrator"`
	Registrar     Management `json:"registrar"`
	Issuers       []string   `json:"identityIssuers"`
	Certification string     `json:"currentCertificationId"`
	Version
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

type Scope struct {
	ID         string   `json:"id"`
	KeyVersion uint64   `json:"appKeyVersion"`
	Types      []string `json:"credentialTypes"`
	Claims     []string `json:"claimNames"`
}

type Certification struct {
	Bound
	ID             string  `json:"certificationId"`
	Domain         string  `json:"domainId"`
	RootKeyVersion uint64  `json:"issuerKeyVersion"`
	Digest         string  `json:"digest"`
	Scopes         []Scope `json:"identityIssuers"`
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

type Probe struct {
	TxID     string     `json:"txId"`
	Identity Management `json:"identity"`
}

func ProbeKey(m Management) string { return Key("probe", m.String()) }
