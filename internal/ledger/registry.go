package ledger

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	StatusPending uint8 = 1
	StatusActive  uint8 = 2
	StatusRevoked uint8 = 4
)

type DomainInput struct {
	DomainId      string         `json:"domainId"`
	DomainDid     string         `json:"domainDid"`
	Administrator common.Address `json:"administrator"`
	Registrar     common.Address `json:"registrar"`
}

type DomainRecord struct {
	DomainId               string         `json:"domainId"`
	DomainDid              string         `json:"domainDid"`
	Administrator          common.Address `json:"administrator"`
	Registrar              common.Address `json:"registrar"`
	IdentityIssuers        []string       `json:"identityIssuers"`
	CurrentCertificationId common.Hash    `json:"currentCertificationId"`
	Status                 uint8          `json:"status"`
	Revision               uint64         `json:"revision"`
}

type IdentityInput struct {
	SubjectId          string         `json:"subjectId"`
	DomainId           string         `json:"domainId"`
	Kind               uint8          `json:"kind"`
	ManagementIdentity common.Address `json:"managementIdentity"`
	DidDocumentDigest  common.Hash    `json:"didDocumentDigest"`
	AppKeyId           string         `json:"appKeyId"`
	AppKeyVersion      uint64         `json:"appKeyVersion"`
	AppPublicKey       []byte         `json:"appPublicKey"`
	AccountCommitment  common.Hash    `json:"accountCommitment"`
}

func (i IdentityInput) MarshalJSON() ([]byte, error) {
	type alias IdentityInput
	return json.Marshal(struct {
		alias
		AppPublicKey hexutil.Bytes `json:"appPublicKey"`
	}{alias(i), hexutil.Bytes(i.AppPublicKey)})
}
func (i *IdentityInput) UnmarshalJSON(b []byte) error {
	type alias IdentityInput
	var v struct {
		alias
		AppPublicKey hexutil.Bytes `json:"appPublicKey"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*i = IdentityInput(v.alias)
	i.AppPublicKey = []byte(v.AppPublicKey)
	return nil
}

type IdentityRecord struct {
	Identity  IdentityInput  `json:"identity"`
	Registrar common.Address `json:"registrar"`
	Status    uint8          `json:"status"`
	Revision  uint64         `json:"revision"`
}

type IssuerScope struct {
	Id              string   `json:"id"`
	AppKeyVersion   uint64   `json:"appKeyVersion"`
	CredentialTypes []string `json:"credentialTypes"`
	ClaimNames      []string `json:"claimNames"`
}

type CertificationInput struct {
	CertificationId  string        `json:"certificationId"`
	DomainId         string        `json:"domainId"`
	IssuerKeyVersion uint64        `json:"issuerKeyVersion"`
	Digest           common.Hash   `json:"digest"`
	Nbf              uint64        `json:"nbf"`
	Exp              uint64        `json:"exp"`
	IdentityIssuers  []IssuerScope `json:"identityIssuers"`
}

type DomainCertificationRecord struct {
	Certification CertificationInput `json:"certification"`
	DomainDid     string             `json:"domainDid"`
	Administrator common.Address     `json:"administrator"`
	Registrar     common.Address     `json:"registrar"`
	Status        uint8              `json:"status"`
	Revision      uint64             `json:"revision"`
}

type Registry struct {
	Client     *ethclient.Client
	Deployment *Deployment
	ABI        abi.ABI
	Dir        string
}

type CredentialInput struct {
	CredentialId     string      `json:"credentialId"`
	Issuer           string      `json:"issuer"`
	Subject          string      `json:"subject"`
	IssuerKeyVersion uint64      `json:"issuerKeyVersion"`
	AppKeyVersion    uint64      `json:"appKeyVersion"`
	CredentialType   string      `json:"credentialType"`
	Digest           common.Hash `json:"digest"`
	Nbf              uint64      `json:"nbf"`
	Exp              uint64      `json:"exp"`
}

type CredentialRecord struct {
	Credential CredentialInput `json:"credential"`
	Status     uint8           `json:"status"`
	Revision   uint64          `json:"revision"`
}

type TaskInput struct {
	TaskId              common.Hash `json:"taskId"`
	DeploymentId        common.Hash `json:"deploymentId"`
	Creator             common.Hash `json:"creator"`
	PrincipalDomain     string      `json:"principalDomain"`
	AuthorizationMode   string      `json:"authorizationMode"`
	TaskSpecDigest      common.Hash `json:"taskSpecDigest"`
	ResourceId          common.Hash `json:"resourceId"`
	CreatorCredentialId common.Hash `json:"creatorCredentialId"`
	CreatorKeyVersion   uint64      `json:"creatorKeyVersion"`
	Nbf                 uint64      `json:"nbf"`
	Exp                 uint64      `json:"exp"`
}
type TaskRecord struct {
	Task     TaskInput `json:"task"`
	Status   uint8     `json:"status"`
	Revision uint64    `json:"revision"`
}

type GrantInput struct {
	GrantId             common.Hash `json:"grantId"`
	SchemaVersion       string      `json:"schemaVersion"`
	DeploymentId        common.Hash `json:"deploymentId"`
	ParentId            common.Hash `json:"parentId"`
	ParentDigest        common.Hash `json:"parentDigest"`
	RootId              common.Hash `json:"rootId"`
	TaskId              common.Hash `json:"taskId"`
	AuthorizationMode   string      `json:"authorizationMode"`
	PrincipalDomain     string      `json:"principalDomain"`
	Issuer              common.Hash `json:"issuer"`
	Grantee             common.Hash `json:"grantee"`
	IssuerKeyVersion    uint64      `json:"issuerKeyVersion"`
	GranteeKeyVersion   uint64      `json:"granteeKeyVersion"`
	IssuerCredentialId  common.Hash `json:"issuerCredentialId"`
	GranteeCredentialId common.Hash `json:"granteeCredentialId"`
	ResourceId          common.Hash `json:"resourceId"`
	Nbf                 uint64      `json:"nbf"`
	Exp                 uint64      `json:"exp"`
	RemainingDepth      uint8       `json:"remainingDepth"`
	Digest              common.Hash `json:"digest"`
}
type GrantRecord struct {
	Grant    GrantInput `json:"grant"`
	Status   uint8      `json:"status"`
	Revision uint64     `json:"revision"`
}

func OpenRegistry(ctx context.Context, dir, manifest, endpoint string) (*Registry, error) {
	if _, err := LoadInstance(dir); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(manifest)
	if err != nil {
		return nil, err
	}
	var d Deployment
	if err = json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	client, err := ethclient.DialContext(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if err = ValidateDeployment(ctx, client, &d); err != nil {
		client.Close()
		return nil, err
	}
	a, err := abi.JSON(strings.NewReader(string(d.ABI)))
	if err != nil {
		client.Close()
		return nil, err
	}
	return &Registry{Client: client, Deployment: &d, ABI: a, Dir: dir}, nil
}

func (r *Registry) Write(ctx context.Context, id, role, method string, args ...any) (*Operation, error) {
	data, err := r.ABI.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	key, err := crypto.LoadECDSA(filepath.Join(r.Dir, "keys", role, "management.key"))
	if err != nil {
		return nil, err
	}
	txCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	op, err := Submit(txCtx, r.Client, r.Dir, id, key, &r.Deployment.RegistryAddress, data, ChainID)
	if err != nil || op.Status != "FAILED" {
		return op, err
	}
	traceCtx, cancelTrace := context.WithTimeout(ctx, 10*time.Second)
	defer cancelTrace()
	return EnrichFailure(traceCtx, r.Client, r.Dir, op, r.ABI)
}

func (r *Registry) View(ctx context.Context, method string, args ...any) ([]any, error) {
	h, err := ReadHeader(ctx, r.Client, nil)
	if err != nil {
		return nil, err
	}
	return ReadView(ctx, r.Client, r.Deployment, new(big.Int).SetUint64(uint64(h.Number)), method, args...)
}

func viewRecord[T any](ctx context.Context, r *Registry, method string, id common.Hash) (*T, error) {
	v, err := r.View(ctx, method, id)
	if err != nil {
		return nil, err
	}
	if len(v) != 1 {
		return nil, fmt.Errorf("unexpected view output: %s", method)
	}
	return abi.ConvertType(v[0], new(T)).(*T), nil
}
