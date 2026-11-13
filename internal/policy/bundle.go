package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

const (
	// DefaultPolicyID is the logical identifier for the procurement OPA bundle.
	DefaultPolicyID = "urn:grad:policy:procurement"
	// DefaultPolicyVersion is the pinned default version of the procurement OPA bundle.
	DefaultPolicyVersion = "1.0.0"

	fileInputSchema = "input.schema.json"
	fileRego        = "procurement.rego"
	fileResources   = "resources.json"
	fileRoles       = "roles.json"
	fileManifest    = "manifest.json"
)

// TrustRoot binds the policy bundle strictly to T's on-chain RootRecord for one deployment.
type TrustRoot struct {
	DeploymentID   string `json:"deploymentId"`
	RootDID        string `json:"rootDid"`
	KeyID          string `json:"appKeyId"`
	KeyVersion     uint64 `json:"appKeyVersion"`
	PublicKey      string `json:"appPublicKey"`
	DocumentDigest string `json:"didDocumentDigest"`
}

// FileDigest records the raw byte SHA-256 hex digest of a bundle content file.
type FileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Manifest describes a canonical verifiable OPA policy bundle without packaging timestamps.
type Manifest struct {
	DeploymentID  string       `json:"deploymentId"`
	Files         []FileDigest `json:"files"`
	PolicyID      string       `json:"policyId"`
	PolicyVersion string       `json:"policyVersion"`
	ServiceDID    string       `json:"serviceDid"`
	TrustRoots    []TrustRoot  `json:"trustRoots"`
}

// RolesConfig captures supplier acceptance modes, domains, and identity roles governed by the policy version.
type RolesConfig struct {
	AcceptedAuthorizationModes []string `json:"acceptedAuthorizationModes"`
	AcceptedAuthorityRoles     []string `json:"acceptedAuthorityRoles"`
	AcceptedBuyerDomains       []string `json:"acceptedBuyerDomains"`
	AcceptedServiceRoles       []string `json:"acceptedServiceRoles"`
}

// ResourcesConfig captures allowed product catalogs, action/quantity caps, and optional policyDeadline.
type ResourcesConfig struct {
	AllowedActions    []string `json:"allowedActions"`
	AllowedProductIDs []string `json:"allowedProductIds"`
	MaxQuantity       int64    `json:"maxQuantity"`
	PolicyDeadline    *int64   `json:"policyDeadline"`
}

// InputSchema captures the strict top-level schema metadata embedded in input.schema.json.
type InputSchema struct {
	SchemaVersion  string   `json:"schemaVersion"`
	RequiredFields []string `json:"requiredFields"`
}

// VerifiedBundle holds a cryptographically and structurally verified OPA bundle and prepared Rego query.
type VerifiedBundle struct {
	Manifest     Manifest
	PolicyDigest string
	Roles        RolesConfig
	Resources    ResourcesConfig
	RegoSource   string
	query        rego.PreparedEvalQuery
}

// DefaultProcurementRego defines the deterministic Rego v1 policy under package procurement.
const DefaultProcurementRego = `package procurement

import rego.v1

default allow := false

base_ok if {
	input.verified == true
	input.task.active == true
	input.path.active == true
	input.context.fresh == true
	input.constraints.withinBounds == true
	input.constraints.beforeDeadline == true
	input.supplierAcceptance == true
}

deny if {
	input.context.riskLevel == "BLOCKED"
}

permit if {
	input.request.action == "quote.read"
	input.context.riskLevel in {"NORMAL", "ELEVATED"}
}

permit if {
	input.request.action == "order.create"
	input.context.riskLevel == "NORMAL"
	input.request.amountMinor >= 0
	input.request.amountMinor <= input.path.maxAmountMinor
}

allow if {
	base_ok
	permit
	not deny
}
`

// BuildDefaultBundle builds a deterministic signed-ready OPA policy bundle map and computes policyDigest = SHA256(JCS(manifest)).
func BuildDefaultBundle(depID, serviceDID, policyVersion string, root api.RootRecord, policyDeadline *int64) (map[string][]byte, string, error) {
	if depID == "" || serviceDID == "" || policyVersion == "" {
		return nil, "", protocol.NewError(protocol.ErrCodeInvalidSchema, "deploymentId, serviceDid, and policyVersion required")
	}
	rolesBytes, err := protocol.MarshalJCS(RolesConfig{
		AcceptedAuthorizationModes: []string{api.RP, protocol.ModeBuyerMandate},
		AcceptedAuthorityRoles:     []string{"procurement-authority"},
		AcceptedBuyerDomains:       []string{"A"},
		AcceptedServiceRoles:       []string{"supplier-service", "SERVICE", "ResourceOwner"},
	})
	if err != nil {
		return nil, "", err
	}
	resourcesBytes, err := protocol.MarshalJCS(ResourcesConfig{
		AllowedActions:    []string{"quote.read", "order.create"},
		AllowedProductIDs: []string{"urn:grad:product:P1"},
		MaxQuantity:       10,
		PolicyDeadline:    policyDeadline,
	})
	if err != nil {
		return nil, "", err
	}
	schemaBytes, err := protocol.MarshalJCS(InputSchema{
		SchemaVersion: protocol.SchemaVersion,
		RequiredFields: []string{
			"verified", "supplierAcceptance", "task", "path", "request", "context", "constraints",
		},
	})
	if err != nil {
		return nil, "", err
	}

	files := map[string][]byte{
		fileInputSchema: append(schemaBytes, '\n'),
		fileRego:        []byte(DefaultProcurementRego),
		fileResources:   append(resourcesBytes, '\n'),
		fileRoles:       append(rolesBytes, '\n'),
	}

	paths := []string{fileInputSchema, fileRego, fileResources, fileRoles}
	sort.Strings(paths)
	digests := make([]FileDigest, len(paths))
	for i, p := range paths {
		digests[i] = FileDigest{Path: p, SHA256: sha256Hex(files[p])}
	}

	manifest := Manifest{
		DeploymentID:  depID,
		Files:         digests,
		PolicyID:      DefaultPolicyID,
		PolicyVersion: policyVersion,
		ServiceDID:    serviceDID,
		TrustRoots: []TrustRoot{{
			DeploymentID:   depID,
			RootDID:        root.DID,
			KeyID:          root.KeyID,
			KeyVersion:     root.KeyVersion,
			PublicKey:      root.PublicKey,
			DocumentDigest: root.DocumentDigest,
		}},
	}
	manifestBytes, err := protocol.MarshalJCS(manifest)
	if err != nil {
		return nil, "", err
	}
	policyDigest := sha256Hex(manifestBytes)
	files[fileManifest] = append(manifestBytes, '\n')
	return files, policyDigest, nil
}

// VerifyAndLoadBundle validates every file SHA-256 sorted by filename, checks JCS(manifest) against expectedDigest
// when provided, enforces fixed TrustRoots matching onChainRoot, scans the Rego AST for forbidden non-deterministic
// built-ins, and prepares the deterministic Rego v1 query.
func VerifyAndLoadBundle(
	files map[string][]byte,
	expectedDepID string,
	expectedServiceDID string,
	onChainRoot api.RootRecord,
	expectedDigest string,
) (*VerifiedBundle, error) {
	rawManifest, ok := files[fileManifest]
	if !ok || len(rawManifest) == 0 {
		return nil, protocol.NewError(protocol.ErrCodeInvalidSchema, "policy bundle missing manifest.json")
	}
	var manifest Manifest
	if err := protocol.DecodeStrictJSON(rawManifest, &manifest); err != nil {
		return nil, protocol.WrapError(protocol.ErrCodeInvalidSchema, "invalid policy manifest.json", err)
	}
	if expectedDepID != "" && manifest.DeploymentID != expectedDepID {
		return nil, protocol.NewError(protocol.ErrCodeBindingMismatch, fmt.Sprintf("policy deploymentId %q != %q", manifest.DeploymentID, expectedDepID))
	}
	if expectedServiceDID != "" && manifest.ServiceDID != expectedServiceDID {
		return nil, protocol.NewError(protocol.ErrCodeBindingMismatch, fmt.Sprintf("policy serviceDid %q != %q", manifest.ServiceDID, expectedServiceDID))
	}

	// Verify fixed T trust root cannot be replaced by any bundle update.
	if len(manifest.TrustRoots) != 1 {
		return nil, protocol.NewError(protocol.ErrCodeRootAuthorityInvalid, "policy manifest trustRoots must contain exactly one pinned T root")
	}
	tr := manifest.TrustRoots[0]
	if tr.DeploymentID != manifest.DeploymentID ||
		tr.RootDID != onChainRoot.DID ||
		tr.KeyID != onChainRoot.KeyID ||
		tr.KeyVersion != onChainRoot.KeyVersion ||
		tr.PublicKey != onChainRoot.PublicKey ||
		tr.DocumentDigest != onChainRoot.DocumentDigest {
		return nil, protocol.NewError(protocol.ErrCodeRootAuthorityInvalid, "policy bundle trustRoots mismatches pinned on-chain RootRecord")
	}

	// Verify sorted file SHA-256 digests and exact file set membership.
	requiredSet := []string{fileInputSchema, fileRego, fileResources, fileRoles}
	if len(manifest.Files) != len(requiredSet) {
		return nil, protocol.NewError(protocol.ErrCodeInvalidSchema, fmt.Sprintf("policy manifest files count %d != %d", len(manifest.Files), len(requiredSet)))
	}
	manifestFileMap := make(map[string]string, len(manifest.Files))
	for i, fd := range manifest.Files {
		if i > 0 && manifest.Files[i-1].Path >= fd.Path {
			return nil, protocol.NewError(protocol.ErrCodeInvalidSchema, "policy manifest.files must be sorted strictly ascending by path")
		}
		if !slices.Contains(requiredSet, fd.Path) {
			return nil, protocol.NewError(protocol.ErrCodeInvalidSchema, fmt.Sprintf("unexpected file %q in policy manifest", fd.Path))
		}
		content, exists := files[fd.Path]
		if !exists {
			return nil, protocol.NewError(protocol.ErrCodeInvalidSchema, fmt.Sprintf("policy bundle missing file %q", fd.Path))
		}
		actual := sha256Hex(content)
		if actual != fd.SHA256 {
			return nil, protocol.NewError(protocol.ErrCodeBindingMismatch, fmt.Sprintf("policy file %q sha256 mismatch: got %s, manifest %s", fd.Path, actual, fd.SHA256))
		}
		manifestFileMap[fd.Path] = actual
	}
	for path := range files {
		if path == fileManifest {
			continue
		}
		if _, ok := manifestFileMap[path]; !ok {
			return nil, protocol.NewError(protocol.ErrCodeInvalidSchema, fmt.Sprintf("unlisted file %q in policy bundle", path))
		}
	}

	manifestCanon, err := protocol.MarshalJCS(manifest)
	if err != nil {
		return nil, err
	}
	policyDigest := sha256Hex(manifestCanon)
	if expectedDigest != "" && policyDigest != expectedDigest {
		return nil, protocol.NewError(protocol.ErrCodeBindingMismatch, fmt.Sprintf("policyDigest mismatch: computed %s != expected %s", policyDigest, expectedDigest))
	}

	var roles RolesConfig
	if err := protocol.DecodeStrictJSON(files[fileRoles], &roles); err != nil {
		return nil, protocol.WrapError(protocol.ErrCodeInvalidSchema, "decode roles.json", err)
	}
	var resources ResourcesConfig
	if err := protocol.DecodeStrictJSON(files[fileResources], &resources); err != nil {
		return nil, protocol.WrapError(protocol.ErrCodeInvalidSchema, "decode resources.json", err)
	}
	var schema InputSchema
	if err := protocol.DecodeStrictJSON(files[fileInputSchema], &schema); err != nil {
		return nil, protocol.WrapError(protocol.ErrCodeInvalidSchema, "decode input.schema.json", err)
	}

	regoSrc := string(files[fileRego])
	if err := inspectRegoAST(regoSrc); err != nil {
		return nil, err
	}

	query, err := rego.New(
		rego.Query("data.procurement.allow"),
		rego.Module(fileRego, regoSrc),
		rego.SetRegoVersion(ast.RegoV1),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(ctxBackground())
	if err != nil {
		return nil, protocol.WrapError(protocol.ErrCodePolicyDenied, "compile Rego v1 policy failed", err)
	}

	return &VerifiedBundle{
		Manifest:     manifest,
		PolicyDigest: policyDigest,
		Roles:        roles,
		Resources:    resources,
		RegoSource:   regoSrc,
		query:        query,
	}, nil
}

var forbiddenBuiltins = map[string]struct{}{
	"time.now_ns":     {},
	"http.send":       {},
	"net.cidr_lookup": {},
	"opa.runtime":     {},
}

func inspectRegoAST(src string) error {
	mod, err := ast.ParseModuleWithOpts(fileRego, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return protocol.WrapError(protocol.ErrCodePolicyDenied, "parse Rego v1 policy", err)
	}
	if mod.Package == nil || mod.Package.Path.String() != "data.procurement" {
		return protocol.NewError(protocol.ErrCodeInvalidSchema, "policy module must belong to package procurement")
	}
	var forbiddenErr error
	ast.WalkRefs(mod, func(r ast.Ref) bool {
		name := r.String()
		if _, bad := forbiddenBuiltins[name]; bad {
			forbiddenErr = protocol.NewError(protocol.ErrCodeInvalidSchema, fmt.Sprintf("forbidden non-deterministic or network builtin %q in policy", name))
			return true
		}
		return false
	})
	return forbiddenErr
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Keep json referenced if needed by callers
var _ = json.Valid
