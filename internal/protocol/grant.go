package protocol

import (
	"crypto/ecdsa"
	"fmt"
	"slices"
	"strings"
)

const (
	// MaxGrantSetSize caps resources, actions, and suppliers sets per Grant.
	MaxGrantSetSize = 32
	// MaxGrantDepth caps remainingDepth per chaincode rule (Depth <= 32).
	MaxGrantDepth = 32
)

// GrantClaims models the signed payload of a grad-auth-v1 Grant JWS (typ="grad-delegation+jwt").
type GrantClaims struct {
	ID                  string   `json:"id"`
	SchemaVersion       string   `json:"schemaVersion"`
	DeploymentID        string   `json:"deploymentId"`
	ParentID            *string  `json:"parentId"`
	ParentDigest        *string  `json:"parentDigest"`
	RootID              string   `json:"rootId"`
	TaskID              string   `json:"taskId"`
	AuthorizationMode   string   `json:"authorizationMode"`
	PrincipalDomain     string   `json:"principalDomain"`
	ResourceID          string   `json:"resourceId"`
	Issuer              string   `json:"issuer"`
	Grantee             string   `json:"grantee"`
	IssuerKeyVersion    uint64   `json:"issuerKeyVersion"`
	GranteeKeyVersion   uint64   `json:"granteeKeyVersion"`
	IssuerCredentialID  string   `json:"issuerCredentialId"`
	GranteeCredentialID string   `json:"granteeCredentialId"`
	Resources           []string `json:"resources"`
	Actions             []string `json:"actions"`
	Suppliers           []string `json:"suppliers"`
	Aud                 string   `json:"aud"`
	Currency            string   `json:"currency"`
	MaxAmountMinor      int64    `json:"maxAmountMinor"`
	NBF                 int64    `json:"nbf"`
	EXP                 int64    `json:"exp"`
	RemainingDepth      int64    `json:"remainingDepth"`
}

// ParsedGrant pairs verified GrantClaims with the exact compact JWS string, its key ID, and SHA256(ASCII(compactJws)).
type ParsedGrant struct {
	Raw    string
	Digest string
	KeyID  string
	Claims GrantClaims
}

// SignGrant validates, canonicalizes, and ES256-signs a Grant JWS (typ="grad-delegation+jwt").
func SignGrant(priv *ecdsa.PrivateKey, issuerKeyID string, claims *GrantClaims) (string, string, error) {
	if claims == nil {
		return "", "", NewError(ErrCodeInvalidSchema, "nil GrantClaims")
	}
	if err := claims.ValidateStructure(); err != nil {
		return "", "", err
	}
	if !strings.HasPrefix(issuerKeyID, claims.Issuer+"#") {
		return "", "", NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("issuerKeyID %q must belong to issuer %q", issuerKeyID, claims.Issuer))
	}
	payload, err := MarshalJCS(claims)
	if err != nil {
		return "", "", err
	}
	return SignCompactJWS(priv, TypGrantDelegation, issuerKeyID, payload)
}

// ParseAndVerifyGrant parses a compact Grant JWS, verifies its ES256 signature under issuerPub/wantKid,
// and validates all structural constraints.
func ParseAndVerifyGrant(compact string, issuerPub *ecdsa.PublicKey, wantIssuerKeyID string) (*ParsedGrant, error) {
	parsed, err := ParseCompactJWS(compact, TypGrantDelegation)
	if err != nil {
		return nil, err
	}
	if err := parsed.Verify(issuerPub, wantIssuerKeyID); err != nil {
		return nil, err
	}
	var claims GrantClaims
	if err := DecodeStrictJSON(parsed.PayloadBytes, &claims); err != nil {
		return nil, err
	}
	if err := claims.ValidateStructure(); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(parsed.Header.Kid, claims.Issuer+"#") {
		return nil, NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("grant kid %q does not belong to issuer %q", parsed.Header.Kid, claims.Issuer))
	}
	return &ParsedGrant{
		Raw:    compact,
		Digest: parsed.Digest,
		KeyID:  parsed.Header.Kid,
		Claims: claims,
	}, nil
}

// ValidateStructure verifies single-grant structural invariants without inspecting parent chain or signatures.
func (c *GrantClaims) ValidateStructure() error {
	if c == nil {
		return NewError(ErrCodeInvalidSchema, "nil GrantClaims")
	}
	if c.ID == "" || c.RootID == "" || c.TaskID == "" || c.ResourceID == "" {
		return NewError(ErrCodeInvalidSchema, "grant id, rootId, taskId, and resourceId required")
	}
	if c.SchemaVersion != SchemaVersion {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("grant schemaVersion %q != %q", c.SchemaVersion, SchemaVersion))
	}
	if !IsHexDigest(c.DeploymentID, false) {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("grant deploymentId invalid %q", c.DeploymentID))
	}
	if c.AuthorizationMode != ModeResourcePreauthorized && c.AuthorizationMode != ModeBuyerMandate {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("grant authorizationMode %q invalid", c.AuthorizationMode))
	}
	if c.PrincipalDomain == "" || !strings.HasPrefix(c.Issuer, "did:") || !strings.HasPrefix(c.Grantee, "did:") {
		return NewError(ErrCodeInvalidSchema, "grant principalDomain, issuer, and grantee DIDs required")
	}
	if c.Issuer == c.Grantee {
		return NewError(ErrCodeGrantChainInvalid, "grant issuer and grantee must be distinct")
	}
	if c.IssuerKeyVersion == 0 || c.GranteeKeyVersion == 0 {
		return NewError(ErrCodeInvalidSchema, "grant key versions must be >= 1")
	}
	if c.IssuerCredentialID == "" || c.GranteeCredentialID == "" {
		return NewError(ErrCodeInvalidSchema, "grant issuerCredentialId and granteeCredentialId required")
	}
	if (c.ParentID == nil) != (c.ParentDigest == nil) {
		return NewError(ErrCodeGrantChainInvalid, "parentId and parentDigest must both be null (root) or both present (child)")
	}
	if c.ParentID == nil {
		if c.RootID != c.ID {
			return NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("root grant rootId %q must equal id %q", c.RootID, c.ID))
		}
	} else {
		if *c.ParentID == "" || !IsHexDigest(*c.ParentDigest, false) {
			return NewError(ErrCodeGrantChainInvalid, "child grant requires non-empty parentId and 64-hex parentDigest")
		}
		if c.RootID == c.ID {
			return NewError(ErrCodeGrantChainInvalid, "child grant rootId cannot equal own id")
		}
	}
	if err := ValidateStringSet("grant.resources", c.Resources, MaxGrantSetSize, true); err != nil {
		return err
	}
	if err := ValidateStringSet("grant.actions", c.Actions, MaxGrantSetSize, true); err != nil {
		return err
	}
	if err := ValidateStringSet("grant.suppliers", c.Suppliers, MaxGrantSetSize, true); err != nil {
		return err
	}
	if c.Aud == "" || c.Currency == "" {
		return NewError(ErrCodeInvalidSchema, "grant aud and currency required")
	}
	if c.MaxAmountMinor <= 0 || c.MaxAmountMinor > MaxSafeInt {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("grant maxAmountMinor %d out of range", c.MaxAmountMinor))
	}
	if c.NBF <= 0 || c.EXP <= c.NBF {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid grant validity window nbf=%d exp=%d", c.NBF, c.EXP))
	}
	if c.RemainingDepth < 0 || c.RemainingDepth > MaxGrantDepth {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("grant remainingDepth %d out of range [0,%d]", c.RemainingDepth, MaxGrantDepth))
	}
	return nil
}

// VerifyGrantChain enforces root->leaf linkage, attenuated budget/interval/depth,
// and subset containment across resources, actions, and suppliers.
func VerifyGrantChain(grants []*ParsedGrant) error {
	if len(grants) == 0 {
		return NewError(ErrCodeGrantChainInvalid, "empty grant chain")
	}
	root := grants[0]
	if root == nil {
		return NewError(ErrCodeGrantChainInvalid, "nil root grant")
	}
	if err := root.Claims.ValidateStructure(); err != nil {
		return err
	}
	if root.Claims.ParentID != nil || root.Claims.ParentDigest != nil {
		return NewError(ErrCodeGrantChainInvalid, "first grant in chain must be root grant (null parentId/parentDigest)")
	}
	for i := 1; i < len(grants); i++ {
		parent := grants[i-1]
		child := grants[i]
		if child == nil {
			return NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("nil grant at index %d", i))
		}
		if err := child.Claims.ValidateStructure(); err != nil {
			return err
		}
		if child.Claims.ParentID == nil || *child.Claims.ParentID != parent.Claims.ID {
			return NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] parentId mismatches parent %q", i, parent.Claims.ID))
		}
		if child.Claims.ParentDigest == nil || *child.Claims.ParentDigest != parent.Digest {
			return NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] parentDigest mismatches parent digest", i))
		}
		if child.Claims.RootID != root.Claims.ID {
			return NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] rootId mismatches %q", i, root.Claims.ID))
		}
		if child.Claims.DeploymentID != parent.Claims.DeploymentID ||
			child.Claims.TaskID != parent.Claims.TaskID ||
			child.Claims.AuthorizationMode != parent.Claims.AuthorizationMode ||
			child.Claims.PrincipalDomain != parent.Claims.PrincipalDomain ||
			child.Claims.ResourceID != parent.Claims.ResourceID ||
			child.Claims.Aud != parent.Claims.Aud ||
			child.Claims.Currency != parent.Claims.Currency {
			return NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] core task/scope bindings mismatch parent", i))
		}
		if child.Claims.Issuer != parent.Claims.Grantee ||
			child.Claims.IssuerKeyVersion != parent.Claims.GranteeKeyVersion ||
			child.Claims.IssuerCredentialID != parent.Claims.GranteeCredentialID {
			return NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] issuer binding mismatches parent grantee", i))
		}
		if child.Claims.MaxAmountMinor > parent.Claims.MaxAmountMinor {
			return NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] maxAmountMinor %d exceeds parent %d", i, child.Claims.MaxAmountMinor, parent.Claims.MaxAmountMinor))
		}
		if child.Claims.NBF < parent.Claims.NBF || child.Claims.EXP > parent.Claims.EXP {
			return NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] interval exceeds parent validity window", i))
		}
		if child.Claims.RemainingDepth >= parent.Claims.RemainingDepth {
			return NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] remainingDepth %d must be < parent %d", i, child.Claims.RemainingDepth, parent.Claims.RemainingDepth))
		}
		if !isSubset(child.Claims.Resources, parent.Claims.Resources) {
			return NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] resources expand parent scope", i))
		}
		if !isSubset(child.Claims.Actions, parent.Claims.Actions) {
			return NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] actions expand parent scope", i))
		}
		if !isSubset(child.Claims.Suppliers, parent.Claims.Suppliers) {
			return NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] suppliers expand parent scope", i))
		}
	}
	return nil
}

func isSubset(child, parent []string) bool {
	for _, item := range child {
		if !slices.Contains(parent, item) {
			return false
		}
	}
	return true
}
