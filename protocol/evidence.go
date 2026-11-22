package protocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"grad/protocol/registry"
)

// SignatureCacheKey uniquely indexes a statically verified JWS signature under B1 mode:
// (SHA256(rawMaterialBytes), alg, appKeyId, appKeyVersion).
type SignatureCacheKey struct {
	MaterialDigest string `json:"materialDigest"`
	Alg            string `json:"alg"`
	KeyID          string `json:"keyId"`
	KeyVersion     uint64 `json:"keyVersion"`
}

// SignatureCache provides concurrency-safe caching of static ECDSA JWS verifications.
// Dynamic state (Identity.Status, Identity.KeyVersion, Domain.Status, Domain.Certification,
// ClaimNames scope, Grant.Status, Task.Status, KB-JWT bindings) is NEVER cached or skipped.
type SignatureCache struct {
	mu      sync.RWMutex
	entries map[SignatureCacheKey]string
	hits    atomic.Int64
	misses  atomic.Int64
}

// NewSignatureCache constructs a concurrency-safe B1 static JWS signature cache.
func NewSignatureCache() *SignatureCache {
	return &SignatureCache{entries: make(map[SignatureCacheKey]string)}
}

// Hits returns the number of cache lookups that avoided static ECDSA signature math.
func (c *SignatureCache) Hits() int64 {
	if c == nil {
		return 0
	}
	return c.hits.Load()
}

// Misses returns the number of uncached static JWS signature verifications performed.
func (c *SignatureCache) Misses() int64 {
	if c == nil {
		return 0
	}
	return c.misses.Load()
}

// ResetStats clears hit and miss counters while retaining cached signature entries.
func (c *SignatureCache) ResetStats() {
	if c == nil {
		return
	}
	c.hits.Store(0)
	c.misses.Store(0)
}

func (c *SignatureCache) lookup(key SignatureCacheKey) (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.RLock()
	pubHex, ok := c.entries[key]
	c.mu.RUnlock()
	if ok {
		c.hits.Add(1)
	}
	return pubHex, ok
}

func (c *SignatureCache) verifyJWS(key SignatureCacheKey, parsed *ParsedJWS, pub *ecdsa.PublicKey, wantKid, pubHex string, recordMiss bool) error {
	if c != nil && recordMiss {
		c.misses.Add(1)
	}
	if err := verifyJWSWithKid(parsed, pub, wantKid); err != nil {
		return err
	}
	if c != nil && pubHex != "" {
		c.mu.Lock()
		c.entries[key] = pubHex
		c.mu.Unlock()
	}
	return nil
}

// AncestorCredential pairs an ancestor credential identifier with its SD-JWT ending in '~' (no KB-JWT).
type AncestorCredential struct {
	CredentialID string `json:"credentialId"`
	Presentation string `json:"presentation"`
}

// TrustPathEntry pairs a distinct credential issuer DID with T's current DomainAuthorityCredential compact JWS.
type TrustPathEntry struct {
	Issuer              string `json:"issuer"`
	DomainCertification string `json:"domainCertification"`
}

// AccessEvidencePackage models the canonical 7-field verifier input bound to a challenge via KB-JWT.
type AccessEvidencePackage struct {
	Request             AccessRequest        `json:"request"`
	TaskSpec            TaskSpec             `json:"taskSpec"`
	ChallengeID         string               `json:"challengeId"`
	LeafPresentation    string               `json:"leafPresentation"`
	AncestorCredentials []AncestorCredential `json:"ancestorCredentials"`
	Grants              []string             `json:"grants"`
	TrustPaths          []TrustPathEntry     `json:"trustPaths"`
}

// PackageBindings captures all recomputed hashes binding AccessEvidencePackage to KB-JWT.
type PackageBindings struct {
	RequestHash  string `json:"requestHash"`
	ChainHash    string `json:"chainHash"`
	EvidenceHash string `json:"evidenceHash"`
	SDHash       string `json:"sd_hash"`
	LeafPrefix   string `json:"-"`
}

// GradBindingClaim models the `urn:grad:binding` extension object inside KB-JWT payload.
type GradBindingClaim struct {
	ChallengeID  string `json:"challengeId"`
	RequestHash  string `json:"requestHash"`
	ChainHash    string `json:"chainHash"`
	EvidenceHash string `json:"evidenceHash"`
}

// KBJWTClaims models the key-binding JWT payload signed by the leaf holder's authentication key.
type KBJWTClaims struct {
	Aud         string           `json:"aud"`
	Nonce       string           `json:"nonce"`
	IAT         int64            `json:"iat"`
	SDHash      string           `json:"sd_hash"`
	GradBinding GradBindingClaim `json:"urn:grad:binding"`
}

// ChallengeContext carries server-issued challenge bindings checked against KB-JWT.
type ChallengeContext struct {
	ChallengeID string
	Nonce       string
	Audience    string
	IssuedAt    int64
	ExpiresAt   int64
}

// SnapshotView represents an immutable fixed-height ledger state snapshot used for access evidence verification.
type SnapshotView struct {
	Height              uint64
	Now                 time.Time
	ClockError          time.Duration
	ExactIntervalBounds bool
	DeploymentID        string
	Root                registry.RootRecord
	Domains             map[string]registry.Domain
	Certifications      map[string]registry.Certification
	Identities          map[string]registry.Identity
	Credentials         map[string]registry.Credential
	Tasks               map[string]registry.Task
	Grants              map[string]registry.Grant
	Links               map[string]registry.IdentityLink
}

// IsIdentityLinkEffective returns true iff linkID exists and is effectively active at the snapshot height and time.
func (s *SnapshotView) IsIdentityLinkEffective(linkID string) bool {
	if s == nil || len(s.Links) == 0 {
		return false
	}
	l, ok := s.Links[linkID]
	if !ok || l.Status != registry.Active || !l.EffectiveActive {
		return false
	}
	now := s.Now.UTC().Unix()
	if now < l.ProposedAt || now >= l.ExpiresAt {
		return false
	}
	srcDom, ok := s.Domains[l.SourceDomain]
	if !ok || srcDom.Status != registry.Active {
		return false
	}
	dstDom, ok := s.Domains[l.TargetDomain]
	if !ok || dstDom.Status != registry.Active {
		return false
	}
	srcID, ok := s.Identities[l.SourceSubject]
	if !ok || srcID.Status != registry.Active || srcID.KeyVersion != l.SourceKeyVersion || srcID.AccountCommitment != l.SourceAccountCommitment {
		return false
	}
	dstID, ok := s.Identities[l.TargetSubject]
	if !ok || dstID.Status != registry.Active || dstID.KeyVersion != l.TargetKeyVersion || dstID.AccountCommitment != l.TargetAccountCommitment {
		return false
	}
	return true
}

// VerifiedEvidenceResult summarizes verified cryptographic bindings recovered from an AccessEvidencePackage.
type VerifiedEvidenceResult struct {
	DIDDocuments      map[string]json.RawMessage
	Bindings          PackageBindings
	LeafCredential    *VerifiedIdentityCredential
	AncestorCreds     map[string]*VerifiedIdentityCredential
	Grants            []*ParsedGrant
	TrustPathCerts    map[string]*DomainAuthorityCredential
	KBClaims          KBJWTClaims
	TaskSpecDigest    string
	MinMaxAmountMinor int64
	RootAuthorityRole string
}

type evidenceAncEntry struct {
	CredentialID string `json:"credentialId"`
	Digest       string `json:"digest"`
}

type evidenceTrustPathEntry struct {
	Issuer              string `json:"issuer"`
	DomainCertification string `json:"domainCertification"`
}

type evidenceHashInput struct {
	Ancestors  []evidenceAncEntry       `json:"ancestors"`
	Leaf       string                   `json:"leaf"`
	TaskSpec   string                   `json:"taskSpec"`
	TrustPaths []evidenceTrustPathEntry `json:"trustPaths"`
}

// ParseAccessEvidencePackage strictly decodes an AccessEvidencePackage JSON payload, rejecting duplicate keys,
// unknown fields at any level, or oversized inputs.
func ParseAccessEvidencePackage(raw []byte) (*AccessEvidencePackage, error) {
	var pkg AccessEvidencePackage
	if err := DecodeStrictJSON(raw, &pkg); err != nil {
		return nil, err
	}
	return &pkg, nil
}

// ComputeBindings strictly validates structural pre-conditions of pkg and recomputes
// requestHash, chainHash, evidenceHash, and sd_hash.
func (p *AccessEvidencePackage) ComputeBindings(allowZeroDeploymentID bool) (*PackageBindings, error) {
	if p == nil {
		return nil, NewError(ErrCodeInvalidSchema, "nil AccessEvidencePackage")
	}
	if p.ChallengeID == "" || p.LeafPresentation == "" || len(p.Grants) == 0 || len(p.TrustPaths) == 0 {
		return nil, NewError(ErrCodeInvalidSchema, "AccessEvidencePackage requires non-empty challengeId, leafPresentation, grants, and trustPaths")
	}
	lastTilde := strings.LastIndexByte(p.LeafPresentation, '~')
	if lastTilde <= 0 || lastTilde == len(p.LeafPresentation)-1 {
		return nil, NewError(ErrCodeInvalidSchema, "leafPresentation must contain '~' separator and non-empty KB-JWT")
	}
	leafPrefix := p.LeafPresentation[:lastTilde+1]
	reqHash, err := p.Request.Hash(allowZeroDeploymentID)
	if err != nil {
		return nil, err
	}
	taskDigest, err := p.TaskSpec.Digest()
	if err != nil {
		return nil, err
	}

	grantDigests := make([]string, len(p.Grants))
	for i, g := range p.Grants {
		if g == "" {
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("grants[%d] empty", i))
		}
		grantDigests[i] = DigestBytes([]byte(g))
	}
	chainHash, err := DigestValueJCS(grantDigests)
	if err != nil {
		return nil, err
	}

	ancEntries := make([]evidenceAncEntry, len(p.AncestorCredentials))
	for i, anc := range p.AncestorCredentials {
		if anc.CredentialID == "" || !strings.HasSuffix(anc.Presentation, "~") {
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("ancestorCredentials[%d] invalid or missing trailing '~'", i))
		}
		if i > 0 && CompareUTF16(p.AncestorCredentials[i-1].CredentialID, anc.CredentialID) >= 0 {
			return nil, NewError(ErrCodeInvalidSchema, "ancestorCredentials must be sorted ascending without duplicates")
		}
		ancEntries[i] = evidenceAncEntry{
			CredentialID: anc.CredentialID,
			Digest:       DigestBytes([]byte(anc.Presentation)),
		}
	}

	pathEntries := make([]evidenceTrustPathEntry, len(p.TrustPaths))
	for i, tp := range p.TrustPaths {
		if tp.Issuer == "" || tp.DomainCertification == "" {
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("trustPaths[%d] empty issuer or domainCertification", i))
		}
		if i > 0 && CompareUTF16(p.TrustPaths[i-1].Issuer, tp.Issuer) >= 0 {
			return nil, NewError(ErrCodeInvalidSchema, "trustPaths must be sorted ascending by issuer without duplicates")
		}
		pathEntries[i] = evidenceTrustPathEntry{
			Issuer:              tp.Issuer,
			DomainCertification: DigestBytes([]byte(tp.DomainCertification)),
		}
	}

	leafSum := sha256.Sum256([]byte(leafPrefix))
	sdHash := base64.RawURLEncoding.EncodeToString(leafSum[:])

	evHash, err := DigestValueJCS(evidenceHashInput{
		Ancestors:  ancEntries,
		Leaf:       DigestBytes([]byte(leafPrefix)),
		TaskSpec:   taskDigest,
		TrustPaths: pathEntries,
	})
	if err != nil {
		return nil, err
	}

	return &PackageBindings{
		RequestHash:  reqHash,
		ChainHash:    chainHash,
		EvidenceHash: evHash,
		SDHash:       sdHash,
		LeafPrefix:   leafPrefix,
	}, nil
}

// AssembleAccessEvidencePackage computes the package bindings for leafPrefix (ending with '~'),
// sorts ancestorCredentials and trustPaths if unsorted, signs a KB-JWT with holderPriv/holderAuthKeyID,
// and writes the resulting `leafPrefix + kbJwt` into pkg.LeafPresentation.
func AssembleAccessEvidencePackage(
	pkg *AccessEvidencePackage,
	leafPrefix string,
	holderAuthKeyID string,
	holderPriv *ecdsa.PrivateKey,
	challenge ChallengeContext,
	iat int64,
	allowZeroDeploymentID bool,
) (*PackageBindings, string, error) {
	if pkg == nil {
		return nil, "", NewError(ErrCodeInvalidSchema, "nil AccessEvidencePackage")
	}
	if !strings.HasSuffix(leafPrefix, "~") {
		return nil, "", NewError(ErrCodeInvalidSchema, "leafPrefix must end with '~'")
	}
	if err := ValidateNonce(challenge.Nonce); err != nil {
		return nil, "", err
	}
	if challenge.ChallengeID == "" {
		return nil, "", NewError(ErrCodeInvalidSchema, "challengeId required")
	}
	slices.SortFunc(pkg.AncestorCredentials, func(a, b AncestorCredential) int {
		return CompareUTF16(a.CredentialID, b.CredentialID)
	})
	slices.SortFunc(pkg.TrustPaths, func(a, b TrustPathEntry) int {
		return CompareUTF16(a.Issuer, b.Issuer)
	})

	pkg.ChallengeID = challenge.ChallengeID
	pkg.LeafPresentation = leafPrefix + "pending-kb"
	bindings, err := pkg.ComputeBindings(allowZeroDeploymentID)
	if err != nil {
		return nil, "", err
	}

	aud := challenge.Audience
	if aud == "" {
		aud = pkg.Request.Audience
	}
	kbClaims := KBJWTClaims{
		Aud:    aud,
		Nonce:  challenge.Nonce,
		IAT:    iat,
		SDHash: bindings.SDHash,
		GradBinding: GradBindingClaim{
			ChallengeID:  challenge.ChallengeID,
			RequestHash:  bindings.RequestHash,
			ChainHash:    bindings.ChainHash,
			EvidenceHash: bindings.EvidenceHash,
		},
	}
	kbPayload, err := MarshalJCS(kbClaims)
	if err != nil {
		return nil, "", err
	}
	kbJWT, err := SignCompactJWS(holderPriv, TypeKBJWT, holderAuthKeyID, kbPayload)
	if err != nil {
		return nil, "", err
	}
	pkg.LeafPresentation = leafPrefix + kbJWT
	return bindings, kbJWT, nil
}

// VerifyAccessEvidencePackage verifies pkg end-to-end against an immutable fixed-height Ledger SnapshotView,
// pinned Test-CA DIDWebResolver (with pre-seeded T root), and active ChallengeContext.
func VerifyAccessEvidencePackage(
	ctx context.Context,
	pkg *AccessEvidencePackage,
	snap *SnapshotView,
	dids *DIDWebResolver,
	challenge ChallengeContext,
) (*VerifiedEvidenceResult, error) {
	return VerifyAccessEvidencePackageWithCache(ctx, pkg, snap, dids, challenge, nil)
}

// VerifyAccessEvidencePackageWithCache verifies pkg end-to-end against an immutable fixed-height Ledger SnapshotView,
// using cache (B1 mode) solely to avoid repeated static ECDSA JWS math while always enforcing dynamic ledger state.
func VerifyAccessEvidencePackageWithCache(
	ctx context.Context,
	pkg *AccessEvidencePackage,
	snap *SnapshotView,
	dids *DIDWebResolver,
	challenge ChallengeContext,
	cache *SignatureCache,
) (*VerifiedEvidenceResult, error) {
	if pkg == nil || snap == nil || dids == nil {
		return nil, NewError(ErrCodeInvalidSchema, "package, snapshot, and DID resolver are required")
	}
	if !IsHexDigest(snap.DeploymentID, false) {
		return nil, NewError(ErrCodeInvalidSchema, "snapshot deploymentId must be non-zero 64-hex")
	}
	if err := ValidateNonce(challenge.Nonce); err != nil {
		return nil, err
	}
	if challenge.ChallengeID == "" || pkg.ChallengeID != challenge.ChallengeID {
		return nil, NewError(ErrCodeChallengeMismatch, fmt.Sprintf("package challengeId %q != %q", pkg.ChallengeID, challenge.ChallengeID))
	}

	margin := snap.ClockError
	if margin <= 0 {
		margin = registry.ClockError
	}
	intervalMargin := margin
	if snap.ExactIntervalBounds {
		intervalMargin = 0
	}
	now := snap.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// 1. Recompute cryptographic package bindings & validate request/taskSpec structural constraints.
	bindings, err := pkg.ComputeBindings(false)
	if err != nil {
		return nil, err
	}
	if pkg.Request.DeploymentID != snap.DeploymentID {
		return nil, NewError(ErrCodeBindingMismatch, fmt.Sprintf("request deploymentId %q != snapshot %q", pkg.Request.DeploymentID, snap.DeploymentID))
	}

	// 2. Verify preseeded T root DID document and public key offline.
	rootDoc, rootPub, err := dids.ResolvePreseededKey(snap.Root.DID, snap.Root.KeyID, snap.Root.KeyVersion, KeyPurposeAssertionMethod, snap.Root.PublicKey)
	if err != nil {
		return nil, err
	}
	documents := map[string]json.RawMessage{}
	documents[snap.Root.DID], _ = json.Marshal(rootDoc)

	// 3. Verify Task anchor and containment of Request within TaskSpec.
	task, ok := snap.Tasks[pkg.Request.TaskID]
	if !ok {
		return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("task %q not found at snapshot height %d", pkg.Request.TaskID, snap.Height))
	}
	if task.Status != registry.Active {
		msg := fmt.Sprintf("task %q status %q != ACTIVE at height %d", task.ID, task.Status, snap.Height)
		return nil, WrapError(ErrCodeTaskInactive, msg, NewError(ErrCodeGrantChainInvalid, msg))
	}
	if task.DeploymentID != snap.DeploymentID || !task.Interval.Current(now, intervalMargin) {
		return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("task %q inactive or expired at height %d", task.ID, snap.Height))
	}
	taskDigest, err := pkg.TaskSpec.Digest()
	if err != nil {
		return nil, err
	}
	if task.Digest != taskDigest {
		return nil, NewError(ErrCodeBindingMismatch, fmt.Sprintf("taskSpecDigest %s mismatches anchored %s", taskDigest, task.Digest))
	}
	if task.Mode != pkg.Request.AuthorizationMode {
		msg := fmt.Sprintf("request authorizationMode %q mismatches anchored task mode %q", pkg.Request.AuthorizationMode, task.Mode)
		return nil, WrapError(ErrCodeAuthorizationModeMismatch, msg, NewError(ErrCodeGrantChainInvalid, msg))
	}
	if task.Domain != pkg.Request.PrincipalDomain {
		return nil, NewError(ErrCodeGrantChainInvalid, "request principalDomain mismatches anchored task")
	}
	if err := checkRequestInTaskSpec(&pkg.Request, &pkg.TaskSpec); err != nil {
		return nil, err
	}
	if creatorCred, ok := snap.Credentials[task.CreatorCredential]; !ok ||
		creatorCred.Status != registry.Active || !creatorCred.Interval.Current(now, intervalMargin) ||
		creatorCred.Subject != task.Creator || creatorCred.SubjectKeyVersion != task.CreatorKeyVersion {
		return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("task creator credential %q invalid or inactive", task.CreatorCredential))
	}

	// 4. Verify each Grant signature (assertionMethod DID resolution), on-chain Grant anchor, and full Grant chain.
	parsedGrants := make([]*ParsedGrant, len(pkg.Grants))
	for i, gRaw := range pkg.Grants {
		prelim, err := ParseCompactJWS(gRaw, TypeGrantJWS)
		if err != nil {
			return nil, err
		}
		var prelimClaims GrantClaims
		if err := DecodeStrictJSON(prelim.PayloadBytes, &prelimClaims); err != nil {
			return nil, err
		}
		sumG := sha256.Sum256([]byte(gRaw))
		grantCacheKey := SignatureCacheKey{
			MaterialDigest: hex.EncodeToString(sumG[:]),
			Alg:            prelim.Header.Alg,
			KeyID:          prelim.Header.Kid,
			KeyVersion:     prelimClaims.IssuerKeyVersion,
		}
		cachedGrantPub, grantCached := cache.lookup(grantCacheKey)

		issuerID, ok := snap.Identities[prelimClaims.Issuer]
		if !ok || issuerID.DeploymentID != snap.DeploymentID {
			return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] issuer identity %q missing", i, prelimClaims.Issuer))
		}
		if issuerID.Status != registry.Active {
			msg := fmt.Sprintf("grant[%d] issuer identity %q status %q != ACTIVE", i, prelimClaims.Issuer, issuerID.Status)
			return nil, WrapError(ErrCodeIdentityInactive, msg, NewError(ErrCodeGrantChainInvalid, msg))
		}
		if issuerID.KeyVersion != prelimClaims.IssuerKeyVersion {
			msg := fmt.Sprintf("grant[%d] issuerKeyVersion %d != registered %d", i, prelimClaims.IssuerKeyVersion, issuerID.KeyVersion)
			return nil, WrapError(ErrCodeKeyVersionStale, msg, NewError(ErrCodeGrantChainInvalid, msg))
		}
		issuerDom, ok := snap.Domains[issuerID.Domain]
		if !ok {
			return nil, NewError(ErrCodeDomainCertificationInvalid, fmt.Sprintf("grant[%d] issuer domain %q missing", i, issuerID.Domain))
		}
		if issuerDom.Status != registry.Active {
			msg := fmt.Sprintf("grant[%d] issuer domain %q status %q != ACTIVE", i, issuerID.Domain, issuerDom.Status)
			return nil, WrapError(ErrCodeDomainInactive, msg, NewError(ErrCodeDomainCertificationInvalid, msg))
		}
		issuerDoc, issuerPub, _, err := dids.ResolveDID(ctx, issuerID.ID, DIDResolutionExpectation{
			ExpectedDigest:       issuerID.DocumentDigest,
			ExpectedKeyID:        prelim.Header.Kid,
			ExpectedKeyVersion:   issuerID.KeyVersion,
			ExpectedPublicKeyHex: issuerID.PublicKey,
			RequiredPurpose:      KeyPurposeAssertionMethod,
		})
		if err != nil {
			return nil, err
		}
		documents[issuerID.ID], _ = json.Marshal(issuerDoc)
		if !grantCached || cachedGrantPub != issuerID.PublicKey {
			if err := cache.verifyJWS(grantCacheKey, prelim, issuerPub, prelim.Header.Kid, issuerID.PublicKey, !grantCached); err != nil {
				return nil, err
			}
		}
		pg, err := decodeAndValidateGrantParsed(gRaw, prelim)
		if err != nil {
			return nil, err
		}
		onChainGrant, ok := snap.Grants[pg.Claims.ID]
		if !ok || onChainGrant.DeploymentID != snap.DeploymentID || !onChainGrant.Interval.Current(now, intervalMargin) {
			return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant %q missing or expired at snapshot height %d", pg.Claims.ID, snap.Height))
		}
		if onChainGrant.Status != registry.Active {
			if i < len(pkg.Grants)-1 {
				msg := fmt.Sprintf("ancestor grant %q status %q != ACTIVE at snapshot height %d", pg.Claims.ID, onChainGrant.Status, snap.Height)
				return nil, WrapError(ErrCodeAncestorInactive, msg, NewError(ErrCodeGrantChainInvalid, msg))
			}
			msg := fmt.Sprintf("grant %q status %q != ACTIVE at snapshot height %d", pg.Claims.ID, onChainGrant.Status, snap.Height)
			return nil, WrapError(ErrCodeGrantInactive, msg, NewError(ErrCodeGrantChainInvalid, msg))
		}
		if err := matchGrantAnchor(&pg.Claims, pg.Digest, onChainGrant); err != nil {
			return nil, err
		}
		parsedGrants[i] = pg
	}
	if err := VerifyGrantChain(parsedGrants); err != nil {
		return nil, err
	}

	rootGrant := parsedGrants[0]
	leafGrant := parsedGrants[len(parsedGrants)-1]
	rootIssuerID, ok := snap.Identities[rootGrant.Claims.Issuer]
	if !ok {
		return nil, NewError(ErrCodeRootAuthorityInvalid, fmt.Sprintf("root grant issuer %q missing at snapshot height %d", rootGrant.Claims.Issuer, snap.Height))
	}
	switch rootGrant.Claims.AuthorizationMode {
	case ModeBuyerMandate:
		rootDom, ok := snap.Domains[rootGrant.Claims.PrincipalDomain]
		if !ok || rootDom.Status != registry.Active ||
			rootDom.PurchasingAuthority == "" ||
			rootDom.PurchasingAuthority != rootGrant.Claims.Issuer ||
			rootIssuerID.Domain != rootGrant.Claims.PrincipalDomain ||
			rootIssuerID.Kind != "SERVICE" {
			msg := fmt.Sprintf("BM root issuer %q is not active purchasingAuthority for domain %q", rootGrant.Claims.Issuer, rootGrant.Claims.PrincipalDomain)
			return nil, WrapError(ErrCodePurchasingAuthorityInvalid, msg, NewError(ErrCodeRootAuthorityInvalid, msg))
		}
	case ModeResourcePreauthorized:
		if rootIssuerID.Domain != "C" || rootIssuerID.Kind != "SERVICE" {
			return nil, NewError(ErrCodeRootAuthorityInvalid, fmt.Sprintf("RP root issuer %q must be a SERVICE in domain C", rootGrant.Claims.Issuer))
		}
	default:
		return nil, NewError(ErrCodeAuthorizationModeMismatch, fmt.Sprintf("unsupported authorizationMode %q", rootGrant.Claims.AuthorizationMode))
	}
	if rootGrant.Claims.TaskID != task.ID || rootGrant.Claims.ResourceID != task.Resource ||
		rootGrant.Claims.PrincipalDomain != task.Domain {
		return nil, NewError(ErrCodeGrantChainInvalid, "root grant task/resource/domain mismatches anchored task")
	}
	if rootGrant.Claims.AuthorizationMode != task.Mode {
		msg := fmt.Sprintf("root grant authorizationMode %q mismatches anchored task mode %q", rootGrant.Claims.AuthorizationMode, task.Mode)
		return nil, WrapError(ErrCodeAuthorizationModeMismatch, msg, NewError(ErrCodeGrantChainInvalid, msg))
	}
	if !rootGrant.Claims.NBFWithin(task.Interval) {
		return nil, NewError(ErrCodeGrantChainInvalid, "root grant validity window exceeds anchored task interval")
	}
	minMaxAmountMinor := parsedGrants[0].Claims.MaxAmountMinor
	for _, g := range parsedGrants[1:] {
		if g.Claims.MaxAmountMinor < minMaxAmountMinor {
			minMaxAmountMinor = g.Claims.MaxAmountMinor
		}
	}
	if err := checkRequestInGrant(&pkg.Request, &leafGrant.Claims); err != nil {
		return nil, err
	}

	// 5. Verify exact referenced credential set (leaf + deduplicated sorted ancestorCredentials) and SD-JWT anchors.
	leafCredID := leafGrant.Claims.GranteeCredentialID
	expectedAncSet := make(map[string]struct{})
	for _, g := range parsedGrants {
		if g.Claims.IssuerCredentialID != leafCredID {
			expectedAncSet[g.Claims.IssuerCredentialID] = struct{}{}
		}
		if g.Claims.GranteeCredentialID != leafCredID {
			expectedAncSet[g.Claims.GranteeCredentialID] = struct{}{}
		}
	}
	expectedAncIDs := make([]string, 0, len(expectedAncSet))
	for id := range expectedAncSet {
		expectedAncIDs = append(expectedAncIDs, id)
	}
	slices.SortFunc(expectedAncIDs, CompareUTF16)

	actualAncIDs := make([]string, len(pkg.AncestorCredentials))
	for i, anc := range pkg.AncestorCredentials {
		actualAncIDs[i] = anc.CredentialID
	}
	if !slices.Equal(actualAncIDs, expectedAncIDs) {
		return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("ancestorCredentials %v mismatch required referenced set %v", actualAncIDs, expectedAncIDs))
	}

	verifyOneSDJWT := func(sdJWT string, requireKB bool) (*VerifiedIdentityCredential, *registry.Identity, *registry.Identity, error) {
		issuerPart, disclosures, kbJWT, err := splitAndCheckSDJWT(sdJWT, requireKB)
		if err != nil {
			return nil, nil, nil, err
		}
		prelim, err := ParseCompactJWS(issuerPart, TypeSDJWT)
		if err != nil {
			return nil, nil, nil, err
		}
		var prelimClaims EnterpriseIdentityCredential
		if err := DecodeStrictJSON(prelim.PayloadBytes, &prelimClaims); err != nil {
			return nil, nil, nil, err
		}
		sumVC := sha256.Sum256([]byte(issuerPart))
		vcCacheKey := SignatureCacheKey{
			MaterialDigest: hex.EncodeToString(sumVC[:]),
			Alg:            prelim.Header.Alg,
			KeyID:          prelim.Header.Kid,
			KeyVersion:     prelimClaims.IssuerKeyVersion,
		}
		cachedVCPub, vcCached := cache.lookup(vcCacheKey)

		issuerID, ok := snap.Identities[prelimClaims.Issuer]
		if !ok || issuerID.DeploymentID != snap.DeploymentID {
			return nil, nil, nil, NewError(ErrCodeIssuerScopeInvalid, fmt.Sprintf("credential issuer %q missing", prelimClaims.Issuer))
		}
		if issuerID.Status != registry.Active {
			msg := fmt.Sprintf("credential issuer %q status %q != ACTIVE", prelimClaims.Issuer, issuerID.Status)
			return nil, nil, nil, WrapError(ErrCodeIdentityInactive, msg, NewError(ErrCodeIssuerScopeInvalid, msg))
		}
		if issuerID.KeyVersion != prelimClaims.IssuerKeyVersion {
			msg := fmt.Sprintf("credential issuer %q keyVersion %d != registered %d", prelimClaims.Issuer, prelimClaims.IssuerKeyVersion, issuerID.KeyVersion)
			return nil, nil, nil, WrapError(ErrCodeKeyVersionStale, msg, NewError(ErrCodeIssuerScopeInvalid, msg))
		}
		holderID, ok := snap.Identities[prelimClaims.Sub]
		if !ok || holderID.DeploymentID != snap.DeploymentID {
			return nil, nil, nil, NewError(ErrCodeHolderMismatch, fmt.Sprintf("credential holder %q missing", prelimClaims.Sub))
		}
		if holderID.Status != registry.Active {
			msg := fmt.Sprintf("credential holder %q status %q != ACTIVE", prelimClaims.Sub, holderID.Status)
			return nil, nil, nil, WrapError(ErrCodeIdentityInactive, msg, NewError(ErrCodeHolderMismatch, msg))
		}
		if holderID.KeyVersion != prelimClaims.AppKeyVersion {
			msg := fmt.Sprintf("credential holder %q appKeyVersion %d != registered %d", prelimClaims.Sub, prelimClaims.AppKeyVersion, holderID.KeyVersion)
			return nil, nil, nil, WrapError(ErrCodeKeyVersionStale, msg, NewError(ErrCodeHolderMismatch, msg))
		}
		issuerDoc, issuerPub, _, err := dids.ResolveDID(ctx, issuerID.ID, DIDResolutionExpectation{
			ExpectedDigest:       issuerID.DocumentDigest,
			ExpectedKeyID:        prelim.Header.Kid,
			ExpectedKeyVersion:   issuerID.KeyVersion,
			ExpectedPublicKeyHex: issuerID.PublicKey,
			RequiredPurpose:      KeyPurposeAssertionMethod,
		})
		if err != nil {
			return nil, nil, nil, err
		}
		documents[issuerID.ID], _ = json.Marshal(issuerDoc)
		if !vcCached || cachedVCPub != issuerID.PublicKey {
			if err := cache.verifyJWS(vcCacheKey, prelim, issuerPub, prelim.Header.Kid, issuerID.PublicKey, !vcCached); err != nil {
				return nil, nil, nil, err
			}
		}
		verCred, err := verifySDJWTPayloadAndDisclosures(sdJWT, prelim, disclosures, kbJWT, holderID.PublicKey)
		if err != nil {
			return nil, nil, nil, err
		}
		chainCred, ok := snap.Credentials[verCred.Claims.ID]
		if !ok || chainCred.DeploymentID != snap.DeploymentID || chainCred.Status != registry.Active || !chainCred.Interval.Current(now, intervalMargin) {
			return nil, nil, nil, NewError(ErrCodeCredentialStatusInvalid, fmt.Sprintf("credential %q missing, inactive, or expired on ledger", verCred.Claims.ID))
		}
		if chainCred.Digest != verCred.AnchorDigest {
			return nil, nil, nil, NewError(ErrCodeBindingMismatch, fmt.Sprintf("credential %q issuer-signed JWT digest mismatches ledger anchor", verCred.Claims.ID))
		}
		if chainCred.Issuer != verCred.Claims.Issuer || chainCred.Subject != verCred.Claims.Sub ||
			chainCred.IssuerKeyVersion != verCred.Claims.IssuerKeyVersion || chainCred.SubjectKeyVersion != verCred.Claims.AppKeyVersion ||
			chainCred.NBF != verCred.Claims.NBF || chainCred.EXP != verCred.Claims.EXP {
			return nil, nil, nil, NewError(ErrCodeBindingMismatch, fmt.Sprintf("credential %q claims mismatch anchored metadata", verCred.Claims.ID))
		}
		if verCred.Domain != holderID.Domain {
			return nil, nil, nil, NewError(ErrCodeHolderMismatch, fmt.Sprintf("credential %q disclosed domain %q mismatches registered %q", verCred.Claims.ID, verCred.Domain, holderID.Domain))
		}
		for name := range verCred.Disclosed {
			if !slices.Contains(chainCred.ClaimNames, name) {
				return nil, nil, nil, NewError(ErrCodeIssuerScopeInvalid, fmt.Sprintf("credential %q disclosed unauthorized claim %q", verCred.Claims.ID, name))
			}
		}
		return verCred, &issuerID, &holderID, nil
	}

	leafVerCred, leafIssuerID, leafHolderID, err := verifyOneSDJWT(pkg.LeafPresentation, true)
	if err != nil {
		return nil, err
	}
	if leafVerCred.Claims.ID != leafCredID || leafVerCred.Claims.Sub != pkg.Request.Actor || leafVerCred.Claims.AppKeyVersion != leafGrant.Claims.GranteeKeyVersion {
		return nil, NewError(ErrCodeHolderMismatch, "leafPresentation subject/credentialId mismatches actor or leaf grant grantee")
	}

	credByID := map[string]*VerifiedIdentityCredential{leafVerCred.Claims.ID: leafVerCred}
	credIssuerMap := map[string]*registry.Identity{leafVerCred.Claims.ID: leafIssuerID}
	credHolderMap := map[string]*registry.Identity{leafVerCred.Claims.ID: leafHolderID}
	ancestorVerCreds := make(map[string]*VerifiedIdentityCredential, len(pkg.AncestorCredentials))

	for _, anc := range pkg.AncestorCredentials {
		vc, issID, holdID, err := verifyOneSDJWT(anc.Presentation, false)
		if err != nil {
			return nil, err
		}
		if vc.Claims.ID != anc.CredentialID {
			return nil, NewError(ErrCodeBindingMismatch, fmt.Sprintf("ancestorCredentials label %q mismatches signed id %q", anc.CredentialID, vc.Claims.ID))
		}
		ancestorVerCreds[anc.CredentialID] = vc
		credByID[vc.Claims.ID] = vc
		credIssuerMap[vc.Claims.ID] = issID
		credHolderMap[vc.Claims.ID] = holdID
	}

	// Verify grant <-> credential bindings across all hops.
	for i, g := range parsedGrants {
		ic, okIC := credByID[g.Claims.IssuerCredentialID]
		gc, okGC := credByID[g.Claims.GranteeCredentialID]
		if !okIC || !okGC {
			return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] credential reference missing from package", i))
		}
		if ic.Claims.Sub != g.Claims.Issuer || ic.Claims.AppKeyVersion != g.Claims.IssuerKeyVersion {
			return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] issuer mismatches %q", i, ic.Claims.ID))
		}
		if gc.Claims.Sub != g.Claims.Grantee || gc.Claims.AppKeyVersion != g.Claims.GranteeKeyVersion {
			return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] grantee mismatches %q", i, gc.Claims.ID))
		}
		if g.Claims.NBF < ic.Claims.NBF || g.Claims.EXP > ic.Claims.EXP || g.Claims.NBF < gc.Claims.NBF || g.Claims.EXP > gc.Claims.EXP {
			return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] interval exceeds credential validity window", i))
		}
	}

	// 6. Verify TrustPaths strictly match the exact set of distinct credential issuers and T domain certifications.
	distinctIssuersSet := make(map[string]struct{})
	for _, vc := range credByID {
		distinctIssuersSet[vc.Claims.Issuer] = struct{}{}
	}
	wantIssuers := make([]string, 0, len(distinctIssuersSet))
	for iss := range distinctIssuersSet {
		wantIssuers = append(wantIssuers, iss)
	}
	slices.SortFunc(wantIssuers, CompareUTF16)

	gotIssuers := make([]string, len(pkg.TrustPaths))
	trustByIssuer := make(map[string]*DomainAuthorityCredential, len(pkg.TrustPaths))
	certDigestCache := make(map[string]string)
	for i, tp := range pkg.TrustPaths {
		gotIssuers[i] = tp.Issuer
	}
	if !slices.Equal(gotIssuers, wantIssuers) {
		return nil, NewError(ErrCodeIssuerScopeInvalid, fmt.Sprintf("trustPaths issuers %v mismatch credential issuers %v", gotIssuers, wantIssuers))
	}

	for _, tp := range pkg.TrustPaths {
		prelimCert, err := ParseCompactJWS(tp.DomainCertification, TypeDomainAuthorityJWS)
		if err != nil {
			return nil, err
		}
		var peek struct {
			IssuerKeyVersion uint64 `json:"issuerKeyVersion"`
		}
		_ = json.Unmarshal(prelimCert.PayloadBytes, &peek)
		sumDC := sha256.Sum256([]byte(tp.DomainCertification))
		certCacheKey := SignatureCacheKey{
			MaterialDigest: hex.EncodeToString(sumDC[:]),
			Alg:            prelimCert.Header.Alg,
			KeyID:          prelimCert.Header.Kid,
			KeyVersion:     peek.IssuerKeyVersion,
		}
		cachedCertPub, certCached := cache.lookup(certCacheKey)
		if !certCached || cachedCertPub != snap.Root.PublicKey {
			if err := cache.verifyJWS(certCacheKey, prelimCert, rootPub, snap.Root.KeyID, snap.Root.PublicKey, !certCached); err != nil {
				return nil, err
			}
		}
		parsedCert, certDigest, err := decodeAndValidateDomainAuthorityParsed(prelimCert)
		if err != nil {
			return nil, err
		}
		if prevDigest, seen := certDigestCache[parsedCert.ID]; seen && prevDigest != certDigest {
			return nil, NewError(ErrCodeDomainCertificationInvalid, fmt.Sprintf("conflicting certification bytes for %q", parsedCert.ID))
		}
		certDigestCache[parsedCert.ID] = certDigest

		dom, ok := snap.Domains[parsedCert.CredentialSubject.DomainID]
		if !ok || dom.DeploymentID != snap.DeploymentID {
			return nil, NewError(ErrCodeDomainCertificationInvalid, fmt.Sprintf("domain %q missing or deployment mismatch", parsedCert.CredentialSubject.DomainID))
		}
		if dom.Status != registry.Active {
			msg := fmt.Sprintf("domain %q status %q != ACTIVE", dom.ID, dom.Status)
			return nil, WrapError(ErrCodeDomainInactive, msg, NewError(ErrCodeDomainCertificationInvalid, msg))
		}
		if dom.Certification != parsedCert.ID {
			return nil, NewError(ErrCodeDomainCertificationInvalid, fmt.Sprintf("domain %q certification %q mismatches %q", dom.ID, dom.Certification, parsedCert.ID))
		}
		certAnchor, ok := snap.Certifications[parsedCert.ID]
		if !ok || certAnchor.DeploymentID != snap.DeploymentID || certAnchor.Status != registry.Active || !certAnchor.Interval.Current(now, intervalMargin) {
			return nil, NewError(ErrCodeDomainCertificationInvalid, fmt.Sprintf("on-chain certification %q missing, inactive, or expired", parsedCert.ID))
		}
		if err := parsedCert.VerifyAgainstChain(certDigest, DomainAnchorState{
			RootDID:            snap.Root.DID,
			RootKeyVersion:     snap.Root.KeyVersion,
			DomainID:           dom.ID,
			DomainDID:          dom.DID,
			DomainIssuers:      dom.Issuers,
			CertificationID:    certAnchor.ID,
			CertificationNBF:   certAnchor.NBF,
			CertificationEXP:   certAnchor.EXP,
			CertificationDig:   certAnchor.Digest,
			CertificationScope: certAnchor.Scopes,
		}); err != nil {
			return nil, err
		}
		trustByIssuer[tp.Issuer] = parsedCert
	}

	// Verify every presented credential is covered by its issuer's domain certification scope & domain membership.
	for credID, vc := range credByID {
		domCert, ok := trustByIssuer[vc.Claims.Issuer]
		if !ok {
			return nil, NewError(ErrCodeIssuerScopeInvalid, fmt.Sprintf("missing trustPath for issuer %q", vc.Claims.Issuer))
		}
		issuerID := credIssuerMap[credID]
		holderID := credHolderMap[credID]
		if issuerID.Domain != domCert.CredentialSubject.DomainID || holderID.Domain != domCert.CredentialSubject.DomainID {
			return nil, NewError(ErrCodeIssuerScopeInvalid, fmt.Sprintf("credential %q issuer/holder domains must belong to certified domain %q", credID, domCert.CredentialSubject.DomainID))
		}
		disclosedNames := make([]string, 0, len(vc.Disclosed))
		for name := range vc.Disclosed {
			disclosedNames = append(disclosedNames, name)
		}
		if _, err := domCert.FindIssuerScope(vc.Claims.Issuer, vc.Claims.IssuerKeyVersion, CredentialTypeEnterpriseIdentity, disclosedNames); err != nil {
			return nil, err
		}
	}

	// 7. Verify KB-JWT (typ="kb+jwt") against actor's DID authentication key and recomputed bindings.
	parsedKB, err := ParseCompactJWS(leafVerCred.KBJWT, TypeKBJWT)
	if err != nil {
		return nil, err
	}
	actorDoc, actorAuthPub, _, err := dids.ResolveDID(ctx, leafHolderID.ID, DIDResolutionExpectation{
		ExpectedDigest:       leafHolderID.DocumentDigest,
		ExpectedKeyID:        parsedKB.Header.Kid,
		ExpectedKeyVersion:   leafHolderID.KeyVersion,
		ExpectedPublicKeyHex: leafHolderID.PublicKey,
		RequiredPurpose:      KeyPurposeAuthentication,
	})
	if err != nil {
		return nil, err
	}
	documents[leafHolderID.ID], _ = json.Marshal(actorDoc)
	if err := verifyJWSWithKid(parsedKB, actorAuthPub, parsedKB.Header.Kid); err != nil {
		return nil, err
	}
	var kbClaims KBJWTClaims
	if err := DecodeStrictJSON(parsedKB.PayloadBytes, &kbClaims); err != nil {
		return nil, err
	}
	if err := ValidateNonce(kbClaims.Nonce); err != nil {
		return nil, err
	}
	if kbClaims.Nonce != challenge.Nonce {
		return nil, NewError(ErrCodeChallengeMismatch, "KB-JWT nonce mismatches issued challenge nonce")
	}
	if kbClaims.Aud != pkg.Request.Audience || (challenge.Audience != "" && kbClaims.Aud != challenge.Audience) {
		return nil, NewError(ErrCodeBindingMismatch, fmt.Sprintf("KB-JWT aud %q mismatches request audience %q", kbClaims.Aud, pkg.Request.Audience))
	}
	marginSec := int64(margin / time.Second)
	nowSec := now.Unix()
	if kbClaims.IAT < challenge.IssuedAt-marginSec || kbClaims.IAT > nowSec+marginSec || kbClaims.IAT >= challenge.ExpiresAt {
		return nil, NewError(ErrCodeChallengeMismatch, fmt.Sprintf("KB-JWT iat %d outside challenge window [%d, %d)", kbClaims.IAT, challenge.IssuedAt, challenge.ExpiresAt))
	}
	if !now.Before(time.Unix(challenge.ExpiresAt, 0)) {
		return nil, NewError(ErrCodeChallengeMismatch, "challenge expired at verification time")
	}
	if kbClaims.SDHash != bindings.SDHash {
		return nil, NewError(ErrCodeBindingMismatch, fmt.Sprintf("KB-JWT sd_hash %q mismatches recomputed %q", kbClaims.SDHash, bindings.SDHash))
	}
	wantBinding := GradBindingClaim{
		ChallengeID:  pkg.ChallengeID,
		RequestHash:  bindings.RequestHash,
		ChainHash:    bindings.ChainHash,
		EvidenceHash: bindings.EvidenceHash,
	}
	if kbClaims.GradBinding != wantBinding {
		return nil, NewError(ErrCodeBindingMismatch, "KB-JWT urn:grad:binding digests mismatch recomputed evidence bindings")
	}

	rootAuthorityRole := ""
	if rc := credByID[rootGrant.Claims.IssuerCredentialID]; rc != nil {
		rootAuthorityRole = rc.Role
	}

	return &VerifiedEvidenceResult{
		DIDDocuments:      documents,
		Bindings:          *bindings,
		LeafCredential:    leafVerCred,
		AncestorCreds:     ancestorVerCreds,
		Grants:            parsedGrants,
		TrustPathCerts:    trustByIssuer,
		KBClaims:          kbClaims,
		TaskSpecDigest:    taskDigest,
		MinMaxAmountMinor: minMaxAmountMinor,
		RootAuthorityRole: rootAuthorityRole,
	}, nil
}

func checkRequestInTaskSpec(req *AccessRequest, spec *TaskSpec) error {
	if req.SupplierID != spec.SupplierID || req.ProductID != spec.ProductID || req.Currency != spec.Currency {
		return NewError(ErrCodeBindingMismatch, "request supplier/product/currency mismatches taskSpec")
	}
	if req.Quantity > spec.MaxQuantity {
		return NewError(ErrCodeBindingMismatch, fmt.Sprintf("request quantity %d exceeds taskSpec maxQuantity %d", req.Quantity, spec.MaxQuantity))
	}
	if !slices.Contains(spec.Resources, req.Resource) || !slices.Contains(spec.Actions, req.Action) {
		return NewError(ErrCodeBindingMismatch, "request resource/action outside taskSpec")
	}
	return nil
}

func checkRequestInGrant(req *AccessRequest, g *GrantClaims) error {
	if req.DeploymentID != g.DeploymentID || req.AuthorizationMode != g.AuthorizationMode ||
		req.PrincipalDomain != g.PrincipalDomain || req.TaskID != g.TaskID {
		return NewError(ErrCodeGrantChainInvalid, "request deployment/mode/domain/task mismatches leaf grant")
	}
	if req.Actor != g.Grantee {
		return NewError(ErrCodeHolderMismatch, fmt.Sprintf("request actor %q != leaf grant grantee %q", req.Actor, g.Grantee))
	}
	if req.Audience != g.Aud || req.Currency != g.Currency {
		return NewError(ErrCodeBindingMismatch, "request audience/currency mismatches leaf grant")
	}
	if req.Action != ActionOrderCreate && req.AmountMinor > g.MaxAmountMinor {
		msg := fmt.Sprintf("request amountMinor %d exceeds grant maxAmountMinor %d", req.AmountMinor, g.MaxAmountMinor)
		return WrapError(ErrCodeAmountLimitExceeded, msg, NewError(ErrCodeBindingMismatch, msg))
	}
	if !slices.Contains(g.Resources, req.Resource) || !slices.Contains(g.Actions, req.Action) || !slices.Contains(g.Suppliers, req.SupplierID) {
		return NewError(ErrCodeGrantChainInvalid, "request resource/action/supplier outside leaf grant scope")
	}
	return nil
}

func matchGrantAnchor(c *GrantClaims, digest string, onChain registry.Grant) error {
	if onChain.Digest != digest {
		return NewError(ErrCodeBindingMismatch, fmt.Sprintf("grant %q JWS digest %s mismatches anchored %s", c.ID, digest, onChain.Digest))
	}
	if c.ParentID == nil {
		if onChain.Parent != "" || onChain.ParentDigest != "" {
			return NewError(ErrCodeBindingMismatch, "root grant parent fields mismatch on-chain grant")
		}
	} else {
		if onChain.Parent != *c.ParentID || onChain.ParentDigest != *c.ParentDigest {
			return NewError(ErrCodeBindingMismatch, "child grant parentId/parentDigest mismatch on-chain grant")
		}
	}
	if onChain.Schema != c.SchemaVersion || onChain.Root != c.RootID || onChain.Task != c.TaskID ||
		onChain.Mode != c.AuthorizationMode || onChain.Domain != c.PrincipalDomain || onChain.Resource != c.ResourceID ||
		onChain.Issuer != c.Issuer || onChain.Grantee != c.Grantee ||
		onChain.IssuerKeyVersion != c.IssuerKeyVersion || onChain.GranteeKeyVersion != c.GranteeKeyVersion ||
		onChain.IssuerCredential != c.IssuerCredentialID || onChain.GranteeCredential != c.GranteeCredentialID ||
		int64(onChain.Depth) != c.RemainingDepth || onChain.NBF != c.NBF || onChain.EXP != c.EXP {
		return NewError(ErrCodeBindingMismatch, fmt.Sprintf("grant %q signed claims mismatch on-chain record", c.ID))
	}
	return nil
}
