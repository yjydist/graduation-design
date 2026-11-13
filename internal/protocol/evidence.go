package protocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"time"

	api "graduation-design/internal/fabricapi"
)

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
	Height         uint64
	Now            time.Time
	ClockError     time.Duration
	DeploymentID   string
	Root           api.RootRecord
	Domains        map[string]api.Domain
	Certifications map[string]api.Certification
	Identities     map[string]api.Identity
	Credentials    map[string]api.Credential
	Tasks          map[string]api.Task
	Grants         map[string]api.Grant
}

// VerifiedEvidenceResult summarizes verified cryptographic bindings recovered from an AccessEvidencePackage.
type VerifiedEvidenceResult struct {
	Bindings       PackageBindings
	LeafCredential *VerifiedIdentityCredential
	AncestorCreds  map[string]*VerifiedIdentityCredential
	Grants         []*ParsedGrant
	TrustPathCerts map[string]*DomainAuthorityCredential
	KBClaims       KBJWTClaims
	TaskSpecDigest string
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
	chainCanon, err := MarshalJCS(grantDigests)
	if err != nil {
		return nil, err
	}
	chainHash := DigestBytes(chainCanon)

	ancEntries := make([]evidenceAncEntry, len(p.AncestorCredentials))
	for i, anc := range p.AncestorCredentials {
		if anc.CredentialID == "" || !strings.HasSuffix(anc.Presentation, "~") {
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("ancestorCredentials[%d] invalid or missing trailing '~'", i))
		}
		if i > 0 && compareUTF16(p.AncestorCredentials[i-1].CredentialID, anc.CredentialID) >= 0 {
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
		if i > 0 && compareUTF16(p.TrustPaths[i-1].Issuer, tp.Issuer) >= 0 {
			return nil, NewError(ErrCodeInvalidSchema, "trustPaths must be sorted ascending by issuer without duplicates")
		}
		pathEntries[i] = evidenceTrustPathEntry{
			Issuer:              tp.Issuer,
			DomainCertification: DigestBytes([]byte(tp.DomainCertification)),
		}
	}

	leafSum := sha256.Sum256([]byte(leafPrefix))
	sdHash := base64.RawURLEncoding.EncodeToString(leafSum[:])

	evObj := evidenceHashInput{
		Ancestors:  ancEntries,
		Leaf:       DigestBytes([]byte(leafPrefix)),
		TaskSpec:   taskDigest,
		TrustPaths: pathEntries,
	}
	evCanon, err := MarshalJCS(evObj)
	if err != nil {
		return nil, err
	}
	evHash := DigestBytes(evCanon)

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
	if _, err := ValidateNonce(challenge.Nonce); err != nil {
		return nil, "", err
	}
	if challenge.ChallengeID == "" {
		return nil, "", NewError(ErrCodeInvalidSchema, "challengeId required")
	}
	slices.SortFunc(pkg.AncestorCredentials, func(a, b AncestorCredential) int {
		return compareUTF16(a.CredentialID, b.CredentialID)
	})
	slices.SortFunc(pkg.TrustPaths, func(a, b TrustPathEntry) int {
		return compareUTF16(a.Issuer, b.Issuer)
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
	kbJWT, _, err := SignCompactJWS(holderPriv, TypKeyBindingJWT, holderAuthKeyID, kbPayload)
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
	if pkg == nil || snap == nil || dids == nil {
		return nil, NewError(ErrCodeInvalidSchema, "package, snapshot, and DID resolver are required")
	}
	if !IsHexDigest(snap.DeploymentID, false) {
		return nil, NewError(ErrCodeInvalidSchema, "snapshot deploymentId must be non-zero 64-hex")
	}
	if _, err := ValidateNonce(challenge.Nonce); err != nil {
		return nil, err
	}
	if challenge.ChallengeID == "" || pkg.ChallengeID != challenge.ChallengeID {
		return nil, NewError(ErrCodeChallengeMismatch, fmt.Sprintf("package challengeId %q != %q", pkg.ChallengeID, challenge.ChallengeID))
	}

	margin := snap.ClockError
	if margin <= 0 {
		margin = api.ClockError
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

	// 2. Verify preseeded T root DID document and public key offline (and cross-check online if routed).
	_, rootPub, err := dids.ResolvePreseededKey(snap.Root.DID, snap.Root.KeyID, snap.Root.KeyVersion, KeyPurposeAssertionMethod, snap.Root.PublicKey)
	if err != nil {
		return nil, err
	}

	// 3. Verify Task anchor and containment of Request within TaskSpec.
	task, ok := snap.Tasks[pkg.Request.TaskID]
	if !ok {
		return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("task %q not found at snapshot height %d", pkg.Request.TaskID, snap.Height))
	}
	if task.DeploymentID != snap.DeploymentID || task.Status != api.Active || !task.Interval.Current(now, margin) {
		return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("task %q inactive or expired at height %d", task.ID, snap.Height))
	}
	taskDigest, err := pkg.TaskSpec.Digest()
	if err != nil {
		return nil, err
	}
	if task.Digest != taskDigest {
		return nil, NewError(ErrCodeBindingMismatch, fmt.Sprintf("taskSpecDigest %s mismatches anchored %s", taskDigest, task.Digest))
	}
	if task.Mode != pkg.Request.AuthorizationMode || task.Domain != pkg.Request.PrincipalDomain {
		return nil, NewError(ErrCodeGrantChainInvalid, "request authorizationMode/principalDomain mismatches anchored task")
	}
	if err := checkRequestInTaskSpec(&pkg.Request, &pkg.TaskSpec); err != nil {
		return nil, err
	}
	if creatorCred, ok := snap.Credentials[task.CreatorCredential]; !ok ||
		creatorCred.Status != api.Active || !creatorCred.Interval.Current(now, margin) ||
		creatorCred.Subject != task.Creator || creatorCred.SubjectKeyVersion != task.CreatorKeyVersion {
		return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("task creator credential %q invalid or inactive", task.CreatorCredential))
	}

	// 4. Verify each Grant signature (assertionMethod DID resolution), on-chain Grant anchor, and full Grant chain.
	parsedGrants := make([]*ParsedGrant, len(pkg.Grants))
	for i, gRaw := range pkg.Grants {
		prelim, err := ParseCompactJWS(gRaw, TypGrantDelegation)
		if err != nil {
			return nil, err
		}
		var prelimClaims GrantClaims
		if err := DecodeStrictJSON(prelim.PayloadBytes, &prelimClaims); err != nil {
			return nil, err
		}
		issuerID, ok := snap.Identities[prelimClaims.Issuer]
		if !ok || issuerID.DeploymentID != snap.DeploymentID || issuerID.Status != api.Active {
			return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] issuer identity %q missing or inactive", i, prelimClaims.Issuer))
		}
		if issuerID.KeyVersion != prelimClaims.IssuerKeyVersion {
			return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant[%d] issuerKeyVersion %d != registered %d", i, prelimClaims.IssuerKeyVersion, issuerID.KeyVersion))
		}
		issuerDom, ok := snap.Domains[issuerID.Domain]
		if !ok || issuerDom.Status != api.Active {
			return nil, NewError(ErrCodeDomainCertificationInvalid, fmt.Sprintf("grant[%d] issuer domain %q missing or inactive", i, issuerID.Domain))
		}
		_, issuerPub, _, err := dids.ResolveDID(ctx, issuerID.ID, DIDResolutionExpectation{
			ExpectedDigest:       issuerID.DocumentDigest,
			ExpectedKeyID:        prelim.Header.Kid,
			ExpectedKeyVersion:   issuerID.KeyVersion,
			ExpectedPublicKeyHex: issuerID.PublicKey,
			RequiredPurpose:      KeyPurposeAssertionMethod,
		})
		if err != nil {
			return nil, err
		}
		pg, err := ParseAndVerifyGrant(gRaw, issuerPub, prelim.Header.Kid)
		if err != nil {
			return nil, err
		}
		onChainGrant, ok := snap.Grants[pg.Claims.ID]
		if !ok || onChainGrant.DeploymentID != snap.DeploymentID || onChainGrant.Status != api.Active || !onChainGrant.Interval.Current(now, margin) {
			return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("grant %q missing, inactive, or expired at snapshot height %d", pg.Claims.ID, snap.Height))
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
	if rootGrant.Claims.TaskID != task.ID || rootGrant.Claims.ResourceID != task.Resource ||
		rootGrant.Claims.AuthorizationMode != task.Mode || rootGrant.Claims.PrincipalDomain != task.Domain {
		return nil, NewError(ErrCodeGrantChainInvalid, "root grant task/resource/mode/domain mismatches anchored task")
	}
	if !rootGrant.Claims.NBFWithin(task.Interval) {
		return nil, NewError(ErrCodeGrantChainInvalid, "root grant validity window exceeds anchored task interval")
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
	slices.SortFunc(expectedAncIDs, compareUTF16)

	actualAncIDs := make([]string, len(pkg.AncestorCredentials))
	for i, anc := range pkg.AncestorCredentials {
		actualAncIDs[i] = anc.CredentialID
	}
	if !slices.Equal(actualAncIDs, expectedAncIDs) {
		return nil, NewError(ErrCodeGrantChainInvalid, fmt.Sprintf("ancestorCredentials %v mismatch required referenced set %v", actualAncIDs, expectedAncIDs))
	}

	verifyOneSDJWT := func(sdJWT string, requireKB bool) (*VerifiedIdentityCredential, *api.Identity, *api.Identity, error) {
		issuerPart, _, found := strings.Cut(sdJWT, "~")
		if !found || issuerPart == "" {
			return nil, nil, nil, NewError(ErrCodeInvalidDisclosure, "SD-JWT missing '~' separator")
		}
		prelim, err := ParseCompactJWS(issuerPart, TypEnterpriseIdentityCredential)
		if err != nil {
			return nil, nil, nil, err
		}
		var prelimClaims EnterpriseIdentityCredential
		if err := DecodeStrictJSON(prelim.PayloadBytes, &prelimClaims); err != nil {
			return nil, nil, nil, err
		}
		issuerID, ok := snap.Identities[prelimClaims.Issuer]
		if !ok || issuerID.DeploymentID != snap.DeploymentID || issuerID.Status != api.Active || issuerID.KeyVersion != prelimClaims.IssuerKeyVersion {
			return nil, nil, nil, NewError(ErrCodeIssuerScopeInvalid, fmt.Sprintf("credential issuer %q missing, inactive, or keyVersion mismatch", prelimClaims.Issuer))
		}
		holderID, ok := snap.Identities[prelimClaims.Sub]
		if !ok || holderID.DeploymentID != snap.DeploymentID || holderID.Status != api.Active || holderID.KeyVersion != prelimClaims.AppKeyVersion {
			return nil, nil, nil, NewError(ErrCodeHolderMismatch, fmt.Sprintf("credential holder %q missing, inactive, or appKeyVersion mismatch", prelimClaims.Sub))
		}
		_, issuerPub, _, err := dids.ResolveDID(ctx, issuerID.ID, DIDResolutionExpectation{
			ExpectedDigest:       issuerID.DocumentDigest,
			ExpectedKeyID:        prelim.Header.Kid,
			ExpectedKeyVersion:   issuerID.KeyVersion,
			ExpectedPublicKeyHex: issuerID.PublicKey,
			RequiredPurpose:      KeyPurposeAssertionMethod,
		})
		if err != nil {
			return nil, nil, nil, err
		}
		verCred, err := VerifySDJWTCredential(sdJWT, issuerPub, prelim.Header.Kid, holderID.PublicKey, requireKB)
		if err != nil {
			return nil, nil, nil, err
		}
		chainCred, ok := snap.Credentials[verCred.Claims.ID]
		if !ok || chainCred.DeploymentID != snap.DeploymentID || chainCred.Status != api.Active || !chainCred.Interval.Current(now, margin) {
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
	credIssuerMap := map[string]*api.Identity{leafVerCred.Claims.ID: leafIssuerID}
	credHolderMap := map[string]*api.Identity{leafVerCred.Claims.ID: leafHolderID}
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
	slices.SortFunc(wantIssuers, compareUTF16)

	gotIssuers := make([]string, len(pkg.TrustPaths))
	trustByIssuer := make(map[string]*DomainAuthorityCredential, len(pkg.TrustPaths))
	certCache := make(map[string]*DomainAuthorityCredential)
	certDigestCache := make(map[string]string)
	for i, tp := range pkg.TrustPaths {
		gotIssuers[i] = tp.Issuer
	}
	if !slices.Equal(gotIssuers, wantIssuers) {
		return nil, NewError(ErrCodeIssuerScopeInvalid, fmt.Sprintf("trustPaths issuers %v mismatch credential issuers %v", gotIssuers, wantIssuers))
	}

	for _, tp := range pkg.TrustPaths {
		parsedCert, certDigest, err := ParseAndVerifyDomainAuthorityCredential(tp.DomainCertification, rootPub, snap.Root.KeyID)
		if err != nil {
			return nil, err
		}
		if prevDigest, seen := certDigestCache[parsedCert.ID]; seen && prevDigest != certDigest {
			return nil, NewError(ErrCodeDomainCertificationInvalid, fmt.Sprintf("conflicting certification bytes for %q", parsedCert.ID))
		}
		certCache[parsedCert.ID] = parsedCert
		certDigestCache[parsedCert.ID] = certDigest

		dom, ok := snap.Domains[parsedCert.CredentialSubject.DomainID]
		if !ok || dom.DeploymentID != snap.DeploymentID || dom.Status != api.Active || dom.Certification != parsedCert.ID {
			return nil, NewError(ErrCodeDomainCertificationInvalid, fmt.Sprintf("domain %q missing, inactive, or mismatches certificationId %q", parsedCert.CredentialSubject.DomainID, parsedCert.ID))
		}
		certAnchor, ok := snap.Certifications[parsedCert.ID]
		if !ok || certAnchor.DeploymentID != snap.DeploymentID || certAnchor.Status != api.Active || !certAnchor.Interval.Current(now, margin) {
			return nil, NewError(ErrCodeDomainCertificationInvalid, fmt.Sprintf("on-chain certification %q missing, inactive, or expired", parsedCert.ID))
		}
		chainScopes := make([]IssuerScope, len(certAnchor.Scopes))
		for j, s := range certAnchor.Scopes {
			chainScopes[j] = IssuerScope{
				ID:              s.ID,
				AppKeyVersion:   s.KeyVersion,
				CredentialTypes: s.Types,
				ClaimNames:      s.Claims,
			}
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
			CertificationScope: chainScopes,
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
	parsedKB, err := ParseCompactJWS(leafVerCred.KBJWT, TypKeyBindingJWT)
	if err != nil {
		return nil, err
	}
	_, actorAuthPub, _, err := dids.ResolveDID(ctx, leafHolderID.ID, DIDResolutionExpectation{
		ExpectedDigest:       leafHolderID.DocumentDigest,
		ExpectedKeyID:        parsedKB.Header.Kid,
		ExpectedKeyVersion:   leafHolderID.KeyVersion,
		ExpectedPublicKeyHex: leafHolderID.PublicKey,
		RequiredPurpose:      KeyPurposeAuthentication,
	})
	if err != nil {
		return nil, err
	}
	if err := parsedKB.Verify(actorAuthPub, parsedKB.Header.Kid); err != nil {
		return nil, err
	}
	var kbClaims KBJWTClaims
	if err := DecodeStrictJSON(parsedKB.PayloadBytes, &kbClaims); err != nil {
		return nil, err
	}
	if _, err := ValidateNonce(kbClaims.Nonce); err != nil {
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

	return &VerifiedEvidenceResult{
		Bindings:       *bindings,
		LeafCredential: leafVerCred,
		AncestorCreds:  ancestorVerCreds,
		Grants:         parsedGrants,
		TrustPathCerts: trustByIssuer,
		KBClaims:       kbClaims,
		TaskSpecDigest: taskDigest,
	}, nil
}

// NBFWithin reports whether grant nbf/exp stays within interval i.
func (c GrantClaims) NBFWithin(i api.Interval) bool {
	return c.NBF >= i.NBF && c.EXP <= i.EXP
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
	if req.AmountMinor > g.MaxAmountMinor {
		return NewError(ErrCodeBindingMismatch, fmt.Sprintf("request amountMinor %d exceeds grant maxAmountMinor %d", req.AmountMinor, g.MaxAmountMinor))
	}
	if !slices.Contains(g.Resources, req.Resource) || !slices.Contains(g.Actions, req.Action) || !slices.Contains(g.Suppliers, req.SupplierID) {
		return NewError(ErrCodeGrantChainInvalid, "request resource/action/supplier outside leaf grant scope")
	}
	return nil
}

func matchGrantAnchor(c *GrantClaims, digest string, onChain api.Grant) error {
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
