package runtime

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/agent"
	"grad/platform/registrysvc"
	"grad/platform/state/fabric"
	"grad/protocol"
	"grad/protocol/registry"
)

// GrantActor is one locally configured grant issuer.
type GrantActor struct {
	Signer     agent.Signer
	Management registry.Management
}

// GrantRecipient identifies the intended recipient and credential.
type GrantRecipient struct {
	DID          string `json:"did"`
	CredentialID string `json:"credentialId"`
}

type GrantOperationsConfig struct {
	Deployment     *fabric.Deployment
	DomainID       string
	DB             *pgxpool.Pool
	Management     *registrysvc.Service
	Actors         map[string]GrantActor
	Certifications map[string]string
	Sync           func(context.Context) error
	Now            func() time.Time
}

// GrantOperations issues and receives actual workbench grants through the management
// transaction journal and the fixed checkpoint of the domain's replayed registry.
type GrantOperations struct {
	cfg      GrantOperationsConfig
	delivery *registrysvc.DeliveryService
	state    *fabric.StateProvider
	root     *ecdsa.PublicKey
}

type RootGrantRequest struct {
	GrantID        string            `json:"grantId"`
	TaskID         string            `json:"taskId"`
	Recipient      GrantRecipient    `json:"recipient"`
	TaskSpec       protocol.TaskSpec `json:"taskSpec"`
	MaxAmountMinor int64             `json:"maxAmountMinor"`
	Depth          int               `json:"depth"`
}

// GrantDelivery travels only on the authenticated service channel. Package
// contains signed grants and the selectively disclosed credentials for this path.
type GrantDelivery struct {
	Operation registrysvc.OperationView        `json:"operation"`
	Package   registrysvc.GrantDeliveryPackage `json:"package"`
	Digest    string                           `json:"digest"`
}

func NewGrantOperations(cfg GrantOperationsConfig) (*GrantOperations, error) {
	if cfg.Deployment == nil || cfg.Deployment.DeploymentID == "" || cfg.DB == nil || cfg.Management == nil ||
		(cfg.DomainID != "A" && cfg.DomainID != "B" && cfg.DomainID != "C") {
		return nil, errors.New("grant operations require a deployment, domain, database and management service")
	}
	cfg.Actors = maps.Clone(cfg.Actors)
	cfg.Certifications = maps.Clone(cfg.Certifications)
	for name, a := range cfg.Actors {
		s := a.Signer
		if name != s.Actor || s.DomainID != cfg.DomainID || s.DID == "" || s.PrivateKey == nil ||
			s.KeyID == "" || s.KeyVersion == 0 || s.CredentialID == "" || s.SDJWTPresentation == "" || !a.Management.Valid() {
			return nil, fmt.Errorf("invalid local grant issuer %q", name)
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	root, err := protocol.ParseAppPublicKey(cfg.Deployment.Bootstrap.Root.PublicKey)
	if err != nil {
		return nil, err
	}
	return &GrantOperations{
		cfg: cfg, root: root,
		delivery: registrysvc.NewDeliveryService(cfg.DB, cfg.Deployment.DeploymentID),
		state:    fabric.NewStateProvider(cfg.DB, cfg.Deployment, nil),
	}, nil
}

func (g *GrantOperations) sync(ctx context.Context) error {
	if g.cfg.Sync == nil {
		return nil
	}
	return g.cfg.Sync(ctx)
}

func (g *GrantOperations) ResolveRecipient(ctx context.Context, recipient GrantRecipient) (agent.GrantRecipient, error) {
	if err := g.sync(ctx); err != nil {
		return agent.GrantRecipient{}, err
	}
	read, err := fabric.ReadAppliedRegistry(ctx, g.cfg.DB, g.cfg.Deployment, recipientKeys(recipient))
	if err != nil {
		return agent.GrantRecipient{}, err
	}
	id, _, err := g.participant(read, recipient, g.cfg.Now())
	if err != nil {
		return agent.GrantRecipient{}, err
	}
	return agent.GrantRecipient{DID: id.ID, KeyVersion: id.KeyVersion, CredentialID: recipient.CredentialID}, nil
}

func recipientKeys(r GrantRecipient) []string {
	return []string{registry.Key("identity", r.DID), registry.Key("credential", r.CredentialID)}
}

func grantRecord[T any](read *fabric.RegistryReadback, kind, id string) (T, error) {
	var rec T
	err := protocol.DecodeStrictJSON(read.Records[registry.Key(kind, id)], &rec)
	return rec, err
}

func (g *GrantOperations) participant(read *fabric.RegistryReadback, recipient GrantRecipient, now time.Time) (registry.Identity, registry.Credential, error) {
	id, err := grantRecord[registry.Identity](read, "identity", recipient.DID)
	if err != nil {
		return id, registry.Credential{}, err
	}
	cred, err := grantRecord[registry.Credential](read, "credential", recipient.CredentialID)
	if err != nil {
		return id, cred, err
	}
	if id.DeploymentID != g.cfg.Deployment.DeploymentID || cred.DeploymentID != id.DeploymentID ||
		id.Status != registry.Active || cred.Status != registry.Active || !cred.Interval.Current(now, 0) ||
		cred.Subject != id.ID || cred.SubjectKeyVersion != id.KeyVersion {
		return id, cred, protocol.NewError(registry.ErrCodeCredentialStatusInvalid, "participant lacks a current credential")
	}
	return id, cred, nil
}

func (g *GrantOperations) actor(name string) (GrantActor, error) {
	actor, ok := g.cfg.Actors[name]
	if !ok {
		return GrantActor{}, protocol.NewError(registry.ErrCodeIdentityManagementForbidden, "grant issuer is outside this domain deployment")
	}
	return actor, nil
}

func (g *GrantOperations) IssueRoot(ctx context.Context, actor, key string, req RootGrantRequest) (*registrysvc.OperationView, *GrantDelivery, error) {
	if !registry.IsDigest(req.GrantID) || !registry.IsDigest(req.TaskID) || key == "" ||
		req.MaxAmountMinor <= 0 || req.MaxAmountMinor > protocol.MaxSafeInt || req.Depth < 0 || req.Depth > protocol.MaxGrantDepth {
		return nil, nil, protocol.NewError(registry.ErrCodeInvalidSchema, "invalid root grant scope or operation key")
	}
	issuer, err := g.actor(actor)
	if err != nil {
		return nil, nil, err
	}
	if err := g.sync(ctx); err != nil {
		return nil, nil, err
	}
	now := g.cfg.Now().UTC()
	dep := g.cfg.Deployment
	keys := []string{registry.Key("task", req.TaskID), registry.Key("domain", dep.Bootstrap.TaskCreator.Domain)}
	keys = append(keys, recipientKeys(req.Recipient)...)
	keys = append(keys, recipientKeys(GrantRecipient{DID: issuer.Signer.DID, CredentialID: issuer.Signer.CredentialID})...)
	read, err := fabric.ReadAppliedRegistry(ctx, g.cfg.DB, dep, keys)
	if err != nil {
		return nil, nil, err
	}
	task, err := grantRecord[registry.Task](read, "task", req.TaskID)
	if err != nil {
		return nil, nil, err
	}
	ownerDomain, err := grantRecord[registry.Domain](read, "domain", dep.Bootstrap.TaskCreator.Domain)
	if err != nil {
		return nil, nil, err
	}
	digest, err := req.TaskSpec.Digest()
	if err != nil {
		return nil, nil, err
	}
	if task.Status != registry.Active || !task.Interval.Current(now, 0) {
		return nil, nil, protocol.NewError(registry.ErrCodeTaskInactive, "confirmed task is inactive or expired")
	}
	if task.Creator != req.Recipient.DID || task.CreatorCredential != req.Recipient.CredentialID ||
		task.Digest != digest || task.Domain != ownerDomain.ID || task.Resource != dep.Bootstrap.ResourceID {
		return nil, nil, protocol.NewError(registry.ErrCodeBindingMismatch, "root grant scope differs from confirmed task")
	}
	issuerID, issuerCred, err := g.participant(read, GrantRecipient{DID: issuer.Signer.DID, CredentialID: issuer.Signer.CredentialID}, now)
	if err != nil {
		return nil, nil, err
	}
	grantee, granteeCred, err := g.participant(read, req.Recipient, now)
	if err != nil {
		return nil, nil, err
	}
	if err := matchGrantActor(issuer, issuerID); err != nil {
		return nil, nil, err
	}
	switch task.Mode {
	case registry.RP:
		if issuerID.Domain != "C" || issuerID.Kind != "SERVICE" ||
			issuerID.ID != dep.Bootstrap.ResourceOwner || issuer.Management != dep.Bootstrap.ResourceManagement {
			return nil, nil, protocol.NewError(registry.ErrCodeRootAuthorityInvalid, "RP root issuer must be the resource service")
		}
	case registry.BM:
		if issuerID.Domain != task.Domain || issuerID.Kind != "SERVICE" || ownerDomain.Status != registry.Active ||
			issuerID.ID != ownerDomain.PurchasingAuthority {
			return nil, nil, protocol.NewError(registry.ErrCodePurchasingAuthorityInvalid, "BM root issuer must be the active purchasing authority")
		}
	default:
		return nil, nil, protocol.NewError(registry.ErrCodeBindingMismatch, "unknown task authorization mode")
	}
	if !task.Interval.Within(issuerCred.Interval) || !task.Interval.Within(granteeCred.Interval) {
		return nil, nil, protocol.NewError(registry.ErrCodeCredentialStatusInvalid, "task interval exceeds participant credential validity")
	}
	claims := protocol.GrantClaims{
		ID: req.GrantID, SchemaVersion: protocol.SchemaVersion, DeploymentID: dep.DeploymentID, RootID: req.GrantID,
		TaskID: task.ID, AuthorizationMode: task.Mode, PrincipalDomain: task.Domain, ResourceID: task.Resource,
		Issuer: issuerID.ID, Grantee: grantee.ID, IssuerKeyVersion: issuerID.KeyVersion, GranteeKeyVersion: grantee.KeyVersion,
		IssuerCredentialID: issuerCred.ID, GranteeCredentialID: granteeCred.ID,
		Resources: slices.Clone(req.TaskSpec.Resources), Actions: slices.Clone(req.TaskSpec.Actions),
		Suppliers: []string{req.TaskSpec.SupplierID}, Aud: defaultAudience, Currency: req.TaskSpec.Currency,
		MaxAmountMinor: req.MaxAmountMinor, NBF: task.NBF, EXP: task.EXP, RemainingDepth: int64(req.Depth),
	}
	raw, _, err := protocol.SignGrant(issuer.Signer.PrivateKey, issuer.Signer.KeyID, &claims)
	if err != nil {
		return nil, nil, err
	}
	requestDigest, err := requestHash(req)
	if err != nil {
		return nil, nil, err
	}
	return g.issue(ctx, issuer, key, requestDigest, req.GrantID, raw, req.TaskSpec, nil, nil)
}

func matchGrantActor(a GrantActor, id registry.Identity) error {
	s := a.Signer
	pub, err := protocol.FormatAppPublicKey(&s.PrivateKey.PublicKey)
	if err != nil {
		return err
	}
	if s.DID != id.ID || s.DomainID != id.Domain || s.KeyID != id.KeyID ||
		s.KeyVersion != id.KeyVersion || pub != id.PublicKey || a.Management != id.Management {
		return protocol.NewError(registry.ErrCodeBindingMismatch, "local grant issuer differs from current registry")
	}
	return nil
}

func requestHash(v any) (string, error) {
	raw, err := protocol.MarshalJCS(v)
	if err != nil {
		return "", err
	}
	return registry.Digest(raw), nil
}

// PublishChild journals a signed wallet delegation after rechecking its delivered parent.
func (g *GrantOperations) PublishChild(ctx context.Context, req agent.AnchorChildGrantRequest) (*registrysvc.OperationView, *GrantDelivery, error) {
	c := req.Claims
	if !registry.IsDigest(c.ID) || c.ParentID == nil || *c.ParentID != req.ParentID || c.Grantee != req.GranteeDID ||
		c.DeploymentID != g.cfg.Deployment.DeploymentID || registry.Digest([]byte(req.RawGrantJWS)) != req.GrantDigest {
		return nil, nil, protocol.NewError(registry.ErrCodeBindingMismatch, "child grant differs from wallet request")
	}
	issuer, err := g.actor(req.IssuerActor)
	if err != nil {
		return nil, nil, err
	}
	pub := &issuer.Signer.PrivateKey.PublicKey
	parsed, err := protocol.ParseAndVerifyGrant(req.RawGrantJWS, pub, issuer.Signer.KeyID)
	if err != nil {
		return nil, nil, err
	}
	left, err := requestHash(c)
	if err != nil {
		return nil, nil, err
	}
	right, err := requestHash(parsed.Claims)
	if err != nil {
		return nil, nil, err
	}
	if left != right || c.Issuer != issuer.Signer.DID || c.IssuerCredentialID != issuer.Signer.CredentialID ||
		c.IssuerKeyVersion != issuer.Signer.KeyVersion {
		return nil, nil, protocol.NewError(registry.ErrCodeBindingMismatch, "signed child differs from local issuer or claimed scope")
	}
	// A repeated wallet operation may generate new signature bytes and a new
	// signing timestamp. Bind the original request terms, then reuse its JWS.
	c.NBF, c.EXP = 0, 0
	requestDigest, err := requestHash(struct {
		Claims   protocol.GrantClaims `json:"claims"`
		Lifetime int64                `json:"lifetime"`
	}{Claims: c, Lifetime: req.RequestedLifetimeSeconds})
	if err != nil {
		return nil, nil, err
	}
	return g.publishSignedChild(ctx, issuer, parsed, requestDigest)
}

// ResumeChild continues a previously signed child grant with its original bytes
// and operation key, independently of the wallet process or model response.
func (g *GrantOperations) ResumeChild(ctx context.Context, actor, grantID string) (*registrysvc.OperationView, *GrantDelivery, error) {
	issuer, err := g.actor(actor)
	if err != nil {
		return nil, nil, err
	}
	var raw, requestDigest string
	err = g.cfg.DB.QueryRow(ctx, `SELECT grant_jws, request_digest FROM workbench_grant_issue
		WHERE deployment_id=$1 AND domain_id=$2 AND grant_id=$3 AND issuer_did=$4 AND operation_key=$5`,
		g.cfg.Deployment.DeploymentID, g.cfg.DomainID, grantID, issuer.Signer.DID, ChildGrantOperationKey(grantID)).Scan(&raw, &requestDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, protocol.NewError(registry.ErrCodeMaterialNotSynced, "no signed child grant to resume")
	}
	if err != nil {
		return nil, nil, err
	}
	parsed, err := protocol.ParseAndVerifyGrant(raw, &issuer.Signer.PrivateKey.PublicKey, issuer.Signer.KeyID)
	if err != nil {
		return nil, nil, err
	}
	if parsed.Claims.ID != grantID || parsed.Claims.ParentID == nil {
		return nil, nil, protocol.NewError(registry.ErrCodeBindingMismatch, "stored child grant differs from original request")
	}
	return g.publishSignedChild(ctx, issuer, parsed, requestDigest)
}

func (g *GrantOperations) publishSignedChild(ctx context.Context, issuer GrantActor, parsed *protocol.ParsedGrant, requestDigest string) (*registrysvc.OperationView, *GrantDelivery, error) {
	c := parsed.Claims
	parentID := *c.ParentID
	parent, err := g.Load(ctx, GrantRecipient{DID: c.Issuer, CredentialID: c.IssuerCredentialID}, parentID)
	if err != nil {
		return nil, nil, err
	}
	path, err := g.grantSnapshot(ctx, parentID)
	if err != nil {
		return nil, nil, err
	}
	if err := matchGrantActor(issuer, path.Identities[c.Issuer]); err != nil {
		return nil, nil, err
	}
	chain, err := parseDeliveryChain(path, parent.ChainRawGrants, true)
	if err != nil {
		return nil, nil, err
	}
	if err := protocol.VerifyGrantChain(append(chain, parsed)); err != nil {
		return nil, nil, err
	}
	return g.issue(ctx, issuer, ChildGrantOperationKey(c.ID), requestDigest, c.ID, parsed.Raw, parent.TaskSpec, parent.ChainRawGrants, parent.AncestorCredentials)
}

// ChildGrantOperationKey derives the stable submission key from a child grant ID.
func ChildGrantOperationKey(grantID string) string { return "workbench-child/" + grantID }

// AnchorChild waits for the original transaction and verified publication. All
// retries re-read the same signed payload and operation from durable storage.
func (g *GrantOperations) AnchorChild(ctx context.Context, req agent.AnchorChildGrantRequest) (*agent.AnchorChildGrantResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		op, delivery, err := g.PublishChild(ctx, req)
		if err != nil && !protocol.HasCode(err, registry.ErrCodeMaterialNotSynced) {
			return nil, err
		}
		if delivery != nil {
			bundle, err := g.bundle(ctx, delivery.Package, true)
			if err != nil {
				return nil, err
			}
			return &agent.AnchorChildGrantResult{Anchored: true, Grant: &bundle}, nil
		}
		if op != nil && op.Status == "FAILED" {
			code := registry.ErrCodeCommitInvalid
			if op.FailureCode != nil {
				code = *op.FailureCode
			}
			return nil, protocol.NewError(code, "child grant transaction failed")
		}
		select {
		case <-ctx.Done():
			return nil, protocol.WrapError(registry.ErrCodeMaterialNotSynced, "child grant is awaiting original confirmation or delivery", ctx.Err())
		case <-tick.C:
		}
	}
}

func (g *GrantOperations) issue(ctx context.Context, issuer GrantActor, key, requestDigest, grantID, raw string, spec protocol.TaskSpec, ancestorGrants []string, ancestorCredentials []protocol.AncestorCredential) (*registrysvc.OperationView, *GrantDelivery, error) {
	dep := g.cfg.Deployment.DeploymentID
	_, err := g.cfg.DB.Exec(ctx, `INSERT INTO workbench_grant_issue
		(deployment_id, domain_id, grant_id, issuer_did, operation_key, request_digest, grant_jws)
		VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
		dep, g.cfg.DomainID, grantID, issuer.Signer.DID, key, requestDigest, raw)
	if err != nil {
		return nil, nil, err
	}
	var storedKey, storedDID, storedDigest, storedJWS string
	err = g.cfg.DB.QueryRow(ctx, `SELECT operation_key, issuer_did, request_digest, grant_jws
		FROM workbench_grant_issue WHERE deployment_id=$1 AND domain_id=$2 AND grant_id=$3`,
		dep, g.cfg.DomainID, grantID).Scan(&storedKey, &storedDID, &storedDigest, &storedJWS)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (storedKey != key || storedDID != issuer.Signer.DID || storedDigest != requestDigest)) {
		return nil, nil, protocol.NewError(registry.ErrCodeIdempotencyConflict, "grant ID or operation key has another issuance request")
	}
	if err != nil {
		return nil, nil, err
	}
	p, err := protocol.ParseAndVerifyGrant(storedJWS, &issuer.Signer.PrivateKey.PublicKey, issuer.Signer.KeyID)
	if err != nil {
		return nil, nil, err
	}
	anchor := ledgerGrant(p)
	op, err := g.cfg.Management.Submit(ctx, issuer.Management, "RegisterGrant", storedKey, anchor)
	if err != nil || op.Status != "CONFIRMED" {
		return op, nil, err
	}
	pkg := registrysvc.GrantDeliveryPackage{
		DeploymentID: dep, Recipient: p.Claims.Grantee, GrantID: grantID, GrantJWS: storedJWS, TaskSpec: spec,
		ServicePresentation: issuer.Signer.SDJWTPresentation, AncestorGrants: ancestorGrants, AncestorCredentials: ancestorCredentials,
	}
	return g.publish(ctx, op, pkg)
}

func ledgerGrant(parsed *protocol.ParsedGrant) registry.Grant {
	c := parsed.Claims
	g := registry.Grant{
		Bound: registry.Bound{DeploymentID: c.DeploymentID},
		ID:    c.ID, Schema: registry.Schema, Root: c.RootID, Task: c.TaskID, Mode: c.AuthorizationMode,
		Domain: c.PrincipalDomain, Resource: c.ResourceID, Issuer: c.Issuer, Grantee: c.Grantee,
		IssuerKeyVersion: c.IssuerKeyVersion, GranteeKeyVersion: c.GranteeKeyVersion,
		IssuerCredential: c.IssuerCredentialID, GranteeCredential: c.GranteeCredentialID,
		Depth: uint8(c.RemainingDepth), Digest: parsed.Digest, Interval: registry.Interval{NBF: c.NBF, EXP: c.EXP},
	}
	if c.ParentID != nil {
		g.Parent = *c.ParentID
	}
	if c.ParentDigest != nil {
		g.ParentDigest = *c.ParentDigest
	}
	return g
}
