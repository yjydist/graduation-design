package procurement

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/domain/wallet"
	"grad/platform/core/ledger"
	"grad/protocol"
	preg "grad/protocol/registry"
)

// GrantOperationsConfig configures GrantOperations for one domain deployment.
type GrantOperationsConfig struct {
	Deployment     *ledger.Deployment
	DomainID       string
	DB             *pgxpool.Pool
	Management     *domreg.Service
	Actors         map[string]GrantActor
	Certifications map[string]string
	Sync           func(context.Context) error
	Now            func() time.Time
}

// GrantOperations issues and receives workbench grants through the management
// transaction journal and the fixed checkpoint of the domain's replayed registry.
type GrantOperations struct {
	cfg      GrantOperationsConfig
	delivery *domreg.DeliveryService
	state    *ledger.StateProvider
	view     ledger.View
	root     *ecdsa.PublicKey
}

// NewGrantOperations validates cfg and constructs a GrantOperations instance.
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
		cfg:      cfg,
		root:     root,
		delivery: domreg.NewDeliveryService(cfg.DB, cfg.Deployment.DeploymentID),
		state:    ledger.NewStateProvider(cfg.DB, cfg.Deployment, nil),
		view:     ledger.View{DB: cfg.DB, Deployment: cfg.Deployment},
	}, nil
}

// Sync runs the configured registry sync hook when present.
func (g *GrantOperations) Sync(ctx context.Context) error {
	if g == nil || g.cfg.Sync == nil {
		return nil
	}
	return g.cfg.Sync(ctx)
}

// Now returns the current time from the configured clock.
func (g *GrantOperations) Now() time.Time {
	if g == nil || g.cfg.Now == nil {
		return time.Now()
	}
	return g.cfg.Now()
}

// ResolveRecipient resolves the active on-chain identity and credential binding for recipient.
func (g *GrantOperations) ResolveRecipient(ctx context.Context, recipient GrantRecipient) (wallet.GrantRecipient, error) {
	if err := g.Sync(ctx); err != nil {
		return wallet.GrantRecipient{}, err
	}
	read, err := ledger.ReadAppliedRegistry(ctx, g.cfg.DB, g.cfg.Deployment, recipientKeys(recipient))
	if err != nil {
		return wallet.GrantRecipient{}, err
	}
	id, _, err := g.participant(read, recipient, g.Now())
	if err != nil {
		return wallet.GrantRecipient{}, err
	}
	return wallet.GrantRecipient{DID: id.ID, KeyVersion: id.KeyVersion, CredentialID: recipient.CredentialID}, nil
}

func recipientKeys(r GrantRecipient) []string {
	return []string{preg.Key("identity", r.DID), preg.Key("credential", r.CredentialID)}
}

func grantRecord[T any](read *ledger.RegistryReadback, kind, id string) (T, error) {
	var rec T
	err := protocol.DecodeStrictJSON(read.Records[preg.Key(kind, id)], &rec)
	return rec, err
}

func (g *GrantOperations) participant(read *ledger.RegistryReadback, recipient GrantRecipient, now time.Time) (preg.Identity, preg.Credential, error) {
	id, err := grantRecord[preg.Identity](read, "identity", recipient.DID)
	if err != nil {
		return id, preg.Credential{}, err
	}
	cred, err := grantRecord[preg.Credential](read, "credential", recipient.CredentialID)
	if err != nil {
		return id, cred, err
	}
	if id.DeploymentID != g.cfg.Deployment.DeploymentID || cred.DeploymentID != id.DeploymentID ||
		id.Status != preg.Active || cred.Status != preg.Active || !cred.Interval.Current(now, 0) ||
		cred.Subject != id.ID || cred.SubjectKeyVersion != id.KeyVersion {
		return id, cred, protocol.NewError(preg.ErrCodeCredentialStatusInvalid, "participant lacks a current credential")
	}
	return id, cred, nil
}

func (g *GrantOperations) actor(name string) (GrantActor, error) {
	actor, ok := g.cfg.Actors[name]
	if !ok {
		return GrantActor{}, protocol.NewError(preg.ErrCodeIdentityManagementForbidden, "grant issuer is outside this domain deployment")
	}
	return actor, nil
}

// IssueRoot signs, journals, and publishes a root grant G0 once its original RegisterGrant commit is verified.
func (g *GrantOperations) IssueRoot(ctx context.Context, actor, key string, req RootGrantRequest) (*domreg.OperationView, *GrantDelivery, error) {
	if !preg.IsDigest(req.GrantID) || !preg.IsDigest(req.TaskID) || key == "" ||
		req.MaxAmountMinor <= 0 || req.MaxAmountMinor > protocol.MaxSafeInt || req.Depth < 0 || req.Depth > protocol.MaxGrantDepth {
		return nil, nil, protocol.NewError(preg.ErrCodeInvalidSchema, "invalid root grant scope or operation key")
	}
	issuer, err := g.actor(actor)
	if err != nil {
		return nil, nil, err
	}
	if err := g.Sync(ctx); err != nil {
		return nil, nil, err
	}
	now := g.Now().UTC()
	dep := g.cfg.Deployment
	keys := []string{preg.Key("task", req.TaskID), preg.Key("domain", dep.Bootstrap.TaskCreator.Domain)}
	keys = append(keys, recipientKeys(req.Recipient)...)
	keys = append(keys, recipientKeys(GrantRecipient{DID: issuer.Signer.DID, CredentialID: issuer.Signer.CredentialID})...)
	read, err := ledger.ReadAppliedRegistry(ctx, g.cfg.DB, dep, keys)
	if err != nil {
		return nil, nil, err
	}
	task, err := grantRecord[preg.Task](read, "task", req.TaskID)
	if err != nil {
		return nil, nil, err
	}
	ownerDomain, err := grantRecord[preg.Domain](read, "domain", dep.Bootstrap.TaskCreator.Domain)
	if err != nil {
		return nil, nil, err
	}
	digest, err := req.TaskSpec.Digest()
	if err != nil {
		return nil, nil, err
	}
	if task.Status != preg.Active || !task.Interval.Current(now, 0) {
		return nil, nil, protocol.NewError(preg.ErrCodeTaskInactive, "confirmed task is inactive or expired")
	}
	if task.Creator != req.Recipient.DID || task.CreatorCredential != req.Recipient.CredentialID ||
		task.Digest != digest || task.Domain != ownerDomain.ID || task.Resource != dep.Bootstrap.ResourceID {
		return nil, nil, protocol.NewError(preg.ErrCodeBindingMismatch, "root grant scope differs from confirmed task")
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
	case preg.RP:
		if issuerID.Domain != "C" || issuerID.Kind != "SERVICE" ||
			issuerID.ID != dep.Bootstrap.ResourceOwner || issuer.Management != dep.Bootstrap.ResourceManagement {
			return nil, nil, protocol.NewError(preg.ErrCodeRootAuthorityInvalid, "RP root issuer must be the resource service")
		}
	case preg.BM:
		if issuerID.Domain != task.Domain || issuerID.Kind != "SERVICE" || ownerDomain.Status != preg.Active ||
			issuerID.ID != ownerDomain.PurchasingAuthority {
			return nil, nil, protocol.NewError(preg.ErrCodePurchasingAuthorityInvalid, "BM root issuer must be the active purchasing authority")
		}
	default:
		return nil, nil, protocol.NewError(preg.ErrCodeBindingMismatch, "unknown task authorization mode")
	}
	if !task.Interval.Within(issuerCred.Interval) || !task.Interval.Within(granteeCred.Interval) {
		return nil, nil, protocol.NewError(preg.ErrCodeCredentialStatusInvalid, "task interval exceeds participant credential validity")
	}
	claims := protocol.GrantClaims{
		ID:                  req.GrantID,
		SchemaVersion:       protocol.SchemaVersion,
		DeploymentID:        dep.DeploymentID,
		RootID:              req.GrantID,
		TaskID:              task.ID,
		AuthorizationMode:   task.Mode,
		PrincipalDomain:     task.Domain,
		ResourceID:          task.Resource,
		Issuer:              issuerID.ID,
		Grantee:             grantee.ID,
		IssuerKeyVersion:    issuerID.KeyVersion,
		GranteeKeyVersion:   grantee.KeyVersion,
		IssuerCredentialID:  issuerCred.ID,
		GranteeCredentialID: granteeCred.ID,
		Resources:           slices.Clone(req.TaskSpec.Resources),
		Actions:             slices.Clone(req.TaskSpec.Actions),
		Suppliers:           []string{req.TaskSpec.SupplierID},
		Aud:                 DefaultAudience,
		Currency:            req.TaskSpec.Currency,
		MaxAmountMinor:      req.MaxAmountMinor,
		NBF:                 task.NBF,
		EXP:                 task.EXP,
		RemainingDepth:      int64(req.Depth),
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

func matchGrantActor(a GrantActor, id preg.Identity) error {
	s := a.Signer
	pub, err := protocol.FormatAppPublicKey(&s.PrivateKey.PublicKey)
	if err != nil {
		return err
	}
	if s.DID != id.ID || s.DomainID != id.Domain || s.KeyID != id.KeyID ||
		s.KeyVersion != id.KeyVersion || pub != id.PublicKey || a.Management != id.Management {
		return protocol.NewError(preg.ErrCodeBindingMismatch, "local grant issuer differs from current registry")
	}
	return nil
}

func requestHash(v any) (string, error) {
	raw, err := protocol.MarshalJCS(v)
	if err != nil {
		return "", err
	}
	return preg.Digest(raw), nil
}

// PublishChild journals a signed wallet delegation after rechecking its delivered parent.
func (g *GrantOperations) PublishChild(ctx context.Context, req wallet.AnchorChildGrantRequest) (*domreg.OperationView, *GrantDelivery, error) {
	c := req.Claims
	if !preg.IsDigest(c.ID) || c.ParentID == nil || *c.ParentID != req.ParentID || c.Grantee != req.GranteeDID ||
		c.DeploymentID != g.cfg.Deployment.DeploymentID || preg.Digest([]byte(req.RawGrantJWS)) != req.GrantDigest {
		return nil, nil, protocol.NewError(preg.ErrCodeBindingMismatch, "child grant differs from wallet request")
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
		return nil, nil, protocol.NewError(preg.ErrCodeBindingMismatch, "signed child differs from local issuer or claimed scope")
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
func (g *GrantOperations) ResumeChild(ctx context.Context, actor, grantID string) (*domreg.OperationView, *GrantDelivery, error) {
	issuer, err := g.actor(actor)
	if err != nil {
		return nil, nil, err
	}
	var raw, requestDigest string
	err = g.cfg.DB.QueryRow(ctx, `SELECT grant_jws, request_digest FROM workbench_grant_issue
		WHERE deployment_id=$1 AND domain_id=$2 AND grant_id=$3 AND issuer_did=$4 AND operation_key=$5`,
		g.cfg.Deployment.DeploymentID, g.cfg.DomainID, grantID, issuer.Signer.DID, ChildGrantOperationKey(grantID)).Scan(&raw, &requestDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, protocol.NewError(preg.ErrCodeMaterialNotSynced, "no signed child grant to resume")
	}
	if err != nil {
		return nil, nil, err
	}
	parsed, err := protocol.ParseAndVerifyGrant(raw, &issuer.Signer.PrivateKey.PublicKey, issuer.Signer.KeyID)
	if err != nil {
		return nil, nil, err
	}
	if parsed.Claims.ID != grantID || parsed.Claims.ParentID == nil {
		return nil, nil, protocol.NewError(preg.ErrCodeBindingMismatch, "stored child grant differs from original request")
	}
	return g.publishSignedChild(ctx, issuer, parsed, requestDigest)
}

func (g *GrantOperations) publishSignedChild(ctx context.Context, issuer GrantActor, parsed *protocol.ParsedGrant, requestDigest string) (*domreg.OperationView, *GrantDelivery, error) {
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
func (g *GrantOperations) AnchorChild(ctx context.Context, req wallet.AnchorChildGrantRequest) (*wallet.AnchorChildGrantResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		op, delivery, err := g.PublishChild(ctx, req)
		if err != nil && !protocol.HasCode(err, preg.ErrCodeMaterialNotSynced) {
			return nil, err
		}
		if delivery != nil {
			bundle, err := g.bundle(ctx, delivery.Package, true)
			if err != nil {
				return nil, err
			}
			return &wallet.AnchorChildGrantResult{Anchored: true, Grant: &bundle}, nil
		}
		if op != nil && op.Status == "FAILED" {
			code := preg.ErrCodeCommitInvalid
			if op.FailureCode != nil {
				code = *op.FailureCode
			}
			return nil, protocol.NewError(code, "child grant transaction failed")
		}
		select {
		case <-ctx.Done():
			return nil, protocol.WrapError(preg.ErrCodeMaterialNotSynced, "child grant is awaiting original confirmation or delivery", ctx.Err())
		case <-tick.C:
		}
	}
}

func (g *GrantOperations) issue(ctx context.Context, issuer GrantActor, key, requestDigest, grantID, raw string, spec protocol.TaskSpec, ancestorGrants []string, ancestorCredentials []protocol.AncestorCredential) (*domreg.OperationView, *GrantDelivery, error) {
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
		return nil, nil, protocol.NewError(preg.ErrCodeIdempotencyConflict, "grant ID or operation key has another issuance request")
	}
	if err != nil {
		return nil, nil, err
	}
	p, err := protocol.ParseAndVerifyGrant(storedJWS, &issuer.Signer.PrivateKey.PublicKey, issuer.Signer.KeyID)
	if err != nil {
		return nil, nil, err
	}
	anchor := LedgerGrant(p)
	op, err := g.cfg.Management.Submit(ctx, issuer.Management, "RegisterGrant", storedKey, anchor)
	if err != nil || op.Status != "CONFIRMED" {
		return op, nil, err
	}
	pkg := domreg.GrantDeliveryPackage{
		DeploymentID:        dep,
		Recipient:           p.Claims.Grantee,
		GrantID:             grantID,
		GrantJWS:            storedJWS,
		TaskSpec:            spec,
		ServicePresentation: issuer.Signer.SDJWTPresentation,
		AncestorGrants:      ancestorGrants,
		AncestorCredentials: ancestorCredentials,
	}
	return g.publish(ctx, op, pkg)
}

// LedgerGrant projects a parsed signed grant into its on-chain registry.Grant anchor representation.
func LedgerGrant(parsed *protocol.ParsedGrant) preg.Grant {
	c := parsed.Claims
	g := preg.Grant{
		Bound:             preg.Bound{DeploymentID: c.DeploymentID},
		ID:                c.ID,
		Schema:            preg.Schema,
		Root:              c.RootID,
		Task:              c.TaskID,
		Mode:              c.AuthorizationMode,
		Domain:            c.PrincipalDomain,
		Resource:          c.ResourceID,
		Issuer:            c.Issuer,
		Grantee:           c.Grantee,
		IssuerKeyVersion:  c.IssuerKeyVersion,
		GranteeKeyVersion: c.GranteeKeyVersion,
		IssuerCredential:  c.IssuerCredentialID,
		GranteeCredential: c.GranteeCredentialID,
		Depth:             uint8(c.RemainingDepth),
		Digest:            parsed.Digest,
		Interval:          preg.Interval{NBF: c.NBF, EXP: c.EXP},
	}
	if c.ParentID != nil {
		g.Parent = *c.ParentID
	}
	if c.ParentDigest != nil {
		g.ParentDigest = *c.ParentDigest
	}
	return g
}

// SyncCertifications publishes and receipts domain certification JWS documents for A, B, and C
// against the locally applied registry view using ledger.View.FirstVersionCommit.
func SyncCertifications(
	ctx context.Context,
	db *pgxpool.Pool,
	dep *ledger.Deployment,
	localDomainID string,
	rawCerts map[string]string,
	now time.Time,
) (map[string]string, error) {
	if db == nil || dep == nil {
		return nil, protocol.NewError(preg.ErrCodeStateUnavailable, "database and deployment required for certification sync")
	}
	if now.IsZero() {
		now = time.Now()
	}
	domainKeys := []string{preg.Key("domain", "A"), preg.Key("domain", "B"), preg.Key("domain", "C")}
	read, err := ledger.ReadAppliedRegistry(ctx, db, dep, domainKeys)
	if err != nil {
		return nil, err
	}
	snap := &protocol.SnapshotView{
		DeploymentID:   dep.DeploymentID,
		Root:           read.Root,
		Height:         read.Number,
		Now:            now,
		ClockError:     preg.ClockError,
		Domains:        map[string]preg.Domain{},
		Certifications: map[string]preg.Certification{},
		Identities:     map[string]preg.Identity{},
	}
	keys := slices.Clone(domainKeys)
	var issuerKeys []string
	for _, key := range domainKeys {
		var item preg.Domain
		if err := json.Unmarshal(read.Records[key], &item); err != nil {
			return nil, err
		}
		keys = append(keys, preg.Key("certification", item.Certification))
		for _, issuer := range item.Issuers {
			issuerKeys = append(issuerKeys, preg.Key("identity", issuer))
		}
	}
	read, err = ledger.ReadAppliedRegistry(ctx, db, dep, append(keys, issuerKeys...))
	if err != nil {
		return nil, err
	}
	for i, key := range domainKeys {
		var domain preg.Domain
		var cert preg.Certification
		if err := json.Unmarshal(read.Records[key], &domain); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(read.Records[keys[i+len(domainKeys)]], &cert); err != nil {
			return nil, err
		}
		if domain.Certification != cert.ID {
			return nil, fmt.Errorf("domain certification changed during workbench startup")
		}
		snap.Domains[domain.ID], snap.Certifications[cert.ID] = domain, cert
	}
	for _, key := range issuerKeys {
		var issuer preg.Identity
		if err := json.Unmarshal(read.Records[key], &issuer); err != nil {
			return nil, err
		}
		snap.Identities[issuer.ID] = issuer
	}
	root, err := protocol.ParseAppPublicKey(dep.Bootstrap.Root.PublicKey)
	if err != nil {
		return nil, err
	}
	view := ledger.View{DB: db, Deployment: dep}
	ds := domreg.NewDeliveryService(db, dep.DeploymentID)
	certs := make(map[string]string, 3)
	recipient := "did:web:" + strings.ToLower(localDomainID) + ".local"
	nowSec := now.Unix()
	for _, domain := range []string{"A", "B", "C"} {
		raw := rawCerts[domain]
		if raw == "" {
			return nil, protocol.NewError(preg.ErrCodeMaterialNotSynced, fmt.Sprintf("missing raw certification JWS for domain %s", domain))
		}
		certID := snap.Domains[domain].Certification
		txID, block, found, err := view.FirstVersionCommit(ctx, preg.Key("certification", certID), 0)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, protocol.NewError(preg.ErrCodeMaterialNotSynced, "original certification transaction is absent from the local applied view")
		}
		certs[domain] = raw
		if err := ds.PublishDomainCertification(ctx, snap, recipient, domain, raw, root, txID, block, true, nowSec); err != nil {
			return nil, err
		}
		if _, err := ds.SyncCertificationReceipt(ctx, snap, recipient, domain, root, nowSec); err != nil {
			return nil, err
		}
	}
	return certs, nil
}

// SyncCertifications syncs the configured domain certification JWS documents for this GrantOperations instance.
func (g *GrantOperations) SyncCertifications(ctx context.Context) error {
	_, err := SyncCertifications(ctx, g.cfg.DB, g.cfg.Deployment, g.cfg.DomainID, g.cfg.Certifications, g.Now())
	return err
}
