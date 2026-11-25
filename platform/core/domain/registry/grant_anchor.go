package registry

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/core/ledger"
	"grad/protocol"
	preg "grad/protocol/registry"
)

// IssuerDeliveryMaterial holds the issuer and domain verification material required
// to publish a grant outbox entry and deliver a wallet receipt after on-chain anchoring.
type IssuerDeliveryMaterial struct {
	DomainID               string
	IssuerPublicKey        *ecdsa.PublicKey
	CredentialIssuerPubKey *ecdsa.PublicKey
	ServicePresentation    string
	DomainCertificationJWS string
}

// GrantAnchorConfig configures GrantAnchorService for anchoring delegated and replacement
// grants on Fabric and synchronizing controlled outbox/receipt deliveries.
type GrantAnchorConfig struct {
	Instance        *ledger.Instance
	DB              *pgxpool.Pool
	Deployment      *ledger.Deployment
	DeploymentID    string
	RootPublicKey   *ecdsa.PublicKey
	WriteOperation  func(ctx context.Context, key, role, method string, raw []byte) (*ledger.Operation, error)
	AwaitEndorsers  func(ctx context.Context, commit ledger.Outcome) error
	Delivery        *DeliveryService
	TaskSpec        protocol.TaskSpec
	SnapshotBuilder func(time.Time) *protocol.SnapshotView
	ResolveIssuer   func(actor string) (IssuerDeliveryMaterial, bool, error)
	Now             func() time.Time
}

// AnchorGrantRequest contains the signed child grant material to anchor via RegisterGrant.
type AnchorGrantRequest struct {
	Claims      protocol.GrantClaims
	RawGrantJWS string
	GrantDigest string
	ParentID    string
	IssuerActor string
}

// ReplaceGrantAnchorRequest contains the old grant reference and signed replacement grant
// material to atomically submit via ReplaceGrant.
type ReplaceGrantAnchorRequest struct {
	OldGrantID       string
	OldGrantRevision uint64
	OldGrantDigest   string
	NewClaims        protocol.GrantClaims
	NewRawGrantJWS   string
	NewGrantDigest   string
	IssuerActor      string
	Reason           string
}

// AnchorGrantResult reports the committed chain grant and original ledger operation.
type AnchorGrantResult struct {
	Anchored  bool
	Grant     preg.Grant
	Operation *ledger.Operation
}

// GrantAnchorService coordinates chain grant construction, original-txID submission via
// ledger.Journal, endorser commit awaiting, and controlled grant outbox/receipt delivery.
type GrantAnchorService struct {
	deploymentID    string
	rootPub         *ecdsa.PublicKey
	writeOp         func(ctx context.Context, key, role, method string, raw []byte) (*ledger.Operation, error)
	awaitEndorsers  func(ctx context.Context, commit ledger.Outcome) error
	deliver         *DeliveryService
	taskSpec        protocol.TaskSpec
	snapshotBuilder func(time.Time) *protocol.SnapshotView
	resolveIssuer   func(actor string) (IssuerDeliveryMaterial, bool, error)
	now             func() time.Time
}

// NewGrantAnchorService validates cfg and constructs a GrantAnchorService.
// When Instance, DB, and Deployment are supplied, missing journal, endorser, root key,
// and DeliveryService bindings default to the standard Fabric journal and PostgreSQL store.
func NewGrantAnchorService(cfg GrantAnchorConfig) (*GrantAnchorService, error) {
	depID := strings.TrimSpace(cfg.DeploymentID)
	if depID == "" && cfg.Deployment != nil {
		depID = strings.TrimSpace(cfg.Deployment.DeploymentID)
	}
	if depID == "" {
		return nil, errors.New("registry: deploymentId is required for GrantAnchorService")
	}

	rootPub := cfg.RootPublicKey
	if rootPub == nil && cfg.Deployment != nil && strings.TrimSpace(cfg.Deployment.Bootstrap.Root.PublicKey) != "" {
		var err error
		rootPub, err = protocol.ParseAppPublicKey(cfg.Deployment.Bootstrap.Root.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("registry: parse root public key: %w", err)
		}
	}

	writeOp := cfg.WriteOperation
	if writeOp == nil && cfg.Instance != nil && cfg.DB != nil {
		journal := ledger.NewJournal(cfg.Instance, cfg.DB, depID)
		writeOp = journal.Write
	}
	if writeOp == nil {
		return nil, errors.New("registry: ledger journal writer is required for GrantAnchorService")
	}

	awaitEndorsers := cfg.AwaitEndorsers
	if awaitEndorsers == nil && cfg.Instance != nil {
		awaitEndorsers = cfg.Instance.AwaitEndorsers
	}

	deliver := cfg.Delivery
	if deliver == nil && cfg.DB != nil {
		deliver = NewDeliveryService(cfg.DB, depID)
	}

	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	return &GrantAnchorService{
		deploymentID:    depID,
		rootPub:         rootPub,
		writeOp:         writeOp,
		awaitEndorsers:  awaitEndorsers,
		deliver:         deliver,
		taskSpec:        cfg.TaskSpec,
		snapshotBuilder: cfg.SnapshotBuilder,
		resolveIssuer:   cfg.ResolveIssuer,
		now:             nowFn,
	}, nil
}

// BuildChainGrant maps signed protocol.GrantClaims and its JWS digest into the on-chain
// registry.Grant anchor record for deploymentID.
func BuildChainGrant(deploymentID string, claims protocol.GrantClaims, digest, parentOverride string) preg.Grant {
	parentID, parentDigest := parentOverride, ""
	if claims.ParentID != nil && *claims.ParentID != "" {
		parentID = *claims.ParentID
	}
	if claims.ParentDigest != nil {
		parentDigest = *claims.ParentDigest
	}
	return preg.Grant{
		Bound:             preg.Bound{DeploymentID: deploymentID},
		ID:                claims.ID,
		Schema:            preg.Schema,
		Parent:            parentID,
		ParentDigest:      parentDigest,
		Root:              claims.RootID,
		Task:              claims.TaskID,
		Mode:              claims.AuthorizationMode,
		Domain:            claims.PrincipalDomain,
		Resource:          claims.ResourceID,
		Issuer:            claims.Issuer,
		Grantee:           claims.Grantee,
		IssuerKeyVersion:  claims.IssuerKeyVersion,
		GranteeKeyVersion: claims.GranteeKeyVersion,
		IssuerCredential:  claims.IssuerCredentialID,
		GranteeCredential: claims.GranteeCredentialID,
		Depth:             uint8(claims.RemainingDepth),
		Digest:            digest,
		Interval:          preg.Interval{NBF: claims.NBF, EXP: claims.EXP},
	}
}

// AnchorGrant submits RegisterGrant using a deterministic original-txID key, awaits endorser
// commit visibility, and publishes controlled outbox/receipt delivery when configured.
func (s *GrantAnchorService) AnchorGrant(ctx context.Context, req AnchorGrantRequest) (*AnchorGrantResult, error) {
	if s == nil {
		return nil, errors.New("registry: GrantAnchorService is nil")
	}
	if strings.TrimSpace(req.Claims.ID) == "" || strings.TrimSpace(req.IssuerActor) == "" {
		return nil, protocol.NewError(preg.ErrCodeInvalidSchema, "grant id and issuerActor are required")
	}
	chainGrant := BuildChainGrant(s.deploymentID, req.Claims, req.GrantDigest, req.ParentID)
	raw, err := json.Marshal(chainGrant)
	if err != nil {
		return nil, err
	}
	opKey := "mcp-anchor/" + preg.Digest([]byte(req.Claims.ID))[:24]
	op, err := s.writeOp(ctx, opKey, req.IssuerActor, "RegisterGrant", raw)
	if err != nil {
		return nil, err
	}
	if err := ledger.ExpectOperation(op, "VALID"); err != nil {
		return nil, err
	}
	if s.awaitEndorsers != nil {
		if err := s.awaitEndorsers(ctx, *op.Commit); err != nil {
			return nil, err
		}
	}
	if err := s.deliverAnchoredGrant(ctx, req.IssuerActor, chainGrant, req.RawGrantJWS, op); err != nil {
		return nil, err
	}
	return &AnchorGrantResult{
		Anchored:  true,
		Grant:     chainGrant,
		Operation: op,
	}, nil
}

// ReplaceGrant atomically submits ReplaceGrant to revoke the old grant and anchor the new grant,
// awaits endorser commit visibility, and publishes controlled outbox/receipt delivery when configured.
func (s *GrantAnchorService) ReplaceGrant(ctx context.Context, req ReplaceGrantAnchorRequest) (*AnchorGrantResult, error) {
	if s == nil {
		return nil, errors.New("registry: GrantAnchorService is nil")
	}
	if strings.TrimSpace(req.OldGrantID) == "" || strings.TrimSpace(req.NewClaims.ID) == "" || strings.TrimSpace(req.IssuerActor) == "" {
		return nil, protocol.NewError(preg.ErrCodeInvalidSchema, "oldGrantId, replacement grant id, and issuerActor are required")
	}
	rev := req.OldGrantRevision
	if rev == 0 {
		rev = 1
	}
	chainGrant := BuildChainGrant(s.deploymentID, req.NewClaims, req.NewGrantDigest, "")
	rep := preg.Replacement{
		Old: preg.Mutation{
			Bound:            preg.Bound{DeploymentID: s.deploymentID},
			ID:               req.OldGrantID,
			ExpectedRevision: rev,
			ExpectedDigest:   req.OldGrantDigest,
			Reason:           req.Reason,
		},
		New: chainGrant,
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		return nil, err
	}
	opKey := "mcp-replace/" + preg.Digest([]byte(req.OldGrantID+"/"+req.NewClaims.ID))[:24]
	op, err := s.writeOp(ctx, opKey, req.IssuerActor, "ReplaceGrant", raw)
	if err != nil {
		return nil, err
	}
	if err := ledger.ExpectOperation(op, "VALID"); err != nil {
		return nil, err
	}
	if s.awaitEndorsers != nil {
		if err := s.awaitEndorsers(ctx, *op.Commit); err != nil {
			return nil, err
		}
	}
	if err := s.deliverAnchoredGrant(ctx, req.IssuerActor, chainGrant, req.NewRawGrantJWS, op); err != nil {
		return nil, err
	}
	return &AnchorGrantResult{
		Anchored:  true,
		Grant:     chainGrant,
		Operation: op,
	}, nil
}

func (s *GrantAnchorService) deliverAnchoredGrant(
	ctx context.Context,
	issuerActor string,
	chainGrant preg.Grant,
	rawJWS string,
	op *ledger.Operation,
) error {
	if s.deliver == nil || s.resolveIssuer == nil || s.snapshotBuilder == nil {
		return nil
	}
	mat, ok, err := s.resolveIssuer(issuerActor)
	if err != nil || !ok {
		return err
	}
	synced, err := s.deliver.HasSyncedCertification(ctx, mat.DomainID)
	if err != nil || !synced {
		return err
	}
	if s.rootPub == nil {
		return errors.New("registry: root public key is required for grant delivery")
	}

	nowSec := s.now().UTC().Unix()
	snap := s.snapshotBuilder(time.Unix(nowSec, 0).UTC())
	if snap == nil {
		return protocol.NewError(preg.ErrCodeStateUnavailable, "snapshot view required for grant delivery")
	}
	if snap.Grants == nil {
		snap.Grants = make(map[string]preg.Grant)
	}
	activeGrant := chainGrant
	activeGrant.Version = preg.Version{Status: preg.Active, Revision: 1}
	snap.Grants[activeGrant.ID] = activeGrant

	txID, blockNo := op.TxID, int64(1)
	if op.Commit != nil {
		blockNo = int64(op.Commit.Number)
	}
	pkg := GrantDeliveryPackage{
		DeploymentID:           s.deploymentID,
		Recipient:              chainGrant.Grantee,
		GrantID:                chainGrant.ID,
		GrantJWS:               rawJWS,
		TaskSpec:               s.taskSpec,
		ServicePresentation:    mat.ServicePresentation,
		DomainCertificationJWS: mat.DomainCertificationJWS,
	}
	if _, err := s.deliver.PublishGrantOutbox(ctx, snap, pkg, s.rootPub, mat.CredentialIssuerPubKey, mat.IssuerPublicKey, txID, blockNo, true, nowSec); err != nil {
		return err
	}
	_, _, err = s.deliver.DeliverGrantReceipt(ctx, snap, s.deploymentID, chainGrant.Grantee, chainGrant.ID, nil, s.rootPub, mat.CredentialIssuerPubKey, mat.IssuerPublicKey, nowSec)
	return err
}
