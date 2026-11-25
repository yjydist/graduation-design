// Package evidence implements L2 five-category evidence projection and role-scoped
// decision/task evidence queries for the workbench without inbound HTTP coupling.
package evidence

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	domgw "grad/platform/core/domain/gateway"
	"grad/platform/core/domain/procurement"
	"grad/platform/core/ledger"
	"grad/protocol"
	preg "grad/protocol/registry"
)

// ErrNotFound reports a missing run, root amount, task evidence, or decision record.
var ErrNotFound = errors.New("evidence not found")

// PurchaseEvidence projects quote and order artifacts bound to a procurement run.
type PurchaseEvidence struct {
	TaskID    string               `json:"taskId"`
	ProductID string               `json:"productId"`
	Quantity  int64                `json:"quantity"`
	Quotes    []domgw.QuotePayload `json:"quotes"`
	Orders    []domgw.OrderPayload `json:"orders"`
}

// WorkbenchEvidence aggregates all five evidence views (identity, disclosure, delegation,
// purchase, and gateway decisions) for a buyer's procurement run.
type WorkbenchEvidence struct {
	domgw.DecisionProof
	Purchase  PurchaseEvidence        `json:"purchase"`
	Decisions []domgw.DecisionSummary `json:"decisions"`
}

// RootGrantAmount carries the authenticated RP root grant digest and max amount from Domain C.
type RootGrantAmount struct {
	Digest         string `json:"digest"`
	MaxAmountMinor int64  `json:"maxAmountMinor"`
}

// PeerEvidenceClient fetches Domain C evidence and RP root amounts over the authenticated peer channel.
type PeerEvidenceClient interface {
	FetchTaskEvidence(ctx context.Context, taskID string) (domgw.TaskEvidence, error)
	FetchRootAmount(ctx context.Context, taskID string) (RootGrantAmount, error)
}

// GrantReader loads a grant anchor by ID (abstracted for offline unit testing).
type GrantReader func(ctx context.Context, grantID string) (preg.Grant, error)

// Config configures the L2 evidence projection Service.
type Config struct {
	DB          *pgxpool.Pool
	Deployment  *ledger.Deployment
	Instance    *ledger.Instance
	Procurement *procurement.Service
	Grants      *procurement.GrantOperations
	Gateway     *domgw.Service
	Peers       PeerEvidenceClient
	ActorB1DID  string
	// ReadGrant overrides Fabric peer grant lookup for unit tests.
	ReadGrant GrantReader
}

// Service projects five-category run evidence (Domain A), remote root amount and task evidence
// (Domain C inter-domain), and role-scoped decision records (Domain C browser).
type Service struct {
	cfg Config
}

// NewService constructs an evidence Service.
func NewService(cfg Config) *Service {
	return &Service{cfg: cfg}
}

// ProjectRunEvidence loads the buyer's confirmed run and projects all five evidence categories.
func (s *Service) ProjectRunEvidence(ctx context.Context, principal procurement.Principal, runID string) (*WorkbenchEvidence, error) {
	if s == nil || s.cfg.Procurement == nil {
		return nil, protocol.NewError(preg.ErrCodeStateUnavailable, "procurement evidence unavailable in this domain")
	}
	run, err := s.cfg.Procurement.GetRunRecord(ctx, principal.SubjectID, runID)
	if err != nil {
		if errors.Is(err, procurement.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return s.ProjectRun(ctx, run)
}

// ProjectRun projects all five evidence categories for a confirmed Run.
func (s *Service) ProjectRun(ctx context.Context, run procurement.Run) (*WorkbenchEvidence, error) {
	var source domgw.TaskEvidence
	if run.Stage == procurement.StageDispatch {
		if s.cfg.Peers == nil {
			return nil, protocol.NewError(preg.ErrCodeStateUnavailable, "peer evidence client unavailable")
		}
		var err error
		source, err = s.cfg.Peers.FetchTaskEvidence(ctx, run.TaskID)
		if err != nil {
			return nil, err
		}
	}
	if source.Identity == nil {
		source.Identity = []domgw.IdentityEvidence{}
	}
	if source.Disclosures == nil {
		source.Disclosures = []domgw.DisclosureEvidence{}
	}
	if source.Decisions == nil {
		source.Decisions = []domgw.DecisionSummary{}
	}
	if source.Quotes == nil {
		source.Quotes = []domgw.QuotePayload{}
	}
	if source.Orders == nil {
		source.Orders = []domgw.OrderPayload{}
	}

	readGrant := s.cfg.ReadGrant
	if readGrant == nil {
		if s.cfg.Instance == nil {
			return nil, protocol.NewError(preg.ErrCodeStateUnavailable, "ledger instance unavailable")
		}
		peer, err := s.cfg.Instance.ReadPeer()
		if err != nil {
			return nil, err
		}
		defer peer.Close()
		readGrant = func(ctx context.Context, id string) (preg.Grant, error) {
			return ledger.ReadLedgerRecord[preg.Grant](ctx, peer, "grant", id)
		}
	}

	delegations, err := s.projectDelegations(ctx, run, source.Delegations, readGrant)
	if err != nil {
		return nil, err
	}
	return &WorkbenchEvidence{
		DecisionProof: domgw.DecisionProof{
			Identity:    source.Identity,
			Disclosures: source.Disclosures,
			Delegations: delegations,
		},
		Purchase: PurchaseEvidence{
			TaskID:    run.TaskID,
			ProductID: run.Task.ProductID,
			Quantity:  run.Task.Quantity,
			Quotes:    source.Quotes,
			Orders:    source.Orders,
		},
		Decisions: source.Decisions,
	}, nil
}

func (s *Service) projectDelegations(ctx context.Context, run procurement.Run, proofs []domgw.DelegationEvidence, read GrantReader) ([]domgw.DelegationEvidence, error) {
	last := make(map[string]domgw.DelegationEvidence, len(proofs))
	for _, item := range proofs {
		last[item.GrantID] = item
	}
	delegations := []domgw.DelegationEvidence{}
	for _, hop := range []string{"G0", "G1", "G2"} {
		anchor, err := read(ctx, run.GrantID(hop))
		if ledger.IsMissingRecord(err) || errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		item := domgw.DelegationFromAnchor(anchor)
		verified := last[anchor.ID]
		item.DecisionID, item.MaxAmountMinor = verified.DecisionID, verified.MaxAmountMinor
		if item.MaxAmountMinor == 0 {
			if s.cfg.Grants != nil {
				item.MaxAmountMinor, err = s.cfg.Grants.AnchoredAmount(ctx, anchor)
				if err != nil {
					return nil, err
				}
			}
			if item.MaxAmountMinor == 0 && hop == "G0" && anchor.Mode == preg.RP && s.cfg.Peers != nil {
				rootCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				root, err := s.cfg.Peers.FetchRootAmount(rootCtx, run.TaskID)
				cancel()
				if err == nil {
					if root.Digest != anchor.Digest || root.MaxAmountMinor <= 0 || root.MaxAmountMinor > protocol.MaxSafeInt {
						return nil, protocol.NewError(preg.ErrCodeBindingMismatch, "root amount differs from the grant anchor")
					}
					item.MaxAmountMinor = root.MaxAmountMinor
				}
			}
		}
		delegations = append(delegations, item)
	}
	return delegations, nil
}

// ReadRemoteRootAmount verifies a Domain A RP root grant in Domain C's applied ledger view
// and returns its digest-authenticated maxAmountMinor.
func (s *Service) ReadRemoteRootAmount(ctx context.Context, taskID string) (RootGrantAmount, error) {
	if !preg.IsDigest(taskID) {
		return RootGrantAmount{}, protocol.NewError(preg.ErrCodeInvalidSchema, "invalid workbench task ID")
	}
	if s == nil || s.cfg.DB == nil || s.cfg.Deployment == nil || s.cfg.Grants == nil {
		return RootGrantAmount{}, protocol.NewError(preg.ErrCodeStateUnavailable, "root amount service unavailable")
	}
	run := procurement.Run{TaskID: taskID}
	rootID := run.GrantID("G0")
	if err := s.cfg.Grants.Sync(ctx); err != nil {
		return RootGrantAmount{}, err
	}
	view, err := ledger.ReadAppliedRegistry(ctx, s.cfg.DB, s.cfg.Deployment, []string{preg.Key("task", taskID), preg.Key("grant", rootID)})
	if err != nil {
		return RootGrantAmount{}, err
	}
	var task preg.Task
	var root preg.Grant
	taskErr := protocol.DecodeStrictJSON(view.Records[preg.Key("task", taskID)], &task)
	rootErr := protocol.DecodeStrictJSON(view.Records[preg.Key("grant", rootID)], &root)
	dep := s.cfg.Deployment
	if taskErr != nil || rootErr != nil || task.Creator != dep.Bootstrap.TaskCreator.Subject || task.Domain != "A" ||
		task.DeploymentID != dep.DeploymentID || task.Mode != preg.RP || root.Mode != preg.RP ||
		root.Task != taskID || root.ID != rootID || root.Root != rootID || root.Parent != "" ||
		root.Issuer != dep.Bootstrap.ResourceOwner || root.Grantee != task.Creator {
		return RootGrantAmount{}, ErrNotFound
	}
	amount, err := s.cfg.Grants.AnchoredAmount(ctx, root)
	if err != nil {
		return RootGrantAmount{}, err
	}
	if amount == 0 {
		return RootGrantAmount{}, ErrNotFound
	}
	return RootGrantAmount{Digest: root.Digest, MaxAmountMinor: amount}, nil
}

// ReadRemoteTaskEvidence verifies the workbench task in Domain C and reads its gateway evidence projection.
func (s *Service) ReadRemoteTaskEvidence(ctx context.Context, taskID string) (*domgw.TaskEvidence, error) {
	if s == nil || s.cfg.Procurement == nil || s.cfg.Gateway == nil {
		return nil, protocol.NewError(preg.ErrCodeStateUnavailable, "task evidence service unavailable")
	}
	if _, err := s.cfg.Procurement.ReadWorkbenchTask(ctx, taskID); err != nil {
		return nil, ErrNotFound
	}
	return s.cfg.Gateway.ReadTaskEvidence(ctx, s.cfg.ActorB1DID, taskID)
}

// ReadDecision returns a role-scoped gateway decision record for a browser principal.
func (s *Service) ReadDecision(ctx context.Context, principal procurement.Principal, decisionID string) (*domgw.DecisionRecord, error) {
	if s == nil || s.cfg.Gateway == nil {
		return nil, ErrNotFound
	}
	rec, err := s.cfg.Gateway.ReadDecision(ctx, decisionID, principal.SubjectID,
		principal.DomainID == "C" && principal.Role == procurement.RoleAuditor)
	if errors.Is(err, domgw.ErrDecisionNotFound) {
		return nil, ErrNotFound
	}
	return rec, err
}
