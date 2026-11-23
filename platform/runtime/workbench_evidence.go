package runtime

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"grad/platform/gateway"
	"grad/platform/internal/httpx"
	"grad/platform/state/fabric"
	"grad/platform/workbench"
	"grad/protocol"
	"grad/protocol/registry"
)

type purchaseEvidence struct {
	TaskID    string                 `json:"taskId"`
	ProductID string                 `json:"productId"`
	Quantity  int64                  `json:"quantity"`
	Quotes    []gateway.QuotePayload `json:"quotes"`
	Orders    []gateway.OrderPayload `json:"orders"`
}

type workbenchEvidence struct {
	gateway.DecisionProof
	Purchase  purchaseEvidence          `json:"purchase"`
	Decisions []gateway.DecisionSummary `json:"decisions"`
}

const rootAmountPath = "/internal/workbench/root-amount/"

type rootGrantAmount struct {
	Digest         string `json:"digest"`
	MaxAmountMinor int64  `json:"maxAmountMinor"`
}

func (d *domainWorkbench) evidence(ctx context.Context, run workbench.Run) (any, error) {
	var source gateway.TaskEvidence
	if run.Stage == workbench.StageDispatch {
		err := d.callPeer(ctx, "C", http.MethodGet, "/internal/workbench/evidence/"+run.TaskID, nil, &source)
		if err != nil {
			return nil, err
		}
	}
	if source.Identity == nil {
		source.Identity = []gateway.IdentityEvidence{}
	}
	if source.Disclosures == nil {
		source.Disclosures = []gateway.DisclosureEvidence{}
	}
	if source.Decisions == nil {
		source.Decisions = []gateway.DecisionSummary{}
	}
	if source.Quotes == nil {
		source.Quotes = []gateway.QuotePayload{}
	}
	if source.Orders == nil {
		source.Orders = []gateway.OrderPayload{}
	}
	peer, err := d.inst.ReadPeer()
	if err != nil {
		return nil, err
	}
	defer peer.Close()
	delegations, err := d.delegations(ctx, run, source.Delegations, func(id string) (registry.Grant, error) {
		return fabric.ReadLedgerRecord[registry.Grant](ctx, peer, "grant", id)
	})
	if err != nil {
		return nil, err
	}
	return workbenchEvidence{
		DecisionProof: gateway.DecisionProof{Identity: source.Identity, Disclosures: source.Disclosures, Delegations: delegations},
		Purchase: purchaseEvidence{TaskID: run.TaskID, ProductID: run.Task.ProductID, Quantity: run.Task.Quantity,
			Quotes: source.Quotes, Orders: source.Orders},
		Decisions: source.Decisions,
	}, nil
}

func (d *domainWorkbench) delegations(ctx context.Context, run workbench.Run, proofs []gateway.DelegationEvidence, read func(string) (registry.Grant, error)) ([]gateway.DelegationEvidence, error) {
	// Keep decision references alongside the current version of each grant.
	last := make(map[string]gateway.DelegationEvidence, len(proofs))
	for _, item := range proofs {
		last[item.GrantID] = item
	}
	delegations := []gateway.DelegationEvidence{}
	for _, hop := range []string{"G0", "G1", "G2"} {
		anchor, err := read(run.GrantID(hop))
		if fabric.IsMissingRecord(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		item := gateway.DelegationFromAnchor(anchor)
		verified := last[anchor.ID]
		item.DecisionID, item.MaxAmountMinor = verified.DecisionID, verified.MaxAmountMinor
		if item.MaxAmountMinor == 0 {
			item.MaxAmountMinor, err = d.grants.anchoredAmount(ctx, anchor)
			if err != nil {
				return nil, err
			}
			if item.MaxAmountMinor == 0 && hop == "G0" && anchor.Mode == registry.RP {
				var root rootGrantAmount
				rootCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				err := d.callPeer(rootCtx, "C", http.MethodGet, rootAmountPath+run.TaskID, nil, &root)
				cancel()
				if err == nil {
					if root.Digest != anchor.Digest || root.MaxAmountMinor <= 0 || root.MaxAmountMinor > protocol.MaxSafeInt {
						return nil, protocol.NewError(registry.ErrCodeBindingMismatch, "root amount differs from the grant anchor")
					}
					item.MaxAmountMinor = root.MaxAmountMinor
				}
			}
		}
		delegations = append(delegations, item)
	}
	return delegations, nil
}

// anchoredAmount reads only local issuance or verified wallet receipts. The
// committed digest authenticates the exact signed bytes, including after expiry.
func (g *GrantOperations) anchoredAmount(ctx context.Context, anchor registry.Grant) (int64, error) {
	var raw string
	err := g.cfg.DB.QueryRow(ctx, `SELECT grant_jws FROM workbench_grant_issue
		WHERE deployment_id=$1 AND domain_id=$2 AND grant_id=$3`, g.cfg.Deployment.DeploymentID, g.cfg.DomainID, anchor.ID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		pkg, _, err := g.delivery.ReceivedGrant(ctx, anchor.Grantee, anchor.ID)
		if protocol.HasCode(err, registry.ErrCodeMaterialNotSynced) {
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
		raw = pkg.GrantJWS
	} else if err != nil {
		return 0, err
	}
	if registry.Digest([]byte(raw)) != anchor.Digest {
		return 0, protocol.NewError(registry.ErrCodeBindingMismatch, "stored grant differs from the grant anchor")
	}
	signed, err := protocol.ParseCompactJWS(raw, protocol.TypeGrantJWS)
	if err != nil {
		return 0, err
	}
	var claims protocol.GrantClaims
	if err := protocol.DecodeStrictJSON(signed.PayloadBytes, &claims); err != nil {
		return 0, err
	}
	if err := claims.ValidateStructure(); err != nil {
		return 0, err
	}
	anchor.Version = registry.Version{}
	if ledgerGrant(&protocol.ParsedGrant{Claims: claims, Digest: signed.Digest}) != anchor {
		return 0, protocol.NewError(registry.ErrCodeBindingMismatch, "stored grant claims differ from the grant anchor")
	}
	return claims.MaxAmountMinor, nil
}

func (d *domainWorkbench) remoteRootAmount(w http.ResponseWriter, r *http.Request) {
	ctx, taskID := r.Context(), r.PathValue("taskId")
	if !registry.IsDigest(taskID) {
		workbench.WriteError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid workbench task ID")
		return
	}
	run := workbench.Run{TaskID: taskID}
	rootID := run.GrantID("G0")
	if err := d.grants.sync(ctx); err != nil {
		writeInternalError(w, r, err)
		return
	}
	view, err := fabric.ReadAppliedRegistry(ctx, d.db, d.dep, []string{registry.Key("task", taskID), registry.Key("grant", rootID)})
	if err != nil {
		writeInternalError(w, r, err)
		return
	}
	task, err := grantRecord[registry.Task](view, "task", taskID)
	root, rootErr := grantRecord[registry.Grant](view, "grant", rootID)
	if err != nil || rootErr != nil || task.Creator != d.dep.Bootstrap.TaskCreator.Subject || task.Domain != "A" ||
		task.DeploymentID != d.dep.DeploymentID || task.Mode != registry.RP || root.Mode != registry.RP ||
		root.Task != taskID || root.ID != rootID || root.Root != rootID || root.Parent != "" ||
		root.Issuer != d.dep.Bootstrap.ResourceOwner || root.Grantee != task.Creator {
		workbench.WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "workbench RP root not found")
		return
	}
	amount, err := d.grants.anchoredAmount(ctx, root)
	if err != nil {
		writeInternalError(w, r, err)
		return
	}
	if amount == 0 {
		workbench.WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "root issuance not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rootGrantAmount{Digest: root.Digest, MaxAmountMinor: amount})
}

func (d *domainWorkbench) remoteEvidence(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("taskId")
	if _, err := d.readWorkbenchTask(r.Context(), id); err != nil {
		workbench.WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "task evidence not found")
		return
	}
	proof, err := d.gateway.ReadTaskEvidence(r.Context(), d.cfg.Actors["B1"].DID, id)
	if err != nil {
		writeInternalError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, proof)
}

func (d *domainWorkbench) decision(w http.ResponseWriter, r *http.Request, principal workbench.Principal) {
	if d.gateway == nil {
		workbench.WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "decision not found")
		return
	}
	decision, err := d.gateway.ReadDecision(r.Context(), r.PathValue("decisionId"), principal.SubjectID,
		principal.DomainID == "C" && principal.Role == workbench.RoleAuditor)
	if errors.Is(err, pgx.ErrNoRows) {
		workbench.WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "decision not found")
		return
	}
	if err != nil {
		workbench.WriteError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "decision unavailable")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, decision)
}
