package runtime

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"grad/platform/gateway"
	"grad/platform/internal/httpx"
	"grad/platform/state/fabric"
	"grad/platform/workbench"
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
	// Current registry state can move after the decision. Keep the originally
	// verified terms, and display the current grant version alongside them.
	last := make(map[string]gateway.DelegationEvidence)
	for _, item := range source.Delegations {
		last[item.GrantID] = item
	}
	delegations := []gateway.DelegationEvidence{}
	peer, err := d.inst.ReadPeer()
	if err != nil {
		return nil, err
	}
	defer peer.Close()
	for _, hop := range []string{"G0", "G1", "G2"} {
		id := run.GrantID(hop)
		anchor, err := fabric.ReadLedgerRecord[registry.Grant](ctx, peer, "grant", id)
		if fabric.IsMissingRecord(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		item := gateway.DelegationFromAnchor(anchor)
		if verified, ok := last[id]; ok {
			item.DecisionID, item.MaxAmountMinor = verified.DecisionID, verified.MaxAmountMinor
		}
		delegations = append(delegations, item)
	}
	return workbenchEvidence{
		DecisionProof: gateway.DecisionProof{Identity: source.Identity, Disclosures: source.Disclosures, Delegations: delegations},
		Purchase: purchaseEvidence{TaskID: run.TaskID, ProductID: run.Task.ProductID, Quantity: run.Task.Quantity,
			Quotes: source.Quotes, Orders: source.Orders},
		Decisions: source.Decisions,
	}, nil
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
