package workbench

import (
	"context"
	"net/http"

	"grad/platform/internal/httpx"
)

func (p *Procurement) EvidenceHandler(project func(context.Context, Run) (any, error)) PrincipalHandler {
	return func(w http.ResponseWriter, r *http.Request, principal Principal) {
		run, err := p.readRun(r.Context(), p.db, principal.SubjectID, r.PathValue("runId"))
		if err != nil {
			procurementError(w, r, err)
			return
		}
		evidence, err := project(r.Context(), run)
		if err != nil {
			procurementError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, evidence)
	}
}
