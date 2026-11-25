package workbench

import (
	"errors"
	"net/http"

	"grad/platform/core/domain/evidence"
	"grad/platform/core/domain/procurement"
	"grad/platform/internal/httpx"
	preg "grad/protocol/registry"
)

func (s *Server) runEvidence(w http.ResponseWriter, r *http.Request, principal procurement.Principal) {
	if s.cfg.Evidence == nil {
		WriteError(w, r, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable, "operation unavailable in this domain")
		return
	}
	out, err := s.cfg.Evidence.ProjectRunEvidence(r.Context(), principal, r.PathValue("runId"))
	if err != nil {
		if errors.Is(err, evidence.ErrNotFound) || errors.Is(err, procurement.ErrNotFound) {
			WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "object not found")
			return
		}
		writeProcurementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) decision(w http.ResponseWriter, r *http.Request, principal procurement.Principal) {
	if s.cfg.Evidence == nil {
		WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "decision not found")
		return
	}
	record, err := s.cfg.Evidence.ReadDecision(r.Context(), principal, r.PathValue("decisionId"))
	if errors.Is(err, evidence.ErrNotFound) {
		WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "decision not found")
		return
	}
	if err != nil {
		WriteError(w, r, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable, "decision unavailable")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, record)
}
