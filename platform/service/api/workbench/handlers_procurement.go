package workbench

import (
	"errors"
	"net/http"

	"grad/platform/core/domain/procurement"
	"grad/platform/internal/httpx"
	"grad/protocol"
	preg "grad/protocol/registry"
)

func (s *Server) requireProcurement(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.Procurement == nil {
		WriteError(w, r, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable, "operation unavailable in this domain")
		return false
	}
	return true
}

func writeProcurementError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, procurement.ErrNotFound):
		WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "object not found")
	case errors.Is(err, procurement.ErrDraftVersionConflict):
		WriteError(w, r, http.StatusConflict, "DRAFT_VERSION_CONFLICT", "reload the draft and confirm its current version")
	case protocol.CodeOf(err) == preg.ErrCodeInvalidSchema:
		WriteError(w, r, http.StatusBadRequest, preg.ErrCodeInvalidSchema, "invalid procurement input")
	default:
		WriteError(w, r, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable, "procurement state unavailable")
	}
}

func (s *Server) chat(w http.ResponseWriter, r *http.Request, principal procurement.Principal) {
	if !s.requireProcurement(w, r) {
		return
	}
	var in struct {
		Message string `json:"message"`
		DraftID string `json:"draftId,omitempty"`
	}
	if !ReadJSON(w, r, &in) {
		return
	}
	reply, draft, err := s.cfg.Procurement.ChatDraft(r.Context(), principal, in.Message, in.DraftID)
	if err != nil {
		writeProcurementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, struct {
		Reply string            `json:"reply"`
		Draft procurement.Draft `json:"draft"`
	}{reply, draft})
}

func (s *Server) getDraft(w http.ResponseWriter, r *http.Request, principal procurement.Principal) {
	if !s.requireProcurement(w, r) {
		return
	}
	draft, err := s.cfg.Procurement.GetDraft(r.Context(), principal.SubjectID, r.PathValue("draftId"))
	if err != nil {
		writeProcurementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, draft)
}

func (s *Server) updateDraft(w http.ResponseWriter, r *http.Request, principal procurement.Principal) {
	if !s.requireProcurement(w, r) {
		return
	}
	var draft procurement.Draft
	if !ReadJSON(w, r, &draft) {
		return
	}
	id := r.PathValue("draftId")
	if draft.DraftID != "" && draft.DraftID != id {
		writeProcurementError(w, r, protocol.NewError(preg.ErrCodeInvalidSchema, "draft ID mismatch"))
		return
	}
	draft.DraftID = id
	out, err := s.cfg.Procurement.UpdateDraft(r.Context(), principal.SubjectID, draft)
	if err != nil {
		writeProcurementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) confirmDraft(w http.ResponseWriter, r *http.Request, principal procurement.Principal) {
	if !s.requireProcurement(w, r) {
		return
	}
	var in struct {
		Version int64 `json:"version"`
	}
	if !ReadJSON(w, r, &in) {
		return
	}
	run, err := s.cfg.Procurement.ConfirmDraft(r.Context(), principal.SubjectID, r.PathValue("draftId"), in.Version)
	if err != nil {
		writeProcurementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, run)
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request, principal procurement.Principal) {
	if !s.requireProcurement(w, r) {
		return
	}
	runs, err := s.cfg.Procurement.ListRuns(r.Context(), principal.SubjectID)
	if err != nil {
		writeProcurementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, struct {
		Runs []procurement.Run `json:"runs"`
	}{runs})
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request, principal procurement.Principal) {
	if !s.requireProcurement(w, r) {
		return
	}
	run, err := s.cfg.Procurement.GetRun(r.Context(), principal.SubjectID, r.PathValue("runId"))
	if err != nil {
		writeProcurementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, run)
}

func (s *Server) suspendRun(w http.ResponseWriter, r *http.Request, principal procurement.Principal) {
	if !s.requireProcurement(w, r) {
		return
	}
	key, ok := IdempotencyKey(w, r)
	if !ok {
		return
	}
	run, err := s.cfg.Procurement.SuspendRun(r.Context(), principal.SubjectID, r.PathValue("runId"), key)
	if err != nil {
		writeProcurementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, run)
}

func (s *Server) resumeRun(w http.ResponseWriter, r *http.Request, principal procurement.Principal) {
	if !s.requireProcurement(w, r) {
		return
	}
	key, ok := IdempotencyKey(w, r)
	if !ok {
		return
	}
	run, err := s.cfg.Procurement.ResumeRun(r.Context(), principal.SubjectID, r.PathValue("runId"), key)
	if err != nil {
		writeProcurementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, run)
}
