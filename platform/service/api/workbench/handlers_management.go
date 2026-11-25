package workbench

import (
	"encoding/json"
	"net/http"
	"strings"

	"grad/platform/core/domain/procurement"
	domreg "grad/platform/core/domain/registry"
	"grad/platform/internal/httpx"
	"grad/protocol"
	preg "grad/protocol/registry"
)

type browserOperation struct {
	domreg.OperationView
	TxID        *string `json:"txId"`
	BlockNumber *int64  `json:"blockNumber"`
}

func operationResponse(view *domreg.OperationView) browserOperation {
	out := browserOperation{OperationView: *view}
	if view.TxID != "" && !strings.HasPrefix(view.TxID, "pending:") {
		txID := view.TxID
		out.TxID = &txID
	}
	if view.BlockHash != "" && view.ValidationCode != nil {
		blockNumber := view.BlockNumber
		out.BlockNumber = &blockNumber
	}
	return out
}

func (s *Server) purchasingAuthority(w http.ResponseWriter, r *http.Request, principal procurement.Principal) {
	view, err := s.cfg.Authority.ReadPurchasingAuthority(r.Context(), principal)
	if err != nil {
		writeManagementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

func (s *Server) setPurchasingAuthority(w http.ResponseWriter, r *http.Request, principal procurement.Principal) {
	var input struct {
		ExpectedRevision    uint64          `json:"expectedRevision"`
		PurchasingAuthority json.RawMessage `json:"purchasingAuthority"`
	}
	if !ReadJSON(w, r, &input) {
		return
	}
	var authority *string
	if input.ExpectedRevision == 0 || input.ExpectedRevision > uint64(protocol.MaxSafeInt) ||
		json.Unmarshal(input.PurchasingAuthority, &authority) != nil ||
		(authority != nil && (!strings.HasPrefix(*authority, "did:web:") || len(*authority) <= len("did:web:"))) {
		WriteError(w, r, http.StatusBadRequest, preg.ErrCodeInvalidSchema, "positive expectedRevision and service DID or null required")
		return
	}
	key, ok := IdempotencyKey(w, r)
	if !ok {
		return
	}
	view, err := s.cfg.Authority.SetPurchasingAuthority(r.Context(), principal, key, input.ExpectedRevision, authority)
	if err != nil {
		writeManagementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, operationResponse(view))
}

func (s *Server) operation(w http.ResponseWriter, r *http.Request, principal procurement.Principal) {
	opID := r.PathValue("operationId")
	view, err := s.cfg.Authority.GetOperation(r.Context(), principal, opID)
	if err != nil {
		if preg.HasCode(err, preg.ErrCodeIdentityManagementForbidden) || preg.HasCode(err, preg.ErrCodeOperationUnknown) {
			WriteError(w, r, http.StatusNotFound, preg.ErrCodeOperationUnknown, "unknown operation")
			return
		}
		writeManagementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, operationResponse(view))
}

func writeManagementError(w http.ResponseWriter, r *http.Request, err error) {
	code := preg.CodeOf(err)
	switch code {
	case preg.ErrCodeIdentityManagementForbidden:
		WriteError(w, r, http.StatusForbidden, code, "local domain administrator required")
	case preg.ErrCodePurchasingAuthorityInvalid:
		WriteError(w, r, http.StatusForbidden, code, "active service in the local domain required")
	case preg.ErrCodeIdempotencyConflict, preg.ErrCodeStateChanged:
		WriteError(w, r, http.StatusConflict, code, err.Error())
	case preg.ErrCodeInvalidSchema:
		WriteError(w, r, http.StatusBadRequest, code, "invalid management input")
	default:
		WriteError(w, r, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable, "management operation unavailable")
	}
}
