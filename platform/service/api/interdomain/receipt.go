package interdomain

import (
	"errors"
	"net/http"

	"grad/platform/core/domain/wallet"
	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	"grad/protocol"
)

const maxReceiptBodyBytes = 256 * 1024

// NewWalletReceiptHandler returns an L3 HTTP handler serving POST /v1/internal/order-outcome-receipts.
// It strictly enforces mTLS caller identity (did:web:c.local with C_AUDIT_SERVICE, C_AUDITOR, or
// C-AUDITOR role) via the wallet domain's AuthorizeReceiptCaller before applying the receipt.
func NewWalletReceiptHandler(w *wallet.WalletContext) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+PathOrderOutcomeReceipts, func(rw http.ResponseWriter, r *http.Request) {
		handleDeliverOrderOutcomeReceipt(w, rw, r)
	})
	return httpx.WithRequestID(mux)
}

func handleDeliverOrderOutcomeReceipt(w *wallet.WalletContext, rw http.ResponseWriter, r *http.Request) {
	reqID := httpx.RequestID(r)
	id, ok := mtls.Caller(r)
	if !ok {
		httpx.WriteError(rw, http.StatusForbidden, reqID, protocol.ErrCodeAuditForbidden, nil, "authenticated C receipt service required")
		return
	}
	var authErr error
	if w != nil {
		authErr = w.AuthorizeReceiptCaller(id.Role, id.DID)
	} else {
		authErr = wallet.AuthorizeReceiptSender(id.Role, id.DID)
	}
	if authErr != nil {
		httpx.WriteError(rw, http.StatusForbidden, reqID, protocol.ErrCodeAuditForbidden, nil, authErr.Error())
		return
	}
	if w == nil {
		httpx.WriteError(rw, http.StatusServiceUnavailable, reqID, protocol.ErrCodeStateUnavailable, nil, "wallet context unavailable")
		return
	}
	var rec wallet.OrderOutcomeReceipt
	if err := httpx.DecodeJSON(r, maxReceiptBodyBytes, &rec); err != nil {
		writeReceiptDecodeError(rw, reqID, err)
		return
	}
	resp, err := w.ApplyOrderOutcomeReceipt(r.Context(), rec)
	if err != nil {
		writeReceiptDomainError(rw, reqID, err)
		return
	}
	httpx.WriteJSON(rw, http.StatusOK, resp)
}

func writeReceiptDecodeError(rw http.ResponseWriter, reqID string, err error) {
	switch {
	case errors.Is(err, httpx.ErrUnsupportedMediaType):
		httpx.WriteError(rw, http.StatusUnsupportedMediaType, reqID, protocol.ErrCodeUnsupportedMediaType, nil, err.Error())
	case errors.Is(err, httpx.ErrPayloadTooLarge):
		httpx.WriteError(rw, http.StatusRequestEntityTooLarge, reqID, protocol.ErrCodePayloadTooLarge, nil, err.Error())
	default:
		httpx.WriteError(rw, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, nil, err.Error())
	}
}

func writeReceiptDomainError(rw http.ResponseWriter, reqID string, err error) {
	code := protocol.CodeOf(err)
	switch code {
	case protocol.ErrCodeAuditForbidden:
		httpx.WriteError(rw, http.StatusForbidden, reqID, code, nil, err.Error())
	case protocol.ErrCodeInvalidSchema:
		httpx.WriteError(rw, http.StatusBadRequest, reqID, code, nil, err.Error())
	case protocol.ErrCodeIdempotencyConflict, protocol.ErrCodeBindingMismatch:
		httpx.WriteError(rw, http.StatusConflict, reqID, code, nil, err.Error())
	case protocol.ErrCodeStateUnavailable:
		httpx.WriteError(rw, http.StatusServiceUnavailable, reqID, code, nil, err.Error())
	default:
		httpx.WriteError(rw, http.StatusInternalServerError, reqID, "INTERNAL_ERROR", nil, err.Error())
	}
}
