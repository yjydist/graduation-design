// Package httpx provides unified REST JSON encoding, strict bounded decoding,
// request ID propagation, and error envelopes shared across platform HTTP services.
package httpx

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

const (
	// HeaderRequestID is the canonical request correlation header.
	HeaderRequestID = "X-Request-Id"
)

var (
	// ErrUnsupportedMediaType indicates a missing or non-JSON Content-Type header.
	ErrUnsupportedMediaType = errors.New("unsupported media type")
	// ErrPayloadTooLarge indicates the request body exceeds the configured byte limit.
	ErrPayloadTooLarge = errors.New("request payload too large")
	// ErrInvalidJSON indicates an empty, malformed, duplicate-key, or unknown-field JSON body.
	ErrInvalidJSON = errors.New("invalid json payload")
)

// ErrorEnvelope is the canonical structured error body returned by platform HTTP endpoints.
// DecisionID intentionally has no omitempty so "decisionId": null is always emitted when absent.
type ErrorEnvelope struct {
	RequestID  string  `json:"requestId"`
	Code       string  `json:"code"`
	DecisionID *string `json:"decisionId"`
	Message    string  `json:"message"`
}

type requestIDKey struct{}

// NewRequestID generates a fresh urn:grad:req:<uuid> correlation identifier.
func NewRequestID() string {
	return "urn:grad:req:" + newUUID()
}

// RequestID returns the request ID from context or the X-Request-Id header,
// generating a new urn:grad:req:<uuid> identifier when neither is present.
func RequestID(r *http.Request) string {
	if r != nil {
		if id, ok := r.Context().Value(requestIDKey{}).(string); ok && id != "" {
			return id
		}
		if id := strings.TrimSpace(r.Header.Get(HeaderRequestID)); id != "" {
			return id
		}
	}
	return NewRequestID()
}

// WithRequestID ensures every request has a stable X-Request-Id stored in context
// and echoed on the HTTP response header.
func WithRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := RequestID(r)
		w.Header().Set(HeaderRequestID, reqID)
		ctx := context.WithValue(r.Context(), requestIDKey{}, reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// WithRequestIDFunc wraps an http.HandlerFunc with X-Request-Id propagation.
func WithRequestIDFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := RequestID(r)
		w.Header().Set(HeaderRequestID, reqID)
		ctx := context.WithValue(r.Context(), requestIDKey{}, reqID)
		next(w, r.WithContext(ctx))
	}
}

// WriteJSON marshals v as JSON and writes it with the given HTTP status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"requestId":"","code":"INTERNAL_ERROR","decisionId":null,"message":"failed to encode response"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

// WriteError writes the canonical ErrorEnvelope and sets X-Request-Id when requestID is non-empty.
func WriteError(w http.ResponseWriter, status int, requestID, code string, decisionID *string, message string) {
	if requestID != "" {
		w.Header().Set(HeaderRequestID, requestID)
	}
	WriteJSON(w, status, ErrorEnvelope{
		RequestID:  requestID,
		Code:       code,
		DecisionID: decisionID,
		Message:    message,
	})
}

// RequireJSONContentType verifies that r carries Content-Type application/json.
func RequireJSONContentType(r *http.Request) error {
	if r == nil {
		return fmt.Errorf("%w: request is nil", ErrUnsupportedMediaType)
	}
	ct := strings.TrimSpace(r.Header.Get("Content-Type"))
	if ct == "" {
		return fmt.Errorf("%w: Content-Type application/json is required", ErrUnsupportedMediaType)
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return fmt.Errorf("%w: malformed Content-Type %q", ErrUnsupportedMediaType, ct)
	}
	if !strings.EqualFold(mediaType, "application/json") {
		return fmt.Errorf("%w: unsupported Content-Type %q", ErrUnsupportedMediaType, ct)
	}
	return nil
}

// ReadBoundedBody validates the JSON content type and reads at most maxBytes from r.Body.
// When maxBytes <= 0, no upper size bound is applied.
func ReadBoundedBody(r *http.Request, maxBytes int64) ([]byte, error) {
	if err := RequireJSONContentType(r); err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, fmt.Errorf("%w: empty request body", ErrInvalidJSON)
	}
	if maxBytes > 0 && r.ContentLength > maxBytes {
		return nil, fmt.Errorf("%w: exceeds %d bytes", ErrPayloadTooLarge, maxBytes)
	}
	var reader io.Reader = r.Body
	if maxBytes > 0 {
		reader = io.LimitReader(r.Body, maxBytes+1)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("%w: read request body: %v", ErrInvalidJSON, err)
	}
	if maxBytes > 0 && int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("%w: exceeds %d bytes", ErrPayloadTooLarge, maxBytes)
	}
	return body, nil
}

// DecodeJSON enforces Content-Type application/json, reads at most maxBytes,
// and strictly unmarshals a single RFC 7493 JSON document into dst while rejecting
// duplicate keys and unknown object members.
func DecodeJSON(r *http.Request, maxBytes int64, dst any) error {
	body, err := ReadBoundedBody(r, maxBytes)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return fmt.Errorf("%w: empty request body", ErrInvalidJSON)
	}
	if err := jsonv2.Unmarshal(body, dst, jsonv2.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	return nil
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
