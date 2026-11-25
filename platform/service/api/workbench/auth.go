package workbench

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"grad/platform/core/domain/procurement"
	"grad/platform/internal/httpx"
	preg "grad/protocol/registry"
)

const csrfHeader = "X-CSRF-Token"

type principalHandler func(http.ResponseWriter, *http.Request, procurement.Principal)

func (s *Server) cookieName() string {
	return "__Host-grad-workbench-" + strings.ToLower(s.cfg.DomainID)
}

func (s *Server) sessionCookie(value string, expires time.Time, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     s.cookieName(),
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

func (s *Server) requestToken(r *http.Request) string {
	cookies := r.CookiesNamed(s.cookieName())
	if len(cookies) != 1 {
		return ""
	}
	token := cookies[0].Value
	if !procurement.ValidSessionToken(token) {
		return ""
	}
	return token
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		WriteError(w, r, http.StatusForbidden, "CSRF_INVALID", "cross-site login forbidden")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !ReadJSON(w, r, &input) {
		return
	}
	if !procurement.ValidUsername(input.Username) || !procurement.ValidPassword(input.Password) {
		WriteError(w, r, http.StatusUnauthorized, "LOGIN_FAILED", "invalid username or password")
		return
	}
	if s.cfg.Sessions == nil {
		WriteError(w, r, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable, "session service unavailable")
		return
	}
	token, principal, expires, err := s.cfg.Sessions.Login(r.Context(), input.Username, input.Password, s.requestToken(r))
	if errors.Is(err, procurement.ErrLoginFailed) || preg.CodeOf(err) == preg.ErrCodeIdentityManagementForbidden {
		WriteError(w, r, http.StatusUnauthorized, "LOGIN_FAILED", "invalid username or password")
		return
	}
	if err != nil {
		WriteError(w, r, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable, "session service unavailable")
		return
	}
	http.SetCookie(w, s.sessionCookie(token, expires, int(procurement.SessionLifetime/time.Second)))
	httpx.WriteJSON(w, http.StatusOK, s.cfg.Sessions.SessionView(principal, token))
}

func (s *Server) authenticated(role procurement.Role, next principalHandler) http.HandlerFunc {
	return s.sessionHandler(role, next, true)
}

func (s *Server) sessionHandler(role procurement.Role, next principalHandler, verify bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := s.requestToken(r)
		if token == "" {
			WriteError(w, r, http.StatusUnauthorized, "SESSION_REQUIRED", "active local session required")
			return
		}
		if s.cfg.Sessions == nil {
			WriteError(w, r, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable, "session service unavailable")
			return
		}
		principal, err := s.cfg.Sessions.Authenticate(r.Context(), token)
		if errors.Is(err, procurement.ErrSessionRequired) {
			WriteError(w, r, http.StatusUnauthorized, "SESSION_REQUIRED", "active local session required")
			return
		}
		if err != nil {
			WriteError(w, r, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable, "session service unavailable")
			return
		}
		if role != "" && principal.Role != role {
			WriteError(w, r, http.StatusForbidden, preg.ErrCodeIdentityManagementForbidden, "account role cannot perform this operation")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead &&
			!procurement.VerifyCSRF(token, r.Header.Get(csrfHeader)) {
			WriteError(w, r, http.StatusForbidden, "CSRF_INVALID", "valid CSRF token required")
			return
		}
		if verify {
			if err := s.cfg.Authority.VerifyPrincipal(r.Context(), principal); err != nil {
				if preg.CodeOf(err) == preg.ErrCodeIdentityManagementForbidden {
					WriteError(w, r, http.StatusForbidden, preg.ErrCodeIdentityManagementForbidden, "account is not authorized by the current registry")
				} else {
					WriteError(w, r, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable, "account authority unavailable")
				}
				return
			}
		}
		if next == nil {
			WriteError(w, r, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable, "operation unavailable in this domain")
			return
		}
		next(w, r, principal)
	}
}

func (s *Server) currentSession(w http.ResponseWriter, r *http.Request, principal procurement.Principal) {
	httpx.WriteJSON(w, http.StatusOK, s.cfg.Sessions.SessionView(principal, s.requestToken(r)))
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, _ procurement.Principal) {
	if err := s.cfg.Sessions.Logout(r.Context(), s.requestToken(r)); err != nil {
		WriteError(w, r, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable, "session service unavailable")
		return
	}
	http.SetCookie(w, s.sessionCookie("", time.Unix(1, 0).UTC(), -1))
	w.WriteHeader(http.StatusNoContent)
}
