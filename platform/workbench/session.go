package workbench

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"grad/platform/internal/httpx"
	"grad/protocol/registry"
)

// Role is assigned to a local account when it is provisioned.
type Role string

const (
	RoleAdmin   Role = "ADMIN"
	RoleBuyer   Role = "BUYER"
	RoleAuditor Role = "AUDITOR"

	sessionLifetime = 8 * time.Hour
	csrfHeader      = "X-CSRF-Token"
)

// Principal binds a browser login to the deployment's local registered identity.
type Principal struct {
	DomainID   string              `json:"domainId"`
	SubjectID  string              `json:"subjectId"`
	Role       Role                `json:"role"`
	Management registry.Management `json:"management"`
}

// AccountSeed supplies a credential and identity binding from the local host configuration.
type AccountSeed struct {
	Principal
	Username string `json:"username"`
	Password string `json:"password"`
}

type sessionView struct {
	DomainID  string   `json:"domainId"`
	SubjectID string   `json:"subjectId"`
	Role      Role     `json:"role"`
	Actions   []string `json:"actions"`
	CSRFToken string   `json:"csrfToken"`
}

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// A known, non-account hash gives unknown and existing usernames the same bcrypt check.
const dummyPasswordHash = "$2a$10$7EqJtq98hPqEX7fNZaFWoO5LNbknSZEZ.pNsnTP/062rQUpH5r3Eq"

// SeedAccounts reconciles the host-supplied local account list and revokes superseded sessions.
func (s *Server) SeedAccounts(ctx context.Context, accounts []AccountSeed) error {
	seen := make(map[string]bool, len(accounts))
	usernames := make([]string, 0, len(accounts))
	for _, account := range accounts {
		if !usernamePattern.MatchString(account.Username) || !validPassword(account.Password) ||
			!validPrincipal(account.Principal, s.cfg.DomainID) || seen[account.Username] {
			return errors.New("invalid or repeated workbench account configuration")
		}
		if err := s.cfg.VerifyPrincipal(ctx, account.Principal); err != nil {
			return fmt.Errorf("verify account %q: %w", account.Username, err)
		}
		seen[account.Username] = true
		usernames = append(usernames, account.Username)
	}

	tx, err := s.cfg.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
		"workbench_accounts/"+s.cfg.DeploymentID+"/"+s.cfg.DomainID); err != nil {
		return err
	}
	for _, account := range accounts {
		var existing Principal
		var hash []byte
		err := tx.QueryRow(ctx, `SELECT domain_id, subject_id, role, management_msp_id, management_fingerprint, password_hash
			FROM workbench_accounts WHERE deployment_id=$1 AND domain_id=$2 AND username=$3 FOR UPDATE`,
			s.cfg.DeploymentID, s.cfg.DomainID, account.Username).Scan(&existing.DomainID, &existing.SubjectID,
			&existing.Role, &existing.Management.MSPID, &existing.Management.CertificateSHA256, &hash)
		if err == nil && existing == account.Principal && bcrypt.CompareHashAndPassword(hash, []byte(account.Password)) == nil {
			continue
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		hash, err = bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO workbench_accounts(domain_id, deployment_id, username, subject_id, role,
			management_msp_id, management_fingerprint, password_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (deployment_id, domain_id, username) DO UPDATE SET subject_id=excluded.subject_id, role=excluded.role,
			management_msp_id=excluded.management_msp_id, management_fingerprint=excluded.management_fingerprint, password_hash=excluded.password_hash`,
			s.cfg.DomainID, s.cfg.DeploymentID, account.Username, account.SubjectID, account.Role, account.Management.MSPID,
			account.Management.CertificateSHA256, hash); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM workbench_sessions WHERE deployment_id=$1 AND domain_id=$2 AND username=$3`,
			s.cfg.DeploymentID, s.cfg.DomainID, account.Username); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM workbench_accounts WHERE deployment_id=$1 AND domain_id=$2 AND NOT (username = ANY($3))`,
		s.cfg.DeploymentID, s.cfg.DomainID, usernames); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func validPassword(password string) bool {
	return password != "" && len(password) <= 72
}

func validPrincipal(principal Principal, domain string) bool {
	if domain != principal.DomainID || principal.SubjectID == "" || !principal.Management.Valid() ||
		principal.Management.MSPID != domain+"Msp" {
		return false
	}
	return principal.Role == RoleAdmin || principal.Role == RoleBuyer && domain == "A" || principal.Role == RoleAuditor && domain == "C"
}

func (s *Server) cookieName() string {
	return "__Host-grad-workbench-" + strings.ToLower(s.cfg.DomainID)
}

func (s *Server) sessionCookie(value string, expires time.Time, maxAge int) *http.Cookie {
	return &http.Cookie{Name: s.cookieName(), Value: value, Path: "/", Expires: expires, MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

func sessionDigest(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

func csrfToken(token string) string {
	digest := sha256.Sum256([]byte("grad-workbench-csrf-v1/" + token))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func sessionResponse(principal Principal, token string) sessionView {
	var actions []string
	switch principal.Role {
	case RoleAdmin:
		actions = []string{"managePurchasingAuthority"}
	case RoleBuyer:
		actions = []string{"procure"}
	case RoleAuditor:
		actions = []string{"auditDecisions"}
	}
	return sessionView{DomainID: principal.DomainID, SubjectID: principal.SubjectID, Role: principal.Role,
		Actions: actions, CSRFToken: csrfToken(token)}
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
	if !usernamePattern.MatchString(input.Username) || !validPassword(input.Password) {
		WriteError(w, r, http.StatusUnauthorized, "LOGIN_FAILED", "invalid username or password")
		return
	}
	token, principal, expires, err := s.startSession(r.Context(), input.Username, input.Password, s.requestToken(r))
	if errors.Is(err, errLoginFailed) || registry.CodeOf(err) == registry.ErrCodeIdentityManagementForbidden {
		WriteError(w, r, http.StatusUnauthorized, "LOGIN_FAILED", "invalid username or password")
		return
	}
	if err != nil {
		WriteError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "session service unavailable")
		return
	}
	http.SetCookie(w, s.sessionCookie(token, expires, int(sessionLifetime/time.Second)))
	httpx.WriteJSON(w, http.StatusOK, sessionResponse(principal, token))
}

var errLoginFailed = errors.New("invalid login")

func (s *Server) startSession(ctx context.Context, username, password, previousToken string) (string, Principal, time.Time, error) {
	var principal Principal
	var expires time.Time
	tx, err := s.cfg.DB.Begin(ctx)
	if err != nil {
		return "", principal, expires, err
	}
	defer tx.Rollback(context.Background())
	var hash []byte
	err = tx.QueryRow(ctx, `SELECT domain_id, subject_id, role, management_msp_id, management_fingerprint, password_hash
		FROM workbench_accounts WHERE deployment_id=$1 AND domain_id=$2 AND username=$3 FOR SHARE`,
		s.cfg.DeploymentID, s.cfg.DomainID, username).Scan(&principal.DomainID, &principal.SubjectID,
		&principal.Role, &principal.Management.MSPID, &principal.Management.CertificateSHA256, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), []byte(password))
		return "", principal, expires, errLoginFailed
	}
	if err != nil {
		return "", principal, expires, err
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil || !validPrincipal(principal, s.cfg.DomainID) {
		return "", principal, expires, errLoginFailed
	}
	if err := s.cfg.VerifyPrincipal(ctx, principal); err != nil {
		return "", principal, expires, err
	}
	if previousToken != "" {
		previous := sessionDigest(previousToken)
		if _, err := tx.Exec(ctx, `DELETE FROM workbench_sessions WHERE deployment_id=$1 AND domain_id=$2 AND session_digest=$3`,
			s.cfg.DeploymentID, s.cfg.DomainID, previous[:]); err != nil {
			return "", principal, expires, err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM workbench_sessions WHERE deployment_id=$1 AND domain_id=$2 AND username=$3 AND expires_at<=now()`,
		s.cfg.DeploymentID, s.cfg.DomainID, username); err != nil {
		return "", principal, expires, err
	}
	var raw [32]byte
	rand.Read(raw[:])
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	digest := sessionDigest(token)
	err = tx.QueryRow(ctx, `INSERT INTO workbench_sessions(deployment_id, domain_id, username, session_digest, expires_at)
		VALUES ($1,$2,$3,$4,now()+$5::interval) RETURNING expires_at`,
		s.cfg.DeploymentID, s.cfg.DomainID, username, digest[:], fmt.Sprintf("%d seconds", int(sessionLifetime/time.Second))).Scan(&expires)
	if err != nil {
		return "", principal, expires, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", principal, expires, err
	}
	return token, principal, expires, nil
}

func (s *Server) requestToken(r *http.Request) string {
	cookies := r.CookiesNamed(s.cookieName())
	if len(cookies) != 1 {
		return ""
	}
	token := cookies[0].Value
	if len(token) != 43 {
		return ""
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(token); err != nil {
		return ""
	}
	return token
}

func (s *Server) sessionPrincipal(ctx context.Context, token string) (Principal, error) {
	var principal Principal
	if token == "" {
		return principal, pgx.ErrNoRows
	}
	digest := sessionDigest(token)
	err := s.cfg.DB.QueryRow(ctx, `SELECT a.domain_id, a.subject_id, a.role, a.management_msp_id, a.management_fingerprint
		FROM workbench_sessions AS s JOIN workbench_accounts AS a USING (deployment_id, domain_id, username)
		WHERE s.deployment_id=$1 AND s.domain_id=$2 AND s.session_digest=$3 AND s.expires_at>now()`,
		s.cfg.DeploymentID, s.cfg.DomainID, digest[:]).Scan(&principal.DomainID, &principal.SubjectID,
		&principal.Role, &principal.Management.MSPID, &principal.Management.CertificateSHA256)
	if err != nil {
		return principal, err
	}
	if !validPrincipal(principal, s.cfg.DomainID) {
		return principal, pgx.ErrNoRows
	}
	return principal, nil
}

func (s *Server) authenticated(role Role, next PrincipalHandler) http.HandlerFunc {
	return s.sessionHandler(role, next, s.cfg.VerifyPrincipal)
}

func (s *Server) sessionHandler(role Role, next PrincipalHandler, verify func(context.Context, Principal) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := s.requestToken(r)
		principal, err := s.sessionPrincipal(r.Context(), token)
		if errors.Is(err, pgx.ErrNoRows) {
			WriteError(w, r, http.StatusUnauthorized, "SESSION_REQUIRED", "active local session required")
			return
		}
		if err != nil {
			WriteError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "session service unavailable")
			return
		}
		if role != "" && principal.Role != role {
			WriteError(w, r, http.StatusForbidden, registry.ErrCodeIdentityManagementForbidden, "account role cannot perform this operation")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead &&
			subtle.ConstantTimeCompare([]byte(csrfToken(token)), []byte(r.Header.Get(csrfHeader))) != 1 {
			WriteError(w, r, http.StatusForbidden, "CSRF_INVALID", "valid CSRF token required")
			return
		}
		if verify != nil {
			if err := verify(r.Context(), principal); err != nil {
				if registry.CodeOf(err) == registry.ErrCodeIdentityManagementForbidden {
					WriteError(w, r, http.StatusForbidden, registry.ErrCodeIdentityManagementForbidden, "account is not authorized by the current registry")
				} else {
					WriteError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "account authority unavailable")
				}
				return
			}
		}
		if next == nil {
			WriteError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "operation unavailable in this domain")
			return
		}
		next(w, r, principal)
	}
}

func (s *Server) currentSession(w http.ResponseWriter, r *http.Request, principal Principal) {
	httpx.WriteJSON(w, http.StatusOK, sessionResponse(principal, s.requestToken(r)))
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, _ Principal) {
	digest := sessionDigest(s.requestToken(r))
	_, err := s.cfg.DB.Exec(r.Context(), `DELETE FROM workbench_sessions WHERE deployment_id=$1 AND domain_id=$2 AND session_digest=$3`,
		s.cfg.DeploymentID, s.cfg.DomainID, digest[:])
	if err != nil {
		WriteError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "session service unavailable")
		return
	}
	http.SetCookie(w, s.sessionCookie("", time.Unix(1, 0).UTC(), -1))
	w.WriteHeader(http.StatusNoContent)
}
