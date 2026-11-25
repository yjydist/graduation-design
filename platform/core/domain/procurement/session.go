package procurement

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"grad/platform/core/dao"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// A known, non-account hash gives unknown and existing usernames the same bcrypt timing cost.
const dummyPasswordHash = "$2a$10$7EqJtq98hPqEX7fNZaFWoO5LNbknSZEZ.pNsnTP/062rQUpH5r3Eq"

// SessionService manages local workbench accounts and browser session persistence
// over workbench_accounts and workbench_sessions.
type SessionService struct {
	db           *pgxpool.Pool
	deploymentID string
	domainID     string
	verifier     AuthorityVerifier
}

// NewSessionService constructs a SessionService bound to deploymentID and domainID.
func NewSessionService(db *pgxpool.Pool, deploymentID, domainID string, verifier AuthorityVerifier) (*SessionService, error) {
	if db == nil || deploymentID == "" || (domainID != "A" && domainID != "B" && domainID != "C") {
		return nil, errors.New("session service requires database, deploymentId, and domainId (A/B/C)")
	}
	return &SessionService{
		db:           db,
		deploymentID: deploymentID,
		domainID:     domainID,
		verifier:     verifier,
	}, nil
}

// ValidUsername reports whether username matches the workbench account naming rule.
func ValidUsername(u string) bool {
	return usernamePattern.MatchString(u)
}

// ValidPassword reports whether password fits bcrypt's non-empty 72-byte limit.
func ValidPassword(p string) bool {
	return p != "" && len(p) <= 72
}

// ValidPrincipal checks that principal is bound to domain and holds a permitted role for that domain.
func ValidPrincipal(p Principal, domain string) bool {
	if domain != p.DomainID || p.SubjectID == "" || !p.Management.Valid() || p.Management.MSPID != domain+"Msp" {
		return false
	}
	return p.Role == RoleAdmin || (p.Role == RoleBuyer && domain == "A") || (p.Role == RoleAuditor && domain == "C")
}

// ValidSessionToken validates the canonical 43-char base64url encoding of a 32-byte session token.
func ValidSessionToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.Strict().DecodeString(token)
	return err == nil
}

// CSRFToken derives the deterministic CSRF token bound to a browser session token.
func CSRFToken(token string) string {
	digest := sha256.Sum256([]byte("grad-workbench-csrf-v1/" + token))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// VerifyCSRF compares candidate against CSRFToken(token) in constant time.
func VerifyCSRF(token, candidate string) bool {
	return subtle.ConstantTimeCompare([]byte(CSRFToken(token)), []byte(candidate)) == 1
}

// BuildSessionView constructs the browser SessionView for principal and token.
func BuildSessionView(principal Principal, token string) SessionView {
	var actions []string
	switch principal.Role {
	case RoleAdmin:
		actions = []string{"managePurchasingAuthority"}
	case RoleBuyer:
		actions = []string{"procure"}
	case RoleAuditor:
		actions = []string{"auditDecisions"}
	}
	return SessionView{
		DomainID:  principal.DomainID,
		SubjectID: principal.SubjectID,
		Role:      principal.Role,
		Actions:   actions,
		CSRFToken: CSRFToken(token),
	}
}

// SessionView returns the browser SessionView for principal and token.
func (s *SessionService) SessionView(principal Principal, token string) SessionView {
	return BuildSessionView(principal, token)
}

// VerifyPrincipal delegates principal authority validation to the configured AuthorityVerifier.
func (s *SessionService) VerifyPrincipal(ctx context.Context, principal Principal) error {
	if s.verifier == nil {
		return nil
	}
	return s.verifier.VerifyPrincipal(ctx, principal)
}

func sessionDigest(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

// SeedAccounts reconciles the host-supplied local account list and revokes superseded sessions.
func (s *SessionService) SeedAccounts(ctx context.Context, accounts []AccountSeed) error {
	seen := make(map[string]bool, len(accounts))
	usernames := make([]string, 0, len(accounts))
	for _, account := range accounts {
		if !ValidUsername(account.Username) || !ValidPassword(account.Password) ||
			!ValidPrincipal(account.Principal, s.domainID) || seen[account.Username] {
			return errors.New("invalid or repeated workbench account configuration")
		}
		if s.verifier != nil {
			if err := s.verifier.VerifyPrincipal(ctx, account.Principal); err != nil {
				return fmt.Errorf("verify account %q: %w", account.Username, err)
			}
		}
		seen[account.Username] = true
		usernames = append(usernames, account.Username)
	}

	return dao.RunInTx(ctx, s.db, func(tx dao.Tx) error {
		if err := tx.AdvisoryXactLock(ctx, "workbench_accounts/"+s.deploymentID+"/"+s.domainID); err != nil {
			return err
		}
		for _, account := range accounts {
			var existing Principal
			var hash []byte
			err := tx.QueryRow(ctx, `SELECT domain_id, subject_id, role, management_msp_id, management_fingerprint, password_hash
				FROM workbench_accounts WHERE deployment_id=$1 AND domain_id=$2 AND username=$3 FOR UPDATE`,
				s.deploymentID, s.domainID, account.Username).Scan(&existing.DomainID, &existing.SubjectID,
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
				s.domainID, s.deploymentID, account.Username, account.SubjectID, account.Role, account.Management.MSPID,
				account.Management.CertificateSHA256, hash); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM workbench_sessions WHERE deployment_id=$1 AND domain_id=$2 AND username=$3`,
				s.deploymentID, s.domainID, account.Username); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `DELETE FROM workbench_accounts WHERE deployment_id=$1 AND domain_id=$2 AND NOT (username = ANY($3))`,
			s.deploymentID, s.domainID, usernames)
		return err
	})
}

// Login authenticates username and password, verifies principal authority, rotates any previous
// session token, and persists a fresh session row in PostgreSQL.
func (s *SessionService) Login(ctx context.Context, username, password, prevToken string) (string, Principal, time.Time, error) {
	var principal Principal
	var expires time.Time
	if !ValidUsername(username) || !ValidPassword(password) {
		return "", principal, expires, ErrLoginFailed
	}
	var token string
	err := dao.RunInTx(ctx, s.db, func(tx dao.Tx) error {
		var hash []byte
		err := tx.QueryRow(ctx, `SELECT domain_id, subject_id, role, management_msp_id, management_fingerprint, password_hash
			FROM workbench_accounts WHERE deployment_id=$1 AND domain_id=$2 AND username=$3 FOR SHARE`,
			s.deploymentID, s.domainID, username).Scan(&principal.DomainID, &principal.SubjectID,
			&principal.Role, &principal.Management.MSPID, &principal.Management.CertificateSHA256, &hash)
		if errors.Is(err, pgx.ErrNoRows) {
			_ = bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), []byte(password))
			return ErrLoginFailed
		}
		if err != nil {
			return err
		}
		if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil || !ValidPrincipal(principal, s.domainID) {
			return ErrLoginFailed
		}
		if s.verifier != nil {
			if err := s.verifier.VerifyPrincipal(ctx, principal); err != nil {
				return err
			}
		}
		if prevToken != "" {
			previous := sessionDigest(prevToken)
			if _, err := tx.Exec(ctx, `DELETE FROM workbench_sessions WHERE deployment_id=$1 AND domain_id=$2 AND session_digest=$3`,
				s.deploymentID, s.domainID, previous[:]); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM workbench_sessions WHERE deployment_id=$1 AND domain_id=$2 AND username=$3 AND expires_at<=now()`,
			s.deploymentID, s.domainID, username); err != nil {
			return err
		}
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return err
		}
		token = base64.RawURLEncoding.EncodeToString(raw[:])
		digest := sessionDigest(token)
		return tx.QueryRow(ctx, `INSERT INTO workbench_sessions(deployment_id, domain_id, username, session_digest, expires_at)
			VALUES ($1,$2,$3,$4,now()+$5::interval) RETURNING expires_at`,
			s.deploymentID, s.domainID, username, digest[:], fmt.Sprintf("%d seconds", int(SessionLifetime/time.Second))).Scan(&expires)
	})
	if err != nil {
		return "", Principal{}, time.Time{}, err
	}
	return token, principal, expires, nil
}

// Authenticate resolves an active local session token into its bound Principal.
// Returns ErrSessionRequired when the token is absent, malformed, expired, or revoked.
func (s *SessionService) Authenticate(ctx context.Context, token string) (Principal, error) {
	var principal Principal
	if !ValidSessionToken(token) {
		return principal, ErrSessionRequired
	}
	digest := sessionDigest(token)
	err := s.db.QueryRow(ctx, `SELECT a.domain_id, a.subject_id, a.role, a.management_msp_id, a.management_fingerprint
		FROM workbench_sessions AS s JOIN workbench_accounts AS a USING (deployment_id, domain_id, username)
		WHERE s.deployment_id=$1 AND s.domain_id=$2 AND s.session_digest=$3 AND s.expires_at>now()`,
		s.deploymentID, s.domainID, digest[:]).Scan(&principal.DomainID, &principal.SubjectID,
		&principal.Role, &principal.Management.MSPID, &principal.Management.CertificateSHA256)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrSessionRequired
	}
	if err != nil {
		return Principal{}, err
	}
	if !ValidPrincipal(principal, s.domainID) {
		return Principal{}, ErrSessionRequired
	}
	return principal, nil
}

// Logout revokes the stored session identified by token.
func (s *SessionService) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	digest := sessionDigest(token)
	_, err := s.db.Exec(ctx, `DELETE FROM workbench_sessions WHERE deployment_id=$1 AND domain_id=$2 AND session_digest=$3`,
		s.deploymentID, s.domainID, digest[:])
	return err
}
