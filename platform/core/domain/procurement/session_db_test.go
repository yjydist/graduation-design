//go:build db

package procurement

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/ledger"
	"grad/platform/internal/testutil"
	"grad/protocol"
	preg "grad/protocol/registry"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.RunWithPostgres(m))
}

type stubAuthorityReader struct {
	domain        string
	verifyErr     error
	eligibleExtra []string
}

func (a *stubAuthorityReader) VerifyPrincipal(_ context.Context, principal Principal) error {
	if a.verifyErr != nil {
		return a.verifyErr
	}
	if !ValidPrincipal(principal, a.domain) {
		return principalForbidden()
	}
	return nil
}

func (a *stubAuthorityReader) ReadPurchasingAuthority(_ context.Context, principal Principal) (PurchasingAuthority, error) {
	if principal.Role != RoleAdmin {
		return PurchasingAuthority{}, principalForbidden()
	}
	return PurchasingAuthority{
		DomainID:           a.domain,
		ExpectedRevision:   2,
		EligibleServiceIDs: append([]string{testServiceDID(a.domain)}, a.eligibleExtra...),
	}, nil
}

func (a *stubAuthorityReader) CheckPurchasingAuthority(_ context.Context, _ Principal, did string) error {
	if did != testServiceDID(a.domain) {
		return preg.Reject(preg.ErrCodePurchasingAuthorityInvalid)
	}
	return nil
}

func testServiceDID(domain string) string {
	return "did:web:" + strings.ToLower(domain) + ".local:pa"
}

func testAccount(domain, name string, role Role, hashChar string) AccountSeed {
	return AccountSeed{
		Principal: Principal{
			DomainID:  domain,
			SubjectID: "did:web:" + strings.ToLower(domain) + ".local:" + name,
			Role:      role,
			Management: preg.Management{
				MSPID:             domain + "Msp",
				CertificateSHA256: strings.Repeat(hashChar, 64),
			},
		},
		Username: name,
		Password: "example-password",
	}
}

type testManagementBackend struct {
	submissionCount atomic.Int32
	submitted       sync.Map
}

func (*testManagementBackend) CurrentRevision(_ context.Context, kind, id string) (uint64, bool, error) {
	if kind != "domain" || (id != "A" && id != "B" && id != "C") {
		return 0, false, errors.New("unexpected record lookup")
	}
	return 2, true, nil
}

func (b *testManagementBackend) SubmitAsync(
	_ context.Context,
	key, id string,
	caller preg.Management,
	method string,
	input json.RawMessage,
	update domreg.OutcomeHandler,
) {
	var body preg.PurchasingAuthorityUpdate
	if method != SetPurchasingAuthorityMethod || json.Unmarshal(input, &body) != nil || body.DeploymentID != "dep-1" ||
		caller.MSPID != body.DomainID+"Msp" || body.PurchasingAuthority != testServiceDID(body.DomainID) {
		return
	}
	if _, replay := b.submitted.LoadOrStore(id, struct{}{}); replay {
		return
	}
	b.submissionCount.Add(1)
	txID := preg.Digest([]byte(id))
	if key == "reject-endorsement" {
		_ = update("ENDORSE", "FAILED", txID, nil, nil, false)
		return
	}
	_ = update("COMMIT", "CONFIRMED", txID, &ledger.Outcome{
		Point:        ledger.Point{Number: 17, Hash: preg.Digest([]byte(txID))},
		Code:         "VALID",
		ObservedPeer: "peer-" + strings.ToLower(body.DomainID),
	}, nil, false)
}

func TestSessionServiceAndAuthorityManagement(t *testing.T) {
	ctx := t.Context()
	db := testutil.OpenMigratedPool(t)
	backend := &testManagementBackend{}

	authA := &stubAuthorityReader{domain: "A"}
	authB := &stubAuthorityReader{domain: "B"}
	authC := &stubAuthorityReader{domain: "C"}

	sessA, err := NewSessionService(db, "dep-1", "A", authA)
	require.NoError(t, err)
	sessB, err := NewSessionService(db, "dep-1", "B", authB)
	require.NoError(t, err)
	sessC, err := NewSessionService(db, "dep-1", "C", authC)
	require.NoError(t, err)

	regSvc := func() *domreg.Service {
		return domreg.NewService(db, "dep-1", preg.Management{}, backend)
	}
	mgmtA := NewAuthorityService("dep-1", authA, regSvc())
	mgmtB := NewAuthorityService("dep-1", authB, regSvc())
	mgmtC := NewAuthorityService("dep-1", authC, regSvc())

	a := testAccount("A", "admin", RoleAdmin, "a")
	b := testAccount("B", "admin", RoleAdmin, "b")
	c := testAccount("C", "admin", RoleAdmin, "c")
	u := testAccount("A", "buyer", RoleBuyer, "d")
	caudit := AccountSeed{Principal: c.Principal, Username: "audit", Password: c.Password}
	caudit.Role = RoleAuditor

	require.NoError(t, sessA.SeedAccounts(ctx, []AccountSeed{a, u}))
	require.NoError(t, sessB.SeedAccounts(ctx, []AccountSeed{b}))
	require.NoError(t, sessC.SeedAccounts(ctx, []AccountSeed{c, caudit}))

	type domainSet struct {
		sess    *SessionService
		mgmt    *AuthorityService
		account AccountSeed
	}
	var operations []string
	var aToken string
	var aPrincipal Principal

	for _, ds := range []domainSet{{sessA, mgmtA, a}, {sessB, mgmtB, b}, {sessC, mgmtC, c}} {
		tok, principal, expires, err := ds.sess.Login(ctx, ds.account.Username, ds.account.Password, "")
		require.NoError(t, err)
		require.True(t, ValidSessionToken(tok))
		require.Equal(t, ds.account.Principal, principal)
		require.True(t, expires.After(time.Now()))
		if ds.account.DomainID == "A" {
			aToken, aPrincipal = tok, principal
		}

		authed, err := ds.sess.Authenticate(ctx, tok)
		require.NoError(t, err)
		require.Equal(t, principal, authed)
		view := ds.sess.SessionView(authed, tok)
		require.Equal(t, []string{"managePurchasingAuthority"}, view.Actions)
		require.True(t, VerifyCSRF(tok, view.CSRFToken))

		qual, err := ds.mgmt.ReadPurchasingAuthority(ctx, principal)
		require.NoError(t, err)
		require.Equal(t, ds.account.DomainID, qual.DomainID)
		require.Len(t, qual.EligibleServiceIDs, 1)

		// Invalid revision / foreign PA / stale revision checks
		_, err = ds.mgmt.SetPurchasingAuthority(ctx, principal, "bad-rev", 0, nil)
		require.Equal(t, preg.ErrCodeInvalidSchema, protocol.CodeOf(err))

		_, err = ds.mgmt.SetPurchasingAuthority(ctx, principal, "stale", 1, nil)
		require.Equal(t, preg.ErrCodeStateChanged, protocol.CodeOf(err))

		foreign := "did:web:foreign.local:pa"
		_, err = ds.mgmt.SetPurchasingAuthority(ctx, principal, "foreign", 2, &foreign)
		require.Equal(t, preg.ErrCodePurchasingAuthorityInvalid, preg.CodeOf(err))

		target := qual.EligibleServiceIDs[0]
		op, err := ds.mgmt.SetPurchasingAuthority(ctx, principal, "update", 2, &target)
		require.NoError(t, err)
		require.Equal(t, "PENDING", op.Status)
		operations = append(operations, op.OperationID)

		// Idempotent replay
		replay, err := ds.mgmt.SetPurchasingAuthority(ctx, principal, "update", 2, &target)
		require.NoError(t, err)
		require.Equal(t, op.OperationID, replay.OperationID)

		// Idempotency conflict with different payload
		_, err = ds.mgmt.SetPurchasingAuthority(ctx, principal, "update", 2, nil)
		require.Equal(t, preg.ErrCodeIdempotencyConflict, protocol.CodeOf(err))

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			res, err := ds.mgmt.GetOperation(ctx, principal, op.OperationID)
			if assert.NoError(ct, err) && assert.Equal(ct, "CONFIRMED", res.Status) {
				assert.True(ct, preg.IsDigest(res.TxID))
				if assert.NotNil(ct, res.ValidationCode) {
					assert.Equal(ct, "VALID", *res.ValidationCode)
				}
			}
		}, 2*time.Second, 10*time.Millisecond)
	}
	require.Equal(t, int32(3), backend.submissionCount.Load())

	// Buyer cannot manage PA or inspect admin operations; A admin cannot inspect B's operations.
	buyerTok, buyerPrincipal, _, err := sessA.Login(ctx, u.Username, u.Password, "")
	require.NoError(t, err)
	_, err = mgmtA.SetPurchasingAuthority(ctx, buyerPrincipal, "forged", 2, nil)
	require.Equal(t, preg.ErrCodeIdentityManagementForbidden, preg.CodeOf(err))
	_, err = mgmtA.GetOperation(ctx, buyerPrincipal, operations[0])
	require.Equal(t, preg.ErrCodeOperationUnknown, protocol.CodeOf(err))
	_, err = mgmtA.GetOperation(ctx, aPrincipal, operations[1])
	require.Equal(t, preg.ErrCodeOperationUnknown, protocol.CodeOf(err))

	// Endorsement rejection propagates to FAILED.
	paA := testServiceDID("A")
	failed, err := mgmtA.SetPurchasingAuthority(ctx, aPrincipal, "reject-endorsement", 2, &paA)
	require.NoError(t, err)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		res, err := mgmtA.GetOperation(ctx, aPrincipal, failed.OperationID)
		if assert.NoError(ct, err) && assert.Equal(ct, "FAILED", res.Status) {
			if assert.NotNil(ct, res.FailureCode) {
				assert.Equal(ct, preg.ErrCodeEndorsementRejected, *res.FailureCode)
			}
		}
	}, 2*time.Second, 10*time.Millisecond)

	// Cross-domain and cross-deployment session isolation.
	_, err = sessB.Authenticate(ctx, aToken)
	require.ErrorIs(t, err, ErrSessionRequired)
	otherDep, err := NewSessionService(db, "dep-2", "A", authA)
	require.NoError(t, err)
	_, err = otherDep.Authenticate(ctx, aToken)
	require.ErrorIs(t, err, ErrSessionRequired)

	// Restart preserves unchanged accounts/sessions; revocation blocks VerifyPrincipal but allows Logout.
	restarted, err := NewSessionService(db, "dep-1", "A", authA)
	require.NoError(t, err)
	require.NoError(t, restarted.SeedAccounts(ctx, []AccountSeed{a, u}))
	_, err = restarted.Authenticate(ctx, buyerTok)
	require.NoError(t, err)

	revokedAuth := &stubAuthorityReader{domain: "A", verifyErr: principalForbidden()}
	revokedSess, err := NewSessionService(db, "dep-1", "A", revokedAuth)
	require.NoError(t, err)
	p, err := revokedSess.Authenticate(ctx, buyerTok)
	require.NoError(t, err)
	require.Equal(t, preg.ErrCodeIdentityManagementForbidden, preg.CodeOf(revokedSess.VerifyPrincipal(ctx, p)))
	require.NoError(t, revokedSess.Logout(ctx, buyerTok))
	_, err = restarted.Authenticate(ctx, buyerTok)
	require.ErrorIs(t, err, ErrSessionRequired)

	// Removing an account or changing password revokes existing sessions.
	oldAuditTok, _, _, err := sessC.Login(ctx, caudit.Username, caudit.Password, "")
	require.NoError(t, err)
	require.NoError(t, sessC.SeedAccounts(ctx, []AccountSeed{c}))
	_, err = sessC.Authenticate(ctx, oldAuditTok)
	require.ErrorIs(t, err, ErrSessionRequired)

	a.Password = "updated-example-password"
	require.NoError(t, restarted.SeedAccounts(ctx, []AccountSeed{a, u}))
	_, err = restarted.Authenticate(ctx, aToken)
	require.ErrorIs(t, err, ErrSessionRequired)
	_, _, _, err = restarted.Login(ctx, a.Username, a.Password, "")
	require.NoError(t, err)
	var hash []byte
	require.NoError(t, db.QueryRow(ctx, `SELECT password_hash FROM workbench_accounts WHERE deployment_id='dep-1' AND domain_id='A' AND username='admin'`).Scan(&hash))
	require.NoError(t, bcrypt.CompareHashAndPassword(hash, []byte(a.Password)))

	// Invalid login returns ErrLoginFailed.
	_, _, _, err = restarted.Login(ctx, "unknown-user", "wrong", "")
	require.ErrorIs(t, err, ErrLoginFailed)
}
