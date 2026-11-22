//go:build db

package baseline

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/gateway"
	"grad/platform/migrations"
	"grad/platform/state/central"
	"grad/protocol"
	"grad/protocol/registry"
)

func testPgPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("TEST_POSTGRES_DSN"))
	if dsn == "" {
		dsn = strings.TrimSpace(os.Getenv("FABRIC_TEST_DSN"))
	}
	if dsn == "" {
		t.Skip("set TEST_POSTGRES_DSN or FABRIC_TEST_DSN to run PostgreSQL baseline tests")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	db, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(db.Close)
	require.NoError(t, db.Ping(ctx))
	require.NoError(t, migrations.Up(ctx, db))
	return db
}

func TestBaselineRegistryReadbackUsesStoredAnchors(t *testing.T) {
	ctx := t.Context()
	db := testPgPool(t)
	r := newBaselineTestRun(t)
	r.db = db
	r.d.DeploymentID = registry.Digest([]byte(t.TempDir()))
	boot := registry.Bootstrap{Root: registry.RootRecord{DID: "did:web:t.local", KeyVersion: 1}}
	bootJSON := marshalTestRecord(t, boot)
	r.d.Bootstrap = boot
	r.d.BootstrapDigest = registry.Digest(bootJSON)

	active := registry.Version{Status: registry.Active, Revision: 1}
	domain := registry.Domain{ID: "A", Version: active}
	grant := registry.Grant{ID: "grant-1", Digest: registry.Digest([]byte("signed grant")), Version: active}
	preload := &protocol.SnapshotView{
		DeploymentID: r.d.DeploymentID,
		Root:         boot.Root,
		Domains:      map[string]registry.Domain{domain.ID: domain},
		Grants:       map[string]registry.Grant{grant.ID: grant},
	}
	centralSrc, err := central.Initialize(ctx, db, preload)
	require.NoError(t, err)
	r.c0 = centralSrc
	t.Cleanup(func() {
		for _, query := range []string{
			`DELETE FROM centralized_registry WHERE deployment_id=$1`,
			`DELETE FROM fabric_current WHERE deployment=$1`,
			`DELETE FROM fabric_head WHERE deployment=$1`,
		} {
			_, err := db.Exec(context.Background(), query, r.d.DeploymentID)
			assert.NoError(t, err)
		}
	})

	blockHash := registry.Digest([]byte(t.Name()))
	_, err = db.Exec(ctx, `INSERT INTO fabric_head VALUES($1, 50, $2)`, r.d.DeploymentID, blockHash)
	require.NoError(t, err)
	domain.Revision = 3
	grantKey := registry.Key("grant", grant.ID)
	for key, raw := range map[string][]byte{
		registry.BootstrapKey:           bootJSON,
		registry.Key("domain", domain.ID): marshalTestRecord(t, domain),
		grantKey:                        marshalTestRecord(t, grant),
	} {
		_, err = db.Exec(ctx, `INSERT INTO fabric_current VALUES($1, $2, $3)`, r.d.DeploymentID, key, raw)
		require.NoError(t, err)
	}

	require.NoError(t, r.checkRegistryReadback(ctx, preload))
	getReadback := func() *baselineRegistryReadback {
		return r.evidence.Manifest["registry_readback"].(*baselineRegistryReadback)
	}
	matched := getReadback()
	require.NotNil(t, matched.Matched)
	assert.True(t, *matched.Matched)
	assert.Equal(t, int64(1), matched.C0.Revision)
	assert.False(t, matched.C0.StateReadAt.IsZero())
	assert.Equal(t, uint64(1), matched.C0.ObjectRevisions["domain/A"])
	assert.Equal(t, uint64(3), matched.Fabric.ObjectRevisions["domain/A"])
	assert.Equal(t, uint64(50), matched.Fabric.BlockNumber)
	assert.Equal(t, blockHash, matched.Fabric.BlockHash)

	// Change a signed anchor after preload without touching the original input.
	changed := grant
	changed.Digest = registry.Digest([]byte("other signed grant"))
	_, err = db.Exec(ctx, `UPDATE fabric_current SET value=$3 WHERE deployment=$1 AND key=$2`,
		r.d.DeploymentID, grantKey, marshalTestRecord(t, changed))
	require.NoError(t, err)
	require.Error(t, r.checkRegistryReadback(ctx, preload), "accepted a different registered grant digest")
	mismatch := getReadback()
	require.NotNil(t, mismatch.Matched)
	assert.False(t, *mismatch.Matched)
	assert.Equal(t, matched.C0.AnchorDigest, mismatch.C0.AnchorDigest)
	assert.NotEqual(t, matched.Fabric.AnchorDigest, mismatch.Fabric.AnchorDigest)

	_, err = db.Exec(ctx, `DELETE FROM fabric_current WHERE deployment=$1 AND key=$2`, r.d.DeploymentID, grantKey)
	require.NoError(t, err)
	require.Error(t, r.checkRegistryReadback(ctx, preload), "accepted a missing Fabric grant")
	partial := getReadback()
	assert.NotNil(t, partial.C0)
	assert.Nil(t, partial.Fabric)
	assert.Nil(t, partial.Matched)
}

func TestBaselineChecksHTTPOrderAndPrimaryIndependently(t *testing.T) {
	cfg := testPgPool(t).Config().Copy()
	cfg.MaxConns = 1 // Keep temporary test tables local to one database session.
	db, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec(t.Context(), `
		CREATE TEMP TABLE decisions (
			deployment_id text, decision_id text, request_id text, challenge_id text,
			task_id text, actor text, idempotency_key text, outcome text, code text,
			quote_id text, order_id text,
			state_source text DEFAULT 'centralized', revision bigint, state_read_at timestamptz,
			block_number bigint, block_hash text, probe_tx_id text, probe_block bigint,
			probe_sent_at bigint, probe_deadline bigint, probe_sent_mono_ns bigint,
			probe_deadline_mono_ns bigint, probe_checked_mono_ns bigint,
			context_version bigint, context_observed_at bigint, context_access_deadline bigint,
			decision_at bigint, effective_deadline bigint, state_rechecks integer
		);
		CREATE TEMP TABLE challenges (
			deployment_id text, challenge_id text, consumed_at bigint, decision_id text, request_hash text
		);
		CREATE TEMP TABLE orders (
			deployment_id text, task_id text, actor text, idempotency_key text,
			order_id text, status text, decision_id text, quote_id text, total_amount_minor bigint
		);
		CREATE TEMP TABLE business_keys (
			deployment_id text, actor text, task_id text, action text,
			idempotency_key text, status text, resource_id text, decision_id text
		);
		CREATE TEMP TABLE quotes (
			deployment_id text, quote_id text, total_amount_minor bigint, actor text, task_id text
		);
		INSERT INTO decisions (deployment_id, decision_id, request_id, challenge_id, task_id, actor, idempotency_key, outcome, code, quote_id, order_id)
			VALUES ('test','decision','request','challenge','task','actor','key','ALLOW','ALLOW','quote','order');
		INSERT INTO challenges VALUES ('test','challenge',1,'decision','hash');
		INSERT INTO orders VALUES ('test','task','actor','key','order','CREATED','decision','quote',80000);
		INSERT INTO business_keys VALUES ('test','actor','task','order.create','key','COMPLETED','order','decision');
		INSERT INTO quotes VALUES ('test','quote',80000,'actor','task');`)
	require.NoError(t, err)

	for _, tc := range []struct {
		name          string
		order         *gateway.OrderPayload
		decisionError bool
		badPrimary    bool
		verdict       string
	}{
		{name: "matching", order: &gateway.OrderPayload{OrderID: "order", QuoteID: "quote", Status: "CREATED", TotalAmountMinor: 80000}, verdict: "PASS"},
		{name: "missing-order", decisionError: true, verdict: "FAIL"},
		{name: "wrong-order-id", order: &gateway.OrderPayload{OrderID: "wrong", QuoteID: "quote", Status: "CREATED", TotalAmountMinor: 80000}, decisionError: true, verdict: "FAIL"},
		{name: "wrong-quote-id", order: &gateway.OrderPayload{OrderID: "order", QuoteID: "wrong", Status: "CREATED", TotalAmountMinor: 80000}, decisionError: true, verdict: "FAIL"},
		{name: "wrong-status", order: &gateway.OrderPayload{OrderID: "order", QuoteID: "quote", Status: "WRONG", TotalAmountMinor: 80000}, verdict: "FAIL"},
		{name: "wrong-amount", order: &gateway.OrderPayload{OrderID: "order", QuoteID: "quote", Status: "CREATED", TotalAmountMinor: 120000}, verdict: "FAIL"},
		{name: "wrong-primary-key-status", order: &gateway.OrderPayload{OrderID: "order", QuoteID: "quote", Status: "CREATED", TotalAmountMinor: 80000}, badPrimary: true, verdict: "FAIL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyStatus := "COMPLETED"
			if tc.badPrimary {
				keyStatus = "IN_PROGRESS"
			}
			_, err := db.Exec(t.Context(), `UPDATE business_keys SET status=$1`, keyStatus)
			require.NoError(t, err)

			r := newBaselineTestRun(t)
			row, check := &r.evidence.Requests[1], &r.evidence.Orders[0]
			row.TaskID = someString("task")
			row.Actor = someString("actor")
			row.IdempotencyKey = someString("key")
			row.QuoteID = someString("quote")
			r.options.RequestTimeout = time.Second

			handler := r.observe(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Request-Id", "request")
				require.NoError(t, json.NewEncoder(w).Encode(gateway.ExecuteResponse{
					DecisionID: "decision",
					Code:       "ALLOW",
					Order:      tc.order,
				}))
			}), func() *RequestRow { return row })

			r.action(t.Context(), row, nil, func(ctx context.Context) error {
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/access/execute", strings.NewReader(`{"challengeId":"challenge"}`))
				handler.ServeHTTP(httptest.NewRecorder(), req)
				return nil
			})
			row.RequestHash = someString("hash")
			httpID, httpQuoteID := row.OrderID, row.QuoteID
			err = r.decision(t.Context(), db, row)
			if tc.decisionError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, httpID, row.OrderID, "database lookup overwrote HTTP order_id")
			assert.Equal(t, httpQuoteID, row.QuoteID, "database lookup overwrote HTTP quote_id")

			r.checkOrder(t.Context(), db, r.inputs.Cases[0], row, check, 0, "quote")
			assert.Equal(t, tc.verdict, check.Verdict)
			assert.Equal(t, someString("order"), check.OrderID)
			assert.Equal(t, someString("CREATED"), check.OrderStatus)
		})
	}

	t.Run("execute-failure-without-decision", func(t *testing.T) {
		_, err := db.Exec(t.Context(), `INSERT INTO challenges VALUES ('test','failed-challenge',NULL,NULL,'failed-hash')`)
		require.NoError(t, err)
		r := newBaselineTestRun(t)
		row, check := &r.evidence.Requests[1], &r.evidence.Orders[0]
		row.TaskID = someString("task")
		row.Actor = someString("actor")
		row.IdempotencyKey = someString("failed-key")
		row.FailureStage = someString("execute")
		row.ChallengeID = someString("failed-challenge")

		r.checkDecision(t.Context(), db, row, "order-decision")
		r.checkOrder(t.Context(), db, r.inputs.Cases[0], row, check, 1, "quote")
		assert.Equal(t, "FAIL", check.Verdict)
		assert.Equal(t, someString("order execution returned no decision"), check.FailureReason)
		assert.Equal(t, someInt64(1), check.OrderRowsAfter)
		assert.Equal(t, someInt64(0), check.OrderKeyRows)
		assert.Equal(t, someBool(false), check.ChallengeConsumed)
		assert.False(t, check.DecisionID.Valid)
		assert.Empty(t, r.evidence.Summary.Failures)
	})
}

func marshalTestRecord(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return raw
}
