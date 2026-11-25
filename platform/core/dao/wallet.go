package dao

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"grad/protocol"
)

const (
	// ActionStatusPending marks an action row prior to network dispatch.
	ActionStatusPending = "PENDING"
	// ActionStatusOutcomeUnknown marks a persisted order intent whose gateway outcome is not yet known.
	ActionStatusOutcomeUnknown = "OUTCOME_UNKNOWN"
	// ActionStatusSubmitted marks an action explicitly recorded as submitted.
	ActionStatusSubmitted = "SUBMITTED"
	// ActionStatusCompleted marks an order intent confirmed directly by a 200 OK gateway response.
	ActionStatusCompleted = "COMPLETED"
	// ActionStatusReconciled marks an order intent finalized via C audit receipt (CREATED or NOT_CREATED).
	ActionStatusReconciled = "RECONCILED"
	// ActionStatusFailed marks an order intent definitively rejected by a 4xx gateway response.
	ActionStatusFailed = "FAILED"
)

// ClientAction models a durable client_actions intent lock row from 005_agent.sql.
type ClientAction struct {
	DeploymentID   string   `db:"deployment_id" json:"deploymentId"`
	ActionID       string   `db:"action_id" json:"actionId"`
	Actor          string   `db:"actor" json:"actor"`
	TaskID         string   `db:"task_id" json:"taskId"`
	Action         string   `db:"action" json:"action"`
	IdempotencyKey string   `db:"idempotency_key" json:"idempotencyKey"`
	RequestHash    string   `db:"request_hash" json:"requestHash"`
	RequestJSON    string   `db:"request_json" json:"-"`
	SendRevision   int64    `db:"send_revision" json:"sendRevision"`
	ChallengeID    string   `db:"challenge_id" json:"challengeId,omitempty"`
	ChallengeIDs   []string `db:"challenge_ids" json:"challengeIds,omitempty"`
	QuoteID        string   `db:"quote_id" json:"quoteId,omitempty"`
	OrderID        string   `db:"order_id" json:"orderId,omitempty"`
	DecisionID     string   `db:"decision_id" json:"decisionId,omitempty"`
	CaseID         string   `db:"case_id" json:"caseId,omitempty"`
	Outcome        string   `db:"outcome" json:"outcome,omitempty"`
	Status         string   `db:"status" json:"status"`
	CreatedAt      int64    `db:"created_at" json:"createdAt"`
	UpdatedAt      int64    `db:"updated_at" json:"updatedAt"`
}

// ClientActionView summarizes an order execution intent lock for inspection without sensitive secrets.
type ClientActionView struct {
	ActionID       string   `json:"actionId"`
	Actor          string   `json:"actor"`
	TaskID         string   `json:"taskId"`
	Action         string   `json:"action"`
	IdempotencyKey string   `json:"idempotencyKey"`
	Status         string   `json:"status"`
	SendRevision   int64    `json:"sendRevision"`
	ChallengeID    string   `json:"challengeId,omitempty"`
	ChallengeIDs   []string `json:"challengeIds,omitempty"`
	QuoteID        string   `json:"quoteId,omitempty"`
	OrderID        string   `json:"orderId,omitempty"`
	DecisionID     string   `json:"decisionId,omitempty"`
	CaseID         string   `json:"caseId,omitempty"`
	Outcome        string   `json:"outcome,omitempty"`
}

// View returns a sanitized ClientActionView copy of a.
func (a ClientAction) View() ClientActionView {
	return ClientActionView{
		ActionID:       a.ActionID,
		Actor:          a.Actor,
		TaskID:         a.TaskID,
		Action:         a.Action,
		IdempotencyKey: a.IdempotencyKey,
		Status:         a.Status,
		SendRevision:   a.SendRevision,
		ChallengeID:    a.ChallengeID,
		ChallengeIDs:   slices.Clone(a.ChallengeIDs),
		QuoteID:        a.QuoteID,
		OrderID:        a.OrderID,
		DecisionID:     a.DecisionID,
		CaseID:         a.CaseID,
		Outcome:        a.Outcome,
	}
}

// OrderOutcomeReceipt models the minimal role-bound reconciliation receipt delivered to B.
type OrderOutcomeReceipt struct {
	CaseID             string  `json:"caseId"`
	CheckNo            int64   `json:"checkNo"`
	SendRevision       int64   `json:"sendRevision"`
	DeploymentID       string  `json:"deploymentId"`
	Actor              string  `json:"actor"`
	TaskID             string  `json:"taskId"`
	RequestHash        string  `json:"requestHash"`
	Outcome            string  `json:"outcome"`
	OrderID            *string `json:"orderId"`
	CreationDecisionID *string `json:"creationDecisionId,omitempty"`
	HistoricalStatus   string  `json:"historicalStatus,omitempty"`
	AuditAt            int64   `json:"auditAt,omitempty"`
}

// OrderOutcomeReceiptResponse models 200 OK from POST /v1/internal/order-outcome-receipts.
type OrderOutcomeReceiptResponse struct {
	Status             string              `json:"status"`
	ClientActionStatus string              `json:"clientActionStatus,omitempty"`
	Receipt            OrderOutcomeReceipt `json:"receipt"`
}

// BoundQuote models a row in wallet_bound_quotes (012_bound_quotes.sql).
type BoundQuote struct {
	DeploymentID     string
	Actor            string
	TaskID           string
	QuoteKey         string
	QuoteID          string
	Currency         string
	TotalAmountMinor int64
}

type receiptKey struct {
	deploymentID string
	caseID       string
	sendRevision int64
	checkNo      int64
}

type storedReceiptRow struct {
	DeploymentID       string  `db:"deployment_id"`
	CaseID             string  `db:"case_id"`
	CheckNo            int64   `db:"check_no"`
	SendRevision       int64   `db:"send_revision"`
	Actor              string  `db:"actor"`
	TaskID             string  `db:"task_id"`
	RequestHash        string  `db:"request_hash"`
	Outcome            string  `db:"outcome"`
	OrderID            *string `db:"order_id"`
	CreationDecisionID *string `db:"creation_decision_id"`
	HistoricalStatus   string  `db:"historical_status"`
	AuditAt            int64   `db:"audit_at"`
	ReceivedAt         int64   `db:"received_at"`
}

// ActionStore owns durable client_actions, order_outcome_receipts (005_agent.sql),
// and wallet_bound_quotes (012_bound_quotes.sql) persistence with an equivalent
// concurrency-safe in-memory fallback when db is nil.
type ActionStore struct {
	db           *pgxpool.Pool
	deploymentID string
	now          func() time.Time

	sendMu   sync.Mutex
	mu       sync.Mutex
	actions  map[string]*ClientAction
	byKey    map[string]string
	receipts map[receiptKey]OrderOutcomeReceipt
}

// NewActionStore constructs an ActionStore bound to deploymentID. When db is nil, an in-memory store is used.
func NewActionStore(db *pgxpool.Pool, deploymentID string, now func() time.Time) *ActionStore {
	if now == nil {
		now = time.Now
	}
	return &ActionStore{
		db:           db,
		deploymentID: deploymentID,
		now:          now,
		actions:      make(map[string]*ClientAction),
		byKey:        make(map[string]string),
		receipts:     make(map[receiptKey]OrderOutcomeReceipt),
	}
}

// Pool returns the underlying database pool, or nil for in-memory stores.
func (s *ActionStore) Pool() *pgxpool.Pool {
	if s == nil {
		return nil
	}
	return s.db
}

const clientActionSelectCols = `
	deployment_id, action_id, actor, task_id, action, idempotency_key,
	request_hash, request_json, send_revision,
	COALESCE(challenge_id, '') AS challenge_id, challenge_ids,
	COALESCE(quote_id, '') AS quote_id, COALESCE(order_id, '') AS order_id,
	COALESCE(decision_id, '') AS decision_id, COALESCE(case_id, '') AS case_id,
	COALESCE(outcome, '') AS outcome, status, created_at, updated_at`

// BeginClientAction idempotently persists a local intent lock with status OUTCOME_UNKNOWN and sendRevision=1
// BEFORE an order.create network request is dispatched.
func (s *ActionStore) BeginClientAction(
	ctx context.Context,
	actor, taskID, action, idempotencyKey, requestHash, requestJSON string,
) (*ClientAction, error) {
	if actor == "" || taskID == "" || action == "" || idempotencyKey == "" || !protocol.IsHexDigest(requestHash, false) {
		return nil, protocol.NewError(protocol.ErrCodeInvalidSchema, "actor, taskId, action, idempotencyKey, and 64-hex requestHash are required")
	}
	nowSec := s.now().UTC().Unix()
	if s.db != nil {
		actionID := "urn:grad:action:" + newUUID()
		if _, err := s.db.Exec(ctx, `INSERT INTO client_actions(
				deployment_id, action_id, actor, task_id, action, idempotency_key,
				request_hash, request_json, send_revision, status, created_at, updated_at
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,$9,$10,$10)
			ON CONFLICT (deployment_id, actor, task_id, action, idempotency_key) DO NOTHING`,
			s.deploymentID, actionID, actor, taskID, action, idempotencyKey,
			requestHash, requestJSON, ActionStatusOutcomeUnknown, nowSec,
		); err != nil {
			return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "insert client_actions row", err)
		}
		rec, err := s.GetClientActionByKey(ctx, actor, taskID, action, idempotencyKey)
		if err != nil {
			return nil, err
		}
		if rec.RequestHash != requestHash {
			return nil, protocol.NewError(protocol.ErrCodeIdempotencyConflict, "client action idempotencyKey bound to different requestHash")
		}
		return rec, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	key := actionMapKey(actor, taskID, action, idempotencyKey)
	if id, ok := s.byKey[key]; ok {
		existing := s.actions[id]
		if existing.RequestHash != requestHash {
			return nil, protocol.NewError(protocol.ErrCodeIdempotencyConflict, "client action idempotencyKey bound to different requestHash")
		}
		return cloneClientAction(existing), nil
	}
	rec := &ClientAction{
		DeploymentID:   s.deploymentID,
		ActionID:       "urn:grad:action:" + newUUID(),
		Actor:          actor,
		TaskID:         taskID,
		Action:         action,
		IdempotencyKey: idempotencyKey,
		RequestHash:    requestHash,
		RequestJSON:    requestJSON,
		SendRevision:   1,
		ChallengeIDs:   []string{},
		Status:         ActionStatusOutcomeUnknown,
		CreatedAt:      nowSec,
		UpdatedAt:      nowSec,
	}
	s.actions[rec.ActionID] = rec
	s.byKey[key] = rec.ActionID
	return cloneClientAction(rec), nil
}

// GetClientActionByKey loads an existing client_actions row by its unique idempotency tuple.
func (s *ActionStore) GetClientActionByKey(
	ctx context.Context,
	actor, taskID, action, idempotencyKey string,
) (*ClientAction, error) {
	if s.db != nil {
		rows, err := s.db.Query(ctx, `SELECT `+clientActionSelectCols+`
			FROM client_actions
			WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND action=$4 AND idempotency_key=$5`,
			s.deploymentID, actor, taskID, action, idempotencyKey,
		)
		if err != nil {
			return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "query client_actions", err)
		}
		rec, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[ClientAction])
		if err != nil {
			return nil, err
		}
		return &rec, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byKey[actionMapKey(actor, taskID, action, idempotencyKey)]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return cloneClientAction(s.actions[id]), nil
}

// ListClientActions returns persisted client_actions rows filtered by optional actor and taskID.
func (s *ActionStore) ListClientActions(ctx context.Context, actor, taskID string) ([]ClientAction, error) {
	if s.db != nil {
		rows, err := s.db.Query(ctx, `SELECT `+clientActionSelectCols+`
			FROM client_actions
			WHERE deployment_id=$1
			  AND ($2 = '' OR actor = $2)
			  AND ($3 = '' OR task_id = $3)
			ORDER BY created_at ASC, action_id ASC`,
			s.deploymentID, actor, taskID,
		)
		if err != nil {
			return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "list client_actions", err)
		}
		list, err := pgx.CollectRows(rows, pgx.RowToStructByName[ClientAction])
		if err != nil {
			return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "collect client_actions", err)
		}
		return list, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ClientAction, 0, len(s.actions))
	for _, rec := range s.actions {
		if actor != "" && rec.Actor != actor {
			continue
		}
		if taskID != "" && rec.TaskID != taskID {
			continue
		}
		out = append(out, *cloneClientAction(rec))
	}
	slices.SortFunc(out, func(a, b ClientAction) int {
		if a.CreatedAt != b.CreatedAt {
			if a.CreatedAt < b.CreatedAt {
				return -1
			}
			return 1
		}
		return strings.Compare(a.ActionID, b.ActionID)
	})
	return out, nil
}

// RecordClientActionChallenge atomically binds a challenge attempt to an active sendRevision
// and keeps the intent in OUTCOME_UNKNOWN before network dispatch.
// Stale workers holding an outdated sendRevision are rejected with STATE_CHANGED.
func (s *ActionStore) RecordClientActionChallenge(
	ctx context.Context,
	actionID string,
	expectedSendRevision int64,
	challengeID, requestJSON string,
) (*ClientAction, error) {
	nowSec := s.now().UTC().Unix()
	if s.db != nil {
		rows, err := s.db.Query(ctx, `UPDATE client_actions
			SET status=$1,
			    challenge_id=COALESCE(NULLIF($2,''), challenge_id),
			    challenge_ids=CASE WHEN $2 <> '' AND NOT ($2 = ANY(challenge_ids)) THEN array_append(challenge_ids, $2) ELSE challenge_ids END,
			    request_json=COALESCE(NULLIF($3,''), request_json),
			    updated_at=$4
			WHERE deployment_id=$5 AND action_id=$6 AND send_revision=$7
			  AND status IN ('PENDING', 'OUTCOME_UNKNOWN', 'FAILED') AND COALESCE(case_id, '') = ''
			RETURNING `+clientActionSelectCols,
			ActionStatusOutcomeUnknown, challengeID, requestJSON, nowSec, s.deploymentID, actionID, expectedSendRevision,
		)
		if err != nil {
			return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "record client action challenge", err)
		}
		rec, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[ClientAction])
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, protocol.NewError(protocol.ErrCodeStateChanged, "client action send_revision mismatch or already stopped/finalized")
		}
		if err != nil {
			return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "scan client action challenge", err)
		}
		return &rec, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.actions[actionID]
	if !ok {
		return nil, protocol.NewError(protocol.ErrCodeInvalidSchema, "unknown local client action")
	}
	if rec.CaseID != "" || rec.SendRevision != expectedSendRevision || !isRetryableActionStatus(rec.Status) {
		return nil, protocol.NewError(protocol.ErrCodeStateChanged, "client action send_revision mismatch or already stopped/finalized")
	}
	rec.Status = ActionStatusOutcomeUnknown
	if challengeID != "" {
		rec.ChallengeID = challengeID
		if !slices.Contains(rec.ChallengeIDs, challengeID) {
			rec.ChallengeIDs = append(rec.ChallengeIDs, challengeID)
		}
	}
	if requestJSON != "" && rec.RequestJSON == "" {
		rec.RequestJSON = requestJSON
	}
	rec.UpdatedAt = nowSec
	return cloneClientAction(rec), nil
}

// DispatchClientAction serializes the final network send against StopClientActionSend
// so a stop transition cannot race a delayed worker between its check and dispatch.
func (s *ActionStore) DispatchClientAction(
	ctx context.Context,
	actionID string,
	expectedSendRevision int64,
	send func() error,
) error {
	if send == nil {
		return protocol.NewError(protocol.ErrCodeInvalidSchema, "send callback is required")
	}
	if s.db != nil {
		return RunInTx(ctx, s.db, func(tx Tx) error {
			var current int64
			var status string
			var caseID *string
			if err := tx.QueryRow(ctx, `SELECT send_revision, status, case_id
				FROM client_actions
				WHERE deployment_id=$1 AND action_id=$2
				FOR UPDATE`,
				s.deploymentID, actionID,
			).Scan(&current, &status, &caseID); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return protocol.NewError(protocol.ErrCodeInvalidSchema, "client action not found")
				}
				return protocol.WrapError(protocol.ErrCodeStateUnavailable, "lock client action for dispatch", err)
			}
			if current != expectedSendRevision || (caseID != nil && *caseID != "") || !isRetryableActionStatus(status) {
				return protocol.NewError(protocol.ErrCodeStateChanged, "client action is stopped, stale, or finalized")
			}
			return send()
		})
	}

	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.mu.Lock()
	rec := s.actions[actionID]
	allowed := rec != nil && rec.CaseID == "" && rec.SendRevision == expectedSendRevision && isRetryableActionStatus(rec.Status)
	s.mu.Unlock()
	if !allowed {
		return protocol.NewError(protocol.ErrCodeStateChanged, "client action is stopped, stale, or finalized")
	}
	return send()
}

// StopClientActionSend atomically increments sendRevision (once per stopped intent) and binds a caseID
// so delayed workers carrying older sendRevision values cannot dispatch further retries.
func (s *ActionStore) StopClientActionSend(
	ctx context.Context,
	actor, taskID, action, idempotencyKey, caseID, requestJSON string,
) (*ClientAction, error) {
	nowSec := s.now().UTC().Unix()
	requestedCaseID := strings.TrimSpace(caseID)
	effectiveCaseID := requestedCaseID
	if effectiveCaseID == "" {
		effectiveCaseID = "urn:grad:case:" + newUUID()
	}

	if s.db != nil {
		rows, err := s.db.Query(ctx, `UPDATE client_actions
			SET send_revision = CASE WHEN COALESCE(case_id, '') = '' THEN send_revision + 1 ELSE send_revision END,
			    status = $1,
			    case_id = COALESCE(NULLIF(case_id, ''), NULLIF($2, '')),
			    request_json = COALESCE(NULLIF(request_json, ''), NULLIF($3, ''), ''),
			    updated_at = $4
			WHERE deployment_id=$5 AND actor=$6 AND task_id=$7 AND action=$8 AND idempotency_key=$9
			  AND status IN ('PENDING', 'OUTCOME_UNKNOWN', 'FAILED')
			  AND (COALESCE(case_id, '') = '' OR NULLIF($10, '') IS NULL OR case_id = $10)
			RETURNING `+clientActionSelectCols,
			ActionStatusOutcomeUnknown, effectiveCaseID, requestJSON, nowSec,
			s.deploymentID, actor, taskID, action, idempotencyKey, requestedCaseID,
		)
		if err != nil {
			return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "stop client action send", err)
		}
		rec, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[ClientAction])
		if errors.Is(err, pgx.ErrNoRows) {
			existing, getErr := s.GetClientActionByKey(ctx, actor, taskID, action, idempotencyKey)
			if errors.Is(getErr, pgx.ErrNoRows) {
				return nil, protocol.NewError(protocol.ErrCodeInvalidSchema, "client action not found")
			}
			if getErr != nil {
				return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "load client action on stop send", getErr)
			}
			if requestedCaseID != "" && existing.CaseID != "" && existing.CaseID != requestedCaseID {
				return nil, protocol.NewError(protocol.ErrCodeIdempotencyConflict, fmt.Sprintf("client action already bound to caseId %s", existing.CaseID))
			}
			return nil, protocol.NewError(protocol.ErrCodeStateChanged, fmt.Sprintf("client action already in terminal state %s", existing.Status))
		}
		if err != nil {
			return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "scan stopped client action", err)
		}
		return &rec, nil
	}

	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byKey[actionMapKey(actor, taskID, action, idempotencyKey)]
	if !ok {
		return nil, protocol.NewError(protocol.ErrCodeInvalidSchema, "client action not found")
	}
	rec := s.actions[id]
	if !isRetryableActionStatus(rec.Status) {
		return nil, protocol.NewError(protocol.ErrCodeStateChanged, fmt.Sprintf("client action already in terminal state %s", rec.Status))
	}
	if requestedCaseID != "" && rec.CaseID != "" && rec.CaseID != requestedCaseID {
		return nil, protocol.NewError(protocol.ErrCodeIdempotencyConflict, fmt.Sprintf("client action already bound to caseId %s", rec.CaseID))
	}
	if rec.CaseID == "" {
		rec.SendRevision++
		rec.CaseID = effectiveCaseID
	}
	rec.Status = ActionStatusOutcomeUnknown
	if rec.RequestJSON == "" && requestJSON != "" {
		rec.RequestJSON = requestJSON
	}
	rec.UpdatedAt = nowSec
	return cloneClientAction(rec), nil
}

// UpdateClientAction updates status and correlated challenge/quote/order/decision references on a client_actions row.
func (s *ActionStore) UpdateClientAction(
	ctx context.Context,
	actionID, status, challengeID, quoteID, orderID, decisionID string,
) error {
	nowSec := s.now().UTC().Unix()
	if s.db != nil {
		if _, err := s.db.Exec(ctx, `UPDATE client_actions
			SET status=$1,
			    challenge_id=COALESCE(NULLIF($2,''), challenge_id),
			    challenge_ids=CASE WHEN $2 <> '' AND NOT ($2 = ANY(challenge_ids)) THEN array_append(challenge_ids, $2) ELSE challenge_ids END,
			    quote_id=COALESCE(NULLIF($3,''), quote_id),
			    order_id=COALESCE(NULLIF($4,''), order_id),
			    decision_id=COALESCE(NULLIF($5,''), decision_id),
			    updated_at=$6
			WHERE deployment_id=$7 AND action_id=$8`,
			status, challengeID, quoteID, orderID, decisionID, nowSec, s.deploymentID, actionID,
		); err != nil {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "update client_actions", err)
		}
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.actions[actionID]
	if !ok {
		return protocol.NewError(protocol.ErrCodeInvalidSchema, "unknown local client action")
	}
	rec.Status = status
	if challengeID != "" {
		rec.ChallengeID = challengeID
		if !slices.Contains(rec.ChallengeIDs, challengeID) {
			rec.ChallengeIDs = append(rec.ChallengeIDs, challengeID)
		}
	}
	if quoteID != "" {
		rec.QuoteID = quoteID
	}
	if orderID != "" {
		rec.OrderID = orderID
	}
	if decisionID != "" {
		rec.DecisionID = decisionID
	}
	rec.UpdatedAt = nowSec
	return nil
}

// SaveBoundQuote idempotently stores immutable quote terms for a confirmed run.
// Returns matched=false when an existing row has conflicting terms.
func (s *ActionStore) SaveBoundQuote(ctx context.Context, q BoundQuote) (bool, error) {
	if s.db == nil {
		return true, nil
	}
	tag, err := s.db.Exec(ctx, `INSERT INTO wallet_bound_quotes
		(deployment_id, actor, task_id, quote_key, quote_id, currency, total_amount_minor)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (deployment_id, actor, task_id, quote_key) DO UPDATE SET quote_id=EXCLUDED.quote_id
		WHERE (wallet_bound_quotes.quote_id, wallet_bound_quotes.currency, wallet_bound_quotes.total_amount_minor)
			= (EXCLUDED.quote_id, EXCLUDED.currency, EXCLUDED.total_amount_minor)`,
		q.DeploymentID, q.Actor, q.TaskID, q.QuoteKey, q.QuoteID, q.Currency, q.TotalAmountMinor)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// GetBoundQuote loads the persisted bound quote for (deploymentID, actor, taskID, quoteKey).
// Returns pgx.ErrNoRows if not found.
func (s *ActionStore) GetBoundQuote(ctx context.Context, deploymentID, actor, taskID, quoteKey string) (BoundQuote, error) {
	if s.db == nil {
		return BoundQuote{}, pgx.ErrNoRows
	}
	out := BoundQuote{
		DeploymentID: deploymentID,
		Actor:        actor,
		TaskID:       taskID,
		QuoteKey:     quoteKey,
	}
	err := s.db.QueryRow(ctx, `SELECT quote_id, currency, total_amount_minor FROM wallet_bound_quotes
		WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND quote_key=$4`,
		deploymentID, actor, taskID, quoteKey).Scan(&out.QuoteID, &out.Currency, &out.TotalAmountMinor)
	return out, err
}

// ApplyOrderOutcomeReceipt validates and idempotently persists a reconciliation receipt in order_outcome_receipts,
// rejects IDEMPOTENCY_CONFLICT and STALE_SEND_REVISION transitions, prevents late UNKNOWN receipts from reopening
// already-finalized intents, and atomically transitions matching client_actions rows to RECONCILED.
func (s *ActionStore) ApplyOrderOutcomeReceipt(ctx context.Context, rec OrderOutcomeReceipt) (*OrderOutcomeReceiptResponse, error) {
	if err := s.validateReceipt(&rec); err != nil {
		return nil, err
	}
	nowSec := s.now().UTC().Unix()

	if s.db != nil {
		return s.applyReceiptDB(ctx, rec, nowSec)
	}
	return s.applyReceiptMemory(rec, nowSec)
}

func (s *ActionStore) validateReceipt(rec *OrderOutcomeReceipt) error {
	if strings.TrimSpace(rec.CaseID) == "" || rec.CheckNo < 1 || rec.SendRevision < 1 ||
		rec.DeploymentID != s.deploymentID || strings.TrimSpace(rec.Actor) == "" ||
		strings.TrimSpace(rec.TaskID) == "" || !protocol.IsHexDigest(rec.RequestHash, false) {
		return protocol.NewError(protocol.ErrCodeInvalidSchema, "invalid order outcome receipt fields")
	}
	switch rec.Outcome {
	case "CREATED":
		if rec.OrderID == nil || strings.TrimSpace(*rec.OrderID) == "" {
			return protocol.NewError(protocol.ErrCodeInvalidSchema, "CREATED receipt requires orderId")
		}
	case "NOT_CREATED", "UNKNOWN":
		if rec.OrderID != nil && *rec.OrderID != "" {
			return protocol.NewError(protocol.ErrCodeInvalidSchema, "non-CREATED receipt cannot specify orderId")
		}
	default:
		return protocol.NewError(protocol.ErrCodeInvalidSchema, fmt.Sprintf("unsupported receipt outcome %q", rec.Outcome))
	}
	if rec.HistoricalStatus == "" {
		rec.HistoricalStatus = "NO_DECISION"
	}
	switch rec.HistoricalStatus {
	case "MATCHED", "INCOMPLETE", "MISMATCH", "NO_DECISION":
	default:
		return protocol.NewError(protocol.ErrCodeInvalidSchema, fmt.Sprintf("unsupported historicalStatus %q", rec.HistoricalStatus))
	}
	return nil
}

func (s *ActionStore) applyReceiptDB(ctx context.Context, rec OrderOutcomeReceipt, nowSec int64) (*OrderOutcomeReceiptResponse, error) {
	var resp *OrderOutcomeReceiptResponse
	err := RunInTx(ctx, s.db, func(tx Tx) error {
		// 1. Idempotent deduplication by (deployment_id, case_id, send_revision, check_no).
		rows, err := tx.Query(ctx, `SELECT
				deployment_id, case_id, check_no, send_revision, actor, task_id, request_hash,
				outcome, order_id, creation_decision_id, historical_status, audit_at, received_at
			FROM order_outcome_receipts
			WHERE deployment_id=$1 AND case_id=$2 AND send_revision=$3 AND check_no=$4
			FOR UPDATE`,
			s.deploymentID, rec.CaseID, rec.SendRevision, rec.CheckNo,
		)
		if err != nil {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "query existing order_outcome_receipts", err)
		}
		existing, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[storedReceiptRow])
		if err == nil {
			if !receiptMatchesRow(rec, existing) {
				return protocol.NewError(protocol.ErrCodeIdempotencyConflict, "conflicting receipt payload for (caseId, sendRevision, checkNo)")
			}
			var actStatus string
			_ = tx.QueryRow(ctx, `SELECT status FROM client_actions
				WHERE deployment_id=$1 AND (case_id=$2 OR (actor=$3 AND task_id=$4 AND action='order.create' AND request_hash=$5))
				ORDER BY updated_at DESC LIMIT 1`,
				s.deploymentID, rec.CaseID, rec.Actor, rec.TaskID, rec.RequestHash,
			).Scan(&actStatus)
			resp = &OrderOutcomeReceiptResponse{
				Status:             "IDEMPOTENT_REPLAY",
				ClientActionStatus: actStatus,
				Receipt:            rec,
			}
			return nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "scan existing order_outcome_receipts", err)
		}

		// 2. Persist receipt row.
		if _, err := tx.Exec(ctx, `INSERT INTO order_outcome_receipts(
				deployment_id, case_id, check_no, send_revision, actor, task_id, request_hash,
				outcome, order_id, creation_decision_id, historical_status, audit_at, received_at
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			s.deploymentID, rec.CaseID, rec.CheckNo, rec.SendRevision, rec.Actor, rec.TaskID,
			rec.RequestHash, rec.Outcome, rec.OrderID, rec.CreationDecisionID, rec.HistoricalStatus, rec.AuditAt, nowSec,
		); err != nil {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "insert order_outcome_receipts", err)
		}

		// 3. Locate and lock the matching client_actions row.
		actRows, err := tx.Query(ctx, `SELECT `+clientActionSelectCols+`
			FROM client_actions
			WHERE deployment_id=$1 AND (case_id=$2 OR (actor=$3 AND task_id=$4 AND action='order.create' AND request_hash=$5))
			ORDER BY updated_at DESC LIMIT 1
			FOR UPDATE`,
			s.deploymentID, rec.CaseID, rec.Actor, rec.TaskID, rec.RequestHash,
		)
		if err != nil {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "query client_actions for receipt", err)
		}
		act, actErr := pgx.CollectOneRow(actRows, pgx.RowToStructByName[ClientAction])
		if actErr != nil && !errors.Is(actErr, pgx.ErrNoRows) {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "scan client_actions for receipt", actErr)
		}

		respStatus := rec.Outcome
		finalActStatus := ""
		if actErr == nil {
			if act.Actor != rec.Actor || act.TaskID != rec.TaskID || act.RequestHash != rec.RequestHash {
				return protocol.NewError(protocol.ErrCodeBindingMismatch, "receipt bindings do not match client action")
			}
			finalActStatus = act.Status
			switch {
			case act.Status == ActionStatusReconciled || act.Status == ActionStatusCompleted:
				respStatus = "ALREADY_FINALIZED"
			case rec.SendRevision != act.SendRevision:
				respStatus = "STALE_SEND_REVISION"
			case rec.Outcome == "CREATED" || rec.Outcome == "NOT_CREATED":
				ordVal := derefString(rec.OrderID)
				decVal := derefString(rec.CreationDecisionID)
				if _, err := tx.Exec(ctx, `UPDATE client_actions
					SET status=$1,
					    outcome=$2,
					    order_id=COALESCE(NULLIF($3,''), order_id),
					    decision_id=COALESCE(NULLIF($4,''), decision_id),
					    case_id=COALESCE(NULLIF(case_id,''), $5),
					    updated_at=$6
					WHERE deployment_id=$7 AND action_id=$8`,
					ActionStatusReconciled, rec.Outcome, ordVal, decVal, rec.CaseID, nowSec, s.deploymentID, act.ActionID,
				); err != nil {
					return protocol.WrapError(protocol.ErrCodeStateUnavailable, "reconcile client_actions row", err)
				}
				finalActStatus = ActionStatusReconciled
				respStatus = "RECONCILED"
			default:
				if _, err := tx.Exec(ctx, `UPDATE client_actions
					SET outcome='UNKNOWN',
					    case_id=COALESCE(NULLIF(case_id,''), $1),
					    updated_at=$2
					WHERE deployment_id=$3 AND action_id=$4`,
					rec.CaseID, nowSec, s.deploymentID, act.ActionID,
				); err != nil {
					return protocol.WrapError(protocol.ErrCodeStateUnavailable, "record UNKNOWN receipt on client_actions", err)
				}
				respStatus = "UNKNOWN"
			}
		}

		resp = &OrderOutcomeReceiptResponse{
			Status:             respStatus,
			ClientActionStatus: finalActStatus,
			Receipt:            rec,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *ActionStore) applyReceiptMemory(rec OrderOutcomeReceipt, nowSec int64) (*OrderOutcomeReceiptResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := receiptKey{
		deploymentID: s.deploymentID,
		caseID:       rec.CaseID,
		sendRevision: rec.SendRevision,
		checkNo:      rec.CheckNo,
	}
	if existing, ok := s.receipts[key]; ok {
		if !receiptsEqual(rec, existing) {
			return nil, protocol.NewError(protocol.ErrCodeIdempotencyConflict, "conflicting receipt payload for (caseId, sendRevision, checkNo)")
		}
		var actStatus string
		if act := s.findActionForReceiptLocked(rec); act != nil {
			actStatus = act.Status
		}
		return &OrderOutcomeReceiptResponse{
			Status:             "IDEMPOTENT_REPLAY",
			ClientActionStatus: actStatus,
			Receipt:            rec,
		}, nil
	}

	act := s.findActionForReceiptLocked(rec)
	if act != nil && (act.Actor != rec.Actor || act.TaskID != rec.TaskID || act.RequestHash != rec.RequestHash) {
		return nil, protocol.NewError(protocol.ErrCodeBindingMismatch, "receipt bindings do not match client action")
	}

	s.receipts[key] = cloneReceipt(rec)

	respStatus := rec.Outcome
	finalActStatus := ""
	if act != nil {
		finalActStatus = act.Status
		switch {
		case act.Status == ActionStatusReconciled || act.Status == ActionStatusCompleted:
			respStatus = "ALREADY_FINALIZED"
		case rec.SendRevision != act.SendRevision:
			respStatus = "STALE_SEND_REVISION"
		case rec.Outcome == "CREATED" || rec.Outcome == "NOT_CREATED":
			act.Status = ActionStatusReconciled
			act.Outcome = rec.Outcome
			if rec.OrderID != nil && *rec.OrderID != "" {
				act.OrderID = *rec.OrderID
			}
			if rec.CreationDecisionID != nil && *rec.CreationDecisionID != "" {
				act.DecisionID = *rec.CreationDecisionID
			}
			if act.CaseID == "" {
				act.CaseID = rec.CaseID
			}
			act.UpdatedAt = nowSec
			finalActStatus = ActionStatusReconciled
			respStatus = "RECONCILED"
		default:
			act.Outcome = "UNKNOWN"
			if act.CaseID == "" {
				act.CaseID = rec.CaseID
			}
			act.UpdatedAt = nowSec
			respStatus = "UNKNOWN"
		}
	}

	return &OrderOutcomeReceiptResponse{
		Status:             respStatus,
		ClientActionStatus: finalActStatus,
		Receipt:            rec,
	}, nil
}

func (s *ActionStore) findActionForReceiptLocked(rec OrderOutcomeReceipt) *ClientAction {
	var matched *ClientAction
	for _, act := range s.actions {
		if act.CaseID == rec.CaseID ||
			(act.Actor == rec.Actor && act.TaskID == rec.TaskID && act.Action == protocol.ActionOrderCreate && act.RequestHash == rec.RequestHash) {
			if matched == nil || act.UpdatedAt > matched.UpdatedAt {
				matched = act
			}
		}
	}
	return matched
}

func isRetryableActionStatus(status string) bool {
	return status == ActionStatusPending || status == ActionStatusOutcomeUnknown || status == ActionStatusFailed
}

func actionMapKey(actor, taskID, action, idempotencyKey string) string {
	return strings.Join([]string{actor, taskID, action, idempotencyKey}, "|")
}

func cloneClientAction(a *ClientAction) *ClientAction {
	if a == nil {
		return nil
	}
	cp := *a
	cp.ChallengeIDs = slices.Clone(a.ChallengeIDs)
	return &cp
}

func cloneReceipt(r OrderOutcomeReceipt) OrderOutcomeReceipt {
	cp := r
	if r.OrderID != nil {
		v := *r.OrderID
		cp.OrderID = &v
	}
	if r.CreationDecisionID != nil {
		v := *r.CreationDecisionID
		cp.CreationDecisionID = &v
	}
	return cp
}

func equalStringPtr(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func receiptMatchesRow(rec OrderOutcomeReceipt, row storedReceiptRow) bool {
	return row.Actor == rec.Actor &&
		row.TaskID == rec.TaskID &&
		row.RequestHash == rec.RequestHash &&
		row.Outcome == rec.Outcome &&
		equalStringPtr(row.OrderID, rec.OrderID) &&
		equalStringPtr(row.CreationDecisionID, rec.CreationDecisionID) &&
		row.HistoricalStatus == rec.HistoricalStatus &&
		row.AuditAt == rec.AuditAt
}

func receiptsEqual(a, b OrderOutcomeReceipt) bool {
	return a.Actor == b.Actor &&
		a.TaskID == b.TaskID &&
		a.RequestHash == b.RequestHash &&
		a.Outcome == b.Outcome &&
		equalStringPtr(a.OrderID, b.OrderID) &&
		equalStringPtr(a.CreationDecisionID, b.CreationDecisionID) &&
		a.HistoricalStatus == b.HistoricalStatus &&
		a.AuditAt == b.AuditAt
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
