package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"grad/platform/core/dao"
	"grad/platform/core/domain/policy"
	"grad/platform/core/ledger"
	"grad/protocol"
	"grad/protocol/registry"
)

// OrderOutcomeCaseRequest models registration of an ambiguous order-outcome reconciliation case.
type OrderOutcomeCaseRequest struct {
	CaseID       string                 `json:"caseId"`
	SendRevision int64                  `json:"sendRevision"`
	DeploymentID string                 `json:"deploymentId"`
	Request      protocol.AccessRequest `json:"request"`
	RequestHash  string                 `json:"requestHash"`
	ChallengeIDs []string               `json:"challengeIds"`
}

// OrderOutcomeCaseResponse models the registered order-outcome reconciliation case acknowledgement.
type OrderOutcomeCaseResponse struct {
	CaseID         string   `json:"caseId"`
	SendRevision   int64    `json:"sendRevision"`
	DeploymentID   string   `json:"deploymentId"`
	Actor          string   `json:"actor"`
	TaskID         string   `json:"taskId"`
	IdempotencyKey string   `json:"idempotencyKey"`
	RequestHash    string   `json:"requestHash"`
	ChallengeIDs   []string `json:"challengeIds"`
	Status         string   `json:"status"`
}

// AuditOrderOutcomeRequest models an auditor-triggered order-outcome reconciliation query.
type AuditOrderOutcomeRequest struct {
	CaseID         string                  `json:"caseId,omitempty"`
	DeploymentID   string                  `json:"deploymentId,omitempty"`
	Request        *protocol.AccessRequest `json:"request,omitempty"`
	Actor          string                  `json:"actor,omitempty"`
	TaskID         string                  `json:"taskId,omitempty"`
	IdempotencyKey string                  `json:"idempotencyKey,omitempty"`
	RequestHash    string                  `json:"requestHash,omitempty"`
	ChallengeIDs   []string                `json:"challengeIds,omitempty"`
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

// OrderOutcomeReceiptResponse models an acknowledgement returned by B's receipt inbox endpoint.
type OrderOutcomeReceiptResponse struct {
	Status             string              `json:"status"`
	ClientActionStatus string              `json:"clientActionStatus,omitempty"`
	Receipt            OrderOutcomeReceipt `json:"receipt"`
}

// AuditOrderOutcomeResponse models the result of AuditOrderOutcome.
type AuditOrderOutcomeResponse struct {
	CaseID             string              `json:"caseId"`
	CheckNo            int64               `json:"checkNo"`
	SendRevision       int64               `json:"sendRevision"`
	DeploymentID       string              `json:"deploymentId"`
	Actor              string              `json:"actor"`
	TaskID             string              `json:"taskId"`
	IdempotencyKey     string              `json:"idempotencyKey"`
	RequestHash        string              `json:"requestHash"`
	Outcome            string              `json:"outcome"`
	OrderID            *string             `json:"orderId"`
	CreationDecisionID *string             `json:"creationDecisionId"`
	DenialDecisionIDs  []string            `json:"denialDecisionIds,omitempty"`
	HistoricalStatus   string              `json:"historicalStatus"`
	HistoricalReason   string              `json:"historicalReason,omitempty"`
	DecisionBlock      *int64              `json:"decisionBlock,omitempty"`
	RevocationBlock    *int64              `json:"revocationBlock,omitempty"`
	LockedChallengeIDs []string            `json:"lockedChallengeIds"`
	VerifierID         string              `json:"verifierId,omitempty"`
	AuditAt            int64               `json:"auditAt"`
	Receipt            OrderOutcomeReceipt `json:"receipt"`
}

// OutboxEntry models a durable row in order_outcome_outbox pending or completed delivery to B.
type OutboxEntry struct {
	DeploymentID string              `json:"deploymentId" db:"deployment_id"`
	CaseID       string              `json:"caseId" db:"case_id"`
	SendRevision int64               `json:"sendRevision" db:"send_revision"`
	CheckNo      int64               `json:"checkNo" db:"check_no"`
	ReceiptJSON  json.RawMessage     `json:"receiptJson" db:"receipt_json"`
	Receipt      OrderOutcomeReceipt `json:"receipt" db:"-"`
	DeliveredAt  *int64              `json:"deliveredAt,omitempty" db:"delivered_at"`
	Attempts     int64               `json:"attempts" db:"attempts"`
	LastError    string              `json:"lastError,omitempty" db:"last_error"`
}

// ReceiptSender delivers one persisted reconciliation receipt to domain B's inbox
// and returns nil only after verifying remote acknowledgement and receipt echo binding.
type ReceiptSender func(ctx context.Context, receipt OrderOutcomeReceipt) error

// VerifyReceiptEcho verifies that an acknowledged receipt matches the canonical
// JSON representation of the persisted receipt.
func VerifyReceiptEcho(sent, ack OrderOutcomeReceipt) error {
	sentBytes, err := json.Marshal(sent)
	if err != nil {
		return err
	}
	ackBytes, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	if !bytes.Equal(sentBytes, ackBytes) {
		return fmt.Errorf("receipt acknowledgement binding mismatch")
	}
	return nil
}

func normalizeUniqueSortedStrings(items []string) []string {
	if len(items) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, s := range items {
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	slices.Sort(out)
	return out
}

func didWebHost(did string) string {
	if !strings.HasPrefix(did, "did:web:") {
		return ""
	}
	rest := strings.TrimPrefix(did, "did:web:")
	host, _, _ := strings.Cut(rest, ":")
	if idx := strings.Index(strings.ToLower(host), "%3a"); idx >= 0 {
		host = host[:idx]
	}
	return host
}

func (s *Service) authorizeAuditor(caller CallerIdentity) (string, error) {
	if caller.Role != "C_AUDITOR" && caller.Role != "C-AUDITOR" {
		return "", protocol.NewError(protocol.ErrCodeAuditForbidden, "caller lacks C_AUDITOR role")
	}
	if caller.DID == "" || didWebHost(caller.DID) == "" || didWebHost(caller.DID) != didWebHost(s.cfg.ServiceDID) {
		return "", protocol.NewError(protocol.ErrCodeAuditForbidden, "auditor certificate does not belong to resource domain")
	}
	if len(s.cfg.AuditorDIDs) > 0 && !slices.Contains(s.cfg.AuditorDIDs, caller.DID) {
		return "", protocol.NewError(protocol.ErrCodeAuditForbidden, "caller DID is not in configured C auditor set")
	}
	if s.cfg.VerifierID != "" {
		return s.cfg.VerifierID, nil
	}
	return caller.DID, nil
}

func authorizeRecoveryCaller(caller CallerIdentity, actor string) error {
	if caller.Role != "B_RECOVERY" && caller.Role != "RECOVERY" {
		return protocol.NewError(protocol.ErrCodeAuditForbidden, "caller lacks B_RECOVERY role")
	}
	if caller.DID == "" || actor == "" {
		return protocol.NewError(protocol.ErrCodeAuditForbidden, "authenticated recovery DID required")
	}
	callerHost := didWebHost(caller.DID)
	actorHost := didWebHost(actor)
	if callerHost == "" || actorHost == "" || callerHost != actorHost {
		return protocol.NewError(protocol.ErrCodeAuditForbidden, fmt.Sprintf("recovery caller domain %q does not match actor domain %q", callerHost, actorHost))
	}
	return nil
}

// RegisterOrderOutcomeCase idempotently registers an ambiguous order.create reconciliation case
// submitted by an authenticated B_RECOVERY caller after send stop (sendRevision >= 2).
func (s *Service) RegisterOrderOutcomeCase(
	ctx context.Context,
	caller CallerIdentity,
	req OrderOutcomeCaseRequest,
) (*OrderOutcomeCaseResponse, error) {
	if strings.TrimSpace(req.CaseID) == "" || req.SendRevision < 1 || strings.TrimSpace(req.DeploymentID) == "" || !hex64Re.MatchString(req.RequestHash) {
		return nil, protocol.NewError(protocol.ErrCodeInvalidSchema, "caseId, sendRevision >= 1, deploymentId, and requestHash are required")
	}
	if req.DeploymentID != s.cfg.DeploymentID {
		return nil, protocol.NewError(protocol.ErrCodeBindingMismatch, fmt.Sprintf("deploymentId %q != %q", req.DeploymentID, s.cfg.DeploymentID))
	}
	if err := authorizeRecoveryCaller(caller, req.Request.Actor); err != nil {
		return nil, err
	}
	if err := req.Request.Validate(false); err != nil {
		return nil, err
	}
	if req.Request.Action != protocol.ActionOrderCreate {
		return nil, protocol.NewError(protocol.ErrCodeInvalidSchema, "order-outcome-cases requires order.create request")
	}
	if !idempotencyKeyRe.MatchString(req.Request.IdempotencyKey) {
		return nil, protocol.NewError(protocol.ErrCodeInvalidSchema, "invalid request.idempotencyKey")
	}
	if req.Request.DeploymentID != s.cfg.DeploymentID {
		return nil, protocol.NewError(protocol.ErrCodeBindingMismatch, "request.deploymentId mismatch")
	}
	computedHash, err := req.Request.Hash(false)
	if err != nil {
		return nil, err
	}
	if computedHash != req.RequestHash {
		return nil, protocol.NewError(protocol.ErrCodeBindingMismatch, "requestHash does not match canonical request digest")
	}

	reqJSONBytes, err := json.Marshal(req.Request)
	if err != nil {
		return nil, protocol.WrapError(protocol.ErrCodeInvalidSchema, "marshal request", err)
	}
	normalizedChals := normalizeUniqueSortedStrings(req.ChallengeIDs)

	var resp *OrderOutcomeCaseResponse
	txErr := dao.RunInTx(ctx, s.cfg.DB, func(tx dao.Tx) error {
		// Idempotent immutability check on caseId first.
		var exActor, exTaskID, exIdemKey, exHash string
		var exSendRev int64
		var exChals []string
		err := tx.QueryRow(ctx, `SELECT
			actor, task_id, idempotency_key, send_revision, request_hash, challenge_ids
			FROM order_outcome_cases
			WHERE deployment_id=$1 AND case_id=$2
			FOR UPDATE`,
			s.cfg.DeploymentID, req.CaseID,
		).Scan(&exActor, &exTaskID, &exIdemKey, &exSendRev, &exHash, &exChals)
		if err == nil {
			exNormChals := normalizeUniqueSortedStrings(exChals)
			if exActor != req.Request.Actor || exTaskID != req.Request.TaskID ||
				exIdemKey != req.Request.IdempotencyKey || exSendRev != req.SendRevision ||
				exHash != req.RequestHash || !slices.Equal(exNormChals, normalizedChals) {
				return protocol.NewError(protocol.ErrCodeIdempotencyConflict, "caseId already bound to different request or challenge list")
			}
			resp = &OrderOutcomeCaseResponse{
				CaseID:         req.CaseID,
				SendRevision:   req.SendRevision,
				DeploymentID:   s.cfg.DeploymentID,
				Actor:          req.Request.Actor,
				TaskID:         req.Request.TaskID,
				IdempotencyKey: req.Request.IdempotencyKey,
				RequestHash:    req.RequestHash,
				ChallengeIDs:   normalizedChals,
				Status:         "REGISTERED",
			}
			return nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "query order_outcome_cases", err)
		}

		if req.SendRevision < 2 {
			return protocol.NewError(protocol.ErrCodeStateChanged, "send stop revision >= 2 is required")
		}

		tag, err := tx.Exec(ctx, `INSERT INTO order_outcome_cases(
			deployment_id, case_id, actor, task_id, idempotency_key, send_revision, request_json, request_hash, challenge_ids, created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT(deployment_id, actor, task_id, idempotency_key) DO NOTHING`,
			s.cfg.DeploymentID, req.CaseID, req.Request.Actor, req.Request.TaskID, req.Request.IdempotencyKey,
			req.SendRevision, string(reqJSONBytes), req.RequestHash, normalizedChals, s.now().Unix(),
		)
		if err != nil {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "insert order_outcome_cases", err)
		}
		if tag.RowsAffected() == 0 {
			return protocol.NewError(protocol.ErrCodeStateChanged, "order outcome case already registered under a different caseId")
		}

		resp = &OrderOutcomeCaseResponse{
			CaseID:         req.CaseID,
			SendRevision:   req.SendRevision,
			DeploymentID:   s.cfg.DeploymentID,
			Actor:          req.Request.Actor,
			TaskID:         req.Request.TaskID,
			IdempotencyKey: req.Request.IdempotencyKey,
			RequestHash:    req.RequestHash,
			ChallengeIDs:   normalizedChals,
			Status:         "REGISTERED",
		}
		return nil
	})
	if txErr != nil {
		if protocol.CodeOf(txErr) == "" {
			return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "register order outcome case transaction", txErr)
		}
		return nil, txErr
	}
	return resp, nil
}

type lockedChallengeState struct {
	ChallengeID string  `db:"challenge_id"`
	Actor       string  `db:"actor"`
	TaskID      string  `db:"task_id"`
	RequestHash string  `db:"request_hash"`
	ExpiresAt   int64   `db:"expires_at"`
	ConsumedAt  *int64  `db:"consumed_at"`
	DecisionID  *string `db:"decision_id"`
}

// AuditOrderOutcome verifies caller authorization, locks all candidate challenges and business
// rows without mutating business state, performs historical h < r audit when CREATED, and
// atomically records the audit row and durable outbox receipt.
func (s *Service) AuditOrderOutcome(
	ctx context.Context,
	caller CallerIdentity,
	req AuditOrderOutcomeRequest,
) (*AuditOrderOutcomeResponse, error) {
	// Authorize C auditor BEFORE inspecting request details or touching any business table.
	verifierID, err := s.authorizeAuditor(caller)
	if err != nil {
		return nil, err
	}

	if req.DeploymentID != "" && req.DeploymentID != s.cfg.DeploymentID {
		return nil, protocol.NewError(protocol.ErrCodeBindingMismatch, "deploymentId mismatch")
	}

	actor := strings.TrimSpace(req.Actor)
	taskID := strings.TrimSpace(req.TaskID)
	idempotencyKey := strings.TrimSpace(req.IdempotencyKey)
	reqHash := strings.TrimSpace(req.RequestHash)
	if req.Request != nil {
		if err := req.Request.Validate(false); err != nil {
			return nil, err
		}
		if req.Request.Action != protocol.ActionOrderCreate {
			return nil, protocol.NewError(protocol.ErrCodeInvalidSchema, "audit only supports order.create requests")
		}
		if req.Request.DeploymentID != s.cfg.DeploymentID {
			return nil, protocol.NewError(protocol.ErrCodeBindingMismatch, "request.deploymentId mismatch")
		}
		computedHash, err := req.Request.Hash(false)
		if err != nil {
			return nil, err
		}
		if reqHash != "" && reqHash != computedHash {
			return nil, protocol.NewError(protocol.ErrCodeBindingMismatch, "requestHash mismatches canonical request")
		}
		actor = req.Request.Actor
		taskID = req.Request.TaskID
		idempotencyKey = req.Request.IdempotencyKey
		reqHash = computedHash
	}

	var resp *AuditOrderOutcomeResponse
	txErr := dao.RunInTx(ctx, s.cfg.DB, func(tx dao.Tx) error {
		// Resolve optional registered order_outcome_cases row (FOR UPDATE serializes concurrent check_no allocation).
		var caseID string
		var sendRevision int64 = 1
		var caseFound bool
		var caseChals []string
		if strings.TrimSpace(req.CaseID) != "" {
			var cActor, cTask, cIdem, cHash string
			err := tx.QueryRow(ctx, `SELECT
				case_id, send_revision, actor, task_id, idempotency_key, request_hash, challenge_ids
				FROM order_outcome_cases
				WHERE deployment_id=$1 AND case_id=$2
				FOR UPDATE`,
				s.cfg.DeploymentID, req.CaseID,
			).Scan(&caseID, &sendRevision, &cActor, &cTask, &cIdem, &cHash, &caseChals)
			if err == nil {
				caseFound = true
				if (actor != "" && actor != cActor) || (taskID != "" && taskID != cTask) ||
					(idempotencyKey != "" && idempotencyKey != cIdem) || (reqHash != "" && reqHash != cHash) {
					return protocol.NewError(protocol.ErrCodeIdempotencyConflict, "audit request mismatches registered caseId")
				}
				actor, taskID, idempotencyKey, reqHash = cActor, cTask, cIdem, cHash
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return protocol.WrapError(protocol.ErrCodeStateUnavailable, "lock order_outcome_cases by caseId", err)
			}
		} else if actor != "" && taskID != "" && idempotencyKey != "" {
			var cHash string
			err := tx.QueryRow(ctx, `SELECT
				case_id, send_revision, request_hash, challenge_ids
				FROM order_outcome_cases
				WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND idempotency_key=$4
				FOR UPDATE`,
				s.cfg.DeploymentID, actor, taskID, idempotencyKey,
			).Scan(&caseID, &sendRevision, &cHash, &caseChals)
			if err == nil {
				caseFound = true
				if reqHash != "" && reqHash != cHash {
					return protocol.NewError(protocol.ErrCodeIdempotencyConflict, "audit requestHash mismatches registered case")
				}
				reqHash = cHash
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return protocol.WrapError(protocol.ErrCodeStateUnavailable, "lock order_outcome_cases by key", err)
			}
		}

		if actor == "" || taskID == "" || !idempotencyKeyRe.MatchString(idempotencyKey) || !hex64Re.MatchString(reqHash) {
			return protocol.NewError(protocol.ErrCodeInvalidSchema, "registered caseId or (actor, taskId, idempotencyKey, requestHash) required")
		}

		// Step 1: Enumerate all challenges bound to (actor, taskId, requestHash), form sorted union, and lock FOR UPDATE.
		unionInputs := make([]string, 0, len(req.ChallengeIDs)+len(caseChals))
		unionInputs = append(unionInputs, req.ChallengeIDs...)
		unionInputs = append(unionInputs, caseChals...)

		rows, err := tx.Query(ctx, `SELECT challenge_id
			FROM challenges
			WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND request_hash=$4`,
			s.cfg.DeploymentID, actor, taskID, reqHash,
		)
		if err != nil {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "list bound challenges", err)
		}
		dbChallengeIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "collect bound challenges", err)
		}
		unionInputs = append(unionInputs, dbChallengeIDs...)

		allChallengeIDs := normalizeUniqueSortedStrings(unionInputs)
		lockedChals := make(map[string]lockedChallengeState, len(allChallengeIDs))
		if len(allChallengeIDs) > 0 {
			lRows, err := tx.Query(ctx, `SELECT
				challenge_id, actor, task_id, request_hash, expires_at, consumed_at, decision_id
				FROM challenges
				WHERE deployment_id=$1 AND challenge_id = ANY($2)
				ORDER BY challenge_id ASC
				FOR UPDATE`,
				s.cfg.DeploymentID, allChallengeIDs,
			)
			if err != nil {
				return protocol.WrapError(protocol.ErrCodeStateUnavailable, "lock bound challenges", err)
			}
			lockedList, err := pgx.CollectRows(lRows, pgx.RowToStructByName[lockedChallengeState])
			if err != nil {
				return protocol.WrapError(protocol.ErrCodeStateUnavailable, "collect locked challenges", err)
			}
			for _, lc := range lockedList {
				lockedChals[lc.ChallengeID] = lc
			}
		}

		// Step 2: Trusted post-lock clock_timestamp().
		dbClockSec, err := tx.ClockEpochSeconds(ctx)
		if err != nil {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "query clock_timestamp()", err)
		}
		auditNow := dbClockSec
		if s.cfg.NowFn != nil {
			auditNow = s.cfg.NowFn().Unix()
		}

		// Step 3: Lock & read business_keys and orders WITHOUT mutating business rows.
		var bkFound bool
		var bkHash, bkStatus string
		var bkResourceID, bkDecisionID *string
		err = tx.QueryRow(ctx, `SELECT request_hash, status, resource_id, decision_id
			FROM business_keys
			WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND action='order.create' AND idempotency_key=$4
			FOR SHARE`,
			s.cfg.DeploymentID, actor, taskID, idempotencyKey,
		).Scan(&bkHash, &bkStatus, &bkResourceID, &bkDecisionID)
		if err == nil {
			bkFound = true
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "lock business_keys", err)
		}

		var orderFound bool
		var ord OrderPayload
		var ordDecisionID string
		err = tx.QueryRow(ctx, `SELECT
			order_id, quote_id, task_id, actor, supplier_id, product_id, quantity, currency,
			total_amount_minor, idempotency_key, status, created_at, decision_id
			FROM orders
			WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND idempotency_key=$4
			FOR SHARE`,
			s.cfg.DeploymentID, actor, taskID, idempotencyKey,
		).Scan(
			&ord.OrderID, &ord.QuoteID, &ord.TaskID, &ord.Actor, &ord.SupplierID, &ord.ProductID,
			&ord.Quantity, &ord.Currency, &ord.TotalAmountMinor, &ord.IdempotencyKey, &ord.Status,
			&ord.CreatedAt, &ordDecisionID,
		)
		if err == nil {
			orderFound = true
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "lock orders", err)
		}

		// Step 4: Determine CREATED / NOT_CREATED / UNKNOWN and execute historical h < r audit.
		var (
			outcome            string
			orderIDPtr         *string
			creationDecisionID *string
			denialDecisionIDs  []string
			historicalStatus   = "NO_DECISION"
			historicalReason   string
			decisionBlockPtr   *int64
			revocationBlockPtr *int64
		)

		if orderFound {
			if bkFound && bkStatus == "COMPLETED" && bkHash == reqHash &&
				bkResourceID != nil && *bkResourceID == ord.OrderID && ord.Status == "CREATED" {
				outcome = "CREATED"
				ordID := ord.OrderID
				orderIDPtr = &ordID
				var hErr error
				creationDecisionID, historicalStatus, historicalReason, decisionBlockPtr, revocationBlockPtr, hErr = s.auditHistoricalCreation(ctx, tx, ord, ordDecisionID, reqHash)
				if hErr != nil {
					return protocol.WrapError(protocol.ErrCodeStateUnavailable, "historical order creation audit", hErr)
				}
			} else {
				outcome = "UNKNOWN"
				historicalStatus = "NO_DECISION"
				historicalReason = "business_keys and orders state are inconsistent"
			}
		} else {
			var allowCount int64
			err = tx.QueryRow(ctx, `SELECT COUNT(*)
				FROM decisions
				WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND action='order.create' AND idempotency_key=$4 AND outcome='ALLOW'`,
				s.cfg.DeploymentID, actor, taskID, idempotencyKey,
			).Scan(&allowCount)
			if err != nil {
				return protocol.WrapError(protocol.ErrCodeStateUnavailable, "count allow decisions", err)
			}

			stopVerified := caseFound && sendRevision >= 2
			allTerminated := len(allChallengeIDs) > 0 && !bkFound && allowCount == 0
			if allTerminated {
				for _, cid := range allChallengeIDs {
					lc, ok := lockedChals[cid]
					if !ok || lc.Actor != actor || lc.TaskID != taskID || lc.RequestHash != reqHash {
						allTerminated = false
						break
					}
					if lc.ConsumedAt != nil {
						if lc.DecisionID == nil || *lc.DecisionID == "" {
							allTerminated = false
							break
						}
						var decOutcome string
						dErr := tx.QueryRow(ctx, `SELECT outcome FROM decisions WHERE deployment_id=$1 AND decision_id=$2`,
							s.cfg.DeploymentID, *lc.DecisionID,
						).Scan(&decOutcome)
						if errors.Is(dErr, pgx.ErrNoRows) || decOutcome != "DENY" {
							if dErr != nil && !errors.Is(dErr, pgx.ErrNoRows) {
								return protocol.WrapError(protocol.ErrCodeStateUnavailable, "read challenge decision outcome", dErr)
							}
							allTerminated = false
							break
						}
						denialDecisionIDs = append(denialDecisionIDs, *lc.DecisionID)
						continue
					}
					if auditNow < lc.ExpiresAt {
						allTerminated = false
						break
					}
				}
			}

			if stopVerified && allTerminated {
				outcome = "NOT_CREATED"
				historicalStatus = "NO_DECISION"
				historicalReason = "all challenges terminated without order creation"
			} else {
				outcome = "UNKNOWN"
				historicalStatus = "NO_DECISION"
				if allowCount > 0 || bkFound {
					historicalReason = "allow decision or in-progress business key exists without order row"
				} else if !stopVerified {
					historicalReason = "send stop not verified"
				} else {
					historicalReason = "executable or unverified challenge remains"
				}
			}
		}

		// Step 5: Persist audit record and durable outbox receipt atomically.
		effectiveCaseID := caseID
		if effectiveCaseID == "" {
			effectiveCaseID = strings.TrimSpace(req.CaseID)
		}
		if effectiveCaseID == "" {
			effectiveCaseID = "urn:grad:audit:" + newUUID()
		}

		var nextCheckNo int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(check_no), 0) + 1
			FROM order_outcome_audits WHERE deployment_id=$1 AND case_id=$2`,
			s.cfg.DeploymentID, effectiveCaseID,
		).Scan(&nextCheckNo); err != nil {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "allocate next audit check_no", err)
		}

		if _, err := tx.Exec(ctx, `INSERT INTO order_outcome_audits(
			deployment_id, case_id, check_no, send_revision, actor, task_id, idempotency_key,
			request_hash, outcome, order_id, creation_decision_id, historical_status, historical_reason,
			verifier_id, audit_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			s.cfg.DeploymentID, effectiveCaseID, nextCheckNo, sendRevision, actor, taskID, idempotencyKey,
			reqHash, outcome, orderIDPtr, creationDecisionID, historicalStatus, historicalReason,
			verifierID, auditNow,
		); err != nil {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "insert order_outcome_audits", err)
		}

		receipt := OrderOutcomeReceipt{
			CaseID:             effectiveCaseID,
			CheckNo:            nextCheckNo,
			SendRevision:       sendRevision,
			DeploymentID:       s.cfg.DeploymentID,
			Actor:              actor,
			TaskID:             taskID,
			RequestHash:        reqHash,
			Outcome:            outcome,
			OrderID:            orderIDPtr,
			CreationDecisionID: creationDecisionID,
			HistoricalStatus:   historicalStatus,
			AuditAt:            auditNow,
		}

		receiptJSON, err := json.Marshal(receipt)
		if err != nil {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "marshal order outcome receipt", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO order_outcome_outbox(
			deployment_id, case_id, send_revision, check_no, receipt_json
		) VALUES($1,$2,$3,$4,$5)`,
			s.cfg.DeploymentID, receipt.CaseID, receipt.SendRevision, receipt.CheckNo, receiptJSON,
		); err != nil {
			return protocol.WrapError(protocol.ErrCodeStateUnavailable, "insert order_outcome_outbox", err)
		}

		resp = &AuditOrderOutcomeResponse{
			CaseID:             effectiveCaseID,
			CheckNo:            nextCheckNo,
			SendRevision:       sendRevision,
			DeploymentID:       s.cfg.DeploymentID,
			Actor:              actor,
			TaskID:             taskID,
			IdempotencyKey:     idempotencyKey,
			RequestHash:        reqHash,
			Outcome:            outcome,
			OrderID:            orderIDPtr,
			CreationDecisionID: creationDecisionID,
			DenialDecisionIDs:  denialDecisionIDs,
			HistoricalStatus:   historicalStatus,
			HistoricalReason:   historicalReason,
			DecisionBlock:      decisionBlockPtr,
			RevocationBlock:    revocationBlockPtr,
			LockedChallengeIDs: allChallengeIDs,
			VerifierID:         verifierID,
			AuditAt:            auditNow,
			Receipt:            receipt,
		}
		return nil
	})
	if txErr != nil {
		if protocol.CodeOf(txErr) == "" {
			return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "audit order outcome transaction", txErr)
		}
		return nil, txErr
	}
	return resp, nil
}

func (s *Service) auditHistoricalCreation(
	ctx context.Context,
	tx dao.Tx,
	ord OrderPayload,
	decID string,
	reqHash string,
) (creationDecID *string, status string, reason string, decBlock *int64, revBlock *int64, dbErr error) {
	if strings.TrimSpace(decID) == "" {
		return nil, "INCOMPLETE", "order creation decisionId missing", nil, nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT `+selectDecisionColumns+`
		FROM decisions WHERE deployment_id=$1 AND decision_id=$2`,
		s.cfg.DeploymentID, decID,
	)
	if err != nil {
		return nil, "", "", nil, nil, err
	}
	d1, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[DecisionRecord])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "INCOMPLETE", fmt.Sprintf("creation decision %q missing in decisions table", decID), nil, nil, nil
	}
	if err != nil {
		return nil, "", "", nil, nil, err
	}
	if d1.StateSource == ledger.SourceCentralized {
		return &d1.DecisionID, "INCOMPLETE", "centralized decision is linked by registry revision; Fabric historical replay is not applicable", nil, nil, nil
	}
	dID := d1.DecisionID
	creationDecID = &dID
	blockCopy := d1.BlockNumber
	decBlock = &blockCopy

	if d1.Outcome != "ALLOW" || d1.Actor != ord.Actor || d1.TaskID != ord.TaskID ||
		d1.Action != protocol.ActionOrderCreate || d1.IdempotencyKey != ord.IdempotencyKey ||
		d1.OrderID == nil || *d1.OrderID != ord.OrderID || d1.QuoteID == nil || *d1.QuoteID != ord.QuoteID {
		return creationDecID, "MISMATCH", "creation decision metadata conflicts with order", decBlock, nil, nil
	}

	// Verify challenge request hash and expiry at decisionAt.
	var chalHash, nonce, audience string
	var issuedAt, chalExpiresAt int64
	err = tx.QueryRow(ctx, `SELECT request_hash, nonce, audience, issued_at, expires_at
		FROM challenges WHERE deployment_id=$1 AND challenge_id=$2`,
		s.cfg.DeploymentID, d1.ChallengeID,
	).Scan(&chalHash, &nonce, &audience, &issuedAt, &chalExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return creationDecID, "INCOMPLETE", "creation decision challenge row missing", decBlock, nil, nil
	}
	if err != nil {
		return nil, "", "", nil, nil, err
	}
	if chalHash != reqHash || d1.DecisionAt >= chalExpiresAt {
		return creationDecID, "MISMATCH", "creation decision challenge binding or expiry invalid", decBlock, nil, nil
	}

	// Verify quote snapshot against order and decisionAt.
	qRows, err := tx.Query(ctx, `SELECT
		quote_id, task_id, actor, supplier_id, product_id, quantity, currency,
		unit_price_minor, total_amount_minor, issued_at, valid_until
		FROM quotes WHERE deployment_id=$1 AND quote_id=$2`,
		s.cfg.DeploymentID, ord.QuoteID,
	)
	if err != nil {
		return nil, "", "", nil, nil, err
	}
	q, err := pgx.CollectOneRow(qRows, pgx.RowToStructByName[QuotePayload])
	if errors.Is(err, pgx.ErrNoRows) {
		return creationDecID, "INCOMPLETE", "referenced quote row missing", decBlock, nil, nil
	}
	if err != nil {
		return nil, "", "", nil, nil, err
	}
	if q.TaskID != d1.TaskID || q.Actor != d1.Actor || q.SupplierID != ord.SupplierID ||
		q.ProductID != ord.ProductID || q.Quantity != ord.Quantity || q.Currency != ord.Currency ||
		q.TotalAmountMinor != ord.TotalAmountMinor || d1.DecisionAt >= q.ValidUntil {
		return creationDecID, "MISMATCH", "quote terms conflict with order or expired before decisionAt", decBlock, nil, nil
	}

	// Verify original probe lease and context/effective deadlines (no renewal on historical replay).
	if d1.ProbeDeadline <= 0 || d1.DecisionAt >= d1.ProbeDeadline {
		return creationDecID, "MISMATCH", fmt.Sprintf("decisionAt %d >= original probeDeadline %d", d1.DecisionAt, d1.ProbeDeadline), decBlock, nil, nil
	}
	if d1.ContextRiskLevel == policy.RiskBlocked || d1.DecisionAt < d1.ContextObservedAt || d1.DecisionAt >= d1.ContextAccessDeadline {
		return creationDecID, "MISMATCH", "decision violated recorded context riskLevel or accessDeadline", decBlock, nil, nil
	}
	if d1.EffectiveDeadline <= 0 || d1.DecisionAt >= d1.EffectiveDeadline {
		return creationDecID, "MISMATCH", "decisionAt exceeded effectiveDeadline", decBlock, nil, nil
	}

	hist, ok := s.cfg.State.(ledger.HistoricalStateSource)
	if !ok {
		return creationDecID, "INCOMPLETE", "state source does not support historical replay", decBlock, nil, nil
	}
	if len(d1.GrantPath) == 0 {
		return creationDecID, "INCOMPLETE", "creation decision missing grantPath", decBlock, nil, nil
	}
	leafGrantID := d1.GrantPath[len(d1.GrantPath)-1]
	decTime := time.Unix(d1.DecisionAt, 0)

	// Locate relevant deactivation at or after h for the h < r comparison.
	checkInactive := func(kind, id string) error {
		if strings.TrimSpace(id) == "" {
			return nil
		}
		rBlock, _, found, fErr := hist.FindInactiveBlock(ctx, kind, id, d1.BlockNumber)
		if fErr != nil {
			return fmt.Errorf("incomplete: lookup deactivation for %s %s: %w", kind, id, fErr)
		}
		if found {
			rCopy := rBlock
			if revBlock == nil || rCopy < *revBlock {
				revBlock = &rCopy
			}
			if rBlock <= d1.BlockNumber {
				return fmt.Errorf("mismatch: %s %q became inactive at block r=%d <= decision block h=%d", kind, id, rBlock, d1.BlockNumber)
			}
		}
		return nil
	}

	for _, gid := range d1.GrantPath {
		if cErr := checkInactive("grant", gid); cErr != nil {
			if strings.HasPrefix(cErr.Error(), "incomplete:") {
				return creationDecID, "INCOMPLETE", cErr.Error(), decBlock, revBlock, nil
			}
			return creationDecID, "MISMATCH", cErr.Error(), decBlock, revBlock, nil
		}
	}
	for _, pair := range [][2]string{{"task", d1.TaskID}, {"domain", d1.DomainID}, {"identity", d1.Actor}} {
		if cErr := checkInactive(pair[0], pair[1]); cErr != nil {
			if strings.HasPrefix(cErr.Error(), "incomplete:") {
				return creationDecID, "INCOMPLETE", cErr.Error(), decBlock, revBlock, nil
			}
			return creationDecID, "MISMATCH", cErr.Error(), decBlock, revBlock, nil
		}
	}

	histSnap, err := hist.AssembleHistoricalSnapshot(ctx, leafGrantID, d1.BlockNumber, decTime)
	if err != nil {
		if protocol.HasCode(err, protocol.ErrCodeStateUnavailable) {
			return creationDecID, "INCOMPLETE", err.Error(), decBlock, revBlock, nil
		}
		return creationDecID, "MISMATCH", fmt.Sprintf("historical snapshot at h=%d rejected: %v", d1.BlockNumber, err), decBlock, revBlock, nil
	}
	if histSnap.BlockHash != d1.BlockHash {
		return creationDecID, "MISMATCH", fmt.Sprintf("historical block %d hash %q != decision blockHash %q", d1.BlockNumber, histSnap.BlockHash, d1.BlockHash), decBlock, revBlock, nil
	}
	snap := histSnap.Snapshot
	if snap == nil || snap.Root.DID != d1.RootDID || int64(snap.Root.KeyVersion) != d1.RootKeyVersion {
		return creationDecID, "MISMATCH", "historical T root authority mismatches decision record", decBlock, revBlock, nil
	}
	if dom, ok := snap.Domains[d1.DomainID]; !ok || dom.Status != registry.Active || int64(dom.Revision) != d1.DomainRevision || dom.Certification != d1.CertificationID {
		return creationDecID, "MISMATCH", "historical domain or certification pointer mismatches decision record", decBlock, revBlock, nil
	}
	if cert, ok := snap.Certifications[d1.CertificationID]; !ok || cert.Status != registry.Active || cert.Digest != d1.CertificationDigest {
		return creationDecID, "MISMATCH", "historical certification record mismatches decision digest", decBlock, revBlock, nil
	}
	if task, ok := snap.Tasks[d1.TaskID]; !ok || task.Status != registry.Active || task.Interval.EXP <= d1.DecisionAt || task.Interval.NBF > d1.DecisionAt {
		return creationDecID, "MISMATCH", "historical task invalid at decisionAt", decBlock, revBlock, nil
	}
	for idName, idRec := range snap.Identities {
		if cErr := checkInactive("identity", idName); cErr != nil {
			if strings.HasPrefix(cErr.Error(), "incomplete:") {
				return creationDecID, "INCOMPLETE", cErr.Error(), decBlock, revBlock, nil
			}
			return creationDecID, "MISMATCH", cErr.Error(), decBlock, revBlock, nil
		}
		if idRec.Status != registry.Active {
			return creationDecID, "MISMATCH", fmt.Sprintf("historical identity %q status %s at h=%d", idName, idRec.Status, d1.BlockNumber), decBlock, revBlock, nil
		}
	}

	// Replay original signed package using only archived DID documents and historical h-state.
	var packageJSON, docsJSON []byte
	var checkedMono *int64
	err = tx.QueryRow(ctx, `SELECT package_json, did_documents, checked_mono_ns
		FROM decision_evidence WHERE deployment_id=$1 AND decision_id=$2`,
		s.cfg.DeploymentID, d1.DecisionID,
	).Scan(&packageJSON, &docsJSON, &checkedMono)
	if errors.Is(err, pgx.ErrNoRows) {
		return creationDecID, "INCOMPLETE", "original cryptographic evidence unavailable", decBlock, revBlock, nil
	}
	if err != nil {
		return nil, "", "", nil, nil, err
	}
	if checkedMono == nil {
		return creationDecID, "INCOMPLETE", "original monotonic check evidence missing", decBlock, revBlock, nil
	}
	if *checkedMono < d1.ProbeSentMonoNs || *checkedMono >= d1.ProbeDeadlineMonoNs {
		return creationDecID, "MISMATCH", "decision exceeded original monotonic probe deadline", decBlock, revBlock, nil
	}
	pkg, pErr := protocol.ParseAccessEvidencePackage(packageJSON)
	var docs map[string]json.RawMessage
	if pErr != nil || json.Unmarshal(docsJSON, &docs) != nil {
		return creationDecID, "MISMATCH", "archived evidence is malformed", decBlock, revBlock, nil
	}
	archivedHash, hErr := pkg.Request.Hash(false)
	if hErr != nil || archivedHash != reqHash || pkg.ChallengeID != d1.ChallengeID {
		return creationDecID, "MISMATCH", "archived request binding mismatch", decBlock, revBlock, nil
	}
	if len(pkg.TrustPaths) == 0 {
		return creationDecID, "INCOMPLETE", "historical certification body unavailable", decBlock, revBlock, nil
	}
	provided := make(map[string]bool, len(pkg.TrustPaths))
	for _, tp := range pkg.TrustPaths {
		if tp.DomainCertification != "" {
			provided[tp.Issuer] = true
		}
	}
	for _, credential := range snap.Credentials {
		if !provided[credential.Issuer] {
			return creationDecID, "INCOMPLETE", "required historical domain certification body unavailable", decBlock, revBlock, nil
		}
	}
	resolver, rErr := protocol.NewArchivedDIDResolver(docs, protocol.RootPreseed{
		DID:               snap.Root.DID,
		KeyID:             snap.Root.KeyID,
		KeyVersion:        snap.Root.KeyVersion,
		PublicKeyHex:      snap.Root.PublicKey,
		DIDDocumentDigest: snap.Root.DocumentDigest,
		RawDocument:       docs[snap.Root.DID],
	})
	if rErr != nil {
		st := "MISMATCH"
		if protocol.HasCode(rErr, protocol.ErrCodeMaterialNotSynced) {
			st = "INCOMPLETE"
		}
		return creationDecID, st, rErr.Error(), decBlock, revBlock, nil
	}
	verified, vErr := protocol.VerifyAccessEvidencePackage(ctx, pkg, snap, resolver, protocol.ChallengeContext{
		ChallengeID: d1.ChallengeID,
		Nonce:       nonce,
		Audience:    audience,
		IssuedAt:    issuedAt,
		ExpiresAt:   chalExpiresAt,
	})
	if vErr != nil {
		st := "MISMATCH"
		if protocol.HasCode(vErr, protocol.ErrCodeMaterialNotSynced) {
			st = "INCOMPLETE"
		}
		return creationDecID, st, vErr.Error(), decBlock, revBlock, nil
	}
	if err := verifyRootAuthority(snap, verified, s.cfg.ServiceDID); err != nil {
		return creationDecID, "MISMATCH", err.Error(), decBlock, revBlock, nil
	}
	actualPath := make([]string, len(verified.Grants))
	for i, g := range verified.Grants {
		actualPath[i] = g.Claims.ID
	}
	if !slices.Equal(actualPath, d1.GrantPath) {
		return creationDecID, "MISMATCH", "archived grant path mismatch", decBlock, revBlock, nil
	}

	var polBundle *policy.VerifiedBundle
	if s.cfg.PolicyArchive != nil {
		if b, ok := s.cfg.PolicyArchive[d1.PolicyDigest]; ok {
			polBundle = b
		}
	}
	if polBundle == nil && s.cfg.Policy != nil && s.cfg.Policy.PolicyDigest == d1.PolicyDigest {
		polBundle = s.cfg.Policy
	}
	if polBundle == nil {
		return creationDecID, "INCOMPLETE", fmt.Sprintf("policy bundle %q unavailable for historical replay", d1.PolicyDigest), decBlock, revBlock, nil
	}

	mode, buyerDomain := pkg.Request.AuthorizationMode, pkg.Request.PrincipalDomain
	authorityRole := verified.RootAuthorityRole
	serviceRole := authorityRole
	if mode == protocol.ModeBuyerMandate {
		serviceRole = "supplier-service"
	}
	attributes := map[string]string{}
	for k, v := range verified.LeafCredential.Disclosed {
		if k != "domain" && k != "role" {
			attributes[k] = v
		}
	}
	polDec, polErr := polBundle.EvaluateFacts(ctx, policy.SupplierFacts{
		AuthorizationMode:   mode,
		BuyerDomain:         buyerDomain,
		AuthorityRole:       authorityRole,
		ServiceDID:          s.cfg.ServiceDID,
		ServiceRole:         serviceRole,
		Resource:            pkg.Request.Resource,
		ProductID:           ord.ProductID,
		Quantity:            ord.Quantity,
		Action:              d1.Action,
		AmountMinor:         ord.TotalAmountMinor,
		MaxPathAmountMinor:  verified.MinMaxAmountMinor,
		NowUnix:             d1.DecisionAt,
		VerifiedCrypto:      true,
		TaskActive:          true,
		PathActive:          true,
		ContextFresh:        d1.DecisionAt < d1.ContextAccessDeadline,
		ContextRiskLevel:    d1.ContextRiskLevel,
		WithinTimeAndBounds: d1.DecisionAt < d1.EffectiveDeadline && ord.TotalAmountMinor <= verified.MinMaxAmountMinor,
		Attributes:          attributes,
	})
	if polErr != nil || !polDec.Allow {
		return creationDecID, "MISMATCH", fmt.Sprintf("historical policy replay denied (%s): %v", polDec.Code, polErr), decBlock, revBlock, nil
	}

	reason = fmt.Sprintf("historical checks matched at h=%d", d1.BlockNumber)
	if revBlock != nil {
		reason = fmt.Sprintf("historical checks matched at h=%d < r=%d", d1.BlockNumber, *revBlock)
	}
	return creationDecID, "MATCHED", reason, decBlock, revBlock, nil
}

// DeliverReceipt locks one committed outbox entry FOR UPDATE, invokes send with the
// immutable persisted receipt, records attempt/delivery metadata atomically, and returns
// any transport error after persisting the attempt count and last_error.
func (s *Service) DeliverReceipt(ctx context.Context, entry OutboxEntry, send ReceiptSender) error {
	if send == nil {
		return fmt.Errorf("receipt sender is required")
	}
	deploymentID := entry.DeploymentID
	if strings.TrimSpace(deploymentID) == "" {
		deploymentID = s.cfg.DeploymentID
	}

	var sendErr error
	txErr := dao.RunInTx(ctx, s.cfg.DB, func(tx dao.Tx) error {
		rows, err := tx.Query(ctx, `SELECT
			deployment_id, case_id, send_revision, check_no, receipt_json, delivered_at, attempts, last_error
			FROM order_outcome_outbox
			WHERE deployment_id=$1 AND case_id=$2 AND send_revision=$3 AND check_no=$4
			FOR UPDATE`,
			deploymentID, entry.CaseID, entry.SendRevision, entry.CheckNo,
		)
		if err != nil {
			return err
		}
		locked, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[OutboxEntry])
		if err != nil {
			return err
		}
		var persisted OrderOutcomeReceipt
		if err := json.Unmarshal(locked.ReceiptJSON, &persisted); err != nil {
			return err
		}

		sendErr = send(ctx, persisted)
		lastError := ""
		if sendErr != nil {
			lastError = sendErr.Error()
		}
		_, err = tx.Exec(ctx, `UPDATE order_outcome_outbox
			SET attempts = attempts + 1,
			    last_error = $5,
			    delivered_at = CASE WHEN $5 = '' THEN EXTRACT(EPOCH FROM clock_timestamp())::bigint ELSE delivered_at END
			WHERE deployment_id=$1 AND case_id=$2 AND send_revision=$3 AND check_no=$4`,
			deploymentID, entry.CaseID, entry.SendRevision, entry.CheckNo, lastError,
		)
		return err
	})
	if txErr != nil {
		return txErr
	}
	return sendErr
}

// DeliverPendingReceipts resumes delivery of all undelivered outbox rows for this
// service's deployment without rerunning audits or allocating new checkNo values.
func (s *Service) DeliverPendingReceipts(ctx context.Context, send ReceiptSender) (int, error) {
	if send == nil {
		return 0, fmt.Errorf("receipt sender is required")
	}
	rows, err := s.cfg.DB.Query(ctx, `SELECT
		deployment_id, case_id, send_revision, check_no, receipt_json, delivered_at, attempts, last_error
		FROM order_outcome_outbox
		WHERE deployment_id=$1 AND delivered_at IS NULL
		ORDER BY case_id, send_revision, check_no`,
		s.cfg.DeploymentID,
	)
	if err != nil {
		return 0, err
	}
	pending, err := pgx.CollectRows(rows, pgx.RowToStructByName[OutboxEntry])
	if err != nil {
		return 0, err
	}
	delivered := 0
	for _, entry := range pending {
		if err := s.DeliverReceipt(ctx, entry, send); err != nil {
			return delivered, err
		}
		delivered++
	}
	return delivered, nil
}
