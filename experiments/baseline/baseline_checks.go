package baseline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type decisionDBRow struct {
	StateSource           string     `db:"state_source"`
	Revision              *int64     `db:"revision"`
	StateReadAt           *time.Time `db:"state_read_at"`
	BlockNumber           *int64     `db:"block_number"`
	BlockHash             *string    `db:"block_hash"`
	ProbeTxID             *string    `db:"probe_tx_id"`
	ProbeBlock            *int64     `db:"probe_block"`
	ProbeSentAt           *int64     `db:"probe_sent_at"`
	ProbeDeadline         *int64     `db:"probe_deadline"`
	ProbeSentMonoNs       *int64     `db:"probe_sent_mono_ns"`
	ProbeDeadlineMonoNs   *int64     `db:"probe_deadline_mono_ns"`
	ProbeCheckedMonoNs    *int64     `db:"probe_checked_mono_ns"`
	ContextVersion        *int64     `db:"context_version"`
	ContextObservedAt     *int64     `db:"context_observed_at"`
	ContextAccessDeadline *int64     `db:"context_access_deadline"`
	DecisionAt            *int64     `db:"decision_at"`
	EffectiveDeadline     *int64     `db:"effective_deadline"`
	StateRechecks         *int64     `db:"state_rechecks"`
	RequestID             string     `db:"request_id"`
	ChallengeID           string     `db:"challenge_id"`
	TaskID                string     `db:"task_id"`
	Actor                 string     `db:"actor"`
	IdempotencyKey        string     `db:"idempotency_key"`
	Outcome               string     `db:"outcome"`
	Code                  string     `db:"code"`
	QuoteID               *string    `db:"quote_id"`
	OrderID               *string    `db:"order_id"`
}

func fromInt64Ptr(p *int64) nullInt64 {
	if p == nil {
		return nullInt64{}
	}
	return someInt64(*p)
}

func fromStringPtr(p *string) nullString {
	if p == nil {
		return nullString{}
	}
	return someString(*p)
}

func fromTimePtr(p *time.Time) nullTime {
	if p == nil {
		return nullTime{}
	}
	return someTime(*p)
}

func fromUnixPtr(p *int64) nullTime {
	if p == nil {
		return nullTime{}
	}
	return someTime(time.Unix(*p, 0).UTC())
}

func equalNullStringPtr(n nullString, p *string) bool {
	if !n.Valid && p == nil {
		return true
	}
	if n.Valid && p != nil {
		return n.Value == *p
	}
	return false
}

func (r *baselineRun) decision(ctx context.Context, db *pgxpool.Pool, row *RequestRow) error {
	if !row.DecisionID.Valid {
		return fmt.Errorf("no decision returned")
	}
	rows, err := db.Query(ctx, `
		SELECT state_source, revision, state_read_at, block_number, block_hash,
			probe_tx_id, probe_block, probe_sent_at, probe_deadline,
			probe_sent_mono_ns, probe_deadline_mono_ns, probe_checked_mono_ns,
			context_version, context_observed_at, context_access_deadline,
			decision_at, effective_deadline, state_rechecks,
			request_id, challenge_id, task_id, actor, idempotency_key,
			outcome, code, quote_id, order_id
		FROM decisions
		WHERE deployment_id=$1 AND decision_id=$2`,
		r.d.DeploymentID, row.DecisionID.Value,
	)
	if err != nil {
		return err
	}
	d, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[decisionDBRow])
	if err != nil {
		return err
	}

	row.StateSource = someString(d.StateSource)
	row.Revision = fromInt64Ptr(d.Revision)
	row.StateReadAt = fromTimePtr(d.StateReadAt)
	row.BlockNumber = fromInt64Ptr(d.BlockNumber)
	row.BlockHash = fromStringPtr(d.BlockHash)
	row.ProbeTxID = fromStringPtr(d.ProbeTxID)
	row.ProbeBlock = fromInt64Ptr(d.ProbeBlock)
	row.ProbeSentAt = fromUnixPtr(d.ProbeSentAt)
	row.ProbeDeadline = fromUnixPtr(d.ProbeDeadline)
	row.ProbeSentMonoNs = fromInt64Ptr(d.ProbeSentMonoNs)
	row.ProbeDeadlineMonoNs = fromInt64Ptr(d.ProbeDeadlineMonoNs)
	row.ProbeCheckedMonoNs = fromInt64Ptr(d.ProbeCheckedMonoNs)
	row.ContextVersion = fromInt64Ptr(d.ContextVersion)
	row.ContextObservedAt = fromUnixPtr(d.ContextObservedAt)
	row.ContextAccessDeadline = fromUnixPtr(d.ContextAccessDeadline)
	row.DecisionAt = fromUnixPtr(d.DecisionAt)
	row.EffectiveDeadline = fromUnixPtr(d.EffectiveDeadline)
	row.StateRechecks = fromInt64Ptr(d.StateRechecks)

	if !row.RequestID.Valid || row.RequestID.Value != d.RequestID ||
		!row.ChallengeID.Valid || row.ChallengeID.Value != d.ChallengeID ||
		!row.TaskID.Valid || row.TaskID.Value != d.TaskID ||
		!row.Actor.Valid || row.Actor.Value != d.Actor ||
		!row.IdempotencyKey.Valid || row.IdempotencyKey.Value != d.IdempotencyKey ||
		!row.Code.Valid || row.Code.Value != d.Code {
		return fmt.Errorf("HTTP decision association mismatch")
	}
	if row.Disposition == "allowed" && d.Outcome != "ALLOW" || row.Disposition == "denied" && d.Outcome != "DENY" {
		return fmt.Errorf("HTTP disposition differs from stored decision")
	}
	if row.Disposition == "allowed" && (!equalNullStringPtr(row.QuoteID, d.QuoteID) || !equalNullStringPtr(row.OrderID, d.OrderID)) {
		return fmt.Errorf("HTTP resource IDs differ from stored decision")
	}

	var consumed *int64
	var challengeDecision *string
	var requestHash string
	if err := db.QueryRow(ctx,
		`SELECT consumed_at, decision_id, request_hash FROM challenges WHERE deployment_id=$1 AND challenge_id=$2`,
		r.d.DeploymentID, row.ChallengeID.Value,
	).Scan(&consumed, &challengeDecision, &requestHash); err != nil {
		return err
	}
	if consumed == nil || challengeDecision == nil || *challengeDecision != row.DecisionID.Value ||
		!row.RequestHash.Valid || requestHash != row.RequestHash.Value {
		return fmt.Errorf("challenge and decision association mismatch")
	}
	return nil
}

func (r *baselineRun) orderCheck(ctx context.Context, db *pgxpool.Pool, c Case, row *RequestRow, check *OrderCheckRow, before int64, quoteID string) error {
	check.QuoteID = someString(quoteID)
	check.ChallengeID = row.ChallengeID
	check.DecisionID = row.DecisionID

	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	var after, keys, quoteAmount int64
	if err = tx.QueryRow(ctx,
		`SELECT count(*) FROM orders WHERE deployment_id=$1 AND task_id=$2`,
		r.d.DeploymentID, row.TaskID.Value,
	).Scan(&after); err != nil {
		return err
	}
	check.OrderRowsAfter = someInt64(after)

	if err = tx.QueryRow(ctx,
		`SELECT count(*) FROM business_keys WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND action='order.create' AND idempotency_key=$4`,
		r.d.DeploymentID, row.Actor.Value, row.TaskID.Value, row.IdempotencyKey.Value,
	).Scan(&keys); err != nil {
		return err
	}
	check.OrderKeyRows = someInt64(keys)

	var qActor, qTask string
	if err = tx.QueryRow(ctx,
		`SELECT total_amount_minor, actor, task_id FROM quotes WHERE deployment_id=$1 AND quote_id=$2`,
		r.d.DeploymentID, quoteID,
	).Scan(&quoteAmount, &qActor, &qTask); err != nil {
		return err
	}
	check.QuoteAmountMinor = someInt64(quoteAmount)

	var consumed *int64
	var challengeDecision *string
	var requestHash string
	if err = tx.QueryRow(ctx,
		`SELECT consumed_at, decision_id, request_hash FROM challenges WHERE deployment_id=$1 AND challenge_id=$2`,
		r.d.DeploymentID, row.ChallengeID.Value,
	).Scan(&consumed, &challengeDecision, &requestHash); err != nil {
		return err
	}
	check.ChallengeConsumed = someBool(consumed != nil)

	if !row.DecisionID.Valid && row.FailureStage.Valid && row.FailureStage.Value == "execute" {
		check.Verdict = "FAIL"
		check.FailureReason = someString("order execution returned no decision")
		return tx.Commit(ctx)
	}

	var outcome, code string
	if err = tx.QueryRow(ctx,
		`SELECT outcome, code FROM decisions WHERE deployment_id=$1 AND decision_id=$2`,
		r.d.DeploymentID, row.DecisionID.Value,
	).Scan(&outcome, &code); err != nil {
		return err
	}
	check.DecisionOutcome = someString(outcome)
	check.DecisionCode = someString(code)

	var ownOrders int64
	if err = tx.QueryRow(ctx,
		`SELECT count(*) FROM orders WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND idempotency_key=$4`,
		r.d.DeploymentID, row.Actor.Value, row.TaskID.Value, row.IdempotencyKey.Value,
	).Scan(&ownOrders); err != nil {
		return err
	}

	httpOK := row.HTTPStatus.Valid && row.HTTPStatus.Value == int64(c.ExpectedStatus) &&
		row.Code.Valid && row.Code.Value == c.ExpectedCode &&
		!row.FailureStage.Valid
	primaryOK := quoteAmount == c.AmountMinor &&
		row.Actor.Valid && qActor == row.Actor.Value &&
		row.TaskID.Valid && qTask == row.TaskID.Value &&
		consumed != nil && challengeDecision != nil &&
		row.DecisionID.Valid && *challengeDecision == row.DecisionID.Value &&
		row.RequestHash.Valid && requestHash == row.RequestHash.Value

	if c.AmountMinor == 80000 {
		var id, status, decision, qid string
		var amount int64
		if ownOrders == 1 {
			if err = tx.QueryRow(ctx,
				`SELECT order_id, status, decision_id, quote_id, total_amount_minor FROM orders WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND idempotency_key=$4`,
				r.d.DeploymentID, row.Actor.Value, row.TaskID.Value, row.IdempotencyKey.Value,
			).Scan(&id, &status, &decision, &qid, &amount); err != nil {
				return err
			}
			check.OrderID = someString(id)
			check.OrderStatus = someString(status)
			check.CreationDecisionID = someString(decision)
		}
		var keyStatus, keyResource, keyDecision string
		if keys == 1 {
			if err = tx.QueryRow(ctx,
				`SELECT status, resource_id, decision_id FROM business_keys WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND action='order.create' AND idempotency_key=$4`,
				r.d.DeploymentID, row.Actor.Value, row.TaskID.Value, row.IdempotencyKey.Value,
			).Scan(&keyStatus, &keyResource, &keyDecision); err != nil {
				return err
			}
			check.OrderKeyStatus = someString(keyStatus)
		}
		httpOK = httpOK && id != "" &&
			row.OrderID.Valid && row.OrderID.Value == id &&
			row.QuoteID.Valid && row.QuoteID.Value == quoteID &&
			row.httpOrderStatus.Valid && row.httpOrderStatus.Value == "CREATED" &&
			row.httpOrderAmountMinor.Valid && row.httpOrderAmountMinor.Value == c.AmountMinor
		primaryOK = primaryOK && after == before+1 && keys == 1 && ownOrders == 1 &&
			outcome == "ALLOW" && code == "ALLOW" &&
			status == "CREATED" && decision == row.DecisionID.Value && qid == quoteID && amount == c.AmountMinor &&
			keyStatus == "COMPLETED" && keyResource == id && keyDecision == decision
	} else {
		httpOK = httpOK && !row.OrderID.Valid
		primaryOK = primaryOK && after == before && ownOrders == 0 && keys == 0 &&
			outcome == "DENY" && code == "AMOUNT_LIMIT_EXCEEDED"
	}

	if httpOK && primaryOK {
		check.Verdict = "PASS"
		check.FailureReason = nullString{}
	} else {
		check.Verdict = "FAIL"
		check.FailureReason = someString("HTTP and primary database facts did not meet the paired case expectation")
	}
	return tx.Commit(ctx)
}

func (r *baselineRun) compare() bool {
	caseResults := make([]CaseResult, 0, len(r.inputs.Cases))
	pairResults := make([]PairResult, 0, 4)
	by := map[string]GroupSummary{}
	passed := len(r.evidence.Summary.Failures) == 0
	seenChallenges := map[string]bool{}

	for n, c := range r.inputs.Cases {
		q := &r.evidence.Requests[2*n]
		o := &r.evidence.Requests[2*n+1]
		check := &r.evidence.Orders[n]
		profile, _ := BaselineConfiguration(c.Configuration)

		ok := check.Verdict == "PASS" &&
			q.HTTPStatus.Valid && q.HTTPStatus.Value == 200 &&
			q.Code.Valid && q.Code.Value == "ALLOW" &&
			!q.FailureStage.Valid

		for _, row := range []*RequestRow{q, o} {
			if !row.ChallengeID.Valid || row.ChallengeID.Value == "" || seenChallenges[row.ChallengeID.Value] {
				ok = false
			}
			if row.ChallengeID.Valid {
				seenChallenges[row.ChallengeID.Value] = true
			}
			if !row.StateSource.Valid || row.StateSource.Value != profile.StateSource {
				ok = false
			}
			if c.Configuration == "C0" {
				if !row.Revision.Valid || !row.StateReadAt.Valid || row.BlockNumber.Valid || row.ProbeTxID.Valid {
					ok = false
				}
			} else {
				if row.Revision.Valid || row.StateReadAt.Valid || !validBaselineFabricEvidence(row) {
					ok = false
				}
			}
			if c.Configuration != "B1" && (!row.SignatureCacheHits.Valid || row.SignatureCacheHits.Value != 0) {
				ok = false
			}
		}

		if !ok {
			passed = false
		}
		key := c.Configuration + "/" + c.Mode
		grp := by[key]
		grp.Cases++
		if ok {
			grp.Passed++
		} else {
			grp.Failed++
		}
		by[key] = grp

		caseResults = append(caseResults, CaseResult{
			Configuration:  c.Configuration,
			CaseID:         c.CaseID,
			Mode:           c.Mode,
			AmountMinor:    c.AmountMinor,
			ExpectedStatus: c.ExpectedStatus,
			ExpectedCode:   c.ExpectedCode,
			ActualStatus:   o.HTTPStatus.intPtr(),
			ActualCode:     o.Code.ptr(),
			OrderDelta:     orderDelta(check),
			OrderKeyRows:   check.OrderKeyRows.ptr(),
			Passed:         ok,
		})
	}

	for n := 0; n < 4; n++ {
		ok := true
		for _, offset := range []int{4, 8} {
			a := &r.evidence.Requests[2*n+1]
			b := &r.evidence.Requests[2*(n+offset)+1]
			x := &r.evidence.Orders[n]
			y := &r.evidence.Orders[n+offset]
			if a.HTTPStatus != b.HTTPStatus || a.Code != b.Code ||
				x.Verdict != "PASS" || y.Verdict != "PASS" ||
				!equalInt64Ptr(orderDelta(x), orderDelta(y)) ||
				x.OrderKeyRows != y.OrderKeyRows {
				ok = false
			}
		}
		if !ok {
			passed = false
		}
		pairResults = append(pairResults, PairResult{
			Seed:        r.inputs.Seed,
			CaseID:      r.inputs.Cases[n].CaseID,
			Mode:        r.inputs.Cases[n].Mode,
			AmountMinor: r.inputs.Cases[n].AmountMinor,
			Passed:      ok,
		})
	}

	var hits int64
	for i := range r.evidence.Requests {
		row := &r.evidence.Requests[i]
		if row.Configuration == "B1" && row.SignatureCacheHits.Valid {
			hits += row.SignatureCacheHits.Value
		}
	}
	if hits == 0 {
		passed = false
	}

	r.evidence.Summary.B1SignatureCacheHits = hits
	r.evidence.Summary.ByConfigurationAndMode = by
	r.evidence.Summary.CaseResults = caseResults
	r.evidence.Summary.PairResults = pairResults
	return passed
}

func validBaselineFabricEvidence(row *RequestRow) bool {
	if !row.BlockHash.Valid || !row.ProbeTxID.Valid || row.ProbeTxID.Value == "" {
		return false
	}
	hash, err := hex.DecodeString(row.BlockHash.Value)
	if err != nil || len(hash) != sha256.Size {
		return false
	}
	if !row.ProbeSentAt.Valid || !row.ProbeDeadline.Valid || !row.ProbeSentAt.Value.Before(row.ProbeDeadline.Value) {
		return false
	}
	if !row.BlockNumber.Valid || !row.ProbeBlock.Valid ||
		!row.ProbeSentMonoNs.Valid || !row.ProbeDeadlineMonoNs.Valid || !row.ProbeCheckedMonoNs.Valid {
		return false
	}
	return row.ProbeBlock.Value >= 0 &&
		row.ProbeBlock.Value <= row.BlockNumber.Value &&
		row.ProbeSentMonoNs.Value >= 0 &&
		row.ProbeSentMonoNs.Value <= row.ProbeCheckedMonoNs.Value &&
		row.ProbeCheckedMonoNs.Value < row.ProbeDeadlineMonoNs.Value
}

func orderDelta(check *OrderCheckRow) *int64 {
	if !check.OrderRowsAfter.Valid || !check.OrderRowsBefore.Valid {
		return nil
	}
	v := check.OrderRowsAfter.Value - check.OrderRowsBefore.Value
	return &v
}

func equalInt64Ptr(a, b *int64) bool {
	if a == nil && b == nil {
		return true
	}
	if a != nil && b != nil {
		return *a == *b
	}
	return false
}
