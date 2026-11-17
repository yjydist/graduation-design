package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/policy"
	"graduation-design/internal/protocol"

	"github.com/jackc/pgx/v5"
)

type precheckResult struct {
	pkg             *protocol.AccessEvidencePackage
	leafGrantID     string
	reqHash         string
	view            *ConsistentSnapshot
	verified        *protocol.VerifiedEvidenceResult
	chal            protocol.ChallengeContext
	rootDID         string
	rootKeyVersion  int64
	domainID        string
	certID          string
	certDigest      string
	domainRevision  int64
	identityIssuer  string
	grantPath       []string
	effectiveExpiry int64
}

func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request) {
	reqID := requestIDFromContext(r.Context())
	body, err := readBoundedBody(r, MaxExecuteBodyBytes)
	if err != nil {
		writeMappedError(w, r, nil, err)
		return
	}
	pkg, err := protocol.ParseAccessEvidencePackage(body)
	if err != nil {
		writeMappedError(w, r, nil, err)
		return
	}
	if err := validateExecuteSchema(pkg, s.cfg.DeploymentID, s.cfg.Audience); err != nil {
		writeMappedError(w, r, nil, err)
		return
	}

	reqHash, err := pkg.Request.Hash(false)
	if err != nil {
		writeMappedError(w, r, nil, err)
		return
	}
	leafGrantID, err := extractLeafGrantID(pkg.Grants)
	if err != nil {
		writeMappedError(w, r, nil, err)
		return
	}

	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		nowTime := s.now()
		pre, err := s.runPrecheck(r.Context(), pkg, leafGrantID, reqHash, nowTime)
		if err != nil {
			writeMappedError(w, r, nil, err)
			return
		}

		if s.cfg.BeforeLockTx != nil {
			s.cfg.BeforeLockTx(attempt)
		}

		outcome, retry, err := s.executeInTx(r.Context(), reqID, pre, attempt)
		if retry {
			continue
		}
		if err != nil {
			var decPtr *string
			if outcome != nil && outcome.decisionID != "" {
				decPtr = &outcome.decisionID
			}
			writeMappedError(w, r, decPtr, err)
			return
		}
		writeJSONResponse(w, http.StatusOK, outcome.resp)
		return
	}

	writeErrorResponse(w, r, http.StatusConflict, protocol.ErrCodeStateChanged, nil, "checkpoint changed across maximum retries")
}

func validateExecuteSchema(pkg *protocol.AccessEvidencePackage, expectedDepID, expectedAudience string) error {
	if pkg == nil {
		return protocol.NewError(protocol.ErrCodeInvalidSchema, "missing AccessEvidencePackage")
	}
	if err := pkg.Request.Validate(false); err != nil {
		return err
	}
	req := pkg.Request
	if !idempotencyKeyRe.MatchString(req.IdempotencyKey) {
		return protocol.NewError(protocol.ErrCodeInvalidSchema, "idempotencyKey must match ^[A-Za-z0-9_-]{1,64}$")
	}
	switch req.Action {
	case "quote.read":
		if req.Resource != "quotes" && req.Resource != "urn:grad:resource:quotes" && req.Resource != "urn:grad:resource:C:quotes" {
			return protocol.NewError(protocol.ErrCodeInvalidSchema, fmt.Sprintf("quote.read requires quotes resource, got %q", req.Resource))
		}
		if req.QuoteID != nil {
			return protocol.NewError(protocol.ErrCodeInvalidSchema, "quote.read requires quoteId == null")
		}
		if req.AmountMinor != 0 {
			return protocol.NewError(protocol.ErrCodeInvalidSchema, "quote.read requires amountMinor == 0")
		}
	case "order.create":
		if req.Resource != "orders" && req.Resource != "urn:grad:resource:orders" && req.Resource != "urn:grad:resource:C:orders" {
			return protocol.NewError(protocol.ErrCodeInvalidSchema, fmt.Sprintf("order.create requires orders resource, got %q", req.Resource))
		}
		if req.QuoteID == nil || strings.TrimSpace(*req.QuoteID) == "" {
			return protocol.NewError(protocol.ErrCodeInvalidSchema, "order.create requires non-empty quoteId")
		}
		if req.AmountMinor <= 0 {
			return protocol.NewError(protocol.ErrCodeInvalidSchema, "order.create requires amountMinor > 0")
		}
	default:
		return protocol.NewError(protocol.ErrCodeInvalidSchema, fmt.Sprintf("resource gateway supports quote.read and order.create, got %q", req.Action))
	}
	if req.Quantity <= 0 {
		return protocol.NewError(protocol.ErrCodeInvalidSchema, fmt.Sprintf("%s requires quantity > 0", req.Action))
	}
	if expectedDepID != "" && req.DeploymentID != expectedDepID {
		return protocol.NewError(protocol.ErrCodeBindingMismatch, fmt.Sprintf("request deploymentId %q != %q", req.DeploymentID, expectedDepID))
	}
	if expectedAudience != "" && req.Audience != expectedAudience {
		return protocol.NewError(protocol.ErrCodeBindingMismatch, fmt.Sprintf("request audience %q != %q", req.Audience, expectedAudience))
	}
	if pkg.ChallengeID == "" || pkg.LeafPresentation == "" || len(pkg.Grants) == 0 || len(pkg.TrustPaths) == 0 {
		return protocol.NewError(protocol.ErrCodeInvalidSchema, "challengeId, leafPresentation, grants, and trustPaths are required")
	}
	return nil
}

func extractLeafGrantID(grants []string) (string, error) {
	if len(grants) == 0 {
		return "", protocol.NewError(protocol.ErrCodeInvalidSchema, "grants must be non-empty")
	}
	prelim, err := protocol.ParseCompactJWS(grants[len(grants)-1], protocol.TypGrantDelegation)
	if err != nil {
		return "", err
	}
	var claims protocol.GrantClaims
	if err := protocol.DecodeStrictJSON(prelim.PayloadBytes, &claims); err != nil {
		return "", err
	}
	if claims.ID == "" {
		return "", protocol.NewError(protocol.ErrCodeInvalidSchema, "leaf grant id is empty")
	}
	return claims.ID, nil
}

func (s *Server) runPrecheck(
	ctx context.Context,
	pkg *protocol.AccessEvidencePackage,
	leafGrantID string,
	reqHash string,
	nowTime time.Time,
) (*precheckResult, error) {
	// 1. Read challenge non-consumingly; never mark consumed on pre-check failure.
	var nonce, chalActor, chalTaskID, chalReqHash, chalAud string
	var chalIssuedAt, chalExpiresAt int64
	var consumedAt *int64
	err := s.cfg.DB.QueryRow(ctx, `SELECT
		nonce, actor, task_id, request_hash, audience, issued_at, expires_at, consumed_at
		FROM challenges WHERE deployment_id=$1 AND challenge_id=$2`,
		s.cfg.DeploymentID, pkg.ChallengeID,
	).Scan(&nonce, &chalActor, &chalTaskID, &chalReqHash, &chalAud, &chalIssuedAt, &chalExpiresAt, &consumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, protocol.NewError(protocol.ErrCodeChallengeUnknown, fmt.Sprintf("challenge %q not found", pkg.ChallengeID))
	}
	if err != nil {
		return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "read challenge", err)
	}
	if consumedAt != nil {
		return nil, protocol.NewError(protocol.ErrCodeChallengeReplay, fmt.Sprintf("challenge %q already consumed", pkg.ChallengeID))
	}
	if chalActor != pkg.Request.Actor || chalTaskID != pkg.Request.TaskID || chalReqHash != reqHash || chalAud != pkg.Request.Audience {
		return nil, protocol.NewError(protocol.ErrCodeChallengeMismatch, "challenge binding mismatches request actor/taskId/requestHash/audience")
	}
	nowSec := nowTime.Unix()
	if nowSec >= chalExpiresAt {
		return nil, protocol.NewError(protocol.ErrCodeChallengeExpired, fmt.Sprintf("challenge %q expired at %d (now=%d)", pkg.ChallengeID, chalExpiresAt, nowSec))
	}
	chalCtx := protocol.ChallengeContext{
		ChallengeID: pkg.ChallengeID,
		Nonce:       nonce,
		Audience:    chalAud,
		IssuedAt:    chalIssuedAt,
		ExpiresAt:   chalExpiresAt,
	}

	// 2. Assemble fixed-height consistent snapshot from PostgreSQL + fresh process probe.
	view, err := s.cfg.State.AssembleSnapshot(ctx, leafGrantID, nowTime)
	if err != nil {
		return nil, err
	}
	snap := view.Snapshot

	// 3. Require synced DomainAuthorityCertification JWS for active domains in the snapshot.
	// Inactive (SUSPENDED/REVOKED) domains proceed to step 4 so VerifyAccessEvidencePackageWithCache
	// emits 403 DOMAIN_INACTIVE cleanly instead of masking suspension as MATERIAL_NOT_SYNCED.
	if s.cfg.Delivery != nil {
		for domID, dom := range snap.Domains {
			if dom.Status != api.Active {
				continue
			}
			cert, ok := snap.Certifications[dom.Certification]
			if !ok {
				return nil, protocol.NewError(protocol.ErrCodeMaterialNotSynced, fmt.Sprintf("active certification %q missing for domain %q", dom.Certification, domID))
			}
			if _, err := s.cfg.Delivery.HasSyncedCertification(ctx, s.cfg.DeploymentID, domID, cert.ID, cert.Digest); err != nil {
				return nil, err
			}
		}
	}

	// 4. Full cryptographic evidence + chain verification on consistent snapshot (with optional B1 signature cache).
	verified, err := protocol.VerifyAccessEvidencePackageWithCache(ctx, pkg, snap, s.cfg.DIDs, chalCtx, s.cfg.SignatureCache)
	if err != nil {
		return nil, err
	}

	// 5. Verify root authority according to authorization mode.
	if err := verifyRootAuthority(snap, verified, s.cfg.ServiceDID); err != nil {
		return nil, err
	}
	if pkg.Request.SupplierID != s.cfg.SupplierID || pkg.Request.Quantity > pkg.TaskSpec.MaxQuantity {
		return nil, protocol.NewError(protocol.ErrCodeTaskScopeMismatch, "request supplierId or quantity exceeds task/service scope")
	}

	// Compute metadata and tightest credential/grant/cert/task expiry bound for exact-second checks.
	grantPath := make([]string, len(verified.Grants))
	minExp := chalExpiresAt
	if task, ok := snap.Tasks[pkg.Request.TaskID]; ok && task.Interval.EXP < minExp {
		minExp = task.Interval.EXP
	}
	for i, g := range verified.Grants {
		grantPath[i] = g.Claims.ID
		if g.Claims.EXP < minExp {
			minExp = g.Claims.EXP
		}
	}
	if verified.LeafCredential.Claims.EXP < minExp {
		minExp = verified.LeafCredential.Claims.EXP
	}
	for _, anc := range verified.AncestorCreds {
		if anc.Claims.EXP < minExp {
			minExp = anc.Claims.EXP
		}
	}
	for _, cert := range verified.TrustPathCerts {
		if cert.EXP < minExp {
			minExp = cert.EXP
		}
	}
	if s.cfg.Policy.Resources.PolicyDeadline != nil && *s.cfg.Policy.Resources.PolicyDeadline < minExp {
		minExp = *s.cfg.Policy.Resources.PolicyDeadline
	}

	dom := snap.Domains[pkg.Request.PrincipalDomain]
	cert := snap.Certifications[dom.Certification]

	return &precheckResult{
		pkg:             pkg,
		leafGrantID:     leafGrantID,
		reqHash:         reqHash,
		view:            view,
		verified:        verified,
		chal:            chalCtx,
		rootDID:         snap.Root.DID,
		rootKeyVersion:  int64(snap.Root.KeyVersion),
		domainID:        dom.ID,
		certID:          cert.ID,
		certDigest:      cert.Digest,
		domainRevision:  int64(dom.Revision),
		identityIssuer:  verified.LeafCredential.Claims.Issuer,
		grantPath:       grantPath,
		effectiveExpiry: minExp,
	}, nil
}

func verifyRootAuthority(snap *protocol.SnapshotView, verified *protocol.VerifiedEvidenceResult, serviceDID string) error {
	if len(verified.Grants) == 0 {
		return protocol.NewError(protocol.ErrCodeRootAuthorityInvalid, "missing root grant")
	}
	rootGrant := verified.Grants[0].Claims
	var rootCred *protocol.VerifiedIdentityCredential
	if rootGrant.IssuerCredentialID == verified.LeafCredential.Claims.ID {
		rootCred = verified.LeafCredential
	} else {
		rootCred = verified.AncestorCreds[rootGrant.IssuerCredentialID]
	}
	if rootCred == nil {
		return protocol.NewError(protocol.ErrCodeRootAuthorityInvalid, "missing root issuer credential")
	}

	switch rootGrant.AuthorizationMode {
	case api.RP:
		if rootGrant.Issuer != serviceDID {
			return protocol.NewError(protocol.ErrCodeRootAuthorityInvalid, fmt.Sprintf("RP root issuer %q != service DID %q", rootGrant.Issuer, serviceDID))
		}
		if rootCred.Role != "supplier-service" && rootCred.Role != "RESOURCE_AUTHORITY" && rootCred.Role != "SERVICE" && rootCred.Role != "ResourceOwner" {
			return protocol.NewError(protocol.ErrCodeRootAuthorityInvalid, fmt.Sprintf("RP root role %q is not an authorized resource service role", rootCred.Role))
		}
		return nil
	case protocol.ModeBuyerMandate:
		dom, ok := snap.Domains[rootGrant.PrincipalDomain]
		if !ok || dom.Status != api.Active || dom.PurchasingAuthority != rootGrant.Issuer ||
			rootCred.Domain != dom.ID || (rootCred.Role != "procurement-authority" && rootCred.Role != "PURCHASING_AUTHORITY") {
			msg := "BM root issuer does not hold active purchasingAuthority credential in principalDomain"
			return protocol.WrapError(protocol.ErrCodePurchasingAuthorityInvalid, msg, protocol.NewError(protocol.ErrCodeRootAuthorityInvalid, msg))
		}
		return nil
	default:
		return protocol.NewError(protocol.ErrCodeRootAuthorityInvalid, fmt.Sprintf("unsupported authorizationMode %q", rootGrant.AuthorizationMode))
	}
}

type txExecOutcome struct {
	decisionID string
	resp       ExecuteResponse
}

func (s *Server) executeInTx(
	ctx context.Context,
	reqID string,
	pre *precheckResult,
	attempt int,
) (outcome *txExecOutcome, retryCheckpoint bool, retErr error) {
	tx, err := s.cfg.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "begin execute transaction", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Step 1: Lock challenge row FOR UPDATE.
	var chalActor, chalTaskID, chalReqHash, chalAud string
	var chalExpiresAt int64
	var consumedAt *int64
	err = tx.QueryRow(ctx, `SELECT
		actor, task_id, request_hash, audience, expires_at, consumed_at
		FROM challenges WHERE deployment_id=$1 AND challenge_id=$2 FOR UPDATE`,
		s.cfg.DeploymentID, pre.pkg.ChallengeID,
	).Scan(&chalActor, &chalTaskID, &chalReqHash, &chalAud, &chalExpiresAt, &consumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, protocol.NewError(protocol.ErrCodeChallengeUnknown, "challenge not found in lock tx")
	}
	if err != nil {
		return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "lock challenge row", err)
	}
	if consumedAt != nil {
		return nil, false, protocol.NewError(protocol.ErrCodeChallengeReplay, fmt.Sprintf("challenge %q already consumed", pre.pkg.ChallengeID))
	}
	if chalActor != pre.pkg.Request.Actor || chalTaskID != pre.pkg.Request.TaskID || chalReqHash != pre.reqHash || chalAud != pre.pkg.Request.Audience {
		return nil, false, protocol.NewError(protocol.ErrCodeChallengeMismatch, "locked challenge mismatches request binding")
	}

	// Step 2: Acquire or insert business_keys placeholder BEFORE reading contexts/checkpoint.
	var existingHash, existingStatus string
	var existingResourceID *string
	insertedPlaceholder := false
	err = tx.QueryRow(ctx, `SELECT request_hash, status, resource_id
		FROM business_keys
		WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND action=$4 AND idempotency_key=$5
		FOR UPDATE`,
		s.cfg.DeploymentID, pre.pkg.Request.Actor, pre.pkg.Request.TaskID, pre.pkg.Request.Action, pre.pkg.Request.IdempotencyKey,
	).Scan(&existingHash, &existingStatus, &existingResourceID)
	if errors.Is(err, pgx.ErrNoRows) {
		tag, insErr := tx.Exec(ctx, `INSERT INTO business_keys(
			deployment_id, actor, task_id, action, idempotency_key, request_hash, status
		) VALUES($1,$2,$3,$4,$5,$6,'IN_PROGRESS')
		ON CONFLICT(deployment_id, actor, task_id, action, idempotency_key) DO NOTHING`,
			s.cfg.DeploymentID, pre.pkg.Request.Actor, pre.pkg.Request.TaskID, pre.pkg.Request.Action, pre.pkg.Request.IdempotencyKey, pre.reqHash,
		)
		if insErr != nil {
			return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "insert idempotency placeholder", insErr)
		}
		if tag.RowsAffected() == 1 {
			insertedPlaceholder = true
			existingHash = pre.reqHash
			existingStatus = "IN_PROGRESS"
		} else {
			err = tx.QueryRow(ctx, `SELECT request_hash, status, resource_id
				FROM business_keys
				WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND action=$4 AND idempotency_key=$5
				FOR UPDATE`,
				s.cfg.DeploymentID, pre.pkg.Request.Actor, pre.pkg.Request.TaskID, pre.pkg.Request.Action, pre.pkg.Request.IdempotencyKey,
			).Scan(&existingHash, &existingStatus, &existingResourceID)
			if err != nil {
				return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "relock business key", err)
			}
		}
	} else if err != nil {
		return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "lock business key", err)
	}
	if existingHash != pre.reqHash {
		return nil, false, protocol.NewError(protocol.ErrCodeIdempotencyConflict, "idempotencyKey already bound to a different requestHash")
	}

	// Step 3: Shared lock trusted_contexts row IN PLACE until transaction end.
	var ctxVersion, ctxObservedAt, ctxDeadline int64
	var ctxRiskLevel, ctxSourceID string
	err = tx.QueryRow(ctx, `SELECT
		context_version, source_id, observed_at, risk_level, access_deadline
		FROM trusted_contexts WHERE deployment_id=$1 AND task_id=$2 FOR SHARE`,
		s.cfg.DeploymentID, pre.pkg.Request.TaskID,
	).Scan(&ctxVersion, &ctxSourceID, &ctxObservedAt, &ctxRiskLevel, &ctxDeadline)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, protocol.NewError(protocol.ErrCodeContextStale, "trusted context row missing")
	}
	if err != nil {
		return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "lock trusted_contexts row", err)
	}

	// Step 4: Shared lock catalog_prices row for productId.
	var catSupplierID, catCurrency string
	var unitPriceMinor int64
	err = tx.QueryRow(ctx, `SELECT supplier_id, currency, unit_price_minor
		FROM catalog_prices WHERE deployment_id=$1 AND product_id=$2 FOR SHARE`,
		s.cfg.DeploymentID, pre.pkg.Request.ProductID,
	).Scan(&catSupplierID, &catCurrency, &unitPriceMinor)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, protocol.NewError(protocol.ErrCodePriceUnavailable, fmt.Sprintf("catalog price missing for %q", pre.pkg.Request.ProductID))
	}
	if err != nil {
		return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "lock catalog_prices row", err)
	}
	if catSupplierID != pre.pkg.Request.SupplierID || catCurrency != pre.pkg.Request.Currency {
		return nil, false, protocol.NewError(protocol.ErrCodeTaskScopeMismatch, "catalog price supplier/currency mismatches request")
	}

	// Step 4b: For fresh order.create, lock referenced quote row IN PLACE prior to locking fabric_head.
	var lockedQuote QuoteDTO
	quoteFound := false
	isFreshOrder := pre.pkg.Request.Action == "order.create" && !(existingStatus == "COMPLETED" && existingResourceID != nil && *existingResourceID != "")
	if isFreshOrder {
		targetQuoteID := ""
		if pre.pkg.Request.QuoteID != nil {
			targetQuoteID = *pre.pkg.Request.QuoteID
		}
		err = tx.QueryRow(ctx, `SELECT
			quote_id, task_id, actor, supplier_id, product_id, quantity, currency,
			unit_price_minor, total_amount_minor, issued_at, valid_until
			FROM quotes WHERE deployment_id=$1 AND quote_id=$2 FOR UPDATE`,
			s.cfg.DeploymentID, targetQuoteID,
		).Scan(
			&lockedQuote.QuoteID, &lockedQuote.TaskID, &lockedQuote.Actor, &lockedQuote.SupplierID, &lockedQuote.ProductID,
			&lockedQuote.Quantity, &lockedQuote.Currency, &lockedQuote.UnitPriceMinor, &lockedQuote.TotalAmountMinor,
			&lockedQuote.IssuedAt, &lockedQuote.ValidUntil,
		)
		if err == nil {
			quoteFound = true
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "lock referenced quote row", err)
		}
	}

	// Optional deterministic concurrency hook before locking fabric_head FOR SHARE.
	if s.cfg.BeforeLockHead != nil {
		s.cfg.BeforeLockHead(attempt)
	}

	// Step 5: Lock and compare the actual source checkpoint AFTER all business row locks.
	unchanged, err := s.cfg.State.LockCheckpoint(ctx, tx, pre.view)
	if err != nil {
		return nil, false, err
	}
	if !unchanged {
		return nil, true, protocol.NewError(protocol.ErrCodeStateChanged, "state checkpoint changed after precheck")
	}

	// Step 6: Post-lock explicit clock_timestamp() query and monotonic probe freshness verification.
	var dbClockSec int64
	if err := tx.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM clock_timestamp())::bigint`).Scan(&dbClockSec); err != nil {
		return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "query clock_timestamp()", err)
	}
	decisionSec := dbClockSec
	if s.cfg.NowFn != nil {
		decisionSec = s.cfg.NowFn().Unix()
	}

	probe, err := s.cfg.State.CheckFresh(ctx, pre.view)
	if err != nil {
		return nil, false, err
	}

	effectiveDeadline := pre.effectiveExpiry
	if ctxDeadline < effectiveDeadline {
		effectiveDeadline = ctxDeadline
	}

	// Infrastructure / transient staleness aborts via rollback without writing DENY decision.
	if decisionSec >= chalExpiresAt {
		return nil, false, protocol.NewError(protocol.ErrCodeChallengeExpired, fmt.Sprintf("challenge expired at %d (decisionAt=%d)", chalExpiresAt, decisionSec))
	}
	if ctxObservedAt > decisionSec || decisionSec >= ctxDeadline {
		return nil, false, protocol.NewError(protocol.ErrCodeContextStale, fmt.Sprintf("trusted context stale/expired at %d (decisionAt=%d)", ctxDeadline, decisionSec))
	}

	// Business/object deadline rejection on verified holder records DENY decision & consumes challenge.
	decID := "urn:grad:decision:" + newUUID()
	recordDeny := func(code, reason string, failedObj *string) (*txExecOutcome, error) {
		if _, err := tx.Exec(ctx, `UPDATE challenges SET consumed_at=$1, decision_id=$2
			WHERE deployment_id=$3 AND challenge_id=$4`,
			decisionSec, decID, s.cfg.DeploymentID, pre.pkg.ChallengeID,
		); err != nil {
			return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "consume challenge on deny", err)
		}
		if insertedPlaceholder {
			if _, err := tx.Exec(ctx, `DELETE FROM business_keys
				WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND action=$4 AND idempotency_key=$5`,
				s.cfg.DeploymentID, pre.pkg.Request.Actor, pre.pkg.Request.TaskID, pre.pkg.Request.Action, pre.pkg.Request.IdempotencyKey,
			); err != nil {
				return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "cleanup placeholder business key on deny", err)
			}
		}
		if err := insertDecisionRow(ctx, tx, DecisionRecord{
			StateSource:           pre.view.StateSource,
			Revision:              centralRevision(pre.view),
			StateReadAt:           centralReadAt(pre.view),
			StateRechecks:         attempt,
			DeploymentID:          s.cfg.DeploymentID,
			DecisionID:            decID,
			RequestID:             reqID,
			ChallengeID:           pre.pkg.ChallengeID,
			Actor:                 pre.pkg.Request.Actor,
			TaskID:                pre.pkg.Request.TaskID,
			Action:                pre.pkg.Request.Action,
			IdempotencyKey:        pre.pkg.Request.IdempotencyKey,
			Outcome:               "DENY",
			Code:                  code,
			Reason:                reason,
			BlockNumber:           pre.view.BlockNumber,
			BlockHash:             pre.view.BlockHash,
			RevocationEpoch:       pre.view.RevocationEpoch,
			ProbeTxID:             probe.TxID,
			ProbeBlock:            int64(probe.ProbeBlock),
			ProbeSentAt:           probe.SentAt.Unix(),
			ProbeDeadline:         probe.Deadline.Unix(),
			ProbeSentMonoNs:       probe.SentMonoNs,
			ProbeDeadlineMonoNs:   probe.DeadlineMonoNs,
			ProbeCheckedMonoNs:    checkedProbe(pre.view, probe),
			DecisionAt:            decisionSec,
			RootDID:               pre.rootDID,
			RootKeyVersion:        pre.rootKeyVersion,
			DomainID:              pre.domainID,
			CertificationID:       pre.certID,
			CertificationDigest:   pre.certDigest,
			DomainRevision:        pre.domainRevision,
			IdentityIssuer:        pre.identityIssuer,
			PolicyDigest:          s.cfg.Policy.PolicyDigest,
			ContextVersion:        ctxVersion,
			ContextRiskLevel:      ctxRiskLevel,
			ContextObservedAt:     ctxObservedAt,
			ContextAccessDeadline: ctxDeadline,
			EffectiveDeadline:     effectiveDeadline,
			GrantPath:             pre.grantPath,
			FailedObjectID:        failedObj,
		}); err != nil {
			return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "insert deny decision", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "commit deny decision", err)
		}
		return &txExecOutcome{decisionID: decID}, protocol.NewError(code, reason)
	}

	task := pre.view.Snapshot.Tasks[pre.pkg.Request.TaskID]
	if decisionSec >= task.Interval.EXP {
		taskIDCopy := task.ID
		out, err := recordDeny(protocol.ErrCodeTaskInactive, fmt.Sprintf("task %q reached deadline %d (decisionAt=%d)", task.ID, task.Interval.EXP, decisionSec), &taskIDCopy)
		return out, false, err
	}
	for _, g := range pre.verified.Grants {
		if decisionSec >= g.Claims.EXP {
			gid := g.Claims.ID
			out, err := recordDeny(protocol.ErrCodeGrantExpired, fmt.Sprintf("grant %q expired at %d (decisionAt=%d)", gid, g.Claims.EXP, decisionSec), &gid)
			return out, false, err
		}
	}
	if decisionSec >= pre.verified.LeafCredential.Claims.EXP {
		cid := pre.verified.LeafCredential.Claims.ID
		out, err := recordDeny(protocol.ErrCodeCredentialStatusInvalid, fmt.Sprintf("leaf credential %q expired at %d (decisionAt=%d)", cid, pre.verified.LeafCredential.Claims.EXP, decisionSec), &cid)
		return out, false, err
	}
	for cid, anc := range pre.verified.AncestorCreds {
		if decisionSec >= anc.Claims.EXP {
			idCopy := cid
			out, err := recordDeny(protocol.ErrCodeCredentialStatusInvalid, fmt.Sprintf("ancestor credential %q expired at %d (decisionAt=%d)", cid, anc.Claims.EXP, decisionSec), &idCopy)
			return out, false, err
		}
	}
	for _, cert := range pre.verified.TrustPathCerts {
		if decisionSec >= cert.EXP {
			idCopy := cert.ID
			out, err := recordDeny(protocol.ErrCodeDomainCertificationInvalid, fmt.Sprintf("domain certification %q expired at %d (decisionAt=%d)", cert.ID, cert.EXP, decisionSec), &idCopy)
			return out, false, err
		}
	}

	if isFreshOrder {
		req := pre.pkg.Request
		var failedQ string
		if req.QuoteID != nil {
			failedQ = *req.QuoteID
		}
		if !quoteFound || lockedQuote.TaskID != req.TaskID || lockedQuote.Actor != req.Actor ||
			lockedQuote.SupplierID != req.SupplierID || lockedQuote.ProductID != req.ProductID ||
			lockedQuote.Quantity != req.Quantity || lockedQuote.Currency != req.Currency {
			out, err := recordDeny(protocol.ErrCodeQuoteScopeMismatch, fmt.Sprintf("quote %q missing or scope mismatches actor/task/product/quantity/currency", failedQ), &failedQ)
			return out, false, err
		}
		if decisionSec >= lockedQuote.ValidUntil {
			out, err := recordDeny(protocol.ErrCodeQuoteExpired, fmt.Sprintf("quote %q expired at %d (decisionAt=%d)", lockedQuote.QuoteID, lockedQuote.ValidUntil, decisionSec), &lockedQuote.QuoteID)
			return out, false, err
		}
		if req.AmountMinor != lockedQuote.TotalAmountMinor {
			out, err := recordDeny(protocol.ErrCodeAmountMismatch, fmt.Sprintf("request amountMinor %d != quote %q totalAmountMinor %d", req.AmountMinor, lockedQuote.QuoteID, lockedQuote.TotalAmountMinor), &lockedQuote.QuoteID)
			return out, false, err
		}
		if req.AmountMinor > pre.verified.MinMaxAmountMinor {
			leafID := pre.verified.Grants[len(pre.verified.Grants)-1].Claims.ID
			out, err := recordDeny(protocol.ErrCodeAmountLimitExceeded, fmt.Sprintf("order amountMinor %d exceeds grant path maxAmountMinor %d", req.AmountMinor, pre.verified.MinMaxAmountMinor), &leafID)
			return out, false, err
		}
	}

	// Step 7: Final OPA deterministic policy evaluation using locked context + actual time.
	serviceCred := pre.verified.LeafCredential
	if rootIssuerCredID := pre.verified.Grants[0].Claims.IssuerCredentialID; rootIssuerCredID != serviceCred.Claims.ID {
		if c := pre.verified.AncestorCreds[rootIssuerCredID]; c != nil {
			serviceCred = c
		}
	}
	authorityRole := serviceCred.Role
	serviceRole := serviceCred.Role
	if pre.pkg.Request.AuthorizationMode == protocol.ModeBuyerMandate {
		serviceRole = "supplier-service"
	}
	var disclosedAttrs map[string]string
	for k, v := range pre.verified.LeafCredential.Disclosed {
		if k == "domain" || k == "role" {
			continue
		}
		if disclosedAttrs == nil {
			disclosedAttrs = make(map[string]string)
		}
		disclosedAttrs[k] = v
	}
	facts := policy.SupplierFacts{
		AuthorizationMode:   pre.pkg.Request.AuthorizationMode,
		BuyerDomain:         pre.pkg.Request.PrincipalDomain,
		AuthorityRole:       authorityRole,
		ServiceDID:          s.cfg.ServiceDID,
		ServiceRole:         serviceRole,
		ProductID:           pre.pkg.Request.ProductID,
		Quantity:            pre.pkg.Request.Quantity,
		Action:              pre.pkg.Request.Action,
		AmountMinor:         pre.pkg.Request.AmountMinor,
		MaxPathAmountMinor:  pre.verified.MinMaxAmountMinor,
		NowUnix:             decisionSec,
		VerifiedCrypto:      true,
		TaskActive:          true,
		PathActive:          true,
		ContextFresh:        decisionSec < ctxDeadline,
		ContextRiskLevel:    ctxRiskLevel,
		WithinTimeAndBounds: decisionSec < effectiveDeadline,
		Attributes:          disclosedAttrs,
	}
	policyDec, policyErr := s.cfg.Policy.EvaluateFacts(ctx, facts)
	if !policyDec.Allow || policyErr != nil {
		denyCode := policyDec.Code
		if denyCode == "" || denyCode == "OK" {
			denyCode = protocol.ErrCodePolicyDenied
		}
		out, err := recordDeny(denyCode, policyDec.Reason, nil)
		return out, false, err
	}

	// Step 8: Atomic ALLOW commit (either create new quote/order or reuse existing on same-key retry).
	var (
		quoteDTO          *QuoteDTO
		orderDTO          *OrderDTO
		quoteIDPtr        *string
		orderIDPtr        *string
		createdResourceID string
	)
	switch pre.pkg.Request.Action {
	case "quote.read":
		var quote QuoteDTO
		if existingStatus == "COMPLETED" && existingResourceID != nil && *existingResourceID != "" {
			err := tx.QueryRow(ctx, `SELECT
				quote_id, task_id, actor, supplier_id, product_id, quantity, currency,
				unit_price_minor, total_amount_minor, issued_at, valid_until
				FROM quotes WHERE deployment_id=$1 AND quote_id=$2`,
				s.cfg.DeploymentID, *existingResourceID,
			).Scan(
				&quote.QuoteID, &quote.TaskID, &quote.Actor, &quote.SupplierID, &quote.ProductID,
				&quote.Quantity, &quote.Currency, &quote.UnitPriceMinor, &quote.TotalAmountMinor,
				&quote.IssuedAt, &quote.ValidUntil,
			)
			if err != nil {
				return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "load idempotent existing quote", err)
			}
		} else {
			qty := pre.pkg.Request.Quantity
			if unitPriceMinor > 0 && qty > math.MaxInt64/unitPriceMinor {
				return nil, false, protocol.NewError(protocol.ErrCodeInvalidSchema, "quote total amount overflow")
			}
			totalAmount := unitPriceMinor * qty
			validUntil := decisionSec + 300
			if task.Interval.EXP < validUntil {
				validUntil = task.Interval.EXP
			}
			quote = QuoteDTO{
				QuoteID:          "urn:grad:quote:" + newUUID(),
				TaskID:           pre.pkg.Request.TaskID,
				Actor:            pre.pkg.Request.Actor,
				SupplierID:       pre.pkg.Request.SupplierID,
				ProductID:        pre.pkg.Request.ProductID,
				Quantity:         qty,
				Currency:         catCurrency,
				UnitPriceMinor:   unitPriceMinor,
				TotalAmountMinor: totalAmount,
				IssuedAt:         decisionSec,
				ValidUntil:       validUntil,
			}
			if _, err := tx.Exec(ctx, `INSERT INTO quotes(
				deployment_id, quote_id, task_id, actor, supplier_id, product_id,
				quantity, currency, unit_price_minor, total_amount_minor, issued_at, valid_until, decision_id
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
				s.cfg.DeploymentID, quote.QuoteID, quote.TaskID, quote.Actor, quote.SupplierID, quote.ProductID,
				quote.Quantity, quote.Currency, quote.UnitPriceMinor, quote.TotalAmountMinor, quote.IssuedAt, quote.ValidUntil, decID,
			); err != nil {
				return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "insert quote", err)
			}
		}
		quoteDTO = &quote
		createdResourceID = quote.QuoteID
		quoteIDCopy := quote.QuoteID
		quoteIDPtr = &quoteIDCopy
	case "order.create":
		var order OrderDTO
		if existingStatus == "COMPLETED" && existingResourceID != nil && *existingResourceID != "" {
			err := tx.QueryRow(ctx, `SELECT
				order_id, quote_id, task_id, actor, supplier_id, product_id, quantity, currency,
				total_amount_minor, idempotency_key, status, created_at
				FROM orders WHERE deployment_id=$1 AND order_id=$2`,
				s.cfg.DeploymentID, *existingResourceID,
			).Scan(
				&order.OrderID, &order.QuoteID, &order.TaskID, &order.Actor, &order.SupplierID, &order.ProductID,
				&order.Quantity, &order.Currency, &order.TotalAmountMinor, &order.IdempotencyKey,
				&order.Status, &order.CreatedAt,
			)
			if err != nil {
				return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "load idempotent existing order", err)
			}
		} else {
			order = OrderDTO{
				OrderID:          "urn:grad:order:" + newUUID(),
				QuoteID:          lockedQuote.QuoteID,
				TaskID:           pre.pkg.Request.TaskID,
				Actor:            pre.pkg.Request.Actor,
				SupplierID:       pre.pkg.Request.SupplierID,
				ProductID:        pre.pkg.Request.ProductID,
				Quantity:         pre.pkg.Request.Quantity,
				Currency:         lockedQuote.Currency,
				TotalAmountMinor: lockedQuote.TotalAmountMinor,
				IdempotencyKey:   pre.pkg.Request.IdempotencyKey,
				Status:           "CREATED",
				CreatedAt:        decisionSec,
			}
			if _, err := tx.Exec(ctx, `INSERT INTO orders(
				deployment_id, order_id, quote_id, task_id, actor, supplier_id, product_id,
				quantity, currency, total_amount_minor, idempotency_key, status, created_at, decision_id
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
				s.cfg.DeploymentID, order.OrderID, order.QuoteID, order.TaskID, order.Actor, order.SupplierID, order.ProductID,
				order.Quantity, order.Currency, order.TotalAmountMinor, order.IdempotencyKey, order.Status, order.CreatedAt, decID,
			); err != nil {
				return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "insert order", err)
			}
		}
		orderDTO = &order
		createdResourceID = order.OrderID
		orderIDCopy := order.OrderID
		orderIDPtr = &orderIDCopy
		qIDCopy := order.QuoteID
		quoteIDPtr = &qIDCopy
	}

	if _, err := tx.Exec(ctx, `UPDATE challenges SET consumed_at=$1, decision_id=$2
		WHERE deployment_id=$3 AND challenge_id=$4`,
		decisionSec, decID, s.cfg.DeploymentID, pre.pkg.ChallengeID,
	); err != nil {
		return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "consume challenge on allow", err)
	}

	if err := insertDecisionRow(ctx, tx, DecisionRecord{
		StateSource:           pre.view.StateSource,
		Revision:              centralRevision(pre.view),
		StateReadAt:           centralReadAt(pre.view),
		StateRechecks:         attempt,
		DeploymentID:          s.cfg.DeploymentID,
		DecisionID:            decID,
		RequestID:             reqID,
		ChallengeID:           pre.pkg.ChallengeID,
		Actor:                 pre.pkg.Request.Actor,
		TaskID:                pre.pkg.Request.TaskID,
		Action:                pre.pkg.Request.Action,
		IdempotencyKey:        pre.pkg.Request.IdempotencyKey,
		Outcome:               "ALLOW",
		Code:                  "ALLOW",
		QuoteID:               quoteIDPtr,
		OrderID:               orderIDPtr,
		BlockNumber:           pre.view.BlockNumber,
		BlockHash:             pre.view.BlockHash,
		RevocationEpoch:       pre.view.RevocationEpoch,
		ProbeTxID:             probe.TxID,
		ProbeBlock:            int64(probe.ProbeBlock),
		ProbeSentAt:           probe.SentAt.Unix(),
		ProbeDeadline:         probe.Deadline.Unix(),
		ProbeSentMonoNs:       probe.SentMonoNs,
		ProbeDeadlineMonoNs:   probe.DeadlineMonoNs,
		ProbeCheckedMonoNs:    checkedProbe(pre.view, probe),
		DecisionAt:            decisionSec,
		RootDID:               pre.rootDID,
		RootKeyVersion:        pre.rootKeyVersion,
		DomainID:              pre.domainID,
		CertificationID:       pre.certID,
		CertificationDigest:   pre.certDigest,
		DomainRevision:        pre.domainRevision,
		IdentityIssuer:        pre.identityIssuer,
		PolicyDigest:          s.cfg.Policy.PolicyDigest,
		ContextVersion:        ctxVersion,
		ContextRiskLevel:      ctxRiskLevel,
		ContextObservedAt:     ctxObservedAt,
		ContextAccessDeadline: ctxDeadline,
		EffectiveDeadline:     effectiveDeadline,
		GrantPath:             pre.grantPath,
	}); err != nil {
		return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "insert allow decision", err)
	}

	// Archive the original verified inputs atomically with the first decision and order.
	evidenceJSON, err := json.Marshal(pre.pkg)
	if err != nil {
		return nil, false, err
	}
	docsJSON, err := json.Marshal(pre.verified.DIDDocuments)
	if err != nil {
		return nil, false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO decision_evidence(deployment_id,decision_id,package_json,did_documents,checked_mono_ns) VALUES($1,$2,$3,$4,$5)`, s.cfg.DeploymentID, decID, evidenceJSON, docsJSON, checkedProbe(pre.view, probe)); err != nil {
		return nil, false, err
	}

	if _, err := tx.Exec(ctx, `UPDATE business_keys SET status='COMPLETED', resource_id=$1, decision_id=$2, updated_at=NOW()
		WHERE deployment_id=$3 AND actor=$4 AND task_id=$5 AND action=$6 AND idempotency_key=$7`,
		createdResourceID, decID, s.cfg.DeploymentID, pre.pkg.Request.Actor, pre.pkg.Request.TaskID, pre.pkg.Request.Action, pre.pkg.Request.IdempotencyKey,
	); err != nil {
		return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "finalize business key", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "commit allow execute transaction", err)
	}

	return &txExecOutcome{
		decisionID: decID,
		resp: ExecuteResponse{
			DecisionID: decID,
			Code:       "ALLOW",
			Quote:      quoteDTO,
			Order:      orderDTO,
		},
	}, false, nil
}

func insertDecisionRow(ctx context.Context, tx pgx.Tx, d DecisionRecord) error {
	var reasonPtr, domPtr, certPtr, certDigPtr, idIssPtr *string
	if d.Reason != "" {
		reasonPtr = &d.Reason
	}
	if d.DomainID != "" {
		domPtr = &d.DomainID
	}
	if d.CertificationID != "" {
		certPtr = &d.CertificationID
	}
	if d.CertificationDigest != "" {
		certDigPtr = &d.CertificationDigest
	}
	if d.IdentityIssuer != "" {
		idIssPtr = &d.IdentityIssuer
	}
	_, err := tx.Exec(ctx, `INSERT INTO decisions(
		deployment_id, decision_id, request_id, challenge_id, actor, task_id, action, idempotency_key,
		outcome, code, reason, quote_id, order_id, block_number, block_hash, revocation_epoch,
		probe_tx_id, probe_block, probe_sent_at, probe_deadline, probe_sent_mono_ns, probe_deadline_mono_ns, decision_at,
		root_did, root_key_version, domain_id, certification_id, certification_digest, domain_revision,
		identity_issuer, policy_digest, context_version, context_risk_level, context_observed_at,
		context_access_deadline, effective_deadline, grant_path, failed_object_id, state_source, revision, state_read_at, state_rechecks, probe_checked_mono_ns
	) VALUES(
		$1,$2,$3,$4,$5,$6,$7,$8,
		$9,$10,$11,$12,$13,$14,$15,$16,
		$17,$18,$19,$20,$21,$22,$23,
		$24,$25,$26,$27,$28,$29,
		$30,$31,$32,$33,$34,
		$35,$36,$37,$38,$39,$40,$41,$42,$43
	)`,
		d.DeploymentID, d.DecisionID, d.RequestID, d.ChallengeID, d.Actor, d.TaskID, d.Action, d.IdempotencyKey,
		d.Outcome, d.Code, reasonPtr, d.QuoteID, d.OrderID, fabricColumn(d, d.BlockNumber), fabricColumn(d, d.BlockHash), fabricColumn(d, d.RevocationEpoch),
		fabricColumn(d, d.ProbeTxID), fabricColumn(d, d.ProbeBlock), fabricColumn(d, d.ProbeSentAt), fabricColumn(d, d.ProbeDeadline), fabricColumn(d, d.ProbeSentMonoNs), fabricColumn(d, d.ProbeDeadlineMonoNs), d.DecisionAt,
		d.RootDID, d.RootKeyVersion, domPtr, certPtr, certDigPtr, d.DomainRevision,
		idIssPtr, d.PolicyDigest, d.ContextVersion, d.ContextRiskLevel, d.ContextObservedAt,
		d.ContextAccessDeadline, d.EffectiveDeadline, d.GrantPath, d.FailedObjectID,
		d.StateSource, d.Revision, d.StateReadAt, d.StateRechecks, d.ProbeCheckedMonoNs,
	)
	return err
}

func writeMappedError(w http.ResponseWriter, r *http.Request, decisionID *string, err error) {
	code := protocol.ErrCodeInvalidSchema
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.Code != "" {
		code = pe.Code
	}
	status := httpStatusForCode(code)
	writeErrorResponse(w, r, status, code, decisionID, err.Error())
}

func httpStatusForCode(code string) int {
	switch code {
	case protocol.ErrCodePayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	case protocol.ErrCodeUnsupportedMediaType:
		return http.StatusUnsupportedMediaType
	case protocol.ErrCodeInvalidSchema, protocol.ErrCodeInvalidDisclosure, protocol.ErrCodeRecoveryProofInvalid:
		return http.StatusBadRequest
	case protocol.ErrCodeSignatureInvalid,
		protocol.ErrCodeHolderMismatch,
		protocol.ErrCodeDIDDocumentMismatch,
		protocol.ErrCodeDIDKeyPurposeInvalid,
		protocol.ErrCodeBindingMismatch,
		protocol.ErrCodeChallengeMismatch,
		protocol.ErrCodeChallengeUnknown,
		protocol.ErrCodeChallengeExpired:
		return http.StatusUnauthorized
	case protocol.ErrCodeChallengeReplay,
		protocol.ErrCodeIdempotencyConflict,
		protocol.ErrCodeStateChanged,
		protocol.ErrCodeDeliveryConflict,
		protocol.ErrCodeQuoteExpired,
		protocol.ErrCodeAmountMismatch,
		protocol.ErrCodeLinkStateConflict,
		protocol.ErrCodeIdentityStateConflict,
		protocol.ErrCodeTaskStateConflict,
		protocol.ErrCodeGrantStateConflict:
		return http.StatusConflict
	case protocol.ErrCodePolicyDenied,
		protocol.ErrCodeSupplierPolicyDenied,
		protocol.ErrCodeRootAuthorityInvalid,
		protocol.ErrCodePurchasingAuthorityInvalid,
		protocol.ErrCodeDelegationExpansion,
		protocol.ErrCodePathInvalid,
		protocol.ErrCodeAuthorizationModeMismatch,
		protocol.ErrCodeAncestorInactive,
		protocol.ErrCodeAmountLimitExceeded,
		protocol.ErrCodeQuoteScopeMismatch,
		protocol.ErrCodeTaskScopeMismatch,
		protocol.ErrCodeTaskInactive,
		protocol.ErrCodeGrantExpired,
		protocol.ErrCodeGrantInactive,
		protocol.ErrCodeGrantChainInvalid,
		protocol.ErrCodeCredentialStatusInvalid,
		protocol.ErrCodeDomainCertificationInvalid,
		protocol.ErrCodeDomainInactive,
		protocol.ErrCodeKeyVersionStale,
		protocol.ErrCodeIdentityInactive,
		protocol.ErrCodeIdentityManagementForbidden,
		protocol.ErrCodeIdentityRecoveryForbidden,
		protocol.ErrCodeTrustManagementForbidden,
		protocol.ErrCodeAuditForbidden,
		protocol.ErrCodeIssuerScopeInvalid,
		protocol.ErrCodeLinkApprovalForbidden,
		protocol.ErrCodeLinkProposalMismatch,
		protocol.ErrCodeLinkProofInvalid:
		return http.StatusForbidden
	case protocol.ErrCodeStateUnavailable,
		protocol.ErrCodeStateStale,
		protocol.ErrCodeMaterialNotSynced,
		protocol.ErrCodeContextStale,
		protocol.ErrCodePriceUnavailable:
		return http.StatusServiceUnavailable
	default:
		if strings.Contains(code, "INVALID") {
			return http.StatusBadRequest
		}
		return http.StatusInternalServerError
	}
}

func centralRevision(view *ConsistentSnapshot) *int64 {
	if view.StateSource != StateCentralized {
		return nil
	}
	v := view.Revision
	return &v
}
func centralReadAt(view *ConsistentSnapshot) *time.Time {
	if view.StateSource != StateCentralized {
		return nil
	}
	v := view.StateReadAt
	return &v
}
func fabricColumn(d DecisionRecord, value any) any {
	if d.StateSource == StateCentralized {
		return nil
	}
	return value
}

func checkedProbe(view *ConsistentSnapshot, p ProbeInfo) *int64 {
	if view.StateSource != StateFabric {
		return nil
	}
	v := p.CheckedMonoNs
	return &v
}
