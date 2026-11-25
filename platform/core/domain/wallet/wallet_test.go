package wallet_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/core/domain/wallet"
	"grad/platform/internal/httpx"
	"grad/protocol"
)

const (
	testHeaderRole = "X-Test-Caller-Role"
	testHeaderDID  = "X-Test-Caller-DID"
)

type localRoleTransport struct {
	handler http.Handler
	role    string
	did     string
}

func (l *localRoleTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set(testHeaderRole, l.role)
	clone.Header.Set(testHeaderDID, l.did)
	rec := httptest.NewRecorder()
	l.handler.ServeHTTP(rec, clone)
	return rec.Result(), nil
}

func newLocalRoleClient(handler http.Handler, role, did string) *http.Client {
	return &http.Client{
		Transport: &localRoleTransport{handler: handler, role: role, did: did},
	}
}

type stubGateway struct {
	mu               sync.Mutex
	depID            string
	audience         string
	supplierID       string
	unitPriceMinor   int64
	maxOrderAmount   int64
	now              func() time.Time
	seq              atomic.Int64
	challenges       map[string]wallet.ChallengeResponse
	quotes           map[string]wallet.QuotePayload
	ordersByKey      map[string]wallet.OrderPayload
	decisionsByKey   map[string]string
	cases            map[string]wallet.OrderOutcomeCaseRequest
	auditCheckNo     map[string]int64
	auditOutcomeHook func(caseReq wallet.OrderOutcomeCaseRequest, checkNo int64) (outcome, histStatus string, orderID, decisionID *string)
	onChallenge      func(req wallet.ChallengeRequest)
	failExecuteOnce  map[string]bool
	revokedGrants    map[string]bool
	verifiedRequests []protocol.AccessRequest
}

func newStubGateway(depID, audience, supplierID string, now func() time.Time) *stubGateway {
	return &stubGateway{
		depID:           depID,
		audience:        audience,
		supplierID:      supplierID,
		unitPriceMinor:  80000,
		maxOrderAmount:  100000,
		now:             now,
		challenges:      make(map[string]wallet.ChallengeResponse),
		quotes:          make(map[string]wallet.QuotePayload),
		ordersByKey:     make(map[string]wallet.OrderPayload),
		decisionsByKey:  make(map[string]string),
		cases:           make(map[string]wallet.OrderOutcomeCaseRequest),
		auditCheckNo:    make(map[string]int64),
		failExecuteOnce: make(map[string]bool),
		revokedGrants:   make(map[string]bool),
	}
}

func (g *stubGateway) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/challenges", g.handleChallenge)
	mux.HandleFunc("POST /v1/access/execute", g.handleExecute)
	mux.HandleFunc("POST /v1/internal/order-outcome-cases", g.handleRegisterCase)
	mux.HandleFunc("POST /v1/audit/order-outcomes", g.handleAuditOutcome)
	return httpx.WithRequestID(mux)
}

func (g *stubGateway) handleChallenge(w http.ResponseWriter, r *http.Request) {
	reqID := httpx.RequestID(r)
	var req wallet.ChallengeRequest
	if err := httpx.DecodeJSON(r, 64*1024, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	if g.onChallenge != nil {
		g.onChallenge(req)
	}
	n := g.seq.Add(1)
	nowSec := g.now().UTC().Unix()
	nonceSum := sha256.Sum256([]byte(fmt.Sprintf("stub-nonce-%s-%d", g.depID, n)))
	resp := wallet.ChallengeResponse{
		ChallengeID: fmt.Sprintf("urn:grad:chal:%04d", n),
		Nonce:       base64.RawURLEncoding.EncodeToString(nonceSum[:]),
		Audience:    g.audience,
		IssuedAt:    nowSec,
		ExpiresAt:   nowSec + 30,
	}
	g.mu.Lock()
	g.challenges[resp.ChallengeID] = resp
	g.mu.Unlock()
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

func (g *stubGateway) handleExecute(w http.ResponseWriter, r *http.Request) {
	reqID := httpx.RequestID(r)
	raw, err := httpx.ReadBoundedBody(r, 256*1024)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	pkg, err := protocol.ParseAccessEvidencePackage(raw)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.CodeOf(err), nil, err.Error())
		return
	}
	bindings, err := pkg.ComputeBindings(false)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.CodeOf(err), nil, err.Error())
		return
	}

	g.mu.Lock()
	chal, ok := g.challenges[pkg.ChallengeID]
	if ok {
		delete(g.challenges, pkg.ChallengeID)
	}
	g.mu.Unlock()
	if !ok {
		httpx.WriteError(w, http.StatusConflict, reqID, protocol.ErrCodeChallengeUnknown, nil, "unknown or replayed challenge")
		return
	}

	// Verify KB-JWT bindings verbatim against issued challenge nonce and computed hashes.
	lastTilde := strings.LastIndexByte(pkg.LeafPresentation, '~')
	kbRaw := pkg.LeafPresentation[lastTilde+1:]
	parsedKB, err := protocol.ParseCompactJWS(kbRaw, protocol.TypeKBJWT)
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	var kbClaims protocol.KBJWTClaims
	if err := protocol.DecodeStrictJSON(parsedKB.PayloadBytes, &kbClaims); err != nil {
		httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	if kbClaims.Nonce != chal.Nonce || kbClaims.Aud != chal.Audience ||
		kbClaims.SDHash != bindings.SDHash ||
		kbClaims.GradBinding.ChallengeID != chal.ChallengeID ||
		kbClaims.GradBinding.RequestHash != bindings.RequestHash ||
		kbClaims.GradBinding.ChainHash != bindings.ChainHash ||
		kbClaims.GradBinding.EvidenceHash != bindings.EvidenceHash {
		httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeBindingMismatch, nil, "KB-JWT bindings mismatch")
		return
	}

	// Check leaf grant revocation or ceiling.
	leafParsed, err := protocol.ParseCompactJWS(pkg.Grants[len(pkg.Grants)-1], protocol.TypeGrantJWS)
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeGrantChainInvalid, nil, err.Error())
		return
	}
	var leafClaims protocol.GrantClaims
	if err := protocol.DecodeStrictJSON(leafParsed.PayloadBytes, &leafClaims); err != nil {
		httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeGrantChainInvalid, nil, err.Error())
		return
	}

	decID := fmt.Sprintf("urn:grad:decision:%04d", g.seq.Add(1))

	g.mu.Lock()
	g.verifiedRequests = append(g.verifiedRequests, pkg.Request)
	isRevoked := g.revokedGrants[leafClaims.ID]
	unitPrice := g.unitPriceMinor
	shouldFail500 := g.failExecuteOnce[pkg.Request.IdempotencyKey]
	if shouldFail500 {
		delete(g.failExecuteOnce, pkg.Request.IdempotencyKey)
	}
	g.mu.Unlock()

	if isRevoked {
		httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeGrantInactive, &decID, "leaf grant revoked")
		return
	}

	nowSec := g.now().UTC().Unix()
	switch pkg.Request.Action {
	case protocol.ActionQuoteRead:
		if pkg.Request.Resource != protocol.ResourceQuotes {
			httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, &decID, "non-canonical quote resource")
			return
		}
		q := wallet.QuotePayload{
			QuoteID:          fmt.Sprintf("urn:grad:quote:%04d", g.seq.Add(1)),
			TaskID:           pkg.Request.TaskID,
			Actor:            pkg.Request.Actor,
			SupplierID:       g.supplierID,
			ProductID:        pkg.Request.ProductID,
			Quantity:         pkg.Request.Quantity,
			Currency:         pkg.Request.Currency,
			UnitPriceMinor:   unitPrice,
			TotalAmountMinor: unitPrice * pkg.Request.Quantity,
			IssuedAt:         nowSec,
			ValidUntil:       nowSec + 600,
		}
		g.mu.Lock()
		g.quotes[q.QuoteID] = q
		g.mu.Unlock()
		httpx.WriteJSON(w, http.StatusOK, wallet.ExecuteResponse{
			DecisionID: decID,
			Code:       "ALLOW",
			Quote:      &q,
		})

	case protocol.ActionOrderCreate:
		if pkg.Request.Resource != protocol.ResourceOrders {
			httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, &decID, "non-canonical order resource")
			return
		}
		if pkg.Request.QuoteID == nil {
			httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, &decID, "quoteId required")
			return
		}
		g.mu.Lock()
		q, hasQuote := g.quotes[*pkg.Request.QuoteID]
		g.mu.Unlock()
		if !hasQuote || q.Actor != pkg.Request.Actor || q.TaskID != pkg.Request.TaskID {
			httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeQuoteScopeMismatch, &decID, "quote belongs to a different actor or task")
			return
		}
		if pkg.Request.AmountMinor > leafClaims.MaxAmountMinor {
			httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeAmountLimitExceeded, &decID, "amountMinor exceeds grant maxAmountMinor")
			return
		}
		ord := wallet.OrderPayload{
			OrderID:          fmt.Sprintf("urn:grad:order:%04d", g.seq.Add(1)),
			QuoteID:          *pkg.Request.QuoteID,
			TaskID:           pkg.Request.TaskID,
			Actor:            pkg.Request.Actor,
			SupplierID:       g.supplierID,
			ProductID:        pkg.Request.ProductID,
			Quantity:         pkg.Request.Quantity,
			Currency:         pkg.Request.Currency,
			TotalAmountMinor: pkg.Request.AmountMinor,
			IdempotencyKey:   pkg.Request.IdempotencyKey,
			Status:           "CONFIRMED",
			CreatedAt:        nowSec,
		}
		g.mu.Lock()
		g.ordersByKey[pkg.Request.IdempotencyKey] = ord
		g.decisionsByKey[pkg.Request.IdempotencyKey] = decID
		g.mu.Unlock()
		if shouldFail500 {
			// Simulate server committing order then failing before response reaches client.
			httpx.WriteError(w, http.StatusInternalServerError, reqID, "INTERNAL_ERROR", nil, "simulated post-commit gateway error")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, wallet.ExecuteResponse{
			DecisionID: decID,
			Code:       "ALLOW",
			Order:      &ord,
		})
	default:
		httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, &decID, "unsupported action")
	}
}

func (g *stubGateway) handleRegisterCase(w http.ResponseWriter, r *http.Request) {
	reqID := httpx.RequestID(r)
	if r.Header.Get(testHeaderRole) != "B_RECOVERY" {
		httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeAuditForbidden, nil, "B_RECOVERY identity required")
		return
	}
	var req wallet.OrderOutcomeCaseRequest
	if err := httpx.DecodeJSON(r, 256*1024, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	g.mu.Lock()
	g.cases[req.CaseID] = req
	g.mu.Unlock()
	httpx.WriteJSON(w, http.StatusAccepted, wallet.OrderOutcomeCaseResponse{
		CaseID:         req.CaseID,
		SendRevision:   req.SendRevision,
		DeploymentID:   req.DeploymentID,
		Actor:          req.Request.Actor,
		TaskID:         req.Request.TaskID,
		IdempotencyKey: req.Request.IdempotencyKey,
		RequestHash:    req.RequestHash,
		ChallengeIDs:   slices.Clone(req.ChallengeIDs),
		Status:         "REGISTERED",
	})
}

func (g *stubGateway) handleAuditOutcome(w http.ResponseWriter, r *http.Request) {
	reqID := httpx.RequestID(r)
	role := r.Header.Get(testHeaderRole)
	did := r.Header.Get(testHeaderDID)
	if role != "C_AUDITOR" && role != "C-AUDITOR" {
		httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeAuditForbidden, nil, "C_AUDITOR identity required")
		return
	}
	var req wallet.AuditOrderOutcomeRequest
	if err := httpx.DecodeJSON(r, 256*1024, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	g.mu.Lock()
	caseReq, ok := g.cases[req.CaseID]
	g.auditCheckNo[req.CaseID]++
	checkNo := g.auditCheckNo[req.CaseID]
	ord, hasOrd := g.ordersByKey[caseReq.Request.IdempotencyKey]
	decID := g.decisionsByKey[caseReq.Request.IdempotencyKey]
	hook := g.auditOutcomeHook
	g.mu.Unlock()
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, reqID, protocol.ErrCodeInvalidSchema, nil, "case not found")
		return
	}

	outcome := "NOT_CREATED"
	histStatus := "NO_DECISION"
	var orderPtr, decPtr *string
	if hasOrd {
		outcome = "CREATED"
		histStatus = "MATCHED"
		oid := ord.OrderID
		didVal := decID
		orderPtr = &oid
		decPtr = &didVal
	}
	if hook != nil {
		outcome, histStatus, orderPtr, decPtr = hook(caseReq, checkNo)
	}
	nowSec := g.now().UTC().Unix()
	receipt := wallet.OrderOutcomeReceipt{
		CaseID:             caseReq.CaseID,
		CheckNo:            checkNo,
		SendRevision:       caseReq.SendRevision,
		DeploymentID:       g.depID,
		Actor:              caseReq.Request.Actor,
		TaskID:             caseReq.Request.TaskID,
		RequestHash:        caseReq.RequestHash,
		Outcome:            outcome,
		OrderID:            orderPtr,
		CreationDecisionID: decPtr,
		HistoricalStatus:   histStatus,
		AuditAt:            nowSec,
	}
	httpx.WriteJSON(w, http.StatusOK, wallet.AuditOrderOutcomeResponse{
		CaseID:             caseReq.CaseID,
		CheckNo:            checkNo,
		SendRevision:       caseReq.SendRevision,
		DeploymentID:       g.depID,
		Actor:              caseReq.Request.Actor,
		TaskID:             caseReq.Request.TaskID,
		IdempotencyKey:     caseReq.Request.IdempotencyKey,
		RequestHash:        caseReq.RequestHash,
		Outcome:            outcome,
		OrderID:            orderPtr,
		CreationDecisionID: decPtr,
		HistoricalStatus:   histStatus,
		LockedChallengeIDs: slices.Clone(caseReq.ChallengeIDs),
		VerifierID:         did,
		AuditAt:            nowSec,
		Receipt:            receipt,
	})
}

func newTestReceiptHandler(w *wallet.WalletContext) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/internal/order-outcome-receipts", func(rw http.ResponseWriter, r *http.Request) {
		reqID := httpx.RequestID(r)
		if err := w.AuthorizeReceiptCaller(r.Header.Get(testHeaderRole), r.Header.Get(testHeaderDID)); err != nil {
			httpx.WriteError(rw, http.StatusForbidden, reqID, protocol.ErrCodeAuditForbidden, nil, err.Error())
			return
		}
		var rec wallet.OrderOutcomeReceipt
		if err := httpx.DecodeJSON(r, 256*1024, &rec); err != nil {
			httpx.WriteError(rw, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, nil, err.Error())
			return
		}
		resp, err := w.ApplyOrderOutcomeReceipt(r.Context(), rec)
		if err != nil {
			code := protocol.CodeOf(err)
			status := http.StatusInternalServerError
			switch code {
			case protocol.ErrCodeInvalidSchema:
				status = http.StatusBadRequest
			case protocol.ErrCodeIdempotencyConflict, protocol.ErrCodeBindingMismatch:
				status = http.StatusConflict
			case protocol.ErrCodeStateUnavailable:
				status = http.StatusServiceUnavailable
			}
			httpx.WriteError(rw, status, reqID, code, nil, err.Error())
			return
		}
		httpx.WriteJSON(rw, http.StatusOK, resp)
	})
	return httpx.WithRequestID(mux)
}

type unitFixture struct {
	depID    string
	taskID   string
	audience string
	now      time.Time
	gw       *stubGateway
	wallet   *wallet.WalletContext
	privA1   *ecdsa.PrivateKey
	pubA1    *ecdsa.PublicKey
	didA1    string
	didB1    string
	didB2    string
	g1ID     string
	g1Bundle wallet.GrantBundle
	secrets  []string
	pemKeys  []string
	signers  []wallet.Signer
	baseCfg  wallet.WalletConfig
}

func newUnitFixture(t *testing.T, walletModifier func(*wallet.WalletConfig)) *unitFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	depID := protocol.DigestBytes([]byte("unit-dep-" + t.Name()))
	taskID := protocol.DigestBytes([]byte("unit-task-" + t.Name()))
	resID := protocol.DigestBytes([]byte("unit-res-" + t.Name()))
	audience := "https://c.local"
	supplierID := "urn:grad:supplier:C"

	genKey := func() *ecdsa.PrivateKey {
		pk, kErr := protocol.GenerateP256Key()
		require.NoError(t, kErr)
		return pk
	}

	privT := genKey()
	privIA := genKey()
	privPA := genKey()
	privU := genKey()
	privA1 := genKey()
	privB1 := genKey()
	privB2 := genKey()

	didT := "did:web:t.local"
	didA := "did:web:a.local"
	didIA := "did:web:a.local:ia"
	didPA := "did:web:a.local:pa"
	didU := "did:web:a.local:u"
	didA1 := "did:web:a.local:a1"
	didB1 := "did:web:a.local:b1"
	didB2 := "did:web:a.local:b2"

	nbf := now.Add(-time.Hour).Unix()
	exp := now.Add(2 * time.Hour).Unix()
	vf := time.Unix(nbf, 0).UTC().Format(time.RFC3339)
	vu := time.Unix(exp, 0).UTC().Format(time.RFC3339)

	certID := "urn:grad:domain-certification:A-unit"
	certJWS, _, err := protocol.SignDomainAuthorityCredential(privT, didT+"#key-1", &protocol.DomainAuthorityCredential{
		Type: []string{protocol.CredentialTypeVC, protocol.CredentialTypeDomainAuthority},
		ID:   certID, DeploymentID: depID, Issuer: didT, Iss: didT, Sub: didA,
		IssuerKeyVersion: 1, ValidFrom: vf, ValidUntil: vu, NBF: nbf, EXP: exp,
		CredentialStatus: protocol.CredentialStatus{ID: certID, Type: protocol.StatusTypeDomainCertification},
		CredentialSubject: protocol.DomainAuthoritySubject{
			ID: didA, DomainID: "A",
			IdentityIssuers: []protocol.IssuerScope{{
				ID: didIA, AppKeyVersion: 1,
				CredentialTypes: []string{protocol.CredentialTypeEnterpriseIdentity},
				ClaimNames:      []string{"domain", "role"},
			}},
		},
	})
	require.NoError(t, err)

	issueSD := func(sub, credID, role string, pub *ecdsa.PublicKey) *protocol.SignedSDJWTCredential {
		jwk, jErr := protocol.JWKFromPublicKey(pub)
		require.NoError(t, jErr)
		sd, sErr := protocol.IssueEnterpriseIdentityCredential(privIA, didIA+"#key-1", protocol.EnterpriseIdentityCredential{
			Type: []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity},
			ID:   credID, DeploymentID: depID, Issuer: didIA, Iss: didIA, Sub: sub,
			IssuerKeyVersion: 1, AppKeyVersion: 1, ValidFrom: vf, ValidUntil: vu, NBF: nbf, EXP: exp,
			CredentialStatus:  protocol.CredentialStatus{ID: credID, Type: protocol.StatusTypeCredential},
			Cnf:               protocol.ConfirmationKey{JWK: jwk},
			CredentialSubject: protocol.SDJWTCredentialSubject{ID: sub},
		}, "A", role, nil)
		require.NoError(t, sErr)
		return sd
	}

	sdPA := issueSD(didPA, "urn:grad:cred:PA", "procurement-authority", &privPA.PublicKey)
	sdU := issueSD(didU, "urn:grad:cred:U", "procurement-owner", &privU.PublicKey)
	sdA1 := issueSD(didA1, "urn:grad:cred:A1", "procurement-agent", &privA1.PublicKey)
	sdB1 := issueSD(didB1, "urn:grad:cred:B1", "buyer-delegate", &privB1.PublicKey)
	sdB2 := issueSD(didB2, "urn:grad:cred:B2", "buyer-delegate", &privB2.PublicKey)

	spec := protocol.TaskSpec{
		SupplierID:  supplierID,
		ProductID:   "urn:grad:product:P1",
		MaxQuantity: 10,
		Currency:    "CNY",
		Resources:   []string{protocol.ResourceOrders, protocol.ResourceQuotes},
		Actions:     []string{protocol.ActionOrderCreate, protocol.ActionQuoteRead},
		Description: "Unit test procurement task",
	}

	g0ID := protocol.DigestBytes([]byte("unit-g0-" + t.Name()))
	g1ID := protocol.DigestBytes([]byte("unit-g1-" + t.Name()))

	g0Claims := protocol.GrantClaims{
		ID: g0ID, SchemaVersion: protocol.SchemaVersion, DeploymentID: depID,
		RootID: g0ID, TaskID: taskID, AuthorizationMode: protocol.ModeBuyerMandate,
		PrincipalDomain: "A", ResourceID: resID, Aud: audience,
		Issuer: didPA, IssuerKeyVersion: 1, IssuerCredentialID: "urn:grad:cred:PA",
		Grantee: didU, GranteeKeyVersion: 1, GranteeCredentialID: "urn:grad:cred:U",
		Resources: spec.Resources, Actions: spec.Actions, Suppliers: []string{supplierID},
		Currency: "CNY", MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 2,
	}
	g0JWS, g0Dig, err := protocol.SignGrant(privPA, didPA+"#key-1", &g0Claims)
	require.NoError(t, err)

	g1Claims := protocol.GrantClaims{
		ID: g1ID, SchemaVersion: protocol.SchemaVersion, DeploymentID: depID,
		ParentID: &g0ID, ParentDigest: &g0Dig, RootID: g0ID, TaskID: taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, PrincipalDomain: "A", ResourceID: resID, Aud: audience,
		Issuer: didU, IssuerKeyVersion: 1, IssuerCredentialID: "urn:grad:cred:U",
		Grantee: didA1, GranteeKeyVersion: 1, GranteeCredentialID: "urn:grad:cred:A1",
		Resources: spec.Resources, Actions: spec.Actions, Suppliers: []string{supplierID},
		Currency: "CNY", MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 1,
	}
	g1JWS, g1Dig, err := protocol.SignGrant(privU, didU+"#key-1", &g1Claims)
	require.NoError(t, err)

	gw := newStubGateway(depID, audience, supplierID, func() time.Time { return now })
	gwHandler := gw.handler()

	cfg := wallet.WalletConfig{
		DeploymentID:    depID,
		Audience:        audience,
		SupplierID:      supplierID,
		DefaultTaskSpec: spec,
		Currency:        "CNY",
		HTTPHandler:     gwHandler,
		RecoveryClient:  newLocalRoleClient(gwHandler, "B_RECOVERY", "did:web:a.local:services:recovery"),
		AuditClient:     newLocalRoleClient(gwHandler, "C_AUDITOR", "did:web:c.local:auditors:c1"),
		Now:             func() time.Time { return now },
		AnchorChildFunc: func(_ context.Context, _ wallet.AnchorChildGrantRequest) (*wallet.AnchorChildGrantResult, error) {
			return &wallet.AnchorChildGrantResult{
				Anchored:   true,
				TrustPaths: []protocol.TrustPathEntry{{Issuer: didIA, DomainCertification: certJWS}},
			}, nil
		},
		ReplaceGrantFunc: func(_ context.Context, req wallet.ReplaceGrantRequest) (*wallet.ReplaceGrantResult, error) {
			gw.mu.Lock()
			gw.revokedGrants[req.OldGrantID] = true
			gw.mu.Unlock()
			return &wallet.ReplaceGrantResult{
				Anchored:   true,
				TrustPaths: []protocol.TrustPathEntry{{Issuer: didIA, DomainCertification: certJWS}},
			}, nil
		},
	}
	if walletModifier != nil {
		walletModifier(&cfg)
	}
	var w *wallet.WalletContext
	if cfg.ReceiptClient == nil && cfg.ReceiptDelivery == nil {
		cfg.ReceiptClient = newLocalRoleClient(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			newTestReceiptHandler(w).ServeHTTP(rw, r)
		}), "C_AUDIT_SERVICE", "did:web:c.local:services:audit")
	}
	w, err = wallet.NewWalletContext(cfg)
	require.NoError(t, err)

	signers := []wallet.Signer{
		{
			Actor: "A1", DID: didA1, KeyID: didA1 + "#key-1", CredentialID: "urn:grad:cred:A1", KeyVersion: 1,
			DomainID: "A", EntityType: "AGENT", Roles: []string{"procurement-agent"},
			PrivateKey: privA1, SDJWTPresentation: sdA1.PresentationPrefix,
		},
		{
			Actor: "B1", DID: didB1, KeyID: didB1 + "#key-1", CredentialID: "urn:grad:cred:B1", KeyVersion: 1,
			DomainID: "A", EntityType: "AGENT", Roles: []string{"buyer-delegate"},
			PrivateKey: privB1, SDJWTPresentation: sdB1.PresentationPrefix,
		},
		{
			Actor: "B2", DID: didB2, KeyID: didB2 + "#key-1", CredentialID: "urn:grad:cred:B2", KeyVersion: 1,
			DomainID: "A", EntityType: "AGENT", Roles: []string{"buyer-delegate"},
			PrivateKey: privB2, SDJWTPresentation: sdB2.PresentationPrefix,
		},
	}
	for _, s := range signers {
		require.NoError(t, w.RegisterActor(s))
	}

	g1Bundle := wallet.GrantBundle{
		Claims:         g1Claims,
		TaskSpec:       spec,
		RawGrantJWS:    g1JWS,
		Digest:         g1Dig,
		ChainRawGrants: []string{g0JWS, g1JWS},
		AncestorCredentials: []protocol.AncestorCredential{
			{CredentialID: "urn:grad:cred:PA", Presentation: sdPA.PresentationPrefix},
			{CredentialID: "urn:grad:cred:U", Presentation: sdU.PresentationPrefix},
		},
		TrustPaths: []protocol.TrustPathEntry{{Issuer: didIA, DomainCertification: certJWS}},
		Anchored:   true,
		Revision:   1,
	}
	require.NoError(t, w.AddGrantBundle(g1Bundle))

	secrets := []string{
		sdA1.PresentationPrefix, sdB1.PresentationPrefix, sdB2.PresentationPrefix,
		sdPA.PresentationPrefix, sdU.PresentationPrefix,
		g0JWS, g1JWS, certJWS,
	}
	for _, sd := range []*protocol.SignedSDJWTCredential{sdA1, sdB1, sdB2, sdPA, sdU} {
		secrets = append(secrets, sd.Disclosures...)
	}

	var pemKeys []string
	for _, pk := range []*ecdsa.PrivateKey{privA1, privB1, privB2} {
		der, mErr := x509.MarshalECPrivateKey(pk)
		require.NoError(t, mErr)
		pemKeys = append(pemKeys, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))
	}

	return &unitFixture{
		depID: depID, taskID: taskID, audience: audience, now: now,
		gw: gw, wallet: w, privA1: privA1, pubA1: &privA1.PublicKey,
		didA1: didA1, didB1: didB1, didB2: didB2,
		g1ID: g1ID, g1Bundle: g1Bundle, secrets: secrets, pemKeys: pemKeys,
		signers: signers, baseCfg: cfg,
	}
}

func assertNoSecretLeaks(t *testing.T, label, payload string, secrets []string) {
	t.Helper()
	assert.NotContains(t, payload, "PRIVATE KEY", "%s leaked private key PEM", label)
	for _, s := range secrets {
		if len(s) < 6 {
			continue
		}
		assert.NotContains(t, payload, s, "%s leaked raw secret/disclosure material", label)
	}
}

func TestPrivateKeyAndDisclosureSaltIsolation(t *testing.T) {
	fx := newUnitFixture(t, nil)

	// 1. Direct marshaling of Signer and GrantBundle omits private keys, SD-JWT prefixes, and raw JWS tokens.
	signerRaw, err := json.Marshal(wallet.Signer{
		Actor: "B1", DID: fx.didB1, KeyID: fx.didB1 + "#key-1",
		PrivateKey: fx.privA1, SDJWTPresentation: fx.secrets[0],
	})
	require.NoError(t, err)
	assertNoSecretLeaks(t, "Signer JSON", string(signerRaw), fx.secrets)

	bundleRaw, err := json.Marshal(fx.g1Bundle)
	require.NoError(t, err)
	assertNoSecretLeaks(t, "GrantBundle JSON", string(bundleRaw), fx.secrets)

	// 2. SanitizeString redacts PEM keys, compact JWS, SD-JWT disclosures, and registered secrets.
	fx.wallet.RegisterSecret("sk-super-secret-api-key-12345")
	dirty := fmt.Sprintf("err pem=%s sd=%s key=sk-super-secret-api-key-12345", fx.pemKeys[0], fx.secrets[0])
	clean := fx.wallet.SanitizeString(dirty)
	assertNoSecretLeaks(t, "SanitizeString", clean, append(slices.Clone(fx.secrets), "sk-super-secret-api-key-12345"))
	assert.Contains(t, clean, "[REDACTED_PRIVATE_KEY]")
	assert.Contains(t, clean, "[REDACTED_SECRET]")

	// 3. SanitizeJSONForLog scrubs nested maps.
	cleanLog := fx.wallet.SanitizeJSONForLog(map[string]any{
		"leakKey": fx.pemKeys[1],
		"leakSD":  fx.secrets[1],
	})
	assertNoSecretLeaks(t, "SanitizeJSONForLog", cleanLog, fx.secrets)
}

func TestAuthorizeReceiptSender(t *testing.T) {
	fx := newUnitFixture(t, nil)

	cases := []struct {
		name string
		role string
		did  string
		want bool
	}{
		{name: "empty", role: "", did: "", want: false},
		{name: "wrong domain", role: "C_AUDIT_SERVICE", did: "did:web:a.local:services:audit", want: false},
		{name: "wrong role", role: "B_RECOVERY", did: "did:web:c.local:services:recovery", want: false},
		{name: "C_AUDIT_SERVICE", role: "C_AUDIT_SERVICE", did: "did:web:c.local:services:audit", want: true},
		{name: "C_AUDITOR", role: "C_AUDITOR", did: "did:web:c.local:auditors:c1", want: true},
		{name: "C-AUDITOR", role: "C-AUDITOR", did: "did:web:c.local:auditors:c2", want: true},
		{name: "c.local with port", role: "C_AUDIT_SERVICE", did: "did:web:c.local%3A8443:services:audit", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, wallet.IsAuthorizedReceiptSender(tc.role, tc.did))
			err := fx.wallet.AuthorizeReceiptCaller(tc.role, tc.did)
			if tc.want {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.True(t, protocol.HasCode(err, protocol.ErrCodeAuditForbidden))
			}
		})
	}
}

func TestWalletDelegationReplacementQuoteOrderAndReconcile(t *testing.T) {
	fx := newUnitFixture(t, nil)
	ctx := t.Context()

	checkCleanJSON := func(label string, v any) {
		t.Helper()
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		assertNoSecretLeaks(t, label, string(raw), fx.secrets)
	}

	// 1. InspectWallet shows A1's G1 grant.
	insp, err := fx.wallet.InspectWallet(ctx, wallet.InspectWalletInput{Actor: "A1"})
	require.NoError(t, err)
	checkCleanJSON("InspectWallet A1", insp)
	require.Len(t, insp.Grants, 1)
	assert.Equal(t, fx.g1ID, insp.Grants[0].GrantID)

	// 2. Monotonic attenuation enforcement: expanding maxAmountMinor or remainingDepth fails closed.
	_, err = fx.wallet.DelegateGrant(ctx, wallet.DelegateGrantInput{
		IssuerActor: "A1", SubjectActor: "B1", ParentGrantID: fx.g1ID,
		MaxAmountMinor: 600000, RemainingDepth: 0,
	})
	require.Error(t, err)
	_, err = fx.wallet.DelegateGrant(ctx, wallet.DelegateGrantInput{
		IssuerActor: "A1", SubjectActor: "B1", ParentGrantID: fx.g1ID,
		MaxAmountMinor: 100000, RemainingDepth: 1,
	})
	require.Error(t, err)

	// 3. DelegateGrant: A1 issues narrowed G2 to B1.
	g2ID := protocol.DigestBytes([]byte("unit-g2-b1"))
	del, err := fx.wallet.DelegateGrant(ctx, wallet.DelegateGrantInput{
		IssuerActor: "A1", SubjectActor: "B1", ParentGrantID: fx.g1ID, GrantID: g2ID,
		TaskID: fx.taskID, AuthorizationMode: protocol.ModeBuyerMandate,
		MaxAmountMinor: 100000, RemainingDepth: 0,
	})
	require.NoError(t, err)
	checkCleanJSON("DelegateGrant", del)
	assert.True(t, del.Anchored)
	assert.Equal(t, g2ID, del.Grant.GrantID)
	assert.Equal(t, fx.didB1, del.Grant.GranteeDID)
	assert.Equal(t, int64(100000), del.Grant.MaxAmountMinor)

	// 4. RequestQuote (uses canonical urn:grad:resource:C:quotes) & CreateOrder (uses canonical urn:grad:resource:C:orders).
	qB1, err := fx.wallet.RequestQuote(ctx, wallet.RequestQuoteInput{
		Actor: "B1", GrantID: g2ID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, ProductID: "urn:grad:product:P1", Quantity: 1,
	})
	require.NoError(t, err)
	checkCleanJSON("RequestQuote B1", qB1)
	assert.Equal(t, "ALLOW", qB1.Decision)
	assert.NotEmpty(t, qB1.QuoteID)
	assert.Equal(t, int64(80000), qB1.TotalAmountMinor)

	ordOK, err := fx.wallet.CreateOrder(ctx, wallet.CreateOrderInput{
		Actor: "B1", GrantID: g2ID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, QuoteID: qB1.QuoteID,
		AmountMinor: 80000, IdempotencyKey: "unit-ok-1",
	})
	require.NoError(t, err)
	checkCleanJSON("CreateOrder B1", ordOK)
	assert.Equal(t, "ALLOW", ordOK.Decision)
	assert.Equal(t, wallet.ActionStatusCompleted, ordOK.ActionStatus)
	assert.NotEmpty(t, ordOK.OrderID)

	// Verify canonical resource URIs reached gateway.
	fx.gw.mu.Lock()
	require.Len(t, fx.gw.verifiedRequests, 2)
	assert.Equal(t, protocol.ResourceQuotes, fx.gw.verifiedRequests[0].Resource)
	assert.Equal(t, protocol.ActionQuoteRead, fx.gw.verifiedRequests[0].Action)
	assert.Equal(t, protocol.ResourceOrders, fx.gw.verifiedRequests[1].Resource)
	assert.Equal(t, protocol.ActionOrderCreate, fx.gw.verifiedRequests[1].Action)
	fx.gw.mu.Unlock()

	// 5. Over-ceiling order returns DENY + FAILED.
	ordOver, err := fx.wallet.CreateOrder(ctx, wallet.CreateOrderInput{
		Actor: "B1", GrantID: g2ID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, QuoteID: qB1.QuoteID,
		AmountMinor: 120000, IdempotencyKey: "unit-over-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "DENY", ordOver.Decision)
	assert.Equal(t, protocol.ErrCodeAmountLimitExceeded, ordOver.ErrorCode)
	assert.Equal(t, wallet.ActionStatusFailed, ordOver.ActionStatus)

	// 6. ReplaceGrant: A1 atomically revokes G2 and delivers G2' to B2.
	g2PrimeID := protocol.DigestBytes([]byte("unit-g2-b2"))
	rep, err := fx.wallet.ReplaceGrant(ctx, wallet.ReplaceGrantInput{
		IssuerActor: "A1", OldGrantID: g2ID, NewSubjectActor: "B2", NewGrantID: g2PrimeID,
		MaxAmountMinor: 100000, RemainingDepth: 0, Reason: "failover to B2",
	})
	require.NoError(t, err)
	checkCleanJSON("ReplaceGrant", rep)
	assert.Equal(t, g2ID, rep.RevokedGrantID)
	assert.Equal(t, g2PrimeID, rep.ReplacementGrant.GrantID)
	assert.Equal(t, fx.didB2, rep.ReplacementGrant.GranteeDID)
	assert.True(t, rep.Anchored)

	// Old G2 is now rejected by gateway (GRANT_INACTIVE).
	revokedOrd, err := fx.wallet.CreateOrder(ctx, wallet.CreateOrderInput{
		Actor: "B1", GrantID: g2ID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, QuoteID: qB1.QuoteID,
		AmountMinor: 80000, IdempotencyKey: "unit-revoked-b1",
	})
	require.NoError(t, err)
	assert.Equal(t, "DENY", revokedOrd.Decision)
	assert.Equal(t, protocol.ErrCodeGrantInactive, revokedOrd.ErrorCode)

	// B2 reusing B1's quote fails with QUOTE_SCOPE_MISMATCH.
	crossQuoteOrd, err := fx.wallet.CreateOrder(ctx, wallet.CreateOrderInput{
		Actor: "B2", GrantID: g2PrimeID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, QuoteID: qB1.QuoteID,
		AmountMinor: 80000, IdempotencyKey: "unit-b2-wrong-quote",
	})
	require.NoError(t, err)
	assert.Equal(t, "DENY", crossQuoteOrd.Decision)
	assert.Equal(t, protocol.ErrCodeQuoteScopeMismatch, crossQuoteOrd.ErrorCode)

	// 7. B2 gets own quote, simulates post-commit response failure, then reconciles via ReconcileOrder.
	qB2, err := fx.wallet.RequestQuote(ctx, wallet.RequestQuoteInput{
		Actor: "B2", GrantID: g2PrimeID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, ProductID: "urn:grad:product:P1", Quantity: 1,
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", qB2.Decision)

	fx.gw.mu.Lock()
	fx.gw.failExecuteOnce["unit-lost-b2"] = true
	fx.gw.mu.Unlock()

	lostOrd, err := fx.wallet.CreateOrder(ctx, wallet.CreateOrderInput{
		Actor: "B2", GrantID: g2PrimeID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, QuoteID: qB2.QuoteID,
		AmountMinor: 80000, IdempotencyKey: "unit-lost-b2",
	})
	require.NoError(t, err)
	assert.Equal(t, "UNKNOWN", lostOrd.Decision)
	assert.Equal(t, wallet.ActionStatusOutcomeUnknown, lostOrd.ActionStatus)
	assert.Equal(t, int64(1), lostOrd.SendRevision)

	recOut, err := fx.wallet.ReconcileOrder(ctx, wallet.ReconcileOrderInput{
		Actor: "B2", TaskID: fx.taskID, IdempotencyKey: "unit-lost-b2",
	})
	require.NoError(t, err)
	checkCleanJSON("ReconcileOrder B2", recOut)
	assert.Equal(t, "CREATED", recOut.Outcome)
	assert.Equal(t, "MATCHED", recOut.HistoricalStatus)
	assert.Equal(t, int64(2), recOut.SendRevision)
	assert.Equal(t, wallet.ActionStatusReconciled, recOut.ActionStatus)
	assert.NotEmpty(t, recOut.OrderID)

	// InspectWallet for B2 surfaces reconciled client_action cleanly.
	inspB2, err := fx.wallet.InspectWallet(ctx, wallet.InspectWalletInput{Actor: "B2", TaskID: fx.taskID})
	require.NoError(t, err)
	checkCleanJSON("InspectWallet B2", inspB2)
	foundReconciled := false
	for _, a := range inspB2.ClientActions {
		if a.IdempotencyKey == "unit-lost-b2" {
			foundReconciled = true
			assert.Equal(t, wallet.ActionStatusReconciled, a.Status)
			assert.Equal(t, "CREATED", a.Outcome)
			assert.Equal(t, recOut.OrderID, a.OrderID)
		}
	}
	assert.True(t, foundReconciled, "expected reconciled action in inspect_wallet")
}

type failingRoundTripper struct {
	base    http.RoundTripper
	dropKey string
	dropped atomic.Bool
}

func (f *failingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost && req.URL.Path == "/v1/access/execute" && req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(raw))
		if strings.Contains(string(raw), f.dropKey) && f.dropped.CompareAndSwap(false, true) {
			resp, err := f.base.RoundTrip(req)
			if err != nil {
				return nil, err
			}
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return nil, errors.New("simulated connection reset after gateway commit")
		}
	}
	return f.base.RoundTrip(req)
}

func TestGatewayClientNetworkEOFResponseLoss(t *testing.T) {
	var gw *stubGateway
	var srv *httptest.Server
	var rt *failingRoundTripper

	fx := newUnitFixture(t, func(cfg *wallet.WalletConfig) {
		gw = newStubGateway(cfg.DeploymentID, cfg.Audience, cfg.SupplierID, cfg.Now)
		srv = httptest.NewServer(gw.handler())
		t.Cleanup(srv.Close)
		rt = &failingRoundTripper{base: http.DefaultTransport, dropKey: "net-eof-drop-1"}
		cfg.GatewayURL = srv.URL
		cfg.HTTPHandler = nil
		cfg.HTTPClient = &http.Client{Transport: rt, Timeout: 5 * time.Second}
		cfg.RecoveryClient = newLocalRoleClient(gw.handler(), "B_RECOVERY", "did:web:a.local:services:recovery")
		cfg.AuditClient = newLocalRoleClient(gw.handler(), "C_AUDITOR", "did:web:c.local:auditors:c1")
	})
	ctx := t.Context()

	g2ID := protocol.DigestBytes([]byte("net-g2"))
	_, err := fx.wallet.DelegateGrant(ctx, wallet.DelegateGrantInput{
		IssuerActor: "A1", SubjectActor: "B1", ParentGrantID: fx.g1ID, GrantID: g2ID,
		TaskID: fx.taskID, AuthorizationMode: protocol.ModeBuyerMandate,
		MaxAmountMinor: 100000, RemainingDepth: 0,
	})
	require.NoError(t, err)

	q, err := fx.wallet.RequestQuote(ctx, wallet.RequestQuoteInput{
		Actor: "B1", GrantID: g2ID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, ProductID: "urn:grad:product:P1", Quantity: 1,
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", q.Decision)

	ord, err := fx.wallet.CreateOrder(ctx, wallet.CreateOrderInput{
		Actor: "B1", GrantID: g2ID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, QuoteID: q.QuoteID,
		AmountMinor: 80000, IdempotencyKey: "net-eof-drop-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "UNKNOWN", ord.Decision)
	assert.Equal(t, wallet.ActionStatusOutcomeUnknown, ord.ActionStatus)

	rec, err := fx.wallet.ReconcileOrder(ctx, wallet.ReconcileOrderInput{
		Actor: "B1", TaskID: fx.taskID, IdempotencyKey: "net-eof-drop-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "CREATED", rec.Outcome)
	assert.Equal(t, wallet.ActionStatusReconciled, rec.ActionStatus)
	assert.Equal(t, int64(2), rec.SendRevision)
	assert.NotEmpty(t, rec.OrderID)
}
