package agent_test

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

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/agent"
	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	"grad/protocol"
)

type stubGateway struct {
	mu               sync.Mutex
	depID            string
	audience         string
	supplierID       string
	unitPriceMinor   int64
	maxOrderAmount   int64
	now              func() time.Time
	seq              atomic.Int64
	challenges       map[string]agent.ChallengeResponse
	quotes           map[string]agent.QuotePayload
	ordersByKey      map[string]agent.OrderPayload
	decisionsByKey   map[string]string
	cases            map[string]agent.OrderOutcomeCaseRequest
	auditCheckNo     map[string]int64
	auditOutcomeHook func(caseReq agent.OrderOutcomeCaseRequest, checkNo int64) (outcome, histStatus string, orderID, decisionID *string)
	onChallenge      func(req agent.ChallengeRequest)
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
		challenges:      make(map[string]agent.ChallengeResponse),
		quotes:          make(map[string]agent.QuotePayload),
		ordersByKey:     make(map[string]agent.OrderPayload),
		decisionsByKey:  make(map[string]string),
		cases:           make(map[string]agent.OrderOutcomeCaseRequest),
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
	var req agent.ChallengeRequest
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
	resp := agent.ChallengeResponse{
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
		q := agent.QuotePayload{
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
		httpx.WriteJSON(w, http.StatusOK, agent.ExecuteResponse{
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
		ord := agent.OrderPayload{
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
		httpx.WriteJSON(w, http.StatusOK, agent.ExecuteResponse{
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
	id, ok := mtls.Caller(r)
	if !ok || id.Role != "B_RECOVERY" {
		httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeAuditForbidden, nil, "B_RECOVERY identity required")
		return
	}
	var req agent.OrderOutcomeCaseRequest
	if err := httpx.DecodeJSON(r, 256*1024, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	g.mu.Lock()
	g.cases[req.CaseID] = req
	g.mu.Unlock()
	httpx.WriteJSON(w, http.StatusAccepted, agent.OrderOutcomeCaseResponse{
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
	id, ok := mtls.Caller(r)
	if !ok || (id.Role != "C_AUDITOR" && id.Role != "C-AUDITOR") {
		httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeAuditForbidden, nil, "C_AUDITOR identity required")
		return
	}
	var req agent.AuditOrderOutcomeRequest
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
		did := decID
		orderPtr = &oid
		decPtr = &did
	}
	if hook != nil {
		outcome, histStatus, orderPtr, decPtr = hook(caseReq, checkNo)
	}
	nowSec := g.now().UTC().Unix()
	receipt := agent.OrderOutcomeReceipt{
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
	httpx.WriteJSON(w, http.StatusOK, agent.AuditOrderOutcomeResponse{
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
		VerifierID:         id.DID,
		AuditAt:            nowSec,
		Receipt:            receipt,
	})
}

type unitFixture struct {
	depID    string
	taskID   string
	audience string
	now      time.Time
	gw       *stubGateway
	wallet   *agent.WalletContext
	privA1   *ecdsa.PrivateKey
	pubA1    *ecdsa.PublicKey
	didA1    string
	didB1    string
	didB2    string
	g1ID     string
	g1Bundle agent.GrantBundle
	secrets  []string
	pemKeys  []string
}

func newUnitFixture(t *testing.T, walletModifier func(*agent.WalletConfig)) *unitFixture {
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

	cfg := agent.WalletConfig{
		DeploymentID:    depID,
		Audience:        audience,
		SupplierID:      supplierID,
		DefaultTaskSpec: spec,
		Currency:        "CNY",
		HTTPHandler:     gwHandler,
		RecoveryClient:  mtls.NewLocalClient(gwHandler, mtls.Identity{Role: "B_RECOVERY", DID: "did:web:a.local:services:recovery"}),
		AuditClient:     mtls.NewLocalClient(gwHandler, mtls.Identity{Role: "C_AUDITOR", DID: "did:web:c.local:auditors:c1"}),
		Now:             func() time.Time { return now },
		AnchorChildFunc: func(_ context.Context, _ agent.AnchorChildGrantRequest) (*agent.AnchorChildGrantResult, error) {
			return &agent.AnchorChildGrantResult{
				Anchored:   true,
				TrustPaths: []protocol.TrustPathEntry{{Issuer: didIA, DomainCertification: certJWS}},
			}, nil
		},
		ReplaceGrantFunc: func(_ context.Context, req agent.ReplaceGrantRequest) (*agent.ReplaceGrantResult, error) {
			gw.mu.Lock()
			gw.revokedGrants[req.OldGrantID] = true
			gw.mu.Unlock()
			return &agent.ReplaceGrantResult{
				Anchored:   true,
				TrustPaths: []protocol.TrustPathEntry{{Issuer: didIA, DomainCertification: certJWS}},
			}, nil
		},
	}
	if walletModifier != nil {
		walletModifier(&cfg)
	}
	var wallet *agent.WalletContext
	if cfg.ReceiptClient == nil && cfg.ReceiptDelivery == nil {
		cfg.ReceiptClient = mtls.NewLocalClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wallet.ReceiptHandler().ServeHTTP(w, r)
		}), mtls.Identity{
			Role: "C_AUDIT_SERVICE",
			DID:  "did:web:c.local:services:audit",
		})
	}
	wallet, err = agent.NewWalletContext(cfg)
	require.NoError(t, err)

	require.NoError(t, wallet.RegisterActor(agent.Signer{
		Actor: "A1", DID: didA1, KeyID: didA1 + "#key-1", CredentialID: "urn:grad:cred:A1", KeyVersion: 1,
		DomainID: "A", EntityType: "AGENT", Roles: []string{"procurement-agent"},
		PrivateKey: privA1, SDJWTPresentation: sdA1.PresentationPrefix,
	}))
	require.NoError(t, wallet.RegisterActor(agent.Signer{
		Actor: "B1", DID: didB1, KeyID: didB1 + "#key-1", CredentialID: "urn:grad:cred:B1", KeyVersion: 1,
		DomainID: "A", EntityType: "AGENT", Roles: []string{"buyer-delegate"},
		PrivateKey: privB1, SDJWTPresentation: sdB1.PresentationPrefix,
	}))
	require.NoError(t, wallet.RegisterActor(agent.Signer{
		Actor: "B2", DID: didB2, KeyID: didB2 + "#key-1", CredentialID: "urn:grad:cred:B2", KeyVersion: 1,
		DomainID: "A", EntityType: "AGENT", Roles: []string{"buyer-delegate"},
		PrivateKey: privB2, SDJWTPresentation: sdB2.PresentationPrefix,
	}))

	g1Bundle := agent.GrantBundle{
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
	require.NoError(t, wallet.AddGrantBundle(g1Bundle))

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
		gw: gw, wallet: wallet, privA1: privA1, pubA1: &privA1.PublicKey,
		didA1: didA1, didB1: didB1, didB2: didB2,
		g1ID: g1ID, g1Bundle: g1Bundle, secrets: secrets, pemKeys: pemKeys,
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
	signerRaw, err := json.Marshal(agent.Signer{
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

func TestMCPToolsListCallDelegationReplacementQuoteOrderAndReconcile(t *testing.T) {
	fx := newUnitFixture(t, nil)
	ctx := t.Context()

	mcpSrv := agent.NewMCPServer(fx.wallet)
	tServer, tClient := mcp.NewInMemoryTransports()
	srvSess, err := mcpSrv.Connect(ctx, tServer, nil)
	require.NoError(t, err)
	defer srvSess.Close()

	cli := mcp.NewClient(&mcp.Implementation{Name: "unit-mcp-client", Version: "v1.0.0"}, nil)
	cliSess, err := cli.Connect(ctx, tClient, nil)
	require.NoError(t, err)
	defer cliSess.Close()

	// 1. tools/list exposes all 6 canonical tools.
	listed, err := cliSess.ListTools(ctx, nil)
	require.NoError(t, err)
	toolNames := make([]string, 0, len(listed.Tools))
	for _, tool := range listed.Tools {
		toolNames = append(toolNames, tool.Name)
	}
	assert.ElementsMatch(t, []string{
		"inspect_wallet",
		"delegate_grant",
		"replace_grant",
		"request_quote",
		"create_order",
		"reconcile_order",
	}, toolNames)

	callTool := func(name string, args map[string]any, dst any) {
		t.Helper()
		res, cErr := cliSess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		require.NoError(t, cErr)
		require.False(t, res.IsError, "tool %s returned error: %+v", name, res.Content)
		raw, mErr := json.Marshal(res.StructuredContent)
		require.NoError(t, mErr)
		assertNoSecretLeaks(t, "MCP "+name, string(raw), fx.secrets)
		require.NoError(t, json.Unmarshal(raw, dst))
	}

	// 2. inspect_wallet shows A1's G1 grant.
	var insp agent.InspectWalletOutput
	callTool("inspect_wallet", map[string]any{"actor": "A1"}, &insp)
	require.Len(t, insp.Grants, 1)
	assert.Equal(t, fx.g1ID, insp.Grants[0].GrantID)

	// 3. Monotonic attenuation enforcement: expanding maxAmountMinor or remainingDepth fails closed.
	_, err = fx.wallet.DelegateGrant(ctx, agent.DelegateGrantInput{
		IssuerActor: "A1", SubjectActor: "B1", ParentGrantID: fx.g1ID,
		MaxAmountMinor: 600000, RemainingDepth: 0,
	})
	require.Error(t, err)
	_, err = fx.wallet.DelegateGrant(ctx, agent.DelegateGrantInput{
		IssuerActor: "A1", SubjectActor: "B1", ParentGrantID: fx.g1ID,
		MaxAmountMinor: 100000, RemainingDepth: 1,
	})
	require.Error(t, err)

	// 4. delegate_grant: A1 issues narrowed G2 to B1.
	g2ID := protocol.DigestBytes([]byte("unit-g2-b1"))
	var del agent.DelegateGrantOutput
	callTool("delegate_grant", map[string]any{
		"issuerActor": "A1", "subjectActor": "B1", "parentGrantId": fx.g1ID, "grantId": g2ID,
		"taskId": fx.taskID, "authorizationMode": protocol.ModeBuyerMandate,
		"maxAmountMinor": 100000, "remainingDepth": 0,
	}, &del)
	assert.True(t, del.Anchored)
	assert.Equal(t, g2ID, del.Grant.GrantID)
	assert.Equal(t, fx.didB1, del.Grant.GranteeDID)
	assert.Equal(t, int64(100000), del.Grant.MaxAmountMinor)

	// 5. request_quote (uses canonical urn:grad:resource:C:quotes) & create_order (uses canonical urn:grad:resource:C:orders).
	var qB1 agent.RequestQuoteOutput
	callTool("request_quote", map[string]any{
		"actor": "B1", "grantId": g2ID, "taskId": fx.taskID,
		"authorizationMode": protocol.ModeBuyerMandate, "productId": "urn:grad:product:P1", "quantity": 1,
	}, &qB1)
	assert.Equal(t, "ALLOW", qB1.Decision)
	assert.NotEmpty(t, qB1.QuoteID)
	assert.Equal(t, int64(80000), qB1.TotalAmountMinor)

	var ordOK agent.CreateOrderOutput
	callTool("create_order", map[string]any{
		"actor": "B1", "grantId": g2ID, "taskId": fx.taskID,
		"authorizationMode": protocol.ModeBuyerMandate, "quoteId": qB1.QuoteID,
		"amountMinor": 80000, "idempotencyKey": "unit-ok-1",
	}, &ordOK)
	assert.Equal(t, "ALLOW", ordOK.Decision)
	assert.Equal(t, agent.ActionStatusCompleted, ordOK.ActionStatus)
	assert.NotEmpty(t, ordOK.OrderID)

	// Verify canonical resource URIs reached gateway.
	fx.gw.mu.Lock()
	require.Len(t, fx.gw.verifiedRequests, 2)
	assert.Equal(t, protocol.ResourceQuotes, fx.gw.verifiedRequests[0].Resource)
	assert.Equal(t, protocol.ActionQuoteRead, fx.gw.verifiedRequests[0].Action)
	assert.Equal(t, protocol.ResourceOrders, fx.gw.verifiedRequests[1].Resource)
	assert.Equal(t, protocol.ActionOrderCreate, fx.gw.verifiedRequests[1].Action)
	fx.gw.mu.Unlock()

	// 6. Over-ceiling order returns DENY + FAILED.
	var ordOver agent.CreateOrderOutput
	callTool("create_order", map[string]any{
		"actor": "B1", "grantId": g2ID, "taskId": fx.taskID,
		"authorizationMode": protocol.ModeBuyerMandate, "quoteId": qB1.QuoteID,
		"amountMinor": 120000, "idempotencyKey": "unit-over-1",
	}, &ordOver)
	assert.Equal(t, "DENY", ordOver.Decision)
	assert.Equal(t, protocol.ErrCodeAmountLimitExceeded, ordOver.ErrorCode)
	assert.Equal(t, agent.ActionStatusFailed, ordOver.ActionStatus)

	// 7. replace_grant: A1 atomically revokes G2 and delivers G2' to B2.
	g2PrimeID := protocol.DigestBytes([]byte("unit-g2-b2"))
	var rep agent.ReplaceGrantOutput
	callTool("replace_grant", map[string]any{
		"issuerActor": "A1", "oldGrantId": g2ID, "newSubjectActor": "B2", "newGrantId": g2PrimeID,
		"maxAmountMinor": 100000, "remainingDepth": 0, "reason": "failover to B2",
	}, &rep)
	assert.Equal(t, g2ID, rep.RevokedGrantID)
	assert.Equal(t, g2PrimeID, rep.ReplacementGrant.GrantID)
	assert.Equal(t, fx.didB2, rep.ReplacementGrant.GranteeDID)
	assert.True(t, rep.Anchored)

	// Old G2 is now rejected by gateway (GRANT_INACTIVE).
	revokedOrd, err := fx.wallet.CreateOrder(ctx, agent.CreateOrderInput{
		Actor: "B1", GrantID: g2ID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, QuoteID: qB1.QuoteID,
		AmountMinor: 80000, IdempotencyKey: "unit-revoked-b1",
	})
	require.NoError(t, err)
	assert.Equal(t, "DENY", revokedOrd.Decision)
	assert.Equal(t, protocol.ErrCodeGrantInactive, revokedOrd.ErrorCode)

	// B2 reusing B1's quote fails with QUOTE_SCOPE_MISMATCH.
	crossQuoteOrd, err := fx.wallet.CreateOrder(ctx, agent.CreateOrderInput{
		Actor: "B2", GrantID: g2PrimeID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, QuoteID: qB1.QuoteID,
		AmountMinor: 80000, IdempotencyKey: "unit-b2-wrong-quote",
	})
	require.NoError(t, err)
	assert.Equal(t, "DENY", crossQuoteOrd.Decision)
	assert.Equal(t, protocol.ErrCodeQuoteScopeMismatch, crossQuoteOrd.ErrorCode)

	// 8. B2 gets own quote, simulates post-commit response failure, then reconciles via reconcile_order.
	qB2, err := fx.wallet.RequestQuote(ctx, agent.RequestQuoteInput{
		Actor: "B2", GrantID: g2PrimeID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, ProductID: "urn:grad:product:P1", Quantity: 1,
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", qB2.Decision)

	fx.gw.mu.Lock()
	fx.gw.failExecuteOnce["unit-lost-b2"] = true
	fx.gw.mu.Unlock()

	lostOrd, err := fx.wallet.CreateOrder(ctx, agent.CreateOrderInput{
		Actor: "B2", GrantID: g2PrimeID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, QuoteID: qB2.QuoteID,
		AmountMinor: 80000, IdempotencyKey: "unit-lost-b2",
	})
	require.NoError(t, err)
	assert.Equal(t, "UNKNOWN", lostOrd.Decision)
	assert.Equal(t, agent.ActionStatusOutcomeUnknown, lostOrd.ActionStatus)
	assert.Equal(t, int64(1), lostOrd.SendRevision)

	var recOut agent.ReconcileOrderOutput
	callTool("reconcile_order", map[string]any{
		"actor": "B2", "taskId": fx.taskID, "idempotencyKey": "unit-lost-b2",
	}, &recOut)
	assert.Equal(t, "CREATED", recOut.Outcome)
	assert.Equal(t, "MATCHED", recOut.HistoricalStatus)
	assert.Equal(t, int64(2), recOut.SendRevision)
	assert.Equal(t, agent.ActionStatusReconciled, recOut.ActionStatus)
	assert.NotEmpty(t, recOut.OrderID)

	// inspect_wallet for B2 surfaces reconciled client_action cleanly.
	inspB2, err := fx.wallet.InspectWallet(ctx, agent.InspectWalletInput{Actor: "B2", TaskID: fx.taskID})
	require.NoError(t, err)
	foundReconciled := false
	for _, a := range inspB2.ClientActions {
		if a.IdempotencyKey == "unit-lost-b2" {
			foundReconciled = true
			assert.Equal(t, agent.ActionStatusReconciled, a.Status)
			assert.Equal(t, "CREATED", a.Outcome)
			assert.Equal(t, recOut.OrderID, a.OrderID)
		}
	}
	assert.True(t, foundReconciled, "expected reconciled action in inspect_wallet")
}

func TestLLMRunnerOpenAIAndAnthropicPlumbingAndRedaction(t *testing.T) {
	ctx := t.Context()

	t.Run("OpenAI", func(t *testing.T) {
		fx := newUnitFixture(t, nil)
		apiKey := "sk-openai-unit-secret-999999"
		fx.wallet.RegisterSecret(apiKey)

		g2ID := protocol.DigestBytes([]byte("oai-g2"))
		var mu sync.Mutex
		step := 0
		lastQuote := ""

		oaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Messages []struct {
					Content any `json:"content"`
				} `json:"messages"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			defer mu.Unlock()
			if n := len(body.Messages); n > 0 {
				if s, ok := body.Messages[n-1].Content.(string); ok {
					var m map[string]any
					if json.Unmarshal([]byte(s), &m) == nil {
						if qid, ok := m["quoteId"].(string); ok && qid != "" {
							lastQuote = qid
						}
					}
				}
			}
			w.Header().Set("Content-Type", "application/json")
			type callSpec struct {
				name string
				args map[string]any
			}
			script := []callSpec{
				{"inspect_wallet", map[string]any{"actor": "A1"}},
				{"delegate_grant", map[string]any{
					"issuerActor": "A1", "subjectActor": "B1", "parentGrantId": fx.g1ID, "grantId": g2ID,
					"taskId": fx.taskID, "authorizationMode": protocol.ModeBuyerMandate,
					"maxAmountMinor": 100000, "remainingDepth": 0,
				}},
				{"request_quote", map[string]any{
					"actor": "B1", "grantId": g2ID, "taskId": fx.taskID,
					"authorizationMode": protocol.ModeBuyerMandate, "productId": "urn:grad:product:P1", "quantity": 1,
				}},
				{"create_order", map[string]any{
					"actor": "B1", "grantId": g2ID, "taskId": fx.taskID,
					"authorizationMode": protocol.ModeBuyerMandate, "quoteId": lastQuote,
					"amountMinor": 80000, "idempotencyKey": "oai-order-1",
				}},
			}
			if step >= len(script) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "chatcmpl-done", "object": "chat.completion", "model": "mock-openai",
					"choices": []any{map[string]any{
						"index": 0, "finish_reason": "stop",
						"message": map[string]any{
							"role":    "assistant",
							"content": "Completed with key " + apiKey,
						},
					}},
				})
				return
			}
			act := script[step]
			step++
			argBytes, _ := json.Marshal(act.args)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": fmt.Sprintf("chatcmpl-%d", step), "object": "chat.completion", "model": "mock-openai",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "tool_calls",
					"message": map[string]any{
						"role": "assistant", "content": "",
						"tool_calls": []any{map[string]any{
							"id": fmt.Sprintf("call_%d", step), "type": "function",
							"function": map[string]any{"name": act.name, "arguments": string(argBytes)},
						}},
					},
				}},
			})
		}))
		defer oaiSrv.Close()

		res, err := agent.RunAgentTask(ctx, agent.NewMCPServer(fx.wallet), agent.RunnerConfig{
			Provider: agent.ProviderOpenAI,
			BaseURL:  oaiSrv.URL + "/v1",
			APIKey:   apiKey,
			Model:    "mock-openai",
			MaxSteps: 8,
		}, "Delegate grant to B1 and purchase 1 unit of P1.")
		require.NoError(t, err)
		assert.Equal(t, agent.ProviderOpenAI, res.Provider)
		assert.Equal(t, 4, res.ToolCallsCount)
		assert.Contains(t, res.FinalText, "[REDACTED_API_KEY]")
		resJSON, err := json.Marshal(res)
		require.NoError(t, err)
		assertNoSecretLeaks(t, "OpenAI RunResult", string(resJSON), append(slices.Clone(fx.secrets), apiKey))
	})

	t.Run("Anthropic", func(t *testing.T) {
		fx := newUnitFixture(t, nil)
		apiKey := "sk-ant-unit-secret-888888"
		fx.wallet.RegisterSecret(apiKey)

		g2ID := protocol.DigestBytes([]byte("ant-g2"))
		var mu sync.Mutex
		step := 0
		lastQuote := ""

		antSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Messages []struct {
					Content []json.RawMessage `json:"content"`
				} `json:"messages"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			defer mu.Unlock()
			if n := len(body.Messages); n > 0 {
				for _, rawBlk := range body.Messages[n-1].Content {
					var blk struct {
						Type    string          `json:"type"`
						Content json.RawMessage `json:"content"`
					}
					if json.Unmarshal(rawBlk, &blk) == nil && blk.Type == "tool_result" {
						var single string
						if json.Unmarshal(blk.Content, &single) == nil {
							var m map[string]any
							if json.Unmarshal([]byte(single), &m) == nil {
								if qid, ok := m["quoteId"].(string); ok && qid != "" {
									lastQuote = qid
								}
							}
						}
					}
				}
			}
			w.Header().Set("Content-Type", "application/json")
			type callSpec struct {
				name string
				args map[string]any
			}
			script := []callSpec{
				{"inspect_wallet", map[string]any{"actor": "A1"}},
				{"delegate_grant", map[string]any{
					"issuerActor": "A1", "subjectActor": "B1", "parentGrantId": fx.g1ID, "grantId": g2ID,
					"taskId": fx.taskID, "authorizationMode": protocol.ModeBuyerMandate,
					"maxAmountMinor": 100000, "remainingDepth": 0,
				}},
				{"request_quote", map[string]any{
					"actor": "B1", "grantId": g2ID, "taskId": fx.taskID,
					"authorizationMode": protocol.ModeBuyerMandate, "productId": "urn:grad:product:P1", "quantity": 1,
				}},
				{"create_order", map[string]any{
					"actor": "B1", "grantId": g2ID, "taskId": fx.taskID,
					"authorizationMode": protocol.ModeBuyerMandate, "quoteId": lastQuote,
					"amountMinor": 80000, "idempotencyKey": "ant-order-1",
				}},
			}
			if step >= len(script) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "msg_done", "type": "message", "role": "assistant", "model": "mock-anthropic",
					"stop_reason": "end_turn",
					"content":     []any{map[string]any{"type": "text", "text": "Anthropic order placed " + apiKey}},
					"usage":       map[string]any{"input_tokens": 50, "output_tokens": 20},
				})
				return
			}
			act := script[step]
			step++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": fmt.Sprintf("msg_%d", step), "type": "message", "role": "assistant", "model": "mock-anthropic",
				"stop_reason": "tool_use",
				"content": []any{map[string]any{
					"type": "tool_use", "id": fmt.Sprintf("toolu_%d", step),
					"name": act.name, "input": act.args,
				}},
				"usage": map[string]any{"input_tokens": 50, "output_tokens": 30},
			})
		}))
		defer antSrv.Close()

		res, err := agent.RunAgentTask(ctx, agent.NewMCPServer(fx.wallet), agent.RunnerConfig{
			Provider: agent.ProviderAnthropic,
			BaseURL:  antSrv.URL,
			APIKey:   apiKey,
			Model:    "mock-anthropic",
			MaxSteps: 8,
		}, "Delegate grant to B1 and purchase 1 unit of P1.")
		require.NoError(t, err)
		assert.Equal(t, agent.ProviderAnthropic, res.Provider)
		assert.Equal(t, 4, res.ToolCallsCount)
		assert.Contains(t, res.FinalText, "[REDACTED_API_KEY]")
		resJSON, err := json.Marshal(res)
		require.NoError(t, err)
		assertNoSecretLeaks(t, "Anthropic RunResult", string(resJSON), append(slices.Clone(fx.secrets), apiKey))
	})

	t.Run("ConfigValidationAndEnv", func(t *testing.T) {
		t.Setenv("LLM_PROVIDER", "openai")
		t.Setenv("LLM_BASE_URL", "https://llm.example.test/v1")
		t.Setenv("LLM_API_KEY", "sk-env-test")
		t.Setenv("LLM_MODEL", "test-model")
		t.Setenv("LLM_MAX_STEPS", "6")
		cfg := agent.LoadRunnerConfigFromEnv()
		assert.Equal(t, agent.ProviderOpenAI, cfg.Provider)
		assert.Equal(t, "https://llm.example.test/v1", cfg.BaseURL)
		assert.Equal(t, "sk-env-test", cfg.APIKey)
		assert.Equal(t, "test-model", cfg.Model)
		assert.Equal(t, 6, cfg.MaxSteps)

		fx := newUnitFixture(t, nil)
		_, err := agent.RunAgentTask(ctx, agent.NewMCPServer(fx.wallet), agent.RunnerConfig{
			Provider: "invalid-provider", Model: "m", APIKey: "k",
		}, "hello")
		require.Error(t, err)
	})
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

	fx := newUnitFixture(t, func(cfg *agent.WalletConfig) {
		gw = newStubGateway(cfg.DeploymentID, cfg.Audience, cfg.SupplierID, cfg.Now)
		srv = httptest.NewServer(gw.handler())
		t.Cleanup(srv.Close)
		rt = &failingRoundTripper{base: http.DefaultTransport, dropKey: "net-eof-drop-1"}
		cfg.GatewayURL = srv.URL
		cfg.HTTPHandler = nil
		cfg.HTTPClient = &http.Client{Transport: rt, Timeout: 5 * time.Second}
		cfg.RecoveryClient = mtls.NewLocalClient(gw.handler(), mtls.Identity{Role: "B_RECOVERY", DID: "did:web:a.local:services:recovery"})
		cfg.AuditClient = mtls.NewLocalClient(gw.handler(), mtls.Identity{Role: "C_AUDITOR", DID: "did:web:c.local:auditors:c1"})
	})
	ctx := t.Context()

	g2ID := protocol.DigestBytes([]byte("net-g2"))
	_, err := fx.wallet.DelegateGrant(ctx, agent.DelegateGrantInput{
		IssuerActor: "A1", SubjectActor: "B1", ParentGrantID: fx.g1ID, GrantID: g2ID,
		TaskID: fx.taskID, AuthorizationMode: protocol.ModeBuyerMandate,
		MaxAmountMinor: 100000, RemainingDepth: 0,
	})
	require.NoError(t, err)

	q, err := fx.wallet.RequestQuote(ctx, agent.RequestQuoteInput{
		Actor: "B1", GrantID: g2ID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, ProductID: "urn:grad:product:P1", Quantity: 1,
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", q.Decision)

	ord, err := fx.wallet.CreateOrder(ctx, agent.CreateOrderInput{
		Actor: "B1", GrantID: g2ID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, QuoteID: q.QuoteID,
		AmountMinor: 80000, IdempotencyKey: "net-eof-drop-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "UNKNOWN", ord.Decision)
	assert.Equal(t, agent.ActionStatusOutcomeUnknown, ord.ActionStatus)

	rec, err := fx.wallet.ReconcileOrder(ctx, agent.ReconcileOrderInput{
		Actor: "B1", TaskID: fx.taskID, IdempotencyKey: "net-eof-drop-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "CREATED", rec.Outcome)
	assert.Equal(t, agent.ActionStatusReconciled, rec.ActionStatus)
	assert.Equal(t, int64(2), rec.SendRevision)
	assert.NotEmpty(t, rec.OrderID)
}
