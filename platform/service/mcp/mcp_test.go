package mcp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/core/domain/wallet"
	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	svcmcp "grad/platform/service/mcp"
	"grad/protocol"
)

type stubGateway struct {
	mu               sync.Mutex
	depID            string
	audience         string
	supplierID       string
	unitPriceMinor   int64
	now              func() time.Time
	seq              atomic.Int64
	challenges       map[string]wallet.ChallengeResponse
	quotes           map[string]wallet.QuotePayload
	ordersByKey      map[string]wallet.OrderPayload
	decisionsByKey   map[string]string
	cases            map[string]wallet.OrderOutcomeCaseRequest
	auditCheckNo     map[string]int64
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
	n := g.seq.Add(1)
	nowSec := g.now().UTC().Unix()
	nonceSum := sha256.Sum256([]byte(fmt.Sprintf("mcp-stub-nonce-%s-%d", g.depID, n)))
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
	id, ok := mtls.Caller(r)
	if !ok || id.Role != "B_RECOVERY" {
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
	id, ok := mtls.Caller(r)
	if !ok || (id.Role != "C_AUDITOR" && id.Role != "C-AUDITOR") {
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
		VerifierID:         id.DID,
		AuditAt:            nowSec,
		Receipt:            receipt,
	})
}

type testFixture struct {
	depID   string
	taskID  string
	gw      *stubGateway
	wallet  *wallet.WalletContext
	didA1   string
	didB1   string
	didB2   string
	g1ID    string
	secrets []string
}

func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	depID := protocol.DigestBytes([]byte("mcp-dep-" + t.Name()))
	taskID := protocol.DigestBytes([]byte("mcp-task-" + t.Name()))
	resID := protocol.DigestBytes([]byte("mcp-res-" + t.Name()))
	audience := "https://c.local"
	supplierID := "urn:grad:supplier:C"

	genKey := func() *ecdsa.PrivateKey {
		pk, err := protocol.GenerateP256Key()
		require.NoError(t, err)
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

	certID := "urn:grad:domain-certification:A-mcp"
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
		Description: "MCP test procurement task",
	}

	g0ID := protocol.DigestBytes([]byte("mcp-g0-" + t.Name()))
	g1ID := protocol.DigestBytes([]byte("mcp-g1-" + t.Name()))

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

	var w *wallet.WalletContext
	cfg := wallet.WalletConfig{
		DeploymentID:    depID,
		Audience:        audience,
		SupplierID:      supplierID,
		DefaultTaskSpec: spec,
		Currency:        "CNY",
		HTTPHandler:     gwHandler,
		RecoveryClient:  mtls.NewLocalClient(gwHandler, mtls.Identity{Role: "B_RECOVERY", DID: "did:web:a.local:services:recovery"}),
		AuditClient:     mtls.NewLocalClient(gwHandler, mtls.Identity{Role: "C_AUDITOR", DID: "did:web:c.local:auditors:c1"}),
		ReceiptDelivery: func(ctx context.Context, receipt wallet.OrderOutcomeReceipt) (*wallet.OrderOutcomeReceiptResponse, error) {
			return w.ApplyOrderOutcomeReceipt(ctx, receipt)
		},
		Now: func() time.Time { return now },
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

	w, err = wallet.NewWalletContext(cfg)
	require.NoError(t, err)

	require.NoError(t, w.RegisterActor(wallet.Signer{
		Actor: "A1", DID: didA1, KeyID: didA1 + "#key-1", CredentialID: "urn:grad:cred:A1", KeyVersion: 1,
		DomainID: "A", EntityType: "AGENT", Roles: []string{"procurement-agent"},
		PrivateKey: privA1, SDJWTPresentation: sdA1.PresentationPrefix,
	}))
	require.NoError(t, w.RegisterActor(wallet.Signer{
		Actor: "B1", DID: didB1, KeyID: didB1 + "#key-1", CredentialID: "urn:grad:cred:B1", KeyVersion: 1,
		DomainID: "A", EntityType: "AGENT", Roles: []string{"buyer-delegate"},
		PrivateKey: privB1, SDJWTPresentation: sdB1.PresentationPrefix,
	}))
	require.NoError(t, w.RegisterActor(wallet.Signer{
		Actor: "B2", DID: didB2, KeyID: didB2 + "#key-1", CredentialID: "urn:grad:cred:B2", KeyVersion: 1,
		DomainID: "A", EntityType: "AGENT", Roles: []string{"buyer-delegate"},
		PrivateKey: privB2, SDJWTPresentation: sdB2.PresentationPrefix,
	}))

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
	for _, pk := range []*ecdsa.PrivateKey{privA1, privB1, privB2} {
		der, mErr := x509.MarshalECPrivateKey(pk)
		require.NoError(t, mErr)
		secrets = append(secrets, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))
	}

	return &testFixture{
		depID:   depID,
		taskID:  taskID,
		gw:      gw,
		wallet:  w,
		didA1:   didA1,
		didB1:   didB1,
		didB2:   didB2,
		g1ID:    g1ID,
		secrets: secrets,
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

func connectInMemory(t *testing.T, srv *sdkmcp.Server) *sdkmcp.ClientSession {
	t.Helper()
	ctx := t.Context()
	tServer, tClient := sdkmcp.NewInMemoryTransports()
	srvSess, err := srv.Connect(ctx, tServer, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srvSess.Close() })

	cli := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "mcp-test-client", Version: "v1.0.0"}, nil)
	cliSess, err := cli.Connect(ctx, tClient, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cliSess.Close() })
	return cliSess
}

func connectOverIOPipe(t *testing.T, srv *sdkmcp.Server) *sdkmcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	c2sReader, c2sWriter := io.Pipe()
	s2cReader, s2cWriter := io.Pipe()

	errCh := make(chan error, 1)
	go func() {
		errCh <- svcmcp.RunMCPServer(ctx, srv, c2sReader, s2cWriter)
	}()

	cli := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "mcp-pipe-client", Version: "v1.0.0"}, nil)
	cliSess, err := cli.Connect(ctx, &sdkmcp.IOTransport{
		Reader: s2cReader,
		Writer: c2sWriter,
	}, nil)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = cliSess.Close()
		cancel()
		_ = c2sWriter.Close()
		_ = c2sReader.Close()
		_ = s2cWriter.Close()
		_ = s2cReader.Close()
		select {
		case <-errCh:
		case <-time.After(3 * time.Second):
			t.Errorf("RunMCPServer did not exit after closing pipes")
		}
	})
	return cliSess
}

func verifySixToolSchemas(t *testing.T, tools []*sdkmcp.Tool) {
	t.Helper()
	wantProps := map[string][]string{
		"inspect_wallet":  {"actor", "taskId", "authorizationMode"},
		"delegate_grant":  {"issuerActor", "subjectActor", "subjectDid", "parentGrantId", "grantId", "taskId", "authorizationMode", "maxAmountMinor", "remainingDepth", "expiresInSeconds"},
		"replace_grant":   {"issuerActor", "oldGrantId", "newSubjectActor", "newSubjectDid", "newGrantId", "maxAmountMinor", "remainingDepth", "expiresInSeconds", "reason"},
		"request_quote":   {"actor", "grantId", "taskId", "authorizationMode", "productId", "quantity", "idempotencyKey", "blockHeight"},
		"create_order":    {"actor", "grantId", "taskId", "authorizationMode", "quoteId", "productId", "quantity", "amountMinor", "currency", "idempotencyKey", "blockHeight"},
		"reconcile_order": {"actor", "taskId", "idempotencyKey", "caseId", "action"},
	}

	gotNames := make([]string, 0, len(tools))
	for _, tool := range tools {
		gotNames = append(gotNames, tool.Name)
		expected, ok := wantProps[tool.Name]
		require.True(t, ok, "unexpected tool %q", tool.Name)
		require.NotNil(t, tool.InputSchema, "tool %s missing InputSchema", tool.Name)

		schemaRaw, err := json.Marshal(tool.InputSchema)
		require.NoError(t, err)
		var schema struct {
			Type       string         `json:"type"`
			Properties map[string]any `json:"properties"`
		}
		require.NoError(t, json.Unmarshal(schemaRaw, &schema))
		assert.Equal(t, "object", schema.Type, "tool %s schema type", tool.Name)
		for _, prop := range expected {
			_, exists := schema.Properties[prop]
			assert.True(t, exists, "tool %s missing JSON schema property %q", tool.Name, prop)
		}
	}

	assert.ElementsMatch(t, []string{
		"inspect_wallet",
		"delegate_grant",
		"replace_grant",
		"request_quote",
		"create_order",
		"reconcile_order",
	}, gotNames)
}

func runFullSixToolWorkflow(t *testing.T, label string, fx *testFixture, sess *sdkmcp.ClientSession) {
	t.Helper()
	ctx := t.Context()

	listed, err := sess.ListTools(ctx, nil)
	require.NoError(t, err)
	verifySixToolSchemas(t, listed.Tools)

	callTool := func(name string, args map[string]any, dst any) {
		t.Helper()
		res, cErr := sess.CallTool(ctx, &sdkmcp.CallToolParams{Name: name, Arguments: args})
		require.NoError(t, cErr)
		require.False(t, res.IsError, "%s tool %s returned error: %+v", label, name, res.Content)

		contentRaw, mErr := json.Marshal(res.Content)
		require.NoError(t, mErr)
		assertNoSecretLeaks(t, label+" content "+name, string(contentRaw), fx.secrets)

		raw, mErr := json.Marshal(res.StructuredContent)
		require.NoError(t, mErr)
		assertNoSecretLeaks(t, label+" structured "+name, string(raw), fx.secrets)
		require.NoError(t, json.Unmarshal(raw, dst))
	}

	// 1. inspect_wallet shows A1's G1 grant.
	var insp wallet.InspectWalletOutput
	callTool("inspect_wallet", map[string]any{"actor": "A1"}, &insp)
	require.Len(t, insp.Grants, 1)
	assert.Equal(t, fx.g1ID, insp.Grants[0].GrantID)

	// 2. delegate_grant issues narrowed G2 to B1.
	g2ID := protocol.DigestBytes([]byte("mcp-g2-b1-" + label))
	var del wallet.DelegateGrantOutput
	callTool("delegate_grant", map[string]any{
		"issuerActor": "A1", "subjectActor": "B1", "parentGrantId": fx.g1ID, "grantId": g2ID,
		"taskId": fx.taskID, "authorizationMode": protocol.ModeBuyerMandate,
		"maxAmountMinor": 100000, "remainingDepth": 0,
	}, &del)
	assert.True(t, del.Anchored)
	assert.Equal(t, g2ID, del.Grant.GrantID)
	assert.Equal(t, fx.didB1, del.Grant.GranteeDID)
	assert.Equal(t, int64(100000), del.Grant.MaxAmountMinor)

	// 3. request_quote obtains binding supplier quote.
	var qB1 wallet.RequestQuoteOutput
	callTool("request_quote", map[string]any{
		"actor": "B1", "grantId": g2ID, "taskId": fx.taskID,
		"authorizationMode": protocol.ModeBuyerMandate, "productId": "urn:grad:product:P1", "quantity": 1,
	}, &qB1)
	assert.Equal(t, "ALLOW", qB1.Decision)
	assert.NotEmpty(t, qB1.QuoteID)
	assert.Equal(t, int64(80000), qB1.TotalAmountMinor)

	// 4. create_order succeeds within ceiling and denies above ceiling.
	var ordOK wallet.CreateOrderOutput
	callTool("create_order", map[string]any{
		"actor": "B1", "grantId": g2ID, "taskId": fx.taskID,
		"authorizationMode": protocol.ModeBuyerMandate, "quoteId": qB1.QuoteID,
		"amountMinor": 80000, "idempotencyKey": "mcp-ok-" + label,
	}, &ordOK)
	assert.Equal(t, "ALLOW", ordOK.Decision)
	assert.Equal(t, wallet.ActionStatusCompleted, ordOK.ActionStatus)
	assert.NotEmpty(t, ordOK.OrderID)

	var ordOver wallet.CreateOrderOutput
	callTool("create_order", map[string]any{
		"actor": "B1", "grantId": g2ID, "taskId": fx.taskID,
		"authorizationMode": protocol.ModeBuyerMandate, "quoteId": qB1.QuoteID,
		"amountMinor": 120000, "idempotencyKey": "mcp-over-" + label,
	}, &ordOver)
	assert.Equal(t, "DENY", ordOver.Decision)
	assert.Equal(t, protocol.ErrCodeAmountLimitExceeded, ordOver.ErrorCode)
	assert.Equal(t, wallet.ActionStatusFailed, ordOver.ActionStatus)

	// 5. replace_grant revokes G2 and delivers G2' to B2.
	g2PrimeID := protocol.DigestBytes([]byte("mcp-g2-b2-" + label))
	var rep wallet.ReplaceGrantOutput
	callTool("replace_grant", map[string]any{
		"issuerActor": "A1", "oldGrantId": g2ID, "newSubjectActor": "B2", "newGrantId": g2PrimeID,
		"maxAmountMinor": 100000, "remainingDepth": 0, "reason": "failover to B2",
	}, &rep)
	assert.Equal(t, g2ID, rep.RevokedGrantID)
	assert.Equal(t, g2PrimeID, rep.ReplacementGrant.GrantID)
	assert.Equal(t, fx.didB2, rep.ReplacementGrant.GranteeDID)
	assert.True(t, rep.Anchored)

	// 6. B2 gets quote, hits simulated post-commit 500, and reconciles via reconcile_order.
	var qB2 wallet.RequestQuoteOutput
	callTool("request_quote", map[string]any{
		"actor": "B2", "grantId": g2PrimeID, "taskId": fx.taskID,
		"authorizationMode": protocol.ModeBuyerMandate, "productId": "urn:grad:product:P1", "quantity": 1,
	}, &qB2)
	require.Equal(t, "ALLOW", qB2.Decision)

	lostKey := "mcp-lost-b2-" + label
	fx.gw.mu.Lock()
	fx.gw.failExecuteOnce[lostKey] = true
	fx.gw.mu.Unlock()

	var lostOrd wallet.CreateOrderOutput
	callTool("create_order", map[string]any{
		"actor": "B2", "grantId": g2PrimeID, "taskId": fx.taskID,
		"authorizationMode": protocol.ModeBuyerMandate, "quoteId": qB2.QuoteID,
		"amountMinor": 80000, "idempotencyKey": lostKey,
	}, &lostOrd)
	assert.Equal(t, "UNKNOWN", lostOrd.Decision)
	assert.Equal(t, wallet.ActionStatusOutcomeUnknown, lostOrd.ActionStatus)
	assert.Equal(t, int64(1), lostOrd.SendRevision)

	var recOut wallet.ReconcileOrderOutput
	callTool("reconcile_order", map[string]any{
		"actor": "B2", "taskId": fx.taskID, "idempotencyKey": lostKey,
	}, &recOut)
	assert.Equal(t, "CREATED", recOut.Outcome)
	assert.Equal(t, "MATCHED", recOut.HistoricalStatus)
	assert.Equal(t, int64(2), recOut.SendRevision)
	assert.Equal(t, wallet.ActionStatusReconciled, recOut.ActionStatus)
	assert.NotEmpty(t, recOut.OrderID)
}

func TestNewMCPServerInMemoryAndPipeTransports(t *testing.T) {
	t.Run("InMemory", func(t *testing.T) {
		fx := newTestFixture(t)
		sess := connectInMemory(t, svcmcp.NewMCPServer(fx.wallet))
		runFullSixToolWorkflow(t, "inmem", fx, sess)
	})

	t.Run("IOPipe", func(t *testing.T) {
		fx := newTestFixture(t)
		sess := connectOverIOPipe(t, svcmcp.NewMCPServer(fx.wallet))
		runFullSixToolWorkflow(t, "pipe", fx, sess)
	})

	t.Run("NilServerRejected", func(t *testing.T) {
		err := svcmcp.RunMCPServer(t.Context(), nil, nil, nil)
		require.Error(t, err)
	})
}

func assertSanitizedErrorEnvelope(t *testing.T, res *sdkmcp.CallToolResult, wantCode string, secrets []string) {
	t.Helper()
	require.True(t, res.IsError, "expected tool error response")
	require.Len(t, res.Content, 1)
	txt, ok := res.Content[0].(*sdkmcp.TextContent)
	require.True(t, ok, "expected TextContent error envelope")
	assertNoSecretLeaks(t, "bound error envelope", txt.Text, secrets)

	var env map[string]string
	require.NoError(t, json.Unmarshal([]byte(txt.Text), &env))
	assert.Equal(t, map[string]string{
		"code":    wantCode,
		"message": "workbench operation declined",
	}, env)
}

func listToolNames(t *testing.T, sess *sdkmcp.ClientSession) []string {
	t.Helper()
	listed, err := sess.ListTools(t.Context(), nil)
	require.NoError(t, err)
	names := make([]string, 0, len(listed.Tools))
	for _, tool := range listed.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func TestNewBoundMCPServerStageRestrictionsAndSanitizedErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		connect func(*testing.T, *sdkmcp.Server) *sdkmcp.ClientSession
	}{
		{name: "InMemory", connect: connectInMemory},
		{name: "IOPipe", connect: connectOverIOPipe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newTestFixture(t)
			ctx := t.Context()
			const productID = "urn:grad:product:P1"
			const mode = protocol.ModeBuyerMandate
			g2ID := protocol.DigestBytes([]byte("bound-mcp-g2-" + tc.name))

			// StageDelegate: ONLY inspect_wallet and delegate_grant.
			delegateOps, err := wallet.NewBoundOperations(fx.wallet, wallet.ExecutionBinding{
				DeploymentID: fx.depID, DomainID: "A", Actor: "A1", DID: fx.didA1, TaskID: fx.taskID,
				Mode: mode, GrantID: fx.g1ID, Stage: wallet.StageDelegate, RunID: "run-del",
				SubjectDID: fx.didB1, SubjectActor: "B1", ChildGrantID: g2ID,
			})
			require.NoError(t, err)

			delegateSess := tc.connect(t, svcmcp.NewBoundMCPServer(delegateOps))
			assert.ElementsMatch(t, []string{"inspect_wallet", "delegate_grant"}, listToolNames(t, delegateSess))

			// Calling out-of-stage tools fails at MCP layer.
			for _, forbidden := range []string{"replace_grant", "request_quote", "create_order", "reconcile_order"} {
				_, callErr := delegateSess.CallTool(ctx, &sdkmcp.CallToolParams{Name: forbidden, Arguments: map[string]any{}})
				require.Error(t, callErr, "StageDelegate must not expose %s", forbidden)
			}

			goodDelegate := wallet.DelegateGrantInput{
				IssuerActor: "A1", SubjectActor: "B1", ParentGrantID: fx.g1ID, GrantID: g2ID,
				TaskID: fx.taskID, AuthorizationMode: mode, MaxAmountMinor: 100000,
			}
			for label, mutate := range map[string]func(*wallet.DelegateGrantInput){
				"signer":    func(in *wallet.DelegateGrantInput) { in.IssuerActor = "B1" },
				"task":      func(in *wallet.DelegateGrantInput) { in.TaskID = "other" },
				"mode":      func(in *wallet.DelegateGrantInput) { in.AuthorizationMode = protocol.ModeResourcePreauthorized },
				"grant":     func(in *wallet.DelegateGrantInput) { in.ParentGrantID = "other" },
				"recipient": func(in *wallet.DelegateGrantInput) { in.SubjectDID = fx.didB2 },
			} {
				t.Run("DelegateMismatch_"+label, func(t *testing.T) {
					bad := goodDelegate
					mutate(&bad)
					res, cErr := delegateSess.CallTool(ctx, &sdkmcp.CallToolParams{Name: "delegate_grant", Arguments: bad})
					require.NoError(t, cErr)
					assertSanitizedErrorEnvelope(t, res, protocol.ErrCodeBindingMismatch, fx.secrets)
				})
			}

			// Invalid schema (maxAmountMinor <= 0) also returns sanitized error envelope.
			invalidAmt := goodDelegate
			invalidAmt.MaxAmountMinor = 0
			res, err := delegateSess.CallTool(ctx, &sdkmcp.CallToolParams{Name: "delegate_grant", Arguments: invalidAmt})
			require.NoError(t, err)
			assertSanitizedErrorEnvelope(t, res, protocol.ErrCodeInvalidSchema, fx.secrets)

			// Valid inspect_wallet and delegate_grant succeed.
			res, err = delegateSess.CallTool(ctx, &sdkmcp.CallToolParams{Name: "inspect_wallet", Arguments: map[string]any{"actor": "A1"}})
			require.NoError(t, err)
			require.False(t, res.IsError)
			raw, err := json.Marshal(res.StructuredContent)
			require.NoError(t, err)
			assertNoSecretLeaks(t, "bound delegate inspect_wallet", string(raw), fx.secrets)

			res, err = delegateSess.CallTool(ctx, &sdkmcp.CallToolParams{Name: "delegate_grant", Arguments: goodDelegate})
			require.NoError(t, err)
			require.False(t, res.IsError)
			raw, err = json.Marshal(res.StructuredContent)
			require.NoError(t, err)
			assertNoSecretLeaks(t, "bound delegate_grant", string(raw), fx.secrets)
			var issued wallet.DelegateGrantOutput
			require.NoError(t, json.Unmarshal(raw, &issued))
			assert.True(t, issued.Anchored)
			assert.Equal(t, g2ID, issued.Grant.GrantID)

			// StageExecute: ONLY inspect_wallet, request_quote, create_order, reconcile_order.
			execOps, err := wallet.NewBoundOperations(fx.wallet, wallet.ExecutionBinding{
				DeploymentID: fx.depID, DomainID: "A", Actor: "B1", DID: fx.didB1, TaskID: fx.taskID,
				Mode: mode, GrantID: g2ID, Stage: wallet.StageExecute, RunID: "run-exec",
				ProductID: productID, Quantity: 1,
			})
			require.NoError(t, err)

			execSess := tc.connect(t, svcmcp.NewBoundMCPServer(execOps))
			assert.ElementsMatch(t, []string{
				"inspect_wallet", "request_quote", "create_order", "reconcile_order",
			}, listToolNames(t, execSess))

			for _, forbidden := range []string{"delegate_grant", "replace_grant"} {
				_, callErr := execSess.CallTool(ctx, &sdkmcp.CallToolParams{Name: forbidden, Arguments: map[string]any{}})
				require.Error(t, callErr, "StageExecute must not expose %s", forbidden)
			}

			// Mismatched product on request_quote returns sanitized BINDING_MISMATCH envelope.
			res, err = execSess.CallTool(ctx, &sdkmcp.CallToolParams{
				Name: "request_quote",
				Arguments: wallet.RequestQuoteInput{
					Actor: "B1", GrantID: g2ID, TaskID: fx.taskID, AuthorizationMode: mode,
					ProductID: "urn:grad:product:WRONG", Quantity: 1,
				},
			})
			require.NoError(t, err)
			assertSanitizedErrorEnvelope(t, res, protocol.ErrCodeBindingMismatch, fx.secrets)

			// Valid request_quote succeeds.
			res, err = execSess.CallTool(ctx, &sdkmcp.CallToolParams{
				Name: "request_quote",
				Arguments: wallet.RequestQuoteInput{
					Actor: "B1", TaskID: fx.taskID, AuthorizationMode: mode, ProductID: productID, Quantity: 1,
				},
			})
			require.NoError(t, err)
			require.False(t, res.IsError)
			raw, err = json.Marshal(res.StructuredContent)
			require.NoError(t, err)
			assertNoSecretLeaks(t, "bound request_quote", string(raw), fx.secrets)
			var quote wallet.RequestQuoteOutput
			require.NoError(t, json.Unmarshal(raw, &quote))
			require.Equal(t, "ALLOW", quote.Decision)

			// Tampered amount on create_order returns sanitized BINDING_MISMATCH envelope.
			res, err = execSess.CallTool(ctx, &sdkmcp.CallToolParams{
				Name: "create_order",
				Arguments: wallet.CreateOrderInput{
					Actor: "B1", TaskID: fx.taskID, QuoteID: quote.QuoteID, AuthorizationMode: mode,
					AmountMinor: quote.TotalAmountMinor + 1, IdempotencyKey: execOps.OrderKey(),
				},
			})
			require.NoError(t, err)
			assertSanitizedErrorEnvelope(t, res, protocol.ErrCodeBindingMismatch, fx.secrets)

			// Simulate post-commit 500 on create_order, then reconcile via reconcile_order over MCP.
			fx.gw.mu.Lock()
			fx.gw.failExecuteOnce[execOps.OrderKey()] = true
			fx.gw.mu.Unlock()

			orderIn := wallet.CreateOrderInput{
				Actor: "B1", TaskID: fx.taskID, QuoteID: quote.QuoteID, AuthorizationMode: mode,
				AmountMinor: quote.TotalAmountMinor, IdempotencyKey: execOps.OrderKey(),
			}
			res, err = execSess.CallTool(ctx, &sdkmcp.CallToolParams{Name: "create_order", Arguments: orderIn})
			require.NoError(t, err)
			require.False(t, res.IsError)
			raw, err = json.Marshal(res.StructuredContent)
			require.NoError(t, err)
			assertNoSecretLeaks(t, "bound create_order unknown", string(raw), fx.secrets)
			var unk wallet.CreateOrderOutput
			require.NoError(t, json.Unmarshal(raw, &unk))
			assert.Equal(t, "UNKNOWN", unk.Decision)
			assert.Equal(t, wallet.ActionStatusOutcomeUnknown, unk.ActionStatus)

			res, err = execSess.CallTool(ctx, &sdkmcp.CallToolParams{
				Name: "reconcile_order",
				Arguments: wallet.ReconcileOrderInput{
					Actor: "B1", TaskID: fx.taskID, IdempotencyKey: execOps.OrderKey(),
				},
			})
			require.NoError(t, err)
			require.False(t, res.IsError)
			raw, err = json.Marshal(res.StructuredContent)
			require.NoError(t, err)
			assertNoSecretLeaks(t, "bound reconcile_order", string(raw), fx.secrets)
			var rec wallet.ReconcileOrderOutput
			require.NoError(t, json.Unmarshal(raw, &rec))
			assert.Equal(t, "CREATED", rec.Outcome)
			assert.Equal(t, "MATCHED", rec.HistoricalStatus)
			assert.Equal(t, wallet.ActionStatusReconciled, rec.ActionStatus)
			assert.NotEmpty(t, rec.OrderID)

			// Re-calling create_order after reconciliation returns idempotent ALLOW matching direct BoundOperations.
			direct, err := execOps.CreateOrder(ctx, orderIn)
			require.NoError(t, err)
			res, err = execSess.CallTool(ctx, &sdkmcp.CallToolParams{Name: "create_order", Arguments: orderIn})
			require.NoError(t, err)
			require.False(t, res.IsError)
			raw, err = json.Marshal(res.StructuredContent)
			require.NoError(t, err)
			var viaMCP wallet.CreateOrderOutput
			require.NoError(t, json.Unmarshal(raw, &viaMCP))
			assert.Equal(t, direct, viaMCP)
		})
	}
}
