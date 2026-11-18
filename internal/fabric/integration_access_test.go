package fabric

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/policy"
	"graduation-design/internal/protocol"

	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"github.com/jackc/pgx/v5"
)

type accessVerificationEvidence struct {
	DeploymentID          string         `json:"deploymentId"`
	RunID                 string         `json:"runId"`
	RegistrationAndSync   map[string]any `json:"registrationAndMaterialDelivery,omitempty"`
	QuoteAndIdempotency   map[string]any `json:"directAccessQuoteAndIdempotency,omitempty"`
	WrongLeafKeyRejected  map[string]any `json:"wrongLeafKeyRejected,omitempty"`
	ProbeExpiryStateStale map[string]any `json:"probeExpiryStateStale,omitempty"`
	PostLockBlocked       map[string]any `json:"postLockBlockedNoQuote,omitempty"`
	ExactSecondDeadline   map[string]any `json:"exactSecondDeadlineRejection,omitempty"`
}

var (
	accessEvidenceMu  sync.Mutex
	accessEvidenceMap = map[string]*accessVerificationEvidence{}
)

func (a acceptance) recordAccessEvidence(fn func(ev *accessVerificationEvidence)) error {
	accessEvidenceMu.Lock()
	defer accessEvidenceMu.Unlock()
	ev, ok := accessEvidenceMap[a.id]
	if !ok {
		ev = &accessVerificationEvidence{
			DeploymentID: a.d.DeploymentID,
			RunID:        a.id,
		}
		accessEvidenceMap[a.id] = ev
	}
	fn(ev)
	return writeJSON(filepath.Join(a.dir, "direct-access.json"), ev)
}

func (a acceptance) directAccessContextVersion() (int64, error) {
	var ver int64
	err := a.j.db.QueryRow(a.ctx,
		`SELECT context_version FROM trusted_contexts WHERE deployment_id=$1 AND task_id=$2`,
		a.d.DeploymentID, a.f.Task.ID,
	).Scan(&ver)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return ver, err
}

func (a acceptance) newControlledDIDResolver() (*protocol.DIDWebServer, *protocol.DIDWebResolver, error) {
	return a.instance.StartRegistryDIDResolver(a.d)
}

func (a acceptance) newDirectAccessServer(
	sp *StateProvider,
	resolver *protocol.DIDWebResolver,
	policyDeadline *int64,
	nowFn func() time.Time,
) (*gateway.Server, *policy.VerifiedBundle, error) {
	if err := gateway.EnsureSchema(a.ctx, a.j.db, a.d.DeploymentID, "urn:grad:supplier:C"); err != nil {
		return nil, nil, err
	}
	cDID := a.f.Identities["C"].ID
	files, dig, err := policy.BuildDefaultBundle(a.d.DeploymentID, cDID, policy.DefaultPolicyVersion, a.d.Bootstrap.Root, policyDeadline)
	if err != nil {
		return nil, nil, err
	}
	bundle, err := policy.VerifyAndLoadBundle(files, a.d.DeploymentID, cDID, a.d.Bootstrap.Root, dig)
	if err != nil {
		return nil, nil, err
	}
	srv, err := gateway.NewServer(gateway.Config{
		DB:           a.j.db,
		State:        sp.GatewayAdapter(),
		Delivery:     NewDeliveryService(a.j.db),
		DIDs:         resolver,
		Policy:       bundle,
		DeploymentID: a.d.DeploymentID,
		ServiceDID:   cDID,
		Audience:     "https://c.local",
		SupplierID:   "urn:grad:supplier:C",
		NowFn:        nowFn,
	})
	if err != nil {
		return nil, nil, err
	}
	return srv, bundle, nil
}

func (a acceptance) loadDirectAccessMaterials() (
	uPriv *ecdsa.PrivateKey,
	uPres string,
	cPres string,
	certAJWS string,
	certCJWS string,
	g0JWS string,
	err error,
) {
	uPriv, err = loadECPrivateKeyPEM(a.instance.privatePath("app", "U.key.pem"))
	if err != nil {
		return
	}
	uBytes, err := os.ReadFile(a.instance.registrySubPath("credentials", "U.sdjwt"))
	if err != nil {
		return
	}
	cBytes, err := os.ReadFile(a.instance.registrySubPath("credentials", "C.sdjwt"))
	if err != nil {
		return
	}
	certABytes, err := os.ReadFile(a.instance.registrySubPath("certifications", "A.jws"))
	if err != nil {
		return
	}
	certCBytes, err := os.ReadFile(a.instance.registrySubPath("certifications", "C.jws"))
	if err != nil {
		return
	}
	g0Bytes, err := os.ReadFile(a.instance.registrySubPath("grants", "G0.jws"))
	if err != nil {
		return
	}
	return uPriv, string(uBytes), string(cBytes), string(certABytes), string(certCBytes), string(g0Bytes), nil
}

func (a acceptance) buildQuoteRequest(idempotencyKey string, qty int64) (protocol.AccessRequest, string, error) {
	req := protocol.AccessRequest{
		SchemaVersion:     api.Schema,
		DeploymentID:      a.d.DeploymentID,
		Actor:             a.f.Identities["U"].ID,
		PrincipalDomain:   "A",
		AuthorizationMode: api.RP,
		TaskID:            a.f.Task.ID,
		Audience:          "https://c.local",
		Resource:          "urn:grad:resource:C:quotes",
		Action:            "quote.read",
		SupplierID:        "urn:grad:supplier:C",
		QuoteID:           nil,
		ProductID:         gateway.DefaultProductID,
		Quantity:          qty,
		Currency:          gateway.DefaultCurrency,
		AmountMinor:       0,
		IdempotencyKey:    idempotencyKey,
	}
	reqHash, err := req.Hash(false)
	return req, reqHash, err
}

func (a acceptance) buildQuoteExecutePackage(
	idempotencyKey string,
	qty int64,
	chal gateway.ChallengeResponse,
	uPres, cPres, certAJWS, certCJWS, g0JWS string,
	leafPriv *ecdsa.PrivateKey,
	iat int64,
) (protocol.AccessEvidencePackage, protocol.AccessRequest, string, error) {
	req, reqHash, err := a.buildQuoteRequest(idempotencyKey, qty)
	if err != nil {
		return protocol.AccessEvidencePackage{}, req, "", err
	}
	iaIss := a.f.Domains["A"].Issuers[0].ID
	icIss := a.f.Domains["C"].Issuers[0].ID
	tps := []protocol.TrustPathEntry{
		{Issuer: iaIss, DomainCertification: certAJWS},
		{Issuer: icIss, DomainCertification: certCJWS},
	}
	if iaIss > icIss {
		tps[0], tps[1] = tps[1], tps[0]
	}
	pkg := protocol.AccessEvidencePackage{
		Request:  req,
		TaskSpec: a.f.TaskSpec,
		AncestorCredentials: []protocol.AncestorCredential{
			{CredentialID: a.f.Credentials["C"].ID, Presentation: cPres},
		},
		Grants:     []string{g0JWS},
		TrustPaths: tps,
	}
	_, _, err = protocol.AssembleAccessEvidencePackage(&pkg, uPres, a.f.Identities["U"].KeyID, leafPriv, protocol.ChallengeContext{
		ChallengeID: chal.ChallengeID,
		Nonce:       chal.Nonce,
		Audience:    chal.Audience,
		IssuedAt:    chal.IssuedAt,
		ExpiresAt:   chal.ExpiresAt,
	}, iat, false)
	if err != nil {
		return protocol.AccessEvidencePackage{}, req, "", err
	}
	return pkg, req, reqHash, nil
}

func gatewayReqChallenge(srv http.Handler, actor, taskID, reqHash string) (gateway.ChallengeResponse, error) {
	body, _ := json.Marshal(gateway.ChallengeRequest{Actor: actor, TaskID: taskID, RequestHash: reqHash})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/challenges", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		return gateway.ChallengeResponse{}, fmt.Errorf("POST /v1/auth/challenges HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var out gateway.ChallengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		return gateway.ChallengeResponse{}, err
	}
	return out, nil
}

func gatewaySetContext(srv http.Handler, taskID string, expectedVer int64, observedAt int64, risk string, deadline int64) (gateway.ContextResponse, error) {
	body, _ := json.Marshal(gateway.ContextUpdateRequest{
		ExpectedContextVersion: expectedVer,
		SourceID:               "ctx-verifier-c",
		ObservedAt:             observedAt,
		RiskLevel:              risk,
		AccessDeadline:         deadline,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/contexts/"+taskID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return gateway.ContextResponse{}, fmt.Errorf("POST /v1/contexts HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var out gateway.ContextResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		return gateway.ContextResponse{}, err
	}
	return out, nil
}

func gatewayPostExecute(srv http.Handler, pkg protocol.AccessEvidencePackage) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(pkg)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/access/execute", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(rec, req)
	return rec
}

func (a acceptance) registrationAndMaterialDelivery() error {
	// 1. Verify PA and C-service identities/credentials are ACTIVE on live peer.
	paID, ok := a.f.Identities["PA"]
	if !ok {
		return fmt.Errorf("PA fixture identity missing")
	}
	livePA, err := ledgerRecord[api.Identity](a.ctx, a.p, "identity", paID.ID)
	if err != nil {
		return fmt.Errorf("live PA identity lookup failed: %w", err)
	}
	if livePA.Status != api.Active || livePA.Domain != "A" {
		return fmt.Errorf("unexpected PA ledger status/domain: %+v", livePA)
	}
	if paCred, ok := a.f.Credentials["PA"]; ok {
		liveCred, err := ledgerRecord[api.Credential](a.ctx, a.p, "credential", paCred.ID)
		if err != nil || liveCred.Status != api.Active {
			return fmt.Errorf("live PA credential inactive/missing: %v", err)
		}
	}

	// 2. Verify domain certifications & G0 root grant are synced in outbox/receipt tables.
	ds := NewDeliveryService(a.j.db)
	for _, domID := range []string{"A", "C"} {
		cert := a.f.Certifications[domID].Certification
		if _, err := ds.HasSyncedCertification(a.ctx, a.d.DeploymentID, domID, cert.ID, cert.Digest); err != nil {
			return fmt.Errorf("domain %s certification sync missing: %w", domID, err)
		}
	}
	var walletReceiptDigest string
	if err := a.j.db.QueryRow(a.ctx,
		`SELECT package_digest FROM wallet_receipts WHERE deployment_id=$1 AND recipient=$2 AND grant_id=$3`,
		a.d.DeploymentID, a.f.Identities["U"].ID, a.f.G0.ID,
	).Scan(&walletReceiptDigest); err != nil {
		return fmt.Errorf("U wallet receipt for G0 missing: %w", err)
	}

	// 3. Exercise RegistrationCoordinator dual-proof validation (negative cases keep challenge unconsumed, positive consumes).
	rc := NewRegistrationCoordinator(a.j.db)
	_, aMgmt, aMSPDir, err := a.instance.role("registrarA")
	if err != nil {
		return err
	}
	aCertFiles, err := filepath.Glob(filepath.Join(aMSPDir, "signcerts", "*-cert.pem"))
	if err != nil || len(aCertFiles) != 1 {
		return fmt.Errorf("expected 1 signcert for role registrarA, got %v %v", aCertFiles, err)
	}
	aCertPEM, err := os.ReadFile(aCertFiles[0])
	if err != nil {
		return err
	}
	aCert, err := identity.CertificateFromPEM(aCertPEM)
	if err != nil {
		return err
	}
	aKeyFiles, err := filepath.Glob(filepath.Join(aMSPDir, "keystore", "*"))
	if err != nil || len(aKeyFiles) != 1 {
		return fmt.Errorf("expected 1 keystore file for role registrarA, got %v %v", aKeyFiles, err)
	}
	aMgmtPriv, err := loadECPrivateKeyPEM(aKeyFiles[0])
	if err != nil {
		return err
	}

	_, uMgmt, uMSPDir, err := a.instance.role("U")
	if err != nil {
		return err
	}
	_ = uMgmt
	uKeyFiles, err := filepath.Glob(filepath.Join(uMSPDir, "keystore", "*"))
	if err != nil || len(uKeyFiles) != 1 {
		return fmt.Errorf("expected 1 keystore file for role U, got %v %v", uKeyFiles, err)
	}
	uMgmtPriv, err := loadECPrivateKeyPEM(uKeyFiles[0])
	if err != nil {
		return err
	}

	candDID := "did:web:a.local:verify-cand-" + a.id
	appPriv, appPubHex, err := protocol.GenerateP256KeyPair()
	if err != nil {
		return err
	}
	doc, err := protocol.NewDIDDocument(candDID, candDID+"#key-1", appPubHex, protocol.KeyPurposeAuthentication)
	if err != nil {
		return err
	}
	docBytes, err := protocol.MarshalJCS(doc)
	if err != nil {
		return err
	}
	docDig := protocol.DigestBytes(docBytes)

	depBind := protocol.DeploymentBinding{
		ChannelID:     a.d.ChannelID,
		GenesisHash:   a.d.GenesisHash,
		InstanceID:    a.d.InstanceID,
		Purpose:       protocol.DeploymentPurpose,
		RegistryName:  a.d.RegistryName,
		SchemaVersion: a.d.SchemaVersion,
	}
	nowSec := time.Now().UTC().Unix()
	chal, _, err := rc.IssueRegistrationChallenge(a.ctx, depBind, IssueChallengeRequest{
		DomainID:          "A",
		SubjectID:         candDID,
		AppKeyID:          candDID + "#key-1",
		AppKeyVersion:     1,
		AppPublicKey:      appPubHex,
		DIDDocumentDigest: docDig,
		AccountCommitment: api.Digest([]byte("grad-auth-account:" + a.d.DeploymentID + ":" + candDID)),
		MSPID:             aMgmt.MSPID,
		CertificateSha256: api.Digest(aCert.Raw),
		IssuedAt:          nowSec,
		TTLSeconds:        120,
	})
	if err != nil {
		return fmt.Errorf("IssueRegistrationChallenge: %w", err)
	}
	// Sign management proof with U's key (wrong signature vs aCert expected for challenge) -> must fail without consuming challenge.
	wrongBundle, err := protocol.SignManagementDualProofBundle(depBind, *chal, aCert.Raw, aMgmtPriv, appPriv)
	if err != nil {
		return err
	}
	chalJCS, err := protocol.MarshalJCS(*chal)
	if err != nil {
		return err
	}
	chalSum := sha256.Sum256(chalJCS)
	wrongSigDER, err := ecdsa.SignASN1(rand.Reader, uMgmtPriv, chalSum[:])
	if err != nil {
		return err
	}
	wrongBundle.ManagementSignatureDER = base64.RawURLEncoding.EncodeToString(wrongSigDER)
	if err := rc.AcceptRegistrationBundle(a.ctx, "reg-wrong-"+a.id, a.d.DeploymentID+":reg-wrong-"+a.id, aMgmt, wrongBundle, aMgmt.MSPID, []*x509.Certificate{aCert}, docBytes, nowSec, func(context.Context) (*SubmitResult, error) {
		return nil, fmt.Errorf("should not submit invalid registration bundle")
	}); err == nil {
		return fmt.Errorf("expected wrong management key registration bundle to fail")
	}
	var consumed bool
	if err := a.j.db.QueryRow(a.ctx, `SELECT consumed FROM registration_challenges WHERE challenge_id=$1`, chal.ChallengeID).Scan(&consumed); err != nil {
		return err
	}
	if consumed {
		return fmt.Errorf("registration challenge must remain unconsumed after failed proof")
	}

	// Positive dual-proof registration bundle with matching A management key -> consumes challenge cleanly.
	validBundle, err := protocol.SignManagementDualProofBundle(depBind, *chal, aCert.Raw, aMgmtPriv, appPriv)
	if err != nil {
		return err
	}
	if err := rc.AcceptRegistrationBundle(a.ctx, "reg-ok-"+a.id, a.d.DeploymentID+":reg-ok-"+a.id, aMgmt, validBundle, aMgmt.MSPID, []*x509.Certificate{aCert}, docBytes, nowSec, func(context.Context) (*SubmitResult, error) {
		return &SubmitResult{
			Method:    "RegisterIdentity",
			TxID:      "tx-reg-" + a.id,
			BlockNo:   1,
			BlockHash: a.d.GenesisHash,
		}, nil
	}); err != nil {
		return fmt.Errorf("expected valid dual-proof registration bundle to succeed: %w", err)
	}

	return a.recordAccessEvidence(func(ev *accessVerificationEvidence) {
		ev.RegistrationAndSync = map[string]any{
			"paSubjectId":             livePA.ID,
			"g0WalletReceiptDigest":   walletReceiptDigest,
			"registrationChallengeId": chal.ChallengeID,
			"invalidProofConsumed":    consumed,
		}
	})
}

func (a acceptance) directAccessQuoteAndIdempotency() error {
	rt := newRuntime(a)
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()
	waitCtx, cancel := context.WithTimeout(a.ctx, 12*time.Second)
	_, err = waitOnline(waitCtx, rt, a.f.G0.ID)
	cancel()
	if err != nil {
		return err
	}

	didSrv, resolver, err := a.newControlledDIDResolver()
	if err != nil {
		return err
	}
	defer didSrv.Close()

	sp := NewStateProvider(a.j.db, a.d, rt)
	srv, bundle, err := a.newDirectAccessServer(sp, resolver, nil, nil)
	if err != nil {
		return err
	}

	// Ensure READY via /v1/health/ready.
	readyRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(readyRec, httptest.NewRequest(http.MethodGet, "/v1/health/ready", nil))
	if readyRec.Code != http.StatusOK {
		return fmt.Errorf("GET /v1/health/ready returned %d: %s", readyRec.Code, readyRec.Body.String())
	}

	curVer, err := a.directAccessContextVersion()
	if err != nil {
		return err
	}
	nowUnix := time.Now().UTC().Unix()
	ctxRes, err := gatewaySetContext(srv.Handler(), a.f.Task.ID, curVer, nowUnix-1, "NORMAL", a.f.Task.Interval.EXP)
	if err != nil {
		return err
	}

	uPriv, uPres, cPres, certAJWS, certCJWS, g0JWS, err := a.loadDirectAccessMaterials()
	if err != nil {
		return err
	}

	// 1. Quote success (U holding C -> U G0).
	idemKey := "verify-quote-" + a.id
	req1, reqHash1, err := a.buildQuoteRequest(idemKey, 1)
	if err != nil {
		return err
	}
	chal1, err := gatewayReqChallenge(srv.Handler(), req1.Actor, req1.TaskID, reqHash1)
	if err != nil {
		return err
	}
	pkg1, _, _, err := a.buildQuoteExecutePackage(idemKey, 1, chal1, uPres, cPres, certAJWS, certCJWS, g0JWS, uPriv, nowUnix)
	if err != nil {
		return err
	}
	rec1 := gatewayPostExecute(srv.Handler(), pkg1)
	if rec1.Code != http.StatusOK {
		return fmt.Errorf("direct quote execute failed HTTP %d: %s", rec1.Code, rec1.Body.String())
	}
	var out1 gateway.ExecuteResponse
	if err := json.Unmarshal(rec1.Body.Bytes(), &out1); err != nil {
		return err
	}
	if out1.Code != "ALLOW" || out1.Quote == nil || out1.Quote.UnitPriceMinor != 80000 {
		return fmt.Errorf("unexpected quote execute response: %+v", out1)
	}

	// Check consumed challenge, GET /v1/decisions/{id}, and quotes row.
	var consumedAt *int64
	if err := a.j.db.QueryRow(a.ctx, `SELECT consumed_at FROM challenges WHERE deployment_id=$1 AND challenge_id=$2`,
		a.d.DeploymentID, chal1.ChallengeID).Scan(&consumedAt); err != nil || consumedAt == nil {
		return fmt.Errorf("expected challenge %s consumed, got consumedAt=%v err=%v", chal1.ChallengeID, consumedAt, err)
	}
	decRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(decRec, httptest.NewRequest(http.MethodGet, "/v1/decisions/"+out1.DecisionID, nil))
	if decRec.Code != http.StatusOK || !strings.Contains(decRec.Body.String(), out1.Quote.QuoteID) {
		return fmt.Errorf("GET /v1/decisions/%s failed: %d %s", out1.DecisionID, decRec.Code, decRec.Body.String())
	}

	// 2. Same-key same-hash retry with fresh challenge -> returns original quoteId + new decisionId.
	chal2, err := gatewayReqChallenge(srv.Handler(), req1.Actor, req1.TaskID, reqHash1)
	if err != nil {
		return err
	}
	pkg2, _, _, err := a.buildQuoteExecutePackage(idemKey, 1, chal2, uPres, cPres, certAJWS, certCJWS, g0JWS, uPriv, nowUnix)
	if err != nil {
		return err
	}
	rec2 := gatewayPostExecute(srv.Handler(), pkg2)
	if rec2.Code != http.StatusOK {
		return fmt.Errorf("idempotent retry execute failed HTTP %d: %s", rec2.Code, rec2.Body.String())
	}
	var out2 gateway.ExecuteResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &out2); err != nil {
		return err
	}
	if out2.Quote == nil || out2.Quote.QuoteID != out1.Quote.QuoteID || out2.DecisionID == out1.DecisionID {
		return fmt.Errorf("idempotent retry did not preserve quoteId with fresh decisionId: out1=%+v out2=%+v", out1, out2)
	}

	// Preload a conflicting business key; the seeded quote task allows only one request digest per key.
	conflictKey := "verify-conflict-" + a.id
	if _, err := a.j.db.Exec(a.ctx, `INSERT INTO business_keys(
		deployment_id, actor, task_id, action, idempotency_key, request_hash, status, resource_id, decision_id
	) VALUES($1,$2,$3,'quote.read',$4,$5,'COMPLETED','urn:grad:quote:prior','urn:grad:decision:prior')
	ON CONFLICT DO NOTHING`,
		a.d.DeploymentID, a.f.Identities["U"].ID, a.f.Task.ID, conflictKey, strings.Repeat("f", 64),
	); err != nil {
		return err
	}
	creq, chash, err := a.buildQuoteRequest(conflictKey, 1)
	if err != nil {
		return err
	}
	cchal, err := gatewayReqChallenge(srv.Handler(), creq.Actor, creq.TaskID, chash)
	if err != nil {
		return err
	}
	cpkg, _, _, err := a.buildQuoteExecutePackage(conflictKey, 1, cchal, uPres, cPres, certAJWS, certCJWS, g0JWS, uPriv, nowUnix)
	if err != nil {
		return err
	}
	crec := gatewayPostExecute(srv.Handler(), cpkg)
	if crec.Code != http.StatusConflict || !strings.Contains(crec.Body.String(), protocol.ErrCodeIdempotencyConflict) {
		return fmt.Errorf("expected 409 IDEMPOTENCY_CONFLICT, got %d %s", crec.Code, crec.Body.String())
	}

	return a.recordAccessEvidence(func(ev *accessVerificationEvidence) {
		ev.QuoteAndIdempotency = map[string]any{
			"contextVersion":      ctxRes.ContextVersion,
			"policyDigest":        bundle.PolicyDigest,
			"quoteId":             out1.Quote.QuoteID,
			"unitPriceMinor":      out1.Quote.UnitPriceMinor,
			"validUntil":          out1.Quote.ValidUntil,
			"firstDecisionId":     out1.DecisionID,
			"retryDecisionId":     out2.DecisionID,
			"idempotencyConflict": protocol.ErrCodeIdempotencyConflict,
		}
	})
}

func (a acceptance) wrongLeafKeyRejected() error {
	rt := newRuntime(a)
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()
	waitCtx, cancel := context.WithTimeout(a.ctx, 12*time.Second)
	_, err = waitOnline(waitCtx, rt, a.f.G0.ID)
	cancel()
	if err != nil {
		return err
	}
	didSrv, resolver, err := a.newControlledDIDResolver()
	if err != nil {
		return err
	}
	defer didSrv.Close()

	sp := NewStateProvider(a.j.db, a.d, rt)
	srv, _, err := a.newDirectAccessServer(sp, resolver, nil, nil)
	if err != nil {
		return err
	}
	_, uPres, cPres, certAJWS, certCJWS, g0JWS, err := a.loadDirectAccessMaterials()
	if err != nil {
		return err
	}
	wrongPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	nowUnix := time.Now().UTC().Unix()
	idemKey := "verify-wrong-key-" + a.id
	req, reqHash, err := a.buildQuoteRequest(idemKey, 1)
	if err != nil {
		return err
	}
	chal, err := gatewayReqChallenge(srv.Handler(), req.Actor, req.TaskID, reqHash)
	if err != nil {
		return err
	}
	pkg, _, _, err := a.buildQuoteExecutePackage(idemKey, 1, chal, uPres, cPres, certAJWS, certCJWS, g0JWS, wrongPriv, nowUnix)
	if err != nil {
		return err
	}
	rec := gatewayPostExecute(srv.Handler(), pkg)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), protocol.ErrCodeSignatureInvalid) {
		return fmt.Errorf("expected 401 SIGNATURE_INVALID for wrong leaf key, got %d %s", rec.Code, rec.Body.String())
	}
	var consumedAt *int64
	if err := a.j.db.QueryRow(a.ctx, `SELECT consumed_at FROM challenges WHERE deployment_id=$1 AND challenge_id=$2`,
		a.d.DeploymentID, chal.ChallengeID).Scan(&consumedAt); err != nil {
		return err
	}
	if consumedAt != nil {
		return fmt.Errorf("wrong leaf key must not consume challenge %s", chal.ChallengeID)
	}

	return a.recordAccessEvidence(func(ev *accessVerificationEvidence) {
		ev.WrongLeafKeyRejected = map[string]any{
			"challengeId":       chal.ChallengeID,
			"httpStatus":        rec.Code,
			"errorCode":         protocol.ErrCodeSignatureInvalid,
			"challengeConsumed": false,
		}
	})
}

func (a acceptance) probeExpiryStateStale() error {
	didSrv, resolver, err := a.newControlledDIDResolver()
	if err != nil {
		return err
	}
	defer didSrv.Close()

	sp := NewStateProvider(a.j.db, a.d, nil)
	baseMono := time.Now().UTC()
	curMono := baseMono
	sp.SetMonoClock(func() time.Time { return curMono })
	sp.SetStaticProbe(&ProbeSnapshot{
		TxID:           "verify-probe-" + a.id,
		ProbeBlock:     1,
		SentAt:         baseMono,
		Deadline:       baseMono.Add(5 * time.Second),
		SentMonoNs:     baseMono.UnixNano(),
		DeadlineMonoNs: baseMono.Add(5 * time.Second).UnixNano(),
		AdoptedAt:      baseMono,
		AdoptedMonoNs:  baseMono.UnixNano(),
	})

	srv, _, err := a.newDirectAccessServer(sp, resolver, nil, nil)
	if err != nil {
		return err
	}
	uPriv, uPres, cPres, certAJWS, certCJWS, g0JWS, err := a.loadDirectAccessMaterials()
	if err != nil {
		return err
	}
	nowUnix := time.Now().UTC().Unix()
	idemKey := "verify-stale-" + a.id
	_, req, reqHash, err := a.buildQuoteExecutePackage(idemKey, 1, gateway.ChallengeResponse{
		ChallengeID: "placeholder",
		Nonce:       strings.Repeat("c", 43),
		Audience:    "https://c.local",
		IssuedAt:    nowUnix,
		ExpiresAt:   nowUnix + 30,
	}, uPres, cPres, certAJWS, certCJWS, g0JWS, uPriv, nowUnix)
	if err != nil {
		return err
	}
	chal, err := gatewayReqChallenge(srv.Handler(), req.Actor, req.TaskID, reqHash)
	if err != nil {
		return err
	}
	pkg, _, _, err := a.buildQuoteExecutePackage(idemKey, 1, chal, uPres, cPres, certAJWS, certCJWS, g0JWS, uPriv, nowUnix)
	if err != nil {
		return err
	}

	// Advance monotonic clock past probe deadline -> both /v1/health/ready and /v1/access/execute MUST return 503 STATE_STALE.
	curMono = baseMono.Add(6 * time.Second)
	readyRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(readyRec, httptest.NewRequest(http.MethodGet, "/v1/health/ready", nil))
	if readyRec.Code != http.StatusServiceUnavailable || !strings.Contains(readyRec.Body.String(), protocol.ErrCodeStateStale) {
		return fmt.Errorf("expected /v1/health/ready 503 STATE_STALE on expired probe, got %d %s", readyRec.Code, readyRec.Body.String())
	}
	execRec := gatewayPostExecute(srv.Handler(), pkg)
	if execRec.Code != http.StatusServiceUnavailable || !strings.Contains(execRec.Body.String(), protocol.ErrCodeStateStale) {
		return fmt.Errorf("expected /v1/access/execute 503 STATE_STALE on expired probe, got %d %s", execRec.Code, execRec.Body.String())
	}

	return a.recordAccessEvidence(func(ev *accessVerificationEvidence) {
		ev.ProbeExpiryStateStale = map[string]any{
			"readyStatus": readyRec.Code,
			"execStatus":  execRec.Code,
			"errorCode":   protocol.ErrCodeStateStale,
		}
	})
}

func (a acceptance) postLockBlockedNoQuote() error {
	rt := newRuntime(a)
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()
	waitCtx, cancel := context.WithTimeout(a.ctx, 12*time.Second)
	_, err = waitOnline(waitCtx, rt, a.f.G0.ID)
	cancel()
	if err != nil {
		return err
	}
	didSrv, resolver, err := a.newControlledDIDResolver()
	if err != nil {
		return err
	}
	defer didSrv.Close()

	sp := NewStateProvider(a.j.db, a.d, rt)
	srv, _, err := a.newDirectAccessServer(sp, resolver, nil, nil)
	if err != nil {
		return err
	}
	curVer, err := a.directAccessContextVersion()
	if err != nil {
		return err
	}
	nowUnix := time.Now().UTC().Unix()
	normalCtx, err := gatewaySetContext(srv.Handler(), a.f.Task.ID, curVer, nowUnix-1, "NORMAL", a.f.Task.Interval.EXP)
	if err != nil {
		return err
	}
	srv.SetTestHooks(func(attempt int) {
		if attempt == 0 {
			_, _ = gatewaySetContext(srv.Handler(), a.f.Task.ID, normalCtx.ContextVersion, nowUnix, "BLOCKED", a.f.Task.Interval.EXP)
		}
	}, nil)

	var beforeQuotes int
	if err := a.j.db.QueryRow(a.ctx, `SELECT COUNT(*) FROM quotes WHERE deployment_id=$1`, a.d.DeploymentID).Scan(&beforeQuotes); err != nil {
		return err
	}

	uPriv, uPres, cPres, certAJWS, certCJWS, g0JWS, err := a.loadDirectAccessMaterials()
	if err != nil {
		return err
	}
	idemKey := "verify-blocked-" + a.id
	req, reqHash, err := a.buildQuoteRequest(idemKey, 1)
	if err != nil {
		return err
	}
	chal, err := gatewayReqChallenge(srv.Handler(), req.Actor, req.TaskID, reqHash)
	if err != nil {
		return err
	}
	pkg, _, _, err := a.buildQuoteExecutePackage(idemKey, 1, chal, uPres, cPres, certAJWS, certCJWS, g0JWS, uPriv, nowUnix)
	if err != nil {
		return err
	}
	rec := gatewayPostExecute(srv.Handler(), pkg)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), protocol.ErrCodePolicyDenied) {
		return fmt.Errorf("expected 403 POLICY_DENIED on post-lock BLOCKED transition, got %d %s", rec.Code, rec.Body.String())
	}
	var errBody gateway.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil || errBody.DecisionID == nil {
		return fmt.Errorf("expected non-null decisionId on post-lock DENY, got %s", rec.Body.String())
	}

	var afterQuotes int
	if err := a.j.db.QueryRow(a.ctx, `SELECT COUNT(*) FROM quotes WHERE deployment_id=$1`, a.d.DeploymentID).Scan(&afterQuotes); err != nil {
		return err
	}
	if afterQuotes != beforeQuotes {
		return fmt.Errorf("quotes count changed after BLOCKED deny: before=%d after=%d", beforeQuotes, afterQuotes)
	}

	return a.recordAccessEvidence(func(ev *accessVerificationEvidence) {
		ev.PostLockBlocked = map[string]any{
			"decisionId":        *errBody.DecisionID,
			"httpStatus":        rec.Code,
			"errorCode":         protocol.ErrCodePolicyDenied,
			"quotesCountBefore": beforeQuotes,
			"quotesCountAfter":  afterQuotes,
		}
	})
}

func (a acceptance) exactSecondDeadlineRejection() error {
	rt := newRuntime(a)
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()
	waitCtx, cancel := context.WithTimeout(a.ctx, 12*time.Second)
	_, err = waitOnline(waitCtx, rt, a.f.G0.ID)
	cancel()
	if err != nil {
		return err
	}
	didSrv, resolver, err := a.newControlledDIDResolver()
	if err != nil {
		return err
	}
	defer didSrv.Close()

	baseNow := time.Now().UTC().Truncate(time.Second)
	curTime := baseNow
	sp := NewStateProvider(a.j.db, a.d, rt)
	srv, _, err := a.newDirectAccessServer(sp, resolver, nil, func() time.Time { return curTime })
	if err != nil {
		return err
	}

	curVer, err := a.directAccessContextVersion()
	if err != nil {
		return err
	}
	if _, err := gatewaySetContext(srv.Handler(), a.f.Task.ID, curVer, baseNow.Unix()-1, "NORMAL", a.f.Task.Interval.EXP); err != nil {
		return err
	}

	uPriv, uPres, cPres, certAJWS, certCJWS, g0JWS, err := a.loadDirectAccessMaterials()
	if err != nil {
		return err
	}
	idemKey := "verify-exact-sec-" + a.id
	req, reqHash, err := a.buildQuoteRequest(idemKey, 1)
	if err != nil {
		return err
	}
	chal, err := gatewayReqChallenge(srv.Handler(), req.Actor, req.TaskID, reqHash)
	if err != nil {
		return err
	}
	pkg, _, _, err := a.buildQuoteExecutePackage(idemKey, 1, chal, uPres, cPres, certAJWS, certCJWS, g0JWS, uPriv, baseNow.Unix())
	if err != nil {
		return err
	}

	// Move wall clock to exact expiresAt second -> must reject with 401 CHALLENGE_EXPIRED.
	curTime = time.Unix(chal.ExpiresAt, 0).UTC()
	rec := gatewayPostExecute(srv.Handler(), pkg)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), protocol.ErrCodeChallengeExpired) {
		return fmt.Errorf("expected 401 CHALLENGE_EXPIRED at exact second now==expiresAt, got %d %s", rec.Code, rec.Body.String())
	}

	return a.recordAccessEvidence(func(ev *accessVerificationEvidence) {
		ev.ExactSecondDeadline = map[string]any{
			"challengeId": chal.ChallengeID,
			"expiresAt":   chal.ExpiresAt,
			"decisionAt":  curTime.Unix(),
			"httpStatus":  rec.Code,
			"errorCode":   protocol.ErrCodeChallengeExpired,
		}
	})
}
