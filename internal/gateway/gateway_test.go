package gateway_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"graduation-design/internal/fabric"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/policy"
	"graduation-design/internal/protocol"

	"github.com/jackc/pgx/v5/pgxpool"
)

func openTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("FABRIC_TEST_DSN")
	if dsn == "" {
		dir := filepath.Join("..", "..", ".local", "fabric-d0")
		envBytes, err := os.ReadFile(filepath.Join(dir, "network.env"))
		if err != nil {
			t.Skipf("live fabric instance not configured: %v", err)
		}
		port := "17009"
		for _, line := range strings.Split(string(envBytes), "\n") {
			line = strings.TrimSpace(line)
			if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "FABRIC_DB" {
				port = strings.TrimSpace(v)
				break
			}
		}
		pw, err := os.ReadFile(filepath.Join(dir, "view-password"))
		if err != nil {
			t.Skipf("view-password unavailable: %v", err)
		}
		dsn = (&url.URL{
			Scheme:   "postgres",
			Host:     "127.0.0.1:" + port,
			User:     url.UserPassword("view", strings.TrimSpace(string(pw))),
			Path:     "/fabric",
			RawQuery: "sslmode=disable",
		}).String()
	}
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Skipf("connect postgres: %v", err)
	}
	if err := pool.Ping(t.Context()); err != nil {
		pool.Close()
		t.Skipf("ping postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := fabric.EnsureStateSchema(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

type gatewayTestHarness struct {
	pool           *pgxpool.Pool
	deploymentID   string
	serviceDID     string
	audience       string
	supplierID     string
	actorDID       string
	taskID         string
	taskSpec       protocol.TaskSpec
	uKeyID         string
	uPriv          *ecdsa.PrivateKey
	wrongPriv      *ecdsa.PrivateKey
	uPresPrefix    string
	cCredID        string
	cPresPrefix    string
	icIssuerDID    string
	iaIssuerDID    string
	certCJWS       string
	certAJWS       string
	g0JWS          string
	boot           api.Bootstrap
	rootRecord     api.RootRecord
	state          *fabric.StateProvider
	delivery       *fabric.DeliveryService
	dids           *protocol.DIDWebResolver
	bundle         *policy.VerifiedBundle
	policyDeadline int64
	taskExp        int64
	fixedNow       time.Time
	fixedMono      time.Time
}

func newGatewayTestHarness(t *testing.T) *gatewayTestHarness {
	t.Helper()
	pool := openTestPool(t)
	ctx := t.Context()

	now := time.Now().UTC().Truncate(time.Second)
	ca, err := protocol.GenerateTestCA(now)
	if err != nil {
		t.Fatal(err)
	}
	caPool, err := protocol.ParseTestCAPublic(ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	certs := make(map[string]*protocol.HostTLSCert, len(protocol.ControlledTestDomains))
	for _, host := range protocol.ControlledTestDomains {
		hc, err := ca.IssueHostCert(host, now)
		if err != nil {
			t.Fatal(err)
		}
		certs[host] = hc
	}

	privT, pubT, _ := protocol.GenerateP256KeyPair()
	privIA, pubIA, _ := protocol.GenerateP256KeyPair()
	privIC, pubIC, _ := protocol.GenerateP256KeyPair()
	privDomA, pubDomA, _ := protocol.GenerateP256KeyPair()
	privDomC, pubDomC, _ := protocol.GenerateP256KeyPair()
	privU, pubU, _ := protocol.GenerateP256KeyPair()
	privC, pubC, _ := protocol.GenerateP256KeyPair()
	privWrong, _, _ := protocol.GenerateP256KeyPair()
	_, _ = privDomA, privDomC

	didT := "did:web:t.local"
	didA := "did:web:a.local"
	didC := "did:web:c.local"
	didIA := "did:web:a.local:ia"
	didIC := "did:web:c.local:ic"
	didU := "did:web:a.local:u"
	didCSvc := "did:web:c.local:supplier"

	docs := map[string][]byte{}
	makeDoc := func(did, keyID, pub string, purposes ...string) string {
		d, err := protocol.NewDIDDocument(did, keyID, pub, purposes...)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := protocol.MarshalJCS(d)
		if err != nil {
			t.Fatal(err)
		}
		dig, err := d.Digest()
		if err != nil {
			t.Fatal(err)
		}
		docs[did] = raw
		return dig
	}

	digT := makeDoc(didT, didT+"#key-1", pubT, protocol.KeyPurposeAssertionMethod)
	digA := makeDoc(didA, didA+"#key-1", pubDomA, protocol.KeyPurposeAssertionMethod)
	digC := makeDoc(didC, didC+"#key-1", pubDomC, protocol.KeyPurposeAssertionMethod)
	digIA := makeDoc(didIA, didIA+"#key-1", pubIA, protocol.KeyPurposeAssertionMethod)
	digIC := makeDoc(didIC, didIC+"#key-1", pubIC, protocol.KeyPurposeAssertionMethod)
	digU := makeDoc(didU, didU+"#key-1", pubU, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
	digCSvc := makeDoc(didCSvc, didCSvc+"#key-1", pubC, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)

	srv, err := protocol.NewDIDWebServer(certs, docs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	dids, err := protocol.NewDIDWebResolver(caPool, srv.Routes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dids.RegisterPreseed(protocol.RootPreseed{
		DID:               didT,
		KeyID:             didT + "#key-1",
		KeyVersion:        1,
		PublicKeyHex:      pubT,
		DIDDocumentDigest: digT,
		RawDocument:       docs[didT],
	}); err != nil {
		t.Fatal(err)
	}

	uniqueTag := fmt.Sprintf("gw-test-%d", time.Now().UnixNano())
	depID := api.Digest([]byte("dep:" + uniqueTag))
	taskID := api.Digest([]byte("task:" + uniqueTag))
	resID := api.Digest([]byte("res:" + uniqueTag))
	g0ID := api.Digest([]byte("g0:" + uniqueTag))

	nbf := now.Add(-time.Hour).Unix()
	exp := now.Add(time.Hour).Unix()
	policyDeadline := now.Add(2 * time.Hour).Unix()
	vf := time.Unix(nbf, 0).UTC().Format(time.RFC3339)
	vu := time.Unix(exp, 0).UTC().Format(time.RFC3339)

	rootRec := api.RootRecord{
		DID:            didT,
		Management:     api.Management{MSPID: "TMSP", Fingerprint: strings.Repeat("1", 64)},
		DocumentDigest: digT,
		KeyID:          didT + "#key-1",
		KeyVersion:     1,
		PublicKey:      pubT,
	}
	boot := api.Bootstrap{
		DeploymentFields: api.DeploymentFields{
			ChannelID:     api.Channel,
			GenesisHash:   api.Digest([]byte("genesis:" + uniqueTag)),
			InstanceID:    api.Digest([]byte("inst:" + uniqueTag)),
			RegistryName:  api.Registry,
			SchemaVersion: api.Schema,
		},
		Root:          rootRec,
		Initializer:   rootRec.Management,
		TaskCreator:   api.TaskAuthority{Domain: "A", Subject: didU, Management: api.Management{MSPID: "AMSP", Fingerprint: strings.Repeat("2", 64)}},
		ResourceID:    resID,
		ResourceOwner: didCSvc,
		ResourceManagement: api.Management{
			MSPID: "CMSP", Fingerprint: strings.Repeat("3", 64),
		},
	}

	issueCert := func(domID, domDID, issuerDID string) (string, string, api.Domain, api.Certification) {
		certID := "urn:grad:domain-certification:" + domID + "-" + uniqueTag
		scopes := []protocol.IssuerScope{{
			ID:              issuerDID,
			AppKeyVersion:   1,
			CredentialTypes: []string{protocol.CredentialTypeEnterpriseIdentity},
			ClaimNames:      []string{"domain", "role"},
		}}
		jws, dig, err := protocol.SignDomainAuthorityCredential(privT, rootRec.KeyID, &protocol.DomainAuthorityCredential{
			Type:             []string{protocol.CredentialTypeVC, protocol.CredentialTypeDomainAuthority},
			ID:               certID,
			DeploymentID:     depID,
			Issuer:           didT,
			Iss:              didT,
			Sub:              domDID,
			IssuerKeyVersion: 1,
			ValidFrom:        vf,
			ValidUntil:       vu,
			NBF:              nbf,
			EXP:              exp,
			CredentialStatus: protocol.CredentialStatus{ID: certID, Type: protocol.StatusTypeDomainCertification},
			CredentialSubject: protocol.DomainAuthoritySubject{
				ID:              domDID,
				DomainID:        domID,
				IdentityIssuers: scopes,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		dom := api.Domain{
			Bound:         api.Bound{DeploymentID: depID},
			ID:            domID,
			DID:           domDID,
			Admin:         api.Management{MSPID: domID + "MSP", Fingerprint: strings.Repeat("a", 64)},
			Registrar:     api.Management{MSPID: domID + "MSP", Fingerprint: strings.Repeat("b", 64)},
			Issuers:       []string{issuerDID},
			Certification: certID,
			Version:       api.Version{Status: api.Active, Revision: 1},
		}
		cert := api.Certification{
			Bound:          api.Bound{DeploymentID: depID},
			ID:             certID,
			Domain:         domID,
			RootKeyVersion: 1,
			Digest:         dig,
			Scopes:         []api.Scope{{ID: issuerDID, KeyVersion: 1, Types: []string{protocol.CredentialTypeEnterpriseIdentity}, Claims: []string{"domain", "role"}}},
			Interval:       api.Interval{NBF: nbf, EXP: exp},
			Version:        api.Version{Status: api.Active, Revision: 1},
		}
		return jws, dig, dom, cert
	}

	certAJWS, _, domA, certA := issueCert("A", didA, didIA)
	certCJWS, certCDig, domC, certC := issueCert("C", didC, didIC)

	makeID := func(did, domID, kind, keyID, pub, dig string) api.Identity {
		return api.Identity{
			Bound:             api.Bound{DeploymentID: depID},
			ID:                did,
			Domain:            domID,
			Kind:              kind,
			Management:        api.Management{MSPID: domID + "MSP", Fingerprint: strings.Repeat("4", 64)},
			DocumentDigest:    dig,
			KeyID:             keyID,
			KeyVersion:        1,
			PublicKey:         pub,
			AccountCommitment: api.Digest([]byte("acct:" + did)),
			Version:           api.Version{Status: api.Active, Revision: 1},
		}
	}
	idA := makeID(didA, "A", "DOMAIN", didA+"#key-1", pubDomA, digA)
	idC_dom := makeID(didC, "C", "DOMAIN", didC+"#key-1", pubDomC, digC)
	idIA := makeID(didIA, "A", "ISSUER", didIA+"#key-1", pubIA, digIA)
	idIC := makeID(didIC, "C", "ISSUER", didIC+"#key-1", pubIC, digIC)
	idU := makeID(didU, "A", "USER", didU+"#key-1", pubU, digU)
	idC := makeID(didCSvc, "C", "SERVICE", didCSvc+"#key-1", pubC, digCSvc)

	issueSD := func(priv *ecdsa.PrivateKey, iss, sub, credID, dom, role, holderPub string) (*protocol.SignedSDJWTCredential, api.Credential) {
		jwk, err := protocol.AppPublicKeyToJWK(holderPub)
		if err != nil {
			t.Fatal(err)
		}
		sd, err := protocol.IssueEnterpriseIdentityCredential(priv, iss+"#key-1", protocol.EnterpriseIdentityCredential{
			Type:              []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity},
			ID:                credID,
			DeploymentID:      depID,
			Issuer:            iss,
			Iss:               iss,
			Sub:               sub,
			IssuerKeyVersion:  1,
			AppKeyVersion:     1,
			ValidFrom:         vf,
			ValidUntil:        vu,
			NBF:               nbf,
			EXP:               exp,
			CredentialStatus:  protocol.CredentialStatus{ID: credID, Type: protocol.StatusTypeCredential},
			Cnf:               protocol.ConfirmationKey{JWK: jwk},
			CredentialSubject: protocol.SDJWTCredentialSubject{ID: sub},
		}, dom, role, nil)
		if err != nil {
			t.Fatal(err)
		}
		return sd, api.Credential{
			Bound:             api.Bound{DeploymentID: depID},
			ID:                credID,
			Issuer:            iss,
			Subject:           sub,
			IssuerKeyVersion:  1,
			SubjectKeyVersion: 1,
			Type:              protocol.CredentialTypeEnterpriseIdentity,
			ClaimNames:        []string{"domain", "role"},
			Digest:            sd.AnchorDigest,
			Interval:          api.Interval{NBF: nbf, EXP: exp},
			Version:           api.Version{Status: api.Active, Revision: 1},
		}
	}

	uCredID := "urn:grad:credential:U-" + uniqueTag
	cCredID := "urn:grad:credential:C-" + uniqueTag
	sdU, chainCredU := issueSD(privIA, didIA, didU, uCredID, "A", "procurement-owner", pubU)
	sdC, chainCredC := issueSD(privIC, didIC, didCSvc, cCredID, "C", "supplier-service", pubC)

	spec := protocol.TaskSpec{
		SupplierID:  "urn:grad:supplier:C",
		ProductID:   "urn:grad:product:P1",
		MaxQuantity: 2,
		Currency:    "CNY",
		Resources:   []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions:     []string{"order.create", "quote.read"},
		Description: "P1 gateway test",
	}
	taskDig, err := spec.Digest()
	if err != nil {
		t.Fatal(err)
	}
	task := api.Task{
		Bound:             api.Bound{DeploymentID: depID},
		ID:                taskID,
		Creator:           didU,
		CreatorKeyVersion: 1,
		CreatorCredential: uCredID,
		Resource:          resID,
		Mode:              api.RP,
		Domain:            "A",
		Digest:            taskDig,
		Interval:          api.Interval{NBF: nbf, EXP: exp},
		Version:           api.Version{Status: api.Active, Revision: 1},
	}

	g0Payload, err := protocol.MarshalJCS(protocol.GrantClaims{
		SchemaVersion:       api.Schema,
		DeploymentID:        depID,
		ID:                  g0ID,
		RootID:              g0ID,
		ParentID:            nil,
		ParentDigest:        nil,
		TaskID:              taskID,
		AuthorizationMode:   api.RP,
		PrincipalDomain:     "A",
		ResourceID:          resID,
		Aud:                 "https://c.local",
		Issuer:              didCSvc,
		IssuerKeyVersion:    1,
		IssuerCredentialID:  cCredID,
		Grantee:             didU,
		GranteeKeyVersion:   1,
		GranteeCredentialID: uCredID,
		Resources:           spec.Resources,
		Actions:             spec.Actions,
		Suppliers:           []string{"urn:grad:supplier:C"},
		Currency:            "CNY",
		MaxAmountMinor:      500000,
		RemainingDepth:      2,
		NBF:                 nbf,
		EXP:                 exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	g0JWS, g0Dig, err := protocol.SignCompactJWS(privC, protocol.TypGrantDelegation, didCSvc+"#key-1", g0Payload)
	if err != nil {
		t.Fatal(err)
	}
	g0Chain := api.Grant{
		Bound:             api.Bound{DeploymentID: depID},
		ID:                g0ID,
		Root:              g0ID,
		Task:              taskID,
		Mode:              api.RP,
		Domain:            "A",
		Resource:          resID,
		Issuer:            didCSvc,
		IssuerKeyVersion:  1,
		IssuerCredential:  cCredID,
		Grantee:           didU,
		GranteeKeyVersion: 1,
		GranteeCredential: uCredID,
		Depth:             2,
		Digest:            g0Dig,
		Schema:            api.Schema,
		Interval:          api.Interval{NBF: nbf, EXP: exp},
		Version:           api.Version{Status: api.Active, Revision: 1},
	}

	// Ensure gateway + delivery receipt schema and seed consistent snapshot block 1.
	if err := gateway.EnsureSchema(ctx, pool, depID, "urn:grad:supplier:C"); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	putKV := func(k string, v any) {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO fabric_current(deployment, key, value) VALUES($1,$2,$3)
			ON CONFLICT(deployment,key) DO UPDATE SET value=EXCLUDED.value`, depID, k, raw); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO fabric_head(deployment, block_no, hash) VALUES($1,1,$2)`,
		depID, api.Digest([]byte("block-1-"+uniqueTag))); err != nil {
		t.Fatal(err)
	}
	putKV(api.BootstrapKey, boot)
	putKV(api.Key("domain", "A"), domA)
	putKV(api.Key("domain", "C"), domC)
	putKV(api.Key("certification", certA.ID), certA)
	putKV(api.Key("certification", certC.ID), certC)
	putKV(api.Key("identity", didA), idA)
	putKV(api.Key("identity", didC), idC_dom)
	putKV(api.Key("identity", didIA), idIA)
	putKV(api.Key("identity", didIC), idIC)
	putKV(api.Key("identity", didU), idU)
	putKV(api.Key("identity", didCSvc), idC)
	putKV(api.Key("credential", uCredID), chainCredU)
	putKV(api.Key("credential", cCredID), chainCredC)
	putKV(api.Key("task", taskID), task)
	putKV(api.Key("grant", g0ID), g0Chain)

	// Sync both domain A and C certifications in certification_receipts.
	for _, item := range []struct {
		domID, certID, jws, dig string
	}{
		{"A", certA.ID, certAJWS, certA.Digest},
		{"C", certC.ID, certCJWS, certCDig},
	} {
		if _, err := tx.Exec(ctx, `INSERT INTO certification_receipts(
			deployment_id, domain_id, certification_id, recipient, cert_jws, cert_digest, received_at
		) VALUES($1,$2,$3,$4,$5,$6,$7)`,
			depID, item.domID, item.certID, didCSvc, item.jws, item.dig, now.Unix(),
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM decision_evidence WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM order_outcome_outbox WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM quotes WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM decisions WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM business_keys WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM challenges WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM trusted_contexts WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM catalog_prices WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM certification_receipts WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM fabric_current WHERE deployment=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM fabric_head WHERE deployment=$1`, depID)
	})

	files, dig, err := policy.BuildDefaultBundle(depID, didCSvc, policy.DefaultPolicyVersion, rootRec, &policyDeadline)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := policy.VerifyAndLoadBundle(files, depID, didCSvc, rootRec, dig)
	if err != nil {
		t.Fatal(err)
	}

	sp := fabric.NewStateProviderFromBootstrap(pool, depID, boot, nil)
	monoNow := now
	sp.SetMonoClock(func() time.Time { return monoNow })
	sp.SetStaticProbe(&fabric.ProbeSnapshot{
		TxID:           "probe-tx-" + uniqueTag,
		ProbeBlock:     1,
		SentAt:         now,
		Deadline:       now.Add(5 * time.Second),
		SentMonoNs:     monoNow.UnixNano(),
		DeadlineMonoNs: monoNow.Add(5 * time.Second).UnixNano(),
		AdoptedAt:      now,
		AdoptedMonoNs:  monoNow.UnixNano(),
	})

	return &gatewayTestHarness{
		pool:           pool,
		deploymentID:   depID,
		serviceDID:     didCSvc,
		audience:       "https://c.local",
		supplierID:     "urn:grad:supplier:C",
		actorDID:       didU,
		taskID:         taskID,
		taskSpec:       spec,
		uKeyID:         didU + "#key-1",
		uPriv:          privU,
		wrongPriv:      privWrong,
		uPresPrefix:    sdU.PresentationPrefix,
		cCredID:        cCredID,
		cPresPrefix:    sdC.PresentationPrefix,
		icIssuerDID:    didIC,
		iaIssuerDID:    didIA,
		certCJWS:       certCJWS,
		certAJWS:       certAJWS,
		g0JWS:          g0JWS,
		boot:           boot,
		rootRecord:     rootRec,
		state:          sp,
		delivery:       fabric.NewDeliveryService(pool),
		dids:           dids,
		bundle:         bundle,
		policyDeadline: policyDeadline,
		taskExp:        exp,
		fixedNow:       now,
		fixedMono:      monoNow,
	}
}

func (h *gatewayTestHarness) newServer(nowFn func() time.Time) *gateway.Server {
	srv, err := gateway.NewServer(gateway.Config{
		DB:           h.pool,
		State:        h.state.GatewayAdapter(),
		Delivery:     h.delivery,
		DIDs:         h.dids,
		Policy:       h.bundle,
		DeploymentID: h.deploymentID,
		ServiceDID:   h.serviceDID,
		Audience:     h.audience,
		SupplierID:   h.supplierID,
		NowFn:        nowFn,
	})
	if err != nil {
		panic(err)
	}
	return srv
}

func (h *gatewayTestHarness) buildQuoteRequest(idempotencyKey string, qty int64) protocol.AccessRequest {
	return protocol.AccessRequest{
		SchemaVersion:     api.Schema,
		DeploymentID:      h.deploymentID,
		Actor:             h.actorDID,
		PrincipalDomain:   "A",
		AuthorizationMode: api.RP,
		TaskID:            h.taskID,
		Audience:          h.audience,
		Resource:          "urn:grad:resource:C:quotes",
		Action:            "quote.read",
		SupplierID:        h.supplierID,
		QuoteID:           nil,
		ProductID:         gateway.DefaultProductID,
		Quantity:          qty,
		Currency:          gateway.DefaultCurrency,
		AmountMinor:       0,
		IdempotencyKey:    idempotencyKey,
	}
}

func (h *gatewayTestHarness) requestChallenge(t *testing.T, srv http.Handler, reqHash string) gateway.ChallengeResponse {
	t.Helper()
	body, _ := json.Marshal(gateway.ChallengeRequest{
		Actor:       h.actorDID,
		TaskID:      h.taskID,
		RequestHash: reqHash,
	})
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/auth/challenges", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(rec, httpReq)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/auth/challenges status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Fatal("missing X-Request-Id header")
	}
	var out gateway.ChallengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (h *gatewayTestHarness) updateContext(t *testing.T, srv http.Handler, expectedVer int64, risk string, deadline int64) gateway.ContextResponse {
	t.Helper()
	body, _ := json.Marshal(gateway.ContextUpdateRequest{
		ExpectedContextVersion: expectedVer,
		SourceID:               "ctx-sensor-c1",
		ObservedAt:             h.fixedNow.Unix(),
		RiskLevel:              risk,
		AccessDeadline:         deadline,
	})
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/contexts/"+h.taskID, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(rec, httpReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /v1/contexts status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out gateway.ContextResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (h *gatewayTestHarness) assemblePackage(t *testing.T, req protocol.AccessRequest, chal gateway.ChallengeResponse, leafPriv *ecdsa.PrivateKey) protocol.AccessEvidencePackage {
	t.Helper()
	pkg := protocol.AccessEvidencePackage{
		Request:  req,
		TaskSpec: h.taskSpec,
		AncestorCredentials: []protocol.AncestorCredential{
			{CredentialID: h.cCredID, Presentation: h.cPresPrefix},
		},
		Grants: []string{h.g0JWS},
		TrustPaths: []protocol.TrustPathEntry{
			{Issuer: h.iaIssuerDID, DomainCertification: h.certAJWS},
			{Issuer: h.icIssuerDID, DomainCertification: h.certCJWS},
		},
	}
	// Ensure canonical UTF-16 ascending TrustPaths ordering.
	if h.iaIssuerDID > h.icIssuerDID {
		pkg.TrustPaths[0], pkg.TrustPaths[1] = pkg.TrustPaths[1], pkg.TrustPaths[0]
	}
	_, _, err := protocol.AssembleAccessEvidencePackage(
		&pkg,
		h.uPresPrefix,
		h.uKeyID,
		leafPriv,
		protocol.ChallengeContext{
			ChallengeID: chal.ChallengeID,
			Nonce:       chal.Nonce,
			Audience:    chal.Audience,
			IssuedAt:    chal.IssuedAt,
			ExpiresAt:   chal.ExpiresAt,
		},
		h.fixedNow.Unix(),
		false,
	)
	if err != nil {
		t.Fatalf("AssembleAccessEvidencePackage: %v", err)
	}
	return pkg
}

func (h *gatewayTestHarness) postExecute(srv http.Handler, body []byte, contentType string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/access/execute", bytes.NewReader(body))
	if contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	}
	srv.ServeHTTP(rec, httpReq)
	return rec
}

func TestGatewayAuxiliaryEndpoints(t *testing.T) {
	h := newGatewayTestHarness(t)
	srv := h.newServer(func() time.Time { return h.fixedNow })

	// Seeded catalog_prices check: P1 == 80000 CNY.
	var price int64
	var cur string
	if err := h.pool.QueryRow(t.Context(), `SELECT unit_price_minor, currency FROM catalog_prices WHERE deployment_id=$1 AND product_id=$2`,
		h.deploymentID, gateway.DefaultProductID).Scan(&price, &cur); err != nil {
		t.Fatalf("query catalog_prices: %v", err)
	}
	if price != 80000 || cur != "CNY" {
		t.Fatalf("unexpected seeded price: %d %s", price, cur)
	}

	// GET /v1/health/ready -> 200 OK without private keys.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/health/ready", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/health/ready status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatal("ready response exposed private key material")
	}

	// POST /v1/auth/challenges -> 201 Created, 43-char nonce, 30s TTL.
	req := h.buildQuoteRequest("aux-key-1", 1)
	reqHash, err := req.Hash(false)
	if err != nil {
		t.Fatal(err)
	}
	chal := h.requestChallenge(t, srv.Handler(), reqHash)
	if !strings.HasPrefix(chal.ChallengeID, "urn:grad:challenge:") || len(chal.Nonce) != 43 || chal.ExpiresAt-chal.IssuedAt != 30 {
		t.Fatalf("unexpected challenge response: %+v", chal)
	}

	// POST /v1/contexts/{taskId} optimistic concurrency: 0 -> 1 -> 2, stale 1 -> 409 STATE_CHANGED.
	c1 := h.updateContext(t, srv.Handler(), 0, "NORMAL", h.taskExp)
	if c1.ContextVersion != 1 {
		t.Fatalf("expected version 1, got %d", c1.ContextVersion)
	}
	c2 := h.updateContext(t, srv.Handler(), 1, "ELEVATED", h.taskExp)
	if c2.ContextVersion != 2 {
		t.Fatalf("expected version 2, got %d", c2.ContextVersion)
	}
	staleBody, _ := json.Marshal(gateway.ContextUpdateRequest{
		ExpectedContextVersion: 1,
		SourceID:               "ctx-sensor-c1",
		ObservedAt:             h.fixedNow.Unix(),
		RiskLevel:              "BLOCKED",
		AccessDeadline:         h.taskExp,
	})
	staleReq := httptest.NewRequest(http.MethodPost, "/v1/contexts/"+h.taskID, bytes.NewReader(staleBody))
	staleReq.Header.Set("Content-Type", "application/json")
	staleRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(staleRec, staleReq)
	if staleRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 on stale context version, got %d body=%s", staleRec.Code, staleRec.Body.String())
	}

	// GET /v1/decisions/unknown -> 404.
	notFoundRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(notFoundRec, httptest.NewRequest(http.MethodGet, "/v1/decisions/urn:grad:decision:missing", nil))
	if notFoundRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown decision, got %d", notFoundRec.Code)
	}

	// Missing certification receipt -> GET /v1/health/ready -> 503 MATERIAL_NOT_SYNCED.
	if _, err := h.pool.Exec(t.Context(), `DELETE FROM certification_receipts WHERE deployment_id=$1 AND domain_id='A'`, h.deploymentID); err != nil {
		t.Fatal(err)
	}
	unreadyRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(unreadyRec, httptest.NewRequest(http.MethodGet, "/v1/health/ready", nil))
	if unreadyRec.Code != http.StatusServiceUnavailable || !strings.Contains(unreadyRec.Body.String(), protocol.ErrCodeMaterialNotSynced) {
		t.Fatalf("expected 503 MATERIAL_NOT_SYNCED, got %d body=%s", unreadyRec.Code, unreadyRec.Body.String())
	}
}

func TestGatewayExecuteSchemaAndCryptoRejection(t *testing.T) {
	h := newGatewayTestHarness(t)
	srv := h.newServer(func() time.Time { return h.fixedNow })
	h.updateContext(t, srv.Handler(), 0, "NORMAL", h.taskExp)

	// 1. 415 Unsupported Media Type.
	rec := h.postExecute(srv.Handler(), []byte("{}"), "text/plain")
	if rec.Code != http.StatusUnsupportedMediaType || !strings.Contains(rec.Body.String(), protocol.ErrCodeUnsupportedMediaType) {
		t.Fatalf("expected 415 UNSUPPORTED_MEDIA_TYPE, got %d %s", rec.Code, rec.Body.String())
	}

	// 2. 413 Payload Too Large (> 256 KiB).
	big := bytes.Repeat([]byte("a"), gateway.MaxExecuteBodyBytes+10)
	rec = h.postExecute(srv.Handler(), big, "application/json")
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), protocol.ErrCodePayloadTooLarge) {
		t.Fatalf("expected 413 PAYLOAD_TOO_LARGE, got %d %s", rec.Code, rec.Body.String())
	}

	// 3. 400 INVALID_SCHEMA on non-null quoteId / non-zero amountMinor / zero quantity.
	req := h.buildQuoteRequest("schema-err-1", 1)
	reqHash, _ := req.Hash(false)
	chal := h.requestChallenge(t, srv.Handler(), reqHash)
	pkg := h.assemblePackage(t, req, chal, h.uPriv)
	badPkg := pkg
	qStr := "urn:grad:quote:should-be-null"
	badPkg.Request.QuoteID = &qStr
	badRaw, _ := json.Marshal(badPkg)
	rec = h.postExecute(srv.Handler(), badRaw, "application/json")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), protocol.ErrCodeInvalidSchema) {
		t.Fatalf("expected 400 INVALID_SCHEMA for non-null quoteId, got %d %s", rec.Code, rec.Body.String())
	}

	badAmtPkg := pkg
	badAmtPkg.Request.AmountMinor = 100
	badRaw, _ = json.Marshal(badAmtPkg)
	rec = h.postExecute(srv.Handler(), badRaw, "application/json")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), protocol.ErrCodeInvalidSchema) {
		t.Fatalf("expected 400 INVALID_SCHEMA for amountMinor != 0, got %d %s", rec.Code, rec.Body.String())
	}

	// 4. 401 SIGNATURE_INVALID with wrong leaf key MUST NOT consume challenge!
	wrongPkg := h.assemblePackage(t, req, chal, h.wrongPriv)
	wrongRaw, _ := json.Marshal(wrongPkg)
	rec = h.postExecute(srv.Handler(), wrongRaw, "application/json")
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), protocol.ErrCodeSignatureInvalid) {
		t.Fatalf("expected 401 SIGNATURE_INVALID, got %d %s", rec.Code, rec.Body.String())
	}
	var consumedAt *int64
	if err := h.pool.QueryRow(t.Context(), `SELECT consumed_at FROM challenges WHERE deployment_id=$1 AND challenge_id=$2`,
		h.deploymentID, chal.ChallengeID).Scan(&consumedAt); err != nil {
		t.Fatal(err)
	}
	if consumedAt != nil {
		t.Fatalf("wrong leaf key failure must NOT consume challenge, got consumed_at=%d", *consumedAt)
	}

	// Same unconsumed challenge now succeeds with the genuine key U!
	goodRaw, _ := json.Marshal(pkg)
	rec = h.postExecute(srv.Handler(), goodRaw, "application/json")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected genuine key after wrong-key failure to reuse challenge and succeed, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestGatewayExecuteQuoteCommitAndIdempotency(t *testing.T) {
	h := newGatewayTestHarness(t)
	srv := h.newServer(func() time.Time { return h.fixedNow })
	h.updateContext(t, srv.Handler(), 0, "NORMAL", h.taskExp)

	// Quote request for P1 x 1 under RP G0.
	req := h.buildQuoteRequest("quote-key-1", 1)
	reqHash, err := req.Hash(false)
	if err != nil {
		t.Fatal(err)
	}
	chal1 := h.requestChallenge(t, srv.Handler(), reqHash)
	pkg1 := h.assemblePackage(t, req, chal1, h.uPriv)
	raw1, _ := json.Marshal(pkg1)
	rec1 := h.postExecute(srv.Handler(), raw1, "application/json")
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for quote.read, got %d %s", rec1.Code, rec1.Body.String())
	}
	var out1 gateway.ExecuteResponse
	if err := json.Unmarshal(rec1.Body.Bytes(), &out1); err != nil {
		t.Fatal(err)
	}
	if out1.Code != "ALLOW" || out1.Quote == nil || !strings.HasPrefix(out1.Quote.QuoteID, "urn:grad:quote:") {
		t.Fatalf("unexpected quote response: %+v", out1)
	}
	if out1.Quote.UnitPriceMinor != 80000 || out1.Quote.TotalAmountMinor != 80000 {
		t.Fatalf("expected 80000 price, got unit=%d total=%d", out1.Quote.UnitPriceMinor, out1.Quote.TotalAmountMinor)
	}
	wantValidUntil := h.fixedNow.Unix() + 300
	if h.taskExp < wantValidUntil {
		wantValidUntil = h.taskExp
	}
	if out1.Quote.ValidUntil != wantValidUntil {
		t.Fatalf("validUntil=%d want %d", out1.Quote.ValidUntil, wantValidUntil)
	}

	// Verify GET /v1/decisions/{id}.
	decRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(decRec, httptest.NewRequest(http.MethodGet, "/v1/decisions/"+out1.DecisionID, nil))
	if decRec.Code != http.StatusOK || !strings.Contains(decRec.Body.String(), out1.Quote.QuoteID) {
		t.Fatalf("GET /v1/decisions failed: %d %s", decRec.Code, decRec.Body.String())
	}

	// Replay consumed challenge -> 409 CHALLENGE_REPLAY.
	recReplay := h.postExecute(srv.Handler(), raw1, "application/json")
	if recReplay.Code != http.StatusConflict || !strings.Contains(recReplay.Body.String(), protocol.ErrCodeChallengeReplay) {
		t.Fatalf("expected 409 CHALLENGE_REPLAY, got %d %s", recReplay.Code, recReplay.Body.String())
	}

	// Same idempotencyKey + same requestHash + fresh challenge -> returns SAME quoteId + NEW decisionId!
	chal2 := h.requestChallenge(t, srv.Handler(), reqHash)
	pkg2 := h.assemblePackage(t, req, chal2, h.uPriv)
	raw2, _ := json.Marshal(pkg2)
	rec2 := h.postExecute(srv.Handler(), raw2, "application/json")
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on same-key idempotent retry, got %d %s", rec2.Code, rec2.Body.String())
	}
	var out2 gateway.ExecuteResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &out2); err != nil {
		t.Fatal(err)
	}
	if out2.Quote == nil || out2.Quote.QuoteID != out1.Quote.QuoteID || out2.DecisionID == out1.DecisionID {
		t.Fatalf("idempotent retry mismatch: out1=%+v out2=%+v", out1, out2)
	}

	// Same idempotencyKey + DIFFERENT requestHash (qty=2) -> 409 IDEMPOTENCY_CONFLICT!
	reqDiff := h.buildQuoteRequest("quote-key-1", 2)
	diffHash, _ := reqDiff.Hash(false)
	chal3 := h.requestChallenge(t, srv.Handler(), diffHash)
	pkg3 := h.assemblePackage(t, reqDiff, chal3, h.uPriv)
	raw3, _ := json.Marshal(pkg3)
	rec3 := h.postExecute(srv.Handler(), raw3, "application/json")
	if rec3.Code != http.StatusConflict || !strings.Contains(rec3.Body.String(), protocol.ErrCodeIdempotencyConflict) {
		t.Fatalf("expected 409 IDEMPOTENCY_CONFLICT, got %d %s", rec3.Code, rec3.Body.String())
	}
}

func TestGatewayExecutePostLockBlockedAndCheckpoints(t *testing.T) {
	// 1. Pre-check saw NORMAL, BeforeLockTx flips trusted_contexts to BLOCKED -> 403 POLICY_DENIED & ZERO quotes.
	h := newGatewayTestHarness(t)
	srv := h.newServer(func() time.Time { return h.fixedNow })
	h.updateContext(t, srv.Handler(), 0, "NORMAL", h.taskExp)

	srv.SetTestHooks(func(attempt int) {
		if attempt == 0 {
			h.updateContext(t, srv.Handler(), 1, "BLOCKED", h.taskExp)
		}
	}, nil)

	req := h.buildQuoteRequest("post-lock-blocked-key", 1)
	reqHash, _ := req.Hash(false)
	chal := h.requestChallenge(t, srv.Handler(), reqHash)
	pkg := h.assemblePackage(t, req, chal, h.uPriv)
	raw, _ := json.Marshal(pkg)
	rec := h.postExecute(srv.Handler(), raw, "application/json")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), protocol.ErrCodePolicyDenied) {
		t.Fatalf("expected 403 POLICY_DENIED when context turns BLOCKED post-precheck, got %d %s", rec.Code, rec.Body.String())
	}
	var errEnv gateway.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &errEnv); err != nil || errEnv.DecisionID == nil {
		t.Fatalf("expected non-null decisionId on post-lock DENY, got %s", rec.Body.String())
	}
	var quoteCount int
	if err := h.pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM quotes WHERE deployment_id=$1`, h.deploymentID).Scan(&quoteCount); err != nil {
		t.Fatal(err)
	}
	if quoteCount != 0 {
		t.Fatalf("expected 0 quote rows after post-lock BLOCKED deny, got %d", quoteCount)
	}

	// 2. Checkpoint advances once during lock (attempt 0 -> fabric_head moves to block 2) -> retry succeeds at block 2.
	h2 := newGatewayTestHarness(t)
	srv2 := h2.newServer(func() time.Time { return h2.fixedNow })
	h2.updateContext(t, srv2.Handler(), 0, "NORMAL", h2.taskExp)
	var advOnce atomic.Int32
	srv2.SetTestHooks(nil, func(attempt int) {
		if attempt == 0 && advOnce.Add(1) == 1 {
			_, _ = h2.pool.Exec(context.Background(), `UPDATE fabric_head SET block_no=2, hash=$2 WHERE deployment=$1`,
				h2.deploymentID, api.Digest([]byte("block-2-adv")))
		}
	})
	req2 := h2.buildQuoteRequest("ckpt-retry-key", 1)
	req2Hash, _ := req2.Hash(false)
	chal2 := h2.requestChallenge(t, srv2.Handler(), req2Hash)
	pkg2 := h2.assemblePackage(t, req2, chal2, h2.uPriv)
	raw2, _ := json.Marshal(pkg2)
	rec2 := h2.postExecute(srv2.Handler(), raw2, "application/json")
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected transparent checkpoint retry to succeed, got %d %s", rec2.Code, rec2.Body.String())
	}
	var out2 gateway.ExecuteResponse
	_ = json.Unmarshal(rec2.Body.Bytes(), &out2)
	var decBlock int64
	if err := h2.pool.QueryRow(t.Context(), `SELECT block_number FROM decisions WHERE deployment_id=$1 AND decision_id=$2`,
		h2.deploymentID, out2.DecisionID).Scan(&decBlock); err != nil {
		t.Fatal(err)
	}
	if decBlock != 2 {
		t.Fatalf("expected decision to record retried block 2, got %d", decBlock)
	}

	// 3. Checkpoint advances on every attempt -> 409 STATE_CHANGED.
	var blockSeq atomic.Int64
	blockSeq.Store(2)
	srv2.SetTestHooks(nil, func(attempt int) {
		b := blockSeq.Add(1)
		_, _ = h2.pool.Exec(context.Background(), `UPDATE fabric_head SET block_no=$2, hash=$3 WHERE deployment=$1`,
			h2.deploymentID, b, api.Digest([]byte(fmt.Sprintf("block-%d", b))))
	})
	req3 := h2.buildQuoteRequest("ckpt-conflict-key", 1)
	req3Hash, _ := req3.Hash(false)
	chal3 := h2.requestChallenge(t, srv2.Handler(), req3Hash)
	pkg3 := h2.assemblePackage(t, req3, chal3, h2.uPriv)
	raw3, _ := json.Marshal(pkg3)
	rec3 := h2.postExecute(srv2.Handler(), raw3, "application/json")
	if rec3.Code != http.StatusConflict || !strings.Contains(rec3.Body.String(), protocol.ErrCodeStateChanged) {
		t.Fatalf("expected 409 STATE_CHANGED on repeated checkpoint drift, got %d %s", rec3.Code, rec3.Body.String())
	}

	// 4. Exact-second deadline rejection (now == expiresAt -> rejected).
	curTime := h2.fixedNow
	srv3 := h2.newServer(func() time.Time { return curTime })
	h2.updateContext(t, srv3.Handler(), 1, "NORMAL", h2.taskExp)
	req4 := h2.buildQuoteRequest("exact-sec-key", 1)
	req4Hash, _ := req4.Hash(false)
	chal4 := h2.requestChallenge(t, srv3.Handler(), req4Hash)
	pkg4 := h2.assemblePackage(t, req4, chal4, h2.uPriv)
	raw4, _ := json.Marshal(pkg4)
	curTime = time.Unix(chal4.ExpiresAt, 0).UTC() // now == expiresAt
	rec4 := h2.postExecute(srv3.Handler(), raw4, "application/json")
	if rec4.Code != http.StatusUnauthorized || !strings.Contains(rec4.Body.String(), protocol.ErrCodeChallengeExpired) {
		t.Fatalf("expected 401 CHALLENGE_EXPIRED at exact second now==expiresAt, got %d %s", rec4.Code, rec4.Body.String())
	}
}
