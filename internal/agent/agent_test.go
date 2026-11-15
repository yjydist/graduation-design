package agent_test

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
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"graduation-design/internal/agent"
	"graduation-design/internal/fabric"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/policy"
	"graduation-design/internal/protocol"
)

type agentTestHarness struct {
	pool     *pgxpool.Pool
	depID    string
	audience string
	taskRP   string
	taskBM   string
	didB1    string
	fixedNow time.Time
	srv      *gateway.Server
	wallet   *agent.WalletContext
	sdJWTs   map[string]string
}

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
	return pool
}

func newAgentTestHarness(t *testing.T) *agentTestHarness {
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
	_, pubDomA, _ := protocol.GenerateP256KeyPair()
	_, pubDomC, _ := protocol.GenerateP256KeyPair()
	privPA, pubPA, _ := protocol.GenerateP256KeyPair()
	privU, pubU, _ := protocol.GenerateP256KeyPair()
	privA1, pubA1, _ := protocol.GenerateP256KeyPair()
	privB1, pubB1, _ := protocol.GenerateP256KeyPair()
	privC, pubC, _ := protocol.GenerateP256KeyPair()

	didT := "did:web:t.local"
	didA := "did:web:a.local"
	didC := "did:web:c.local"
	didIA := "did:web:a.local:ia"
	didIC := "did:web:c.local:ic"
	didPA := "did:web:a.local:pa"
	didU := "did:web:a.local:u"
	didA1 := "did:web:a.local:a1"
	didB1 := "did:web:a.local:b1"
	didCSvc := "did:web:c.local:supplier"
	audience := "https://c.local"

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
	digPA := makeDoc(didPA, didPA+"#key-1", pubPA, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
	digU := makeDoc(didU, didU+"#key-1", pubU, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
	digA1 := makeDoc(didA1, didA1+"#key-1", pubA1, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
	digB1 := makeDoc(didB1, didB1+"#key-1", pubB1, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
	digCSvc := makeDoc(didCSvc, didCSvc+"#key-1", pubC, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)

	didSrv, err := protocol.NewDIDWebServer(certs, docs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = didSrv.Close() })

	dids, err := protocol.NewDIDWebResolver(caPool, didSrv.Routes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dids.RegisterPreseed(protocol.RootPreseed{
		DID: didT, KeyID: didT + "#key-1", KeyVersion: 1,
		PublicKeyHex: pubT, DIDDocumentDigest: digT, RawDocument: docs[didT],
	}); err != nil {
		t.Fatal(err)
	}

	uniqueTag := fmt.Sprintf("agent-m2-%d", time.Now().UnixNano())
	depID := api.Digest([]byte("dep:" + uniqueTag))
	taskRP := api.Digest([]byte("task-rp:" + uniqueTag))
	taskBM := api.Digest([]byte("task-bm:" + uniqueTag))
	resID := api.Digest([]byte("res:" + uniqueTag))

	nbf := now.Add(-time.Hour).Unix()
	exp := now.Add(2 * time.Hour).Unix()
	policyDeadline := now.Add(4 * time.Hour).Unix()
	vf := time.Unix(nbf, 0).UTC().Format(time.RFC3339)
	vu := time.Unix(exp, 0).UTC().Format(time.RFC3339)

	rootRec := api.RootRecord{
		DID: didT, Management: api.Management{MSPID: "TMSP", Fingerprint: strings.Repeat("1", 64)},
		DocumentDigest: digT, KeyID: didT + "#key-1", KeyVersion: 1, PublicKey: pubT,
	}
	boot := api.Bootstrap{
		DeploymentFields: api.DeploymentFields{
			ChannelID: api.Channel, GenesisHash: api.Digest([]byte("genesis:" + uniqueTag)),
			InstanceID: api.Digest([]byte("inst:" + uniqueTag)), RegistryName: api.Registry, SchemaVersion: api.Schema,
		},
		Root: rootRec, Initializer: rootRec.Management,
		TaskCreator: api.TaskAuthority{Domain: "A", Subject: didU, Management: api.Management{MSPID: "AMSP", Fingerprint: strings.Repeat("2", 64)}},
		ResourceID:  resID, ResourceOwner: didCSvc,
		ResourceManagement: api.Management{MSPID: "CMSP", Fingerprint: strings.Repeat("3", 64)},
	}

	issueCert := func(domID, domDID, issuerDID, paDID string) (string, string, api.Domain, api.Certification) {
		certID := "urn:grad:domain-certification:" + domID + "-" + uniqueTag
		scopes := []protocol.IssuerScope{{
			ID: issuerDID, AppKeyVersion: 1,
			CredentialTypes: []string{protocol.CredentialTypeEnterpriseIdentity},
			ClaimNames:      []string{"domain", "role"},
		}}
		jws, dig, err := protocol.SignDomainAuthorityCredential(privT, rootRec.KeyID, &protocol.DomainAuthorityCredential{
			Type: []string{protocol.CredentialTypeVC, protocol.CredentialTypeDomainAuthority},
			ID: certID, DeploymentID: depID, Issuer: didT, Iss: didT, Sub: domDID,
			IssuerKeyVersion: 1, ValidFrom: vf, ValidUntil: vu, NBF: nbf, EXP: exp,
			CredentialStatus: protocol.CredentialStatus{ID: certID, Type: protocol.StatusTypeDomainCertification},
			CredentialSubject: protocol.DomainAuthoritySubject{ID: domDID, DomainID: domID, IdentityIssuers: scopes},
		})
		if err != nil {
			t.Fatal(err)
		}
		dom := api.Domain{
			Bound: api.Bound{DeploymentID: depID}, ID: domID, DID: domDID,
			Admin:     api.Management{MSPID: domID + "MSP", Fingerprint: strings.Repeat("a", 64)},
			Registrar: api.Management{MSPID: domID + "MSP", Fingerprint: strings.Repeat("b", 64)},
			Issuers:   []string{issuerDID}, Certification: certID, PurchasingAuthority: paDID,
			Version: api.Version{Status: api.Active, Revision: 1},
		}
		cert := api.Certification{
			Bound: api.Bound{DeploymentID: depID}, ID: certID, Domain: domID,
			RootKeyVersion: 1, Digest: dig,
			Scopes:   []api.Scope{{ID: issuerDID, KeyVersion: 1, Types: []string{protocol.CredentialTypeEnterpriseIdentity}, Claims: []string{"domain", "role"}}},
			Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1},
		}
		return jws, dig, dom, cert
	}

	certAJWS, certADig, domA, certA := issueCert("A", didA, didIA, didPA)
	certCJWS, certCDig, domC, certC := issueCert("C", didC, didIC, "")

	makeID := func(did, domID, kind, keyID, pub, dig string) api.Identity {
		return api.Identity{
			Bound: api.Bound{DeploymentID: depID}, ID: did, Domain: domID, Kind: kind,
			Management: api.Management{MSPID: domID + "MSP", Fingerprint: strings.Repeat("4", 64)},
			DocumentDigest: dig, KeyID: keyID, KeyVersion: 1, PublicKey: pub,
			AccountCommitment: api.Digest([]byte("acct:" + did)),
			Version:           api.Version{Status: api.Active, Revision: 1},
		}
	}
	idA := makeID(didA, "A", "DOMAIN", didA+"#key-1", pubDomA, digA)
	idC_dom := makeID(didC, "C", "DOMAIN", didC+"#key-1", pubDomC, digC)
	idIA := makeID(didIA, "A", "ISSUER", didIA+"#key-1", pubIA, digIA)
	idIC := makeID(didIC, "C", "ISSUER", didIC+"#key-1", pubIC, digIC)
	idPA := makeID(didPA, "A", "SERVICE", didPA+"#key-1", pubPA, digPA)
	idU := makeID(didU, "A", "USER", didU+"#key-1", pubU, digU)
	idA1 := makeID(didA1, "A", "AGENT", didA1+"#key-1", pubA1, digA1)
	idB1 := makeID(didB1, "A", "AGENT", didB1+"#key-1", pubB1, digB1)
	idCSvc := makeID(didCSvc, "C", "SERVICE", didCSvc+"#key-1", pubC, digCSvc)

	issueSD := func(priv *ecdsa.PrivateKey, iss, sub, credID, dom, role, holderPub string) (*protocol.SignedSDJWTCredential, api.Credential) {
		jwk, err := protocol.AppPublicKeyToJWK(holderPub)
		if err != nil {
			t.Fatal(err)
		}
		sd, err := protocol.IssueEnterpriseIdentityCredential(priv, iss+"#key-1", protocol.EnterpriseIdentityCredential{
			Type: []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity},
			ID: credID, DeploymentID: depID, Issuer: iss, Iss: iss, Sub: sub,
			IssuerKeyVersion: 1, AppKeyVersion: 1, ValidFrom: vf, ValidUntil: vu, NBF: nbf, EXP: exp,
			CredentialStatus: protocol.CredentialStatus{ID: credID, Type: protocol.StatusTypeCredential},
			Cnf:              protocol.ConfirmationKey{JWK: jwk},
			CredentialSubject: protocol.SDJWTCredentialSubject{ID: sub},
		}, dom, role, nil)
		if err != nil {
			t.Fatal(err)
		}
		return sd, api.Credential{
			Bound: api.Bound{DeploymentID: depID}, ID: credID, Issuer: iss, Subject: sub,
			IssuerKeyVersion: 1, SubjectKeyVersion: 1, Type: protocol.CredentialTypeEnterpriseIdentity,
			ClaimNames: []string{"domain", "role"}, Digest: sd.AnchorDigest,
			Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1},
		}
	}

	cCredID := "urn:grad:credential:C-" + uniqueTag
	paCredID := "urn:grad:credential:PA-" + uniqueTag
	uCredID := "urn:grad:credential:U-" + uniqueTag
	a1CredID := "urn:grad:credential:A1-" + uniqueTag
	b1CredID := "urn:grad:credential:B1-" + uniqueTag

	sdC, chainCredC := issueSD(privIC, didIC, didCSvc, cCredID, "C", "supplier-service", pubC)
	sdPA, chainCredPA := issueSD(privIA, didIA, didPA, paCredID, "A", "procurement-authority", pubPA)
	sdU, chainCredU := issueSD(privIA, didIA, didU, uCredID, "A", "procurement-owner", pubU)
	sdA1, chainCredA1 := issueSD(privIA, didIA, didA1, a1CredID, "A", "procurement-agent", pubA1)
	sdB1, chainCredB1 := issueSD(privIA, didIA, didB1, b1CredID, "A", "buyer-delegate", pubB1)

	spec := protocol.TaskSpec{
		SupplierID:  "urn:grad:supplier:C",
		ProductID:   "urn:grad:product:P1",
		MaxQuantity: 10,
		Currency:    "CNY",
		Resources:   []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions:     []string{"order.create", "quote.read"},
		Description: "agent M2 procurement delegation",
	}
	taskDig, err := spec.Digest()
	if err != nil {
		t.Fatal(err)
	}

	makeGrant := func(id, taskID, mode, resID string, parent *string, parentDig *string, rootID, iss, issCred string, issPriv *ecdsa.PrivateKey, sub, subCred string, depth int64) (protocol.GrantClaims, string, string, api.Grant) {
		c := protocol.GrantClaims{
			SchemaVersion: api.Schema, DeploymentID: depID, ID: id, RootID: rootID,
			ParentID: parent, ParentDigest: parentDig, TaskID: taskID,
			AuthorizationMode: mode, PrincipalDomain: "A", ResourceID: resID,
			Aud: audience, Issuer: iss, IssuerKeyVersion: 1, IssuerCredentialID: issCred,
			Grantee: sub, GranteeKeyVersion: 1, GranteeCredentialID: subCred,
			Resources: spec.Resources, Actions: spec.Actions, Suppliers: []string{"urn:grad:supplier:C"},
			Currency: "CNY", MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: depth,
		}
		jws, dig, gErr := protocol.SignGrant(issPriv, iss+"#key-1", &c)
		if gErr != nil {
			t.Fatal(gErr)
		}
		var pID, pDig string
		if parent != nil {
			pID = *parent
		}
		if parentDig != nil {
			pDig = *parentDig
		}
		chain := api.Grant{
			Bound: api.Bound{DeploymentID: depID}, ID: id, Schema: api.Schema, Parent: pID, ParentDigest: pDig, Root: rootID,
			Task: taskID, Mode: mode, Domain: "A", Resource: resID,
			Issuer: iss, Grantee: sub, IssuerKeyVersion: 1, GranteeKeyVersion: 1,
			IssuerCredential: issCred, GranteeCredential: subCred,
			Depth: uint8(depth), Digest: dig,
			Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1},
		}
		return c, jws, dig, chain
	}

	rpG0ID := api.Digest([]byte("rp-g0:" + uniqueTag))
	rpG1ID := api.Digest([]byte("rp-g1:" + uniqueTag))
	rpG0Claims, rpG0JWS, rpG0Dig, rpG0Chain := makeGrant(rpG0ID, taskRP, api.RP, resID, nil, nil, rpG0ID, didCSvc, cCredID, privC, didU, uCredID, 2)
	rpG1Claims, rpG1JWS, rpG1Dig, rpG1Chain := makeGrant(rpG1ID, taskRP, api.RP, resID, &rpG0ID, &rpG0Dig, rpG0ID, didU, uCredID, privU, didA1, a1CredID, 1)

	bmG0ID := api.Digest([]byte("bm-g0:" + uniqueTag))
	bmG1ID := api.Digest([]byte("bm-g1:" + uniqueTag))
	bmG0Claims, bmG0JWS, bmG0Dig, bmG0Chain := makeGrant(bmG0ID, taskBM, api.BM, didPA, nil, nil, bmG0ID, didPA, paCredID, privPA, didU, uCredID, 2)
	bmG1Claims, bmG1JWS, bmG1Dig, bmG1Chain := makeGrant(bmG1ID, taskBM, api.BM, didPA, &bmG0ID, &bmG0Dig, bmG0ID, didU, uCredID, privU, didA1, a1CredID, 1)
	_, _ = rpG0Claims, bmG0Claims

	if err := gateway.EnsureSchema(ctx, pool, depID, "urn:grad:supplier:C"); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	putKV := func(k string, v any) {
		raw, mErr := json.Marshal(v)
		if mErr != nil {
			t.Fatal(mErr)
		}
		if _, eErr := tx.Exec(ctx, `INSERT INTO fabric_current(deployment, key, value) VALUES($1,$2,$3)
			ON CONFLICT(deployment,key) DO UPDATE SET value=EXCLUDED.value`, depID, k, raw); eErr != nil {
			t.Fatal(eErr)
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
	putKV(api.Key("identity", didPA), idPA)
	putKV(api.Key("identity", didU), idU)
	putKV(api.Key("identity", didA1), idA1)
	putKV(api.Key("identity", didB1), idB1)
	putKV(api.Key("identity", didCSvc), idCSvc)
	putKV(api.Key("credential", cCredID), chainCredC)
	putKV(api.Key("credential", paCredID), chainCredPA)
	putKV(api.Key("credential", uCredID), chainCredU)
	putKV(api.Key("credential", a1CredID), chainCredA1)
	putKV(api.Key("credential", b1CredID), chainCredB1)
	putKV(api.Key("task", taskRP), api.Task{
		Bound: api.Bound{DeploymentID: depID}, ID: taskRP, Creator: didU, CreatorKeyVersion: 1,
		CreatorCredential: uCredID, Resource: resID, Mode: api.RP, Domain: "A", Digest: taskDig,
		Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1},
	})
	putKV(api.Key("task", taskBM), api.Task{
		Bound: api.Bound{DeploymentID: depID}, ID: taskBM, Creator: didU, CreatorKeyVersion: 1,
		CreatorCredential: uCredID, Resource: didPA, Mode: api.BM, Domain: "A", Digest: taskDig,
		Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1},
	})
	putKV(api.Key("grant", rpG0ID), rpG0Chain)
	putKV(api.Key("grant", rpG1ID), rpG1Chain)
	putKV(api.Key("grant", bmG0ID), bmG0Chain)
	putKV(api.Key("grant", bmG1ID), bmG1Chain)

	for _, item := range []struct{ domID, certID, jws, dig string }{
		{"A", certA.ID, certAJWS, certADig},
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
		_, _ = pool.Exec(bg, `DELETE FROM client_actions WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM orders WHERE deployment_id=$1`, depID)
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

	files, polDig, err := policy.BuildDefaultBundle(depID, didCSvc, policy.DefaultPolicyVersion, rootRec, &policyDeadline)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := policy.VerifyAndLoadBundle(files, depID, didCSvc, rootRec, polDig)
	if err != nil {
		t.Fatal(err)
	}

	sp := fabric.NewStateProviderFromBootstrap(pool, depID, boot, nil)
	monoNow := now
	sp.SetMonoClock(func() time.Time { return monoNow })
	sp.SetStaticProbe(&fabric.ProbeSnapshot{
		TxID: "probe-tx-" + uniqueTag, ProbeBlock: 1, SentAt: now, Deadline: now.Add(5 * time.Second),
		SentMonoNs: monoNow.UnixNano(), DeadlineMonoNs: monoNow.Add(5 * time.Second).UnixNano(),
		AdoptedAt: now, AdoptedMonoNs: monoNow.UnixNano(),
	})

	srv, err := gateway.NewServer(gateway.Config{
		DB: pool, State: sp.GatewayAdapter(), Delivery: fabric.NewDeliveryService(pool),
		DIDs: dids, Policy: bundle, DeploymentID: depID, ServiceDID: didCSvc,
		Audience: audience, SupplierID: "urn:grad:supplier:C",
		NowFn: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("gateway.NewServer: %v", err)
	}

	for _, tid := range []string{taskRP, taskBM} {
		ctxBody, _ := json.Marshal(gateway.ContextUpdateRequest{
			ExpectedContextVersion: 0,
			SourceID:               "risk-engine-1",
			ObservedAt:             now.Unix(),
			RiskLevel:              "NORMAL",
			AccessDeadline:         exp,
		})
		ctxReq := httptest.NewRequest(http.MethodPost, "/v1/contexts/"+tid, bytes.NewReader(ctxBody))
		ctxReq.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, ctxReq)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST /v1/contexts/%s status=%d body=%s", tid, rec.Code, rec.Body.String())
		}
	}

	wallet, err := agent.NewWalletContext(agent.WalletConfig{
		DeploymentID: depID, Audience: audience, SupplierID: "urn:grad:supplier:C", SupplierDID: didCSvc,
		DefaultTaskSpec: spec, Currency: "CNY", DB: pool, HTTPHandler: srv.Handler(),
		Now: func() time.Time { return now },
		AnchorChildFunc: func(ctx context.Context, req agent.AnchorChildGrantRequest) (*agent.AnchorChildGrantResult, error) {
			pDig := ""
			if req.Claims.ParentDigest != nil {
				pDig = *req.Claims.ParentDigest
			}
			gChain := api.Grant{
				Bound: api.Bound{DeploymentID: depID}, ID: req.Claims.ID, Schema: api.Schema,
				Parent: req.ParentID, ParentDigest: pDig, Root: req.Claims.RootID, Task: req.Claims.TaskID,
				Mode: req.Claims.AuthorizationMode, Domain: req.Claims.PrincipalDomain, Resource: req.Claims.ResourceID,
				Issuer: req.Claims.Issuer, Grantee: req.Claims.Grantee,
				IssuerKeyVersion: req.Claims.IssuerKeyVersion, GranteeKeyVersion: req.Claims.GranteeKeyVersion,
				IssuerCredential: req.Claims.IssuerCredentialID, GranteeCredential: req.Claims.GranteeCredentialID,
				Depth: uint8(req.Claims.RemainingDepth), Digest: req.GrantDigest,
				Interval: api.Interval{NBF: req.Claims.NBF, EXP: req.Claims.EXP},
				Version: api.Version{Status: api.Active, Revision: 1},
			}
			raw, _ := json.Marshal(gChain)
			if _, eErr := pool.Exec(ctx, `INSERT INTO fabric_current(deployment, key, value) VALUES($1,$2,$3)
				ON CONFLICT(deployment,key) DO UPDATE SET value=EXCLUDED.value`, depID, api.Key("grant", req.Claims.ID), raw); eErr != nil {
				return nil, eErr
			}
			tp := []protocol.TrustPathEntry{{Issuer: didIA, DomainCertification: certAJWS}}
			if req.Claims.AuthorizationMode == api.RP {
				tp = append(tp, protocol.TrustPathEntry{Issuer: didIC, DomainCertification: certCJWS})
			}
			return &agent.AnchorChildGrantResult{Anchored: true, TrustPaths: tp}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewWalletContext: %v", err)
	}

	if err := wallet.RegisterActor(agent.ActorConfig{
		Actor: "A1", DID: didA1, KeyID: didA1 + "#key-1", CredentialID: a1CredID, KeyVersion: 1,
		DomainID: "A", EntityType: "AGENT", Roles: []string{"procurement-agent"}, PrivateKey: privA1, SDJWTPresentation: sdA1.PresentationPrefix,
	}); err != nil {
		t.Fatal(err)
	}
	if err := wallet.RegisterActor(agent.ActorConfig{
		Actor: "B1", DID: didB1, KeyID: didB1 + "#key-1", CredentialID: b1CredID, KeyVersion: 1,
		DomainID: "A", EntityType: "AGENT", Roles: []string{"buyer-delegate"}, PrivateKey: privB1, SDJWTPresentation: sdB1.PresentationPrefix,
	}); err != nil {
		t.Fatal(err)
	}

	if err := wallet.AddGrantBundle(agent.GrantBundle{
		Claims: rpG1Claims, TaskSpec: spec, RawGrantJWS: rpG1JWS, Digest: rpG1Dig,
		ChainRawGrants: []string{rpG0JWS, rpG1JWS},
		AncestorCredentials: []protocol.AncestorCredential{
			{CredentialID: cCredID, Presentation: sdC.PresentationPrefix},
			{CredentialID: uCredID, Presentation: sdU.PresentationPrefix},
		},
		TrustPaths: []protocol.TrustPathEntry{
			{Issuer: didIA, DomainCertification: certAJWS},
			{Issuer: didIC, DomainCertification: certCJWS},
		},
		Anchored: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := wallet.AddGrantBundle(agent.GrantBundle{
		Claims: bmG1Claims, TaskSpec: spec, RawGrantJWS: bmG1JWS, Digest: bmG1Dig,
		ChainRawGrants: []string{bmG0JWS, bmG1JWS},
		AncestorCredentials: []protocol.AncestorCredential{
			{CredentialID: paCredID, Presentation: sdPA.PresentationPrefix},
			{CredentialID: uCredID, Presentation: sdU.PresentationPrefix},
		},
		TrustPaths: []protocol.TrustPathEntry{
			{Issuer: didIA, DomainCertification: certAJWS},
		},
		Anchored: true,
	}); err != nil {
		t.Fatal(err)
	}

	return &agentTestHarness{
		pool: pool, depID: depID, audience: audience, taskRP: taskRP, taskBM: taskBM,
		didB1: didB1, fixedNow: now, srv: srv, wallet: wallet,
		sdJWTs: map[string]string{
			"A1": sdA1.PresentationPrefix, "B1": sdB1.PresentationPrefix,
			"C": sdC.PresentationPrefix, "PA": sdPA.PresentationPrefix, "U": sdU.PresentationPrefix,
		},
	}
}

func assertNoSecrets(t *testing.T, label, payload string, secrets ...string) {
	t.Helper()
	if strings.Contains(payload, "PRIVATE KEY") {
		t.Fatalf("%s leaked PRIVATE KEY", label)
	}
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(payload, s) {
			t.Fatalf("%s leaked raw secret material", label)
		}
		if idx := strings.IndexByte(s, '~'); idx >= 0 && idx+1 < len(s) {
			for _, part := range strings.Split(s[idx+1:], "~") {
				if len(part) >= 8 && strings.Contains(payload, part) {
					t.Fatalf("%s leaked raw SD-JWT disclosure salt", label)
				}
			}
		}
	}
}

func TestMCPInMemoryToolsDelegationClientActionsAndRedaction(t *testing.T) {
	h := newAgentTestHarness(t)
	ctx := t.Context()

	mcpSrv := agent.NewMCPServer(h.wallet)
	t1, t2 := mcp.NewInMemoryTransports()
	srvSess, err := mcpSrv.Connect(ctx, t1, nil)
	if err != nil {
		t.Fatalf("connect MCP server: %v", err)
	}
	defer srvSess.Close()

	cli := mcp.NewClient(&mcp.Implementation{Name: "test-mcp-client", Version: "v0.1"}, nil)
	cliSess, err := cli.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("connect MCP client: %v", err)
	}
	defer cliSess.Close()

	callJSON := func(name string, args map[string]any, dst any) {
		res, cErr := cliSess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if cErr != nil {
			t.Fatalf("CallTool(%s): %v", name, cErr)
		}
		if res.IsError {
			t.Fatalf("CallTool(%s) returned error: %+v", name, res.Content)
		}
		raw, _ := json.Marshal(res.StructuredContent)
		assertNoSecrets(t, "MCP "+name, string(raw), h.sdJWTs["A1"], h.sdJWTs["B1"], h.sdJWTs["U"], h.sdJWTs["PA"], h.sdJWTs["C"])
		if err := json.Unmarshal(raw, dst); err != nil {
			t.Fatalf("decode %s output: %v", name, err)
		}
	}

	var insp agent.InspectWalletOutput
	callJSON("inspect_wallet", map[string]any{"actor": "A1"}, &insp)
	if len(insp.Grants) != 2 {
		t.Fatalf("expected 2 grants for A1 (RP+BM), got %d", len(insp.Grants))
	}

	for _, tc := range []struct {
		mode   string
		taskID string
		parent string
		child  string
	}{
		{api.RP, h.taskRP, api.Digest([]byte("rp-g1:"+strings.TrimPrefix(h.depID, ""))), ""},
	} {
		_ = tc
	}

	// Select A1's actual RP and BM parent grant IDs from inspect_wallet
	parentsByMode := map[string]agent.SanitizedGrantView{}
	for _, g := range insp.Grants {
		parentsByMode[g.AuthorizationMode] = g
	}
	for _, mode := range []string{api.RP, api.BM} {
		parent := parentsByMode[mode]
		childID := fmt.Sprintf("g2-%s-%d", mode, len(h.depID))
		var del agent.DelegateGrantOutput
		callJSON("delegate_grant", map[string]any{
			"issuerActor": "A1", "subjectActor": "B1", "parentGrantId": parent.GrantID, "grantId": childID,
			"taskId": parent.TaskID, "authorizationMode": mode, "maxAmountMinor": 100000, "remainingDepth": 0,
		}, &del)
		if !del.Anchored || del.Grant.MaxAmountMinor != 100000 || del.Grant.RemainingDepth != 0 {
			t.Fatalf("unexpected delegate_grant output for %s: %+v", mode, del)
		}

		var qOK agent.RequestQuoteOutput
		callJSON("request_quote", map[string]any{
			"actor": "B1", "grantId": childID, "taskId": parent.TaskID, "authorizationMode": mode,
			"productId": "urn:grad:product:P1", "quantity": 1,
		}, &qOK)
		if qOK.Decision != "ALLOW" || qOK.TotalAmountMinor != 80000 || qOK.QuoteID == "" {
			t.Fatalf("%s 800 quote failed: %+v", mode, qOK)
		}

		idemOK := "mcp-ok-" + mode
		var ordOK agent.CreateOrderOutput
		callJSON("create_order", map[string]any{
			"actor": "B1", "grantId": childID, "taskId": parent.TaskID, "authorizationMode": mode,
			"quoteId": qOK.QuoteID, "amountMinor": 80000, "idempotencyKey": idemOK,
		}, &ordOK)
		if ordOK.Decision != "ALLOW" || ordOK.OrderID == "" || ordOK.ActionStatus != "COMPLETED" {
			t.Fatalf("%s 800 create_order expected ALLOW, got %+v", mode, ordOK)
		}

		actRec, actErr := gateway.GetClientActionByKey(ctx, h.pool, h.depID, h.didB1, parent.TaskID, "order.create", idemOK)
		if actErr != nil || actRec == nil || actRec.Status != "COMPLETED" || actRec.OrderID != ordOK.OrderID {
			t.Fatalf("%s client_actions mismatch: rec=%+v err=%v", mode, actRec, actErr)
		}

		if _, err := h.pool.Exec(ctx, `UPDATE catalog_prices SET unit_price_minor=120000 WHERE deployment_id=$1 AND product_id=$2`, h.depID, gateway.DefaultProductID); err != nil {
			t.Fatal(err)
		}
		var qOver agent.RequestQuoteOutput
		callJSON("request_quote", map[string]any{
			"actor": "B1", "grantId": childID, "taskId": parent.TaskID, "authorizationMode": mode,
			"productId": "urn:grad:product:P1", "quantity": 1,
		}, &qOver)
		if qOver.Decision != "ALLOW" || qOver.TotalAmountMinor != 120000 {
			t.Fatalf("%s 1200 quote failed: %+v", mode, qOver)
		}

		idemOver := "mcp-over-" + mode
		var ordOver agent.CreateOrderOutput
		callJSON("create_order", map[string]any{
			"actor": "B1", "grantId": childID, "taskId": parent.TaskID, "authorizationMode": mode,
			"quoteId": qOver.QuoteID, "amountMinor": 120000, "idempotencyKey": idemOver,
		}, &ordOver)
		if ordOver.Decision != "DENY" || ordOver.ErrorCode != protocol.ErrCodeAmountLimitExceeded || ordOver.OrderID != "" || ordOver.ActionStatus != "FAILED" {
			t.Fatalf("%s 1200 create_order expected AMOUNT_LIMIT_EXCEEDED/FAILED, got %+v", mode, ordOver)
		}
		if _, err := h.pool.Exec(ctx, `UPDATE catalog_prices SET unit_price_minor=80000 WHERE deployment_id=$1 AND product_id=$2`, h.depID, gateway.DefaultProductID); err != nil {
			t.Fatal(err)
		}
	}

	var orderCount int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM orders WHERE deployment_id=$1`, h.depID).Scan(&orderCount); err != nil {
		t.Fatalf("count orders: %v", err)
	}
	if orderCount != 2 {
		t.Fatalf("expected exactly 2 orders (RP 800 + BM 800), got %d", orderCount)
	}
}

func TestAgentRunnerDualSDKOpenAIAndAnthropicMockClosedLoop(t *testing.T) {
	h := newAgentTestHarness(t)
	ctx := t.Context()

	type scriptAction struct {
		toolName string
		args     map[string]any
	}
	// Query A1 grants from wallet via MCP inspect_wallet once so exact grantIds are used.
	scriptForMode := func(mode, taskID, parentID, childID string) []scriptAction {
		return []scriptAction{
			{"inspect_wallet", map[string]any{"actor": "A1", "taskId": taskID, "authorizationMode": mode}},
			{"delegate_grant", map[string]any{
				"issuerActor": "A1", "subjectActor": "B1", "parentGrantId": parentID, "grantId": childID,
				"taskId": taskID, "authorizationMode": mode, "maxAmountMinor": 100000, "remainingDepth": 0,
			}},
			{"request_quote", map[string]any{"actor": "B1", "grantId": childID, "taskId": taskID, "authorizationMode": mode, "productId": "urn:grad:product:P1", "quantity": 1}},
			{"create_order", map[string]any{"actor": "B1", "grantId": childID, "taskId": taskID, "authorizationMode": mode, "quoteId": "{{LAST_QUOTE_ID}}", "amountMinor": 80000, "idempotencyKey": "llm-ok-" + childID}},
			{"request_quote", map[string]any{"actor": "B1", "grantId": childID, "taskId": taskID, "authorizationMode": mode, "productId": "urn:grad:product:P1", "quantity": 1}},
			{"create_order", map[string]any{"actor": "B1", "grantId": childID, "taskId": taskID, "authorizationMode": mode, "quoteId": "{{LAST_QUOTE_ID}}", "amountMinor": 120000, "idempotencyKey": "llm-over-" + childID}},
		}
	}

	resolveArgs := func(raw map[string]any, lastQuoteID string) map[string]any {
		out := map[string]any{}
		for k, v := range raw {
			if s, ok := v.(string); ok && s == "{{LAST_QUOTE_ID}}" {
				out[k] = lastQuoteID
			} else {
				out[k] = v
			}
		}
		return out
	}

	extractLastQuoteID := func(content string) string {
		var m map[string]any
		if json.Unmarshal([]byte(content), &m) == nil {
			if qid, ok := m["quoteId"].(string); ok && qid != "" {
				return qid
			}
		}
		return ""
	}
	extractFirstGrantID := func(content string) string {
		var m struct {
			Grants []struct {
				GrantID string `json:"grantId"`
			} `json:"grants"`
		}
		if json.Unmarshal([]byte(content), &m) == nil && len(m.Grants) > 0 {
			return m.Grants[0].GrantID
		}
		return ""
	}

	// 1. OpenAI mock driving RP mode end-to-end
	{
		var mu sync.Mutex
		step := 0
		lastQuote := ""
		parentID := ""
		actions := scriptForMode(api.RP, h.taskRP, "{{PARENT_GRANT_ID}}", "rpg2-oai")
		oaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody struct {
				Messages []struct {
					Role    string `json:"role"`
					Content any    `json:"content"`
				} `json:"messages"`
			}
			_ = json.NewDecoder(r.Body).Decode(&reqBody)
			mu.Lock()
			defer mu.Unlock()
			if n := len(reqBody.Messages); n > 0 {
				if cStr, ok := reqBody.Messages[n-1].Content.(string); ok {
					if q := extractLastQuoteID(cStr); q != "" {
						lastQuote = q
					}
					if g := extractFirstGrantID(cStr); g != "" {
						parentID = g
					}
				}
			}
			w.Header().Set("Content-Type", "application/json")
			if step >= len(actions) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "chatcmpl-done", "object": "chat.completion", "model": "mock-openai-model",
					"choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": "RP closed loop complete: 80000 order succeeded, 120000 refused."}}},
				})
				return
			}
			act := actions[step]
			if act.toolName == "request_quote" && step == 4 {
				_, _ = h.pool.Exec(ctx, `UPDATE catalog_prices SET unit_price_minor=120000 WHERE deployment_id=$1 AND product_id=$2`, h.depID, gateway.DefaultProductID)
			} else if act.toolName == "request_quote" && step == 2 {
				_, _ = h.pool.Exec(ctx, `UPDATE catalog_prices SET unit_price_minor=80000 WHERE deployment_id=$1 AND product_id=$2`, h.depID, gateway.DefaultProductID)
			}
			step++
			args := resolveArgs(act.args, lastQuote)
			if p, ok := args["parentGrantId"].(string); ok && p == "{{PARENT_GRANT_ID}}" {
				args["parentGrantId"] = parentID
			}
			argBytes, _ := json.Marshal(args)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": fmt.Sprintf("chatcmpl-%d", step), "object": "chat.completion", "model": "mock-openai-model",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "tool_calls",
					"message": map[string]any{
						"role": "assistant", "content": "",
						"tool_calls": []any{map[string]any{
							"id": fmt.Sprintf("call_%d", step), "type": "function",
							"function": map[string]any{"name": act.toolName, "arguments": string(argBytes)},
						}},
					},
				}},
			})
		}))
		defer oaiSrv.Close()

		secretKey := "sk-mock-openai-secret-999"
		h.wallet.RegisterSecret(secretKey)
		res, err := agent.RunAgentTask(ctx, agent.NewMCPServer(h.wallet), agent.RunnerConfig{
			Provider: agent.ProviderOpenAI, BaseURL: oaiSrv.URL + "/v1", APIKey: secretKey,
			Model: "mock-openai-model", MaxSteps: 10,
		}, "Execute RP delegation, 80000 quote+order and verify 120000 denial.")
		if err != nil {
			t.Fatalf("RunAgentTask(openai): %v", err)
		}
		if res.ToolCallsCount != 6 || res.Steps != 7 || res.LLMLatencyMs < 0 {
			t.Fatalf("unexpected OpenAI RunResult metrics: %+v", res)
		}
		resJSON, _ := json.Marshal(res)
		assertNoSecrets(t, "OpenAI RunResult", string(resJSON), secretKey, h.sdJWTs["A1"], h.sdJWTs["B1"])
	}

	// 2. Anthropic mock driving BM mode end-to-end
	{
		var mu sync.Mutex
		step := 0
		lastQuote := ""
		parentID := ""
		actions := scriptForMode(api.BM, h.taskBM, "{{PARENT_GRANT_ID}}", "bmg2-ant")
		antSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody struct {
				Messages []struct {
					Role    string            `json:"role"`
					Content []json.RawMessage `json:"content"`
				} `json:"messages"`
			}
			_ = json.NewDecoder(r.Body).Decode(&reqBody)
			mu.Lock()
			defer mu.Unlock()
			if n := len(reqBody.Messages); n > 0 {
				for _, rawBlk := range reqBody.Messages[n-1].Content {
					var blk struct {
						Type    string          `json:"type"`
						Content json.RawMessage `json:"content"`
					}
					if json.Unmarshal(rawBlk, &blk) == nil && blk.Type == "tool_result" {
						var texts []string
						var single string
						if json.Unmarshal(blk.Content, &single) == nil {
							texts = append(texts, single)
						} else {
							var arr []struct {
								Text string `json:"text"`
							}
							if json.Unmarshal(blk.Content, &arr) == nil {
								for _, item := range arr {
									texts = append(texts, item.Text)
								}
							}
						}
						for _, txt := range texts {
							if q := extractLastQuoteID(txt); q != "" {
								lastQuote = q
							}
							if g := extractFirstGrantID(txt); g != "" {
								parentID = g
							}
						}
					}
				}
			}
			w.Header().Set("Content-Type", "application/json")
			if step >= len(actions) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "msg_done", "type": "message", "role": "assistant", "model": "mock-anthropic-model",
					"stop_reason": "end_turn",
					"content":     []any{map[string]any{"type": "text", "text": "BM closed loop complete: 80000 order succeeded, 120000 refused."}},
					"usage":       map[string]any{"input_tokens": 100, "output_tokens": 40},
				})
				return
			}
			act := actions[step]
			if act.toolName == "request_quote" && step == 4 {
				_, _ = h.pool.Exec(ctx, `UPDATE catalog_prices SET unit_price_minor=120000 WHERE deployment_id=$1 AND product_id=$2`, h.depID, gateway.DefaultProductID)
			} else if act.toolName == "request_quote" && step == 2 {
				_, _ = h.pool.Exec(ctx, `UPDATE catalog_prices SET unit_price_minor=80000 WHERE deployment_id=$1 AND product_id=$2`, h.depID, gateway.DefaultProductID)
			}
			step++
			args := resolveArgs(act.args, lastQuote)
			if p, ok := args["parentGrantId"].(string); ok && p == "{{PARENT_GRANT_ID}}" {
				args["parentGrantId"] = parentID
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": fmt.Sprintf("msg_%d", step), "type": "message", "role": "assistant", "model": "mock-anthropic-model",
				"stop_reason": "tool_use",
				"content": []any{map[string]any{
					"type": "tool_use", "id": fmt.Sprintf("toolu_%d", step), "name": act.toolName, "input": args,
				}},
				"usage": map[string]any{"input_tokens": 120, "output_tokens": 60},
			})
		}))
		defer antSrv.Close()

		secretKey := "sk-ant-mock-secret-999"
		h.wallet.RegisterSecret(secretKey)
		res, err := agent.RunAgentTask(ctx, agent.NewMCPServer(h.wallet), agent.RunnerConfig{
			Provider: agent.ProviderAnthropic, BaseURL: antSrv.URL, APIKey: secretKey,
			Model: "mock-anthropic-model", MaxSteps: 10,
		}, "Execute BM delegation, 80000 quote+order and verify 120000 denial.")
		if err != nil {
			t.Fatalf("RunAgentTask(anthropic): %v", err)
		}
		if res.ToolCallsCount != 6 || res.Steps != 7 || res.LLMLatencyMs < 0 {
			t.Fatalf("unexpected Anthropic RunResult metrics: %+v", res)
		}
		for _, tr := range res.ToolTraces {
			t.Logf("anthropic step=%d tool=%s err=%v out=%v", tr.Step, tr.ToolName, tr.IsError, tr.Output)
		}
		resJSON, _ := json.Marshal(res)
		assertNoSecrets(t, "Anthropic RunResult", string(resJSON), secretKey, h.sdJWTs["A1"], h.sdJWTs["B1"])
	}

	var orderCount int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM orders WHERE deployment_id=$1`, h.depID).Scan(&orderCount); err != nil {
		t.Fatalf("count orders: %v", err)
	}
	if orderCount != 2 {
		t.Fatalf("expected exactly 2 orders (RP 800 + BM 800), got %d", orderCount)
	}
}
