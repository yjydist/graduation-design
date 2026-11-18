package agent_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
	"graduation-design/internal/serviceauth"
)

type dropResponseTransport struct {
	base           http.RoundTripper
	dropAfterKeys  map[string]bool
	dropBeforeKeys map[string]bool
	mu             sync.Mutex
}

func (d *dropResponseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || req.URL.Path != "/v1/access/execute" || req.Body == nil {
		return d.base.RoundTrip(req)
	}
	rawBody, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(rawBody))

	var pkg struct {
		Request struct {
			Action         string `json:"action"`
			IdempotencyKey string `json:"idempotencyKey"`
		} `json:"request"`
	}
	_ = json.Unmarshal(rawBody, &pkg)
	idemKey := pkg.Request.IdempotencyKey

	d.mu.Lock()
	shouldDropBefore := d.dropBeforeKeys[idemKey] && pkg.Request.Action == "order.create"
	if shouldDropBefore {
		delete(d.dropBeforeKeys, idemKey)
	}
	shouldDropAfter := d.dropAfterKeys[idemKey] && pkg.Request.Action == "order.create"
	if shouldDropAfter {
		delete(d.dropAfterKeys, idemKey)
	}
	d.mu.Unlock()

	if shouldDropBefore {
		return nil, errors.New("simulated network timeout before gateway delivery")
	}
	resp, err := d.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if shouldDropAfter {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, io.ErrUnexpectedEOF
	}
	return resp, nil
}

type agentRecoveryHarness struct {
	pool       *pgxpool.Pool
	depID      string
	audience   string
	taskRP     string
	taskBM     string
	resID      string
	rpG1ID     string
	bmG1ID     string
	didB1      string
	didB2      string
	fixedNow   time.Time
	advanceNow func(time.Duration)
	srv        *gateway.Server
	httpSrv    *httptest.Server
	transport  *dropResponseTransport
	sp         *fabric.StateProvider
	wallet     *agent.WalletContext
	sdJWTs     map[string]string
	revokeFn   func(grantID string)
}

func newAgentRecoveryHarness(t *testing.T, tag string) *agentRecoveryHarness {
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
	privB2, pubB2, _ := protocol.GenerateP256KeyPair()
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
	didB2 := "did:web:a.local:b2"
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
	digB2 := makeDoc(didB2, didB2+"#key-1", pubB2, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
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

	uniqueTag := fmt.Sprintf("agent-recovery-%s-%d", tag, time.Now().UnixNano())
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
			ID:   certID, DeploymentID: depID, Issuer: didT, Iss: didT, Sub: domDID,
			IssuerKeyVersion: 1, ValidFrom: vf, ValidUntil: vu, NBF: nbf, EXP: exp,
			CredentialStatus:  protocol.CredentialStatus{ID: certID, Type: protocol.StatusTypeDomainCertification},
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
			Management:     api.Management{MSPID: domID + "MSP", Fingerprint: strings.Repeat("4", 64)},
			DocumentDigest: dig, KeyID: keyID, KeyVersion: 1, PublicKey: pub,
			AccountCommitment: api.Digest([]byte("acct:" + did)),
			Version:           api.Version{Status: api.Active, Revision: 1},
		}
	}
	idA := makeID(didA, "A", "DOMAIN", didA+"#key-1", pubDomA, digA)
	idCDom := makeID(didC, "C", "DOMAIN", didC+"#key-1", pubDomC, digC)
	idIA := makeID(didIA, "A", "ISSUER", didIA+"#key-1", pubIA, digIA)
	idIC := makeID(didIC, "C", "ISSUER", didIC+"#key-1", pubIC, digIC)
	idPA := makeID(didPA, "A", "SERVICE", didPA+"#key-1", pubPA, digPA)
	idU := makeID(didU, "A", "USER", didU+"#key-1", pubU, digU)
	idA1 := makeID(didA1, "A", "AGENT", didA1+"#key-1", pubA1, digA1)
	idB1 := makeID(didB1, "A", "AGENT", didB1+"#key-1", pubB1, digB1)
	idB2 := makeID(didB2, "A", "AGENT", didB2+"#key-1", pubB2, digB2)
	idCSvc := makeID(didCSvc, "C", "SERVICE", didCSvc+"#key-1", pubC, digCSvc)

	issueSD := func(priv *ecdsa.PrivateKey, iss, sub, credID, dom, role, holderPub string) (*protocol.SignedSDJWTCredential, api.Credential) {
		jwk, err := protocol.AppPublicKeyToJWK(holderPub)
		if err != nil {
			t.Fatal(err)
		}
		sd, err := protocol.IssueEnterpriseIdentityCredential(priv, iss+"#key-1", protocol.EnterpriseIdentityCredential{
			Type: []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity},
			ID:   credID, DeploymentID: depID, Issuer: iss, Iss: iss, Sub: sub,
			IssuerKeyVersion: 1, AppKeyVersion: 1, ValidFrom: vf, ValidUntil: vu, NBF: nbf, EXP: exp,
			CredentialStatus:  protocol.CredentialStatus{ID: credID, Type: protocol.StatusTypeCredential},
			Cnf:               protocol.ConfirmationKey{JWK: jwk},
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
	b2CredID := "urn:grad:credential:B2-" + uniqueTag

	sdC, chainCredC := issueSD(privIC, didIC, didCSvc, cCredID, "C", "supplier-service", pubC)
	sdPA, chainCredPA := issueSD(privIA, didIA, didPA, paCredID, "A", "procurement-authority", pubPA)
	sdU, chainCredU := issueSD(privIA, didIA, didU, uCredID, "A", "procurement-owner", pubU)
	sdA1, chainCredA1 := issueSD(privIA, didIA, didA1, a1CredID, "A", "procurement-agent", pubA1)
	sdB1, chainCredB1 := issueSD(privIA, didIA, didB1, b1CredID, "A", "buyer-delegate", pubB1)
	sdB2, chainCredB2 := issueSD(privIA, didIA, didB2, b2CredID, "A", "buyer-delegate", pubB2)

	spec := protocol.TaskSpec{
		SupplierID:  "urn:grad:supplier:C",
		ProductID:   "urn:grad:product:P1",
		MaxQuantity: 10,
		Currency:    "CNY",
		Resources:   []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions:     []string{"order.create", "quote.read"},
		Description: "agent dynamic replacement and reconciliation",
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

	txIdx := 0
	putKV := func(k string, v any) {
		raw, mErr := json.Marshal(v)
		if mErr != nil {
			t.Fatal(mErr)
		}
		if _, eErr := tx.Exec(ctx, `INSERT INTO fabric_current(deployment, key, value) VALUES($1,$2,$3)
			ON CONFLICT(deployment,key) DO UPDATE SET value=EXCLUDED.value`, depID, k, raw); eErr != nil {
			t.Fatal(eErr)
		}
		if _, eErr := tx.Exec(ctx, `INSERT INTO fabric_version(deployment, key, block_no, tx_index, tx_id, value)
			VALUES($1,$2,1,$3,$4,$5)`, depID, k, txIdx, "tx-init-"+uniqueTag, raw); eErr != nil {
			t.Fatal(eErr)
		}
		txIdx++
	}
	b0Hash := api.Digest([]byte("block-0-" + uniqueTag))
	b1Hash := api.Digest([]byte("block-1-" + uniqueTag))
	if _, err := tx.Exec(ctx, `INSERT INTO fabric_block(deployment, block_no, hash, parent, data)
		VALUES($1,0,$2,'',''::bytea), ($1,1,$3,$2,''::bytea)`, depID, b0Hash, b1Hash); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO fabric_head(deployment, block_no, hash) VALUES($1,1,$2)`, depID, b1Hash); err != nil {
		t.Fatal(err)
	}
	putKV(api.BootstrapKey, boot)
	putKV(api.Key("domain", "A"), domA)
	putKV(api.Key("domain", "C"), domC)
	putKV(api.Key("certification", certA.ID), certA)
	putKV(api.Key("certification", certC.ID), certC)
	putKV(api.Key("identity", didA), idA)
	putKV(api.Key("identity", didC), idCDom)
	putKV(api.Key("identity", didIA), idIA)
	putKV(api.Key("identity", didIC), idIC)
	putKV(api.Key("identity", didPA), idPA)
	putKV(api.Key("identity", didU), idU)
	putKV(api.Key("identity", didA1), idA1)
	putKV(api.Key("identity", didB1), idB1)
	putKV(api.Key("identity", didB2), idB2)
	putKV(api.Key("identity", didCSvc), idCSvc)
	putKV(api.Key("credential", cCredID), chainCredC)
	putKV(api.Key("credential", paCredID), chainCredPA)
	putKV(api.Key("credential", uCredID), chainCredU)
	putKV(api.Key("credential", a1CredID), chainCredA1)
	putKV(api.Key("credential", b1CredID), chainCredB1)
	putKV(api.Key("credential", b2CredID), chainCredB2)
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
		_, _ = pool.Exec(bg, `DELETE FROM decision_evidence WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM order_outcome_outbox WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM order_outcome_receipts WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM order_outcome_audits WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM order_outcome_cases WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM client_actions WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM orders WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM quotes WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM decisions WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM business_keys WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM challenges WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM trusted_contexts WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM catalog_prices WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM certification_receipts WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM fabric_version WHERE deployment=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM fabric_block WHERE deployment=$1`, depID)
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

	var curNowUnix atomic.Int64
	curNowUnix.Store(now.Unix())
	curNowFn := func() time.Time { return time.Unix(curNowUnix.Load(), 0).UTC() }

	sp := fabric.NewStateProviderFromBootstrap(pool, depID, boot, nil)
	monoNow := now
	sp.SetMonoClock(func() time.Time { return monoNow })
	sp.SetStaticProbe(&fabric.ProbeSnapshot{
		TxID: "probe-tx-b1-" + uniqueTag, ProbeBlock: 1, SentAt: now, Deadline: now.Add(5 * time.Second),
		SentMonoNs: monoNow.UnixNano(), DeadlineMonoNs: monoNow.Add(5 * time.Second).UnixNano(),
		AdoptedAt: now, AdoptedMonoNs: monoNow.UnixNano(),
	})

	auditorDID := "did:web:c.local:auditors:c1"
	srv, err := gateway.NewServer(gateway.Config{
		DB: pool, State: sp.GatewayAdapter(), Delivery: fabric.NewDeliveryService(pool),
		DIDs: dids, Policy: bundle,
		PolicyArchive: map[string]*policy.VerifiedBundle{bundle.PolicyDigest: bundle},
		AuditorDIDs:   []string{auditorDID},
		VerifierID:    auditorDID,
		DeploymentID:  depID, ServiceDID: didCSvc,
		Audience: audience, SupplierID: "urn:grad:supplier:C",
		NowFn: curNowFn,
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

	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	rt := &dropResponseTransport{
		base:           http.DefaultTransport,
		dropAfterKeys:  map[string]bool{},
		dropBeforeKeys: map[string]bool{},
	}
	httpClient := &http.Client{Transport: rt, Timeout: 10 * time.Second}

	var curBlock atomic.Int64
	curBlock.Store(1)
	var curHeadMu sync.Mutex
	curHeadHash := b1Hash

	appendBlockKV := func(txTag string, updates []struct {
		key   string
		value api.Grant
	}) int64 {
		curHeadMu.Lock()
		defer curHeadMu.Unlock()
		nextBlk := curBlock.Add(1)
		nextHash := api.Digest([]byte(fmt.Sprintf("block-%d-%s-%s", nextBlk, txTag, uniqueTag)))
		txDB, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer txDB.Rollback(context.Background())
		if _, err := txDB.Exec(ctx, `INSERT INTO fabric_block(deployment, block_no, hash, parent, data) VALUES($1,$2,$3,$4,''::bytea)`,
			depID, nextBlk, nextHash, curHeadHash); err != nil {
			t.Fatal(err)
		}
		for i, upd := range updates {
			raw, _ := json.Marshal(upd.value)
			if _, err := txDB.Exec(ctx, `INSERT INTO fabric_version(deployment, key, block_no, tx_index, tx_id, value) VALUES($1,$2,$3,$4,$5,$6)`,
				depID, upd.key, nextBlk, i, fmt.Sprintf("tx-%s-%d", txTag, nextBlk), raw); err != nil {
				t.Fatal(err)
			}
			if _, err := txDB.Exec(ctx, `INSERT INTO fabric_current(deployment, key, value) VALUES($1,$2,$3)
				ON CONFLICT(deployment,key) DO UPDATE SET value=EXCLUDED.value`, depID, upd.key, raw); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := txDB.Exec(ctx, `UPDATE fabric_head SET block_no=$1, hash=$2 WHERE deployment=$3`, nextBlk, nextHash, depID); err != nil {
			t.Fatal(err)
		}
		if err := txDB.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		curHeadHash = nextHash
		sp.SetStaticProbe(&fabric.ProbeSnapshot{
			TxID: fmt.Sprintf("probe-tx-b%d-%s", nextBlk, uniqueTag), ProbeBlock: uint64(nextBlk),
			SentAt: now, Deadline: now.Add(5 * time.Second),
			SentMonoNs: monoNow.UnixNano(), DeadlineMonoNs: monoNow.Add(5 * time.Second).UnixNano(),
			AdoptedAt: now, AdoptedMonoNs: monoNow.UnixNano(),
		})
		return nextBlk
	}

	grantToAPI := func(claims protocol.GrantClaims, digest, parentOverride string, status string, rev uint64) api.Grant {
		pID, pDig := parentOverride, ""
		if claims.ParentID != nil && *claims.ParentID != "" {
			pID = *claims.ParentID
		}
		if claims.ParentDigest != nil {
			pDig = *claims.ParentDigest
		}
		return api.Grant{
			Bound: api.Bound{DeploymentID: depID}, ID: claims.ID, Schema: api.Schema,
			Parent: pID, ParentDigest: pDig, Root: claims.RootID, Task: claims.TaskID,
			Mode: claims.AuthorizationMode, Domain: claims.PrincipalDomain, Resource: claims.ResourceID,
			Issuer: claims.Issuer, Grantee: claims.Grantee,
			IssuerKeyVersion: claims.IssuerKeyVersion, GranteeKeyVersion: claims.GranteeKeyVersion,
			IssuerCredential: claims.IssuerCredentialID, GranteeCredential: claims.GranteeCredentialID,
			Depth: uint8(claims.RemainingDepth), Digest: digest,
			Interval: api.Interval{NBF: claims.NBF, EXP: claims.EXP},
			Version:  api.Version{Status: status, Revision: rev},
		}
	}

	trustPathsForMode := func(mode string) []protocol.TrustPathEntry {
		tp := []protocol.TrustPathEntry{{Issuer: didIA, DomainCertification: certAJWS}}
		if mode == api.RP {
			tp = append(tp, protocol.TrustPathEntry{Issuer: didIC, DomainCertification: certCJWS})
		}
		return tp
	}

	var receiptDelivery func(context.Context, gateway.OrderOutcomeReceipt) (*gateway.OrderOutcomeReceiptResponse, error)
	if srv.Handler() != nil {
		receiptDelivery = func(ctx context.Context, r gateway.OrderOutcomeReceipt) (*gateway.OrderOutcomeReceiptResponse, error) {
			return gateway.DeliverStoredReceipt(ctx, pool, depID, serviceauth.NewLocalClient(srv.Handler(), serviceauth.Identity{Role: "C_AUDIT_SERVICE", DID: auditorDID}), "https://c.local/v1/internal/order-outcome-receipts", r)
		}
	}
	wallet, err := agent.NewWalletContext(agent.WalletConfig{
		ReceiptDelivery: receiptDelivery,
		DeploymentID:    depID, GatewayURL: httpSrv.URL, Audience: audience, SupplierID: "urn:grad:supplier:C", SupplierDID: didCSvc,
		DefaultTaskSpec: spec, Currency: "CNY",
		AuditorDID: auditorDID, RecoveryDID: "did:web:a.local:services:recovery",
		DB: pool, HTTPClient: httpClient,
		RecoveryClient: serviceauth.NewLocalClient(srv.Handler(), serviceauth.Identity{Role: "B_RECOVERY", DID: "did:web:a.local:services:recovery"}),
		AuditClient:    serviceauth.NewLocalClient(srv.Handler(), serviceauth.Identity{Role: "C_AUDITOR", DID: auditorDID}),
		ReceiptClient:  serviceauth.NewLocalClient(srv.Handler(), serviceauth.Identity{Role: "C_AUDIT_SERVICE", DID: auditorDID}),
		Now:            curNowFn,
		AnchorChildFunc: func(callCtx context.Context, req agent.AnchorChildGrantRequest) (*agent.AnchorChildGrantResult, error) {
			gChain := grantToAPI(req.Claims, req.GrantDigest, req.ParentID, api.Active, 1)
			appendBlockKV("anchor-"+req.Claims.ID, []struct {
				key   string
				value api.Grant
			}{{key: api.Key("grant", req.Claims.ID), value: gChain}})
			return &agent.AnchorChildGrantResult{Anchored: true, TrustPaths: trustPathsForMode(req.Claims.AuthorizationMode)}, nil
		},
		ReplaceGrantFunc: func(callCtx context.Context, req agent.ReplaceGrantRequest) (*agent.ReplaceGrantResult, error) {
			var rawOld []byte
			if err := pool.QueryRow(callCtx, `SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2`,
				depID, api.Key("grant", req.OldGrantID)).Scan(&rawOld); err != nil {
				return nil, fmt.Errorf("load old grant for replace: %w", err)
			}
			var oldGrant api.Grant
			if err := json.Unmarshal(rawOld, &oldGrant); err != nil {
				return nil, err
			}
			if req.OldGrantRevision > 0 && oldGrant.Revision != req.OldGrantRevision {
				return nil, fmt.Errorf("STATE_CHANGED: old grant revision %d != expected %d", oldGrant.Revision, req.OldGrantRevision)
			}
			oldGrant.Status = api.Revoked
			oldGrant.Revision++
			newGrant := grantToAPI(req.NewClaims, req.NewGrantDigest, "", api.Active, 1)
			appendBlockKV("replace-"+req.NewClaims.ID, []struct {
				key   string
				value api.Grant
			}{
				{key: api.Key("grant", oldGrant.ID), value: oldGrant},
				{key: api.Key("grant", newGrant.ID), value: newGrant},
			})
			return &agent.ReplaceGrantResult{Anchored: true, TrustPaths: trustPathsForMode(req.NewClaims.AuthorizationMode)}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewWalletContext: %v", err)
	}

	registerActor := func(actor, did, credID string, priv *ecdsa.PrivateKey, sd string) {
		if err := wallet.RegisterActor(agent.ActorConfig{
			Actor: actor, DID: did, KeyID: did + "#key-1", CredentialID: credID, KeyVersion: 1,
			DomainID: "A", EntityType: "AGENT", Roles: []string{"broker-agent"}, PrivateKey: priv, SDJWTPresentation: sd,
		}); err != nil {
			t.Fatal(err)
		}
	}
	registerActor("A1", didA1, a1CredID, privA1, sdA1.PresentationPrefix)
	registerActor("B1", didB1, b1CredID, privB1, sdB1.PresentationPrefix)
	registerActor("B2", didB2, b2CredID, privB2, sdB2.PresentationPrefix)

	if err := wallet.AddGrantBundle(agent.GrantBundle{
		Claims: rpG1Claims, TaskSpec: spec, RawGrantJWS: rpG1JWS, Digest: rpG1Dig,
		Revision: 1, ChainRawGrants: []string{rpG0JWS, rpG1JWS},
		AncestorCredentials: []protocol.AncestorCredential{
			{CredentialID: cCredID, Presentation: sdC.PresentationPrefix},
			{CredentialID: uCredID, Presentation: sdU.PresentationPrefix},
		},
		TrustPaths: trustPathsForMode(api.RP), Anchored: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := wallet.AddGrantBundle(agent.GrantBundle{
		Claims: bmG1Claims, TaskSpec: spec, RawGrantJWS: bmG1JWS, Digest: bmG1Dig,
		Revision: 1, ChainRawGrants: []string{bmG0JWS, bmG1JWS},
		AncestorCredentials: []protocol.AncestorCredential{
			{CredentialID: paCredID, Presentation: sdPA.PresentationPrefix},
			{CredentialID: uCredID, Presentation: sdU.PresentationPrefix},
		},
		TrustPaths: trustPathsForMode(api.BM), Anchored: true,
	}); err != nil {
		t.Fatal(err)
	}

	return &agentRecoveryHarness{
		pool: pool, depID: depID, audience: audience, taskRP: taskRP, taskBM: taskBM, resID: resID,
		rpG1ID: rpG1ID, bmG1ID: bmG1ID, didB1: didB1, didB2: didB2, fixedNow: now,
		advanceNow: func(d time.Duration) { curNowUnix.Store(time.Unix(curNowUnix.Load(), 0).Add(d).Unix()) },
		srv:        srv, httpSrv: httpSrv, transport: rt, sp: sp, wallet: wallet,
		sdJWTs: map[string]string{
			"A1": sdA1.PresentationPrefix, "B1": sdB1.PresentationPrefix, "B2": sdB2.PresentationPrefix,
			"C": sdC.PresentationPrefix, "PA": sdPA.PresentationPrefix, "U": sdU.PresentationPrefix,
		},
		revokeFn: func(grantID string) {
			var raw []byte
			if err := pool.QueryRow(ctx, `SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2`,
				depID, api.Key("grant", grantID)).Scan(&raw); err != nil {
				t.Fatalf("load grant %s for revoke: %v", grantID, err)
			}
			var g api.Grant
			if err := json.Unmarshal(raw, &g); err != nil {
				t.Fatal(err)
			}
			g.Status = api.Revoked
			g.Revision++
			appendBlockKV("revoke-"+grantID, []struct {
				key   string
				value api.Grant
			}{{key: api.Key("grant", grantID), value: g}})
		},
	}
}

func callMCPJSON(t *testing.T, cliSess *mcp.ClientSession, ctx context.Context, name string, args map[string]any, dst any, secrets ...string) {
	t.Helper()
	res, err := cliSess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	if res.IsError {
		t.Fatalf("CallTool(%s) returned error: %+v", name, res.Content)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	assertNoSecrets(t, "MCP "+name, string(raw), secrets...)
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("decode %s output: %v (raw=%s)", name, err, string(raw))
	}
}

func TestAgentReplaceGrantAndStdioParity(t *testing.T) {
	h := newAgentRecoveryHarness(t, "replace")
	ctx := t.Context()

	mcpSrv := agent.NewMCPServer(h.wallet)
	c2sR, c2sW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	s2cR, s2cW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2sR.Close(); _ = c2sW.Close(); _ = s2cR.Close(); _ = s2cW.Close() }()

	srvSess, err := mcpSrv.Connect(ctx, &mcp.IOTransport{Reader: c2sR, Writer: s2cW}, nil)
	if err != nil {
		t.Fatalf("connect stdio-pipe MCP server: %v", err)
	}
	defer srvSess.Close()

	cli := mcp.NewClient(&mcp.Implementation{Name: "test-recovery-stdio", Version: "v0.1"}, nil)
	cliSess, err := cli.Connect(ctx, &mcp.IOTransport{Reader: s2cR, Writer: c2sW}, nil)
	if err != nil {
		t.Fatalf("connect stdio-pipe MCP client: %v", err)
	}
	defer cliSess.Close()

	listed, err := cliSess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(listed.Tools) != 6 {
		t.Fatalf("expected 6 MCP tools over stdio transport, got %d", len(listed.Tools))
	}

	secrets := []string{h.sdJWTs["A1"], h.sdJWTs["B1"], h.sdJWTs["B2"], h.sdJWTs["C"], h.sdJWTs["PA"], h.sdJWTs["U"]}

	// 1. A1 delegates RP child G2 to B1.
	g2ID := api.Digest([]byte("recovery-g2-b1:" + h.depID))
	var del agent.DelegateGrantOutput
	callMCPJSON(t, cliSess, ctx, "delegate_grant", map[string]any{
		"issuerActor": "A1", "subjectActor": "B1", "parentGrantId": h.rpG1ID, "grantId": g2ID,
		"taskId": h.taskRP, "authorizationMode": api.RP, "maxAmountMinor": 100000, "remainingDepth": 0,
	}, &del, secrets...)
	if !del.Anchored || del.Grant.GranteeDID != h.didB1 {
		t.Fatalf("unexpected initial delegate_grant: %+v", del)
	}

	// 2. B1 obtains Q800 (80000 CNY).
	var qB1 agent.RequestQuoteOutput
	callMCPJSON(t, cliSess, ctx, "request_quote", map[string]any{
		"actor": "B1", "grantId": g2ID, "taskId": h.taskRP, "authorizationMode": api.RP,
		"productId": "urn:grad:product:P1", "quantity": 1,
	}, &qB1, secrets...)
	if qB1.Decision != "ALLOW" || qB1.QuoteID == "" {
		t.Fatalf("B1 quote failed: %+v", qB1)
	}

	// 3. A1 atomically replaces G2 -> G2' for B2 via replace_grant.
	g2PrimeID := api.Digest([]byte("recovery-g2-b2:" + h.depID))
	var rep agent.ReplaceGrantOutput
	callMCPJSON(t, cliSess, ctx, "replace_grant", map[string]any{
		"issuerActor": "A1", "oldGrantId": g2ID, "newSubjectActor": "B2", "newGrantId": g2PrimeID,
		"maxAmountMinor": 100000, "remainingDepth": 0, "reason": "B1 failover to B2",
	}, &rep, secrets...)
	if rep.RevokedGrantID != g2ID || !rep.Anchored || rep.ReplacementGrant.GrantID != g2PrimeID || rep.ReplacementGrant.GranteeDID != h.didB2 {
		t.Fatalf("unexpected replace_grant output: %+v", rep)
	}

	// 4. S41: B1 reusing revoked G2 MUST be rejected with 403 GRANT_INACTIVE.
	var s41Out agent.CreateOrderOutput
	callMCPJSON(t, cliSess, ctx, "create_order", map[string]any{
		"actor": "B1", "grantId": g2ID, "taskId": h.taskRP, "authorizationMode": api.RP,
		"quoteId": qB1.QuoteID, "amountMinor": 80000, "idempotencyKey": "recovery-s41-b1-old-g2",
	}, &s41Out, secrets...)
	if s41Out.StatusCode != http.StatusForbidden || s41Out.ErrorCode != protocol.ErrCodeGrantInactive {
		t.Fatalf("S41 expected 403 GRANT_INACTIVE, got %+v", s41Out)
	}

	// 5. S55: B2 reusing B1's quote Q800 MUST be rejected with 403 QUOTE_SCOPE_MISMATCH.
	var s55Out agent.CreateOrderOutput
	callMCPJSON(t, cliSess, ctx, "create_order", map[string]any{
		"actor": "B2", "grantId": g2PrimeID, "taskId": h.taskRP, "authorizationMode": api.RP,
		"quoteId": qB1.QuoteID, "amountMinor": 80000, "idempotencyKey": "recovery-s55-b2-reuse-q800",
	}, &s55Out, secrets...)
	if s55Out.StatusCode != http.StatusForbidden || s55Out.ErrorCode != protocol.ErrCodeQuoteScopeMismatch {
		t.Fatalf("S55 expected 403 QUOTE_SCOPE_MISMATCH, got %+v", s55Out)
	}

	// 6. B2 requests its own quote and succeeds with 200 ALLOW + 1 order in DB.
	var qB2 agent.RequestQuoteOutput
	callMCPJSON(t, cliSess, ctx, "request_quote", map[string]any{
		"actor": "B2", "grantId": g2PrimeID, "taskId": h.taskRP, "authorizationMode": api.RP,
		"productId": "urn:grad:product:P1", "quantity": 1,
	}, &qB2, secrets...)
	if qB2.Decision != "ALLOW" || qB2.QuoteID == "" {
		t.Fatalf("B2 quote failed: %+v", qB2)
	}
	var okOrd agent.CreateOrderOutput
	callMCPJSON(t, cliSess, ctx, "create_order", map[string]any{
		"actor": "B2", "grantId": g2PrimeID, "taskId": h.taskRP, "authorizationMode": api.RP,
		"quoteId": qB2.QuoteID, "amountMinor": 80000, "idempotencyKey": "recovery-b2-order-ok",
	}, &okOrd, secrets...)
	if okOrd.StatusCode != http.StatusOK || okOrd.Decision != "ALLOW" || okOrd.OrderID == "" {
		t.Fatalf("B2 create_order failed: %+v", okOrd)
	}

	// Compare inspect_wallet over in-memory transport vs IOTransport parity.
	t1, t2 := mcp.NewInMemoryTransports()
	inSrvSess, err := mcpSrv.Connect(ctx, t1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer inSrvSess.Close()
	inCli := mcp.NewClient(&mcp.Implementation{Name: "test-recovery-mem", Version: "v0.1"}, nil)
	inCliSess, err := inCli.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer inCliSess.Close()

	var inspStdio, inspMem agent.InspectWalletOutput
	callMCPJSON(t, cliSess, ctx, "inspect_wallet", map[string]any{"actor": "B2", "taskId": h.taskRP}, &inspStdio, secrets...)
	callMCPJSON(t, inCliSess, ctx, "inspect_wallet", map[string]any{"actor": "B2", "taskId": h.taskRP}, &inspMem, secrets...)
	rawStdio, _ := json.Marshal(inspStdio)
	rawMem, _ := json.Marshal(inspMem)
	if string(rawStdio) != string(rawMem) {
		t.Fatalf("stdio vs in-memory inspect_wallet mismatch:\nstdio=%s\nmem=%s", rawStdio, rawMem)
	}
}

func TestAgentReconcileOrderCreatedAndNotCreated(t *testing.T) {
	h := newAgentRecoveryHarness(t, "reconcile")
	ctx := t.Context()

	mcpSrv := agent.NewMCPServer(h.wallet)
	t1, t2 := mcp.NewInMemoryTransports()
	srvSess, err := mcpSrv.Connect(ctx, t1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srvSess.Close()
	cli := mcp.NewClient(&mcp.Implementation{Name: "test-recovery-reconcile", Version: "v0.1"}, nil)
	cliSess, err := cli.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cliSess.Close()

	secrets := []string{h.sdJWTs["A1"], h.sdJWTs["B1"], h.sdJWTs["B2"], h.sdJWTs["C"], h.sdJWTs["PA"], h.sdJWTs["U"]}

	// 1. Delegate BM G2 to B1 and get quote Q_lost.
	g2ID := api.Digest([]byte("recovery-bm-g2-b1:" + h.depID))
	var del agent.DelegateGrantOutput
	callMCPJSON(t, cliSess, ctx, "delegate_grant", map[string]any{
		"issuerActor": "A1", "subjectActor": "B1", "parentGrantId": h.bmG1ID, "grantId": g2ID,
		"taskId": h.taskBM, "authorizationMode": api.BM, "maxAmountMinor": 100000, "remainingDepth": 0,
	}, &del, secrets...)

	var qLost agent.RequestQuoteOutput
	callMCPJSON(t, cliSess, ctx, "request_quote", map[string]any{
		"actor": "B1", "grantId": g2ID, "taskId": h.taskBM, "authorizationMode": api.BM,
		"productId": "urn:grad:product:P1", "quantity": 1,
	}, &qLost, secrets...)
	if qLost.Decision != "ALLOW" {
		t.Fatalf("quote failed: %+v", qLost)
	}

	// 2. Simulate S63 response EOF loss AFTER gateway commits order.create at block h=1.
	lostKey := "recovery-s63-lost-after-commit"
	h.transport.mu.Lock()
	h.transport.dropAfterKeys[lostKey] = true
	h.transport.mu.Unlock()

	var unkOut agent.CreateOrderOutput
	callMCPJSON(t, cliSess, ctx, "create_order", map[string]any{
		"actor": "B1", "grantId": g2ID, "taskId": h.taskBM, "authorizationMode": api.BM,
		"quoteId": qLost.QuoteID, "amountMinor": 80000, "idempotencyKey": lostKey,
	}, &unkOut, secrets...)
	if unkOut.Decision != "UNKNOWN" || unkOut.ActionStatus != "OUTCOME_UNKNOWN" || unkOut.SendRevision != 1 {
		t.Fatalf("expected OUTCOME_UNKNOWN after EOF drop, got %+v", unkOut)
	}

	// 3. Revoke ancestor G1 at block r=2 -> retrying B1 hits 403 ANCESTOR_INACTIVE, so B reconciles instead.
	h.revokeFn(h.bmG1ID)
	var postRevokeQuote agent.RequestQuoteOutput
	callMCPJSON(t, cliSess, ctx, "request_quote", map[string]any{
		"actor": "B1", "grantId": g2ID, "taskId": h.taskBM, "authorizationMode": api.BM,
		"productId": "urn:grad:product:P1", "quantity": 1,
	}, &postRevokeQuote, secrets...)
	if postRevokeQuote.StatusCode != http.StatusForbidden || postRevokeQuote.ErrorCode != protocol.ErrCodeAncestorInactive {
		t.Fatalf("expected 403 ANCESTOR_INACTIVE after G1 revoke at r=2, got %+v", postRevokeQuote)
	}

	// 4. Call reconcile_order -> must stop send (sendRevision=2), audit C with h=1 < r=2 -> CREATED + MATCHED -> RECONCILED.
	var recOut agent.ReconcileOrderOutput
	callMCPJSON(t, cliSess, ctx, "reconcile_order", map[string]any{
		"actor": "B1", "taskId": h.taskBM, "idempotencyKey": lostKey,
	}, &recOut, secrets...)
	if recOut.Outcome != "CREATED" || recOut.HistoricalStatus != "MATCHED" || recOut.SendRevision != 2 || recOut.OrderID == "" || recOut.ActionStatus != "RECONCILED" {
		t.Fatalf("unexpected reconcile_order(CREATED) output: %+v", recOut)
	}

	// 5. Drop BEFORE gateway commits on RP path -> reconcile_order yields NOT_CREATED.
	rpG2ID := api.Digest([]byte("recovery-rp-g2-b1:" + h.depID))
	var delRP agent.DelegateGrantOutput
	callMCPJSON(t, cliSess, ctx, "delegate_grant", map[string]any{
		"issuerActor": "A1", "subjectActor": "B1", "parentGrantId": h.rpG1ID, "grantId": rpG2ID,
		"taskId": h.taskRP, "authorizationMode": api.RP, "maxAmountMinor": 100000, "remainingDepth": 0,
	}, &delRP, secrets...)
	var qRP agent.RequestQuoteOutput
	callMCPJSON(t, cliSess, ctx, "request_quote", map[string]any{
		"actor": "B1", "grantId": rpG2ID, "taskId": h.taskRP, "authorizationMode": api.RP,
		"productId": "urn:grad:product:P1", "quantity": 1,
	}, &qRP, secrets...)

	notCreatedKey := "recovery-s63-drop-before-commit"
	h.transport.mu.Lock()
	h.transport.dropBeforeKeys[notCreatedKey] = true
	h.transport.mu.Unlock()

	var unkNotCreated agent.CreateOrderOutput
	callMCPJSON(t, cliSess, ctx, "create_order", map[string]any{
		"actor": "B1", "grantId": rpG2ID, "taskId": h.taskRP, "authorizationMode": api.RP,
		"quoteId": qRP.QuoteID, "amountMinor": 80000, "idempotencyKey": notCreatedKey,
	}, &unkNotCreated, secrets...)
	if unkNotCreated.Decision != "UNKNOWN" || unkNotCreated.ActionStatus != "OUTCOME_UNKNOWN" {
		t.Fatalf("expected OUTCOME_UNKNOWN before commit drop, got %+v", unkNotCreated)
	}

	var recUnknownFirst agent.ReconcileOrderOutput
	callMCPJSON(t, cliSess, ctx, "reconcile_order", map[string]any{
		"actor": "B1", "taskId": h.taskRP, "idempotencyKey": notCreatedKey,
	}, &recUnknownFirst, secrets...)
	if recUnknownFirst.Outcome != "UNKNOWN" || recUnknownFirst.ActionStatus != "OUTCOME_UNKNOWN" || recUnknownFirst.CheckNo != 1 {
		t.Fatalf("expected UNKNOWN before challenge expires, got %+v", recUnknownFirst)
	}

	h.advanceNow(2 * time.Minute)
	var recNotCreated agent.ReconcileOrderOutput
	callMCPJSON(t, cliSess, ctx, "reconcile_order", map[string]any{
		"actor": "B1", "taskId": h.taskRP, "idempotencyKey": notCreatedKey,
	}, &recNotCreated, secrets...)
	if recNotCreated.Outcome != "NOT_CREATED" || recNotCreated.OrderID != "" || recNotCreated.ActionStatus != "RECONCILED" || recNotCreated.CheckNo != 2 {
		t.Fatalf("unexpected reconcile_order(NOT_CREATED) output: %+v", recNotCreated)
	}

	var orderCount int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM orders WHERE deployment_id=$1`, h.depID).Scan(&orderCount); err != nil {
		t.Fatal(err)
	}
	if orderCount != 1 {
		t.Fatalf("expected exactly 1 order in DB across CREATED + NOT_CREATED reconciliations, got %d", orderCount)
	}
}

func TestAgentRecoveryWithOpenAIAndAnthropicMocks(t *testing.T) {
	ctx := t.Context()
	type scriptAct struct {
		toolName string
		args     map[string]any
	}

	buildScript := func(h *agentRecoveryHarness, suffix string) []scriptAct {
		g2ID := api.Digest([]byte("recovery-g2-" + suffix + ":" + h.depID))
		g2PrimeID := api.Digest([]byte("recovery-g2p-" + suffix + ":" + h.depID))
		return []scriptAct{
			{"inspect_wallet", map[string]any{"actor": "A1", "taskId": h.taskRP, "authorizationMode": api.RP}},
			{"delegate_grant", map[string]any{"issuerActor": "A1", "subjectActor": "B1", "parentGrantId": h.rpG1ID, "grantId": g2ID, "taskId": h.taskRP, "authorizationMode": api.RP, "maxAmountMinor": 100000, "remainingDepth": 0}},
			{"request_quote", map[string]any{"actor": "B1", "grantId": g2ID, "taskId": h.taskRP, "authorizationMode": api.RP, "productId": "urn:grad:product:P1", "quantity": 1}},
			{"replace_grant", map[string]any{"issuerActor": "A1", "oldGrantId": g2ID, "newSubjectActor": "B2", "newGrantId": g2PrimeID, "maxAmountMinor": 100000, "remainingDepth": 0, "reason": "migrate B1->B2"}},
			{"create_order", map[string]any{"actor": "B1", "grantId": g2ID, "taskId": h.taskRP, "authorizationMode": api.RP, "quoteId": "{{B1_QUOTE}}", "amountMinor": 80000, "idempotencyKey": "recovery-s41-" + suffix}},
			{"create_order", map[string]any{"actor": "B2", "grantId": g2PrimeID, "taskId": h.taskRP, "authorizationMode": api.RP, "quoteId": "{{B1_QUOTE}}", "amountMinor": 80000, "idempotencyKey": "recovery-s55-" + suffix}},
			{"request_quote", map[string]any{"actor": "B2", "grantId": g2PrimeID, "taskId": h.taskRP, "authorizationMode": api.RP, "productId": "urn:grad:product:P1", "quantity": 1}},
			{"create_order", map[string]any{"actor": "B2", "grantId": g2PrimeID, "taskId": h.taskRP, "authorizationMode": api.RP, "quoteId": "{{B2_QUOTE}}", "amountMinor": 80000, "idempotencyKey": "recovery-s63-" + suffix}},
			{"reconcile_order", map[string]any{"actor": "B2", "taskId": h.taskRP, "idempotencyKey": "recovery-s63-" + suffix}},
		}
	}

	resolveDynamic := func(raw map[string]any, b1Q, b2Q string) map[string]any {
		out := map[string]any{}
		for k, v := range raw {
			if s, ok := v.(string); ok {
				switch s {
				case "{{B1_QUOTE}}":
					out[k] = b1Q
				case "{{B2_QUOTE}}":
					out[k] = b2Q
				default:
					out[k] = s
				}
			} else {
				out[k] = v
			}
		}
		return out
	}
	extractQuote := func(txt string) string {
		var m map[string]any
		if json.Unmarshal([]byte(txt), &m) == nil {
			if q, ok := m["quoteId"].(string); ok && q != "" {
				return q
			}
		}
		return ""
	}

	// 1. OpenAI mock SDK trajectory.
	{
		h := newAgentRecoveryHarness(t, "oai")
		h.transport.mu.Lock()
		h.transport.dropAfterKeys["recovery-s63-oai"] = true
		h.transport.mu.Unlock()

		var mu sync.Mutex
		step := 0
		var b1Quote, b2Quote string
		actions := buildScript(h, "oai")
		oaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody struct {
				Messages []struct {
					Content any `json:"content"`
				} `json:"messages"`
			}
			_ = json.NewDecoder(r.Body).Decode(&reqBody)
			mu.Lock()
			defer mu.Unlock()
			if n := len(reqBody.Messages); n > 0 {
				if cs, ok := reqBody.Messages[n-1].Content.(string); ok {
					if q := extractQuote(cs); q != "" {
						if b1Quote == "" {
							b1Quote = q
						} else {
							b2Quote = q
						}
					}
				}
			}
			if step == 8 { // right before reconcile_order, revoke G1 at block r+1
				h.revokeFn(h.rpG1ID)
			}
			w.Header().Set("Content-Type", "application/json")
			if step >= len(actions) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "chatcmpl-recovery-done", "object": "chat.completion", "model": "mock-openai-model",
					"choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": "B2 failover & S63 reconciliation complete."}}},
				})
				return
			}
			act := actions[step]
			step++
			argBytes, _ := json.Marshal(resolveDynamic(act.args, b1Quote, b2Quote))
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": fmt.Sprintf("chatcmpl-recovery-%d", step), "object": "chat.completion", "model": "mock-openai-model",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "tool_calls",
					"message": map[string]any{
						"role": "assistant", "content": "",
						"tool_calls": []any{map[string]any{
							"id": fmt.Sprintf("call_m3_%d", step), "type": "function",
							"function": map[string]any{"name": act.toolName, "arguments": string(argBytes)},
						}},
					},
				}},
			})
		}))
		defer oaiSrv.Close()

		secretKey := "sk-recovery-openai-secret"
		h.wallet.RegisterSecret(secretKey)
		res, err := agent.RunAgentTask(ctx, agent.NewMCPServer(h.wallet), agent.RunnerConfig{
			Provider: agent.ProviderOpenAI, BaseURL: oaiSrv.URL + "/v1", APIKey: secretKey, Model: "mock-openai-model", MaxSteps: 15,
		}, "Migrate B1 grant to B2 via replace_grant, verify S41/S55 refusals, and reconcile lost B2 order after G1 revocation.")
		if err != nil {
			t.Fatalf("RunAgentTask(openai): %v", err)
		}
		if res.ToolCallsCount != len(actions) || res.LLMLatencyMs < 0 {
			t.Fatalf("unexpected OpenAI RunResult: %+v", res)
		}
		lastTrace := res.ToolTraces[len(res.ToolTraces)-1]
		if lastTrace.ToolName != "reconcile_order" || lastTrace.Output["outcome"] != "CREATED" || lastTrace.Output["historicalStatus"] != "MATCHED" {
			t.Fatalf("expected final reconcile_order CREATED+MATCHED, got %+v", lastTrace)
		}
		resJSON, _ := json.Marshal(res)
		assertNoSecrets(t, "OpenAI RunResult", string(resJSON), secretKey, h.sdJWTs["A1"], h.sdJWTs["B1"], h.sdJWTs["B2"], h.sdJWTs["U"], h.sdJWTs["C"])
	}

	// 2. Anthropic mock SDK trajectory.
	{
		h := newAgentRecoveryHarness(t, "ant")
		h.transport.mu.Lock()
		h.transport.dropAfterKeys["recovery-s63-ant"] = true
		h.transport.mu.Unlock()

		var mu sync.Mutex
		step := 0
		var b1Quote, b2Quote string
		actions := buildScript(h, "ant")
		antSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody struct {
				Messages []struct {
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
						var single string
						if json.Unmarshal(blk.Content, &single) == nil {
							if q := extractQuote(single); q != "" {
								if b1Quote == "" {
									b1Quote = q
								} else {
									b2Quote = q
								}
							}
						} else {
							var arr []struct {
								Text string `json:"text"`
							}
							if json.Unmarshal(blk.Content, &arr) == nil {
								for _, item := range arr {
									if q := extractQuote(item.Text); q != "" {
										if b1Quote == "" {
											b1Quote = q
										} else {
											b2Quote = q
										}
									}
								}
							}
						}
					}
				}
			}
			if step == 8 {
				h.revokeFn(h.rpG1ID)
			}
			w.Header().Set("Content-Type", "application/json")
			if step >= len(actions) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "msg_m3_done", "type": "message", "role": "assistant", "model": "mock-anthropic-model",
					"stop_reason": "end_turn",
					"content":     []any{map[string]any{"type": "text", "text": "B2 failover & S63 reconciliation complete."}},
					"usage":       map[string]any{"input_tokens": 120, "output_tokens": 50},
				})
				return
			}
			act := actions[step]
			step++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": fmt.Sprintf("msg_m3_%d", step), "type": "message", "role": "assistant", "model": "mock-anthropic-model",
				"stop_reason": "tool_use",
				"content": []any{map[string]any{
					"type": "tool_use", "id": fmt.Sprintf("toolu_m3_%d", step), "name": act.toolName, "input": resolveDynamic(act.args, b1Quote, b2Quote),
				}},
				"usage": map[string]any{"input_tokens": 120, "output_tokens": 60},
			})
		}))
		defer antSrv.Close()

		secretKey := "sk-ant-recovery-mock-secret"
		h.wallet.RegisterSecret(secretKey)
		res, err := agent.RunAgentTask(ctx, agent.NewMCPServer(h.wallet), agent.RunnerConfig{
			Provider: agent.ProviderAnthropic, BaseURL: antSrv.URL, APIKey: secretKey, Model: "mock-anthropic-model", MaxSteps: 15,
		}, "Migrate B1 grant to B2 via replace_grant, verify S41/S55 refusals, and reconcile lost B2 order after G1 revocation.")
		if err != nil {
			t.Fatalf("RunAgentTask(anthropic): %v", err)
		}
		if res.ToolCallsCount != len(actions) || res.LLMLatencyMs < 0 {
			t.Fatalf("unexpected Anthropic RunResult: %+v", res)
		}
		lastTrace := res.ToolTraces[len(res.ToolTraces)-1]
		if lastTrace.ToolName != "reconcile_order" || lastTrace.Output["outcome"] != "CREATED" || lastTrace.Output["historicalStatus"] != "MATCHED" {
			t.Fatalf("expected final reconcile_order CREATED+MATCHED, got %+v", lastTrace)
		}
		resJSON, _ := json.Marshal(res)
		assertNoSecrets(t, "Anthropic RunResult", string(resJSON), secretKey, h.sdJWTs["A1"], h.sdJWTs["B1"], h.sdJWTs["B2"], h.sdJWTs["U"], h.sdJWTs["C"])
	}
	_ = filepath.Join("", "")
}
