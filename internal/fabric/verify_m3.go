package fabric

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"graduation-design/internal/agent"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/policy"
	"graduation-design/internal/protocol"
	"graduation-design/internal/serviceauth"
)

type m3EvidenceReport struct {
	DeploymentID       string            `json:"deploymentId"`
	RunID              string            `json:"runId"`
	DynamicLifecycle   map[string]any    `json:"dynamicLifecycle,omitempty"`
	AgentTraces        []agent.RunResult `json:"agentTraces,omitempty"`
	AgentDeterministic map[string]any    `json:"agentDeterministic,omitempty"`
	RevocationWindowE6 map[string]any    `json:"revocationWindowE6,omitempty"`
	FaultInjectionE7   map[string]any    `json:"faultInjectionE7,omitempty"`
}

var (
	m3EvidenceMu  sync.Mutex
	m3EvidenceMap = map[string]*m3EvidenceReport{}
)

func (a acceptance) recordM3Evidence(fileName string, payload any, update func(*m3EvidenceReport), secrets ...string) error {
	m3EvidenceMu.Lock()
	defer m3EvidenceMu.Unlock()
	ev := m3EvidenceMap[a.dir]
	if ev == nil {
		ev = &m3EvidenceReport{
			DeploymentID: a.d.DeploymentID,
			RunID:        a.id,
		}
		m3EvidenceMap[a.dir] = ev
	}
	update(ev)
	if fileName != "" && payload != nil {
		if err := writePublicJSON(filepath.Join(a.dir, fileName), payload); err != nil {
			return err
		}
	}
	if err := writePublicJSON(filepath.Join(a.dir, "m3-recovery.json"), ev); err != nil {
		return err
	}
	if _, err := scanDirForPrivateKeys(a.dir); err != nil {
		return err
	}
	if fileName != "" {
		raw, err := os.ReadFile(filepath.Join(a.dir, fileName))
		if err != nil {
			return err
		}
		if err := assertNoScrubbedSecrets(fileName, string(raw), secrets...); err != nil {
			return err
		}
	}
	return nil
}

func assertNoScrubbedSecrets(label, content string, secrets ...string) error {
	if strings.Contains(content, "PRIVATE KEY") {
		return fmt.Errorf("%s leaked PRIVATE KEY material", label)
	}
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(content, s) {
			return fmt.Errorf("%s leaked sensitive credential or API key", label)
		}
		if idx := strings.IndexByte(s, '~'); idx >= 0 && idx+1 < len(s) {
			for _, part := range strings.Split(s[idx+1:], "~") {
				if len(part) >= 8 && strings.Contains(content, part) {
					return fmt.Errorf("%s leaked raw SD-JWT disclosure salt", label)
				}
			}
		}
	}
	return nil
}

type dropAfterHTTPTransport struct {
	base    http.RoundTripper
	mu      sync.Mutex
	dropIDs map[string]bool
	onDrop  map[string]func() error
	dropped []string
}

func (t *dropAfterHTTPTransport) MarkDropAfter(idemKey string, after ...func() error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dropIDs == nil {
		t.dropIDs = map[string]bool{}
	}
	t.dropIDs[idemKey] = true
	if len(after) > 0 {
		if t.onDrop == nil {
			t.onDrop = map[string]func() error{}
		}
		t.onDrop[idemKey] = after[0]
	}
}

func (t *dropAfterHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || req.URL.Path != "/v1/access/execute" || req.Body == nil {
		return t.base.RoundTrip(req)
	}
	rawBody, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(rawBody))
	var parsed struct {
		Request struct {
			Action         string `json:"action"`
			IdempotencyKey string `json:"idempotencyKey"`
		} `json:"request"`
	}
	_ = json.Unmarshal(rawBody, &parsed)
	t.mu.Lock()
	shouldDrop := parsed.Request.Action == "order.create" && t.dropIDs[parsed.Request.IdempotencyKey]
	afterDrop := t.onDrop[parsed.Request.IdempotencyKey]
	if shouldDrop {
		delete(t.dropIDs, parsed.Request.IdempotencyKey)
		delete(t.onDrop, parsed.Request.IdempotencyKey)
		t.dropped = append(t.dropped, parsed.Request.IdempotencyKey)
	}
	t.mu.Unlock()

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if shouldDrop {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if afterDrop != nil {
			if err := afterDrop(); err != nil {
				return nil, fmt.Errorf("post-commit response-loss injection: %w", err)
			}
		}
		return nil, io.ErrUnexpectedEOF
	}
	return resp, nil
}

func (a acceptance) loadM2RoleMaterials() (
	cPriv *ecdsa.PrivateKey, cSD []byte, cCredID string,
	uPriv *ecdsa.PrivateKey, uSD []byte,
	a1Priv *ecdsa.PrivateKey, a1SD []byte,
	b1Priv *ecdsa.PrivateKey, b1SD []byte,
	cSvcSD []byte, paSD []byte, certB []byte, certC []byte, certA []byte,
	err error,
) {
	if cPriv, err = loadECPrivateKeyPEM(a.instance.privatePath("app", "C.key.pem")); err != nil {
		return
	}
	if cSD, err = os.ReadFile(a.instance.registrySubPath("credentials", "C.sdjwt")); err != nil {
		return
	}
	cCredID = a.f.Credentials["C"].ID
	if cSvc, ok := a.f.Credentials["C-service"]; ok && cSvc.ID != "" {
		cCredID = cSvc.ID
	}
	if uPriv, err = loadECPrivateKeyPEM(a.instance.privatePath("app", "U.key.pem")); err != nil {
		return
	}
	if uSD, err = os.ReadFile(a.instance.registrySubPath("credentials", "U.sdjwt")); err != nil {
		return
	}
	if a1Priv, err = loadECPrivateKeyPEM(a.instance.privatePath("app", "A1.key.pem")); err != nil {
		return
	}
	if a1SD, err = os.ReadFile(a.instance.registrySubPath("credentials", "A1.sdjwt")); err != nil {
		return
	}
	if b1Priv, err = loadECPrivateKeyPEM(a.instance.privatePath("app", "B1.key.pem")); err != nil {
		return
	}
	if b1SD, err = os.ReadFile(a.instance.registrySubPath("credentials", "B1.sdjwt")); err != nil {
		return
	}
	if cSvcSD, err = os.ReadFile(a.instance.registrySubPath("credentials", "C-service.sdjwt")); err != nil {
		cSvcSD = cSD
		err = nil
	}
	paSD, _ = os.ReadFile(a.instance.registrySubPath("credentials", "PA.sdjwt"))
	if certB, err = os.ReadFile(a.instance.registrySubPath("certifications", "B.jws")); err != nil {
		return
	}
	if certC, err = os.ReadFile(a.instance.registrySubPath("certifications", "C.jws")); err != nil {
		return
	}
	if certA, err = os.ReadFile(a.instance.registrySubPath("certifications", "A.jws")); err != nil {
		return
	}
	return
}

type m3RPChainFixture struct {
	Task  api.Task
	G0    api.Grant
	G1    api.Grant
	G2    api.Grant
	G0JWS string
	G1JWS string
	G2JWS string
	G0Dig string
	G1Dig string
	G2Dig string
	Ops   []*operation
}

func (a acceptance) provisionEphemeralM3RPChain(
	rt *online,
	sp *StateProvider,
	tag string,
	maxG1 int64,
	withLeaf bool,
	baseNow time.Time,
) (*m3RPChainFixture, error) {
	cPriv, _, _, uPriv, uSD, a1Priv, a1SD, b1Priv, b1SD, cSvcSD, _, _, certC, certA, err := a.loadM2RoleMaterials()
	if err != nil {
		return nil, err
	}
	_ = b1Priv
	_ = b1SD
	taskDig, err := a.f.M2TaskSpec.Digest()
	if err != nil {
		return nil, err
	}
	valid := a.f.RPTask.Interval
	taskID := api.Digest([]byte(a.d.DeploymentID + "/m3/" + tag + "/task"))
	task := api.Task{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: taskID, Creator: a.f.Identities["U"].ID,
		CreatorKeyVersion: 1, CreatorCredential: a.f.Credentials["U"].ID,
		Resource: a.f.RPTask.Resource, Mode: api.RP, Domain: "A", Digest: taskDig, Interval: valid,
	}
	if _, err := a.op("m3-"+tag+"-task", "U", "RegisterTask", task, "VALID"); err != nil {
		return nil, err
	}
	cCredID := a.f.Credentials["C"].ID
	if cSvc, ok := a.f.Credentials["C-service"]; ok && cSvc.ID != "" {
		cCredID = cSvc.ID
	}

	g0ID := api.Digest([]byte(a.d.DeploymentID + "/m3/" + tag + "/g0"))
	g1ID := api.Digest([]byte(a.d.DeploymentID + "/m3/" + tag + "/g1"))
	mkGrant := func(opLabel, role, id string, parentID, parentDig *string, iss, issCred string, issPriv *ecdsa.PrivateKey, sub, subCred string, amt, depth int64) (api.Grant, string, string, *operation, error) {
		claims := protocol.GrantClaims{
			SchemaVersion: api.Schema, DeploymentID: a.d.DeploymentID, ID: id, RootID: g0ID,
			ParentID: parentID, ParentDigest: parentDig, TaskID: taskID, AuthorizationMode: api.RP,
			PrincipalDomain: "A", ResourceID: task.Resource, Aud: "https://c.local",
			Issuer: iss, IssuerKeyVersion: 1, IssuerCredentialID: issCred,
			Grantee: sub, GranteeKeyVersion: 1, GranteeCredentialID: subCred,
			Resources: a.f.M2TaskSpec.Resources, Actions: a.f.M2TaskSpec.Actions,
			Suppliers: []string{"urn:grad:supplier:C"}, Currency: "CNY", MaxAmountMinor: amt,
			NBF: valid.NBF, EXP: valid.EXP, RemainingDepth: depth,
		}
		jws, dig, signErr := protocol.SignGrant(issPriv, iss+"#key-1", &claims)
		if signErr != nil {
			return api.Grant{}, "", "", nil, signErr
		}
		pID, pDig := "", ""
		if parentID != nil {
			pID = *parentID
		}
		if parentDig != nil {
			pDig = *parentDig
		}
		g := api.Grant{
			Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: id, Schema: api.Schema, Parent: pID, ParentDigest: pDig,
			Root: g0ID, Task: taskID, Mode: api.RP, Domain: "A", Resource: task.Resource,
			Issuer: iss, IssuerKeyVersion: 1, IssuerCredential: issCred, Grantee: sub, GranteeKeyVersion: 1, GranteeCredential: subCred,
			Depth: uint8(depth), Digest: dig, Interval: valid,
		}
		op, opErr := a.op(opLabel, role, "RegisterGrant", g, "VALID")
		return g, jws, dig, op, opErr
	}

	g0, g0JWS, g0Dig, op0, err := mkGrant("m3-"+tag+"-g0", "C", g0ID, nil, nil, a.f.Identities["C"].ID, cCredID, cPriv, a.f.Identities["U"].ID, a.f.Credentials["U"].ID, maxG1, 2)
	if err != nil {
		return nil, err
	}
	g1, g1JWS, g1Dig, op1, err := mkGrant("m3-"+tag+"-g1", "U", g1ID, &g0.ID, &g0Dig, a.f.Identities["U"].ID, a.f.Credentials["U"].ID, uPriv, a.f.Identities["A1"].ID, a.f.Credentials["A1"].ID, maxG1, 1)
	if err != nil {
		return nil, err
	}

	out := &m3RPChainFixture{Task: task, G0: g0, G1: g1, G0JWS: g0JWS, G1JWS: g1JWS, G0Dig: g0Dig, G1Dig: g1Dig, Ops: []*operation{op0, op1}}
	waitTarget := g1.ID
	if withLeaf {
		g2ID := api.Digest([]byte(a.d.DeploymentID + "/m3/" + tag + "/g2"))
		g2, g2JWS, g2Dig, op2, err := mkGrant("m3-"+tag+"-g2", "A1", g2ID, &g1.ID, &g1Dig, a.f.Identities["A1"].ID, a.f.Credentials["A1"].ID, a1Priv, a.f.Identities["B1"].ID, a.f.Credentials["B1"].ID, 100000, 0)
		if err != nil {
			return nil, err
		}
		out.G2, out.G2JWS, out.G2Dig = g2, g2JWS, g2Dig
		out.Ops = append(out.Ops, op2)
		waitTarget = g2.ID
	}
	// Commit observation can precede the asynchronous local block replay.
	// Do not assemble the newly registered chain until its commit is applied.
	if err := a.waitApplied(out.Ops[len(out.Ops)-1].Commit.Number); err != nil {
		return nil, err
	}

	waitCtx, cancel := context.WithTimeout(a.ctx, 15*time.Second)
	_, err = waitOnline(waitCtx, rt, waitTarget)
	cancel()
	if err != nil {
		return nil, err
	}
	snapView, err := sp.AssembleProtocolSnapshot(a.ctx, waitTarget, baseNow)
	if err != nil {
		return nil, err
	}

	ds := NewDeliveryService(a.j.db)
	rootPub, _, _ := protocol.ParseAppPublicKey(a.d.Bootstrap.Root.PublicKey)
	icPub, _, _ := protocol.ParseAppPublicKey(a.f.Domains["C"].Issuers[0].PublicKey)
	iaPub, _, _ := protocol.ParseAppPublicKey(a.f.Domains["A"].Issuers[0].PublicKey)
	deliver := []struct {
		g         api.Grant
		jws       string
		anc       []string
		grantorSD []byte
		cert      []byte
		issPub    *ecdsa.PublicKey
		grantor   *ecdsa.PublicKey
		op        *operation
	}{
		{out.G0, out.G0JWS, nil, cSvcSD, certC, icPub, &cPriv.PublicKey, out.Ops[0]},
		{out.G1, out.G1JWS, []string{out.G0JWS}, uSD, certA, iaPub, &uPriv.PublicKey, out.Ops[1]},
	}
	if withLeaf {
		deliver = append(deliver, struct {
			g         api.Grant
			jws       string
			anc       []string
			grantorSD []byte
			cert      []byte
			issPub    *ecdsa.PublicKey
			grantor   *ecdsa.PublicKey
			op        *operation
		}{out.G2, out.G2JWS, []string{out.G0JWS, out.G1JWS}, a1SD, certA, iaPub, &a1Priv.PublicKey, out.Ops[2]})
	}
	for _, item := range deliver {
		pkg := GrantDeliveryPackage{
			DeploymentID: a.d.DeploymentID, Recipient: item.g.Grantee, GrantID: item.g.ID, GrantJWS: item.jws,
			TaskSpec: a.f.M2TaskSpec, ServicePresentation: string(item.grantorSD), DomainCertificationJWS: string(item.cert), AncestorGrants: item.anc,
		}
		if _, err := ds.PublishGrantOutbox(a.ctx, snapView.Snapshot, pkg, rootPub, item.issPub, item.grantor, item.op.TxID, int64(item.op.Commit.Number), true, baseNow.Unix()); err != nil {
			return nil, err
		}
		if _, _, err := ds.DeliverGrantReceipt(a.ctx, snapView.Snapshot, a.d.DeploymentID, item.g.Grantee, item.g.ID, nil, rootPub, item.issPub, item.grantor, baseNow.Unix()); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (a acceptance) loadRoleCertAndKey(role string) ([]byte, *ecdsa.PrivateKey, api.Management, error) {
	xid, mgmt, mspDir, err := a.instance.role(role)
	if err != nil {
		return nil, nil, api.Management{}, err
	}
	cert, err := identity.CertificateFromPEM(xid.Credentials())
	if err != nil {
		return nil, nil, api.Management{}, err
	}
	keys, err := filepath.Glob(filepath.Join(mspDir, "keystore", "*"))
	if err != nil || len(keys) != 1 {
		return nil, nil, api.Management{}, fmt.Errorf("role %s keystore expected 1 key, got %v %v", role, keys, err)
	}
	keyPEM, err := os.ReadFile(keys[0])
	if err != nil {
		return nil, nil, api.Management{}, err
	}
	privAny, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, nil, api.Management{}, err
	}
	privEC, ok := privAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, api.Management{}, fmt.Errorf("role %s management key is not ECDSA", role)
	}
	return cert.Raw, privEC, mgmt, nil
}

func (a acceptance) m3AuthorityIdentityAndLifecycle() error {
	rt := newRuntime(a)
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()
	if _, err := a.waitProbe(rt, time.Time{}, 12*time.Second); err != nil {
		return err
	}

	baseNow := time.Now().UTC().Truncate(time.Second)
	sp := NewStateProvider(a.j.db, a.d, rt)
	didSrv, resolver, err := a.newControlledDIDResolver()
	if err != nil {
		return err
	}
	defer didSrv.Close()
	_ = resolver

	// 1. Live Fabric Domain B status suspend -> DOMAIN_INACTIVE check -> resume -> ACTIVE, plus S85 non-T denial.
	domB, err := ledgerRecord[api.Domain](a.ctx, a.p, "domain", "B")
	if err != nil {
		return err
	}
	if _, err := a.op("m3-s85-non-t-revoke-cert-"+a.id[:8], "domainB", "RevokeCertification", api.Mutation{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: domB.Certification, ExpectedRevision: 1,
	}, "TRUST_MANAGEMENT_FORBIDDEN"); err != nil {
		return err
	}
	if _, err := a.op("m3-s85-non-t-update-ib-"+a.id[:8], "B1", "UpdateAuthorityIdentity", api.AuthorityIdentityUpdateInput{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: a.f.Domains["B"].Issuers[0].ID,
	}, "TRUST_MANAGEMENT_FORBIDDEN"); err != nil {
		return err
	}

	if _, err := a.op("m3-domB-suspend-"+a.id[:8], "T", "SetDomainStatus", api.DomainStatus{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: "B", ExpectedRevision: domB.Revision, Status: api.Suspended,
	}, "VALID"); err != nil {
		return err
	}
	if err := poll(a.ctx, 12*time.Second, func() (bool, error) {
		snap, sErr := sp.AssembleProtocolSnapshot(a.ctx, a.f.RPG2.ID, baseNow)
		return sErr == nil && snap.Snapshot.Domains["B"].Status == api.Suspended, nil
	}); err != nil {
		return fmt.Errorf("wait domain B suspended adoption: %w", err)
	}
	domBSusp, err := ledgerRecord[api.Domain](a.ctx, a.p, "domain", "B")
	if err != nil {
		return err
	}
	if _, err := a.op("m3-domB-resume-"+a.id[:8], "T", "SetDomainStatus", api.DomainStatus{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: "B", ExpectedRevision: domBSusp.Revision, Status: api.Active,
	}, "VALID"); err != nil {
		return err
	}
	if err := poll(a.ctx, 12*time.Second, func() (bool, error) {
		snap, sErr := sp.AssembleProtocolSnapshot(a.ctx, a.f.RPG2.ID, baseNow)
		return sErr == nil && snap.Snapshot.Domains["B"].Status == api.Active, nil
	}); err != nil {
		return fmt.Errorf("wait domain B active adoption: %w", err)
	}

	// 2. Live Fabric atomic same-key CertifyDomain renewal on B (S82 stale rejection + valid renewal + receipt sync).
	domB, err = ledgerRecord[api.Domain](a.ctx, a.p, "domain", "B")
	if err != nil {
		return err
	}
	curCertB, err := ledgerRecord[api.Certification](a.ctx, a.p, "certification", domB.Certification)
	if err != nil {
		return err
	}
	tPriv, err := loadECPrivateKeyPEM(a.instance.privatePath("app", "T.key.pem"))
	if err != nil {
		return err
	}
	newCertBID := fmt.Sprintf("urn:grad:cert:B:m3-%s", a.id[:12])
	ibID := a.f.Domains["B"].Issuers[0]
	certBExp := curCertB.EXP
	if certBExp < baseNow.Add(30*time.Minute).Unix() {
		certBExp = baseNow.Add(2 * time.Hour).Unix()
	}
	certBNBF := baseNow.Add(-time.Hour).Unix()
	newCertBJWS, newCertBDig, err := protocol.SignDomainAuthorityCredential(tPriv, a.d.Bootstrap.Root.KeyID, &protocol.DomainAuthorityCredential{
		Type: []string{protocol.CredentialTypeVC, protocol.CredentialTypeDomainAuthority},
		ID:   newCertBID, DeploymentID: a.d.DeploymentID, Issuer: a.d.Bootstrap.Root.DID, Iss: a.d.Bootstrap.Root.DID,
		Sub: a.f.Domains["B"].Domain.DID, IssuerKeyVersion: a.d.Bootstrap.Root.KeyVersion,
		ValidFrom:  time.Unix(certBNBF, 0).UTC().Format(time.RFC3339),
		ValidUntil: time.Unix(certBExp, 0).UTC().Format(time.RFC3339),
		NBF:        certBNBF, EXP: certBExp,
		CredentialStatus: protocol.CredentialStatus{ID: newCertBID, Type: protocol.StatusTypeDomainCertification},
		CredentialSubject: protocol.DomainAuthoritySubject{
			ID: a.f.Domains["B"].Domain.DID, DomainID: "B",
			IdentityIssuers: []protocol.IssuerScope{{
				ID: ibID.ID, AppKeyVersion: ibID.KeyVersion,
				CredentialTypes: []string{protocol.CredentialTypeEnterpriseIdentity},
				ClaimNames:      []string{"domain", "role"},
			}},
		},
	})
	if err != nil {
		return err
	}
	newCertChain := api.Certify{
		ExpectedRevision:      domB.Revision,
		ExpectedCertification: domB.Certification,
		Certification: api.Certification{
			Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: newCertBID, Domain: "B",
			RootKeyVersion: a.d.Bootstrap.Root.KeyVersion, Digest: newCertBDig,
			Scopes: []api.Scope{{
				ID: ibID.ID, KeyVersion: ibID.KeyVersion,
				Types: []string{protocol.CredentialTypeEnterpriseIdentity}, Claims: []string{"domain", "role"},
			}},
			Interval: api.Interval{NBF: certBNBF, EXP: certBExp},
		},
	}
	staleCertChain := newCertChain
	staleCertChain.ExpectedCertification = "urn:grad:cert:B:WRONG"
	if _, err := a.op("m3-s82-cert-stale-"+a.id[:8], "T", "CertifyDomain", staleCertChain, "STATE_CHANGED"); err != nil {
		return err
	}
	certRenewOp, err := a.op("m3-f15-cert-renew-"+a.id[:8], "T", "CertifyDomain", newCertChain, "VALID")
	if err != nil {
		return err
	}
	if err := poll(a.ctx, 12*time.Second, func() (bool, error) {
		snap, sErr := sp.AssembleProtocolSnapshot(a.ctx, a.f.RPG2.ID, baseNow)
		return sErr == nil && snap.Snapshot.Domains["B"].Certification == newCertBID && snap.Snapshot.Height >= certRenewOp.Commit.Number, nil
	}); err != nil {
		return fmt.Errorf("wait domain B renewed certification adoption: %w", err)
	}
	if err := writePublicFile(a.instance.registrySubPath("certifications", "B.jws"), []byte(newCertBJWS)); err != nil {
		return err
	}
	a.f.Certifications["B"] = newCertChain
	_ = writePublicJSON(a.instance.registryPath("fixtures.json"), a.f)
	snapRenewed, err := sp.AssembleProtocolSnapshot(a.ctx, a.f.RPG2.ID, baseNow)
	if err != nil {
		return err
	}
	rootPub, _, _ := protocol.ParseAppPublicKey(a.d.Bootstrap.Root.PublicKey)
	ds := NewDeliveryService(a.j.db)
	for _, rec := range []string{a.f.Identities["C"].ID, a.f.Identities["U"].ID, a.f.Identities["A1"].ID, a.f.Identities["B1"].ID, a.f.Identities["B2"].ID} {
		if err := ds.PublishDomainCertification(a.ctx, snapRenewed.Snapshot, rec, "B", newCertBJWS, rootPub, certRenewOp.TxID, int64(certRenewOp.Commit.Number), true, baseNow.Unix()); err != nil {
			return err
		}
		if _, err := ds.SyncCertificationReceipt(a.ctx, snapRenewed.Snapshot, rec, "B", rootPub, baseNow.Unix()); err != nil {
			return err
		}
	}

	// 3. Live Fabric ephemeral identity lifecycle: S94 (Suspend/Resume permissions), RotateIdentity, RecoverIdentity (S95-S97).
	_, oldMgmt, _, err := a.instance.role("wrongB")
	if err != nil {
		return err
	}
	recCertDER, recMgmtPriv, recMgmt, err := a.loadRoleCertAndKey("recoverB")
	if err != nil {
		return err
	}
	ephDID := fmt.Sprintf("did:web:b.local:m3-eph-%s", a.id[:8])
	appPriv1, appPub1, err := protocol.GenerateP256KeyPair()
	if err != nil {
		return err
	}
	appPriv2, appPub2, err := protocol.GenerateP256KeyPair()
	if err != nil {
		return err
	}
	_ = appPriv1
	_ = appPriv2
	doc1, _ := protocol.NewDIDDocument(ephDID, ephDID+"#key-1", appPub1, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
	doc1Dig, _ := doc1.Digest()
	doc2, _ := protocol.NewDIDDocument(ephDID, ephDID+"#key-2", appPub2, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
	doc2Dig, _ := doc2.Digest()
	ephAcct := api.Digest([]byte("acct:" + ephDID))

	if _, err := a.op("m3-eph-reg-"+a.id[:8], "registrarB", "RegisterIdentity", api.Identity{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: ephDID, Domain: "B", Kind: "AGENT",
		Management: oldMgmt, DocumentDigest: doc1Dig, KeyID: ephDID + "#key-1", KeyVersion: 1, PublicKey: appPub1, AccountCommitment: ephAcct,
	}, "VALID"); err != nil {
		return err
	}
	// Self suspend -> non-registrar resume rejected (IDENTITY_MANAGEMENT_FORBIDDEN) -> registrarB resume succeeds.
	if _, err := a.op("m3-s94-self-susp-"+a.id[:8], "wrongB", "SetIdentityStatus", api.IdentityStatusInput{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: ephDID, ExpectedRevision: 1, Status: api.Suspended,
	}, "VALID"); err != nil {
		return err
	}
	for _, r := range []string{"wrongB", "domainB", "registrarA"} {
		if _, err := a.op("m3-s94-deny-"+r+"-"+a.id[:8], r, "SetIdentityStatus", api.IdentityStatusInput{
			Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: ephDID, ExpectedRevision: 2, Status: api.Active,
		}, "IDENTITY_MANAGEMENT_FORBIDDEN"); err != nil {
			return err
		}
	}
	if _, err := a.op("m3-s94-reg-resume-"+a.id[:8], "registrarB", "SetIdentityStatus", api.IdentityStatusInput{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: ephDID, ExpectedRevision: 2, Status: api.Active,
	}, "VALID"); err != nil {
		return err
	}
	// RotateIdentity -> KeyVersion 1 -> 2.
	if _, err := a.op("m3-eph-rotate-"+a.id[:8], "wrongB", "RotateIdentity", api.RotateIdentityInput{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: ephDID, ExpectedRevision: 3, ExpectedKeyVersion: 1,
		DocumentDigest: doc2Dig, KeyID: ephDID + "#key-2", PublicKey: appPub2,
	}, "VALID"); err != nil {
		return err
	}
	// Suspend -> RecoverIdentity swapping management cert to recoverB while preserving SUSPENDED status (S95, S97).
	if _, err := a.op("m3-eph-susp2-"+a.id[:8], "registrarB", "SetIdentityStatus", api.IdentityStatusInput{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: ephDID, ExpectedRevision: 4, Status: api.Suspended,
	}, "VALID"); err != nil {
		return err
	}
	recAppPriv3, recAppPub3Hex, err := protocol.GenerateP256KeyPair()
	if err != nil {
		return err
	}
	doc3, _ := protocol.NewDIDDocument(ephDID, ephDID+"#key-3", recAppPub3Hex, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
	doc3Dig, _ := doc3.Digest()
	recoveryDeployment := protocol.DeploymentBinding{ChannelID: api.Channel, GenesisHash: a.d.GenesisHash, InstanceID: a.d.InstanceID, RegistryName: api.Registry, SchemaVersion: api.Schema, Purpose: protocol.DeploymentPurpose}
	challenge, _, err := NewRegistrationCoordinator(a.j.db).IssueRecoveryChallenge(a.ctx, recoveryDeployment, IssueRecoveryChallengeRequest{
		DomainID: "B", SubjectID: ephDID, AccountCommitment: ephAcct, ExpectedRevision: 5, ExpectedKeyVersion: 2,
		OldManagementIdentity: protocol.ManagementIdentity{MSPID: oldMgmt.MSPID, CertificateSha256: oldMgmt.Fingerprint},
		NewManagementIdentity: protocol.ManagementIdentity{MSPID: recMgmt.MSPID, CertificateSha256: recMgmt.Fingerprint},
		DIDDocumentDigest:     doc3Dig, NewAppKeyID: ephDID + "#key-3", NewAppPublicKey: recAppPub3Hex, IssuedAt: time.Now().Unix(), TTLSeconds: 300,
	})
	if err != nil {
		return err
	}
	recDual, err := protocol.SignRecoveryDualProofBundle(recoveryDeployment, *challenge, recCertDER, recMgmtPriv, recAppPriv3)
	if err != nil {
		return err
	}
	recoveryHTTPReport, err := a.verifyRecoveryHTTP(recDual)
	if err != nil {
		return err
	}
	recoveredID, err := ledgerRecord[api.Identity](a.ctx, a.p, "identity", ephDID)
	if err != nil || recoveredID.Status != api.Suspended || recoveredID.Management != recMgmt || recoveredID.KeyVersion != 3 {
		return fmt.Errorf("S95/S97 recovered identity invariant failed: %+v err=%v", recoveredID, err)
	}
	// Old cert rejected, registrarB resumes -> recoverB rotates key -> revoke terminal -> further recover rejected.
	if _, err := a.op("m3-s95-oldcert-deny-"+a.id[:8], "wrongB", "RotateIdentity", api.RotateIdentityInput{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: ephDID, ExpectedRevision: recoveredID.Revision, ExpectedKeyVersion: 3,
		DocumentDigest: doc2Dig, KeyID: ephDID + "#key-4", PublicKey: appPub2,
	}, "IDENTITY_MANAGEMENT_FORBIDDEN"); err != nil {
		return err
	}
	if _, err := a.op("m3-s97-resume-"+a.id[:8], "registrarB", "SetIdentityStatus", api.IdentityStatusInput{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: ephDID, ExpectedRevision: recoveredID.Revision, Status: api.Active,
	}, "VALID"); err != nil {
		return err
	}
	if _, err := a.op("m3-s97-revoke-"+a.id[:8], "registrarB", "SetIdentityStatus", api.IdentityStatusInput{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: ephDID, ExpectedRevision: recoveredID.Revision + 1, Status: api.Revoked,
	}, "VALID"); err != nil {
		return err
	}
	if _, err := a.op("m3-s97-revoked-recover-"+a.id[:8], "registrarB", "RecoverIdentity", api.RecoverIdentityInput{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: ephDID, ExpectedRevision: recoveredID.Revision + 2, ExpectedKeyVersion: 3,
		AccountCommitment: ephAcct, OldManagement: recMgmt, NewManagement: oldMgmt,
		DocumentDigest: doc1Dig, KeyID: ephDID + "#key-4", PublicKey: appPub1,
	}, "IDENTITY_STATE_CONFLICT"); err != nil {
		return err
	}

	// 4. Live Fabric E3 Grant/Task/Credential lifecycle (SuspendGrant/ResumeGrant preserving EXP, CancelTask, RevokeCredential).
	chain, err := a.provisionEphemeralM3RPChain(rt, sp, "lc-"+a.id[:8], 500000, true, baseNow)
	if err != nil {
		return err
	}
	if _, err := a.op("m3-e3-susp-g2-"+a.id[:8], "A1", "SuspendGrant", revokeOf(chain.G2), "VALID"); err != nil {
		return err
	}
	g2Susp, err := ledgerRecord[api.Grant](a.ctx, a.p, "grant", chain.G2.ID)
	if err != nil || g2Susp.Status != api.Suspended || g2Susp.EXP != chain.G2.EXP {
		return fmt.Errorf("SuspendGrant mismatch: %+v err=%v", g2Susp, err)
	}
	if _, err := a.op("m3-e3-res-g2-"+a.id[:8], "A1", "ResumeGrant", revokeOf(g2Susp), "VALID"); err != nil {
		return err
	}
	if _, err := a.op("m3-e3-cancel-task-"+a.id[:8], "U", "CancelTask", api.Mutation{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: chain.Task.ID, ExpectedRevision: 1, ExpectedDigest: chain.Task.Digest,
	}, "VALID"); err != nil {
		return err
	}

	// 5. Actual mTLS REST -> Fabric submissions and original-transaction recovery.
	managementReport, err := a.verifyM3ManagementHTTP(chain.G1)
	if err != nil {
		return err
	}

	// 6. Isolated PostgreSQL + real gateway.Server checks for F14 (T offline, 0 calls), S81 (B1 cache + stale KeyVersion), S84 (MATERIAL_NOT_SYNCED), S93 (department shrink).
	b1CacheReport, err := a.verifyIsolatedM3CacheAndTOfflineChecks(baseNow)
	if err != nil {
		return err
	}

	dynPayload := map[string]any{
		"s85Forbidden":               true,
		"domainBStatusRestored":      true,
		"domainBRenewedCertId":       newCertBID,
		"domainBRenewedCertJWS":      newCertBJWS,
		"ephemeralRecoveredIdentity": recoveredID,
		"recoveryDualProof":          recDual,
		"recoveryHTTP":               recoveryHTTPReport,
		"grantSuspendResumeExpKept":  true,
		"taskCancelled":              chain.Task.ID,
		"asyncMgmtConfirmedStatus":   managementReport["confirmed"].(OperationView).Status,
		"managementHTTP":             managementReport,
		"offlineAndCacheChecks":      b1CacheReport,
	}
	return a.recordM3Evidence("m3-dynamic-recovery.json", dynPayload, func(ev *m3EvidenceReport) {
		ev.DynamicLifecycle = dynPayload
	})
}

func (a acceptance) verifyIsolatedM3CacheAndTOfflineChecks(baseNow time.Time) (map[string]any, error) {
	ca, err := protocol.GenerateTestCA(baseNow)
	if err != nil {
		return nil, err
	}
	caPool, err := protocol.ParseTestCAPublic(ca.CertPEM)
	if err != nil {
		return nil, err
	}
	certs := make(map[string]*protocol.HostTLSCert, len(protocol.ControlledTestDomains))
	for _, host := range protocol.ControlledTestDomains {
		hc, err := ca.IssueHostCert(host, baseNow)
		if err != nil {
			return nil, err
		}
		certs[host] = hc
	}
	privT, pubT, _ := protocol.GenerateP256KeyPair()
	privIC, pubIC, _ := protocol.GenerateP256KeyPair()
	privIB1, pubIB1, _ := protocol.GenerateP256KeyPair()
	privIB2, pubIB2, _ := protocol.GenerateP256KeyPair()
	_, pubDomB, _ := protocol.GenerateP256KeyPair()
	_, pubDomC, _ := protocol.GenerateP256KeyPair()
	privC, pubC, _ := protocol.GenerateP256KeyPair()
	privU, pubU, _ := protocol.GenerateP256KeyPair()
	privB1, pubB1, _ := protocol.GenerateP256KeyPair()
	privIA, pubIA, _ := protocol.GenerateP256KeyPair()
	_, pubDomA, _ := protocol.GenerateP256KeyPair()
	_ = privIB2
	_ = pubIB2

	didT, didB, didC := "did:web:t.local", "did:web:b.local", "did:web:c.local"
	didIB, didIC, didCSvc := "did:web:b.local:ib", "did:web:c.local:ic", "did:web:c.local:supplier"
	didU, didB1 := "did:web:a.local:u", "did:web:b.local:b1"
	didA, didIA := "did:web:a.local", "did:web:a.local:ia"
	docs := map[string][]byte{}
	mkDoc := func(did, kid, pub string, purposes ...string) string {
		d, _ := protocol.NewDIDDocument(did, kid, pub, purposes...)
		raw, _ := protocol.MarshalJCS(d)
		dig, _ := d.Digest()
		docs[did] = raw
		return dig
	}
	digT := mkDoc(didT, didT+"#key-1", pubT, protocol.KeyPurposeAssertionMethod)
	mkDoc(didA, didA+"#key-1", pubDomA, protocol.KeyPurposeAssertionMethod)
	mkDoc(didIA, didIA+"#key-1", pubIA, protocol.KeyPurposeAssertionMethod)
	mkDoc(didB, didB+"#key-1", pubDomB, protocol.KeyPurposeAssertionMethod)
	mkDoc(didC, didC+"#key-1", pubDomC, protocol.KeyPurposeAssertionMethod)
	mkDoc(didIB, didIB+"#key-1", pubIB1, protocol.KeyPurposeAssertionMethod)
	mkDoc(didIC, didIC+"#key-1", pubIC, protocol.KeyPurposeAssertionMethod)
	mkDoc(didCSvc, didCSvc+"#key-1", pubC, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
	mkDoc(didU, didU+"#key-1", pubU, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
	mkDoc(didB1, didB1+"#key-1", pubB1, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)

	// Start DIDWebServer WITHOUT t.local route (T offline F14); also install a counting dead T handler to prove 0 calls.
	var tOfflineHits atomic.Int64
	deadTSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tOfflineHits.Add(1)
		http.Error(w, "T offline", http.StatusServiceUnavailable)
	}))
	defer deadTSrv.Close()

	didSrv, err := protocol.NewDIDWebServer(certs, docs)
	if err != nil {
		return nil, err
	}
	defer didSrv.Close()
	routes := didSrv.Routes()
	routes["t.local"] = strings.TrimPrefix(deadTSrv.URL, "https://")
	resolver, err := protocol.NewDIDWebResolver(caPool, routes)
	if err != nil {
		return nil, err
	}
	if _, err := resolver.RegisterPreseed(protocol.RootPreseed{
		DID: didT, KeyID: didT + "#key-1", KeyVersion: 1, PublicKeyHex: pubT, DIDDocumentDigest: digT, RawDocument: docs[didT],
	}); err != nil {
		return nil, err
	}

	isoTag := "iso-" + a.id[:12]
	isoDep := api.Digest([]byte("dep:" + isoTag))
	isoTask := api.Digest([]byte("task:" + isoTag))
	isoRes := api.Digest([]byte("res:" + isoTag))
	nbf, exp := baseNow.Add(-time.Hour).Unix(), baseNow.Add(2*time.Hour).Unix()
	polExp := baseNow.Add(4 * time.Hour).Unix()
	rootRec := api.RootRecord{
		DID: didT, Management: api.Management{MSPID: "TMSP", Fingerprint: strings.Repeat("1", 64)},
		DocumentDigest: digT, KeyID: didT + "#key-1", KeyVersion: 1, PublicKey: pubT,
	}
	boot := api.Bootstrap{
		DeploymentFields: api.DeploymentFields{
			ChannelID: api.Channel, GenesisHash: api.Digest([]byte("g:" + isoTag)),
			InstanceID: api.Digest([]byte("i:" + isoTag)), RegistryName: api.Registry, SchemaVersion: api.Schema,
		},
		Root: rootRec, Initializer: rootRec.Management,
		TaskCreator: api.TaskAuthority{Domain: "A", Subject: didU, Management: api.Management{MSPID: "AMSP", Fingerprint: strings.Repeat("2", 64)}},
		ResourceID:  isoRes, ResourceOwner: didCSvc, ResourceManagement: api.Management{MSPID: "CMSP", Fingerprint: strings.Repeat("3", 64)},
	}

	signCert := func(certID, domID, domDID, issDID string, claims []string) (string, string, api.Domain, api.Certification) {
		jws, dig, _ := protocol.SignDomainAuthorityCredential(privT, didT+"#key-1", &protocol.DomainAuthorityCredential{
			Type: []string{protocol.CredentialTypeVC, protocol.CredentialTypeDomainAuthority},
			ID:   certID, DeploymentID: isoDep, Issuer: didT, Iss: didT, Sub: domDID, IssuerKeyVersion: 1,
			ValidFrom: time.Unix(nbf, 0).UTC().Format(time.RFC3339), ValidUntil: time.Unix(exp, 0).UTC().Format(time.RFC3339),
			NBF: nbf, EXP: exp,
			CredentialStatus: protocol.CredentialStatus{ID: certID, Type: protocol.StatusTypeDomainCertification},
			CredentialSubject: protocol.DomainAuthoritySubject{ID: domDID, DomainID: domID, IdentityIssuers: []protocol.IssuerScope{{
				ID: issDID, AppKeyVersion: 1, CredentialTypes: []string{protocol.CredentialTypeEnterpriseIdentity}, ClaimNames: claims,
			}}},
		})
		return jws, dig, api.Domain{
			Bound: api.Bound{DeploymentID: isoDep}, ID: domID, DID: domDID,
			Admin:     api.Management{MSPID: domID + "Msp", Fingerprint: strings.Repeat("a", 64)},
			Registrar: api.Management{MSPID: domID + "Msp", Fingerprint: strings.Repeat("b", 64)},
			Issuers:   []string{issDID}, Certification: certID, Version: api.Version{Status: api.Active, Revision: 1},
		}, api.Certification{
			Bound: api.Bound{DeploymentID: isoDep}, ID: certID, Domain: domID, RootKeyVersion: 1, Digest: dig,
			Scopes:   []api.Scope{{ID: issDID, KeyVersion: 1, Types: []string{protocol.CredentialTypeEnterpriseIdentity}, Claims: claims}},
			Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1},
		}
	}
	certBJWS, certBDig, domB, certB := signCert("cert:B:shrink-"+isoTag, "B", didB, didIB, []string{"domain", "role"})
	certAJWS, certADig, domA, certA := signCert("cert:A:"+isoTag, "A", didA, didIA, []string{"domain", "role"})
	certCJWS, certCDig, domC, certC := signCert("cert:C:"+isoTag, "C", didC, didIC, []string{"domain", "role"})

	mkID := func(did, dom, kind, pub, dig string) api.Identity {
		if dig == "" {
			_, dig, _ = protocol.ParseDIDDocument(docs[did])
		}
		return api.Identity{
			Bound: api.Bound{DeploymentID: isoDep}, ID: did, Domain: dom, Kind: kind,
			Management:     api.Management{MSPID: dom + "Msp", Fingerprint: strings.Repeat("4", 64)},
			DocumentDigest: dig, KeyID: did + "#key-1", KeyVersion: 1, PublicKey: pub,
			AccountCommitment: api.Digest([]byte("a:" + did)), Version: api.Version{Status: api.Active, Revision: 1},
		}
	}
	issueSD := func(priv *ecdsa.PrivateKey, iss, sub, cid, dom, role, pub string, extra map[string]string) (*protocol.SignedSDJWTCredential, api.Credential) {
		jwk, _ := protocol.AppPublicKeyToJWK(pub)
		sd, _ := protocol.IssueEnterpriseIdentityCredential(priv, iss+"#key-1", protocol.EnterpriseIdentityCredential{
			Type: []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity},
			ID:   cid, DeploymentID: isoDep, Issuer: iss, Iss: iss, Sub: sub, IssuerKeyVersion: 1, AppKeyVersion: 1,
			ValidFrom: time.Unix(nbf, 0).UTC().Format(time.RFC3339), ValidUntil: time.Unix(exp, 0).UTC().Format(time.RFC3339),
			NBF: nbf, EXP: exp, CredentialStatus: protocol.CredentialStatus{ID: cid, Type: protocol.StatusTypeCredential},
			Cnf: protocol.ConfirmationKey{JWK: jwk}, CredentialSubject: protocol.SDJWTCredentialSubject{ID: sub},
		}, dom, role, extra)
		claimNames := []string{"domain", "role"}
		if _, hasDept := extra["department"]; hasDept {
			claimNames = []string{"department", "domain", "role"}
		}
		return sd, api.Credential{
			Bound: api.Bound{DeploymentID: isoDep}, ID: cid, Issuer: iss, Subject: sub, IssuerKeyVersion: 1, SubjectKeyVersion: 1,
			Type: protocol.CredentialTypeEnterpriseIdentity, ClaimNames: claimNames, Digest: sd.AnchorDigest,
			Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1},
		}
	}
	sdC, cCred := issueSD(privIC, didIC, didCSvc, "cred:C:"+isoTag, "C", "supplier-service", pubC, nil)
	sdU, uCred := issueSD(privIA, didIA, didU, "cred:U:"+isoTag, "A", "procurement-owner", pubU, nil)
	sdB1Dept, b1Cred := issueSD(privIB1, didIB, didB1, "cred:B1:"+isoTag, "B", "broker-agent", pubB1, map[string]string{"department": "finance"})
	sdB1HiddenDept := sdB1Dept.IssuerSignedJWT + "~" + sdB1Dept.DisclosureByClaim["domain"] + "~" + sdB1Dept.DisclosureByClaim["role"] + "~"
	sdB1DisclosedDept := sdB1Dept.PresentationPrefix
	spec := protocol.TaskSpec{
		SupplierID: "urn:grad:supplier:C", ProductID: "urn:grad:product:P1", MaxQuantity: 10, Currency: "CNY",
		Resources: []string{"urn:grad:resource:C:quotes"}, Actions: []string{"quote.read"},
		Description: "M3 offline root and disclosure-scope acceptance",
	}
	tDig, err := spec.Digest()
	if err != nil {
		return nil, err
	}
	g0ID := api.Digest([]byte("g0:" + isoTag))
	g0Claims := protocol.GrantClaims{
		SchemaVersion: api.Schema, DeploymentID: isoDep, ID: g0ID, RootID: g0ID, TaskID: isoTask,
		AuthorizationMode: api.RP, PrincipalDomain: "A", ResourceID: isoRes, Aud: "https://c.local",
		Issuer: didCSvc, IssuerKeyVersion: 1, IssuerCredentialID: cCred.ID,
		Grantee: didU, GranteeKeyVersion: 1, GranteeCredentialID: uCred.ID,
		Resources: spec.Resources, Actions: spec.Actions, Suppliers: []string{"urn:grad:supplier:C"},
		Currency: "CNY", MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 1,
	}
	g0JWS, g0Dig, _ := protocol.SignGrant(privC, didCSvc+"#key-1", &g0Claims)
	g0Chain := api.Grant{
		Bound: api.Bound{DeploymentID: isoDep}, ID: g0ID, Schema: api.Schema, Root: g0ID, Task: isoTask,
		Mode: api.RP, Domain: "A", Resource: isoRes, Issuer: didCSvc, Grantee: didU, Depth: 1,
		IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: cCred.ID, GranteeCredential: uCred.ID,
		Digest: g0Dig, Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1},
	}
	g1ID := api.Digest([]byte("g1:" + isoTag))
	g1Claims := g0Claims
	g1Claims.ID, g1Claims.ParentID, g1Claims.ParentDigest = g1ID, &g0ID, &g0Dig
	g1Claims.Issuer, g1Claims.IssuerCredentialID = didU, uCred.ID
	g1Claims.Grantee, g1Claims.GranteeCredentialID, g1Claims.RemainingDepth = didB1, b1Cred.ID, 0
	g1JWS, g1Dig, err := protocol.SignGrant(privU, didU+"#key-1", &g1Claims)
	if err != nil {
		return nil, err
	}
	g1Chain := g0Chain
	g1Chain.ID, g1Chain.Parent, g1Chain.ParentDigest, g1Chain.Digest = g1ID, g0ID, g0Dig, g1Dig
	g1Chain.Issuer, g1Chain.IssuerCredential = didU, uCred.ID
	g1Chain.Grantee, g1Chain.GranteeCredential, g1Chain.Depth = didB1, b1Cred.ID, 0

	if err := gateway.EnsureSchema(a.ctx, a.j.db, isoDep, "urn:grad:supplier:C"); err != nil {
		return nil, err
	}
	defer func() {
		bg := context.Background()
		_, _ = a.j.db.Exec(bg, `DELETE FROM quotes WHERE deployment_id=$1`, isoDep)
		_, _ = a.j.db.Exec(bg, `DELETE FROM decisions WHERE deployment_id=$1`, isoDep)
		_, _ = a.j.db.Exec(bg, `DELETE FROM business_keys WHERE deployment_id=$1`, isoDep)
		_, _ = a.j.db.Exec(bg, `DELETE FROM challenges WHERE deployment_id=$1`, isoDep)
		_, _ = a.j.db.Exec(bg, `DELETE FROM trusted_contexts WHERE deployment_id=$1`, isoDep)
		_, _ = a.j.db.Exec(bg, `DELETE FROM certification_receipts WHERE deployment_id=$1`, isoDep)
		_, _ = a.j.db.Exec(bg, `DELETE FROM fabric_current WHERE deployment=$1`, isoDep)
		_, _ = a.j.db.Exec(bg, `DELETE FROM fabric_head WHERE deployment=$1`, isoDep)
	}()
	put := func(k string, v any) {
		raw, _ := json.Marshal(v)
		_, _ = a.j.db.Exec(a.ctx, `INSERT INTO fabric_current(deployment, key, value) VALUES($1,$2,$3)
			ON CONFLICT(deployment,key) DO UPDATE SET value=EXCLUDED.value`, isoDep, k, raw)
	}
	_, _ = a.j.db.Exec(a.ctx, `INSERT INTO fabric_head(deployment, block_no, hash) VALUES($1,1,$2) ON CONFLICT DO NOTHING`, isoDep, api.Digest([]byte("bh:"+isoTag)))
	put(api.BootstrapKey, boot)
	put(api.Key("domain", "A"), domA)
	put(api.Key("domain", "B"), domB)
	put(api.Key("domain", "C"), domC)
	put(api.Key("certification", certB.ID), certB)
	put(api.Key("certification", certA.ID), certA)
	put(api.Key("certification", certC.ID), certC)
	put(api.Key("identity", didIB), mkID(didIB, "B", "ISSUER", pubIB1, ""))
	put(api.Key("identity", didIC), mkID(didIC, "C", "ISSUER", pubIC, ""))
	put(api.Key("identity", didIA), mkID(didIA, "A", "ISSUER", pubIA, ""))
	put(api.Key("identity", didU), mkID(didU, "A", "USER", pubU, ""))
	for _, domain := range []struct {
		did, id, pub string
		record       api.Domain
	}{{didA, "A", pubDomA, domA}, {didB, "B", pubDomB, domB}, {didC, "C", pubDomC, domC}} {
		rec := mkID(domain.did, domain.id, "DOMAIN", domain.pub, "")
		rec.Management = domain.record.Admin
		put(api.Key("identity", domain.did), rec)
	}
	put(api.Key("identity", didCSvc), mkID(didCSvc, "C", "SERVICE", pubC, ""))
	put(api.Key("identity", didB1), mkID(didB1, "B", "AGENT", pubB1, ""))
	put(api.Key("credential", cCred.ID), cCred)
	put(api.Key("credential", b1Cred.ID), b1Cred)
	put(api.Key("credential", uCred.ID), uCred)
	put(api.Key("task", isoTask), api.Task{
		Bound: api.Bound{DeploymentID: isoDep}, ID: isoTask, Creator: didU, CreatorKeyVersion: 1,
		CreatorCredential: uCred.ID, Resource: isoRes, Mode: api.RP, Domain: "A", Digest: tDig,
		Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1},
	})
	put(api.Key("grant", g0ID), g0Chain)
	put(api.Key("grant", g1ID), g1Chain)
	_, _ = a.j.db.Exec(a.ctx, `INSERT INTO certification_receipts(deployment_id,domain_id,certification_id,recipient,cert_jws,cert_digest,received_at) VALUES($1,'A',$2,$3,$4,$5,$6)`,
		isoDep, certA.ID, didCSvc, certAJWS, certADig, baseNow.Unix())
	_, _ = a.j.db.Exec(a.ctx, `INSERT INTO certification_receipts(deployment_id,domain_id,certification_id,recipient,cert_jws,cert_digest,received_at) VALUES($1,'B',$2,$3,$4,$5,$6)`,
		isoDep, certB.ID, didCSvc, certBJWS, certBDig, baseNow.Unix())
	_, _ = a.j.db.Exec(a.ctx, `INSERT INTO certification_receipts(deployment_id,domain_id,certification_id,recipient,cert_jws,cert_digest,received_at) VALUES($1,'C',$2,$3,$4,$5,$6)`,
		isoDep, certC.ID, didCSvc, certCJWS, certCDig, baseNow.Unix())

	files, polDig, _ := policy.BuildDefaultBundle(isoDep, didCSvc, policy.DefaultPolicyVersion, rootRec, &polExp)
	bundle, _ := policy.VerifyAndLoadBundle(files, isoDep, didCSvc, rootRec, polDig)
	sp := NewStateProviderFromBootstrap(a.j.db, isoDep, boot, nil)
	sp.SetMonoClock(func() time.Time { return baseNow })
	sp.SetStaticProbe(&ProbeSnapshot{TxID: "iso-p-" + isoTag, ProbeBlock: 1, SentAt: baseNow, Deadline: baseNow.Add(5 * time.Second), SentMonoNs: baseNow.UnixNano(), DeadlineMonoNs: baseNow.Add(5 * time.Second).UnixNano(), AdoptedAt: baseNow, AdoptedMonoNs: baseNow.UnixNano()})
	sigCache := protocol.NewSignatureCache()
	srv, err := gateway.NewServer(gateway.Config{
		DB: a.j.db, State: sp.GatewayAdapter(), Delivery: NewDeliveryService(a.j.db), DIDs: resolver,
		Policy: bundle, SignatureCache: sigCache, DeploymentID: isoDep, ServiceDID: didCSvc, Audience: "https://c.local", SupplierID: "urn:grad:supplier:C",
		NowFn: func() time.Time { return baseNow },
	})
	if err != nil {
		return nil, err
	}
	if _, err := gatewaySetContext(srv.Handler(), isoTask, 0, baseNow.Unix()-1, "NORMAL", exp); err != nil {
		return nil, err
	}

	req := protocol.AccessRequest{
		SchemaVersion: api.Schema, DeploymentID: isoDep, Actor: didB1, PrincipalDomain: "A", AuthorizationMode: api.RP,
		TaskID: isoTask, Audience: "https://c.local", Resource: "urn:grad:resource:C:quotes", Action: "quote.read",
		SupplierID: "urn:grad:supplier:C", ProductID: "urn:grad:product:P1", Quantity: 1, Currency: "CNY", AmountMinor: 0,
	}
	tp := []protocol.TrustPathEntry{{Issuer: didIA, DomainCertification: certAJWS}, {Issuer: didIB, DomainCertification: certBJWS}, {Issuer: didIC, DomainCertification: certCJWS}}
	anc := []protocol.AncestorCredential{{CredentialID: cCred.ID, Presentation: sdC.PresentationPrefix}, {CredentialID: uCred.ID, Presentation: sdU.PresentationPrefix}}

	// S93 + F14 (T offline, hidden department succeeds twice populating B1 cache; disclosed department returns 403 ISSUER_SCOPE_INVALID).
	for i := 1; i <= 2; i++ {
		r1 := req
		r1.IdempotencyKey = fmt.Sprintf("iso-s93-ok-%d", i)
		pkg, _, err := a.buildLeafExecutePackage(srv.Handler(), r1, spec, privB1, didB1+"#key-1", sdB1HiddenDept, anc, []string{g0JWS, g1JWS}, tp, baseNow.Unix())
		if err != nil {
			return nil, err
		}
		rec := gatewayPostExecute(srv.Handler(), pkg)
		if rec.Code != http.StatusOK {
			return nil, fmt.Errorf("F14/S93 hidden department execute #%d failed: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	if tOfflineHits.Load() != 0 {
		return nil, fmt.Errorf("F14 violated: expected 0 calls to T offline host, got %d", tOfflineHits.Load())
	}
	if sigCache.Hits() == 0 {
		return nil, fmt.Errorf("expected B1 signature cache hits > 0 on warm call")
	}
	rDisclose := req
	rDisclose.IdempotencyKey = "iso-s93-disclose"
	pkgDisclose, _, err := a.buildLeafExecutePackage(srv.Handler(), rDisclose, spec, privB1, didB1+"#key-1", sdB1DisclosedDept, anc, []string{g0JWS, g1JWS}, tp, baseNow.Unix())
	if err != nil {
		return nil, err
	}
	recDisclose := gatewayPostExecute(srv.Handler(), pkgDisclose)
	if recDisclose.Code != http.StatusForbidden || !strings.Contains(recDisclose.Body.String(), protocol.ErrCodeIssuerScopeInvalid) {
		return nil, fmt.Errorf("S93 expected 403 ISSUER_SCOPE_INVALID for disclosed shrunk claim, got %d %s", recDisclose.Code, recDisclose.Body.String())
	}

	// S81: Rotate B1 identity KeyVersion=2 in fabric_current while presenting old VC -> cached signatures still hit 403 KEY_VERSION_STALE!
	b1Rot := mkID(didB1, "B", "AGENT", pubB1, "")
	b1Rot.KeyVersion = 2
	b1Rot.KeyID = didB1 + "#key-2"
	_, pubB1v2, _ := protocol.GenerateP256KeyPair()
	b1Rot.PublicKey = pubB1v2
	put(api.Key("identity", didB1), b1Rot)
	rStale := req
	rStale.IdempotencyKey = "iso-s81-stale"
	pkgStale, _, err := a.buildLeafExecutePackage(srv.Handler(), rStale, spec, privB1, didB1+"#key-1", sdB1HiddenDept, anc, []string{g0JWS, g1JWS}, tp, baseNow.Unix())
	if err != nil {
		return nil, err
	}
	recStale := gatewayPostExecute(srv.Handler(), pkgStale)
	if recStale.Code != http.StatusForbidden || !strings.Contains(recStale.Body.String(), protocol.ErrCodeKeyVersionStale) {
		return nil, fmt.Errorf("S81 expected 403 KEY_VERSION_STALE after KeyVersion bump, got %d %s", recStale.Code, recStale.Body.String())
	}
	// Restore KeyVersion=1, delete synced certB receipt -> S84 503 MATERIAL_NOT_SYNCED.
	put(api.Key("identity", didB1), mkID(didB1, "B", "AGENT", pubB1, ""))
	_, _ = a.j.db.Exec(a.ctx, `DELETE FROM certification_receipts WHERE deployment_id=$1 AND certification_id=$2`, isoDep, certB.ID)
	rNoMat := req
	rNoMat.IdempotencyKey = "iso-s84-nomat"
	pkgNoMat, _, err := a.buildLeafExecutePackage(srv.Handler(), rNoMat, spec, privB1, didB1+"#key-1", sdB1HiddenDept, anc, []string{g0JWS, g1JWS}, tp, baseNow.Unix())
	if err != nil {
		return nil, err
	}
	recNoMat := gatewayPostExecute(srv.Handler(), pkgNoMat)
	if recNoMat.Code != http.StatusServiceUnavailable || !strings.Contains(recNoMat.Body.String(), protocol.ErrCodeMaterialNotSynced) {
		return nil, fmt.Errorf("S84 expected 503 MATERIAL_NOT_SYNCED when local cert body absent, got %d %s", recNoMat.Code, recNoMat.Body.String())
	}

	_ = privIB1
	_ = privU
	return map[string]any{
		"f14OfflineTHits":        tOfflineHits.Load(),
		"b1SignatureCacheHits":   sigCache.Hits(),
		"b1SignatureCacheMisses": sigCache.Misses(),
		"s93DisclosedCode":       recDisclose.Code,
		"s81StaleCode":           recStale.Code,
		"s84MaterialMissingCode": recNoMat.Code,
	}, nil
}

func (a acceptance) m3AgentB2ReplacementAndReconcile() error {
	rt := newRuntime(a)
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()

	baseNow := time.Now().UTC().Truncate(time.Second)
	sp := NewStateProvider(a.j.db, a.d, rt)
	chain, err := a.provisionEphemeralM3RPChain(rt, sp, "e3-"+a.id[:8], 500000, false, baseNow)
	if err != nil {
		return err
	}

	didSrv, resolver, err := a.newControlledDIDResolver()
	if err != nil {
		return err
	}
	defer didSrv.Close()
	_ = resolver

	if err := gateway.EnsureSchema(a.ctx, a.j.db, a.d.DeploymentID, "urn:grad:supplier:C"); err != nil {
		return err
	}
	if _, err := a.j.db.Exec(a.ctx, `UPDATE catalog_prices SET unit_price_minor=80000 WHERE deployment_id=$1 AND product_id=$2`,
		a.d.DeploymentID, gateway.DefaultProductID); err != nil {
		return err
	}
	cDID := a.f.Identities["C"].ID
	polDeadline := baseNow.Add(4 * time.Hour).Unix()
	files, polDig, err := policy.BuildDefaultBundle(a.d.DeploymentID, cDID, policy.DefaultPolicyVersion, a.d.Bootstrap.Root, &polDeadline)
	if err != nil {
		return err
	}
	bundle, err := policy.VerifyAndLoadBundle(files, a.d.DeploymentID, cDID, a.d.Bootstrap.Root, polDig)
	if err != nil {
		return err
	}
	auditorDID := "did:web:c.local:auditors:c1"
	srv, err := gateway.NewServer(gateway.Config{
		DB: a.j.db, State: sp.GatewayAdapter(), Delivery: NewDeliveryService(a.j.db), DIDs: resolver,
		Policy: bundle, PolicyArchive: map[string]*policy.VerifiedBundle{bundle.PolicyDigest: bundle},
		AuditorDIDs: []string{auditorDID}, VerifierID: auditorDID,
		DeploymentID: a.d.DeploymentID, ServiceDID: cDID, Audience: "https://c.local", SupplierID: "urn:grad:supplier:C",
		NowFn: func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return err
	}
	if _, err := a.ensureTaskContextNormal(srv.Handler(), chain.Task.ID, baseNow.Unix()); err != nil {
		return err
	}

	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()
	dropRT := &dropAfterHTTPTransport{base: http.DefaultTransport, dropIDs: map[string]bool{}}
	httpClient := &http.Client{Transport: dropRT, Timeout: 15 * time.Second}

	// Load actor materials to wire live Fabric Anchor/Replace + receipt delivery callbacks.
	_, _, _, uPriv, uSD, a1Priv, a1SD, _, _, cSvcSD, _, _, certC, certA, err := a.loadM2RoleMaterials()
	if err != nil {
		return err
	}
	bIssuerDID := a.f.Domains["B"].Issuers[0].ID
	certB, err := os.ReadFile(a.instance.registrySubPath("certifications", "B.jws"))
	if err != nil {
		return err
	}
	tpRP := []protocol.TrustPathEntry{
		{Issuer: a.f.Domains["A"].Issuers[0].ID, DomainCertification: string(certA)},
		{Issuer: bIssuerDID, DomainCertification: string(certB)},
		{Issuer: a.f.Domains["C"].Issuers[0].ID, DomainCertification: string(certC)},
	}
	ds := NewDeliveryService(a.j.db)
	rootPub, _, _ := protocol.ParseAppPublicKey(a.d.Bootstrap.Root.PublicKey)
	iaPub, _, _ := protocol.ParseAppPublicKey(a.f.Domains["A"].Issuers[0].PublicKey)
	_ = cSvcSD
	_ = uPriv
	_ = uSD

	buildWallet := func(chain *m3RPChainFixture) (*agent.WalletContext, error) {
		parentJWS := chain.G1JWS
		var receiptDelivery func(context.Context, gateway.OrderOutcomeReceipt) (*gateway.OrderOutcomeReceiptResponse, error)
		if srv.Handler() != nil {
			receiptDelivery = func(ctx context.Context, r gateway.OrderOutcomeReceipt) (*gateway.OrderOutcomeReceiptResponse, error) {
				return gateway.DeliverStoredReceipt(ctx, a.j.db, a.d.DeploymentID, serviceauth.NewLocalClient(srv.Handler(), serviceauth.Identity{Role: "C_AUDIT_SERVICE", DID: auditorDID}), "https://c.local/v1/internal/order-outcome-receipts", r)
			}
		}
		w, err := agent.NewWalletContext(agent.WalletConfig{
			ReceiptDelivery: receiptDelivery,
			DeploymentID:    a.d.DeploymentID, GatewayURL: httpSrv.URL, Audience: "https://c.local",
			SupplierID: "urn:grad:supplier:C", SupplierDID: cDID, DefaultTaskSpec: a.f.M2TaskSpec, Currency: "CNY",
			AuditorDID: auditorDID, RecoveryDID: "did:web:b.local:services:recovery",
			DB: a.j.db, HTTPClient: httpClient,
			RecoveryClient: serviceauth.NewLocalClient(srv.Handler(), serviceauth.Identity{Role: "B_RECOVERY", DID: "did:web:b.local:services:recovery"}),
			AuditClient:    serviceauth.NewLocalClient(srv.Handler(), serviceauth.Identity{Role: "C_AUDITOR", DID: auditorDID}),
			ReceiptClient:  serviceauth.NewLocalClient(srv.Handler(), serviceauth.Identity{Role: "C_AUDIT_SERVICE", DID: auditorDID}),
			Now:            func() time.Time { return time.Now().UTC() },
			AnchorChildFunc: func(callCtx context.Context, req agent.AnchorChildGrantRequest) (*agent.AnchorChildGrantResult, error) {
				chainGrant := api.Grant{
					Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: req.Claims.ID, Schema: api.Schema,
					Parent: req.ParentID, ParentDigest: derefStr(req.Claims.ParentDigest), Root: req.Claims.RootID, Task: req.Claims.TaskID,
					Mode: req.Claims.AuthorizationMode, Domain: req.Claims.PrincipalDomain, Resource: req.Claims.ResourceID,
					Issuer: req.Claims.Issuer, Grantee: req.Claims.Grantee, IssuerKeyVersion: req.Claims.IssuerKeyVersion,
					GranteeKeyVersion: req.Claims.GranteeKeyVersion, IssuerCredential: req.Claims.IssuerCredentialID,
					GranteeCredential: req.Claims.GranteeCredentialID, Depth: uint8(req.Claims.RemainingDepth), Digest: req.GrantDigest,
					Interval: api.Interval{NBF: req.Claims.NBF, EXP: req.Claims.EXP},
				}
				op, err := a.op("m3-mcp-anc-"+api.Digest([]byte(req.Claims.ID))[:10], req.IssuerActor, "RegisterGrant", chainGrant, "VALID")
				if err != nil {
					return nil, err
				}
				if err := poll(a.ctx, 12*time.Second, func() (bool, error) {
					cur, sErr := sp.AssembleProtocolSnapshot(a.ctx, req.Claims.ID, baseNow)
					return sErr == nil && cur.Snapshot.Height >= op.Commit.Number && cur.Snapshot.Grants[req.Claims.ID].Status == api.Active, nil
				}); err != nil {
					return nil, err
				}
				snapView, err := sp.AssembleProtocolSnapshot(a.ctx, req.Claims.ID, baseNow)
				if err != nil {
					return nil, err
				}
				if _, err := ds.PublishGrantOutbox(a.ctx, snapView.Snapshot, GrantDeliveryPackage{
					DeploymentID: a.d.DeploymentID, Recipient: req.GranteeDID, GrantID: req.Claims.ID, GrantJWS: req.RawGrantJWS,
					TaskSpec: a.f.M2TaskSpec, ServicePresentation: string(a1SD), DomainCertificationJWS: string(certA),
					AncestorGrants: []string{chain.G0JWS, parentJWS},
				}, rootPub, iaPub, &a1Priv.PublicKey, op.TxID, int64(op.Commit.Number), true, time.Now().Unix()); err != nil {
					return nil, err
				}
				if _, _, err := ds.DeliverGrantReceipt(a.ctx, snapView.Snapshot, a.d.DeploymentID, req.GranteeDID, req.Claims.ID, nil, rootPub, iaPub, &a1Priv.PublicKey, time.Now().Unix()); err != nil {
					return nil, err
				}
				return &agent.AnchorChildGrantResult{Anchored: true, TrustPaths: tpRP}, nil
			},
			ReplaceGrantFunc: func(callCtx context.Context, req agent.ReplaceGrantRequest) (*agent.ReplaceGrantResult, error) {
				rev := req.OldGrantRevision
				if rev == 0 {
					rev = 1
				}
				chainNew := api.Grant{
					Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: req.NewClaims.ID, Schema: api.Schema,
					Parent: derefStr(req.NewClaims.ParentID), ParentDigest: derefStr(req.NewClaims.ParentDigest), Root: req.NewClaims.RootID,
					Task: req.NewClaims.TaskID, Mode: req.NewClaims.AuthorizationMode, Domain: req.NewClaims.PrincipalDomain,
					Resource: req.NewClaims.ResourceID, Issuer: req.NewClaims.Issuer, Grantee: req.NewClaims.Grantee,
					IssuerKeyVersion: req.NewClaims.IssuerKeyVersion, GranteeKeyVersion: req.NewClaims.GranteeKeyVersion,
					IssuerCredential: req.NewClaims.IssuerCredentialID, GranteeCredential: req.NewClaims.GranteeCredentialID,
					Depth: uint8(req.NewClaims.RemainingDepth), Digest: req.NewGrantDigest,
					Interval: api.Interval{NBF: req.NewClaims.NBF, EXP: req.NewClaims.EXP},
				}
				op, err := a.op("m3-mcp-rep-"+api.Digest([]byte(req.OldGrantID + req.NewClaims.ID))[:10], req.IssuerActor, "ReplaceGrant", api.Replacement{
					Old: api.Mutation{Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: req.OldGrantID, ExpectedRevision: rev, ExpectedDigest: req.OldGrantDigest},
					New: chainNew,
				}, "VALID")
				if err != nil {
					return nil, err
				}
				if err := poll(a.ctx, 12*time.Second, func() (bool, error) {
					cur, sErr := sp.AssembleProtocolSnapshot(a.ctx, req.NewClaims.ID, baseNow)
					old, oldErr := ledgerRecord[api.Grant](a.ctx, a.p, "grant", req.OldGrantID)
					return sErr == nil && cur.Snapshot.Height >= op.Commit.Number &&
						oldErr == nil && old.Status == api.Revoked &&
						cur.Snapshot.Grants[req.NewClaims.ID].Status == api.Active, nil
				}); err != nil {
					return nil, err
				}
				snapView, err := sp.AssembleProtocolSnapshot(a.ctx, req.NewClaims.ID, baseNow)
				if err != nil {
					return nil, err
				}
				if _, err := ds.PublishGrantOutbox(a.ctx, snapView.Snapshot, GrantDeliveryPackage{
					DeploymentID: a.d.DeploymentID, Recipient: req.NewGranteeDID, GrantID: req.NewClaims.ID, GrantJWS: req.NewRawGrantJWS,
					TaskSpec: a.f.M2TaskSpec, ServicePresentation: string(a1SD), DomainCertificationJWS: string(certA),
					AncestorGrants: []string{chain.G0JWS, parentJWS},
				}, rootPub, iaPub, &a1Priv.PublicKey, op.TxID, int64(op.Commit.Number), true, time.Now().Unix()); err != nil {
					return nil, err
				}
				if _, _, err := ds.DeliverGrantReceipt(a.ctx, snapView.Snapshot, a.d.DeploymentID, req.NewGranteeDID, req.NewClaims.ID, nil, rootPub, iaPub, &a1Priv.PublicKey, time.Now().Unix()); err != nil {
					return nil, err
				}
				return &agent.ReplaceGrantResult{Anchored: true, TrustPaths: tpRP}, nil
			},
		})
		if err != nil {
			return nil, err
		}
		for _, role := range []string{"U", "A1", "B1", "B2"} {
			id, ok := a.f.Identities[role]
			if !ok {
				continue
			}
			priv, err := loadECPrivateKeyPEM(a.instance.privatePath("app", role+".key.pem"))
			if err != nil {
				return nil, err
			}
			sdBytes, err := os.ReadFile(a.instance.registrySubPath("credentials", role+".sdjwt"))
			if err != nil {
				return nil, err
			}
			if err := w.RegisterActor(agent.ActorConfig{
				Actor: role, DID: id.ID, KeyID: id.KeyID, CredentialID: a.f.Credentials[role].ID,
				KeyVersion: id.KeyVersion, DomainID: id.Domain, EntityType: id.Kind,
				Roles: []string{id.Kind}, PrivateKey: priv, SDJWTPresentation: string(sdBytes),
			}); err != nil {
				return nil, err
			}
		}
		parentClaims, err := decodeGrantPayload(parentJWS)
		if err != nil {
			return nil, err
		}
		cCredID := a.f.Credentials["C"].ID
		if cSvc, ok := a.f.Credentials["C-service"]; ok && cSvc.ID != "" {
			cCredID = cSvc.ID
		}
		if err := w.AddGrantBundle(agent.GrantBundle{
			Claims: parentClaims, TaskSpec: a.f.M2TaskSpec, RawGrantJWS: parentJWS,
			Revision: 1, ChainRawGrants: []string{chain.G0JWS, parentJWS},
			AncestorCredentials: []protocol.AncestorCredential{
				{CredentialID: cCredID, Presentation: string(cSvcSD)},
				{CredentialID: a.f.Credentials["U"].ID, Presentation: string(uSD)},
			},
			TrustPaths: tpRP, Anchored: true,
		}); err != nil {
			return nil, err
		}
		return w, nil
	}

	w, err := buildWallet(chain)
	if err != nil {
		return err
	}

	mcpSrv := agent.NewMCPServer(w)
	t1, t2 := mcp.NewInMemoryTransports()
	srvSess, err := mcpSrv.Connect(a.ctx, t1, nil)
	if err != nil {
		return err
	}
	defer srvSess.Close()
	cli := mcp.NewClient(&mcp.Implementation{Name: "m3-e3-driver", Version: "v0.1"}, nil)
	cliSess, err := cli.Connect(a.ctx, t2, nil)
	if err != nil {
		return err
	}
	defer cliSess.Close()

	callMCP := func(name string, args map[string]any, dst any) error {
		res, cErr := cliSess.CallTool(a.ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if cErr != nil {
			return cErr
		}
		if res.IsError {
			raw, _ := json.Marshal(res.Content)
			return fmt.Errorf("MCP %s error: %s", name, raw)
		}
		raw, _ := json.Marshal(res.StructuredContent)
		return json.Unmarshal(raw, dst)
	}

	// Deterministic E3 trajectory on live Fabric + PostgreSQL.
	ordersBefore, err := a.countOrdersForDeployment()
	if err != nil {
		return err
	}
	g2ID := api.Digest([]byte("m3-e3-g2-" + a.id))
	g2PrimeID := api.Digest([]byte("m3-e3-g2p-" + a.id))
	var delOut agent.DelegateGrantOutput
	if err := callMCP("delegate_grant", map[string]any{
		"issuerActor": "A1", "subjectActor": "B1", "parentGrantId": chain.G1.ID, "grantId": g2ID,
		"taskId": chain.Task.ID, "authorizationMode": api.RP, "maxAmountMinor": 100000, "remainingDepth": 0,
	}, &delOut); err != nil {
		return err
	}
	var qB1 agent.RequestQuoteOutput
	if err := callMCP("request_quote", map[string]any{
		"actor": "B1", "grantId": g2ID, "taskId": chain.Task.ID, "authorizationMode": api.RP,
		"productId": "urn:grad:product:P1", "quantity": 1,
	}, &qB1); err != nil || qB1.Decision != "ALLOW" {
		return fmt.Errorf("B1 request_quote failed: %+v err=%v", qB1, err)
	}
	var repOut agent.ReplaceGrantOutput
	if err := callMCP("replace_grant", map[string]any{
		"issuerActor": "A1", "oldGrantId": g2ID, "newSubjectActor": "B2", "newGrantId": g2PrimeID,
		"maxAmountMinor": 100000, "remainingDepth": 0, "reason": "failover B1 -> B2",
	}, &repOut); err != nil || !repOut.Anchored {
		return fmt.Errorf("replace_grant failed: %+v err=%v", repOut, err)
	}
	// S41: B1 reusing old G2 -> 403 GRANT_INACTIVE.
	var s41 agent.CreateOrderOutput
	if err := callMCP("create_order", map[string]any{
		"actor": "B1", "grantId": g2ID, "taskId": chain.Task.ID, "authorizationMode": api.RP,
		"quoteId": qB1.QuoteID, "amountMinor": 80000, "idempotencyKey": "m3-s41-" + a.id[:8],
	}, &s41); err != nil || s41.StatusCode != http.StatusForbidden || s41.ErrorCode != protocol.ErrCodeGrantInactive {
		return fmt.Errorf("S41 expected 403 GRANT_INACTIVE, got %+v err=%v", s41, err)
	}
	// S55: B2 reusing B1 quote Q800 -> 403 QUOTE_SCOPE_MISMATCH.
	var s55 agent.CreateOrderOutput
	if err := callMCP("create_order", map[string]any{
		"actor": "B2", "grantId": g2PrimeID, "taskId": chain.Task.ID, "authorizationMode": api.RP,
		"quoteId": qB1.QuoteID, "amountMinor": 80000, "idempotencyKey": "m3-s55-" + a.id[:8],
	}, &s55); err != nil || s55.StatusCode != http.StatusForbidden || s55.ErrorCode != protocol.ErrCodeQuoteScopeMismatch {
		return fmt.Errorf("S55 expected 403 QUOTE_SCOPE_MISMATCH, got %+v err=%v", s55, err)
	}
	// B2 obtains its own quote and creates exactly one order after replacement.
	var qB2 agent.RequestQuoteOutput
	if err := callMCP("request_quote", map[string]any{
		"actor": "B2", "grantId": g2PrimeID, "taskId": chain.Task.ID, "authorizationMode": api.RP,
		"productId": "urn:grad:product:P1", "quantity": 1,
	}, &qB2); err != nil || qB2.Decision != "ALLOW" {
		return fmt.Errorf("B2 request_quote failed: %+v err=%v", qB2, err)
	}
	var b2Order agent.CreateOrderOutput
	if err := callMCP("create_order", map[string]any{
		"actor": "B2", "grantId": g2PrimeID, "taskId": chain.Task.ID, "authorizationMode": api.RP,
		"quoteId": qB2.QuoteID, "amountMinor": 80000, "idempotencyKey": "m3-e3-b2-" + a.id[:8],
	}, &b2Order); err != nil || b2Order.StatusCode != http.StatusOK || b2Order.OrderID == "" {
		return fmt.Errorf("B2 create_order failed: %+v err=%v", b2Order, err)
	}

	// A separate B1 intent loses its response, then G1 is revoked before retry/reconcile (S63).
	recoveryChain, err := a.provisionEphemeralM3RPChain(rt, sp, "s63-"+a.id[:8], 500000, false, baseNow)
	if err != nil {
		return err
	}
	if _, err := a.ensureTaskContextNormal(srv.Handler(), recoveryChain.Task.ID, baseNow.Unix()); err != nil {
		return err
	}
	recoveryWallet, err := buildWallet(recoveryChain)
	if err != nil {
		return err
	}
	tr1, tr2 := mcp.NewInMemoryTransports()
	recoveryServer, err := agent.NewMCPServer(recoveryWallet).Connect(a.ctx, tr1, nil)
	if err != nil {
		return err
	}
	defer recoveryServer.Close()
	recoveryClient, err := cli.Connect(a.ctx, tr2, nil)
	if err != nil {
		return err
	}
	defer recoveryClient.Close()
	cliSess = recoveryClient
	recoveryG2ID := api.Digest([]byte("m3-s63-g2-" + a.id))
	if err := callMCP("delegate_grant", map[string]any{
		"issuerActor": "A1", "subjectActor": "B1", "parentGrantId": recoveryChain.G1.ID, "grantId": recoveryG2ID,
		"taskId": recoveryChain.Task.ID, "authorizationMode": api.RP, "maxAmountMinor": 100000, "remainingDepth": 0,
	}, &delOut); err != nil {
		return err
	}
	var recoveryQuote agent.RequestQuoteOutput
	if err := callMCP("request_quote", map[string]any{
		"actor": "B1", "grantId": recoveryG2ID, "taskId": recoveryChain.Task.ID, "authorizationMode": api.RP,
		"productId": "urn:grad:product:P1", "quantity": 1,
	}, &recoveryQuote); err != nil || recoveryQuote.Decision != "ALLOW" {
		return fmt.Errorf("S63 B1 quote failed: %+v err=%v", recoveryQuote, err)
	}
	lostKey := "m3-e3-s63-" + a.id[:8]
	dropRT.MarkDropAfter(lostKey)
	var unkOut agent.CreateOrderOutput
	if err := callMCP("create_order", map[string]any{
		"actor": "B1", "grantId": recoveryG2ID, "taskId": recoveryChain.Task.ID, "authorizationMode": api.RP,
		"quoteId": recoveryQuote.QuoteID, "amountMinor": 80000, "idempotencyKey": lostKey,
	}, &unkOut); err != nil || unkOut.ActionStatus != "OUTCOME_UNKNOWN" {
		return fmt.Errorf("expected OUTCOME_UNKNOWN after EOF drop, got %+v err=%v", unkOut, err)
	}
	// Revoke G1 on live Fabric -> adopt block r!
	revG1Op, err := a.op("m3-e3-rev-g1-"+a.id[:8], "U", "RevokeGrant", revokeOf(recoveryChain.G1), "VALID")
	if err != nil {
		return err
	}
	if err := poll(a.ctx, 12*time.Second, func() (bool, error) {
		cur, sErr := sp.AssembleProtocolSnapshot(a.ctx, recoveryG2ID, baseNow)
		return sErr == nil && cur.Snapshot.Height >= revG1Op.Commit.Number && cur.Snapshot.Grants[recoveryChain.G1.ID].Status == api.Revoked, nil
	}); err != nil {
		return fmt.Errorf("wait G1 revocation block %d adoption: %w", revG1Op.Commit.Number, err)
	}
	var retryOut agent.CreateOrderOutput
	if err := callMCP("create_order", map[string]any{
		"actor": "B1", "grantId": recoveryG2ID, "taskId": recoveryChain.Task.ID, "authorizationMode": api.RP,
		"quoteId": recoveryQuote.QuoteID, "amountMinor": 80000, "idempotencyKey": lostKey,
	}, &retryOut); err != nil || retryOut.ErrorCode != protocol.ErrCodeAncestorInactive {
		return fmt.Errorf("S63 B1 retry expected ANCESTOR_INACTIVE: %+v err=%v", retryOut, err)
	}
	// Reconcile lost order!
	var recOut agent.ReconcileOrderOutput
	if err := callMCP("reconcile_order", map[string]any{
		"actor": "B1", "taskId": recoveryChain.Task.ID, "idempotencyKey": lostKey,
	}, &recOut); err != nil || recOut.Outcome != "CREATED" || recOut.HistoricalStatus != "MATCHED" || recOut.OrderID == "" {
		return fmt.Errorf("S63 reconcile_order failed: %+v err=%v", recOut, err)
	}
	ordersAfterDet, _ := a.countOrdersForDeployment()
	if ordersAfterDet != ordersBefore+2 {
		return fmt.Errorf("expected +2 orders across E3 replacement + S63 recovery, before=%d after=%d", ordersBefore, ordersAfterDet)
	}

	// Optional / Live LLM API Trajectory if LLM env (or ANTHROPIC_BASE_URL/TOKEN) is configured!
	var llmTraces []agent.RunResult
	var scrubbedSecrets []string
	for _, r := range []string{"U", "A1", "B1", "B2"} {
		if b, rErr := os.ReadFile(a.instance.registrySubPath("credentials", r+".sdjwt")); rErr == nil {
			scrubbedSecrets = append(scrubbedSecrets, string(b))
		}
	}
	if llmCfg := agent.LoadRunnerConfigFromEnv(); llmCfg.BaseURL != "" && llmCfg.APIKey != "" {
		scrubbedSecrets = append(scrubbedSecrets, llmCfg.APIKey)
		llmTraces, err = a.runM3LLMTrajectories(rt, sp, srv.Handler(), buildWallet, dropRT, baseNow, llmCfg)
		if err != nil {
			return err
		}
		ordersAfterLLM, err := a.countOrdersForDeployment()
		if err != nil || ordersAfterLLM != ordersAfterDet+2 {
			return fmt.Errorf("expected exactly two LLM-driven orders: before=%d after=%d err=%v", ordersAfterDet, ordersAfterLLM, err)
		}
	}

	detSummary := map[string]any{
		"replaceGrantId":    g2PrimeID,
		"revokedOldGrantId": g2ID,
		"s41StatusCode":     s41.StatusCode,
		"s41ErrorCode":      s41.ErrorCode,
		"s55StatusCode":     s55.StatusCode,
		"s55ErrorCode":      s55.ErrorCode,
		"s63Reconcile":      recOut,
		"s63Retry":          retryOut,
		"b2Order":           b2Order,
		"ordersAdded":       ordersAfterDet - ordersBefore,
	}
	payload := map[string]any{
		"deterministicTrajectory": detSummary,
		"llmTrajectories":         llmTraces,
	}
	return a.recordM3Evidence("m3-agent-traces.json", payload, func(ev *m3EvidenceReport) {
		ev.AgentDeterministic = detSummary
		ev.AgentTraces = llmTraces
	}, scrubbedSecrets...)
}

func (a acceptance) m3RevocationWindowE6() error {
	rt := newRuntime(a)
	// Capture application events before submission; a later head query can race adoption.
	var appliedMu sync.Mutex
	appliedAt := map[uint64]time.Time{}
	rt.observe = func(event string, details any) {
		if event == "block_applied" {
			if p, ok := details.(point); ok {
				appliedMu.Lock()
				if _, exists := appliedAt[p.Number]; !exists {
					appliedAt[p.Number] = time.Now().UTC()
				}
				appliedMu.Unlock()
			}
		}
		a.log.event(event, details)
	}

	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()

	baseNow := time.Now().UTC().Truncate(time.Second)
	sp := NewStateProvider(a.j.db, a.d, rt)
	chain, err := a.provisionEphemeralM3RPChain(rt, sp, "e6-"+a.id[:8], 500000, true, baseNow)
	if err != nil {
		return err
	}
	didSrv, resolver, err := a.newControlledDIDResolver()
	if err != nil {
		return err
	}
	defer didSrv.Close()
	_ = resolver
	srv, _, err := a.newDirectAccessServer(sp, resolver, nil, func() time.Time { return time.Now().UTC() })
	if err != nil {
		return err
	}
	if _, err := a.ensureTaskContextNormal(srv.Handler(), chain.Task.ID, baseNow.Unix()); err != nil {
		return err
	}
	_, _, _, _, _, _, _, b1Priv, b1SD, cSvcSD, _, _, certC, certA, err := a.loadM2RoleMaterials()
	if err != nil {
		return err
	}
	uSD, err := os.ReadFile(a.instance.registrySubPath("credentials", "U.sdjwt"))
	if err != nil {
		return err
	}
	a1SD, err := os.ReadFile(a.instance.registrySubPath("credentials", "A1.sdjwt"))
	if err != nil {
		return err
	}
	certB, err := os.ReadFile(a.instance.registrySubPath("certifications", "B.jws"))
	if err != nil {
		return err
	}
	tpRP := []protocol.TrustPathEntry{
		{Issuer: a.f.Domains["A"].Issuers[0].ID, DomainCertification: string(certA)},
		{Issuer: a.f.Domains["B"].Issuers[0].ID, DomainCertification: string(certB)},
		{Issuer: a.f.Domains["C"].Issuers[0].ID, DomainCertification: string(certC)},
	}
	cCredID := a.f.Credentials["C"].ID
	if cSvc, ok := a.f.Credentials["C-service"]; ok && cSvc.ID != "" {
		cCredID = cSvc.ID
	}
	anc := []protocol.AncestorCredential{
		{CredentialID: cCredID, Presentation: string(cSvcSD)},
		{CredentialID: a.f.Credentials["U"].ID, Presentation: string(uSD)},
		{CredentialID: a.f.Credentials["A1"].ID, Presentation: string(a1SD)},
	}
	grants := []string{chain.G0JWS, chain.G1JWS, chain.G2JWS}

	// Obtain valid Q800 for B1 and run 1 warmup order.
	qReq := protocol.AccessRequest{
		SchemaVersion: api.Schema, DeploymentID: a.d.DeploymentID, Actor: a.f.Identities["B1"].ID,
		PrincipalDomain: "A", AuthorizationMode: api.RP, TaskID: chain.Task.ID, Audience: "https://c.local",
		Resource: "urn:grad:resource:C:quotes", Action: "quote.read", SupplierID: "urn:grad:supplier:C",
		ProductID: "urn:grad:product:P1", Quantity: 1, Currency: "CNY", AmountMinor: 0, IdempotencyKey: "e6-q-" + a.id[:8],
	}
	qPkg, _, err := a.buildLeafExecutePackage(srv.Handler(), qReq, a.f.M2TaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD), anc, grants, tpRP, time.Now().UTC().Unix())
	if err != nil {
		return err
	}
	qRec := gatewayPostExecute(srv.Handler(), qPkg)
	if qRec.Code != http.StatusOK {
		return fmt.Errorf("E6 quote failed: %d %s", qRec.Code, qRec.Body.String())
	}
	var qResp gateway.ExecuteResponse
	_ = json.Unmarshal(qRec.Body.Bytes(), &qResp)

	warmReq := protocol.AccessRequest{
		SchemaVersion: api.Schema, DeploymentID: a.d.DeploymentID, Actor: a.f.Identities["B1"].ID,
		PrincipalDomain: "A", AuthorizationMode: api.RP, TaskID: chain.Task.ID, Audience: "https://c.local",
		Resource: "urn:grad:resource:C:orders", Action: "order.create", SupplierID: "urn:grad:supplier:C",
		QuoteID: &qResp.Quote.QuoteID, ProductID: "urn:grad:product:P1", Quantity: 1, Currency: "CNY", AmountMinor: 80000,
		IdempotencyKey: "e6-warm-" + a.id[:8],
	}
	warmPkg, _, err := a.buildLeafExecutePackage(srv.Handler(), warmReq, a.f.M2TaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD), anc, grants, tpRP, time.Now().UTC().Unix())
	if err != nil {
		return err
	}
	if rec := gatewayPostExecute(srv.Handler(), warmPkg); rec.Code != http.StatusOK {
		return fmt.Errorf("E6 warmup order failed: %d %s", rec.Code, rec.Body.String())
	}

	// Probe every 20 ms while U submits RevokeGrant(G1).
	type e6Sample struct {
		Seq           int    `json:"seq"`
		SubmittedAt   int64  `json:"submittedAtUnixMs"`
		RespondedAt   int64  `json:"respondedAtUnixMs"`
		StatusCode    int    `json:"statusCode"`
		ErrorCode     string `json:"errorCode,omitempty"`
		Decision      string `json:"decision,omitempty"`
		DecisionBlock uint64 `json:"decisionBlock,omitempty"`
		DecisionAt    int64  `json:"decisionAtUnixSec,omitempty"`
		ProbeDeadline int64  `json:"probeDeadlineUnixSec,omitempty"`
	}
	var samples []e6Sample
	var samplesMu sync.Mutex
	stopProbe := make(chan struct{})
	probeDone := make(chan struct{})
	go func() {
		defer close(probeDone)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		seq := 0
		for {
			select {
			case <-stopProbe:
				return
			case <-a.ctx.Done():
				return
			case <-ticker.C:
				seq++
				snapBefore, _ := sp.AssembleProtocolSnapshot(a.ctx, chain.G2.ID, time.Now().UTC())
				req := warmReq
				req.IdempotencyKey = fmt.Sprintf("e6-p-%s-%04d", a.id[:6], seq)
				pkg, _, bErr := a.buildLeafExecutePackage(srv.Handler(), req, a.f.M2TaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD), anc, grants, tpRP, time.Now().UTC().Unix())
				if bErr != nil {
					continue
				}
				subAt := time.Now().UTC()
				rec := gatewayPostExecute(srv.Handler(), pkg)
				respAt := time.Now().UTC()
				var execResp gateway.ExecuteResponse
				_ = json.Unmarshal(rec.Body.Bytes(), &execResp)
				errCode := ""
				if rec.Code != http.StatusOK {
					var errEnv gateway.ErrorBody
					_ = json.Unmarshal(rec.Body.Bytes(), &errEnv)
					errCode = errEnv.Code
				}
				var pDead int64
				if snapBefore != nil && !snapBefore.Probe.Deadline.IsZero() {
					pDead = snapBefore.Probe.Deadline.Unix()
				}
				var decOutcome string
				var decBlock uint64
				var decAt, decProbeDead int64
				if execResp.DecisionID != "" {
					if qErr := a.j.db.QueryRow(a.ctx,
						`SELECT outcome, block_number, decision_at, probe_deadline FROM decisions WHERE deployment_id=$1 AND decision_id=$2`,
						a.d.DeploymentID, execResp.DecisionID,
					).Scan(&decOutcome, &decBlock, &decAt, &decProbeDead); qErr == nil && decProbeDead > 0 {
						pDead = decProbeDead
					}
				} else {
					if qErr := a.j.db.QueryRow(a.ctx,
						`SELECT outcome, block_number, decision_at, probe_deadline FROM decisions WHERE deployment_id=$1 AND idempotency_key=$2 ORDER BY decision_at DESC LIMIT 1`,
						a.d.DeploymentID, req.IdempotencyKey,
					).Scan(&decOutcome, &decBlock, &decAt, &decProbeDead); qErr == nil && decProbeDead > 0 {
						pDead = decProbeDead
					}
				}
				samplesMu.Lock()
				samples = append(samples, e6Sample{
					Seq: seq, SubmittedAt: subAt.UnixMilli(), RespondedAt: respAt.UnixMilli(),
					StatusCode: rec.Code, ErrorCode: errCode, Decision: decOutcome,
					DecisionBlock: decBlock, DecisionAt: decAt, ProbeDeadline: pDead,
				})
				samplesMu.Unlock()
			}
		}
	}()

	time.Sleep(120 * time.Millisecond)
	tSubmit := time.Now().UTC()
	revOp, revErr := a.op("m3-e6-rev-g1-"+a.id[:8], "U", "RevokeGrant", revokeOf(chain.G1), "VALID")
	tValid := time.Now().UTC()
	if revErr != nil {
		close(stopProbe)
		<-probeDone
		return revErr
	}
	revBlock := revOp.Commit.Number
	var tApply, tAdopt time.Time
	if err := poll(a.ctx, 12*time.Second, func() (bool, error) {
		appliedMu.Lock()
		tApply = appliedAt[revBlock]
		appliedMu.Unlock()
		cur, sErr := sp.AssembleProtocolSnapshot(a.ctx, chain.G2.ID, time.Now().UTC())
		if !tApply.IsZero() && sErr == nil && cur.Snapshot.Height >= revBlock && cur.Snapshot.Grants[chain.G1.ID].Status == api.Revoked {
			tAdopt = time.Now().UTC()
			return true, nil
		}
		return false, nil
	}); err != nil {
		close(stopProbe)
		<-probeDone
		return fmt.Errorf("wait E6 adoption of r=%d: %w", revBlock, err)
	}
	time.Sleep(300 * time.Millisecond)
	close(stopProbe)
	<-probeDone

	samplesMu.Lock()
	defer samplesMu.Unlock()
	var tLastAllowMs, tFirstDenyMs int64
	var allowCount, denyCount int
	for _, s := range samples {
		if s.StatusCode == http.StatusOK && s.Decision == "ALLOW" {
			allowCount++
			if s.DecisionBlock >= revBlock {
				return fmt.Errorf("E6 violation: allowed order on block %d >= revocation block %d (seq=%d)", s.DecisionBlock, revBlock, s.Seq)
			}
			if s.ProbeDeadline > 0 && s.DecisionAt >= s.ProbeDeadline {
				return fmt.Errorf("E6 violation: allowed order at %d >= probeDeadline %d (seq=%d)", s.DecisionAt, s.ProbeDeadline, s.Seq)
			}
			if s.RespondedAt > tLastAllowMs {
				tLastAllowMs = s.RespondedAt
			}
		} else if s.StatusCode == http.StatusForbidden {
			denyCount++
			if tFirstDenyMs == 0 {
				tFirstDenyMs = s.RespondedAt
			}
		}
	}
	if denyCount == 0 || allowCount == 0 {
		return fmt.Errorf("E6 requires both allowed and denied samples (allows=%d, denies=%d)", allowCount, denyCount)
	}
	windowAfterValidMs := int64(0)
	if tLastAllowMs > tValid.UnixMilli() {
		windowAfterValidMs = tLastAllowMs - tValid.UnixMilli()
	}
	if windowAfterValidMs > api.ProbeLifetime.Milliseconds() {
		return fmt.Errorf("E6 revocation window after VALID (%d ms) exceeded deltaState (%d ms)", windowAfterValidMs, api.ProbeLifetime.Milliseconds())
	}

	e6Payload := map[string]any{
		"revokedGrantId":     chain.G1.ID,
		"revocationBlockR":   revBlock,
		"revocationTxId":     revOp.TxID,
		"tSubmitUnixMs":      tSubmit.UnixMilli(),
		"tValidUnixMs":       tValid.UnixMilli(),
		"tApplyUnixMs":       tApply.UnixMilli(),
		"tAdoptUnixMs":       tAdopt.UnixMilli(),
		"tLastAllowUnixMs":   tLastAllowMs,
		"tFirstDenyUnixMs":   tFirstDenyMs,
		"windowAfterValidMs": windowAfterValidMs,
		"deltaStateMs":       api.ProbeLifetime.Milliseconds(),
		"probeIntervalMs":    20,
		"totalProbes":        len(samples),
		"allowCount":         allowCount,
		"denyCount":          denyCount,
		"samples":            samples,
	}
	return a.recordM3Evidence("m3-e6-revocation-window.json", e6Payload, func(ev *m3EvidenceReport) {
		ev.RevocationWindowE6 = e6Payload
	})
}

func (a acceptance) m3FaultInjectionE7() error {
	rt := newRuntime(a)
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()

	baseNow := time.Now().UTC().Truncate(time.Second)
	sp := NewStateProvider(a.j.db, a.d, rt)
	chain, err := a.provisionEphemeralM3RPChain(rt, sp, "e7-"+a.id[:8], 500000, true, baseNow)
	if err != nil {
		return err
	}
	didSrv, resolver, err := a.newControlledDIDResolver()
	if err != nil {
		return err
	}
	defer didSrv.Close()
	_ = resolver

	// 1. Orderer unbroadcast tx hold -> PENDING -> recovery VALID.
	gHold := a.cloneGrant("m3-e7-hold-" + a.id[:8])
	holdOp, err := a.prepared("m3-e7-hold-"+a.id[:8], "U", "RegisterGrant", gHold)
	if err != nil {
		return err
	}
	if err := a.absent("grant", gHold.ID); err != nil {
		return err
	}
	if _, err := a.finish(holdOp, "VALID"); err != nil {
		return err
	}

	// 2. Post-lock risk escalation (S91) & S66 concurrent challenge expiry barrier on live PostgreSQL + gateway.Server.
	_, _, _, _, _, _, _, b1Priv, b1SD, cSvcSD, _, _, certC, certA, err := a.loadM2RoleMaterials()
	if err != nil {
		return err
	}
	uSD, _ := os.ReadFile(a.instance.registrySubPath("credentials", "U.sdjwt"))
	a1SD, _ := os.ReadFile(a.instance.registrySubPath("credentials", "A1.sdjwt"))
	certB, _ := os.ReadFile(a.instance.registrySubPath("certifications", "B.jws"))
	tpRP := []protocol.TrustPathEntry{
		{Issuer: a.f.Domains["A"].Issuers[0].ID, DomainCertification: string(certA)},
		{Issuer: a.f.Domains["B"].Issuers[0].ID, DomainCertification: string(certB)},
		{Issuer: a.f.Domains["C"].Issuers[0].ID, DomainCertification: string(certC)},
	}
	cCredID := a.f.Credentials["C"].ID
	if cSvc, ok := a.f.Credentials["C-service"]; ok && cSvc.ID != "" {
		cCredID = cSvc.ID
	}
	anc := []protocol.AncestorCredential{
		{CredentialID: cCredID, Presentation: string(cSvcSD)},
		{CredentialID: a.f.Credentials["U"].ID, Presentation: string(uSD)},
		{CredentialID: a.f.Credentials["A1"].ID, Presentation: string(a1SD)},
	}
	grants := []string{chain.G0JWS, chain.G1JWS, chain.G2JWS}

	var curClock atomic.Int64
	curClock.Store(baseNow.Unix())
	cDID := a.f.Identities["C"].ID
	polExp := baseNow.Add(4 * time.Hour).Unix()
	files, polDig, _ := policy.BuildDefaultBundle(a.d.DeploymentID, cDID, policy.DefaultPolicyVersion, a.d.Bootstrap.Root, &polExp)
	bundle, _ := policy.VerifyAndLoadBundle(files, a.d.DeploymentID, cDID, a.d.Bootstrap.Root, polDig)
	if err := gateway.EnsureSchema(a.ctx, a.j.db, a.d.DeploymentID, "urn:grad:supplier:C"); err != nil {
		return err
	}
	_, _ = a.j.db.Exec(a.ctx, `UPDATE catalog_prices SET unit_price_minor=80000 WHERE deployment_id=$1 AND product_id=$2`,
		a.d.DeploymentID, gateway.DefaultProductID)

	var riskHookCalled atomic.Bool
	var srvPtr *gateway.Server
	srvS91, err := gateway.NewServer(gateway.Config{
		DB: a.j.db, State: sp.GatewayAdapter(), Delivery: NewDeliveryService(a.j.db), DIDs: resolver,
		Policy: bundle, PolicyArchive: map[string]*policy.VerifiedBundle{bundle.PolicyDigest: bundle},
		AuditorDIDs: []string{"did:web:c.local:auditors:c1"}, VerifierID: "did:web:c.local:auditors:c1",
		DeploymentID: a.d.DeploymentID, ServiceDID: cDID, Audience: "https://c.local", SupplierID: "urn:grad:supplier:C",
		NowFn: func() time.Time { return time.Unix(curClock.Load(), 0).UTC() },
		BeforeLockTx: func(int) {
			if riskHookCalled.CompareAndSwap(false, true) && srvPtr != nil {
				var curVer int64
				_ = a.j.db.QueryRow(context.Background(), `SELECT COALESCE(MAX(context_version),0) FROM trusted_contexts WHERE deployment_id=$1 AND task_id=$2`,
					a.d.DeploymentID, chain.Task.ID).Scan(&curVer)
				_, _ = gatewaySetContext(srvPtr.Handler(), chain.Task.ID, curVer, curClock.Load(), "BLOCKED", a.f.RPTask.Interval.EXP)
			}
		},
	})
	if err != nil {
		return err
	}
	srvPtr = srvS91
	if _, err := a.ensureTaskContextNormal(srvS91.Handler(), chain.Task.ID, baseNow.Unix()); err != nil {
		return err
	}
	qReq := protocol.AccessRequest{
		SchemaVersion: api.Schema, DeploymentID: a.d.DeploymentID, Actor: a.f.Identities["B1"].ID,
		PrincipalDomain: "A", AuthorizationMode: api.RP, TaskID: chain.Task.ID, Audience: "https://c.local",
		Resource: "urn:grad:resource:C:quotes", Action: "quote.read", SupplierID: "urn:grad:supplier:C",
		ProductID: "urn:grad:product:P1", Quantity: 1, Currency: "CNY", AmountMinor: 0, IdempotencyKey: "e7-q-" + a.id[:8],
	}
	// Disable hook temporarily to get Q800, then enable BeforeLockTx S91 escalation for order.create.
	riskHookCalled.Store(true)
	qPkg, _, err := a.buildLeafExecutePackage(srvS91.Handler(), qReq, a.f.M2TaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD), anc, grants, tpRP, curClock.Load())
	if err != nil {
		return err
	}
	qRec := gatewayPostExecute(srvS91.Handler(), qPkg)
	if qRec.Code != http.StatusOK {
		return fmt.Errorf("E7 quote failed: %d %s", qRec.Code, qRec.Body.String())
	}
	var qResp gateway.ExecuteResponse
	_ = json.Unmarshal(qRec.Body.Bytes(), &qResp)

	ordersBefore, _ := a.countOrdersForDeployment()
	riskHookCalled.Store(false)
	ordS91 := protocol.AccessRequest{
		SchemaVersion: api.Schema, DeploymentID: a.d.DeploymentID, Actor: a.f.Identities["B1"].ID,
		PrincipalDomain: "A", AuthorizationMode: api.RP, TaskID: chain.Task.ID, Audience: "https://c.local",
		Resource: "urn:grad:resource:C:orders", Action: "order.create", SupplierID: "urn:grad:supplier:C",
		QuoteID: &qResp.Quote.QuoteID, ProductID: "urn:grad:product:P1", Quantity: 1, Currency: "CNY", AmountMinor: 80000,
		IdempotencyKey: "e7-s91-" + a.id[:8],
	}
	pkgS91, _, err := a.buildLeafExecutePackage(srvS91.Handler(), ordS91, a.f.M2TaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD), anc, grants, tpRP, curClock.Load())
	if err != nil {
		return err
	}
	recS91 := gatewayPostExecute(srvS91.Handler(), pkgS91)
	if recS91.Code != http.StatusForbidden || !strings.Contains(recS91.Body.String(), protocol.ErrCodePolicyDenied) {
		return fmt.Errorf("S91 expected 403 POLICY_DENIED on post-lock BLOCKED escalation, got %d %s", recS91.Code, recS91.Body.String())
	}
	// Restore NORMAL context for S66 concurrent challenge expiry test.
	var verNow int64
	_ = a.j.db.QueryRow(a.ctx, `SELECT COALESCE(MAX(context_version),0) FROM trusted_contexts WHERE deployment_id=$1 AND task_id=$2`, a.d.DeploymentID, chain.Task.ID).Scan(&verNow)
	if _, err := gatewaySetContext(srvS91.Handler(), chain.Task.ID, verNow, curClock.Load(), "NORMAL", a.f.RPTask.Interval.EXP); err != nil {
		return err
	}

	// 3. S66 concurrent challenge expiry barrier: worker 1 holds business lock until worker 2's challenge expires!
	w1Entered := make(chan struct{})
	releaseW1 := make(chan struct{})
	var releaseOnce, enterOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseW1) }) }
	defer release()
	barrierCtx, cancelBarrier := context.WithTimeout(a.ctx, 45*time.Second)
	defer cancelBarrier()
	srvS66, err := gateway.NewServer(gateway.Config{
		DB: a.j.db, State: sp.GatewayAdapter(), Delivery: NewDeliveryService(a.j.db), DIDs: resolver,
		Policy: bundle, DeploymentID: a.d.DeploymentID, ServiceDID: cDID, Audience: "https://c.local", SupplierID: "urn:grad:supplier:C",
		NowFn: time.Now,
		BeforeLockHead: func(int) {
			enterOnce.Do(func() {
				close(w1Entered)
				select {
				case <-releaseW1:
				case <-barrierCtx.Done():
				}
			})
		},
	})
	if err != nil {
		return err
	}
	sharedOrd := ordS91
	sharedOrd.IdempotencyKey = "e7-s66-" + a.id[:8]
	// Issue the losing challenge first so only that challenge expires while it waits.
	pkg2, ch2, err := a.buildLeafExecutePackage(srvS66.Handler(), sharedOrd, a.f.M2TaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD), anc, grants, tpRP, time.Now().Unix())
	if err != nil {
		return err
	}
	select {
	case <-time.After(2 * time.Second):
	case <-barrierCtx.Done():
		return barrierCtx.Err()
	}
	pkg1, ch1, err := a.buildLeafExecutePackage(srvS66.Handler(), sharedOrd, a.f.M2TaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD), anc, grants, tpRP, time.Now().Unix())
	if err != nil {
		return err
	}
	post := func(pkg protocol.AccessEvidencePackage) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(pkg)
		req := httptest.NewRequest(http.MethodPost, "/v1/access/execute", bytes.NewReader(raw)).WithContext(barrierCtx)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srvS66.Handler().ServeHTTP(rec, req)
		return rec
	}

	rec1Ch := make(chan *httptest.ResponseRecorder, 1)
	go func() { rec1Ch <- post(pkg1) }()
	select {
	case <-w1Entered:
	case r := <-rec1Ch:
		return fmt.Errorf("S66 winner failed before barrier: %d %s", r.Code, r.Body.String())
	case <-barrierCtx.Done():
		return barrierCtx.Err()
	}
	rec2Ch := make(chan *httptest.ResponseRecorder, 1)
	go func() { rec2Ch <- post(pkg2) }()

	// Wait until worker 2 blocks on PostgreSQL lock, then expire ch2 and release worker 1!
	if err := poll(barrierCtx, 5*time.Second, func() (bool, error) {
		var waits int
		if qErr := a.j.db.QueryRow(a.ctx, `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock'`).Scan(&waits); qErr == nil && waits > 0 {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return fmt.Errorf("S66 second request did not reach database lock: %w", err)
	}
	// Let the real challenge deadline pass while the live runtime keeps issuing probes.
	select {
	case <-time.After(time.Until(time.Unix(ch2.ExpiresAt, 0))):
	case <-barrierCtx.Done():
		return barrierCtx.Err()
	}
	release()
	r1 := <-rec1Ch
	r2 := <-rec2Ch
	if r1.Code != http.StatusOK || r2.Code != http.StatusUnauthorized {
		return fmt.Errorf("S66 expected w1=200 & w2=401 expired, got w1=%d(%s) w2=%d(%s)", r1.Code, r1.Body.String(), r2.Code, r2.Body.String())
	}
	var ch2Consumed *int64
	if err := a.j.db.QueryRow(a.ctx, `SELECT consumed_at FROM challenges WHERE deployment_id=$1 AND challenge_id=$2`, a.d.DeploymentID, ch2.ChallengeID).Scan(&ch2Consumed); err != nil {
		return err
	}
	if ch2Consumed != nil {
		return fmt.Errorf("S66 expired challenge %s was unexpectedly consumed", ch2.ChallengeID)
	}
	ordersAfter, _ := a.countOrdersForDeployment()
	if ordersAfter != ordersBefore+1 {
		return fmt.Errorf("expected +1 order across S91 deny + S66 concurrent execution, before=%d after=%d", ordersBefore, ordersAfter)
	}

	e7Payload := map[string]any{
		"preparedHoldTxId":   holdOp.TxID,
		"s91PostLockStatus":  recS91.Code,
		"s66WinnerStatus":    r1.Code,
		"s66ExpiredStatus":   r2.Code,
		"s66ExpiredConsumed": ch2Consumed != nil,
		"s66WinnerExpiresAt": ch1.ExpiresAt,
		"s66ExpiredAt":       ch2.ExpiresAt,
		"ordersAdded":        ordersAfter - ordersBefore,
		"networkFaultCases":  []string{"sorter-and-peer-failures", "chaincode-outage-and-recovery", "restart-keeps-checkpoint"},
	}
	return a.recordM3Evidence("m3-e7-fault-injection.json", e7Payload, func(ev *m3EvidenceReport) {
		ev.FaultInjectionE7 = e7Payload
	})
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
