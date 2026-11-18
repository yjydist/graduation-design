package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	api "graduation-design/internal/fabricapi"

	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type memStub struct {
	shim.ChaincodeStubInterface
	channel string
	txID    string
	txAt    time.Time
	creator []byte
	state   map[string][]byte
}

func (m *memStub) GetChannelID() string { return m.channel }
func (m *memStub) GetTxID() string      { return m.txID }
func (m *memStub) GetTxTimestamp() (*timestamppb.Timestamp, error) {
	return timestamppb.New(m.txAt), nil
}
func (m *memStub) GetCreator() ([]byte, error) { return m.creator, nil }
func (m *memStub) GetState(key string) ([]byte, error) {
	v, ok := m.state[key]
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), v...), nil
}
func (m *memStub) PutState(key string, val []byte) error {
	m.state[key] = append([]byte(nil), val...)
	return nil
}
func (m *memStub) DelState(key string) error {
	delete(m.state, key)
	return nil
}

func makeSerializedCaller(t *testing.T, mspID, cn string) ([]byte, api.Management) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	sid, err := proto.Marshal(&msp.SerializedIdentity{
		Mspid:   mspID,
		IdBytes: certPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sid, api.Management{MSPID: mspID, Fingerprint: api.Digest(der)}
}

func makeAppKey(t *testing.T, subject string) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)
	pubHex := hex.EncodeToString(raw)
	return subject + "#key-1", pubHex
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type registryHarness struct {
	stub       *memStub
	now        time.Time
	depID      string
	tCreator   []byte
	aAdmin     []byte
	aReg       []byte
	aRegMgmt   api.Management
	aIA        []byte
	aU         []byte
	aA1        []byte
	aPA        []byte
	bAdmin     []byte
	bReg       []byte
	bIB        []byte
	bB1        []byte
	bUinB      []byte
	cAdmin     []byte
	cReg       []byte
	cIC        []byte
	cSvc       []byte
	uMgmt      api.Management
	paMgmt     api.Management
	uInBMgmt   api.Management
	uCommit    string
	uInBCommit string
}

func newRegistryHarness(t *testing.T) *registryHarness {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	initCreator, initMgmt := makeSerializedCaller(t, "AMsp", "init")
	tCreator, tMgmt := makeSerializedCaller(t, "TMsp", "t-root")
	_, p1Mgmt := makeSerializedCaller(t, "CMsp", "probe-1")
	_, p2Mgmt := makeSerializedCaller(t, "CMsp", "probe-2")

	aAdmin, aAdminMgmt := makeSerializedCaller(t, "AMsp", "admin-a")
	aReg, aRegMgmt := makeSerializedCaller(t, "AMsp", "reg-a")
	aIA, aIAMgmt := makeSerializedCaller(t, "AMsp", "ia")
	aU, aUMgmt := makeSerializedCaller(t, "AMsp", "u")
	aA1, aA1Mgmt := makeSerializedCaller(t, "AMsp", "a1")
	aPA, aPAMgmt := makeSerializedCaller(t, "AMsp", "pa")

	bAdmin, bAdminMgmt := makeSerializedCaller(t, "BMsp", "admin-b")
	bReg, bRegMgmt := makeSerializedCaller(t, "BMsp", "reg-b")
	bIB, bIBMgmt := makeSerializedCaller(t, "BMsp", "ib")
	bB1, bB1Mgmt := makeSerializedCaller(t, "BMsp", "b1")
	bUinB, bUinBMgmt := makeSerializedCaller(t, "BMsp", "u-in-b")

	cAdmin, cAdminMgmt := makeSerializedCaller(t, "CMsp", "admin-c")
	cReg, cRegMgmt := makeSerializedCaller(t, "CMsp", "reg-c")
	cIC, cICMgmt := makeSerializedCaller(t, "CMsp", "ic")
	cSvc, cSvcMgmt := makeSerializedCaller(t, "CMsp", "c-svc")

	tKeyID, tPub := makeAppKey(t, "did:web:t.local")
	boot := api.Bootstrap{
		DeploymentFields: api.DeploymentFields{
			ChannelID:     api.Channel,
			GenesisHash:   api.Digest([]byte("genesis-test")),
			InstanceID:    api.Digest([]byte("instance-test")),
			RegistryName:  api.Registry,
			SchemaVersion: api.Schema,
		},
		Root: api.RootRecord{
			DID:            "did:web:t.local",
			Management:     tMgmt,
			DocumentDigest: api.Digest([]byte("t-doc")),
			KeyID:          tKeyID,
			KeyVersion:     1,
			PublicKey:      tPub,
		},
		Initializer: initMgmt,
		TaskCreator: api.TaskAuthority{
			Domain:     "A",
			Subject:    "did:web:a.local:u",
			Management: aUMgmt,
		},
		ResourceID:         api.Digest([]byte("resource:c")),
		ResourceOwner:      "did:web:c.local:supplier",
		ResourceManagement: cSvcMgmt,
	}
	bootRaw := mustJSON(t, boot)

	// Bind package globals required by main.go/identity.go.
	bootstrapDigest = api.Digest(bootRaw)
	initializer = initMgmt.String()
	probeOne = p1Mgmt.String()
	probeTwo = p2Mgmt.String()

	stub := &memStub{
		channel: api.Channel,
		txID:    "tx-init",
		txAt:    now,
		creator: initCreator,
		state:   map[string][]byte{},
	}
	if _, err := invoke(stub, "Initialize", bootRaw); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	depID := boot.ID()
	nbf := now.Add(-time.Hour).Unix()
	exp := now.Add(24 * time.Hour).Unix()

	mkID := func(id, dom, kind string, mgmt api.Management) api.Identity {
		kid, pub := makeAppKey(t, id)
		return api.Identity{
			Bound:             api.Bound{DeploymentID: depID},
			ID:                id,
			Domain:            dom,
			Kind:              kind,
			Management:        mgmt,
			DocumentDigest:    api.Digest([]byte("doc:" + id)),
			KeyID:             kid,
			KeyVersion:        1,
			PublicKey:         pub,
			AccountCommitment: api.Digest([]byte("acct:" + id)),
		}
	}

	// Bootstrap domains A, B, C and certify them via T.
	for _, item := range []struct {
		id, did, issuerDID string
		admin, reg         []byte
		adminMgmt, regMgmt api.Management
		issuerMgmt         api.Management
	}{
		{"A", "did:web:a.local", "did:web:a.local:ia", aAdmin, aReg, aAdminMgmt, aRegMgmt, aIAMgmt},
		{"B", "did:web:b.local", "did:web:b.local:ib", bAdmin, bReg, bAdminMgmt, bRegMgmt, bIBMgmt},
		{"C", "did:web:c.local", "did:web:c.local:ic", cAdmin, cReg, cAdminMgmt, cRegMgmt, cICMgmt},
	} {
		domBoot := api.DomainBootstrap{
			Domain: api.Domain{
				Bound:     api.Bound{DeploymentID: depID},
				ID:        item.id,
				DID:       item.did,
				Admin:     item.adminMgmt,
				Registrar: item.regMgmt,
			},
			Identity: mkID(item.did, item.id, "DOMAIN", item.adminMgmt),
			Issuers:  []api.Identity{mkID(item.issuerDID, item.id, "ISSUER", item.issuerMgmt)},
		}
		stub.creator = tCreator
		if _, err := invoke(stub, "BootstrapDomain", mustJSON(t, domBoot)); err != nil {
			t.Fatalf("BootstrapDomain %s: %v", item.id, err)
		}
		cert := api.Certify{
			Certification: api.Certification{
				Bound:          api.Bound{DeploymentID: depID},
				ID:             "urn:grad:cert:" + item.id,
				Domain:         item.id,
				RootKeyVersion: 1,
				Digest:         api.Digest([]byte("cert:" + item.id)),
				Scopes: []api.Scope{{
					ID:         item.issuerDID,
					KeyVersion: 1,
					Types:      []string{"EnterpriseIdentityCredential"},
					Claims:     []string{"domain", "role"},
				}},
				Interval: api.Interval{NBF: nbf, EXP: exp},
			},
			ExpectedRevision: 1,
		}
		if _, err := invoke(stub, "CertifyDomain", mustJSON(t, cert)); err != nil {
			t.Fatalf("CertifyDomain %s: %v", item.id, err)
		}
	}

	// Register identities & credentials.
	uID := mkID("did:web:a.local:u", "A", "USER", aUMgmt)
	uInBID := mkID("did:web:b.local:u-in-b", "B", "USER", bUinBMgmt)
	paID := mkID("did:web:a.local:pa", "A", "SERVICE", aPAMgmt)
	a1ID := mkID("did:web:a.local:a1", "A", "AGENT", aA1Mgmt)
	b1ID := mkID("did:web:b.local:b1", "B", "AGENT", bB1Mgmt)
	cSvcID := mkID("did:web:c.local:supplier", "C", "SERVICE", cSvcMgmt)

	regEntity := func(regCaller, issCaller []byte, id api.Identity, issuerDID, credID string) {
		stub.creator = regCaller
		if _, err := invoke(stub, "RegisterIdentity", mustJSON(t, id)); err != nil {
			t.Fatalf("RegisterIdentity %s: %v", id.ID, err)
		}
		stub.creator = issCaller
		cred := api.Credential{
			Bound:             api.Bound{DeploymentID: depID},
			ID:                credID,
			Issuer:            issuerDID,
			Subject:           id.ID,
			IssuerKeyVersion:  1,
			SubjectKeyVersion: 1,
			Type:              "EnterpriseIdentityCredential",
			ClaimNames:        []string{"domain", "role"},
			Digest:            api.Digest([]byte("cred:" + credID)),
			Interval:          api.Interval{NBF: nbf, EXP: exp},
		}
		if _, err := invoke(stub, "RegisterCredential", mustJSON(t, cred)); err != nil {
			t.Fatalf("RegisterCredential %s: %v", credID, err)
		}
	}

	regEntity(aReg, aIA, uID, "did:web:a.local:ia", "cred-U")
	regEntity(aReg, aIA, paID, "did:web:a.local:ia", "cred-PA")
	regEntity(aReg, aIA, a1ID, "did:web:a.local:ia", "cred-A1")
	regEntity(bReg, bIB, b1ID, "did:web:b.local:ib", "cred-B1")
	regEntity(bReg, bIB, uInBID, "did:web:b.local:ib", "cred-U-in-B")
	regEntity(cReg, cIC, cSvcID, "did:web:c.local:ic", "cred-C")

	return &registryHarness{
		stub:       stub,
		now:        now,
		depID:      depID,
		tCreator:   tCreator,
		aAdmin:     aAdmin,
		aReg:       aReg,
		aRegMgmt:   aRegMgmt,
		aIA:        aIA,
		aU:         aU,
		aA1:        aA1,
		aPA:        aPA,
		bAdmin:     bAdmin,
		bReg:       bReg,
		bIB:        bIB,
		bB1:        bB1,
		bUinB:      bUinB,
		cAdmin:     cAdmin,
		cReg:       cReg,
		cIC:        cIC,
		cSvc:       cSvc,
		uMgmt:      aUMgmt,
		paMgmt:     aPAMgmt,
		uInBMgmt:   bUinBMgmt,
		uCommit:    uID.AccountCommitment,
		uInBCommit: uInBID.AccountCommitment,
	}
}

func TestSetPurchasingAuthorityAndBuyerMandateRoot(t *testing.T) {
	h := newRegistryHarness(t)
	nbf := h.now.Add(-time.Hour).Unix()
	exp := h.now.Add(24 * time.Hour).Unix()

	// Create BM task by U.
	taskBM := api.Task{
		Bound:             api.Bound{DeploymentID: h.depID},
		ID:                api.Digest([]byte("task-bm")),
		Creator:           "did:web:a.local:u",
		CreatorCredential: "cred-U",
		CreatorKeyVersion: 1,
		Domain:            "A",
		Mode:              api.BM,
		Resource:          api.Digest([]byte("resource:c")),
		Digest:            api.Digest([]byte("task-bm-spec")),
		Interval:          api.Interval{NBF: nbf, EXP: exp},
	}
	h.stub.creator = h.aU
	if _, err := invoke(h.stub, "RegisterTask", mustJSON(t, taskBM)); err != nil {
		t.Fatalf("RegisterTask BM: %v", err)
	}

	// Before PA is configured, PA cannot issue BM root G0.
	g0BM := api.Grant{
		Bound:             api.Bound{DeploymentID: h.depID},
		ID:                api.Digest([]byte("g0-bm")),
		Schema:            api.Schema,
		Root:              api.Digest([]byte("g0-bm")),
		Task:              taskBM.ID,
		Mode:              api.BM,
		Domain:            "A",
		Resource:          taskBM.Resource,
		Issuer:            "did:web:a.local:pa",
		Grantee:           "did:web:a.local:u",
		IssuerKeyVersion:  1,
		GranteeKeyVersion: 1,
		IssuerCredential:  "cred-PA",
		GranteeCredential: "cred-U",
		Depth:             2,
		Digest:            api.Digest([]byte("g0-bm-jws")),
		Interval:          api.Interval{NBF: nbf, EXP: exp},
	}
	h.stub.creator = h.aPA
	if _, err := invoke(h.stub, "RegisterGrant", mustJSON(t, g0BM)); err == nil || !strings.Contains(err.Error(), paInvalid) {
		t.Fatalf("expected PURCHASING_AUTHORITY_INVALID before SetPurchasingAuthority, got %v", err)
	}

	// SetPurchasingAuthority negatives:
	// 1. Non-admin (registrarA) rejected.
	h.stub.creator = h.aReg
	if _, err := invoke(h.stub, "SetPurchasingAuthority", mustJSON(t, api.PurchasingAuthorityUpdate{
		Bound:               api.Bound{DeploymentID: h.depID},
		DomainID:            "A",
		PurchasingAuthority: "did:web:a.local:pa",
		ExpectedRevision:    2,
	})); err == nil || !strings.Contains(err.Error(), denied) {
		t.Fatalf("expected UNAUTHORIZED for registrarA calling SetPurchasingAuthority, got %v", err)
	}
	// 2. Non-SERVICE identity (U or IA) rejected.
	h.stub.creator = h.aAdmin
	if _, err := invoke(h.stub, "SetPurchasingAuthority", mustJSON(t, api.PurchasingAuthorityUpdate{
		Bound:               api.Bound{DeploymentID: h.depID},
		DomainID:            "A",
		PurchasingAuthority: "did:web:a.local:u",
		ExpectedRevision:    2,
	})); err == nil || !strings.Contains(err.Error(), paInvalid) {
		t.Fatalf("expected PURCHASING_AUTHORITY_INVALID for USER identity, got %v", err)
	}
	// 3. Cross-domain SERVICE identity (C) rejected.
	if _, err := invoke(h.stub, "SetPurchasingAuthority", mustJSON(t, api.PurchasingAuthorityUpdate{
		Bound:               api.Bound{DeploymentID: h.depID},
		DomainID:            "A",
		PurchasingAuthority: "did:web:c.local:supplier",
		ExpectedRevision:    2,
	})); err == nil || !strings.Contains(err.Error(), paInvalid) {
		t.Fatalf("expected PURCHASING_AUTHORITY_INVALID for cross-domain SERVICE, got %v", err)
	}
	// 4. Positive SetPurchasingAuthority by domainA admin -> revision 3.
	if _, err := invoke(h.stub, "SetPurchasingAuthority", mustJSON(t, api.PurchasingAuthorityUpdate{
		Bound:               api.Bound{DeploymentID: h.depID},
		DomainID:            "A",
		PurchasingAuthority: "did:web:a.local:pa",
		ExpectedRevision:    2,
	})); err != nil {
		t.Fatalf("SetPurchasingAuthority positive: %v", err)
	}

	// Reject IA / T signing BM root G0, and reject PA signing RP root G0.
	g0IA := g0BM
	g0IA.ID = api.Digest([]byte("g0-ia"))
	g0IA.Root = g0IA.ID
	g0IA.Issuer = "did:web:a.local:ia"
	h.stub.creator = h.aIA
	if _, err := invoke(h.stub, "RegisterGrant", mustJSON(t, g0IA)); err == nil || !strings.Contains(err.Error(), badInput) {
		t.Fatalf("expected failure when IA attempts BM root G0, got %v", err)
	}
	h.stub.creator = h.tCreator
	if _, err := invoke(h.stub, "RegisterGrant", mustJSON(t, g0BM)); err == nil || !strings.Contains(err.Error(), denied) {
		t.Fatalf("expected UNAUTHORIZED when T attempts BM root G0, got %v", err)
	}

	taskRP := taskBM
	taskRP.ID = api.Digest([]byte("task-rp"))
	taskRP.Mode = api.RP
	h.stub.creator = h.aU
	if _, err := invoke(h.stub, "RegisterTask", mustJSON(t, taskRP)); err != nil {
		t.Fatalf("RegisterTask RP: %v", err)
	}
	g0PAonRP := g0BM
	g0PAonRP.ID = api.Digest([]byte("g0-pa-on-rp"))
	g0PAonRP.Root = g0PAonRP.ID
	g0PAonRP.Task = taskRP.ID
	g0PAonRP.Mode = api.RP
	h.stub.creator = h.aPA
	if _, err := invoke(h.stub, "RegisterGrant", mustJSON(t, g0PAonRP)); err == nil || !strings.Contains(err.Error(), badInput) {
		t.Fatalf("expected INVALID_STRUCTURE when PA attempts RP root G0, got %v", err)
	}

	// Positive BM 2-hop chain: PA -> U -> A1 -> B1 (depth 2 -> 1 -> 0).
	h.stub.creator = h.aPA
	if _, err := invoke(h.stub, "RegisterGrant", mustJSON(t, g0BM)); err != nil {
		t.Fatalf("RegisterGrant BM G0 by PA: %v", err)
	}
	g1BM := api.Grant{
		Bound:             api.Bound{DeploymentID: h.depID},
		ID:                api.Digest([]byte("g1-bm")),
		Schema:            api.Schema,
		Parent:            g0BM.ID,
		ParentDigest:      g0BM.Digest,
		Root:              g0BM.ID,
		Task:              taskBM.ID,
		Mode:              api.BM,
		Domain:            "A",
		Resource:          taskBM.Resource,
		Issuer:            "did:web:a.local:u",
		Grantee:           "did:web:a.local:a1",
		IssuerKeyVersion:  1,
		GranteeKeyVersion: 1,
		IssuerCredential:  "cred-U",
		GranteeCredential: "cred-A1",
		Depth:             1,
		Digest:            api.Digest([]byte("g1-bm-jws")),
		Interval:          api.Interval{NBF: nbf + 1, EXP: exp - 1},
	}
	h.stub.creator = h.aU
	if _, err := invoke(h.stub, "RegisterGrant", mustJSON(t, g1BM)); err != nil {
		t.Fatalf("RegisterGrant BM G1 (U->A1): %v", err)
	}
	g2BM := api.Grant{
		Bound:             api.Bound{DeploymentID: h.depID},
		ID:                api.Digest([]byte("g2-bm")),
		Schema:            api.Schema,
		Parent:            g1BM.ID,
		ParentDigest:      g1BM.Digest,
		Root:              g0BM.ID,
		Task:              taskBM.ID,
		Mode:              api.BM,
		Domain:            "A",
		Resource:          taskBM.Resource,
		Issuer:            "did:web:a.local:a1",
		Grantee:           "did:web:b.local:b1",
		IssuerKeyVersion:  1,
		GranteeKeyVersion: 1,
		IssuerCredential:  "cred-A1",
		GranteeCredential: "cred-B1",
		Depth:             0,
		Digest:            api.Digest([]byte("g2-bm-jws")),
		Interval:          api.Interval{NBF: nbf + 2, EXP: exp - 2},
	}
	h.stub.creator = h.aA1
	if _, err := invoke(h.stub, "RegisterGrant", mustJSON(t, g2BM)); err != nil {
		t.Fatalf("RegisterGrant BM G2 (A1->B1): %v", err)
	}
}

func TestIdentityLinkDualDomainStateMachine(t *testing.T) {
	h := newRegistryHarness(t)
	propDigest := api.Digest([]byte("link-proposal-U-UinB"))
	link := api.IdentityLink{
		Bound:                   api.Bound{DeploymentID: h.depID},
		ID:                      "urn:grad:link:U-UinB",
		SourceDomain:            "A",
		SourceSubject:           "did:web:a.local:u",
		SourceKeyVersion:        1,
		SourceAccountCommitment: h.uCommit,
		TargetDomain:            "B",
		TargetSubject:           "did:web:b.local:u-in-b",
		TargetKeyVersion:        1,
		TargetAccountCommitment: h.uInBCommit,
		ProposalDigest:          propDigest,
		ProposedAt:              h.now.Unix(),
		ExpiresAt:               h.now.Add(time.Hour).Unix(),
	}

	// Non-source registrar (registrarB) cannot propose A->B link.
	h.stub.creator = h.bReg
	if _, err := invoke(h.stub, "ProposeIdentityLink", mustJSON(t, link)); err == nil || !strings.Contains(err.Error(), denied) {
		t.Fatalf("expected UNAUTHORIZED when registrarB proposes A->B link, got %v", err)
	}

	// Positive propose by registrarA -> PENDING with effectiveActive=false.
	h.stub.creator = h.aReg
	if _, err := invoke(h.stub, "ProposeIdentityLink", mustJSON(t, link)); err != nil {
		t.Fatalf("ProposeIdentityLink: %v", err)
	}
	stored, err := get[api.IdentityLink](h.stub, api.Key("link", link.ID))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != api.Pending || stored.EffectiveActive || stored.Revision != 1 {
		t.Fatalf("unexpected pending link state: %+v", stored)
	}

	// Source domain self-approval (registrarA) rejected with LINK_APPROVAL_FORBIDDEN.
	h.stub.creator = h.aReg
	if _, err := invoke(h.stub, "ApproveIdentityLink", mustJSON(t, api.IdentityLinkApproval{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               link.ID,
		ProposalDigest:   propDigest,
		ExpectedRevision: 1,
		ApprovedAt:       h.now.Unix(),
	})); err == nil || !strings.Contains(err.Error(), linkApprovalForbidden) {
		t.Fatalf("expected LINK_APPROVAL_FORBIDDEN for registrarA self-approval, got %v", err)
	}

	// Wrong proposalDigest rejected by registrarB with LINK_PROPOSAL_MISMATCH.
	h.stub.creator = h.bReg
	if _, err := invoke(h.stub, "ApproveIdentityLink", mustJSON(t, api.IdentityLinkApproval{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               link.ID,
		ProposalDigest:   api.Digest([]byte("tampered")),
		ExpectedRevision: 1,
		ApprovedAt:       h.now.Unix(),
	})); err == nil || !strings.Contains(err.Error(), linkProposalMismatch) {
		t.Fatalf("expected LINK_PROPOSAL_MISMATCH, got %v", err)
	}

	// Target registrar (registrarB) approves matching proposalDigest -> ACTIVE & effectiveActive=true.
	if _, err := invoke(h.stub, "ApproveIdentityLink", mustJSON(t, api.IdentityLinkApproval{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               link.ID,
		ProposalDigest:   propDigest,
		ExpectedRevision: 1,
		ApprovedAt:       h.now.Unix(),
	})); err != nil {
		t.Fatalf("ApproveIdentityLink: %v", err)
	}
	stored, err = get[api.IdentityLink](h.stub, api.Key("link", link.ID))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != api.Active || !stored.EffectiveActive || stored.Revision != 2 || stored.ApprovedBy != "did:web:b.local" {
		t.Fatalf("unexpected active link state: %+v", stored)
	}

	// Unrelated registrar (registrarC) cannot revoke A<->B link.
	h.stub.creator = h.cReg
	if _, err := invoke(h.stub, "RevokeIdentityLink", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               link.ID,
		ExpectedRevision: 2,
		Reason:           "unauthorized",
	})); err == nil || !strings.Contains(err.Error(), denied) {
		t.Fatalf("expected UNAUTHORIZED for registrarC revoking A<->B link, got %v", err)
	}

	// Endpoint user U revokes A<->B link -> REVOKED & effectiveActive=false.
	h.stub.creator = h.aU
	if _, err := invoke(h.stub, "RevokeIdentityLink", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               link.ID,
		ExpectedRevision: 2,
		Reason:           "user requested unlink",
	})); err != nil {
		t.Fatalf("RevokeIdentityLink: %v", err)
	}
	stored, err = get[api.IdentityLink](h.stub, api.Key("link", link.ID))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != api.Revoked || stored.EffectiveActive || stored.Revision != 3 {
		t.Fatalf("unexpected revoked link state: %+v", stored)
	}

	// Re-approving revoked link fails with LINK_STATE_CONFLICT.
	h.stub.creator = h.bReg
	if _, err := invoke(h.stub, "ApproveIdentityLink", mustJSON(t, api.IdentityLinkApproval{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               link.ID,
		ProposalDigest:   propDigest,
		ExpectedRevision: 3,
		ApprovedAt:       h.now.Unix(),
	})); err == nil || !strings.Contains(err.Error(), linkStateConflict) {
		t.Fatalf("expected LINK_STATE_CONFLICT after revocation, got %v", err)
	}
}

func TestDomainCertRenewalRevocationAndAuthorityUpdate(t *testing.T) {
	h := newRegistryHarness(t)
	nbf := h.now.Add(-time.Hour).Unix()
	exp := h.now.Add(24 * time.Hour).Unix()

	// 1. Atomic same-key domain cert renewal & claim scope shrink on ACTIVE domain B (F15, S82, S93).
	domB, err := get[api.Domain](h.stub, api.Key("domain", "B"))
	if err != nil {
		t.Fatal(err)
	}
	if domB.Revision != 2 || domB.Certification != "urn:grad:cert:B" {
		t.Fatalf("unexpected initial domain B state: %+v", domB)
	}

	// Non-T caller rejected with TRUST_MANAGEMENT_FORBIDDEN on RevokeCertification / UpdateAuthorityIdentity and UNAUTHORIZED on CertifyDomain (S85).
	h.stub.creator = h.bAdmin
	if _, err := invoke(h.stub, "RevokeCertification", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "urn:grad:cert:B",
		ExpectedRevision: 1,
	})); err == nil || !strings.Contains(err.Error(), trustMgmtForbidden) {
		t.Fatalf("expected TRUST_MANAGEMENT_FORBIDDEN, got %v", err)
	}
	if _, err := invoke(h.stub, "UpdateAuthorityIdentity", mustJSON(t, api.AuthorityIdentityUpdateInput{
		Bound: api.Bound{DeploymentID: h.depID},
		ID:    "did:web:b.local:ib",
	})); err == nil || !strings.Contains(err.Error(), trustMgmtForbidden) {
		t.Fatalf("expected TRUST_MANAGEMENT_FORBIDDEN, got %v", err)
	}

	// Stale expectedCertificationId or expectedRevision fails with STATE_CHANGED (S82).
	h.stub.creator = h.tCreator
	certB2 := api.Certify{
		Certification: api.Certification{
			Bound:          api.Bound{DeploymentID: h.depID},
			ID:             "urn:grad:cert:B:v2",
			Domain:         "B",
			RootKeyVersion: 1,
			Digest:         api.Digest([]byte("cert:B:v2")),
			Scopes: []api.Scope{{
				ID:         "did:web:b.local:ib",
				KeyVersion: 1,
				Types:      []string{"EnterpriseIdentityCredential"},
				Claims:     []string{"domain", "role"},
			}},
			Interval: api.Interval{NBF: nbf, EXP: exp},
		},
		ExpectedRevision:      2,
		ExpectedCertification: "urn:grad:cert:WRONG",
	}
	if _, err := invoke(h.stub, "CertifyDomain", mustJSON(t, certB2)); err == nil || !strings.Contains(err.Error(), stale) {
		t.Fatalf("expected STATE_CHANGED on stale expectedCertificationId, got %v", err)
	}
	certB2.ExpectedCertification = "urn:grad:cert:B"
	if _, err := invoke(h.stub, "CertifyDomain", mustJSON(t, certB2)); err != nil {
		t.Fatalf("CertifyDomain atomic same-key renewal: %v", err)
	}
	domB, err = get[api.Domain](h.stub, api.Key("domain", "B"))
	if err != nil {
		t.Fatal(err)
	}
	if domB.Revision != 3 || domB.Certification != "urn:grad:cert:B:v2" || domB.Status != api.Active {
		t.Fatalf("unexpected domain B after atomic renewal: %+v", domB)
	}

	// 2. Suspend domain B and resume while cert is valid (S89).
	if _, err := invoke(h.stub, "SetDomainStatus", mustJSON(t, api.DomainStatus{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "B",
		ExpectedRevision: 3,
		Status:           api.Suspended,
	})); err != nil {
		t.Fatalf("suspend domain B: %v", err)
	}
	if _, err := invoke(h.stub, "SetDomainStatus", mustJSON(t, api.DomainStatus{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "B",
		ExpectedRevision: 4,
		Status:           api.Active,
	})); err != nil {
		t.Fatalf("resume domain B: %v", err)
	}

	// 3. Rotate IB key via UpdateAuthorityIdentity (F15, S81), then re-certify B with keyVersion=2.
	ibBefore, err := get[api.Identity](h.stub, api.Key("identity", "did:web:b.local:ib"))
	if err != nil {
		t.Fatal(err)
	}
	_, ibPub2 := makeAppKey(t, "did:web:b.local:ib")
	_, ibNewMgmt := makeSerializedCaller(t, "BMsp", "ib-v2")
	if _, err := invoke(h.stub, "UpdateAuthorityIdentity", mustJSON(t, api.AuthorityIdentityUpdateInput{
		Bound:              api.Bound{DeploymentID: h.depID},
		ID:                 "did:web:b.local:ib",
		ExpectedRevision:   ibBefore.Revision,
		ExpectedKeyVersion: ibBefore.KeyVersion,
		Management:         ibNewMgmt,
		DocumentDigest:     api.Digest([]byte("doc:ib:v2")),
		KeyID:              "did:web:b.local:ib#key-2",
		PublicKey:          ibPub2,
	})); err != nil {
		t.Fatalf("UpdateAuthorityIdentity IB: %v", err)
	}
	// Attempting CertifyDomain while still specifying old IB KeyVersion=1 must fail.
	certB3Bad := api.Certify{
		Certification: api.Certification{
			Bound:          api.Bound{DeploymentID: h.depID},
			ID:             "urn:grad:cert:B:v3-bad",
			Domain:         "B",
			RootKeyVersion: 1,
			Digest:         api.Digest([]byte("cert:B:v3-bad")),
			Scopes: []api.Scope{{
				ID:         "did:web:b.local:ib",
				KeyVersion: 1,
				Types:      []string{"EnterpriseIdentityCredential"},
				Claims:     []string{"domain", "role"},
			}},
			Interval: api.Interval{NBF: nbf, EXP: exp},
		},
		ExpectedRevision:      5,
		ExpectedCertification: "urn:grad:cert:B:v2",
	}
	if _, err := invoke(h.stub, "CertifyDomain", mustJSON(t, certB3Bad)); err == nil || !strings.Contains(err.Error(), badInput) {
		t.Fatalf("expected INVALID_STRUCTURE when cert references stale IB KeyVersion, got %v", err)
	}
	// Re-certify B with IB KeyVersion=2 succeeds.
	certB3 := certB3Bad
	certB3.Certification.ID = "urn:grad:cert:B:v3"
	certB3.Certification.Digest = api.Digest([]byte("cert:B:v3"))
	certB3.Certification.Scopes[0].KeyVersion = 2
	if _, err := invoke(h.stub, "CertifyDomain", mustJSON(t, certB3)); err != nil {
		t.Fatalf("CertifyDomain with IB keyVersion=2: %v", err)
	}

	// 4. RevokeCertification is irreversible; suspended domain cannot resume once its certification is REVOKED; REVOKED domain cannot be resumed (S78, S89).
	if _, err := invoke(h.stub, "RevokeCertification", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "urn:grad:cert:B:v3",
		ExpectedRevision: 1,
	})); err != nil {
		t.Fatalf("RevokeCertification: %v", err)
	}
	if _, err := invoke(h.stub, "SetDomainStatus", mustJSON(t, api.DomainStatus{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "B",
		ExpectedRevision: 6,
		Status:           api.Suspended,
	})); err != nil {
		t.Fatalf("suspend domain B after cert revoke: %v", err)
	}
	if _, err := invoke(h.stub, "SetDomainStatus", mustJSON(t, api.DomainStatus{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "B",
		ExpectedRevision: 7,
		Status:           api.Active,
	})); err == nil || !strings.Contains(err.Error(), invalid) {
		t.Fatalf("expected INVALID_STATE resuming domain whose cert is REVOKED, got %v", err)
	}
	if _, err := invoke(h.stub, "SetDomainStatus", mustJSON(t, api.DomainStatus{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "B",
		ExpectedRevision: 7,
		Status:           api.Revoked,
	})); err != nil {
		t.Fatalf("revoke domain B: %v", err)
	}
	if _, err := invoke(h.stub, "SetDomainStatus", mustJSON(t, api.DomainStatus{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "B",
		ExpectedRevision: 8,
		Status:           api.Active,
	})); err == nil || !strings.Contains(err.Error(), invalid) {
		t.Fatalf("expected INVALID_STATE resuming REVOKED domain, got %v", err)
	}
}

func TestIdentityLifecycleRotateAndRecover(t *testing.T) {
	h := newRegistryHarness(t)

	// 1. Self suspends A1; self, domainA admin, registrarB cannot resume; only registrarA can resume (S94).
	h.stub.creator = h.aA1
	if _, err := invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "did:web:a.local:a1",
		ExpectedRevision: 1,
		Status:           api.Suspended,
	})); err != nil {
		t.Fatalf("self suspend A1: %v", err)
	}
	for _, attempt := range []struct {
		name    string
		creator []byte
	}{
		{"self", h.aA1},
		{"domain-admin", h.aAdmin},
		{"cross-domain-registrar", h.bReg},
	} {
		h.stub.creator = attempt.creator
		if _, err := invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
			Bound:            api.Bound{DeploymentID: h.depID},
			ID:               "did:web:a.local:a1",
			ExpectedRevision: 2,
			Status:           api.Active,
		})); err == nil || !strings.Contains(err.Error(), identityMgmtForbidden) {
			t.Fatalf("expected IDENTITY_MANAGEMENT_FORBIDDEN for %s resuming A1, got %v", attempt.name, err)
		}
	}
	// Same-status transition (SUSPENDED -> SUSPENDED) returns IDENTITY_STATE_CONFLICT.
	h.stub.creator = h.aReg
	if _, err := invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "did:web:a.local:a1",
		ExpectedRevision: 2,
		Status:           api.Suspended,
	})); err == nil || !strings.Contains(err.Error(), identityStateConflict) {
		t.Fatalf("expected IDENTITY_STATE_CONFLICT on repeat SUSPENDED, got %v", err)
	}
	// Registrar A resumes A1 -> ACTIVE.
	if _, err := invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "did:web:a.local:a1",
		ExpectedRevision: 2,
		Status:           api.Active,
	})); err != nil {
		t.Fatalf("registrarA resume A1: %v", err)
	}

	// Non-T caller cannot manage bootstrap authority IA/IB/IC (S94).
	h.stub.creator = h.aReg
	if _, err := invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "did:web:a.local:ia",
		ExpectedRevision: 1,
		Status:           api.Suspended,
	})); err == nil || !strings.Contains(err.Error(), identityMgmtForbidden) {
		t.Fatalf("expected IDENTITY_MANAGEMENT_FORBIDDEN for registrarA managing IA, got %v", err)
	}

	// 2. RotateIdentity increments KeyVersion and Revision.
	_, a1Pub2 := makeAppKey(t, "did:web:a.local:a1")
	h.stub.creator = h.aA1
	if _, err := invoke(h.stub, "RotateIdentity", mustJSON(t, api.RotateIdentityInput{
		Bound:              api.Bound{DeploymentID: h.depID},
		ID:                 "did:web:a.local:a1",
		ExpectedRevision:   3,
		ExpectedKeyVersion: 1,
		DocumentDigest:     api.Digest([]byte("doc:a1:v2")),
		KeyID:              "did:web:a.local:a1#key-2",
		PublicKey:          a1Pub2,
	})); err != nil {
		t.Fatalf("RotateIdentity A1: %v", err)
	}

	// 3. RecoverIdentity on SUSPENDED ordinary identity preserves SUSPENDED status and atomically swaps binding (S95, S97).
	b1Before, err := get[api.Identity](h.stub, api.Key("identity", "did:web:b.local:b1"))
	if err != nil {
		t.Fatal(err)
	}
	h.stub.creator = h.bReg
	if _, err := invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "did:web:b.local:b1",
		ExpectedRevision: b1Before.Revision,
		Status:           api.Suspended,
	})); err != nil {
		t.Fatalf("suspend B1 before recovery: %v", err)
	}
	b1NewCreator, b1NewMgmt := makeSerializedCaller(t, "BMsp", "b1-recovered")
	_, b1Pub2 := makeAppKey(t, "did:web:b.local:b1")
	if _, err := invoke(h.stub, "RecoverIdentity", mustJSON(t, api.RecoverIdentityInput{
		Bound:              api.Bound{DeploymentID: h.depID},
		ID:                 "did:web:b.local:b1",
		ExpectedRevision:   b1Before.Revision + 1,
		ExpectedKeyVersion: b1Before.KeyVersion,
		AccountCommitment:  b1Before.AccountCommitment,
		OldManagement:      b1Before.Management,
		NewManagement:      b1NewMgmt,
		DocumentDigest:     api.Digest([]byte("doc:b1:recovered")),
		KeyID:              "did:web:b.local:b1#key-2",
		PublicKey:          b1Pub2,
	})); err != nil {
		t.Fatalf("RecoverIdentity on SUSPENDED B1: %v", err)
	}
	b1After, err := get[api.Identity](h.stub, api.Key("identity", "did:web:b.local:b1"))
	if err != nil {
		t.Fatal(err)
	}
	if b1After.Status != api.Suspended || b1After.KeyVersion != 2 || b1After.Management != b1NewMgmt || b1After.AccountCommitment != b1Before.AccountCommitment {
		t.Fatalf("unexpected B1 after RecoverIdentity: %+v", b1After)
	}
	// Registrar must still resume B1 -> ACTIVE before B1 can rotate/operate again (S97).
	h.stub.creator = b1NewCreator
	if _, err := invoke(h.stub, "RotateIdentity", mustJSON(t, api.RotateIdentityInput{
		Bound:              api.Bound{DeploymentID: h.depID},
		ID:                 "did:web:b.local:b1",
		ExpectedRevision:   b1After.Revision,
		ExpectedKeyVersion: b1After.KeyVersion,
		DocumentDigest:     api.Digest([]byte("doc:b1:v3")),
		KeyID:              "did:web:b.local:b1#key-3",
		PublicKey:          b1Pub2,
	})); err == nil || !strings.Contains(err.Error(), identityStateConflict) {
		t.Fatalf("expected IDENTITY_STATE_CONFLICT rotating SUSPENDED B1 after recovery, got %v", err)
	}
	// Old management certificate can no longer manage B1 (S95).
	h.stub.creator = h.bB1
	if _, err := invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "did:web:b.local:b1",
		ExpectedRevision: b1After.Revision,
		Status:           api.Revoked,
	})); err == nil || !strings.Contains(err.Error(), identityMgmtForbidden) {
		t.Fatalf("expected IDENTITY_MANAGEMENT_FORBIDDEN for old B1 cert after recovery, got %v", err)
	}

	// 4. Revoke B1 then verify RecoverIdentity, RotateIdentity, SetIdentityStatus, and RegisterIdentity re-use all return IDENTITY_STATE_CONFLICT (S97).
	h.stub.creator = h.bReg
	if _, err := invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "did:web:b.local:b1",
		ExpectedRevision: b1After.Revision,
		Status:           api.Revoked,
	})); err != nil {
		t.Fatalf("revoke B1: %v", err)
	}
	_, b1ThirdMgmt := makeSerializedCaller(t, "BMsp", "b1-3")
	if _, err := invoke(h.stub, "RecoverIdentity", mustJSON(t, api.RecoverIdentityInput{
		Bound:              api.Bound{DeploymentID: h.depID},
		ID:                 "did:web:b.local:b1",
		ExpectedRevision:   b1After.Revision + 1,
		ExpectedKeyVersion: b1After.KeyVersion,
		AccountCommitment:  b1After.AccountCommitment,
		OldManagement:      b1NewMgmt,
		NewManagement:      b1ThirdMgmt,
		DocumentDigest:     api.Digest([]byte("doc:b1:v3")),
		KeyID:              "did:web:b.local:b1#key-3",
		PublicKey:          b1Pub2,
	})); err == nil || !strings.Contains(err.Error(), identityStateConflict) {
		t.Fatalf("expected IDENTITY_STATE_CONFLICT recovering REVOKED B1, got %v", err)
	}
	b1Revoked := b1After
	b1Revoked.Management = b1ThirdMgmt
	b1Revoked.KeyID = "did:web:b.local:b1#key-1"
	b1Revoked.KeyVersion = 1
	if _, err := invoke(h.stub, "RegisterIdentity", mustJSON(t, b1Revoked)); err == nil || !strings.Contains(err.Error(), identityStateConflict) {
		t.Fatalf("expected IDENTITY_STATE_CONFLICT re-registering REVOKED DID, got %v", err)
	}
}

func TestCredentialTaskAndGrantLifecycle(t *testing.T) {
	h := newRegistryHarness(t)
	nbf := h.now.Add(-time.Hour).Unix()
	exp := h.now.Add(24 * time.Hour).Unix()

	taskRP := api.Task{
		Bound:             api.Bound{DeploymentID: h.depID},
		ID:                api.Digest([]byte("lifecycle-task-rp")),
		Creator:           "did:web:a.local:u",
		CreatorCredential: "cred-U",
		CreatorKeyVersion: 1,
		Domain:            "A",
		Mode:              api.RP,
		Resource:          api.Digest([]byte("resource:c")),
		Digest:            api.Digest([]byte("lifecycle-task-rp-spec")),
		Interval:          api.Interval{NBF: nbf, EXP: exp},
	}
	h.stub.creator = h.aU
	if _, err := invoke(h.stub, "RegisterTask", mustJSON(t, taskRP)); err != nil {
		t.Fatalf("RegisterTask: %v", err)
	}
	g0 := api.Grant{
		Bound:             api.Bound{DeploymentID: h.depID},
		ID:                api.Digest([]byte("g0-m3")),
		Schema:            api.Schema,
		Root:              api.Digest([]byte("g0-m3")),
		Task:              taskRP.ID,
		Mode:              api.RP,
		Domain:            "A",
		Resource:          taskRP.Resource,
		Issuer:            "did:web:c.local:supplier",
		Grantee:           "did:web:a.local:u",
		IssuerKeyVersion:  1,
		GranteeKeyVersion: 1,
		IssuerCredential:  "cred-C",
		GranteeCredential: "cred-U",
		Depth:             1,
		Digest:            api.Digest([]byte("lifecycle-g0-jws")),
		Interval:          api.Interval{NBF: nbf, EXP: exp},
	}
	h.stub.creator = h.cSvc
	if _, err := invoke(h.stub, "RegisterGrant", mustJSON(t, g0)); err != nil {
		t.Fatalf("RegisterGrant G0: %v", err)
	}

	// SuspendGrant -> ResumeGrant preserves original EXP (E3).
	if _, err := invoke(h.stub, "SuspendGrant", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               g0.ID,
		ExpectedRevision: 1,
		ExpectedDigest:   g0.Digest,
	})); err != nil {
		t.Fatalf("SuspendGrant: %v", err)
	}
	g0Susp, err := get[api.Grant](h.stub, api.Key("grant", g0.ID))
	if err != nil {
		t.Fatal(err)
	}
	if g0Susp.Status != api.Suspended || g0Susp.EXP != exp {
		t.Fatalf("unexpected suspended grant: %+v", g0Susp)
	}
	if _, err := invoke(h.stub, "ResumeGrant", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               g0.ID,
		ExpectedRevision: 2,
		ExpectedDigest:   g0.Digest,
	})); err != nil {
		t.Fatalf("ResumeGrant: %v", err)
	}
	g0Resumed, err := get[api.Grant](h.stub, api.Key("grant", g0.ID))
	if err != nil {
		t.Fatal(err)
	}
	if g0Resumed.Status != api.Active || g0Resumed.EXP != exp {
		t.Fatalf("unexpected resumed grant: %+v", g0Resumed)
	}

	// CancelTask is terminal CANCELLED and rejects repeat cancel with TASK_STATE_CONFLICT.
	h.stub.creator = h.aU
	if _, err := invoke(h.stub, "CancelTask", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               taskRP.ID,
		ExpectedRevision: 1,
		ExpectedDigest:   taskRP.Digest,
	})); err != nil {
		t.Fatalf("CancelTask: %v", err)
	}
	if _, err := invoke(h.stub, "CancelTask", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               taskRP.ID,
		ExpectedRevision: 2,
		ExpectedDigest:   taskRP.Digest,
	})); err == nil || !strings.Contains(err.Error(), taskStateConflict) {
		t.Fatalf("expected TASK_STATE_CONFLICT on repeat CancelTask, got %v", err)
	}

	// RevokeCredential works even when issuer's domain B is REVOKED (S89).
	h.stub.creator = h.tCreator
	if _, err := invoke(h.stub, "SetDomainStatus", mustJSON(t, api.DomainStatus{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "B",
		ExpectedRevision: 2,
		Status:           api.Revoked,
	})); err != nil {
		t.Fatalf("revoke domain B: %v", err)
	}
	h.stub.creator = h.bIB
	if _, err := invoke(h.stub, "RevokeCredential", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "cred-B1",
		ExpectedRevision: 1,
	})); err != nil {
		t.Fatalf("RevokeCredential while domain B revoked: %v", err)
	}
	credB1, err := get[api.Credential](h.stub, api.Key("credential", "cred-B1"))
	if err != nil {
		t.Fatal(err)
	}
	if credB1.Status != api.Revoked || credB1.Revision != 2 {
		t.Fatalf("unexpected cred-B1 after RevokeCredential: %+v", credB1)
	}
}
