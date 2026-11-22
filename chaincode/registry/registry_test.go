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
	"testing"
	"time"

	api "grad/protocol/registry"

	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type memStub struct {
	shim.ChaincodeStubInterface
	channel string
	txID    string
	txAt    time.Time
	creator []byte
	fn      string
	args    []string
	state   map[string][]byte
}

func (m *memStub) GetChannelID() string                  { return m.channel }
func (m *memStub) GetTxID() string                       { return m.txID }
func (m *memStub) GetFunctionAndParameters() (string, []string) { return m.fn, m.args }
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
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	sid, err := proto.Marshal(&msp.SerializedIdentity{
		Mspid:   mspID,
		IdBytes: certPEM,
	})
	require.NoError(t, err)
	return sid, api.Management{MSPID: mspID, CertificateSHA256: api.Digest(der)}
}

func makeAppKey(t *testing.T, subject string) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	raw, err := priv.PublicKey.Bytes()
	require.NoError(t, err)
	return subject + "#key-1", hex.EncodeToString(raw)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func requireCode(t *testing.T, err error, wantCode string) {
	t.Helper()
	require.Error(t, err)
	assert.Equal(t, wantCode, err.Error())
	assert.Equal(t, wantCode, api.CodeOf(err))
	assert.True(t, api.IsKnownCode(err.Error()))
}

type registryHarness struct {
	stub       *memStub
	now        time.Time
	depID      string
	initCaller []byte
	probe1     []byte
	probe2     []byte
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
	p1Caller, p1Mgmt := makeSerializedCaller(t, "CMsp", "probe-1")
	p2Caller, p2Mgmt := makeSerializedCaller(t, "CMsp", "probe-2")

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

	// Bind package globals injected by approved chaincode build ldflags.
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
	_, err := invoke(stub, "Initialize", bootRaw)
	require.NoError(t, err)

	depID := boot.DeploymentID()
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
		_, err := invoke(stub, "BootstrapDomain", mustJSON(t, domBoot))
		require.NoError(t, err, "BootstrapDomain %s", item.id)

		cert := api.Certify{
			Certification: api.Certification{
				Bound:          api.Bound{DeploymentID: depID},
				ID:             "urn:grad:cert:" + item.id,
				Domain:         item.id,
				RootKeyVersion: 1,
				Digest:         api.Digest([]byte("cert:" + item.id)),
				Scopes: []api.IssuerScope{{
					ID:              item.issuerDID,
					AppKeyVersion:   1,
					CredentialTypes: []string{"EnterpriseIdentityCredential"},
					ClaimNames:      []string{"domain", "role"},
				}},
				Interval: api.Interval{NBF: nbf, EXP: exp},
			},
			ExpectedRevision: 1,
		}
		_, err = invoke(stub, "CertifyDomain", mustJSON(t, cert))
		require.NoError(t, err, "CertifyDomain %s", item.id)
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
		_, err := invoke(stub, "RegisterIdentity", mustJSON(t, id))
		require.NoError(t, err, "RegisterIdentity %s", id.ID)

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
		_, err = invoke(stub, "RegisterCredential", mustJSON(t, cred))
		require.NoError(t, err, "RegisterCredential %s", credID)
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
		initCaller: initCreator,
		probe1:     p1Caller,
		probe2:     p2Caller,
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

func TestInitializeProbeReadAndInvokeEnvelope(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	initCaller, initMgmt := makeSerializedCaller(t, "TMsp", "t-initializer")
	tCaller, tMgmt := makeSerializedCaller(t, "TMsp", "t-root")
	otherCaller, _ := makeSerializedCaller(t, "AMsp", "non-initializer")
	_, uMgmt := makeSerializedCaller(t, "AMsp", "u")
	_, cSvcMgmt := makeSerializedCaller(t, "CMsp", "c-svc")
	p1Caller, p1Mgmt := makeSerializedCaller(t, "CMsp", "probe-1")
	_, p2Mgmt := makeSerializedCaller(t, "CMsp", "probe-2")

	tKeyID, tPub := makeAppKey(t, "did:web:t.local")
	validBoot := api.Bootstrap{
		DeploymentFields: api.DeploymentFields{
			ChannelID:     api.Channel,
			GenesisHash:   api.Digest([]byte("genesis-init")),
			InstanceID:    api.Digest([]byte("instance-init")),
			RegistryName:  api.Registry,
			SchemaVersion: api.Schema,
		},
		Root: api.RootRecord{
			DID:            "did:web:t.local",
			Management:     tMgmt,
			DocumentDigest: api.Digest([]byte("t-doc-init")),
			KeyID:          tKeyID,
			KeyVersion:     1,
			PublicKey:      tPub,
		},
		Initializer: initMgmt,
		TaskCreator: api.TaskAuthority{
			Domain:     "A",
			Subject:    "did:web:a.local:u",
			Management: uMgmt,
		},
		ResourceID:         api.Digest([]byte("resource:c")),
		ResourceOwner:      "did:web:c.local:supplier",
		ResourceManagement: cSvcMgmt,
	}
	validRaw := mustJSON(t, validBoot)

	bootstrapDigest = api.Digest(validRaw)
	initializer = initMgmt.String()
	probeOne = p1Mgmt.String()
	probeTwo = p2Mgmt.String()

	stub := &memStub{
		channel: api.Channel,
		txID:    "tx-env",
		txAt:    now,
		creator: initCaller,
		state:   map[string][]byte{},
	}

	// Init() is always rejected with the bare canonical UNAUTHORIZED code.
	cc := registry{}
	initResp := cc.Init(stub)
	assert.Equal(t, int32(shim.ERROR), initResp.Status)
	assert.Equal(t, api.ErrCodeUnauthorized, initResp.Message)

	// Invoke() rejects wrong argument count with canonical INVALID_STRUCTURE.
	stub.fn = "Read"
	stub.args = nil
	resp := cc.Invoke(stub)
	assert.Equal(t, int32(shim.ERROR), resp.Status)
	assert.Equal(t, api.ErrCodeInvalidStructure, resp.Message)

	// Wrong channel rejected.
	stub.channel = "wrong-channel"
	_, err := invoke(stub, "Initialize", validRaw)
	requireCode(t, err, api.ErrCodeInvalidStructure)
	stub.channel = api.Channel

	// Non-initializer caller (even T root or other MSP) rejected with UNAUTHORIZED.
	for _, caller := range [][]byte{otherCaller, tCaller} {
		stub.creator = caller
		_, err = invoke(stub, "Initialize", validRaw)
		requireCode(t, err, api.ErrCodeUnauthorized)
	}

	// Digest mismatch rejected with INVALID_STRUCTURE.
	stub.creator = initCaller
	_, err = invoke(stub, "Initialize", []byte(`{"tampered":true}`))
	requireCode(t, err, api.ErrCodeInvalidStructure)

	// Malformed JSON (unknown field) even with matching digest rejected with INVALID_STRUCTURE.
	unknownFieldRaw := []byte(`{"unknownField":1}`)
	bootstrapDigest = api.Digest(unknownFieldRaw)
	_, err = invoke(stub, "Initialize", unknownFieldRaw)
	requireCode(t, err, api.ErrCodeInvalidStructure)

	// Semantically invalid bootstrap (Root MSP != TMsp) rejected with INVALID_STRUCTURE.
	badRoot := validBoot
	badRoot.Root.Management.MSPID = "AMsp"
	badRootRaw := mustJSON(t, badRoot)
	bootstrapDigest = api.Digest(badRootRaw)
	_, err = invoke(stub, "Initialize", badRootRaw)
	requireCode(t, err, api.ErrCodeInvalidStructure)

	// Valid Initialize via Invoke() envelope succeeds once; repeat Initialize fails with ID_ALREADY_USED.
	bootstrapDigest = api.Digest(validRaw)
	stub.fn = "Initialize"
	stub.args = []string{string(validRaw)}
	resp = cc.Invoke(stub)
	require.Equal(t, int32(shim.OK), resp.Status)

	resp = cc.Invoke(stub)
	assert.Equal(t, int32(shim.ERROR), resp.Status)
	assert.Equal(t, api.ErrCodeIDAlreadyUsed, resp.Message)

	// Read returns stored bootstrap record and returns MISSING_DEPENDENCY for absent key.
	stub.fn = "Read"
	stub.args = []string{api.BootstrapKey}
	resp = cc.Invoke(stub)
	require.Equal(t, int32(shim.OK), resp.Status)
	assert.NotEmpty(t, resp.Payload)

	_, err = invoke(stub, "Read", []byte("nonexistent-key"))
	requireCode(t, err, api.ErrCodeMissingDependency)

	// Probe access control & payload validation.
	stub.creator = otherCaller
	_, err = invoke(stub, "Probe", nil)
	requireCode(t, err, api.ErrCodeUnauthorized)

	stub.creator = p1Caller
	_, err = invoke(stub, "Probe", []byte("extra"))
	requireCode(t, err, api.ErrCodeInvalidStructure)

	_, err = invoke(stub, "Probe", nil)
	require.NoError(t, err)
	probeRec, err := get[api.Probe](stub, api.ProbeKey(p1Mgmt))
	require.NoError(t, err)
	assert.Equal(t, "tx-env", probeRec.TxID)
	assert.Equal(t, p1Mgmt, probeRec.Identity)
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
	_, err := invoke(h.stub, "RegisterTask", mustJSON(t, taskBM))
	require.NoError(t, err)

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
	_, err = invoke(h.stub, "RegisterGrant", mustJSON(t, g0BM))
	requireCode(t, err, api.ErrCodePurchasingAuthorityInvalid)

	// SetPurchasingAuthority negatives:
	// 1. Non-admin (registrarA) rejected.
	h.stub.creator = h.aReg
	_, err = invoke(h.stub, "SetPurchasingAuthority", mustJSON(t, api.PurchasingAuthorityUpdate{
		Bound:               api.Bound{DeploymentID: h.depID},
		DomainID:            "A",
		PurchasingAuthority: "did:web:a.local:pa",
		ExpectedRevision:    2,
	}))
	requireCode(t, err, api.ErrCodeUnauthorized)

	// 2. Non-SERVICE identity (U) rejected.
	h.stub.creator = h.aAdmin
	_, err = invoke(h.stub, "SetPurchasingAuthority", mustJSON(t, api.PurchasingAuthorityUpdate{
		Bound:               api.Bound{DeploymentID: h.depID},
		DomainID:            "A",
		PurchasingAuthority: "did:web:a.local:u",
		ExpectedRevision:    2,
	}))
	requireCode(t, err, api.ErrCodePurchasingAuthorityInvalid)

	// 3. Cross-domain SERVICE identity (C) rejected.
	_, err = invoke(h.stub, "SetPurchasingAuthority", mustJSON(t, api.PurchasingAuthorityUpdate{
		Bound:               api.Bound{DeploymentID: h.depID},
		DomainID:            "A",
		PurchasingAuthority: "did:web:c.local:supplier",
		ExpectedRevision:    2,
	}))
	requireCode(t, err, api.ErrCodePurchasingAuthorityInvalid)

	// 4. Positive SetPurchasingAuthority by domainA admin -> revision 3.
	_, err = invoke(h.stub, "SetPurchasingAuthority", mustJSON(t, api.PurchasingAuthorityUpdate{
		Bound:               api.Bound{DeploymentID: h.depID},
		DomainID:            "A",
		PurchasingAuthority: "did:web:a.local:pa",
		ExpectedRevision:    2,
	}))
	require.NoError(t, err)

	// Reject IA / T signing BM root G0, and reject PA signing RP root G0.
	g0IA := g0BM
	g0IA.ID = api.Digest([]byte("g0-ia"))
	g0IA.Root = g0IA.ID
	g0IA.Issuer = "did:web:a.local:ia"
	h.stub.creator = h.aIA
	_, err = invoke(h.stub, "RegisterGrant", mustJSON(t, g0IA))
	requireCode(t, err, api.ErrCodeInvalidStructure)

	h.stub.creator = h.tCreator
	_, err = invoke(h.stub, "RegisterGrant", mustJSON(t, g0BM))
	requireCode(t, err, api.ErrCodeUnauthorized)

	taskRP := taskBM
	taskRP.ID = api.Digest([]byte("task-rp"))
	taskRP.Mode = api.RP
	h.stub.creator = h.aU
	_, err = invoke(h.stub, "RegisterTask", mustJSON(t, taskRP))
	require.NoError(t, err)

	g0PAonRP := g0BM
	g0PAonRP.ID = api.Digest([]byte("g0-pa-on-rp"))
	g0PAonRP.Root = g0PAonRP.ID
	g0PAonRP.Task = taskRP.ID
	g0PAonRP.Mode = api.RP
	h.stub.creator = h.aPA
	_, err = invoke(h.stub, "RegisterGrant", mustJSON(t, g0PAonRP))
	requireCode(t, err, api.ErrCodeInvalidStructure)

	// Positive BM 2-hop chain: PA -> U -> A1 -> B1 (depth 2 -> 1 -> 0).
	h.stub.creator = h.aPA
	_, err = invoke(h.stub, "RegisterGrant", mustJSON(t, g0BM))
	require.NoError(t, err)

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
	_, err = invoke(h.stub, "RegisterGrant", mustJSON(t, g1BM))
	require.NoError(t, err)

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
	_, err = invoke(h.stub, "RegisterGrant", mustJSON(t, g2BM))
	require.NoError(t, err)
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
	_, err := invoke(h.stub, "ProposeIdentityLink", mustJSON(t, link))
	requireCode(t, err, api.ErrCodeUnauthorized)

	// Positive propose by registrarA -> PENDING with effectiveActive=false.
	h.stub.creator = h.aReg
	_, err = invoke(h.stub, "ProposeIdentityLink", mustJSON(t, link))
	require.NoError(t, err)

	stored, err := get[api.IdentityLink](h.stub, api.Key("link", link.ID))
	require.NoError(t, err)
	assert.Equal(t, api.Pending, stored.Status)
	assert.False(t, stored.EffectiveActive)
	assert.Equal(t, uint64(1), stored.Revision)

	// Source domain self-approval (registrarA) rejected with LINK_APPROVAL_FORBIDDEN.
	h.stub.creator = h.aReg
	_, err = invoke(h.stub, "ApproveIdentityLink", mustJSON(t, api.IdentityLinkApproval{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               link.ID,
		ProposalDigest:   propDigest,
		ExpectedRevision: 1,
		ApprovedAt:       h.now.Unix(),
	}))
	requireCode(t, err, api.ErrCodeLinkApprovalForbidden)

	// Wrong proposalDigest rejected by registrarB with LINK_PROPOSAL_MISMATCH.
	h.stub.creator = h.bReg
	_, err = invoke(h.stub, "ApproveIdentityLink", mustJSON(t, api.IdentityLinkApproval{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               link.ID,
		ProposalDigest:   api.Digest([]byte("tampered")),
		ExpectedRevision: 1,
		ApprovedAt:       h.now.Unix(),
	}))
	requireCode(t, err, api.ErrCodeLinkProposalMismatch)

	// Target registrar (registrarB) approves matching proposalDigest -> ACTIVE & effectiveActive=true.
	_, err = invoke(h.stub, "ApproveIdentityLink", mustJSON(t, api.IdentityLinkApproval{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               link.ID,
		ProposalDigest:   propDigest,
		ExpectedRevision: 1,
		ApprovedAt:       h.now.Unix(),
	}))
	require.NoError(t, err)

	stored, err = get[api.IdentityLink](h.stub, api.Key("link", link.ID))
	require.NoError(t, err)
	assert.Equal(t, api.Active, stored.Status)
	assert.True(t, stored.EffectiveActive)
	assert.Equal(t, uint64(2), stored.Revision)
	assert.Equal(t, "did:web:b.local", stored.ApprovedBy)

	// Unrelated registrar (registrarC) cannot revoke A<->B link.
	h.stub.creator = h.cReg
	_, err = invoke(h.stub, "RevokeIdentityLink", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               link.ID,
		ExpectedRevision: 2,
		Reason:           "unauthorized",
	}))
	requireCode(t, err, api.ErrCodeUnauthorized)

	// Endpoint user U revokes A<->B link -> REVOKED & effectiveActive=false.
	h.stub.creator = h.aU
	_, err = invoke(h.stub, "RevokeIdentityLink", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               link.ID,
		ExpectedRevision: 2,
		Reason:           "user requested unlink",
	}))
	require.NoError(t, err)

	stored, err = get[api.IdentityLink](h.stub, api.Key("link", link.ID))
	require.NoError(t, err)
	assert.Equal(t, api.Revoked, stored.Status)
	assert.False(t, stored.EffectiveActive)
	assert.Equal(t, uint64(3), stored.Revision)

	// Re-approving revoked link fails with LINK_STATE_CONFLICT.
	h.stub.creator = h.bReg
	_, err = invoke(h.stub, "ApproveIdentityLink", mustJSON(t, api.IdentityLinkApproval{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               link.ID,
		ProposalDigest:   propDigest,
		ExpectedRevision: 3,
		ApprovedAt:       h.now.Unix(),
	}))
	requireCode(t, err, api.ErrCodeLinkStateConflict)
}

func TestDomainCertRenewalRevocationAndAuthorityUpdate(t *testing.T) {
	h := newRegistryHarness(t)
	nbf := h.now.Add(-time.Hour).Unix()
	exp := h.now.Add(24 * time.Hour).Unix()

	// 1. Atomic same-key domain cert renewal & claim scope shrink on ACTIVE domain B.
	domB, err := get[api.Domain](h.stub, api.Key("domain", "B"))
	require.NoError(t, err)
	assert.Equal(t, uint64(2), domB.Revision)
	assert.Equal(t, "urn:grad:cert:B", domB.Certification)

	// Non-T caller rejected with TRUST_MANAGEMENT_FORBIDDEN on RevokeCertification / UpdateAuthorityIdentity.
	h.stub.creator = h.bAdmin
	_, err = invoke(h.stub, "RevokeCertification", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "urn:grad:cert:B",
		ExpectedRevision: 1,
	}))
	requireCode(t, err, api.ErrCodeTrustManagementForbidden)

	_, err = invoke(h.stub, "UpdateAuthorityIdentity", mustJSON(t, api.AuthorityIdentityUpdateInput{
		Bound: api.Bound{DeploymentID: h.depID},
		ID:    "did:web:b.local:ib",
	}))
	requireCode(t, err, api.ErrCodeTrustManagementForbidden)

	// Stale expectedCertificationId fails with STATE_CHANGED.
	h.stub.creator = h.tCreator
	certB2 := api.Certify{
		Certification: api.Certification{
			Bound:          api.Bound{DeploymentID: h.depID},
			ID:             "urn:grad:cert:B:v2",
			Domain:         "B",
			RootKeyVersion: 1,
			Digest:         api.Digest([]byte("cert:B:v2")),
			Scopes: []api.IssuerScope{{
				ID:              "did:web:b.local:ib",
				AppKeyVersion:   1,
				CredentialTypes: []string{"EnterpriseIdentityCredential"},
				ClaimNames:      []string{"domain"}, // Shrunk scope: "role" removed.
			}},
			Interval: api.Interval{NBF: nbf, EXP: exp},
		},
		ExpectedRevision:      2,
		ExpectedCertification: "urn:grad:cert:WRONG",
	}
	_, err = invoke(h.stub, "CertifyDomain", mustJSON(t, certB2))
	requireCode(t, err, api.ErrCodeStateChanged)

	certB2.ExpectedCertification = "urn:grad:cert:B"
	_, err = invoke(h.stub, "CertifyDomain", mustJSON(t, certB2))
	require.NoError(t, err)

	domB, err = get[api.Domain](h.stub, api.Key("domain", "B"))
	require.NoError(t, err)
	assert.Equal(t, uint64(3), domB.Revision)
	assert.Equal(t, "urn:grad:cert:B:v2", domB.Certification)
	assert.Equal(t, api.Active, domB.Status)

	// After scope shrink, issuing a credential with removed claim "role" fails; "domain" alone succeeds.
	h.stub.creator = h.bIB
	_, err = invoke(h.stub, "RegisterCredential", mustJSON(t, api.Credential{
		Bound:             api.Bound{DeploymentID: h.depID},
		ID:                "cred-B1-out-of-scope",
		Issuer:            "did:web:b.local:ib",
		Subject:           "did:web:b.local:b1",
		IssuerKeyVersion:  1,
		SubjectKeyVersion: 1,
		Type:              "EnterpriseIdentityCredential",
		ClaimNames:        []string{"domain", "role"},
		Digest:            api.Digest([]byte("cred:B1:out-of-scope")),
		Interval:          api.Interval{NBF: nbf, EXP: exp},
	}))
	requireCode(t, err, api.ErrCodeInvalidStructure)

	_, err = invoke(h.stub, "RegisterCredential", mustJSON(t, api.Credential{
		Bound:             api.Bound{DeploymentID: h.depID},
		ID:                "cred-B1-shrunk",
		Issuer:            "did:web:b.local:ib",
		Subject:           "did:web:b.local:b1",
		IssuerKeyVersion:  1,
		SubjectKeyVersion: 1,
		Type:              "EnterpriseIdentityCredential",
		ClaimNames:        []string{"domain"},
		Digest:            api.Digest([]byte("cred:B1:shrunk")),
		Interval:          api.Interval{NBF: nbf, EXP: exp},
	}))
	require.NoError(t, err)

	// 2. Suspend domain B and resume while cert is valid.
	h.stub.creator = h.tCreator
	_, err = invoke(h.stub, "SetDomainStatus", mustJSON(t, api.DomainStatus{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "B",
		ExpectedRevision: 3,
		Status:           api.Suspended,
	}))
	require.NoError(t, err)

	_, err = invoke(h.stub, "SetDomainStatus", mustJSON(t, api.DomainStatus{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "B",
		ExpectedRevision: 4,
		Status:           api.Active,
	}))
	require.NoError(t, err)

	// 3. Rotate IB key via UpdateAuthorityIdentity, then re-certify B with AppKeyVersion=2.
	ibBefore, err := get[api.Identity](h.stub, api.Key("identity", "did:web:b.local:ib"))
	require.NoError(t, err)
	_, ibPub2 := makeAppKey(t, "did:web:b.local:ib")
	_, ibNewMgmt := makeSerializedCaller(t, "BMsp", "ib-v2")
	_, err = invoke(h.stub, "UpdateAuthorityIdentity", mustJSON(t, api.AuthorityIdentityUpdateInput{
		Bound:              api.Bound{DeploymentID: h.depID},
		ID:                 "did:web:b.local:ib",
		ExpectedRevision:   ibBefore.Revision,
		ExpectedKeyVersion: ibBefore.KeyVersion,
		Management:         ibNewMgmt,
		DocumentDigest:     api.Digest([]byte("doc:ib:v2")),
		KeyID:              "did:web:b.local:ib#key-2",
		PublicKey:          ibPub2,
	}))
	require.NoError(t, err)

	// Attempting CertifyDomain while still specifying old IB AppKeyVersion=1 must fail.
	certB3Bad := api.Certify{
		Certification: api.Certification{
			Bound:          api.Bound{DeploymentID: h.depID},
			ID:             "urn:grad:cert:B:v3-bad",
			Domain:         "B",
			RootKeyVersion: 1,
			Digest:         api.Digest([]byte("cert:B:v3-bad")),
			Scopes: []api.IssuerScope{{
				ID:              "did:web:b.local:ib",
				AppKeyVersion:   1,
				CredentialTypes: []string{"EnterpriseIdentityCredential"},
				ClaimNames:      []string{"domain", "role"},
			}},
			Interval: api.Interval{NBF: nbf, EXP: exp},
		},
		ExpectedRevision:      5,
		ExpectedCertification: "urn:grad:cert:B:v2",
	}
	_, err = invoke(h.stub, "CertifyDomain", mustJSON(t, certB3Bad))
	requireCode(t, err, api.ErrCodeInvalidStructure)

	// Re-certify B with IB AppKeyVersion=2 succeeds.
	certB3 := certB3Bad
	certB3.Certification.ID = "urn:grad:cert:B:v3"
	certB3.Certification.Digest = api.Digest([]byte("cert:B:v3"))
	certB3.Certification.Scopes[0].AppKeyVersion = 2
	_, err = invoke(h.stub, "CertifyDomain", mustJSON(t, certB3))
	require.NoError(t, err)

	// 4. RevokeCertification is irreversible; suspended domain cannot resume once cert is REVOKED; REVOKED domain cannot resume.
	_, err = invoke(h.stub, "RevokeCertification", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "urn:grad:cert:B:v3",
		ExpectedRevision: 1,
	}))
	require.NoError(t, err)

	_, err = invoke(h.stub, "RevokeCertification", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "urn:grad:cert:B:v3",
		ExpectedRevision: 2,
	}))
	requireCode(t, err, api.ErrCodeAlreadyRevoked)

	_, err = invoke(h.stub, "SetDomainStatus", mustJSON(t, api.DomainStatus{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "B",
		ExpectedRevision: 6,
		Status:           api.Suspended,
	}))
	require.NoError(t, err)

	_, err = invoke(h.stub, "SetDomainStatus", mustJSON(t, api.DomainStatus{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "B",
		ExpectedRevision: 7,
		Status:           api.Active,
	}))
	requireCode(t, err, api.ErrCodeInvalidState)

	_, err = invoke(h.stub, "SetDomainStatus", mustJSON(t, api.DomainStatus{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "B",
		ExpectedRevision: 7,
		Status:           api.Revoked,
	}))
	require.NoError(t, err)

	_, err = invoke(h.stub, "SetDomainStatus", mustJSON(t, api.DomainStatus{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "B",
		ExpectedRevision: 8,
		Status:           api.Active,
	}))
	requireCode(t, err, api.ErrCodeInvalidState)
}

func TestIdentityLifecycleRotateAndRecover(t *testing.T) {
	h := newRegistryHarness(t)

	// 1. Self suspends A1; self, domainA admin, registrarB cannot resume; only registrarA can resume.
	h.stub.creator = h.aA1
	_, err := invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "did:web:a.local:a1",
		ExpectedRevision: 1,
		Status:           api.Suspended,
	}))
	require.NoError(t, err)

	for _, attempt := range []struct {
		name    string
		creator []byte
	}{
		{"self", h.aA1},
		{"domain-admin", h.aAdmin},
		{"cross-domain-registrar", h.bReg},
	} {
		h.stub.creator = attempt.creator
		_, err = invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
			Bound:            api.Bound{DeploymentID: h.depID},
			ID:               "did:web:a.local:a1",
			ExpectedRevision: 2,
			Status:           api.Active,
		}))
		requireCode(t, err, api.ErrCodeIdentityManagementForbidden)
	}

	// Same-status transition (SUSPENDED -> SUSPENDED) returns IDENTITY_STATE_CONFLICT.
	h.stub.creator = h.aReg
	_, err = invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "did:web:a.local:a1",
		ExpectedRevision: 2,
		Status:           api.Suspended,
	}))
	requireCode(t, err, api.ErrCodeIdentityStateConflict)

	// Registrar A resumes A1 -> ACTIVE.
	_, err = invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "did:web:a.local:a1",
		ExpectedRevision: 2,
		Status:           api.Active,
	}))
	require.NoError(t, err)

	// Non-T caller cannot manage bootstrap authority IA.
	h.stub.creator = h.aReg
	_, err = invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "did:web:a.local:ia",
		ExpectedRevision: 1,
		Status:           api.Suspended,
	}))
	requireCode(t, err, api.ErrCodeIdentityManagementForbidden)

	// 2. RotateIdentity increments KeyVersion and Revision.
	_, a1Pub2 := makeAppKey(t, "did:web:a.local:a1")
	h.stub.creator = h.aA1
	_, err = invoke(h.stub, "RotateIdentity", mustJSON(t, api.RotateIdentityInput{
		Bound:              api.Bound{DeploymentID: h.depID},
		ID:                 "did:web:a.local:a1",
		ExpectedRevision:   3,
		ExpectedKeyVersion: 1,
		DocumentDigest:     api.Digest([]byte("doc:a1:v2")),
		KeyID:              "did:web:a.local:a1#key-2",
		PublicKey:          a1Pub2,
	}))
	require.NoError(t, err)

	a1After, err := get[api.Identity](h.stub, api.Key("identity", "did:web:a.local:a1"))
	require.NoError(t, err)
	assert.Equal(t, uint64(2), a1After.KeyVersion)
	assert.Equal(t, uint64(4), a1After.Revision)

	// 3. RecoverIdentity on SUSPENDED ordinary identity preserves SUSPENDED status and atomically swaps binding.
	b1Before, err := get[api.Identity](h.stub, api.Key("identity", "did:web:b.local:b1"))
	require.NoError(t, err)

	h.stub.creator = h.bReg
	_, err = invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "did:web:b.local:b1",
		ExpectedRevision: b1Before.Revision,
		Status:           api.Suspended,
	}))
	require.NoError(t, err)

	b1NewCreator, b1NewMgmt := makeSerializedCaller(t, "BMsp", "b1-recovered")
	_, b1Pub2 := makeAppKey(t, "did:web:b.local:b1")
	_, err = invoke(h.stub, "RecoverIdentity", mustJSON(t, api.RecoverIdentityInput{
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
	}))
	require.NoError(t, err)

	b1After, err := get[api.Identity](h.stub, api.Key("identity", "did:web:b.local:b1"))
	require.NoError(t, err)
	assert.Equal(t, api.Suspended, b1After.Status)
	assert.Equal(t, uint64(2), b1After.KeyVersion)
	assert.Equal(t, b1NewMgmt, b1After.Management)
	assert.Equal(t, b1Before.AccountCommitment, b1After.AccountCommitment)

	// Registrar must resume B1 -> ACTIVE before B1 can rotate/operate again.
	h.stub.creator = b1NewCreator
	_, err = invoke(h.stub, "RotateIdentity", mustJSON(t, api.RotateIdentityInput{
		Bound:              api.Bound{DeploymentID: h.depID},
		ID:                 "did:web:b.local:b1",
		ExpectedRevision:   b1After.Revision,
		ExpectedKeyVersion: b1After.KeyVersion,
		DocumentDigest:     api.Digest([]byte("doc:b1:v3")),
		KeyID:              "did:web:b.local:b1#key-3",
		PublicKey:          b1Pub2,
	}))
	requireCode(t, err, api.ErrCodeIdentityStateConflict)

	// Old management certificate can no longer manage B1.
	h.stub.creator = h.bB1
	_, err = invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "did:web:b.local:b1",
		ExpectedRevision: b1After.Revision,
		Status:           api.Revoked,
	}))
	requireCode(t, err, api.ErrCodeIdentityManagementForbidden)

	// 4. Revoke B1 then verify RecoverIdentity and RegisterIdentity re-use both return IDENTITY_STATE_CONFLICT.
	h.stub.creator = h.bReg
	_, err = invoke(h.stub, "SetIdentityStatus", mustJSON(t, api.IdentityStatusInput{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "did:web:b.local:b1",
		ExpectedRevision: b1After.Revision,
		Status:           api.Revoked,
	}))
	require.NoError(t, err)

	_, b1ThirdMgmt := makeSerializedCaller(t, "BMsp", "b1-3")
	_, err = invoke(h.stub, "RecoverIdentity", mustJSON(t, api.RecoverIdentityInput{
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
	}))
	requireCode(t, err, api.ErrCodeIdentityStateConflict)

	b1Revoked := b1After
	b1Revoked.Management = b1ThirdMgmt
	b1Revoked.KeyID = "did:web:b.local:b1#key-1"
	b1Revoked.KeyVersion = 1
	_, err = invoke(h.stub, "RegisterIdentity", mustJSON(t, b1Revoked))
	requireCode(t, err, api.ErrCodeIdentityStateConflict)
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
	_, err := invoke(h.stub, "RegisterTask", mustJSON(t, taskRP))
	require.NoError(t, err)

	g0 := api.Grant{
		Bound:             api.Bound{DeploymentID: h.depID},
		ID:                api.Digest([]byte("lifecycle-g0-rp")),
		Schema:            api.Schema,
		Root:              api.Digest([]byte("lifecycle-g0-rp")),
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
	_, err = invoke(h.stub, "RegisterGrant", mustJSON(t, g0))
	require.NoError(t, err)

	// SuspendGrant -> ResumeGrant preserves original EXP; repeat suspend fails with GRANT_STATE_CONFLICT.
	_, err = invoke(h.stub, "SuspendGrant", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               g0.ID,
		ExpectedRevision: 1,
		ExpectedDigest:   g0.Digest,
	}))
	require.NoError(t, err)

	g0Susp, err := get[api.Grant](h.stub, api.Key("grant", g0.ID))
	require.NoError(t, err)
	assert.Equal(t, api.Suspended, g0Susp.Status)
	assert.Equal(t, exp, g0Susp.EXP)

	_, err = invoke(h.stub, "SuspendGrant", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               g0.ID,
		ExpectedRevision: 2,
		ExpectedDigest:   g0.Digest,
	}))
	requireCode(t, err, api.ErrCodeGrantStateConflict)

	_, err = invoke(h.stub, "ResumeGrant", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               g0.ID,
		ExpectedRevision: 2,
		ExpectedDigest:   g0.Digest,
	}))
	require.NoError(t, err)

	g0Resumed, err := get[api.Grant](h.stub, api.Key("grant", g0.ID))
	require.NoError(t, err)
	assert.Equal(t, api.Active, g0Resumed.Status)
	assert.Equal(t, exp, g0Resumed.EXP)

	// Atomic ReplaceGrant: only issuer may replace; old becomes REVOKED and new becomes ACTIVE atomically.
	g0Next := g0
	g0Next.ID = api.Digest([]byte("lifecycle-g0-rp-v2"))
	g0Next.Root = g0Next.ID
	g0Next.Digest = api.Digest([]byte("lifecycle-g0-jws-v2"))
	g0Next.Interval = api.Interval{NBF: nbf + 1, EXP: exp - 1}

	// Non-issuer (grantee U) rejected with UNAUTHORIZED.
	h.stub.creator = h.aU
	_, err = invoke(h.stub, "ReplaceGrant", mustJSON(t, api.Replacement{
		Old: api.Mutation{
			Bound:            api.Bound{DeploymentID: h.depID},
			ID:               g0.ID,
			ExpectedRevision: 3,
			ExpectedDigest:   g0.Digest,
		},
		New: g0Next,
	}))
	requireCode(t, err, api.ErrCodeUnauthorized)

	// Stale expectedRevision rejected with STATE_CHANGED.
	h.stub.creator = h.cSvc
	_, err = invoke(h.stub, "ReplaceGrant", mustJSON(t, api.Replacement{
		Old: api.Mutation{
			Bound:            api.Bound{DeploymentID: h.depID},
			ID:               g0.ID,
			ExpectedRevision: 1,
			ExpectedDigest:   g0.Digest,
		},
		New: g0Next,
	}))
	requireCode(t, err, api.ErrCodeStateChanged)

	// Positive atomic replacement by issuer C.
	_, err = invoke(h.stub, "ReplaceGrant", mustJSON(t, api.Replacement{
		Old: api.Mutation{
			Bound:            api.Bound{DeploymentID: h.depID},
			ID:               g0.ID,
			ExpectedRevision: 3,
			ExpectedDigest:   g0.Digest,
		},
		New: g0Next,
	}))
	require.NoError(t, err)

	g0Replaced, err := get[api.Grant](h.stub, api.Key("grant", g0.ID))
	require.NoError(t, err)
	assert.Equal(t, api.Revoked, g0Replaced.Status)
	assert.Equal(t, uint64(4), g0Replaced.Revision)

	g0V2, err := get[api.Grant](h.stub, api.Key("grant", g0Next.ID))
	require.NoError(t, err)
	assert.Equal(t, api.Active, g0V2.Status)
	assert.Equal(t, uint64(1), g0V2.Revision)

	// RevokeGrant: unrelated caller (B1) rejected; grantee U can revoke; revoked grant rejects suspend/resume/re-revoke.
	h.stub.creator = h.bB1
	_, err = invoke(h.stub, "RevokeGrant", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               g0Next.ID,
		ExpectedRevision: 1,
		ExpectedDigest:   g0Next.Digest,
	}))
	requireCode(t, err, api.ErrCodeUnauthorized)

	h.stub.creator = h.aU
	_, err = invoke(h.stub, "RevokeGrant", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               g0Next.ID,
		ExpectedRevision: 1,
		ExpectedDigest:   g0Next.Digest,
	}))
	require.NoError(t, err)

	g0V2Revoked, err := get[api.Grant](h.stub, api.Key("grant", g0Next.ID))
	require.NoError(t, err)
	assert.Equal(t, api.Revoked, g0V2Revoked.Status)
	assert.Equal(t, uint64(2), g0V2Revoked.Revision)

	h.stub.creator = h.cSvc
	_, err = invoke(h.stub, "SuspendGrant", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               g0Next.ID,
		ExpectedRevision: 2,
		ExpectedDigest:   g0Next.Digest,
	}))
	requireCode(t, err, api.ErrCodeAlreadyRevoked)

	// CancelTask is terminal CANCELLED and rejects repeat cancel with TASK_STATE_CONFLICT.
	h.stub.creator = h.aU
	_, err = invoke(h.stub, "CancelTask", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               taskRP.ID,
		ExpectedRevision: 1,
		ExpectedDigest:   taskRP.Digest,
	}))
	require.NoError(t, err)

	_, err = invoke(h.stub, "CancelTask", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               taskRP.ID,
		ExpectedRevision: 2,
		ExpectedDigest:   taskRP.Digest,
	}))
	requireCode(t, err, api.ErrCodeTaskStateConflict)

	// RevokeCredential works even when issuer's domain B is REVOKED, and repeat revoke returns ALREADY_REVOKED.
	h.stub.creator = h.tCreator
	_, err = invoke(h.stub, "SetDomainStatus", mustJSON(t, api.DomainStatus{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "B",
		ExpectedRevision: 2,
		Status:           api.Revoked,
	}))
	require.NoError(t, err)

	h.stub.creator = h.bIB
	_, err = invoke(h.stub, "RevokeCredential", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "cred-B1",
		ExpectedRevision: 1,
	}))
	require.NoError(t, err)

	credB1, err := get[api.Credential](h.stub, api.Key("credential", "cred-B1"))
	require.NoError(t, err)
	assert.Equal(t, api.Revoked, credB1.Status)
	assert.Equal(t, uint64(2), credB1.Revision)

	_, err = invoke(h.stub, "RevokeCredential", mustJSON(t, api.Mutation{
		Bound:            api.Bound{DeploymentID: h.depID},
		ID:               "cred-B1",
		ExpectedRevision: 2,
	}))
	requireCode(t, err, api.ErrCodeAlreadyRevoked)
}
