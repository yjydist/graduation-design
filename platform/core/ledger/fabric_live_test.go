//go:build fabriclive

package ledger

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	gw "github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset/kvrwset"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	grpcpeer "google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"grad/protocol"
	"grad/protocol/registry"
)

type liveFixtures struct {
	Domains        map[string]registry.DomainBootstrap
	Certifications map[string]registry.Certify
	Identities     map[string]registry.Identity
	Credentials    map[string]registry.Credential
	Task           registry.Task
	G0             registry.Grant
	G1             registry.Grant
}

type liveHarness struct {
	t   *testing.T
	ctx context.Context
	i   *Instance
	d   *Deployment
	j   Journal
	v   View
	p   *PeerClient
	f   *liveFixtures
	id  string
}

func openLiveHarness(t *testing.T) *liveHarness {
	t.Helper()
	dir := os.Getenv("FABRIC_INSTANCE")
	if dir == "" {
		t.Skip("set FABRIC_INSTANCE to a running Fabric instance directory")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	t.Cleanup(cancel)

	inst, err := OpenInstance(dir)
	require.NoError(t, err)
	dep, err := inst.Deploy(ctx, false)
	require.NoError(t, err)
	db, err := inst.Database(ctx)
	require.NoError(t, err)
	t.Cleanup(db.Close)
	require.NoError(t, EnsureSchema(ctx, db))
	p, err := inst.Peer("c", "read")
	require.NoError(t, err)
	t.Cleanup(p.Close)

	h := &liveHarness{
		t:   t,
		ctx: ctx,
		i:   inst,
		d:   dep,
		j:   NewJournal(inst, db, dep.DeploymentID),
		v:   View{DB: db, Deployment: dep},
		p:   p,
		id:  "live-" + randomID()[:12],
	}
	h.seedMinimalFixtures()
	return h
}

func mustJSON(v any) []byte {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func livePublicKey(t *testing.T) string {
	t.Helper()
	k, err := protocol.GenerateP256Key()
	require.NoError(t, err)
	hexPub, err := protocol.FormatAppPublicKey(&k.PublicKey)
	require.NoError(t, err)
	return hexPub
}

func (h *liveHarness) seedMinimalFixtures() {
	h.t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	iv := registry.Interval{NBF: now.Add(-time.Hour).Unix(), EXP: now.Add(24 * time.Hour).Unix()}
	bound := registry.Bound{DeploymentID: h.d.DeploymentID}

	roleMgmt := func(role string) registry.Management {
		_, m, _, err := h.i.Role(role)
		require.NoError(h.t, err)
		return m
	}
	mkID := func(did, dom, kind, role string) registry.Identity {
		pub := livePublicKey(h.t)
		return registry.Identity{
			Bound:             bound,
			ID:                did,
			Domain:            dom,
			Kind:              kind,
			Management:        roleMgmt(role),
			DocumentDigest:    registry.Digest([]byte("doc:" + did)),
			KeyID:             did + "#key-1",
			KeyVersion:        1,
			PublicKey:         pub,
			AccountCommitment: registry.Digest([]byte("acct:" + did)),
		}
	}

	f := &liveFixtures{
		Domains:        map[string]registry.DomainBootstrap{},
		Certifications: map[string]registry.Certify{},
		Identities:     map[string]registry.Identity{},
		Credentials:    map[string]registry.Credential{},
	}

	ensure := func(key, role, method string, val any) {
		op, err := h.j.Write(h.ctx, "live-seed/"+key, role, method, mustJSON(val))
		require.NoError(h.t, err)
		if op.Status == "CONFIRMED" && op.Commit != nil && op.Commit.Code == "VALID" {
			require.NoError(h.t, h.i.AwaitEndorsers(h.ctx, *op.Commit))
			return
		}
		if op.FailureCode != nil && *op.FailureCode == registry.ErrCodeIDAlreadyUsed {
			return
		}
		h.t.Fatalf("seed %s failed: status=%s code=%v obs=%s", key, op.Status, op.FailureCode, op.Observation)
	}

	domIssuerScope := map[string]registry.IssuerScope{}
	domInterval := map[string]registry.Interval{}
	for _, dom := range []struct {
		id, did, admin, reg, issuer, issuerDID string
	}{
		{"A", "did:web:a.local", "domainA", "registrarA", "IA", "did:web:a.local:ia"},
		{"C", "did:web:c.local", "domainC", "registrarC", "IC", "did:web:c.local:ic"},
	} {
		domID := mkID(dom.did, dom.id, "DOMAIN", dom.admin)
		issID := mkID(dom.issuerDID, dom.id, "ISSUER", dom.issuer)
		db := registry.DomainBootstrap{
			Domain: registry.Domain{
				Bound:     bound,
				ID:        dom.id,
				DID:       dom.did,
				Admin:     roleMgmt(dom.admin),
				Registrar: roleMgmt(dom.reg),
			},
			Identity: domID,
			Issuers:  []registry.Identity{issID},
		}
		f.Domains[dom.id] = db
		curDom, dErr := ReadLedgerRecord[registry.Domain](h.ctx, h.p, "domain", dom.id)
		if IsMissingRecord(dErr) {
			ensure("domain-"+dom.id, "T", "BootstrapDomain", db)
			curDom, dErr = ReadLedgerRecord[registry.Domain](h.ctx, h.p, "domain", dom.id)
		}
		require.NoError(h.t, dErr)

		cert := registry.Certify{
			Certification: registry.Certification{
				Bound:          bound,
				ID:             "live-cert-" + dom.id,
				Domain:         dom.id,
				RootKeyVersion: 1,
				Digest:         registry.Digest([]byte("live-cert-" + dom.id)),
				Scopes: []registry.IssuerScope{{
					ID:              dom.issuerDID,
					AppKeyVersion:   1,
					CredentialTypes: []string{"EnterpriseIdentityCredential"},
					ClaimNames:      []string{"domain", "role"},
				}},
				Interval: iv,
			},
			ExpectedRevision: curDom.Revision,
		}
		f.Certifications[dom.id] = cert
		if curDom.Certification == "" {
			ensure("cert-"+dom.id, "T", "CertifyDomain", cert)
			curDom, dErr = ReadLedgerRecord[registry.Domain](h.ctx, h.p, "domain", dom.id)
			require.NoError(h.t, dErr)
		}
		storedCert, cErr := ReadLedgerRecord[registry.Certification](h.ctx, h.p, "certification", curDom.Certification)
		require.NoError(h.t, cErr)
		require.NotEmpty(h.t, storedCert.Scopes)
		domIssuerScope[dom.id] = storedCert.Scopes[0]
		domInterval[dom.id] = storedCert.Interval
	}

	// Clamp shared task/grant validity strictly within both domains' active certification intervals.
	sharedIV := iv
	for _, div := range domInterval {
		if div.NBF > sharedIV.NBF {
			sharedIV.NBF = div.NBF
		}
		if div.EXP < sharedIV.EXP {
			sharedIV.EXP = div.EXP
		}
	}

	for _, entry := range []struct {
		role, did, dom, kind, reg, issuer string
	}{
		{"U", SubjectU, "A", "USER", "registrarA", "IA"},
		{"A1", "did:web:a.local:a1", "A", "AGENT", "registrarA", "IA"},
		{"alt", "did:web:a.local:other", "A", "USER", "registrarA", "IA"},
		{"C", SubjectC, "C", "SERVICE", "registrarC", "IC"},
	} {
		storedID, idErr := ReadLedgerRecord[registry.Identity](h.ctx, h.p, "identity", entry.did)
		if IsMissingRecord(idErr) {
			id := mkID(entry.did, entry.dom, entry.kind, entry.role)
			ensure("id-"+entry.role, entry.reg, "RegisterIdentity", id)
			storedID, idErr = ReadLedgerRecord[registry.Identity](h.ctx, h.p, "identity", entry.did)
		}
		require.NoError(h.t, idErr)
		f.Identities[entry.role] = storedID

		credID := "live-cred-" + entry.role
		storedCred, cErr := ReadLedgerRecord[registry.Credential](h.ctx, h.p, "credential", credID)
		if IsMissingRecord(cErr) {
			scope := domIssuerScope[entry.dom]
			credType := "EnterpriseIdentityCredential"
			if len(scope.CredentialTypes) > 0 {
				credType = scope.CredentialTypes[0]
			}
			claimNames := scope.ClaimNames
			if len(claimNames) == 0 {
				claimNames = []string{"domain", "role"}
			}
			cred := registry.Credential{
				Bound:             bound,
				ID:                credID,
				Issuer:            scope.ID,
				Subject:           entry.did,
				IssuerKeyVersion:  scope.AppKeyVersion,
				SubjectKeyVersion: storedID.KeyVersion,
				Type:              credType,
				ClaimNames:        claimNames,
				Digest:            registry.Digest([]byte(credID)),
				Interval:          sharedIV,
			}
			ensure("cred-"+entry.role, entry.issuer, "RegisterCredential", cred)
			storedCred, cErr = ReadLedgerRecord[registry.Credential](h.ctx, h.p, "credential", credID)
		}
		require.NoError(h.t, cErr)
		f.Credentials[entry.role] = storedCred
	}

	liveTaskID := registry.Digest([]byte("live-task-1"))
	if storedTask, tErr := ReadLedgerRecord[registry.Task](h.ctx, h.p, "task", liveTaskID); tErr == nil {
		f.Task = storedTask
	} else {
		f.Task = registry.Task{
			Bound:             bound,
			ID:                liveTaskID,
			Creator:           f.Identities["U"].ID,
			CreatorCredential: f.Credentials["U"].ID,
			CreatorKeyVersion: f.Identities["U"].KeyVersion,
			Domain:            "A",
			Mode:              registry.RP,
			Resource:          h.d.Bootstrap.ResourceID,
			Digest:            registry.Digest([]byte("live-task-1-spec")),
			Interval:          sharedIV,
		}
		ensure("task-1", "U", "RegisterTask", f.Task)
	}

	liveG0ID := registry.Digest([]byte("live-g0"))
	if storedG0, gErr := ReadLedgerRecord[registry.Grant](h.ctx, h.p, "grant", liveG0ID); gErr == nil {
		f.G0 = storedG0
	} else {
		f.G0 = registry.Grant{
			Bound:             bound,
			ID:                liveG0ID,
			Schema:            registry.Schema,
			Root:              liveG0ID,
			Task:              f.Task.ID,
			Mode:              registry.RP,
			Domain:            "A",
			Resource:          h.d.Bootstrap.ResourceID,
			Issuer:            f.Identities["C"].ID,
			Grantee:           f.Identities["U"].ID,
			IssuerKeyVersion:  f.Identities["C"].KeyVersion,
			GranteeKeyVersion: f.Identities["U"].KeyVersion,
			IssuerCredential:  f.Credentials["C"].ID,
			GranteeCredential: f.Credentials["U"].ID,
			Depth:             2,
			Digest:            registry.Digest([]byte("live-g0-doc")),
			Interval:          sharedIV,
		}
		ensure("g0", "C", "RegisterGrant", f.G0)
	}

	liveG1ID := registry.Digest([]byte("live-g1"))
	if storedG1, gErr := ReadLedgerRecord[registry.Grant](h.ctx, h.p, "grant", liveG1ID); gErr == nil {
		f.G1 = storedG1
	} else {
		f.G1 = registry.Grant{
			Bound:             bound,
			ID:                liveG1ID,
			Schema:            registry.Schema,
			Parent:            f.G0.ID,
			ParentDigest:      f.G0.Digest,
			Root:              f.G0.ID,
			Task:              f.Task.ID,
			Mode:              registry.RP,
			Domain:            "A",
			Resource:          h.d.Bootstrap.ResourceID,
			Issuer:            f.Identities["U"].ID,
			Grantee:           f.Identities["A1"].ID,
			IssuerKeyVersion:  f.Identities["U"].KeyVersion,
			GranteeKeyVersion: f.Identities["A1"].KeyVersion,
			IssuerCredential:  f.Credentials["U"].ID,
			GranteeCredential: f.Credentials["A1"].ID,
			Depth:             1,
			Digest:            registry.Digest([]byte("live-g1-doc")),
			Interval:          sharedIV,
		}
		ensure("g1", "U", "RegisterGrant", f.G1)
	}
	h.f = f
}

func (h *liveHarness) op(label, role, method string, value any, expected string) (*Operation, error) {
	op, err := h.j.Write(h.ctx, h.id+"/"+label, role, method, mustJSON(value))
	if err != nil {
		return op, err
	}
	return op, ExpectOperation(op, expected)
}

func (h *liveHarness) prepared(label, role, method string, value any, orgs ...string) (*Operation, error) {
	op, err := h.j.Prepare(h.ctx, h.id+"/"+label, role, method, mustJSON(value), orgs...)
	if err == nil && (op.Status != "PENDING" || len(op.Signed) == 0 || op.BroadcastAt != nil) {
		err = fmt.Errorf("expected signed unbroadcast transaction: %s (%s)", label, op.Observation)
	}
	return op, err
}

func (h *liveHarness) finish(op *Operation, expected string) (*Operation, error) {
	op, err := h.j.Recover(h.ctx, op.Key, nil)
	if err != nil {
		return op, err
	}
	return op, ExpectOperation(op, expected)
}

func (h *liveHarness) cloneGrant(label string) registry.Grant {
	g := h.f.G1
	g.ID = registry.Digest([]byte(h.id + "/" + label))
	g.Digest = registry.Digest([]byte("grant:" + g.ID))
	return g
}

func liveRevokeOf(g registry.Grant) registry.Mutation {
	rev := g.Revision
	if rev == 0 {
		rev = 1
	}
	return registry.Mutation{Bound: g.Bound, ID: g.ID, ExpectedRevision: rev, ExpectedDigest: g.Digest}
}

func (h *liveHarness) absent(kind, id string) error {
	_, err := h.p.Direct(h.ctx, registry.Registry, "Read", registry.Key(kind, id))
	if !IsMissingRecord(err) {
		return fmt.Errorf("expected absent %s/%s: %v", kind, id, err)
	}
	return nil
}

func (h *liveHarness) newRuntime() *Online {
	return &Online{
		View:      h.v,
		Instance:  h.i,
		Role:      "probe1",
		Interval:  registry.ProbeInterval,
		TimeLimit: registry.ProbeLifetime,
	}
}

func (h *liveHarness) waitApplied(blockNo uint64) error {
	return Poll(h.ctx, 8*time.Second, func() (bool, error) {
		head, err := h.v.Head(h.ctx, h.v.DB, false)
		return head != nil && head.Number >= blockNo, err
	})
}

func (h *liveHarness) applyThrough(height uint64) error {
	last, err := h.v.Head(h.ctx, h.v.DB, false)
	if err != nil {
		return err
	}
	start := uint64(0)
	if last != nil {
		start = last.Number + 1
	}
	for n := start; n <= height; n++ {
		b, err := h.p.GetBlock(h.ctx, n)
		if err != nil {
			return err
		}
		if err := h.v.Apply(h.ctx, b, nil); err != nil {
			return err
		}
	}
	return nil
}

func liveTimedProposal(p *PeerClient, method string, arg []byte, timestamp time.Time) (*pb.SignedProposal, error) {
	_, raw, err := p.Proposal(method, arg, nil)
	if err != nil {
		return nil, err
	}
	w, err := decodeProto(raw, &gw.ProposedTransaction{})
	if err != nil {
		return nil, err
	}
	proposal, err := decodeProto(w.Proposal.ProposalBytes, &pb.Proposal{})
	if err != nil {
		return nil, err
	}
	hdr, err := decodeProto(proposal.Header, &cb.Header{})
	if err != nil {
		return nil, err
	}
	ch, err := decodeProto(hdr.ChannelHeader, &cb.ChannelHeader{})
	if err != nil {
		return nil, err
	}
	ch.Timestamp = timestamppb.New(timestamp)
	hdr.ChannelHeader, err = proto.Marshal(ch)
	if err != nil {
		return nil, err
	}
	proposal.Header, err = proto.Marshal(hdr)
	if err != nil {
		return nil, err
	}
	body, err := proto.Marshal(proposal)
	if err != nil {
		return nil, err
	}
	sig, err := p.signer(digestBytes(body))
	return &pb.SignedProposal{ProposalBytes: body, Signature: sig}, err
}

func TestFabricLiveChannelAndBFT(t *testing.T) {
	h := openLiveHarness(t)

	b, err := h.p.GetBlock(h.ctx, 0)
	require.NoError(t, err)
	for _, org := range []string{"a", "b", "c"} {
		peer, err := h.i.Peer(org, "read")
		require.NoError(t, err)
		seen, err := peer.GetBlock(h.ctx, 0)
		peer.Close()
		require.NoError(t, err)
		require.Equal(t, b.Hash, seen.Hash)
	}
	pl, _, err := EnvelopeHeader(b.Transactions[0].Envelope)
	require.NoError(t, err)
	cfg, err := decodeProto(pl.Data, &cb.ConfigEnvelope{})
	require.NoError(t, err)
	orderer := cfg.GetConfig().GetChannelGroup().GetGroups()["Orderer"]
	consensus, err := decodeProto(orderer.GetValues()["ConsensusType"].GetValue(), &ab.ConsensusType{})
	require.NoError(t, err)
	require.Equal(t, "BFT", consensus.Type)
	mapping, err := decodeProto(orderer.GetValues()["Orderers"].GetValue(), &cb.Orderers{})
	require.NoError(t, err)
	require.Len(t, mapping.ConsenterMapping, 4)

	policy, err := decodeProto(orderer.GetPolicies()["BlockValidation"].GetPolicy().GetValue(), &cb.SignaturePolicyEnvelope{})
	require.NoError(t, err)
	require.Equal(t, int32(3), policy.GetRule().GetNOutOf().GetN())
	require.Len(t, policy.GetIdentities(), 4)

	// Unadmitted rogue client write and Deliver read are rejected.
	rogue, err := h.i.Peer("c", "rogue")
	require.NoError(t, err)
	defer rogue.Close()
	_, writeErr := rogue.Direct(h.ctx, registry.Registry, "RegisterTask", string(mustJSON(h.f.Task)))
	require.Error(t, writeErr)
	require.Contains(t, writeErr.Error(), "access denied")

	c, cancel := context.WithTimeout(h.ctx, 4*time.Second)
	defer cancel()
	stream, err := rogue.Deliver(c, 0, 0)
	require.NoError(t, err)
	_, err = ReceiveBlock(stream)
	require.Error(t, err)
	require.Contains(t, err.Error(), "FORBIDDEN")

	// Rogue orderer authentication check.
	addr, err := h.i.Port("FABRIC_ORDERER_A")
	require.NoError(t, err)
	dir := filepath.Join(h.i.Dir(), "crypto", "ordererOrganizations")
	conn, err := DialTLS(addr, "orderer-a", filepath.Join(dir, "oa.local", "orderers", "orderer-a.oa.local", "tls", "ca.crt"))
	require.NoError(t, err)
	defer conn.Close()
	stepCtx, stepCancel := context.WithTimeout(h.ctx, 4*time.Second)
	defer stepCancel()
	stepStream, err := ab.NewClusterNodeServiceClient(conn).Step(stepCtx)
	require.NoError(t, err)
	gp, ok := grpcpeer.FromContext(stepStream.Context())
	require.True(t, ok)
	tlsInfo, ok := gp.AuthInfo.(credentials.TLSInfo)
	require.True(t, ok)
	req := &ab.NodeAuthRequest{Version: 0, FromId: 5, ToId: 1, Timestamp: timestamppb.Now(), Channel: registry.Channel}
	ts := binary.LittleEndian.AppendUint64(nil, uint64(req.Timestamp.Seconds))
	fields := bytes.Join([][]byte{[]byte("0"), ts, []byte("5"), []byte("1"), []byte(registry.Channel)}, nil)
	req.SessionBinding, err = tlsInfo.State.ExportKeyingMaterial("orderer v3 authentication label", digestBytes(fields), 32)
	require.NoError(t, err)
	toSign, err := asn1.Marshal(struct {
		Version           int64
		Timestamp         []byte
		From, To, Channel string
		Binding           []byte
	}{0, ts, "5", "1", registry.Channel, req.SessionBinding})
	require.NoError(t, err)
	keys, err := filepath.Glob(filepath.Join(dir, "ox.local", "orderers", "orderer-rogue.ox.local", "msp", "keystore", "*"))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	pemBytes, err := os.ReadFile(keys[0])
	require.NoError(t, err)
	key, err := identity.PrivateKeyFromPEM(pemBytes)
	require.NoError(t, err)
	sign, err := identity.NewPrivateKeySign(key)
	require.NoError(t, err)
	req.Signature, err = sign(digestBytes(toSign))
	require.NoError(t, err)
	require.NoError(t, stepStream.Send(&ab.ClusterNodeServiceStepRequest{Payload: &ab.ClusterNodeServiceStepRequest_NodeAuthrequest{NodeAuthrequest: req}}))
	_, err = stepStream.Recv()
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestFabricLiveDeploymentBindingAndResume(t *testing.T) {
	h := openLiveHarness(t)

	for _, tc := range []struct {
		name   string
		modify func(*Deployment)
	}{
		{"channel", func(d *Deployment) { d.ChannelID = "wrong-channel" }},
		{"genesis", func(d *Deployment) {
			d.GenesisHash = randomID()
			d.DeploymentID = d.DeploymentFields.DeploymentID()
			d.Bootstrap.GenesisHash = d.GenesisHash
		}},
		{"instance", func(d *Deployment) {
			d.InstanceID = randomID()
			d.DeploymentID = d.DeploymentFields.DeploymentID()
			d.Bootstrap.InstanceID = d.InstanceID
		}},
		{"root", func(d *Deployment) { d.Bootstrap.Root.DocumentDigest = randomID() }},
		{"policy", func(d *Deployment) { d.ConfigDigest = randomID() }},
		{"definition", func(d *Deployment) { d.DefinitionDigest = randomID() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := *h.d
			tc.modify(&bad)
			err := bad.ValidatePeer(h.ctx, h.p)
			require.ErrorIs(t, err, ErrDeploymentMismatch)
		})
	}

	// Wrong deploymentId grant is rejected.
	old := h.cloneGrant("old-deployment")
	old.DeploymentID = randomID()
	_, err := h.op("old-deployment", "U", "RegisterGrant", old, registry.ErrCodeInvalidStructure)
	require.NoError(t, err)
	require.NoError(t, h.absent("grant", old.ID))

	// Repeat Initialize is rejected with ID_ALREADY_USED.
	raw, err := os.ReadFile(h.i.RegistryPath("bootstrap.json"))
	require.NoError(t, err)
	repeat, err := h.j.Write(h.ctx, h.id+"/repeat-init", "init", "Initialize", raw)
	require.NoError(t, err)
	require.NoError(t, ExpectOperation(repeat, registry.ErrCodeIDAlreadyUsed))
}

func TestFabricLiveRolesPathAndMutations(t *testing.T) {
	h := openLiveHarness(t)

	// Non-T domain bootstrap / certify rejected.
	_, err := h.op("non-t-bootstrap", "registrarA", "BootstrapDomain", h.f.Domains["A"], registry.ErrCodeUnauthorized)
	require.NoError(t, err)
	_, err = h.op("non-t-certify", "registrarA", "CertifyDomain", h.f.Certifications["A"], registry.ErrCodeUnauthorized)
	require.NoError(t, err)

	// Revocation and atomic 2-write ReplaceGrant.
	g := h.cloneGrant("revoke")
	_, err = h.op("register-revoke", "U", "RegisterGrant", g, "VALID")
	require.NoError(t, err)
	m := liveRevokeOf(g)
	_, err = h.op("revoke-T", "T", "RevokeGrant", m, registry.ErrCodeUnauthorized)
	require.NoError(t, err)
	_, err = h.op("revoke-grantee", "A1", "RevokeGrant", m, "VALID")
	require.NoError(t, err)
	gone, err := ReadLedgerRecord[registry.Grant](h.ctx, h.p, "grant", g.ID)
	require.NoError(t, err)
	require.Equal(t, registry.Revoked, gone.Status)
	require.Equal(t, uint64(2), gone.Revision)
	_, err = h.op("reuse-terminal", "U", "RegisterGrant", g, registry.ErrCodeIDAlreadyUsed)
	require.NoError(t, err)

	oldG, nextG := h.cloneGrant("old"), h.cloneGrant("new")
	_, err = h.op("register-old", "U", "RegisterGrant", oldG, "VALID")
	require.NoError(t, err)
	rep := registry.Replacement{Old: liveRevokeOf(oldG), New: nextG}
	_, err = h.op("replace-grantee", "A1", "ReplaceGrant", rep, registry.ErrCodeUnauthorized)
	require.NoError(t, err)
	res, err := h.op("replace-issuer", "U", "ReplaceGrant", rep, "VALID")
	require.NoError(t, err)
	blk, err := h.p.GetBlock(h.ctx, res.Commit.Number)
	require.NoError(t, err)
	require.Len(t, blk.Transactions[res.Commit.Index].Writes, 2)
}

func TestFabricLiveTimestampsConcurrencyAndReplay(t *testing.T) {
	h := openLiveHarness(t)

	// Backfilled proposal time rejected by Peer.
	pU, err := h.i.Peer("c", "U")
	require.NoError(t, err)
	defer pU.Close()
	backfill := time.Now().Add(-12 * time.Second)
	prop, err := liveTimedProposal(pU, "RegisterGrant", mustJSON(h.cloneGrant("backfill")), backfill)
	require.NoError(t, err)
	resp, rpcErr := pb.NewEndorserClient(pU.Conn()).ProcessProposal(h.ctx, prop)
	require.True(t, rpcErr != nil || resp.GetResponse().GetStatus() != 200)

	// Concurrent idempotent Prepare returns identical TxID & signed bytes; changed input conflicts.
	g := h.cloneGrant("concurrent")
	key := h.id + "/concurrent"
	var ops [2]*Operation
	var errs [2]error
	var wg sync.WaitGroup
	for n := range ops {
		wg.Go(func() { ops[n], errs[n] = h.j.Prepare(h.ctx, key, "U", "RegisterGrant", mustJSON(g)) })
	}
	wg.Wait()
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
	require.Equal(t, ops[0].TxID, ops[1].TxID)
	require.Equal(t, ops[0].Signed, ops[1].Signed)

	bad := g
	bad.Digest = randomID()
	_, err = h.j.Prepare(h.ctx, key, "U", "RegisterGrant", mustJSON(bad))
	require.Error(t, err)
	require.Contains(t, err.Error(), "OPERATION_KEY_CONFLICT")

	_, err = h.finish(ops[0], "VALID")
	require.NoError(t, err)

	// MVCC revision race maps to STATE_CHANGED.
	revoke, err := h.prepared("race-revoke", "A1", "RevokeGrant", liveRevokeOf(g))
	require.NoError(t, err)
	replace, err := h.prepared("race-replace", "U", "ReplaceGrant", registry.Replacement{Old: liveRevokeOf(g), New: h.cloneGrant("race-next")})
	require.NoError(t, err)
	_, err = h.finish(revoke, "VALID")
	require.NoError(t, err)
	invalid, err := h.finish(replace, "MVCC_READ_CONFLICT")
	require.NoError(t, err)
	require.NotNil(t, invalid.FailureCode)
	require.Equal(t, registry.ErrCodeStateChanged, *invalid.FailureCode)

	// Lost submit response followed by recovery preserves original VALID commit.
	gLost := h.cloneGrant("lost-resp")
	before, err := h.prepared("lost-resp", "U", "RegisterGrant", gLost)
	require.NoError(t, err)
	pending, err := h.j.Recover(h.ctx, before.Key, func(ctx context.Context, tx *client.Transaction) error {
		if _, err := tx.SubmitWithContext(ctx); err != nil {
			return err
		}
		return status.Error(codes.Unavailable, "injected loss")
	})
	require.NoError(t, err)
	require.NoError(t, ExpectOperation(pending, "PENDING"))
	final, err := h.finish(pending, "VALID")
	require.NoError(t, err)
	require.Equal(t, before.TxID, final.TxID)
}

func TestFabricLiveViewFaultsAndProbes(t *testing.T) {
	h := openLiveHarness(t)

	// Isolated deployment view fault tests.
	depCopy := *h.d
	depCopy.DeploymentID = "injected-view-" + h.id
	v := View{DB: h.v.DB, Deployment: &depCopy}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for _, name := range []string{"fabric_version", "fabric_current", "fabric_block", "fabric_head"} {
			_, _ = v.DB.Exec(ctx, "DELETE FROM "+name+" WHERE deployment=$1", depCopy.DeploymentID)
		}
	})

	var blocks []*Block
	for n := uint64(0); n < 4; n++ {
		b, err := h.p.GetBlock(h.ctx, n)
		require.NoError(t, err)
		blocks = append(blocks, b)
	}
	require.NoError(t, v.Apply(h.ctx, blocks[0], nil))
	require.Error(t, v.Apply(h.ctx, blocks[2], nil))

	corrupt := proto.CloneOf(blocks[1].Raw)
	corrupt.Header.DataHash[0] ^= 1
	_, err := ParseBlock(corrupt)
	require.Error(t, err)

	// Atomicity rollback on beforeCommit hook failure.
	injected := *blocks[1]
	key := "injected-key"
	write := func(val string) []*kvrwset.KVWrite { return []*kvrwset.KVWrite{{Key: key, Value: []byte(val)}} }
	injected.Transactions = []BlockTx{
		{ID: "first", Index: 0, Code: pb.TxValidationCode_VALID, Writes: write("one")},
		{ID: "invalid", Index: 1, Code: pb.TxValidationCode_MVCC_READ_CONFLICT, Writes: write("wrong")},
		{ID: "last", Index: 2, Code: pb.TxValidationCode_VALID, Writes: write("two")},
	}
	stopErr := errors.New("injected interruption")
	require.ErrorIs(t, v.Apply(h.ctx, &injected, func() error { return stopErr }), stopErr)
	head, err := v.Head(h.ctx, v.DB, false)
	require.NoError(t, err)
	require.Equal(t, uint64(0), head.Number)

	// Idempotent replay applies only VALID writes in tx_index order.
	require.NoError(t, v.Apply(h.ctx, &injected, nil))
	require.NoError(t, v.Apply(h.ctx, &injected, nil))
	var curVal []byte
	require.NoError(t, v.DB.QueryRow(h.ctx, "SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2", depCopy.DeploymentID, key).Scan(&curVal))
	require.Equal(t, "two", string(curVal))

	// Online runtime interleaved snapshot across revocation + historical audit.
	rt := h.newRuntime()
	stop, err := rt.Start(h.ctx)
	require.NoError(t, err)
	defer stop()
	waitCtx, waitCancel := context.WithTimeout(h.ctx, 15*time.Second)
	_, err = rt.WaitOnline(waitCtx, h.f.G1.ID)
	waitCancel()
	require.NoError(t, err)

	g := h.cloneGrant("interleaved")
	created, err := h.op("interleaved-create", "U", "RegisterGrant", g, "VALID")
	require.NoError(t, err)
	require.NoError(t, h.i.AwaitEndorsers(h.ctx, *created.Commit))
	require.NoError(t, h.waitApplied(created.Commit.Number))

	var revoked *Operation
	oldSnap, err := h.v.RawSnapshot(h.ctx, g.ID, nil, rt, func() error {
		op, err := h.op("interleaved-revoke", "A1", "RevokeGrant", liveRevokeOf(g), "VALID")
		revoked = op
		if err != nil {
			return err
		}
		return h.waitApplied(revoked.Commit.Number)
	})
	require.NoError(t, err)
	require.Equal(t, registry.Active, oldSnap.Grants[0].Status)
	require.Less(t, oldSnap.Number, revoked.Commit.Number)

	histActive, err := h.v.RawSnapshot(h.ctx, g.ID, &oldSnap.Number, nil, nil)
	require.NoError(t, err)
	require.Equal(t, registry.Active, histActive.Grants[0].Status)
	require.Nil(t, histActive.Probe)

	histRevoked, err := h.v.RawSnapshot(h.ctx, g.ID, &revoked.Commit.Number, nil, nil)
	require.NoError(t, err)
	require.Equal(t, registry.Revoked, histRevoked.Grants[0].Status)

	// Checkpoint query outage error classification.
	last, err := h.v.Head(h.ctx, h.v.DB, false)
	require.NoError(t, err)
	require.NotNil(t, last)
	addr, err := h.i.Port("FABRIC_PEER_C")
	require.NoError(t, err)
	heightStr := strconv.FormatUint(last.Number, 10)
	var injectedCode codes.Code
	intercept := func(ctx context.Context, method string, req, reply any, conn *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if method == pb.Endorser_ProcessProposal_FullMethodName {
			p, err := decodeProto(req.(*pb.SignedProposal).GetProposalBytes(), &pb.Proposal{})
			if err == nil {
				pl, err := decodeProto(p.Payload, &pb.ChaincodeProposalPayload{})
				if err == nil {
					spec, err := decodeProto(pl.Input, &pb.ChaincodeInvocationSpec{})
					if err == nil {
						args := spec.GetChaincodeSpec().GetInput().GetArgs()
						if spec.GetChaincodeSpec().GetChaincodeId().GetName() == "qscc" && len(args) == 3 &&
							string(args[0]) == "GetBlockByNumber" && string(args[2]) == heightStr {
							return status.Error(injectedCode, "injected checkpoint query failure")
						}
					}
				}
			}
		}
		return invoke(ctx, method, req, reply, conn, opts...)
	}
	conn, err := DialTLS(addr, "peer-c", h.i.PeerTLS("c"), grpc.WithUnaryInterceptor(intercept))
	require.NoError(t, err)
	defer conn.Close()
	reader := *h.p
	reader.conn = conn
	rtCheck := h.newRuntime()
	for _, tc := range []struct {
		code codes.Code
		want error
	}{
		{codes.Unavailable, ErrStale},
		{codes.NotFound, ErrUnavailable},
	} {
		injectedCode = tc.code
		ctx, cancel := context.WithTimeout(h.ctx, 8*time.Second)
		fetchErr := rtCheck.followOnce(ctx, &reader)
		cancel()
		require.Equal(t, tc.code, status.Code(fetchErr))
		_, err := h.v.RawSnapshot(h.ctx, h.f.G1.ID, nil, rtCheck, nil)
		require.ErrorIs(t, err, tc.want)
	}
}
