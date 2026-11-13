package fabric

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	api "graduation-design/internal/fabricapi"

	"github.com/hyperledger/fabric-gateway/pkg/identity"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	msp "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	grpcpeer "google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (a acceptance) channel() error {
	b, err := a.p.getBlock(a.ctx, 0)
	if err != nil {
		return err
	}
	for _, org := range []string{"a", "b", "c"} {
		peer, err := a.instance.peer(org, "read")
		if err != nil {
			return err
		}
		seen, err := peer.getBlock(a.ctx, 0)
		peer.close()
		if err != nil || seen.Hash != b.Hash {
			return fmt.Errorf("peer %s different genesis: %v", org, err)
		}
		a.log.event("peer_genesis", map[string]any{"peer": org, "point": seen.point})
	}
	pl, _, err := envelopeHeader(b.Transactions[0].Envelope)
	if err != nil {
		return err
	}
	cfg, err := decode(pl.Data, &cb.ConfigEnvelope{})
	if err != nil {
		return err
	}
	channel := cfg.GetConfig().GetChannelGroup()
	orderer := channel.GetGroups()["Orderer"]
	consensus, err := decode(orderer.GetValues()["ConsensusType"].GetValue(), &ab.ConsensusType{})
	if err != nil || consensus.Type != "BFT" {
		return fmt.Errorf("unexpected consensus type %q: %v", consensus.Type, err)
	}
	mapping, err := decode(orderer.GetValues()["Orderers"].GetValue(), &cb.Orderers{})
	if err != nil || len(mapping.ConsenterMapping) != 4 {
		return fmt.Errorf("expected four consenters: %v", err)
	}
	policy, err := decode(orderer.GetPolicies()["BlockValidation"].GetPolicy().GetValue(), &cb.SignaturePolicyEnvelope{})
	if err != nil || policy.GetRule().GetNOutOf().GetN() != 3 || len(policy.GetIdentities()) != 4 ||
		len(policy.GetRule().GetNOutOf().GetRules()) != 4 {
		return fmt.Errorf("expected three-of-four BFT block signature policy: %v", err)
	}
	members := map[string]bool{}
	for _, p := range policy.Identities {
		id, err := decode(p.Principal, &msp.SerializedIdentity{})
		if err != nil || p.PrincipalClassification != msp.MSPPrincipal_IDENTITY {
			return fmt.Errorf("invalid BFT identity: %v", err)
		}
		cert, err := identity.CertificateFromPEM(id.IdBytes)
		if err != nil {
			return err
		}
		members[id.Mspid+"/"+api.Digest(cert.Raw)] = true
	}
	for index, org := range []string{"a", "b", "c", "d"} {
		name := "Orderer" + strings.ToUpper(org) + "Msp"
		node := "orderer-" + org
		root := filepath.Join(a.instance.dir, "crypto", "ordererOrganizations", "o"+org+".local", "orderers", node+".o"+org+".local")
		certPEM, err := os.ReadFile(filepath.Join(root, "msp", "signcerts", node+".o"+org+".local-cert.pem"))
		if err != nil {
			return err
		}
		cert, err := identity.CertificateFromPEM(certPEM)
		if err != nil {
			return err
		}
		tlsPEM, err := os.ReadFile(filepath.Join(root, "tls", "server.crt"))
		if err != nil {
			return err
		}
		sign := api.Digest(cert.Raw)
		m := mapping.ConsenterMapping[index]
		if m.Id != uint32(index+1) || m.Host != node || m.Port != 7050 || m.MspId != name ||
			!bytes.Equal(m.Identity, certPEM) || !bytes.Equal(m.ClientTlsCert, tlsPEM) || !bytes.Equal(m.ServerTlsCert, tlsPEM) || !members[name+"/"+sign] {
			return fmt.Errorf("consenter %s does not match the generated enrollment and TLS materials", org)
		}
		out, err := a.instance.run(a.ctx, "orderer", org, "list", "--channelID", api.Channel)
		a.log.event("consenter", map[string]any{"id": m.Id, "mspId": name, "fingerprint": sign, "adminResponse": string(out)})
		if err != nil || !bytes.Contains(out, []byte(`"consensusRelation": "consenter"`)) {
			return fmt.Errorf("orderer %s is not a consenter: %v", org, err)
		}
	}
	rogue, err := a.instance.peer("c", "rogue")
	if err != nil {
		return err
	}
	defer rogue.close()
	_, writeErr := rogue.direct(a.ctx, api.Registry, "RegisterTask", string(payload(a.f.Task)))
	a.log.event("unadmitted_write", fmt.Sprint(writeErr))
	if writeErr == nil || !strings.Contains(writeErr.Error(), "access denied") {
		return fmt.Errorf("unexpected unadmitted proposal result: %v", writeErr)
	}
	c, cancel := context.WithTimeout(a.ctx, 4*time.Second)
	defer cancel()
	stream, err := rogue.deliver(c, 0, 0)
	if err != nil {
		return err
	}
	_, err = receiveBlock(stream)
	a.log.event("unadmitted_read", fmt.Sprint(err))
	if err == nil || !strings.Contains(err.Error(), "FORBIDDEN") {
		return fmt.Errorf("unexpected unadmitted Deliver result: %v", err)
	}
	if err := a.rogueOrderer(); err != nil {
		return err
	}
	return a.oneOrgUpgrade()
}

func (a acceptance) rogueOrderer() error {
	if _, err := a.instance.run(a.ctx, "compose", "--profile", "negative", "up", "-d", "--wait", "--wait-timeout", "15", "orderer-rogue"); err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		out, err := a.instance.run(ctx, "stop", "orderer-rogue")
		a.log.event("rogue_cleanup", map[string]any{"output": string(out), "error": fmt.Sprint(err)})
	}()
	out, _ := a.instance.run(a.ctx, "orderer", "x", "join", "--channelID", api.Channel, "--config-block", filepath.Join(a.instance.dir, "genesis.pb"))
	a.log.event("rogue_join_attempt", string(out))
	out, err := a.instance.run(a.ctx, "orderer", "x", "list", "--channelID", api.Channel)
	a.log.event("rogue_membership", string(out))
	if err != nil || !bytes.Contains(out, []byte(`"consensusRelation": "follower"`)) || !bytes.Contains(out, []byte(`"height": 0`)) {
		return fmt.Errorf("unexpected rogue membership: %s (%v)", out, err)
	}
	addr, err := a.instance.port("FABRIC_ORDERER_A")
	if err != nil {
		return err
	}
	dir := filepath.Join(a.instance.dir, "crypto", "ordererOrganizations")
	conn, err := dialTLS(addr, "orderer-a", filepath.Join(dir, "oa.local", "orderers", "orderer-a.oa.local", "tls", "ca.crt"))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(a.ctx, 4*time.Second)
	defer cancel()
	stream, err := ab.NewClusterNodeServiceClient(conn).Step(ctx)
	if err != nil {
		return err
	}
	p, ok := grpcpeer.FromContext(stream.Context())
	if !ok {
		return fmt.Errorf("no authenticated orderer TLS connection")
	}
	tls, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return fmt.Errorf("no authenticated orderer TLS context")
	}
	req := &ab.NodeAuthRequest{Version: 0, FromId: 5, ToId: 1, Timestamp: timestamppb.Now(), Channel: api.Channel}
	ts := binary.LittleEndian.AppendUint64(nil, uint64(req.Timestamp.Seconds))
	fields := bytes.Join([][]byte{[]byte("0"), ts, []byte("5"), []byte("1"), []byte(api.Channel)}, nil)
	req.SessionBinding, err = tls.State.ExportKeyingMaterial("orderer v3 authentication label", digestBytes(fields), 32)
	if err != nil {
		return err
	}
	toSign, err := asn1.Marshal(struct {
		Version           int64
		Timestamp         []byte
		From, To, Channel string
		Binding           []byte
	}{
		0, ts, "5", "1", api.Channel, req.SessionBinding,
	})
	if err != nil {
		return err
	}
	keys, err := filepath.Glob(filepath.Join(dir, "ox.local", "orderers", "orderer-rogue.ox.local", "msp", "keystore", "*"))
	if err != nil || len(keys) != 1 {
		return fmt.Errorf("missing rogue enrollment key")
	}
	pem, err := os.ReadFile(keys[0])
	if err != nil {
		return err
	}
	key, err := identity.PrivateKeyFromPEM(pem)
	if err != nil {
		return err
	}
	sign, err := identity.NewPrivateKeySign(key)
	if err != nil {
		return err
	}
	req.Signature, err = sign(digestBytes(toSign))
	if err != nil {
		return err
	}
	if err := stream.Send(&ab.ClusterNodeServiceStepRequest{Payload: &ab.ClusterNodeServiceStepRequest_NodeAuthrequest{NodeAuthrequest: req}}); err != nil {
		return err
	}
	_, err = stream.Recv()
	a.log.event("rogue_consensus_authentication", map[string]any{"from": 5, "to": 1, "status": fmt.Sprint(err)})
	if status.Code(err) != codes.Unauthenticated {
		return fmt.Errorf("unexpected consensus authorization outcome: %v", err)
	}
	logs, err := a.instance.run(a.ctx, "logs", "--tail", "60", "orderer-a")
	if err != nil || !bytes.Contains(logs, []byte("node 5 is not member of channel procurement")) {
		return fmt.Errorf("ordering node did not record the expected membership denial: %v", err)
	}
	return writeFile(filepath.Join(a.dir, "rogue-orderer-denial.log"), logs, 0644)
}

func (a acceptance) oneOrgUpgrade() error {
	orderer, err := a.instance.ordererArgs()
	if err != nil {
		return err
	}
	def := []string{"-C", api.Channel, "-n", api.Registry, "-v", "2.0", "--sequence", "2", "--signature-policy", signaturePolicy}
	args := []string{"peer", "a", "Admin", "lifecycle", "chaincode", "queryapproved", "--output", "json", "-C", api.Channel, "-n", api.Registry, "--sequence", "2"}
	if _, err := a.instance.run(a.ctx, args...); err != nil {
		args := append([]string{"peer", "a", "Admin", "lifecycle", "chaincode", "approveformyorg", "--package-id", a.d.PackageIDs["a"], "--waitForEventTimeout", "15s"}, def...)
		out, err := a.instance.run(a.ctx, append(args, orderer...)...)
		a.log.event("single_org_approval", string(out))
		if err != nil {
			return err
		}
	}
	address, err := a.instance.port("FABRIC_PEER_A")
	if err != nil {
		return err
	}
	args = append([]string{"peer", "a", "Admin", "lifecycle", "chaincode", "commit", "--waitForEventTimeout", "12s", "--peerAddresses", address,
		"--tlsRootCertFiles", a.instance.peerTLS("a")}, def...)
	out, err := a.instance.run(a.ctx, append(args, orderer...)...)
	a.log.event("single_org_upgrade", string(out))
	if err == nil || !bytes.Contains(out, []byte("ENDORSEMENT_POLICY_FAILURE")) {
		return fmt.Errorf("single-org definition commit did not fail its endorsement policy: %v", err)
	}
	return a.d.validatePeer(a.ctx, a.p)
}

func (a acceptance) deploymentBinding() error {
	for _, t := range []struct {
		name   string
		modify func(*deployment)
	}{
		{"channel", func(d *deployment) { d.ChannelID = "wrong-channel" }},
		{"genesis", func(d *deployment) {
			d.GenesisHash = randomID()
			d.DeploymentID = d.ID()
			d.Bootstrap.GenesisHash = d.GenesisHash
		}},
		{"instance", func(d *deployment) {
			d.InstanceID = randomID()
			d.DeploymentID = d.ID()
			d.Bootstrap.InstanceID = d.InstanceID
		}},
		{"root", func(d *deployment) { d.Bootstrap.Root.DocumentDigest = randomID() }},
		{"u-qualification", func(d *deployment) { d.Bootstrap.TaskCreator.Subject = "did:web:a.local:wrong" }},
		{"policy", func(d *deployment) { d.ConfigDigest = randomID() }},
		{"definition", func(d *deployment) { d.DefinitionDigest = randomID() }},
	} {
		bad := *a.d
		t.modify(&bad)
		err := bad.validatePeer(a.ctx, a.p)
		a.log.event("deployment_mismatch", map[string]any{"field": t.name, "error": fmt.Sprint(err)})
		if !errors.Is(err, errDeploymentMismatch) {
			return fmt.Errorf("manifest mutation accepted: %s", t.name)
		}
	}
	bad := *a.d
	bad.ConfigDigest = randomID()
	rt := newRuntime(a)
	rt.d = &bad
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()
	err := rt.followOnce(ctx, a.p)
	a.log.event("deployment_mismatch_online", fmt.Sprint(rt.hardError))
	if !errors.Is(err, errDeploymentMismatch) || !errors.Is(rt.hardError, errDeploymentMismatch) {
		return fmt.Errorf("deployment mismatch did not inhibit online replay: %v", err)
	}
	old := a.cloneGrant("old-deployment")
	old.DeploymentID = randomID()
	if _, err := a.op("old-deployment", "U", "RegisterGrant", old, "INVALID_STRUCTURE"); err != nil {
		return err
	}
	if err := a.absent("grant", old.ID); err != nil {
		return err
	}
	old.DeploymentID = a.d.DeploymentID
	_, err = a.op("current-deployment", "U", "RegisterGrant", old, "VALID")
	return err
}

func (a acceptance) initializationResume() error {
	path := a.instance.registryPath("initialization.json")
	before, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(a.instance.registryPath("bootstrap.json"))
	if err != nil {
		return err
	}
	// Repeat the initialization step with no in-memory result after the
	// original operations have been journaled, as in an interrupted deploy.
	resumed := *a.d
	resumed.InitBlock = point{}
	if err := a.instance.initializeRegistry(a.ctx, a.j, a.p, &resumed, raw, false); err != nil {
		return err
	}
	after, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sameOperations := bytes.Equal(before, after)
	a.log.event("initialization_resumed", map[string]any{"initializationBlock": resumed.InitBlock, "originalOperationsPreserved": sameOperations})
	if resumed.InitBlock != a.d.InitBlock || !sameOperations {
		return fmt.Errorf("deployment resume changed the initialization block or original operations")
	}
	repeat, err := a.j.write(a.ctx, a.id+"/repeat-initialization", "init", "Initialize", raw)
	a.log.event("operation", repeat)
	if err != nil {
		return err
	}
	if err := expectOperation(repeat, "ID_ALREADY_USED"); err != nil {
		return err
	}
	root, err := a.p.direct(a.ctx, api.Registry, "Read", api.BootstrapKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(root, raw) {
		return fmt.Errorf("repeat initialization changed the approved bootstrap record")
	}
	return nil
}

func (a acceptance) roles() error {
	if _, err := a.op("non-t-bootstrap", "registrarA", "BootstrapDomain", a.f.Domains["A"], "UNAUTHORIZED"); err != nil {
		return err
	}
	if _, err := a.op("non-t-certify", "registrarA", "CertifyDomain", a.f.Certifications["A"], "UNAUTHORIZED"); err != nil {
		return err
	}
	id := a.f.Identities["A1"]
	id.ID = "did:web:a.local:test-" + a.id
	id.KeyID = id.ID + "#auth"
	// Use a certificate unique to this acceptance case on this instance.
	_, m, _, err := a.instance.role("wrongA")
	if err != nil {
		return err
	}
	id.Management = m
	key, err := publicKey()
	if err != nil {
		return err
	}
	id.PublicKey, id.DocumentDigest = key, api.Digest([]byte(key))
	for _, role := range []string{"registrarC", "wrongA"} {
		if _, err := a.op("identity-"+role, role, "RegisterIdentity", id, "UNAUTHORIZED"); err != nil {
			return err
		}
		if err := a.absent("identity", id.ID); err != nil {
			return err
		}
	}
	// On a rerun this management certificate may already be bound by an earlier run.
	existing, err := a.p.direct(a.ctx, api.Registry, "Read", api.Key("binding", m.String()))
	if err == nil && len(existing) > 0 {
		id = a.f.Identities["A1"]
	} else if _, err := a.op("identity-positive", "registrarA", "RegisterIdentity", id, "VALID"); err != nil {
		return err
	}
	c := a.f.Credentials["A1"]
	c.ID, c.Subject, c.Digest = "cred-"+a.id, id.ID, randomID()
	for _, change := range []struct {
		name, role, code string
		modify           func(*api.Credential)
	}{
		{"same-msp", "wrongA", "UNAUTHORIZED", func(*api.Credential) {}},
		{"cross-domain", "IC", "INVALID_STRUCTURE", func(c *api.Credential) { c.Issuer = a.f.Credentials["C"].Issuer }},
		{"type", "IA", "INVALID_STRUCTURE", func(c *api.Credential) { c.Type = "OutsideType" }},
		{"claim", "IA", "INVALID_STRUCTURE", func(c *api.Credential) { c.ClaimNames = []string{"bank", "domain", "role"} }},
		{"issuer-version", "IA", "INVALID_STRUCTURE", func(c *api.Credential) { c.IssuerKeyVersion++ }},
		{"subject-version", "IA", "INVALID_STRUCTURE", func(c *api.Credential) { c.SubjectKeyVersion++ }},
	} {
		bad := c
		change.modify(&bad)
		if _, err := a.op("credential-"+change.name, change.role, "RegisterCredential", bad, change.code); err != nil {
			return err
		}
		if err := a.absent("credential", c.ID); err != nil {
			return err
		}
	}
	_, err = a.op("credential-positive", "IA", "RegisterCredential", c, "VALID")
	return err
}

func (a acceptance) credentialValidityBoundaries() error {
	domain, err := ledgerRecord[api.Domain](a.ctx, a.p, "domain", "A")
	if err != nil {
		return err
	}
	cert, err := ledgerRecord[api.Certification](a.ctx, a.p, "certification", domain.Certification)
	if err != nil {
		return err
	}
	allowed := a.f.Credentials["U"]
	allowed.ID, allowed.Digest = "credential-boundaries-"+a.id, randomID()
	allowed.Interval = cert.Interval
	for _, tc := range []struct {
		label    string
		interval api.Interval
		want     string
	}{
		{"credential-nbf-before", api.Interval{NBF: cert.NBF - 1, EXP: cert.EXP}, "INVALID_STRUCTURE"},
		{"credential-exp-after", api.Interval{NBF: cert.NBF, EXP: cert.EXP + 1}, "INVALID_STRUCTURE"},
		{"credential-on-boundaries", cert.Interval, "VALID"},
	} {
		c := allowed
		c.Interval = tc.interval
		a.log.event("credential_validity_boundary", map[string]any{
			"case": tc.label, "certificationId": cert.ID, "certification": cert.Interval, "credential": c.Interval,
		})
		if _, err := a.op(tc.label, "IA", "RegisterCredential", c, tc.want); err != nil {
			return err
		}
		if tc.want != "VALID" {
			if err := a.absent("credential", c.ID); err != nil {
				return err
			}
		}
	}
	stored, err := ledgerRecord[api.Credential](a.ctx, a.p, "credential", allowed.ID)
	if err != nil {
		return err
	}
	if stored.Interval != cert.Interval || stored.Status != api.Active {
		return fmt.Errorf("credential at certification boundaries has unexpected interval or status")
	}
	return nil
}

func (a acceptance) path() error {
	t := a.f.Task
	t.ID = randomID()
	unqualified := t
	unqualified.Creator, unqualified.CreatorCredential = a.f.Identities["alt"].ID, a.f.Credentials["alt"].ID
	if _, err := a.op("task-alt", "alt", "RegisterTask", unqualified, "UNAUTHORIZED"); err != nil {
		return err
	}
	if err := a.absent("task", t.ID); err != nil {
		return err
	}
	if _, err := a.op("task-u", "U", "RegisterTask", t, "VALID"); err != nil {
		return err
	}
	g0 := a.f.G0
	g0.ID, g0.Task = randomID(), t.ID
	g0.Root = g0.ID
	other := g0
	other.Issuer, other.IssuerCredential = a.f.Identities["alt"].ID, a.f.Credentials["alt"].ID
	if _, err := a.op("wrong-resource-owner", "alt", "RegisterGrant", other, "INVALID_STRUCTURE"); err != nil {
		return err
	}
	if err := a.absent("grant", g0.ID); err != nil {
		return err
	}
	if _, err := a.op("resource-owner", "C", "RegisterGrant", g0, "VALID"); err != nil {
		return err
	}
	for _, change := range []struct {
		name, role, code string
		modify           func(*api.Grant)
	}{
		{"parent-grantee", "alt", "UNAUTHORIZED", func(g *api.Grant) { g.Issuer, g.IssuerCredential = a.f.Identities["alt"].ID, a.f.Credentials["alt"].ID }},
		{"parent-digest", "U", "INVALID_STRUCTURE", func(g *api.Grant) { g.ParentDigest = randomID() }},
		{"root", "U", "INVALID_STRUCTURE", func(g *api.Grant) { g.Root = randomID() }},
		{"task", "U", "INVALID_STRUCTURE", func(g *api.Grant) { g.Task = t.ID }},
		{"mode", "U", "INVALID_STRUCTURE", func(g *api.Grant) { g.Mode = "BUYER_MANDATE" }},
		{"key-version", "U", "INVALID_STRUCTURE", func(g *api.Grant) { g.GranteeKeyVersion++ }},
		{"interval", "U", "INVALID_STRUCTURE", func(g *api.Grant) { g.EXP++ }},
		{"depth", "U", "INVALID_STRUCTURE", func(g *api.Grant) { g.Depth = a.f.G0.Depth }},
	} {
		good := a.cloneGrant("path-" + change.name)
		bad := good
		change.modify(&bad)
		if _, err := a.op("path-bad-"+change.name, change.role, "RegisterGrant", bad, change.code); err != nil {
			return err
		}
		if err := a.absent("grant", good.ID); err != nil {
			return err
		}
		if _, err := a.op("path-good-"+change.name, "U", "RegisterGrant", good, "VALID"); err != nil {
			return err
		}
	}
	return nil
}

func (a acceptance) mutations() error {
	g := a.cloneGrant("revoke")
	if _, err := a.op("register-revoke", "U", "RegisterGrant", g, "VALID"); err != nil {
		return err
	}
	m := revokeOf(g)
	for _, role := range []string{"T", "alt"} {
		if _, err := a.op("revoke-"+role, role, "RevokeGrant", m, "UNAUTHORIZED"); err != nil {
			return err
		}
	}
	if _, err := a.op("revoke-grantee", "A1", "RevokeGrant", m, "VALID"); err != nil {
		return err
	}
	gone, err := ledgerRecord[api.Grant](a.ctx, a.p, "grant", g.ID)
	if err != nil || gone.Status != api.Revoked || gone.Revision != 2 || gone.Digest != g.Digest {
		return fmt.Errorf("invalid revocation result: %+v %v", gone, err)
	}
	if _, err := a.op("revoke-terminal", "U", "RevokeGrant", revokeOf(gone), "INVALID_STATE"); err != nil {
		return err
	}
	if _, err := a.op("reuse-terminal", "U", "RegisterGrant", g, "ID_ALREADY_USED"); err != nil {
		return err
	}
	old, next := a.cloneGrant("old"), a.cloneGrant("new")
	if _, err := a.op("register-old", "U", "RegisterGrant", old, "VALID"); err != nil {
		return err
	}
	r := api.Replacement{Old: revokeOf(old), New: next}
	if _, err := a.op("replace-grantee", "A1", "ReplaceGrant", r, "UNAUTHORIZED"); err != nil {
		return err
	}
	bad := r
	bad.New.ParentDigest = randomID()
	if _, err := a.op("replace-bad", "U", "ReplaceGrant", bad, "INVALID_STRUCTURE"); err != nil {
		return err
	}
	seen, err := ledgerRecord[api.Grant](a.ctx, a.p, "grant", old.ID)
	if err != nil || seen.Status != api.Active || seen.Revision != 1 {
		return fmt.Errorf("failed replacement changed the original grant: %+v %v", seen, err)
	}
	if err := a.absent("grant", next.ID); err != nil {
		return err
	}
	replace, err := a.op("replace-issuer", "U", "ReplaceGrant", r, "VALID")
	if err != nil {
		return err
	}
	b, err := a.p.getBlock(a.ctx, replace.Commit.Number)
	if err != nil {
		return err
	}
	writes := b.Transactions[replace.Commit.Index].Writes
	if len(writes) != 2 {
		return fmt.Errorf("replacement has %d registry writes", len(writes))
	}
	seen, err = ledgerRecord[api.Grant](a.ctx, a.p, "grant", old.ID)
	if err != nil || seen.Status != api.Revoked || seen.Revision != 2 {
		return fmt.Errorf("replacement did not revoke the old grant: %v", err)
	}
	seen, err = ledgerRecord[api.Grant](a.ctx, a.p, "grant", next.ID)
	if err != nil || seen.Status != api.Active || seen.Revision != 1 {
		return fmt.Errorf("replacement did not register the new grant: %v", err)
	}
	return nil
}
