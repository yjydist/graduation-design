package ledger

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type registryHarness struct {
	t     *testing.T
	ctx   context.Context
	r     *Registry
	f     *Fixtures
	cases []map[string]any
}

func newRegistryHarness(t *testing.T, name string) *registryHarness {
	t.Helper()
	manifest := os.Getenv("LEDGER_MANIFEST")
	dir := os.Getenv("LEDGER_INSTANCE")
	out := os.Getenv("LEDGER_EVIDENCE")
	if manifest == "" || dir == "" {
		t.Skip("set LEDGER_MANIFEST, LEDGER_INSTANCE and LEDGER_EVIDENCE for real Besu tests")
	}
	if out == "" {
		t.Fatal("LEDGER_EVIDENCE required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	r, err := OpenRegistry(ctx, dir, manifest, "http://127.0.0.1:18547")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	f, err := LoadFixtures(ctx, r)
	if err != nil {
		r.Client.Close()
		cancel()
		t.Fatal(err)
	}
	h := &registryHarness{t: t, ctx: ctx, r: r, f: f}
	t.Cleanup(func() {
		defer cancel()
		defer r.Client.Close()
		if err := os.MkdirAll(out, 0755); err != nil {
			t.Error(err)
			return
		}
		if err := writeJSON(filepath.Join(out, name+".json"), map[string]any{"passed": !t.Failed(), "synthetic": true, "deploymentId": r.Deployment.DeploymentID, "cases": h.cases}); err != nil {
			t.Error(err)
		}
	})
	return h
}

func (h *registryHarness) tx(id, role, method string, success bool, args ...any) *Operation {
	h.t.Helper()
	op, err := h.r.Write(h.ctx, h.r.Deployment.DeploymentID[:8]+"-"+id, role, method, args...)
	if err != nil {
		h.cases = append(h.cases, map[string]any{"name": id, "error": err.Error(), "passed": false})
		h.t.Fatal(err)
	}
	passed := (op.Status == "CONFIRMED") == success && op.Receipt != nil && (op.Receipt.Status == 1) == success
	h.cases = append(h.cases, map[string]any{"name": id, "operation": op, "expectedSuccess": success, "passed": passed})
	if !passed {
		h.t.Fatalf("%s: status %s", id, op.Status)
	}
	return op
}

func (h *registryHarness) snapshot(method string, ids ...string) []any {
	h.t.Helper()
	result := []any{}
	for _, id := range ids {
		v, err := h.r.View(h.ctx, method, hashID(id))
		if err != nil {
			result = append(result, map[string]any{"id": id, "error": err.Error()})
		} else {
			result = append(result, v[0])
		}
	}
	return result
}

func cloneValue[T any](value T) T {
	b, _ := json.Marshal(value)
	var result T
	_ = json.Unmarshal(b, &result)
	return result
}

func (h *registryHarness) rejectUnchanged(id, role, method string, before func() any, args ...any) {
	h.t.Helper()
	old := before()
	h.tx(id, role, method, false, args...)
	after := before()
	passed := reflect.DeepEqual(old, after)
	h.cases = append(h.cases, map[string]any{"name": id + "-atomicity", "before": old, "after": after, "passed": passed})
	if !passed {
		h.t.Fatalf("%s: partial state mutation", id)
	}
}

func TestDomainRegistrationIntegration(t *testing.T) {
	h := newRegistryHarness(t, "domains")
	a := h.f.Domains["A"]
	c := h.f.Domains["C"]
	b := h.f.Domains["B"]
	missing := func() any {
		return []any{h.snapshot("getDomain", b.Domain.DomainId), h.snapshot("getIdentity", b.Identity.SubjectId, b.Issuers[0].SubjectId), h.snapshot("getDomainCertification", b.Certification.CertificationId)}
	}
	h.rejectUnchanged("bootstrap-unrelated", "unrelated", "bootstrapDomain", missing, b.Domain, b.Identity, b.Issuers)
	h.rejectUnchanged("certify-missing-domain", "T", "registerDomainCertification", missing, b.Certification, uint64(1), common.Hash{})
	invalid := cloneValue(b)
	invalid.Issuers[0].AppPublicKey[0] = 3
	h.rejectUnchanged("bootstrap-invalid-key", "T", "bootstrapDomain", missing, invalid.Domain, invalid.Identity, invalid.Issuers)
	for _, d := range []DomainFixture{a, c} {
		name := d.Domain.DomainId[len(d.Domain.DomainId)-1:]
		bootstrap := h.tx("bootstrap-"+name, "T", "bootstrapDomain", true, d.Domain, d.Identity, d.Issuers)
		v, err := ReadView(h.ctx, h.r.Client, h.r.Deployment, bootstrap.Receipt.BlockNumber, "getDomain", hashID(d.Domain.DomainId))
		if err != nil {
			t.Fatal(err)
		}
		pending := abi.ConvertType(v[0], new(DomainRecord)).(*DomainRecord)
		if pending.Status != StatusPending || pending.CurrentCertificationId != (common.Hash{}) || pending.Revision != 1 {
			t.Fatal("invalid bootstrap state")
		}
		snapshot := func() any {
			return []any{h.snapshot("getDomain", d.Domain.DomainId), h.snapshot("getIdentity", d.Identity.SubjectId, d.Issuers[0].SubjectId), h.snapshot("getDomainCertification", d.Certification.CertificationId)}
		}
		h.rejectUnchanged("certify-unrelated-"+name, "unrelated", "registerDomainCertification", snapshot, d.Certification, uint64(1), common.Hash{})
		h.rejectUnchanged("certify-revision-"+name, "T", "registerDomainCertification", snapshot, d.Certification, uint64(2), common.Hash{})
		h.rejectUnchanged("certify-pointer-"+name, "T", "registerDomainCertification", snapshot, d.Certification, uint64(1), hashID("wrong"))
		bad := cloneValue(d.Certification)
		bad.IdentityIssuers[0].AppKeyVersion++
		h.rejectUnchanged("certify-key-version-"+name, "T", "registerDomainCertification", snapshot, bad, uint64(1), common.Hash{})
		bad = cloneValue(d.Certification)
		bad.IdentityIssuers[0].ClaimNames = []string{"*"}
		h.rejectUnchanged("certify-scope-"+name, "T", "registerDomainCertification", snapshot, bad, uint64(1), common.Hash{})
		cert := h.tx("certify-"+name, "T", "registerDomainCertification", true, d.Certification, uint64(1), common.Hash{})
		v, err = ReadView(h.ctx, h.r.Client, h.r.Deployment, cert.Receipt.BlockNumber, "getDomain", hashID(d.Domain.DomainId))
		if err != nil {
			t.Fatal(err)
		}
		active := abi.ConvertType(v[0], new(DomainRecord)).(*DomainRecord)
		if active.Status != StatusActive || active.Revision != 2 || active.CurrentCertificationId != hashID(d.Certification.CertificationId) {
			t.Fatal("invalid certified state")
		}
		h.cases = append(h.cases, map[string]any{"name": "transition-" + name, "pending": pending, "active": active, "passed": true})
	}
}

func TestIdentityRegistrationIntegration(t *testing.T) {
	h := newRegistryHarness(t, "identities")
	u := h.f.Identities["U"]
	state := func() any { return h.snapshot("getIdentity", u.SubjectId) }
	h.rejectUnchanged("identity-cross-domain", "registrarC", "registerIdentity", state, u)
	h.rejectUnchanged("identity-root-not-registrar", "T", "registerIdentity", state, u)
	bad := cloneValue(u)
	bad.AppKeyVersion++
	h.rejectUnchanged("identity-wrong-version", "registrarA", "registerIdentity", state, bad)
	bad = cloneValue(u)
	bad.Kind = 2
	h.rejectUnchanged("identity-no-issuer-shortcut", "registrarA", "registerIdentity", state, bad)
	bad = cloneValue(u)
	bad.AppPublicKey[10] ^= 1
	h.rejectUnchanged("identity-invalid-point", "registrarA", "registerIdentity", state, bad)
	for _, role := range []string{"U", "A1", "C", "B1"} {
		registrar := "registrarA"
		if role == "C" {
			registrar = "registrarC"
		}
		op := h.tx("identity-"+role, registrar, "registerIdentity", true, h.f.Identities[role])
		v, err := ReadView(h.ctx, h.r.Client, h.r.Deployment, op.Receipt.BlockNumber, "getIdentity", hashID(h.f.Identities[role].SubjectId))
		if err != nil {
			t.Fatal(err)
		}
		stored := abi.ConvertType(v[0], new(IdentityRecord)).(*IdentityRecord)
		if !reflect.DeepEqual(stored.Identity, h.f.Identities[role]) || stored.Status != StatusActive || stored.Revision != 1 {
			t.Fatal("identity record mismatch")
		}
	}
	c := h.f.Credentials["U"]
	credentialState := func() any {
		return []any{h.snapshot("getCredential", c.CredentialId), h.snapshot("getIdentity", c.Subject, c.Issuer)}
	}
	h.rejectUnchanged("credential-wrong-sender", "IC", "registerCredential", credentialState, c)
	badCredential := c
	badCredential.Issuer = h.f.Domains["C"].Issuers[0].SubjectId
	h.rejectUnchanged("credential-cross-domain", "IC", "registerCredential", credentialState, badCredential)
	badCredential = c
	badCredential.IssuerKeyVersion++
	h.rejectUnchanged("credential-issuer-version", "IA", "registerCredential", credentialState, badCredential)
	badCredential = c
	badCredential.AppKeyVersion++
	h.rejectUnchanged("credential-subject-version", "IA", "registerCredential", credentialState, badCredential)
	badCredential = c
	badCredential.CredentialType = "UncertifiedType"
	h.rejectUnchanged("credential-outside-scope", "IA", "registerCredential", credentialState, badCredential)
	badCredential = c
	badCredential.Exp = badCredential.Nbf + 1
	h.rejectUnchanged("credential-expired", "IA", "registerCredential", credentialState, badCredential)
	badCredential = c
	badCredential.Subject = "did:web:missing.example.test"
	h.rejectUnchanged("credential-missing-subject", "IA", "registerCredential", credentialState, badCredential)
	for _, role := range []string{"U", "A1", "C", "B1"} {
		issuer := "IA"
		if role == "C" {
			issuer = "IC"
		}
		op := h.tx("credential-"+role, issuer, "registerCredential", true, h.f.Credentials[role])
		v, err := ReadView(h.ctx, h.r.Client, h.r.Deployment, op.Receipt.BlockNumber, "getCredential", hashID(h.f.Credentials[role].CredentialId))
		if err != nil {
			t.Fatal(err)
		}
		stored := abi.ConvertType(v[0], new(CredentialRecord)).(*CredentialRecord)
		if !reflect.DeepEqual(stored.Credential, h.f.Credentials[role]) || stored.Status != StatusActive || stored.Revision != 1 {
			t.Fatal("credential record mismatch")
		}
	}
	// A pending domain must not register ordinary identities.
	b := h.f.Domains["B"]
	h.tx("bootstrap-pending-B", "T", "bootstrapDomain", true, b.Domain, b.Identity, b.Issuers)
	pendingIdentity := cloneValue(u)
	pendingIdentity.DomainId = b.Domain.DomainId
	h.rejectUnchanged("identity-pending-domain", "registrarB", "registerIdentity", state, pendingIdentity)
}

func TestRPRegistrationIntegration(t *testing.T) {
	h := newRegistryHarness(t, "rp-registration")
	task := h.f.Task
	g0 := h.f.Grants["G0"]
	g1 := h.f.Grants["G1"]
	taskState := func() any { return h.snapshot("getTask", TaskFixtureID) }
	other := task
	other.Creator = hashID(h.f.Identities["B1"].SubjectId)
	other.CreatorCredentialId = hashID(h.f.Credentials["B1"].CredentialId)
	h.rejectUnchanged("task-unconfigured-valid-user", "B1", "registerTask", taskState, other)
	h.rejectUnchanged("task-root-no-business-role", "T", "registerTask", taskState, task)
	op := h.tx("task-U", "U", "registerTask", true, task)
	v, err := ReadView(h.ctx, h.r.Client, h.r.Deployment, op.Receipt.BlockNumber, "getTask", task.TaskId)
	if err != nil {
		t.Fatal(err)
	}
	storedTask := abi.ConvertType(v[0], new(TaskRecord)).(*TaskRecord)
	if !reflect.DeepEqual(storedTask.Task, task) || storedTask.Status != StatusActive {
		t.Fatal("task record mismatch")
	}
	grantState := func() any { return h.snapshot("getGrant", RootFixtureID, ChildFixtureID) }
	bad := g0
	bad.Issuer = task.Creator
	bad.IssuerCredentialId = task.CreatorCredentialId
	h.rejectUnchanged("root-not-resource-owner", "U", "registerGrant", grantState, bad)
	bad = g0
	bad.Grantee = other.Creator
	bad.GranteeCredentialId = other.CreatorCredentialId
	h.rejectUnchanged("root-wrong-task-grantee", "C", "registerGrant", grantState, bad)
	rootOp := h.tx("grant-G0", "C", "registerGrant", true, g0)
	h.rejectUnchanged("child-wrong-caller", "A1", "registerGrant", grantState, g1)
	bad = g1
	bad.Issuer = g0.Issuer
	bad.IssuerCredentialId = g0.IssuerCredentialId
	h.rejectUnchanged("child-not-parent-grantee", "C", "registerGrant", grantState, bad)
	childOp := h.tx("grant-G1", "U", "registerGrant", true, g1)
	for _, entry := range []struct {
		input GrantInput
		op    *Operation
	}{{g0, rootOp}, {g1, childOp}} {
		v, err := ReadView(h.ctx, h.r.Client, h.r.Deployment, entry.op.Receipt.BlockNumber, "getGrant", entry.input.GrantId)
		if err != nil {
			t.Fatal(err)
		}
		g := abi.ConvertType(v[0], new(GrantRecord)).(*GrantRecord)
		if g.Status != StatusActive || g.Revision != 1 || !reflect.DeepEqual(g.Grant, entry.input) {
			t.Fatal("grant record mismatch")
		}
		h.cases = append(h.cases, map[string]any{"name": "stored-" + g.Grant.GrantId.Hex(), "grant": g, "passed": true})
	}
}

func TestGrantStructureIntegration(t *testing.T) {
	h := newRegistryHarness(t, "grant-structure")
	mutations := []struct {
		name   string
		change func(*GrantInput)
	}{
		{"parent-digest", func(g *GrantInput) { g.ParentDigest[0] ^= 1 }},
		{"missing-parent", func(g *GrantInput) { g.ParentId = hashID("missing-parent") }},
		{"root-reference", func(g *GrantInput) { g.RootId[0] ^= 1 }},
		{"task-reference", func(g *GrantInput) { g.TaskId[0] ^= 1 }},
		{"mode", func(g *GrantInput) { g.AuthorizationMode = "BUYER_MANDATE" }},
		{"principal-domain", func(g *GrantInput) { g.PrincipalDomain = "urn:grad:domain:C" }},
		{"issuer-key-version", func(g *GrantInput) { g.IssuerKeyVersion++ }},
		{"grantee-key-version", func(g *GrantInput) { g.GranteeKeyVersion++ }},
		{"issuer-credential", func(g *GrantInput) { g.IssuerCredentialId = hashID(h.f.Credentials["C"].CredentialId) }},
		{"grantee-credential", func(g *GrantInput) { g.GranteeCredentialId = hashID(h.f.Credentials["C"].CredentialId) }},
		{"nbf-containment", func(g *GrantInput) { g.Nbf-- }},
		{"exp-containment", func(g *GrantInput) { g.Exp++ }},
		{"remaining-depth", func(g *GrantInput) { g.RemainingDepth = 2 }},
		{"resource-reference", func(g *GrantInput) { g.ResourceId[0] ^= 1 }},
		{"deployment-reference", func(g *GrantInput) { g.DeploymentId[0] ^= 1 }},
		{"schema-version", func(g *GrantInput) { g.SchemaVersion = "wrong" }},
	}
	for _, entry := range mutations {
		label := "urn:grad:grant:pair:" + entry.name
		valid := cloneValue(h.f.Grants["G1"])
		valid.GrantId = hashID(label)
		valid = anchorSyntheticGrant(h.f, valid)
		bad := cloneValue(valid)
		entry.change(&bad)
		snapshot := func() any { return h.snapshot("getGrant", label, RootFixtureID, ChildFixtureID) }
		h.rejectUnchanged("bad-"+entry.name, "U", "registerGrant", snapshot, bad)
		op := h.tx("good-"+entry.name, "U", "registerGrant", true, valid)
		v, err := ReadView(h.ctx, h.r.Client, h.r.Deployment, op.Receipt.BlockNumber, "getGrant", valid.GrantId)
		if err != nil {
			t.Fatal(err)
		}
		stored := abi.ConvertType(v[0], new(GrantRecord)).(*GrantRecord)
		if stored.Status != StatusActive || !reflect.DeepEqual(stored.Grant, valid) {
			t.Fatal("paired valid object not preserved")
		}
		h.cases = append(h.cases, map[string]any{"name": "pair-" + entry.name, "invalid": bad, "valid": valid, "syntheticMaterial": h.f.Materials[valid.GrantId.Hex()], "passed": true})
	}
	snapshot := func() any { return h.snapshot("getGrant", RootFixtureID, ChildFixtureID) }
	h.rejectUnchanged("duplicate-active-id", "U", "registerGrant", snapshot, h.f.Grants["G1"])
}

func TestRevocationIntegration(t *testing.T) {
	h := newRegistryHarness(t, "revocation")
	g1 := h.f.Grants["G1"]
	snapshot := func() any { return h.snapshot("getGrant", RootFixtureID, ChildFixtureID) }
	for _, role := range []string{"T", "unrelated"} {
		h.rejectUnchanged("revoke-denied-"+role, role, "revokeGrant", snapshot, g1.GrantId, uint64(1), g1.Digest)
	}
	h.rejectUnchanged("revoke-wrong-revision", "U", "revokeGrant", snapshot, g1.GrantId, uint64(2), g1.Digest)
	h.rejectUnchanged("revoke-wrong-digest", "U", "revokeGrant", snapshot, g1.GrantId, uint64(1), hashID("wrong"))
	for _, entry := range []struct{ name, role string }{{"issuer", "U"}, {"grantee", "A1"}, {"root-issuer", "C"}, {"resource-owner", "C"}} {
		label := "urn:grad:grant:revoke:" + entry.name
		g := g1
		g.GrantId = hashID(label)
		g = anchorSyntheticGrant(h.f, g)
		h.tx("revoke-register-"+entry.name, "U", "registerGrant", true, g)
		op := h.tx("revoke-authorized-"+entry.name, entry.role, "revokeGrant", true, g.GrantId, uint64(1), g.Digest)
		v, err := ReadView(h.ctx, h.r.Client, h.r.Deployment, op.Receipt.BlockNumber, "getGrant", g.GrantId)
		if err != nil {
			t.Fatal(err)
		}
		stored := abi.ConvertType(v[0], new(GrantRecord)).(*GrantRecord)
		if stored.Status != StatusRevoked || stored.Revision != 2 || !reflect.DeepEqual(stored.Grant, g) {
			t.Fatal("revocation changed immutable grant fields")
		}
		state := func() any { return h.snapshot("getGrant", label) }
		h.rejectUnchanged("revoke-terminal-"+entry.name, entry.role, "revokeGrant", state, g.GrantId, uint64(2), g.Digest)
		h.rejectUnchanged("reuse-terminal-"+entry.name, "U", "registerGrant", state, g)
		key, err := crypto.LoadECDSA(filepath.Join(h.r.Dir, "keys", entry.role, "management.key"))
		if err != nil {
			t.Fatal(err)
		}
		data := append(crypto.Keccak256([]byte("restoreGrant(bytes32,uint64)"))[:4], g.GrantId[:]...)
		data = append(data, common.LeftPadBytes(big.NewInt(2).Bytes(), 32)...)
		before := state()
		restore, err := Submit(h.ctx, h.r.Client, h.r.Dir, h.r.Deployment.DeploymentID[:8]+"-restore-"+entry.name, key, &h.r.Deployment.RegistryAddress, data, ChainID)
		if err != nil {
			t.Fatal(err)
		}
		if restore.Status != "FAILED" || !reflect.DeepEqual(before, state()) {
			t.Fatal("terminal restore succeeded")
		}
		h.cases = append(h.cases, map[string]any{"name": "restore-missing-" + entry.name, "operation": restore, "selector": hexutil.Encode(data[:4]), "grant": stored, "passed": true})
	}
}

func TestOriginalTransactionTraceIntegration(t *testing.T) {
	h := newRegistryHarness(t, "original-transaction-trace")
	g := h.f.Grants["G1"]
	m, err := LoadInstance(h.r.Dir)
	if err != nil {
		t.Fatal(err)
	}
	var address common.Address
	for _, a := range m.Accounts {
		if a.Role == "unrelated" {
			address = common.HexToAddress(a.Address)
		}
	}
	header, err := ReadHeader(h.ctx, h.r.Client, nil)
	if err != nil {
		t.Fatal(err)
	}
	balance, err := h.r.Client.BalanceAt(h.ctx, address, new(big.Int).SetUint64(uint64(header.Number)))
	if err != nil || balance.Cmp(big.NewInt(8_000_000*1000)) <= 0 {
		t.Fatalf("negative account must have enough balance: %v", err)
	}
	state := func() any { return h.snapshot("getGrant", RootFixtureID, ChildFixtureID) }
	before := state()
	op := h.tx("trace-revoke-unrelated", "unrelated", "revokeGrant", false, g.GrantId, uint64(1), g.Digest)
	if !reflect.DeepEqual(before, state()) || op.Receipt.Status != 0 || op.FailureCode != "UNAUTHORIZED" || len(op.TraceAttempts) == 0 {
		t.Fatal("original failure trace or unchanged-state check failed")
	}
	attempt := op.TraceAttempts[len(op.TraceAttempts)-1]
	if attempt.TxHash != op.TxHash || attempt.BlockHash != op.Receipt.BlockHash || attempt.TransactionIndex != op.Receipt.TransactionIndex || attempt.Error != "" || len(attempt.RevertData) != 4 {
		t.Fatal("trace binding mismatch")
	}
	options := map[string]any{"opcodes": []string{"REVERT"}, "disableStorage": true, "disableMemory": true, "disableStack": true}
	var opcode json.RawMessage
	if err = h.r.Client.Client().CallContext(h.ctx, &opcode, "debug_traceTransaction", op.TxHash, options); err != nil {
		t.Fatal(err)
	}
	h.cases = append(h.cases, map[string]any{"name": "bound-original-execution", "passed": true, "balanceBefore": balance.String(), "before": before, "after": state(), "operation": op, "opcodeRequest": map[string]any{"method": "debug_traceTransaction", "txHash": op.TxHash, "options": options}, "opcodeResult": opcode})
}

func TestTraceFailureRecoveryIntegration(t *testing.T) {
	h := newRegistryHarness(t, "trace-failure-recovery")
	g := h.f.Grants["G1"]
	original := h.tx("trace-revoke-unrelated", "unrelated", "revokeGrant", false, g.GrantId, uint64(1), g.Digest)
	for _, kind := range []string{"missing", "truncated", "unknown-selector", "malformed-data"} {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "operations"), 0700); err != nil {
			t.Fatal(err)
		}
		op := cloneValue(*original)
		op.FailureCode = "TRANSACTION_REVERTED"
		op.TraceAttempts = nil
		if err := durableJSON(filepath.Join(dir, "operations", op.ID+".json"), &op); err != nil {
			t.Fatal(err)
		}
		injected := true
		recorder := &RPCRecorder{}
		recorder.Before = func(q RPCRequest) error {
			if injected && kind == "missing" && q.Method == "debug_traceTransaction" {
				return fmt.Errorf("injected unavailable original trace")
			}
			return nil
		}
		recorder.After = func(q RPCRequest, b []byte) ([]byte, error) {
			if !injected || q.Method != "debug_traceTransaction" {
				return b, nil
			}
			var envelope map[string]any
			if err := json.Unmarshal(b, &envelope); err != nil {
				return nil, err
			}
			result := envelope["result"].(map[string]any)
			switch kind {
			case "truncated":
				result["truncated"] = true
			case "unknown-selector":
				result["output"] = "0xdeadbeef"
			case "malformed-data":
				result["output"] = "0x0"
			}
			return json.Marshal(envelope)
		}
		client, err := RecordedClient(h.ctx, "http://127.0.0.1:18547", recorder)
		if err != nil {
			t.Fatal(err)
		}
		failed, err := EnrichFailure(h.ctx, client, dir, &op, h.r.ABI)
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		if failed.Status != "FAILED" || failed.FailureCode != "TRANSACTION_REVERTED" || len(failed.TraceAttempts) != 1 || failed.TraceAttempts[0].Error == "" {
			t.Fatal("invalid missing-reason failure result")
		}
		before := cloneValue(*failed)
		injected = false
		recovered, err := EnrichFailure(h.ctx, client, dir, failed, h.r.ABI)
		client.Close()
		if err != nil {
			t.Fatal(err)
		}
		if recovered.Status != "FAILED" || recovered.FailureCode != "UNAUTHORIZED" || recovered.TxHash != before.TxHash || !reflect.DeepEqual(recovered.Receipt, before.Receipt) || !reflect.DeepEqual(recovered.Raw, before.Raw) {
			t.Fatal("reason recovery changed failure terminal or original evidence")
		}
		for _, sample := range recorder.Snapshot() {
			if sample.Request.Method == "eth_sendRawTransaction" || sample.Request.Method == "eth_getTransactionCount" {
				t.Fatal("reason recovery created another operation")
			}
		}
		h.cases = append(h.cases, map[string]any{"name": kind, "passed": true, "before": before, "after": recovered, "rpc": recorder.Snapshot()})
	}
}

func TestRevisionCompetitionIntegration(t *testing.T) {
	h := newRegistryHarness(t, "revision-competition")
	g := h.f.Grants["G1"]
	runID := fmt.Sprint(time.Now().UnixNano())
	g.GrantId = hashID("urn:grad:grant:revision-competition:" + runID)
	g = anchorSyntheticGrant(h.f, g)
	h.tx("race-register-"+runID, "U", "registerGrant", true, g)
	data, err := h.r.ABI.Pack("revokeGrant", g.GrantId, uint64(1), g.Digest)
	if err != nil {
		t.Fatal(err)
	}
	actions := []BatchAction{}
	for _, role := range []string{"U", "A1"} {
		key, err := crypto.LoadECDSA(filepath.Join(h.r.Dir, "keys", role, "management.key"))
		if err != nil {
			t.Fatal(err)
		}
		actions = append(actions, BatchAction{ID: h.r.Deployment.DeploymentID[:8] + "-race-" + runID + "-" + role, Key: key, Target: &h.r.Deployment.RegistryAddress, Data: data})
	}
	bothPersisted := false
	recorder := &RPCRecorder{}
	recorder.Before = func(q RPCRequest) error {
		if q.Method == "eth_sendRawTransaction" && !bothPersisted {
			for _, a := range actions {
				b, err := os.ReadFile(filepath.Join(h.r.Dir, "operations", a.ID+".json"))
				var op Operation
				if err != nil || json.Unmarshal(b, &op) != nil || len(op.Raw) == 0 {
					return fmt.Errorf("batch operation missing before broadcast")
				}
			}
			bothPersisted = true
		}
		return nil
	}
	client, err := RecordedClient(h.ctx, "http://127.0.0.1:18547", recorder)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ops, err := SubmitBatch(h.ctx, client, h.r.Dir, actions, ChainID)
	if err != nil {
		t.Fatal(err)
	}
	success, failed := 0, 0
	for i, op := range ops {
		if op.Status == "CONFIRMED" {
			success++
		} else if op.Status == "FAILED" {
			failed++
			ops[i], err = EnrichFailure(h.ctx, client, h.r.Dir, op, h.r.ABI)
			if err != nil || ops[i].FailureCode != "STATE_CHANGED" {
				t.Fatalf("competition error not bound to original transaction: %v", err)
			}
		}
	}
	stored, err := viewRecord[GrantRecord](h.ctx, h.r, "getGrant", g.GrantId)
	if err != nil {
		t.Fatal(err)
	}
	if success != 1 || failed != 1 || stored.Status != StatusRevoked || stored.Revision != 2 || ops[0].TxHash == ops[1].TxHash || !bothPersisted {
		t.Fatal("invalid revision competition result")
	}
	h.cases = append(h.cases, map[string]any{"name": "two-prepared-revocations", "passed": true, "expectedRevision": 1, "bothPersistedBeforeFirstBroadcast": bothPersisted, "operations": ops, "finalGrant": stored, "rpc": recorder.Snapshot()})
}

func TestBlockTraceFallbackFaultsIntegration(t *testing.T) {
	h := newRegistryHarness(t, "block-trace-fallback-faults")
	b, err := os.ReadFile(filepath.Join(os.Getenv("LEDGER_EVIDENCE"), "revision-competition.json"))
	if err != nil {
		t.Fatal("run TestRevisionCompetitionIntegration first: ", err)
	}
	var report struct {
		DeploymentID string `json:"deploymentId"`
		Cases        []struct {
			Operations []*Operation `json:"operations"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(b, &report); err != nil || report.DeploymentID != h.r.Deployment.DeploymentID {
		t.Fatal("competition evidence deployment mismatch")
	}
	var original *Operation
	for _, c := range report.Cases {
		for _, op := range c.Operations {
			if op.Status == "FAILED" && op.Receipt.TransactionIndex > 0 {
				original = op
			}
		}
	}
	if original == nil {
		t.Fatal("need a same-block losing transaction for fallback validation")
	}
	for _, kind := range []string{"missing", "wrong-order", "truncated", "wrong-gas", "wrong-status", "missing-root-revert"} {
		dir := t.TempDir()
		os.MkdirAll(filepath.Join(dir, "operations"), 0700)
		op := cloneValue(*original)
		op.FailureCode = "TRANSACTION_REVERTED"
		op.TraceAttempts = nil
		if err = durableJSON(filepath.Join(dir, "operations", op.ID+".json"), &op); err != nil {
			t.Fatal(err)
		}
		injected := true
		recorder := &RPCRecorder{}
		recorder.Before = func(q RPCRequest) error {
			if injected && kind == "missing" && q.Method == "debug_traceBlockByHash" {
				return fmt.Errorf("injected missing original block trace")
			}
			return nil
		}
		recorder.After = func(q RPCRequest, b []byte) ([]byte, error) {
			if !injected || q.Method != "debug_traceBlockByHash" {
				return b, nil
			}
			var envelope map[string]any
			if err := json.Unmarshal(b, &envelope); err != nil {
				return nil, err
			}
			entries := envelope["result"].([]any)
			result := entries[original.Receipt.TransactionIndex].(map[string]any)["result"].(map[string]any)
			switch kind {
			case "wrong-order":
				entries[0], entries[1] = entries[1], entries[0]
			case "truncated":
				result["truncated"] = true
			case "wrong-gas":
				result["gas"] = result["gas"].(float64) + 1
			case "wrong-status":
				result["failed"] = false
			case "missing-root-revert":
				result["structLogs"] = []any{}
				result["returnValue"] = "0x"
			}
			return json.Marshal(envelope)
		}
		client, err := RecordedClient(h.ctx, "http://127.0.0.1:18547", recorder)
		if err != nil {
			t.Fatal(err)
		}
		failed, err := EnrichFailure(h.ctx, client, dir, &op, h.r.ABI)
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		if failed.Status != "FAILED" || failed.FailureCode != "TRANSACTION_REVERTED" {
			t.Fatalf("accepted invalid original block trace: %s", kind)
		}
		before := cloneValue(*failed)
		injected = false
		recovered, err := EnrichFailure(h.ctx, client, dir, failed, h.r.ABI)
		client.Close()
		if err != nil {
			t.Fatal(err)
		}
		if recovered.Status != "FAILED" || recovered.FailureCode != "STATE_CHANGED" || !reflect.DeepEqual(recovered.Raw, before.Raw) || !reflect.DeepEqual(recovered.Receipt, before.Receipt) {
			t.Fatalf("invalid original block trace recovery: %s", kind)
		}
		h.cases = append(h.cases, map[string]any{"name": kind, "passed": true, "before": before, "after": recovered, "rpc": recorder.Snapshot()})
	}
}
