package runtime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/agent"
	"grad/platform/state/fabric"
	"grad/protocol"
	"grad/protocol/registry"
)

func newOfflineInstanceAndDeployment(t *testing.T) (*fabric.Instance, *fabric.Deployment) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "network.env"), []byte("FABRIC_DB=5432\n"), 0644))

	inst, err := fabric.OpenInstance(dir)
	require.NoError(t, err)
	writeTestRoleCerts(t, inst)

	now := time.Now().UTC().Truncate(time.Second)
	mat, err := inst.EnsureBootstrapMaterials(now)
	require.NoError(t, err)

	bindings := map[string]registry.Management{}
	for _, role := range []string{"init", "T", "U", "C"} {
		_, m, _, err := inst.Role(role)
		require.NoError(t, err)
		bindings[role] = m
	}

	fields := registry.DeploymentFields{
		ChannelID:     registry.Channel,
		GenesisHash:   registry.Digest([]byte("genesis/" + t.Name())),
		InstanceID:    registry.Digest([]byte("instance/" + t.Name())),
		RegistryName:  registry.Registry,
		SchemaVersion: registry.Schema,
	}
	boot := registry.Bootstrap{
		DeploymentFields: fields,
		Root: registry.RootRecord{
			DID:            "did:web:t.local",
			Management:     bindings["T"],
			DocumentDigest: mat.RootDIDDigest,
			KeyID:          "did:web:t.local#key-1",
			KeyVersion:     1,
			PublicKey:      mat.RootPubHex,
		},
		Initializer:        bindings["init"],
		TaskCreator:        registry.TaskAuthority{Domain: "A", Subject: fabric.SubjectU, Management: bindings["U"]},
		ResourceID:         registry.Digest([]byte("resource:" + fabric.SubjectC)),
		ResourceOwner:      fabric.SubjectC,
		ResourceManagement: bindings["C"],
	}
	bootRaw, err := json.Marshal(boot)
	require.NoError(t, err)
	require.NoError(t, fabric.WritePublicFile(inst.RegistryPath("bootstrap.json"), bootRaw))

	dep := &fabric.Deployment{
		DeploymentFields: fields,
		DeploymentID:     fields.DeploymentID(),
		ConfigDigest:     registry.Digest([]byte("config/" + t.Name())),
		BootstrapDigest:  registry.Digest(bootRaw),
		BuildDigest:      registry.Digest([]byte("build/" + t.Name())),
		SourceDigest:     registry.Digest([]byte("source/" + t.Name())),
		PackageIDs: map[string]string{
			"a": "authregistry_a:" + registry.Digest([]byte("pkg-a")),
			"b": "authregistry_b:" + registry.Digest([]byte("pkg-b")),
			"c": "authregistry_c:" + registry.Digest([]byte("pkg-c")),
		},
		DefinitionDigest: registry.Digest([]byte("def/" + t.Name())),
		DefinitionBlock:  fabric.Point{Number: 1, Hash: registry.Digest([]byte("blk1"))},
		DefinitionTxID:   registry.Digest([]byte("deftx")),
		InitBlock:        fabric.Point{Number: 2, Hash: registry.Digest([]byte("blk2"))},
		Bootstrap:        boot,
	}
	require.NoError(t, fabric.WriteJSON(inst.RegistryPath("deployment.json"), dep))
	return inst, dep
}

func writeTestRoleCerts(t *testing.T, inst *fabric.Instance) {
	t.Helper()
	type loc struct{ org, user string }
	locs := map[string]loc{
		"init":       {"a", "User1"},
		"T":          {"t", "User1"},
		"domainA":    {"a", "User2"},
		"registrarA": {"a", "User3"},
		"IA":         {"a", "User4"},
		"U":          {"a", "User5"},
		"A1":         {"a", "User6"},
		"alt":        {"a", "User7"},
		"PA":         {"a", "User9"},
		"domainB":    {"b", "User2"},
		"registrarB": {"b", "User3"},
		"IB":         {"b", "User4"},
		"B1":         {"b", "User5"},
		"U-in-B":     {"b", "User6"},
		"B2":         {"b", "User8"},
		"recoverB":   {"b", "User9"},
		"domainC":    {"c", "User2"},
		"registrarC": {"c", "User3"},
		"IC":         {"c", "User4"},
		"C":          {"c", "User5"},
		"probe1":     {"c", "User6"},
		"probe2":     {"c", "User7"},
		"read":       {"c", "User8"},
	}
	now := time.Now().UTC()
	for _, r := range locs {
		user := r.user + "@" + r.org + ".local"
		certPath := filepath.Join(inst.OrgDir(r.org), "users", user, "msp", "signcerts", user+"-cert.pem")
		require.NoError(t, os.MkdirAll(filepath.Dir(certPath), 0755))
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: user},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
		require.NoError(t, err)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		require.NoError(t, os.WriteFile(certPath, certPEM, 0644))
	}
}

func TestPrepareFixturesSchemaAndVerification(t *testing.T) {
	inst, dep := newOfflineInstanceAndDeployment(t)

	ids := func(mode string) ProcurementPathIDs {
		return ProcurementPathIDs{
			Task: registry.Digest([]byte(mode + "/task")),
			G0:   registry.Digest([]byte(mode + "/G0")),
			G1:   registry.Digest([]byte(mode + "/G1")),
			G2:   registry.Digest([]byte(mode + "/G2")),
		}
	}
	setup := ProcurementSetup{
		Spec: protocol.TaskSpec{
			SupplierID:  "urn:grad:supplier:C",
			ProductID:   "urn:grad:product:P1",
			MaxQuantity: 2,
			Currency:    "CNY",
			Description: "Unit test procurement setup",
			Resources:   []string{protocol.ResourceOrders, protocol.ResourceQuotes},
			Actions:     []string{protocol.ActionOrderCreate, protocol.ActionQuoteRead},
		},
		RP: ids(registry.RP),
		BM: ids(registry.BM),
	}

	f, err := PrepareFixtures(inst, dep, &setup)
	require.NoError(t, err)
	require.Equal(t, protocol.SchemaVersion, f.SchemaVersion)
	require.Equal(t, dep.DeploymentID, f.DeploymentID)
	require.Equal(t, setup.RP.Task, f.RPTask.ID)
	require.Equal(t, setup.BM.Task, f.BMTask.ID)

	// Verify standardized credential key "C" and zero legacy keys.
	_, hasC := f.Credentials["C"]
	assert.True(t, hasC)
	_, hasLegacyCService := f.Credentials["C-service"]
	assert.False(t, hasLegacyCService)

	// Verify persisted fixtures.json schema: "procurementTaskSpec" present, NO "m2TaskSpec" or "synthetic".
	persisted, err := os.ReadFile(inst.RegistryPath("fixtures.json"))
	require.NoError(t, err)
	assert.Contains(t, string(persisted), `"procurementTaskSpec"`)
	assert.NotContains(t, string(persisted), `"m2TaskSpec"`)
	assert.NotContains(t, string(persisted), `"synthetic"`)

	// Strict reload must succeed and match; differing setup must fail.
	reloaded, err := LoadFixtures(inst)
	require.NoError(t, err)
	assert.Equal(t, f.RPTask.ID, reloaded.RPTask.ID)
	_, err = PrepareFixtures(inst, dep, &setup)
	require.NoError(t, err)

	modified := setup
	modified.Spec.MaxQuantity++
	_, err = PrepareFixtures(inst, dep, &modified)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "differs from persisted fixtures")

	// Verify T private key is isolated under private/ with 0600 mode.
	info, err := os.Stat(inst.PrivatePath("app", "T.key.pem"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Verify both RP and BM 2-hop grant chains cryptographically.
	snap := BuildFixtureSnapshot(dep, f, time.Now().UTC())
	for n, mode := range []string{registry.RP, registry.BM} {
		prefix := []string{"rp", "bm"}[n]
		grants := []registry.Grant{f.RPG0, f.RPG1, f.RPG2}
		if n == 1 {
			grants = []registry.Grant{f.BMG0, f.BMG1, f.BMG2}
		}
		var parsed []*protocol.ParsedGrant
		for hop, anchored := range grants {
			jwsBytes, err := os.ReadFile(inst.RegistryPath("grants", prefix+"_"+[]string{"g0", "g1", "g2"}[hop]+".jws"))
			require.NoError(t, err)
			issuer := snap.Identities[anchored.Issuer]
			pub, err := protocol.ParseAppPublicKey(issuer.PublicKey)
			require.NoError(t, err)
			p, err := protocol.ParseAndVerifyGrant(string(jwsBytes), pub, issuer.KeyID)
			require.NoError(t, err)
			assert.Equal(t, mode, p.Claims.AuthorizationMode)
			assert.Equal(t, []int64{500000, 500000, 100000}[hop], p.Claims.MaxAmountMinor)
			assert.Equal(t, int64(2-hop), p.Claims.RemainingDepth)
			assert.Equal(t, anchored.Digest, registry.Digest(jwsBytes))
			parsed = append(parsed, p)
		}
		require.NoError(t, protocol.VerifyGrantChain(parsed))
	}

	// Verify sample AccessEvidencePackage against controlled did:web server.
	didSrv, resolver, err := inst.StartRegistryDIDResolver(dep)
	require.NoError(t, err)
	defer didSrv.Close()

	for _, sampleName := range []string{"evidence-sample.json", "u-quote-sample.json"} {
		sampleRaw, err := os.ReadFile(inst.RegistryPath(sampleName))
		require.NoError(t, err)
		var sample EvidenceSample
		require.NoError(t, protocol.DecodeStrictJSON(sampleRaw, &sample))
		res, err := protocol.VerifyAccessEvidencePackage(context.Background(), &sample.Package, snap, resolver, protocol.ChallengeContext{
			ChallengeID: sample.ChallengeID,
			Nonce:       sample.Nonce,
			Audience:    sample.Audience,
			IssuedAt:    sample.IssuedAt,
			ExpiresAt:   sample.ExpiresAt,
		})
		require.NoError(t, err, "sample %s verification failed", sampleName)
		assert.Equal(t, sample.Bindings.EvidenceHash, res.Bindings.EvidenceHash)
	}
}

func TestScanDirForPrivateKeysAndPublicFileCollection(t *testing.T) {
	inst, dep := newOfflineInstanceAndDeployment(t)
	_, err := PrepareFixtures(inst, dep, nil)
	require.NoError(t, err)

	scanned, err := ScanDirForPrivateKeys(inst.RegistryPath("."))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(scanned), 25)

	pubFiles, err := CollectRegistryPublicFiles(inst)
	require.NoError(t, err)
	assert.Contains(t, pubFiles, "fixtures.json")
	assert.Contains(t, pubFiles, "credentials/C.sdjwt")
	assert.Contains(t, pubFiles, "certifications/A.jws")
	assert.Contains(t, pubFiles, "grants/rp_g2.jws")
	assert.Contains(t, pubFiles, "grants/bm_g2.jws")

	// Reject leaked private key PEM content.
	leakDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(leakDir, "leaked.pem"), []byte("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"), 0644))
	_, err = ScanDirForPrivateKeys(leakDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PRIVATE KEY")

	// Reject forbidden filename.
	nameLeakDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(nameLeakDir, "actor.key.pem"), []byte("not-pem"), 0644))
	_, err = ScanDirForPrivateKeys(nameLeakDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden private key filename")
}

func TestBuildWalletOfflineAndMCPStdioHandshake(t *testing.T) {
	inst, dep := newOfflineInstanceAndDeployment(t)
	f, err := PrepareFixtures(inst, dep, nil)
	require.NoError(t, err)

	// Verify SeedReport helper methods.
	rep := &SeedReport{fixtureBody: f, Scope: "unit"}
	assert.Equal(t, f, rep.Fixtures())
	assert.Equal(t, dep.DeploymentID, rep.RegistrationSnapshot(dep).DeploymentID)

	// Build offline wallet (db=nil, handler=nil) and inspect B1 grants.
	w, err := BuildWallet(context.Background(), inst, dep, f, nil, nil, WithGatewayURL("https://c.local"))
	require.NoError(t, err)
	out, err := w.InspectWallet(context.Background(), agent.InspectWalletInput{Actor: "B1"})
	require.NoError(t, err)
	assert.Equal(t, f.Identities["B1"].ID, out.DID)
	assert.Len(t, out.Grants, 2) // RP G2 and BM G2

	// Verify NewLocalMTLSClient forwards requests cleanly to ReceiptHandler.
	client := NewLocalMTLSClient(w.ReceiptHandler(), defaultAuditSvcDID, "C_AUDIT_SERVICE", "CMsp")
	resp, err := client.Post(receiptEndpointPath, "application/json", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode) // Authenticated mTLS caller passes authz, fails schema validation.

	// Verify RunMCP over io.Pipe() completes initialize + tools/list with all 6 tools.
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srvErrCh := make(chan error, 1)
	go func() {
		defer s2cW.Close()
		srvErrCh <- RunMCP(ctx, inst, dep, nil, "https://c.local", c2sR, s2cW)
	}()

	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1.0.0"}, nil)
	session, err := mcpClient.Connect(ctx, &mcp.IOTransport{Reader: s2cR, Writer: c2sW}, nil)
	require.NoError(t, err)

	toolsResp, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	require.NoError(t, err)
	var names []string
	for _, tool := range toolsResp.Tools {
		names = append(names, tool.Name)
	}
	assert.ElementsMatch(t, []string{
		"inspect_wallet",
		"delegate_grant",
		"replace_grant",
		"request_quote",
		"create_order",
		"reconcile_order",
	}, names)

	// Invoke inspect_wallet via MCP and confirm zero private key or JWS leaks.
	callRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "inspect_wallet",
		Arguments: map[string]any{"actor": "B1"},
	})
	require.NoError(t, err)
	rawRes, err := json.Marshal(callRes)
	require.NoError(t, err)
	assert.Contains(t, string(rawRes), f.Identities["B1"].ID)
	assert.NotContains(t, string(rawRes), "PRIVATE KEY")
	assert.False(t, strings.Contains(string(rawRes), "~"), "MCP tool output must never leak SD-JWT disclosure segments")

	require.NoError(t, session.Close())
	cancel()
	select {
	case <-srvErrCh:
	case <-time.After(3 * time.Second):
		t.Fatal("RunMCP did not exit after closing client session")
	}
}
