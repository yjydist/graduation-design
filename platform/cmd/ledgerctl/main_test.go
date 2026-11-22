package main

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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/runtime"
	"grad/platform/state/fabric"
	"grad/protocol/registry"
)

func prepareOfflineInstanceDir(t *testing.T) (string, *runtime.Fixtures) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "network.env"), []byte("FABRIC_DB=5432\n"), 0644))

	inst, err := fabric.OpenInstance(dir)
	require.NoError(t, err)

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
	now := time.Now().UTC().Truncate(time.Second)
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
		require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644))
	}

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
		GenesisHash:   registry.Digest([]byte("cli-genesis/" + t.Name())),
		InstanceID:    registry.Digest([]byte("cli-instance/" + t.Name())),
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
		ConfigDigest:     registry.Digest([]byte("cli-config")),
		BootstrapDigest:  registry.Digest(bootRaw),
		BuildDigest:      registry.Digest([]byte("cli-build")),
		SourceDigest:     registry.Digest([]byte("cli-source")),
		PackageIDs: map[string]string{
			"a": "authregistry_a:" + registry.Digest([]byte("pkg-a")),
			"b": "authregistry_b:" + registry.Digest([]byte("pkg-b")),
			"c": "authregistry_c:" + registry.Digest([]byte("pkg-c")),
		},
		DefinitionDigest: registry.Digest([]byte("cli-def")),
		DefinitionBlock:  fabric.Point{Number: 1, Hash: registry.Digest([]byte("b1"))},
		DefinitionTxID:   registry.Digest([]byte("tx1")),
		InitBlock:        fabric.Point{Number: 2, Hash: registry.Digest([]byte("b2"))},
		Bootstrap:        boot,
	}
	require.NoError(t, fabric.WriteJSON(inst.RegistryPath("deployment.json"), dep))

	f, err := runtime.PrepareFixtures(inst, dep, nil)
	require.NoError(t, err)
	return dir, f
}

func TestLedgerctlHelpListsAllSevenSubcommands(t *testing.T) {
	var out, errOut bytes.Buffer
	cmd := newRootCmd(strings.NewReader(""), &out, &errOut)

	expected := []string{"deploy", "seed", "check", "inspect", "invoke", "operation", "mcp"}
	var registered []string
	for _, sub := range cmd.Commands() {
		registered = append(registered, sub.Name())
	}
	assert.ElementsMatch(t, expected, registered)

	cmd.SetArgs([]string{"--help"})
	require.NoError(t, cmd.Execute())

	help := out.String()
	for _, sub := range expected {
		assert.Contains(t, help, sub)
	}
}

func TestLedgerctlFlagValidationAndErrors(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "unknown subcommand",
			args:    []string{"nonexistent"},
			wantErr: "unknown command",
		},
		{
			name:    "invalid non-positive timeout",
			args:    []string{"--timeout", "0s", "seed"},
			wantErr: "invalid --timeout",
		},
		{
			name:    "invoke missing required flags",
			args:    []string{"invoke", "--key", "op-1"},
			wantErr: "invoke requires --key, --role, --method, and --input",
		},
		{
			name:    "operation missing key",
			args:    []string{"operation"},
			wantErr: "operation requires --key",
		},
		{
			name:    "inspect missing block",
			args:    []string{"inspect"},
			wantErr: "inspect requires --block",
		},
		{
			name:    "inspect negative block",
			args:    []string{"inspect", "--block", "-5"},
			wantErr: "inspect requires --block",
		},
		{
			name:    "deploy rejects unexpected positional arg",
			args:    []string{"deploy", "extra"},
			wantErr: "unknown command",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			cmd := newRootCmd(strings.NewReader(""), &out, &errOut)
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestLedgerctlMCPStdioHandshakeInProcessAndCommandTransport(t *testing.T) {
	dir, f := prepareOfflineInstanceDir(t)
	expectedTools := []string{
		"inspect_wallet",
		"delegate_grant",
		"replace_grant",
		"request_quote",
		"create_order",
		"reconcile_order",
	}

	t.Run("in-process io.Pipe stdio loop", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		c2sR, c2sW := io.Pipe()
		s2cR, s2cW := io.Pipe()
		var errOut bytes.Buffer

		cmd := newRootCmd(c2sR, s2cW, &errOut)
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{"mcp", "--dir", dir, "--offline", "--gateway", "https://c.local"})

		done := make(chan error, 1)
		go func() {
			defer s2cW.Close()
			done <- cmd.Execute()
		}()

		client := mcp.NewClient(&mcp.Implementation{Name: "ledgerctl-test", Version: "v1.0.0"}, nil)
		session, err := client.Connect(ctx, &mcp.IOTransport{Reader: s2cR, Writer: c2sW}, nil)
		require.NoError(t, err)

		toolsResp, err := session.ListTools(ctx, &mcp.ListToolsParams{})
		require.NoError(t, err)
		var got []string
		for _, tool := range toolsResp.Tools {
			got = append(got, tool.Name)
		}
		assert.ElementsMatch(t, expectedTools, got)

		callRes, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name:      "inspect_wallet",
			Arguments: map[string]any{"actor": "B1"},
		})
		require.NoError(t, err)
		raw, err := json.Marshal(callRes)
		require.NoError(t, err)
		assert.Contains(t, string(raw), f.Identities["B1"].ID)
		assert.NotContains(t, string(raw), "PRIVATE KEY")

		require.NoError(t, session.Close())
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("ledgerctl mcp goroutine did not terminate")
		}
	})

	t.Run("real subprocess CommandTransport", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		bin := filepath.Join(t.TempDir(), "ledgerctl")
		buildOut, err := exec.CommandContext(ctx, "go", "build", "-o", bin, ".").CombinedOutput()
		require.NoError(t, err, "build ledgerctl: %s", buildOut)

		client := mcp.NewClient(&mcp.Implementation{Name: "ledgerctl-cmd-test", Version: "v1.0.0"}, nil)
		session, err := client.Connect(ctx, &mcp.CommandTransport{
			Command: exec.CommandContext(ctx, bin, "mcp", "--dir", dir, "--offline", "--gateway", "https://c.local"),
		}, nil)
		require.NoError(t, err)

		toolsResp, err := session.ListTools(ctx, &mcp.ListToolsParams{})
		require.NoError(t, err)
		var got []string
		for _, tool := range toolsResp.Tools {
			got = append(got, tool.Name)
		}
		assert.ElementsMatch(t, expectedTools, got)
		require.NoError(t, session.Close())
	})
}
