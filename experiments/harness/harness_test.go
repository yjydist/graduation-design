package harness

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteJSONReadJSONAndMergeJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "manifest.json")

	type sample struct {
		RunID  string `json:"runId"`
		Status string `json:"status"`
		Count  int    `json:"count"`
	}

	in := sample{RunID: "run-0123456789abcdef", Status: "INITIALIZED", Count: 3}
	require.NoError(t, WriteJSON(path, in))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, bytes.HasSuffix(raw, []byte("\n")), "WriteJSON should append trailing newline")

	var got sample
	require.NoError(t, ReadJSON(path, &got))
	assert.Equal(t, in, got)

	// Merge into existing file.
	require.NoError(t, MergeJSON(path, map[string]any{
		"status": "PASS",
		"stage":  "finalize",
	}))

	var merged map[string]any
	require.NoError(t, ReadJSON(path, &merged))
	assert.Equal(t, "run-0123456789abcdef", merged["runId"])
	assert.Equal(t, "PASS", merged["status"])
	assert.Equal(t, "finalize", merged["stage"])
	assert.Equal(t, float64(3), merged["count"])

	// Merge into non-existent file creates it cleanly.
	freshPath := filepath.Join(dir, "summary.json")
	require.NoError(t, MergeJSON(freshPath, map[string]any{"ok": true}))
	var fresh map[string]any
	require.NoError(t, ReadJSON(freshPath, &fresh))
	assert.Equal(t, true, fresh["ok"])
}

func TestWriteCSVAndReadCSVRoundTrip(t *testing.T) {
	t.Parallel()

	type row struct {
		RunID     string  `csv:"run_id"`
		Seq       int     `csv:"seq"`
		Disposition string `csv:"disposition"`
		LatencyMs float64 `csv:"latency_ms"`
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "requests.csv")
	want := []row{
		{RunID: "run-1", Seq: 1, Disposition: "allow", LatencyMs: 12.5},
		{RunID: "run-1", Seq: 2, Disposition: "deny", LatencyMs: 3.25},
	}

	require.NoError(t, WriteCSV(path, want))
	got, err := ReadCSV[row](path)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	// Empty slice still writes header and reads back as empty slice.
	emptyPath := filepath.Join(dir, "empty.csv")
	require.NoError(t, WriteCSV(emptyPath, []row{}))
	emptyRaw, err := os.ReadFile(emptyPath)
	require.NoError(t, err)
	assert.Contains(t, string(emptyRaw), "run_id,seq,disposition,latency_ms")

	emptyGot, err := ReadCSV[row](emptyPath)
	require.NoError(t, err)
	assert.Empty(t, emptyGot)
}

func TestSHA256Helpers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "data.txt")
	content := []byte("deterministic-payload\n")
	require.NoError(t, WriteAtomic(p, content, 0o644))

	fileDigest, err := SHA256File(p)
	require.NoError(t, err)
	assert.Equal(t, SHA256Bytes(content), fileDigest)
	assert.Len(t, fileDigest, 64)
}

func TestScanExportsAndCollectInstanceSecrets(t *testing.T) {
	t.Parallel()

	t.Run("clean directory passes", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		require.NoError(t, WriteJSON(filepath.Join(dir, "manifest.json"), map[string]any{
			"runId":         "run-0123456789abcdef",
			"status":        "PASS",
			"archiveSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		}))
		require.NoError(t, WriteAtomic(filepath.Join(dir, "requests.csv"), []byte("seq,status\n1,200\n"), 0o644))
		// Skipped archive extension should not be scanned.
		require.NoError(t, WriteAtomic(filepath.Join(dir, "driver-source.tar.gz"), []byte("-----BEGIN PRIVATE KEY-----"), 0o644))

		findings, err := ScanExports(dir)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("catches PEM private key, hex private key, API keys, salt, SD-JWT, and runtime secrets", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		require.NoError(t, WriteAtomic(filepath.Join(dir, "key.txt"), []byte("-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----\n"), 0o644))
		require.NoError(t, WriteAtomic(filepath.Join(dir, "hex.json"), []byte(`{"appPrivateKey":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`), 0o644))
		require.NoError(t, WriteAtomic(filepath.Join(dir, "openai.log"), []byte("leaked key sk-proj1234567890abcdef1234\n"), 0o644))
		require.NoError(t, WriteAtomic(filepath.Join(dir, "env.log"), []byte("OPENAI_API_KEY=supersecretvalue12345\nAuthorization: Bearer tok_abcdef12345678\n"), 0o644))
		require.NoError(t, WriteAtomic(filepath.Join(dir, "salt.json"), []byte(`{"account_salt":"saltyvalue123456"}`), 0o644))
		require.NoError(t, WriteAtomic(filepath.Join(dir, "sdjwt.txt"), []byte("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6d2ViOmEifQ.sigvalue12345~WyJzYWx0MTIzNDU2Iiwicm9sZSIsImJ1eWVyIl0~"), 0o644))

		// Set up a mock Fabric instance dir with view-password and credential salt.
		instDir := t.TempDir()
		require.NoError(t, WriteAtomic(filepath.Join(instDir, "view-password"), []byte("pg-secret-pass-9876\n"), 0o600))
		disc := base64.RawURLEncoding.EncodeToString([]byte(`["cred-salt-xyz98765","role","buyer"]`))
		cred := "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6d2ViOmEifQ.sigval123456~" + disc + "~"
		require.NoError(t, WriteAtomic(filepath.Join(instDir, "registry", "credentials", "buyer.sdjwt"), []byte(cred), 0o600))

		require.NoError(t, WriteAtomic(filepath.Join(dir, "leak-runtime.txt"), []byte("salt leaked: cred-salt-xyz98765\n"), 0o644))

		secrets := CollectInstanceSecrets(instDir)
		require.NotEmpty(t, secrets)

		findings, err := ScanExports(dir, secrets...)
		require.NoError(t, err)

		rulesByFile := map[string][]string{}
		for _, f := range findings {
			rulesByFile[f.Path] = append(rulesByFile[f.Path], f.Rule)
		}
		assert.Contains(t, rulesByFile["key.txt"], "private_key_pem")
		assert.Contains(t, rulesByFile["hex.json"], "private_key_field")
		assert.Contains(t, rulesByFile["openai.log"], "api_key")
		assert.Contains(t, rulesByFile["env.log"], "api_key")
		assert.Contains(t, rulesByFile["env.log"], "bearer_token")
		assert.Contains(t, rulesByFile["salt.json"], "sensitive_field")
		assert.Contains(t, rulesByFile["sdjwt.txt"], "sd_jwt_disclosure")
		assert.Contains(t, rulesByFile["leak-runtime.txt"], "runtime_secret")
	})

	t.Run("RedactSecrets masks sensitive values", func(t *testing.T) {
		t.Parallel()
		got := RedactSecrets("failed with token sk-secret-1234567890", "sk-secret-1234567890")
		assert.Equal(t, "failed with token [REDACTED]", got)
	})
}

func TestRepoRoot(t *testing.T) {
	t.Parallel()

	root, err := RepoRoot()
	require.NoError(t, err)
	_, statErr := os.Stat(filepath.Join(root, "go.work"))
	require.NoError(t, statErr)
}

func TestValidateIsolatedInstance(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	defaultDir := filepath.Join(repoRoot, ".local", "fabric-d0")
	require.NoError(t, os.MkdirAll(defaultDir, 0o755))

	// Direct relative and absolute default path must be rejected.
	_, err := ValidateIsolatedInstance(repoRoot, ".local/fabric-d0", false)
	require.Error(t, err)
	_, err = ValidateIsolatedInstance(repoRoot, defaultDir, true)
	require.Error(t, err)

	// Subdirectory inside default instance must be rejected.
	_, err = ValidateIsolatedInstance(repoRoot, filepath.Join(defaultDir, "sub"), true)
	require.Error(t, err)

	// Symlink to default instance must be rejected.
	symlinkPath := filepath.Join(repoRoot, ".local", "alias-d0")
	require.NoError(t, os.Symlink(defaultDir, symlinkPath))
	_, err = ValidateIsolatedInstance(repoRoot, symlinkPath, false)
	require.Error(t, err)
	_, err = ValidateIsolatedInstance(repoRoot, symlinkPath, true)
	require.Error(t, err)

	// Symlink to .local parent + fabric-d0 leaf must be rejected even if mustNotExist=true.
	localLink := filepath.Join(repoRoot, "local-link")
	require.NoError(t, os.Symlink(filepath.Join(repoRoot, ".local"), localLink))
	_, err = ValidateIsolatedInstance(repoRoot, filepath.Join(localLink, "fabric-d0"), true)
	require.Error(t, err)

	// Isolated non-existent path passes when mustNotExist=true, fails when mustNotExist=false.
	isolated := filepath.Join(repoRoot, ".local", "fabric-e6-iso")
	got, err := ValidateIsolatedInstance(repoRoot, isolated, true)
	require.NoError(t, err)
	assert.Equal(t, isolated, got)

	_, err = ValidateIsolatedInstance(repoRoot, isolated, false)
	require.Error(t, err)

	// Once created, isolated path passes when mustNotExist=false and fails when mustNotExist=true.
	require.NoError(t, os.MkdirAll(isolated, 0o755))
	_, err = ValidateIsolatedInstance(repoRoot, isolated, true)
	require.Error(t, err)

	gotExisting, err := ValidateIsolatedInstance(repoRoot, isolated, false)
	require.NoError(t, err)
	resolvedIsolated, err := filepath.EvalSymlinks(isolated)
	require.NoError(t, err)
	assert.Equal(t, resolvedIsolated, gotExisting)
}

func TestClaimInstanceExclusivity(t *testing.T) {
	t.Parallel()

	instDir := t.TempDir()

	release, err := ClaimInstance(instDir, "baseline-run", "run-aaaabbbbccccdddd")
	require.NoError(t, err)

	raw, err := os.ReadFile(filepath.Join(instDir, "baseline-run"))
	require.NoError(t, err)
	assert.Equal(t, "run-aaaabbbbccccdddd\n", string(raw))

	// Duplicate claim must fail with os.ErrExist.
	_, err = ClaimInstance(instDir, "baseline-run", "run-1111222233334444")
	require.ErrorIs(t, err, os.ErrExist)

	// Releasing allows subsequent claim; release is idempotent.
	release()
	release()

	release2, err := ClaimInstance(instDir, "baseline-run", "run-1111222233334444")
	require.NoError(t, err)
	defer release2()

	// Invalid claim names are rejected.
	_, err = ClaimInstance(instDir, "../escape", "run-1")
	require.Error(t, err)
}

func TestNewRunIDAndCreateRunDirAntiOverwrite(t *testing.T) {
	t.Parallel()

	idRe := regexp.MustCompile(`^run-[0-9a-f]{16}$`)
	id1, err := NewRunID()
	require.NoError(t, err)
	id2, err := NewRunID()
	require.NoError(t, err)
	assert.Regexp(t, idRe, id1)
	assert.Regexp(t, idRe, id2)
	assert.NotEqual(t, id1, id2)

	root := t.TempDir()
	runDir, err := CreateRunDir(root, id1)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, id1), runDir)

	// Creating the same run directory again must fail (anti-overwrite).
	_, err = CreateRunDir(root, id1)
	require.ErrorIs(t, err, os.ErrExist)
}

func TestParseEnvFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	envPath := filepath.Join(dir, "test.env")
	content := `
# comment line
export OPENAI_API_KEY="sk-test-value"
LLM_MODEL='gpt-4o-mini'
FABRIC_BASE_PORT = 17050
EMPTY_VAL=
INVALID_LINE_WITHOUT_EQUALS
`
	require.NoError(t, WriteAtomic(envPath, []byte(content), 0o600))

	got, err := ParseEnvFile(envPath)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"OPENAI_API_KEY":   "sk-test-value",
		"LLM_MODEL":        "gpt-4o-mini",
		"FABRIC_BASE_PORT": "17050",
		"EMPTY_VAL":        "",
	}, got)
}

func TestFabricNetworkCmd(t *testing.T) {
	t.Parallel()

	repoDir := t.TempDir()
	scriptPath := filepath.Join(repoDir, "infra", "fabric", "network.sh")
	script := "#!/bin/sh\necho \"action=$1 instance=$FABRIC_INSTANCE port=$FABRIC_BASE_PORT\"\n"
	require.NoError(t, WriteAtomic(scriptPath, []byte(script), 0o755))

	logPath := filepath.Join(repoDir, "logs", "network-up.log")
	instDir := filepath.Join(repoDir, ".local", "fabric-test")
	require.NoError(t, FabricNetworkCmd(context.Background(), repoDir, "up", instDir, 18050, logPath))

	logBytes, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Contains(t, string(logBytes), "action=up instance="+instDir+" port=18050")
}

func TestBuildSourceSnapshotDeterminism(t *testing.T) {
	t.Parallel()

	repoDir := t.TempDir()
	f1 := filepath.Join(repoDir, "a", "one.go")
	f2 := filepath.Join(repoDir, "b", "two.go")
	require.NoError(t, WriteAtomic(f1, []byte("package a\n"), 0o644))
	require.NoError(t, WriteAtomic(f2, []byte("package b\n"), 0o644))

	out1 := filepath.Join(t.TempDir(), "snap1.tar.gz")
	out2 := filepath.Join(t.TempDir(), "snap2.tar.gz")

	patterns := []string{"b/*.go", "a/*.go", "a/one.go"} // unsorted with duplicate
	hash1, err := BuildSourceSnapshot(repoDir, out1, patterns)
	require.NoError(t, err)

	// Touch mtime to prove archive bytes and digest are independent of file mtimes.
	future := time.Now().Add(2 * time.Hour)
	require.NoError(t, os.Chtimes(f1, future, future))
	require.NoError(t, os.Chtimes(f2, future, future))

	hash2, err := BuildSourceSnapshot(repoDir, out2, []string{"a/*.go", "b/*.go"})
	require.NoError(t, err)
	assert.Equal(t, hash1, hash2)

	b1, err := os.ReadFile(out1)
	require.NoError(t, err)
	b2, err := os.ReadFile(out2)
	require.NoError(t, err)
	assert.Equal(t, b1, b2)

	// Verify sorted entries inside tar.gz.
	gz, err := gzip.NewReader(bytes.NewReader(b1))
	require.NoError(t, err)
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		names = append(names, hdr.Name)
	}
	assert.Equal(t, []string{"a/one.go", "b/two.go"}, names)
}

func TestGitHeadRevisionAndExportGitWorktree(t *testing.T) {
	t.Parallel()

	repoDir := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v failed: %s", args, string(out))
	}

	runGit("init")
	runGit("config", "user.email", "test@example.com")
	runGit("config", "user.name", "Test User")
	require.NoError(t, WriteAtomic(filepath.Join(repoDir, "hello.txt"), []byte("hello world\n"), 0o644))
	runGit("add", "hello.txt")
	runGit("commit", "-m", "init")

	commit, dirty, err := GitHeadRevision(repoDir)
	require.NoError(t, err)
	assert.Len(t, commit, 40)
	assert.False(t, dirty)

	// Export committed tree into destination dir.
	exportDir := filepath.Join(t.TempDir(), "exported")
	require.NoError(t, ExportGitWorktree(context.Background(), repoDir, commit, exportDir))
	got, err := os.ReadFile(filepath.Join(exportDir, "hello.txt"))
	require.NoError(t, err)
	assert.Equal(t, "hello world\n", string(got))

	// Dirty working tree is detected.
	require.NoError(t, WriteAtomic(filepath.Join(repoDir, "untracked.txt"), []byte("dirty"), 0o644))
	commit2, dirty2, err := GitHeadRevision(repoDir)
	require.NoError(t, err)
	assert.Equal(t, commit, commit2)
	assert.True(t, dirty2)
}

func TestMeasureClockResolutionNs(t *testing.T) {
	t.Parallel()

	res := MeasureClockResolutionNs(500)
	assert.Greater(t, res, int64(0))
	assert.Less(t, res, int64(time.Second))
}

func TestComputeLatencyStats(t *testing.T) {
	t.Parallel()

	assert.Equal(t, LatencyStats{}, ComputeLatencyStats(nil))
	assert.Equal(t, LatencyStats{
		Count: 1, MinMs: 7.5, P50Ms: 7.5, P95Ms: 7.5, P99Ms: 7.5, MaxMs: 7.5, MeanMs: 7.5,
	}, ComputeLatencyStats([]float64{7.5}))

	input := []float64{5, 1, 4, 2, 3, math.NaN(), math.Inf(1)}
	orig := append([]float64(nil), input...)
	stats := ComputeLatencyStats(input)

	// Input slice must not be mutated.
	assert.Equal(t, orig[:5], input[:5])

	assert.Equal(t, 5, stats.Count)
	assert.InDelta(t, 1.0, stats.MinMs, 1e-9)
	assert.InDelta(t, 3.0, stats.P50Ms, 1e-9)
	assert.InDelta(t, 4.8, stats.P95Ms, 1e-9)
	assert.InDelta(t, 4.96, stats.P99Ms, 1e-9)
	assert.InDelta(t, 5.0, stats.MaxMs, 1e-9)
	assert.InDelta(t, 3.0, stats.MeanMs, 1e-9)
}

func TestRequestAccountingConcurrent(t *testing.T) {
	t.Parallel()

	acct := NewRequestAccounting()
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			acct.RecordAllow(time.Duration(n+1) * time.Millisecond)
			acct.RecordDeny(2 * time.Millisecond)
			acct.RecordError(5 * time.Millisecond)
			acct.Record(OutcomeMissed, -1)
		}(i)
	}
	wg.Wait()

	snap := acct.Snapshot()
	assert.Equal(t, 40, snap.Total)
	assert.Equal(t, 10, snap.Allow)
	assert.Equal(t, 10, snap.Deny)
	assert.Equal(t, 10, snap.Error)
	assert.Equal(t, 10, snap.Missed)
	assert.Equal(t, 30, snap.Latencies.Count)
	assert.InDelta(t, 1.0, snap.Latencies.MinMs, 1e-6)
	assert.InDelta(t, 10.0, snap.Latencies.MaxMs, 1e-6)
}
