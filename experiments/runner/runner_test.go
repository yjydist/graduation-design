package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func TestInitialManifestAndSnapshotReconstructionBeforeBuild(t *testing.T) {
	repo := testRepoRoot(t)
	tmp := t.TempDir()
	outRoot := filepath.Join(tmp, "runs")
	instanceDir := filepath.Join(tmp, "fabric-e1-plan")

	deps := defaultRunnerDeps()
	deps.RepoRoot = repo
	deps.LookupEnv = func(key string) (string, bool) {
		if key == "LLM_API_KEY" {
			return "test-secret-api-key-12345", true
		}
		return "", false
	}

	res, err := ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: instanceDir,
		BasePort:    19500,
		OutRoot:     outRoot,
		Seed:        2026,
		PlanOnly:    true,
	}, deps)
	if err != nil {
		t.Fatalf("PlanOnly run failed: %v", err)
	}
	if !strings.HasPrefix(res.RunID, "run-") {
		t.Fatalf("expected run-* id, got %q", res.RunID)
	}

	manifest, err := readJSONMap(filepath.Join(res.RunDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read initial manifest: %v", err)
	}
	if manifest["experiment"] != "E1" || manifest["runId"] != res.RunID {
		t.Fatalf("unexpected manifest identity: %+v", manifest)
	}
	if manifest["driverType"] != DriverTypeRealLLMMCP {
		t.Fatalf("unexpected driverType: %v", manifest["driverType"])
	}
	if manifest["sourceCommit"] == "" || manifest["instance"] != instanceDir {
		t.Fatalf("missing sourceCommit or instance in manifest")
	}
	if manifest["binarySHA256"] != nil {
		t.Fatalf("binarySHA256 must be null before build, got %v", manifest["binarySHA256"])
	}
	rawManifest, err := os.ReadFile(filepath.Join(res.RunDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawManifest), "test-secret-api-key-12345") {
		t.Fatalf("manifest leaked LLM_API_KEY")
	}

	// Verify source snapshot reconstructs exact recorded file hashes.
	snapMap, ok := manifest["driverSnapshot"].(map[string]any)
	if !ok {
		t.Fatalf("driverSnapshot missing")
	}
	archivePath := filepath.Join(res.RunDir, snapMap["archiveFile"].(string))
	gotArchiveHash, err := sha256File(archivePath)
	if err != nil || gotArchiveHash != snapMap["archiveSha256"].(string) {
		t.Fatalf("snapshot archive hash mismatch: %v vs %v", gotArchiveHash, snapMap["archiveSha256"])
	}
	fileHashes := manifest["fileSHA256"].(map[string]any)
	extracted := extractTarGz(t, archivePath)
	for rel, expectedHash := range fileHashes {
		content, exists := extracted[rel]
		if !exists {
			t.Fatalf("snapshot archive missing recorded file %s", rel)
		}
		tmpFile := filepath.Join(tmp, "verify-hash")
		if err := os.WriteFile(tmpFile, content, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := sha256File(tmpFile)
		if err != nil || got != expectedHash.(string) {
			t.Fatalf("reconstructed %s hash mismatch: got %s want %s", rel, got, expectedHash)
		}
	}
	for _, mustHave := range []string{"mise.toml", "experiments/runner/run.go", "experiments/e1-procurement/driver/main.go", "experiments/llm.env"} {
		if _, ok := extracted[mustHave]; !ok {
			t.Fatalf("snapshot archive missing essential orchestrator/driver file %s", mustHave)
		}
	}
}

func TestManifestEnrichedWithBinariesAndIsolatedInstance(t *testing.T) {
	repo := testRepoRoot(t)
	tmp := t.TempDir()
	outRoot := filepath.Join(tmp, "runs")
	instanceDir := filepath.Join(tmp, "fabric-e1-enrich")

	deps := defaultRunnerDeps()
	deps.RepoRoot = repo
	deps.LookupEnv = func(key string) (string, bool) {
		if key == "LLM_API_KEY" {
			return "super-secret-llm-key-987654", true
		}
		return "", false
	}
	deps.ArchiveCommit = func(_ context.Context, _, _, destDir string) error {
		return os.MkdirAll(filepath.Join(destDir, "infra", "fabric"), 0755)
	}
	deps.RunCmd = func(_ context.Context, dir string, _ []string, logPath string, name string, args ...string) error {
		if logPath != "" {
			_ = os.WriteFile(logPath, []byte("ok\n"), 0644)
		}
		if name == "go" && len(args) >= 3 && args[0] == "build" && args[1] == "-o" {
			return os.WriteFile(args[2], []byte("binary:"+filepath.Base(args[2])), 0755)
		}
		if name == "sh" && len(args) >= 4 && args[1] == "rebuild" {
			if err := os.MkdirAll(args[2], 0755); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(args[2], "network.env"), []byte("FABRIC_DB=19510\nINSTANCE_ID=iso-123\nDB_PASSWORD=should-not-export\n"), 0644)
		}
		// Simulated driver execution merges deployment & writes summary.
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "-out" {
				out := args[i+1]
				_, _ = mergeManifest(filepath.Join(out, "manifest.json"), map[string]any{
					"deployment":   map[string]any{"deploymentId": "dep-abc"},
					"policyDigest": "policy-123",
				})
				var cases []map[string]any
				for k := 1; k <= 16; k++ {
					cases = append(cases, map[string]any{"name": "F" + pad2(k), "pass": true})
				}
				raw, _ := json.Marshal(map[string]any{"runId": filepath.Base(out), "status": "PASS", "deploymentId": "dep-abc", "cases": cases})
				return os.WriteFile(filepath.Join(out, "summary.json"), raw, 0644)
			}
		}
		return nil
	}
	deps.TeardownFabric = func(_ context.Context, _, _, logPath string) error {
		return os.WriteFile(logPath, []byte("down\n"), 0644)
	}

	res, err := ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: instanceDir,
		BasePort:    19500,
		OutRoot:     outRoot,
	}, deps)
	if err != nil {
		t.Fatalf("ExecuteRun failed: %v", err)
	}
	if res.Summary.Status != "PASS" {
		t.Fatalf("expected PASS summary, got %+v", res.Summary)
	}
	m, err := readJSONMap(filepath.Join(res.RunDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	bins, ok := m["binarySHA256"].(map[string]any)
	if !ok || bins["ledgerctl"] == "" || bins["driver"] == "" {
		t.Fatalf("binarySHA256 not populated: %+v", m["binarySHA256"])
	}
	netEnv, ok := m["networkEnv"].(map[string]any)
	if !ok || netEnv["FABRIC_DB"] != "19510" {
		t.Fatalf("networkEnv not populated: %+v", m["networkEnv"])
	}
	if _, leaked := netEnv["DB_PASSWORD"]; leaked {
		t.Fatalf("networkEnv leaked password field")
	}
	if m["policyDigest"] != "policy-123" || m["plan"] == nil || m["driverSnapshot"] == nil {
		t.Fatalf("manifest lost initial or enriched fields: %+v", m)
	}
}

func extractTarGz(t *testing.T, archivePath string) map[string][]byte {
	t.Helper()
	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		files[hdr.Name] = data
	}
	return files
}

func pad2(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

func TestControlledBuildFailureRecordsStageAndMissingReasons(t *testing.T) {
	repo := testRepoRoot(t)
	tmp := t.TempDir()
	deps := defaultRunnerDeps()
	deps.RepoRoot = repo
	deps.LookupEnv = func(key string) (string, bool) {
		if key == "LLM_API_KEY" {
			return "secret-key-build-fail-1234", true
		}
		return "", false
	}
	deps.ArchiveCommit = func(_ context.Context, _, _, destDir string) error {
		return os.MkdirAll(filepath.Join(destDir, "infra", "fabric"), 0755)
	}
	deps.RunCmd = func(_ context.Context, _ string, _ []string, logPath string, name string, args ...string) error {
		if logPath != "" {
			_ = os.WriteFile(logPath, []byte("compile error: synthetic build failure\n"), 0644)
		}
		return os.ErrInvalid
	}

	res, err := ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: filepath.Join(tmp, "iso-build-fail"),
		BasePort:    19510,
		OutRoot:     filepath.Join(tmp, "runs"),
	}, deps)
	if err == nil {
		t.Fatalf("expected build failure error")
	}
	if res.Summary.Status != "FAIL" || res.Summary.Stage != "build" || res.Summary.ExitCode == 0 {
		t.Fatalf("unexpected build failure summary: %+v", res.Summary)
	}
	if res.Summary.Diagnostic == "" || res.Summary.MissingCount != 16 || len(res.Summary.MissingItems) != 16 {
		t.Fatalf("expected diagnostic and 16 missing items, got %+v", res.Summary)
	}
	if !strings.Contains(res.Summary.MissingItems[0].Reason, "build") {
		t.Fatalf("expected missing reason to mention build stage, got %q", res.Summary.MissingItems[0].Reason)
	}
	if res.Summary.SecretScan == nil || !res.Summary.SecretScan.Passed {
		t.Fatalf("expected clean secret scan on build failure, got %+v", res.Summary.SecretScan)
	}
}

func TestControlledPreparationFailureAndTeardown(t *testing.T) {
	repo := testRepoRoot(t)
	tmp := t.TempDir()
	teardownCalled := false
	deps := defaultRunnerDeps()
	deps.RepoRoot = repo
	deps.LookupEnv = func(key string) (string, bool) {
		if key == "LLM_API_KEY" {
			return "secret-key-prep-fail-1234", true
		}
		return "", false
	}
	deps.ArchiveCommit = func(_ context.Context, _, _, destDir string) error {
		return os.MkdirAll(filepath.Join(destDir, "infra", "fabric"), 0755)
	}
	deps.RunCmd = func(_ context.Context, _ string, _ []string, logPath string, name string, args ...string) error {
		if name == "go" && len(args) >= 3 && args[0] == "build" {
			return os.WriteFile(args[2], []byte("fake-bin"), 0755)
		}
		if name == "sh" && len(args) >= 4 && args[1] == "rebuild" {
			_ = os.MkdirAll(args[2], 0755)
			_ = os.WriteFile(filepath.Join(args[2], "network.env"), []byte("FABRIC_DB=19520\n"), 0644)
			_ = os.WriteFile(logPath, []byte("docker port conflict\n"), 0644)
			return os.ErrPermission
		}
		return nil
	}
	deps.TeardownFabric = func(_ context.Context, _, _, logPath string) error {
		teardownCalled = true
		return os.WriteFile(logPath, []byte("stopped\n"), 0644)
	}

	res, err := ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: filepath.Join(tmp, "iso-prep-fail"),
		BasePort:    19520,
		OutRoot:     filepath.Join(tmp, "runs"),
	}, deps)
	if err == nil {
		t.Fatalf("expected preparation failure error")
	}
	if !teardownCalled {
		t.Fatalf("expected Fabric teardown to run on preparation failure")
	}
	if res.Summary.Status != "FAIL" || res.Summary.Stage != "network" || res.Summary.MissingCount != 16 {
		t.Fatalf("unexpected preparation failure summary: %+v", res.Summary)
	}
}

func TestControlledCollectionAbortPreservesObservedAndMarksMissing(t *testing.T) {
	repo := testRepoRoot(t)
	tmp := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	teardownCalled := false

	deps := defaultRunnerDeps()
	deps.RepoRoot = repo
	deps.LookupEnv = func(key string) (string, bool) {
		if key == "LLM_API_KEY" {
			return "secret-key-abort-123456", true
		}
		return "", false
	}
	deps.ArchiveCommit = func(_ context.Context, _, _, destDir string) error {
		return os.MkdirAll(filepath.Join(destDir, "infra", "fabric"), 0755)
	}
	deps.RunCmd = func(_ context.Context, _ string, _ []string, logPath string, name string, args ...string) error {
		if name == "go" && len(args) >= 3 && args[0] == "build" {
			return os.WriteFile(args[2], []byte("fake-bin"), 0755)
		}
		if name == "sh" && len(args) >= 4 && args[1] == "rebuild" {
			_ = os.MkdirAll(args[2], 0755)
			return os.WriteFile(filepath.Join(args[2], "network.env"), []byte("FABRIC_DB=19530\n"), 0644)
		}
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "-out" {
				out := args[i+1]
				// Simulate partial evidence written before abort after F01-F04.
				_ = os.WriteFile(filepath.Join(out, "events.jsonl"), []byte("{\"event\":\"case_result\",\"case\":\"F04\"}\n"), 0644)
				partial := map[string]any{
					"runId":  filepath.Base(out),
					"status": "FAIL",
					"cases": []map[string]any{
						{"name": "F01", "pass": true, "status": "passed"},
						{"name": "F02", "pass": true, "status": "passed"},
						{"name": "F03", "pass": true, "status": "passed"},
						{"name": "F04", "pass": true, "status": "passed"},
					},
				}
				raw, _ := json.Marshal(partial)
				_ = os.WriteFile(filepath.Join(out, "summary.json"), raw, 0644)
				cancel()
				return context.Canceled
			}
		}
		return nil
	}
	deps.TeardownFabric = func(_ context.Context, _, _, logPath string) error {
		teardownCalled = true
		return os.WriteFile(logPath, []byte("stopped\n"), 0644)
	}

	res, err := ExecuteRun(ctx, RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: filepath.Join(tmp, "iso-abort"),
		BasePort:    19530,
		OutRoot:     filepath.Join(tmp, "runs"),
	}, deps)
	if err == nil {
		t.Fatalf("expected abort error")
	}
	if !teardownCalled {
		t.Fatalf("expected Fabric teardown on abort")
	}
	if res.Summary.Status != "ABORTED" || !res.Summary.Aborted || res.Summary.Stage != "execution" {
		t.Fatalf("unexpected abort summary: %+v", res.Summary)
	}
	if res.Summary.ExecutedCount != 4 || res.Summary.MissingCount != 12 {
		t.Fatalf("expected 4 executed and 12 missing after F04 abort, got executed=%d missing=%d", res.Summary.ExecutedCount, res.Summary.MissingCount)
	}
	if _, statErr := os.Stat(filepath.Join(res.RunDir, "events.jsonl")); statErr != nil {
		t.Fatalf("partial events.jsonl was not preserved: %v", statErr)
	}
}

func TestNewRunIDAndAntiOverwriteProtection(t *testing.T) {
	repo := testRepoRoot(t)
	tmp := t.TempDir()
	outRoot := filepath.Join(tmp, "runs")
	deps := defaultRunnerDeps()
	deps.RepoRoot = repo

	r1, err := ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: filepath.Join(tmp, "iso-1"),
		BasePort:    19540,
		OutRoot:     outRoot,
		PlanOnly:    true,
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: filepath.Join(tmp, "iso-2"),
		BasePort:    19545,
		OutRoot:     outRoot,
		PlanOnly:    true,
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if r1.RunID == r2.RunID {
		t.Fatalf("expected distinct run IDs on rerun, both got %s", r1.RunID)
	}
	beforeHash, err := sha256File(filepath.Join(r1.RunDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Attempting to reuse r1.RunID must fail without overwriting r1.
	_, err = ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: filepath.Join(tmp, "iso-3"),
		BasePort:    19550,
		OutRoot:     outRoot,
		RunID:       r1.RunID,
		PlanOnly:    true,
	}, deps)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected anti-overwrite error, got %v", err)
	}
	afterHash, err := sha256File(filepath.Join(r1.RunDir, "manifest.json"))
	if err != nil || beforeHash != afterHash {
		t.Fatalf("existing run manifest was modified on overwrite attempt")
	}
}

func TestSensitiveFieldScannerDetectsAllRestrictedMaterial(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		content string
		secrets []string
	}{
		{"private-key", "F01.json", "-----BEGIN EC PRIVATE KEY-----\nabc\n", nil},
		{"api-key-literal", "driver.log", "failed with my-live-secret-token-999", []string{"my-live-secret-token-999"}},
		{"bearer-token", "driver.log", "Authorization: Bearer abcdef1234567890", nil},
		{"account-salt", "manifest.json", `{"accountSalt":"salty-secret-value"}`, nil},
		{"sdjwt-disclosure", "F15.json", "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.sig~WyJzYWx0MTIzNDU2Iiwicm9sZSIsImFnZW50Il0~", nil},
		{"challenge-nonce", "F16.json", `{"nonce":"8SYiY26Bx4-bNFfQWemTYIpD5GzgCIZB"}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.content), 0644); err != nil {
				t.Fatal(err)
			}
			scan := scanRunExports(dir, "", tc.secrets)
			if scan.Passed || len(scan.Findings) == 0 {
				t.Fatalf("expected scanner to reject %s, got %+v", tc.name, scan)
			}
		})
	}
	cleanDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(cleanDir, "manifest.json"), []byte(`{"runId":"run-1234","status":"PASS"}`), 0644)
	_ = os.WriteFile(filepath.Join(cleanDir, "requests.csv"), []byte("case,http_status\nF06,200\n"), 0644)
	clean := scanRunExports(cleanDir, "", []string{"unrelated-secret-key"})
	if !clean.Passed || clean.Files != 2 {
		t.Fatalf("expected clean scan to pass, got %+v", clean)
	}
}
