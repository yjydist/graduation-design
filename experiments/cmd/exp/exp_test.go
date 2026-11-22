package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/experiments/harness"
)

func testRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := harness.RepoRoot()
	require.NoError(t, err)
	return root
}

func extractTarGz(t *testing.T, archivePath string) map[string][]byte {
	t.Helper()
	f, err := os.Open(archivePath)
	require.NoError(t, err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	require.NoError(t, err)
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		files[hdr.Name] = data
	}
	return files
}

func hashDirFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	hashes := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		sum, err := harness.SHA256File(p)
		if err != nil {
			return err
		}
		hashes[filepath.ToSlash(rel)] = sum
		return nil
	})
	require.NoError(t, err)
	return hashes
}

func execCLI(args ...string) (string, string, error) {
	cmd := newRootCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestCLIHelpAndSubcommands(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		contains []string
	}{
		{
			name:     "root",
			args:     []string{"--help"},
			contains: []string{"exp", "baseline", "run", "analyze"},
		},
		{
			name:     "baseline",
			args:     []string{"baseline", "--help"},
			contains: []string{"--dir", "--c0-database", "--out", "--seed", "1109", "--request-timeout", "15s", "--timeout", "10m0s"},
		},
		{
			name: "run",
			args: []string{"run", "--help"},
			contains: []string{
				"--experiment", "--revision", "--instance", "--port", "--out-root",
				"--run-id", "--seed", "--mode", "--configuration", "--probe-interval",
				"--probe-lifetime", "--detect-interval", "--revoke-after", "--duration",
				"--instances", "--plan-only", "--workspace-sut",
			},
		},
		{
			name:     "analyze",
			args:     []string{"analyze", "--help"},
			contains: []string{"--experiment", "--run-dir", "--out"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := execCLI(tc.args...)
			require.NoError(t, err)
			for _, token := range tc.contains {
				assert.Contains(t, out, token)
			}
		})
	}

	_, _, err := execCLI("analyze", "--experiment", "E1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")

	_, _, err = execCLI("analyze", "--experiment", "E99", "--run-dir", t.TempDir(), "--out", t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported experiment")
}

func TestRunPlanOnlyAndSourceSnapshotReconstruction(t *testing.T) {
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
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(res.RunID, "run-"))
	assert.Equal(t, "PLANNED", res.Summary.Status)

	var manifest map[string]any
	require.NoError(t, harness.ReadJSON(filepath.Join(res.RunDir, "manifest.json"), &manifest))
	assert.Equal(t, "E1", manifest["experiment"])
	assert.Equal(t, res.RunID, manifest["runId"])
	assert.Equal(t, DriverTypeRealLLMMCP, manifest["driverType"])
	assert.NotEmpty(t, manifest["sourceCommit"])
	assert.Equal(t, instanceDir, manifest["instance"])
	assert.Nil(t, manifest["binarySHA256"])

	rawManifest, err := os.ReadFile(filepath.Join(res.RunDir, "manifest.json"))
	require.NoError(t, err)
	assert.NotContains(t, string(rawManifest), "test-secret-api-key-12345")

	snapMap, ok := manifest["driverSnapshot"].(map[string]any)
	require.True(t, ok)
	archivePath := filepath.Join(res.RunDir, snapMap["archiveFile"].(string))
	gotArchiveHash, err := harness.SHA256File(archivePath)
	require.NoError(t, err)
	assert.Equal(t, snapMap["archiveSha256"], gotArchiveHash)

	fileHashes := manifest["fileSHA256"].(map[string]any)
	extracted := extractTarGz(t, archivePath)
	for rel, expectedHash := range fileHashes {
		content, exists := extracted[rel]
		require.True(t, exists, "snapshot archive missing recorded file %s", rel)
		assert.Equal(t, expectedHash, harness.SHA256Bytes(content), "hash mismatch for %s", rel)
	}
	for _, mustHave := range []string{
		"go.work",
		"experiments/go.mod",
		"experiments/go.sum",
		"experiments/harness/io.go",
		"experiments/cmd/exp/run.go",
		"experiments/e1/driver/main.go",
		"experiments/llm.env",
	} {
		assert.Contains(t, extracted, mustHave)
	}
}

func TestRunE6PlanOnlyAndValidation(t *testing.T) {
	repo := testRepoRoot(t)
	tmp := t.TempDir()
	deps := defaultRunnerDeps()
	deps.RepoRoot = repo

	// Missing --mode must fail for E6.
	_, err := ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E6",
		Revision:    "HEAD",
		InstanceDir: filepath.Join(tmp, "iso-e6-nomode"),
		BasePort:    19600,
		OutRoot:     filepath.Join(tmp, "runs"),
		PlanOnly:    true,
	}, deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--mode")

	res, err := ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E6",
		Revision:    "HEAD",
		Mode:        "RP",
		InstanceDir: filepath.Join(tmp, "iso-e6-plan"),
		BasePort:    19600,
		OutRoot:     filepath.Join(tmp, "runs"),
		PlanOnly:    true,
	}, deps)
	require.NoError(t, err)
	assert.Equal(t, "PLANNED", res.Summary.Status)

	extracted := extractTarGz(t, filepath.Join(res.RunDir, "driver-source.tar.gz"))
	for _, mustHave := range []string{
		"go.work",
		"experiments/go.mod",
		"experiments/go.sum",
		"experiments/harness/io.go",
		"experiments/cmd/exp/run.go",
		"experiments/e6/driver/main.go",
	} {
		assert.Contains(t, extracted, mustHave)
	}
}

func TestRunGuardsAntiOverwriteIsolatedInstanceAndRevisionConflict(t *testing.T) {
	repo := testRepoRoot(t)
	tmp := t.TempDir()
	outRoot := filepath.Join(tmp, "runs")
	deps := defaultRunnerDeps()
	deps.RepoRoot = repo

	// 1. Refuse default Fabric instance.
	_, err := ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: filepath.Join(repo, ".local", "fabric-d0"),
		BasePort:    19540,
		OutRoot:     outRoot,
		PlanOnly:    true,
	}, deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "default Fabric instance")

	// 2. Refuse already-existing isolated instance directory.
	existingInst := filepath.Join(tmp, "already-exists")
	require.NoError(t, os.MkdirAll(existingInst, 0o755))
	_, err = ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: existingInst,
		BasePort:    19540,
		OutRoot:     outRoot,
		PlanOnly:    true,
	}, deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	// 3. Refuse --workspace-sut with explicit non-HEAD revision.
	_, err = ExecuteRun(context.Background(), RunOptions{
		Experiment:   "E1",
		Revision:     "79125cc40855014c16fcfb0a962bc276202023d8",
		InstanceDir:  filepath.Join(tmp, "iso-ws-conflict"),
		BasePort:     19540,
		OutRoot:      outRoot,
		WorkspaceSUT: true,
	}, deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--workspace-sut")

	// 4. Refuse invalid port.
	_, err = ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: filepath.Join(tmp, "iso-bad-port"),
		BasePort:    80,
		OutRoot:     outRoot,
		PlanOnly:    true,
	}, deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base port")

	// 5. Anti-overwrite protection on duplicate run ID.
	r1, err := ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: filepath.Join(tmp, "iso-1"),
		BasePort:    19540,
		OutRoot:     outRoot,
		PlanOnly:    true,
	}, deps)
	require.NoError(t, err)

	r2, err := ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: filepath.Join(tmp, "iso-2"),
		BasePort:    19545,
		OutRoot:     outRoot,
		PlanOnly:    true,
	}, deps)
	require.NoError(t, err)
	assert.NotEqual(t, r1.RunID, r2.RunID)

	beforeHash, err := harness.SHA256File(filepath.Join(r1.RunDir, "manifest.json"))
	require.NoError(t, err)

	_, err = ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: filepath.Join(tmp, "iso-3"),
		BasePort:    19550,
		OutRoot:     outRoot,
		RunID:       r1.RunID,
		PlanOnly:    true,
	}, deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	afterHash, err := harness.SHA256File(filepath.Join(r1.RunDir, "manifest.json"))
	require.NoError(t, err)
	assert.Equal(t, beforeHash, afterHash)
}

func TestRunFourModuleBuildPathsAndWorkspaceSUT(t *testing.T) {
	repo := testRepoRoot(t)
	tmp := t.TempDir()
	outRoot := filepath.Join(tmp, "runs")
	instanceDir := filepath.Join(tmp, "fabric-e1-enrich")

	type buildCall struct {
		dir    string
		target string
	}
	var buildCalls []buildCall

	deps := defaultRunnerDeps()
	deps.RepoRoot = repo
	deps.LookupEnv = func(key string) (string, bool) {
		if key == "LLM_API_KEY" {
			return "super-secret-llm-key-987654", true
		}
		return "", false
	}
	deps.ArchiveCommit = func(_ context.Context, _, _, destDir string) error {
		driverDir := filepath.Join(destDir, e1DriverDir)
		require.NoError(t, os.MkdirAll(driverDir, 0o755))
		return os.WriteFile(filepath.Join(driverDir, "obsolete.go"), []byte("package obsolete"), 0o644)
	}
	deps.RunCmd = func(_ context.Context, dir string, _ []string, logPath string, name string, args ...string) error {
		if logPath != "" {
			_ = os.WriteFile(logPath, []byte("ok\n"), 0o644)
		}
		if name == "go" && len(args) >= 4 && args[0] == "build" && args[1] == "-o" {
			buildCalls = append(buildCalls, buildCall{dir: dir, target: args[len(args)-1]})
			if args[len(args)-1] == "./e1/driver" {
				stagedDir := filepath.Join(dir, "e1", "driver")
				_, err := os.Stat(filepath.Join(stagedDir, "obsolete.go"))
				assert.True(t, os.IsNotExist(err), "archived driver file must be stripped before build")
				stagedHash, err := harness.SHA256File(filepath.Join(stagedDir, "main.go"))
				require.NoError(t, err)
				var manifest map[string]any
				require.NoError(t, harness.ReadJSON(filepath.Join(outRoot, "run-fixed-e1", "manifest.json"), &manifest))
				assert.Equal(t, manifest["fileSHA256"].(map[string]any)[e1DriverDir+"/main.go"], stagedHash)
			}
			return os.WriteFile(args[2], []byte("binary:"+filepath.Base(args[2])), 0o755)
		}
		if name == "sh" && len(args) >= 4 && args[1] == "rebuild" {
			require.NoError(t, os.MkdirAll(args[2], 0o755))
			return os.WriteFile(filepath.Join(args[2], "network.env"), []byte("FABRIC_DB=19510\nINSTANCE_ID=iso-123\nDB_PASSWORD=should-not-export\n"), 0o644)
		}
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "-out" {
				out := args[i+1]
				_ = harness.MergeJSON(filepath.Join(out, "manifest.json"), map[string]any{
					"deployment":   map[string]any{"deploymentId": "dep-abc"},
					"policyDigest": "policy-123",
				})
				var cases []map[string]any
				for k := 1; k <= 16; k++ {
					cases = append(cases, map[string]any{"name": fmt.Sprintf("F%02d", k), "pass": true})
				}
				return harness.WriteJSON(filepath.Join(out, "summary.json"), map[string]any{
					"runId": filepath.Base(out), "status": "PASS", "deploymentId": "dep-abc", "cases": cases,
				})
			}
		}
		return nil
	}
	deps.TeardownFabric = func(_ context.Context, _, _, logPath string) error {
		return os.WriteFile(logPath, []byte("down\n"), 0o644)
	}

	res, err := ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: instanceDir,
		BasePort:    19500,
		OutRoot:     outRoot,
		RunID:       "run-fixed-e1",
	}, deps)
	require.NoError(t, err)
	assert.Equal(t, "PASS", res.Summary.Status)

	require.Len(t, buildCalls, 2)
	assert.Equal(t, "platform", filepath.Base(buildCalls[0].dir))
	assert.Equal(t, "./cmd/ledgerctl", buildCalls[0].target)
	assert.Equal(t, "experiments", filepath.Base(buildCalls[1].dir))
	assert.Equal(t, "./e1/driver", buildCalls[1].target)

	var m map[string]any
	require.NoError(t, harness.ReadJSON(filepath.Join(res.RunDir, "manifest.json"), &m))
	bins := m["binarySHA256"].(map[string]any)
	assert.NotEmpty(t, bins["ledgerctl"])
	assert.NotEmpty(t, bins["driver"])
	netEnv := m["networkEnv"].(map[string]any)
	assert.Equal(t, "19510", netEnv["FABRIC_DB"])
	assert.NotContains(t, netEnv, "DB_PASSWORD")

	// WorkspaceSUT builds directly in repoRoot/{platform,experiments} without calling ArchiveCommit.
	archiveCalled := false
	buildCalls = nil
	deps.ArchiveCommit = func(_ context.Context, _, _, _ string) error {
		archiveCalled = true
		return nil
	}
	deps.RunCmd = func(_ context.Context, dir string, _ []string, logPath string, name string, args ...string) error {
		if logPath != "" {
			_ = os.WriteFile(logPath, []byte("ok\n"), 0o644)
		}
		if name == "go" && len(args) >= 4 && args[0] == "build" {
			buildCalls = append(buildCalls, buildCall{dir: dir, target: args[len(args)-1]})
			return os.WriteFile(args[2], []byte("fake-bin"), 0o755)
		}
		if name == "sh" && len(args) >= 4 && args[1] == "rebuild" {
			require.NoError(t, os.MkdirAll(args[2], 0o755))
			return os.WriteFile(filepath.Join(args[2], "network.env"), []byte("FABRIC_DB=19565\n"), 0o644)
		}
		return nil
	}
	resWS, err := ExecuteRun(context.Background(), RunOptions{
		Experiment:   "E1",
		Revision:     "HEAD",
		InstanceDir:  filepath.Join(tmp, "iso-e1-ws"),
		BasePort:     19565,
		OutRoot:      outRoot,
		WorkspaceSUT: true,
	}, deps)
	require.NoError(t, err)
	assert.False(t, archiveCalled)
	require.Len(t, buildCalls, 2)
	assert.Equal(t, filepath.Join(repo, "platform"), buildCalls[0].dir)
	assert.Equal(t, filepath.Join(repo, "experiments"), buildCalls[1].dir)

	var mWS map[string]any
	require.NoError(t, harness.ReadJSON(filepath.Join(resWS.RunDir, "manifest.json"), &mWS))
	assert.Equal(t, "workspace", mWS["sutSource"])
}

func TestRunControlledFailureAbortAndSecretScan(t *testing.T) {
	repo := testRepoRoot(t)
	tmp := t.TempDir()

	// Controlled build failure.
	deps := defaultRunnerDeps()
	deps.RepoRoot = repo
	deps.LookupEnv = func(key string) (string, bool) {
		if key == "LLM_API_KEY" {
			return "secret-key-build-fail-1234", true
		}
		return "", false
	}
	deps.ArchiveCommit = func(_ context.Context, _, _, destDir string) error {
		return os.MkdirAll(filepath.Join(destDir, "infra", "fabric"), 0o755)
	}
	deps.RunCmd = func(_ context.Context, _ string, _ []string, logPath string, _ string, _ ...string) error {
		if logPath != "" {
			_ = os.WriteFile(logPath, []byte("compile error\n"), 0o644)
		}
		return os.ErrInvalid
	}
	resFail, err := ExecuteRun(context.Background(), RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: filepath.Join(tmp, "iso-build-fail"),
		BasePort:    19510,
		OutRoot:     filepath.Join(tmp, "runs"),
	}, deps)
	require.Error(t, err)
	assert.Equal(t, "FAIL", resFail.Summary.Status)
	assert.Equal(t, "build", resFail.Summary.Stage)
	assert.Equal(t, 16, resFail.Summary.MissingCount)
	require.NotNil(t, resFail.Summary.SecretScan)
	assert.True(t, resFail.Summary.SecretScan.Passed)

	// Controlled abort during execution preserves partial outputs and runs teardown.
	ctx, cancel := context.WithCancel(context.Background())
	teardownCalled := false
	deps.RunCmd = func(_ context.Context, _ string, _ []string, _ string, name string, args ...string) error {
		if name == "go" && len(args) >= 3 && args[0] == "build" {
			return os.WriteFile(args[2], []byte("fake-bin"), 0o755)
		}
		if name == "sh" && len(args) >= 4 && args[1] == "rebuild" {
			_ = os.MkdirAll(args[2], 0o755)
			return os.WriteFile(filepath.Join(args[2], "network.env"), []byte("FABRIC_DB=19535\n"), 0o644)
		}
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "-out" {
				out := args[i+1]
				_ = os.WriteFile(filepath.Join(out, "events.jsonl"), []byte(`{"case":"F04"}`+"\n"), 0o644)
				cases := make([]map[string]any, 0, 16)
				for k := 1; k <= 4; k++ {
					cases = append(cases, map[string]any{"name": fmt.Sprintf("F%02d", k), "pass": true, "status": "passed"})
				}
				for k := 5; k <= 16; k++ {
					cases = append(cases, map[string]any{
						"name":          fmt.Sprintf("F%02d", k),
						"pass":          false,
						"status":        "not_executed",
						"missingReason": fmt.Sprintf("aborted before F%02d: context canceled", k),
					})
				}
				_ = harness.WriteJSON(filepath.Join(out, "summary.json"), map[string]any{"runId": filepath.Base(out), "status": "FAIL", "cases": cases})
				cancel()
				return context.Canceled
			}
		}
		return nil
	}
	deps.TeardownFabric = func(_ context.Context, _, _, logPath string) error {
		teardownCalled = true
		return os.WriteFile(logPath, []byte("stopped\n"), 0o644)
	}

	resAbort, err := ExecuteRun(ctx, RunOptions{
		Experiment:  "E1",
		Revision:    "HEAD",
		InstanceDir: filepath.Join(tmp, "iso-abort"),
		BasePort:    19535,
		OutRoot:     filepath.Join(tmp, "runs"),
	}, deps)
	require.Error(t, err)
	assert.True(t, teardownCalled)
	assert.Equal(t, "ABORTED", resAbort.Summary.Status)
	assert.True(t, resAbort.Summary.Aborted)
	assert.Equal(t, 4, resAbort.Summary.ExecutedCount)
	assert.Equal(t, 12, resAbort.Summary.MissingCount)
	assert.FileExists(t, filepath.Join(resAbort.RunDir, "events.jsonl"))

	// Secret scanner detects restricted material and passes clean exports.
	dirtyDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dirtyDir, "F01.json"), []byte("-----BEGIN EC PRIVATE KEY-----\nabc\n"), 0o644))
	scanDirty := scanRunExports(dirtyDir, "", nil)
	assert.False(t, scanDirty.Passed)
	assert.NotEmpty(t, scanDirty.Findings)

	cleanDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(cleanDir, "manifest.json"), []byte(`{"runId":"run-clean","status":"PASS"}`), 0o644))
	scanClean := scanRunExports(cleanDir, "", []string{"unrelated-secret-key"})
	assert.True(t, scanClean.Passed)
	assert.Equal(t, 1, scanClean.Files)
}

func buildE1PassFixture(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "run-e1-pass-fixture")
	require.NoError(t, os.MkdirAll(dir, 0o755))

	require.NoError(t, harness.WriteJSON(filepath.Join(dir, "manifest.json"), map[string]any{
		"runId":        "run-e1-pass-fixture",
		"sourceCommit": "abc1234",
		"deployment":   map[string]any{"deploymentId": "dep-e1"},
		"llm":          map[string]any{"provider": "openai", "model": "gpt-test"},
	}))

	cases := make([]map[string]any, 0, 16)
	for i := 1; i <= 16; i++ {
		cases = append(cases, map[string]any{"name": fmt.Sprintf("F%02d", i), "pass": true, "status": "passed"})
	}
	require.NoError(t, harness.WriteJSON(filepath.Join(dir, "summary.json"), map[string]any{
		"runId":        "run-e1-pass-fixture",
		"status":       "PASS",
		"stage":        "finalize",
		"deploymentId": "dep-e1",
		"cases":        cases,
	}))

	// Build requests, DB exports, LLM traces, per-case files, and blocks for RP and BM.
	var reqRows []e1RequestCSVRow
	var traces []map[string]any
	var challenges, decisions, orders, quotes, bizKeys []map[string]any
	auditModes := map[string]any{}

	for idx, spec := range []struct {
		short, mode string
		blockNo     int64
	}{
		{"rp", "RESOURCE_PREAUTHORIZED", 2},
		{"bm", "BUYER_MANDATE", 3},
	} {
		taskID := "task-" + spec.short
		probeTx := "probe-tx-" + spec.short
		blockHash := fmt.Sprintf("hash-%d", spec.blockNo)

		// LLM traces for F05 and F15 with delegate_grant anchored.
		for _, cName := range []string{"F05", "F15"} {
			traces = append(traces, map[string]any{
				"Case": cName,
				"Mode": spec.mode,
				"Result": map[string]any{
					"provider":       "openai",
					"model":          "gpt-test",
					"llmLatencyMs":   120,
					"toolCallsCount": 2,
					"toolTraces": []map[string]any{
						{"toolName": "delegate_grant", "output": map[string]any{"anchored": true}, "isError": false},
					},
				},
			})
		}

		addDecisionAndChallenge := func(decID, chalID, reqHash string) {
			challenges = append(challenges, map[string]any{
				"challenge_id": chalID,
				"decision_id":  decID,
				"task_id":      taskID,
				"request_hash": reqHash,
				"consumed_at":  1700000001,
			})
			decisions = append(decisions, map[string]any{
				"decision_id":            decID,
				"challenge_id":           chalID,
				"task_id":                taskID,
				"block_number":           spec.blockNo,
				"block_hash":             blockHash,
				"probe_block":            spec.blockNo,
				"probe_tx_id":            probeTx,
				"probe_sent_mono_ns":     1000,
				"probe_checked_mono_ns":  2000,
				"probe_deadline_mono_ns": 5000000,
			})
		}

		// F06: 4 round trips (201, 200, 201, 200).
		q800ID := "q800-" + spec.short
		o800ID := "o800-" + spec.short
		cQ6, dQ6 := "ch-f06-q-"+spec.short, "dec-f06-q-"+spec.short
		cO6, dO6 := "ch-f06-o-"+spec.short, "dec-f06-o-"+spec.short
		addDecisionAndChallenge(dQ6, cQ6, "rh-f06-q-"+spec.short)
		addDecisionAndChallenge(dO6, cO6, "rh-f06-o-"+spec.short)
		quotes = append(quotes, map[string]any{"quote_id": q800ID, "total_amount_minor": 80000})
		orders = append(orders, map[string]any{
			"order_id":           o800ID,
			"quote_id":           q800ID,
			"decision_id":        dO6,
			"idempotency_key":    "idem-f06-o-" + spec.short,
			"total_amount_minor": 80000,
		})
		bizKeys = append(bizKeys, map[string]any{"idempotency_key": "idem-f06-o-" + spec.short})

		reqRows = append(reqRows,
			e1RequestCSVRow{Case: "F06", Mode: spec.mode, Method: "POST", Path: "/v1/auth/challenges", TaskID: taskID, HTTPStatus: "201", ChallengeID: cQ6},
			e1RequestCSVRow{Case: "F06", Mode: spec.mode, Method: "POST", Path: "/v1/access/execute", TaskID: taskID, Action: "quote.read", Key: "idem-f06-q-" + spec.short, HTTPStatus: "200", ChallengeID: cQ6, DecisionID: dQ6, RequestHash: "rh-f06-q-" + spec.short, QuoteID: q800ID},
			e1RequestCSVRow{Case: "F06", Mode: spec.mode, Method: "POST", Path: "/v1/auth/challenges", TaskID: taskID, HTTPStatus: "201", ChallengeID: cO6},
			e1RequestCSVRow{Case: "F06", Mode: spec.mode, Method: "POST", Path: "/v1/access/execute", TaskID: taskID, Action: "order.create", Key: "idem-f06-o-" + spec.short, HTTPStatus: "200", ChallengeID: cO6, DecisionID: dO6, RequestHash: "rh-f06-o-" + spec.short, QuoteID: q800ID, OrderID: o800ID},
		)

		// F07: Q1200 + 2 negative controls (AMOUNT_MISMATCH, AMOUNT_LIMIT_EXCEEDED) with zero order side effect.
		q1200ID := "q1200-" + spec.short
		cQ7, dQ7 := "ch-f07-q-"+spec.short, "dec-f07-q-"+spec.short
		cM7, dM7 := "ch-f07-m-"+spec.short, "dec-f07-m-"+spec.short
		cL7, dL7 := "ch-f07-l-"+spec.short, "dec-f07-l-"+spec.short
		addDecisionAndChallenge(dQ7, cQ7, "rh-f07-q-"+spec.short)
		addDecisionAndChallenge(dM7, cM7, "rh-f07-m-"+spec.short)
		addDecisionAndChallenge(dL7, cL7, "rh-f07-l-"+spec.short)
		quotes = append(quotes, map[string]any{"quote_id": q1200ID, "total_amount_minor": 120000})

		reqRows = append(reqRows,
			e1RequestCSVRow{Case: "F07", Mode: spec.mode, Method: "POST", Path: "/v1/auth/challenges", TaskID: taskID, HTTPStatus: "201", ChallengeID: cQ7},
			e1RequestCSVRow{Case: "F07", Mode: spec.mode, Method: "POST", Path: "/v1/access/execute", TaskID: taskID, Action: "quote.read", Key: "idem-f07-q-" + spec.short, HTTPStatus: "200", ChallengeID: cQ7, DecisionID: dQ7, RequestHash: "rh-f07-q-" + spec.short, QuoteID: q1200ID},
			e1RequestCSVRow{Case: "F07", Mode: spec.mode, Method: "POST", Path: "/v1/auth/challenges", TaskID: taskID, HTTPStatus: "201", ChallengeID: cM7},
			e1RequestCSVRow{Case: "F07", Mode: spec.mode, Method: "POST", Path: "/v1/access/execute", TaskID: taskID, Action: "order.create", Key: "idem-f07-m-" + spec.short, HTTPStatus: "403", ChallengeID: cM7, DecisionID: dM7, RequestHash: "rh-f07-m-" + spec.short, QuoteID: q1200ID, Code: "AMOUNT_MISMATCH"},
			e1RequestCSVRow{Case: "F07", Mode: spec.mode, Method: "POST", Path: "/v1/auth/challenges", TaskID: taskID, HTTPStatus: "201", ChallengeID: cL7},
			e1RequestCSVRow{Case: "F07", Mode: spec.mode, Method: "POST", Path: "/v1/access/execute", TaskID: taskID, Action: "order.create", Key: "idem-f07-l-" + spec.short, HTTPStatus: "403", ChallengeID: cL7, DecisionID: dL7, RequestHash: "rh-f07-l-" + spec.short, QuoteID: q1200ID, Code: "AMOUNT_LIMIT_EXCEEDED"},
		)

		// F08, F14, F15, F16 files.
		f08OrderID := fmt.Sprintf("o-f08-%s-%d", spec.short, idx)
		require.NoError(t, harness.WriteJSON(filepath.Join(dir, "F08-"+spec.short+".json"), map[string]any{
			"firstChallenge":  "c1",
			"retryChallenge":  "c2",
			"orderRowsBefore": 1,
			"orderRowsAfter":  2,
			"firstOrder":      map[string]any{"orderId": f08OrderID},
			"retryOrder":      map[string]any{"orderId": f08OrderID},
		}))
		require.NoError(t, harness.WriteJSON(filepath.Join(dir, "F14-expired-"+spec.short+".json"), map[string]any{
			"code": "DOMAIN_CERTIFICATION_INVALID",
		}))
		require.NoError(t, harness.WriteJSON(filepath.Join(dir, "F15-reissued-"+spec.short+".json"), map[string]any{
			"quote": map[string]any{"decision": "ALLOW"},
		}))
		canonical := `{"mode":"` + spec.mode + `","seq":1}`
		evHash := harness.SHA256Bytes([]byte(canonical))
		require.NoError(t, harness.WriteJSON(filepath.Join(dir, "F16-"+spec.short+".json"), map[string]any{
			"canonicalEvidence":       canonical,
			"kbEvidenceHash":          evHash,
			"verifiedEvidenceHash":    evHash,
			"changedEvidenceHash":     "0000000000000000",
			"absentCredentialControl": "denied: CREDENTIAL_STATUS_INVALID",
		}))

		auditModes[spec.short] = map[string]any{
			"F06OrderId":            o800ID,
			"F06CreationDecisionId": dO6,
			"F06QuoteId":            q800ID,
			"F07Denials": map[string]string{
				"AMOUNT_MISMATCH":       dM7,
				"AMOUNT_LIMIT_EXCEEDED": dL7,
			},
			"F08OrderId":      f08OrderID,
			"F16EvidenceHash": evHash,
		}
	}

	require.NoError(t, harness.WriteCSV(filepath.Join(dir, "requests.csv"), reqRows))
	require.NoError(t, harness.WriteJSON(filepath.Join(dir, "llm-traces.json"), traces))
	require.NoError(t, harness.WriteJSON(filepath.Join(dir, "db-challenges.json"), challenges))
	require.NoError(t, harness.WriteJSON(filepath.Join(dir, "db-decisions.json"), decisions))
	require.NoError(t, harness.WriteJSON(filepath.Join(dir, "db-orders.json"), orders))
	require.NoError(t, harness.WriteJSON(filepath.Join(dir, "db-quotes.json"), quotes))
	require.NoError(t, harness.WriteJSON(filepath.Join(dir, "db-business-keys.json"), bizKeys))

	// Continuous blocks 0..3; block 2 has probe-tx-rp, block 3 has probe-tx-bm (only probe/ write keys).
	var blockBuf bytes.Buffer
	for h := int64(0); h <= 3; h++ {
		txs := []map[string]any{}
		if h == 2 {
			txs = append(txs, map[string]any{"txId": "probe-tx-rp", "validationCode": "VALID", "writeKeys": []string{"probe/probe1"}})
		}
		if h == 3 {
			txs = append(txs, map[string]any{"txId": "probe-tx-bm", "validationCode": "VALID", "writeKeys": []string{"probe/probe1"}})
		}
		line, err := json.Marshal(map[string]any{
			"point":        map[string]any{"blockNumber": h, "blockHash": fmt.Sprintf("hash-%d", h)},
			"transactions": txs,
		})
		require.NoError(t, err)
		blockBuf.Write(line)
		blockBuf.WriteByte('\n')
	}
	require.NoError(t, harness.WriteAtomic(filepath.Join(dir, "blocks.jsonl"), blockBuf.Bytes(), 0o644))

	require.NoError(t, harness.WriteJSON(filepath.Join(dir, "audit.json"), map[string]any{
		"runId":                   "run-e1-pass-fixture",
		"summaryVerdicts":         16,
		"capturedGatewayRequests": len(reqRows),
		"llmSessions":             len(traces),
		"llmToolCalls":            8,
		"blocks":                  4,
		"storedQuotes":            len(quotes),
		"storedOrders":            len(orders),
		"storedDecisions":         len(decisions),
		"authorizationModes":      auditModes,
	}))
	return dir
}

func TestAnalyzeE1OfflinePassFixtureDeterministicAndImmutable(t *testing.T) {
	runDir := buildE1PassFixture(t)
	beforeHashes := hashDirFiles(t, runDir)

	out1 := filepath.Join(t.TempDir(), "out1")
	out2 := filepath.Join(t.TempDir(), "out2")

	rep1, err := AnalyzeE1Run(runDir, out1)
	require.NoError(t, err)
	assert.True(t, rep1.ReconciliationPassed, "anomalies=%v rp=%v bm=%v", rep1.Anomalies, rep1.AuthorizationModes["rp"].Anomalies, rep1.AuthorizationModes["bm"].Anomalies)
	assert.True(t, rep1.PublishedAuditChecked)
	assert.True(t, rep1.PublishedAuditMatches)
	assert.Equal(t, 16, rep1.PassedCases)
	assert.Equal(t, 20, rep1.CapturedGatewayRequests)
	assert.Equal(t, 4, rep1.LLMSessions)
	assert.Equal(t, 8, rep1.LLMToolCalls)
	assert.True(t, rep1.BlocksContinuous)
	require.NotNil(t, rep1.F06BlockInterval)
	assert.Equal(t, 0, rep1.F06BlockInterval.NonProbeWriteKeys)

	// Run second time via Cobra CLI and check deterministic JSON output.
	cliOut, _, err := execCLI("analyze", "--experiment", "E1", "--run-dir", runDir, "--out", out2)
	require.NoError(t, err)
	assert.Contains(t, cliOut, "reconciliationPassed=true")

	b1, err := os.ReadFile(filepath.Join(out1, "recomputed.json"))
	require.NoError(t, err)
	b2, err := os.ReadFile(filepath.Join(out2, "recomputed.json"))
	require.NoError(t, err)
	assert.Equal(t, b1, b2)
	assert.FileExists(t, filepath.Join(out1, "recomputed-table.md"))

	// Raw run directory must remain untouched.
	afterHashes := hashDirFiles(t, runDir)
	assert.Equal(t, beforeHashes, afterHashes)

	// Reject writing derived output inside raw run directory.
	_, err = AnalyzeE1Run(runDir, filepath.Join(runDir, "derived"))
	require.Error(t, err)
}

func TestAnalyzeE1OfflineFailedRunDetectsCascadeAndMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run-e1-fail-fixture")
	require.NoError(t, os.MkdirAll(dir, 0o755))

	cases := []map[string]any{
		{"name": "F01", "pass": true, "status": "passed"},
		{"name": "F02", "pass": true, "status": "passed"},
		{"name": "F03", "pass": true, "status": "passed"},
		{"name": "F04", "pass": true, "status": "passed"},
		{"name": "F05", "pass": false, "status": "failed", "error": "llm timeout"},
	}
	for i := 6; i <= 15; i++ {
		cases = append(cases, map[string]any{
			"name":   fmt.Sprintf("F%02d", i),
			"pass":   false,
			"status": "failed",
			"error":  "upstream did not confirm the leaf grant",
		})
	}
	require.NoError(t, harness.WriteJSON(filepath.Join(dir, "manifest.json"), map[string]any{"runId": "run-e1-fail-fixture"}))
	require.NoError(t, harness.WriteJSON(filepath.Join(dir, "summary.json"), map[string]any{
		"runId":  "run-e1-fail-fixture",
		"status": "FAIL",
		"stage":  "execution",
		"cases":  cases,
	}))
	require.NoError(t, harness.WriteJSON(filepath.Join(dir, "llm-traces.json"), []map[string]any{
		{"Case": "F05", "Mode": "RESOURCE_PREAUTHORIZED", "Error": "context deadline exceeded"},
	}))

	rep, err := AnalyzeE1Run(dir, filepath.Join(t.TempDir(), "out"))
	require.NoError(t, err)
	assert.Equal(t, "FAIL", rep.RunStatus)
	assert.False(t, rep.ReconciliationPassed)
	assert.Equal(t, 4, rep.PassedCases)
	assert.Equal(t, 11, rep.FailedCases)
	assert.Equal(t, 10, rep.UpstreamBlockedCases)
	assert.Equal(t, 1, rep.NotExecutedCases) // F16 missing from summary
	assert.Equal(t, 1, rep.LLMErrorSessions)
	assert.NotEmpty(t, rep.MissingInputFiles)
	assert.NotEmpty(t, rep.FailureAndMissingDiagnostic)
}

const (
	e6RevHeader = "run_id,mode,configuration,revoked_grant_id,revocation_tx_id,revocation_block_r,revocation_block_hash,tx_index,validation_code,t_submit_ns,t_valid_ns,t_apply_ns,instance_id,probe_role,t_adopt_ns,adopt_block_h,probe_interval_ms,probe_lifetime_ms,detect_interval_ms,clock_timebase,clock_resolution_ns,clock_error_ns,status,unobserved_reason\n"
	e6ReqHeader = "run_id,mode,configuration,phase,instance_id,probe_role,seq,planned_at_ns,actual_interval_ns,submitted_at_ns,decision_at_ns,committed_at_ns,responded_at_ns,decision_at_sec,idempotency_key,request_id,challenge_id,decision_id,order_id,http_status,code,outcome,disposition,block_number,block_hash,g1_status_at_block,probe_tx_id,probe_block,probe_sent_at_ns,probe_deadline_ns,probe_sent_mono_ns,probe_checked_mono_ns,probe_deadline_mono_ns,clock_timebase,clock_resolution_ns,unobserved_reason\n"
)

func writeE6Fixture(t *testing.T, revRows, reqRows []string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "run-e6-fixture")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"runId":"run-e6-fixture","experiment":"E6"}`+"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "summary.json"), []byte(`{"runId":"run-e6-fixture","status":"PASS"}`+"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "revocations.csv"), []byte(e6RevHeader+strings.Join(revRows, "\n")+"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requests.csv"), []byte(e6ReqHeader+strings.Join(reqRows, "\n")+"\n"), 0o644))
	return dir
}

func TestAnalyzeE6DelayedResponseAfterOldBlockDecision(t *testing.T) {
	const base int64 = 1_700_000_000_000_000_000
	tSubmit := base + 100_000_000
	tValid := base + 200_000_000
	tApply := base + 220_000_000
	tAdopt := base + 260_000_000

	rev := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,grant-g1,tx-rev,50,hash50,0,VALID,%d,%d,%d,gw-1,probe1,%d,50,1000,5000,20,host-utc-unix-ns,1000,0,CONFIRMED,",
		tSubmit, tValid, tApply, tAdopt)
	req1 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,1,%d,20000000,%d,%d,%d,%d,1700000000,k1,r1,c1,d1,o1,200,ALLOW,ALLOW,allowed,49,hash49,ACTIVE,ptx1,49,%d,%d,1000,180000000,5000001000,host-utc-unix-ns,1000,",
		base+170_000_000, base+170_000_000, base+180_000_000, base+185_000_000, base+350_000_000, base, base+5_000_000_000)
	req2 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,2,%d,20000000,%d,%d,%d,%d,1700000000,k2,r2,c2,d2,o2,200,ALLOW,ALLOW,allowed,49,hash49,ACTIVE,ptx1,49,%d,%d,1000,240000000,5000001000,host-utc-unix-ns,1000,",
		base+230_000_000, base+230_000_000, base+240_000_000, base+245_000_000, base+400_000_000, base, base+5_000_000_000)
	req3 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,3,%d,20000000,%d,null,null,%d,null,k3,r3,c3,,,403,ANCESTOR_INACTIVE,DENY,denied,50,hash50,REVOKED,ptx2,50,%d,%d,1000,null,5000001000,host-utc-unix-ns,1000,precheck_deny_no_decision_row",
		base+270_000_000, base+270_000_000, base+280_000_000, base+200_000_000, base+5_200_000_000)

	runDir := writeE6Fixture(t, []string{rev}, []string{req1, req2, req3})
	outDir := filepath.Join(t.TempDir(), "out")
	rep, err := AnalyzeE6Run(runDir, outDir)
	require.NoError(t, err)
	assert.True(t, rep.Passed)
	assert.Equal(t, 0, rep.TotalViolations)

	require.Len(t, rep.Instances, 1)
	ia := rep.Instances[0]
	assert.Equal(t, "observed", ia.WindowStatus)
	require.NotNil(t, ia.PostValidWindowMs)
	assert.InDelta(t, 40.0, *ia.PostValidWindowMs, 0.01)
	assert.Len(t, ia.DelayedResponseAfterOldBlock, 2)
	assert.Equal(t, "responded_at_ns", ia.FirstDenySource)
	assert.Equal(t, "precheck_deny_no_decision_row", ia.FirstDenyUnobservedReason)

	// Also test Cobra CLI dispatch for E6 analyze.
	cliOut, _, err := execCLI("analyze", "--experiment", "E6", "--run-dir", runDir, "--out", filepath.Join(t.TempDir(), "cli-out"))
	require.NoError(t, err)
	assert.Contains(t, cliOut, "passed=true")
}

func TestAnalyzeE6Violations(t *testing.T) {
	const base int64 = 1_700_000_000_000_000_000

	t.Run("allow_after_revocation_block", func(t *testing.T) {
		rev := fmt.Sprintf("run-e6-fixture,BUYER_MANDATE,B0,grant-g1,tx-rev,50,hash50,0,VALID,%d,%d,%d,gw-1,probe1,%d,50,1000,5000,20,host-utc-unix-ns,1000,0,CONFIRMED,",
			base+100_000_000, base+200_000_000, base+220_000_000, base+250_000_000)
		reqBad := fmt.Sprintf("run-e6-fixture,BUYER_MANDATE,B0,probe,gw-1,probe1,1,%d,20000000,%d,%d,%d,%d,1700000000,k1,r1,c1,d1,o1,200,ALLOW,ALLOW,allowed,50,hash50,REVOKED,ptx1,50,%d,%d,1000,260000000,5000001000,host-utc-unix-ns,1000,",
			base+255_000_000, base+255_000_000, base+260_000_000, base+262_000_000, base+265_000_000, base, base+5_000_000_000)

		rep, err := AnalyzeE6Run(writeE6Fixture(t, []string{rev}, []string{reqBad}), filepath.Join(t.TempDir(), "out"))
		require.NoError(t, err)
		assert.False(t, rep.Passed)
		assert.Equal(t, 1, rep.TotalViolations)
		assert.Equal(t, "VIOLATION", rep.Instances[0].WindowStatus)
		assert.Equal(t, "allow_after_revocation_block", rep.Instances[0].Violations[0].Type)
	})

	t.Run("allow_past_probe_deadline", func(t *testing.T) {
		rev := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,grant-g1,tx-rev,50,hash50,0,VALID,%d,%d,%d,gw-1,probe1,%d,50,1000,5000,20,host-utc-unix-ns,1000,0,CONFIRMED,",
			base+100_000_000, base+200_000_000, base+220_000_000, base+6_000_000_000)
		reqExpired := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,1,%d,20000000,%d,%d,%d,%d,1700000005,k1,r1,c1,d1,o1,200,ALLOW,ALLOW,allowed,49,hash49,ACTIVE,ptx1,49,%d,%d,1000,5100001000,5000001000,host-utc-unix-ns,1000,",
			base+5_090_000_000, base+5_090_000_000, base+5_100_000_000, base+5_102_000_000, base+5_105_000_000, base, base+5_000_000_000)

		rep, err := AnalyzeE6Run(writeE6Fixture(t, []string{rev}, []string{reqExpired}), filepath.Join(t.TempDir(), "out"))
		require.NoError(t, err)
		assert.False(t, rep.Passed)
		assert.Equal(t, 1, rep.TotalViolations)
		assert.Equal(t, "allow_past_probe_deadline", rep.Instances[0].Violations[0].Type)
	})
}

func TestAnalyzeE6InsufficientTimeResolutionAndMultiInstanceAggregation(t *testing.T) {
	const base int64 = 1_700_000_000_000_000_000

	t.Run("insufficient_time_resolution", func(t *testing.T) {
		rev := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,grant-g1,tx-rev,50,hash50,0,VALID,%d,%d,%d,gw-1,probe1,%d,50,1000,5000,20,host-utc-unix-sec,1000000000,0,CONFIRMED,",
			base+100_000_000, base+200_000_000, base+220_000_000, base+250_000_000)
		rCoarse := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,1,%d,20000000,%d,null,null,%d,1700000000,k1,r1,c1,d1,o1,200,ALLOW,ALLOW,allowed,49,hash49,ACTIVE,ptx1,49,%d,%d,1000,230000000,5000001000,host-utc-unix-sec,1000000000,",
			base+220_000_000, base+220_000_000, base+240_000_000, base, base+5_000_000_000)

		rep, err := AnalyzeE6Run(writeE6Fixture(t, []string{rev}, []string{rCoarse}), filepath.Join(t.TempDir(), "out"))
		require.NoError(t, err)
		ia := rep.Instances[0]
		assert.True(t, rep.Passed)
		assert.Equal(t, "insufficient_time_resolution", ia.WindowStatus)
		require.Len(t, ia.AmbiguousTimingSamples, 1)
		assert.True(t, ia.AmbiguousTimingSamples[0].UsedSecondLevel)
	})

	t.Run("missed_probes_and_post_valid_unobserved", func(t *testing.T) {
		rev := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,grant-g1,tx-rev,50,hash50,0,VALID,%d,%d,%d,gw-1,probe1,%d,50,1000,5000,20,host-utc-unix-ns,1000,0,CONFIRMED,",
			base+100_000_000, base+200_000_000, base+210_000_000, base+215_000_000)
		r1 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,1,%d,20000000,%d,%d,%d,%d,1700000000,k1,r1,c1,d1,o1,200,ALLOW,ALLOW,allowed,49,hash49,ACTIVE,ptx1,49,%d,%d,1000,150000000,5000001000,host-utc-unix-ns,1000,",
			base+140_000_000, base+140_000_000, base+150_000_000, base+152_000_000, base+155_000_000, base, base+5_000_000_000)
		r2 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,2,%d,null,null,null,null,null,null,k2,,,,,null,,,missed,null,,,,null,null,null,null,null,null,host-utc-unix-ns,1000,missed_probe_slot",
			base+205_000_000)
		r3 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,3,%d,20000000,%d,null,null,null,null,k3,r3,c3,,,null,,,timeout,null,,,,null,null,null,null,null,null,host-utc-unix-ns,1000,execute_timeout",
			base+210_000_000, base+210_000_000)
		r4 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,4,%d,20000000,%d,null,null,%d,null,k4,r4,c4,,,403,ANCESTOR_INACTIVE,DENY,denied,50,hash50,REVOKED,ptx2,50,%d,%d,1000,null,5000001000,host-utc-unix-ns,1000,precheck_deny_no_decision_row",
			base+225_000_000, base+225_000_000, base+230_000_000, base+200_000_000, base+5_200_000_000)

		rep, err := AnalyzeE6Run(writeE6Fixture(t, []string{rev}, []string{r1, r2, r3, r4}), filepath.Join(t.TempDir(), "out"))
		require.NoError(t, err)
		ia := rep.Instances[0]
		assert.True(t, rep.Passed)
		assert.Equal(t, "post_valid_allow_unobserved", ia.WindowStatus)
		assert.Nil(t, ia.PostValidWindowMs)
		assert.Equal(t, 4, ia.Accounting.Planned)
		assert.Equal(t, 3, ia.Accounting.Started)
		assert.Equal(t, 2, ia.Accounting.Completed)
		assert.Equal(t, 1, ia.Accounting.Missed)
		assert.Equal(t, 1, ia.Accounting.Timeout)
	})

	t.Run("multi_instance_interval_aggregation", func(t *testing.T) {
		rev1 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,grant-g1,tx-rev,50,hash50,0,VALID,%d,%d,%d,gw-1,probe1,%d,50,1000,5000,20,host-utc-unix-ns,1000,0,CONFIRMED,",
			base+100_000_000, base+200_000_000, base+210_000_000, base+215_000_000)
		rev2 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,grant-g1,tx-rev,50,hash50,0,VALID,%d,%d,%d,gw-2,probe2,%d,50,1000,5000,20,host-utc-unix-ns,1000,0,CONFIRMED,",
			base+100_000_000, base+200_000_000, base+210_000_000, base+216_000_000)

		makeReq := func(inst, role string, seq int, intervalNs int64, decNs int64) string {
			return fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,%s,%s,%d,%d,%d,%d,%d,%d,%d,1700000000,k-%s-%d,r-%s-%d,c-%s-%d,d-%s-%d,o-%s-%d,200,ALLOW,ALLOW,allowed,49,hash49,ACTIVE,ptx1,49,%d,%d,1000,%d,5000001000,host-utc-unix-ns,1000,",
				inst, role, seq, decNs-5_000_000, intervalNs, decNs-5_000_000, decNs, decNs+1_000_000, decNs+2_000_000,
				inst, seq, inst, seq, inst, seq, inst, seq, inst, seq, base, base+5_000_000_000, decNs-base)
		}
		reqs := []string{
			makeReq("gw-1", "probe1", 1, 20_000_000, base+110_000_000),
			makeReq("gw-1", "probe1", 2, 20_000_000, base+130_000_000),
			makeReq("gw-1", "probe1", 3, 55_000_000, base+185_000_000),
			makeReq("gw-2", "probe2", 1, 20_000_000, base+110_000_000),
			makeReq("gw-2", "probe2", 2, 21_000_000, base+131_000_000),
			makeReq("gw-2", "probe2", 3, 62_000_000, base+193_000_000),
		}

		rep, err := AnalyzeE6Run(writeE6Fixture(t, []string{rev1, rev2}, reqs), filepath.Join(t.TempDir(), "out"))
		require.NoError(t, err)
		require.NotNil(t, rep.TotalAccounting.MaxIntervalMs)
		require.NotNil(t, rep.TotalAccounting.MedianIntervalMs)
		require.NotNil(t, rep.TotalAccounting.IntervalStats)
		assert.InDelta(t, 62.0, *rep.TotalAccounting.MaxIntervalMs, 0.001)
		assert.InDelta(t, 20.5, *rep.TotalAccounting.MedianIntervalMs, 0.001)
		assert.Equal(t, 6, rep.TotalAccounting.IntervalStats.Count)
	})
}
