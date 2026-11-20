package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

const (
	DriverTypeRealLLMMCP         = "real-llm-mcp"
	DriverTypeDeterministicTools = "deterministic-wallet-tools"
)

type PlannedItem struct {
	ID   string `json:"id"`
	Mode string `json:"mode,omitempty"`
	Kind string `json:"kind,omitempty"`
}

type RunPlan struct {
	Experiment         string         `json:"experiment"`
	DriverType         string         `json:"driverType"`
	Configuration      string         `json:"configuration"`
	AuthorizationModes []string       `json:"authorizationModes"`
	Seed               *int           `json:"seed,omitempty"`
	Items              []PlannedItem  `json:"items"`
	Sampling           map[string]any `json:"sampling,omitempty"`
}

type SourceSnapshotInfo struct {
	WorkspaceCommit string   `json:"workspaceCommit"`
	WorkspaceDirty  bool     `json:"workspaceDirty"`
	ArchiveFile     string   `json:"archiveFile"`
	ArchiveSHA256   string   `json:"archiveSha256"`
	IncludedFiles   []string `json:"includedFiles"`
}

type MissingItem struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type SecretScanResult struct {
	Passed   bool     `json:"passed"`
	Files    int      `json:"files"`
	Findings []string `json:"findings,omitempty"`
}

type RunSummary struct {
	RunID         string            `json:"runId"`
	Experiment    string            `json:"experiment"`
	Status        string            `json:"status"`
	Stage         string            `json:"stage"`
	Aborted       bool              `json:"aborted,omitempty"`
	DeploymentID  string            `json:"deploymentId,omitempty"`
	StartedAt     time.Time         `json:"startedAt"`
	FinishedAt    *time.Time        `json:"finishedAt,omitempty"`
	ExitCode      int               `json:"exitCode"`
	Diagnostic    string            `json:"diagnostic,omitempty"`
	Error         string            `json:"error,omitempty"`
	PlannedCount  int               `json:"plannedCount"`
	ExecutedCount int               `json:"executedCount"`
	MissingCount  int               `json:"missingCount"`
	MissingItems  []MissingItem     `json:"missingItems,omitempty"`
	SecretScan        *SecretScanResult `json:"secretScan,omitempty"`
	Cases             []any             `json:"cases,omitempty"`
	Revocation        any               `json:"revocation,omitempty"`
	Instances         any               `json:"instances,omitempty"`
	RequestAccounting any               `json:"requestAccounting,omitempty"`
	Mode              string            `json:"mode,omitempty"`
	ModeShort         string            `json:"modeShort,omitempty"`
	Configuration     string            `json:"configuration,omitempty"`
	ClockTimebase     string            `json:"clockTimebase,omitempty"`
	ClockResolutionNs *int64            `json:"clockResolutionNs,omitempty"`
}

func generateRunID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "run-" + hex.EncodeToString(b[:]), nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeJSONFile(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSONMap(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func mergeManifest(path string, updates map[string]any) (map[string]any, error) {
	m, err := readJSONMap(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		m = map[string]any{}
	}
	for k, v := range updates {
		m[k] = v
	}
	if err := writeJSONFile(path, m); err != nil {
		return nil, err
	}
	return m, nil
}

// buildSourceSnapshot archives the exact runner and experiment driver files participating
// in orchestration and builds so inputs can be reconstructed offline.
func buildSourceSnapshot(repoRoot, archivePath string, relFiles []string) (*SourceSnapshotInfo, map[string]string, error) {
	unique := make([]string, 0, len(relFiles))
	seen := make(map[string]struct{}, len(relFiles))
	for _, rel := range relFiles {
		norm := filepath.ToSlash(filepath.Clean(rel))
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		unique = append(unique, norm)
	}
	slices.Sort(unique)

	f, err := os.Create(archivePath)
	if err != nil {
		return nil, nil, err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	fileHashes := make(map[string]string, len(unique))
	for _, rel := range unique {
		abs := filepath.Join(repoRoot, filepath.FromSlash(rel))
		raw, err := os.ReadFile(abs)
		if err != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = f.Close()
			return nil, nil, fmt.Errorf("snapshot read %s: %w", rel, err)
		}
		sum := sha256.Sum256(raw)
		fileHashes[rel] = hex.EncodeToString(sum[:])
		hdr := &tar.Header{
			Name:    rel,
			Mode:    0644,
			Size:    int64(len(raw)),
			ModTime: time.Unix(0, 0).UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = f.Close()
			return nil, nil, err
		}
		if _, err := tw.Write(raw); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = f.Close()
			return nil, nil, err
		}
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		_ = f.Close()
		return nil, nil, err
	}
	if err := gz.Close(); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if err := f.Close(); err != nil {
		return nil, nil, err
	}
	archiveHash, err := sha256File(archivePath)
	if err != nil {
		return nil, nil, err
	}
	return &SourceSnapshotInfo{
		ArchiveFile:   filepath.Base(archivePath),
		ArchiveSHA256: archiveHash,
		IncludedFiles: unique,
	}, fileHashes, nil
}

func collectRelFiles(repoRoot string, patterns []string) ([]string, error) {
	var out []string
	for _, pat := range patterns {
		matches, err := filepath.Glob(filepath.Join(repoRoot, filepath.FromSlash(pat)))
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil || info.IsDir() {
				continue
			}
			rel, err := filepath.Rel(repoRoot, m)
			if err != nil {
				return nil, err
			}
			out = append(out, filepath.ToSlash(rel))
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func buildInitialManifest(runID string, startedAt time.Time, plan RunPlan, sourceCommit string, snap *SourceSnapshotInfo, fileHashes map[string]string, instanceDir string, basePort int, extra map[string]any) map[string]any {
	m := map[string]any{
		"schemaVersion":      "grad-experiment-manifest-v1",
		"experiment":         plan.Experiment,
		"runId":              runID,
		"startedAt":          startedAt.UTC().Format(time.RFC3339Nano),
		"status":             "INITIALIZED",
		"stage":              "plan",
		"sourceCommit":       sourceCommit,
		"driverType":         plan.DriverType,
		"configuration":      plan.Configuration,
		"authorizationModes": plan.AuthorizationModes,
		"plan":               plan,
		"driverSnapshot":     snap,
		"fileSHA256":         fileHashes,
		"binarySHA256":       nil,
		"instance":           instanceDir,
		"basePort":           basePort,
		"deployment":         nil,
		"policyDigest":       nil,
		"fixtureDigest":      nil,
		"host":               runtime.GOOS + "/" + runtime.GOARCH,
		"go":                 runtime.Version(),
		"clock":              "host-utc-unix-ns and per-process monotonic ns",
	}
	if plan.Seed != nil {
		m["seed"] = *plan.Seed
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func missingItemsFromPlan(plan RunPlan, reason string) []MissingItem {
	items := make([]MissingItem, 0, len(plan.Items))
	for _, item := range plan.Items {
		id := item.ID
		if item.Mode != "" {
			id = item.ID + "/" + item.Mode
		}
		items = append(items, MissingItem{
			ID:     id,
			Status: "not_executed",
			Reason: reason,
		})
	}
	return items
}

func parseEnvFile(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		trimmed = strings.TrimPrefix(trimmed, "export ")
		k, v, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		if k != "" {
			env[k] = v
		}
	}
	return env, nil
}
