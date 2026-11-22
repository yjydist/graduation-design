package harness

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RepoRoot walks up from the current working directory until it locates
// go.work and returns that directory path.
func RepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("harness: get working directory: %w", err)
	}
	return repoRootFrom(wd)
}

func repoRootFrom(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("harness: resolve path %s: %w", start, err)
	}
	for {
		candidate := filepath.Join(dir, "go.work")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("harness: go.work not found walking up from %s", start)
		}
		dir = parent
	}
}

// ValidateIsolatedInstance verifies that instanceDir is isolated from the
// repository default Fabric instance (.local/fabric-d0), including symlink
// aliases, and enforces the requested existence condition.
func ValidateIsolatedInstance(repoRoot, instanceDir string, mustNotExist bool) (string, error) {
	if strings.TrimSpace(repoRoot) == "" {
		return "", errors.New("harness: repoRoot is required")
	}
	if strings.TrimSpace(instanceDir) == "" {
		return "", errors.New("harness: instance directory is required")
	}

	absRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return "", fmt.Errorf("harness: resolve repoRoot: %w", err)
	}
	defaultDir := filepath.Clean(filepath.Join(absRoot, ".local", "fabric-d0"))
	resolvedDefault := defaultDir
	if r, err := evalPathWithMissingLeaf(defaultDir); err == nil {
		resolvedDefault = r
	}

	target := instanceDir
	if !filepath.IsAbs(target) {
		target = filepath.Join(absRoot, target)
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("harness: resolve instance directory: %w", err)
	}
	target = filepath.Clean(target)

	if sameOrInside(target, defaultDir) || sameOrInside(target, resolvedDefault) {
		return "", fmt.Errorf("harness: refusing to use default Fabric instance %s; specify an isolated directory", defaultDir)
	}

	resolvedTarget, resolveErr := evalPathWithMissingLeaf(target)
	if resolveErr == nil {
		if sameOrInside(resolvedTarget, defaultDir) || sameOrInside(resolvedTarget, resolvedDefault) {
			return "", fmt.Errorf("harness: instance directory %s resolves to default Fabric instance %s", instanceDir, defaultDir)
		}
	}

	linfo, lerr := os.Lstat(target)
	if mustNotExist {
		if lerr == nil {
			return "", fmt.Errorf("harness: isolated Fabric instance directory already exists: %s", target)
		}
		if !errors.Is(lerr, os.ErrNotExist) {
			return "", fmt.Errorf("harness: lstat instance directory %s: %w", target, lerr)
		}
		return target, nil
	}

	if lerr != nil {
		return "", fmt.Errorf("harness: instance directory %s does not exist: %w", target, lerr)
	}
	if linfo.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(target)
		if err != nil {
			return "", fmt.Errorf("harness: resolve instance symlink %s: %w", target, err)
		}
		resolvedTarget = filepath.Clean(resolved)
		if sameOrInside(resolvedTarget, defaultDir) || sameOrInside(resolvedTarget, resolvedDefault) {
			return "", fmt.Errorf("harness: instance directory %s symlinks to default Fabric instance %s", instanceDir, defaultDir)
		}
	}

	info, err := os.Stat(target)
	if err != nil {
		return "", fmt.Errorf("harness: stat instance directory %s: %w", target, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("harness: instance path is not a directory: %s", target)
	}
	if defaultInfo, derr := os.Stat(defaultDir); derr == nil && os.SameFile(info, defaultInfo) {
		return "", fmt.Errorf("harness: instance directory %s refers to default Fabric instance %s", instanceDir, defaultDir)
	}
	if resolveErr == nil {
		return resolvedTarget, nil
	}
	return target, nil
}

func sameOrInside(path, base string) bool {
	if path == base {
		return true
	}
	return strings.HasPrefix(path, base+string(filepath.Separator))
}

// evalPathWithMissingLeaf resolves symlinks on the deepest existing ancestor
// of path and reattaches any non-existent trailing path segments.
func evalPathWithMissingLeaf(path string) (string, error) {
	cleaned := filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
		return filepath.Clean(resolved), nil
	}
	var tail []string
	cur := cleaned
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			return cleaned, nil
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			slices.Reverse(tail)
			parts := append([]string{resolved}, tail...)
			return filepath.Clean(filepath.Join(parts...)), nil
		}
	}
}

// ClaimInstance creates an exclusive claim file inside instanceDir using
// O_CREATE|O_EXCL to prevent concurrent runs from clobbering the same instance.
// The returned release function removes the claim file idempotently.
func ClaimInstance(instanceDir, claimName, runID string) (func(), error) {
	if strings.TrimSpace(instanceDir) == "" {
		return nil, errors.New("harness: instanceDir is required")
	}
	if claimName == "" || claimName == "." || claimName == ".." || strings.ContainsAny(claimName, `/\`) {
		return nil, fmt.Errorf("harness: invalid claim name %q", claimName)
	}
	root, err := os.OpenRoot(instanceDir)
	if err != nil {
		return nil, fmt.Errorf("harness: open instance root %s: %w", instanceDir, err)
	}
	defer root.Close()

	f, err := root.OpenFile(claimName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("harness: claim instance %s (%s): %w", instanceDir, claimName, err)
	}
	_, writeErr := f.WriteString(strings.TrimSpace(runID) + "\n")
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = root.Remove(claimName)
		return nil, fmt.Errorf("harness: write claim file: %w", err)
	}

	claimPath := filepath.Join(instanceDir, claimName)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_ = os.Remove(claimPath)
		})
	}
	return release, nil
}

// NewRunID returns a fresh run identifier of the form "run-<16hex>".
func NewRunID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("harness: generate run id: %w", err)
	}
	return "run-" + hex.EncodeToString(b[:]), nil
}

// CreateRunDir creates a new run directory under root with anti-overwrite
// protection (os.Mkdir fails if the directory already exists).
func CreateRunDir(root, runID string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("harness: run root directory is required")
	}
	if runID == "" || runID == "." || runID == ".." || strings.ContainsAny(runID, `/\`) {
		return "", fmt.Errorf("harness: invalid run ID %q", runID)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", fmt.Errorf("harness: create runs root %s: %w", root, err)
	}
	runDir := filepath.Join(root, runID)
	if err := os.Mkdir(runDir, 0o755); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("harness: run directory already exists (refusing to overwrite): %s: %w", runDir, err)
		}
		return "", fmt.Errorf("harness: create run directory %s: %w", runDir, err)
	}
	return runDir, nil
}

// ParseEnvFile parses simple KEY=VALUE lines (with optional leading "export ",
// comments starting with "#", and single or double quoted values).
func ParseEnvFile(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("harness: read env file %s: %w", path, err)
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
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		if k != "" {
			env[k] = v
		}
	}
	return env, nil
}

// FabricNetworkCmd invokes "sh infra/fabric/network.sh <action>" inside
// repoRoot with FABRIC_INSTANCE and optional FABRIC_BASE_PORT set, writing
// combined stdout/stderr to logPath when non-empty.
func FabricNetworkCmd(ctx context.Context, repoRoot, action, instanceDir string, port int, logPath string) error {
	if strings.TrimSpace(repoRoot) == "" {
		return errors.New("harness: repoRoot is required")
	}
	if strings.TrimSpace(action) == "" {
		return errors.New("harness: fabric network action is required")
	}
	if strings.TrimSpace(instanceDir) == "" {
		return errors.New("harness: instanceDir is required")
	}

	script := filepath.Join(repoRoot, "infra", "fabric", "network.sh")
	cmd := exec.CommandContext(ctx, "sh", script, action)
	cmd.Dir = repoRoot
	env := append(os.Environ(), "FABRIC_INSTANCE="+instanceDir)
	if port > 0 {
		env = append(env, "FABRIC_BASE_PORT="+strconv.Itoa(port))
	}
	cmd.Env = env

	if logPath != "" {
		if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
			return fmt.Errorf("harness: create log dir for %s: %w", logPath, err)
		}
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("harness: open log %s: %w", logPath, err)
		}
		defer f.Close()
		cmd.Stdout = f
		cmd.Stderr = f
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("harness: fabric network %s: %w (see %s)", action, err, filepath.Base(logPath))
		}
		return nil
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("harness: fabric network %s: %w: %s", action, err, strings.TrimSpace(out.String()))
	}
	return nil
}

// BuildSourceSnapshot creates a deterministic tar.gz archive at outTarGz
// containing all files matched by relPatterns relative to repoRoot, and returns
// the archive's lowercase SHA-256 hex digest.
func BuildSourceSnapshot(repoRoot, outTarGz string, relPatterns []string) (string, error) {
	if strings.TrimSpace(repoRoot) == "" {
		return "", errors.New("harness: repoRoot is required")
	}
	if strings.TrimSpace(outTarGz) == "" {
		return "", errors.New("harness: outTarGz path is required")
	}

	var relFiles []string
	for _, pat := range relPatterns {
		matches, err := filepath.Glob(filepath.Join(repoRoot, filepath.FromSlash(pat)))
		if err != nil {
			return "", fmt.Errorf("harness: glob %q: %w", pat, err)
		}
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil || info.IsDir() {
				continue
			}
			rel, err := filepath.Rel(repoRoot, m)
			if err != nil {
				return "", fmt.Errorf("harness: rel path for %s: %w", m, err)
			}
			relFiles = append(relFiles, filepath.ToSlash(filepath.Clean(rel)))
		}
	}
	slices.Sort(relFiles)
	relFiles = slices.Compact(relFiles)
	if len(relFiles) == 0 {
		return "", errors.New("harness: source snapshot matched no files")
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.ModTime = time.Unix(0, 0).UTC()
	gz.OS = 255
	tw := tar.NewWriter(gz)

	for _, rel := range relFiles {
		abs := filepath.Join(repoRoot, filepath.FromSlash(rel))
		raw, err := os.ReadFile(abs)
		if err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return "", fmt.Errorf("harness: snapshot read %s: %w", rel, err)
		}
		hdr := &tar.Header{
			Name:    rel,
			Mode:    0o644,
			Size:    int64(len(raw)),
			ModTime: time.Unix(0, 0).UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return "", fmt.Errorf("harness: tar header %s: %w", rel, err)
		}
		if _, err := tw.Write(raw); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return "", fmt.Errorf("harness: tar write %s: %w", rel, err)
		}
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return "", fmt.Errorf("harness: close tar writer: %w", err)
	}
	if err := gz.Close(); err != nil {
		return "", fmt.Errorf("harness: close gzip writer: %w", err)
	}

	archiveBytes := buf.Bytes()
	if err := WriteAtomic(outTarGz, archiveBytes, 0o644); err != nil {
		return "", err
	}
	return SHA256Bytes(archiveBytes), nil
}

// GitHeadRevision returns the full HEAD commit hash and whether the working
// tree has uncommitted changes.
func GitHeadRevision(repoRoot string) (commit string, dirty bool, err error) {
	headOut, err := exec.Command("git", "-C", repoRoot, "rev-parse", "--verify", "HEAD^{commit}").Output()
	if err != nil {
		return "", false, fmt.Errorf("harness: git rev-parse HEAD: %w", err)
	}
	statusOut, err := exec.Command("git", "-C", repoRoot, "status", "--porcelain").Output()
	if err != nil {
		return "", false, fmt.Errorf("harness: git status: %w", err)
	}
	return strings.TrimSpace(string(headOut)), len(bytes.TrimSpace(statusOut)) > 0, nil
}

// ExportGitWorktree extracts the git tree at revision from repoRoot into
// dstDir using "git archive".
func ExportGitWorktree(ctx context.Context, repoRoot, revision, dstDir string) error {
	if strings.TrimSpace(revision) == "" {
		revision = "HEAD"
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("harness: create export dir %s: %w", dstDir, err)
	}

	archive := exec.CommandContext(ctx, "git", "-C", repoRoot, "archive", revision)
	extract := exec.CommandContext(ctx, "tar", "-xf", "-", "-C", dstDir)

	pipe, err := archive.StdoutPipe()
	if err != nil {
		return fmt.Errorf("harness: git archive pipe: %w", err)
	}
	extract.Stdin = pipe

	var aErr, eErr bytes.Buffer
	archive.Stderr = &aErr
	extract.Stderr = &eErr

	if err := archive.Start(); err != nil {
		return fmt.Errorf("harness: start git archive: %w", err)
	}
	if err := extract.Start(); err != nil {
		_ = archive.Process.Kill()
		_ = archive.Wait()
		return fmt.Errorf("harness: start tar extract: %w", err)
	}

	errA := archive.Wait()
	errE := extract.Wait()
	if errA != nil {
		return fmt.Errorf("harness: git archive %s: %w: %s", revision, errA, strings.TrimSpace(aErr.String()))
	}
	if errE != nil {
		return fmt.Errorf("harness: tar extract: %w: %s", errE, strings.TrimSpace(eErr.String()))
	}
	return nil
}
