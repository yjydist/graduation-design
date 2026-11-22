package harness

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Finding describes a single sensitive-data leak detected during export
// scanning.
type Finding struct {
	Path   string `json:"path,omitempty"`
	Rule   string `json:"rule"`
	Detail string `json:"detail"`
}

// String renders a concise human-readable representation of f.
func (f Finding) String() string {
	if f.Path == "" {
		return fmt.Sprintf("%s: %s", f.Rule, f.Detail)
	}
	return fmt.Sprintf("%s: [%s] %s", f.Path, f.Rule, f.Detail)
}

var (
	rePrivateKeyPEM   = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	rePrivateKeyField = regexp.MustCompile(`(?i)"?(app_?private_?key|private_?key)"?\s*[:=]\s*"?[0-9a-f]{32,}"?`)
	rePrivateKeyJSON  = regexp.MustCompile(`"(appPrivateKey|app_private_key|privateKey|private_key)"\s*:\s*"[^"]+"`)
	reBearerToken     = regexp.MustCompile(`(?i)authorization["':=\s]+bearer\s+[A-Za-z0-9._-]{8,}`)
	reAPIKeyHeader    = regexp.MustCompile(`(?i)(OPENAI_API_KEY|ANTHROPIC_API_KEY|x-api-key|api_key|apiKey)["':=\s]+[A-Za-z0-9._-]{8,}`)
	reOpenAISecret    = regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}\b`)
	reSDJWTDisclosure = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+~[A-Za-z0-9_-]{10,}~`)
	reSaltOrSecretKey = regexp.MustCompile(`(?i)"(account_salt|accountSalt|disclosure_salt|disclosureSalt|access_token|accessToken|db_password|dbPassword|view_password|viewPassword)"\s*:\s*"[^"]+"`)
	reSaltPlainText   = regexp.MustCompile(`(?i)\b(account_salt|accountSalt|disclosure_salt|disclosureSalt)\s*[:=]\s*["']?[A-Za-z0-9+/=_-]{8,}["']?`)
	reChallengeNonce  = regexp.MustCompile(`"(nonce|Nonce)"\s*:\s*"[A-Za-z0-9_-]{16,}"`)
	reCompactJWS      = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
)

// ScanBytes inspects an in-memory buffer for private keys, API keys, bearer
// tokens, account/disclosure salts, raw SD-JWT disclosures, challenge nonces,
// compact JWS tokens (on strict public exports), and caller-supplied runtime
// secrets.
func ScanBytes(relPath string, data []byte, extraSecrets ...string) []Finding {
	relPath = filepath.ToSlash(relPath)
	var findings []Finding
	add := func(rule, detail string) {
		findings = append(findings, Finding{
			Path:   relPath,
			Rule:   rule,
			Detail: detail,
		})
	}

	if rePrivateKeyPEM.Match(data) {
		add("private_key_pem", "private key PEM block detected")
	}
	if rePrivateKeyField.Match(data) || rePrivateKeyJSON.Match(data) {
		add("private_key_field", "private key material field detected")
	}
	if reBearerToken.Match(data) {
		add("bearer_token", "bearer authorization token detected")
	}
	if reAPIKeyHeader.Match(data) || reOpenAISecret.Match(data) {
		add("api_key", "API key detected")
	}
	if reSDJWTDisclosure.Match(data) {
		add("sd_jwt_disclosure", "raw SD-JWT disclosure detected")
	}
	if reSaltOrSecretKey.Match(data) || reSaltPlainText.Match(data) {
		add("sensitive_field", "sensitive secret or salt field detected")
	}
	if reChallengeNonce.Match(data) {
		add("challenge_nonce", "raw challenge nonce detected")
	}
	if isStrictPublicExport(relPath) && reCompactJWS.Match(data) {
		add("compact_jws", "compact JWS/JWT token in public export")
	}
	for _, secret := range extraSecrets {
		trimmed := strings.TrimSpace(secret)
		if len(trimmed) < 8 {
			continue
		}
		if bytes.Contains(data, []byte(trimmed)) {
			add("runtime_secret", "runtime secret or disclosure leaked")
			break
		}
	}
	return findings
}

// ScanExports recursively scans all text/structured export files under root
// and returns all sensitive-data findings sorted deterministically.
func ScanExports(root string, extraSecrets ...string) ([]Finding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("harness: stat scan root %s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("harness: scan root %s is not a directory", root)
	}

	var findings []Finding
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if isSkippedScanExt(filepath.Ext(rel)) {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("harness: read %s: %w", rel, err)
		}
		findings = append(findings, ScanBytes(rel, raw, extraSecrets...)...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	slices.SortFunc(findings, func(a, b Finding) int {
		if c := cmp.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return cmp.Compare(a.Rule, b.Rule)
	})
	return findings, nil
}

// CollectInstanceSecrets loads runtime secrets (database password, issued
// SD-JWT credentials, and raw disclosure salts) from an isolated Fabric
// instance directory so callers can feed them into ScanExports.
func CollectInstanceSecrets(instanceDir string) []string {
	if instanceDir == "" {
		return nil
	}
	var secrets []string
	seen := map[string]struct{}{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) < 8 {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		secrets = append(secrets, s)
	}

	if pw, err := os.ReadFile(filepath.Join(instanceDir, "view-password")); err == nil {
		add(string(pw))
	}

	credsDir := filepath.Join(instanceDir, "registry", "credentials")
	entries, err := os.ReadDir(credsDir)
	if err != nil {
		return secrets
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(credsDir, entry.Name()))
		if err != nil {
			continue
		}
		text := strings.TrimSpace(string(raw))
		if len(text) >= 24 {
			add(text)
		}
		for _, part := range strings.Split(text, "~")[1:] {
			if part == "" {
				continue
			}
			decoded, err := base64.RawURLEncoding.DecodeString(part)
			if err != nil {
				continue
			}
			var disclosure []any
			if json.Unmarshal(decoded, &disclosure) == nil && len(disclosure) > 0 {
				if salt, ok := disclosure[0].(string); ok {
					add(salt)
				}
			}
		}
	}
	return secrets
}

// RedactSecrets replaces occurrences of any non-empty secret in text with
// "[REDACTED]".
func RedactSecrets(text string, secrets ...string) string {
	for _, s := range secrets {
		if s != "" {
			text = strings.ReplaceAll(text, s, "[REDACTED]")
		}
	}
	return text
}

func isSkippedScanExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".pb", ".gz", ".png", ".pdf", ".tar", ".zip":
		return true
	default:
		return false
	}
}

func isStrictPublicExport(rel string) bool {
	base := filepath.Base(rel)
	switch base {
	case "manifest.json", "summary.json", "requests.csv", "revocations.csv", "order_checks.csv",
		"llm-traces.json", "db-challenges.json", "db-decisions.json", "db-orders.json",
		"db-quotes.json", "db-business-keys.json", "build.log", "network-up.log", "network-down.log":
		return true
	default:
		return false
	}
}
