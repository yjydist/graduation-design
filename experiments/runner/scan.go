package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	rePrivateKeyPEM   = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	reBearerToken     = regexp.MustCompile(`(?i)authorization["':=\s]+bearer\s+[A-Za-z0-9._-]{8,}`)
	reAPIKeyHeader    = regexp.MustCompile(`(?i)(x-api-key|api_key|apiKey)["':=\s]+[A-Za-z0-9._-]{12,}`)
	reOpenAISecret    = regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}\b`)
	reSDJWTDisclosure = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+~[A-Za-z0-9_-]{10,}~`)
	reAccountSaltKey  = regexp.MustCompile(`"(account_salt|accountSalt|private_key|privateKey|api_key|apiKey|access_token|accessToken)"\s*:\s*"[^"]+"`)
	reCompactJWS      = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	reChallengeNonce  = regexp.MustCompile(`"(nonce|Nonce)"\s*:\s*"[A-Za-z0-9_-]{16,}"`)
)

// scanRunExports verifies that public run exports exclude API keys, private keys,
// DB passwords, account salts, full SD-JWT disclosures, and raw access tokens/nonces.
func scanRunExports(runDir, instanceDir string, extraSecrets []string) SecretScanResult {
	res := SecretScanResult{Passed: true}
	var literalSecrets []string
	for _, s := range extraSecrets {
		if len(strings.TrimSpace(s)) >= 8 {
			literalSecrets = append(literalSecrets, s)
		}
	}
	if instanceDir != "" {
		if pw, err := os.ReadFile(filepath.Join(instanceDir, "view-password")); err == nil {
			if trimmed := strings.TrimSpace(string(pw)); len(trimmed) >= 8 {
				literalSecrets = append(literalSecrets, trimmed)
			}
		}
		credsDir := filepath.Join(instanceDir, "registry", "credentials")
		if entries, err := os.ReadDir(credsDir); err == nil {
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
					literalSecrets = append(literalSecrets, text)
				}
				for _, part := range strings.Split(text, "~")[1:] {
					decoded, err := base64.RawURLEncoding.DecodeString(part)
					if err != nil {
						continue
					}
					var disclosure []any
					if json.Unmarshal(decoded, &disclosure) == nil && len(disclosure) > 0 {
						if salt, ok := disclosure[0].(string); ok && len(salt) >= 8 {
							literalSecrets = append(literalSecrets, salt)
						}
					}
				}
			}
		}
	}

	_ = filepath.WalkDir(runDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(runDir, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		ext := strings.ToLower(filepath.Ext(rel))
		if ext == ".pb" || ext == ".gz" || ext == ".png" || ext == ".pdf" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			res.Passed = false
			res.Findings = append(res.Findings, fmt.Sprintf("%s: read error: %v", rel, err))
			return nil
		}
		res.Files++

		check := func(kind string) {
			res.Passed = false
			res.Findings = append(res.Findings, fmt.Sprintf("%s: %s", rel, kind))
		}
		if rePrivateKeyPEM.Match(raw) {
			check("private key PEM detected")
		}
		if reBearerToken.Match(raw) {
			check("bearer token detected")
		}
		if reAPIKeyHeader.Match(raw) || reOpenAISecret.Match(raw) {
			check("API key detected")
		}
		if reSDJWTDisclosure.Match(raw) {
			check("full SD-JWT disclosure detected")
		}
		if reAccountSaltKey.Match(raw) {
			check("sensitive secret or salt field detected")
		}
		if reChallengeNonce.Match(raw) {
			check("raw challenge nonce detected")
		}
		for _, secret := range literalSecrets {
			if bytes.Contains(raw, []byte(secret)) {
				check("runtime secret or credential disclosure leaked")
				break
			}
		}
		// Strict token check on primary public metadata/tables/logs.
		if isStrictPublicExport(rel) && reCompactJWS.Match(raw) {
			check("compact JWS/JWT token in public table or metadata")
		}
		return nil
	})
	return res
}

func isStrictPublicExport(rel string) bool {
	switch rel {
	case "manifest.json", "summary.json", "requests.csv", "revocations.csv", "llm-traces.json",
		"db-challenges.json", "db-decisions.json", "db-orders.json", "db-quotes.json", "db-business-keys.json",
		"build.log", "network-up.log", "network-down.log":
		return true
	default:
		return false
	}
}
