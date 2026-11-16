package fabric

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// scanBaselineEvidence checks the four public exports against token encodings and actual disclosure salts.
func scanBaselineEvidence(dir string, i *instance) error {
	var secrets []string
	if i != nil {
		entries, err := os.ReadDir(i.registrySubPath("credentials"))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			raw, err := os.ReadFile(i.registrySubPath("credentials", entry.Name()))
			if err != nil {
				return err
			}
			secrets = append(secrets, string(raw))
			for _, part := range strings.Split(string(raw), "~")[1:] {
				decoded, err := base64.RawURLEncoding.DecodeString(part)
				if err != nil {
					continue
				}
				var disclosure []any
				if json.Unmarshal(decoded, &disclosure) == nil && len(disclosure) > 0 {
					if salt, ok := disclosure[0].(string); ok && len(salt) >= 8 {
						secrets = append(secrets, salt)
					}
				}
			}
		}
	}
	jws := regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	for _, file := range []string{"manifest.json", "requests.csv", "order_checks.csv", "summary.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return err
		}
		if bytes.Contains(raw, []byte("PRIVATE KEY")) || jws.Match(raw) {
			return fmt.Errorf("sensitive key or token encoding in %s", file)
		}
		for _, secret := range secrets {
			if secret != "" && bytes.Contains(raw, []byte(secret)) {
				return fmt.Errorf("sensitive disclosure in %s", file)
			}
		}
	}
	return nil
}
