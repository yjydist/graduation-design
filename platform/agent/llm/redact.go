package llm

import (
	"encoding/json"
	"regexp"
	"strings"
)

var (
	rePrivateKeyPEM = regexp.MustCompile(`(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`)
	reSDJWTSegment  = regexp.MustCompile(`~[A-Za-z0-9_-]{8,}`)
	reJWSCompact    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
)

// SanitizeText redacts private key PEM blocks, compact JWS tokens, SD-JWT disclosure
// segments, and any caller-supplied secret strings (such as API keys).
func SanitizeText(s string, secrets ...string) string {
	out := rePrivateKeyPEM.ReplaceAllString(s, "[REDACTED_PRIVATE_KEY]")
	out = reJWSCompact.ReplaceAllString(out, "[REDACTED_TOKEN]")
	out = reSDJWTSegment.ReplaceAllString(out, "~[REDACTED_DISCLOSURE]")
	for _, secret := range secrets {
		if secret != "" {
			out = strings.ReplaceAll(out, secret, "[REDACTED_API_KEY]")
		}
	}
	return out
}

// SanitizeMap returns a deep-sanitized copy of a JSON-compatible map without
// exposing private keys, raw tokens, disclosures, or caller-supplied secrets.
func SanitizeMap(in map[string]any, secrets ...string) map[string]any {
	if len(in) == 0 {
		return in
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[SanitizeText(k, secrets...)] = sanitizeValue(v, secrets...)
	}
	return out
}

func sanitizeValue(v any, secrets ...string) any {
	switch tv := v.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return tv
	case string:
		return SanitizeText(tv, secrets...)
	case map[string]any:
		return SanitizeMap(tv, secrets...)
	case []any:
		out := make([]any, len(tv))
		for i, item := range tv {
			out[i] = sanitizeValue(item, secrets...)
		}
		return out
	default:
		raw, err := json.Marshal(tv)
		if err != nil {
			return SanitizeText(err.Error(), secrets...)
		}
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return SanitizeText(string(raw), secrets...)
		}
		return sanitizeValue(decoded, secrets...)
	}
}
