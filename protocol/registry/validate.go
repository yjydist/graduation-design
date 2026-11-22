package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// Digest computes the 64-character lowercase SHA-256 hex digest of data.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// IsDigest reports whether s is a non-zero 64-character lowercase hex SHA-256 digest.
func IsDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	nonZero := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '1' && c <= '9', c >= 'a' && c <= 'f':
			nonZero = true
		case c == '0':
		default:
			return false
		}
	}
	return nonZero
}

// ParseAppPublicKey decodes and validates a 130-character lowercase hex SEC 1 uncompressed P-256 point.
func ParseAppPublicKey(publicHex string) (*ecdsa.PublicKey, error) {
	if len(publicHex) != 130 {
		return nil, NewError(ErrCodeInvalidSchema, "appPublicKey must be 130 lowercase hex characters")
	}
	for i := 0; i < len(publicHex); i++ {
		c := publicHex[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return nil, NewError(ErrCodeInvalidSchema, "appPublicKey must be lowercase hex")
		}
	}
	point, err := hex.DecodeString(publicHex)
	if err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "decode appPublicKey hex", err)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "parse uncompressed P-256 public key", err)
	}
	return pub, nil
}

// ValidAppPublicKey reports whether publicHex is a valid 130-char lowercase hex SEC 1 uncompressed P-256 public key.
func ValidAppPublicKey(publicHex string) bool {
	_, err := ParseAppPublicKey(publicHex)
	return err == nil
}

// ValidAppKey validates a did:web subject identifier, fragment key ID, uncompressed P-256 hex key, and positive version.
func ValidAppKey(id, keyID, publicHex string, version uint64) bool {
	return strings.HasPrefix(id, "did:web:") &&
		len(id) > len("did:web:") &&
		strings.HasPrefix(keyID, id+"#") &&
		len(keyID) > len(id)+1 &&
		version > 0 &&
		ValidAppPublicKey(publicHex)
}

// CompareUTF16 compares two strings lexicographically by UTF-16 code units (RFC 8785 JCS ordering).
func CompareUTF16(a, b string) int {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] < ub[i] {
			return -1
		}
		if ua[i] > ub[i] {
			return 1
		}
	}
	if len(ua) < len(ub) {
		return -1
	}
	if len(ua) > len(ub) {
		return 1
	}
	return 0
}

// ValidStringSet reports whether s is a non-empty, wildcard-free set of at most MaxIssuerTypesOrClaims
// valid UTF-8 strings strictly sorted in ascending UTF-16 code unit order.
func ValidStringSet(s []string) bool {
	if len(s) == 0 || len(s) > MaxIssuerTypesOrClaims {
		return false
	}
	for i, v := range s {
		if v == "" || !utf8.ValidString(v) || strings.ContainsRune(v, '*') {
			return false
		}
		if i > 0 && CompareUTF16(s[i-1], v) >= 0 {
			return false
		}
	}
	return true
}

// Valid reports whether m has a non-empty MSPID and valid non-zero SHA-256 DER certificate digest.
func (m Management) Valid() bool {
	return m.MSPID != "" && IsDigest(m.CertificateSHA256)
}

// Valid reports whether d matches the canonical channel, registry, schema, optional purpose, and non-zero digests.
func (d DeploymentFields) Valid() bool {
	return (d.Purpose == "" || d.Purpose == DeploymentPurpose) &&
		d.ChannelID == Channel &&
		d.RegistryName == Registry &&
		d.SchemaVersion == Schema &&
		IsDigest(d.GenesisHash) &&
		IsDigest(d.InstanceID)
}

// Valid reports whether b carries a valid non-zero deploymentId digest.
func (b Bound) Valid() bool {
	return IsDigest(b.DeploymentID)
}

// Valid reports whether i is a non-empty left-closed right-open Unix second interval within [1, MaxUnixTimestamp].
func (i Interval) Valid() bool {
	return i.NBF > 0 && i.NBF < i.EXP && i.EXP <= MaxUnixTimestamp
}

// Within reports whether interval i is wholly contained within parent.
func (i Interval) Within(parent Interval) bool {
	return i.NBF >= parent.NBF && i.EXP <= parent.EXP
}

// Current reports whether time t satisfies [nbf, exp) with safety margin on both ends.
func (i Interval) Current(t time.Time, margin time.Duration) bool {
	return i.Valid() && !t.Add(-margin).Before(time.Unix(i.NBF, 0)) && t.Add(margin).Before(time.Unix(i.EXP, 0))
}

// Valid reports whether s has a valid did:web issuer ID, positive key version, and valid credential/claim sets.
func (s IssuerScope) Valid() bool {
	return strings.HasPrefix(s.ID, "did:web:") &&
		len(s.ID) > len("did:web:") &&
		s.AppKeyVersion > 0 &&
		ValidStringSet(s.CredentialTypes) &&
		ValidStringSet(s.ClaimNames)
}
