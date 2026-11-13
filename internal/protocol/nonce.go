package protocol

import (
	"crypto/rand"
	"encoding/base64"
)

const (
	// ChallengeNonceBytes is the fixed raw byte length (32) of challenge nonces.
	ChallengeNonceBytes = 32
	// ChallengeNonceLen is the exact canonical unpadded base64url length (43) of 32 bytes.
	ChallengeNonceLen = 43
)

// GenerateNonce draws 32 CSPRNG bytes and encodes them as a canonical 43-char unpadded base64url string.
func GenerateNonce() (string, error) {
	buf := make([]byte, ChallengeNonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return EncodeNonce(buf)
}

// EncodeNonce encodes a 32-byte slice as a canonical 43-char unpadded base64url string.
func EncodeNonce(raw []byte) (string, error) {
	if len(raw) != ChallengeNonceBytes {
		return "", NewError(ErrCodeInvalidSchema, "nonce raw bytes must be 32 bytes")
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ValidateNonce validates s as a canonical 43-character unpadded RFC 4648 base64url string
// encoding 32 bytes without padding, invalid alphabet, or non-zero trailing unused bits.
func ValidateNonce(s string) ([]byte, error) {
	if len(s) != ChallengeNonceLen {
		return nil, NewError(ErrCodeInvalidSchema, "challenge nonce must be 43 unpadded base64url characters")
	}
	raw, err := DecodeStrictBase64URLFixed(s, ChallengeNonceBytes)
	if err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "invalid challenge nonce", err)
	}
	return raw, nil
}
