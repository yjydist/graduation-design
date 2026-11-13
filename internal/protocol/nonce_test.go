package protocol

import (
	"encoding/hex"
	"testing"
)

const (
	wantNonceRawHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	wantNonceStr    = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
)

func TestNonceVectorAndValidation(t *testing.T) {
	raw, err := hex.DecodeString(wantNonceRawHex)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeNonce(raw)
	if err != nil {
		t.Fatalf("EncodeNonce failed: %v", err)
	}
	if encoded != wantNonceStr || len(encoded) != ChallengeNonceLen {
		t.Fatalf("nonce mismatch: got %q (len %d), want %q", encoded, len(encoded), wantNonceStr)
	}
	decoded, err := ValidateNonce(encoded)
	if err != nil {
		t.Fatalf("ValidateNonce failed on canonical vector: %v", err)
	}
	if hex.EncodeToString(decoded) != wantNonceRawHex {
		t.Fatalf("decoded nonce hex mismatch: got %x", decoded)
	}

	// CSPRNG nonce generation must validate cleanly and produce unique values.
	n1, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce failed: %v", err)
	}
	n2, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce 2 failed: %v", err)
	}
	if n1 == n2 {
		t.Fatal("GenerateNonce produced identical nonces")
	}
	if _, err := ValidateNonce(n1); err != nil {
		t.Fatalf("generated nonce failed validation: %v", err)
	}

	// Negative tests from spec Section 2.1: '=', '+', '/', whitespace, hex, wrong length, and last char '8' -> '9'
	badCases := []struct {
		name  string
		nonce string
	}{
		{"with equals padding", wantNonceStr + "="},
		{"non-canonical trailing bit 8->9", wantNonceStr[:42] + "9"},
		{"hex string instead of base64url", wantNonceRawHex},
		{"plus char", "+" + wantNonceStr[1:]},
		{"slash char", "/" + wantNonceStr[1:]},
		{"leading whitespace", " " + wantNonceStr[:42]},
		{"trailing newline", wantNonceStr[:42] + "\n"},
		{"too short", wantNonceStr[:42]},
		{"too long", wantNonceStr + "A"},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateNonce(tc.nonce)
			if !HasCode(err, ErrCodeInvalidSchema) {
				t.Fatalf("expected %s for %s, got %v", ErrCodeInvalidSchema, tc.name, err)
			}
		})
	}
}
