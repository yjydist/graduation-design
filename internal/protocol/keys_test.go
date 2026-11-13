package protocol

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

const vectorDIDDocJSON = `{
  "id": "did:web:example.test:subjects:vector",
  "verificationMethod": [{
    "id": "did:web:example.test:subjects:vector#key-1",
    "type": "JsonWebKey",
    "controller": "did:web:example.test:subjects:vector",
    "publicKeyJwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
      "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
    }
  }],
  "authentication": ["did:web:example.test:subjects:vector#key-1"],
  "assertionMethod": ["did:web:example.test:subjects:vector#key-1"]
}`

const (
	wantVectorDIDDigest     = "e08e529fe445c3506b707a790adc556b93148015621303fb48a7ccd7f1b3e8e8"
	wantVectorJWKThumbprint = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
	wantVectorAppPublicKey  = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)

func TestKeysVectorRecomputation(t *testing.T) {
	doc, digest, err := ParseDIDDocument([]byte(vectorDIDDocJSON))
	if err != nil {
		t.Fatalf("ParseDIDDocument failed: %v", err)
	}
	if digest != wantVectorDIDDigest {
		t.Fatalf("didDocumentDigest mismatch: got %s, want %s", digest, wantVectorDIDDigest)
	}

	_, gotHex, err := doc.VerificationMethod[0].PublicKeyJWK.Validate()
	if err != nil {
		t.Fatalf("JWK validate failed: %v", err)
	}
	if gotHex != wantVectorAppPublicKey {
		t.Fatalf("appPublicKey mismatch: got %s, want %s", gotHex, wantVectorAppPublicKey)
	}

	tp, err := doc.VerificationMethod[0].PublicKeyJWK.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint failed: %v", err)
	}
	if tp != wantVectorJWKThumbprint {
		t.Fatalf("thumbprint mismatch: got %s, want %s", tp, wantVectorJWKThumbprint)
	}

	// Verify round-trip from appPublicKey back to JWK & DID document
	jwk, err := AppPublicKeyToJWK(wantVectorAppPublicKey)
	if err != nil {
		t.Fatalf("AppPublicKeyToJWK failed: %v", err)
	}
	if jwk != doc.VerificationMethod[0].PublicKeyJWK {
		t.Fatalf("round-trip JWK mismatch: got %+v, want %+v", jwk, doc.VerificationMethod[0].PublicKeyJWK)
	}

	tp2, err := ThumbprintFromAppPublicKey(wantVectorAppPublicKey)
	if err != nil || tp2 != wantVectorJWKThumbprint {
		t.Fatalf("ThumbprintFromAppPublicKey mismatch: got %s err %v", tp2, err)
	}

	if _, _, err := doc.ResolveKey("did:web:example.test:subjects:vector#key-1", KeyPurposeAuthentication, wantVectorAppPublicKey); err != nil {
		t.Fatalf("ResolveKey authentication failed: %v", err)
	}
	if _, _, err := doc.ResolveKey("did:web:example.test:subjects:vector#key-1", KeyPurposeAssertionMethod, wantVectorAppPublicKey); err != nil {
		t.Fatalf("ResolveKey assertionMethod failed: %v", err)
	}
}

func TestKeysRejectInvalidPointsAndExtraFields(t *testing.T) {
	// Flip last hex nibble of G -> guaranteed off P-256 curve
	offCurve := wantVectorAppPublicKey[:len(wantVectorAppPublicKey)-1] + "6"
	compressed := "02" + wantVectorAppPublicKey[2:66]
	infinity := "04" + strings.Repeat("00", 64)

	badPoints := []struct {
		name string
		hex  string
	}{
		{"compressed 02", compressed},
		{"infinity", infinity},
		{"off-curve", offCurve},
		{"uppercase hex", strings.ToUpper(wantVectorAppPublicKey)},
		{"with 0x prefix", "0x" + wantVectorAppPublicKey},
		{"wrong length", wantVectorAppPublicKey[:128]},
	}
	for _, tc := range badPoints {
		t.Run("point_"+tc.name, func(t *testing.T) {
			if _, _, err := ParseAppPublicKey(tc.hex); !HasCode(err, ErrCodeInvalidSchema) {
				t.Fatalf("expected INVALID_SCHEMA for %s, got %v", tc.name, err)
			}
		})
	}

	// Off-curve inside JWK
	offX := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	offY := base64.RawURLEncoding.EncodeToString(big.NewInt(1).FillBytes(make([]byte, 32)))
	// Verify (0,1) is off P-256 curve: 1 != 0 - 0 + b
	if elliptic.P256().IsOnCurve(big.NewInt(0), big.NewInt(1)) {
		t.Fatal("expected (0,1) to be off curve")
	}
	badJWK := PublicKeyJWK{Kty: "EC", Crv: "P-256", X: offX, Y: offY}
	if _, _, err := badJWK.Validate(); !HasCode(err, ErrCodeInvalidSchema) {
		t.Fatalf("expected INVALID_SCHEMA for off-curve JWK, got %v", err)
	}

	// Extra field in DID document, verificationMethod, and publicKeyJwk (e.g., private key "d")
	extraDoc := strings.Replace(vectorDIDDocJSON, `"id":`, `"extra":"x","id":`, 1)
	if _, _, err := ParseDIDDocument([]byte(extraDoc)); !HasCode(err, ErrCodeInvalidSchema) {
		t.Fatalf("expected INVALID_SCHEMA for DID doc extra field, got %v", err)
	}
	extraJWK := strings.Replace(vectorDIDDocJSON, `"y":`, `"d":"AAAA","y":`, 1)
	if _, _, err := ParseDIDDocument([]byte(extraJWK)); !HasCode(err, ErrCodeInvalidSchema) {
		t.Fatalf("expected INVALID_SCHEMA for JWK extra field d, got %v", err)
	}
	extraVM := strings.Replace(vectorDIDDocJSON, `"type":`, `"extraVm":1,"type":`, 1)
	if _, _, err := ParseDIDDocument([]byte(extraVM)); !HasCode(err, ErrCodeInvalidSchema) {
		t.Fatalf("expected INVALID_SCHEMA for VM extra field, got %v", err)
	}

	// Verify key purpose enforcement
	docOnlyAuth, err := NewDIDDocument("did:web:a.local:u", "did:web:a.local:u#key-1", wantVectorAppPublicKey, KeyPurposeAuthentication)
	if err != nil {
		t.Fatalf("NewDIDDocument failed: %v", err)
	}
	if _, _, err := docOnlyAuth.ResolveKey("did:web:a.local:u#key-1", KeyPurposeAssertionMethod, wantVectorAppPublicKey); !HasCode(err, ErrCodeDIDKeyPurposeInvalid) {
		t.Fatalf("expected %s when assertionMethod missing, got %v", ErrCodeDIDKeyPurposeInvalid, err)
	}
	// Mismatched appPublicKey
	raw, _ := hex.DecodeString(wantVectorAppPublicKey)
	if len(raw) != 65 {
		t.Fatal("bad test raw len")
	}
	if _, _, err := docOnlyAuth.ResolveKey("did:web:a.local:u#key-1", KeyPurposeAuthentication, strings.Replace(wantVectorAppPublicKey, "046b", "0400", 1)); !HasCode(err, ErrCodeDIDDocumentMismatch) && !HasCode(err, ErrCodeInvalidSchema) {
		t.Fatalf("expected mismatch/schema error, got %v", err)
	}
}
