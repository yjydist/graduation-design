package protocol_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/protocol"
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

	wantNonceRawHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	wantNonceStr    = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
)

func TestKeysAndDIDVectorRecomputation(t *testing.T) {
	doc, digest, err := protocol.ParseDIDDocument([]byte(vectorDIDDocJSON))
	require.NoError(t, err)
	assert.Equal(t, wantVectorDIDDigest, digest)

	docDigest, err := doc.Digest()
	require.NoError(t, err)
	assert.Equal(t, wantVectorDIDDigest, docDigest)

	pub, err := protocol.PublicKeyFromJWK(doc.VerificationMethod[0].PublicKeyJWK)
	require.NoError(t, err)

	gotHex, err := protocol.FormatAppPublicKey(pub)
	require.NoError(t, err)
	assert.Equal(t, wantVectorAppPublicKey, gotHex)

	// RFC 7638 thumbprint via go-jose/v4 must match static vector.
	tp, err := protocol.JWKThumbprint(doc.VerificationMethod[0].PublicKeyJWK)
	require.NoError(t, err)
	assert.Equal(t, wantVectorJWKThumbprint, tp)

	// Round-trip appPublicKey -> *ecdsa.PublicKey -> PublicKeyJWK -> JWKThumbprint.
	parsedPub, err := protocol.ParseAppPublicKey(wantVectorAppPublicKey)
	require.NoError(t, err)
	jwk, err := protocol.JWKFromPublicKey(parsedPub)
	require.NoError(t, err)
	assert.Equal(t, doc.VerificationMethod[0].PublicKeyJWK, jwk)

	tp2, err := protocol.JWKThumbprint(jwk)
	require.NoError(t, err)
	assert.Equal(t, wantVectorJWKThumbprint, tp2)

	// ResolveKey for both authentication and assertionMethod.
	authPub, err := doc.ResolveKey("did:web:example.test:subjects:vector#key-1", protocol.KeyPurposeAuthentication)
	require.NoError(t, err)
	authHex, err := protocol.FormatAppPublicKey(authPub)
	require.NoError(t, err)
	assert.Equal(t, wantVectorAppPublicKey, authHex)

	assertPub, err := doc.ResolveKey("did:web:example.test:subjects:vector#key-1", protocol.KeyPurposeAssertionMethod)
	require.NoError(t, err)
	assertHex, err := protocol.FormatAppPublicKey(assertPub)
	require.NoError(t, err)
	assert.Equal(t, wantVectorAppPublicKey, assertHex)

	// Fresh P-256 key generation round-trip.
	priv, err := protocol.GenerateP256Key()
	require.NoError(t, err)
	pubHex, err := protocol.FormatAppPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	assert.Len(t, pubHex, protocol.AppPublicKeyHexLen)
	_, err = protocol.ParseAppPublicKey(pubHex)
	require.NoError(t, err)
}

func TestKeysRejectInvalidPointsCurvesAndExtraFields(t *testing.T) {
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
			_, err := protocol.ParseAppPublicKey(tc.hex)
			require.Error(t, err)
			assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema), "got %v", err)
		})
	}

	// Non-P256 curve rejected.
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	_, err = protocol.FormatAppPublicKey(&p384Key.PublicKey)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))
	_, err = protocol.JWKFromPublicKey(&p384Key.PublicKey)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))

	// Off-curve point (0, 1) inside JWK rejected.
	offX := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	offY := base64.RawURLEncoding.EncodeToString(big.NewInt(1).FillBytes(make([]byte, 32)))
	badJWK := protocol.PublicKeyJWK{Kty: "EC", Crv: "P-256", X: offX, Y: offY}
	_, err = protocol.PublicKeyFromJWK(badJWK)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))

	// Extra field in DID document, verificationMethod, and publicKeyJwk (e.g., private "d").
	extraDoc := strings.Replace(vectorDIDDocJSON, `"id":`, `"extra":"x","id":`, 1)
	_, _, err = protocol.ParseDIDDocument([]byte(extraDoc))
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))

	extraJWK := strings.Replace(vectorDIDDocJSON, `"y":`, `"d":"AAAA","y":`, 1)
	_, _, err = protocol.ParseDIDDocument([]byte(extraJWK))
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))

	extraVM := strings.Replace(vectorDIDDocJSON, `"type":`, `"extraVm":1,"type":`, 1)
	_, _, err = protocol.ParseDIDDocument([]byte(extraVM))
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))
}

func TestDIDDocumentPurposeSeparation(t *testing.T) {
	pub, err := protocol.ParseAppPublicKey(wantVectorAppPublicKey)
	require.NoError(t, err)

	docAuthOnly, err := protocol.NewDIDDocument("did:web:a.local:u", "did:web:a.local:u#key-1", pub, protocol.KeyPurposeAuthentication)
	require.NoError(t, err)

	_, err = docAuthOnly.ResolveKey("did:web:a.local:u#key-1", protocol.KeyPurposeAuthentication)
	require.NoError(t, err)

	_, err = docAuthOnly.ResolveKey("did:web:a.local:u#key-1", protocol.KeyPurposeAssertionMethod)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeDIDKeyPurposeInvalid), "got %v", err)

	docAssertOnly, err := protocol.NewDIDDocument("did:web:a.local:u", "did:web:a.local:u#key-1", pub, protocol.KeyPurposeAssertionMethod)
	require.NoError(t, err)

	_, err = docAssertOnly.ResolveKey("did:web:a.local:u#key-1", protocol.KeyPurposeAssertionMethod)
	require.NoError(t, err)

	_, err = docAssertOnly.ResolveKey("did:web:a.local:u#key-1", protocol.KeyPurposeAuthentication)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeDIDKeyPurposeInvalid), "got %v", err)

	_, err = docAssertOnly.ResolveKey("did:web:other.local:u#key-1", protocol.KeyPurposeAssertionMethod)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeDIDDocumentMismatch), "got %v", err)

	_, err = docAssertOnly.ResolveKey("did:web:a.local:u#key-1", "keyAgreement")
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema), "got %v", err)
}

func TestNonceAndStrictBase64URLValidation(t *testing.T) {
	raw, err := hex.DecodeString(wantNonceRawHex)
	require.NoError(t, err)
	assert.Equal(t, wantNonceStr, base64.RawURLEncoding.EncodeToString(raw))
	require.NoError(t, protocol.ValidateNonce(wantNonceStr))

	n1, err := protocol.GenerateNonce()
	require.NoError(t, err)
	n2, err := protocol.GenerateNonce()
	require.NoError(t, err)
	assert.NotEqual(t, n1, n2)
	assert.Len(t, n1, protocol.ChallengeNonceLen)
	require.NoError(t, protocol.ValidateNonce(n1))

	// Construct a valid 43-char nonce whose last char is '8' (bits 111100 -> 4 trailing zero bits valid)
	// and mutate '8' -> '9' (bits 111101 -> non-zero unused trailing bit).
	base32 := make([]byte, 32)
	base32[31] = 0xF0 // last 2 bits of byte 31 are 00; actually 32*8=256 bits -> 42*6=252 bits, 4 bits remain:
	// Byte 31 lower 4 bits = 0xF (1111) -> 6-bit value 111100 = 60 -> base64url char '8'!
	base32[31] = 0x0F
	nonceEnding8 := base64.RawURLEncoding.EncodeToString(base32)
	require.True(t, strings.HasSuffix(nonceEnding8, "8"), "got %q", nonceEnding8)
	require.NoError(t, protocol.ValidateNonce(nonceEnding8))

	nonceMutated8To9 := nonceEnding8[:42] + "9"

	badCases := []struct {
		name  string
		nonce string
	}{
		{"empty", ""},
		{"with equals padding", wantNonceStr + "="},
		{"non-canonical trailing bit 8->9", nonceMutated8To9},
		{"non-canonical trailing bit on vector", wantNonceStr[:42] + "9"},
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
			err := protocol.ValidateNonce(tc.nonce)
			require.Error(t, err)
			assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema), "got %v", err)
		})
	}

	// DecodeStrictBase64URL rejects empty, padding, and non-canonical trailing bits.
	_, err = protocol.DecodeStrictBase64URL("")
	require.Error(t, err)
	_, err = protocol.DecodeStrictBase64URL("YQ==")
	require.Error(t, err)
	_, err = protocol.DecodeStrictBase64URL("YR") // 'a' is "YQ" (011000 010000); "YR" has non-zero trailing bit
	require.Error(t, err)
	got, err := protocol.DecodeStrictBase64URL("YQ")
	require.NoError(t, err)
	assert.Equal(t, []byte("a"), got)
}

func TestCompactAndDetachedES256JWS(t *testing.T) {
	priv, err := protocol.GenerateP256Key()
	require.NoError(t, err)
	otherPriv, err := protocol.GenerateP256Key()
	require.NoError(t, err)

	kid := "did:web:a.local:subjects:u#key-1"
	// Deliberately include non-canonical whitespace to confirm raw payload bytes are preserved verbatim.
	rawPayload := []byte(`{ "hello": "world", "n": 42 }`)

	types := []string{
		protocol.TypeDomainAuthorityJWS,
		protocol.TypeSDJWT,
		protocol.TypeGrantJWS,
		protocol.TypeKBJWT,
		protocol.TypeManagementProofJWS,
		protocol.TypeLinkProofJWS,
	}
	for _, typ := range types {
		t.Run("typ_"+typ, func(t *testing.T) {
			tok, err := protocol.SignCompactJWS(priv, typ, kid, rawPayload)
			require.NoError(t, err)

			parsed, err := protocol.ParseCompactJWS(tok, typ)
			require.NoError(t, err)
			assert.Equal(t, tok, parsed.Raw)
			assert.Equal(t, protocol.DigestBytes([]byte(tok)), parsed.Digest)
			assert.Equal(t, "ES256", parsed.Header.Alg)
			assert.Equal(t, typ, parsed.Header.Typ)
			assert.Equal(t, kid, parsed.Header.Kid)
			assert.Equal(t, rawPayload, parsed.PayloadBytes)
			assert.Len(t, parsed.Signature, 64)

			require.NoError(t, parsed.Verify(&priv.PublicKey))

			// Wrong verification key fails with SIGNATURE_INVALID.
			err = parsed.Verify(&otherPriv.PublicKey)
			require.Error(t, err)
			assert.True(t, protocol.HasCode(err, protocol.ErrCodeSignatureInvalid), "got %v", err)
		})
	}

	tok, err := protocol.SignCompactJWS(priv, protocol.TypeGrantJWS, kid, rawPayload)
	require.NoError(t, err)
	parts := strings.Split(tok, ".")
	require.Len(t, parts, 3)

	// Tampered payload fails verification.
	tamperedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{ "hello": "evil", "n": 42 }`))
	tamperedTok := parts[0] + "." + tamperedPayload + "." + parts[2]
	parsedTampered, err := protocol.ParseCompactJWS(tamperedTok, protocol.TypeGrantJWS)
	require.NoError(t, err)
	err = parsedTampered.Verify(&priv.PublicKey)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeSignatureInvalid), "got %v", err)

	// Wrong expectedTyp fails with INVALID_SCHEMA.
	_, err = protocol.ParseCompactJWS(tok, protocol.TypeKBJWT)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema), "got %v", err)

	// Disallowed alg ("none", "HS256") fails with SIGNATURE_INVALID.
	for _, alg := range []string{"none", "HS256", "RS256"} {
		badHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + alg + `","kid":"` + kid + `","typ":"` + protocol.TypeGrantJWS + `"}`))
		_, err = protocol.ParseCompactJWS(badHdr+"."+parts[1]+"."+parts[2], protocol.TypeGrantJWS)
		require.Error(t, err)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodeSignatureInvalid), "alg=%s got %v", alg, err)
	}

	// Extra header field (e.g. embedded jwk) or duplicate header key rejected with INVALID_SCHEMA.
	extraHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"` + kid + `","typ":"` + protocol.TypeGrantJWS + `","extra":"x"}`))
	_, err = protocol.ParseCompactJWS(extraHdr+"."+parts[1]+"."+parts[2], protocol.TypeGrantJWS)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))

	dupHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","alg":"ES256","kid":"` + kid + `","typ":"` + protocol.TypeGrantJWS + `"}`))
	_, err = protocol.ParseCompactJWS(dupHdr+"."+parts[1]+"."+parts[2], protocol.TypeGrantJWS)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))

	// Malformed segment count, non-ASCII, padded base64url, and oversized token.
	_, err = protocol.ParseCompactJWS("a.b", protocol.TypeGrantJWS)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))

	_, err = protocol.ParseCompactJWS(parts[0]+"=."+parts[1]+"."+parts[2], protocol.TypeGrantJWS)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))

	_, err = protocol.ParseCompactJWS(parts[0]+"."+parts[1]+"=."+parts[2], protocol.TypeGrantJWS)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))

	_, err = protocol.ParseCompactJWS(parts[0]+"."+parts[1]+"."+parts[2]+"=", protocol.TypeGrantJWS)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeSignatureInvalid))

	_, err = protocol.ParseCompactJWS(parts[0]+"."+parts[1]+"."+parts[2]+"\u00e9", protocol.TypeGrantJWS)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))

	_, err = protocol.ParseCompactJWS(strings.Repeat("a", protocol.MaxJSONBytes+1), protocol.TypeGrantJWS)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodePayloadTooLarge))

	// Detached JWS sign and verify.
	protB64, sigB64, err := protocol.SignDetachedJWS(priv, protocol.TypeManagementProofJWS, kid, rawPayload)
	require.NoError(t, err)
	require.NoError(t, protocol.VerifyDetachedJWS(protB64, rawPayload, sigB64, &priv.PublicKey, protocol.TypeManagementProofJWS, kid))

	// Detached JWS with wrong kid -> DID_DOCUMENT_MISMATCH.
	err = protocol.VerifyDetachedJWS(protB64, rawPayload, sigB64, &priv.PublicKey, protocol.TypeManagementProofJWS, "did:web:a.local:subjects:u#key-2")
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeDIDDocumentMismatch), "got %v", err)

	// Detached JWS with tampered payload -> SIGNATURE_INVALID.
	err = protocol.VerifyDetachedJWS(protB64, []byte(`{"tampered":true}`), sigB64, &priv.PublicKey, protocol.TypeManagementProofJWS, kid)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeSignatureInvalid), "got %v", err)
}
