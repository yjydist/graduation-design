package protocol

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	jose "github.com/go-jose/go-jose/v4"

	"grad/protocol/registry"
)

const (
	// UncompressedP256Bytes is the byte length of an uncompressed SEC 1 P-256 point (0x04 || X || Y).
	UncompressedP256Bytes = 65
	// AppPublicKeyHexLen is the lowercase hex length of UncompressedP256Bytes.
	AppPublicKeyHexLen = UncompressedP256Bytes * 2

	// KeyPurposeAuthentication requires the keyId in DID Document authentication.
	KeyPurposeAuthentication = "authentication"
	// KeyPurposeAssertionMethod requires the keyId in DID Document assertionMethod.
	KeyPurposeAssertionMethod = "assertionMethod"

	// ChallengeNonceBytes is the fixed raw byte length (32) of challenge nonces.
	ChallengeNonceBytes = 32
	// ChallengeNonceLen is the exact canonical unpadded base64url length (43) of 32 bytes.
	ChallengeNonceLen = 43

	// Standard grad-auth-v1 JOSE typ header values.
	TypeDomainAuthorityJWS = "vc+jwt"
	TypeSDJWT              = "vc+sd-jwt"
	TypeGrantJWS           = "grad-delegation+jwt"
	TypeKBJWT              = "kb+jwt"
	TypeManagementProofJWS = "grad-management-proof+jwt"
	TypeLinkProofJWS       = "grad-link-proof+jwt"
)

// PublicKeyJWK represents a strict P-256 EC public JWK without private parameters.
type PublicKeyJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// VerificationMethod represents one entry in a DID Document verificationMethod array.
type VerificationMethod struct {
	ID           string       `json:"id"`
	Type         string       `json:"type"`
	Controller   string       `json:"controller"`
	PublicKeyJWK PublicKeyJWK `json:"publicKeyJwk"`
}

// DIDDocument models a strict application/did+json document under grad-auth-v1.
type DIDDocument struct {
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []string             `json:"authentication,omitempty"`
	AssertionMethod    []string             `json:"assertionMethod,omitempty"`
}

// JWSHeader represents the strict grad-auth-v1 compact ES256 protected header.
type JWSHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// ParsedJWS represents a strictly parsed compact ES256 JWS preserving raw payload bytes.
type ParsedJWS struct {
	Raw          string
	Digest       string
	Header       JWSHeader
	PayloadBytes []byte
	Signature    []byte

	jws *jose.JSONWebSignature
}

// GenerateP256Key generates a fresh ECDSA P-256 private key.
func GenerateP256Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func encodeUncompressedP256(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, NewError(ErrCodeInvalidSchema, "public key must use P-256 curve")
	}
	raw, err := pub.Bytes()
	if err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "encode P-256 public key", err)
	}
	if len(raw) != UncompressedP256Bytes || raw[0] != 0x04 {
		return nil, NewError(ErrCodeInvalidSchema, "unexpected uncompressed P-256 point length")
	}
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw); err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "invalid P-256 public key point", err)
	}
	return raw, nil
}

// FormatAppPublicKey encodes a valid P-256 public key as a 130-char lowercase hex SEC 1 uncompressed point.
func FormatAppPublicKey(pub *ecdsa.PublicKey) (string, error) {
	raw, err := encodeUncompressedP256(pub)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// ParseAppPublicKey decodes and validates a 130-character lowercase hex SEC 1 uncompressed P-256 public key.
func ParseAppPublicKey(publicHex string) (*ecdsa.PublicKey, error) {
	return registry.ParseAppPublicKey(publicHex)
}

// DecodeStrictBase64URL decodes s as canonical unpadded RFC 4648 base64url, rejecting padding,
// invalid alphabet characters, and non-canonical trailing unused bits.
func DecodeStrictBase64URL(s string) ([]byte, error) {
	if s == "" {
		return nil, NewError(ErrCodeInvalidSchema, "base64url string must not be empty")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid base64url character %q", c))
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "base64url decode failed", err)
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != s {
		return nil, NewError(ErrCodeInvalidSchema, "non-canonical base64url trailing bits")
	}
	return decoded, nil
}

// DecodeStrictBase64URLFixed decodes s strictly as canonical unpadded base64url of exact expectedBytes length.
func DecodeStrictBase64URLFixed(s string, expectedBytes int) ([]byte, error) {
	if expectedBytes <= 0 {
		return nil, NewError(ErrCodeInvalidSchema, "expected base64url byte length must be positive")
	}
	expectedLen := base64.RawURLEncoding.EncodedLen(expectedBytes)
	if len(s) != expectedLen {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("expected base64url length %d, got %d", expectedLen, len(s)))
	}
	decoded, err := DecodeStrictBase64URL(s)
	if err != nil {
		return nil, err
	}
	if len(decoded) != expectedBytes {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("expected %d decoded bytes, got %d", expectedBytes, len(decoded)))
	}
	return decoded, nil
}

// JWKFromPublicKey converts a valid P-256 public key into a strict PublicKeyJWK.
func JWKFromPublicKey(pub *ecdsa.PublicKey) (PublicKeyJWK, error) {
	raw, err := encodeUncompressedP256(pub)
	if err != nil {
		return PublicKeyJWK{}, err
	}
	return PublicKeyJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(raw[1:33]),
		Y:   base64.RawURLEncoding.EncodeToString(raw[33:65]),
	}, nil
}

// PublicKeyFromJWK validates a strict EC/P-256 PublicKeyJWK and returns its *ecdsa.PublicKey.
func PublicKeyFromJWK(jwk PublicKeyJWK) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("JWK must use EC/P-256, got %q/%q", jwk.Kty, jwk.Crv))
	}
	xBytes, err := DecodeStrictBase64URLFixed(jwk.X, 32)
	if err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "invalid JWK x coordinate", err)
	}
	yBytes, err := DecodeStrictBase64URLFixed(jwk.Y, 32)
	if err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "invalid JWK y coordinate", err)
	}
	raw := make([]byte, UncompressedP256Bytes)
	raw[0] = 0x04
	copy(raw[1:33], xBytes)
	copy(raw[33:65], yBytes)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "invalid P-256 point in JWK", err)
	}
	return pub, nil
}

// JWKThumbprint computes the RFC 7638 SHA-256 unpadded base64url thumbprint of a validated P-256 PublicKeyJWK.
func JWKThumbprint(jwk PublicKeyJWK) (string, error) {
	pub, err := PublicKeyFromJWK(jwk)
	if err != nil {
		return "", err
	}
	jk := jose.JSONWebKey{Key: pub}
	sum, err := jk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", WrapError(ErrCodeInvalidSchema, "compute RFC 7638 JWK thumbprint", err)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// NewDIDDocument builds a validated single-key grad-auth-v1 DID Document.
// When purposes is omitted, both authentication and assertionMethod are enabled.
func NewDIDDocument(did, keyID string, pub *ecdsa.PublicKey, purposes ...string) (*DIDDocument, error) {
	jwk, err := JWKFromPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(keyID, did+"#") || len(keyID) <= len(did)+1 {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("keyID %q must have prefix %q", keyID, did+"#"))
	}
	doc := &DIDDocument{
		ID: did,
		VerificationMethod: []VerificationMethod{
			{
				ID:           keyID,
				Type:         "JsonWebKey",
				Controller:   did,
				PublicKeyJWK: jwk,
			},
		},
	}
	if len(purposes) == 0 {
		purposes = []string{KeyPurposeAuthentication, KeyPurposeAssertionMethod}
	}
	for _, p := range purposes {
		switch p {
		case KeyPurposeAuthentication:
			doc.Authentication = append(doc.Authentication, keyID)
		case KeyPurposeAssertionMethod:
			doc.AssertionMethod = append(doc.AssertionMethod, keyID)
		default:
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("unknown DID key purpose %q", p))
		}
	}
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	return doc, nil
}

// ParseDIDDocument strictly parses and validates a DID Document and returns it with its JCS SHA-256 digest.
func ParseDIDDocument(raw []byte) (*DIDDocument, string, error) {
	digest, err := DigestJCS(raw)
	if err != nil {
		return nil, "", err
	}
	var doc DIDDocument
	if err := DecodeStrictJSON(raw, &doc); err != nil {
		return nil, "", err
	}
	if err := doc.Validate(); err != nil {
		return nil, "", err
	}
	return &doc, digest, nil
}

// Validate verifies structural and cryptographic invariants of a DIDDocument.
func (d *DIDDocument) Validate() error {
	if d == nil {
		return NewError(ErrCodeInvalidSchema, "nil DID document")
	}
	if !strings.HasPrefix(d.ID, "did:") || len(d.ID) <= len("did:") {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid DID document id %q", d.ID))
	}
	if len(d.VerificationMethod) == 0 {
		return NewError(ErrCodeInvalidSchema, "DID document verificationMethod must not be empty")
	}
	seenVM := make(map[string]struct{}, len(d.VerificationMethod))
	for i, vm := range d.VerificationMethod {
		if !strings.HasPrefix(vm.ID, d.ID+"#") || len(vm.ID) <= len(d.ID)+1 {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("verificationMethod[%d].id %q must reference %s", i, vm.ID, d.ID))
		}
		if _, dup := seenVM[vm.ID]; dup {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("duplicate verificationMethod id %q", vm.ID))
		}
		seenVM[vm.ID] = struct{}{}
		if vm.Type != "JsonWebKey" {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("verificationMethod[%d].type must be JsonWebKey, got %q", i, vm.Type))
		}
		if vm.Controller != d.ID {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("verificationMethod[%d].controller %q must equal %q", i, vm.Controller, d.ID))
		}
		if _, err := PublicKeyFromJWK(vm.PublicKeyJWK); err != nil {
			return err
		}
	}
	if len(d.Authentication) == 0 && len(d.AssertionMethod) == 0 {
		return NewError(ErrCodeInvalidSchema, "DID document must define authentication or assertionMethod")
	}
	for _, ref := range d.Authentication {
		if !strings.HasPrefix(ref, d.ID+"#") {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("authentication reference %q must belong to %s", ref, d.ID))
		}
	}
	for _, ref := range d.AssertionMethod {
		if !strings.HasPrefix(ref, d.ID+"#") {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("assertionMethod reference %q must belong to %s", ref, d.ID))
		}
	}
	return nil
}

// Digest computes the RFC 8785 JCS SHA-256 digest of a validated DIDDocument.
func (d *DIDDocument) Digest() (string, error) {
	if err := d.Validate(); err != nil {
		return "", err
	}
	return DigestValueJCS(d)
}

// ResolveKey resolves kid in the DID Document while enforcing authentication vs assertionMethod separation.
func (d *DIDDocument) ResolveKey(kid, purpose string) (*ecdsa.PublicKey, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(kid, d.ID+"#") {
		return nil, NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("kid %q does not belong to DID %q", kid, d.ID))
	}
	var allowed []string
	switch purpose {
	case KeyPurposeAuthentication:
		allowed = d.Authentication
	case KeyPurposeAssertionMethod:
		allowed = d.AssertionMethod
	default:
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("unsupported DID key purpose %q", purpose))
	}
	if !slices.Contains(allowed, kid) {
		return nil, NewError(ErrCodeDIDKeyPurposeInvalid, fmt.Sprintf("kid %q lacks %s purpose in DID document %q", kid, purpose, d.ID))
	}
	for _, vm := range d.VerificationMethod {
		if vm.ID == kid {
			return PublicKeyFromJWK(vm.PublicKeyJWK)
		}
	}
	return nil, NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("kid %q not found in verificationMethod of %q", kid, d.ID))
}

// GenerateNonce generates a 32-byte CSPRNG challenge nonce encoded as a canonical 43-char unpadded base64url string.
func GenerateNonce() (string, error) {
	buf := make([]byte, ChallengeNonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// ValidateNonce validates nonce as a canonical 43-char unpadded base64url encoding of 32 bytes.
func ValidateNonce(nonce string) error {
	if len(nonce) != ChallengeNonceLen {
		return NewError(ErrCodeInvalidSchema, "challenge nonce must be 43 unpadded base64url characters")
	}
	if _, err := DecodeStrictBase64URLFixed(nonce, ChallengeNonceBytes); err != nil {
		return WrapError(ErrCodeInvalidSchema, "invalid challenge nonce", err)
	}
	return nil
}

// SignCompactJWS signs raw payload bytes with ES256 (P-256 + SHA-256) using go-jose/v4
// and returns the ASCII compact JWS without re-encoding payload.
func SignCompactJWS(key *ecdsa.PrivateKey, typ, kid string, payload []byte) (string, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return "", NewError(ErrCodeInvalidSchema, "ES256 signer requires P-256 private key")
	}
	if typ == "" || kid == "" {
		return "", NewError(ErrCodeInvalidSchema, "JWS typ and kid must be non-empty")
	}
	if len(payload) == 0 {
		return "", NewError(ErrCodeInvalidSchema, "JWS payload must not be empty")
	}
	opts := (&jose.SignerOptions{}).
		WithType(jose.ContentType(typ)).
		WithHeader(jose.HeaderKey("kid"), kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		return "", WrapError(ErrCodeInvalidSchema, "create ES256 JWS signer", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", WrapError(ErrCodeSignatureInvalid, "sign ES256 JWS", err)
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		return "", WrapError(ErrCodeInvalidSchema, "serialize compact JWS", err)
	}
	return compact, nil
}

// ParseCompactJWS strictly validates and parses an ASCII compact ES256 JWS without verifying the signature.
func ParseCompactJWS(token string, expectedTyp string) (*ParsedJWS, error) {
	if token == "" {
		return nil, NewError(ErrCodeInvalidSchema, "compact JWS must not be empty")
	}
	if len(token) > MaxJSONBytes {
		return nil, NewError(ErrCodePayloadTooLarge, fmt.Sprintf("compact JWS size %d exceeds %d bytes", len(token), MaxJSONBytes))
	}
	for i := 0; i < len(token); i++ {
		if token[i] > 0x7F {
			return nil, NewError(ErrCodeInvalidSchema, "compact JWS contains non-ASCII bytes")
		}
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, NewError(ErrCodeInvalidSchema, "compact JWS must have exactly 3 segments")
	}

	hdrBytes, err := DecodeStrictBase64URL(parts[0])
	if err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "decode compact JWS protected header", err)
	}
	var hdr JWSHeader
	if err := DecodeStrictJSON(hdrBytes, &hdr); err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "parse compact JWS protected header", err)
	}
	if hdr.Alg != string(jose.ES256) {
		return nil, NewError(ErrCodeSignatureInvalid, fmt.Sprintf("unsupported JWS alg %q", hdr.Alg))
	}
	if hdr.Kid == "" || hdr.Typ == "" {
		return nil, NewError(ErrCodeInvalidSchema, "JWS protected header kid and typ must not be empty")
	}
	if expectedTyp != "" && hdr.Typ != expectedTyp {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("unexpected JWS typ %q, want %q", hdr.Typ, expectedTyp))
	}

	payloadBytes, err := DecodeStrictBase64URL(parts[1])
	if err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "decode compact JWS payload", err)
	}
	sigRaw, err := DecodeStrictBase64URLFixed(parts[2], 64)
	if err != nil {
		return nil, WrapError(ErrCodeSignatureInvalid, "decode ES256 compact signature", err)
	}

	jwsObj, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, WrapError(ErrCodeSignatureInvalid, "parse compact ES256 JWS", err)
	}
	return &ParsedJWS{
		Raw:          token,
		Digest:       DigestBytes([]byte(token)),
		Header:       hdr,
		PayloadBytes: payloadBytes,
		Signature:    sigRaw,
		jws:          jwsObj,
	}, nil
}

// Verify verifies the ES256 signature on ParsedJWS against a P-256 public key.
func (p *ParsedJWS) Verify(pub *ecdsa.PublicKey) error {
	if p == nil || p.jws == nil {
		return NewError(ErrCodeInvalidSchema, "nil ParsedJWS")
	}
	if pub == nil || pub.Curve != elliptic.P256() {
		return NewError(ErrCodeSignatureInvalid, "ES256 verifier requires P-256 public key")
	}
	verified, err := p.jws.Verify(pub)
	if err != nil {
		return WrapError(ErrCodeSignatureInvalid, "compact JWS ES256 signature verification failed", err)
	}
	if !bytes.Equal(verified, p.PayloadBytes) {
		return NewError(ErrCodeSignatureInvalid, "verified JWS payload mismatch")
	}
	return nil
}

// SignDetachedJWS signs payload with ES256 and returns the detached protected header and signature base64url segments.
func SignDetachedJWS(key *ecdsa.PrivateKey, typ, kid string, payload []byte) (protectedB64, sigB64 string, err error) {
	compact, err := SignCompactJWS(key, typ, kid, payload)
	if err != nil {
		return "", "", err
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return "", "", NewError(ErrCodeInvalidSchema, "internal error splitting compact JWS")
	}
	return parts[0], parts[2], nil
}

// VerifyDetachedJWS verifies a detached ES256 JWS protected header and signature against raw payload bytes.
func VerifyDetachedJWS(protectedB64 string, payload []byte, sigB64 string, pub *ecdsa.PublicKey, expectedTyp, expectedKid string) error {
	if len(payload) == 0 {
		return NewError(ErrCodeInvalidSchema, "detached JWS payload must not be empty")
	}
	token := protectedB64 + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + sigB64
	parsed, err := ParseCompactJWS(token, expectedTyp)
	if err != nil {
		return err
	}
	if expectedKid != "" && parsed.Header.Kid != expectedKid {
		return NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("JWS kid %q mismatches expected %q", parsed.Header.Kid, expectedKid))
	}
	return parsed.Verify(pub)
}
