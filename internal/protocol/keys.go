package protocol

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

const (
	// UncompressedP256Bytes is the byte length of an uncompressed P-256 point (0x04 || X || Y).
	UncompressedP256Bytes = 65
	// AppPublicKeyHexLen is the lowercase hex length of UncompressedP256Bytes.
	AppPublicKeyHexLen = UncompressedP256Bytes * 2
	// KeyPurposeAuthentication requires the keyId in DID Document authentication.
	KeyPurposeAuthentication = "authentication"
	// KeyPurposeAssertionMethod requires the keyId in DID Document assertionMethod.
	KeyPurposeAssertionMethod = "assertionMethod"
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

// GenerateP256KeyPair generates a fresh P-256 keypair and returns it with its lowercase 130-hex appPublicKey.
func GenerateP256KeyPair() (*ecdsa.PrivateKey, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	pubHex, err := EncodeAppPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return priv, pubHex, nil
}

// EncodeAppPublicKey encodes a valid P-256 *ecdsa.PublicKey to 130-char lowercase hex (04 || X || Y).
func EncodeAppPublicKey(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return "", NewError(ErrCodeInvalidSchema, "public key must use P-256 curve")
	}
	raw, err := pub.Bytes()
	if err != nil {
		return "", WrapError(ErrCodeInvalidSchema, "encode P-256 public key", err)
	}
	if len(raw) != UncompressedP256Bytes || raw[0] != 0x04 {
		return "", NewError(ErrCodeInvalidSchema, "unexpected encoded P-256 point length")
	}
	if err := validateP256PointBytes(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// ParseAppPublicKey parses a strict 130-char lowercase hex uncompressed P-256 point.
func ParseAppPublicKey(hexStr string) (*ecdsa.PublicKey, []byte, error) {
	if len(hexStr) != AppPublicKeyHexLen {
		return nil, nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("appPublicKey must be %d lowercase hex chars, got %d", AppPublicKeyHexLen, len(hexStr)))
	}
	for i := 0; i < len(hexStr); i++ {
		c := hexStr[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return nil, nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("appPublicKey contains non-lowercase-hex char %q", c))
		}
	}
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, nil, WrapError(ErrCodeInvalidSchema, "decode appPublicKey hex", err)
	}
	if len(raw) != UncompressedP256Bytes || raw[0] != 0x04 {
		return nil, nil, NewError(ErrCodeInvalidSchema, "appPublicKey must be uncompressed 0x04 point")
	}
	if err := validateP256PointBytes(raw); err != nil {
		return nil, nil, err
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, nil, WrapError(ErrCodeInvalidSchema, "invalid P-256 public key", err)
	}
	return pub, raw, nil
}

func validateP256PointBytes(raw []byte) error {
	if len(raw) != UncompressedP256Bytes || raw[0] != 0x04 {
		return NewError(ErrCodeInvalidSchema, "point must be 65-byte uncompressed P-256 format")
	}
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		return WrapError(ErrCodeInvalidSchema, "point is not on P-256 curve or is infinity", err)
	}
	p256 := elliptic.P256().Params()
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])
	if x.Sign() == 0 && y.Sign() == 0 {
		return NewError(ErrCodeInvalidSchema, "point at infinity rejected")
	}
	if x.Cmp(p256.P) >= 0 || y.Cmp(p256.P) >= 0 || !p256.IsOnCurve(x, y) {
		return NewError(ErrCodeInvalidSchema, "point coordinates fail P-256 curve equation")
	}
	return nil
}

// AppPublicKeyToJWK converts a validated 130-char lowercase hex appPublicKey to a PublicKeyJWK.
func AppPublicKeyToJWK(hexStr string) (PublicKeyJWK, error) {
	_, raw, err := ParseAppPublicKey(hexStr)
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

// DecodeStrictBase64URLFixed decodes s strictly as unpadded RFC 4648 base64url of exactByteLen bytes,
// verifying no padding, invalid alphabet, or non-canonical trailing bits.
func DecodeStrictBase64URLFixed(s string, expectedBytes int) ([]byte, error) {
	if s == "" || strings.ContainsAny(s, "=+/\r\n\t ") {
		return nil, NewError(ErrCodeInvalidSchema, "base64url contains padding or invalid characters")
	}
	expectedLen := base64.RawURLEncoding.EncodedLen(expectedBytes)
	if len(s) != expectedLen {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("expected base64url length %d, got %d", expectedLen, len(s)))
	}
	for i := 0; i < len(s); i++ {
		if !isBase64URLChar(s[i]) {
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid base64url char %q", s[i]))
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(decoded) != expectedBytes {
		return nil, NewError(ErrCodeInvalidSchema, "base64url decode failed")
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != s {
		return nil, NewError(ErrCodeInvalidSchema, "non-canonical base64url trailing bits")
	}
	return decoded, nil
}

func isBase64URLChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_'
}

// Validate checks JWK fields and returns the *ecdsa.PublicKey and lowercase 130-hex appPublicKey.
func (j PublicKeyJWK) Validate() (*ecdsa.PublicKey, string, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, "", NewError(ErrCodeInvalidSchema, fmt.Sprintf("JWK must use EC/P-256, got %q/%q", j.Kty, j.Crv))
	}
	xBytes, err := DecodeStrictBase64URLFixed(j.X, 32)
	if err != nil {
		return nil, "", WrapError(ErrCodeInvalidSchema, "invalid JWK x coordinate", err)
	}
	yBytes, err := DecodeStrictBase64URLFixed(j.Y, 32)
	if err != nil {
		return nil, "", WrapError(ErrCodeInvalidSchema, "invalid JWK y coordinate", err)
	}
	raw := make([]byte, UncompressedP256Bytes)
	raw[0] = 0x04
	copy(raw[1:33], xBytes)
	copy(raw[33:65], yBytes)
	hexStr := hex.EncodeToString(raw)
	pub, _, err := ParseAppPublicKey(hexStr)
	if err != nil {
		return nil, "", err
	}
	return pub, hexStr, nil
}

// Thumbprint computes the RFC 7638 SHA-256 JWK thumbprint encoded as unpadded base64url.
func (j PublicKeyJWK) Thumbprint() (string, error) {
	if _, _, err := j.Validate(); err != nil {
		return "", err
	}
	// RFC 7638 Section 3.2 required members for EC keys in lexicographic order: crv, kty, x, y.
	canon := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, j.Crv, j.Kty, j.X, j.Y)
	sum := sha256.Sum256([]byte(canon))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ThumbprintFromAppPublicKey computes the RFC 7638 JWK thumbprint for a 130-char lowercase hex appPublicKey.
func ThumbprintFromAppPublicKey(hexStr string) (string, error) {
	jwk, err := AppPublicKeyToJWK(hexStr)
	if err != nil {
		return "", err
	}
	return jwk.Thumbprint()
}

// ParseDIDDocument parses raw DID document bytes strictly, validates structure and keys,
// and returns the parsed DIDDocument together with its JCS SHA-256 digest (didDocumentDigest).
func ParseDIDDocument(raw []byte) (*DIDDocument, string, error) {
	digest, _, err := DigestJCS(raw)
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

// Validate verifies structural integrity and cryptographic validity of the DIDDocument.
func (d *DIDDocument) Validate() error {
	if d == nil {
		return NewError(ErrCodeInvalidSchema, "nil DID document")
	}
	if !strings.HasPrefix(d.ID, "did:") {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid DID document id %q", d.ID))
	}
	if len(d.VerificationMethod) == 0 {
		return NewError(ErrCodeInvalidSchema, "DID document verificationMethod must not be empty")
	}
	seenVM := make(map[string]struct{}, len(d.VerificationMethod))
	for i, vm := range d.VerificationMethod {
		if !strings.HasPrefix(vm.ID, d.ID+"#") || len(vm.ID) <= len(d.ID)+1 {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("verificationMethod[%d].id %q must be absolute DID URL referencing %s", i, vm.ID, d.ID))
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
		if _, _, err := vm.PublicKeyJWK.Validate(); err != nil {
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

// Digest computes the JCS SHA-256 digest of a DIDDocument.
func (d *DIDDocument) Digest() (string, error) {
	if err := d.Validate(); err != nil {
		return "", err
	}
	canon, err := MarshalJCS(d)
	if err != nil {
		return "", err
	}
	return DigestBytes(canon), nil
}

// ResolveKey finds keyID in the DID Document, checks the required key purpose, and verifies
// the resolved public key matches expectedAppPublicKey (if non-empty).
func (d *DIDDocument) ResolveKey(keyID, purpose, expectedAppPublicKey string) (*ecdsa.PublicKey, string, error) {
	if err := d.Validate(); err != nil {
		return nil, "", err
	}
	if !strings.HasPrefix(keyID, d.ID+"#") {
		return nil, "", NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("keyID %q does not belong to DID %q", keyID, d.ID))
	}

	var list []string
	switch purpose {
	case KeyPurposeAuthentication:
		list = d.Authentication
	case KeyPurposeAssertionMethod:
		list = d.AssertionMethod
	default:
		return nil, "", NewError(ErrCodeInvalidSchema, fmt.Sprintf("unsupported DID key purpose %q", purpose))
	}

	allowed := false
	for _, id := range list {
		if id == keyID {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, "", NewError(ErrCodeDIDKeyPurposeInvalid, fmt.Sprintf("keyID %q lacks %s purpose in DID document %q", keyID, purpose, d.ID))
	}

	for _, vm := range d.VerificationMethod {
		if vm.ID == keyID {
			pub, pubHex, err := vm.PublicKeyJWK.Validate()
			if err != nil {
				return nil, "", err
			}
			if expectedAppPublicKey != "" && pubHex != expectedAppPublicKey {
				return nil, "", NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("DID document public key %s mismatches registered appPublicKey", pubHex))
			}
			return pub, pubHex, nil
		}
	}
	return nil, "", NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("keyID %q not found in verificationMethod of %q", keyID, d.ID))
}

// NewDIDDocument builds a standard single-key grad-auth-v1 DID Document with both
// authentication and assertionMethod enabled (or customized purposes).
func NewDIDDocument(did, keyID, appPublicKeyHex string, purposes ...string) (*DIDDocument, error) {
	jwk, err := AppPublicKeyToJWK(appPublicKeyHex)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(keyID, did+"#") {
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
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("unknown purpose %q", p))
		}
	}
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	return doc, nil
}
