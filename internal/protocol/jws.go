package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

// Standard grad-auth-v1 JOSE typ header values.
const (
	TypDomainAuthorityCredential    = "vc+jwt"
	TypEnterpriseIdentityCredential = "vc+sd-jwt"
	TypGrantDelegation              = "grad-delegation+jwt"
	TypKeyBindingJWT                = "kb+jwt"
)

// ParsedJWS represents a parsed compact JWS before or after signature verification.
type ParsedJWS struct {
	Raw          string
	Digest       string
	Header       jwsProtectedHeader
	PayloadBytes []byte
	SigningInput string
	Signature    []byte
}

// SignCompactJWS signs payload with ES256 (P-256 + SHA-256 + raw 64-byte r||s signature)
// and returns the compact JWS ASCII string alongside its SHA-256 lowercase hex digest.
func SignCompactJWS(priv *ecdsa.PrivateKey, typ, kid string, payload []byte) (string, string, error) {
	if priv == nil || priv.Curve != elliptic.P256() {
		return "", "", NewError(ErrCodeInvalidSchema, "ES256 signer requires P-256 private key")
	}
	if typ == "" || kid == "" {
		return "", "", NewError(ErrCodeInvalidSchema, "JWS typ and kid must be non-empty")
	}
	hdrBytes, err := MarshalJCS(jwsProtectedHeader{
		Alg: "ES256",
		Kid: kid,
		Typ: typ,
	})
	if err != nil {
		return "", "", err
	}
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrBytes)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := hdrB64 + "." + payloadB64
	sum := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		return "", "", err
	}
	sigRaw := make([]byte, 64)
	r.FillBytes(sigRaw[:32])
	s.FillBytes(sigRaw[32:])
	compact := signingInput + "." + base64.RawURLEncoding.EncodeToString(sigRaw)
	return compact, DigestBytes([]byte(compact)), nil
}

// ParseCompactJWS strictly parses an ASCII compact JWS without verifying the signature.
func ParseCompactJWS(compact, wantTyp string) (*ParsedJWS, error) {
	if compact == "" || len(compact) > MaxJSONBytes {
		return nil, NewError(ErrCodeInvalidSchema, "compact JWS empty or exceeds size limit")
	}
	for i := 0; i < len(compact); i++ {
		if compact[i] > 0x7F {
			return nil, NewError(ErrCodeInvalidSchema, "compact JWS contains non-ASCII bytes")
		}
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, NewError(ErrCodeInvalidSchema, "compact JWS must have exactly 3 segments")
	}
	hdrBytes, err := decodeStrictBase64URLAny(parts[0])
	if err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "decode compact JWS header", err)
	}
	var hdr jwsProtectedHeader
	if err := DecodeStrictJSON(hdrBytes, &hdr); err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "parse compact JWS header", err)
	}
	if hdr.Alg != "ES256" {
		return nil, NewError(ErrCodeSignatureInvalid, fmt.Sprintf("unsupported JWS alg %q", hdr.Alg))
	}
	if hdr.Kid == "" {
		return nil, NewError(ErrCodeInvalidSchema, "JWS protected header kid must not be empty")
	}
	if wantTyp != "" && hdr.Typ != wantTyp {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("unexpected JWS typ %q, want %q", hdr.Typ, wantTyp))
	}
	payloadBytes, err := decodeStrictBase64URLAny(parts[1])
	if err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "decode compact JWS payload", err)
	}
	sigRaw, err := DecodeStrictBase64URLFixed(parts[2], 64)
	if err != nil {
		return nil, WrapError(ErrCodeSignatureInvalid, "decode ES256 compact signature", err)
	}
	return &ParsedJWS{
		Raw:          compact,
		Digest:       DigestBytes([]byte(compact)),
		Header:       hdr,
		PayloadBytes: payloadBytes,
		SigningInput: parts[0] + "." + parts[1],
		Signature:    sigRaw,
	}, nil
}

// Verify checks the ES256 signature on ParsedJWS against pub and optional expected kid.
func (p *ParsedJWS) Verify(pub *ecdsa.PublicKey, wantKid string) error {
	if p == nil {
		return NewError(ErrCodeInvalidSchema, "nil ParsedJWS")
	}
	if pub == nil || pub.Curve != elliptic.P256() {
		return NewError(ErrCodeSignatureInvalid, "verifier requires P-256 public key")
	}
	if wantKid != "" && p.Header.Kid != wantKid {
		return NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("JWS kid %q mismatches expected %q", p.Header.Kid, wantKid))
	}
	sum := sha256.Sum256([]byte(p.SigningInput))
	r := new(big.Int).SetBytes(p.Signature[:32])
	s := new(big.Int).SetBytes(p.Signature[32:64])
	if !ecdsa.Verify(pub, sum[:], r, s) {
		return NewError(ErrCodeSignatureInvalid, "compact JWS ES256 signature verification failed")
	}
	return nil
}
