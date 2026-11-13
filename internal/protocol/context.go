package protocol

import (
	_ "embed"
	"fmt"
)

const (
	// VCv2ContextURL is the normative W3C VC v2 base context URI.
	VCv2ContextURL = "https://www.w3.org/ns/credentials/v2"
	// GradAuthVocabURI is the inline extension vocabulary namespace for grad-auth-v1 credentials.
	GradAuthVocabURI = "https://grad-auth.example.test/vocab#"
	// PinnedVCv2ContextSHA256 pins the exact SHA-256 hex digest of the bundled local vc-v2.json copy.
	PinnedVCv2ContextSHA256 = "59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734"
)

//go:embed contexts/vc-v2.json
var bundledVCv2ContextRaw []byte

// ContextManifestEntry records a pinned offline context artifact for deployment manifests.
type ContextManifestEntry struct {
	URI        string `json:"uri"`
	VocabURI   string `json:"vocabUri"`
	SHA256     string `json:"sha256"`
	JCSSHA256  string `json:"jcsSha256"`
	ByteLength int    `json:"byteLength"`
}

// LocalVCv2Context returns the bundled W3C VC v2 base context bytes after verifying its pinned SHA-256 digest
// and strict I-JSON validity completely offline.
func LocalVCv2Context() ([]byte, *JSONValue, ContextManifestEntry, error) {
	return verifyBundledContext(bundledVCv2ContextRaw, PinnedVCv2ContextSHA256)
}

func verifyBundledContext(raw []byte, expectedSHA string) ([]byte, *JSONValue, ContextManifestEntry, error) {
	rawDigest := DigestBytes(raw)
	if rawDigest != expectedSHA {
		return nil, nil, ContextManifestEntry{}, NewError(ErrCodeInvalidSchema, fmt.Sprintf("bundled VC v2 context SHA-256 mismatch: got %s, want %s", rawDigest, expectedSHA))
	}
	ast, err := ParseStrictJSON(raw)
	if err != nil {
		return nil, nil, ContextManifestEntry{}, WrapError(ErrCodeInvalidSchema, "bundled VC v2 context failed strict JSON parse", err)
	}
	ctxObj, ok := ast.Get("@context")
	if !ok || ctxObj.Kind != KindObject {
		return nil, nil, ContextManifestEntry{}, NewError(ErrCodeInvalidSchema, "bundled VC v2 context missing @context object")
	}
	if _, ok := ctxObj.Get("VerifiableCredential"); !ok {
		return nil, nil, ContextManifestEntry{}, NewError(ErrCodeInvalidSchema, "bundled VC v2 context missing VerifiableCredential term")
	}
	jcsDigest, _, err := DigestJCS(raw)
	if err != nil {
		return nil, nil, ContextManifestEntry{}, err
	}
	out := append([]byte(nil), raw...)
	entry := ContextManifestEntry{
		URI:        VCv2ContextURL,
		VocabURI:   GradAuthVocabURI,
		SHA256:     rawDigest,
		JCSSHA256:  jcsDigest,
		ByteLength: len(raw),
	}
	return out, ast, entry, nil
}

// DefaultCredentialContext returns a fresh copy of the canonical grad-auth-v1 @context array:
// ["https://www.w3.org/ns/credentials/v2", {"@vocab": "https://grad-auth.example.test/vocab#"}].
func DefaultCredentialContext() []any {
	return []any{
		VCv2ContextURL,
		map[string]string{"@vocab": GradAuthVocabURI},
	}
}

// ValidateCredentialContextValue enforces that @context is strictly:
// ["https://www.w3.org/ns/credentials/v2", {"@vocab": "https://grad-auth.example.test/vocab#"}]
// and verifies the local pinned VC v2 base context without any network IO.
func ValidateCredentialContextValue(val *JSONValue) error {
	if _, _, _, err := LocalVCv2Context(); err != nil {
		return err
	}
	if val == nil || val.Kind != KindArray || len(val.ArrayVal) != 2 {
		return NewError(ErrCodeInvalidSchema, "credential @context must be a 2-element array")
	}
	first := val.ArrayVal[0]
	if first.Kind != KindString || first.StrVal != VCv2ContextURL {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("credential @context[0] must equal %q", VCv2ContextURL))
	}
	second := val.ArrayVal[1]
	if second.Kind != KindObject || len(second.ObjectVal) != 1 {
		return NewError(ErrCodeInvalidSchema, "credential @context[1] must be a single-key object containing only @vocab")
	}
	vocab, ok := second.Get("@vocab")
	if !ok || vocab.Kind != KindString || vocab.StrVal != GradAuthVocabURI {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("credential @context[1].@vocab must equal %q", GradAuthVocabURI))
	}
	return nil
}

// ValidateCredentialContext validates an arbitrary Go-typed @context slice/value via JCS round-trip.
func ValidateCredentialContext(ctx any) error {
	canon, err := MarshalJCS(ctx)
	if err != nil {
		return err
	}
	val, err := ParseStrictJSON(canon)
	if err != nil {
		return err
	}
	return ValidateCredentialContextValue(val)
}
