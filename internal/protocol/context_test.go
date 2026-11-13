package protocol

import (
	"testing"
)

func TestLocalVCv2ContextAndValidation(t *testing.T) {
	raw, _, manifest, err := LocalVCv2Context()
	if err != nil {
		t.Fatalf("LocalVCv2Context failed: %v", err)
	}
	if manifest.SHA256 != PinnedVCv2ContextSHA256 || manifest.ByteLength != len(raw) {
		t.Fatalf("unexpected context manifest: %+v", manifest)
	}

	// Ensure digest tamper on bundled context fails offline check.
	tampered := append([]byte(nil), raw...)
	tampered[0] = ' '
	if _, _, _, err := verifyBundledContext(tampered, PinnedVCv2ContextSHA256); !HasCode(err, ErrCodeInvalidSchema) {
		t.Fatalf("expected INVALID_SCHEMA on context digest tamper, got %v", err)
	}

	// Default context validates cleanly.
	if err := ValidateCredentialContext(DefaultCredentialContext()); err != nil {
		t.Fatalf("DefaultCredentialContext failed validation: %v", err)
	}

	badContexts := []struct {
		name string
		ctx  any
	}{
		{"wrong order", []any{map[string]string{"@vocab": GradAuthVocabURI}, VCv2ContextURL}},
		{"string only", VCv2ContextURL},
		{"v1 url", []any{"https://www.w3.org/2018/credentials/v1", map[string]string{"@vocab": GradAuthVocabURI}}},
		{"extra array element", []any{VCv2ContextURL, map[string]string{"@vocab": GradAuthVocabURI}, "https://other.example/ctx"}},
		{"extra key in vocab object", []any{VCv2ContextURL, map[string]string{"@vocab": GradAuthVocabURI, "foo": "bar"}}},
		{"tampered vocab URI", []any{VCv2ContextURL, map[string]string{"@vocab": "https://evil.example.test/vocab#"}}},
		{"missing vocab", []any{VCv2ContextURL}},
	}
	for _, tc := range badContexts {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCredentialContext(tc.ctx)
			if !HasCode(err, ErrCodeInvalidSchema) {
				t.Fatalf("expected INVALID_SCHEMA for %s, got %v", tc.name, err)
			}
		})
	}
}
