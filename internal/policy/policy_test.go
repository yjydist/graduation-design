package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
)

func testRootRecord() api.RootRecord {
	return api.RootRecord{
		DID:            "did:web:t.example.test",
		KeyID:          "did:web:t.example.test#t-app-v1",
		KeyVersion:     1,
		PublicKey:      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
		DocumentDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}

func testValidFacts(deadline int64) SupplierFacts {
	return SupplierFacts{
		AuthorizationMode:   api.RP,
		BuyerDomain:         "A",
		AuthorityRole:       "",
		ServiceDID:          "did:web:c.example.test",
		ServiceRole:         "supplier-service",
		ProductID:           "urn:grad:product:P1",
		Quantity:            2,
		Action:              "quote.read",
		AmountMinor:         0,
		MaxPathAmountMinor:  500000,
		NowUnix:             deadline - 10,
		VerifiedCrypto:      true,
		TaskActive:          true,
		PathActive:          true,
		ContextFresh:        true,
		ContextRiskLevel:    "NORMAL",
		WithinTimeAndBounds: true,
	}
}

func resignBundleManifest(t *testing.T, depID, serviceDID string, root api.RootRecord, files map[string][]byte) (map[string][]byte, string) {
	t.Helper()
	cloned := make(map[string][]byte, len(files))
	var names []string
	for k, v := range files {
		if k == fileManifest {
			continue
		}
		cp := make([]byte, len(v))
		copy(cp, v)
		cloned[k] = cp
		names = append(names, k)
	}
	sort.Strings(names)
	var digests []FileDigest
	for _, name := range names {
		sum := sha256.Sum256(cloned[name])
		digests = append(digests, FileDigest{
			Path:   name,
			SHA256: hex.EncodeToString(sum[:]),
		})
	}
	manifest := Manifest{
		DeploymentID:  depID,
		Files:         digests,
		PolicyID:      DefaultPolicyID,
		PolicyVersion: DefaultPolicyVersion,
		ServiceDID:    serviceDID,
		TrustRoots: []TrustRoot{{
			DeploymentID:   depID,
			RootDID:        root.DID,
			KeyID:          root.KeyID,
			KeyVersion:     root.KeyVersion,
			PublicKey:      root.PublicKey,
			DocumentDigest: root.DocumentDigest,
		}},
	}
	manifestBytes, err := protocol.MarshalJCS(manifest)
	if err != nil {
		t.Fatalf("MarshalJCS manifest: %v", err)
	}
	sum := sha256.Sum256(manifestBytes)
	policyDigest := hex.EncodeToString(sum[:])
	cloned[fileManifest] = append(manifestBytes, '\n')
	return cloned, policyDigest
}

func TestPolicyBundleVerificationAndTamperRejection(t *testing.T) {
	root := testRootRecord()
	depID := "dep-policy-test"
	serviceDID := "did:web:c.example.test"
	deadline := int64(1800000000)

	files, digest, err := BuildDefaultBundle(depID, serviceDID, DefaultPolicyVersion, root, &deadline)
	if err != nil {
		t.Fatalf("BuildDefaultBundle failed: %v", err)
	}
	if len(digest) != 64 {
		t.Fatalf("unexpected digest length: %q", digest)
	}

	bundle, err := VerifyAndLoadBundle(files, depID, serviceDID, root, digest)
	if err != nil {
		t.Fatalf("VerifyAndLoadBundle failed: %v", err)
	}
	if bundle.PolicyDigest != digest {
		t.Fatalf("PolicyDigest mismatch: got %s want %s", bundle.PolicyDigest, digest)
	}

	// 1. Tamper procurement.rego without updating manifest -> rejected.
	tamperedRego := make(map[string][]byte, len(files))
	for k, v := range files {
		tamperedRego[k] = append([]byte(nil), v...)
	}
	tamperedRego[fileRego] = append(tamperedRego[fileRego], []byte("\n# tampered\n")...)
	if _, err := VerifyAndLoadBundle(tamperedRego, depID, serviceDID, root, digest); err == nil {
		t.Fatal("expected tampered procurement.rego to fail verification")
	}

	// 2. Tamper T trustRoots on bundle verification -> rejected with ErrCodeRootAuthorityInvalid.
	otherRoot := root
	otherRoot.PublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=="
	replacedFiles, replacedDigest, err := BuildDefaultBundle(depID, serviceDID, DefaultPolicyVersion, otherRoot, &deadline)
	if err != nil {
		t.Fatalf("BuildDefaultBundle otherRoot: %v", err)
	}
	if _, err := VerifyAndLoadBundle(replacedFiles, depID, serviceDID, root, replacedDigest); !protocol.HasCode(err, protocol.ErrCodeRootAuthorityInvalid) {
		t.Fatalf("expected ErrCodeRootAuthorityInvalid when T trustRoot replaced, got %v", err)
	}

	// 3. Reject wrong expectedDigest when manifest changes.
	if _, err := VerifyAndLoadBundle(files, depID, serviceDID, root, strings.Repeat("0", 64)); err == nil {
		t.Fatal("expected mismatched expectedDigest to fail verification")
	}
}

func TestPolicyRejectsForbiddenBuiltins(t *testing.T) {
	root := testRootRecord()
	depID := "dep-policy-ast"
	serviceDID := "did:web:c.example.test"
	baseFiles, _, err := BuildDefaultBundle(depID, serviceDID, DefaultPolicyVersion, root, nil)
	if err != nil {
		t.Fatalf("BuildDefaultBundle failed: %v", err)
	}

	forbiddenCases := []struct {
		name string
		rego string
	}{
		{
			name: "time.now_ns",
			rego: "package procurement\nimport rego.v1\ndefault allow := false\nallow if {\n\ttime.now_ns() > 0\n\tinput.verified == true\n}\n",
		},
		{
			name: "http.send",
			rego: "package procurement\nimport rego.v1\ndefault allow := false\nallow if {\n\tresp := http.send({\"method\": \"GET\", \"url\": \"https://evil.invalid\"})\n\tresp.status_code == 200\n}\n",
		},
	}

	for _, tc := range forbiddenCases {
		t.Run(tc.name, func(t *testing.T) {
			f := make(map[string][]byte, len(baseFiles))
			for k, v := range baseFiles {
				f[k] = append([]byte(nil), v...)
			}
			f[fileRego] = []byte(tc.rego)
			resigned, digest := resignBundleManifest(t, depID, serviceDID, root, f)
			if _, err := VerifyAndLoadBundle(resigned, depID, serviceDID, root, digest); err == nil {
				t.Fatalf("expected %s to be rejected by AST check", tc.name)
			}
		})
	}
}

func TestPolicyDeterministicEvalAndFailClosed(t *testing.T) {
	ctx := context.Background()
	root := testRootRecord()
	depID := "dep-policy-eval"
	serviceDID := "did:web:c.example.test"
	deadline := int64(1800000000)

	files, digest, err := BuildDefaultBundle(depID, serviceDID, DefaultPolicyVersion, root, &deadline)
	if err != nil {
		t.Fatalf("BuildDefaultBundle failed: %v", err)
	}
	bundle, err := VerifyAndLoadBundle(files, depID, serviceDID, root, digest)
	if err != nil {
		t.Fatalf("VerifyAndLoadBundle failed: %v", err)
	}

	// NORMAL -> allow.
	facts := testValidFacts(deadline)
	dec, err := bundle.EvaluateFacts(ctx, facts)
	if err != nil || !dec.Allow || dec.Code != "OK" {
		t.Fatalf("expected quote.read under NORMAL to allow, got dec=%+v err=%v", dec, err)
	}

	// ELEVATED -> quote.read still allowed (order.create would deny).
	facts.ContextRiskLevel = "ELEVATED"
	dec, err = bundle.EvaluateFacts(ctx, facts)
	if err != nil || !dec.Allow || dec.Code != "OK" {
		t.Fatalf("expected quote.read under ELEVATED to allow, got dec=%+v err=%v", dec, err)
	}

	// BLOCKED -> fail-closed POLICY_DENIED.
	facts.ContextRiskLevel = "BLOCKED"
	dec, err = bundle.EvaluateFacts(ctx, facts)
	if dec.Allow || !protocol.HasCode(err, protocol.ErrCodePolicyDenied) {
		t.Fatalf("expected quote.read under BLOCKED to deny with ErrCodePolicyDenied, got dec=%+v err=%v", dec, err)
	}

	// Unsupported product -> server computes supplierAcceptance=false -> ErrCodeSupplierPolicyDenied.
	facts = testValidFacts(deadline)
	facts.ProductID = "urn:grad:product:UNKNOWN"
	dec, err = bundle.EvaluateFacts(ctx, facts)
	if dec.Allow || dec.Input.SupplierAcceptance || !protocol.HasCode(err, protocol.ErrCodeSupplierPolicyDenied) {
		t.Fatalf("expected unknown product to fail supplierAcceptance with ErrCodeSupplierPolicyDenied, got dec=%+v err=%v", dec, err)
	}

	// Exact-second policyDeadline (NowUnix == deadline) -> rejected.
	facts = testValidFacts(deadline)
	facts.NowUnix = deadline
	dec, err = bundle.EvaluateFacts(ctx, facts)
	if dec.Allow || dec.Input.Constraints.BeforeDeadline || !protocol.HasCode(err, protocol.ErrCodePolicyDenied) {
		t.Fatalf("expected exact-second policyDeadline rejection, got dec=%+v err=%v", dec, err)
	}

	// Undefined Rego result fails closed.
	undefinedFiles := make(map[string][]byte, len(files))
	for k, v := range files {
		undefinedFiles[k] = append([]byte(nil), v...)
	}
	undefinedFiles[fileRego] = []byte("package procurement\nimport rego.v1\nallow if {\n\tinput.verified == true\n\tinput.task.active == false\n}\n")
	resignedUndef, digestUndef := resignBundleManifest(t, depID, serviceDID, root, undefinedFiles)
	undefBundle, err := VerifyAndLoadBundle(resignedUndef, depID, serviceDID, root, digestUndef)
	if err != nil {
		t.Fatalf("VerifyAndLoadBundle undefined rego: %v", err)
	}
	dec, err = undefBundle.EvaluateFacts(ctx, testValidFacts(deadline))
	if dec.Allow || !protocol.HasCode(err, protocol.ErrCodePolicyDenied) {
		t.Fatalf("expected undefined Rego output to fail closed, got dec=%+v err=%v", dec, err)
	}

	// StrictBuiltinErrors triggers evaluation error -> fails closed.
	builtinErrFiles := make(map[string][]byte, len(files))
	for k, v := range files {
		builtinErrFiles[k] = append([]byte(nil), v...)
	}
	builtinErrFiles[fileRego] = []byte("package procurement\nimport rego.v1\ndefault allow := false\nallow if {\n\tto_number(\"not-a-number\") == 1\n}\n")
	resignedBuiltin, digestBuiltin := resignBundleManifest(t, depID, serviceDID, root, builtinErrFiles)
	builtinBundle, err := VerifyAndLoadBundle(resignedBuiltin, depID, serviceDID, root, digestBuiltin)
	if err != nil {
		t.Fatalf("VerifyAndLoadBundle builtin error rego: %v", err)
	}
	dec, err = builtinBundle.EvaluateFacts(ctx, testValidFacts(deadline))
	if dec.Allow || !protocol.HasCode(err, protocol.ErrCodePolicyDenied) {
		t.Fatalf("expected strict builtin error to fail closed with ErrCodePolicyDenied, got dec=%+v err=%v", dec, err)
	}
}
