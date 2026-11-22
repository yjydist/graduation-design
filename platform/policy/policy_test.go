package policy

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"

	"grad/protocol"
	api "grad/protocol/registry"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		Resource:            protocol.ResourceQuotes,
		ProductID:           "urn:grad:product:P1",
		Quantity:            2,
		Action:              protocol.ActionQuoteRead,
		AmountMinor:         0,
		MaxPathAmountMinor:  500000,
		NowUnix:             deadline - 10,
		VerifiedCrypto:      true,
		TaskActive:          true,
		PathActive:          true,
		ContextFresh:        true,
		ContextRiskLevel:    RiskNormal,
		WithinTimeAndBounds: true,
	}
}

func cloneFiles(src map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(src))
	for k, v := range src {
		out[k] = slices.Clone(v)
	}
	return out
}

func resignBundleManifest(t *testing.T, depID, serviceDID string, root api.RootRecord, files map[string][]byte) (map[string][]byte, string) {
	t.Helper()
	cloned := make(map[string][]byte, len(files))
	names := make([]string, 0, len(files))
	for k, v := range files {
		if k == fileManifest {
			continue
		}
		cloned[k] = slices.Clone(v)
		names = append(names, k)
	}
	slices.Sort(names)
	digests := make([]FileDigest, 0, len(names))
	for _, name := range names {
		digests = append(digests, FileDigest{
			Path:   name,
			SHA256: protocol.DigestBytes(cloned[name]),
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
	require.NoError(t, err)
	policyDigest := protocol.DigestBytes(manifestBytes)
	cloned[fileManifest] = append(manifestBytes, '\n')
	return cloned, policyDigest
}

func TestPolicyBundleVerificationAndTamperRejection(t *testing.T) {
	root := testRootRecord()
	depID := "dep-policy-test"
	serviceDID := "did:web:c.example.test"
	deadline := int64(1800000000)

	files, digest, err := BuildDefaultBundle(depID, serviceDID, DefaultPolicyVersion, root, &deadline)
	require.NoError(t, err)
	require.Len(t, digest, 64)

	bundle, err := VerifyAndLoadBundle(files, depID, serviceDID, root, digest)
	require.NoError(t, err)
	assert.Equal(t, digest, bundle.PolicyDigest)
	assert.Equal(t, []string{protocol.ResourceQuotes, protocol.ResourceOrders}, bundle.Resources.AllowedResources)
	assert.Equal(t, []string{protocol.ActionQuoteRead, protocol.ActionOrderCreate}, bundle.Resources.AllowedActions)

	t.Run("tampered procurement.rego fails digest check", func(t *testing.T) {
		tampered := cloneFiles(files)
		tampered[fileRego] = append(tampered[fileRego], []byte("\n# tampered\n")...)
		_, err := VerifyAndLoadBundle(tampered, depID, serviceDID, root, digest)
		require.Error(t, err)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodeBindingMismatch))
	})

	t.Run("tampered resources.json fails digest check", func(t *testing.T) {
		tampered := cloneFiles(files)
		tampered[fileResources] = append(tampered[fileResources], ' ')
		_, err := VerifyAndLoadBundle(tampered, depID, serviceDID, root, digest)
		require.Error(t, err)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodeBindingMismatch))
	})

	t.Run("replaced T trustRoot fails with ErrCodeRootAuthorityInvalid", func(t *testing.T) {
		otherRoot := root
		otherRoot.PublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=="
		replacedFiles, replacedDigest, err := BuildDefaultBundle(depID, serviceDID, DefaultPolicyVersion, otherRoot, &deadline)
		require.NoError(t, err)

		_, err = VerifyAndLoadBundle(replacedFiles, depID, serviceDID, root, replacedDigest)
		require.Error(t, err)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodeRootAuthorityInvalid))
	})

	t.Run("mismatched expectedDigest fails with ErrCodeBindingMismatch", func(t *testing.T) {
		_, err := VerifyAndLoadBundle(files, depID, serviceDID, root, strings.Repeat("0", 64))
		require.Error(t, err)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodeBindingMismatch))
	})

	t.Run("mismatched deploymentId or serviceDid fails", func(t *testing.T) {
		_, err := VerifyAndLoadBundle(files, "other-dep", serviceDID, root, digest)
		require.Error(t, err)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodeBindingMismatch))

		_, err = VerifyAndLoadBundle(files, depID, "did:web:other.example.test", root, digest)
		require.Error(t, err)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodeBindingMismatch))
	})

	t.Run("unsorted manifest.files and unlisted bundle file rejected", func(t *testing.T) {
		var mf Manifest
		require.NoError(t, protocol.DecodeStrictJSON(files[fileManifest], &mf))
		mf.Files[0], mf.Files[1] = mf.Files[1], mf.Files[0]
		rawUnsorted, err := protocol.MarshalJCS(mf)
		require.NoError(t, err)

		unsortedFiles := cloneFiles(files)
		unsortedFiles[fileManifest] = rawUnsorted
		_, err = VerifyAndLoadBundle(unsortedFiles, depID, serviceDID, root, "")
		require.Error(t, err)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))

		extraFiles := maps.Clone(files)
		extraFiles["extra.txt"] = []byte("extra")
		_, err = VerifyAndLoadBundle(extraFiles, depID, serviceDID, root, digest)
		require.Error(t, err)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))
	})

	t.Run("non-canonical resource alias rejected in resources.json", func(t *testing.T) {
		roles := RolesConfig{
			AcceptedAuthorizationModes: []string{api.RP},
			AcceptedAuthorityRoles:     []string{},
			AcceptedBuyerDomains:       []string{"A"},
			AcceptedServiceRoles:       []string{"supplier-service"},
		}
		for _, badResource := range []string{"quotes", "orders", "urn:grad:resource:quotes"} {
			_, _, err := BuildCustomBundle(depID, serviceDID, "1.0.1", root, roles, ResourcesConfig{
				AllowedResources:  []string{badResource},
				AllowedActions:    []string{protocol.ActionQuoteRead},
				AllowedProductIDs: []string{"urn:grad:product:P1"},
				MaxQuantity:       5,
			})
			require.Error(t, err)
			assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))
		}
	})
}

func TestPolicyRejectsForbiddenBuiltinsAndWrongPackage(t *testing.T) {
	root := testRootRecord()
	depID := "dep-policy-ast"
	serviceDID := "did:web:c.example.test"
	baseFiles, _, err := BuildDefaultBundle(depID, serviceDID, DefaultPolicyVersion, root, nil)
	require.NoError(t, err)

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
		{
			name: "opa.runtime",
			rego: "package procurement\nimport rego.v1\ndefault allow := false\nallow if {\n\trt := opa.runtime()\n\trt.env != null\n}\n",
		},
		{
			name: "net.cidr_lookup",
			rego: "package procurement\nimport rego.v1\ndefault allow := false\nallow if {\n\tnet.cidr_lookup(\"10.0.0.1\") != \"\"\n}\n",
		},
		{
			name: "rand.intn",
			rego: "package procurement\nimport rego.v1\ndefault allow := false\nallow if {\n\trand.intn(\"k\", 10) >= 0\n}\n",
		},
		{
			name: "wrong package name",
			rego: "package other\nimport rego.v1\ndefault allow := true\n",
		},
	}

	for _, tc := range forbiddenCases {
		t.Run(tc.name, func(t *testing.T) {
			f := cloneFiles(baseFiles)
			f[fileRego] = []byte(tc.rego)
			resigned, digest := resignBundleManifest(t, depID, serviceDID, root, f)
			_, err := VerifyAndLoadBundle(resigned, depID, serviceDID, root, digest)
			require.Error(t, err)
			assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))
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
	require.NoError(t, err)
	bundle, err := VerifyAndLoadBundle(files, depID, serviceDID, root, digest)
	require.NoError(t, err)

	t.Run("quote.read across NORMAL ELEVATED BLOCKED", func(t *testing.T) {
		facts := testValidFacts(deadline)
		dec, err := bundle.EvaluateFacts(ctx, facts)
		require.NoError(t, err)
		assert.True(t, dec.Allow)
		assert.Equal(t, "OK", dec.Code)
		assert.Equal(t, digest, dec.PolicyDigest)
		assert.Equal(t, protocol.ResourceQuotes, dec.Input.Request.Resource)

		facts.ContextRiskLevel = RiskElevated
		dec, err = bundle.EvaluateFacts(ctx, facts)
		require.NoError(t, err)
		assert.True(t, dec.Allow)
		assert.Equal(t, "OK", dec.Code)

		facts.ContextRiskLevel = RiskBlocked
		dec, err = bundle.EvaluateFacts(ctx, facts)
		require.Error(t, err)
		assert.False(t, dec.Allow)
		assert.Equal(t, protocol.ErrCodePolicyDenied, dec.Code)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodePolicyDenied))
	})

	t.Run("canonical resource validation rejects aliases and action-resource mismatch", func(t *testing.T) {
		for _, badRes := range []string{"quotes", "urn:grad:resource:quotes", protocol.ResourceOrders} {
			facts := testValidFacts(deadline)
			facts.Resource = badRes
			dec, err := bundle.EvaluateFacts(ctx, facts)
			require.Error(t, err)
			assert.False(t, dec.Allow)
			assert.Equal(t, protocol.ErrCodeInvalidSchema, dec.Code)
			assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))
		}

		// Empty resource in SupplierFacts derives the canonical URI for the action.
		facts := testValidFacts(deadline)
		facts.Resource = ""
		dec, err := bundle.EvaluateFacts(ctx, facts)
		require.NoError(t, err)
		assert.True(t, dec.Allow)
		assert.Equal(t, protocol.ResourceQuotes, dec.Input.Request.Resource)

		// Direct OPAInput evaluation still strictly requires explicit canonical resource URI.
		raw := dec.Input
		raw.Request.Resource = ""
		rawDec, err := bundle.EvaluateRawInput(ctx, raw)
		require.Error(t, err)
		assert.False(t, rawDec.Allow)
		assert.Equal(t, protocol.ErrCodeInvalidSchema, rawDec.Code)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))
	})

	t.Run("deadline and amount bounds fail closed", func(t *testing.T) {
		facts := testValidFacts(deadline)
		facts.NowUnix = deadline
		dec, err := bundle.EvaluateFacts(ctx, facts)
		require.Error(t, err)
		assert.False(t, dec.Allow)
		assert.False(t, dec.Input.Constraints.BeforeDeadline)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodePolicyDenied))

		orderFacts := testValidFacts(deadline)
		orderFacts.Action = protocol.ActionOrderCreate
		orderFacts.Resource = protocol.ResourceOrders
		orderFacts.AmountMinor = 120000
		orderFacts.MaxPathAmountMinor = 100000
		dec, err = bundle.EvaluateFacts(ctx, orderFacts)
		require.Error(t, err)
		assert.False(t, dec.Allow)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodePolicyDenied))
	})

	t.Run("undefined Rego result and strict builtin errors fail closed", func(t *testing.T) {
		undefinedFiles := cloneFiles(files)
		undefinedFiles[fileRego] = []byte("package procurement\nimport rego.v1\nallow if {\n\tinput.verified == true\n\tinput.task.active == false\n}\n")
		resignedUndef, digestUndef := resignBundleManifest(t, depID, serviceDID, root, undefinedFiles)
		undefBundle, err := VerifyAndLoadBundle(resignedUndef, depID, serviceDID, root, digestUndef)
		require.NoError(t, err)

		dec, err := undefBundle.EvaluateFacts(ctx, testValidFacts(deadline))
		require.Error(t, err)
		assert.False(t, dec.Allow)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodePolicyDenied))

		builtinErrFiles := cloneFiles(files)
		builtinErrFiles[fileRego] = []byte("package procurement\nimport rego.v1\ndefault allow := false\nallow if {\n\tto_number(\"not-a-number\") == 1\n}\n")
		resignedBuiltin, digestBuiltin := resignBundleManifest(t, depID, serviceDID, root, builtinErrFiles)
		builtinBundle, err := VerifyAndLoadBundle(resignedBuiltin, depID, serviceDID, root, digestBuiltin)
		require.NoError(t, err)

		dec, err = builtinBundle.EvaluateFacts(ctx, testValidFacts(deadline))
		require.Error(t, err)
		assert.False(t, dec.Allow)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodePolicyDenied))
	})
}

func TestPolicyDualModeOrderCreateAndSupplierAcceptance(t *testing.T) {
	ctx := context.Background()
	root := testRootRecord()
	depID := "dep-policy-dual-mode"
	serviceDID := "did:web:c.example.test"
	deadline := int64(1800000000)

	files, digest, err := BuildDefaultBundle(depID, serviceDID, DefaultPolicyVersion, root, &deadline)
	require.NoError(t, err)
	bundle, err := VerifyAndLoadBundle(files, depID, serviceDID, root, digest)
	require.NoError(t, err)

	bmOrder := SupplierFacts{
		AuthorizationMode:   protocol.ModeBuyerMandate,
		BuyerDomain:         "A",
		AuthorityRole:       "procurement-authority",
		ServiceDID:          serviceDID,
		ServiceRole:         "supplier-service",
		Resource:            protocol.ResourceOrders,
		ProductID:           "urn:grad:product:P2",
		Quantity:            1,
		Action:              protocol.ActionOrderCreate,
		AmountMinor:         80000,
		MaxPathAmountMinor:  100000,
		NowUnix:             deadline - 10,
		VerifiedCrypto:      true,
		TaskActive:          true,
		PathActive:          true,
		ContextFresh:        true,
		ContextRiskLevel:    RiskNormal,
		WithinTimeAndBounds: true,
	}
	rpOrder := bmOrder
	rpOrder.AuthorizationMode = protocol.ModeResourcePreauthorized
	rpOrder.AuthorityRole = ""

	t.Run("RP and BM order.create risk level behavior", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			facts SupplierFacts
		}{
			{name: "RP", facts: rpOrder},
			{name: "BM", facts: bmOrder},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dec, err := bundle.EvaluateFacts(ctx, tc.facts)
				require.NoError(t, err)
				assert.True(t, dec.Allow)
				assert.Equal(t, "OK", dec.Code)

				elev := tc.facts
				elev.ContextRiskLevel = RiskElevated
				dec, err = bundle.EvaluateFacts(ctx, elev)
				require.Error(t, err)
				assert.False(t, dec.Allow)
				assert.True(t, protocol.HasCode(err, protocol.ErrCodePolicyDenied))

				blocked := tc.facts
				blocked.ContextRiskLevel = RiskBlocked
				dec, err = bundle.EvaluateFacts(ctx, blocked)
				require.Error(t, err)
				assert.False(t, dec.Allow)
				assert.True(t, protocol.HasCode(err, protocol.ErrCodePolicyDenied))
			})
		}
	})

	t.Run("supplierAcceptance denies unaccepted domain, roles, product, quantity, resource, or mode", func(t *testing.T) {
		denyCases := []struct {
			name   string
			mutate func(*SupplierFacts)
		}{
			{name: "unaccepted buyer domain", mutate: func(f *SupplierFacts) { f.BuyerDomain = "B" }},
			{name: "BM missing authority role", mutate: func(f *SupplierFacts) { f.AuthorityRole = "" }},
			{name: "BM wrong authority role", mutate: func(f *SupplierFacts) { f.AuthorityRole = "broker-agent" }},
			{name: "wrong service DID", mutate: func(f *SupplierFacts) { f.ServiceDID = "did:web:evil.example.test" }},
			{name: "unaccepted service role", mutate: func(f *SupplierFacts) { f.ServiceRole = "procurement-agent" }},
			{name: "unknown product", mutate: func(f *SupplierFacts) { f.ProductID = "urn:grad:product:UNKNOWN" }},
			{name: "quantity exceeds maxQuantity", mutate: func(f *SupplierFacts) { f.Quantity = 11 }},
		}
		for _, tc := range denyCases {
			t.Run(tc.name, func(t *testing.T) {
				f := bmOrder
				tc.mutate(&f)
				dec, err := bundle.EvaluateFacts(ctx, f)
				require.Error(t, err)
				assert.False(t, dec.Allow)
				assert.False(t, dec.Input.SupplierAcceptance)
				assert.Equal(t, protocol.ErrCodeSupplierPolicyDenied, dec.Code)
				assert.True(t, protocol.HasCode(err, protocol.ErrCodeSupplierPolicyDenied))
			})
		}
	})

	t.Run("custom RP-only supplier bundle rejects BM mode", func(t *testing.T) {
		rpOnlyRoles := RolesConfig{
			AcceptedAuthorizationModes: []string{protocol.ModeResourcePreauthorized},
			AcceptedAuthorityRoles:     []string{},
			AcceptedBuyerDomains:       []string{"A"},
			AcceptedServiceRoles:       []string{"supplier-service"},
		}
		rpResources := ResourcesConfig{
			AllowedResources:  []string{protocol.ResourceQuotes, protocol.ResourceOrders},
			AllowedActions:    []string{protocol.ActionQuoteRead, protocol.ActionOrderCreate},
			AllowedProductIDs: []string{"urn:grad:product:P1", "urn:grad:product:P2"},
			MaxQuantity:       10,
			PolicyDeadline:    &deadline,
		}
		rpFiles, rpDig, err := BuildCustomBundle(depID, serviceDID, "1.0.1", root, rpOnlyRoles, rpResources)
		require.NoError(t, err)
		rpBundle, err := VerifyAndLoadBundle(rpFiles, depID, serviceDID, root, rpDig)
		require.NoError(t, err)

		dec, err := rpBundle.EvaluateFacts(ctx, bmOrder)
		require.Error(t, err)
		assert.False(t, dec.Allow)
		assert.False(t, dec.Input.SupplierAcceptance)
		assert.Equal(t, protocol.ErrCodeSupplierPolicyDenied, dec.Code)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodeSupplierPolicyDenied))

		// RP mode still allowed under RP-only bundle.
		dec, err = rpBundle.EvaluateFacts(ctx, rpOrder)
		require.NoError(t, err)
		assert.True(t, dec.Allow)
		assert.True(t, dec.Input.SupplierAcceptance)
	})

	t.Run("custom quotes-only resources bundle rejects orders resource", func(t *testing.T) {
		roles := RolesConfig{
			AcceptedAuthorizationModes: []string{protocol.ModeResourcePreauthorized, protocol.ModeBuyerMandate},
			AcceptedAuthorityRoles:     []string{"procurement-authority"},
			AcceptedBuyerDomains:       []string{"A"},
			AcceptedServiceRoles:       []string{"supplier-service"},
		}
		quotesOnly := ResourcesConfig{
			AllowedResources:  []string{protocol.ResourceQuotes},
			AllowedActions:    []string{protocol.ActionQuoteRead, protocol.ActionOrderCreate},
			AllowedProductIDs: []string{"urn:grad:product:P1", "urn:grad:product:P2"},
			MaxQuantity:       10,
			PolicyDeadline:    &deadline,
		}
		qFiles, qDig, err := BuildCustomBundle(depID, serviceDID, "1.0.2", root, roles, quotesOnly)
		require.NoError(t, err)
		qBundle, err := VerifyAndLoadBundle(qFiles, depID, serviceDID, root, qDig)
		require.NoError(t, err)

		dec, err := qBundle.EvaluateFacts(ctx, rpOrder)
		require.Error(t, err)
		assert.False(t, dec.Allow)
		assert.False(t, dec.Input.SupplierAcceptance)
		assert.Equal(t, protocol.ErrCodeSupplierPolicyDenied, dec.Code)
		assert.True(t, protocol.HasCode(err, protocol.ErrCodeSupplierPolicyDenied))
	})
}
