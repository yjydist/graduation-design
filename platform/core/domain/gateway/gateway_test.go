package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/core/ledger"
	"grad/protocol"
)

func TestNewServiceValidation(t *testing.T) {
	_, err := NewService(Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db pool")

	_, err = NewService(Config{DeploymentID: "dep", ServiceDID: "did:web:c.local:supplier", Audience: "https://c.local"})
	require.Error(t, err)

	err = EnsureSchema(context.Background(), nil, "dep", "sup")
	require.Error(t, err)

	err = EnsureCatalogPrices(context.Background(), nil, "dep", "sup")
	require.Error(t, err)

	err = SetCatalogPrice(context.Background(), nil, "dep", DefaultProductID, 80000)
	require.Error(t, err)
}

func TestValidateExecuteSchemaCanonicalResourcesAndLegacyRejection(t *testing.T) {
	const (
		depID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		aud   = "https://c.local"
	)
	qID := "urn:grad:quote:test-1"

	basePkg := func(action, resource string, quoteID *string, amount int64) *protocol.AccessEvidencePackage {
		return &protocol.AccessEvidencePackage{
			ChallengeID: "urn:grad:challenge:test-1",
			Request: protocol.AccessRequest{
				SchemaVersion:     protocol.SchemaVersion,
				DeploymentID:      depID,
				Actor:             "did:web:b.local:b1",
				PrincipalDomain:   "A",
				AuthorizationMode: protocol.ModeResourcePreauthorized,
				TaskID:            "task-1",
				Audience:          aud,
				Resource:          resource,
				Action:            action,
				SupplierID:        DefaultSupplierID,
				ProductID:         DefaultProductID,
				Quantity:          1,
				Currency:          DefaultCurrency,
				QuoteID:           quoteID,
				AmountMinor:       amount,
				IdempotencyKey:    "idem-key_1",
			},
			TaskSpec: protocol.TaskSpec{
				SupplierID:  DefaultSupplierID,
				ProductID:   DefaultProductID,
				MaxQuantity: 1,
				Currency:    DefaultCurrency,
				Resources:   []string{protocol.ResourceQuotes, protocol.ResourceOrders},
				Actions:     []string{protocol.ActionQuoteRead, protocol.ActionOrderCreate},
			},
			Grants:           []string{"g0"},
			TrustPaths:       []protocol.TrustPathEntry{{Issuer: "did:web:a.local:ia", DomainCertification: "cert"}},
			LeafPresentation: "sd~kb",
		}
	}

	// Canonical quote.read and order.create pass schema validation.
	require.NoError(t, validateExecuteSchema(basePkg(protocol.ActionQuoteRead, protocol.ResourceQuotes, nil, 0), depID, aud))
	require.NoError(t, validateExecuteSchema(basePkg(protocol.ActionOrderCreate, protocol.ResourceOrders, &qID, 80000), depID, aud))

	// Legacy short aliases and mismatched action/resource pairs MUST fail with INVALID_SCHEMA.
	legacyCases := []struct {
		name     string
		action   string
		resource string
		quoteID  *string
		amount   int64
	}{
		{"short_quotes", protocol.ActionQuoteRead, "quotes", nil, 0},
		{"unqualified_urn_quotes", protocol.ActionQuoteRead, "urn:grad:resource:quotes", nil, 0},
		{"short_orders", protocol.ActionOrderCreate, "orders", &qID, 80000},
		{"unqualified_urn_orders", protocol.ActionOrderCreate, "urn:grad:resource:orders", &qID, 80000},
		{"quote_action_on_orders_resource", protocol.ActionQuoteRead, protocol.ResourceOrders, nil, 0},
		{"order_action_on_quotes_resource", protocol.ActionOrderCreate, protocol.ResourceQuotes, &qID, 80000},
	}
	for _, tc := range legacyCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateExecuteSchema(basePkg(tc.action, tc.resource, tc.quoteID, tc.amount), depID, aud)
			require.Error(t, err)
			assert.Equal(t, protocol.ErrCodeInvalidSchema, protocol.CodeOf(err))
		})
	}

	// Invalid idempotencyKey rejected with INVALID_SCHEMA.
	badKey := basePkg(protocol.ActionQuoteRead, protocol.ResourceQuotes, nil, 0)
	badKey.Request.IdempotencyKey = "bad key with spaces!"
	err := validateExecuteSchema(badKey, depID, aud)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeInvalidSchema, protocol.CodeOf(err))

	// DeploymentID and Audience binding mismatches return BINDING_MISMATCH.
	badDep := basePkg(protocol.ActionQuoteRead, protocol.ResourceQuotes, nil, 0)
	badDep.Request.DeploymentID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	err = validateExecuteSchema(badDep, depID, aud)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeBindingMismatch, protocol.CodeOf(err))

	badAud := basePkg(protocol.ActionQuoteRead, protocol.ResourceQuotes, nil, 0)
	badAud.Request.Audience = "https://other.local"
	err = validateExecuteSchema(badAud, depID, aud)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeBindingMismatch, protocol.CodeOf(err))
}

func TestDecisionRecordMarshalJSONByStateSource(t *testing.T) {
	rev := int64(42)
	checked := int64(999)
	fab := DecisionRecord{
		StateSource: ledger.SourceFabric,
		DecisionID:  "urn:grad:decision:fab-1",
		BlockNumber: 7,
		BlockHash:   "abcd",
		ProbeTxID:   "tx-1",
		ProbeBlock:  7,
	}
	rawFab, err := json.Marshal(fab)
	require.NoError(t, err)
	var fabMap map[string]any
	require.NoError(t, json.Unmarshal(rawFab, &fabMap))
	assert.Equal(t, float64(7), fabMap["blockNumber"])
	assert.Equal(t, "abcd", fabMap["blockHash"])

	cent := DecisionRecord{
		StateSource:        ledger.SourceCentralized,
		Revision:           &rev,
		DecisionID:         "urn:grad:decision:cent-1",
		BlockNumber:        7,
		BlockHash:          "should-be-null",
		ProbeTxID:          "should-be-null",
		ProbeCheckedMonoNs: &checked,
	}
	rawCent, err := json.Marshal(cent)
	require.NoError(t, err)
	var centMap map[string]any
	require.NoError(t, json.Unmarshal(rawCent, &centMap))
	assert.Equal(t, float64(42), centMap["revision"])
	for _, k := range []string{"blockNumber", "blockHash", "revocationEpoch", "probeTxId", "probeBlock", "probeSentAt", "probeDeadline", "probeSentMonoNs", "probeDeadlineMonoNs"} {
		val, exists := centMap[k]
		assert.True(t, exists, "expected key %s in centralized decision JSON", k)
		assert.Nil(t, val, "expected %s to be null for centralized state", k)
	}
}

func TestDecisionErrorUnwrapAndDecisionIDOf(t *testing.T) {
	base := protocol.NewError(protocol.ErrCodePolicyDenied, "blocked by context risk")
	assert.Nil(t, DecisionIDOf(base))

	wrapped := &DecisionError{
		DecisionID: "urn:grad:decision:deny-1",
		Err:        base,
	}
	assert.Equal(t, protocol.ErrCodePolicyDenied, protocol.CodeOf(wrapped))
	assert.True(t, protocol.HasCode(wrapped, protocol.ErrCodePolicyDenied))
	assert.True(t, errors.Is(wrapped, base))
	assert.Contains(t, wrapped.Error(), "blocked by context risk")

	decID := DecisionIDOf(wrapped)
	require.NotNil(t, decID)
	assert.Equal(t, "urn:grad:decision:deny-1", *decID)
}

func TestAuditorAndRecoveryAuthorizationBoundaries(t *testing.T) {
	s := &Service{
		cfg: Config{
			ServiceDID:  "did:web:c.local:supplier",
			AuditorDIDs: []string{"did:web:c.local:auditors:c1"},
			VerifierID:  "c-gw-1",
		},
	}

	// Empty caller identity MUST be rejected.
	_, err := s.authorizeAuditor(CallerIdentity{})
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeAuditForbidden, protocol.CodeOf(err))

	// Wrong domain auditor rejected.
	_, err = s.authorizeAuditor(CallerIdentity{
		Role: "C_AUDITOR",
		DID:  "did:web:b.local:auditors:b1",
	})
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeAuditForbidden, protocol.CodeOf(err))

	// Unlisted C auditor rejected.
	_, err = s.authorizeAuditor(CallerIdentity{
		Role: "C_AUDITOR",
		DID:  "did:web:c.local:auditors:c2",
	})
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeAuditForbidden, protocol.CodeOf(err))

	// Valid C auditor accepted.
	vid, err := s.authorizeAuditor(CallerIdentity{
		Role: "C_AUDITOR",
		DID:  "did:web:c.local:auditors:c1",
	})
	require.NoError(t, err)
	assert.Equal(t, "c-gw-1", vid)

	// Recovery caller: domain must match actor domain.
	err = authorizeRecoveryCaller(CallerIdentity{
		Role: "B_RECOVERY",
		DID:  "did:web:a.local:services:recovery",
	}, "did:web:b.local:b1")
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeAuditForbidden, protocol.CodeOf(err))

	require.NoError(t, authorizeRecoveryCaller(CallerIdentity{
		Role: "B_RECOVERY",
		DID:  "did:web:b.local:services:recovery",
	}, "did:web:b.local:b1"))
}

func TestVerifyReceiptEchoAndHelpers(t *testing.T) {
	assert.Equal(t, "c.local", didWebHost("did:web:c.local:supplier"))
	assert.Equal(t, "c.local", didWebHost("did:web:c.local%3A8443:supplier"))
	assert.Equal(t, "c.local", didWebHost("did:web:c.local%3a8443:supplier"))
	assert.Equal(t, "", didWebHost("did:key:z123"))

	assert.Equal(t, []string{"a", "b", "c"}, normalizeUniqueSortedStrings([]string{" b ", "a", "", "b", "c", "a"}))
	assert.Empty(t, normalizeUniqueSortedStrings(nil))

	ordID := "urn:grad:order:1"
	sent := OrderOutcomeReceipt{
		CaseID:       "urn:grad:case:1",
		CheckNo:      1,
		SendRevision: 2,
		DeploymentID: "dep-1",
		Actor:        "did:web:b.local:b1",
		TaskID:       "task-1",
		RequestHash:  "abcd",
		Outcome:      "CREATED",
		OrderID:      &ordID,
	}
	require.NoError(t, VerifyReceiptEcho(sent, sent))

	tampered := sent
	tampered.Outcome = "NOT_CREATED"
	require.Error(t, VerifyReceiptEcho(sent, tampered))
}
