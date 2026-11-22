package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/internal/mtls"
	"grad/platform/state"
	"grad/protocol"
)

func TestNewServerValidation(t *testing.T) {
	_, err := NewServer(ServerConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db pool")

	_, err = NewServer(ServerConfig{DeploymentID: "dep", ServiceDID: "did:web:c.local:supplier", Audience: "https://c.local"})
	require.Error(t, err)

	err = EnsureSchema(context.Background(), nil, "dep", "sup")
	require.Error(t, err)

	err = EnsureCatalogPrices(context.Background(), nil, "dep", "sup")
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
		StateSource: state.SourceFabric,
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
		StateSource:        state.SourceCentralized,
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

func TestErrorBodyAlwaysEmitsDecisionIDKey(t *testing.T) {
	eb := ErrorBody{
		RequestID:  "urn:grad:req:test-1",
		Code:       protocol.ErrCodeInvalidSchema,
		DecisionID: nil,
		Message:    "bad request",
	}
	raw, err := json.Marshal(eb)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	v, ok := m["decisionId"]
	require.True(t, ok, "decisionId key must be present")
	assert.Nil(t, v)
	assert.Equal(t, "urn:grad:req:test-1", m["requestId"])
	assert.Equal(t, protocol.ErrCodeInvalidSchema, m["code"])
	assert.Equal(t, "bad request", m["message"])
}

func TestAuditorAndRecoveryAuthorizationBoundaries(t *testing.T) {
	s := &Server{
		cfg: ServerConfig{
			ServiceDID:  "did:web:c.local:supplier",
			AuditorDIDs: []string{"did:web:c.local:auditors:c1"},
			VerifierID:  "c-gw-1",
		},
	}

	// Self-asserted X-Caller-* headers without mTLS identity MUST be rejected.
	rHeaderOnly := httptest.NewRequest(http.MethodPost, "/v1/audit/order-outcomes", nil)
	rHeaderOnly.Header.Set("X-Caller-Role", "C_AUDITOR")
	rHeaderOnly.Header.Set("X-Caller-DID", "did:web:c.local:auditors:c1")
	_, err := s.authorizeAuditor(rHeaderOnly)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeAuditForbidden, protocol.CodeOf(err))

	// Wrong domain auditor rejected.
	rWrongDom := httptest.NewRequest(http.MethodPost, "/v1/audit/order-outcomes", nil)
	rWrongDom = rWrongDom.WithContext(mtls.WithIdentity(rWrongDom.Context(), mtls.Identity{
		Role: "C_AUDITOR",
		DID:  "did:web:b.local:auditors:b1",
	}))
	_, err = s.authorizeAuditor(rWrongDom)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeAuditForbidden, protocol.CodeOf(err))

	// Unlisted C auditor rejected.
	rUnlisted := httptest.NewRequest(http.MethodPost, "/v1/audit/order-outcomes", nil)
	rUnlisted = rUnlisted.WithContext(mtls.WithIdentity(rUnlisted.Context(), mtls.Identity{
		Role: "C_AUDITOR",
		DID:  "did:web:c.local:auditors:c2",
	}))
	_, err = s.authorizeAuditor(rUnlisted)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeAuditForbidden, protocol.CodeOf(err))

	// Valid C auditor accepted.
	rValid := httptest.NewRequest(http.MethodPost, "/v1/audit/order-outcomes", nil)
	rValid = rValid.WithContext(mtls.WithIdentity(rValid.Context(), mtls.Identity{
		Role: "C_AUDITOR",
		DID:  "did:web:c.local:auditors:c1",
	}))
	vid, err := s.authorizeAuditor(rValid)
	require.NoError(t, err)
	assert.Equal(t, "c-gw-1", vid)

	// Recovery caller: domain must match actor domain.
	rRecBad := httptest.NewRequest(http.MethodPost, "/v1/internal/order-outcome-cases", nil)
	rRecBad = rRecBad.WithContext(mtls.WithIdentity(rRecBad.Context(), mtls.Identity{
		Role: "B_RECOVERY",
		DID:  "did:web:a.local:services:recovery",
	}))
	err = authorizeRecoveryCaller(rRecBad, "did:web:b.local:b1")
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeAuditForbidden, protocol.CodeOf(err))

	rRecOK := httptest.NewRequest(http.MethodPost, "/v1/internal/order-outcome-cases", nil)
	rRecOK = rRecOK.WithContext(mtls.WithIdentity(rRecOK.Context(), mtls.Identity{
		Role: "B_RECOVERY",
		DID:  "did:web:b.local:services:recovery",
	}))
	require.NoError(t, authorizeRecoveryCaller(rRecOK, "did:web:b.local:b1"))
}

func TestHelpers(t *testing.T) {
	assert.Equal(t, "c.local", didWebHost("did:web:c.local:supplier"))
	assert.Equal(t, "c.local", didWebHost("did:web:c.local%3A8443:supplier"))
	assert.Equal(t, "c.local", didWebHost("did:web:c.local%3a8443:supplier"))
	assert.Equal(t, "", didWebHost("did:key:z123"))

	assert.Equal(t, []string{"a", "b", "c"}, normalizeUniqueSortedStrings([]string{" b ", "a", "", "b", "c", "a"}))
	assert.Empty(t, normalizeUniqueSortedStrings(nil))

	assert.Equal(t, http.StatusRequestEntityTooLarge, httpStatusForCode(protocol.ErrCodePayloadTooLarge))
	assert.Equal(t, http.StatusUnsupportedMediaType, httpStatusForCode(protocol.ErrCodeUnsupportedMediaType))
	assert.Equal(t, http.StatusBadRequest, httpStatusForCode(protocol.ErrCodeInvalidSchema))
	assert.Equal(t, http.StatusUnauthorized, httpStatusForCode(protocol.ErrCodeSignatureInvalid))
	assert.Equal(t, http.StatusConflict, httpStatusForCode(protocol.ErrCodeIdempotencyConflict))
	assert.Equal(t, http.StatusForbidden, httpStatusForCode(protocol.ErrCodeAuditForbidden))
	assert.Equal(t, http.StatusServiceUnavailable, httpStatusForCode(protocol.ErrCodeStateStale))
}
