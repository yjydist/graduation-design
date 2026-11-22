package main

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/agent"
	"grad/platform/gateway"
	platformrt "grad/platform/runtime"
	"grad/protocol"
	"grad/protocol/registry"
)

func TestValidateFlags(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		trial   e1Trial
		wantErr bool
	}{
		{
			name:    "empty flags rejected",
			trial:   e1Trial{},
			wantErr: true,
		},
		{
			name:    "missing ledgerctl rejected",
			trial:   e1Trial{revision: "abc123", dir: "/tmp/out", instanceDir: "/tmp/inst"},
			wantErr: true,
		},
		{
			name:    "missing dir rejected",
			trial:   e1Trial{revision: "abc123", dir: "/tmp/out", ledgerctl: "/tmp/ledgerctl"},
			wantErr: true,
		},
		{
			name:    "all required flags accepted",
			trial:   e1Trial{revision: "abc123", dir: "/tmp/out", ledgerctl: "/tmp/ledgerctl", instanceDir: "/tmp/inst"},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.trial.validateFlags()
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFixturesSchemaProcurementTaskSpec(t *testing.T) {
	t.Parallel()

	spec := protocol.TaskSpec{
		SupplierID:  gateway.DefaultSupplierID,
		ProductID:   gateway.DefaultProductID,
		MaxQuantity: 1,
		Currency:    gateway.DefaultCurrency,
		Resources:   []string{registry.ResourceOrders, registry.ResourceQuotes},
		Actions:     []string{registry.ActionOrderCreate, registry.ActionQuoteRead},
		Description: "E1 procurement task",
	}
	require.NoError(t, spec.Validate())

	fx := platformrt.Fixtures{
		SchemaVersion:       protocol.SchemaVersion,
		Bound:               registry.Bound{DeploymentID: strings.Repeat("a", 64)},
		Domains:             map[string]registry.DomainBootstrap{},
		Certifications:      map[string]registry.Certify{},
		Identities:          map[string]registry.Identity{},
		Credentials:         map[string]registry.Credential{},
		DIDDocuments:        map[string]string{},
		TaskSpec:            spec,
		ProcurementTaskSpec: spec,
	}
	raw, err := json.Marshal(fx)
	require.NoError(t, err)
	var rawObj map[string]any
	require.NoError(t, json.Unmarshal(raw, &rawObj))
	assert.Contains(t, rawObj, "procurementTaskSpec")

	var decoded platformrt.Fixtures
	require.NoError(t, protocol.DecodeStrictJSON(raw, &decoded))
	assert.Equal(t, spec, decoded.ProcurementTaskSpec)
	assert.True(t, slices.Contains(decoded.ProcurementTaskSpec.Resources, registry.ResourceQuotes))
	assert.True(t, slices.Contains(decoded.ProcurementTaskSpec.Resources, registry.ResourceOrders))
}

func TestManifestInputFilesNoLegacyRootGoMod(t *testing.T) {
	t.Parallel()

	assert.Contains(t, e1ManifestInputFiles, "go.work")
	assert.Contains(t, e1ManifestInputFiles, "platform/go.mod")
	assert.Contains(t, e1ManifestInputFiles, "experiments/go.mod")
	assert.Contains(t, e1ManifestInputFiles, "infra/fabric/compose.yaml")
	assert.NotContains(t, e1ManifestInputFiles, "go.mod")
	assert.NotContains(t, e1ManifestInputFiles, "go.sum")
}

func TestWriteHTTPCSVSchema(t *testing.T) {
	t.Parallel()

	outDir := t.TempDir()
	start := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	finish := start.Add(25 * time.Millisecond)

	trial := &e1Trial{
		dir: outDir,
		requests: []e1HTTPRecord{
			{
				Case:        "F06",
				Mode:        registry.RP,
				Method:      "POST",
				Path:        "/v1/access/execute",
				TaskID:      strings.Repeat("1", 64),
				Action:      registry.ActionOrderCreate,
				Key:         "e1-rp-q800",
				Started:     start,
				Finished:    finish,
				Status:      200,
				RequestID:   "req-1",
				ChallengeID: "chal-1",
				DecisionID:  "dec-1",
				RequestHash: strings.Repeat("2", 64),
				QuoteID:     "quote-1",
				OrderID:     "order-1",
				Code:        "OK",
				AmountMinor: 80000,
			},
		},
	}
	require.NoError(t, trial.writeHTTP())

	raw, err := os.ReadFile(filepath.Join(outDir, "requests.csv"))
	require.NoError(t, err)
	records, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 2)

	wantHeader := []string{
		"case", "authorization_mode", "method", "path", "task_id", "action", "idempotency_key",
		"started_at", "finished_at", "duration_ns", "http_status", "request_id", "challenge_id",
		"decision_id", "request_hash", "quote_id", "order_id", "code", "amount_minor",
	}
	assert.Equal(t, wantHeader, records[0])
	assert.Equal(t, "F06", records[1][0])
	assert.Equal(t, registry.RP, records[1][1])
	assert.Equal(t, "25000000", records[1][9])
	assert.Equal(t, "200", records[1][10])
	assert.Equal(t, "80000", records[1][18])
}

func TestWritePublicJSONRejectsPrivateKeyAndRedacts(t *testing.T) {
	t.Parallel()

	outDir := t.TempDir()
	err := writePublicJSON(filepath.Join(outDir, "bad.json"), map[string]string{
		"leak": "-----BEGIN EC PRIVATE KEY-----\nSECRET\n-----END EC PRIVATE KEY-----",
	})
	require.Error(t, err)

	goodPath := filepath.Join(outDir, "good.json")
	require.NoError(t, writePublicJSON(goodPath, map[string]string{"status": "ok"}))
	raw, err := os.ReadFile(goodPath)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"status": "ok"`)

	trial := &e1Trial{cfg: agent.RunnerConfig{APIKey: "sk-supersecretkey123456"}}
	assert.Equal(t, "auth failed: [REDACTED]", trial.redact("auth failed: sk-supersecretkey123456"))
}

func TestFreshRequestAndDecodeGrantPayload(t *testing.T) {
	t.Parallel()

	quoteID := "quote-1"
	mode := &e1Mode{
		tag: "rp",
		pkg: &protocol.AccessEvidencePackage{
			Request: protocol.AccessRequest{
				SchemaVersion:     registry.Schema,
				DeploymentID:      strings.Repeat("a", 64),
				Actor:             "did:web:b.local:agents:b1",
				PrincipalDomain:   "A",
				AuthorizationMode: registry.RP,
				TaskID:            strings.Repeat("b", 64),
				Audience:          "https://c.local",
				Resource:          registry.ResourceOrders,
				Action:            registry.ActionOrderCreate,
				SupplierID:        gateway.DefaultSupplierID,
				QuoteID:           &quoteID,
				ProductID:         gateway.DefaultProductID,
				Quantity:          1,
				Currency:          gateway.DefaultCurrency,
				AmountMinor:       80000,
				IdempotencyKey:    "orig-key",
			},
		},
	}

	trial := &e1Trial{}
	req, err := trial.freshRequest(mode, registry.ActionQuoteRead, "new-key")
	require.NoError(t, err)
	assert.Equal(t, registry.ResourceQuotes, req.Resource)
	assert.Equal(t, registry.ActionQuoteRead, req.Action)
	assert.Equal(t, int64(0), req.AmountMinor)
	assert.Nil(t, req.QuoteID)
	assert.Equal(t, "new-key", req.IdempotencyKey)

	claims := protocol.GrantClaims{
		ID:                strings.Repeat("c", 64),
		RootID:            strings.Repeat("c", 64),
		TaskID:            strings.Repeat("b", 64),
		AuthorizationMode: registry.RP,
		PrincipalDomain:   "A",
		ResourceID:        registry.ResourceOrders,
		Issuer:            "did:web:c.local:supplier",
		Grantee:           "did:web:a.local:u",
		Resources:         []string{registry.ResourceOrders, registry.ResourceQuotes},
		Actions:           []string{registry.ActionOrderCreate, registry.ActionQuoteRead},
		Suppliers:         []string{gateway.DefaultSupplierID},
		MaxAmountMinor:    500000,
		RemainingDepth:    2,
	}
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	compact := "eyJhbGciOiJFUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
	decoded, err := decodeGrantPayload(compact)
	require.NoError(t, err)
	assert.Equal(t, claims.ID, decoded.ID)
	assert.Equal(t, int64(500000), decoded.MaxAmountMinor)

	_, err = decodeGrantPayload("not-a-jws")
	require.Error(t, err)
}
