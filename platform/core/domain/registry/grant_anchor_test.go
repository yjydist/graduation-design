package registry

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/core/ledger"
	"grad/protocol"
	preg "grad/protocol/registry"
)

func TestBuildChainGrant(t *testing.T) {
	depID := strings.Repeat("a", 64)
	parentID := strings.Repeat("b", 64)
	parentDigest := strings.Repeat("c", 64)
	grantDigest := strings.Repeat("d", 64)

	claims := protocol.GrantClaims{
		ID:                  strings.Repeat("e", 64),
		SchemaVersion:       protocol.SchemaVersion,
		DeploymentID:        depID,
		ParentID:            &parentID,
		ParentDigest:        &parentDigest,
		RootID:              strings.Repeat("f", 64),
		TaskID:              strings.Repeat("1", 64),
		AuthorizationMode:   preg.RP,
		PrincipalDomain:     "A",
		ResourceID:          strings.Repeat("2", 64),
		Issuer:              "did:web:a.local:a1",
		Grantee:             "did:web:b.local:b1",
		IssuerKeyVersion:    2,
		GranteeKeyVersion:   3,
		IssuerCredentialID:  "urn:grad:cred:A1",
		GranteeCredentialID: "urn:grad:cred:B1",
		RemainingDepth:      0,
		NBF:                 100,
		EXP:                 200,
	}

	got := BuildChainGrant(depID, claims, grantDigest, "ignored-override")
	assert.Equal(t, depID, got.DeploymentID)
	assert.Equal(t, claims.ID, got.ID)
	assert.Equal(t, preg.Schema, got.Schema)
	assert.Equal(t, parentID, got.Parent)
	assert.Equal(t, parentDigest, got.ParentDigest)
	assert.Equal(t, claims.RootID, got.Root)
	assert.Equal(t, claims.TaskID, got.Task)
	assert.Equal(t, preg.RP, got.Mode)
	assert.Equal(t, uint8(0), got.Depth)
	assert.Equal(t, grantDigest, got.Digest)
	assert.Equal(t, preg.Interval{NBF: 100, EXP: 200}, got.Interval)

	// Falls back to parentOverride when claims.ParentID is nil.
	claims.ParentID = nil
	claims.ParentDigest = nil
	fallback := BuildChainGrant(depID, claims, grantDigest, parentID)
	assert.Equal(t, parentID, fallback.Parent)
	assert.Empty(t, fallback.ParentDigest)
}

func TestGrantAnchorServiceValidation(t *testing.T) {
	_, err := NewGrantAnchorService(GrantAnchorConfig{})
	require.Error(t, err)

	_, err = NewGrantAnchorService(GrantAnchorConfig{DeploymentID: strings.Repeat("a", 64)})
	require.Error(t, err)
}

func TestGrantAnchorServiceAnchorAndReplace(t *testing.T) {
	depID := strings.Repeat("a", 64)
	g1ID := strings.Repeat("1", 64)
	g2ID := strings.Repeat("2", 64)
	g2PrimeID := strings.Repeat("3", 64)
	g1Digest := strings.Repeat("4", 64)
	g2Digest := strings.Repeat("5", 64)
	g2PrimeDigest := strings.Repeat("6", 64)

	type writeCall struct {
		key, role, method string
		raw               []byte
	}
	var writes []writeCall
	var awaited []ledger.Outcome

	svc, err := NewGrantAnchorService(GrantAnchorConfig{
		DeploymentID: depID,
		WriteOperation: func(_ context.Context, key, role, method string, raw []byte) (*ledger.Operation, error) {
			writes = append(writes, writeCall{key: key, role: role, method: method, raw: append([]byte(nil), raw...)})
			return &ledger.Operation{
				Key:    key,
				Method: method,
				TxID:   "tx-" + method,
				Status: "CONFIRMED",
				Commit: &ledger.Outcome{
					Point: ledger.Point{Number: uint64(len(writes) + 10)},
					Code:  "VALID",
				},
			}, nil
		},
		AwaitEndorsers: func(_ context.Context, commit ledger.Outcome) error {
			awaited = append(awaited, commit)
			return nil
		},
		Now: func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	require.NoError(t, err)

	g2Claims := protocol.GrantClaims{
		ID:                  g2ID,
		DeploymentID:        depID,
		ParentID:            &g1ID,
		ParentDigest:        &g1Digest,
		RootID:              strings.Repeat("0", 64),
		TaskID:              strings.Repeat("9", 64),
		AuthorizationMode:   preg.RP,
		PrincipalDomain:     "A",
		ResourceID:          strings.Repeat("8", 64),
		Issuer:              "did:web:a.local:a1",
		Grantee:             "did:web:b.local:b1",
		IssuerKeyVersion:    1,
		GranteeKeyVersion:   1,
		IssuerCredentialID:  "urn:grad:cred:A1",
		GranteeCredentialID: "urn:grad:cred:B1",
		RemainingDepth:      0,
		NBF:                 1699990000,
		EXP:                 1700010000,
	}

	anchorRes, err := svc.AnchorGrant(t.Context(), AnchorGrantRequest{
		Claims:      g2Claims,
		RawGrantJWS: "raw-g2-jws",
		GrantDigest: g2Digest,
		ParentID:    g1ID,
		IssuerActor: "A1",
	})
	require.NoError(t, err)
	assert.True(t, anchorRes.Anchored)
	assert.Equal(t, g2ID, anchorRes.Grant.ID)
	require.Len(t, writes, 1)
	assert.Equal(t, "mcp-anchor/"+preg.Digest([]byte(g2ID))[:24], writes[0].key)
	assert.Equal(t, "A1", writes[0].role)
	assert.Equal(t, "RegisterGrant", writes[0].method)
	var anchoredPayload preg.Grant
	require.NoError(t, json.Unmarshal(writes[0].raw, &anchoredPayload))
	assert.Equal(t, g2ID, anchoredPayload.ID)
	assert.Equal(t, g2Digest, anchoredPayload.Digest)
	require.Len(t, awaited, 1)
	assert.Equal(t, uint64(11), awaited[0].Number)

	g2PrimeClaims := g2Claims
	g2PrimeClaims.ID = g2PrimeID
	g2PrimeClaims.Grantee = "did:web:b.local:b2"
	g2PrimeClaims.GranteeCredentialID = "urn:grad:cred:B2"

	repRes, err := svc.ReplaceGrant(t.Context(), ReplaceGrantAnchorRequest{
		OldGrantID:       g2ID,
		OldGrantRevision: 0, // defaults to 1
		OldGrantDigest:   g2Digest,
		NewClaims:        g2PrimeClaims,
		NewRawGrantJWS:   "raw-g2-prime-jws",
		NewGrantDigest:   g2PrimeDigest,
		IssuerActor:      "A1",
		Reason:           "failover to B2",
	})
	require.NoError(t, err)
	assert.True(t, repRes.Anchored)
	assert.Equal(t, g2PrimeID, repRes.Grant.ID)
	require.Len(t, writes, 2)
	assert.Equal(t, "mcp-replace/"+preg.Digest([]byte(g2ID+"/"+g2PrimeID))[:24], writes[1].key)
	assert.Equal(t, "A1", writes[1].role)
	assert.Equal(t, "ReplaceGrant", writes[1].method)
	var repPayload preg.Replacement
	require.NoError(t, json.Unmarshal(writes[1].raw, &repPayload))
	assert.Equal(t, g2ID, repPayload.Old.ID)
	assert.Equal(t, uint64(1), repPayload.Old.ExpectedRevision)
	assert.Equal(t, g2Digest, repPayload.Old.ExpectedDigest)
	assert.Equal(t, "failover to B2", repPayload.Old.Reason)
	assert.Equal(t, g2PrimeID, repPayload.New.ID)
	require.Len(t, awaited, 2)
	assert.Equal(t, uint64(12), awaited[1].Number)
}

func TestGrantAnchorServiceRejectsInvalidCommitAndEndorserFailure(t *testing.T) {
	depID := strings.Repeat("a", 64)
	g2ID := strings.Repeat("2", 64)

	t.Run("non-VALID commit rejected", func(t *testing.T) {
		svc, err := NewGrantAnchorService(GrantAnchorConfig{
			DeploymentID: depID,
			WriteOperation: func(_ context.Context, key, _, method string, _ []byte) (*ledger.Operation, error) {
				return &ledger.Operation{
					Key:    key,
					Method: method,
					TxID:   "tx-invalid",
					Status: "FAILED",
					Commit: &ledger.Outcome{Point: ledger.Point{Number: 5}, Code: "MVCC_READ_CONFLICT"},
				}, nil
			},
		})
		require.NoError(t, err)
		_, err = svc.AnchorGrant(t.Context(), AnchorGrantRequest{
			Claims:      protocol.GrantClaims{ID: g2ID},
			IssuerActor: "A1",
		})
		require.Error(t, err)
	})

	t.Run("endorser wait failure propagated", func(t *testing.T) {
		wantErr := errors.New("endorser lagging")
		svc, err := NewGrantAnchorService(GrantAnchorConfig{
			DeploymentID: depID,
			WriteOperation: func(_ context.Context, key, _, method string, _ []byte) (*ledger.Operation, error) {
				return &ledger.Operation{
					Key:    key,
					Method: method,
					TxID:   "tx-ok",
					Status: "CONFIRMED",
					Commit: &ledger.Outcome{Point: ledger.Point{Number: 6}, Code: "VALID"},
				}, nil
			},
			AwaitEndorsers: func(_ context.Context, _ ledger.Outcome) error {
				return wantErr
			},
		})
		require.NoError(t, err)
		_, err = svc.ReplaceGrant(t.Context(), ReplaceGrantAnchorRequest{
			OldGrantID:  strings.Repeat("1", 64),
			NewClaims:   protocol.GrantClaims{ID: g2ID},
			IssuerActor: "A1",
		})
		require.ErrorIs(t, err, wantErr)
	})
}
