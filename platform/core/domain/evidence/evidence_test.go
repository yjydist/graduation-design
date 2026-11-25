package evidence_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/core/domain/evidence"
	domgw "grad/platform/core/domain/gateway"
	"grad/platform/core/domain/procurement"
	"grad/protocol"
	preg "grad/protocol/registry"
)

type stubPeerEvidence struct {
	taskEvidence domgw.TaskEvidence
	rootAmount   evidence.RootGrantAmount
	rootErr      error
}

func (s stubPeerEvidence) FetchTaskEvidence(context.Context, string) (domgw.TaskEvidence, error) {
	return s.taskEvidence, nil
}

func (s stubPeerEvidence) FetchRootAmount(context.Context, string) (evidence.RootGrantAmount, error) {
	return s.rootAmount, s.rootErr
}

func TestProjectRunFiveEvidenceCategoriesAndRootAmountBinding(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	taskID := preg.Digest([]byte("evidence-task-1"))
	run := procurement.Run{
		RunID:  "run-1",
		TaskID: taskID,
		Stage:  procurement.StageDispatch,
		Task: procurement.Draft{
			ProductID: "urn:grad:product:P1",
			Quantity:  2,
			Mode:      preg.RP,
		},
	}
	g0ID := run.GrantID("G0")
	g1ID := run.GrantID("G1")
	g0Digest := preg.Digest([]byte("g0-jws"))
	g1Digest := preg.Digest([]byte("g1-jws"))

	anchors := map[string]preg.Grant{
		g0ID: {
			ID: g0ID, Root: g0ID, Task: taskID, Mode: preg.RP,
			Issuer: "did:web:c.local:services:c", Grantee: "did:web:a.local:u",
			Digest: g0Digest, Version: preg.Version{Status: preg.Active, Revision: 1},
		},
		g1ID: {
			ID: g1ID, Parent: g0ID, Root: g0ID, Task: taskID, Mode: preg.RP,
			Issuer: "did:web:a.local:u", Grantee: "did:web:a.local:a1",
			Digest: g1Digest, Version: preg.Version{Status: preg.Active, Revision: 2},
		},
	}

	readGrant := func(_ context.Context, id string) (preg.Grant, error) {
		g, ok := anchors[id]
		if !ok {
			return preg.Grant{}, evidence.ErrNotFound
		}
		return g, nil
	}

	svc := evidence.NewService(evidence.Config{
		Peers: stubPeerEvidence{
			taskEvidence: domgw.TaskEvidence{
				Identity: []domgw.IdentityEvidence{{DID: "did:web:b.local:b1"}},
				Disclosures: []domgw.DisclosureEvidence{
					{CredentialID: "cred-b1", Disclosed: map[string]string{"role": "executor"}},
				},
				Delegations: []domgw.DelegationEvidence{
					{GrantID: g1ID, DecisionID: "dec-1", MaxAmountMinor: 5000},
				},
				Decisions: []domgw.DecisionSummary{{DecisionID: "dec-1", Outcome: "ALLOW"}},
				Quotes:    []domgw.QuotePayload{{QuoteID: "q-1", TotalAmountMinor: 2000}},
				Orders:    []domgw.OrderPayload{{OrderID: "o-1", TotalAmountMinor: 2000}},
			},
			rootAmount: evidence.RootGrantAmount{Digest: g0Digest, MaxAmountMinor: 10000},
		},
		ReadGrant: readGrant,
	})

	out, err := svc.ProjectRun(ctx, run)
	require.NoError(t, err)
	assert.Len(t, out.Identity, 1)
	assert.Len(t, out.Disclosures, 1)
	require.Len(t, out.Delegations, 2)
	assert.Equal(t, g0ID, out.Delegations[0].GrantID)
	assert.Equal(t, int64(10000), out.Delegations[0].MaxAmountMinor)
	assert.Equal(t, g1ID, out.Delegations[1].GrantID)
	assert.Equal(t, "dec-1", out.Delegations[1].DecisionID)
	assert.Equal(t, int64(5000), out.Delegations[1].MaxAmountMinor)
	assert.Equal(t, taskID, out.Purchase.TaskID)
	assert.Len(t, out.Purchase.Quotes, 1)
	assert.Len(t, out.Purchase.Orders, 1)
	assert.Len(t, out.Decisions, 1)

	// Tampered root digest from peer C must fail with BINDING_MISMATCH.
	tampered := evidence.NewService(evidence.Config{
		Peers: stubPeerEvidence{
			rootAmount: evidence.RootGrantAmount{Digest: preg.Digest([]byte("wrong")), MaxAmountMinor: 10000},
		},
		ReadGrant: readGrant,
	})
	_, err = tampered.ProjectRun(ctx, run)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeBindingMismatch))
}

func TestReadDecisionWithoutGatewayReturnsNotFound(t *testing.T) {
	t.Parallel()
	svc := evidence.NewService(evidence.Config{})
	_, err := svc.ReadDecision(context.Background(), procurement.Principal{DomainID: "A", Role: procurement.RoleBuyer}, "dec-1")
	require.ErrorIs(t, err, evidence.ErrNotFound)
}
