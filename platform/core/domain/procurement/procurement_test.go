package procurement

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	domreg "grad/platform/core/domain/registry"
	"grad/protocol"
	preg "grad/protocol/registry"
)

func TestBoundedTracePreservesBusinessReferences(t *testing.T) {
	t.Parallel()
	grantID := preg.Digest([]byte("committed G2"))
	actionID := "urn:grad:action:original-order"
	decisionID := "urn:grad:decision:original-order"
	for _, tc := range []struct {
		tool   string
		output map[string]any
		want   map[string]any
	}{
		{
			"delegate_grant",
			map[string]any{"grant": map[string]any{"grantId": grantID, "privateMaterial": "excluded"}, "anchored": true},
			map[string]any{"grantId": grantID, "anchored": true},
		},
		{
			"create_order",
			map[string]any{"actionId": actionID, "decision": "UNKNOWN", "errorMessage": "excluded"},
			map[string]any{"actionId": actionID, "decision": "UNKNOWN"},
		},
		{
			"reconcile_order",
			map[string]any{"creationDecisionId": decisionID, "outcome": "CREATED", "historicalReason": "excluded"},
			map[string]any{"decisionId": decisionID, "outcome": "CREATED"},
		},
		{
			"unexpected_tool",
			map[string]any{"code": "OK"},
			map[string]any{"code": "OK"},
		},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			trace := BoundedTrace(ToolTrace{
				ToolName:  tc.tool,
				Step:      2,
				Output:    tc.output,
				Arguments: map[string]any{"secret": "excluded"},
				RawText:   "excluded",
			})
			wantTool := tc.tool
			if tc.tool == "unexpected_tool" {
				wantTool = "unknown_tool"
			}
			require.Equal(t, ToolTrace{ToolName: wantTool, Step: 2, Output: tc.want}, trace)
		})
	}
}

func TestDispatchBridgeUsesStrictJSON(t *testing.T) {
	t.Parallel()
	status := "VALID"
	in := DispatchRequest{
		Run: DispatchRun{
			RunID:  preg.Digest([]byte("run")),
			TaskID: preg.Digest([]byte("task")),
			Task: Draft{
				ProductID: "urn:grad:product:P1",
				Mode:      preg.RP,
				Quantity:  1,
			},
		},
		Delivery: GrantDelivery{
			Operation: domreg.OperationView{Status: "CONFIRMED", ValidationCode: &status},
			Package:   domreg.GrantDeliveryPackage{TaskSpec: protocol.TaskSpec{Resources: []string{}, Actions: []string{}}},
		},
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var decoded DispatchRequest
	require.NoError(t, protocol.DecodeStrictJSON(raw, &decoded))
	require.Equal(t, in, decoded)
}

func TestDraftValidateAndTaskSpec(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	const delegate = "did:web:a.local:a1"
	valid := Draft{
		ProductID:      "urn:grad:product:P1",
		Quantity:       2,
		Mode:           preg.RP,
		MaxAmountMinor: 160000,
		ExpiresAt:      now.Add(time.Hour).Unix(),
		DelegateDID:    delegate,
		Description:    strings.Repeat("采", MaxDraftDescriptionLength),
	}
	require.NoError(t, valid.Validate(delegate, now))
	spec := valid.TaskSpec()
	require.Equal(t, DefaultSupplierID, spec.SupplierID)
	require.Equal(t, DefaultCurrency, spec.Currency)
	require.Equal(t, int64(2), spec.MaxQuantity)

	cases := []struct {
		name   string
		mutate func(*Draft)
	}{
		{"invalid mode", func(d *Draft) { d.Mode = "UNKNOWN" }},
		{"wrong delegate", func(d *Draft) { d.DelegateDID = "did:web:a.local:other" }},
		{"zero amount", func(d *Draft) { d.MaxAmountMinor = 0 }},
		{"expired", func(d *Draft) { d.ExpiresAt = now.Unix() }},
		{"too far in future", func(d *Draft) { d.ExpiresAt = now.Add(25 * time.Hour).Unix() }},
		{"unknown product", func(d *Draft) { d.ProductID = "urn:grad:product:P99" }},
		{"description too long", func(d *Draft) { d.Description = strings.Repeat("采", MaxDraftDescriptionLength+1) }},
		{"zero quantity", func(d *Draft) { d.Quantity = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := valid
			tc.mutate(&d)
			err := d.Validate(delegate, now)
			require.Error(t, err)
			require.Equal(t, preg.ErrCodeInvalidSchema, protocol.CodeOf(err))
		})
	}
}

func TestSessionHelpersAndCSRF(t *testing.T) {
	t.Parallel()
	require.True(t, ValidUsername("buyer_1.demo-a"))
	require.False(t, ValidUsername(""))
	require.False(t, ValidUsername("bad user"))
	require.True(t, ValidPassword("secret"))
	require.False(t, ValidPassword(""))
	require.False(t, ValidPassword(strings.Repeat("x", 73)))

	mgmtA := preg.Management{MSPID: "AMsp", CertificateSHA256: strings.Repeat("a", 64)}
	mgmtC := preg.Management{MSPID: "CMsp", CertificateSHA256: strings.Repeat("c", 64)}
	require.True(t, ValidPrincipal(Principal{DomainID: "A", SubjectID: "did:web:a.local:u", Role: RoleBuyer, Management: mgmtA}, "A"))
	require.False(t, ValidPrincipal(Principal{DomainID: "C", SubjectID: "did:web:c.local:u", Role: RoleBuyer, Management: mgmtC}, "C"))
	require.True(t, ValidPrincipal(Principal{DomainID: "C", SubjectID: "did:web:c.local", Role: RoleAuditor, Management: mgmtC}, "C"))
	require.False(t, ValidPrincipal(Principal{DomainID: "A", SubjectID: "did:web:a.local", Role: RoleAuditor, Management: mgmtA}, "A"))

	tok := strings.Repeat("A", 43)
	csrf := CSRFToken(tok)
	require.True(t, VerifyCSRF(tok, csrf))
	require.False(t, VerifyCSRF(tok, csrf+"x"))
	view := BuildSessionView(Principal{DomainID: "A", SubjectID: "did:web:a.local:u", Role: RoleBuyer, Management: mgmtA}, tok)
	require.Equal(t, []string{"procure"}, view.Actions)
	require.Equal(t, csrf, view.CSRFToken)
}

func TestApplyControlResultAndAppendStep(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	run := &Run{
		RunID:          preg.Digest([]byte("r1")),
		TaskID:         preg.Digest([]byte("t1")),
		Stage:          StageDispatch,
		Status:         RunPending,
		GrantRevision:  1,
		GrantStatus:    preg.Active,
		AllowedActions: []string{"suspend"},
	}
	mut := preg.Mutation{ID: run.GrantID("G1"), ExpectedRevision: 1}
	pendingOp := &domreg.OperationView{OperationID: "op-1", Status: RunPending}
	require.False(t, applyControlResult(run, "SuspendGrant", mut, pendingOp, now))
	require.Empty(t, run.AllowedActions)
	require.Len(t, run.Steps, 1)

	// Identical pending observation is deduplicated.
	require.False(t, applyControlResult(run, "SuspendGrant", mut, pendingOp, now.Add(time.Second)))
	require.Len(t, run.Steps, 1)

	valid := "VALID"
	confirmedOp := &domreg.OperationView{
		OperationID:    "op-1",
		Status:         "CONFIRMED",
		TxID:           preg.Digest([]byte("tx-1")),
		ValidationCode: &valid,
	}
	require.True(t, applyControlResult(run, "SuspendGrant", mut, confirmedOp, now.Add(2*time.Second)))
	require.Equal(t, uint64(2), run.GrantRevision)
	require.Equal(t, preg.Suspended, run.GrantStatus)
	require.Equal(t, []string{"resume"}, run.AllowedActions)
	require.Len(t, run.Steps, 2)

	resumeMut := preg.Mutation{ID: run.GrantID("G1"), ExpectedRevision: 2}
	resumeOp := &domreg.OperationView{OperationID: "op-2", Status: "CONFIRMED", ValidationCode: &valid}
	require.True(t, applyControlResult(run, "ResumeGrant", resumeMut, resumeOp, now.Add(3*time.Second)))
	require.Equal(t, uint64(3), run.GrantRevision)
	require.Equal(t, preg.Active, run.GrantStatus)
	require.Equal(t, []string{"suspend"}, run.AllowedActions)
}
