package runtime

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"grad/platform/agent"
	"grad/platform/registrysvc"
	"grad/platform/workbench"
	"grad/protocol"
	"grad/protocol/registry"
)

func TestWorkbenchTracePreservesBusinessReferences(t *testing.T) {
	grantID := registry.Digest([]byte("committed G2"))
	actionID := "urn:grad:action:original-order"
	decisionID := "urn:grad:decision:original-order"
	for _, tc := range []struct {
		tool   string
		output map[string]any
		want   map[string]any
	}{
		{"delegate_grant", map[string]any{
			"grant": map[string]any{"grantId": grantID, "privateMaterial": "excluded"}, "anchored": true,
		}, map[string]any{"grantId": grantID, "anchored": true}},
		{"create_order", map[string]any{
			"actionId": actionID, "decision": "UNKNOWN", "errorMessage": "excluded",
		}, map[string]any{"actionId": actionID, "decision": "UNKNOWN"}},
		{"reconcile_order", map[string]any{
			"creationDecisionId": decisionID, "outcome": "CREATED", "historicalReason": "excluded",
		}, map[string]any{"decisionId": decisionID, "outcome": "CREATED"}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			trace := boundedTrace(agent.ToolTrace{
				ToolName: tc.tool, Step: 2, Output: tc.output,
				Arguments: map[string]any{"secret": "excluded"}, RawText: "excluded",
			})
			require.Equal(t, agent.ToolTrace{ToolName: tc.tool, Step: 2, Output: tc.want}, trace)
		})
	}
}

func TestWorkbenchDispatchBridgeUsesStrictJSON(t *testing.T) {
	status := "VALID"
	in := dispatchInput{
		Run: dispatchRun{RunID: registry.Digest([]byte("run")), TaskID: registry.Digest([]byte("task")), Task: workbench.Draft{
			ProductID: "urn:grad:product:P1", Mode: registry.RP, Quantity: 1,
		}},
		Delivery: GrantDelivery{
			Operation: registrysvc.OperationView{Status: "CONFIRMED", ValidationCode: &status},
			Package:   registrysvc.GrantDeliveryPackage{TaskSpec: protocol.TaskSpec{Resources: []string{}, Actions: []string{}}},
		},
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var decoded dispatchInput
	require.NoError(t, protocol.DecodeStrictJSON(raw, &decoded))
	require.Equal(t, in, decoded)
}
