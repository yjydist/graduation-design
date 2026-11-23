package runtime

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"grad/platform/registrysvc"
	"grad/platform/workbench"
	"grad/protocol"
	"grad/protocol/registry"
)

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
