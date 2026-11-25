package baseline

import (
	"fmt"

	"grad/platform/core/ledger"
	"grad/protocol"
)

// Configuration fixes the two controlled factors of a baseline gateway.
type Configuration struct {
	Name           string `json:"configuration"`
	StateSource    string `json:"state_source"`
	SignatureCache bool   `json:"signature_cache"`
}

// BaselineConfiguration resolves one of the three controlled baseline groups (C0, B0, B1).
func BaselineConfiguration(name string) (Configuration, error) {
	switch name {
	case "C0":
		return Configuration{Name: name, StateSource: ledger.SourceCentralized, SignatureCache: false}, nil
	case "B0":
		return Configuration{Name: name, StateSource: ledger.SourceFabric, SignatureCache: false}, nil
	case "B1":
		return Configuration{Name: name, StateSource: ledger.SourceFabric, SignatureCache: true}, nil
	default:
		return Configuration{}, fmt.Errorf("unknown baseline configuration %q", name)
	}
}

// NewSignatureCache creates one fresh cache for this gateway and round. Disabled groups return nil.
func (c Configuration) NewSignatureCache() *protocol.SignatureCache {
	if !c.SignatureCache {
		return nil
	}
	return protocol.NewSignatureCache()
}
