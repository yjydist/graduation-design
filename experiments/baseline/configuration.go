package main

import (
	"fmt"

	"graduation-design/internal/gateway"
	"graduation-design/internal/protocol"
)

// Configuration fixes the two controlled factors of a baseline gateway.
type Configuration struct {
	Name           string `json:"configuration"`
	StateSource    string `json:"state_source"`
	SignatureCache bool   `json:"signature_cache"`
}

func BaselineConfiguration(name string) (Configuration, error) {
	switch name {
	case "C0":
		return Configuration{name, gateway.StateCentralized, false}, nil
	case "B0":
		return Configuration{name, gateway.StateFabric, false}, nil
	case "B1":
		return Configuration{name, gateway.StateFabric, true}, nil
	default:
		return Configuration{}, fmt.Errorf("unknown baseline configuration %q", name)
	}
}

// NewSignatureCache creates one fresh cache for this gateway and round. Disabled groups use nil.
func (c Configuration) NewSignatureCache() *protocol.SignatureCache {
	if !c.SignatureCache {
		return nil
	}
	return protocol.NewSignatureCache()
}
