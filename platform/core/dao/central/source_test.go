package central

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/core/ledger"
	"grad/protocol"
	"grad/protocol/registry"
)

func TestCheckFreshValidation(t *testing.T) {
	src := &Source{DeploymentID: registry.Digest([]byte("dep-central"))}
	now := time.Now().UTC()

	for _, tc := range []struct {
		name string
		snap *ledger.StateSnapshot
		want bool
	}{
		{"nil snapshot", nil, false},
		{"wrong source", &ledger.StateSnapshot{StateSource: ledger.SourceFabric, Revision: 1, StateReadAt: now}, false},
		{"zero revision", &ledger.StateSnapshot{StateSource: ledger.SourceCentralized, Revision: 0, StateReadAt: now}, false},
		{"zero read time", &ledger.StateSnapshot{StateSource: ledger.SourceCentralized, Revision: 1}, false},
		{"valid centralized", &ledger.StateSnapshot{StateSource: ledger.SourceCentralized, Revision: 1, StateReadAt: now}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lease, err := src.CheckFresh(context.Background(), tc.snap)
			if tc.want {
				require.NoError(t, err)
				assert.Equal(t, ledger.ProbeLease{}, lease)
			} else {
				require.Error(t, err)
				assert.True(t, protocol.HasCode(err, protocol.ErrCodeStateUnavailable))
			}
		})
	}
}

func TestDependenciesClosureAndCycleDetection(t *testing.T) {
	snap := sampleCentralSnapshot()
	// Add unrelated domain B which must be pruned from A/C grant closure.
	snap.Domains["B"] = registry.Domain{ID: "B", DID: "did:web:b.local", Certification: "cert-B"}
	snap.Certifications["cert-B"] = registry.Certification{ID: "cert-B", Domain: "B"}

	err := dependencies(snap, "g1")
	require.NoError(t, err)
	assert.Contains(t, snap.Grants, "g1")
	assert.Contains(t, snap.Grants, "g0")
	assert.Contains(t, snap.Domains, "A")
	assert.Contains(t, snap.Domains, "C")
	assert.NotContains(t, snap.Domains, "B")

	// Cycle detection
	cyclic := sampleCentralSnapshot()
	g0 := cyclic.Grants["g0"]
	g0.Parent = "g1"
	cyclic.Grants["g0"] = g0
	err = dependencies(cyclic, "g1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid central grant path")
}

func sampleCentralSnapshot() *protocol.SnapshotView {
	depID := registry.Digest([]byte("central-deployment"))
	return &protocol.SnapshotView{
		DeploymentID: depID,
		Root: registry.RootRecord{
			DID:            "did:web:t.local",
			Management:     registry.Management{MSPID: "TMsp", CertificateSHA256: registry.Digest([]byte("t-cert"))},
			DocumentDigest: registry.Digest([]byte("t-doc")),
			KeyID:          "did:web:t.local#key-1",
			KeyVersion:     1,
			PublicKey:      "04" + registry.Digest([]byte("pub-x")) + registry.Digest([]byte("pub-y")),
		},
		Domains: map[string]registry.Domain{
			"A": {Bound: registry.Bound{DeploymentID: depID}, ID: "A", DID: "did:web:a.local", Certification: "cert-A", Version: registry.Version{Status: registry.Active, Revision: 1}},
			"C": {Bound: registry.Bound{DeploymentID: depID}, ID: "C", DID: "did:web:c.local", Certification: "cert-C", Version: registry.Version{Status: registry.Active, Revision: 1}},
		},
		Certifications: map[string]registry.Certification{
			"cert-A": {Bound: registry.Bound{DeploymentID: depID}, ID: "cert-A", Domain: "A", Version: registry.Version{Status: registry.Active, Revision: 1}},
			"cert-C": {Bound: registry.Bound{DeploymentID: depID}, ID: "cert-C", Domain: "C", Version: registry.Version{Status: registry.Active, Revision: 1}},
		},
		Identities: map[string]registry.Identity{
			"did:web:a.local":          {ID: "did:web:a.local", Domain: "A", Version: registry.Version{Status: registry.Active, Revision: 1}},
			"did:web:c.local":          {ID: "did:web:c.local", Domain: "C", Version: registry.Version{Status: registry.Active, Revision: 1}},
			"did:web:a.local:ia":       {ID: "did:web:a.local:ia", Domain: "A", Version: registry.Version{Status: registry.Active, Revision: 1}},
			"did:web:c.local:ic":       {ID: "did:web:c.local:ic", Domain: "C", Version: registry.Version{Status: registry.Active, Revision: 1}},
			"did:web:a.local:u":        {ID: "did:web:a.local:u", Domain: "A", Version: registry.Version{Status: registry.Active, Revision: 1}},
			"did:web:a.local:a1":       {ID: "did:web:a.local:a1", Domain: "A", Version: registry.Version{Status: registry.Active, Revision: 1}},
			"did:web:c.local:supplier": {ID: "did:web:c.local:supplier", Domain: "C", Version: registry.Version{Status: registry.Active, Revision: 1}},
		},
		Credentials: map[string]registry.Credential{
			"cred-u":  {ID: "cred-u", Issuer: "did:web:a.local:ia", Subject: "did:web:a.local:u", Version: registry.Version{Status: registry.Active, Revision: 1}},
			"cred-a1": {ID: "cred-a1", Issuer: "did:web:a.local:ia", Subject: "did:web:a.local:a1", Version: registry.Version{Status: registry.Active, Revision: 1}},
			"cred-c":  {ID: "cred-c", Issuer: "did:web:c.local:ic", Subject: "did:web:c.local:supplier", Version: registry.Version{Status: registry.Active, Revision: 1}},
		},
		Tasks: map[string]registry.Task{
			"task-1": {ID: "task-1", Creator: "did:web:a.local:u", CreatorCredential: "cred-u", Domain: "A", Mode: registry.RP, Version: registry.Version{Status: registry.Active, Revision: 1}},
		},
		Grants: map[string]registry.Grant{
			"g0": {
				ID: "g0", Root: "g0", Task: "task-1", Mode: registry.RP, Domain: "A",
				Issuer: "did:web:c.local:supplier", Grantee: "did:web:a.local:u",
				IssuerCredential: "cred-c", GranteeCredential: "cred-u",
				Version: registry.Version{Status: registry.Active, Revision: 1},
			},
			"g1": {
				ID: "g1", Parent: "g0", Root: "g0", Task: "task-1", Mode: registry.RP, Domain: "A",
				Issuer: "did:web:a.local:u", Grantee: "did:web:a.local:a1",
				IssuerCredential: "cred-u", GranteeCredential: "cred-a1",
				Version: registry.Version{Status: registry.Active, Revision: 1},
			},
		},
		Links: map[string]registry.IdentityLink{},
	}
}
