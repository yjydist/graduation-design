package baseline

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"grad/platform/core/domain/policy"
	"grad/protocol"
	"grad/protocol/registry"
)

//go:embed baseline.json
var baselineJSON []byte

// Root binds an authorization mode to its root issuer role.
type Root struct {
	Mode   string `json:"mode"`
	Issuer string `json:"issuer"`
}

// Hop describes one delegation hop in the fixed procurement chain.
type Hop struct {
	Grant          string `json:"grant"`
	Grantee        string `json:"grantee"`
	AmountMinor    int64  `json:"amount_minor"`
	RemainingDepth int64  `json:"remaining_depth"`
}

// TimeRules pins the relative validity windows and liveness parameters for a baseline round.
type TimeRules struct {
	NBFOffset      int64  `json:"credential_nbf_offset_seconds"`
	EXPOffset      int64  `json:"credential_exp_offset_seconds"`
	ChallengeTTL   int64  `json:"challenge_ttl_seconds"`
	QuoteTTL       int64  `json:"quote_ttl_seconds"`
	ProbeInterval  int64  `json:"probe_interval_seconds"`
	ProbeLifetime  int64  `json:"probe_lifetime_seconds"`
	PolicyDeadline string `json:"policy_deadline"`
	Clock          string `json:"clock"`
}

// Fixture captures the frozen paired baseline experiment specification.
type Fixture struct {
	Seeds               []int                  `json:"seeds"`
	Root                string                 `json:"root"`
	Domains             map[string]string      `json:"domains"`
	Identities          map[string]string      `json:"identities"`
	Disclosures         []string               `json:"disclosures"`
	Roots               []Root                 `json:"roots"`
	Path                []Hop                  `json:"path"`
	Supplier            string                 `json:"supplier"`
	Product             string                 `json:"product"`
	Quantity            int64                  `json:"quantity"`
	Currency            string                 `json:"currency"`
	PricesMinor         []int64                `json:"prices_minor"`
	ExpectedOrderStatus []int                  `json:"expected_order_status"`
	ExpectedOrderCode   []string               `json:"expected_order_code"`
	Configurations      []string               `json:"configuration_order"`
	Actions             []string               `json:"actions"`
	PolicyVersion       string                 `json:"policy_version"`
	Roles               policy.RolesConfig     `json:"roles"`
	Resources           policy.ResourcesConfig `json:"resources"`
	TimeRules           TimeRules              `json:"time_rules"`
	Randomness          string                 `json:"randomness"`
}

// Case describes a single planned quote+order baseline case.
type Case struct {
	Configuration  string `json:"configuration"`
	CaseID         string `json:"case_id"`
	Mode           string `json:"mode"`
	AmountMinor    int64  `json:"amount_minor"`
	ExpectedStatus int    `json:"expected_http_status"`
	ExpectedCode   string `json:"expected_code"`
}

// Inputs holds the seed-bound logical fixture and 12 planned paired cases.
type Inputs struct {
	Seed               int     `json:"seed"`
	Fixture            Fixture `json:"fixture"`
	PolicySourceDigest string  `json:"policy_source_digest"`
	Cases              []Case  `json:"planned_cases"`
}

// Baseline returns a fresh copy of the frozen specification and a seed-specific plan.
func Baseline(seed int) (*Inputs, error) {
	var f Fixture
	if err := json.Unmarshal(baselineJSON, &f); err != nil {
		return nil, err
	}
	if !slices.Contains(f.Seeds, seed) {
		return nil, fmt.Errorf("baseline seed must be one of %v", f.Seeds)
	}
	if f.PolicyVersion != policy.DefaultPolicyVersion {
		return nil, fmt.Errorf("baseline policy version differs from pinned source")
	}
	in := &Inputs{
		Seed:               seed,
		Fixture:            f,
		PolicySourceDigest: registry.Digest([]byte(policy.DefaultProcurementRego)),
	}
	for _, config := range f.Configurations {
		for _, root := range f.Roots {
			short := "rp"
			if root.Mode == registry.BM {
				short = "bm"
			}
			for n, amount := range f.PricesMinor {
				in.Cases = append(in.Cases, Case{
					Configuration:  config,
					CaseID:         fmt.Sprintf("%d-%s-%d", seed, short, amount),
					Mode:           root.Mode,
					AmountMinor:    amount,
					ExpectedStatus: f.ExpectedOrderStatus[n],
					ExpectedCode:   f.ExpectedOrderCode[n],
				})
			}
		}
	}
	return in, nil
}

// Digest returns the RFC 8785 JCS SHA-256 digest of the seed-bound logical inputs.
func (in *Inputs) Digest() (string, error) {
	raw, err := protocol.MarshalJCS(in)
	if err != nil {
		return "", err
	}
	return registry.Digest(raw), nil
}

// LogicalID pairs a task or grant across clean deployments without seeding cryptographic keys.
func (in *Inputs) LogicalID(mode, label string) string {
	return fmt.Sprintf("%d/%s/%s", in.Seed, strings.ToLower(mode), label)
}

// Policy binds the pinned policy source and configuration to this round's root and deadlines.
func (in *Inputs) Policy(deploymentID, serviceDID string, root registry.RootRecord, rpExpiry, bmExpiry int64) (*policy.VerifiedBundle, error) {
	deadline := min(rpExpiry, bmExpiry)
	resources := in.Fixture.Resources
	resources.PolicyDeadline = &deadline
	files, digest, err := policy.BuildCustomBundle(deploymentID, serviceDID, in.Fixture.PolicyVersion, root, in.Fixture.Roles, resources)
	if err != nil {
		return nil, err
	}
	return policy.VerifyAndLoadBundle(files, deploymentID, serviceDID, root, digest)
}
