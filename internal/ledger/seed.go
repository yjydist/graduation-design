package ledger

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

type SeedReport struct {
	Synthetic     bool                    `json:"synthetic"`
	DeploymentID  string                  `json:"deploymentId"`
	Unimplemented []string                `json:"unimplementedValidation"`
	Operations    []*Operation            `json:"operations"`
	Fixtures      *Fixtures               `json:"fixtures"`
	CurrentGrants map[string]*GrantRecord `json:"currentGrants"`
}

func Seed(ctx context.Context, r *Registry) (*SeedReport, error) {
	f, err := LoadFixtures(ctx, r)
	if err != nil {
		return nil, err
	}
	report := &SeedReport{Synthetic: true, DeploymentID: r.Deployment.DeploymentID, Fixtures: f, CurrentGrants: map[string]*GrantRecord{}, Unimplemented: []string{"HTTP challenge consumption and DID control proofs", "online did:web resolution", "ES256 and SD-JWT signature verification", "full resource/action/amount containment", "procurement policy and orders"}}
	write := func(id, role, method string, args ...any) error {
		op, err := r.Write(ctx, r.Deployment.DeploymentID[:8]+"-"+id, role, method, args...)
		if op != nil {
			report.Operations = append(report.Operations, op)
		}
		if err != nil {
			return err
		}
		if op.Status != "CONFIRMED" {
			return fmt.Errorf("seed stopped after %s: %s", id, op.Status)
		}
		return nil
	}
	for _, name := range []string{"A", "C"} {
		d := f.Domains[name]
		if err = write("bootstrap-"+name, "T", "bootstrapDomain", d.Domain, d.Identity, d.Issuers); err != nil {
			return report, err
		}
		if err = write("certify-"+name, "T", "registerDomainCertification", d.Certification, uint64(1), common.Hash{}); err != nil {
			return report, err
		}
	}
	for _, role := range []string{"U", "A1", "C", "B1"} {
		registrar, issuer := "registrarA", "IA"
		if role == "C" {
			registrar, issuer = "registrarC", "IC"
		}
		if err = write("identity-"+role, registrar, "registerIdentity", f.Identities[role]); err != nil {
			return report, err
		}
		if err = write("credential-"+role, issuer, "registerCredential", f.Credentials[role]); err != nil {
			return report, err
		}
	}
	if err = write("task-U", "U", "registerTask", f.Task); err != nil {
		return report, err
	}
	if err = write("grant-G0", "C", "registerGrant", f.Grants["G0"]); err != nil {
		return report, err
	}
	if err = write("grant-G1", "U", "registerGrant", f.Grants["G1"]); err != nil {
		return report, err
	}
	for _, label := range []string{"G0", "G1"} {
		g, err := viewRecord[GrantRecord](ctx, r, "getGrant", f.Grants[label].GrantId)
		if err != nil {
			return report, err
		}
		report.CurrentGrants[label] = g
	}
	return report, nil
}
