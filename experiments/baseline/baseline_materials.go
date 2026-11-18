package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"graduation-design/internal/fabric"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
)

func baselineProcurement(deploymentID string, in *Inputs) fabric.ProcurementSetup {
	ids := func(mode string) fabric.ProcurementPathIDs {
		namespace := deploymentID + "/baseline/" + in.LogicalID(mode, "")
		return fabric.ProcurementPathIDs{
			Task: api.Digest([]byte(namespace + "task")),
			G0:   api.Digest([]byte(namespace + "G0")),
			G1:   api.Digest([]byte(namespace + "G1")),
			G2:   api.Digest([]byte(namespace + "G2")),
		}
	}
	return fabric.ProcurementSetup{
		Spec: protocol.TaskSpec{
			SupplierID:  in.Fixture.Supplier,
			ProductID:   in.Fixture.Product,
			MaxQuantity: in.Fixture.Quantity,
			Currency:    in.Fixture.Currency,
			Resources:   []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
			Actions:     slices.Sorted(slices.Values(in.Fixture.Actions)),
			Description: "Paired baseline procurement",
		},
		RP: ids(api.RP),
		BM: ids(api.BM),
	}
}

// baselineRegistration contains public anchors only. Full presentations stay in the private instance database.
type baselineRegistration struct {
	Snapshot       *protocol.SnapshotView
	MaterialDigest string
	InputDigest    string
}

// prepareRegistration prepares the C0 input from the same fixtures submitted by seed.
func prepareRegistration(dir string, d *fabric.Deployment, report *fabric.SeedReport, setup fabric.ProcurementSetup) (*baselineRegistration, error) {
	f := report.Fixtures()
	if f.RPTask.ID != setup.RP.Task || f.BMTask.ID != setup.BM.Task {
		return nil, fmt.Errorf("baseline requires fixtures prepared for this seed in a clean instance")
	}
	digests := map[string]string{}
	registry := filepath.Join(dir, "registry")
	for _, sub := range []string{"did", "certifications", "credentials", "grants"} {
		err := filepath.WalkDir(filepath.Join(registry, sub), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(raw), "PRIVATE KEY") {
				return fmt.Errorf("private material in public registry")
			}
			rel, err := filepath.Rel(registry, path)
			if err != nil {
				return err
			}
			digests[filepath.ToSlash(rel)] = api.Digest(raw)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	public, err := protocol.MarshalJCS(digests)
	if err != nil {
		return nil, err
	}
	snap := report.RegistrationSnapshot(d)
	snap.ExactIntervalBounds = true
	snap.ClockError = api.ClockError
	input, err := protocol.MarshalJCS(snap)
	if err != nil {
		return nil, err
	}
	return &baselineRegistration{Snapshot: snap, MaterialDigest: api.Digest(public), InputDigest: api.Digest(input)}, nil
}
