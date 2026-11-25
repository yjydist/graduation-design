package baseline

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"grad/platform/bootstrap"
	"grad/platform/core/ledger"
	"grad/protocol"
	"grad/protocol/registry"
)

func baselineProcurement(deploymentID string, in *Inputs) bootstrap.ProcurementSetup {
	ids := func(mode string) bootstrap.ProcurementPathIDs {
		namespace := deploymentID + "/baseline/" + in.LogicalID(mode, "")
		return bootstrap.ProcurementPathIDs{
			Task: registry.Digest([]byte(namespace + "task")),
			G0:   registry.Digest([]byte(namespace + "G0")),
			G1:   registry.Digest([]byte(namespace + "G1")),
			G2:   registry.Digest([]byte(namespace + "G2")),
		}
	}
	return bootstrap.ProcurementSetup{
		Spec: protocol.TaskSpec{
			SupplierID:  in.Fixture.Supplier,
			ProductID:   in.Fixture.Product,
			MaxQuantity: in.Fixture.Quantity,
			Currency:    in.Fixture.Currency,
			Resources:   []string{protocol.ResourceOrders, protocol.ResourceQuotes},
			Actions:     slices.Sorted(slices.Values(in.Fixture.Actions)),
			Description: "Paired baseline procurement",
		},
		RP: ids(registry.RP),
		BM: ids(registry.BM),
	}
}

// baselineRegistration contains public anchors only. Full presentations stay in the private instance database.
type baselineRegistration struct {
	Snapshot       *protocol.SnapshotView
	MaterialDigest string
	InputDigest    string
}

// prepareRegistration prepares the C0 preload snapshot from the exact fixtures submitted to Fabric.
func prepareRegistration(dir string, d *ledger.Deployment, report *bootstrap.SeedReport, setup bootstrap.ProcurementSetup) (*baselineRegistration, error) {
	f := report.Fixtures()
	if f.RPTask.ID != setup.RP.Task || f.BMTask.ID != setup.BM.Task {
		return nil, fmt.Errorf("baseline requires fixtures prepared for this seed in a clean instance")
	}
	digests := map[string]string{}
	regDir := filepath.Join(dir, "registry")
	for _, sub := range []string{"did", "certifications", "credentials", "grants"} {
		err := filepath.WalkDir(filepath.Join(regDir, sub), func(path string, entry os.DirEntry, err error) error {
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
			rel, err := filepath.Rel(regDir, path)
			if err != nil {
				return err
			}
			digests[filepath.ToSlash(rel)] = registry.Digest(raw)
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
	snap.ClockError = registry.ClockError
	input, err := protocol.MarshalJCS(snap)
	if err != nil {
		return nil, err
	}
	return &baselineRegistration{
		Snapshot:       snap,
		MaterialDigest: registry.Digest(public),
		InputDigest:    registry.Digest(input),
	}, nil
}
