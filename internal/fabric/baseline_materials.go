package fabric

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
)

// baselineRegistration contains public anchors only. Full presentations stay in the private instance database.
type baselineRegistration struct {
	Snapshot       *protocol.SnapshotView
	MaterialDigest string
	InputDigest    string
}

// baselineRegistration prepares the C0 input from the same fixtures submitted by seed.
func (i *instance) baselineRegistration(d *deployment, f *fixtures) (*baselineRegistration, error) {
	if i.baseline == nil {
		return nil, fmt.Errorf("baseline inputs required")
	}
	for _, task := range []api.Task{f.RPTask, f.BMTask} {
		want := api.Digest([]byte(d.DeploymentID + "/baseline/" + i.baseline.LogicalID(task.Mode, "") + "task"))
		if task.ID != want {
			return nil, fmt.Errorf("baseline requires fixtures prepared for this seed in a clean instance")
		}
	}
	digests := map[string]string{}
	for _, sub := range []string{"did", "certifications", "credentials", "grants"} {
		err := filepath.WalkDir(i.registrySubPath(sub), func(path string, entry os.DirEntry, err error) error {
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
			rel, err := filepath.Rel(i.registrySubPath(), path)
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
	snap := fixtureSnapshot(d, f, time.Time{})
	snap.ExactIntervalBounds = true
	snap.ClockError = api.ClockError
	input, err := protocol.MarshalJCS(snap)
	if err != nil {
		return nil, err
	}
	return &baselineRegistration{Snapshot: snap, MaterialDigest: api.Digest(public), InputDigest: api.Digest(input)}, nil
}
