package fabric

import (
	"encoding/json"
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
	AnchorDigest   string
	PublicDigests  map[string]string
}

// baselineRegistrations derives two independent inputs from the same real signed materials.
// The Fabric input was submitted by seed; the C0 input is for its trusted preloader.
func (i *instance) baselineRegistrations(d *deployment, f *fixtures) (*baselineRegistration, *baselineRegistration, error) {
	if i.baseline == nil {
		return nil, nil, fmt.Errorf("baseline inputs required")
	}
	for _, task := range []api.Task{f.RPTask, f.BMTask} {
		want := api.Digest([]byte(d.DeploymentID + "/baseline/" + i.baseline.LogicalID(task.Mode, "") + "task"))
		if task.ID != want {
			return nil, nil, fmt.Errorf("baseline requires fixtures prepared for this seed in a clean instance")
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
			return nil, nil, err
		}
	}
	public, err := protocol.MarshalJCS(digests)
	if err != nil {
		return nil, nil, err
	}
	snap := fixtureSnapshot(d, f, time.Time{})
	snap.ExactIntervalBounds = true
	snap.ClockError = api.ClockError
	anchors, err := protocol.MarshalJCS(snap)
	if err != nil {
		return nil, nil, err
	}
	one := &baselineRegistration{snap, api.Digest(public), api.Digest(anchors), digests}
	// Do not share mutable maps between the two registration writers.
	raw, err := json.Marshal(one)
	if err != nil {
		return nil, nil, err
	}
	var two baselineRegistration
	if err = json.Unmarshal(raw, &two); err != nil {
		return nil, nil, err
	}
	return one, &two, nil
}
