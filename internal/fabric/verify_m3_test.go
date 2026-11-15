package fabric

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This opt-in regression uses and mutates a deployed, seeded experimental Fabric instance.
func TestM3LiveAcceptance(t *testing.T) {
	dir := os.Getenv("FABRIC_M3_TEST_DIR")
	if dir == "" {
		t.Skip("set FABRIC_M3_TEST_DIR to a deployed experimental instance")
	}
	i, err := loadInstance(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := i.loadDeployment()
	if err != nil {
		t.Fatal(err)
	}
	db, err := i.database(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := i.peer("c", "read")
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	f, err := i.fixtures(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"authority", "offline", "agent", "e6", "faults", "management"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
			defer cancel()
			id := "run-" + randomID()[:16]
			out := filepath.Join(i.dir, "m3-regression", id)
			if err := os.MkdirAll(out, 0755); err != nil {
				t.Fatal(err)
			}
			logFile, err := os.Create(filepath.Join(out, "events.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			defer logFile.Close()
			a := acceptance{ctx: ctx, instance: i, d: d, f: f, p: p, id: id, dir: out,
				j: journal{instance: i, deploymentID: d.DeploymentID, db: db},
				v: view{db: db, d: d}, log: &evidenceLog{file: logFile}}
			t.Logf("evidence: %s", out)
			cases := map[string]func() error{"authority": a.m3AuthorityIdentityAndLifecycle, "management": a.m3ManagementHTTPRegression,
				"offline": func() error {
					_, err := a.verifyIsolatedM3CacheAndTOfflineChecks(time.Now().UTC().Truncate(time.Second))
					return err
				},
				"agent": a.m3AgentB2ReplacementAndReconcile, "e6": a.m3RevocationWindowE6, "faults": a.m3FaultInjectionE7}
			defer func() {
				captureCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				if err := a.exportBlocks(captureCtx); err != nil {
					t.Error(err)
				}
			}()
			if err := cases[name](); err != nil {
				t.Fatal(err)
			}
		})
	}
}
