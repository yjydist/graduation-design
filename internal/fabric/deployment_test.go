package fabric

import (
	"bytes"
	"context"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	api "graduation-design/internal/fabricapi"
)

func TestInitializationRetryRequiresRejectedUnsignedProposal(t *testing.T) {
	code := "ENDORSEMENT_REJECTED"
	now := time.Now()
	rejected := operation{
		Status: "FAILED", Stage: "ENDORSE", FailureCode: &code, Observation: "incorrect timestamp",
		TxID: api.Digest([]byte("original")), Proposal: []byte("signed proposal"),
	}
	if !rejected.rejectedBeforeSigning() {
		t.Fatal("a rejected unsigned operation should be eligible")
	}
	for _, tc := range []struct {
		name   string
		change func(*operation)
	}{
		{"pending", func(op *operation) { op.Status = "PENDING" }},
		{"commit stage", func(op *operation) { op.Stage = "COMMIT" }},
		{"no rejection code", func(op *operation) { op.FailureCode = nil }},
		{"no rejection observation", func(op *operation) { op.Observation = "" }},
		{"no original proposal", func(op *operation) { op.Proposal = nil }},
		{"signed transaction", func(op *operation) { op.Signed = []byte("signed transaction") }},
		{"signing recorded", func(op *operation) { op.SignedAt = &now }},
		{"broadcast recorded", func(op *operation) { op.BroadcastAt = &now }},
		{"commit recorded", func(op *operation) { op.Commit = &outcome{Code: "MVCC_READ_CONFLICT"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := rejected
			tc.change(&op)
			if op.rejectedBeforeSigning() {
				t.Fatal("operation must retain its original attempt")
			}
		})
	}
}

func TestInterruptedInitialization(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	p, d, raw, j := provisionInitializationTest(t, ctx, "FABRIC_INIT_RETRY_TEST_DIR")
	i, db := j.instance, j.db
	const key = "initialize/approved"
	if op, err := j.load(ctx, key, db); err != nil || op != nil {
		t.Fatalf("test requires an empty initialization journal: %v", err)
	}
	original := saveUnendorsedInitialization(t, ctx, p, j, key, raw)

	args := []string{"deploy", "--dir", i.dir}
	if err := Run(args, io.Discard); err == nil || !strings.Contains(err.Error(), "--retry-initialization") {
		t.Fatalf("ordinary deploy should report the rejected original operation and request explicit retry: %v", err)
	}
	rejected, err := j.load(ctx, key, db)
	if err != nil || rejected == nil || !rejected.rejectedBeforeSigning() ||
		!strings.Contains(rejected.Observation, "incorrect timestamp") ||
		rejected.TxID != original.TxID || !bytes.Equal(rejected.Proposal, original.Proposal) {
		t.Fatalf("original proposal was not preserved with its time-window rejection: %v", err)
	}
	t.Logf("original rejection: %s", rejected.Observation)
	retryKey := key + "/retry/" + original.TxID
	if op, err := j.load(ctx, retryKey, db); err != nil || op != nil {
		t.Fatalf("ordinary deploy created a new operation: %v", err)
	}
	if err := p.requireEmptyBootstrap(ctx); err != nil {
		t.Fatal(err)
	}

	retryArgs := append(args, "--retry-initialization")
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			if err := Run(retryArgs, io.Discard); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	confirmed, err := j.load(ctx, retryKey, db)
	if err != nil || confirmed == nil || confirmed.Status != "CONFIRMED" ||
		confirmed.Commit == nil || confirmed.Commit.Code != "VALID" ||
		confirmed.TxID == original.TxID || confirmed.InputDigest != original.InputDigest {
		t.Fatalf("explicit retry did not confirm the same input under a new operation: %v", err)
	}
	kept, err := j.load(ctx, key, db)
	if err != nil || !bytes.Equal(payload(kept), payload(rejected)) {
		t.Fatalf("explicit retry changed the rejected operation: %v", err)
	}
	var approvedAttempts int
	err = db.QueryRow(ctx, "SELECT count(*) FROM fabric_operation WHERE deployment=$1 AND (operation_key=$2 OR operation_key LIKE $3)",
		d.DeploymentID, key, key+"/retry/%").Scan(&approvedAttempts)
	if err != nil || approvedAttempts != 2 {
		t.Fatalf("expected one original and one retry, found %d: %v", approvedAttempts, err)
	}
	manifest, err := i.loadDeployment()
	if err != nil || manifest.DeploymentID != d.DeploymentID || manifest.InitBlock != confirmed.Commit.point {
		t.Fatalf("deployment manifest did not retain the instance and bind the confirmed retry: %v", err)
	}
	if err := p.requireEmptyBootstrap(ctx); err == nil || !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("initialized root must block a new initialization attempt: %v", err)
	}
	t.Logf("explicit retry confirmed once: key=%s txID=%s block=%d deployment=%s", confirmed.Key, confirmed.TxID, confirmed.Commit.Number, manifest.DeploymentID)
}

func TestDeploymentResumesAfterCommittedInitialization(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	p, d, raw, j := provisionInitializationTest(t, ctx, "FABRIC_INIT_COMMITTED_TEST_DIR")
	i := j.instance
	approved, err := j.write(ctx, "initialize/approved", "init", "Initialize", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := expectOperation(approved, "VALID"); err != nil {
		t.Fatal(err)
	}
	t.Logf("original initialization confirmed: txID=%s block=%d", approved.TxID, approved.Commit.Number)

	// Reproduce an older deploy stopping before its repeat-initialization proposal was endorsed.
	repeat := saveUnendorsedInitialization(t, ctx, p, j, "initialize/repeat", raw)
	if _, err := os.Stat(i.registryPath("deployment.json")); !os.IsNotExist(err) {
		t.Fatalf("deployment manifest already exists: %v", err)
	}
	height, err := p.height(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"deploy", "--dir", i.dir}, io.Discard); err != nil {
		t.Fatalf("deploy could not resume after the root committed: %v", err)
	}
	manifest, err := i.loadDeployment()
	if err != nil {
		t.Fatal(err)
	}
	if manifest.DeploymentID != d.DeploymentID || manifest.InitBlock != approved.Commit.point ||
		!maps.Equal(manifest.PackageIDs, d.PackageIDs) {
		t.Fatal("resumed manifest changed the deployment, original commit, or approved packages")
	}
	for _, original := range []*operation{approved, repeat} {
		kept, err := j.load(ctx, original.Key, j.db)
		if err != nil || !bytes.Equal(payload(kept), payload(original)) {
			t.Fatalf("deployment resume changed original operation %s: %v", original.Key, err)
		}
	}
	if now, err := p.height(ctx); err != nil || now != height {
		t.Fatalf("deployment resume changed Peer height from %d to %d: %v", height, now, err)
	}
	t.Logf("resumed deployment %s with original initialization block %d, unchanged height %d and original repeat proposal %s",
		manifest.DeploymentID, manifest.InitBlock.Number, height, repeat.TxID)
}

func provisionInitializationTest(t *testing.T, ctx context.Context, env string) (*peerClient, *deployment, []byte, journal) {
	t.Helper()
	dir := os.Getenv(env)
	if dir == "" {
		t.Skipf("set %s to a running empty Fabric instance", env)
	}
	t.Chdir(filepath.Join("..", ".."))
	i, err := loadInstance(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(i.registryPath("deployment.json")); !os.IsNotExist(err) {
		t.Fatalf("test requires a fresh instance without a deployment manifest: %v", err)
	}
	p, err := i.peer("c", "read")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.close)
	d, raw, err := i.provisionRegistry(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.requireEmptyBootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := i.database(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err := initSchema(ctx, db, operationsSchema); err != nil {
		t.Fatal(err)
	}
	return p, d, raw, journal{instance: i, deploymentID: d.DeploymentID, db: db}
}

func saveUnendorsedInitialization(t *testing.T, ctx context.Context, p *peerClient, j journal, key string, raw []byte) *operation {
	t.Helper()
	i := j.instance
	if _, err := i.run(ctx, "stop", "peer-c"); err != nil {
		t.Fatal(err)
	}
	peerStopped := true
	t.Cleanup(func() {
		if peerStopped {
			c, stop := context.WithTimeout(context.Background(), 20*time.Second)
			defer stop()
			if _, err := i.run(c, "start", "peer-c"); err != nil {
				t.Error(err)
			}
		}
	})
	original, err := j.prepare(ctx, key, "init", "Initialize", raw)
	if err != nil {
		t.Fatal(err)
	}
	if original.Status != "PENDING" || original.Stage != "ENDORSE" || len(original.Signed) != 0 {
		t.Fatalf("expected a pending proposal without a signed transaction, got %s/%s", original.Status, original.Stage)
	}
	t.Logf("proposal saved before endorsement: key=%s txID=%s", original.Key, original.TxID)
	timer := time.NewTimer(time.Until(original.AcceptedAt.Add(api.PeerTimeWindow + api.ClockError + time.Second)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	if _, err := i.run(ctx, "start", "peer-c"); err != nil {
		t.Fatal(err)
	}
	peerStopped = false
	if err := poll(ctx, 10*time.Second, func() (bool, error) {
		_, err := p.getBlock(ctx, 0)
		return err == nil, nil
	}); err != nil {
		t.Fatalf("C Peer did not come back online: %v", err)
	}
	return original
}
