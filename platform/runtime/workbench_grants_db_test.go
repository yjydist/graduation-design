//go:build db

package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset/kvrwset"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/stretchr/testify/require"

	"grad/platform/agent"
	"grad/platform/internal/testutil"
	"grad/platform/registrysvc"
	"grad/platform/state/fabric"
	"grad/platform/workbench"
	"grad/protocol"
	"grad/protocol/registry"
)

func TestWorkbenchGrantIssueAndDeliveryUseOriginalCommitAndActualTask(t *testing.T) {
	ctx := t.Context()
	dbA, dbB, dbC := testutil.OpenMigratedPool(t), testutil.OpenMigratedPool(t), testutil.OpenMigratedPool(t)
	inst, dep := newOfflineInstanceAndDeployment(t)
	f, err := PrepareFixtures(inst, dep, nil)
	require.NoError(t, err)
	now := time.Now().UTC()
	clock := func() time.Time { return now }
	snap := BuildFixtureSnapshot(dep, f, now)
	spec := f.ProcurementTaskSpec
	spec.Description = "verifiable dynamically confirmed task"
	run := workbench.Run{RunID: registry.Digest([]byte("original run")), Stage: workbench.StageDispatch, Status: workbench.RunPending}
	run.TaskID = registry.Digest([]byte(dep.DeploymentID + "/workbench/" + run.RunID))
	task := snap.Tasks[f.RPTask.ID]
	task.ID = run.TaskID
	task.Digest, err = spec.Digest()
	require.NoError(t, err)
	task.Interval = registry.Interval{NBF: now.Add(-time.Minute).Unix(), EXP: now.Add(15 * time.Minute).Unix()}
	run.Task = workbench.Draft{ProductID: spec.ProductID, Quantity: spec.MaxQuantity, Mode: task.Mode,
		MaxAmountMinor: 100000, ExpiresAt: task.EXP, DelegateDID: f.Identities["A1"].ID, Description: spec.Description}

	certs := map[string]string{}
	for _, dom := range []string{"A", "B", "C"} {
		raw, err := os.ReadFile(inst.RegistryPath("certifications", dom+".jws"))
		require.NoError(t, err)
		certs[dom] = string(raw)
	}

	records := map[string]any{registry.BootstrapKey: dep.Bootstrap, registry.Key("task", task.ID): task}
	for id, rec := range snap.Domains {
		records[registry.Key("domain", id)] = rec
	}
	for id, rec := range snap.Certifications {
		records[registry.Key("certification", id)] = rec
	}
	for id, rec := range snap.Identities {
		records[registry.Key("identity", id)] = rec
	}
	for id, rec := range snap.Credentials {
		records[registry.Key("credential", id)] = rec
	}
	viewA := fabric.View{DB: dbA, Deployment: dep}
	viewB := fabric.View{DB: dbB, Deployment: dep}
	viewC := fabric.View{DB: dbC, Deployment: dep}
	initialTx := registry.Digest([]byte("confirmed task and identity state"))
	for _, v := range []fabric.View{viewA, viewB, viewC} {
		require.NoError(t, v.Apply(ctx, &fabric.Block{
			Point: fabric.Point{Number: 0, Hash: dep.GenesisHash}, ConfigDigest: dep.ConfigDigest, Raw: &cb.Block{},
		}, nil))
		require.NoError(t, v.Apply(ctx, &fabric.Block{
			Point: dep.DefinitionBlock, Parent: dep.GenesisHash, Raw: &cb.Block{},
		}, nil))
		require.NoError(t, v.Apply(ctx, testRegistryBlock(t, dep.InitBlock, dep.DefinitionBlock.Hash, initialTx, records), nil))
	}

	rec := func(actor string) GrantRecipient {
		return GrantRecipient{DID: f.Identities[actor].ID, CredentialID: f.Credentials[actor].ID}
	}
	loadActor := func(actor string) GrantActor {
		id, credential := f.Identities[actor], f.Credentials[actor]
		priv, err := fabric.LoadECPrivateKeyPEM(inst.PrivatePath("app", actor+".key.pem"))
		require.NoError(t, err)
		raw, err := os.ReadFile(inst.RegistryPath("credentials", actor+".sdjwt"))
		require.NoError(t, err)
		return GrantActor{Management: id.Management, Signer: agent.Signer{
			Actor: actor, DomainID: id.Domain, DID: id.ID, KeyID: id.KeyID, KeyVersion: id.KeyVersion,
			CredentialID: credential.ID, PrivateKey: priv, SDJWTPresentation: string(raw),
		}}
	}

	mgmtC := registrysvc.NewService(dbC, dep.DeploymentID, dep.Bootstrap.Root.Management, nil)
	gC, err := NewGrantOperations(GrantOperationsConfig{
		Deployment: dep, DomainID: "C", DB: dbC, Management: mgmtC, Certifications: certs, Now: clock,
		Actors: map[string]GrantActor{"C": loadActor("C")},
	})
	require.NoError(t, err)
	mgmtA := registrysvc.NewService(dbA, dep.DeploymentID, dep.Bootstrap.Root.Management, nil)
	gA, err := NewGrantOperations(GrantOperationsConfig{
		Deployment: dep, DomainID: "A", DB: dbA, Management: mgmtA, Certifications: certs, Now: clock,
		Actors: map[string]GrantActor{"U": loadActor("U"), "PA": loadActor("PA"), "A1": loadActor("A1")},
	})
	require.NoError(t, err)

	req := RootGrantRequest{
		GrantID: run.GrantID("G0"), TaskID: task.ID, Recipient: rec("U"),
		TaskSpec: spec, MaxAmountMinor: 100000, Depth: 2,
	}
	const key = "actual-g0"
	_, _, err = gA.IssueRoot(ctx, "PA", key, req)
	require.True(t, protocol.HasCode(err, registry.ErrCodeRootAuthorityInvalid), "%v", err)
	op, delivery, err := gC.IssueRoot(ctx, "C", key, req)
	require.NoError(t, err)
	require.Equal(t, "PENDING", op.Status)
	require.Nil(t, delivery)
	_, err = gA.Load(ctx, rec("U"), req.GrantID)
	require.True(t, protocol.HasCode(err, registry.ErrCodeMaterialNotSynced), "%v", err)
	_, err = gC.Published(ctx, rec("U"), req.GrantID)
	require.True(t, protocol.HasCode(err, registry.ErrCodeMaterialNotSynced), "%v", err)

	var storedJWS string
	require.NoError(t, dbC.QueryRow(ctx, "SELECT grant_jws FROM workbench_grant_issue WHERE grant_id=$1", req.GrantID).Scan(&storedJWS))
	parsed, err := protocol.ParseAndVerifyGrant(storedJWS, &gC.cfg.Actors["C"].Signer.PrivateKey.PublicKey, f.Identities["C"].KeyID)
	require.NoError(t, err)
	txID := registry.Digest([]byte("original valid root transaction"))
	point := fabric.Point{Number: 3, Hash: registry.Digest([]byte("original root block"))}
	commit := &fabric.Outcome{Point: point, Code: "VALID", ObservedPeer: "peer0.c.local", Index: 0}
	require.NoError(t, mgmtC.RecordOutcome(ctx, op.OperationID, "COMMIT", "CONFIRMED", txID, commit, nil, false))

	_, delivery, err = gC.IssueRoot(ctx, "C", key, req)
	require.True(t, protocol.HasCode(err, registry.ErrCodeMaterialNotSynced), "%v", err)
	require.Nil(t, delivery)
	anchor := ledgerGrant(parsed)
	anchor.Version = registry.Version{Status: registry.Active, Revision: 1}
	block := testRegistryBlock(t, point, dep.InitBlock.Hash, txID, map[string]any{registry.Key("grant", anchor.ID): anchor})
	require.NoError(t, viewC.Apply(ctx, block, nil))
	require.NoError(t, viewB.Apply(ctx, block, nil))

	actual, delivery, err := gC.IssueRoot(ctx, "C", key, req)
	require.NoError(t, err)
	require.NotNil(t, delivery)
	require.Equal(t, op.OperationID, actual.OperationID)
	require.Equal(t, storedJWS, delivery.Package.GrantJWS)
	require.Equal(t, spec, delivery.Package.TaskSpec)
	_, _, err = gA.Receive(ctx, rec("U"), *delivery)
	require.True(t, protocol.HasCode(err, registry.ErrCodeMaterialNotSynced), "%v", err)
	require.NoError(t, viewA.Apply(ctx, block, nil))
	_, _, err = gA.Receive(ctx, rec("A1"), *delivery)
	require.True(t, protocol.HasCode(err, registry.ErrCodeBindingMismatch), "%v", err)
	_, err = gA.Load(ctx, rec("U"), req.GrantID)
	require.True(t, protocol.HasCode(err, registry.ErrCodeMaterialNotSynced), "%v", err)
	childID := run.GrantID("G1")
	signChild := func(parent agent.GrantBundle, issuer, recipient, id string, depth int) agent.AnchorChildGrantRequest {
		t.Helper()
		var signed agent.AnchorChildGrantRequest
		wallet, err := agent.NewWalletContext(agent.WalletConfig{
			DeploymentID: dep.DeploymentID, Now: clock,
			AnchorChildFunc: func(_ context.Context, req agent.AnchorChildGrantRequest) (*agent.AnchorChildGrantResult, error) {
				signed = req
				return &agent.AnchorChildGrantResult{}, nil
			},
		})
		require.NoError(t, err)
		require.NoError(t, wallet.RegisterActor(loadActor(issuer).Signer))
		require.NoError(t, wallet.RegisterActor(loadActor(recipient).Signer))
		require.NoError(t, wallet.AddGrantBundle(parent))
		_, err = wallet.DelegateGrant(ctx, agent.DelegateGrantInput{
			IssuerActor: issuer, SubjectActor: recipient, ParentGrantID: parent.Claims.ID, GrantID: id,
			MaxAmountMinor: 95000, RemainingDepth: depth,
		})
		require.NoError(t, err)
		return signed
	}
	withoutReceipt := signChild(agent.GrantBundle{Claims: parsed.Claims, RawGrantJWS: parsed.Raw, TaskSpec: spec}, "U", "A1", childID, 1)
	childOp, childDelivery, err := gA.PublishChild(ctx, withoutReceipt)
	require.True(t, protocol.HasCode(err, registry.ErrCodeMaterialNotSynced), "%v", err)
	require.Nil(t, childOp)
	require.Nil(t, childDelivery)

	bundle, receipt, err := gA.Receive(ctx, rec("U"), *delivery)
	require.NoError(t, err)
	require.Equal(t, delivery.Digest, receipt)
	require.Equal(t, task.ID, bundle.Claims.TaskID)
	require.Equal(t, spec, bundle.TaskSpec)
	require.NoError(t, gC.MarkReceived(ctx, *delivery, receipt))

	replay, err := gC.Published(ctx, rec("U"), req.GrantID)
	require.NoError(t, err)
	require.True(t, replay.Operation.Delivered)
	require.Equal(t, actual.OperationID, replay.Operation.OperationID)
	require.Equal(t, txID, replay.Operation.TxID)
	require.Equal(t, delivery.Digest, replay.Digest)
	_, secondReceipt, err := gA.Receive(ctx, rec("U"), *replay)
	require.NoError(t, err)
	require.Equal(t, receipt, secondReceipt)

	signedChild := signChild(bundle, "U", "A1", childID, 1)
	childOp, childDelivery, err = gA.PublishChild(ctx, signedChild)
	require.NoError(t, err)
	require.Equal(t, "PENDING", childOp.Status)
	require.Nil(t, childDelivery)
	child, err := protocol.ParseAndVerifyGrant(signedChild.RawGrantJWS, &gA.cfg.Actors["U"].Signer.PrivateKey.PublicKey, f.Identities["U"].KeyID)
	require.NoError(t, err)
	childAnchor := ledgerGrant(child)
	childAnchor.Version = registry.Version{Status: registry.Active, Revision: 1}
	childTx := registry.Digest([]byte("original valid child transaction"))
	childPoint := fabric.Point{Number: 4, Hash: registry.Digest([]byte("original child block"))}
	commit = &fabric.Outcome{Point: childPoint, Code: "VALID", ObservedPeer: "peer0.a.local", Index: 0}
	require.NoError(t, mgmtA.RecordOutcome(ctx, childOp.OperationID, "COMMIT", "CONFIRMED", childTx, commit, nil, false))
	block = testRegistryBlock(t, childPoint, point.Hash, childTx, map[string]any{registry.Key("grant", childID): childAnchor})
	require.NoError(t, viewA.Apply(ctx, block, nil))
	require.NoError(t, viewB.Apply(ctx, block, nil))
	childRetry, childDelivery, err := gA.ResumeChild(ctx, "U", childID)
	require.NoError(t, err)
	require.Equal(t, childOp.OperationID, childRetry.OperationID)
	require.Equal(t, childTx, childRetry.TxID)
	require.Equal(t, child.Raw, childDelivery.Package.GrantJWS)
	require.Equal(t, []string{storedJWS}, childDelivery.Package.AncestorGrants)
	_, rerun, err := gA.PublishChild(ctx, signChild(bundle, "U", "A1", childID, 1))
	require.NoError(t, err)
	require.Equal(t, childDelivery.Digest, rerun.Digest)
	childBundle, _, err := gA.Receive(ctx, rec("A1"), *childDelivery)
	require.NoError(t, err)
	require.Len(t, childBundle.AncestorCredentials, 2)
	require.Equal(t, int64(95000), childBundle.Claims.MaxAmountMinor)

	g2 := signChild(childBundle, "A1", "B1", run.GrantID("G2"), 0)
	operation, _, err := gA.PublishChild(ctx, g2)
	require.NoError(t, err)
	leaf, err := protocol.ParseAndVerifyGrant(g2.RawGrantJWS, &gA.cfg.Actors["A1"].Signer.PrivateKey.PublicKey, f.Identities["A1"].KeyID)
	require.NoError(t, err)
	g2Anchor := ledgerGrant(leaf)
	g2Anchor.Version = registry.Version{Status: registry.Active, Revision: 1}
	g2Tx := registry.Digest([]byte("original valid G2 transaction"))
	g2Point := fabric.Point{Number: 5, Hash: registry.Digest([]byte("original G2 block"))}
	require.NoError(t, mgmtA.RecordOutcome(ctx, operation.OperationID, "COMMIT", "CONFIRMED", g2Tx,
		&fabric.Outcome{Point: g2Point, Code: "VALID", ObservedPeer: "peer0.a.local", Index: 0}, nil, false))
	block = testRegistryBlock(t, g2Point, childPoint.Hash, g2Tx, map[string]any{registry.Key("grant", g2Anchor.ID): g2Anchor})
	require.NoError(t, viewA.Apply(ctx, block, nil))
	require.NoError(t, viewB.Apply(ctx, block, nil))
	_, g2Delivery, err := gA.ResumeChild(ctx, "A1", g2Anchor.ID)
	require.NoError(t, err)
	require.NotNil(t, g2Delivery)
	mgmtB := registrysvc.NewService(dbB, dep.DeploymentID, dep.Bootstrap.Root.Management, nil)
	gB, err := NewGrantOperations(GrantOperationsConfig{
		Deployment: dep, DomainID: "B", DB: dbB, Management: mgmtB, Certifications: certs, Now: clock,
		Actors: map[string]GrantActor{"B1": loadActor("B1")},
	})
	require.NoError(t, err)
	actors := map[string]workbenchActor{
		"A1": {DID: rec("A1").DID, CredentialID: rec("A1").CredentialID},
		"B1": {DID: rec("B1").DID, CredentialID: rec("B1").CredentialID},
	}
	fingerprint := registry.Digest([]byte("A domain mTLS"))
	b := &domainWorkbench{dep: dep, db: dbB, grants: gB, cfg: workbenchConfig{
		DomainID: "B", Actors: actors, Peers: map[string]workbenchPeer{"A": {Fingerprint: fingerprint}},
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+workbenchDispatchPath, b.fromDomain("A", b.acceptDispatch))
	mux.HandleFunc("GET "+workbenchDispatchPath+"/{runId}", b.fromDomain("A", b.dispatchStatus))
	a := &domainWorkbench{dep: dep, grants: gA, cfg: workbenchConfig{
		DomainID: "A", Actors: actors, Peers: map[string]workbenchPeer{"B": {URL: "https://workbench-b:8081"}},
	}}
	role, did := workbenchTransportRole("A")
	client := NewLocalMTLSClientWithFingerprint(mux, did, role, "AMsp", fingerprint)
	a.clients = map[string]*http.Client{"B": client}

	// A has no receipt because the first accepted POST response did not reach it.
	require.NoError(t, a.callPeer(ctx, "B", http.MethodPost, workbenchDispatchPath,
		dispatchInput{Run: dispatchRun{RunID: run.RunID, TaskID: run.TaskID, Task: run.Task}, Delivery: *g2Delivery}, nil))
	publication, err := gA.Published(ctx, rec("B1"), g2Anchor.ID)
	require.NoError(t, err)
	require.False(t, publication.Operation.Delivered)

	childAnchor.Version = registry.Version{Status: registry.Suspended, Revision: 2}
	pausedPoint := fabric.Point{Number: 6, Hash: registry.Digest([]byte("paused child block"))}
	block = testRegistryBlock(t, pausedPoint, g2Point.Hash, registry.Digest([]byte("pause child")), map[string]any{registry.Key("grant", childID): childAnchor})
	require.NoError(t, viewA.Apply(ctx, block, nil))
	_, err = gA.Load(ctx, rec("A1"), childID)
	require.True(t, protocol.HasCode(err, registry.ErrCodeAncestorInactive), "%v", err)
	retained, err := gA.LoadRetained(ctx, rec("A1"), childID)
	require.NoError(t, err)
	require.Equal(t, childBundle.RawGrantJWS, retained.RawGrantJWS)

	now = time.Unix(task.EXP, 0).UTC()
	_, err = gA.Load(ctx, rec("U"), req.GrantID)
	require.True(t, protocol.HasCode(err, registry.ErrCodeAncestorInactive), "%v", err)
	retained, err = gA.LoadRetained(ctx, rec("A1"), childID)
	require.NoError(t, err)
	require.Equal(t, childBundle.RawGrantJWS, retained.RawGrantJWS)

	now = now.Add(3 * time.Second)
	owner := dep.Bootstrap.TaskCreator.Subject
	a.clients["B"] = NewLocalMTLSClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		workbench.WriteError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "dispatcher unavailable")
	}), did, role, "AMsp")
	step, err := a.Advance(ctx, owner, run)
	require.True(t, protocol.HasCode(err, registry.ErrCodeStateUnavailable), "%v", err)
	require.Equal(t, workbench.RunPending, step.Status)
	a.clients["B"] = client
	step, err = a.Advance(ctx, owner, run)
	require.NoError(t, err)
	require.Equal(t, workbench.RunPending, step.Status)
	require.Equal(t, operation.OperationID, step.Operation.OperationID)
	require.Equal(t, g2Tx, step.Operation.TxID)
	publication, err = gA.Published(ctx, rec("B1"), g2Anchor.ID)
	require.NoError(t, err)
	require.True(t, publication.Operation.Delivered)

	for _, status := range []string{workbench.RunUnknown, workbench.RunDecided} {
		_, err := dbB.Exec(ctx, `UPDATE workbench_dispatch SET status=$3,result=$4 WHERE deployment_id=$1 AND run_id=$2`,
			dep.DeploymentID, run.RunID, status, dispatchResult{Receipt: g2Delivery.Digest, Status: status})
		require.NoError(t, err)
		step, err := a.Advance(ctx, owner, run)
		require.NoError(t, err)
		require.Equal(t, status, step.Status)
		run.Status = status
	}

	// Late probe traces are read from B's persisted log after the dispatch reaches a terminal state.
	trace := agent.ToolTrace{ToolName: "request_quote", Output: map[string]any{"decision": "DENY", "errorCode": registry.ErrCodeAncestorInactive}}
	require.NoError(t, b.storeTrace(ctx, run.RunID, trace))
	traces, err := a.DispatchTraces(ctx, run)
	require.NoError(t, err)
	require.Equal(t, []agent.ToolTrace{trace}, traces)

	missing := run
	missing.RunID = registry.Digest([]byte("run never accepted"))
	missing.TaskID = registry.Digest([]byte(dep.DeploymentID + "/workbench/" + missing.RunID))
	missing.Status = workbench.RunPending
	step, err = a.Advance(ctx, owner, missing)
	require.NoError(t, err)
	require.Equal(t, workbench.RunFailed, step.Status)
	require.Equal(t, registry.ErrCodeTaskInactive, step.Code)
}

func testRegistryBlock(t *testing.T, point fabric.Point, parent, txID string, records map[string]any) *fabric.Block {
	t.Helper()
	writes := make([]*kvrwset.KVWrite, 0, len(records))
	for key, value := range records {
		raw, err := json.Marshal(value)
		require.NoError(t, err)
		writes = append(writes, &kvrwset.KVWrite{Key: key, Value: raw})
	}
	return &fabric.Block{
		Point: point, Parent: parent, Raw: &cb.Block{},
		Transactions: []fabric.BlockTx{{Index: 0, ID: txID, Code: pb.TxValidationCode_VALID, Writes: writes}},
	}
}
