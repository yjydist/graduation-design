package fabric

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/protocol"
	"graduation-design/internal/serviceauth"
)

type stubOpBackend struct {
	revision    uint64
	exists      bool
	revErr      error
	submitCalls int
}

func (b *stubOpBackend) CurrentRevision(ctx context.Context, method string, input json.RawMessage) (uint64, bool, error) {
	return b.revision, b.exists, b.revErr
}

func (b *stubOpBackend) SubmitAsync(
	ctx context.Context,
	opKey, opID string,
	caller api.Management,
	method string,
	input json.RawMessage,
	onUpdate func(stage, status string, txID string, blockNo int64, blockHash string, valCode, failCode *string, delivered bool) error,
) {
	b.submitCalls++
}

func TestM3ManagementOperationAsyncStateMachine(t *testing.T) {
	pool := testPgPool(t)
	ctx := context.Background()
	depID := strings.Repeat("d", 63) + "1"

	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM operations WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(ctx, `DELETE FROM recovery_challenges WHERE deployment_id=$1`, depID)
	}
	cleanup()
	t.Cleanup(cleanup)

	backend := &stubOpBackend{revision: 2, exists: true}
	rootMgmt := api.Management{MSPID: "AMsp", Fingerprint: strings.Repeat("f", 64)}
	svc := NewManagementOperationService(pool, depID, rootMgmt, backend)
	caller := api.Management{MSPID: "AMsp", Fingerprint: strings.Repeat("a", 64)}

	// 1. Pre-acceptance stale expectedRevision -> 409 STATE_CHANGED with ZERO rows in operations (S100).
	staleInput := json.RawMessage(`{"id":"did:web:a.local:u","expectedRevision":1}`)
	code, _, err := svc.Accept(ctx, "op-stale-1", caller, "RotateIdentity", staleInput, true)
	if code != http.StatusConflict || !protocol.HasCode(err, protocol.ErrCodeStateChanged) {
		t.Fatalf("expected 409 STATE_CHANGED for stale revision, got code=%d err=%v", code, err)
	}
	if backend.submitCalls != 0 {
		t.Fatalf("expected zero backend submissions on pre-acceptance 409, got %d", backend.submitCalls)
	}
	var opCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM operations WHERE deployment_id=$1`, depID).Scan(&opCount); err != nil || opCount != 0 {
		t.Fatalf("expected 0 rows in operations after pre-acceptance 409, got %d (err=%v)", opCount, err)
	}

	// 2. Two distinct operationKeys both pass expectedRevision=2 -> both 202 (S100).
	inA := json.RawMessage(`{"id":"did:web:a.local:u","expectedRevision":2,"keyId":"k2","publicKey":"04` + strings.Repeat("1", 128) + `"}`)
	inB := json.RawMessage(`{"id":"did:web:a.local:u","expectedRevision":2,"keyId":"k3","publicKey":"04` + strings.Repeat("2", 128) + `"}`)
	c1, v1, err := svc.Accept(ctx, "op-conc-1", caller, "RotateIdentity", inA, true)
	if err != nil || c1 != http.StatusAccepted || v1.OperationID == "" {
		t.Fatalf("expected 202 accept for op-conc-1, got %d %v", c1, err)
	}
	c2, v2, err := svc.Accept(ctx, "op-conc-2", caller, "RotateIdentity", inB, true)
	if err != nil || c2 != http.StatusAccepted || v2.OperationID == "" {
		t.Fatalf("expected 202 accept for op-conc-2, got %d %v", c2, err)
	}

	// Exact idempotent retry -> 202 same operationId; same key different body -> 409 IDEMPOTENCY_CONFLICT (S101).
	c1Retry, v1Retry, err := svc.Accept(ctx, "op-conc-1", caller, "RotateIdentity", inA, false)
	if err != nil || c1Retry != http.StatusAccepted || v1Retry.OperationID != v1.OperationID {
		t.Fatalf("expected idempotent 202 same operationId, got %d %+v err=%v", c1Retry, v1Retry, err)
	}
	c1Conflict, _, err := svc.Accept(ctx, "op-conc-1", caller, "RotateIdentity", inB, false)
	if c1Conflict != http.StatusConflict || !protocol.HasCode(err, protocol.ErrCodeIdempotencyConflict) {
		t.Fatalf("expected 409 IDEMPOTENCY_CONFLICT on mutated payload retry, got %d %v", c1Conflict, err)
	}

	// Visibility suppression -> GET /v1/operations/{id} returns PENDING/null until visibility restored (S101).
	svc.SetVisibilitySuppressed(v1.OperationID, true)
	valCode := "VALID"
	blkHash := strings.Repeat("9", 64)
	if err := svc.RecordOutcome(ctx, v1.OperationID, "COMMITTED", "CONFIRMED", "tx-win-1", 10, blkHash, &valCode, nil, true); err != nil {
		t.Fatalf("RecordOutcome winner: %v", err)
	}
	mvccCode := "MVCC_READ_CONFLICT"
	failState := protocol.ErrCodeStateChanged
	if err := svc.RecordOutcome(ctx, v2.OperationID, "COMMITTED", "FAILED", "tx-lose-2", 11, blkHash, &mvccCode, &failState, false); err != nil {
		t.Fatalf("RecordOutcome loser: %v", err)
	}

	h := svc.Handler()
	req := httptest.NewRequest(http.MethodGet, "/v1/operations/"+v1.OperationID, nil)
	req = req.WithContext(serviceauth.WithIdentity(req.Context(), serviceauth.Identity{Role: "MANAGEMENT", MSPID: caller.MSPID, Fingerprint: caller.Fingerprint}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 during suppression, got %d %s", rec.Code, rec.Body.String())
	}
	var suppressedView OperationView
	if err := json.Unmarshal(rec.Body.Bytes(), &suppressedView); err != nil {
		t.Fatal(err)
	}
	if suppressedView.Status != "PENDING" || suppressedView.ErrorCode != nil {
		t.Fatalf("expected PENDING/null while visibility suppressed, got %+v", suppressedView)
	}

	// Restore visibility and check DUPLICATE_TXID non-overwrite (S101).
	svc.SetVisibilitySuppressed(v1.OperationID, false)
	dupFail := "COMMIT_INVALID"
	if err := svc.RecordOutcome(ctx, v1.OperationID, "COMMITTED", "FAILED", "tx-win-dup", 99, blkHash, &dupFail, &dupFail, false); err != nil {
		t.Fatalf("RecordOutcome duplicate overwrite attempt: %v", err)
	}
	got1, err := svc.GetOperation(ctx, v1.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if got1.Status != "CONFIRMED" || got1.ErrorCode != nil || got1.TxID != "tx-win-1" || got1.BlockNumber != 10 || !got1.Delivered {
		t.Fatalf("CONFIRMED outcome must not be overwritten by DUPLICATE_TXID/retry; got %+v", got1)
	}
	got2, err := svc.GetOperation(ctx, v2.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if got2.Status != "FAILED" || got2.ErrorCode == nil || *got2.ErrorCode != protocol.ErrCodeStateChanged || got2.ValidationCode == nil || *got2.ValidationCode != "MVCC_READ_CONFLICT" || got2.Delivered {
		t.Fatalf("loser op mismatch: got %+v", got2)
	}
}

func TestM3RecoveryChallengeAndBundle(t *testing.T) {
	f := newRecoveryServiceFixture(t)
	ctx := t.Context()
	raw, _ := json.Marshal(f.bundle)
	// An unapproved certificate must not consume the server challenge.
	original := f.backend.certificate
	_, other, _ := makeSelfSignedUserCert(t, "other", time.Now())
	f.backend.certificate = other
	if code, _, err := f.svc.Accept(ctx, "bad-cert", f.caller, "RecoverIdentity", raw, false); code != 403 || !protocol.HasCode(err, protocol.ErrCodeSignatureInvalid) {
		t.Fatalf("unapproved certificate: %d %v", code, err)
	}
	f.backend.certificate = original
	code, view, err := f.svc.Accept(ctx, "recover", f.caller, "RecoverIdentity", raw, false)
	if err != nil || code != 202 {
		t.Fatalf("admission: %d %v", code, err)
	}
	if err := f.svc.ResumePending(ctx); err != nil {
		t.Fatal(err)
	}
	<-f.backend.calls
	result, err := f.svc.GetOperation(ctx, view.OperationID)
	if err != nil || result.Status != "CONFIRMED" {
		t.Fatalf("result: %+v %v", result, err)
	}
	if code, retry, err := f.svc.Accept(ctx, "recover", f.caller, "RecoverIdentity", raw, true); err != nil || code != 202 || retry.OperationID != view.OperationID {
		t.Fatalf("retry: %d %+v %v", code, retry, err)
	}
	if code, _, err := f.svc.Accept(ctx, "other-key", f.caller, "RecoverIdentity", raw, false); code != 403 || !protocol.HasCode(err, protocol.ErrCodeChallengeReplay) {
		t.Fatalf("challenge replay: %d %v", code, err)
	}
}

func TestM3HistoricalSnapshotAndFindInactiveBlock(t *testing.T) {
	pool := testPgPool(t)
	ctx := context.Background()
	now := time.Now().UTC()
	depFields := api.DeploymentFields{
		ChannelID:     api.Channel,
		GenesisHash:   strings.Repeat("1", 64),
		InstanceID:    strings.Repeat("2", 64),
		RegistryName:  api.Registry,
		SchemaVersion: api.Schema,
	}
	boot := api.Bootstrap{
		DeploymentFields: depFields,
		Root: api.RootRecord{
			DID:            "did:web:t.local",
			Management:     api.Management{MSPID: "TMsp", Fingerprint: strings.Repeat("f", 64)},
			DocumentDigest: strings.Repeat("a", 64),
			KeyID:          "did:web:t.local#key-1",
			KeyVersion:     1,
			PublicKey:      "04" + strings.Repeat("1", 128),
		},
	}
	depID := depFields.ID()

	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM fabric_current WHERE deployment=$1`, depID)
		_, _ = pool.Exec(ctx, `DELETE FROM fabric_version WHERE deployment=$1`, depID)
		_, _ = pool.Exec(ctx, `DELETE FROM fabric_block WHERE deployment=$1`, depID)
		_, _ = pool.Exec(ctx, `DELETE FROM fabric_head WHERE deployment=$1`, depID)
	}
	cleanup()
	t.Cleanup(cleanup)

	rawBoot, _ := json.Marshal(boot)
	b0Hash := strings.Repeat("a", 64)
	b1Hash := strings.Repeat("b", 64)
	b2Hash := strings.Repeat("c", 64)
	if _, err := pool.Exec(ctx, `INSERT INTO fabric_block (deployment, block_no, hash, parent, data) VALUES ($1, 0, $2, '', ''::bytea), ($1, 1, $3, $2, ''::bytea), ($1, 2, $4, $3, ''::bytea)`, depID, b0Hash, b1Hash, b2Hash); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fabric_head (deployment, block_no, hash) VALUES ($1, 2, $2)`, depID, b2Hash); err != nil {
		t.Fatal(err)
	}

	taskActive := api.Task{
		Bound: api.Bound{DeploymentID: depID}, ID: "task-m3-1", Domain: "A", Mode: api.RP,
		Creator: "did:web:a.local:u", CreatorKeyVersion: 1, CreatorCredential: "cred-u", Resource: "res-1",
		Digest: strings.Repeat("1", 64), Interval: api.Interval{NBF: now.Add(-time.Hour).Unix(), EXP: now.Add(time.Hour).Unix()},
		Version: api.Version{Status: api.Active, Revision: 1},
	}
	taskCancelled := taskActive
	taskCancelled.Version = api.Version{Status: api.Cancelled, Revision: 2}

	grantActive := api.Grant{
		Bound: api.Bound{DeploymentID: depID}, ID: "grant-m3-1", Schema: api.Schema, Root: "grant-m3-1", Task: "task-m3-1",
		Mode: api.RP, Domain: "A", Resource: "res-1", Issuer: "did:web:a.local:u", Grantee: "did:web:b.local:b1",
		IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: "cred-u", GranteeCredential: "cred-b1",
		Depth: 0, Digest: strings.Repeat("2", 64), Interval: taskActive.Interval, Version: api.Version{Status: api.Active, Revision: 1},
	}
	grantSusp := grantActive
	grantSusp.Version = api.Version{Status: api.Suspended, Revision: 2}

	credU := api.Credential{
		Bound: api.Bound{DeploymentID: depID}, ID: "cred-u", Type: protocol.CredentialTypeEnterpriseIdentity,
		Issuer: "did:web:a.local:ia", Subject: "did:web:a.local:u", IssuerKeyVersion: 1, SubjectKeyVersion: 1,
		ClaimNames: []string{"domain", "role"}, Digest: strings.Repeat("3", 64), Interval: taskActive.Interval,
		Version: api.Version{Status: api.Active, Revision: 1},
	}
	credB1 := credU
	credB1.ID, credB1.Subject = "cred-b1", "did:web:b.local:b1"

	domA := api.Domain{Bound: api.Bound{DeploymentID: depID}, ID: "A", DID: "did:web:a.local", Certification: "cert-a", Version: api.Version{Status: api.Active, Revision: 1}}
	certA := api.Certification{Bound: api.Bound{DeploymentID: depID}, ID: "cert-a", Domain: "A", RootKeyVersion: 1, Digest: strings.Repeat("4", 64), Interval: taskActive.Interval, Version: api.Version{Status: api.Active, Revision: 1}}
	idU := api.Identity{Bound: api.Bound{DeploymentID: depID}, ID: "did:web:a.local:u", Domain: "A", Kind: "USER", DocumentDigest: strings.Repeat("5", 64), KeyID: "did:web:a.local:u#key-1", KeyVersion: 1, PublicKey: "04" + strings.Repeat("2", 128), Version: api.Version{Status: api.Active, Revision: 1}}
	idB1 := idU
	idB1.ID = "did:web:b.local:b1"
	idDomA := idU
	idDomA.ID, idDomA.Kind = domA.DID, "DOMAIN"
	idIA := idU
	idIA.ID, idIA.Kind = "did:web:a.local:ia", "ISSUER"

	writeVer := func(blk int64, idx int, txID, key string, val any) {
		raw, err := json.Marshal(val)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO fabric_version (deployment, key, block_no, tx_index, tx_id, value) VALUES ($1,$2,$3,$4,$5,$6)`,
			depID, key, blk, idx, txID, raw); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO fabric_current (deployment, key, value) VALUES ($1,$2,$3) ON CONFLICT (deployment, key) DO UPDATE SET value=EXCLUDED.value`,
			depID, key, raw); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fabric_version (deployment, key, block_no, tx_index, tx_id, value) VALUES ($1,$2,1,0,'tx-b1-boot',$3)`,
		depID, api.BootstrapKey, rawBoot); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fabric_current (deployment, key, value) VALUES ($1,$2,$3)`,
		depID, api.BootstrapKey, rawBoot); err != nil {
		t.Fatal(err)
	}
	writeVer(1, 1, "tx-b1-1", api.Key("domain", "A"), domA)
	writeVer(1, 2, "tx-b1-2", api.Key("certification", "cert-a"), certA)
	writeVer(1, 3, "tx-b1-3", api.Key("identity", domA.DID), idDomA)
	writeVer(1, 4, "tx-b1-4", api.Key("identity", idU.ID), idU)
	writeVer(1, 5, "tx-b1-5", api.Key("identity", idB1.ID), idB1)
	writeVer(1, 6, "tx-b1-6", api.Key("identity", idIA.ID), idIA)
	writeVer(1, 7, "tx-b1-7", api.Key("credential", credU.ID), credU)
	writeVer(1, 8, "tx-b1-8", api.Key("credential", credB1.ID), credB1)
	writeVer(1, 9, "tx-b1-9", api.Key("task", taskActive.ID), taskActive)
	writeVer(1, 10, "tx-b1-10", api.Key("grant", grantActive.ID), grantActive)

	// Block 2: suspend grant and cancel task
	writeVer(2, 0, "tx-b2-task", api.Key("task", taskCancelled.ID), taskCancelled)
	writeVer(2, 1, "tx-b2-grant", api.Key("grant", grantSusp.ID), grantSusp)

	sp := NewStateProviderFromBootstrap(pool, depID, boot, nil)
	_ = rawBoot
	adapter := sp.GatewayAdapter().(gateway.HistoricalStateSource)

	h1, err := adapter.AssembleHistoricalSnapshot(ctx, grantActive.ID, 1, now)
	if err != nil {
		t.Fatalf("historical snapshot block 1 failed: %v", err)
	}
	if h1.Snapshot.Grants[grantActive.ID].Status != api.Active || h1.Snapshot.Tasks[taskActive.ID].Status != api.Active {
		t.Fatalf("expected ACTIVE grant/task at block 1, got %+v %+v", h1.Snapshot.Grants[grantActive.ID], h1.Snapshot.Tasks[taskActive.ID])
	}

	h2, err := adapter.AssembleHistoricalSnapshot(ctx, grantActive.ID, 2, now)
	if err != nil {
		t.Fatalf("historical snapshot block 2 failed: %v", err)
	}
	if h2.Snapshot.Grants[grantActive.ID].Status != api.Suspended || h2.Snapshot.Tasks[taskActive.ID].Status != api.Cancelled {
		t.Fatalf("expected SUSPENDED grant & CANCELLED task at block 2, got %+v %+v", h2.Snapshot.Grants[grantActive.ID], h2.Snapshot.Tasks[taskActive.ID])
	}

	// Missing future block 3 -> STATE_UNAVAILABLE
	if _, err := adapter.AssembleHistoricalSnapshot(ctx, grantActive.ID, 3, now); !protocol.HasCode(err, protocol.ErrCodeStateUnavailable) {
		t.Fatalf("expected STATE_UNAVAILABLE for unavailable block 3, got %v", err)
	}

	// FindInactiveBlock detects block 2 for grant & task
	rBlk, rTx, found, err := adapter.FindInactiveBlock(ctx, "grant", grantActive.ID, 1)
	if err != nil || !found || rBlk != 2 || rTx != "tx-b2-grant" {
		t.Fatalf("expected FindInactiveBlock=(2, tx-b2-grant, true), got (%d, %q, %v, %v)", rBlk, rTx, found, err)
	}

}
