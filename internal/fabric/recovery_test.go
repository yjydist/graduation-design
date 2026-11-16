package fabric

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
	"graduation-design/internal/serviceauth"
)

type recoveryTestBackend struct {
	caller      api.Management
	certificate *x509.Certificate
	calls       chan json.RawMessage
}

func (b *recoveryTestBackend) CurrentRevision(context.Context, string, json.RawMessage) (uint64, bool, error) {
	return 1, true, nil
}
func (b *recoveryTestBackend) AuthorizeRecovery(_ context.Context, caller api.Management, bundle *protocol.RecoveryDualProofBundle) error {
	if caller != b.caller {
		return protocol.NewError(protocol.ErrCodeIdentityManagementForbidden, "registrar required")
	}
	der, err := base64.RawURLEncoding.DecodeString(bundle.NewManagementCertificateDER)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	return verifyAuthorizedMgmtCert(cert, []*x509.Certificate{b.certificate})
}
func (b *recoveryTestBackend) SubmitAsync(ctx context.Context, key, id string, caller api.Management, method string, input json.RawMessage, update func(string, string, string, int64, string, *string, *string, bool) error) {
	code := "VALID"
	if err := update("COMMIT", "CONFIRMED", "test-original-recovery", 2, strings.Repeat("e", 64), &code, nil, false); err == nil {
		b.calls <- append(json.RawMessage(nil), input...)
	}
}

type recoveryServiceFixture struct {
	svc             *ManagementOperationService
	backend         *recoveryTestBackend
	caller          api.Management
	bundle          *protocol.RecoveryDualProofBundle
	mgmtKey, appKey *ecdsa.PrivateKey
	certDER         []byte
}

func newRecoveryServiceFixture(t *testing.T) *recoveryServiceFixture {
	t.Helper()
	pool := testPgPool(t)
	dep := protocol.DeploymentBinding{Purpose: protocol.DeploymentPurpose, SchemaVersion: api.Schema, ChannelID: api.Channel, RegistryName: api.Registry, GenesisHash: api.Digest([]byte(t.Name())), InstanceID: api.Digest([]byte(t.Name() + time.Now().String()))}
	depID, err := dep.ComputeID()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM operations WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM recovery_challenges WHERE deployment_id=$1`, depID)
	})
	now := time.Now().UTC()
	mgmtKey, cert, der := makeSelfSignedUserCert(t, "new-management", now)
	appKey, pub, err := protocol.GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := protocol.NewDIDDocument("did:web:a.local:u", "did:web:a.local:u#key-2", pub, protocol.KeyPurposeAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := doc.Digest()
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := NewRegistrationCoordinator(pool).IssueRecoveryChallenge(t.Context(), dep, IssueRecoveryChallengeRequest{
		DomainID: "A", SubjectID: "did:web:a.local:u", AccountCommitment: api.Digest([]byte("account")),
		OldManagementIdentity: protocol.ManagementIdentity{MSPID: "AMsp", CertificateSha256: strings.Repeat("a", 64)},
		NewManagementIdentity: protocol.ManagementIdentity{MSPID: "AMsp", CertificateSha256: api.Digest(der)},
		ExpectedRevision:      1, ExpectedKeyVersion: 1, NewAppKeyID: "did:web:a.local:u#key-2", NewAppPublicKey: pub, DIDDocumentDigest: digest, IssuedAt: now.Unix(), TTLSeconds: 120,
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := protocol.SignRecoveryDualProofBundle(dep, *c, der, mgmtKey, appKey)
	if err != nil {
		t.Fatal(err)
	}
	caller := api.Management{MSPID: "AMsp", Fingerprint: strings.Repeat("b", 64)}
	backend := &recoveryTestBackend{caller: caller, certificate: cert, calls: make(chan json.RawMessage, 4)}
	return &recoveryServiceFixture{svc: NewManagementOperationService(pool, depID, api.Management{}, backend), backend: backend, caller: caller, bundle: bundle, mgmtKey: mgmtKey, appKey: appKey, certDER: der}
}

func (f *recoveryServiceFixture) request(t *testing.T, key string, caller api.Management, payload any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/management/RecoverIdentity", bytes.NewReader(raw))
	req.Header.Set("Idempotency-Key", key)
	req = req.WithContext(serviceauth.WithIdentity(req.Context(), serviceauth.Identity{Role: "MANAGEMENT", MSPID: caller.MSPID, Fingerprint: caller.Fingerprint}))
	w := httptest.NewRecorder()
	f.svc.Handler().ServeHTTP(w, req)
	return w
}

func TestRecoveryHTTPRejectsMissingProofTamperingAndReplay(t *testing.T) {
	f := newRecoveryServiceFixture(t)
	for _, name := range []string{"raw-mutation", "missing-application", "missing-management", "bad-application", "bad-management", "unissued", "changed-subject", "changed-version", "changed-deployment", "wrong-registrar", "expired"} {
		t.Run(name, func(t *testing.T) {
			bundle := *f.bundle
			caller := f.caller
			var payload any = &bundle
			switch name {
			case "raw-mutation":
				payload = recoveryMutation(bundle.Challenge)
			case "missing-application":
				bundle.NewAppJWSSignature = ""
			case "missing-management":
				bundle.NewManagementSignatureDER = ""
			case "bad-application":
				bundle.NewAppJWSSignature = strings.Repeat("A", 86)
			case "bad-management":
				bundle.NewManagementSignatureDER = "AA"
			case "unissued":
				bundle.Challenge.ChallengeID += "-not-issued"
			case "changed-subject":
				bundle.Challenge.SubjectID += "-other"
				bundle.Challenge.NewAppKeyID = bundle.Challenge.SubjectID + "#key-2"
			case "changed-version":
				bundle.Challenge.ExpectedRevision++
			case "changed-deployment":
				bundle.Deployment.InstanceID = strings.Repeat("e", 64)
			case "wrong-registrar":
				caller.Fingerprint = strings.Repeat("c", 64)
			case "expired":
				_, err := f.svc.db.Exec(t.Context(), `UPDATE recovery_challenges SET expires_at=1 WHERE deployment_id=$1`, f.svc.deploymentID)
				if err != nil {
					t.Fatal(err)
				}
				defer f.svc.db.Exec(context.Background(), `UPDATE recovery_challenges SET expires_at=$2 WHERE deployment_id=$1`, f.svc.deploymentID, f.bundle.Challenge.ExpiresAt)
			}
			if name == "unissued" || name == "changed-subject" || name == "changed-version" || name == "changed-deployment" {
				var err error
				b, err := protocol.SignRecoveryDualProofBundle(bundle.Deployment, bundle.Challenge, f.certDER, f.mgmtKey, f.appKey)
				if err != nil {
					t.Fatal(err)
				}
				bundle = *b
			}
			resp := f.request(t, name, caller, payload)
			if resp.Code == 202 {
				t.Fatalf("invalid recovery accepted: %s", resp.Body.String())
			}
			var count int
			if err := f.svc.db.QueryRow(t.Context(), `SELECT COUNT(*) FROM operations WHERE deployment_id=$1`, f.svc.deploymentID).Scan(&count); err != nil || count != 0 {
				t.Fatalf("rejected recovery queued: %d %v", count, err)
			}
			var consumed bool
			if err := f.svc.db.QueryRow(t.Context(), `SELECT consumed FROM recovery_challenges WHERE deployment_id=$1`, f.svc.deploymentID).Scan(&consumed); err != nil || consumed {
				t.Fatalf("rejected proof consumed challenge: %v %v", consumed, err)
			}
		})
	}
	resp := f.request(t, "valid", f.caller, f.bundle)
	if resp.Code != 202 {
		t.Fatalf("valid recovery: %d %s", resp.Code, resp.Body.String())
	}
	select {
	case input := <-f.backend.calls:
		var mutation api.RecoverIdentityInput
		if err := json.Unmarshal(input, &mutation); err != nil || mutation != recoveryMutation(f.bundle.Challenge) {
			t.Fatalf("submitted input differs: %+v %v", mutation, err)
		}
	case <-time.After(time.Second):
		t.Fatal("accepted recovery never submitted")
	}
	if retry := f.request(t, "valid", f.caller, f.bundle); retry.Code != 202 {
		t.Fatalf("exact retry: %d %s", retry.Code, retry.Body.String())
	}
	if replay := f.request(t, "new-key", f.caller, f.bundle); replay.Code != 403 || !strings.Contains(replay.Body.String(), protocol.ErrCodeChallengeReplay) {
		t.Fatalf("replay: %d %s", replay.Code, replay.Body.String())
	}
}

func TestRecoveryAdmissionSurvivesRestartAndRejectsLegacyQueue(t *testing.T) {
	f := newRecoveryServiceFixture(t)
	raw, _ := json.Marshal(f.bundle)
	code, view, err := f.svc.Accept(t.Context(), "restart", f.caller, "RecoverIdentity", raw, false)
	if err != nil || code != 202 {
		t.Fatalf("admission: %d %v", code, err)
	}
	var status string
	var consumed bool
	if err = f.svc.db.QueryRow(t.Context(), `SELECT o.status,c.consumed FROM operations o JOIN recovery_challenges c ON c.consumed_by_operation_id=o.operation_id WHERE o.operation_id=$1`, view.OperationID).Scan(&status, &consumed); err != nil || status != "PENDING" || !consumed {
		t.Fatalf("atomic acceptance: %s %v %v", status, consumed, err)
	}
	restarted := NewManagementOperationService(f.svc.db, f.svc.deploymentID, api.Management{}, f.backend)
	if err = restarted.ResumePending(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-f.backend.calls
	result, err := restarted.GetOperation(t.Context(), view.OperationID)
	if err != nil || result.Status != "CONFIRMED" || result.TxID != "test-original-recovery" {
		t.Fatalf("recovery: %+v %v", result, err)
	}
	// Simulate a pre-fix raw request with no durable challenge approval.
	_, err = f.svc.db.Exec(t.Context(), `INSERT INTO operations SELECT deployment_id,'legacy',operation_id||'-legacy',caller_msp_id,caller_fingerprint,method,'legacy-pending',0,'','ACCEPT','PENDING',NULL,NULL,payload_hash,NOW(),request_json,FALSE FROM operations WHERE operation_id=$1`, view.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.ResumePending(t.Context()); err != nil {
		t.Fatal(err)
	}
	legacy, err := restarted.GetOperation(t.Context(), view.OperationID+"-legacy")
	if err != nil || legacy.Status != "FAILED" || legacy.ErrorCode == nil || *legacy.ErrorCode != protocol.ErrCodeRecoveryProofInvalid {
		t.Fatalf("legacy queue: %+v %v", legacy, err)
	}
	select {
	case <-f.backend.calls:
		t.Fatal("legacy raw recovery reached backend")
	default:
	}
}

func TestRecoveryChallengeConsumedOnceAcrossConcurrentOperations(t *testing.T) {
	f := newRecoveryServiceFixture(t)
	raw, _ := json.Marshal(f.bundle)
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for _, key := range []string{"one", "two"} {
		wg.Go(func() {
			code, _, _ := f.svc.Accept(t.Context(), key, f.caller, "RecoverIdentity", raw, false)
			codes <- code
		})
	}
	wg.Wait()
	close(codes)
	counts := map[int]int{}
	for code := range codes {
		counts[code]++
	}
	if counts[202] != 1 || counts[403] != 1 {
		t.Fatalf("concurrent consumption: %v", counts)
	}
}

func TestRecoveryAdmissionRollsBackChallengeWhenQueueInsertFails(t *testing.T) {
	f := newRecoveryServiceFixture(t)
	// Reserve the target operation ID under another key to fail the final insert,
	// after the admission transaction has attempted challenge consumption.
	_, existing, err := f.svc.Accept(t.Context(), "other", f.caller, "RotateIdentity", json.RawMessage(`{"expectedRevision":1}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.db.Exec(t.Context(), `UPDATE operations SET operation_id=$2 WHERE operation_id=$1`, existing.OperationID, f.svc.deploymentID+":blocked"); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f.bundle)
	code, _, err := f.svc.Accept(t.Context(), "blocked", f.caller, "RecoverIdentity", raw, false)
	if err == nil || code != http.StatusServiceUnavailable {
		t.Fatalf("queue insert should fail: HTTP %d: %v", code, err)
	}
	var consumed bool
	if err := f.svc.db.QueryRow(t.Context(), `SELECT consumed FROM recovery_challenges WHERE deployment_id=$1`, f.svc.deploymentID).Scan(&consumed); err != nil || consumed {
		t.Fatalf("failed admission consumed challenge: %v: %v", consumed, err)
	}
	if _, err := f.svc.db.Exec(t.Context(), `DELETE FROM operations WHERE deployment_id=$1`, f.svc.deploymentID); err != nil {
		t.Fatal(err)
	}
	if code, _, err := f.svc.Accept(t.Context(), "blocked", f.caller, "RecoverIdentity", raw, false); err != nil || code != http.StatusAccepted {
		t.Fatalf("rolled-back challenge must remain usable: HTTP %d: %v", code, err)
	}
}

func TestRecoveryRestartRejectsModifiedDurableRequest(t *testing.T) {
	f := newRecoveryServiceFixture(t)
	raw, _ := json.Marshal(f.bundle)
	_, view, err := f.svc.Accept(t.Context(), "tampered-queue", f.caller, "RecoverIdentity", raw, false)
	if err != nil {
		t.Fatal(err)
	}
	mutation := recoveryMutation(f.bundle.Challenge)
	mutation.PublicKey = "changed-after-approval"
	changed, _ := json.Marshal(mutation)
	if _, err := f.svc.db.Exec(t.Context(), `UPDATE operations SET request_json=$2 WHERE operation_id=$1`, view.OperationID, changed); err != nil {
		t.Fatal(err)
	}
	restarted := NewManagementOperationService(f.svc.db, f.svc.deploymentID, api.Management{}, f.backend)
	if err := restarted.ResumePending(t.Context()); err != nil {
		t.Fatal(err)
	}
	result, err := restarted.GetOperation(t.Context(), view.OperationID)
	if err != nil || result.Status != "FAILED" || result.ErrorCode == nil || *result.ErrorCode != protocol.ErrCodeRecoveryProofInvalid {
		t.Fatalf("modified queue did not fail closed: %+v: %v", result, err)
	}
	select {
	case <-f.backend.calls:
		t.Fatal("modified request reached Fabric backend")
	default:
	}
}
