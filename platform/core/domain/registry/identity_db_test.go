//go:build db

package registry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/core/ledger"
	"grad/platform/internal/testutil"
	"grad/protocol"
	preg "grad/protocol/registry"
)

func makeSelfSignedUserCert(t *testing.T, cn string, now time.Time) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, OrganizationalUnit: []string{"client"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return priv, cert, der
}

func TestRegistrationChallengeDualProofFlow(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)

	dep := protocol.DeploymentBinding{
		ChannelID:     preg.Channel,
		GenesisHash:   preg.Digest([]byte("test-reg-genesis")),
		InstanceID:    preg.Digest([]byte("test-reg-instance")),
		Purpose:       protocol.DeploymentPurpose,
		RegistryName:  preg.Registry,
		SchemaVersion: protocol.SchemaVersion,
	}
	depID, err := protocol.ComputeDeploymentID(dep)
	require.NoError(t, err)

	appPriv, err := protocol.GenerateP256Key()
	require.NoError(t, err)
	appPubHex, err := protocol.FormatAppPublicKey(&appPriv.PublicKey)
	require.NoError(t, err)

	did := "did:web:a.local:test-reg"
	keyID := did + "#key-1"
	doc, err := protocol.NewDIDDocument(did, keyID, &appPriv.PublicKey, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
	require.NoError(t, err)
	docBytes, err := protocol.MarshalJCS(doc)
	require.NoError(t, err)
	docDigest := protocol.DigestBytes(docBytes)

	mgmtPriv, mgmtCert, mgmtCertDER := makeSelfSignedUserCert(t, "User5@a.local", now)
	wrongPriv, _, wrongCertDER := makeSelfSignedUserCert(t, "User8@a.local", now)

	rc := NewRegistrationCoordinator(pool)
	chal, _, err := rc.IssueRegistrationChallenge(ctx, dep, IssueChallengeRequest{
		DomainID:          "A",
		SubjectID:         did,
		AppKeyID:          keyID,
		AppKeyVersion:     1,
		AppPublicKey:      appPubHex,
		DIDDocumentDigest: docDigest,
		AccountCommitment: preg.Digest([]byte("acct:" + depID + ":" + did)),
		MSPID:             "AMsp",
		CertificateSHA256: preg.Digest(mgmtCertDER),
		IssuedAt:          now.Unix(),
		TTLSeconds:        60,
	})
	require.NoError(t, err)

	caller := preg.Management{MSPID: "AMsp", CertificateSHA256: preg.Digest(mgmtCertDER)}
	checkNotConsumed := func() {
		t.Helper()
		var consumed bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT consumed FROM registration_challenges WHERE challenge_id=$1`, chal.ChallengeID).Scan(&consumed))
		assert.False(t, consumed, "challenge must remain unconsumed after rejected proof")
	}

	validBundle, err := protocol.SignManagementDualProofBundle(dep, *chal, mgmtCertDER, mgmtPriv, appPriv)
	require.NoError(t, err)

	// Negative 1: wrong user cert from same MSP.
	wrongBundle, err := protocol.SignManagementDualProofBundle(dep, *chal, wrongCertDER, wrongPriv, appPriv)
	require.NoError(t, err)
	err = rc.AcceptRegistrationBundle(ctx, "reg-wrong-cert", caller, wrongBundle, "AMsp", []*x509.Certificate{mgmtCert}, docBytes, now.Unix(), nil)
	assert.Error(t, err)
	checkNotConsumed()

	// Negative 2: replaced challenge nonce.
	otherChal := *chal
	otherNonce, err := protocol.GenerateNonce()
	require.NoError(t, err)
	otherChal.Nonce = otherNonce
	replacedBundle, err := protocol.SignManagementDualProofBundle(dep, otherChal, mgmtCertDER, mgmtPriv, appPriv)
	require.NoError(t, err)
	err = rc.AcceptRegistrationBundle(ctx, "reg-replaced-nonce", caller, replacedBundle, "AMsp", []*x509.Certificate{mgmtCert}, docBytes, now.Unix(), nil)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeChallengeMismatch))
	checkNotConsumed()

	// Negative 3: missing management signature.
	missingMgmtSig := *validBundle
	missingMgmtSig.ManagementSignatureDER = ""
	err = rc.AcceptRegistrationBundle(ctx, "reg-no-mgmt-sig", caller, &missingMgmtSig, "AMsp", []*x509.Certificate{mgmtCert}, docBytes, now.Unix(), nil)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeRegistrationProofInvalid))
	checkNotConsumed()

	// Negative 4: missing DID application proof.
	missingAppSig := *validBundle
	missingAppSig.AppJWSSignature = ""
	err = rc.AcceptRegistrationBundle(ctx, "reg-no-app-sig", caller, &missingAppSig, "AMsp", []*x509.Certificate{mgmtCert}, docBytes, now.Unix(), nil)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeRegistrationProofInvalid))
	checkNotConsumed()

	// Negative 5: expired challenge.
	err = rc.AcceptRegistrationBundle(ctx, "reg-expired", caller, validBundle, "AMsp", []*x509.Certificate{mgmtCert}, docBytes, now.Unix()+61, nil)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeChallengeExpired))
	checkNotConsumed()

	// Negative 6: wrong MSPID.
	err = rc.AcceptRegistrationBundle(ctx, "reg-wrong-msp", caller, validBundle, "BMsp", []*x509.Certificate{mgmtCert}, docBytes, now.Unix(), nil)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeRegistrationProofInvalid))
	checkNotConsumed()

	// Negative 7: DID document mismatch.
	otherAppPriv, err := protocol.GenerateP256Key()
	require.NoError(t, err)
	wrongDoc, err := protocol.NewDIDDocument(did, keyID, &otherAppPriv.PublicKey, protocol.KeyPurposeAuthentication)
	require.NoError(t, err)
	wrongDocBytes, err := protocol.MarshalJCS(wrongDoc)
	require.NoError(t, err)
	err = rc.AcceptRegistrationBundle(ctx, "reg-bad-did", caller, validBundle, "AMsp", []*x509.Certificate{mgmtCert}, wrongDocBytes, now.Unix(), nil)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeDIDDocumentMismatch))
	checkNotConsumed()

	// Positive: valid dual proof consumes challenge and records CONFIRMED operations row.
	opKey := "reg-valid-pa"
	opID := ManagementOperationID(depID, caller, "RegisterIdentity", opKey)
	err = rc.AcceptRegistrationBundle(ctx, opKey, caller, validBundle, "AMsp", []*x509.Certificate{mgmtCert}, docBytes, now.Unix(), func(_ context.Context, key string) (*ledger.Operation, error) {
		require.Equal(t, opID, key)
		return &ledger.Operation{Key: key, Status: "CONFIRMED",
			TxID:   preg.Digest([]byte("tx-" + opID)),
			Commit: testCommit(42, preg.Digest([]byte("block-42")), "VALID"),
		}, nil
	})
	require.NoError(t, err)

	var consumed bool
	var consumedBy string
	require.NoError(t, pool.QueryRow(ctx, `SELECT consumed, consumed_by_operation_id FROM registration_challenges WHERE challenge_id=$1`, chal.ChallengeID).Scan(&consumed, &consumedBy))
	assert.True(t, consumed)
	assert.Equal(t, opID, consumedBy)

	var opStatus string
	var opBlock int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT status, block_no FROM operations WHERE operation_id=$1`, opID).Scan(&opStatus, &opBlock))
	assert.Equal(t, "CONFIRMED", opStatus)
	assert.Equal(t, int64(42), opBlock)

	// A retry in the original scope resolves the recorded operation without submitting again.
	require.NoError(t, rc.AcceptRegistrationBundle(ctx, opKey, caller, validBundle, "AMsp", []*x509.Certificate{mgmtCert}, docBytes, now.Unix(), nil))

	// Replay of consumed challenge must fail with CHALLENGE_REPLAY.
	err = rc.AcceptRegistrationBundle(ctx, "reg-replay", caller, validBundle, "AMsp", []*x509.Certificate{mgmtCert}, docBytes, now.Unix(), nil)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeChallengeReplay))
}

type recoveryTestBackend struct {
	caller      preg.Management
	certificate *x509.Certificate
	calls       chan json.RawMessage
}

func (b *recoveryTestBackend) CurrentRevision(context.Context, string, string) (uint64, bool, error) {
	return 1, true, nil
}

func (b *recoveryTestBackend) AuthorizeRecovery(_ context.Context, caller preg.Management, bundle *protocol.RecoveryDualProofBundle) error {
	if caller != b.caller {
		return protocol.NewError(preg.ErrCodeIdentityManagementForbidden, "registrar required")
	}
	der, err := protocol.DecodeStrictBase64URL(bundle.NewManagementCertificateDER)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	return verifyAuthorizedMgmtCert(cert, []*x509.Certificate{b.certificate})
}

func (b *recoveryTestBackend) SubmitAsync(
	_ context.Context,
	_, _ string,
	_ preg.Management,
	_ string,
	input json.RawMessage,
	update OutcomeHandler,
) {
	code := "VALID"
	if err := update("COMMIT", "CONFIRMED", "test-original-recovery", testCommit(2, strings.Repeat("e", 64), code), nil, false); err == nil {
		b.calls <- append(json.RawMessage(nil), input...)
	}
}

type recoveryServiceFixture struct {
	svc             *Service
	backend         *recoveryTestBackend
	caller          preg.Management
	bundle          *protocol.RecoveryDualProofBundle
	mgmtKey, appKey *ecdsa.PrivateKey
	certDER         []byte
}

func newRecoveryServiceFixture(t *testing.T) *recoveryServiceFixture {
	t.Helper()
	pool := testutil.OpenMigratedPool(t)
	dep := protocol.DeploymentBinding{
		Purpose:       protocol.DeploymentPurpose,
		SchemaVersion: preg.Schema,
		ChannelID:     preg.Channel,
		RegistryName:  preg.Registry,
		GenesisHash:   preg.Digest([]byte(t.Name())),
		InstanceID:    preg.Digest([]byte(t.Name() + time.Now().String())),
	}
	depID, err := protocol.ComputeDeploymentID(dep)
	require.NoError(t, err)

	now := time.Now().UTC()
	mgmtKey, cert, der := makeSelfSignedUserCert(t, "new-management", now)
	appKey, err := protocol.GenerateP256Key()
	require.NoError(t, err)
	pubHex, err := protocol.FormatAppPublicKey(&appKey.PublicKey)
	require.NoError(t, err)

	doc, err := protocol.NewDIDDocument("did:web:a.local:u", "did:web:a.local:u#key-2", &appKey.PublicKey, protocol.KeyPurposeAuthentication)
	require.NoError(t, err)
	digest, err := doc.Digest()
	require.NoError(t, err)

	rc := NewRegistrationCoordinator(pool)
	// Reject TTL > 300s.
	_, _, err = rc.IssueRecoveryChallenge(t.Context(), dep, IssueRecoveryChallengeRequest{
		DomainID:              "A",
		SubjectID:             "did:web:a.local:u",
		AccountCommitment:     preg.Digest([]byte("account")),
		OldManagementIdentity: protocol.ManagementIdentity{MSPID: "AMsp", CertificateSHA256: strings.Repeat("a", 64)},
		NewManagementIdentity: protocol.ManagementIdentity{MSPID: "AMsp", CertificateSHA256: preg.Digest(der)},
		ExpectedRevision:      1,
		ExpectedKeyVersion:    1,
		NewAppKeyID:           "did:web:a.local:u#key-2",
		NewAppPublicKey:       pubHex,
		DIDDocumentDigest:     digest,
		IssuedAt:              now.Unix(),
		TTLSeconds:            301,
	})
	require.True(t, protocol.HasCode(err, preg.ErrCodeRecoveryProofInvalid))

	c, _, err := rc.IssueRecoveryChallenge(t.Context(), dep, IssueRecoveryChallengeRequest{
		DomainID:              "A",
		SubjectID:             "did:web:a.local:u",
		AccountCommitment:     preg.Digest([]byte("account")),
		OldManagementIdentity: protocol.ManagementIdentity{MSPID: "AMsp", CertificateSHA256: strings.Repeat("a", 64)},
		NewManagementIdentity: protocol.ManagementIdentity{MSPID: "AMsp", CertificateSHA256: preg.Digest(der)},
		ExpectedRevision:      1,
		ExpectedKeyVersion:    1,
		NewAppKeyID:           "did:web:a.local:u#key-2",
		NewAppPublicKey:       pubHex,
		DIDDocumentDigest:     digest,
		IssuedAt:              now.Unix(),
		TTLSeconds:            120,
	})
	require.NoError(t, err)

	bundle, err := protocol.SignRecoveryDualProofBundle(dep, *c, der, mgmtKey, appKey)
	require.NoError(t, err)

	caller := preg.Management{MSPID: "AMsp", CertificateSHA256: strings.Repeat("b", 64)}
	backend := &recoveryTestBackend{caller: caller, certificate: cert, calls: make(chan json.RawMessage, 4)}
	return &recoveryServiceFixture{
		svc:     NewService(pool, depID, preg.Management{}, backend),
		backend: backend,
		caller:  caller,
		bundle:  bundle,
		mgmtKey: mgmtKey,
		appKey:  appKey,
		certDER: der,
	}
}

func (f *recoveryServiceFixture) accept(t *testing.T, key string, caller preg.Management, payload any) (*OperationView, error) {
	t.Helper()
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	return f.svc.Accept(t.Context(), key, caller, "RecoverIdentity", raw, true)
}

func TestRecoveryAcceptRejectsMissingProofTamperingAndReplay(t *testing.T) {
	f := newRecoveryServiceFixture(t)
	cases := []struct {
		name     string
		wantCode string
	}{
		{"raw-mutation", preg.ErrCodeRecoveryProofInvalid},
		{"missing-application", preg.ErrCodeRecoveryProofInvalid},
		{"missing-management", preg.ErrCodeRecoveryProofInvalid},
		{"bad-application", preg.ErrCodeRecoveryProofInvalid},
		{"bad-management", preg.ErrCodeRecoveryProofInvalid},
		{"unissued", preg.ErrCodeChallengeUnknown},
		{"changed-subject", preg.ErrCodeChallengeMismatch},
		{"changed-version", preg.ErrCodeStateChanged},
		{"changed-deployment", preg.ErrCodeRecoveryProofInvalid},
		{"wrong-registrar", preg.ErrCodeIdentityManagementForbidden},
		{"expired", preg.ErrCodeChallengeExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bundle := *f.bundle
			caller := f.caller
			var payload any = &bundle
			switch tc.name {
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
				caller.CertificateSHA256 = strings.Repeat("c", 64)
			case "expired":
				_, err := f.svc.db.Exec(t.Context(), `UPDATE recovery_challenges SET expires_at=1 WHERE deployment_id=$1`, f.svc.deploymentID)
				require.NoError(t, err)
				defer func() {
					_, _ = f.svc.db.Exec(context.Background(), `UPDATE recovery_challenges SET expires_at=$2 WHERE deployment_id=$1`, f.svc.deploymentID, f.bundle.Challenge.ExpiresAt)
				}()
			}
			if tc.name == "unissued" || tc.name == "changed-subject" || tc.name == "changed-version" || tc.name == "changed-deployment" {
				b, err := protocol.SignRecoveryDualProofBundle(bundle.Deployment, bundle.Challenge, f.certDER, f.mgmtKey, f.appKey)
				require.NoError(t, err)
				bundle = *b
			}
			view, err := f.accept(t, tc.name, caller, payload)
			assert.Nil(t, view)
			assert.True(t, protocol.HasCode(err, tc.wantCode), "got err=%v want code=%s", err, tc.wantCode)

			var count int
			require.NoError(t, f.svc.db.QueryRow(t.Context(), `SELECT COUNT(*) FROM operations WHERE deployment_id=$1`, f.svc.deploymentID).Scan(&count))
			assert.Equal(t, 0, count)

			var consumed bool
			require.NoError(t, f.svc.db.QueryRow(t.Context(), `SELECT consumed FROM recovery_challenges WHERE deployment_id=$1`, f.svc.deploymentID).Scan(&consumed))
			assert.False(t, consumed)
		})
	}

	// Unapproved certificate must not consume challenge.
	originalCert := f.backend.certificate
	_, otherCert, _ := makeSelfSignedUserCert(t, "other", time.Now())
	f.backend.certificate = otherCert
	_, err := f.accept(t, "unapproved-cert", f.caller, f.bundle)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeSignatureInvalid))
	f.backend.certificate = originalCert

	// Valid recovery bundle -> accepted and derived RecoverIdentityInput dispatched.
	view, err := f.accept(t, "valid", f.caller, f.bundle)
	require.NoError(t, err)
	require.NotNil(t, view)

	select {
	case input := <-f.backend.calls:
		var mutation preg.RecoverIdentityInput
		require.NoError(t, json.Unmarshal(input, &mutation))
		assert.Equal(t, recoveryMutation(f.bundle.Challenge), mutation)
	case <-time.After(2 * time.Second):
		t.Fatal("accepted recovery never submitted")
	}

	// Exact retry -> accepted with same operationId.
	retry, err := f.accept(t, "valid", f.caller, f.bundle)
	require.NoError(t, err)
	assert.Equal(t, view.OperationID, retry.OperationID)

	// Replay under new key -> CHALLENGE_REPLAY.
	_, err = f.accept(t, "new-key", f.caller, f.bundle)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeChallengeReplay))
}

func TestRecoveryCrashResumeConcurrencyRollbackAndTamperFailClosed(t *testing.T) {
	t.Run("restart-and-legacy-fail-closed", func(t *testing.T) {
		f := newRecoveryServiceFixture(t)
		raw, err := json.Marshal(f.bundle)
		require.NoError(t, err)
		view, err := f.svc.Accept(t.Context(), "restart", f.caller, "RecoverIdentity", raw, false)
		require.NoError(t, err)

		var status string
		var consumed bool
		require.NoError(t, f.svc.db.QueryRow(t.Context(),
			`SELECT o.status, c.consumed FROM operations o JOIN recovery_challenges c ON c.consumed_by_operation_id=o.operation_id WHERE o.operation_id=$1`,
			view.OperationID).Scan(&status, &consumed))
		assert.Equal(t, "PENDING", status)
		assert.True(t, consumed)

		restarted := NewService(f.svc.db, f.svc.deploymentID, preg.Management{}, f.backend)
		require.NoError(t, restarted.ResumePending(t.Context()))
		<-f.backend.calls

		result, err := restarted.GetOperation(t.Context(), view.OperationID)
		require.NoError(t, err)
		assert.Equal(t, "CONFIRMED", result.Status)
		assert.Equal(t, "test-original-recovery", result.TxID)

		// Unapproved/legacy pending RecoverIdentity row without challenge link must fail closed.
		_, err = f.svc.db.Exec(t.Context(), `INSERT INTO operations(
			deployment_id, operation_key, operation_id, caller_msp_id, caller_fingerprint,
			method, tx_id, block_no, block_hash, stage, status, validation_code, failure_code, payload_hash, request_json, delivered, updated_at
		) SELECT deployment_id, 'legacy', operation_id||'-legacy', caller_msp_id, caller_fingerprint,
			method, 'legacy-pending', 0, '', 'ACCEPT', 'PENDING', NULL, NULL, payload_hash, request_json, FALSE, NOW()
		  FROM operations WHERE operation_id=$1`, view.OperationID)
		require.NoError(t, err)

		require.NoError(t, restarted.ResumePending(t.Context()))
		legacy, err := restarted.GetOperation(t.Context(), view.OperationID+"-legacy")
		require.NoError(t, err)
		assert.Equal(t, "FAILED", legacy.Status)
		require.NotNil(t, legacy.FailureCode)
		assert.Equal(t, preg.ErrCodeRecoveryProofInvalid, *legacy.FailureCode)
		select {
		case <-f.backend.calls:
			t.Fatal("legacy raw recovery reached backend")
		default:
		}
	})

	t.Run("tampered-queue-fails-closed", func(t *testing.T) {
		f := newRecoveryServiceFixture(t)
		raw, err := json.Marshal(f.bundle)
		require.NoError(t, err)
		view, err := f.svc.Accept(t.Context(), "tampered-queue", f.caller, "RecoverIdentity", raw, false)
		require.NoError(t, err)

		mutation := recoveryMutation(f.bundle.Challenge)
		mutation.PublicKey = "changed-after-approval"
		changed, err := json.Marshal(mutation)
		require.NoError(t, err)
		_, err = f.svc.db.Exec(t.Context(), `UPDATE operations SET request_json=$2 WHERE operation_id=$1`, view.OperationID, changed)
		require.NoError(t, err)

		restarted := NewService(f.svc.db, f.svc.deploymentID, preg.Management{}, f.backend)
		require.NoError(t, restarted.ResumePending(t.Context()))

		result, err := restarted.GetOperation(t.Context(), view.OperationID)
		require.NoError(t, err)
		assert.Equal(t, "FAILED", result.Status)
		require.NotNil(t, result.FailureCode)
		assert.Equal(t, preg.ErrCodeRecoveryProofInvalid, *result.FailureCode)
		select {
		case <-f.backend.calls:
			t.Fatal("modified request reached backend")
		default:
		}
	})

	t.Run("concurrent-consumption-single-use", func(t *testing.T) {
		f := newRecoveryServiceFixture(t)
		raw, err := json.Marshal(f.bundle)
		require.NoError(t, err)

		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for _, key := range []string{"one", "two"} {
			k := key
			wg.Go(func() {
				_, err := f.svc.Accept(t.Context(), k, f.caller, "RecoverIdentity", raw, false)
				errs <- err
			})
		}
		wg.Wait()
		close(errs)

		var accepted, replayed int
		for err := range errs {
			if err == nil {
				accepted++
			} else if protocol.HasCode(err, preg.ErrCodeChallengeReplay) {
				replayed++
			} else {
				t.Fatalf("unexpected concurrent recovery error: %v", err)
			}
		}
		assert.Equal(t, 1, accepted)
		assert.Equal(t, 1, replayed)
	})

	t.Run("rollback-on-queue-insert-failure", func(t *testing.T) {
		f := newRecoveryServiceFixture(t)
		existing, err := f.svc.Accept(t.Context(), "other", f.caller, "RotateIdentity", json.RawMessage(`{"expectedRevision":1}`), false)
		require.NoError(t, err)
		_, err = f.svc.db.Exec(t.Context(), `UPDATE operations SET operation_id=$2 WHERE operation_id=$1`, existing.OperationID, ManagementOperationID(f.svc.deploymentID, f.caller, "RecoverIdentity", "blocked"))
		require.NoError(t, err)

		raw, err := json.Marshal(f.bundle)
		require.NoError(t, err)
		_, err = f.svc.Accept(t.Context(), "blocked", f.caller, "RecoverIdentity", raw, false)
		require.Error(t, err)
		assert.True(t, protocol.HasCode(err, preg.ErrCodeStateUnavailable))

		var consumed bool
		require.NoError(t, f.svc.db.QueryRow(t.Context(), `SELECT consumed FROM recovery_challenges WHERE deployment_id=$1`, f.svc.deploymentID).Scan(&consumed))
		assert.False(t, consumed)

		_, err = f.svc.db.Exec(t.Context(), `DELETE FROM operations WHERE deployment_id=$1`, f.svc.deploymentID)
		require.NoError(t, err)

		view, err := f.svc.Accept(t.Context(), "blocked", f.caller, "RecoverIdentity", raw, false)
		require.NoError(t, err)
		assert.NotEmpty(t, view.OperationID)
	})
}
