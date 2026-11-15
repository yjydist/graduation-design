package fabric

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testPgPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("FABRIC_TEST_DSN")
	if dsn == "" {
		dir := filepath.Join("..", "..", ".local", "fabric-d0")
		inst, err := loadInstance(dir)
		if err != nil {
			t.Skipf("live fabric instance not configured: %v", err)
		}
		host, err := inst.port("FABRIC_DB")
		if err != nil {
			t.Skipf("live fabric DB port unavailable: %v", err)
		}
		pw, err := os.ReadFile(filepath.Join(dir, "view-password"))
		if err != nil {
			t.Skipf("view-password unavailable: %v", err)
		}
		dsn = (&url.URL{
			Scheme:   "postgres",
			Host:     host,
			User:     url.UserPassword("view", strings.TrimSpace(string(pw))),
			Path:     "/fabric",
			RawQuery: "sslmode=disable",
		}).String()
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("postgres connect failed: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("postgres ping failed: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := initSchema(ctx, pool, operationsSchema+viewSchema); err != nil {
		t.Fatalf("initSchema failed: %v", err)
	}
	return pool
}

func makeSelfSignedUserCert(t *testing.T, cn string, now time.Time) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, OrganizationalUnit: []string{"client"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return priv, cert, der
}

func TestRegistrationDualProofSigningAndFlow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dep := protocol.DeploymentBinding{
		ChannelID:     api.Channel,
		GenesisHash:   api.Digest([]byte("test-reg-genesis-" + now.Format(time.RFC3339Nano))),
		InstanceID:    api.Digest([]byte("test-reg-instance-" + now.Format(time.RFC3339Nano))),
		Purpose:       protocol.DeploymentPurpose,
		RegistryName:  api.Registry,
		SchemaVersion: protocol.SchemaVersion,
	}
	depID, err := dep.ComputeID()
	if err != nil {
		t.Fatal(err)
	}

	appPriv, appPubHex, err := protocol.GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	did := "did:web:a.local:test-reg"
	keyID := did + "#key-1"
	doc, err := protocol.NewDIDDocument(did, keyID, appPubHex, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
	if err != nil {
		t.Fatal(err)
	}
	docBytes, err := protocol.MarshalJCS(doc)
	if err != nil {
		t.Fatal(err)
	}
	docDigest := protocol.DigestBytes(docBytes)

	mgmtPriv, mgmtCert, mgmtCertDER := makeSelfSignedUserCert(t, "User5@a.local", now)
	wrongPriv, _, wrongCertDER := makeSelfSignedUserCert(t, "User8@a.local", now)

	// Pure unit check on SignManagementDualProofBundle
	chalOffline := protocol.RegistrationChallenge{
		AccountCommitment: api.Digest([]byte("acct:" + depID + ":" + did)),
		AppKeyID:          keyID,
		AppKeyVersion:     1,
		AppPublicKey:      appPubHex,
		ChallengeID:       "urn:grad:reg-challenge:offline",
		DeploymentID:      depID,
		DIDDocumentDigest: docDigest,
		DomainID:          "A",
		IssuedAt:          now.Unix(),
		ExpiresAt:         now.Unix() + 60,
		ManagementIdentity: protocol.ManagementIdentity{
			CertificateSha256: api.Digest(mgmtCertDER),
			MSPID:             "AMsp",
		},
		Nonce:     "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		Purpose:   protocol.RegistrationChallengePurpose,
		SubjectID: did,
	}
	bundleOffline, err := protocol.SignManagementDualProofBundle(dep, chalOffline, mgmtCertDER, mgmtPriv, appPriv)
	if err != nil {
		t.Fatalf("SignManagementDualProofBundle failed: %v", err)
	}
	if err := bundleOffline.Verify(); err != nil {
		t.Fatalf("signed bundle failed Verify: %v", err)
	}

	pool := testPgPool(t)
	ctx := t.Context()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM registration_challenges WHERE deployment_id=$1", depID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM operations WHERE deployment_id=$1", depID)
	})

	rc := NewRegistrationCoordinator(pool)
	chal, _, err := rc.IssueRegistrationChallenge(ctx, dep, IssueChallengeRequest{
		DomainID:          "A",
		SubjectID:         did,
		AppKeyID:          keyID,
		AppKeyVersion:     1,
		AppPublicKey:      appPubHex,
		DIDDocumentDigest: docDigest,
		AccountCommitment: api.Digest([]byte("acct:" + depID + ":" + did)),
		MSPID:             "AMsp",
		CertificateSha256: api.Digest(mgmtCertDER),
		IssuedAt:          now.Unix(),
		TTLSeconds:        60,
	})
	if err != nil {
		t.Fatalf("IssueRegistrationChallenge failed: %v", err)
	}

	caller := api.Management{MSPID: "AMsp", Fingerprint: api.Digest(mgmtCertDER)}
	checkNotConsumed := func() {
		var consumed bool
		if err := pool.QueryRow(ctx, "SELECT consumed FROM registration_challenges WHERE challenge_id=$1", chal.ChallengeID).Scan(&consumed); err != nil {
			t.Fatalf("query consumed flag: %v", err)
		}
		if consumed {
			t.Fatalf("challenge %s must remain unconsumed after rejected proof", chal.ChallengeID)
		}
	}

	// Negative 1: wrong user cert from same MSP
	wrongBundle, err := protocol.SignManagementDualProofBundle(dep, *chal, wrongCertDER, wrongPriv, appPriv)
	if err != nil {
		t.Fatalf("SignManagementDualProofBundle with wrong cert: %v", err)
	}
	if err := rc.AcceptRegistrationBundle(ctx, "reg-wrong-cert", depID+":reg-wrong-cert", caller, wrongBundle, "AMsp", []*x509.Certificate{mgmtCert}, docBytes, now.Unix(), nil); err == nil {
		t.Fatal("expected rejection for wrong user certificate in same MSP")
	}
	checkNotConsumed()

	// Negative 2: replaced challenge / nonce
	validBundle, err := protocol.SignManagementDualProofBundle(dep, *chal, mgmtCertDER, mgmtPriv, appPriv)
	if err != nil {
		t.Fatal(err)
	}
	otherChal := *chal
	otherNonce, _ := protocol.GenerateNonce()
	otherChal.Nonce = otherNonce
	replacedBundle, err := protocol.SignManagementDualProofBundle(dep, otherChal, mgmtCertDER, mgmtPriv, appPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.AcceptRegistrationBundle(ctx, "reg-replaced-nonce", depID+":reg-replaced-nonce", caller, replacedBundle, "AMsp", []*x509.Certificate{mgmtCert}, docBytes, now.Unix(), nil); err == nil {
		t.Fatal("expected rejection for replaced nonce")
	}
	checkNotConsumed()

	// Negative 3: missing management signature
	missingMgmtSig := *validBundle
	missingMgmtSig.ManagementSignatureDER = ""
	if err := rc.AcceptRegistrationBundle(ctx, "reg-no-mgmt-sig", depID+":reg-no-mgmt-sig", caller, &missingMgmtSig, "AMsp", []*x509.Certificate{mgmtCert}, docBytes, now.Unix(), nil); !protocol.HasCode(err, protocol.ErrCodeRegistrationProofInvalid) {
		t.Fatalf("expected REGISTRATION_PROOF_INVALID for missing management signature, got %v", err)
	}
	checkNotConsumed()

	// Negative 4: missing DID application proof
	missingAppSig := *validBundle
	missingAppSig.AppJWSSignature = ""
	if err := rc.AcceptRegistrationBundle(ctx, "reg-no-app-sig", depID+":reg-no-app-sig", caller, &missingAppSig, "AMsp", []*x509.Certificate{mgmtCert}, docBytes, now.Unix(), nil); !protocol.HasCode(err, protocol.ErrCodeRegistrationProofInvalid) {
		t.Fatalf("expected REGISTRATION_PROOF_INVALID for missing DID proof, got %v", err)
	}
	checkNotConsumed()

	// Positive: valid dual proof consumes challenge and records operations row
	opKey := "reg-valid-pa"
	opID := depID + ":" + opKey
	if err := rc.AcceptRegistrationBundle(ctx, opKey, opID, caller, validBundle, "AMsp", []*x509.Certificate{mgmtCert}, docBytes, now.Unix(), func(context.Context) (*SubmitResult, error) {
		return &SubmitResult{
			Method:    "RegisterIdentity",
			TxID:      api.Digest([]byte("tx-" + opID)),
			BlockNo:   42,
			BlockHash: api.Digest([]byte("block-42")),
		}, nil
	}); err != nil {
		t.Fatalf("valid AcceptRegistrationBundle failed: %v", err)
	}

	var consumed bool
	var consumedBy string
	if err := pool.QueryRow(ctx, "SELECT consumed, consumed_by_operation_id FROM registration_challenges WHERE challenge_id=$1", chal.ChallengeID).Scan(&consumed, &consumedBy); err != nil {
		t.Fatal(err)
	}
	if !consumed || consumedBy != opID {
		t.Fatalf("expected challenge consumed by %s, got consumed=%v by=%q", opID, consumed, consumedBy)
	}
	var opStatus string
	var opBlock int64
	if err := pool.QueryRow(ctx, "SELECT status, block_no FROM operations WHERE operation_id=$1", opID).Scan(&opStatus, &opBlock); err != nil {
		t.Fatal(err)
	}
	if opStatus != "CONFIRMED" || opBlock != 42 {
		t.Fatalf("unexpected operations row: status=%s block=%d", opStatus, opBlock)
	}

	// Replay of consumed challenge must fail
	if err := rc.AcceptRegistrationBundle(ctx, "reg-replay", depID+":reg-replay", caller, validBundle, "AMsp", []*x509.Certificate{mgmtCert}, docBytes, now.Unix(), nil); !protocol.HasCode(err, protocol.ErrCodeChallengeReplay) {
		t.Fatalf("expected CHALLENGE_REPLAY on reused challenge, got %v", err)
	}
}

func TestCertificationAndGrantDeliveryFlow(t *testing.T) {
	pool := testPgPool(t)
	ctx := t.Context()

	dir := t.TempDir()
	inst := &instance{dir: dir, env: map[string]string{}}
	writeTestRoleCerts(t, inst)

	genesis := &block{}
	genesis.Hash = api.Digest([]byte("test-delivery-genesis"))
	boot, bootRaw, err := inst.bootstrap(genesis)
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
	dep := &deployment{
		DeploymentFields: boot.DeploymentFields,
		DeploymentID:     api.Digest(bootRaw),
		Bootstrap:        boot,
	}
	f, err := inst.fixtures(dep)
	if err != nil {
		t.Fatalf("fixtures failed: %v", err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM certification_outbox WHERE deployment_id=$1", dep.DeploymentID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM certification_receipts WHERE deployment_id=$1", dep.DeploymentID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM grant_outbox WHERE deployment_id=$1", dep.DeploymentID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM wallet_receipts WHERE deployment_id=$1", dep.DeploymentID)
	})

	// Verify PA, U, C credentials and roles
	if f.Identities["PA"].ID != "did:web:a.local:pa" || f.Identities["PA"].Kind != "SERVICE" {
		t.Fatalf("unexpected PA fixture identity: %+v", f.Identities["PA"])
	}
	now := time.Now().UTC().Unix()
	snap := &protocol.SnapshotView{
		Height:         5,
		Now:            time.Unix(now, 0).UTC(),
		DeploymentID:   dep.DeploymentID,
		Root:           boot.Root,
		Domains:        make(map[string]api.Domain),
		Certifications: make(map[string]api.Certification),
		Identities:     make(map[string]api.Identity),
		Credentials:    make(map[string]api.Credential),
		Tasks:          map[string]api.Task{f.Task.ID: activateTaskSnapshot(f.Task)},
		Grants:         map[string]api.Grant{f.G0.ID: activateGrantSnapshot(f.G0)},
	}
	for domID, db := range f.Domains {
		d := db.Domain
		d.Issuers = []string{db.Issuers[0].ID}
		d.Certification = f.Certifications[domID].Certification.ID
		d.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Domains[domID] = d
		c := f.Certifications[domID].Certification
		c.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Certifications[c.ID] = c
		di := db.Identity
		di.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Identities[di.ID] = di
		ii := db.Issuers[0]
		ii.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Identities[ii.ID] = ii
	}
	for role, id := range f.Identities {
		id.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Identities[id.ID] = id
		cred := f.Credentials[role]
		cred.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Credentials[cred.ID] = cred
	}

	rootPub, _, err := protocol.ParseAppPublicKey(boot.Root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	icPub, _, err := protocol.ParseAppPublicKey(f.Domains["C"].Issuers[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	iaPub, _, err := protocol.ParseAppPublicKey(f.Domains["A"].Issuers[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cPub, _, err := protocol.ParseAppPublicKey(f.Identities["C"].PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Verify U, PA, C SD-JWT role claims
	for role, wantRole := range map[string]string{
		"U":  "procurement-owner",
		"PA": "procurement-authority",
		"C":  "supplier-service",
	} {
		raw, err := os.ReadFile(inst.registrySubPath("credentials", role+".sdjwt"))
		if err != nil {
			t.Fatal(err)
		}
		issPub := iaPub
		issKID := f.Domains["A"].Issuers[0].KeyID
		if role == "C" {
			issPub = icPub
			issKID = f.Domains["C"].Issuers[0].KeyID
		}
		vc, err := protocol.VerifySDJWTCredential(string(raw), issPub, issKID, f.Identities[role].PublicKey, false)
		if err != nil {
			t.Fatalf("verify %s SD-JWT failed: %v", role, err)
		}
		if vc.Role != wantRole {
			t.Fatalf("role %s claim = %q, want %q", role, vc.Role, wantRole)
		}
	}

	ds := NewDeliveryService(pool)

	// Task 1.2 negative: SyncCertificationReceipt before outbox exists -> 503 MATERIAL_NOT_SYNCED
	if _, err := ds.SyncCertificationReceipt(ctx, snap, f.Identities["U"].ID, "C", rootPub, now); !protocol.HasCode(err, protocol.ErrCodeMaterialNotSynced) {
		t.Fatalf("expected MATERIAL_NOT_SYNCED before publish, got %v", err)
	}

	certAJWS, err := os.ReadFile(inst.registrySubPath("certifications", "A.jws"))
	if err != nil {
		t.Fatal(err)
	}
	certCJWS, err := os.ReadFile(inst.registrySubPath("certifications", "C.jws"))
	if err != nil {
		t.Fatal(err)
	}

	// Task 1.2 negative: invalid original tx OR tampered cert JWS rejected
	if err := ds.PublishDomainCertification(ctx, snap, f.Identities["U"].ID, "C", string(certCJWS), rootPub, "tx-bad", 3, false, now); !protocol.HasCode(err, protocol.ErrCodeMaterialInvalid) {
		t.Fatalf("expected MATERIAL_INVALID for non-VALID tx, got %v", err)
	}
	if err := ds.PublishDomainCertification(ctx, snap, f.Identities["U"].ID, "C", string(certAJWS), rootPub, "tx-mismatch", 3, true, now); !protocol.HasCode(err, protocol.ErrCodeDomainCertificationInvalid) {
		t.Fatalf("expected DOMAIN_CERTIFICATION_INVALID for mismatched domain cert anchor, got %v", err)
	}

	// Prepare C -> U G0 package bytes
	g0Raw, err := os.ReadFile(inst.registrySubPath("grants", "g0.jws"))
	if err != nil {
		t.Fatal(err)
	}
	cSD, err := os.ReadFile(inst.registrySubPath("credentials", "C.sdjwt"))
	if err != nil {
		t.Fatal(err)
	}
	pkg := GrantDeliveryPackage{
		DeploymentID:           dep.DeploymentID,
		Recipient:              f.Identities["U"].ID,
		GrantID:                f.G0.ID,
		GrantJWS:               string(g0Raw),
		TaskSpec:               f.TaskSpec,
		ServicePresentation:    string(cSD),
		DomainCertificationJWS: string(certCJWS),
	}

	// Task 1.3 negative: missing synced C domain certification -> MATERIAL_NOT_SYNCED, no wallet_receipts write
	if _, err := ds.PublishGrantOutbox(ctx, snap, pkg, rootPub, icPub, cPub, "tx-g0", 6, true, now); !protocol.HasCode(err, protocol.ErrCodeMaterialNotSynced) {
		t.Fatalf("expected MATERIAL_NOT_SYNCED for grant outbox without synced C cert, got %v", err)
	}
	if _, _, err := ds.DeliverGrantReceipt(ctx, snap, dep.DeploymentID, f.Identities["U"].ID, f.G0.ID, &pkg, rootPub, icPub, cPub, now); !protocol.HasCode(err, protocol.ErrCodeMaterialNotSynced) {
		t.Fatalf("expected MATERIAL_NOT_SYNCED for wallet delivery without synced C cert, got %v", err)
	}
	var receiptCnt int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM wallet_receipts WHERE deployment_id=$1", dep.DeploymentID).Scan(&receiptCnt); err != nil {
		t.Fatal(err)
	}
	if receiptCnt != 0 {
		t.Fatalf("expected 0 wallet_receipts rows on MATERIAL_NOT_SYNCED, got %d", receiptCnt)
	}

	// Task 1.2 positive: publish and sync A and C domain certifications
	if err := ds.PublishDomainCertification(ctx, snap, f.Identities["U"].ID, "A", string(certAJWS), rootPub, "tx-cert-A", 2, true, now); err != nil {
		t.Fatalf("PublishDomainCertification A failed: %v", err)
	}
	if _, err := ds.SyncCertificationReceipt(ctx, snap, f.Identities["U"].ID, "A", rootPub, now); err != nil {
		t.Fatalf("SyncCertificationReceipt A failed: %v", err)
	}
	if err := ds.PublishDomainCertification(ctx, snap, f.Identities["U"].ID, "C", string(certCJWS), rootPub, "tx-cert-C", 3, true, now); err != nil {
		t.Fatalf("PublishDomainCertification C failed: %v", err)
	}
	gotCertC, err := ds.SyncCertificationReceipt(ctx, snap, f.Identities["U"].ID, "C", rootPub, now)
	if err != nil || gotCertC != string(certCJWS) {
		t.Fatalf("SyncCertificationReceipt C failed: %v", err)
	}

	// Task 1.3 positive: PublishGrantOutbox + DeliverGrantReceipt + idempotent retry
	dig1, err := ds.PublishGrantOutbox(ctx, snap, pkg, rootPub, icPub, cPub, "tx-g0", 6, true, now)
	if err != nil {
		t.Fatalf("PublishGrantOutbox failed: %v", err)
	}
	dig2, err := ds.PublishGrantOutbox(ctx, snap, pkg, rootPub, icPub, cPub, "tx-g0", 6, true, now)
	if err != nil || dig2 != dig1 {
		t.Fatalf("idempotent PublishGrantOutbox failed: dig=%s err=%v", dig2, err)
	}
	delPkg, delDig1, err := ds.DeliverGrantReceipt(ctx, snap, dep.DeploymentID, f.Identities["U"].ID, f.G0.ID, nil, rootPub, icPub, cPub, now)
	if err != nil || delDig1 != dig1 || delPkg.GrantID != f.G0.ID {
		t.Fatalf("DeliverGrantReceipt failed: %v", err)
	}
	_, delDig2, err := ds.DeliverGrantReceipt(ctx, snap, dep.DeploymentID, f.Identities["U"].ID, f.G0.ID, nil, rootPub, icPub, cPub, now)
	if err != nil || delDig2 != delDig1 {
		t.Fatalf("idempotent DeliverGrantReceipt failed: %v", err)
	}

	// Task 1.3 negative: conflicting package under same (deploymentId, recipient, grantId) -> 409 DELIVERY_CONFLICT
	privIC, err := loadECPrivateKeyPEM(inst.privatePath("app", "IC.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	privT, err := loadECPrivateKeyPEM(inst.privatePath("app", "T.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	_ = privT
	// Re-issue an alternate ServicePresentation with identical on-chain hash? Wait: any valid different package
	// triggers DELIVERY_CONFLICT as soon as verified digest differs (e.g. TaskSpec has matching digest unless
	// we swap C service cred to C-service-v1 or different salt disclosures with same anchor or different valid SDJWT).
	holderJWKC, err := protocol.AppPublicKeyToJWK(f.Identities["C"].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	valid := f.Certifications["C"].Certification.Interval
	altSD, err := protocol.IssueEnterpriseIdentityCredential(
		privIC,
		f.Domains["C"].Issuers[0].KeyID,
		protocol.EnterpriseIdentityCredential{
			Type:              []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity},
			ID:                "urn:grad:credential:C-alt-v1",
			DeploymentID:      dep.DeploymentID,
			Issuer:            f.Domains["C"].Issuers[0].ID,
			Iss:               f.Domains["C"].Issuers[0].ID,
			Sub:               f.Identities["C"].ID,
			IssuerKeyVersion:  f.Domains["C"].Issuers[0].KeyVersion,
			AppKeyVersion:     f.Identities["C"].KeyVersion,
			ValidFrom:         time.Unix(valid.NBF, 0).UTC().Format(time.RFC3339),
			ValidUntil:        time.Unix(valid.EXP, 0).UTC().Format(time.RFC3339),
			NBF:               valid.NBF,
			EXP:               valid.EXP,
			CredentialStatus:  protocol.CredentialStatus{ID: "urn:grad:credential:C-alt-v1", Type: protocol.StatusTypeCredential},
			Cnf:               protocol.ConfirmationKey{JWK: holderJWKC},
			CredentialSubject: protocol.SDJWTCredentialSubject{ID: f.Identities["C"].ID},
		},
		"C",
		"supplier-service",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	snap.Credentials["urn:grad:credential:C-alt-v1"] = api.Credential{
		Bound:             api.Bound{DeploymentID: dep.DeploymentID},
		ID:                "urn:grad:credential:C-alt-v1",
		Issuer:            f.Domains["C"].Issuers[0].ID,
		Subject:           f.Identities["C"].ID,
		IssuerKeyVersion:  f.Domains["C"].Issuers[0].KeyVersion,
		SubjectKeyVersion: f.Identities["C"].KeyVersion,
		Type:              protocol.CredentialTypeEnterpriseIdentity,
		ClaimNames:        []string{"domain", "role"},
		Digest:            altSD.AnchorDigest,
		Interval:          valid,
		Version:           api.Version{Status: api.Active, Revision: 1},
	}
	conflictPkg := pkg
	conflictPkg.ServicePresentation = altSD.PresentationPrefix
	if _, err := ds.PublishGrantOutbox(ctx, snap, conflictPkg, rootPub, icPub, cPub, "tx-g0-conflict", 7, true, now); !protocol.HasCode(err, protocol.ErrCodeDeliveryConflict) {
		t.Fatalf("expected DELIVERY_CONFLICT on grant_outbox, got %v", err)
	}
	if _, _, err := ds.DeliverGrantReceipt(ctx, snap, dep.DeploymentID, f.Identities["U"].ID, f.G0.ID, &conflictPkg, rootPub, icPub, cPub, now); !protocol.HasCode(err, protocol.ErrCodeDeliveryConflict) {
		t.Fatalf("expected DELIVERY_CONFLICT on wallet_receipts, got %v", err)
	}
}

func TestM2MultiHopDeliveryAndTrustPathDedup(t *testing.T) {
	pool := testPgPool(t)
	ctx := t.Context()

	dir := t.TempDir()
	inst := &instance{dir: dir, env: map[string]string{}}
	writeTestRoleCerts(t, inst)

	genesis := &block{}
	genesis.Hash = api.Digest([]byte("test-m2-delivery-genesis"))
	boot, bootRaw, err := inst.bootstrap(genesis)
	if err != nil {
		t.Fatal(err)
	}
	dep := &deployment{DeploymentFields: boot.DeploymentFields, DeploymentID: api.Digest(bootRaw), Bootstrap: boot}
	f, err := inst.fixtures(dep)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM certification_outbox WHERE deployment_id=$1", dep.DeploymentID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM certification_receipts WHERE deployment_id=$1", dep.DeploymentID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM grant_outbox WHERE deployment_id=$1", dep.DeploymentID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM wallet_receipts WHERE deployment_id=$1", dep.DeploymentID)
	})

	// Test BuildAccessTrustPaths deduplicates IA across U and A1 while sorting UTF-16 ascending.
	snap := &protocol.SnapshotView{
		Height: 1, Now: time.Now().UTC(), DeploymentID: dep.DeploymentID, Root: boot.Root,
		Domains: map[string]api.Domain{}, Certifications: map[string]api.Certification{},
		Identities: map[string]api.Identity{}, Credentials: map[string]api.Credential{},
		Tasks: map[string]api.Task{}, Grants: map[string]api.Grant{},
	}
	for domID, db := range f.Domains {
		d := db.Domain
		d.Issuers = []string{db.Issuers[0].ID}
		d.Certification = f.Certifications[domID].Certification.ID
		d.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Domains[domID] = d
		snap.Identities[db.Issuers[0].ID] = db.Issuers[0]
	}
	tp, err := BuildAccessTrustPaths(
		map[string]string{"A": "certA", "B": "certB", "C": "certC"},
		snap,
		f.Domains["B"].Issuers[0].ID,
		f.Domains["A"].Issuers[0].ID,
		f.Domains["A"].Issuers[0].ID,
	)
	if err != nil || len(tp) != 2 || tp[0].Issuer != f.Domains["A"].Issuers[0].ID || tp[1].Issuer != f.Domains["B"].Issuers[0].ID {
		t.Fatalf("unexpected deduplicated trustPaths: %+v err=%v", tp, err)
	}

	// Sync all M2 outboxes & receipts via syncMaterialOutboxes.
	report := &seedReport{fixtures: f}
	if err := inst.syncMaterialOutboxes(ctx, journal{db: pool}, dep, f, report); err != nil {
		t.Fatalf("syncMaterialOutboxes failed: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM wallet_receipts WHERE deployment_id=$1", dep.DeploymentID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	// Expect 1 legacy M1 G0 + 3 RP hops + 3 BM hops = 7 wallet_receipts rows.
	if count != 7 {
		t.Fatalf("expected 7 wallet_receipts rows for M1+M2 delivery, got %d", count)
	}
}

