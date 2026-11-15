package fabric

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf16"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IssueChallengeRequest defines parameters for issuing a registration challenge.
type IssueChallengeRequest struct {
	ChallengeID       string
	DomainID          string
	SubjectID         string
	AppKeyID          string
	AppKeyVersion     int64
	AppPublicKey      string
	DIDDocumentDigest string
	AccountCommitment string
	MSPID             string
	CertificateSha256 string
	IssuedAt          int64
	TTLSeconds        int64
}

// RegistrationCoordinator manages registration challenges and dual-proof verification in PostgreSQL.
type RegistrationCoordinator struct {
	db *pgxpool.Pool
}

// NewRegistrationCoordinator constructs a RegistrationCoordinator backed by db.
func NewRegistrationCoordinator(db *pgxpool.Pool) *RegistrationCoordinator {
	return &RegistrationCoordinator{db: db}
}

// IssueRegistrationChallenge creates and persists a fresh registration challenge in registration_challenges.
func (rc *RegistrationCoordinator) IssueRegistrationChallenge(
	ctx context.Context,
	dep protocol.DeploymentBinding,
	req IssueChallengeRequest,
) (*protocol.RegistrationChallenge, string, error) {
	if rc == nil || rc.db == nil {
		return nil, "", protocol.NewError(protocol.ErrCodeStateUnavailable, "registration store not configured")
	}
	depID, err := dep.ComputeID()
	if err != nil {
		return nil, "", err
	}
	nonce, err := protocol.GenerateNonce()
	if err != nil {
		return nil, "", err
	}
	chalID := req.ChallengeID
	if chalID == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return nil, "", err
		}
		chalID = "urn:grad:reg-challenge:" + hex.EncodeToString(raw)
	}
	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 60
	}
	keyVer := req.AppKeyVersion
	if keyVer <= 0 {
		keyVer = 1
	}
	chal := &protocol.RegistrationChallenge{
		AccountCommitment: req.AccountCommitment,
		AppKeyID:          req.AppKeyID,
		AppKeyVersion:     keyVer,
		AppPublicKey:      req.AppPublicKey,
		ChallengeID:       chalID,
		DeploymentID:      depID,
		DIDDocumentDigest: req.DIDDocumentDigest,
		DomainID:          req.DomainID,
		ExpiresAt:         req.IssuedAt + ttl,
		IssuedAt:          req.IssuedAt,
		ManagementIdentity: protocol.ManagementIdentity{
			CertificateSha256: req.CertificateSha256,
			MSPID:             req.MSPID,
		},
		Nonce:     nonce,
		Purpose:   protocol.RegistrationChallengePurpose,
		SubjectID: req.SubjectID,
	}
	jcsBytes, err := protocol.MarshalJCS(chal)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(jcsBytes)
	chalSha256 := hex.EncodeToString(sum[:])

	_, err = rc.db.Exec(ctx, `INSERT INTO registration_challenges(
		challenge_id, deployment_id, challenge_sha256, msp_id, certificate_sha256,
		domain_id, subject_id, app_key_id, nonce, challenge_json, issued_at, expires_at, consumed
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,FALSE)`,
		chal.ChallengeID, depID, chalSha256, req.MSPID, req.CertificateSha256,
		req.DomainID, req.SubjectID, req.AppKeyID, nonce, jcsBytes, chal.IssuedAt, chal.ExpiresAt,
	)
	if err != nil {
		return nil, "", err
	}
	return chal, chalSha256, nil
}

// SubmitResult captures the confirmed Fabric transaction coordinates returned by submitFn.
type SubmitResult struct {
	Method      string
	TxID        string
	BlockNo     int64
	BlockHash   string
	PayloadHash string
}

// AcceptRegistrationBundle validates a submitted ManagementDualProofBundle against the persisted
// registration challenge, optional authorized MSP certificates, and optional DID document before
// atomically consuming the challenge and persisting the operations record.
func (rc *RegistrationCoordinator) AcceptRegistrationBundle(
	ctx context.Context,
	operationKey string,
	operationID string,
	caller api.Management,
	bundle *protocol.ManagementDualProofBundle,
	expectedMSPID string,
	authorizedCerts []*x509.Certificate,
	didDocBytes []byte,
	now int64,
	submitFn func(context.Context) (*SubmitResult, error),
) error {
	if rc == nil || rc.db == nil {
		return protocol.NewError(protocol.ErrCodeStateUnavailable, "registration store not configured")
	}
	if bundle == nil {
		return protocol.NewError(protocol.ErrCodeInvalidSchema, "nil ManagementDualProofBundle")
	}
	if bundle.ManagementSignatureDER == "" || bundle.ManagementCertificateDER == "" ||
		bundle.AppJWSProtected == "" || bundle.AppJWSSignature == "" {
		return protocol.NewError(protocol.ErrCodeRegistrationProofInvalid, "missing management or DID proof")
	}

	tx, err := rc.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	var (
		storedDepID      string
		storedChalSha256 string
		storedMSPID      string
		storedCertSha256 string
		storedDomainID   string
		storedSubjectID  string
		storedAppKeyID   string
		storedNonce      string
		storedIssuedAt   int64
		storedExpiresAt  int64
		consumed         bool
	)
	err = tx.QueryRow(ctx, `SELECT deployment_id, challenge_sha256, msp_id, certificate_sha256,
		domain_id, subject_id, app_key_id, nonce, issued_at, expires_at, consumed
		FROM registration_challenges WHERE challenge_id=$1 FOR UPDATE`, bundle.Challenge.ChallengeID).
		Scan(&storedDepID, &storedChalSha256, &storedMSPID, &storedCertSha256,
			&storedDomainID, &storedSubjectID, &storedAppKeyID, &storedNonce, &storedIssuedAt, &storedExpiresAt, &consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return protocol.NewError(protocol.ErrCodeChallengeUnknown, "unknown registration challenge")
	}
	if err != nil {
		return err
	}
	if consumed {
		return protocol.NewError(protocol.ErrCodeChallengeReplay, "registration challenge already consumed")
	}
	if expectedMSPID != "" && expectedMSPID != storedMSPID {
		return protocol.NewError(protocol.ErrCodeRegistrationProofInvalid, "caller MSP mismatch")
	}
	if now < storedIssuedAt || now >= storedExpiresAt {
		return protocol.NewError(protocol.ErrCodeChallengeExpired, "registration challenge expired")
	}

	if bundle.DeploymentID != storedDepID ||
		bundle.Challenge.DeploymentID != storedDepID ||
		bundle.ChallengeSha256 != storedChalSha256 ||
		bundle.Challenge.Nonce != storedNonce ||
		bundle.Challenge.DomainID != storedDomainID ||
		bundle.Challenge.SubjectID != storedSubjectID ||
		bundle.Challenge.AppKeyID != storedAppKeyID ||
		bundle.Challenge.ManagementIdentity.MSPID != storedMSPID ||
		bundle.Challenge.ManagementIdentity.CertificateSha256 != storedCertSha256 {
		return protocol.NewError(protocol.ErrCodeChallengeMismatch, "registration bundle does not match issued challenge")
	}

	if err := bundle.Verify(); err != nil {
		return protocol.WrapError(protocol.ErrCodeRegistrationProofInvalid, "dual proof verification failed", err)
	}

	certDER, err := base64.RawURLEncoding.DecodeString(bundle.ManagementCertificateDER)
	if err != nil {
		return protocol.WrapError(protocol.ErrCodeRegistrationProofInvalid, "decode management certificate", err)
	}
	leafCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return protocol.WrapError(protocol.ErrCodeRegistrationProofInvalid, "parse management certificate", err)
	}
	if len(authorizedCerts) > 0 {
		if err := verifyAuthorizedMgmtCert(leafCert, authorizedCerts); err != nil {
			return err
		}
	}

	if len(didDocBytes) > 0 {
		doc, dig, err := protocol.ParseDIDDocument(didDocBytes)
		if err != nil {
			return protocol.WrapError(protocol.ErrCodeRegistrationProofInvalid, "parse DID document", err)
		}
		if dig != bundle.Challenge.DIDDocumentDigest {
			return protocol.NewError(protocol.ErrCodeDIDDocumentMismatch, "DID document digest mismatches challenge")
		}
		if _, _, err := doc.ResolveKey(bundle.Challenge.AppKeyID, protocol.KeyPurposeAuthentication, bundle.Challenge.AppPublicKey); err != nil {
			return protocol.WrapError(protocol.ErrCodeDIDDocumentMismatch, "DID key mismatch", err)
		}
	}

	var res SubmitResult
	if submitFn != nil {
		out, err := submitFn(ctx)
		if err != nil {
			return err
		}
		if out != nil {
			res = *out
		}
	}
	if res.PayloadHash == "" {
		res.PayloadHash = bundle.ChallengeSha256
	}
	if res.Method == "" {
		res.Method = "RegisterIdentity"
	}

	if _, err := tx.Exec(ctx, `UPDATE registration_challenges
		SET consumed=TRUE, consumed_by_operation_id=$2, consumed_at=$3
		WHERE challenge_id=$1`, bundle.Challenge.ChallengeID, operationID, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO operations(
		deployment_id, operation_key, operation_id, caller_msp_id, caller_fingerprint,
		method, tx_id, block_no, block_hash, stage, status, validation_code, failure_code, payload_hash, updated_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'COMMIT','CONFIRMED','VALID',NULL,$10,NOW())
	ON CONFLICT(deployment_id, operation_key) DO UPDATE SET
		tx_id=EXCLUDED.tx_id, block_no=EXCLUDED.block_no, block_hash=EXCLUDED.block_hash,
		stage='COMMIT', status='CONFIRMED', validation_code='VALID', failure_code=NULL, updated_at=NOW()`,
		bundle.DeploymentID, operationKey, operationID, caller.MSPID, caller.Fingerprint,
		res.Method, res.TxID, res.BlockNo, res.BlockHash, res.PayloadHash); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func verifyAuthorizedMgmtCert(leaf *x509.Certificate, authorized []*x509.Certificate) error {
	var leafAllowed []*x509.Certificate
	roots := x509.NewCertPool()
	hasCA := false
	for _, c := range authorized {
		if c.IsCA {
			roots.AddCert(c)
			hasCA = true
		} else {
			leafAllowed = append(leafAllowed, c)
		}
	}
	if len(leafAllowed) > 0 {
		matched := false
		for _, allowed := range leafAllowed {
			if bytes.Equal(leaf.Raw, allowed.Raw) {
				matched = true
				break
			}
		}
		if !matched {
			return protocol.NewError(protocol.ErrCodeSignatureInvalid, "management certificate does not match authorized account certificate in MSP")
		}
	}
	if hasCA {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
			return protocol.WrapError(protocol.ErrCodeSignatureInvalid, "management certificate not issued by MSP CA", err)
		}
	}
	return nil
}

// GrantDeliveryPackage bundles C/PA -> U (or grantor -> grantee) root or delegated grant delivery materials
// verified prior to writing grant_outbox and wallet_receipts.
type GrantDeliveryPackage struct {
	DeploymentID           string                             `json:"deploymentId"`
	Recipient              string                             `json:"recipient"`
	GrantID                string                             `json:"grantId"`
	GrantJWS               string                             `json:"grantJws"`
	TaskSpec               protocol.TaskSpec                  `json:"taskSpec"`
	ServicePresentation    string                             `json:"servicePresentation"`
	DomainCertificationJWS string                             `json:"domainCertificationJws"`
	AncestorGrants         []string                      `json:"ancestorGrants,omitempty"`
	AncestorCredentials    []protocol.AncestorCredential `json:"ancestorCredentials,omitempty"`
	TrustPaths             []protocol.TrustPathEntry     `json:"trustPaths,omitempty"`
}

// BuildAccessTrustPaths constructs a deduplicated, UTF-16 ascending trustPaths slice
// ordered by credential issuer DID using domain certification JWS documents mapped by domainID.
func BuildAccessTrustPaths(certJWSByDomain map[string]string, snap *protocol.SnapshotView, issuerDIDs ...string) ([]protocol.TrustPathEntry, error) {
	if snap == nil {
		return nil, protocol.NewError(protocol.ErrCodeStateUnavailable, "snapshot view required to build trustPaths")
	}
	seen := make(map[string]struct{}, len(issuerDIDs))
	unique := make([]string, 0, len(issuerDIDs))
	for _, iss := range issuerDIDs {
		if iss == "" {
			continue
		}
		if _, ok := seen[iss]; ok {
			continue
		}
		seen[iss] = struct{}{}
		unique = append(unique, iss)
	}
	slices.SortFunc(unique, func(a, b string) int {
		ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
		n := len(ua)
		if len(ub) < n {
			n = len(ub)
		}
		for i := 0; i < n; i++ {
			if ua[i] < ub[i] {
				return -1
			}
			if ua[i] > ub[i] {
				return 1
			}
		}
		return len(ua) - len(ub)
	})
	out := make([]protocol.TrustPathEntry, 0, len(unique))
	for _, iss := range unique {
		idRec, ok := snap.Identities[iss]
		if !ok {
			return nil, protocol.NewError(protocol.ErrCodeIssuerScopeInvalid, fmt.Sprintf("issuer identity %q not found in snapshot", iss))
		}
		certJWS := certJWSByDomain[idRec.Domain]
		if certJWS == "" {
			return nil, protocol.NewError(protocol.ErrCodeMaterialNotSynced, fmt.Sprintf("missing domain certification JWS for domain %q", idRec.Domain))
		}
		out = append(out, protocol.TrustPathEntry{
			Issuer:              iss,
			DomainCertification: certJWS,
		})
	}
	return out, nil
}

// PackageDigest computes SHA-256(JCS(GrantDeliveryPackage)) as 64-char lowercase hex.
func (p GrantDeliveryPackage) Digest() ([]byte, string, error) {
	canon, err := protocol.MarshalJCS(p)
	if err != nil {
		return nil, "", err
	}
	return canon, api.Digest(canon), nil
}

// DeliveryService implements controlled outbox/receipt synchronization for domain certifications
// and root grant packages against synchronized ledger snapshots.
type DeliveryService struct {
	db *pgxpool.Pool
}

// NewDeliveryService creates a DeliveryService backed by db.
func NewDeliveryService(db *pgxpool.Pool) *DeliveryService {
	return &DeliveryService{db: db}
}

// PublishDomainCertification verifies T's DomainAuthorityCredential JWS against the fixed-height snapshot
// (and confirms original transaction VALID status) before persisting raw JWS bytes into certification_outbox.
func (ds *DeliveryService) PublishDomainCertification(
	ctx context.Context,
	snap *protocol.SnapshotView,
	recipient string,
	domainID string,
	certJWS string,
	rootPub *ecdsa.PublicKey,
	txID string,
	blockNo int64,
	origValid bool,
	now int64,
) error {
	if ds == nil || ds.db == nil {
		return protocol.NewError(protocol.ErrCodeStateUnavailable, "delivery store not configured")
	}
	if snap == nil {
		return protocol.NewError(protocol.ErrCodeStateUnavailable, "snapshot view required")
	}
	if !origValid {
		return protocol.NewError(protocol.ErrCodeMaterialInvalid, "original certification transaction is not VALID")
	}
	if recipient == "" || certJWS == "" {
		return protocol.NewError(protocol.ErrCodeInvalidSchema, "recipient and certJws are required")
	}
	cert, err := verifyDomainCertAgainstSnap(snap, domainID, certJWS, rootPub, now)
	if err != nil {
		return err
	}
	_, err = ds.db.Exec(ctx, `INSERT INTO certification_outbox(
		deployment_id, domain_id, certification_id, recipient, cert_jws, cert_digest,
		root_key_version, tx_id, block_no, created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	ON CONFLICT(deployment_id, domain_id, certification_id, recipient) DO UPDATE SET
		cert_jws=EXCLUDED.cert_jws, cert_digest=EXCLUDED.cert_digest,
		root_key_version=EXCLUDED.root_key_version, tx_id=EXCLUDED.tx_id, block_no=EXCLUDED.block_no`,
		snap.DeploymentID, domainID, cert.ID, recipient, certJWS, cert.Digest,
		cert.RootKeyVersion, txID, blockNo, now,
	)
	return err
}

// SyncCertificationReceipt pulls the raw domain certification JWS from certification_outbox,
// verifies it against the current snapshot anchor, and writes certification_receipts.
// Missing outbox material returns 503 MATERIAL_NOT_SYNCED without writing certification_receipts.
func (ds *DeliveryService) SyncCertificationReceipt(
	ctx context.Context,
	snap *protocol.SnapshotView,
	recipient string,
	domainID string,
	rootPub *ecdsa.PublicKey,
	now int64,
) (string, error) {
	if ds == nil || ds.db == nil {
		return "", protocol.NewError(protocol.ErrCodeStateUnavailable, "delivery store not configured")
	}
	if snap == nil {
		return "", protocol.NewError(protocol.ErrCodeStateUnavailable, "snapshot view required")
	}
	dom, ok := snap.Domains[domainID]
	if !ok || dom.DeploymentID != snap.DeploymentID || dom.Status != api.Active || dom.Certification == "" {
		return "", protocol.NewError(protocol.ErrCodeDomainCertificationInvalid, fmt.Sprintf("domain %q inactive or missing certification", domainID))
	}
	certAnchor, ok := snap.Certifications[dom.Certification]
	if !ok || certAnchor.DeploymentID != snap.DeploymentID || certAnchor.Status != api.Active ||
		now < certAnchor.NBF || now >= certAnchor.EXP {
		return "", protocol.NewError(protocol.ErrCodeDomainCertificationInvalid, fmt.Sprintf("certification %q inactive or expired", dom.Certification))
	}

	var certJWS, certDigest string
	err := ds.db.QueryRow(ctx, `SELECT cert_jws, cert_digest FROM certification_outbox
		WHERE deployment_id=$1 AND domain_id=$2 AND certification_id=$3 AND recipient=$4`,
		snap.DeploymentID, domainID, certAnchor.ID, recipient).Scan(&certJWS, &certDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", protocol.NewError(protocol.ErrCodeMaterialNotSynced,
			fmt.Sprintf("certification %s for domain %s not synced in outbox for %s", certAnchor.ID, domainID, recipient))
	}
	if err != nil {
		return "", err
	}
	if certDigest != certAnchor.Digest {
		return "", protocol.NewError(protocol.ErrCodeDomainCertificationInvalid, "outbox certification digest mismatches ledger anchor")
	}
	if _, err := verifyDomainCertAgainstSnap(snap, domainID, certJWS, rootPub, now); err != nil {
		return "", err
	}
	if _, err := ds.db.Exec(ctx, `INSERT INTO certification_receipts(
		deployment_id, domain_id, certification_id, recipient, cert_jws, cert_digest, received_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)
	ON CONFLICT(deployment_id, domain_id, certification_id, recipient) DO UPDATE SET
		cert_jws=EXCLUDED.cert_jws, cert_digest=EXCLUDED.cert_digest, received_at=EXCLUDED.received_at`,
		snap.DeploymentID, domainID, certAnchor.ID, recipient, certJWS, certDigest, now,
	); err != nil {
		return "", err
	}
	return certJWS, nil
}

// HasSyncedCertification verifies that a valid domain certification JWS exists in certification_receipts
// (or certification_outbox) matching the current anchor digest.
func (ds *DeliveryService) HasSyncedCertification(ctx context.Context, deploymentID, domainID, certID, certDigest string) (string, error) {
	if ds == nil || ds.db == nil {
		return "", protocol.NewError(protocol.ErrCodeStateUnavailable, "delivery store not configured")
	}
	var jws string
	err := ds.db.QueryRow(ctx, `SELECT cert_jws FROM certification_receipts
		WHERE deployment_id=$1 AND domain_id=$2 AND certification_id=$3 AND cert_digest=$4 LIMIT 1`,
		deploymentID, domainID, certID, certDigest).Scan(&jws)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ds.db.QueryRow(ctx, `SELECT cert_jws FROM certification_outbox
			WHERE deployment_id=$1 AND domain_id=$2 AND certification_id=$3 AND cert_digest=$4 LIMIT 1`,
			deploymentID, domainID, certID, certDigest).Scan(&jws)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return "", protocol.NewError(protocol.ErrCodeMaterialNotSynced, fmt.Sprintf("domain %s certification %s JWS not synced", domainID, certID))
	}
	if err != nil {
		return "", err
	}
	return jws, nil
}

// PublishGrantOutbox verifies C -> grantee RP root grant delivery materials against snap, confirms synced C
// domain certification, and stores the package in grant_outbox with (deploymentId, recipient, grantId)
// deduplication and 409 DELIVERY_CONFLICT detection.
func (ds *DeliveryService) PublishGrantOutbox(
	ctx context.Context,
	snap *protocol.SnapshotView,
	pkg GrantDeliveryPackage,
	rootPub *ecdsa.PublicKey,
	issuerCPub *ecdsa.PublicKey,
	grantorPub *ecdsa.PublicKey,
	txID string,
	blockNo int64,
	origValid bool,
	now int64,
) (string, error) {
	if ds == nil || ds.db == nil {
		return "", protocol.NewError(protocol.ErrCodeStateUnavailable, "delivery store not configured")
	}
	if !origValid {
		return "", protocol.NewError(protocol.ErrCodeMaterialInvalid, "original grant transaction is not VALID")
	}
	if err := ds.verifyGrantDeliveryPackage(ctx, snap, pkg, rootPub, issuerCPub, grantorPub, now); err != nil {
		return "", err
	}
	canon, pkgDigest, err := pkg.Digest()
	if err != nil {
		return "", err
	}

	tx, err := ds.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return "", err
	}
	defer tx.Rollback(context.Background())

	var existingDigest string
	err = tx.QueryRow(ctx, `SELECT package_digest FROM grant_outbox
		WHERE deployment_id=$1 AND recipient=$2 AND grant_id=$3 FOR UPDATE`,
		pkg.DeploymentID, pkg.Recipient, pkg.GrantID).Scan(&existingDigest)
	if err == nil {
		if existingDigest == pkgDigest {
			if err := tx.Commit(ctx); err != nil {
				return "", err
			}
			return pkgDigest, nil
		}
		return "", protocol.NewError(protocol.ErrCodeDeliveryConflict,
			fmt.Sprintf("grant_outbox conflict for (%s, %s, %s): existing %s != %s", pkg.DeploymentID, pkg.Recipient, pkg.GrantID, existingDigest, pkgDigest))
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	if _, err := tx.Exec(ctx, `INSERT INTO grant_outbox(
		deployment_id, recipient, grant_id, package_json, package_digest, tx_id, block_no, created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		pkg.DeploymentID, pkg.Recipient, pkg.GrantID, canon, pkgDigest, txID, blockNo, now); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return pkgDigest, nil
}

// DeliverGrantReceipt delivers the verified grant package from grant_outbox (or explicit overridePkg)
// into wallet_receipts with deduplication, idempotent confirmation, 409 DELIVERY_CONFLICT detection,
// and 503 MATERIAL_NOT_SYNCED guard (no wallet_receipts write when domain certification is missing).
func (ds *DeliveryService) DeliverGrantReceipt(
	ctx context.Context,
	snap *protocol.SnapshotView,
	deploymentID string,
	recipient string,
	grantID string,
	overridePkg *GrantDeliveryPackage,
	rootPub *ecdsa.PublicKey,
	issuerCPub *ecdsa.PublicKey,
	grantorPub *ecdsa.PublicKey,
	now int64,
) (*GrantDeliveryPackage, string, error) {
	if ds == nil || ds.db == nil {
		return nil, "", protocol.NewError(protocol.ErrCodeStateUnavailable, "delivery store not configured")
	}
	var pkg GrantDeliveryPackage
	if overridePkg != nil {
		pkg = *overridePkg
	} else {
		var raw []byte
		err := ds.db.QueryRow(ctx, `SELECT package_json FROM grant_outbox
			WHERE deployment_id=$1 AND recipient=$2 AND grant_id=$3`,
			deploymentID, recipient, grantID).Scan(&raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", protocol.NewError(protocol.ErrCodeMaterialNotSynced,
				fmt.Sprintf("grant %s package not synced in grant_outbox for %s", grantID, recipient))
		}
		if err != nil {
			return nil, "", err
		}
		if err := protocol.DecodeStrictJSON(raw, &pkg); err != nil {
			return nil, "", err
		}
	}
	if pkg.DeploymentID != deploymentID || pkg.Recipient != recipient || pkg.GrantID != grantID {
		return nil, "", protocol.NewError(protocol.ErrCodeBindingMismatch, "delivery package key mismatches target receipt key")
	}
	if err := ds.verifyGrantDeliveryPackage(ctx, snap, pkg, rootPub, issuerCPub, grantorPub, now); err != nil {
		return nil, "", err
	}
	canon, pkgDigest, err := pkg.Digest()
	if err != nil {
		return nil, "", err
	}

	tx, err := ds.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(context.Background())

	var existingDigest string
	err = tx.QueryRow(ctx, `SELECT package_digest FROM wallet_receipts
		WHERE deployment_id=$1 AND recipient=$2 AND grant_id=$3 FOR UPDATE`,
		deploymentID, recipient, grantID).Scan(&existingDigest)
	if err == nil {
		if existingDigest == pkgDigest {
			if err := tx.Commit(ctx); err != nil {
				return nil, "", err
			}
			return &pkg, pkgDigest, nil
		}
		return nil, "", protocol.NewError(protocol.ErrCodeDeliveryConflict,
			fmt.Sprintf("wallet_receipts conflict for (%s, %s, %s): existing %s != %s", deploymentID, recipient, grantID, existingDigest, pkgDigest))
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, "", err
	}

	if _, err := tx.Exec(ctx, `INSERT INTO wallet_receipts(
		deployment_id, recipient, grant_id, package_json, package_digest, received_at
	) VALUES($1,$2,$3,$4,$5,$6)`,
		deploymentID, recipient, grantID, canon, pkgDigest, now); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return &pkg, pkgDigest, nil
}

func (ds *DeliveryService) verifyGrantDeliveryPackage(
	ctx context.Context,
	snap *protocol.SnapshotView,
	pkg GrantDeliveryPackage,
	rootPub *ecdsa.PublicKey,
	grantorCredIssuerPub *ecdsa.PublicKey,
	grantorPub *ecdsa.PublicKey,
	now int64,
) error {
	if snap == nil || pkg.DeploymentID != snap.DeploymentID {
		return protocol.NewError(protocol.ErrCodeBindingMismatch, "snapshot deployment mismatch")
	}
	grant, ok := snap.Grants[pkg.GrantID]
	if !ok || grant.DeploymentID != snap.DeploymentID || grant.Status != api.Active ||
		now < grant.NBF || now >= grant.EXP {
		return protocol.NewError(protocol.ErrCodeMaterialInvalid, fmt.Sprintf("grant %q missing, inactive, or expired", pkg.GrantID))
	}
	if (grant.Mode != api.RP && grant.Mode != api.BM) || grant.Grantee != pkg.Recipient {
		return protocol.NewError(protocol.ErrCodeMaterialInvalid, "grant is not an active RP/BM grant for recipient")
	}
	task, ok := snap.Tasks[grant.Task]
	if !ok || task.DeploymentID != snap.DeploymentID || task.Status != api.Active ||
		now < task.NBF || now >= task.EXP {
		return protocol.NewError(protocol.ErrCodeTaskInactive, fmt.Sprintf("task %q missing, inactive, or expired", grant.Task))
	}
	taskDig, err := pkg.TaskSpec.Digest()
	if err != nil || taskDig != task.Digest {
		return protocol.NewError(protocol.ErrCodeBindingMismatch, "taskSpec digest mismatches ledger task anchor")
	}

	// Verify grantor identity, mode-specific root/parent constraints, and grantor domain certification sync.
	grantorID, ok := snap.Identities[grant.Issuer]
	if !ok || grantorID.Status != api.Active || grantorID.KeyVersion != grant.IssuerKeyVersion {
		return protocol.NewError(protocol.ErrCodeMaterialInvalid, "grantor identity missing or inactive")
	}
	if pkg.DomainCertificationJWS == "" {
		return protocol.NewError(protocol.ErrCodeMaterialNotSynced, fmt.Sprintf("missing %s domain certification JWS in package", grantorID.Domain))
	}
	if grant.Parent == "" {
		switch grant.Mode {
		case api.RP:
			if grantorID.Domain != "C" || grantorID.Kind != "SERVICE" {
				return protocol.NewError(protocol.ErrCodeRootAuthorityInvalid, "RP root grantor must be a SERVICE in domain C")
			}
		case api.BM:
			dom, ok := snap.Domains[task.Domain]
			if !ok || dom.Status != api.Active || dom.PurchasingAuthority != grant.Issuer ||
				grantorID.Domain != task.Domain || grantorID.Kind != "SERVICE" {
				return protocol.NewError(protocol.ErrCodePurchasingAuthorityInvalid, "BM root grantor is not active purchasingAuthority for task domain")
			}
		}
	} else {
		parentGrant, ok := snap.Grants[grant.Parent]
		if !ok || parentGrant.DeploymentID != snap.DeploymentID || parentGrant.Status != api.Active ||
			now < parentGrant.NBF || now >= parentGrant.EXP || parentGrant.Grantee != grant.Issuer {
			return protocol.NewError(protocol.ErrCodeAncestorInactive, fmt.Sprintf("parent grant %q missing, inactive, or grantee mismatch", grant.Parent))
		}
		if len(pkg.AncestorGrants) > 0 {
			for i, ancRaw := range pkg.AncestorGrants {
				prelim, err := protocol.ParseCompactJWS(ancRaw, protocol.TypGrantDelegation)
				if err != nil {
					return err
				}
				var ancClaims protocol.GrantClaims
				if err := protocol.DecodeStrictJSON(prelim.PayloadBytes, &ancClaims); err != nil {
					return err
				}
				ancOnChain, ok := snap.Grants[ancClaims.ID]
				if !ok || ancOnChain.Status != api.Active || now < ancOnChain.NBF || now >= ancOnChain.EXP {
					return protocol.NewError(protocol.ErrCodeAncestorInactive, fmt.Sprintf("ancestor grant[%d] %q missing or inactive", i, ancClaims.ID))
				}
			}
		}
	}

	certAnchor, err := verifyDomainCertAgainstSnap(snap, grantorID.Domain, pkg.DomainCertificationJWS, rootPub, now)
	if err != nil {
		return err
	}
	if _, err := ds.HasSyncedCertification(ctx, snap.DeploymentID, grantorID.Domain, certAnchor.ID, certAnchor.Digest); err != nil {
		return err
	}

	// Verify grantor's Grant JWS.
	pg, err := protocol.ParseAndVerifyGrant(pkg.GrantJWS, grantorPub, grantorID.KeyID)
	if err != nil {
		return err
	}
	if pg.Digest != grant.Digest || pg.Claims.ID != grant.ID || pg.Claims.TaskID != grant.Task ||
		pg.Claims.Issuer != grant.Issuer || pg.Claims.Grantee != grant.Grantee {
		return protocol.NewError(protocol.ErrCodeBindingMismatch, "grant JWS claims or digest mismatch ledger anchor")
	}

	// Verify grantor's minimal SD-JWT presentation.
	vc, err := protocol.VerifySDJWTCredential(pkg.ServicePresentation, grantorCredIssuerPub, "", grantorID.PublicKey, false)
	if err != nil {
		return err
	}
	credAnchor, ok := snap.Credentials[vc.Claims.ID]
	if !ok || credAnchor.Status != api.Active || credAnchor.Digest != vc.AnchorDigest ||
		now < credAnchor.NBF || now >= credAnchor.EXP || credAnchor.Subject != grant.Issuer {
		return protocol.NewError(protocol.ErrCodeCredentialStatusInvalid, "grantor credential anchor invalid or inactive")
	}
	if vc.Claims.ID != grant.IssuerCredential {
		if vc.Role != "supplier-service" && vc.Role != "RESOURCE_AUTHORITY" && vc.Role != "PURCHASING_AUTHORITY" {
			return protocol.NewError(protocol.ErrCodeIssuerScopeInvalid, "grantor presentation credential mismatches grant.issuerCredentialId")
		}
	} else if vc.Role != "supplier-service" && vc.Role != "purchasing-authority" &&
		vc.Role != "procurement-authority" && vc.Role != "procurement-owner" &&
		vc.Role != "procurement-agent" && vc.Role != "broker-agent" &&
		vc.Role != "RESOURCE_AUTHORITY" && vc.Role != "PURCHASING_AUTHORITY" && vc.Role != grantorID.Kind {
		return protocol.NewError(protocol.ErrCodeIssuerScopeInvalid, fmt.Sprintf("unexpected grantor credential role %q", vc.Role))
	}
	parts := strings.Split(pkg.ServicePresentation, "~")
	if len(parts) < 2 || parts[1] == "" || !slices.Contains(vc.Claims.CredentialSubject.SD, protocol.DisclosureDigest(parts[1])) {
		return protocol.NewError(protocol.ErrCodeInvalidDisclosure, "invalid grantor disclosure")
	}
	return nil
}

func verifyDomainCertAgainstSnap(snap *protocol.SnapshotView, domainID, certJWS string, rootPub *ecdsa.PublicKey, now int64) (api.Certification, error) {
	dom, ok := snap.Domains[domainID]
	if !ok || dom.DeploymentID != snap.DeploymentID || dom.Status != api.Active || dom.Certification == "" {
		return api.Certification{}, protocol.NewError(protocol.ErrCodeDomainCertificationInvalid, fmt.Sprintf("domain %q missing or inactive", domainID))
	}
	certAnchor, ok := snap.Certifications[dom.Certification]
	if !ok || certAnchor.DeploymentID != snap.DeploymentID || certAnchor.Status != api.Active ||
		now < certAnchor.NBF || now >= certAnchor.EXP {
		return api.Certification{}, protocol.NewError(protocol.ErrCodeDomainCertificationInvalid, fmt.Sprintf("certification %q missing, inactive, or expired", dom.Certification))
	}
	parsedCert, dig, err := protocol.ParseAndVerifyDomainAuthorityCredential(certJWS, rootPub, snap.Root.KeyID)
	if err != nil {
		return api.Certification{}, err
	}
	scopes := make([]protocol.IssuerScope, len(certAnchor.Scopes))
	for i, s := range certAnchor.Scopes {
		scopes[i] = protocol.IssuerScope{ID: s.ID, AppKeyVersion: s.KeyVersion, CredentialTypes: s.Types, ClaimNames: s.Claims}
	}
	if err := parsedCert.VerifyAgainstChain(dig, protocol.DomainAnchorState{
		RootDID:            snap.Root.DID,
		RootKeyVersion:     snap.Root.KeyVersion,
		DomainID:           dom.ID,
		DomainDID:          dom.DID,
		DomainIssuers:      dom.Issuers,
		CertificationID:    certAnchor.ID,
		CertificationNBF:   certAnchor.NBF,
		CertificationEXP:   certAnchor.EXP,
		CertificationDig:   certAnchor.Digest,
		CertificationScope: scopes,
	}); err != nil {
		return api.Certification{}, err
	}
	// Verify every certified issuer identity in this domain is registered and active on-chain
	for _, sc := range certAnchor.Scopes {
		issID, ok := snap.Identities[sc.ID]
		if !ok || issID.Status != api.Active || issID.Kind != "ISSUER" || issID.Domain != domainID || issID.KeyVersion != sc.KeyVersion {
			return api.Certification{}, protocol.NewError(protocol.ErrCodeIssuerScopeInvalid, fmt.Sprintf("certified issuer %q missing or inactive on ledger", sc.ID))
		}
	}
	return certAnchor, nil
}

// Unused helper check for future task 1.2/1.3 types
var _ = json.Marshal
