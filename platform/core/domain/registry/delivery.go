package registry

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/core/dao"
	"grad/protocol"
	preg "grad/protocol/registry"
)

// GrantDeliveryPackage bundles C/PA -> U (or grantor -> grantee) root or delegated grant
// delivery materials verified prior to writing grant_outbox and wallet_receipts.
type GrantDeliveryPackage struct {
	DeploymentID           string                        `json:"deploymentId"`
	Recipient              string                        `json:"recipient"`
	GrantID                string                        `json:"grantId"`
	GrantJWS               string                        `json:"grantJws"`
	TaskSpec               protocol.TaskSpec             `json:"taskSpec"`
	ServicePresentation    string                        `json:"servicePresentation"`
	DomainCertificationJWS string                        `json:"domainCertificationJws"`
	AncestorGrants         []string                      `json:"ancestorGrants,omitempty"`
	AncestorCredentials    []protocol.AncestorCredential `json:"ancestorCredentials,omitempty"`
	TrustPaths             []protocol.TrustPathEntry     `json:"trustPaths,omitempty"`
}

// Digest computes SHA-256(JCS(GrantDeliveryPackage)) as 64-char lowercase hex.
func (p GrantDeliveryPackage) Digest() ([]byte, string, error) {
	canon, err := protocol.MarshalJCS(p)
	if err != nil {
		return nil, "", err
	}
	return canon, preg.Digest(canon), nil
}

// BuildAccessTrustPaths constructs a deduplicated, UTF-16 ascending trustPaths slice
// ordered by credential issuer DID using domain certification JWS documents mapped by domainID.
func BuildAccessTrustPaths(certJWSByDomain map[string]string, snap *protocol.SnapshotView, issuerDIDs ...string) ([]protocol.TrustPathEntry, error) {
	if snap == nil {
		return nil, protocol.NewError(preg.ErrCodeStateUnavailable, "snapshot view required to build trustPaths")
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
	slices.SortFunc(unique, protocol.CompareUTF16)

	out := make([]protocol.TrustPathEntry, 0, len(unique))
	for _, iss := range unique {
		idRec, ok := snap.Identities[iss]
		if !ok {
			return nil, protocol.NewError(preg.ErrCodeIssuerScopeInvalid, fmt.Sprintf("issuer identity %q not found in snapshot", iss))
		}
		certJWS := certJWSByDomain[idRec.Domain]
		if certJWS == "" {
			return nil, protocol.NewError(preg.ErrCodeMaterialNotSynced, fmt.Sprintf("missing domain certification JWS for domain %q", idRec.Domain))
		}
		out = append(out, protocol.TrustPathEntry{
			Issuer:              iss,
			DomainCertification: certJWS,
		})
	}
	return out, nil
}

// DeliveryService implements controlled outbox/receipt synchronization for domain certifications
// and grant delivery packages against synchronized ledger snapshots.
type DeliveryService struct {
	db           *pgxpool.Pool
	deploymentID string
}

// NewDeliveryService creates a DeliveryService bound to db and deploymentID.
func NewDeliveryService(db *pgxpool.Pool, deploymentID string) *DeliveryService {
	return &DeliveryService{db: db, deploymentID: deploymentID}
}

type certOutboxRow struct {
	CertJWS    string `db:"cert_jws"`
	CertDigest string `db:"cert_digest"`
}

type certJWSRow struct {
	CertJWS string `db:"cert_jws"`
}

type grantDigestRow struct {
	PackageDigest string `db:"package_digest"`
}

type grantPackageRow struct {
	PackageJSON []byte `db:"package_json"`
}

// PublishedGrant loads an immutable package from the issuer's outbox.
func (ds *DeliveryService) PublishedGrant(ctx context.Context, recipient, grantID string) (GrantDeliveryPackage, string, error) {
	return ds.storedGrant(ctx, "grant_outbox", recipient, grantID)
}

// ReceivedGrant loads material that has already passed recipient-side verification.
func (ds *DeliveryService) ReceivedGrant(ctx context.Context, recipient, grantID string) (GrantDeliveryPackage, string, error) {
	return ds.storedGrant(ctx, "wallet_receipts", recipient, grantID)
}

func (ds *DeliveryService) storedGrant(ctx context.Context, table, recipient, grantID string) (GrantDeliveryPackage, string, error) {
	var pkg GrantDeliveryPackage
	if ds == nil || ds.db == nil || ds.deploymentID == "" {
		return pkg, "", protocol.NewError(preg.ErrCodeStateUnavailable, "bound delivery store required")
	}
	var raw []byte
	var digest string
	err := ds.db.QueryRow(ctx, `SELECT package_json, package_digest FROM `+table+
		` WHERE deployment_id=$1 AND recipient=$2 AND grant_id=$3`, ds.deploymentID, recipient, grantID).Scan(&raw, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return pkg, "", protocol.NewError(preg.ErrCodeMaterialNotSynced, "grant material has not been delivered")
	}
	if err != nil {
		return pkg, "", err
	}
	if err := protocol.DecodeStrictJSON(raw, &pkg); err != nil {
		return GrantDeliveryPackage{}, "", err
	}
	_, actual, err := pkg.Digest()
	if err != nil {
		return GrantDeliveryPackage{}, "", err
	}
	if actual != digest || pkg.DeploymentID != ds.deploymentID || pkg.Recipient != recipient || pkg.GrantID != grantID {
		return GrantDeliveryPackage{}, "", protocol.NewError(preg.ErrCodeDeliveryConflict, "stored grant package binding differs")
	}
	return pkg, digest, nil
}

// PublishDomainCertification verifies T's DomainAuthorityCredential JWS against the fixed-height snapshot
// and confirms original transaction VALID status before persisting raw JWS bytes into certification_outbox.
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
		return protocol.NewError(preg.ErrCodeStateUnavailable, "delivery store not configured")
	}
	if snap == nil {
		return protocol.NewError(preg.ErrCodeStateUnavailable, "snapshot view required")
	}
	if !origValid {
		return protocol.NewError(preg.ErrCodeMaterialInvalid, "original certification transaction is not VALID")
	}
	if recipient == "" || certJWS == "" {
		return protocol.NewError(preg.ErrCodeInvalidSchema, "recipient and certJws are required")
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
// Missing outbox material returns MATERIAL_NOT_SYNCED without writing certification_receipts.
func (ds *DeliveryService) SyncCertificationReceipt(
	ctx context.Context,
	snap *protocol.SnapshotView,
	recipient string,
	domainID string,
	rootPub *ecdsa.PublicKey,
	now int64,
) (string, error) {
	if ds == nil || ds.db == nil {
		return "", protocol.NewError(preg.ErrCodeStateUnavailable, "delivery store not configured")
	}
	if snap == nil {
		return "", protocol.NewError(preg.ErrCodeStateUnavailable, "snapshot view required")
	}
	dom, ok := snap.Domains[domainID]
	if !ok || dom.DeploymentID != snap.DeploymentID || dom.Status != preg.Active || dom.Certification == "" {
		return "", protocol.NewError(preg.ErrCodeDomainCertificationInvalid, fmt.Sprintf("domain %q inactive or missing certification", domainID))
	}
	certAnchor, ok := snap.Certifications[dom.Certification]
	if !ok || certAnchor.DeploymentID != snap.DeploymentID || certAnchor.Status != preg.Active ||
		now < certAnchor.NBF || now >= certAnchor.EXP {
		return "", protocol.NewError(preg.ErrCodeDomainCertificationInvalid, fmt.Sprintf("certification %q inactive or expired", dom.Certification))
	}

	rows, err := ds.db.Query(ctx, `SELECT cert_jws, cert_digest FROM certification_outbox
		WHERE deployment_id=$1 AND domain_id=$2 AND certification_id=$3 AND recipient=$4`,
		snap.DeploymentID, domainID, certAnchor.ID, recipient)
	if err != nil {
		return "", err
	}
	outbox, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[certOutboxRow])
	if errors.Is(err, pgx.ErrNoRows) {
		return "", protocol.NewError(preg.ErrCodeMaterialNotSynced,
			fmt.Sprintf("certification %s for domain %s not synced in outbox for %s", certAnchor.ID, domainID, recipient))
	}
	if err != nil {
		return "", err
	}
	if outbox.CertDigest != certAnchor.Digest {
		return "", protocol.NewError(preg.ErrCodeDomainCertificationInvalid, "outbox certification digest mismatches ledger anchor")
	}
	if _, err := verifyDomainCertAgainstSnap(snap, domainID, outbox.CertJWS, rootPub, now); err != nil {
		return "", err
	}
	if _, err := ds.db.Exec(ctx, `INSERT INTO certification_receipts(
		deployment_id, domain_id, certification_id, recipient, cert_jws, cert_digest, received_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)
	ON CONFLICT(deployment_id, domain_id, certification_id, recipient) DO UPDATE SET
		cert_jws=EXCLUDED.cert_jws, cert_digest=EXCLUDED.cert_digest, received_at=EXCLUDED.received_at`,
		snap.DeploymentID, domainID, certAnchor.ID, recipient, outbox.CertJWS, outbox.CertDigest, now,
	); err != nil {
		return "", err
	}
	return outbox.CertJWS, nil
}

// HasSyncedCertification reports whether a synced domain certification JWS exists in
// certification_receipts or certification_outbox for domainID under this service's deployment.
// Its signature directly satisfies gateway.CertificationChecker.
func (ds *DeliveryService) HasSyncedCertification(ctx context.Context, domainID string) (bool, error) {
	if ds == nil || ds.db == nil {
		return false, protocol.NewError(preg.ErrCodeStateUnavailable, "delivery store not configured")
	}
	if domainID == "" {
		return false, nil
	}
	queryTable := func(table string) (bool, error) {
		var (
			rows pgx.Rows
			err  error
		)
		if ds.deploymentID != "" {
			rows, err = ds.db.Query(ctx, `SELECT cert_jws FROM `+table+`
				WHERE deployment_id=$1 AND domain_id=$2 LIMIT 1`, ds.deploymentID, domainID)
		} else {
			rows, err = ds.db.Query(ctx, `SELECT cert_jws FROM `+table+`
				WHERE domain_id=$1 LIMIT 1`, domainID)
		}
		if err != nil {
			return false, err
		}
		row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[certJWSRow])
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return row.CertJWS != "", nil
	}
	if ok, err := queryTable("certification_receipts"); err != nil || ok {
		return ok, err
	}
	return queryTable("certification_outbox")
}

// SyncedCertificationJWS verifies that a valid domain certification JWS exists in
// certification_receipts (or certification_outbox) matching the exact anchor digest.
func (ds *DeliveryService) SyncedCertificationJWS(ctx context.Context, deploymentID, domainID, certID, certDigest string) (string, error) {
	if ds == nil || ds.db == nil {
		return "", protocol.NewError(preg.ErrCodeStateUnavailable, "delivery store not configured")
	}
	queryTable := func(table string) (string, error) {
		rows, err := ds.db.Query(ctx, `SELECT cert_jws FROM `+table+`
			WHERE deployment_id=$1 AND domain_id=$2 AND certification_id=$3 AND cert_digest=$4 LIMIT 1`,
			deploymentID, domainID, certID, certDigest)
		if err != nil {
			return "", err
		}
		row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[certJWSRow])
		if err != nil {
			return "", err
		}
		return row.CertJWS, nil
	}
	jws, err := queryTable("certification_receipts")
	if errors.Is(err, pgx.ErrNoRows) {
		jws, err = queryTable("certification_outbox")
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return "", protocol.NewError(preg.ErrCodeMaterialNotSynced, fmt.Sprintf("domain %s certification %s JWS not synced", domainID, certID))
	}
	if err != nil {
		return "", err
	}
	return jws, nil
}

// PublishGrantOutbox verifies grant delivery materials against snap, confirms synced grantor
// domain certification, and stores the package in grant_outbox with (deploymentId, recipient, grantId)
// deduplication and DELIVERY_CONFLICT detection.
func (ds *DeliveryService) PublishGrantOutbox(
	ctx context.Context,
	snap *protocol.SnapshotView,
	pkg GrantDeliveryPackage,
	rootPub *ecdsa.PublicKey,
	grantorCredIssuerPub *ecdsa.PublicKey,
	grantorPub *ecdsa.PublicKey,
	txID string,
	blockNo int64,
	origValid bool,
	now int64,
) (string, error) {
	if ds == nil || ds.db == nil {
		return "", protocol.NewError(preg.ErrCodeStateUnavailable, "delivery store not configured")
	}
	if !origValid {
		return "", protocol.NewError(preg.ErrCodeMaterialInvalid, "original grant transaction is not VALID")
	}
	if err := ds.verifyGrantDeliveryPackage(ctx, snap, pkg, rootPub, grantorCredIssuerPub, grantorPub, now); err != nil {
		return "", err
	}
	canon, pkgDigest, err := pkg.Digest()
	if err != nil {
		return "", err
	}

	err = dao.RunInTx(ctx, ds.db, func(tx dao.Tx) error {
		lockKey, _ := protocol.MarshalJCS([]string{"grant_outbox", pkg.DeploymentID, pkg.Recipient, pkg.GrantID})
		if err := tx.AdvisoryXactLock(ctx, string(lockKey)); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT package_digest FROM grant_outbox
			WHERE deployment_id=$1 AND recipient=$2 AND grant_id=$3 FOR UPDATE`,
			pkg.DeploymentID, pkg.Recipient, pkg.GrantID)
		if err != nil {
			return err
		}
		existing, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[grantDigestRow])
		if err == nil {
			if existing.PackageDigest == pkgDigest {
				return nil
			}
			return protocol.NewError(preg.ErrCodeDeliveryConflict,
				fmt.Sprintf("grant_outbox conflict for (%s, %s, %s): existing %s != %s", pkg.DeploymentID, pkg.Recipient, pkg.GrantID, existing.PackageDigest, pkgDigest))
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}

		_, err = tx.Exec(ctx, `INSERT INTO grant_outbox(
			deployment_id, recipient, grant_id, package_json, package_digest, tx_id, block_no, created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
			pkg.DeploymentID, pkg.Recipient, pkg.GrantID, canon, pkgDigest, txID, blockNo, now)
		return err
	})
	if err != nil {
		return "", err
	}
	return pkgDigest, nil
}

// DeliverGrantReceipt delivers the verified grant package from grant_outbox (or explicit overridePkg)
// into wallet_receipts with deduplication, idempotent confirmation, DELIVERY_CONFLICT detection,
// and MATERIAL_NOT_SYNCED guard (no wallet_receipts write when domain certification is missing).
func (ds *DeliveryService) DeliverGrantReceipt(
	ctx context.Context,
	snap *protocol.SnapshotView,
	deploymentID string,
	recipient string,
	grantID string,
	overridePkg *GrantDeliveryPackage,
	rootPub *ecdsa.PublicKey,
	grantorCredIssuerPub *ecdsa.PublicKey,
	grantorPub *ecdsa.PublicKey,
	now int64,
) (*GrantDeliveryPackage, string, error) {
	if ds == nil || ds.db == nil {
		return nil, "", protocol.NewError(preg.ErrCodeStateUnavailable, "delivery store not configured")
	}
	var pkg GrantDeliveryPackage
	if overridePkg != nil {
		pkg = *overridePkg
	} else {
		rows, err := ds.db.Query(ctx, `SELECT package_json FROM grant_outbox
			WHERE deployment_id=$1 AND recipient=$2 AND grant_id=$3`,
			deploymentID, recipient, grantID)
		if err != nil {
			return nil, "", err
		}
		outbox, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[grantPackageRow])
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", protocol.NewError(preg.ErrCodeMaterialNotSynced,
				fmt.Sprintf("grant %s package not synced in grant_outbox for %s", grantID, recipient))
		}
		if err != nil {
			return nil, "", err
		}
		if err := protocol.DecodeStrictJSON(outbox.PackageJSON, &pkg); err != nil {
			return nil, "", err
		}
	}
	if pkg.DeploymentID != deploymentID || pkg.Recipient != recipient || pkg.GrantID != grantID {
		return nil, "", protocol.NewError(preg.ErrCodeBindingMismatch, "delivery package key mismatches target receipt key")
	}
	if err := ds.verifyGrantDeliveryPackage(ctx, snap, pkg, rootPub, grantorCredIssuerPub, grantorPub, now); err != nil {
		return nil, "", err
	}
	canon, pkgDigest, err := pkg.Digest()
	if err != nil {
		return nil, "", err
	}

	err = dao.RunInTx(ctx, ds.db, func(tx dao.Tx) error {
		lockKey, _ := protocol.MarshalJCS([]string{"wallet_receipts", deploymentID, recipient, grantID})
		if err := tx.AdvisoryXactLock(ctx, string(lockKey)); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT package_digest FROM wallet_receipts
			WHERE deployment_id=$1 AND recipient=$2 AND grant_id=$3 FOR UPDATE`,
			deploymentID, recipient, grantID)
		if err != nil {
			return err
		}
		existing, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[grantDigestRow])
		if err == nil {
			if existing.PackageDigest == pkgDigest {
				return nil
			}
			return protocol.NewError(preg.ErrCodeDeliveryConflict,
				fmt.Sprintf("wallet_receipts conflict for (%s, %s, %s): existing %s != %s", deploymentID, recipient, grantID, existing.PackageDigest, pkgDigest))
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}

		_, err = tx.Exec(ctx, `INSERT INTO wallet_receipts(
			deployment_id, recipient, grant_id, package_json, package_digest, received_at
		) VALUES($1,$2,$3,$4,$5,$6)`,
			deploymentID, recipient, grantID, canon, pkgDigest, now)
		return err
	})
	if err != nil {
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
		return protocol.NewError(preg.ErrCodeBindingMismatch, "snapshot deployment mismatch")
	}
	grant, ok := snap.Grants[pkg.GrantID]
	if !ok || grant.DeploymentID != snap.DeploymentID || grant.Status != preg.Active ||
		now < grant.NBF || now >= grant.EXP {
		return protocol.NewError(preg.ErrCodeMaterialInvalid, fmt.Sprintf("grant %q missing, inactive, or expired", pkg.GrantID))
	}
	if (grant.Mode != preg.RP && grant.Mode != preg.BM) || grant.Grantee != pkg.Recipient {
		return protocol.NewError(preg.ErrCodeMaterialInvalid, "grant is not an active RP/BM grant for recipient")
	}
	task, ok := snap.Tasks[grant.Task]
	if !ok || task.DeploymentID != snap.DeploymentID || task.Status != preg.Active ||
		now < task.NBF || now >= task.EXP {
		return protocol.NewError(preg.ErrCodeTaskInactive, fmt.Sprintf("task %q missing, inactive, or expired", grant.Task))
	}
	taskDig, err := pkg.TaskSpec.Digest()
	if err != nil || taskDig != task.Digest {
		return protocol.NewError(preg.ErrCodeBindingMismatch, "taskSpec digest mismatches ledger task anchor")
	}

	// Verify grantor identity, mode-specific root/parent constraints, and grantor domain certification sync.
	grantorID, ok := snap.Identities[grant.Issuer]
	if !ok || grantorID.Status != preg.Active || grantorID.KeyVersion != grant.IssuerKeyVersion {
		return protocol.NewError(preg.ErrCodeMaterialInvalid, "grantor identity missing or inactive")
	}
	if pkg.DomainCertificationJWS == "" {
		return protocol.NewError(preg.ErrCodeMaterialNotSynced, fmt.Sprintf("missing %s domain certification JWS in package", grantorID.Domain))
	}
	if grant.Parent == "" {
		switch grant.Mode {
		case preg.RP:
			if grantorID.Domain != "C" || grantorID.Kind != "SERVICE" {
				return protocol.NewError(preg.ErrCodeRootAuthorityInvalid, "RP root grantor must be a SERVICE in domain C")
			}
		case preg.BM:
			dom, ok := snap.Domains[task.Domain]
			if !ok || dom.Status != preg.Active || dom.PurchasingAuthority != grant.Issuer ||
				grantorID.Domain != task.Domain || grantorID.Kind != "SERVICE" {
				return protocol.NewError(preg.ErrCodePurchasingAuthorityInvalid, "BM root grantor is not active purchasingAuthority for task domain")
			}
		}
	} else {
		parentGrant, ok := snap.Grants[grant.Parent]
		if !ok || parentGrant.DeploymentID != snap.DeploymentID || parentGrant.Status != preg.Active ||
			now < parentGrant.NBF || now >= parentGrant.EXP || parentGrant.Grantee != grant.Issuer {
			return protocol.NewError(preg.ErrCodeAncestorInactive, fmt.Sprintf("parent grant %q missing, inactive, or grantee mismatch", grant.Parent))
		}
		for i, ancRaw := range pkg.AncestorGrants {
			prelim, err := protocol.ParseCompactJWS(ancRaw, protocol.TypeGrantJWS)
			if err != nil {
				return err
			}
			var ancClaims protocol.GrantClaims
			if err := protocol.DecodeStrictJSON(prelim.PayloadBytes, &ancClaims); err != nil {
				return err
			}
			ancOnChain, ok := snap.Grants[ancClaims.ID]
			if !ok || ancOnChain.Status != preg.Active || now < ancOnChain.NBF || now >= ancOnChain.EXP {
				return protocol.NewError(preg.ErrCodeAncestorInactive, fmt.Sprintf("ancestor grant[%d] %q missing or inactive", i, ancClaims.ID))
			}
		}
	}

	certAnchor, err := verifyDomainCertAgainstSnap(snap, grantorID.Domain, pkg.DomainCertificationJWS, rootPub, now)
	if err != nil {
		return err
	}
	if _, err := ds.SyncedCertificationJWS(ctx, snap.DeploymentID, grantorID.Domain, certAnchor.ID, certAnchor.Digest); err != nil {
		return err
	}

	// Verify grantor's Grant JWS.
	pg, err := protocol.ParseAndVerifyGrant(pkg.GrantJWS, grantorPub, grantorID.KeyID)
	if err != nil {
		return err
	}
	if pg.Digest != grant.Digest || pg.Claims.ID != grant.ID || pg.Claims.TaskID != grant.Task ||
		pg.Claims.Issuer != grant.Issuer || pg.Claims.Grantee != grant.Grantee {
		return protocol.NewError(preg.ErrCodeBindingMismatch, "grant JWS claims or digest mismatch ledger anchor")
	}

	// Verify grantor's minimal SD-JWT presentation.
	vc, err := protocol.VerifySDJWTCredential(pkg.ServicePresentation, grantorCredIssuerPub, "", grantorID.PublicKey, false)
	if err != nil {
		return err
	}
	credAnchor, ok := snap.Credentials[vc.Claims.ID]
	if !ok || credAnchor.Status != preg.Active || credAnchor.Digest != vc.AnchorDigest ||
		now < credAnchor.NBF || now >= credAnchor.EXP || credAnchor.Subject != grant.Issuer {
		return protocol.NewError(preg.ErrCodeCredentialStatusInvalid, "grantor credential anchor invalid or inactive")
	}
	if vc.Claims.ID != grant.IssuerCredential {
		if vc.Role != "supplier-service" && vc.Role != "RESOURCE_AUTHORITY" && vc.Role != "PURCHASING_AUTHORITY" {
			return protocol.NewError(preg.ErrCodeIssuerScopeInvalid, "grantor presentation credential mismatches grant.issuerCredentialId")
		}
	} else if vc.Role != "supplier-service" && vc.Role != "purchasing-authority" &&
		vc.Role != "procurement-authority" && vc.Role != "procurement-owner" &&
		vc.Role != "procurement-agent" && vc.Role != "broker-agent" &&
		vc.Role != "RESOURCE_AUTHORITY" && vc.Role != "PURCHASING_AUTHORITY" && vc.Role != grantorID.Kind {
		return protocol.NewError(preg.ErrCodeIssuerScopeInvalid, fmt.Sprintf("unexpected grantor credential role %q", vc.Role))
	}
	parts := strings.Split(pkg.ServicePresentation, "~")
	if len(parts) < 2 || parts[1] == "" || !slices.Contains(vc.Claims.CredentialSubject.SD, protocol.DisclosureDigest(parts[1])) {
		return protocol.NewError(preg.ErrCodeInvalidDisclosure, "invalid grantor disclosure")
	}
	return nil
}

func verifyDomainCertAgainstSnap(snap *protocol.SnapshotView, domainID, certJWS string, rootPub *ecdsa.PublicKey, now int64) (preg.Certification, error) {
	dom, ok := snap.Domains[domainID]
	if !ok || dom.DeploymentID != snap.DeploymentID || dom.Status != preg.Active || dom.Certification == "" {
		return preg.Certification{}, protocol.NewError(preg.ErrCodeDomainCertificationInvalid, fmt.Sprintf("domain %q missing or inactive", domainID))
	}
	certAnchor, ok := snap.Certifications[dom.Certification]
	if !ok || certAnchor.DeploymentID != snap.DeploymentID || certAnchor.Status != preg.Active ||
		now < certAnchor.NBF || now >= certAnchor.EXP {
		return preg.Certification{}, protocol.NewError(preg.ErrCodeDomainCertificationInvalid, fmt.Sprintf("certification %q missing, inactive, or expired", dom.Certification))
	}
	parsedCert, dig, err := protocol.ParseAndVerifyDomainAuthorityCredential(certJWS, rootPub, snap.Root.KeyID)
	if err != nil {
		return preg.Certification{}, err
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
		CertificationScope: certAnchor.Scopes,
	}); err != nil {
		return preg.Certification{}, err
	}
	// Verify every certified issuer identity in this domain is registered and active on-chain.
	for _, sc := range certAnchor.Scopes {
		issID, ok := snap.Identities[sc.ID]
		if !ok || issID.Status != preg.Active || issID.Kind != "ISSUER" || issID.Domain != domainID || issID.KeyVersion != sc.AppKeyVersion {
			return preg.Certification{}, protocol.NewError(preg.ErrCodeIssuerScopeInvalid, fmt.Sprintf("certified issuer %q missing or inactive on ledger", sc.ID))
		}
	}
	return certAnchor, nil
}
