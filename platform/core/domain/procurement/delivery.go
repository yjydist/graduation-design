package procurement

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/domain/wallet"
	"grad/protocol"
	preg "grad/protocol/registry"
)

func (g *GrantOperations) grantSnapshot(ctx context.Context, grantID string) (*protocol.SnapshotView, error) {
	head, err := g.view.Head(ctx, g.cfg.DB, false)
	if err != nil {
		return nil, err
	}
	if head == nil || head.Number == 0 {
		return nil, protocol.NewError(preg.ErrCodeMaterialNotSynced, "registry checkpoint has not reached grant registration")
	}
	state, err := g.state.AssembleHistoricalSnapshot(ctx, grantID, int64(head.Number), g.Now())
	if err != nil {
		return nil, err
	}
	return state.Snapshot, nil
}

func (g *GrantOperations) verifyOriginal(ctx context.Context, op domreg.OperationView, grantID, grantDigest string) error {
	if op.Method != "RegisterGrant" || op.Status != "CONFIRMED" || op.ValidationCode == nil || *op.ValidationCode != "VALID" ||
		!preg.IsDigest(op.TxID) || op.BlockNumber <= 0 || !preg.IsDigest(op.BlockHash) ||
		op.TransactionIndex == nil || *op.TransactionIndex < 0 {
		return protocol.NewError(preg.ErrCodeMaterialNotSynced, "original grant transaction is not confirmed")
	}
	// AppliedVersionValue verifies writes from independently validated VALID
	// transactions in the continuous locally applied block history.
	raw, found, err := g.view.AppliedVersionValue(ctx, preg.Key("grant", grantID), op.TxID, op.BlockNumber, op.BlockHash, *op.TransactionIndex)
	if err != nil {
		return err
	}
	if !found {
		return protocol.NewError(preg.ErrCodeMaterialNotSynced, "original grant transaction is absent from the local applied view")
	}
	var anchor preg.Grant
	if err := protocol.DecodeStrictJSON(raw, &anchor); err != nil {
		return err
	}
	if anchor.ID != grantID || anchor.Revision != 1 || anchor.Status != preg.Active || anchor.Digest != grantDigest {
		return protocol.NewError(preg.ErrCodeBindingMismatch, "original transaction did not register this grant")
	}
	return nil
}

func (g *GrantOperations) publish(ctx context.Context, op *domreg.OperationView, pkg domreg.GrantDeliveryPackage) (*domreg.OperationView, *GrantDelivery, error) {
	if err := g.Sync(ctx); err != nil {
		return op, nil, err
	}
	if err := g.verifyOriginal(ctx, *op, pkg.GrantID, preg.Digest([]byte(pkg.GrantJWS))); err != nil {
		return op, nil, err
	}
	snap, err := g.grantSnapshot(ctx, pkg.GrantID)
	if err != nil {
		return op, nil, err
	}
	grant := snap.Grants[pkg.GrantID]
	issuer := snap.Identities[grant.Issuer]
	pkg.DomainCertificationJWS = g.cfg.Certifications[issuer.Domain]
	pkg.TrustPaths, err = g.trustPaths(ctx, snap, pkg.GrantID)
	if err != nil {
		return op, nil, err
	}
	_, keys, err := g.verifyPackage(snap, pkg, true)
	if err != nil {
		return op, nil, err
	}
	digest, err := g.delivery.PublishGrantOutbox(ctx, snap, pkg, g.root, keys.credentialIssuer, keys.grantor,
		op.TxID, op.BlockNumber, true, g.Now().UTC().Unix())
	if err != nil {
		return op, nil, err
	}
	return op, &GrantDelivery{Operation: *op, Package: pkg, Digest: digest}, nil
}

// Published returns the original outbox entry after a restart or tool response loss.
func (g *GrantOperations) Published(ctx context.Context, recipient GrantRecipient, grantID string) (*GrantDelivery, error) {
	pkg, digest, err := g.delivery.PublishedGrant(ctx, recipient.DID, grantID)
	if err != nil {
		return nil, err
	}
	var issuer, key string
	err = g.cfg.DB.QueryRow(ctx, `SELECT issuer_did, operation_key FROM workbench_grant_issue
		WHERE deployment_id=$1 AND domain_id=$2 AND grant_id=$3`,
		g.cfg.Deployment.DeploymentID, g.cfg.DomainID, grantID).Scan(&issuer, &key)
	if err != nil {
		return nil, err
	}
	var a GrantActor
	for _, candidate := range g.cfg.Actors {
		if candidate.Signer.DID == issuer {
			a = candidate
			break
		}
	}
	if !a.Management.Valid() {
		return nil, protocol.NewError(preg.ErrCodeBindingMismatch, "outbox grant originated outside this domain")
	}
	parsed, err := protocol.ParseAndVerifyGrant(pkg.GrantJWS, &a.Signer.PrivateKey.PublicKey, a.Signer.KeyID)
	if err != nil {
		return nil, err
	}
	if parsed.Claims.GranteeCredentialID != recipient.CredentialID {
		return nil, protocol.NewError(preg.ErrCodeBindingMismatch, "publication recipient credential differs")
	}
	dep := g.cfg.Deployment.DeploymentID
	opID := domreg.ManagementOperationID(dep, a.Management, "RegisterGrant", key)
	op, err := g.cfg.Management.Operation(ctx, a.Management, opID)
	if err != nil {
		return nil, err
	}
	if err := g.verifyOriginal(ctx, *op, grantID, parsed.Digest); err != nil {
		return nil, err
	}
	return &GrantDelivery{Operation: *op, Package: pkg, Digest: digest}, nil
}

// Receive verifies the remote publication against the recipient domain's own
// applied registry, then stores or reuses that domain's wallet receipt.
func (g *GrantOperations) Receive(ctx context.Context, recipient GrantRecipient, delivery GrantDelivery) (wallet.GrantBundle, string, error) {
	pkg := delivery.Package
	if pkg.Recipient != recipient.DID || pkg.DeploymentID != g.cfg.Deployment.DeploymentID {
		return wallet.GrantBundle{}, "", protocol.NewError(preg.ErrCodeBindingMismatch, "delivery is addressed to another wallet or deployment")
	}
	_, digest, err := pkg.Digest()
	if err != nil {
		return wallet.GrantBundle{}, "", err
	}
	if digest != delivery.Digest {
		return wallet.GrantBundle{}, "", protocol.NewError(preg.ErrCodeBindingMismatch, "delivery digest differs from package")
	}
	if err := g.Sync(ctx); err != nil {
		return wallet.GrantBundle{}, "", err
	}
	if err := g.verifyOriginal(ctx, delivery.Operation, pkg.GrantID, preg.Digest([]byte(pkg.GrantJWS))); err != nil {
		return wallet.GrantBundle{}, "", err
	}
	snap, err := g.grantSnapshot(ctx, pkg.GrantID)
	if err != nil {
		return wallet.GrantBundle{}, "", err
	}
	if err := g.matchRecipient(snap, recipient, pkg.GrantID); err != nil {
		return wallet.GrantBundle{}, "", err
	}
	issuer := snap.Identities[snap.Grants[pkg.GrantID].Issuer]
	op := delivery.Operation
	if op.OperationID != domreg.ManagementOperationID(snap.DeploymentID, issuer.Management, op.Method, op.OperationKey) {
		return wallet.GrantBundle{}, "", protocol.NewError(preg.ErrCodeBindingMismatch, "original operation does not match issuer and operation key")
	}
	bundle, keys, err := g.verifyPackage(snap, pkg, true)
	if err != nil {
		return wallet.GrantBundle{}, "", err
	}
	paths, err := g.trustPaths(ctx, snap, pkg.GrantID)
	if err != nil {
		return wallet.GrantBundle{}, "", err
	}
	if !slices.Equal(paths, pkg.TrustPaths) {
		return wallet.GrantBundle{}, "", protocol.NewError(preg.ErrCodeBindingMismatch, "delivery trust paths differ from registry")
	}
	_, receipt, err := g.delivery.DeliverGrantReceipt(ctx, snap, snap.DeploymentID, recipient.DID, pkg.GrantID,
		&pkg, g.root, keys.credentialIssuer, keys.grantor, g.Now().UTC().Unix())
	if err != nil {
		return wallet.GrantBundle{}, "", err
	}
	return bundle, receipt, nil
}

// MarkReceived advances the issuer-side operation after its authenticated
// recipient acknowledges the verified receipt digest.
func (g *GrantOperations) MarkReceived(ctx context.Context, delivery GrantDelivery, receiptDigest string) error {
	if delivery.Digest != receiptDigest {
		return protocol.NewError(preg.ErrCodeBindingMismatch, "recipient receipt digest differs from delivery")
	}
	claims, err := decodeGrantPayload(delivery.Package.GrantJWS)
	if err != nil {
		return err
	}
	stored, err := g.Published(ctx, GrantRecipient{DID: claims.Grantee, CredentialID: claims.GranteeCredentialID}, claims.ID)
	if err != nil {
		return err
	}
	if stored.Digest != receiptDigest || stored.Operation.OperationID != delivery.Operation.OperationID {
		return protocol.NewError(preg.ErrCodeBindingMismatch, "receipt does not match original publication")
	}
	op := stored.Operation
	return g.cfg.Management.RecordOutcome(ctx, op.OperationID, op.Stage, op.Status, op.TxID, nil, nil, true)
}

func (g *GrantOperations) matchRecipient(snap *protocol.SnapshotView, recipient GrantRecipient, grantID string) error {
	gnt, found := snap.Grants[grantID]
	id := snap.Identities[recipient.DID]
	if !found || gnt.Grantee != recipient.DID || gnt.GranteeCredential != recipient.CredentialID ||
		id.Domain != g.cfg.DomainID || id.DeploymentID != snap.DeploymentID {
		return protocol.NewError(preg.ErrCodeBindingMismatch, "grant recipient does not belong to this deployment and domain")
	}
	return nil
}

// Load requires a durable receipt and rechecks its current authorization chain.
func (g *GrantOperations) Load(ctx context.Context, recipient GrantRecipient, grantID string) (wallet.GrantBundle, error) {
	return g.load(ctx, recipient, grantID, true)
}

// LoadRetained gives a trusted caller previously delivered material for
// reconciliation or a supplier-side decision about a disabled ancestor.
// Expired grants cannot be used to submit new requests through BoundOperations.
func (g *GrantOperations) LoadRetained(ctx context.Context, recipient GrantRecipient, grantID string) (wallet.GrantBundle, error) {
	return g.load(ctx, recipient, grantID, false)
}

func (g *GrantOperations) load(ctx context.Context, recipient GrantRecipient, grantID string, requireActive bool) (wallet.GrantBundle, error) {
	pkg, _, err := g.delivery.ReceivedGrant(ctx, recipient.DID, grantID)
	if err != nil {
		return wallet.GrantBundle{}, err
	}
	if err := g.Sync(ctx); err != nil {
		return wallet.GrantBundle{}, err
	}
	snap, err := g.grantSnapshot(ctx, grantID)
	if err != nil {
		return wallet.GrantBundle{}, err
	}
	if err := g.matchRecipient(snap, recipient, grantID); err != nil {
		return wallet.GrantBundle{}, err
	}
	bundle, _, err := g.verifyPackage(snap, pkg, requireActive)
	if err != nil || !requireActive {
		return bundle, err
	}
	paths, err := g.trustPaths(ctx, snap, grantID)
	if err != nil {
		return wallet.GrantBundle{}, err
	}
	if !slices.Equal(paths, bundle.TrustPaths) {
		return wallet.GrantBundle{}, protocol.NewError(preg.ErrCodeBindingMismatch, "stored trust paths differ from registry")
	}
	return bundle, nil
}

// AnchoredAmount reads only local issuance or verified wallet receipts. The
// committed digest authenticates the exact signed bytes, including after expiry.
func (g *GrantOperations) AnchoredAmount(ctx context.Context, anchor preg.Grant) (int64, error) {
	var raw string
	err := g.cfg.DB.QueryRow(ctx, `SELECT grant_jws FROM workbench_grant_issue
		WHERE deployment_id=$1 AND domain_id=$2 AND grant_id=$3`, g.cfg.Deployment.DeploymentID, g.cfg.DomainID, anchor.ID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		pkg, _, err := g.delivery.ReceivedGrant(ctx, anchor.Grantee, anchor.ID)
		if protocol.HasCode(err, preg.ErrCodeMaterialNotSynced) {
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
		raw = pkg.GrantJWS
	} else if err != nil {
		return 0, err
	}
	if preg.Digest([]byte(raw)) != anchor.Digest {
		return 0, protocol.NewError(preg.ErrCodeBindingMismatch, "stored grant differs from the grant anchor")
	}
	signed, err := protocol.ParseCompactJWS(raw, protocol.TypeGrantJWS)
	if err != nil {
		return 0, err
	}
	var claims protocol.GrantClaims
	if err := protocol.DecodeStrictJSON(signed.PayloadBytes, &claims); err != nil {
		return 0, err
	}
	if err := claims.ValidateStructure(); err != nil {
		return 0, err
	}
	anchor.Version = preg.Version{}
	if LedgerGrant(&protocol.ParsedGrant{Claims: claims, Digest: signed.Digest}) != anchor {
		return 0, protocol.NewError(preg.ErrCodeBindingMismatch, "stored grant claims differ from the grant anchor")
	}
	return claims.MaxAmountMinor, nil
}

func (g *GrantOperations) bundle(ctx context.Context, pkg domreg.GrantDeliveryPackage, requireActive bool) (wallet.GrantBundle, error) {
	snap, err := g.grantSnapshot(ctx, pkg.GrantID)
	if err != nil {
		return wallet.GrantBundle{}, err
	}
	bundle, _, err := g.verifyPackage(snap, pkg, requireActive)
	return bundle, err
}

type deliveryKeys struct {
	grantor          *ecdsa.PublicKey
	credentialIssuer *ecdsa.PublicKey
}

func (g *GrantOperations) verifyPackage(snap *protocol.SnapshotView, pkg domreg.GrantDeliveryPackage, requireActive bool) (wallet.GrantBundle, deliveryKeys, error) {
	var bundle wallet.GrantBundle
	var keys deliveryKeys
	rawChain := append(slices.Clone(pkg.AncestorGrants), pkg.GrantJWS)
	chain, err := parseDeliveryChain(snap, rawChain, requireActive)
	if err != nil {
		return bundle, keys, err
	}
	leaf := chain[len(chain)-1]
	c := leaf.Claims
	task := snap.Tasks[c.TaskID]
	taskSpec := pkg.TaskSpec
	digest, err := taskSpec.Digest()
	if err != nil {
		return bundle, keys, err
	}
	if pkg.DeploymentID != c.DeploymentID || pkg.Recipient != c.Grantee || pkg.GrantID != c.ID ||
		task.DeploymentID != c.DeploymentID || task.Digest != digest || chain[0].Claims.Grantee != task.Creator ||
		task.Domain != c.PrincipalDomain || task.Mode != c.AuthorizationMode || task.Resource != c.ResourceID {
		return bundle, keys, protocol.NewError(preg.ErrCodeBindingMismatch, "grant package differs from confirmed task or recipient")
	}
	if requireActive && (task.Status != preg.Active || !task.Interval.Current(snap.Now, 0)) {
		return bundle, keys, protocol.NewError(preg.ErrCodeTaskInactive, "delivered task is inactive or expired")
	}
	root := chain[0].Claims
	if root.AuthorizationMode == preg.RP && root.Issuer != g.cfg.Deployment.Bootstrap.ResourceOwner {
		return bundle, keys, protocol.NewError(preg.ErrCodeRootAuthorityInvalid, "root issuer differs from deployment resource authority")
	}
	issuer := snap.Identities[c.Issuer]
	if pkg.DomainCertificationJWS != g.cfg.Certifications[issuer.Domain] || pkg.DomainCertificationJWS == "" {
		return bundle, keys, protocol.NewError(preg.ErrCodeDomainCertificationInvalid, "publication certification differs from configured trust material")
	}

	ancestors := append(slices.Clone(pkg.AncestorCredentials),
		protocol.AncestorCredential{CredentialID: c.IssuerCredentialID, Presentation: pkg.ServicePresentation})
	expected := make(map[string]struct{}, len(chain))
	for _, p := range chain {
		expected[p.Claims.IssuerCredentialID] = struct{}{}
	}
	for _, a := range ancestors {
		if _, ok := expected[a.CredentialID]; !ok {
			return bundle, keys, protocol.NewError(preg.ErrCodeBindingMismatch, "unexpected or repeated ancestor credential")
		}
		delete(expected, a.CredentialID)
		credentialIssuer, err := verifyDeliveryCredential(snap, a, requireActive)
		if err != nil {
			return bundle, keys, err
		}
		if a.CredentialID == c.IssuerCredentialID {
			keys.credentialIssuer = credentialIssuer
		}
	}
	if len(expected) != 0 {
		return bundle, keys, protocol.NewError(preg.ErrCodeMaterialNotSynced, "delivery is missing ancestor credentials")
	}
	keys.grantor, err = protocol.ParseAppPublicKey(issuer.PublicKey)
	if err != nil {
		return bundle, keys, err
	}
	slices.SortFunc(ancestors, func(a, b protocol.AncestorCredential) int {
		return protocol.CompareUTF16(a.CredentialID, b.CredentialID)
	})
	bundle = wallet.GrantBundle{
		Claims:              c,
		TaskSpec:            taskSpec,
		RawGrantJWS:         leaf.Raw,
		Digest:              leaf.Digest,
		ChainRawGrants:      rawChain,
		AncestorCredentials: ancestors,
		TrustPaths:          slices.Clone(pkg.TrustPaths),
		Anchored:            true,
		Revision:            snap.Grants[c.ID].Revision,
	}
	return bundle, keys, nil
}

func parseDeliveryChain(snap *protocol.SnapshotView, rawChain []string, requireActive bool) ([]*protocol.ParsedGrant, error) {
	if len(rawChain) == 0 || len(rawChain) > protocol.MaxGrantDepth+1 {
		return nil, protocol.NewError(preg.ErrCodeMaterialInvalid, "invalid number of delivered grants")
	}
	chain := make([]*protocol.ParsedGrant, 0, len(rawChain))
	for _, raw := range rawChain {
		claims, err := decodeGrantPayload(raw)
		if err != nil {
			return nil, err
		}
		onChain, ok := snap.Grants[claims.ID]
		if !ok {
			return nil, protocol.NewError(preg.ErrCodeBindingMismatch, "delivered grant is absent from the registry path")
		}
		if requireActive && (onChain.Status != preg.Active || !onChain.Interval.Current(snap.Now, 0)) {
			return nil, protocol.NewError(preg.ErrCodeAncestorInactive, "delivered grant or ancestor is inactive or expired")
		}
		issuer := snap.Identities[onChain.Issuer]
		grantee := snap.Identities[onChain.Grantee]
		if issuer.Status != preg.Active || grantee.Status != preg.Active ||
			issuer.KeyVersion != onChain.IssuerKeyVersion || grantee.KeyVersion != onChain.GranteeKeyVersion {
			return nil, protocol.NewError(preg.ErrCodeCredentialStatusInvalid, "grant participant identity no longer matches registration")
		}
		granteeCred := snap.Credentials[onChain.GranteeCredential]
		if granteeCred.DeploymentID != snap.DeploymentID || granteeCred.Subject != grantee.ID ||
			granteeCred.SubjectKeyVersion != grantee.KeyVersion ||
			(requireActive && (granteeCred.Status != preg.Active || !granteeCred.Interval.Current(snap.Now, 0))) {
			return nil, protocol.NewError(preg.ErrCodeCredentialStatusInvalid, "grant recipient credential no longer matches registration")
		}
		pub, err := protocol.ParseAppPublicKey(issuer.PublicKey)
		if err != nil {
			return nil, err
		}
		parsed, err := protocol.ParseAndVerifyGrant(raw, pub, issuer.KeyID)
		if err != nil {
			return nil, err
		}
		onChain.Version = preg.Version{}
		if onChain != LedgerGrant(parsed) {
			return nil, protocol.NewError(preg.ErrCodeBindingMismatch, "signed grant differs from registry anchor")
		}
		chain = append(chain, parsed)
	}
	if err := protocol.VerifyGrantChain(chain); err != nil {
		return nil, err
	}
	return chain, nil
}

func verifyDeliveryCredential(snap *protocol.SnapshotView, credential protocol.AncestorCredential, requireActive bool) (*ecdsa.PublicKey, error) {
	anchor := snap.Credentials[credential.CredentialID]
	holder := snap.Identities[anchor.Subject]
	issuer := snap.Identities[anchor.Issuer]
	if anchor.DeploymentID != snap.DeploymentID ||
		(requireActive && (anchor.Status != preg.Active || !anchor.Interval.Current(snap.Now, 0))) ||
		holder.Status != preg.Active || holder.KeyVersion != anchor.SubjectKeyVersion ||
		issuer.Status != preg.Active || issuer.KeyVersion != anchor.IssuerKeyVersion {
		return nil, protocol.NewError(preg.ErrCodeCredentialStatusInvalid, "delivered credential is not current")
	}
	pub, err := protocol.ParseAppPublicKey(issuer.PublicKey)
	if err != nil {
		return nil, err
	}
	vc, err := protocol.VerifySDJWTCredential(credential.Presentation, pub, issuer.KeyID, holder.PublicKey, false)
	if err != nil {
		return nil, err
	}
	c := vc.Claims
	if c.ID != anchor.ID || c.Issuer != issuer.ID || c.Sub != holder.ID || vc.Domain != holder.Domain ||
		c.DeploymentID != snap.DeploymentID || vc.AnchorDigest != anchor.Digest ||
		c.IssuerKeyVersion != anchor.IssuerKeyVersion || c.AppKeyVersion != anchor.SubjectKeyVersion ||
		c.NBF != anchor.NBF || c.EXP != anchor.EXP {
		return nil, protocol.NewError(preg.ErrCodeBindingMismatch, "presented credential differs from registry")
	}
	issuerDomain := snap.Domains[issuer.Domain]
	cert := snap.Certifications[issuerDomain.Certification]
	var claims []string
	for name := range vc.Disclosed {
		claims = append(claims, name)
	}
	if !slices.Contains(c.Type, anchor.Type) ||
		(requireActive && (issuerDomain.Status != preg.Active || cert.Status != preg.Active || !cert.Interval.Current(snap.Now, 0))) ||
		!slices.ContainsFunc(cert.Scopes, func(scope preg.IssuerScope) bool {
			return scope.ID == issuer.ID && scope.AppKeyVersion == issuer.KeyVersion &&
				slices.Contains(scope.CredentialTypes, anchor.Type) && claimsInScope(claims, scope.ClaimNames, anchor.ClaimNames)
		}) {
		return nil, protocol.NewError(preg.ErrCodeIssuerScopeInvalid, "disclosure is outside certified issuer scope")
	}
	return pub, nil
}

func claimsInScope(value, certified, registered []string) bool {
	for _, claim := range value {
		if !slices.Contains(certified, claim) || !slices.Contains(registered, claim) {
			return false
		}
	}
	return true
}

func (g *GrantOperations) trustPaths(ctx context.Context, snap *protocol.SnapshotView, grantID string) ([]protocol.TrustPathEntry, error) {
	var issuers []string
	for grant := snap.Grants[grantID]; grant.ID != ""; grant = snap.Grants[grant.Parent] {
		issuers = append(issuers, snap.Credentials[grant.IssuerCredential].Issuer, snap.Credentials[grant.GranteeCredential].Issuer)
	}
	paths, err := domreg.BuildAccessTrustPaths(g.cfg.Certifications, snap, issuers...)
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		domainID := snap.Identities[p.Issuer].Domain
		if err := g.syncCertification(ctx, snap, domainID, p.DomainCertification); err != nil {
			return nil, err
		}
	}
	return paths, nil
}

func (g *GrantOperations) syncCertification(ctx context.Context, snap *protocol.SnapshotView, domainID, raw string) error {
	dom := snap.Domains[domainID]
	cert := snap.Certifications[dom.Certification]
	if dom.Status != preg.Active || cert.Status != preg.Active || !cert.Interval.Current(snap.Now, 0) ||
		cert.DeploymentID != snap.DeploymentID || cert.Domain != domainID || cert.Digest != preg.Digest([]byte(raw)) {
		return protocol.NewError(preg.ErrCodeDomainCertificationInvalid, "configured certification differs from current domain")
	}
	if existing, err := g.delivery.SyncedCertificationJWS(ctx, snap.DeploymentID, domainID, cert.ID, cert.Digest); err == nil && existing == raw {
		return nil
	}
	txID, blockNo, found, err := g.view.FirstVersionCommit(ctx, preg.Key("certification", cert.ID), snap.Height)
	if err != nil {
		return err
	}
	if !found {
		return protocol.NewError(preg.ErrCodeMaterialNotSynced, "original certification transaction is absent from the local applied view")
	}
	return g.delivery.PublishDomainCertification(ctx, snap, "workbench:"+g.cfg.DomainID, domainID, raw, g.root,
		txID, blockNo, true, snap.Now.Unix())
}

func decodeGrantPayload(compact string) (protocol.GrantClaims, error) {
	parts := strings.Split(strings.TrimSpace(compact), ".")
	if len(parts) != 3 {
		return protocol.GrantClaims{}, fmt.Errorf("invalid compact grant JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return protocol.GrantClaims{}, err
	}
	var claims protocol.GrantClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return protocol.GrantClaims{}, err
	}
	return claims, nil
}
