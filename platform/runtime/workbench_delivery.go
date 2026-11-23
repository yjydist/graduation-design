package runtime

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"

	"grad/platform/agent"
	"grad/platform/registrysvc"
	"grad/platform/state/fabric"
	"grad/protocol"
	"grad/protocol/registry"
)

func (g *GrantOperations) grantSnapshot(ctx context.Context, grantID string) (*protocol.SnapshotView, error) {
	view := fabric.View{DB: g.cfg.DB, Deployment: g.cfg.Deployment}
	head, err := view.Head(ctx, g.cfg.DB, false)
	if err != nil {
		return nil, err
	}
	if head == nil || head.Number == 0 {
		return nil, protocol.NewError(registry.ErrCodeMaterialNotSynced, "registry checkpoint has not reached grant registration")
	}
	state, err := g.state.AssembleHistoricalSnapshot(ctx, grantID, int64(head.Number), g.cfg.Now())
	if err != nil {
		return nil, err
	}
	return state.Snapshot, nil
}

func (g *GrantOperations) verifyOriginal(ctx context.Context, op registrysvc.OperationView, grantID, grantDigest string) error {
	if op.Method != "RegisterGrant" || op.Status != "CONFIRMED" || op.ValidationCode == nil || *op.ValidationCode != "VALID" ||
		!registry.IsDigest(op.TxID) || op.BlockNumber <= 0 || !registry.IsDigest(op.BlockHash) ||
		op.TransactionIndex == nil || *op.TransactionIndex < 0 {
		return protocol.NewError(registry.ErrCodeMaterialNotSynced, "original grant transaction is not confirmed")
	}
	// fabric_version contains writes only from independently verified VALID
	// transactions in the continuous locally applied block history.
	var raw []byte
	err := g.cfg.DB.QueryRow(ctx, `SELECT v.value FROM fabric_version v
		JOIN fabric_block b ON b.deployment=v.deployment AND b.block_no=v.block_no
		WHERE v.deployment=$1 AND v.key=$2 AND v.tx_id=$3 AND v.block_no=$4 AND b.hash=$5 AND v.tx_index=$6`,
		g.cfg.Deployment.DeploymentID, registry.Key("grant", grantID), op.TxID, op.BlockNumber, op.BlockHash, *op.TransactionIndex).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return protocol.NewError(registry.ErrCodeMaterialNotSynced, "original grant transaction is absent from the local applied view")
	}
	if err != nil {
		return err
	}
	var anchor registry.Grant
	if err := protocol.DecodeStrictJSON(raw, &anchor); err != nil {
		return err
	}
	if anchor.ID != grantID || anchor.Revision != 1 || anchor.Status != registry.Active || anchor.Digest != grantDigest {
		return protocol.NewError(registry.ErrCodeBindingMismatch, "original transaction did not register this grant")
	}
	return nil
}

func (g *GrantOperations) publish(ctx context.Context, op *registrysvc.OperationView, pkg registrysvc.GrantDeliveryPackage) (*registrysvc.OperationView, *GrantDelivery, error) {
	if err := g.sync(ctx); err != nil {
		return op, nil, err
	}
	if err := g.verifyOriginal(ctx, *op, pkg.GrantID, registry.Digest([]byte(pkg.GrantJWS))); err != nil {
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
		op.TxID, op.BlockNumber, true, g.cfg.Now().UTC().Unix())
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
		return nil, protocol.NewError(registry.ErrCodeBindingMismatch, "outbox grant originated outside this domain")
	}
	parsed, err := protocol.ParseAndVerifyGrant(pkg.GrantJWS, &a.Signer.PrivateKey.PublicKey, a.Signer.KeyID)
	if err != nil {
		return nil, err
	}
	if parsed.Claims.GranteeCredentialID != recipient.CredentialID {
		return nil, protocol.NewError(registry.ErrCodeBindingMismatch, "publication recipient credential differs")
	}
	dep := g.cfg.Deployment.DeploymentID
	opID := registrysvc.ManagementOperationID(dep, a.Management, "RegisterGrant", key)
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
func (g *GrantOperations) Receive(ctx context.Context, recipient GrantRecipient, delivery GrantDelivery) (agent.GrantBundle, string, error) {
	pkg := delivery.Package
	if pkg.Recipient != recipient.DID || pkg.DeploymentID != g.cfg.Deployment.DeploymentID {
		return agent.GrantBundle{}, "", protocol.NewError(registry.ErrCodeBindingMismatch, "delivery is addressed to another wallet or deployment")
	}
	_, digest, err := pkg.Digest()
	if err != nil {
		return agent.GrantBundle{}, "", err
	}
	if digest != delivery.Digest {
		return agent.GrantBundle{}, "", protocol.NewError(registry.ErrCodeBindingMismatch, "delivery digest differs from package")
	}
	if err := g.sync(ctx); err != nil {
		return agent.GrantBundle{}, "", err
	}
	if err := g.verifyOriginal(ctx, delivery.Operation, pkg.GrantID, registry.Digest([]byte(pkg.GrantJWS))); err != nil {
		return agent.GrantBundle{}, "", err
	}
	snap, err := g.grantSnapshot(ctx, pkg.GrantID)
	if err != nil {
		return agent.GrantBundle{}, "", err
	}
	if err := g.matchRecipient(snap, recipient, pkg.GrantID); err != nil {
		return agent.GrantBundle{}, "", err
	}
	issuer := snap.Identities[snap.Grants[pkg.GrantID].Issuer]
	op := delivery.Operation
	if op.OperationID != registrysvc.ManagementOperationID(snap.DeploymentID, issuer.Management, op.Method, op.OperationKey) {
		return agent.GrantBundle{}, "", protocol.NewError(registry.ErrCodeBindingMismatch, "original operation does not match issuer and operation key")
	}
	bundle, keys, err := g.verifyPackage(snap, pkg, true)
	if err != nil {
		return agent.GrantBundle{}, "", err
	}
	paths, err := g.trustPaths(ctx, snap, pkg.GrantID)
	if err != nil {
		return agent.GrantBundle{}, "", err
	}
	if !slices.Equal(paths, pkg.TrustPaths) {
		return agent.GrantBundle{}, "", protocol.NewError(registry.ErrCodeBindingMismatch, "delivery trust paths differ from registry")
	}
	_, receipt, err := g.delivery.DeliverGrantReceipt(ctx, snap, snap.DeploymentID, recipient.DID, pkg.GrantID,
		&pkg, g.root, keys.credentialIssuer, keys.grantor, g.cfg.Now().UTC().Unix())
	if err != nil {
		return agent.GrantBundle{}, "", err
	}
	return bundle, receipt, nil
}

// MarkReceived advances the issuer-side operation after its authenticated
// recipient acknowledges the verified receipt digest.
func (g *GrantOperations) MarkReceived(ctx context.Context, delivery GrantDelivery, receiptDigest string) error {
	if delivery.Digest != receiptDigest {
		return protocol.NewError(registry.ErrCodeBindingMismatch, "recipient receipt digest differs from delivery")
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
		return protocol.NewError(registry.ErrCodeBindingMismatch, "receipt does not match original publication")
	}
	op := stored.Operation
	return g.cfg.Management.RecordOutcome(ctx, op.OperationID, op.Stage, op.Status, op.TxID, nil, nil, true)
}

func (g *GrantOperations) matchRecipient(snap *protocol.SnapshotView, recipient GrantRecipient, grantID string) error {
	gnt, found := snap.Grants[grantID]
	id := snap.Identities[recipient.DID]
	if !found || gnt.Grantee != recipient.DID || gnt.GranteeCredential != recipient.CredentialID ||
		id.Domain != g.cfg.DomainID || id.DeploymentID != snap.DeploymentID {
		return protocol.NewError(registry.ErrCodeBindingMismatch, "grant recipient does not belong to this deployment and domain")
	}
	return nil
}

// Load requires a durable receipt and rechecks its current authorization chain.
func (g *GrantOperations) Load(ctx context.Context, recipient GrantRecipient, grantID string) (agent.GrantBundle, error) {
	return g.load(ctx, recipient, grantID, true)
}

// LoadRetained gives a trusted caller previously delivered material for
// reconciliation or a supplier-side decision about a disabled ancestor.
// Expired grants cannot be used to submit new requests through BoundOperations.
func (g *GrantOperations) LoadRetained(ctx context.Context, recipient GrantRecipient, grantID string) (agent.GrantBundle, error) {
	return g.load(ctx, recipient, grantID, false)
}

func (g *GrantOperations) load(ctx context.Context, recipient GrantRecipient, grantID string, requireActive bool) (agent.GrantBundle, error) {
	pkg, _, err := g.delivery.ReceivedGrant(ctx, recipient.DID, grantID)
	if err != nil {
		return agent.GrantBundle{}, err
	}
	if err := g.sync(ctx); err != nil {
		return agent.GrantBundle{}, err
	}
	snap, err := g.grantSnapshot(ctx, grantID)
	if err != nil {
		return agent.GrantBundle{}, err
	}
	if err := g.matchRecipient(snap, recipient, grantID); err != nil {
		return agent.GrantBundle{}, err
	}
	bundle, _, err := g.verifyPackage(snap, pkg, requireActive)
	if err != nil || !requireActive {
		return bundle, err
	}
	paths, err := g.trustPaths(ctx, snap, grantID)
	if err != nil {
		return agent.GrantBundle{}, err
	}
	if !slices.Equal(paths, bundle.TrustPaths) {
		return agent.GrantBundle{}, protocol.NewError(registry.ErrCodeBindingMismatch, "stored trust paths differ from registry")
	}
	return bundle, nil
}

func (g *GrantOperations) bundle(ctx context.Context, pkg registrysvc.GrantDeliveryPackage, requireActive bool) (agent.GrantBundle, error) {
	snap, err := g.grantSnapshot(ctx, pkg.GrantID)
	if err != nil {
		return agent.GrantBundle{}, err
	}
	bundle, _, err := g.verifyPackage(snap, pkg, requireActive)
	return bundle, err
}

type deliveryKeys struct {
	grantor          *ecdsa.PublicKey
	credentialIssuer *ecdsa.PublicKey
}

func (g *GrantOperations) verifyPackage(snap *protocol.SnapshotView, pkg registrysvc.GrantDeliveryPackage, requireActive bool) (agent.GrantBundle, deliveryKeys, error) {
	var bundle agent.GrantBundle
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
		return bundle, keys, protocol.NewError(registry.ErrCodeBindingMismatch, "grant package differs from confirmed task or recipient")
	}
	if requireActive && (task.Status != registry.Active || !task.Interval.Current(snap.Now, 0)) {
		return bundle, keys, protocol.NewError(registry.ErrCodeTaskInactive, "delivered task is inactive or expired")
	}
	root := chain[0].Claims
	if root.AuthorizationMode == registry.RP && root.Issuer != g.cfg.Deployment.Bootstrap.ResourceOwner {
		return bundle, keys, protocol.NewError(registry.ErrCodeRootAuthorityInvalid, "root issuer differs from deployment resource authority")
	}
	issuer := snap.Identities[c.Issuer]
	if pkg.DomainCertificationJWS != g.cfg.Certifications[issuer.Domain] || pkg.DomainCertificationJWS == "" {
		return bundle, keys, protocol.NewError(registry.ErrCodeDomainCertificationInvalid, "publication certification differs from configured trust material")
	}

	ancestors := append(slices.Clone(pkg.AncestorCredentials),
		protocol.AncestorCredential{CredentialID: c.IssuerCredentialID, Presentation: pkg.ServicePresentation})
	expected := make(map[string]struct{}, len(chain))
	for _, p := range chain {
		expected[p.Claims.IssuerCredentialID] = struct{}{}
	}
	for _, a := range ancestors {
		if _, ok := expected[a.CredentialID]; !ok {
			return bundle, keys, protocol.NewError(registry.ErrCodeBindingMismatch, "unexpected or repeated ancestor credential")
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
		return bundle, keys, protocol.NewError(registry.ErrCodeMaterialNotSynced, "delivery is missing ancestor credentials")
	}
	keys.grantor, err = protocol.ParseAppPublicKey(issuer.PublicKey)
	if err != nil {
		return bundle, keys, err
	}
	slices.SortFunc(ancestors, func(a, b protocol.AncestorCredential) int {
		return protocol.CompareUTF16(a.CredentialID, b.CredentialID)
	})
	bundle = agent.GrantBundle{
		Claims: c, TaskSpec: taskSpec, RawGrantJWS: leaf.Raw, Digest: leaf.Digest, ChainRawGrants: rawChain,
		AncestorCredentials: ancestors, TrustPaths: slices.Clone(pkg.TrustPaths), Anchored: true, Revision: snap.Grants[c.ID].Revision,
	}
	return bundle, keys, nil
}

func parseDeliveryChain(snap *protocol.SnapshotView, rawChain []string, requireActive bool) ([]*protocol.ParsedGrant, error) {
	if len(rawChain) == 0 || len(rawChain) > protocol.MaxGrantDepth+1 {
		return nil, protocol.NewError(registry.ErrCodeMaterialInvalid, "invalid number of delivered grants")
	}
	chain := make([]*protocol.ParsedGrant, 0, len(rawChain))
	for _, raw := range rawChain {
		claims, err := decodeGrantPayload(raw)
		if err != nil {
			return nil, err
		}
		onChain, ok := snap.Grants[claims.ID]
		if !ok {
			return nil, protocol.NewError(registry.ErrCodeBindingMismatch, "delivered grant is absent from the registry path")
		}
		if requireActive && (onChain.Status != registry.Active || !onChain.Interval.Current(snap.Now, 0)) {
			return nil, protocol.NewError(registry.ErrCodeAncestorInactive, "delivered grant or ancestor is inactive or expired")
		}
		issuer := snap.Identities[onChain.Issuer]
		grantee := snap.Identities[onChain.Grantee]
		if issuer.Status != registry.Active || grantee.Status != registry.Active ||
			issuer.KeyVersion != onChain.IssuerKeyVersion || grantee.KeyVersion != onChain.GranteeKeyVersion {
			return nil, protocol.NewError(registry.ErrCodeCredentialStatusInvalid, "grant participant identity no longer matches registration")
		}
		granteeCred := snap.Credentials[onChain.GranteeCredential]
		if granteeCred.DeploymentID != snap.DeploymentID || granteeCred.Subject != grantee.ID ||
			granteeCred.SubjectKeyVersion != grantee.KeyVersion ||
			(requireActive && (granteeCred.Status != registry.Active || !granteeCred.Interval.Current(snap.Now, 0))) {
			return nil, protocol.NewError(registry.ErrCodeCredentialStatusInvalid, "grant recipient credential no longer matches registration")
		}
		pub, err := protocol.ParseAppPublicKey(issuer.PublicKey)
		if err != nil {
			return nil, err
		}
		parsed, err := protocol.ParseAndVerifyGrant(raw, pub, issuer.KeyID)
		if err != nil {
			return nil, err
		}
		onChain.Version = registry.Version{}
		if onChain != ledgerGrant(parsed) {
			return nil, protocol.NewError(registry.ErrCodeBindingMismatch, "signed grant differs from registry anchor")
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
		(requireActive && (anchor.Status != registry.Active || !anchor.Interval.Current(snap.Now, 0))) ||
		holder.Status != registry.Active || holder.KeyVersion != anchor.SubjectKeyVersion ||
		issuer.Status != registry.Active || issuer.KeyVersion != anchor.IssuerKeyVersion {
		return nil, protocol.NewError(registry.ErrCodeCredentialStatusInvalid, "delivered credential is not current")
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
		return nil, protocol.NewError(registry.ErrCodeBindingMismatch, "presented credential differs from registry")
	}
	issuerDomain := snap.Domains[issuer.Domain]
	cert := snap.Certifications[issuerDomain.Certification]
	var claims []string
	for name := range vc.Disclosed {
		claims = append(claims, name)
	}
	if !slices.Contains(c.Type, anchor.Type) ||
		(requireActive && (issuerDomain.Status != registry.Active || cert.Status != registry.Active || !cert.Interval.Current(snap.Now, 0))) ||
		!slices.ContainsFunc(cert.Scopes, func(scope registry.IssuerScope) bool {
			return scope.ID == issuer.ID && scope.AppKeyVersion == issuer.KeyVersion &&
				slices.Contains(scope.CredentialTypes, anchor.Type) && claimsInScope(claims, scope.ClaimNames, anchor.ClaimNames)
		}) {
		return nil, protocol.NewError(registry.ErrCodeIssuerScopeInvalid, "disclosure is outside certified issuer scope")
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
	paths, err := registrysvc.BuildAccessTrustPaths(g.cfg.Certifications, snap, issuers...)
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
	if dom.Status != registry.Active || cert.Status != registry.Active || !cert.Interval.Current(snap.Now, 0) ||
		cert.DeploymentID != snap.DeploymentID || cert.Domain != domainID || cert.Digest != registry.Digest([]byte(raw)) {
		return protocol.NewError(registry.ErrCodeDomainCertificationInvalid, "configured certification differs from current domain")
	}
	if existing, err := g.delivery.SyncedCertificationJWS(ctx, snap.DeploymentID, domainID, cert.ID, cert.Digest); err == nil && existing == raw {
		return nil
	}
	var txID string
	var blockNo int64
	err := g.cfg.DB.QueryRow(ctx, `SELECT tx_id, block_no FROM fabric_version
		WHERE deployment=$1 AND key=$2 AND block_no<=$3 AND value IS NOT NULL
		ORDER BY block_no ASC, tx_index ASC LIMIT 1`, snap.DeploymentID, registry.Key("certification", cert.ID), snap.Height).Scan(&txID, &blockNo)
	if errors.Is(err, pgx.ErrNoRows) {
		return protocol.NewError(registry.ErrCodeMaterialNotSynced, "original certification transaction is absent from the local applied view")
	}
	if err != nil {
		return err
	}
	return g.delivery.PublishDomainCertification(ctx, snap, "workbench:"+g.cfg.DomainID, domainID, raw, g.root,
		txID, blockNo, true, snap.Now.Unix())
}
