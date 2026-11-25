package procurement

import (
	"context"
	"slices"
	"strings"
	"time"

	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/ledger"
	"grad/protocol"
	preg "grad/protocol/registry"
)

// FabricAuthority resolves browser principals and PA eligibility from the deployment's pinned peer.
type FabricAuthority struct {
	Deployment         *ledger.Deployment
	Instance           *ledger.Instance
	EligibleServiceIDs []string
}

var _ AuthorityReader = FabricAuthority{}

func (a FabricAuthority) VerifyPrincipal(ctx context.Context, principal Principal) error {
	if !ValidPrincipal(principal, principal.DomainID) {
		return principalForbidden()
	}
	peer, err := a.Instance.ReadPeer()
	if err != nil {
		return err
	}
	defer peer.Close()
	domain, err := ledger.ReadLedgerRecord[preg.Domain](ctx, peer, "domain", principal.DomainID)
	if err != nil {
		return authorityReadError(err)
	}
	if domain.ID != principal.DomainID || domain.DeploymentID != a.Deployment.DeploymentID ||
		domain.Status != preg.Active || domain.Certification == "" {
		return principalForbidden()
	}
	cert, err := ledger.ReadLedgerRecord[preg.Certification](ctx, peer, "certification", domain.Certification)
	if err != nil {
		return authorityReadError(err)
	}
	if cert.DeploymentID != a.Deployment.DeploymentID || cert.ID != domain.Certification || cert.Domain != domain.ID ||
		cert.Status != preg.Active || cert.RootKeyVersion != a.Deployment.Bootstrap.Root.KeyVersion ||
		!cert.Interval.Current(time.Now(), preg.PeerTimeWindow+preg.ClockError) {
		return principalForbidden()
	}
	domainIdentity, err := ledger.ReadLedgerRecord[preg.Identity](ctx, peer, "identity", domain.DID)
	if err != nil {
		return authorityReadError(err)
	}
	if !identityMatches(domainIdentity, a.Deployment.DeploymentID, domain.ID, domain.DID, domain.Admin) || domainIdentity.Kind != "DOMAIN" {
		return principalForbidden()
	}
	if principal.Role == RoleAdmin || principal.Role == RoleAuditor {
		if principal.SubjectID == domain.DID && principal.Management == domain.Admin {
			return nil
		}
		return principalForbidden()
	}
	id, err := ledger.ReadLedgerRecord[preg.Identity](ctx, peer, "identity", principal.SubjectID)
	if err != nil {
		return authorityReadError(err)
	}
	if !identityMatches(id, a.Deployment.DeploymentID, domain.ID, principal.SubjectID, principal.Management) {
		return principalForbidden()
	}
	buyer := a.Deployment.Bootstrap.TaskCreator
	if principal.Role == RoleBuyer && id.Kind == "USER" && buyer.Domain == domain.ID && buyer.Subject == id.ID && buyer.Management == id.Management {
		return nil
	}
	return principalForbidden()
}

func identityMatches(id preg.Identity, deploymentID, domainID, subjectID string, management preg.Management) bool {
	return id.DeploymentID == deploymentID && id.Domain == domainID && id.ID == subjectID &&
		id.Management == management && id.Status == preg.Active && id.KeyVersion > 0
}

func authorityReadError(err error) error {
	if ledger.IsMissingRecord(err) {
		return principalForbidden()
	}
	return err
}

func principalForbidden() error {
	return preg.NewError(preg.ErrCodeIdentityManagementForbidden, "local principal inactive or does not match registry")
}

func (a FabricAuthority) ReadPurchasingAuthority(ctx context.Context, principal Principal) (PurchasingAuthority, error) {
	var view PurchasingAuthority
	peer, err := a.Instance.ReadPeer()
	if err != nil {
		return view, err
	}
	defer peer.Close()
	domain, err := ledger.ReadLedgerRecord[preg.Domain](ctx, peer, "domain", principal.DomainID)
	if err != nil {
		return view, authorityReadError(err)
	}
	if principal.Role != RoleAdmin || domain.ID != principal.DomainID || domain.DID != principal.SubjectID ||
		domain.DeploymentID != a.Deployment.DeploymentID || domain.Status != preg.Active || domain.Admin != principal.Management {
		return view, principalForbidden()
	}
	view.DomainID = domain.ID
	view.ExpectedRevision = domain.Revision
	if domain.PurchasingAuthority != "" {
		view.PurchasingAuthority = &domain.PurchasingAuthority
	}
	candidates := append(slices.Clone(a.EligibleServiceIDs), domain.PurchasingAuthority)
	slices.Sort(candidates)
	view.EligibleServiceIDs = make([]string, 0, len(candidates))
	for _, candidate := range slices.Compact(candidates) {
		if candidate == "" {
			continue
		}
		if err := a.checkPurchasingAuthority(ctx, peer, principal, candidate); err != nil {
			if preg.HasCode(err, preg.ErrCodePurchasingAuthorityInvalid) {
				continue
			}
			return view, err
		}
		view.EligibleServiceIDs = append(view.EligibleServiceIDs, candidate)
	}
	return view, nil
}

func (a FabricAuthority) CheckPurchasingAuthority(ctx context.Context, principal Principal, subject string) error {
	if principal.Role != RoleAdmin {
		return principalForbidden()
	}
	peer, err := a.Instance.ReadPeer()
	if err != nil {
		return err
	}
	defer peer.Close()
	return a.checkPurchasingAuthority(ctx, peer, principal, subject)
}

func (a FabricAuthority) checkPurchasingAuthority(ctx context.Context, peer *ledger.PeerClient, principal Principal, subject string) error {
	id, err := ledger.ReadLedgerRecord[preg.Identity](ctx, peer, "identity", subject)
	if err != nil && !ledger.IsMissingRecord(err) {
		return err
	}
	if !identityMatches(id, a.Deployment.DeploymentID, principal.DomainID, subject, id.Management) || id.Kind != "SERVICE" ||
		!id.Management.Valid() || id.Management.MSPID != principal.DomainID+"Msp" {
		return preg.Reject(preg.ErrCodePurchasingAuthorityInvalid)
	}
	return nil
}

// AuthorityService coordinates purchasing authority reads, idempotent updates,
// and operation status lookups on top of an AuthorityReader and domreg.Service.
type AuthorityService struct {
	deploymentID string
	authority    AuthorityReader
	registry     *domreg.Service
}

// NewAuthorityService creates an AuthorityService for deploymentID.
func NewAuthorityService(deploymentID string, authority AuthorityReader, reg *domreg.Service) *AuthorityService {
	return &AuthorityService{
		deploymentID: deploymentID,
		authority:    authority,
		registry:     reg,
	}
}

// VerifyPrincipal validates that principal is active and authorized by the current registry.
func (s *AuthorityService) VerifyPrincipal(ctx context.Context, principal Principal) error {
	if s == nil || s.authority == nil {
		return ErrUnavailable
	}
	return s.authority.VerifyPrincipal(ctx, principal)
}

// ReadPurchasingAuthority returns the domain's current purchasing authority configuration.
func (s *AuthorityService) ReadPurchasingAuthority(ctx context.Context, principal Principal) (PurchasingAuthority, error) {
	if s == nil || s.authority == nil {
		return PurchasingAuthority{}, ErrUnavailable
	}
	if principal.Role != RoleAdmin {
		return PurchasingAuthority{}, principalForbidden()
	}
	return s.authority.ReadPurchasingAuthority(ctx, principal)
}

// SetPurchasingAuthority validates and submits an idempotent SetPurchasingAuthority management operation.
func (s *AuthorityService) SetPurchasingAuthority(
	ctx context.Context,
	principal Principal,
	idempotencyKey string,
	expectedRevision uint64,
	authority *string,
) (*domreg.OperationView, error) {
	if s == nil || s.authority == nil || s.registry == nil {
		return nil, ErrUnavailable
	}
	if principal.Role != RoleAdmin {
		return nil, principalForbidden()
	}
	if expectedRevision == 0 || expectedRevision > uint64(protocol.MaxSafeInt) ||
		(authority != nil && (!strings.HasPrefix(*authority, "did:web:") || len(*authority) <= len("did:web:"))) {
		return nil, protocol.NewError(preg.ErrCodeInvalidSchema, "positive expectedRevision and service DID or null required")
	}
	if idempotencyKey == "" {
		return nil, protocol.NewError(preg.ErrCodeInvalidSchema, "idempotency key required")
	}
	update := preg.PurchasingAuthorityUpdate{
		Bound:            preg.Bound{DeploymentID: s.deploymentID},
		DomainID:         principal.DomainID,
		ExpectedRevision: expectedRevision,
	}
	if authority != nil {
		update.PurchasingAuthority = *authority
		// A replay already bound to the exact caller and key must return its original outcome,
		// even when the target service has since lost eligibility.
		opID := domreg.ManagementOperationID(s.deploymentID, principal.Management, SetPurchasingAuthorityMethod, idempotencyKey)
		_, err := s.registry.Operation(ctx, principal.Management, opID)
		switch preg.CodeOf(err) {
		case preg.ErrCodeOperationUnknown:
			if err := s.authority.CheckPurchasingAuthority(ctx, principal, *authority); err != nil {
				return nil, err
			}
		default:
			if err != nil {
				return nil, err
			}
		}
	}
	return s.registry.Submit(ctx, principal.Management, SetPurchasingAuthorityMethod, idempotencyKey, update)
}

// GetOperation returns an operation owned by principal's management identity, hiding foreign
// or unauthorized operations as OPERATION_UNKNOWN.
func (s *AuthorityService) GetOperation(ctx context.Context, principal Principal, opID string) (*domreg.OperationView, error) {
	if s == nil || s.registry == nil {
		return nil, ErrUnavailable
	}
	view, err := s.registry.Operation(ctx, principal.Management, opID)
	if err != nil {
		if preg.HasCode(err, preg.ErrCodeIdentityManagementForbidden) || preg.HasCode(err, preg.ErrCodeOperationUnknown) {
			return nil, protocol.NewError(preg.ErrCodeOperationUnknown, "unknown operation")
		}
		return nil, err
	}
	return view, nil
}
