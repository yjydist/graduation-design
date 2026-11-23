package workbench

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"grad/platform/internal/httpx"
	"grad/platform/registrysvc"
	"grad/platform/state/fabric"
	"grad/protocol"
	"grad/protocol/registry"
)

const setPurchasingAuthorityMethod = "SetPurchasingAuthority"

type PurchasingAuthority struct {
	DomainID            string   `json:"domainId"`
	ExpectedRevision    uint64   `json:"expectedRevision"`
	PurchasingAuthority *string  `json:"purchasingAuthority"`
	EligibleServiceIDs  []string `json:"eligibleServiceIds"`
}

type browserOperation struct {
	registrysvc.OperationView
	TxID        *string `json:"txId"`
	BlockNumber *int64  `json:"blockNumber"`
}

func operationResponse(view *registrysvc.OperationView) browserOperation {
	out := browserOperation{OperationView: *view}
	if view.TxID != "" && !strings.HasPrefix(view.TxID, "pending:") {
		out.TxID = &view.TxID
	}
	if view.BlockHash != "" && view.ValidationCode != nil {
		out.BlockNumber = &view.BlockNumber
	}
	return out
}

func (s *Server) purchasingAuthority(w http.ResponseWriter, r *http.Request, principal Principal) {
	view, err := s.cfg.ReadPurchasingAuthority(r.Context(), principal)
	if err != nil {
		writeManagementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

func (s *Server) setPurchasingAuthority(w http.ResponseWriter, r *http.Request, principal Principal) {
	var input struct {
		ExpectedRevision    uint64          `json:"expectedRevision"`
		PurchasingAuthority json.RawMessage `json:"purchasingAuthority"`
	}
	if !ReadJSON(w, r, &input) {
		return
	}
	var authority *string
	if input.ExpectedRevision == 0 || input.ExpectedRevision > uint64(protocol.MaxSafeInt) ||
		json.Unmarshal(input.PurchasingAuthority, &authority) != nil ||
		authority != nil && (!strings.HasPrefix(*authority, "did:web:") || len(*authority) <= len("did:web:")) {
		WriteError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "positive expectedRevision and service DID or null required")
		return
	}
	key, ok := IdempotencyKey(w, r)
	if !ok {
		return
	}
	update := registry.PurchasingAuthorityUpdate{Bound: registry.Bound{DeploymentID: s.cfg.DeploymentID},
		DomainID: principal.DomainID, ExpectedRevision: input.ExpectedRevision}
	if authority != nil {
		update.PurchasingAuthority = *authority
		// A replay already bound to the exact caller and key must return its original outcome,
		// even when the target service has since lost eligibility.
		opID := registrysvc.ManagementOperationID(s.cfg.DeploymentID, principal.Management, setPurchasingAuthorityMethod, key)
		_, err := s.cfg.Registry.Operation(r.Context(), principal.Management, opID)
		switch registry.CodeOf(err) {
		case registry.ErrCodeOperationUnknown:
			if err := s.cfg.CheckPurchasingAuthority(r.Context(), principal, *authority); err != nil {
				writeManagementError(w, r, err)
				return
			}
		default:
			if err != nil {
				writeManagementError(w, r, err)
				return
			}
		}
	}
	view, err := s.cfg.Registry.Submit(r.Context(), principal.Management, setPurchasingAuthorityMethod, key, update)
	if err != nil {
		writeManagementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, operationResponse(view))
}

func (s *Server) operation(w http.ResponseWriter, r *http.Request, principal Principal) {
	opID := r.PathValue("operationId")
	view, err := s.cfg.Registry.Operation(r.Context(), principal.Management, opID)
	if err != nil {
		if registry.HasCode(err, registry.ErrCodeIdentityManagementForbidden) || registry.HasCode(err, registry.ErrCodeOperationUnknown) {
			WriteError(w, r, http.StatusNotFound, registry.ErrCodeOperationUnknown, "unknown operation")
			return
		}
		writeManagementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, operationResponse(view))
}

func writeManagementError(w http.ResponseWriter, r *http.Request, err error) {
	code := registry.CodeOf(err)
	switch code {
	case registry.ErrCodeIdentityManagementForbidden:
		WriteError(w, r, http.StatusForbidden, code, "local domain administrator required")
	case registry.ErrCodePurchasingAuthorityInvalid:
		WriteError(w, r, http.StatusForbidden, code, "active service in the local domain required")
	case registry.ErrCodeIdempotencyConflict, registry.ErrCodeStateChanged:
		WriteError(w, r, http.StatusConflict, code, err.Error())
	case registry.ErrCodeInvalidSchema:
		WriteError(w, r, http.StatusBadRequest, code, "invalid management input")
	default:
		WriteError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "management operation unavailable")
	}
}

// FabricAuthority resolves browser principals and PA eligibility from the deployment's pinned peer.
type FabricAuthority struct {
	Deployment         *fabric.Deployment
	Instance           *fabric.Instance
	EligibleServiceIDs []string
}

func (a FabricAuthority) VerifyPrincipal(ctx context.Context, principal Principal) error {
	if !validPrincipal(principal, principal.DomainID) {
		return principalForbidden()
	}
	peer, err := a.Instance.ReadPeer()
	if err != nil {
		return err
	}
	defer peer.Close()
	domain, err := fabric.ReadLedgerRecord[registry.Domain](ctx, peer, "domain", principal.DomainID)
	if err != nil {
		return authorityReadError(err)
	}
	if domain.ID != principal.DomainID || domain.DeploymentID != a.Deployment.DeploymentID ||
		domain.Status != registry.Active || domain.Certification == "" {
		return principalForbidden()
	}
	cert, err := fabric.ReadLedgerRecord[registry.Certification](ctx, peer, "certification", domain.Certification)
	if err != nil {
		return authorityReadError(err)
	}
	if cert.DeploymentID != a.Deployment.DeploymentID || cert.ID != domain.Certification || cert.Domain != domain.ID ||
		cert.Status != registry.Active || cert.RootKeyVersion != a.Deployment.Bootstrap.Root.KeyVersion ||
		!cert.Interval.Current(time.Now(), registry.PeerTimeWindow+registry.ClockError) {
		return principalForbidden()
	}
	domainIdentity, err := fabric.ReadLedgerRecord[registry.Identity](ctx, peer, "identity", domain.DID)
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
	id, err := fabric.ReadLedgerRecord[registry.Identity](ctx, peer, "identity", principal.SubjectID)
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

func identityMatches(id registry.Identity, deploymentID, domainID, subjectID string, management registry.Management) bool {
	return id.DeploymentID == deploymentID && id.Domain == domainID && id.ID == subjectID &&
		id.Management == management && id.Status == registry.Active && id.KeyVersion > 0
}

func authorityReadError(err error) error {
	if fabric.IsMissingRecord(err) {
		return principalForbidden()
	}
	return err
}

func principalForbidden() error {
	return registry.NewError(registry.ErrCodeIdentityManagementForbidden, "local principal inactive or does not match registry")
}

func (a FabricAuthority) ReadPurchasingAuthority(ctx context.Context, principal Principal) (PurchasingAuthority, error) {
	var view PurchasingAuthority
	peer, err := a.Instance.ReadPeer()
	if err != nil {
		return view, err
	}
	defer peer.Close()
	domain, err := fabric.ReadLedgerRecord[registry.Domain](ctx, peer, "domain", principal.DomainID)
	if err != nil {
		return view, authorityReadError(err)
	}
	if principal.Role != RoleAdmin || domain.ID != principal.DomainID || domain.DID != principal.SubjectID ||
		domain.DeploymentID != a.Deployment.DeploymentID || domain.Status != registry.Active || domain.Admin != principal.Management {
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
			if registry.HasCode(err, registry.ErrCodePurchasingAuthorityInvalid) {
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

func (a FabricAuthority) checkPurchasingAuthority(ctx context.Context, peer *fabric.PeerClient, principal Principal, subject string) error {
	id, err := fabric.ReadLedgerRecord[registry.Identity](ctx, peer, "identity", subject)
	if err != nil && !fabric.IsMissingRecord(err) {
		return err
	}
	if !identityMatches(id, a.Deployment.DeploymentID, principal.DomainID, subject, id.Management) || id.Kind != "SERVICE" ||
		!id.Management.Valid() || id.Management.MSPID != principal.DomainID+"Msp" {
		return registry.Reject(registry.ErrCodePurchasingAuthorityInvalid)
	}
	return nil
}
