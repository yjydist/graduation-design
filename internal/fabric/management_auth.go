package fabric

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/serviceauth"

	"github.com/jackc/pgx/v5"
)

var errOperationQueryForbidden = errors.New("operation query forbidden")

// SetOperationAuditors installs exact, host-approved certificate bindings. A role
// asserted in headers or a certificate alone never grants operation audit access.
// Call on each host startup; an auditor may read only its own MSP's operations.
func (s *ManagementOperationService) SetOperationAuditors(auditors []api.Management) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.operationAuditors = make(map[api.Management]bool)
	for _, auditor := range auditors {
		if auditor.Valid() {
			s.operationAuditors[auditor] = true
		}
	}
}

func (s *ManagementOperationService) managementCaller(r *http.Request) (api.Management, bool) {
	id, authenticated := serviceauth.Caller(r)
	if !authenticated || id.Fingerprint == "" {
		return api.Management{}, false
	}
	caller := api.Management{MSPID: id.MSPID, Fingerprint: id.Fingerprint}
	if resolver, ok := s.backend.(interface {
		ManagementForFingerprint(string) (api.Management, bool)
	}); ok {
		if resolved, found := resolver.ManagementForFingerprint(id.Fingerprint); found {
			return resolved, resolved.Valid()
		}
		// Audit credentials need not have access to a Fabric signing key.
		s.mu.RLock()
		defer s.mu.RUnlock()
		for auditor := range s.operationAuditors {
			if auditor.Fingerprint == id.Fingerprint {
				return auditor, true
			}
		}
		return api.Management{}, false
	}
	return caller, caller.Valid()
}

func (s *ManagementOperationService) authorizeOperationQuery(ctx context.Context, opID string, caller api.Management) error {
	var owner api.Management
	err := s.db.QueryRow(ctx, `SELECT caller_msp_id,caller_fingerprint FROM operations WHERE deployment_id=$1 AND operation_id=$2`, s.deploymentID, opID).Scan(&owner.MSPID, &owner.Fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		// The authenticated handler retains its ordinary 404 for unknown IDs.
		return nil
	}
	if err != nil {
		return err
	}
	if caller == owner {
		return nil
	}
	s.mu.RLock()
	allowed := s.operationAuditors[caller] && caller.MSPID == owner.MSPID
	s.mu.RUnlock()
	if !allowed {
		return errOperationQueryForbidden
	}
	return nil
}

func writeManagementForbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{"errorCode": "IDENTITY_MANAGEMENT_FORBIDDEN"})
}
