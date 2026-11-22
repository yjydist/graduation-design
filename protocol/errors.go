package protocol

import (
	"fmt"

	"grad/protocol/registry"
)

// Error is the canonical grad-auth-v1 structured error shared with registry.
type Error = registry.Error

// Canonical error codes re-exported from grad/protocol/registry.
const (
	// Protocol and gateway error codes (58).
	ErrCodeInvalidSchema               = registry.ErrCodeInvalidSchema
	ErrCodeInvalidDisclosure           = registry.ErrCodeInvalidDisclosure
	ErrCodeSignatureInvalid            = registry.ErrCodeSignatureInvalid
	ErrCodeHolderMismatch              = registry.ErrCodeHolderMismatch
	ErrCodeDIDDocumentMismatch         = registry.ErrCodeDIDDocumentMismatch
	ErrCodeDIDKeyPurposeInvalid        = registry.ErrCodeDIDKeyPurposeInvalid
	ErrCodeDomainCertificationInvalid  = registry.ErrCodeDomainCertificationInvalid
	ErrCodeIssuerScopeInvalid          = registry.ErrCodeIssuerScopeInvalid
	ErrCodeCredentialStatusInvalid     = registry.ErrCodeCredentialStatusInvalid
	ErrCodeGrantChainInvalid           = registry.ErrCodeGrantChainInvalid
	ErrCodeBindingMismatch             = registry.ErrCodeBindingMismatch
	ErrCodeChallengeMismatch           = registry.ErrCodeChallengeMismatch
	ErrCodeChallengeUnknown            = registry.ErrCodeChallengeUnknown
	ErrCodeChallengeExpired            = registry.ErrCodeChallengeExpired
	ErrCodeChallengeReplay             = registry.ErrCodeChallengeReplay
	ErrCodeRegistrationProofInvalid    = registry.ErrCodeRegistrationProofInvalid
	ErrCodeMaterialNotSynced           = registry.ErrCodeMaterialNotSynced
	ErrCodeDeliveryConflict            = registry.ErrCodeDeliveryConflict
	ErrCodeMaterialInvalid             = registry.ErrCodeMaterialInvalid
	ErrCodeStateUnavailable            = registry.ErrCodeStateUnavailable
	ErrCodeStateStale                  = registry.ErrCodeStateStale
	ErrCodeStateChanged                = registry.ErrCodeStateChanged
	ErrCodePolicyDenied                = registry.ErrCodePolicyDenied
	ErrCodeSupplierPolicyDenied        = registry.ErrCodeSupplierPolicyDenied
	ErrCodeRootAuthorityInvalid        = registry.ErrCodeRootAuthorityInvalid
	ErrCodeIdempotencyConflict         = registry.ErrCodeIdempotencyConflict
	ErrCodeContextStale                = registry.ErrCodeContextStale
	ErrCodePriceUnavailable            = registry.ErrCodePriceUnavailable
	ErrCodeTaskScopeMismatch           = registry.ErrCodeTaskScopeMismatch
	ErrCodeTaskInactive                = registry.ErrCodeTaskInactive
	ErrCodeGrantExpired                = registry.ErrCodeGrantExpired
	ErrCodePayloadTooLarge             = registry.ErrCodePayloadTooLarge
	ErrCodeUnsupportedMediaType        = registry.ErrCodeUnsupportedMediaType
	ErrCodePurchasingAuthorityInvalid  = registry.ErrCodePurchasingAuthorityInvalid
	ErrCodeDelegationExpansion         = registry.ErrCodeDelegationExpansion
	ErrCodePathInvalid                 = registry.ErrCodePathInvalid
	ErrCodeAuthorizationModeMismatch   = registry.ErrCodeAuthorizationModeMismatch
	ErrCodeAncestorInactive            = registry.ErrCodeAncestorInactive
	ErrCodeAmountLimitExceeded         = registry.ErrCodeAmountLimitExceeded
	ErrCodeQuoteScopeMismatch          = registry.ErrCodeQuoteScopeMismatch
	ErrCodeQuoteExpired                = registry.ErrCodeQuoteExpired
	ErrCodeAmountMismatch              = registry.ErrCodeAmountMismatch
	ErrCodeLinkProofInvalid            = registry.ErrCodeLinkProofInvalid
	ErrCodeLinkApprovalForbidden       = registry.ErrCodeLinkApprovalForbidden
	ErrCodeLinkProposalMismatch        = registry.ErrCodeLinkProposalMismatch
	ErrCodeLinkStateConflict           = registry.ErrCodeLinkStateConflict
	ErrCodeKeyVersionStale             = registry.ErrCodeKeyVersionStale
	ErrCodeIdentityInactive            = registry.ErrCodeIdentityInactive
	ErrCodeIdentityStateConflict       = registry.ErrCodeIdentityStateConflict
	ErrCodeIdentityManagementForbidden = registry.ErrCodeIdentityManagementForbidden
	ErrCodeIdentityRecoveryForbidden   = registry.ErrCodeIdentityRecoveryForbidden
	ErrCodeRecoveryProofInvalid        = registry.ErrCodeRecoveryProofInvalid
	ErrCodeTrustManagementForbidden    = registry.ErrCodeTrustManagementForbidden
	ErrCodeDomainInactive              = registry.ErrCodeDomainInactive
	ErrCodeTaskStateConflict           = registry.ErrCodeTaskStateConflict
	ErrCodeGrantInactive               = registry.ErrCodeGrantInactive
	ErrCodeGrantStateConflict          = registry.ErrCodeGrantStateConflict
	ErrCodeAuditForbidden              = registry.ErrCodeAuditForbidden

	// Management operation outcomes.
	ErrCodeOperationUnknown    = registry.ErrCodeOperationUnknown
	ErrCodeEndorsementRejected = registry.ErrCodeEndorsementRejected
	ErrCodeCommitInvalid       = registry.ErrCodeCommitInvalid

	// Registry chaincode-specific error codes (6).
	ErrCodeInvalidStructure  = registry.ErrCodeInvalidStructure
	ErrCodeUnauthorized      = registry.ErrCodeUnauthorized
	ErrCodeMissingDependency = registry.ErrCodeMissingDependency
	ErrCodeInvalidState      = registry.ErrCodeInvalidState
	ErrCodeIDAlreadyUsed     = registry.ErrCodeIDAlreadyUsed
	ErrCodeAlreadyRevoked    = registry.ErrCodeAlreadyRevoked
)

// Canonical protocol identifiers, modes, resources, and actions re-exported from registry.
const (
	SchemaVersion             = registry.Schema
	DeploymentPurpose         = registry.DeploymentPurpose
	ModeResourcePreauthorized = registry.RP
	ModeBuyerMandate          = registry.BM

	ResourceQuotes    = registry.ResourceQuotes
	ResourceOrders    = registry.ResourceOrders
	ActionQuoteRead   = registry.ActionQuoteRead
	ActionOrderCreate = registry.ActionOrderCreate
)

// NewError creates a structured protocol error with the given canonical code and message.
func NewError(code, msg string) *Error {
	return registry.NewError(code, msg)
}

// WrapError creates a structured protocol error wrapping an underlying cause.
func WrapError(code, msg string, cause error) *Error {
	return registry.WrapError(code, msg, cause)
}

// HasCode reports whether err or any wrapped error in its chain carries code.
func HasCode(err error, code string) bool {
	return registry.HasCode(err, code)
}

// CodeOf extracts the canonical error code from err or any wrapped error in its chain.
func CodeOf(err error) string {
	return registry.CodeOf(err)
}

// IsCanonicalResource reports whether resource is one of the canonical grad-auth-v1 resource URIs.
func IsCanonicalResource(resource string) bool {
	return resource == ResourceQuotes || resource == ResourceOrders
}

// ValidateCanonicalResource enforces the strict action-to-canonical-resource-URI mapping,
// rejecting historical short aliases such as "quotes", "orders", or "urn:grad:resource:quotes".
func ValidateCanonicalResource(action, resource string) error {
	switch action {
	case ActionQuoteRead:
		if resource != ResourceQuotes {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("action %q requires canonical resource %q, got %q", action, ResourceQuotes, resource))
		}
		return nil
	case ActionOrderCreate:
		if resource != ResourceOrders {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("action %q requires canonical resource %q, got %q", action, ResourceOrders, resource))
		}
		return nil
	default:
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("unsupported canonical action %q", action))
	}
}
