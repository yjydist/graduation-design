package registry

import (
	"errors"
	"fmt"
	"strings"
)

// Canonical machine-readable error codes shared across protocol, chaincode, and platform services.
const (
	// Protocol and gateway error codes (58).
	ErrCodeInvalidSchema               = "INVALID_SCHEMA"
	ErrCodeInvalidDisclosure           = "INVALID_DISCLOSURE"
	ErrCodeSignatureInvalid            = "SIGNATURE_INVALID"
	ErrCodeHolderMismatch              = "HOLDER_MISMATCH"
	ErrCodeDIDDocumentMismatch         = "DID_DOCUMENT_MISMATCH"
	ErrCodeDIDKeyPurposeInvalid        = "DID_KEY_PURPOSE_INVALID"
	ErrCodeDomainCertificationInvalid  = "DOMAIN_CERTIFICATION_INVALID"
	ErrCodeIssuerScopeInvalid          = "ISSUER_SCOPE_INVALID"
	ErrCodeCredentialStatusInvalid     = "CREDENTIAL_STATUS_INVALID"
	ErrCodeGrantChainInvalid           = "GRANT_CHAIN_INVALID"
	ErrCodeBindingMismatch             = "BINDING_MISMATCH"
	ErrCodeChallengeMismatch           = "CHALLENGE_MISMATCH"
	ErrCodeChallengeUnknown            = "CHALLENGE_UNKNOWN"
	ErrCodeChallengeExpired            = "CHALLENGE_EXPIRED"
	ErrCodeChallengeReplay             = "CHALLENGE_REPLAY"
	ErrCodeRegistrationProofInvalid    = "REGISTRATION_PROOF_INVALID"
	ErrCodeMaterialNotSynced           = "MATERIAL_NOT_SYNCED"
	ErrCodeDeliveryConflict            = "DELIVERY_CONFLICT"
	ErrCodeMaterialInvalid             = "MATERIAL_INVALID"
	ErrCodeStateUnavailable            = "STATE_UNAVAILABLE"
	ErrCodeStateStale                  = "STATE_STALE"
	ErrCodeStateChanged                = "STATE_CHANGED"
	ErrCodePolicyDenied                = "POLICY_DENIED"
	ErrCodeSupplierPolicyDenied        = "SUPPLIER_POLICY_DENIED"
	ErrCodeRootAuthorityInvalid        = "ROOT_AUTHORITY_INVALID"
	ErrCodeIdempotencyConflict         = "IDEMPOTENCY_CONFLICT"
	ErrCodeContextStale                = "CONTEXT_STALE"
	ErrCodePriceUnavailable            = "PRICE_UNAVAILABLE"
	ErrCodeTaskScopeMismatch           = "TASK_SCOPE_MISMATCH"
	ErrCodeTaskInactive                = "TASK_INACTIVE"
	ErrCodeGrantExpired                = "GRANT_EXPIRED"
	ErrCodePayloadTooLarge             = "PAYLOAD_TOO_LARGE"
	ErrCodeUnsupportedMediaType        = "UNSUPPORTED_MEDIA_TYPE"
	ErrCodePurchasingAuthorityInvalid  = "PURCHASING_AUTHORITY_INVALID"
	ErrCodeDelegationExpansion         = "DELEGATION_EXPANSION"
	ErrCodePathInvalid                 = "PATH_INVALID"
	ErrCodeAuthorizationModeMismatch   = "AUTHORIZATION_MODE_MISMATCH"
	ErrCodeAncestorInactive            = "ANCESTOR_INACTIVE"
	ErrCodeAmountLimitExceeded         = "AMOUNT_LIMIT_EXCEEDED"
	ErrCodeQuoteScopeMismatch          = "QUOTE_SCOPE_MISMATCH"
	ErrCodeQuoteExpired                = "QUOTE_EXPIRED"
	ErrCodeAmountMismatch              = "AMOUNT_MISMATCH"
	ErrCodeLinkProofInvalid            = "LINK_PROOF_INVALID"
	ErrCodeLinkApprovalForbidden       = "LINK_APPROVAL_FORBIDDEN"
	ErrCodeLinkProposalMismatch        = "LINK_PROPOSAL_MISMATCH"
	ErrCodeLinkStateConflict           = "LINK_STATE_CONFLICT"
	ErrCodeKeyVersionStale             = "KEY_VERSION_STALE"
	ErrCodeIdentityInactive            = "IDENTITY_INACTIVE"
	ErrCodeIdentityStateConflict       = "IDENTITY_STATE_CONFLICT"
	ErrCodeIdentityManagementForbidden = "IDENTITY_MANAGEMENT_FORBIDDEN"
	ErrCodeIdentityRecoveryForbidden   = "IDENTITY_RECOVERY_FORBIDDEN"
	ErrCodeRecoveryProofInvalid        = "RECOVERY_PROOF_INVALID"
	ErrCodeTrustManagementForbidden    = "TRUST_MANAGEMENT_FORBIDDEN"
	ErrCodeDomainInactive              = "DOMAIN_INACTIVE"
	ErrCodeTaskStateConflict           = "TASK_STATE_CONFLICT"
	ErrCodeGrantInactive               = "GRANT_INACTIVE"
	ErrCodeGrantStateConflict          = "GRANT_STATE_CONFLICT"
	ErrCodeAuditForbidden              = "AUDIT_FORBIDDEN"

	// Registry chaincode-specific error codes (6).
	ErrCodeInvalidStructure  = "INVALID_STRUCTURE"
	ErrCodeUnauthorized      = "UNAUTHORIZED"
	ErrCodeMissingDependency = "MISSING_DEPENDENCY"
	ErrCodeInvalidState      = "INVALID_STATE"
	ErrCodeIDAlreadyUsed     = "ID_ALREADY_USED"
	ErrCodeAlreadyRevoked    = "ALREADY_REVOKED"
)

var knownErrorCodes = map[string]struct{}{
	ErrCodeInvalidSchema:               {},
	ErrCodeInvalidDisclosure:           {},
	ErrCodeSignatureInvalid:            {},
	ErrCodeHolderMismatch:              {},
	ErrCodeDIDDocumentMismatch:         {},
	ErrCodeDIDKeyPurposeInvalid:        {},
	ErrCodeDomainCertificationInvalid:  {},
	ErrCodeIssuerScopeInvalid:          {},
	ErrCodeCredentialStatusInvalid:     {},
	ErrCodeGrantChainInvalid:           {},
	ErrCodeBindingMismatch:             {},
	ErrCodeChallengeMismatch:           {},
	ErrCodeChallengeUnknown:            {},
	ErrCodeChallengeExpired:            {},
	ErrCodeChallengeReplay:             {},
	ErrCodeRegistrationProofInvalid:    {},
	ErrCodeMaterialNotSynced:           {},
	ErrCodeDeliveryConflict:            {},
	ErrCodeMaterialInvalid:             {},
	ErrCodeStateUnavailable:            {},
	ErrCodeStateStale:                  {},
	ErrCodeStateChanged:                {},
	ErrCodePolicyDenied:                {},
	ErrCodeSupplierPolicyDenied:        {},
	ErrCodeRootAuthorityInvalid:        {},
	ErrCodeIdempotencyConflict:         {},
	ErrCodeContextStale:                {},
	ErrCodePriceUnavailable:            {},
	ErrCodeTaskScopeMismatch:           {},
	ErrCodeTaskInactive:                {},
	ErrCodeGrantExpired:                {},
	ErrCodePayloadTooLarge:             {},
	ErrCodeUnsupportedMediaType:        {},
	ErrCodePurchasingAuthorityInvalid:  {},
	ErrCodeDelegationExpansion:         {},
	ErrCodePathInvalid:                 {},
	ErrCodeAuthorizationModeMismatch:   {},
	ErrCodeAncestorInactive:            {},
	ErrCodeAmountLimitExceeded:         {},
	ErrCodeQuoteScopeMismatch:          {},
	ErrCodeQuoteExpired:                {},
	ErrCodeAmountMismatch:              {},
	ErrCodeLinkProofInvalid:            {},
	ErrCodeLinkApprovalForbidden:       {},
	ErrCodeLinkProposalMismatch:        {},
	ErrCodeLinkStateConflict:           {},
	ErrCodeKeyVersionStale:             {},
	ErrCodeIdentityInactive:            {},
	ErrCodeIdentityStateConflict:       {},
	ErrCodeIdentityManagementForbidden: {},
	ErrCodeIdentityRecoveryForbidden:   {},
	ErrCodeRecoveryProofInvalid:        {},
	ErrCodeTrustManagementForbidden:    {},
	ErrCodeDomainInactive:              {},
	ErrCodeTaskStateConflict:           {},
	ErrCodeGrantInactive:               {},
	ErrCodeGrantStateConflict:          {},
	ErrCodeAuditForbidden:              {},
	ErrCodeInvalidStructure:            {},
	ErrCodeUnauthorized:                {},
	ErrCodeMissingDependency:           {},
	ErrCodeInvalidState:                {},
	ErrCodeIDAlreadyUsed:               {},
	ErrCodeAlreadyRevoked:              {},
}

// Error represents a deterministic grad-auth-v1 failure carrying a canonical machine-readable code.
type Error struct {
	Code    string
	Message string
	Cause   error
}

// Error returns the canonical error string. When Message and Cause are both empty, it emits Code directly.
func (e *Error) Error() string {
	switch {
	case e.Message != "" && e.Cause != nil:
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	case e.Message != "":
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	case e.Cause != nil:
		return fmt.Sprintf("%s: %v", e.Code, e.Cause)
	default:
		return e.Code
	}
}

// Unwrap exposes the wrapped underlying cause for errors.Is / errors.As.
func (e *Error) Unwrap() error {
	return e.Cause
}

// NewError creates a structured error with the given canonical code and message.
func NewError(code, msg string) *Error {
	return &Error{Code: code, Message: msg}
}

// WrapError creates a structured error wrapping an underlying cause.
func WrapError(code, msg string, cause error) *Error {
	return &Error{Code: code, Message: msg, Cause: cause}
}

// Reject returns an error whose Error() string is the exact canonical code.
func Reject(code string) error {
	return &Error{Code: code}
}

// IsKnownCode reports whether code is one of the canonical grad-auth-v1 error codes.
func IsKnownCode(code string) bool {
	_, ok := knownErrorCodes[code]
	return ok
}

// CodeOf extracts the canonical error code from err or any wrapped error in its chain.
func CodeOf(err error) string {
	if err == nil {
		return ""
	}
	var pe *Error
	if errors.As(err, &pe) && pe.Code != "" {
		return pe.Code
	}
	return plainCodeFromChain(err)
}

// HasCode reports whether err or any wrapped error in its chain carries the given canonical code.
func HasCode(err error, code string) bool {
	if err == nil || code == "" {
		return false
	}
	return hasCodeInChain(err, code)
}

func hasCodeInChain(err error, code string) bool {
	if err == nil {
		return false
	}
	if pe, ok := err.(*Error); ok && pe.Code == code {
		return true
	}
	if plainCode(err) == code {
		return true
	}
	if u, ok := err.(interface{ Unwrap() error }); ok {
		return hasCodeInChain(u.Unwrap(), code)
	}
	if u, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range u.Unwrap() {
			if hasCodeInChain(child, code) {
				return true
			}
		}
	}
	return false
}

func plainCodeFromChain(err error) string {
	if err == nil {
		return ""
	}
	if code := plainCode(err); code != "" {
		return code
	}
	if u, ok := err.(interface{ Unwrap() error }); ok {
		return plainCodeFromChain(u.Unwrap())
	}
	if u, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range u.Unwrap() {
			if code := plainCodeFromChain(child); code != "" {
				return code
			}
		}
	}
	return ""
}

func plainCode(err error) string {
	s := strings.TrimSpace(err.Error())
	if IsKnownCode(s) {
		return s
	}
	if prefix, _, ok := strings.Cut(s, ": "); ok && IsKnownCode(prefix) {
		return prefix
	}
	return ""
}
