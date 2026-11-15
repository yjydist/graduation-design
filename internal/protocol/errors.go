package protocol

import "fmt"

// Error codes defined by grad-auth-v1 specification.
const (
	ErrCodeInvalidSchema              = "INVALID_SCHEMA"
	ErrCodeInvalidDisclosure          = "INVALID_DISCLOSURE"
	ErrCodeSignatureInvalid           = "SIGNATURE_INVALID"
	ErrCodeHolderMismatch             = "HOLDER_MISMATCH"
	ErrCodeDIDDocumentMismatch        = "DID_DOCUMENT_MISMATCH"
	ErrCodeDIDKeyPurposeInvalid       = "DID_KEY_PURPOSE_INVALID"
	ErrCodeDomainCertificationInvalid = "DOMAIN_CERTIFICATION_INVALID"
	ErrCodeIssuerScopeInvalid         = "ISSUER_SCOPE_INVALID"
	ErrCodeCredentialStatusInvalid    = "CREDENTIAL_STATUS_INVALID"
	ErrCodeGrantChainInvalid          = "GRANT_CHAIN_INVALID"
	ErrCodeBindingMismatch            = "BINDING_MISMATCH"
	ErrCodeChallengeMismatch          = "CHALLENGE_MISMATCH"
	ErrCodeChallengeUnknown           = "CHALLENGE_UNKNOWN"
	ErrCodeChallengeExpired           = "CHALLENGE_EXPIRED"
	ErrCodeChallengeReplay            = "CHALLENGE_REPLAY"
	ErrCodeRegistrationProofInvalid   = "REGISTRATION_PROOF_INVALID"
	ErrCodeMaterialNotSynced          = "MATERIAL_NOT_SYNCED"
	ErrCodeDeliveryConflict           = "DELIVERY_CONFLICT"
	ErrCodeMaterialInvalid            = "MATERIAL_INVALID"
	ErrCodeStateUnavailable           = "STATE_UNAVAILABLE"
	ErrCodeStateStale                 = "STATE_STALE"
	ErrCodeStateChanged               = "STATE_CHANGED"
	ErrCodePolicyDenied               = "POLICY_DENIED"
	ErrCodeSupplierPolicyDenied       = "SUPPLIER_POLICY_DENIED"
	ErrCodeRootAuthorityInvalid       = "ROOT_AUTHORITY_INVALID"
	ErrCodeIdempotencyConflict        = "IDEMPOTENCY_CONFLICT"
	ErrCodeContextStale               = "CONTEXT_STALE"
	ErrCodePriceUnavailable           = "PRICE_UNAVAILABLE"
	ErrCodeTaskScopeMismatch          = "TASK_SCOPE_MISMATCH"
	ErrCodeTaskInactive               = "TASK_INACTIVE"
	ErrCodeGrantExpired               = "GRANT_EXPIRED"
	ErrCodePayloadTooLarge            = "PAYLOAD_TOO_LARGE"
	ErrCodeUnsupportedMediaType       = "UNSUPPORTED_MEDIA_TYPE"
	ErrCodePurchasingAuthorityInvalid = "PURCHASING_AUTHORITY_INVALID"
	ErrCodeDelegationExpansion        = "DELEGATION_EXPANSION"
	ErrCodePathInvalid                = "PATH_INVALID"
	ErrCodeAuthorizationModeMismatch  = "AUTHORIZATION_MODE_MISMATCH"
	ErrCodeAncestorInactive           = "ANCESTOR_INACTIVE"
	ErrCodeAmountLimitExceeded        = "AMOUNT_LIMIT_EXCEEDED"
	ErrCodeQuoteScopeMismatch         = "QUOTE_SCOPE_MISMATCH"
	ErrCodeQuoteExpired               = "QUOTE_EXPIRED"
	ErrCodeAmountMismatch             = "AMOUNT_MISMATCH"
	ErrCodeLinkProofInvalid           = "LINK_PROOF_INVALID"
	ErrCodeLinkApprovalForbidden      = "LINK_APPROVAL_FORBIDDEN"
	ErrCodeLinkProposalMismatch       = "LINK_PROPOSAL_MISMATCH"
	ErrCodeLinkStateConflict          = "LINK_STATE_CONFLICT"
)

// Error represents a deterministic grad-auth-v1 protocol failure with a machine-readable code.
type Error struct {
	Code    string
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error {
	return e.Cause
}

// NewError creates a protocol error with the given error code and message.
func NewError(code, msg string) error {
	return &Error{Code: code, Message: msg}
}

// WrapError creates a protocol error wrapping an underlying cause.
func WrapError(code, msg string, cause error) error {
	return &Error{Code: code, Message: msg, Cause: cause}
}

// HasCode checks whether err (or any wrapped error in its chain) carries the specified protocol error code.
func HasCode(err error, code string) bool {
	for err != nil {
		if pe, ok := err.(*Error); ok && pe.Code == code {
			return true
		}
		type unwrapper interface {
			Unwrap() error
		}
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
