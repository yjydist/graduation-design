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
