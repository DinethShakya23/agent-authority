// Package apierr defines the stable AI-xxxx reason codes.
//
//	AI-11xx WSO2 identity   AI-1xxx certificate   AI-2xxx passport
//	AI-3xxx signature       AI-4xxx replay        AI-5xxx authority
//	AI-6xxx budget          AI-7xxx delegation    AI-8xxx approval
//	AI-9xxx internal (fail closed)
//
// Codes are public API: never renumber, only append.
package apierr

import "fmt"

// Code is a stable AI-xxxx error code. Append-only; never renumber.
type Code string

const (
	CodeOK Code = "AI-0000"

	// WSO2 identity AI-11xx
	CodeNoAgentMapping  Code = "AI-1101"
	CodeIssuerNotAllowed Code = "AI-1102"
	CodeTokenInvalid    Code = "AI-1103"
	CodeTokenRevoked    Code = "AI-1104"
	CodeScopeMissing    Code = "AI-1105"
	CodeOBORequired     Code = "AI-1106"
	CodeAgentSuspended  Code = "AI-1107"

	// Certificate AI-1xxx
	CodeCertChainInvalid Code = "AI-1001"
	CodeCertExpired      Code = "AI-1002"
	CodeCertThumbprint   Code = "AI-1003"
	CodeCertRevoked      Code = "AI-1004"

	// Passport AI-2xxx
	CodePassportInvalid    Code = "AI-2001"
	CodePassportUnknownKid Code = "AI-2002"
	CodePassportExpired    Code = "AI-2003"
	CodePassportNotYet     Code = "AI-2004"
	CodePassportRevoked    Code = "AI-2005"
	CodePassportEpochStale Code = "AI-2006"

	// Signature AI-3xxx
	CodeSigInvalid    Code = "AI-3001"
	CodeSigMalformed  Code = "AI-3002"
	CodePayloadHash   Code = "AI-3003"

	// Replay AI-4xxx
	CodeTimestampWindow Code = "AI-4001"
	CodeNonceReused     Code = "AI-4002"

	// Authority AI-5xxx
	CodeAudienceMismatch Code = "AI-5001"
	CodeCapabilityDenied Code = "AI-5002"
	CodeResourceDenied   Code = "AI-5003"
	CodeSchemaInvalid    Code = "AI-5004"
	CodeConstraintFailed Code = "AI-5005"

	// Budget AI-6xxx
	CodeBudgetExhausted    Code = "AI-6001"
	CodeCallLimit          Code = "AI-6002"
	CodeDistinctLimit      Code = "AI-6003"
	CodeLeaseUnavailable   Code = "AI-6004"
	CodeEpochBumped        Code = "AI-6005"

	// Delegation AI-7xxx
	CodeMonotonicity    Code = "AI-7001"
	CodeDepthExceeded   Code = "AI-7002"
	CodeBrokenChain     Code = "AI-7003"
	CodeAncestorRevoked Code = "AI-7004"

	// Approval AI-8xxx
	CodeApprovalRequired Code = "AI-8001"
	CodeApprovalDenied   Code = "AI-8002"
	CodeApprovalTimeout  Code = "AI-8003"

	// Internal AI-9xxx — always fail closed
	CodeCacheUnavailable    Code = "AI-9001"
	CodeUpstreamUnreachable Code = "AI-9002"
	CodeMisconfiguration    Code = "AI-9003"
)

// HTTPStatus maps a Code to the correct HTTP status per AIP-1 §15.
func HTTPStatus(c Code) int {
	switch {
	case c == CodeOK:
		return 200
	case c >= "AI-1101" && c <= "AI-1107", // WSO2 identity
		c >= "AI-1001" && c <= "AI-1004", // certificate
		c >= "AI-2001" && c <= "AI-2006", // passport
		c >= "AI-3001" && c <= "AI-3003": // signature
		return 401
	case c >= "AI-4001" && c <= "AI-4002": // replay
		return 409
	case c >= "AI-5001" && c <= "AI-5005", // authority
		c >= "AI-7001" && c <= "AI-7004": // delegation
		return 403
	case c >= "AI-6001" && c <= "AI-6005": // budget
		return 429
	case c == CodeApprovalRequired:
		return 202
	case c >= "AI-8002" && c <= "AI-8003": // approval denied/timeout
		return 403
	case c >= "AI-9001" && c <= "AI-9003": // internal
		return 503
	default:
		return 500
	}
}

// Error wraps a Code with a human-readable message.
type Error struct {
	Code    Code
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

// New creates an Error.
func New(code Code, msg string) *Error { return &Error{Code: code, Message: msg} }

// Newf creates an Error with a formatted message.
func Newf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
