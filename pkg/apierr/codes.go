// Copyright 2026 Agent Integrator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apierr

import "fmt"

type Code string

const (
	CodeOK Code = "AI-0000"

	CodeNoAgentMapping  Code = "AI-1101"
	CodeIssuerNotAllowed Code = "AI-1102"
	CodeTokenInvalid    Code = "AI-1103"
	CodeTokenRevoked    Code = "AI-1104"
	CodeScopeMissing    Code = "AI-1105"
	CodeOBORequired     Code = "AI-1106"
	CodeAgentSuspended  Code = "AI-1107"

	CodeCertChainInvalid Code = "AI-1001"
	CodeCertExpired      Code = "AI-1002"
	CodeCertThumbprint   Code = "AI-1003"
	CodeCertRevoked      Code = "AI-1004"

	CodePassportInvalid    Code = "AI-2001"
	CodePassportUnknownKid Code = "AI-2002"
	CodePassportExpired    Code = "AI-2003"
	CodePassportNotYet     Code = "AI-2004"
	CodePassportRevoked    Code = "AI-2005"
	CodePassportEpochStale Code = "AI-2006"

	CodeSigInvalid   Code = "AI-3001"
	CodeSigMalformed Code = "AI-3002"
	CodePayloadHash  Code = "AI-3003"

	CodeTimestampWindow Code = "AI-4001"
	CodeNonceReused     Code = "AI-4002"

	CodeAudienceMismatch Code = "AI-5001"
	CodeCapabilityDenied Code = "AI-5002"
	CodeResourceDenied   Code = "AI-5003"
	CodeSchemaInvalid    Code = "AI-5004"
	CodeConstraintFailed Code = "AI-5005"

	CodeBudgetExhausted  Code = "AI-6001"
	CodeCallLimit        Code = "AI-6002"
	CodeDistinctLimit    Code = "AI-6003"
	CodeLeaseUnavailable Code = "AI-6004"
	CodeEpochBumped      Code = "AI-6005"

	CodeMonotonicity    Code = "AI-7001"
	CodeDepthExceeded   Code = "AI-7002"
	CodeBrokenChain     Code = "AI-7003"
	CodeAncestorRevoked Code = "AI-7004"

	CodeApprovalRequired Code = "AI-8001"
	CodeApprovalDenied   Code = "AI-8002"
	CodeApprovalTimeout  Code = "AI-8003"

	CodeCacheUnavailable    Code = "AI-9001"
	CodeUpstreamUnreachable Code = "AI-9002"
	CodeMisconfiguration    Code = "AI-9003"
)

func HTTPStatus(c Code) int {
	switch {
	case c == CodeOK:
		return 200
	case c >= "AI-1101" && c <= "AI-1107",
		c >= "AI-1001" && c <= "AI-1004",
		c >= "AI-2001" && c <= "AI-2006",
		c >= "AI-3001" && c <= "AI-3003":
		return 401
	case c >= "AI-4001" && c <= "AI-4002":
		return 409
	case c >= "AI-5001" && c <= "AI-5005",
		c >= "AI-7001" && c <= "AI-7004":
		return 403
	case c >= "AI-6001" && c <= "AI-6005":
		return 429
	case c == CodeApprovalRequired:
		return 202
	case c >= "AI-8002" && c <= "AI-8003":
		return 403
	case c >= "AI-9001" && c <= "AI-9003":
		return 503
	default:
		return 500
	}
}

type Error struct {
	Code    Code
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

func New(code Code, msg string) *Error { return &Error{Code: code, Message: msg} }

func Newf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
