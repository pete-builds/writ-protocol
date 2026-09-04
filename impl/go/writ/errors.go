package writ

import "fmt"

// Reason is a rejection code from spec section 11.
type Reason string

const (
	TooLarge            Reason = "too_large"
	Noncanonical        Reason = "noncanonical"
	UnsupportedVersion  Reason = "unsupported_version"
	WrongType           Reason = "wrong_type"
	UnsupportedCritical Reason = "unsupported_critical"
	Malformed           Reason = "malformed"
	BadKey              Reason = "bad_key"
	BadSignature        Reason = "bad_signature"
	ChainBroken         Reason = "chain_broken"
	NotNarrowed         Reason = "not_narrowed"
	UnknownBound        Reason = "unknown_bound"
	Expired             Reason = "expired"
	RootNotAccepted     Reason = "root_not_accepted"
	WrongExecutor       Reason = "wrong_executor"
	Revoked             Reason = "revoked"
	NoStanding          Reason = "no_standing"
	ForbiddenOp         Reason = "forbidden_op"
	MissingArg          Reason = "missing_arg"
	OutOfBounds         Reason = "out_of_bounds"
	CountExhausted      Reason = "count_exhausted"
	TallyMismatch       Reason = "tally_mismatch"
	SubUnmatched        Reason = "sub_unmatched"
	NotReversible       Reason = "not_reversible"
	Undeliverable       Reason = "undeliverable"
	UnknownOutcome      Reason = "unknown_outcome"
)

// Error carries a reason code and a human explanation.
type Error struct {
	Code Reason
	Msg  string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Msg }

func fail(code Reason, format string, a ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// CodeOf extracts the reason from an error, or "" for a non-protocol error.
func CodeOf(err error) Reason {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}
