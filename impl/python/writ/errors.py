"""Rejection type shared by every module.

A verifier stops at the first failure and reports one reason code from
section 11 of the specification. WritError carries that code in ``reason``
and a human readable ``message`` explaining which check tripped.
"""


class WritError(Exception):
    """A rejection with a section 11 reason code."""

    def __init__(self, reason, message=""):
        super().__init__(f"{reason}: {message}" if message else reason)
        self.reason = reason
        self.message = message


REASONS = (
    "too_large",
    "noncanonical",
    "unsupported_version",
    "wrong_type",
    "unsupported_critical",
    "malformed",
    "bad_key",
    "bad_signature",
    "chain_broken",
    "not_narrowed",
    "unknown_bound",
    "expired",
    "root_not_accepted",
    "wrong_executor",
    "revoked",
    "no_standing",
    "forbidden_op",
    "missing_arg",
    "out_of_bounds",
    "count_exhausted",
    "tally_mismatch",
    "sub_unmatched",
    "not_reversible",
    "undeliverable",
    "unknown_outcome",
)
