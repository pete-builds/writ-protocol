"""Writ protocol v0.1, independent Python implementation.

Written from the specification text alone (docs/spec/writ-v0.1.md).
Modules:

- canon:   strict JSON parsing and RFC 8785 canonical serialization
- keys:    did:key for Ed25519, signing and verification
- bounds:  the five bound types, narrows() and satisfies()
- objects: structural validation and signature checks (section 6.1)
- chain:   attenuation (section 4)
- verify:  single object, chain, call and tally tree verification
- issue:   builders that sign writs, child writs, calls and tallies
"""

from .errors import WritError, REASONS  # noqa: F401

__all__ = ["WritError", "REASONS"]
