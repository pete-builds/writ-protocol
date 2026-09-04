"""did:key identifiers for Ed25519 (section 1.3) and signatures (section 1.4).

A principal is ``did:key:z`` + base58btc(0xed 0x01 + 32 byte public key).
Anything else is rejected with reason ``bad_key``. No resolution, no
registry: the identifier is the key.
"""

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from .errors import WritError

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}
_MULTICODEC_ED25519 = b"\xed\x01"
DID_PREFIX = "did:key:z"


# ---------------------------------------------------------------- base58

def b58encode(raw):
    n = int.from_bytes(raw, "big")
    out = []
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_B58[r])
    pad = 0
    for b in raw:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(out))


def b58decode(text):
    n = 0
    for ch in text:
        try:
            n = n * 58 + _B58_INDEX[ch]
        except KeyError:
            raise ValueError(f"character {ch!r} is not base58btc") from None
    pad = 0
    for ch in text:
        if ch == "1":
            pad += 1
        else:
            break
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body


# --------------------------------------------------------------- base64url

def b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


_B64U_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def b64u_decode(text):
    """Decode base64url without padding (section 1.1 rule 5).

    Rejects padding, characters outside the alphabet, and a string that does
    not round-trip (non-zero trailing bits), raising ValueError.
    """
    if not isinstance(text, str) or not text:
        raise ValueError("empty or non-string base64url value")
    if any(ch not in _B64U_ALPHABET for ch in text):
        raise ValueError("base64url value has padding or a bad character")
    if len(text) % 4 == 1:
        raise ValueError("base64url value has an impossible length")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u_encode(raw) != text:
        raise ValueError("base64url value is not canonical")
    return raw


def is_b64u(text, nbytes=None, min_bytes=None):
    try:
        raw = b64u_decode(text)
    except ValueError:
        return False
    if nbytes is not None and len(raw) != nbytes:
        return False
    if min_bytes is not None and len(raw) < min_bytes:
        return False
    return True


def sha256_b64u(data):
    """The spec's Hash: base64url without padding of SHA-256, 43 characters."""
    return b64u_encode(hashlib.sha256(data).digest())


# --------------------------------------------------------------- did:key

def encode_did(public_bytes):
    if len(public_bytes) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return DID_PREFIX + b58encode(_MULTICODEC_ED25519 + public_bytes)


def decode_did(did):
    """Return the 32 raw public key bytes of an Ed25519 did:key.

    Raises WritError('bad_key') for any other identifier, including other
    DID methods, other multicodec key types, and malformed base58.
    """
    if not isinstance(did, str):
        raise WritError("bad_key", "identifier is not a string")
    if not did.startswith(DID_PREFIX):
        raise WritError("bad_key", f"identifier is not a did:key with base58btc: {did!r}")
    try:
        raw = b58decode(did[len(DID_PREFIX):])
    except ValueError as e:
        raise WritError("bad_key", str(e)) from None
    if len(raw) != 34 or raw[:2] != _MULTICODEC_ED25519:
        raise WritError("bad_key", "did:key is not an Ed25519 public key")
    pk = raw[2:]
    if encode_did(pk) != did:
        raise WritError("bad_key", "did:key is not canonical")
    return pk


def is_did(did):
    try:
        decode_did(did)
        return True
    except WritError:
        return False


# ------------------------------------------------------------- key pairs

class Key:
    """An Ed25519 key pair with its did:key identifier."""

    def __init__(self, private):
        self._private = private
        self.public_bytes = private.public_key().public_bytes_raw()
        self.did = encode_did(self.public_bytes)

    @classmethod
    def from_seed(cls, seed):
        if isinstance(seed, str):
            seed = bytes.fromhex(seed)
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        return cls(ed25519.Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def generate(cls):
        return cls(ed25519.Ed25519PrivateKey.generate())

    @property
    def seed(self):
        return self._private.private_bytes_raw()

    def sign(self, message):
        """Return the base64url signature (86 characters) over message bytes."""
        return b64u_encode(self._private.sign(message))

    def __repr__(self):
        return f"Key({self.did})"


def verify(did, message, signature):
    """Verify an Ed25519 signature (base64url text) by the key in a did:key.

    Raises WritError('bad_key') for a bad identifier and
    WritError('bad_signature') when the signature does not verify.
    """
    pk = decode_did(did)
    try:
        raw = b64u_decode(signature)
    except ValueError as e:
        raise WritError("bad_signature", str(e)) from None
    if len(raw) != 64:
        raise WritError("bad_signature", "signature is not 64 bytes")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(raw, message)
    except InvalidSignature:
        raise WritError("bad_signature", f"signature does not verify under {did}") from None
    except ValueError as e:
        raise WritError("bad_key", str(e)) from None
