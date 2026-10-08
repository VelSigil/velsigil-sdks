"""Ed25519 verification of Velsigil signed envelopes and offline leases.

Everything here follows SPEC section 10:

* The server's Ed25519 signature covers the **exact ASCII bytes** of the
  base64url ``data`` string (envelopes) or of the first token segment
  (leases). Signatures are always verified *before* anything is decoded or
  parsed, so no JSON canonicalisation is involved.
* Only the public key handed to the client is trusted. The envelope ``kid``
  is informational and never used to pick a key.
* The two public keys of the shared SDK test vectors are refused: their
  private keys are published in ``test-vectors.json``. The public helpers
  here have no server URL, so they refuse them unconditionally
  (:class:`ConfigurationError`, as for an invalid key); only
  :class:`~velsigil_client.VelsigilClient` allows them, for a loopback
  ``api_url``. The client and the SDK's own vector tests use the internal,
  unguarded equivalents (``_new_verifier``, ``_open_envelope``,
  ``_verify_lease``), which are not part of the public API.

No custom cryptography: verification is delegated to ``cryptography``
(preferred) or ``PyNaCl`` (fallback).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
from typing import Any, Callable, Dict, Mapping, Optional

from .errors import ConfigurationError, CryptoBackendError, EnvelopeError, LeaseError

PUBLIC_KEY_LENGTH = 32
SIGNATURE_LENGTH = 64

#: Upper bound for signed data we are willing to verify and decode.
MAX_SIGNED_DATA_LENGTH = 1024 * 1024

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*={0,2}\Z")
_B64STD_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}\Z")
_HEX64_RE = re.compile(r"^[0-9A-Fa-f]{64}\Z")

#: Message of every refusal of a published test key (the client constructor and the public helpers here).
_PUBLISHED_TEST_KEY_MESSAGE = (
    "This is the public test key from the Velsigil SDK test vectors, whose private key is published: "
    "anyone could forge license answers for it. Use your product's public key "
    "(panel: Products > your product > Integration)."
)


def _is_published_test_key(raw: Any) -> bool:
    """``True`` if ``raw`` (decoded key bytes) is one of the published test keys.

    The decoded bytes are compared, so no other spelling of a test key (no
    padding, whitespace, non-canonical base64) gets through.
    """
    # The key set is defined in client.py, the one module of this SDK that holds the published keys (the SDK
    # repository's CI allows them only there). Imported here at call time because client.py imports this module;
    # importing the package always loads client.py first, so this is a plain lookup.
    from .client import _PUBLISHED_TEST_PUBLIC_KEYS

    return isinstance(raw, (bytes, bytearray)) and bytes(raw) in _PUBLISHED_TEST_PUBLIC_KEYS


def _refuse_published_test_key(raw: Any) -> None:
    """Raise :class:`ConfigurationError` (as for an invalid key) for a published test key."""
    if _is_published_test_key(raw):
        raise ConfigurationError(_PUBLISHED_TEST_KEY_MESSAGE)


def _refuse_test_key_verifier(verifier: Any) -> None:
    """Refuse a verifier whose public key is a published test key.

    A public :class:`Ed25519Verifier` never holds one; this catches the
    client's internal verifier (loopback ``api_url``) or one built with
    ``_new_verifier`` being passed to the public helpers.
    """
    _refuse_published_test_key(getattr(verifier, "public_key_bytes", None))


# --------------------------------------------------------------------------- #
# Encoding helpers
# --------------------------------------------------------------------------- #


def b64url_encode(raw: bytes) -> str:
    """Encode bytes as base64url without padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Strictly decode base64url, tolerating missing ``=`` padding.

    Raises :class:`ValueError` for characters outside the base64url alphabet
    or an impossible length (the stdlib decoder would silently skip them).
    """
    if not isinstance(text, str) or not _B64URL_RE.match(text):
        raise ValueError("not base64url")
    stripped = text.rstrip("=")
    if len(stripped) % 4 == 1:
        raise ValueError("invalid base64url length")
    padded = stripped + "=" * (-len(stripped) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("not base64url") from exc


def decode_public_key(public_key_base64: str) -> bytes:
    """Decode the product public key (standard base64 of the raw 32-byte key).

    Missing padding and surrounding whitespace are tolerated; anything else
    raises :class:`ConfigurationError`. The two public keys of the SDK test
    vectors are refused with :class:`ConfigurationError` too: their private
    keys are published.
    """
    raw = _decode_public_key(public_key_base64)
    _refuse_published_test_key(raw)
    return raw


def _decode_public_key(public_key_base64: str) -> bytes:
    """Internal: :func:`decode_public_key` without the published-test-key refusal."""
    if not isinstance(public_key_base64, str):
        raise ConfigurationError("public_key must be a base64 string")
    text = public_key_base64.strip().rstrip("=")
    if not text or not _B64STD_RE.match(text) or len(text) % 4 == 1:
        raise ConfigurationError("public_key is not valid standard base64")
    try:
        raw = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ConfigurationError("public_key is not valid standard base64") from exc
    if len(raw) != PUBLIC_KEY_LENGTH:
        raise ConfigurationError("public_key must decode to exactly 32 bytes (raw Ed25519 key)")
    return raw


def key_id_for(public_key_base64: str) -> str:
    """Return the key id (first 16 hex chars of SHA-256 of the raw key).

    Raises :class:`ConfigurationError` for an invalid key and for the two
    public keys of the SDK test vectors (:func:`decode_public_key`).
    """
    return hashlib.sha256(decode_public_key(public_key_base64)).hexdigest()[:16]


def sha256_hex(text: str) -> str:
    """Lowercase hex SHA-256 of the UTF-8 encoding of ``text``."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def new_nonce() -> str:
    """Fresh request nonce: 32 CSPRNG bytes, base64url without padding (43 chars)."""
    return b64url_encode(secrets.token_bytes(32))


# --------------------------------------------------------------------------- #
# Ed25519 verifier with pluggable backend
# --------------------------------------------------------------------------- #


def _cryptography_verifier(raw: bytes) -> Callable[[bytes, bytes], bool]:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key = Ed25519PublicKey.from_public_bytes(raw)

    def verify(signature: bytes, message: bytes) -> bool:
        try:
            key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    return verify


def _nacl_verifier(raw: bytes) -> Callable[[bytes, bytes], bool]:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    key = VerifyKey(raw)

    def verify(signature: bytes, message: bytes) -> bool:
        try:
            key.verify(message, signature)
            return True
        except BadSignatureError:
            return False

    return verify


class Ed25519Verifier:
    """Verifies Ed25519 signatures against one trusted public key.

    ``backend`` may be ``"auto"`` (default: ``cryptography``, then ``PyNaCl``),
    ``"cryptography"`` or ``"nacl"``.

    Raises :class:`ConfigurationError` for an invalid key and for the two
    public keys of the SDK test vectors, whose private keys are published
    (there is no server URL here, so they are refused unconditionally).
    """

    __slots__ = ("_verify", "_raw", "backend")

    def __init__(self, public_key_base64: str, backend: str = "auto") -> None:
        self._setup(decode_public_key(public_key_base64), backend)

    def _setup(self, raw: bytes, backend: str) -> None:
        factories = []
        if backend in ("auto", "cryptography"):
            factories.append(("cryptography", _cryptography_verifier))
        if backend in ("auto", "nacl"):
            factories.append(("nacl", _nacl_verifier))
        if not factories:
            raise ConfigurationError("backend must be 'auto', 'cryptography' or 'nacl'")
        last_error: Optional[BaseException] = None
        for name, factory in factories:
            try:
                self._verify = factory(raw)
                self.backend = name
                self._raw = raw
                return
            except Exception as exc:  # ImportError, or UnsupportedAlgorithm on old OpenSSL builds
                last_error = exc
        raise CryptoBackendError(
            "No Ed25519 backend available: install 'cryptography>=50.0.0' or 'PyNaCl>=1.6.2'"
        ) from last_error

    @property
    def public_key_bytes(self) -> bytes:
        return self._raw

    @property
    def key_id(self) -> str:
        return hashlib.sha256(self._raw).hexdigest()[:16]

    def verify(self, signature: bytes, message: bytes) -> bool:
        """Return ``True`` only if ``signature`` is valid for ``message``."""
        if not isinstance(signature, bytes) or len(signature) != SIGNATURE_LENGTH:
            return False
        if not isinstance(message, bytes):
            return False
        return self._verify(signature, message)

    def __repr__(self) -> str:
        return "Ed25519Verifier(key_id=%r, backend=%r)" % (self.key_id, self.backend)


def _new_verifier(public_key_base64: str, backend: str = "auto") -> Ed25519Verifier:
    """Internal: an :class:`Ed25519Verifier` that does not refuse the published test keys.

    Only for :class:`~velsigil_client.VelsigilClient`, which refuses them
    itself unless ``api_url`` is a loopback host, and for the SDK's own
    vector tests. Not part of the public API.
    """
    verifier = Ed25519Verifier.__new__(Ed25519Verifier)
    verifier._setup(_decode_public_key(public_key_base64), backend)
    return verifier


def _verify_ascii(verifier: Ed25519Verifier, signed_text: Any, signature_text: Any) -> bool:
    """Verify a base64url signature over the ASCII bytes of ``signed_text``."""
    if not isinstance(signed_text, str) or not isinstance(signature_text, str):
        return False
    if not signed_text or len(signed_text) > MAX_SIGNED_DATA_LENGTH:
        return False
    try:
        message = signed_text.encode("ascii")
        signature = b64url_decode(signature_text)
    except (UnicodeEncodeError, ValueError):
        return False
    return verifier.verify(signature, message)


def _reject_constant(name: str) -> Any:
    raise ValueError("non-standard JSON constant %s" % name)


def _decode_json_object(segment: str) -> Dict[str, Any]:
    """base64url -> UTF-8 -> JSON object (raises ValueError on any problem)."""
    raw = b64url_decode(segment)
    value = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise ValueError("JSON payload is not an object")
    return value


def as_int(value: Any) -> Optional[int]:
    """Return ``value`` as int if it is a JSON integer (bools rejected), else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


# --------------------------------------------------------------------------- #
# Envelopes (SPEC 10.1)
# --------------------------------------------------------------------------- #


def open_envelope(
    verifier: Ed25519Verifier,
    envelope: Any,
    expected_nonce: str,
    expected_product_id: str,
    expected_type: str,
    expected_hwid: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a signed response envelope and return its payload.

    Order: signature over the ASCII ``data`` bytes -> decode/parse -> version
    -> nonce echo -> product id -> response type -> (optional) device binding.

    ``expected_type`` is required: the endpoint the request went to
    (``validate``, ``deactivate``, ``update_check``, ``download`` or
    ``trial``). The server also signs ``ok: true`` answers to
    ``update_check``, which needs no license, so without this check such an
    answer would pass as a validation. ``None`` or an empty value raises
    :class:`ValueError`.

    ``expected_hwid`` is the hwid a device-bound request (validate,
    deactivate, download, trial) was sent with. The signature binds the payload to
    the request only through nonce, product and type, so the signed lease and
    the optional ``activation.hwidHash`` must also belong to that hwid:
    otherwise the request was rewritten in transit (e.g. by a license-sharing
    proxy) and the answer describes another device.

    Raises :class:`EnvelopeError` with ``reason`` ``invalid_signature``,
    ``malformed``, ``nonce_mismatch``, ``product_mismatch``,
    ``type_mismatch`` or ``hwid_mismatch``.

    A ``verifier`` whose public key is one of the two public keys of the SDK
    test vectors (private keys published) raises :class:`ConfigurationError`,
    as :class:`Ed25519Verifier` does for such a key, before anything else is
    checked.
    """
    _refuse_test_key_verifier(verifier)
    return _open_envelope(verifier, envelope, expected_nonce, expected_product_id, expected_type, expected_hwid)


def _open_envelope(
    verifier: Ed25519Verifier,
    envelope: Any,
    expected_nonce: str,
    expected_product_id: str,
    expected_type: str,
    expected_hwid: Optional[str] = None,
) -> Dict[str, Any]:
    """Internal: :func:`open_envelope` without the published-test-key refusal."""
    # A programming error, not a verdict on the response: the type check must never be skipped.
    if not isinstance(expected_type, str) or not expected_type:
        raise ValueError("expected_type must be the request type (validate, deactivate, update_check, download or trial)")
    if not isinstance(envelope, Mapping):
        raise EnvelopeError(EnvelopeError.MALFORMED, "response is not a signed envelope")
    data = envelope.get("data")
    sig = envelope.get("sig")
    # 1. Signature first, over the exact bytes received. kid is ignored.
    if not _verify_ascii(verifier, data, sig):
        raise EnvelopeError(EnvelopeError.INVALID_SIGNATURE, "response signature is invalid")
    # 2. Only now decode and parse.
    try:
        payload = _decode_json_object(data)
    except (ValueError, UnicodeDecodeError):
        raise EnvelopeError(EnvelopeError.MALFORMED, "signed payload is not valid JSON") from None
    if as_int(payload.get("v")) != 1:
        raise EnvelopeError(EnvelopeError.MALFORMED, "unsupported payload version")
    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or not hmac.compare_digest(
        nonce.encode("utf-8"), str(expected_nonce).encode("utf-8")
    ):
        raise EnvelopeError(EnvelopeError.NONCE_MISMATCH, "response nonce does not match the request")
    if payload.get("productId") != expected_product_id:
        raise EnvelopeError(EnvelopeError.PRODUCT_MISMATCH, "response is for a different product")
    if payload.get("type") != expected_type:
        raise EnvelopeError(EnvelopeError.TYPE_MISMATCH, "response type does not match the request")
    if not isinstance(payload.get("ok"), bool) or not isinstance(payload.get("code"), str):
        raise EnvelopeError(EnvelopeError.MALFORMED, "signed payload lacks ok/code")
    if expected_hwid is not None:
        _check_device_binding(verifier, payload, expected_product_id, expected_hwid)
    return payload


def _check_device_binding(
    verifier: Ed25519Verifier, payload: Mapping[str, Any], product_id: str, hwid: str
) -> None:
    """Reject a verified payload whose lease or activation belongs to another device.

    Other lease defects (expired, ...) are not binding failures: such a lease
    is simply never stored by the client.
    """
    expected_hash = sha256_hex(hwid)
    activation = payload.get("activation")
    if isinstance(activation, Mapping) and activation.get("hwidHash") is not None:
        claimed = activation["hwidHash"]
        if not isinstance(claimed, str) or not _HEX64_RE.match(claimed):
            raise EnvelopeError(EnvelopeError.MALFORMED, "activation hwidHash is not a SHA-256 hex string")
        if not hmac.compare_digest(claimed.lower().encode("ascii"), expected_hash.encode("ascii")):
            raise EnvelopeError(EnvelopeError.HWID_MISMATCH, "response activation belongs to a different device")
    lease = payload.get("lease")
    if isinstance(lease, Mapping) and isinstance(lease.get("token"), str):
        server_time = as_int(payload.get("serverTime"))
        try:
            _verify_lease(verifier, lease["token"], product_id, hwid, server_time if server_time is not None else 0)
        except LeaseError as exc:
            if exc.reason == LeaseError.HWID_MISMATCH:
                raise EnvelopeError(
                    EnvelopeError.HWID_MISMATCH, "response lease was issued to a different device"
                ) from None
            if exc.reason == LeaseError.PRODUCT_MISMATCH:
                raise EnvelopeError(
                    EnvelopeError.PRODUCT_MISMATCH, "response lease is for a different product"
                ) from None


# --------------------------------------------------------------------------- #
# Offline leases (SPEC 10.4)
# --------------------------------------------------------------------------- #


def verify_lease(
    verifier: Ed25519Verifier,
    token: Any,
    product_id: str,
    hwid: str,
    now: float,
) -> Dict[str, Any]:
    """Verify an offline lease token and return its payload.

    ``token = base64url(JSON) "." base64url(Ed25519 signature over the ASCII
    bytes of the first part)``. Acceptance requires a valid signature,
    ``v == 1``, ``typ == "lease"``, matching ``productId`` and ``hwidHash``
    (SHA-256 of ``hwid``) and ``now < exp``.

    Raises :class:`LeaseError` with ``reason`` ``malformed``,
    ``invalid_signature``, ``product_mismatch``, ``hwid_mismatch`` or
    ``expired``.

    A ``verifier`` whose public key is one of the two public keys of the SDK
    test vectors (private keys published) raises :class:`ConfigurationError`,
    as :class:`Ed25519Verifier` does for such a key, before the token is
    looked at.
    """
    _refuse_test_key_verifier(verifier)
    return _verify_lease(verifier, token, product_id, hwid, now)


def _verify_lease(
    verifier: Ed25519Verifier,
    token: Any,
    product_id: str,
    hwid: str,
    now: float,
) -> Dict[str, Any]:
    """Internal: :func:`verify_lease` without the published-test-key refusal."""
    if not isinstance(token, str) or len(token) > MAX_SIGNED_DATA_LENGTH:
        raise LeaseError(LeaseError.MALFORMED, "lease token is not a string")
    parts = token.split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise LeaseError(LeaseError.MALFORMED, "lease token is malformed")
    body, signature = parts
    if not _verify_ascii(verifier, body, signature):
        raise LeaseError(LeaseError.INVALID_SIGNATURE, "lease signature is invalid")
    try:
        payload = _decode_json_object(body)
    except (ValueError, UnicodeDecodeError):
        raise LeaseError(LeaseError.MALFORMED, "lease payload is not valid JSON") from None
    if as_int(payload.get("v")) != 1 or payload.get("typ") != "lease":
        raise LeaseError(LeaseError.MALFORMED, "token is not a v1 lease")
    exp = as_int(payload.get("exp"))
    hwid_hash = payload.get("hwidHash")
    if exp is None or not isinstance(hwid_hash, str) or not isinstance(payload.get("productId"), str):
        raise LeaseError(LeaseError.MALFORMED, "lease payload lacks required fields")
    if payload.get("productId") != product_id:
        raise LeaseError(LeaseError.PRODUCT_MISMATCH, "lease is for a different product")
    expected_hash = sha256_hex(hwid)
    if not hmac.compare_digest(hwid_hash.lower().encode("utf-8"), expected_hash.encode("ascii")):
        raise LeaseError(LeaseError.HWID_MISMATCH, "lease was issued to a different device")
    if not now < exp:
        raise LeaseError(LeaseError.EXPIRED, "lease has expired")
    return payload


__all__ = [
    "Ed25519Verifier",
    "b64url_encode",
    "b64url_decode",
    "decode_public_key",
    "key_id_for",
    "sha256_hex",
    "new_nonce",
    "as_int",
    "open_envelope",
    "verify_lease",
    "MAX_SIGNED_DATA_LENGTH",
]
