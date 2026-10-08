"""Exceptions and result codes used by the Velsigil client.

Request methods on :class:`~velsigil_client.VelsigilClient` never raise for
license or transport failures; they return a result whose ``code`` is one of
the values in :class:`Code`. Exceptions are reserved for programmer and
environment errors (invalid constructor arguments, no Ed25519 backend, no
hardware id) and for the low-level verification helpers in
:mod:`velsigil_client.crypto`, which report *why* a signed object was rejected.
"""

from __future__ import annotations

from typing import FrozenSet


class Code:
    """Result codes (SPEC section 10.3 plus SDK-side codes)."""

    # --- signed server codes -------------------------------------------------
    OK = "ok"
    INVALID_KEY = "invalid_key"
    LICENSE_EXPIRED = "license_expired"
    LICENSE_SUSPENDED = "license_suspended"
    LICENSE_REVOKED = "license_revoked"
    LICENSE_BANNED = "license_banned"
    DEVICE_LIMIT_REACHED = "device_limit_reached"
    DEVICE_REVOKED = "device_revoked"
    DEVICE_VERIFICATION_FAILED = "device_verification_failed"
    DEVICE_NOT_FOUND = "device_not_found"
    DEVICE_NOT_ACTIVATED = "device_not_activated"
    ACTIVATION_RATE_LIMITED = "activation_rate_limited"
    ACTIVATION_COOLDOWN = "activation_cooldown"
    ACTIVATIONS_DISABLED = "activations_disabled"
    DOWNLOADS_DISABLED = "downloads_disabled"
    BLACKLISTED = "blacklisted"
    OUTDATED_VERSION = "outdated_version"
    PRODUCT_PAUSED = "product_paused"
    PRODUCT_DISABLED = "product_disabled"
    CLOCK_SKEW = "clock_skew"
    REPLAY_DETECTED = "replay_detected"
    NO_RELEASE = "no_release"
    RELEASE_NOT_FOUND = "release_not_found"
    #: Free trials (SPEC 9.7): this device already used a free trial of the
    #: product. A signed failure that keeps the stored lease.
    TRIAL_ALREADY_USED = "trial_already_used"
    #: In-app free trials (``start_trial``, SPEC 9.7): signed failures, none
    #: lease-revoking. ``TRIAL_CONFIRMATION_SENT`` means the offer confirms an
    #: e-mail address first: the key arrives by e-mail.
    TRIAL_UNAVAILABLE = "trial_unavailable"
    TRIAL_EMAIL_REQUIRED = "trial_email_required"
    TRIAL_EMAIL_INVALID = "trial_email_invalid"
    TRIAL_EMAIL_NOT_ACCEPTED = "trial_email_not_accepted"
    TRIAL_CONFIRMATION_SENT = "trial_confirmation_sent"

    # --- unsigned HTTP error codes (can never produce ok=True) ----------------
    VALIDATION_ERROR = "validation_error"
    IP_BLOCKED = "ip_blocked"
    UNKNOWN_PRODUCT = "unknown_product"
    RATE_LIMITED = "rate_limited"
    INTERNAL_ERROR = "internal_error"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"

    # --- SDK-side codes (SPEC 14; identical names in every Velsigil SDK) -----
    #: Unsigned 200, bad signature, nonce/productId/type mismatch, a signed lease or activation of
    #: another device, malformed or oversized response, redirect.
    INVALID_RESPONSE = "invalid_response"
    #: No HTTP response (DNS, connect, TLS, timeout) or a 502/503/504 without a Velsigil error body.
    NETWORK_ERROR = "network_error"
    #: :class:`ConfigurationError` code (constructor arguments rejected).
    INVALID_CONFIGURATION = "invalid_configuration"
    NO_LEASE = "no_lease"
    LEASE_EXPIRED = "lease_expired"
    LEASE_INVALID = "lease_invalid"
    #: :class:`DownloadError` codes (``download_to_file``).
    DOWNLOAD_FAILED = "download_failed"
    INTEGRITY_MISMATCH = "integrity_mismatch"
    IO_ERROR = "io_error"
    #: ``start_trial`` reached a Velsigil server without the in-app trial
    #: endpoint (HTTP 404 with the error code ``not_found``): update the panel.
    PANEL_TOO_OLD = "panel_too_old"
    #: ``start_trial`` refused locally: a device secret or an offline lease is
    #: already stored for the product (this device holds a license; a trial
    #: must not replace it). Nothing is sent and the stored state is untouched.
    ALREADY_LICENSED = "already_licensed"
    #: ``start_trial`` refused locally: the store could not be read, so it
    #: cannot tell whether this device already holds a license (a failed
    #: read is never "nothing stored"). Nothing is sent; try again later.
    STORE_UNAVAILABLE = "store_unavailable"
    # ``VALIDATION_ERROR`` (above) is also returned for local argument checks.


#: Error codes the server may return in an *unsigned* error body. Any other
#: code found in an unsigned body is ignored (the body is attacker-controllable).
UNSIGNED_ERROR_CODES: FrozenSet[str] = frozenset(
    {
        Code.VALIDATION_ERROR,
        Code.IP_BLOCKED,
        Code.UNKNOWN_PRODUCT,
        Code.RATE_LIMITED,
        Code.INTERNAL_ERROR,
        Code.PAYLOAD_TOO_LARGE,
        Code.UNSUPPORTED_MEDIA_TYPE,
    }
)


class VelsigilError(Exception):
    """Base class for every exception raised by this package."""


class ConfigurationError(VelsigilError, ValueError):
    """Invalid client configuration (URL, product id, public key, options).

    ``code`` is always ``"invalid_configuration"`` (the cross-SDK code).
    """

    code = Code.INVALID_CONFIGURATION


class CryptoBackendError(VelsigilError):
    """Neither ``cryptography`` nor ``PyNaCl`` provides Ed25519 verification."""


class HardwareIdError(VelsigilError):
    """The machine identifier could not be read on this platform."""


class StoreError(VelsigilError):
    """A license store could not read or persist its state."""


class DownloadError(VelsigilError):
    """A release download failed or did not match its signed size/SHA-256.

    ``code`` is one of the cross-SDK codes ``download_failed`` (non-200
    status, e.g. an expired link, or a URL rejected by the HTTPS policy),
    ``integrity_mismatch`` (size or SHA-256 differs from the signed values),
    ``io_error`` (the destination could not be written), ``network_error``
    (transport failure) or ``validation_error`` (bad arguments).
    """

    def __init__(self, message: str, code: str = Code.DOWNLOAD_FAILED) -> None:
        super().__init__(message)
        self.code = code


class EnvelopeError(VelsigilError):
    """A signed response envelope was rejected.

    ``reason`` is one of the ``EnvelopeError.*`` constants.
    """

    INVALID_SIGNATURE = "invalid_signature"
    NONCE_MISMATCH = "nonce_mismatch"
    PRODUCT_MISMATCH = "product_mismatch"
    TYPE_MISMATCH = "type_mismatch"
    #: The signed lease or ``activation.hwidHash`` belongs to another device
    #: than the one the request was sent for.
    HWID_MISMATCH = "hwid_mismatch"
    MALFORMED = "malformed"

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class LeaseError(VelsigilError):
    """An offline lease token was rejected.

    ``reason`` is one of the ``LeaseError.*`` constants.
    """

    INVALID_SIGNATURE = "invalid_signature"
    EXPIRED = "expired"
    PRODUCT_MISMATCH = "product_mismatch"
    HWID_MISMATCH = "hwid_mismatch"
    MALFORMED = "malformed"

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


__all__ = [
    "Code",
    "UNSIGNED_ERROR_CODES",
    "VelsigilError",
    "ConfigurationError",
    "CryptoBackendError",
    "HardwareIdError",
    "StoreError",
    "DownloadError",
    "EnvelopeError",
    "LeaseError",
]
