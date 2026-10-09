"""Exceptions and result codes; client requests return codes rather than raising."""

from __future__ import annotations

from typing import FrozenSet


class Code:
    """Result codes from the server and the SDK."""

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
    TRIAL_ALREADY_USED = "trial_already_used"
    TRIAL_UNAVAILABLE = "trial_unavailable"
    TRIAL_EMAIL_REQUIRED = "trial_email_required"
    TRIAL_EMAIL_INVALID = "trial_email_invalid"
    TRIAL_EMAIL_NOT_ACCEPTED = "trial_email_not_accepted"
    #: The trial key arrives by e-mail once the user confirms their address.
    TRIAL_CONFIRMATION_SENT = "trial_confirmation_sent"

    VALIDATION_ERROR = "validation_error"
    IP_BLOCKED = "ip_blocked"
    UNKNOWN_PRODUCT = "unknown_product"
    RATE_LIMITED = "rate_limited"
    INTERNAL_ERROR = "internal_error"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"

    #: Untrusted answer: unsigned 200, bad signature, mismatch, redirect or oversized.
    INVALID_RESPONSE = "invalid_response"
    #: No HTTP response, or a gateway 502/503/504 without a Velsigil error body.
    NETWORK_ERROR = "network_error"
    INVALID_CONFIGURATION = "invalid_configuration"
    NO_LEASE = "no_lease"
    LEASE_EXPIRED = "lease_expired"
    LEASE_INVALID = "lease_invalid"
    DOWNLOAD_FAILED = "download_failed"
    INTEGRITY_MISMATCH = "integrity_mismatch"
    IO_ERROR = "io_error"
    #: The server has no in-app trial endpoint; the seller must update the panel.
    PANEL_TOO_OLD = "panel_too_old"
    #: ``start_trial`` refused locally: this device already stores a license.
    ALREADY_LICENSED = "already_licensed"
    #: ``start_trial`` refused locally: the store could not be read.
    STORE_UNAVAILABLE = "store_unavailable"


#: Unsigned bodies are attacker-controllable, so any other code in one is ignored.
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
    """Invalid client configuration (URL, product id, public key, options)."""

    code = Code.INVALID_CONFIGURATION


class CryptoBackendError(VelsigilError):
    """Neither ``cryptography`` nor ``PyNaCl`` provides Ed25519 verification."""


class HardwareIdError(VelsigilError):
    """The machine identifier could not be read on this platform."""


class StoreError(VelsigilError):
    """A license store could not read or persist its state."""


class DownloadError(VelsigilError):
    """A release download failed or did not match its signed size/SHA-256."""

    def __init__(self, message: str, code: str = Code.DOWNLOAD_FAILED) -> None:
        super().__init__(message)
        self.code = code


class EnvelopeError(VelsigilError):
    """A signed response envelope was rejected; ``reason`` is one of the constants."""

    INVALID_SIGNATURE = "invalid_signature"
    NONCE_MISMATCH = "nonce_mismatch"
    PRODUCT_MISMATCH = "product_mismatch"
    TYPE_MISMATCH = "type_mismatch"
    HWID_MISMATCH = "hwid_mismatch"
    MALFORMED = "malformed"

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class LeaseError(VelsigilError):
    """An offline lease token was rejected; ``reason`` is one of the constants."""

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
