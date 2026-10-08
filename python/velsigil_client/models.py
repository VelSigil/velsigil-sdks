"""Immutable result objects returned by :class:`~velsigil_client.VelsigilClient`.

All timestamps are unix seconds (UTC), exactly as signed by the server.
The ``from_payload`` constructors are strict: a signed payload with
unexpected field types raises :class:`ValueError`, which the client turns
into an ``invalid_response`` result (fail closed).
"""

from __future__ import annotations

import datetime as _dt
import math
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Tuple

from .crypto import as_int


# --------------------------------------------------------------------------- #
# Strict field readers
# --------------------------------------------------------------------------- #


def _obj(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("%s must be an object" % name)
    return value


def _str(obj: Mapping[str, Any], key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str):
        raise ValueError("%s must be a string" % key)
    return value


def _opt_str(obj: Mapping[str, Any], key: str) -> Optional[str]:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("%s must be a string or null" % key)
    return value


def _int(obj: Mapping[str, Any], key: str) -> int:
    value = as_int(obj.get(key))
    if value is None:
        raise ValueError("%s must be an integer" % key)
    return value


def _opt_int(obj: Mapping[str, Any], key: str) -> Optional[int]:
    if obj.get(key) is None:
        return None
    return _int(obj, key)


def _bool(obj: Mapping[str, Any], key: str) -> bool:
    value = obj.get(key)
    if not isinstance(value, bool):
        raise ValueError("%s must be a boolean" % key)
    return value


def _opt_flag(obj: Mapping[str, Any], key: str) -> bool:
    """An optional boolean field: absent or null -> ``False``; any other non-boolean is malformed."""
    value = obj.get(key)
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ValueError("%s must be a boolean" % key)
    return value


#: URL parameter (and Paddle custom-data key / FastSpring tag) that carries a trial conversion reference (SPEC 9.7).
TRIAL_REF_PARAM = "velsigil_trial"
_STRIPE_PAYMENT_LINK_HOST = "buy.stripe.com"
_STRIPE_REFERENCE_PARAM = "client_reference_id"
_TRIAL_REF_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")


def _is_trial_ref(value: Any) -> bool:
    """1-200 characters of ``[A-Za-z0-9_-]`` (safe in a URL without encoding)."""
    return isinstance(value, str) and 1 <= len(value) <= 200 and all(c in _TRIAL_REF_CHARS for c in value)


def _opt_trial_ref(obj: Mapping[str, Any]) -> Optional[str]:
    """The optional signed ``trialRef`` (SPEC 9.7): absent/null -> ``None``; anything else malformed raises."""
    value = obj.get("trialRef")
    if value is None:
        return None
    if not _is_trial_ref(value):
        raise ValueError("trialRef must be 1-200 characters of [A-Za-z0-9_-]")
    return value


def with_trial_ref(url: str, trial_ref: Optional[str]) -> str:
    """``url`` with a trial conversion reference appended (SPEC 9.7).

    Adds ``velsigil_trial=<ref>`` to the query (before any ``#fragment``; the
    rest of the URL is kept as it is), or ``client_reference_id=<ref>`` for a
    Stripe Payment Link (``https://buy.stripe.com/...``). Returns ``url``
    unchanged when the reference is missing or malformed, or ``url`` is not an
    absolute http(s) URL.
    """
    if not _is_trial_ref(trial_ref) or not isinstance(url, str):
        return url
    lower = url.lower()
    if lower.startswith("https://"):
        rest = url[8:]
    elif lower.startswith("http://"):
        rest = url[7:]
    else:
        return url
    host_end = len(rest)
    for sep in "/?#":
        i = rest.find(sep)
        if i != -1 and i < host_end:
            host_end = i
    authority = rest[:host_end]
    if authority == "":
        return url
    host = authority.rsplit("@", 1)[-1].split(":", 1)[0].lower()
    param = _STRIPE_REFERENCE_PARAM if host == _STRIPE_PAYMENT_LINK_HOST else TRIAL_REF_PARAM
    hash_at = url.find("#")
    base = url if hash_at == -1 else url[:hash_at]
    fragment = "" if hash_at == -1 else url[hash_at:]
    if "?" not in base:
        separator = "?"
    elif base.endswith("?") or base.endswith("&"):
        separator = ""
    else:
        separator = "&"
    return "%s%s%s=%s%s" % (base, separator, param, trial_ref, fragment)


def _str_tuple(obj: Mapping[str, Any], key: str) -> Tuple[str, ...]:
    value = obj.get(key)
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("%s must be a list of strings" % key)
    return tuple(value)


def _to_datetime(timestamp: Optional[int]) -> Optional[_dt.datetime]:
    if timestamp is None:
        return None
    return _dt.datetime.fromtimestamp(timestamp, tz=_dt.timezone.utc)


def _now(now: Optional[float]) -> float:
    return time.time() if now is None else now


# --------------------------------------------------------------------------- #
# Payload objects
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class LicenseInfo:
    """License details from a signed response (or from an offline lease).

    Fields the offline lease does not carry (``max_devices``, ``devices_used``,
    ``created_at``) are ``None`` for offline results.

    ``features`` is informational on a failed result (a denial such as
    ``license_revoked``): gate paid features with
    :meth:`VelsigilResult.has_feature`, which is ``False`` unless the result
    is ``ok``. :meth:`has_feature` here is gated the same way.
    """

    id: str
    plan: str
    status: str
    features: Tuple[str, ...]
    expires_at: Optional[int]
    max_devices: Optional[int] = None
    devices_used: Optional[int] = None
    created_at: Optional[int] = None
    #: ``True`` only when this came from an ``ok`` signed response or a valid
    #: offline lease (set by the SDK; a hand-made instance grants nothing).
    granted: bool = field(default=False, repr=False, compare=False)
    #: ``True`` for a free-trial license (SPEC 9.7): the optional signed
    #: ``trial`` field of the response or of the offline lease. Absent (paid
    #: licenses, older servers) means ``False``.
    is_trial: bool = False
    #: The trial's conversion reference (SPEC 9.7, servers since 2026-10-06):
    #: set for a free trial a purchase can still convert, ``None`` otherwise
    #: (paid licenses, offline leases, older servers). Opaque.
    trial_ref: Optional[str] = None

    @classmethod
    def from_payload(cls, value: Any, granted: bool = False) -> "LicenseInfo":
        obj = _obj(value, "license")
        return cls(
            id=_str(obj, "id"),
            plan=_str(obj, "plan"),
            status=_str(obj, "status"),
            features=_str_tuple(obj, "features"),
            expires_at=_opt_int(obj, "expiresAt"),
            max_devices=_int(obj, "maxDevices"),
            devices_used=_int(obj, "devicesUsed"),
            created_at=_int(obj, "createdAt"),
            granted=granted,
            is_trial=_opt_flag(obj, "trial"),
            trial_ref=_opt_trial_ref(obj),
        )

    @property
    def is_lifetime(self) -> bool:
        """``True`` when the license never expires."""
        return self.expires_at is None

    @property
    def expires_at_datetime(self) -> Optional[_dt.datetime]:
        """Expiry as an aware UTC :class:`datetime.datetime` (``None`` = lifetime)."""
        return _to_datetime(self.expires_at)

    def has_feature(self, name: str) -> bool:
        """``True`` only for a license from an ``ok`` result (or a valid offline
        lease) whose status is ``active`` or ``pending`` and that lists ``name``.

        A denial (revoked, banned, suspended, expired, ...) never unlocks a
        feature, even when an older server still listed the plan's features.
        """
        return self.granted and self.status in ("active", "pending") and name in self.features

    def seconds_remaining(self, now: Optional[float] = None) -> Optional[float]:
        """Seconds until expiry (never negative); ``None`` for lifetime licenses."""
        if self.expires_at is None:
            return None
        return max(0.0, self.expires_at - _now(now))

    def is_expired(self, now: Optional[float] = None) -> bool:
        return self.expires_at is not None and self.expires_at <= _now(now)


@dataclass(frozen=True)
class ActivationInfo:
    """The server-side device record for this machine.

    The device secret itself is never exposed here; the client persists it in
    its store. ``device_secret_issued`` tells you a new secret arrived with
    this response.
    """

    id: str
    status: str
    first_seen_at: Optional[int] = None
    device_secret_issued: bool = False

    @classmethod
    def from_payload(cls, value: Any) -> "ActivationInfo":
        obj = _obj(value, "activation")
        secret = obj.get("deviceSecret")
        if secret is not None and not isinstance(secret, str):
            raise ValueError("deviceSecret must be a string or null")
        return cls(
            id=_str(obj, "id"),
            status=_str(obj, "status"),
            first_seen_at=_int(obj, "firstSeenAt"),
            device_secret_issued=bool(secret),
        )


@dataclass(frozen=True)
class LeaseInfo:
    """A signed offline lease: lets the app run offline until ``expires_at``."""

    token: str = field(repr=False)
    expires_at: int

    @classmethod
    def from_payload(cls, value: Any) -> "LeaseInfo":
        obj = _obj(value, "lease")
        return cls(token=_str(obj, "token"), expires_at=_int(obj, "expiresAt"))

    @property
    def expires_at_datetime(self) -> Optional[_dt.datetime]:
        return _to_datetime(self.expires_at)


@dataclass(frozen=True)
class UpdateInfo:
    """Release information attached to validate / update-check responses."""

    latest_version: str
    min_version: Optional[str]
    update_available: bool
    mandatory: bool
    changelog: str

    @classmethod
    def from_payload(cls, value: Any) -> "UpdateInfo":
        obj = _obj(value, "update")
        return cls(
            latest_version=_str(obj, "latestVersion"),
            min_version=_opt_str(obj, "minVersion"),
            update_available=_bool(obj, "updateAvailable"),
            mandatory=_bool(obj, "mandatory"),
            changelog=_str(obj, "changelog") if obj.get("changelog") is not None else "",
        )


@dataclass(frozen=True)
class DownloadInfo:
    """A short-lived download link for a release.

    ``url`` embeds a bearer token valid for a few minutes, so it is excluded
    from ``repr`` to keep it out of logs. ``size`` and ``sha256`` are signed by
    the server; :meth:`VelsigilClient.download_to_file` enforces both.
    """

    url: str = field(repr=False)
    expires_at: int
    file_name: str
    size: int
    sha256: str
    version: str

    @classmethod
    def from_payload(cls, value: Any) -> "DownloadInfo":
        obj = _obj(value, "download")
        sha = _str(obj, "sha256").lower()
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise ValueError("download.sha256 must be 64 hex characters")
        size = _int(obj, "size")
        if size < 0:
            raise ValueError("download.size must not be negative")
        return cls(
            url=_str(obj, "url"),
            expires_at=_int(obj, "expiresAt"),
            file_name=_str(obj, "fileName"),
            size=size,
            sha256=sha,
            version=_str(obj, "version"),
        )


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class VelsigilResult:
    """Outcome of a client call. Request methods never raise; check ``ok``.

    ``ok`` can only be ``True`` when it came from a response whose Ed25519
    signature, nonce and product id were verified, or from a verified offline
    lease (``offline=True``).
    """

    ok: bool
    code: str
    message: str
    license: Optional[LicenseInfo] = None
    activation: Optional[ActivationInfo] = None
    lease: Optional[LeaseInfo] = None
    update: Optional[UpdateInfo] = None
    download: Optional[DownloadInfo] = None
    request_id: Optional[str] = None
    offline: bool = False
    server_time: Optional[int] = None
    http_status: Optional[int] = None
    retry_after: Optional[int] = None
    #: The license key of the free trial :meth:`VelsigilClient.start_trial`
    #: just started (``ok`` results of ``start_trial`` only; otherwise
    #: ``None``). The server sends it once and can never send it again: store
    #: it right away, like a key the user typed. Kept out of ``repr``.
    trial_key: Optional[str] = field(default=None, repr=False)
    #: Unix time the result refers to when it has no ``server_time``
    #: (offline results: the time of the check, local clock plus the learned
    #: server offset). The default ``now`` of :meth:`days_remaining`.
    reference_time: Optional[float] = field(default=None, repr=False, compare=False)

    # -- features -------------------------------------------------------------

    @property
    def features(self) -> Tuple[str, ...]:
        """Enabled features; empty unless the result is ``ok``."""
        if not self.ok or self.license is None:
            return ()
        return self.license.features

    def has_feature(self, name: str) -> bool:
        """``True`` only for an ``ok`` result whose license includes ``name``."""
        return self.ok and self.license is not None and name in self.license.features

    # -- expiry helpers -------------------------------------------------------

    @property
    def expires_at(self) -> Optional[int]:
        """License expiry (unix seconds); ``None`` if lifetime or unknown."""
        return self.license.expires_at if self.license is not None else None

    @property
    def expires_at_datetime(self) -> Optional[_dt.datetime]:
        return _to_datetime(self.expires_at)

    @property
    def is_lifetime(self) -> bool:
        """``True`` when a license is present and has no expiry."""
        return self.license is not None and self.license.expires_at is None

    @property
    def is_trial(self) -> bool:
        """``True`` when the license is a free trial (SPEC 9.7), online or offline.

        A purchase with the same e-mail address keeps the key; this turns
        ``False`` with the next online validation.
        """
        return self.license is not None and self.license.is_trial

    @property
    def trial_ref(self) -> Optional[str]:
        """The current trial's conversion reference (SPEC 9.7), or ``None``.

        Present on online results for a free trial a purchase can still
        convert, also on ``license_expired`` (the moment to offer "Buy now").
        Add it to the "Buy now" link with :meth:`with_trial_ref`: the purchase
        then converts THIS trial into the paid license (same key) whatever
        e-mail address the buyer pays with. A fresh one comes with every
        answer; offline results have none.
        """
        return self.license.trial_ref if self.license is not None else None

    def with_trial_ref(self, buy_url: str) -> str:
        """``buy_url`` with this trial's conversion reference, or unchanged when there is none."""
        return with_trial_ref(buy_url, self.trial_ref)

    def seconds_remaining(self, now: Optional[float] = None) -> Optional[float]:
        """Seconds until license expiry; ``None`` for lifetime/unknown."""
        return self.license.seconds_remaining(now) if self.license is not None else None

    def days_remaining(self, now: Optional[float] = None) -> Optional[int]:
        """Days until license expiry, rounded up; ``None`` for lifetime/unknown.

        The "days left" rule of CLIENT_PROTOCOL 5.2, the same in every
        Velsigil SDK. Without ``now`` it measures at the result's own time:
        the signed ``server_time`` of an online answer, the time of the check
        for an offline result. So right after ``start_trial`` of an N-day
        trial it is N; it is 1 throughout the last day and 0 once expired.
        """
        if now is None:
            now = self.server_time if self.server_time is not None else self.reference_time
        seconds = self.seconds_remaining(now)
        if seconds is None:
            return None
        return int(math.ceil(seconds / 86400.0))

    def is_expired(self, now: Optional[float] = None) -> bool:
        """``True`` when the license expiry lies in the past."""
        return self.license is not None and self.license.is_expired(now)


__all__ = [
    "LicenseInfo",
    "ActivationInfo",
    "LeaseInfo",
    "UpdateInfo",
    "DownloadInfo",
    "VelsigilResult",
    "TRIAL_REF_PARAM",
    "with_trial_ref",
]
