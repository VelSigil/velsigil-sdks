"""Velsigil license client (SPEC sections 10 and 14).

Security model in one paragraph: every response that can report success is
an Ed25519-signed envelope. The client verifies the signature over the exact
bytes it received *before* parsing, using only the public key it was
constructed with, then checks that the payload echoes the request's fresh
nonce, this product id and the request type, and that a signed lease or
activation describes this device (hwid). Unsigned HTTP errors are mapped to failure codes
and can never produce ``ok=True``. Request methods never raise; they return
a :class:`~velsigil_client.models.VelsigilResult`.
"""

from __future__ import annotations

import base64
import dataclasses
import datetime
import functools
import hashlib
import hmac
import http.client
import json
import logging
import math
import os
import platform
import re
import socket
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Dict, Mapping, Optional, Tuple, TypeVar

from .crypto import (
    _PUBLISHED_TEST_KEY_MESSAGE,
    _is_published_test_key,
    _new_verifier,
    _open_envelope,
    _verify_lease,
    as_int,
    new_nonce,
)
from .errors import (
    UNSIGNED_ERROR_CODES,
    Code,
    ConfigurationError,
    DownloadError,
    EnvelopeError,
    LeaseError,
)
from .hwid import get_hardware_id as _detect_hardware_id
from .models import (
    ActivationInfo,
    DownloadInfo,
    LeaseInfo,
    LicenseInfo,
    UpdateInfo,
    VelsigilResult,
)
from .store import LicenseStore, MemoryStore, StoredState

SDK_VERSION = "1.0.4"

API_PATH = "/api/client/v1"
DEFAULT_TIMEOUT = 15.0
#: Responses larger than this are rejected (the protocol's are a few KiB).
MAX_RESPONSE_BYTES = 1024 * 1024
#: Server-side limit for license key input (SPEC 3.2 ``licenseKeyInput``).
MAX_LICENSE_KEY_LENGTH = 64
#: Longest e-mail address ``start_trial`` sends (the server's ``email`` schema).
MAX_EMAIL_LENGTH = 254
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

#: The two public keys of the shared SDK test vectors (``test-vectors.json``:
#: ``keys.publicKey`` and ``keys.wrongPublicKey``), as raw 32-byte keys. Their
#: private seeds are published next to them, so anyone can sign "valid" answers
#: for them. The constructor refuses them unless ``api_url`` is loopback; the
#: public helpers in :mod:`velsigil_client.crypto` refuse them always (through
#: ``crypto._is_published_test_key``). Internal, not part of the public API.
_PUBLISHED_TEST_PUBLIC_KEYS = frozenset(
    base64.b64decode(key)
    for key in (
        "I8lY1RS9MwgbPMa+7xrzLkdKhAGCoMbVmRApSuJjToI=",
        "b/OKSQM/kKwu80PNfHkda3EM9dk1/ZmNKkQz/1azw/Q=",
    )
)

_log =logging.getLogger("velsigil_client")

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_DEVICE_SECRET_RE = re.compile(r"^[\x21-\x7e]{16,256}\Z")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}\Z")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
#: A license key as the server issues it: 1-64 printable ASCII characters.
_TRIAL_KEY_RE = re.compile(r"^[\x21-\x7e]{1,64}\Z")
#: ``Retry-After`` as delta-seconds (ASCII digits only; ``str.isdigit`` would accept other digits).
_DELTA_SECONDS_RE = re.compile(r"^[0-9]+\Z")
#: Upper bound of ``VelsigilResult.retry_after``: one day.
_MAX_RETRY_AFTER = 86400

#: Signed denials after which a stored offline lease must no longer be used.
#: This exact set is binding for every Velsigil SDK (SPEC 14); any other
#: signed failure (product_paused, outdated_version, activation_rate_limited,
#: clock_skew, replay_detected, ...) keeps the lease.
LEASE_REVOKING_CODES = frozenset(
    {
        Code.INVALID_KEY,
        Code.LICENSE_EXPIRED,
        Code.LICENSE_SUSPENDED,
        Code.LICENSE_REVOKED,
        Code.LICENSE_BANNED,
        Code.DEVICE_REVOKED,
        Code.DEVICE_VERIFICATION_FAILED,
        Code.DEVICE_LIMIT_REACHED,
        Code.DEVICE_NOT_ACTIVATED,
        Code.DEVICE_NOT_FOUND,
        Code.BLACKLISTED,
        Code.PRODUCT_DISABLED,
    }
)
_LEASE_REVOKING_CODES = LEASE_REVOKING_CODES

_INVALID_RESPONSE_MESSAGES = {
    EnvelopeError.INVALID_SIGNATURE: "The server response signature is invalid.",
    EnvelopeError.NONCE_MISMATCH: "The server response does not match this request (nonce).",
    EnvelopeError.PRODUCT_MISMATCH: "The server response is for a different product.",
    EnvelopeError.TYPE_MISMATCH: "The server response is for a different operation.",
    EnvelopeError.HWID_MISMATCH: "The server response is for a different device.",
    EnvelopeError.MALFORMED: "The server response is malformed.",
}

_UNSIGNED_MESSAGES = {
    Code.VALIDATION_ERROR: "The server rejected the request as invalid.",
    Code.IP_BLOCKED: "Requests from this network are temporarily blocked.",
    Code.UNKNOWN_PRODUCT: "The product is not known to the license server.",
    Code.RATE_LIMITED: "Too many requests; try again later.",
    Code.INTERNAL_ERROR: "The license server encountered an error.",
    Code.PAYLOAD_TOO_LARGE: "The request was too large.",
    Code.UNSUPPORTED_MEDIA_TYPE: "The request content type was rejected.",
    Code.NETWORK_ERROR: "The license server is unavailable.",
    Code.INVALID_RESPONSE: "Unexpected response from the license server.",
    Code.PANEL_TOO_OLD: (
        "The license server does not support starting free trials from the app yet. "
        "The seller needs to update the Velsigil panel."
    ),
}

#: ``already_licensed`` (SPEC 14): ``start_trial`` on a device that already
#: holds a license (stored device secret or lease) for the product.
_ALREADY_LICENSED_MESSAGE = (
    "This device already holds a license for this product (a stored device secret or offline lease); "
    "a free trial cannot replace it. Validate the saved license key instead, or call deactivate() or "
    "clear_stored_state() first. No request was sent."
)

#: ``store_unavailable`` (SPEC 14): ``start_trial`` could not read the store,
#: so it cannot tell whether a license is stored for the product.
_STORE_UNAVAILABLE_MESSAGE = (
    "The license store could not be read, so it is unknown whether this device already holds a license for this "
    "product; a free trial was not started. Try again once the store can be read. No request was sent."
)


class _NetworkFailure(Exception):
    """Transport-level failure (DNS, TCP, TLS, timeout, broken connection)."""


class _ResponseTooLarge(Exception):
    """The response body exceeded :data:`MAX_RESPONSE_BYTES`.

    ``status`` and ``headers`` are those of that response (``None`` when
    unknown): an oversized 429 or 503 still carries its ``Retry-After``.
    """

    def __init__(self, status: Optional[int] = None, headers: Any = None) -> None:
        super().__init__()
        self.status = status
        self.headers = headers


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: a 3xx surfaces as an HTTPError instead.

    Following a redirect could downgrade to plain HTTP or forward the license
    key to another host; the protocol never redirects.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _build_opener(context: ssl.SSLContext) -> urllib.request.OpenerDirector:
    """An opener limited to HTTP(S): no file:, ftp: or data: handlers, no redirects.

    System proxy settings (``HTTPS_PROXY`` etc.) are honoured; TLS is still
    verified end to end through a proxy.
    """
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler(),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPDefaultErrorHandler(),
        _NoRedirect(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener


_F = TypeVar("_F", bound=Callable[..., VelsigilResult])


def _never_raise(method: _F) -> _F:
    """Turn unexpected exceptions into a fail-closed result instead of raising."""

    @functools.wraps(method)
    def wrapper(*args: Any, **kwargs: Any) -> VelsigilResult:
        try:
            return method(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - deliberate: request methods never raise
            # Only the exception type is logged: messages could echo inputs.
            _log.error("unexpected %s in VelsigilClient.%s", type(exc).__name__, method.__name__)
            return _failure(Code.INVALID_RESPONSE, "Unexpected client error while processing the response.")

    return wrapper  # type: ignore[return-value]


def _failure(code: str, message: str, **extra: Any) -> VelsigilResult:
    return VelsigilResult(ok=False, code=code, message=message, **extra)


def _is_local_host(host: Optional[str]) -> bool:
    return (host or "").lower() in LOCAL_HOSTS


def _normalize_api_url(api_url: Any, allow_insecure_http: bool) -> str:
    if not isinstance(api_url, str) or not api_url.strip():
        raise ConfigurationError("api_url must be a non-empty URL string")
    try:
        parts = urllib.parse.urlsplit(api_url.strip())
        parts.port  # noqa: B018 - raises ValueError for an invalid port
    except ValueError as exc:
        raise ConfigurationError("api_url is not a valid URL") from exc
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http") or not parts.hostname:
        raise ConfigurationError("api_url must be an absolute http(s) URL")
    if parts.username is not None or parts.password is not None:
        raise ConfigurationError("api_url must not contain credentials")
    if parts.query or parts.fragment:
        raise ConfigurationError("api_url must not contain a query string or fragment")
    if scheme == "http" and not allow_insecure_http and not _is_local_host(parts.hostname):
        raise ConfigurationError(
            "api_url must use HTTPS (plain HTTP is only allowed for localhost "
            "unless allow_insecure_http=True)"
        )
    path = parts.path.rstrip("/")
    if not path.endswith(API_PATH):
        path += API_PATH
    return urllib.parse.urlunsplit((scheme, parts.netloc, path, "", ""))


def _validate_hwid(hwid: Any) -> str:
    if not isinstance(hwid, str) or not 8 <= len(hwid) <= 256 or _CONTROL_CHARS_RE.search(hwid):
        raise ConfigurationError("hwid must be a string of 8..256 printable characters")
    return hwid


class VelsigilClient:
    """Client for the Velsigil license server.

    :param api_url: Base URL of the Velsigil server, e.g.
        ``https://licenses.example.com`` (``/api/client/v1`` is appended unless
        already present). HTTPS is required except for localhost.
    :param product_id: The product's UUID.
    :param public_key: The product's Ed25519 public key (standard base64).
        Embed it in your application; it is the only key that is trusted.
        The public test keys of the SDK test vectors are refused unless
        ``api_url`` is a loopback host (localhost, 127.0.0.1, ::1).
    :param timeout: Per-request timeout in seconds (default 15).
    :param hwid: Override the hardware id (8..256 characters). By default it
        is derived from the OS machine id (:meth:`get_hardware_id`).
    :param store: Where the device secret and offline lease are persisted.
        Defaults to a :class:`~velsigil_client.store.MemoryStore`; use a
        :class:`~velsigil_client.store.FileStore` in production.
    :param allow_insecure_http: Permit plain HTTP to non-local hosts. Never
        enable this in production.
    :param ssl_context: Custom :class:`ssl.SSLContext` (e.g. a private CA).
        Certificate and hostname verification must stay enabled.
    :param clock: Callable returning the current unix time in seconds
        (default :func:`time.time`); useful for tests.
    :param crypto_backend: ``"auto"``, ``"cryptography"`` or ``"nacl"``.

    The constructor raises :class:`~velsigil_client.errors.ConfigurationError`
    (bad arguments), :class:`~velsigil_client.errors.CryptoBackendError` or
    :class:`~velsigil_client.errors.HardwareIdError`. Request methods never
    raise.
    """

    def __init__(
        self,
        api_url: str,
        product_id: str,
        public_key: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        hwid: Optional[str] = None,
        store: Optional[LicenseStore] = None,
        allow_insecure_http: bool = False,
        ssl_context: Optional[ssl.SSLContext] = None,
        user_agent: Optional[str] = None,
        clock: Optional[Callable[[], float]] = None,
        crypto_backend: str = "auto",
    ) -> None:
        self._base_url = _normalize_api_url(api_url, allow_insecure_http)
        self._allow_insecure_http = bool(allow_insecure_http)

        if not isinstance(product_id, str) or not _UUID_RE.match(product_id.strip().lower()):
            raise ConfigurationError("product_id must be a UUID string")
        self._product_id = product_id.strip().lower()

        # The internal verifier: the public Ed25519Verifier refuses the published test keys
        # unconditionally, the client allows them for a loopback api_url (the same hosts that may use
        # plain HTTP). The decoded key bytes are compared, so no other encoding of a test key gets through.
        self._verifier = _new_verifier(public_key, backend=crypto_backend)
        if _is_published_test_key(self._verifier.public_key_bytes) and not _is_local_host(
            urllib.parse.urlsplit(self._base_url).hostname
        ):
            raise ConfigurationError(_PUBLISHED_TEST_KEY_MESSAGE)

        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 600:
            raise ConfigurationError("timeout must be a number of seconds in (0, 600]")
        self._timeout = float(timeout)

        if store is not None and not isinstance(store, LicenseStore):
            raise ConfigurationError("store must implement velsigil_client.LicenseStore")
        self._store: LicenseStore = store if store is not None else MemoryStore()

        if clock is not None and not callable(clock):
            raise ConfigurationError("clock must be callable")
        self._clock: Callable[[], float] = clock if clock is not None else time.time

        self._hwid = _validate_hwid(hwid) if hwid is not None else _detect_hardware_id()

        if ssl_context is not None:
            if ssl_context.verify_mode != ssl.CERT_REQUIRED or not ssl_context.check_hostname:
                raise ConfigurationError("ssl_context must verify certificates and hostnames")
            context = ssl_context
        else:
            context = ssl.create_default_context()
        self._opener = _build_opener(context)
        self._user_agent = user_agent or "velsigil-client-python/%s (Python %s)" % (
            SDK_VERSION,
            platform.python_version(),
        )

        # _op_lock serialises stateful operations (device secret / lease
        # read-modify-write); _state_lock guards the small shared fields.
        self._op_lock = threading.RLock()
        self._state_lock = threading.Lock()
        self._clock_offset = 0
        self._cached_state = StoredState()
        # False until the store was read or written once: until then the
        # cache is a placeholder, never "nothing stored".
        self._state_known = False
        self._unsaved = False

    # ------------------------------------------------------------------ info

    @property
    def api_url(self) -> str:
        """Normalised client API base URL (``…/api/client/v1``)."""
        return self._base_url

    @property
    def product_id(self) -> str:
        return self._product_id

    @property
    def hwid(self) -> str:
        """Hardware id sent to the server."""
        return self._hwid

    @property
    def clock_offset(self) -> int:
        """Seconds added to the local clock, learned from signed ``clock_skew`` replies."""
        with self._state_lock:
            return self._clock_offset

    @property
    def key_id(self) -> str:
        """Key id of the trusted public key (for display/diagnostics only)."""
        return self._verifier.key_id

    @staticmethod
    def get_hardware_id() -> str:
        """This machine's HWID (SPEC 10.6). Raises ``HardwareIdError`` on failure."""
        return _detect_hardware_id()

    def __repr__(self) -> str:
        return "VelsigilClient(api_url=%r, product_id=%r, key_id=%r)" % (
            self._base_url,
            self._product_id,
            self._verifier.key_id,
        )

    # ------------------------------------------------------------ operations

    @_never_raise
    def validate(
        self,
        license_key: str,
        version: Optional[str] = None,
        device_name: Optional[str] = None,
    ) -> VelsigilResult:
        """Validate (and on first use activate) ``license_key`` on this device."""
        problem = _input_problem(license_key, version, device_name)
        if problem is not None:
            return problem
        with self._op_lock:
            fields = self._device_fields(license_key)
            if version:
                fields["version"] = version
            if device_name:
                fields["deviceName"] = device_name
            result, payload = self._round_trip("validate", "validate", fields)
            if payload is not None:
                self._absorb_validate(result, payload)
            return result

    @_never_raise
    def start_trial(
        self,
        version: Optional[str] = None,
        device_name: Optional[str] = None,
        email: Optional[str] = None,
    ) -> VelsigilResult:
        """Start a free trial of the product on this device, without a license key.

        SPEC 9.7 "In-app trials": the seller turns on the in-app channel of
        the product's trial offer. On ``ok``, ``result.trial_key`` is the new
        license key: store it right away (the server can never send it again;
        the SDK does not persist it) and use :meth:`validate` from then on.
        The device secret and the offline lease are stored like after a
        validation. ``email`` is sent only when given and read only by offers
        that confirm an address first (answer ``trial_confirmation_sent``: the
        key arrives by e-mail). Other signed failures: ``trial_already_used``,
        ``trial_unavailable``, ``trial_email_required``, ``trial_email_invalid``,
        ``trial_email_not_accepted``; ``panel_too_old`` when the server
        predates in-app trials. Call it only when the app has no key yet: when
        a device secret or an offline lease is already stored for the product
        it returns ``already_licensed`` without sending anything and leaves the
        stored state untouched, so a trial never replaces this device's
        license. When the store cannot be read it returns ``store_unavailable``
        (nothing sent): it cannot tell whether a license is stored. Never
        raises.
        """
        problem = _input_problem(version=version, device_name=device_name, require_key=False)
        if problem is not None:
            return problem
        if email is not None and email != "":
            if not isinstance(email, str) or len(email.strip()) > MAX_EMAIL_LENGTH or _CONTROL_CHARS_RE.search(email):
                return _failure(Code.VALIDATION_ERROR, "email must be a string of at most 254 characters.")
        with self._op_lock:
            # The trial answer would overwrite the stored device secret and lease
            # of this device's license (a paid one included). Checked under the
            # operation lock, so no concurrent validate can slip in between.
            state, readable = self._read_state()
            if not readable:
                # A failed read is not "nothing stored": the store may hold this
                # device's (paid) license. Fail closed.
                return _failure(Code.STORE_UNAVAILABLE, _STORE_UNAVAILABLE_MESSAGE)
            if state.device_secret or state.lease_token:
                return _failure(Code.ALREADY_LICENSED, _ALREADY_LICENSED_MESSAGE)
            fields: Dict[str, Any] = {"hwid": self._hwid}
            if device_name:
                fields["deviceName"] = device_name
            if version:
                fields["version"] = version
            if isinstance(email, str) and email.strip():
                fields["email"] = email.strip()
            result, payload = self._round_trip("trial", "trial", fields)
            if payload is not None:
                # A started trial is a validation of the new license on this device: same storage rules.
                self._absorb_validate(result, payload)
            return result

    @_never_raise
    def deactivate(self, license_key: str) -> VelsigilResult:
        """Release this device's activation slot. Clears the stored state on success."""
        problem = _input_problem(license_key)
        if problem is not None:
            return problem
        with self._op_lock:
            fields = self._device_fields(license_key)
            result, payload = self._round_trip("deactivate", "deactivate", fields)
            if payload is not None:
                if result.ok or result.code == Code.DEVICE_NOT_FOUND:
                    # The server no longer knows this device: its secret and
                    # lease are worthless now.
                    self._save_state(StoredState())
                else:
                    self._absorb_common(result, payload)
            return result

    @_never_raise
    def check_update(self, current_version: Optional[str] = None) -> VelsigilResult:
        """Ask for the latest published release (``result.update``)."""
        problem = _input_problem(version=current_version, require_key=False)
        if problem is not None:
            return problem
        fields: Dict[str, Any] = {}
        if current_version:
            fields["version"] = current_version
        result, _payload = self._round_trip("update-check", "update_check", fields)
        return result

    @_never_raise
    def get_download(self, license_key: str, version: Optional[str] = None) -> VelsigilResult:
        """Request a short-lived download link (``result.download``).

        Requires an already activated device when the product locks HWIDs.
        Use :meth:`download_to_file` to fetch and integrity-check the file.
        """
        problem = _input_problem(license_key, version)
        if problem is not None:
            return problem
        with self._op_lock:
            fields = self._device_fields(license_key)
            if version:
                fields["version"] = version
            result, payload = self._round_trip("download", "download", fields)
            if payload is None:
                return result
            self._absorb_common(result, payload)
            if result.download is not None:
                url = self._resolve_download_url(result.download.url)
                if url is None:
                    _log.warning("rejected download URL with a disallowed scheme or host")
                    return _failure(
                        Code.INVALID_RESPONSE,
                        "The server returned a download URL that is not allowed.",
                        request_id=result.request_id,
                        server_time=result.server_time,
                    )
                result = dataclasses.replace(result, download=dataclasses.replace(result.download, url=url))
            return result

    @_never_raise
    def validate_offline(self) -> VelsigilResult:
        """Validate the stored offline lease without contacting the server.

        Checks the lease signature, type, product, HWID and expiry against the
        local clock (plus any learned server offset). Clock tampering is a
        known limitation of offline validation.
        """
        state = self._load_state()
        token = state.lease_token
        if not token:
            return _failure(Code.NO_LEASE, "No offline lease is stored for this product.", offline=True)
        now = self._now()
        try:
            claims = _verify_lease(self._verifier, token, self._product_id, self._hwid, now)
            license_info = LicenseInfo(
                id=_claim_str(claims, "licenseId"),
                plan=_claim_str(claims, "plan"),
                status="active",
                features=_claim_features(claims),
                expires_at=_claim_opt_int(claims, "licenseExpiresAt"),
                granted=True,
                is_trial=_claim_trial(claims),
            )
            activation = ActivationInfo(id=_claim_str(claims, "activationId"), status="active")
            lease = LeaseInfo(token=token, expires_at=int(claims["exp"]))
        except LeaseError as exc:
            if exc.reason == LeaseError.EXPIRED:
                return _failure(Code.LEASE_EXPIRED, "The offline lease has expired.", offline=True)
            _log.warning("stored offline lease rejected: %s", exc.reason)
            return _failure(Code.LEASE_INVALID, "The stored offline lease is not valid (%s)." % exc.reason, offline=True)
        except ValueError:
            return _failure(Code.LEASE_INVALID, "The stored offline lease is not valid (malformed).", offline=True)
        return VelsigilResult(
            ok=True,
            code=Code.OK,
            message="Valid offline lease.",
            license=license_info,
            activation=activation,
            lease=lease,
            offline=True,
            reference_time=now,
        )

    @_never_raise
    def validate_with_offline_fallback(
        self,
        license_key: str,
        version: Optional[str] = None,
        device_name: Optional[str] = None,
    ) -> VelsigilResult:
        """Validate online; fall back to the stored lease only while the server is unavailable.

        "Unavailable" means no HTTP answer at all (``network_error``: DNS,
        connect, TLS, timeout, reset) or an unsigned HTTP 5xx answer, whatever
        its body (a Velsigil error such as ``internal_error`` while the
        server's database is down, a proxy's HTML error page, an empty or
        garbled body). Every other answer is returned as is: signed answers
        (``license_revoked``, ``license_expired``, ...), unsigned 4xx
        (``rate_limited``, ``validation_error``, ...), redirects and
        ``invalid_response`` on an HTTP 200. When it falls back, the result is
        that of :meth:`validate_offline`: ``ok`` (``offline=True``) for a usable
        lease, ``lease_expired`` or ``lease_invalid`` (``offline=True``) for a
        stored lease that cannot be used (kept or removed exactly as by
        :meth:`validate_offline`), and the original online failure
        (``network_error``, ``internal_error``, ...) when no lease is stored at
        all, not ``no_lease``. A result of the fallback (``ok`` offline,
        ``lease_expired``, ``lease_invalid``) carries the ``retry_after`` of the
        failed online attempt (the ``Retry-After`` of a 503, else ``None``), so
        the app knows when to try online again. :meth:`validate` itself never
        falls back.
        """
        online = self.validate(license_key, version=version, device_name=device_name)
        if not _server_unavailable(online):
            return online
        offline = self.validate_offline()
        # Without any stored lease the original failure (network_error, internal_error, ...) is more useful.
        if offline.code == Code.NO_LEASE:
            return online
        return dataclasses.replace(offline, retry_after=online.retry_after)

    def clear_stored_state(self) -> None:
        """Forget the stored device secret and offline lease for this product."""
        with self._op_lock:
            self._save_state(StoredState())

    def download_to_file(self, download: DownloadInfo, destination: str) -> str:
        """Fetch a release to ``destination`` and verify its signed size and SHA-256.

        The file is streamed to a temporary file in the destination directory
        and only moved into place when both checks pass, so a tampered or
        truncated download never appears at ``destination``. Returns the
        absolute destination path. Raises
        :class:`~velsigil_client.errors.DownloadError` on any failure.
        """
        if not isinstance(download, DownloadInfo):
            raise DownloadError("download must be a DownloadInfo from get_download()", Code.VALIDATION_ERROR)
        url = self._resolve_download_url(download.url)
        if url is None:
            raise DownloadError("download URL is not allowed", Code.DOWNLOAD_FAILED)
        target = os.path.abspath(os.fspath(destination))
        directory = os.path.dirname(target)
        try:
            os.makedirs(directory, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(prefix=".velsigil-dl-", suffix=".part", dir=directory)
        except OSError as exc:
            raise DownloadError("cannot create the destination file", Code.IO_ERROR) from exc
        try:
            handle = os.fdopen(fd, "wb")
        except OSError as exc:
            os.close(fd)
            _unlink_quietly(tmp_path)
            raise DownloadError("cannot create the destination file", Code.IO_ERROR) from exc
        digest = hashlib.sha256()
        received = 0
        try:
            with handle:
                request = urllib.request.Request(
                    url,
                    method="GET",
                    headers={"User-Agent": self._user_agent, "Accept": "application/octet-stream"},
                )
                try:
                    with self._opener.open(request, timeout=self._timeout) as response:
                        while True:
                            try:
                                chunk = response.read(64 * 1024)
                            except (http.client.HTTPException, OSError, ValueError) as exc:
                                raise DownloadError(
                                    "download interrupted: %s" % type(exc).__name__, Code.NETWORK_ERROR
                                ) from None
                            if not chunk:
                                break
                            received += len(chunk)
                            if received > download.size:
                                raise DownloadError("download is larger than its signed size", Code.INTEGRITY_MISMATCH)
                            digest.update(chunk)
                            try:
                                handle.write(chunk)
                            except OSError as exc:
                                raise DownloadError("cannot write the destination file", Code.IO_ERROR) from exc
                except urllib.error.HTTPError as exc:
                    exc.close()
                    # 410: the short-lived link expired; request a new one.
                    raise DownloadError("download failed with HTTP %d" % exc.code, Code.DOWNLOAD_FAILED) from None
                except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
                    raise DownloadError("download failed: %s" % type(exc).__name__, Code.NETWORK_ERROR) from None
                handle.flush()
                os.fsync(handle.fileno())
            if received != download.size:
                raise DownloadError("download size does not match its signed size", Code.INTEGRITY_MISMATCH)
            if not hmac.compare_digest(digest.hexdigest(), download.sha256.lower()):
                raise DownloadError("download SHA-256 does not match its signed hash", Code.INTEGRITY_MISMATCH)
            os.replace(tmp_path, target)
        except DownloadError:
            _unlink_quietly(tmp_path)
            raise
        except OSError as exc:
            _unlink_quietly(tmp_path)
            raise DownloadError("cannot write the destination file", Code.IO_ERROR) from exc
        return target

    # ------------------------------------------------------------- internals

    def _now(self) -> float:
        with self._state_lock:
            offset = self._clock_offset
        return float(self._clock()) + offset

    def _learn_offset(self, server_time: int) -> None:
        offset = int(round(server_time - float(self._clock())))
        with self._state_lock:
            self._clock_offset = offset
        _log.info("adjusted clock offset to %+d s from a signed clock_skew response", offset)

    def _device_fields(self, license_key: str) -> Dict[str, Any]:
        fields: Dict[str, Any] = {"licenseKey": license_key.strip(), "hwid": self._hwid}
        secret = self._load_state().device_secret
        if secret:
            fields["deviceSecret"] = secret
        return fields

    def _round_trip(
        self, endpoint: str, response_type: str, fields: Mapping[str, Any]
    ) -> Tuple[VelsigilResult, Optional[Dict[str, Any]]]:
        """POST with a fresh nonce/timestamp; retry once after a signed clock_skew."""
        retried = False
        while True:
            nonce = new_nonce()
            body = dict(fields)
            body["productId"] = self._product_id
            body["nonce"] = nonce
            body["timestamp"] = int(self._now())
            result, payload = self._exchange(endpoint, response_type, body, nonce)
            if payload is not None and result.code == Code.CLOCK_SKEW and not retried:
                server_time = as_int(payload.get("serverTime"))
                if server_time is not None:
                    self._learn_offset(server_time)
                    retried = True
                    continue
            return result, payload

    def _exchange(
        self, endpoint: str, response_type: str, body: Mapping[str, Any], nonce: str
    ) -> Tuple[VelsigilResult, Optional[Dict[str, Any]]]:
        url = "%s/%s" % (self._base_url, endpoint)
        data = json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        try:
            status, raw, headers = self._post(url, data)
        except _NetworkFailure as exc:
            return _failure(Code.NETWORK_ERROR, "Could not reach the license server (%s)." % exc), None
        except _ResponseTooLarge as exc:
            # The status is kept: an oversized 5xx (e.g. a proxy error page) is still an unsigned 5xx
            # answer, which lets validate_with_offline_fallback use the stored lease.
            return (
                _failure(
                    Code.INVALID_RESPONSE,
                    "The server response is too large.",
                    http_status=exc.status,
                    retry_after=_retry_after(exc.status, exc.headers, float(self._clock())),
                ),
                None,
            )

        if status != 200:
            return _unsigned_error(status, raw, headers, response_type, now=float(self._clock())), None

        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return _failure(Code.INVALID_RESPONSE, _UNSIGNED_MESSAGES[Code.INVALID_RESPONSE], http_status=status), None
        try:
            # Device-bound requests carry "hwid": the signed lease/activation must then belong to it.
            hwid = body.get("hwid")
            payload = _open_envelope(
                self._verifier,
                envelope,
                nonce,
                self._product_id,
                response_type,
                hwid if isinstance(hwid, str) else None,
            )
        except EnvelopeError as exc:
            _log.warning("rejected %s response: %s", endpoint, exc.reason)
            return _failure(Code.INVALID_RESPONSE, _INVALID_RESPONSE_MESSAGES[exc.reason], http_status=status), None
        try:
            result = _result_from_payload(payload)
        except ValueError:
            _log.warning("rejected %s response: signed payload has unexpected field types", endpoint)
            return _failure(Code.INVALID_RESPONSE, _INVALID_RESPONSE_MESSAGES[EnvelopeError.MALFORMED]), None
        return result, payload

    def _post(self, url: str, data: bytes) -> Tuple[int, bytes, Any]:
        request = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": self._user_agent,
            },
        )
        deadline = time.monotonic() + self._timeout
        try:
            try:
                response = self._opener.open(request, timeout=self._timeout)
            except urllib.error.HTTPError as err:
                try:
                    raw = _read_capped(err, deadline) if getattr(err, "fp", None) is not None else b""
                except _ResponseTooLarge:
                    raise _ResponseTooLarge(err.code, err.headers) from None
                finally:
                    err.close()
                return err.code, raw, err.headers
            with response:
                status = response.getcode()
                try:
                    return status, _read_capped(response, deadline), response.headers
                except _ResponseTooLarge:
                    raise _ResponseTooLarge(status, response.headers) from None
        except _ResponseTooLarge:
            raise
        except (socket.timeout, TimeoutError):
            raise _NetworkFailure("timed out") from None
        except urllib.error.URLError as err:
            reason = err.reason
            if isinstance(reason, (socket.timeout, TimeoutError)):
                raise _NetworkFailure("timed out") from None
            if isinstance(reason, ssl.SSLError):
                raise _NetworkFailure("TLS error") from None
            if isinstance(reason, ConnectionRefusedError):
                raise _NetworkFailure("connection refused") from None
            raise _NetworkFailure(type(reason).__name__ if isinstance(reason, BaseException) else "unreachable") from None
        except ssl.SSLError:
            raise _NetworkFailure("TLS error") from None
        except (http.client.HTTPException, OSError, ValueError) as err:
            raise _NetworkFailure(type(err).__name__) from None

    # -- stored state ---------------------------------------------------------

    def _read_state(self) -> Tuple[StoredState, bool]:
        """The stored state, and whether it was read: ``False`` when the store
        failed, the state is then the last one this client read or wrote
        (empty before the first), which must never count as "nothing stored".
        After a failed save the in-memory state is newer than the store and
        counts as read."""
        with self._state_lock:
            if self._unsaved:
                return self._cached_state, True
        try:
            state = self._store.load(self._product_id)
            if not isinstance(state, StoredState):
                raise TypeError("store returned %s" % type(state).__name__)
        except Exception as exc:  # noqa: BLE001 - custom stores may raise anything
            _log.warning("license store load failed (%s); using in-memory state", type(exc).__name__)
            with self._state_lock:
                return self._cached_state, False
        with self._state_lock:
            self._cached_state = state
            self._state_known = True
        return state, True

    def _load_state(self) -> StoredState:
        return self._read_state()[0]

    def _merge_base(self) -> Optional[StoredState]:
        """The state an answer is merged into: a fresh read of the store, else
        the last state this client read or wrote; ``None`` while the store has
        never been readable (then only a newly issued secret may be written,
        never a state built on an unknown one)."""
        state, readable = self._read_state()
        if readable:
            return state
        with self._state_lock:
            return state if self._state_known else None

    def _save_state(self, state: StoredState) -> None:
        with self._state_lock:
            self._cached_state = state
            self._state_known = True
        try:
            self._store.save(self._product_id, state)
        except Exception as exc:  # noqa: BLE001
            with self._state_lock:
                self._unsaved = True
            _log.warning(
                "license store save failed (%s); state kept in memory for this process",
                type(exc).__name__,
            )
            return
        with self._state_lock:
            self._unsaved = False

    def _new_device_secret(self, payload: Mapping[str, Any]) -> Optional[str]:
        activation = payload.get("activation")
        if not isinstance(activation, Mapping):
            return None
        secret = activation.get("deviceSecret")
        if secret is None:
            return None
        if not isinstance(secret, str) or not _DEVICE_SECRET_RE.match(secret):
            _log.warning("ignoring a device secret with an unexpected format")
            return None
        return secret

    def _absorb_common(self, result: VelsigilResult, payload: Mapping[str, Any]) -> None:
        """Persist a newly issued device secret; drop the lease on revoking codes."""
        issued = self._new_device_secret(payload)
        current = self._merge_base()
        if current is None:
            if issued is None:
                return  # the store is unreadable: never write a state built on nothing
            current = StoredState()
        secret = issued or current.device_secret
        lease = current.lease_token
        if not result.ok and result.code in _LEASE_REVOKING_CODES:
            lease = None
        updated = StoredState(device_secret=secret, lease_token=lease)
        if updated != current:
            self._save_state(updated)

    def _absorb_validate(self, result: VelsigilResult, payload: Mapping[str, Any]) -> None:
        """Persist secret and lease from a signed validate response.

        The answer is merged into a fresh read of the store. While the store
        cannot be read (and never was), nothing is written except a newly
        issued device secret, which belongs to a new activation: a failed read
        must never erase the stored secret of this device.
        """
        issued = self._new_device_secret(payload)
        current = self._merge_base()
        if current is None:
            if issued is None:
                return
            current = StoredState()
        secret = issued or current.device_secret
        if result.ok:
            lease = None
            if result.lease is not None:
                try:
                    _verify_lease(self._verifier, result.lease.token, self._product_id, self._hwid, self._now())
                    lease = result.lease.token
                except LeaseError as exc:
                    _log.warning("not storing offline lease from server: %s", exc.reason)
        elif result.code in _LEASE_REVOKING_CODES:
            # A signed, definitive denial: the license may no longer be used
            # offline either.
            lease = None
        else:
            # Signed but not definitive (paused product, outdated version,
            # activation limits, clock skew, replay ...): keep the lease.
            lease = current.lease_token
        updated = StoredState(device_secret=secret, lease_token=lease)
        if updated != current:
            self._save_state(updated)

    def _resolve_download_url(self, url: str) -> Optional[str]:
        try:
            absolute = urllib.parse.urljoin(self._base_url + "/", url)
            parts = urllib.parse.urlsplit(absolute)
        except ValueError:
            return None
        scheme = parts.scheme.lower()
        if parts.username is not None or parts.password is not None or not parts.hostname:
            return None
        if scheme == "https":
            return absolute
        if scheme == "http" and (self._allow_insecure_http or _is_local_host(parts.hostname)):
            return absolute
        return None


# --------------------------------------------------------------------------- #
# Module helpers
# --------------------------------------------------------------------------- #


def _server_unavailable(result: VelsigilResult) -> bool:
    """Whether ``result`` says the license server is unavailable (not that it refused the request).

    True for ``network_error`` (no HTTP answer, or a 502/503/504 without a
    Velsigil error body) and for any other unsigned HTTP 5xx answer
    (``http_status`` 500-599, whatever its body or code, typically
    ``internal_error``). Signed answers always arrive with HTTP 200, so a
    signed denial is never "unavailable"; neither are unsigned 4xx answers
    (``rate_limited``, ``validation_error``, ...), redirects or
    ``invalid_response`` on an HTTP 200. These are exactly the results on
    which :meth:`VelsigilClient.validate_with_offline_fallback` uses the
    stored offline lease.

    Falling back on an unsigned 5xx gives an attacker on the network nothing
    new: one who can inject such an answer can as well drop the connection,
    which already means ``network_error``; and the lease itself is signed,
    bound to this device and time-limited.
    """
    if result.ok or result.offline:
        return False
    status = result.http_status
    if status is None:
        # No HTTP answer at all (a signed answer always carries http_status 200, so it never gets here).
        return result.code == Code.NETWORK_ERROR
    return isinstance(status, int) and 500 <= status <= 599


def _unlink_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _read_capped(stream: Any, deadline: float) -> bytes:
    """Read a response body, enforcing the size cap and an overall deadline."""
    chunks = []
    total = 0
    while True:
        if time.monotonic() > deadline:
            raise socket.timeout("response deadline exceeded")
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise _ResponseTooLarge()
        chunks.append(chunk)
    return b"".join(chunks)


def _input_problem(
    license_key: Any = None,
    version: Any = None,
    device_name: Any = None,
    *,
    require_key: bool = True,
) -> Optional[VelsigilResult]:
    """Client-side input checks mirroring the server's limits (UX only).

    Returns a ``validation_error`` result instead of raising, so callers can
    pass user-entered values straight through.
    """
    if require_key:
        if not isinstance(license_key, str) or not license_key.strip():
            return _failure(Code.VALIDATION_ERROR, "A license key is required.")
        key = license_key.strip()
        if len(key) > MAX_LICENSE_KEY_LENGTH or _CONTROL_CHARS_RE.search(key):
            return _failure(Code.VALIDATION_ERROR, "The license key format is invalid.")
    if version is not None and version != "":
        if not isinstance(version, str) or len(version) > 32 or _CONTROL_CHARS_RE.search(version):
            return _failure(Code.VALIDATION_ERROR, "version must be a string of at most 32 characters.")
    if device_name is not None and device_name != "":
        if not isinstance(device_name, str) or len(device_name) > 255 or _CONTROL_CHARS_RE.search(device_name):
            return _failure(Code.VALIDATION_ERROR, "device_name must be a string of at most 255 characters.")
    return None


def _sanitize_request_id(value: Any) -> Optional[str]:
    if isinstance(value, str) and _REQUEST_ID_RE.match(value):
        return value
    return None


def _retry_after(status: Optional[int], headers: Any, now: float) -> Optional[int]:
    """Seconds to wait from the ``Retry-After`` header of an HTTP 429 or 503 answer (SPEC 14, every SDK).

    Every 429 and 503 counts, whatever code it maps to: ``rate_limited``,
    ``network_error`` for the server's empty 503 while its database is
    unreachable (CLIENT_PROTOCOL 5.3) or a gateway's 503, the code of a
    Velsigil error body such as 503 ``service_busy``. Delta-seconds or an
    HTTP-date (rounded up, measured from ``now``, the local clock), clamped to
    0..86400 (one day). ``None`` for every other status and when the header is
    absent or unparseable.
    """
    if status not in (429, 503):
        return None
    try:
        value = headers.get("Retry-After") if headers is not None else None
    except Exception:  # noqa: BLE001 - defensive against odd header objects
        return None
    if not isinstance(value, str):
        return None
    value = value.strip()
    if _DELTA_SECONDS_RE.match(value):
        digits = value.lstrip("0") or "0"
        return _MAX_RETRY_AFTER if len(digits) > 6 else min(int(digits), _MAX_RETRY_AFTER)
    try:
        when = parsedate_to_datetime(value)
        if when.tzinfo is None:  # "-0000" or no zone: an HTTP-date is always GMT
            when = when.replace(tzinfo=datetime.timezone.utc)
        seconds = math.ceil(when.timestamp() - now)
    except Exception:  # noqa: BLE001 - email.utils on odd input (some 3.x releases raise more than ValueError)
        # Never let a malformed header break the result: an exception here would turn a 503 into an
        # invalid_response without http_status, which validate_with_offline_fallback does not fall back on.
        return None
    return max(0, min(seconds, _MAX_RETRY_AFTER))


def _code_for_status(status: int, velsigil_body: bool) -> str:
    """Status fallback when an unsigned body carries no known code (SPEC 14, same in every SDK).

    ``velsigil_body``: the body is a Velsigil error object (``{"error": {"code": ...}}``).
    """
    if status == 400:
        return Code.VALIDATION_ERROR
    if status == 413:
        return Code.PAYLOAD_TOO_LARGE
    if status == 415:
        return Code.UNSUPPORTED_MEDIA_TYPE
    if status == 429:
        return Code.RATE_LIMITED
    if status in (502, 503, 504):
        # A gateway in front of Velsigil could not reach it: report it like an
        # unreachable server unless Velsigil itself answered with an error
        # body. (validate_with_offline_fallback falls back on every unsigned
        # 5xx either way, see _server_unavailable.)
        return Code.INTERNAL_ERROR if velsigil_body else Code.NETWORK_ERROR
    if 500 <= status <= 599:
        return Code.INTERNAL_ERROR
    return Code.INVALID_RESPONSE


def _unsigned_error(
    status: int, raw: bytes, headers: Any, response_type: Optional[str] = None, now: Optional[float] = None
) -> VelsigilResult:
    """Map an unsigned (non-200) response to a failure. Never yields ok=True.

    ``now``: the client's local clock (unix seconds) for an HTTP-date
    ``Retry-After``; the system clock when omitted.
    """
    code: Optional[str] = None
    request_id: Optional[str] = None
    velsigil_body = False
    try:
        document = json.loads(raw.decode("utf-8")) if raw else None
    except (ValueError, UnicodeDecodeError):
        document = None
    error = document.get("error") if isinstance(document, dict) else None
    if isinstance(error, dict) and isinstance(error.get("code"), str):
        velsigil_body = True
        if error["code"] in UNSIGNED_ERROR_CODES:
            code = error["code"]
        elif response_type == "trial" and status == 404 and error["code"] == "not_found":
            # A Velsigil server without the in-app trial endpoint answers its generic 404 (SPEC 14).
            code = Code.PANEL_TOO_OLD
        request_id = _sanitize_request_id(error.get("requestId"))
    if request_id is None and headers is not None:
        try:
            request_id = _sanitize_request_id(headers.get("X-Request-Id"))
        except Exception:  # noqa: BLE001
            request_id = None
    if code is None:
        code = _code_for_status(status, velsigil_body)
    return _failure(
        code,
        _UNSIGNED_MESSAGES.get(code, _UNSIGNED_MESSAGES[Code.INVALID_RESPONSE]),
        request_id=request_id,
        http_status=status,
        retry_after=_retry_after(status, headers, time.time() if now is None else now),
    )


def _optional(payload: Mapping[str, Any], key: str, parser: Callable[[Any], Any]) -> Any:
    value = payload.get(key)
    return None if value is None else parser(value)


def _trial_key(payload: Mapping[str, Any]) -> Optional[str]:
    """The key of a started trial (SPEC 10.1): required on an ``ok`` answer of
    type ``trial`` (raises ValueError when missing or malformed), never read
    from any other answer."""
    if payload.get("type") != "trial" or payload.get("ok") is not True:
        return None
    trial = payload.get("trial")
    key = trial.get("key") if isinstance(trial, Mapping) else None
    if not isinstance(key, str) or not _TRIAL_KEY_RE.match(key):
        raise ValueError("an ok trial answer must carry trial.key")
    return key


def _result_from_payload(payload: Mapping[str, Any]) -> VelsigilResult:
    """Build a result from a *verified* payload (raises ValueError on bad types)."""
    message = payload.get("message")
    return VelsigilResult(
        ok=payload["ok"] is True,
        code=payload["code"],
        message=message if isinstance(message, str) else "",
        # Only an ok answer grants features through the license-level helper too (MONEY-V1).
        license=_optional(payload, "license", lambda value: LicenseInfo.from_payload(value, granted=payload["ok"] is True)),
        activation=_optional(payload, "activation", ActivationInfo.from_payload),
        lease=_optional(payload, "lease", LeaseInfo.from_payload),
        update=_optional(payload, "update", UpdateInfo.from_payload),
        download=_optional(payload, "download", DownloadInfo.from_payload),
        request_id=_sanitize_request_id(payload.get("requestId")),
        server_time=as_int(payload.get("serverTime")),
        http_status=200,
        trial_key=_trial_key(payload),
    )


def _claim_str(claims: Mapping[str, Any], key: str) -> str:
    value = claims.get(key)
    if not isinstance(value, str):
        raise ValueError("lease %s must be a string" % key)
    return value


def _claim_opt_int(claims: Mapping[str, Any], key: str) -> Optional[int]:
    value = claims.get(key)
    if value is None:
        return None
    number = as_int(value)
    if number is None:
        raise ValueError("lease %s must be an integer" % key)
    return number


def _claim_trial(claims: Mapping[str, Any]) -> bool:
    """The optional signed ``trial`` flag of a lease (SPEC 9.7): absent/null -> False."""
    value = claims.get("trial")
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ValueError("lease trial must be a boolean")
    return value


def _claim_features(claims: Mapping[str, Any]) -> Tuple[str, ...]:
    value = claims.get("features")
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("lease features must be a list of strings")
    return tuple(value)


__all__ = ["VelsigilClient", "SDK_VERSION", "API_PATH", "DEFAULT_TIMEOUT", "MAX_RESPONSE_BYTES", "LEASE_REVOKING_CODES"]
