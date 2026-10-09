"""VelsigilClient behaviour against a local mock server that signs like Velsigil."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import mock_server as ms  # noqa: E402
from mock_server import (  # noqa: E402
    LICENSE_OBJ,
    PRODUCT_ID,
    PUBLIC_KEY,
    TEST_HWID,
    FakeClock,
    MockVelsigilServer,
    Reply,
    base_payload,
    make_lease,
    refused_url,
    sign_envelope,
)

from velsigil_client import (  # noqa: E402
    LEASE_REVOKING_CODES,
    Code,
    ConfigurationError,
    DownloadError,
    Ed25519Verifier,
    FileStore,
    HardwareIdError,
    LicenseStore,
    MemoryStore,
    StoredState,
    VelsigilClient,
    VelsigilResult,
    get_hardware_id,
    key_id_for,
)
from velsigil_client import client as client_module  # noqa: E402
from velsigil_client.client import MAX_RESPONSE_BYTES  # noqa: E402
from velsigil_client.crypto import _decode_public_key, open_envelope, verify_lease  # noqa: E402
from velsigil_client.models import LicenseInfo  # noqa: E402

LICENSE_KEY = "VSG-ABCDE-FGHJK-LMNPQ-RSTVW-XYZ23"
DEVICE_SECRET = "dsk_Xq3vR9mT2pL8wN5kJ7hG4fD1sA6zC0bV9yU2iO3eW4r"
ACTIVATION_ID = "9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d"
FILE_BYTES = b"Velsigil release payload\n" * 1000
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


class LicenseServerLogic:
    """Stateful happy-path server: issues the device secret once, leases, updates."""

    def __init__(self, clock=None, lease_seconds=86400):
        self.clock = clock or time.time
        self.lease_seconds = lease_seconds
        self.secret_issued = False
        self.override = None  # callable(request) -> Optional[Reply]
        self.file_bytes = FILE_BYTES  # what GET /api/download/* serves
        self.signed_file_bytes = FILE_BYTES  # what the signed size/sha256 describe
        self.download_url = "/api/download/tok_abc123"

    def __call__(self, request):
        if self.override is not None:
            reply = self.override(request)
            if reply is not None:
                return reply
        body = request.body
        now = int(self.clock())
        path = request.path
        if request.method == "GET" and path.startswith("/api/download/"):
            return Reply(200, self.file_bytes)
        if path.endswith("/api/client/v1/validate"):
            payload = base_payload(body, "validate", True, "ok", "License is valid.", server_time=now)
            payload["license"] = dict(LICENSE_OBJ)
            issue = not self.secret_issued
            self.secret_issued = True
            payload["activation"] = {
                "id": ACTIVATION_ID,
                "status": "active",
                "firstSeenAt": now,
                "deviceSecret": DEVICE_SECRET if issue else None,
            }
            if self.lease_seconds:
                exp = now + self.lease_seconds
                payload["lease"] = {"token": make_lease(exp, hwid=TEST_HWID), "expiresAt": exp}
            payload["update"] = {
                "latestVersion": "1.4.0",
                "minVersion": "1.0.0",
                "updateAvailable": True,
                "mandatory": False,
                "changelog": "Bug fixes.",
            }
            return Reply(200, sign_envelope(payload))
        if path.endswith("/api/client/v1/deactivate"):
            return Reply(200, sign_envelope(base_payload(body, "deactivate", True, "ok", "Device removed.", now)))
        if path.endswith("/api/client/v1/update-check"):
            payload = base_payload(body, "update_check", True, "ok", "Update available.", now)
            payload["update"] = {
                "latestVersion": "1.4.0",
                "minVersion": None,
                "updateAvailable": True,
                "mandatory": True,
                "changelog": "Security fixes.",
            }
            return Reply(200, sign_envelope(payload))
        if path.endswith("/api/client/v1/download"):
            payload = base_payload(body, "download", True, "ok", "Download ready.", now)
            payload["download"] = {
                "url": self.download_url,
                "expiresAt": now + 600,
                "fileName": "app-1.4.0.zip",
                "size": len(self.signed_file_bytes),
                "sha256": hashlib.sha256(self.signed_file_bytes).hexdigest(),
                "version": "1.4.0",
            }
            return Reply(200, sign_envelope(payload))
        return Reply(404, {"error": {"code": "not_found", "message": "Not found.", "requestId": "rid-404"}})


def signed(request, code, ok=False, type_="validate", seed=ms.SEED, **fields):
    payload = base_payload(request.body, type_, ok, code, code.replace("_", " "))
    payload.update(fields)
    return Reply(200, sign_envelope(payload, seed))


class ClientTestCase(unittest.TestCase):
    def start(self, handler):
        server = MockVelsigilServer(handler)
        self.addCleanup(server.close)
        return server

    def make_client(self, url, **options):
        options.setdefault("hwid", TEST_HWID)
        options.setdefault("timeout", 5)
        return VelsigilClient(url, PRODUCT_ID, PUBLIC_KEY, **options)

    def assertFailure(self, result, code):
        self.assertFalse(result.ok, result)
        self.assertEqual(result.code, code, result)
        self.assertFalse(result.has_feature("pro"))
        self.assertEqual(result.features, ())
        if result.license is not None:
            self.assertFalse(result.license.has_feature("pro"))


class DenialFeatureTests(ClientTestCase):
    """A signed denial never unlocks a feature, not even through ``license.has_feature``."""

    def test_denials_with_features_grant_nothing(self):
        logic = LicenseServerLogic()
        server = self.start(logic)
        client = self.make_client(server.url)
        for code, status in (
            ("license_revoked", "revoked"),
            ("license_banned", "banned"),
            ("license_suspended", "suspended"),
            ("license_expired", "expired"),
            ("device_limit_reached", "active"),
        ):
            with self.subTest(code=code):
                # An older server still listed the plan's features on a denial.
                lic = dict(LICENSE_OBJ, status=status)
                logic.override = lambda request, c=code, l=lic: signed(request, c, license=l)
                result = client.validate(LICENSE_KEY)
                self.assertFailure(result, code)
                self.assertEqual(result.license.status, status)
                self.assertEqual(result.license.features, ("pro", "export"))
                self.assertFalse(result.license.has_feature("pro"))

    def test_ok_result_and_hand_made_license(self):
        logic = LicenseServerLogic()
        server = self.start(logic)
        result = self.make_client(server.url).validate(LICENSE_KEY)
        self.assertTrue(result.ok, result)
        self.assertTrue(result.license.has_feature("pro"))
        self.assertTrue(result.has_feature("pro"))
        # Built outside the SDK: grants nothing.
        self.assertFalse(LicenseInfo.from_payload(LICENSE_OBJ).has_feature("pro"))


class ValidateTests(ClientTestCase):
    def test_validate_ok_and_request_shape(self):
        logic = LicenseServerLogic()
        server = self.start(logic)
        client = self.make_client(server.url)
        result = client.validate(LICENSE_KEY, version="1.2.0", device_name="Build agent")

        self.assertTrue(result.ok, result)
        self.assertEqual(result.code, Code.OK)
        self.assertEqual(result.message, "License is valid.")
        self.assertFalse(result.offline)
        self.assertEqual(result.license.id, LICENSE_OBJ["id"])
        self.assertEqual(result.license.plan, "Monthly")
        self.assertEqual(result.license.features, ("pro", "export"))
        self.assertTrue(result.has_feature("pro"))
        self.assertFalse(result.has_feature("enterprise"))
        self.assertEqual(result.expires_at, LICENSE_OBJ["expiresAt"])
        self.assertFalse(result.is_lifetime)
        self.assertEqual(result.days_remaining(now=LICENSE_OBJ["expiresAt"] - 86400 * 2 - 10), 3)
        self.assertEqual(result.seconds_remaining(now=LICENSE_OBJ["expiresAt"] + 5), 0.0)
        self.assertTrue(result.is_expired(now=LICENSE_OBJ["expiresAt"]))
        self.assertEqual(result.activation.id, ACTIVATION_ID)
        self.assertTrue(result.activation.device_secret_issued)
        self.assertEqual(result.update.latest_version, "1.4.0")
        self.assertTrue(result.update.update_available)
        self.assertIsNotNone(result.lease)
        self.assertRegex(result.request_id, r"^[0-9a-f-]{36}$")

        self.assertEqual(len(server.requests), 1)
        request = server.requests[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.path, "/api/client/v1/validate")
        self.assertEqual(request.headers.get("Content-Type"), "application/json")
        self.assertTrue(request.headers.get("User-Agent", "").startswith("velsigil-client-python/"))
        body = request.body
        self.assertEqual(
            set(body), {"productId", "licenseKey", "hwid", "version", "deviceName", "nonce", "timestamp"}
        )
        self.assertEqual(body["productId"], PRODUCT_ID)
        self.assertEqual(body["licenseKey"], LICENSE_KEY)
        self.assertEqual(body["hwid"], TEST_HWID)
        self.assertEqual(body["version"], "1.2.0")
        self.assertEqual(body["deviceName"], "Build agent")
        self.assertRegex(body["nonce"], NONCE_RE)
        self.assertIsInstance(body["timestamp"], int)
        self.assertLessEqual(abs(body["timestamp"] - time.time()), 5)

    def test_fresh_nonce_per_request(self):
        server = self.start(LicenseServerLogic())
        client = self.make_client(server.url)
        for _ in range(3):
            self.assertTrue(client.validate(LICENSE_KEY).ok)
        nonces = [body["nonce"] for body in server.bodies("/validate")]
        self.assertEqual(len(set(nonces)), 3)

    def test_device_secret_persisted_and_resent(self):
        logic = LicenseServerLogic()
        server = self.start(logic)
        store = MemoryStore()
        client = self.make_client(server.url, store=store)

        self.assertTrue(client.validate(LICENSE_KEY).ok)
        self.assertEqual(store.load(PRODUCT_ID).device_secret, DEVICE_SECRET)
        second = client.validate(LICENSE_KEY)
        self.assertTrue(second.ok)
        self.assertFalse(second.activation.device_secret_issued)
        bodies = server.bodies("/validate")
        self.assertNotIn("deviceSecret", bodies[0])
        self.assertEqual(bodies[1]["deviceSecret"], DEVICE_SECRET)
        self.assertEqual(store.load(PRODUCT_ID).device_secret, DEVICE_SECRET)

    def test_device_secret_survives_restart_with_file_store(self):
        server = self.start(LicenseServerLogic())
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state", "license.json")
            first = self.make_client(server.url, store=FileStore(path))
            self.assertTrue(first.validate(LICENSE_KEY).ok)
            with open(path, "r", encoding="utf-8") as handle:
                document = json.load(handle)
            self.assertEqual(document["products"][PRODUCT_ID]["deviceSecret"], DEVICE_SECRET)

            restarted = self.make_client(server.url, store=FileStore(path))
            self.assertTrue(restarted.validate(LICENSE_KEY).ok)
            self.assertTrue(restarted.deactivate(LICENSE_KEY).ok)
            bodies = server.bodies("/validate") + server.bodies("/deactivate")
            self.assertEqual(bodies[1]["deviceSecret"], DEVICE_SECRET)
            self.assertEqual(bodies[2]["deviceSecret"], DEVICE_SECRET)

    def test_business_failure_is_returned_not_raised(self):
        logic = LicenseServerLogic()
        server = self.start(logic)
        store = MemoryStore()
        client = self.make_client(server.url, store=store)
        self.assertTrue(client.validate(LICENSE_KEY).ok)
        self.assertIsNotNone(store.load(PRODUCT_ID).lease_token)

        suspended = dict(LICENSE_OBJ, status="suspended")
        logic.override = lambda request: signed(request, "license_suspended", license=suspended)
        result = client.validate(LICENSE_KEY)
        self.assertFailure(result, Code.LICENSE_SUSPENDED)
        self.assertEqual(result.message, "license suspended")
        self.assertEqual(result.license.status, "suspended")
        self.assertIsNotNone(result.request_id)
        state = store.load(PRODUCT_ID)
        self.assertIsNone(state.lease_token)
        self.assertEqual(state.device_secret, DEVICE_SECRET)

    def test_nonce_mismatch_rejected(self):
        def handler(request):
            payload = base_payload(request.body, "validate", True, "ok", "License is valid.")
            payload["nonce"] = "a-different-nonce-0000000000"
            payload["license"] = dict(LICENSE_OBJ)
            return Reply(200, sign_envelope(payload))

        server = self.start(handler)
        result = self.make_client(server.url).validate(LICENSE_KEY)
        self.assertFailure(result, Code.INVALID_RESPONSE)
        self.assertIsNone(result.license)

    def test_replayed_response_rejected(self):
        captured = {}

        def handler(request):
            if "reply" not in captured:
                captured["reply"] = signed(request, "ok", ok=True, license=dict(LICENSE_OBJ))
            return captured["reply"]  # replays the first signed response

        server = self.start(handler)
        client = self.make_client(server.url)
        self.assertTrue(client.validate(LICENSE_KEY).ok)
        self.assertFailure(client.validate(LICENSE_KEY), Code.INVALID_RESPONSE)

    def test_product_mismatch_rejected(self):
        def handler(request):
            payload = base_payload(request.body, "validate", True, "ok")
            payload["productId"] = "7c3e9a10-1b2c-4d5e-8f90-a1b2c3d4e5f6"
            return Reply(200, sign_envelope(payload))

        server = self.start(handler)
        self.assertFailure(self.make_client(server.url).validate(LICENSE_KEY), Code.INVALID_RESPONSE)

    def test_bad_signature_rejected(self):
        def wrong_key(request):
            return signed(request, "ok", ok=True, seed=ms.WRONG_SEED, license=dict(LICENSE_OBJ))

        def tampered(request):
            envelope = signed(request, "ok", ok=False).body
            forged = base_payload(request.body, "validate", True, "ok")
            envelope["data"] = ms.encode_payload(forged)
            return Reply(200, envelope)

        def unsigned_envelope(request):
            envelope = signed(request, "ok", ok=True).body
            del envelope["sig"]
            return Reply(200, envelope)

        for handler in (wrong_key, tampered, unsigned_envelope):
            with self.subTest(handler=handler.__name__):
                server = self.start(handler)
                store = MemoryStore()
                result = self.make_client(server.url, store=store).validate(LICENSE_KEY)
                self.assertFailure(result, Code.INVALID_RESPONSE)
                self.assertTrue(store.load(PRODUCT_ID).is_empty)

    def test_type_mismatch_rejected(self):
        server = self.start(lambda request: signed(request, "ok", ok=True, type_="deactivate"))
        self.assertFailure(self.make_client(server.url).validate(LICENSE_KEY), Code.INVALID_RESPONSE)

    def test_signed_payload_with_bad_field_types_rejected(self):
        server = self.start(lambda request: signed(request, "ok", ok=True, license={"id": 5}))
        self.assertFailure(self.make_client(server.url).validate(LICENSE_KEY), Code.INVALID_RESPONSE)

    def test_unsigned_success_is_never_ok(self):
        bodies = [
            {"ok": True, "code": "ok", "license": LICENSE_OBJ},
            {"data": ms.encode_payload({"ok": True}), "sig": "", "kid": ms.KEY_ID},
            b"<html>captive portal</html>",
            b"",
        ]
        for body in bodies:
            with self.subTest(body=str(body)[:40]):
                server = self.start(lambda request, body=body: Reply(200, body))
                self.assertFailure(self.make_client(server.url).validate(LICENSE_KEY), Code.INVALID_RESPONSE)

    def test_clock_skew_learns_offset_and_retries_once(self):
        skew = 3600

        def handler(request):
            server_now = int(time.time()) + skew
            if abs(request.body["timestamp"] - server_now) > 300:
                return Reply(200, sign_envelope(base_payload(request.body, "validate", False, "clock_skew", "", server_now)))
            return signed(request, "ok", ok=True, license=dict(LICENSE_OBJ))

        server = self.start(handler)
        client = self.make_client(server.url)
        result = client.validate(LICENSE_KEY)
        self.assertTrue(result.ok, result)
        self.assertAlmostEqual(client.clock_offset, skew, delta=2)
        bodies = server.bodies("/validate")
        self.assertEqual(len(bodies), 2)
        self.assertNotEqual(bodies[0]["nonce"], bodies[1]["nonce"])
        self.assertAlmostEqual(bodies[1]["timestamp"], time.time() + skew, delta=5)
        self.assertTrue(client.validate(LICENSE_KEY).ok)
        self.assertEqual(len(server.bodies("/validate")), 3)

    def test_clock_skew_retry_happens_only_once(self):
        def handler(request):
            server_time = request.body["timestamp"] + 10000  # always "skewed"
            return Reply(200, sign_envelope(base_payload(request.body, "validate", False, "clock_skew", "", server_time)))

        server = self.start(handler)
        result = self.make_client(server.url).validate(LICENSE_KEY)
        self.assertFailure(result, Code.CLOCK_SKEW)
        self.assertEqual(len(server.requests), 2)

    def test_forged_clock_skew_is_ignored(self):
        def handler(request):
            payload = base_payload(request.body, "validate", False, "clock_skew", "", int(time.time()) + 99999)
            return Reply(200, sign_envelope(payload, ms.WRONG_SEED))

        server = self.start(handler)
        client = self.make_client(server.url)
        self.assertFailure(client.validate(LICENSE_KEY), Code.INVALID_RESPONSE)
        self.assertEqual(client.clock_offset, 0)
        self.assertEqual(len(server.requests), 1)

    def test_input_validation_without_network(self):
        server = self.start(LicenseServerLogic())
        client = self.make_client(server.url)
        for key in ("", "   ", None, 12345, "K" * 65, "VSG-\x00ABC"):
            with self.subTest(key=key):
                self.assertFailure(client.validate(key), Code.VALIDATION_ERROR)  # type: ignore[arg-type]
        self.assertFailure(client.validate(LICENSE_KEY, version="1" * 33), Code.VALIDATION_ERROR)
        self.assertFailure(client.validate(LICENSE_KEY, device_name="x" * 256), Code.VALIDATION_ERROR)
        self.assertFailure(client.check_update(current_version="v\n1"), Code.VALIDATION_ERROR)
        self.assertEqual(server.requests, [])


class HttpErrorTests(ClientTestCase):
    def _error(self, status, code, headers=None):
        body = {"error": {"code": code, "message": "server text", "requestId": "3f2e1d0c-0000-4000-8000-000000000000"}}
        return lambda request: Reply(status, body, headers=headers)

    def test_rate_limited_429(self):
        server = self.start(self._error(429, "rate_limited", {"Retry-After": "30"}))
        result = self.make_client(server.url).validate(LICENSE_KEY)
        self.assertFailure(result, Code.RATE_LIMITED)
        self.assertEqual(result.retry_after, 30)
        self.assertEqual(result.http_status, 429)
        self.assertEqual(result.request_id, "3f2e1d0c-0000-4000-8000-000000000000")

    def test_retry_after_on_every_429_and_503(self):
        def answer(status, body, retry_after=None):
            return Reply(status, body, headers=None if retry_after is None else {"Retry-After": retry_after})

        busy = {"error": {"code": "service_busy", "message": "Busy.", "requestId": "rid-busy"}}
        internal = {"error": {"code": "internal_error"}}
        limited = {"error": {"code": "rate_limited"}}
        redirect = Reply(307, b"", headers={"Location": "http://127.0.0.1:9/x", "Retry-After": "30"})
        cases = (
            ("503 empty body (database unreachable)", answer(503, None, "30"), Code.NETWORK_ERROR, 30),
            ("503 Velsigil service_busy", answer(503, busy, "5"), Code.INTERNAL_ERROR, 5),
            ("503 Velsigil internal_error", answer(503, internal, "7"), Code.INTERNAL_ERROR, 7),
            ("503 proxy HTML", answer(503, b"<html>Service Unavailable</html>", "120"), Code.NETWORK_ERROR, 120),
            ("503 naming a 4xx code", answer(503, limited, "9"), Code.RATE_LIMITED, 9),
            ("429 rate_limited", answer(429, limited, "30"), Code.RATE_LIMITED, 30),
            ("429 without body", answer(429, b"", "12"), Code.RATE_LIMITED, 12),
            ("503 without Retry-After", answer(503, None), Code.NETWORK_ERROR, None),
            ("503 unparseable Retry-After", answer(503, None, "soon"), Code.NETWORK_ERROR, None),
            # str.isdigit() accepts superscript digits; int() does not.
            ("503 non-ASCII digits", answer(503, None, "\u00b3"), Code.NETWORK_ERROR, None),
            ("429 non-ASCII digits", answer(429, b"", "\u00b3"), Code.RATE_LIMITED, None),
            ("429 negative delta", answer(429, b"", "-5"), Code.RATE_LIMITED, None),
            ("503 delta capped at one day", answer(503, None, "999999999999"), Code.NETWORK_ERROR, 86400),
            ("503 zero", answer(503, None, " 0 "), Code.NETWORK_ERROR, 0),
            ("500 internal_error", answer(500, internal, "30"), Code.INTERNAL_ERROR, None),
            ("502 proxy HTML", answer(502, b"<html>Bad Gateway</html>", "30"), Code.NETWORK_ERROR, None),
            ("504 empty body", answer(504, b"", "30"), Code.NETWORK_ERROR, None),
            ("400 validation_error", answer(400, {"error": {"code": "validation_error"}}, "30"), Code.VALIDATION_ERROR, None),
            ("307 redirect", redirect, Code.INVALID_RESPONSE, None),
        )
        server = self.start(None)
        client = self.make_client(server.url)
        for name, reply, code, retry_after in cases:
            with self.subTest(case=name):
                server.handler = lambda request, r=reply: r
                result = client.validate(LICENSE_KEY)
                self.assertFailure(result, code)
                self.assertEqual(result.retry_after, retry_after)
                self.assertFalse(result.offline)

    def test_retry_after_http_date(self):
        clock = FakeClock(1767225600)  # Thu, 01 Jan 2026 00:00:00 GMT
        server = self.start(None)
        client = self.make_client(server.url, clock=clock)
        cases = (
            ("IMF-fixdate", "Thu, 01 Jan 2026 00:01:30 GMT", 503, 90),
            ("IMF-fixdate on a 429", "Thu, 01 Jan 2026 00:00:45 GMT", 429, 45),
            ("RFC 850", "Thursday, 01-Jan-26 00:02:00 GMT", 503, 120),
            ("asctime", "Thu Jan  1 00:00:10 2026", 503, 10),
            ("in the past", "Wed, 31 Dec 2025 23:59:00 GMT", 503, 0),
            ("capped at one day", "Sat, 03 Jan 2026 00:00:00 GMT", 503, 86400),
            ("invalid day", "Sat, 31 Feb 2026 00:00:00 GMT", 503, None),
            ("not a date", "Thu, 01 Jan 2026 nope", 503, None),
        )
        for name, value, status, expected in cases:
            with self.subTest(case=name):
                server.handler = lambda request, s=status, v=value: Reply(s, None, headers={"Retry-After": v})
                self.assertEqual(client.validate(LICENSE_KEY).retry_after, expected)
        clock.now = 1767225600.25
        server.handler = lambda request: Reply(503, None, headers={"Retry-After": "Thu, 01 Jan 2026 00:01:30 GMT"})
        self.assertEqual(client.validate(LICENSE_KEY).retry_after, 90)

    def test_retry_after_of_an_oversized_503(self):
        server = self.start(lambda request: Reply(503, b"x" * (MAX_RESPONSE_BYTES + 1), headers={"Retry-After": "30"}))
        result = self.make_client(server.url).validate(LICENSE_KEY)
        self.assertFailure(result, Code.INVALID_RESPONSE)
        self.assertEqual(result.http_status, 503)
        self.assertEqual(result.retry_after, 30)

    def test_validation_error_400(self):
        server = self.start(self._error(400, "validation_error"))
        result = self.make_client(server.url).validate(LICENSE_KEY)
        self.assertFailure(result, Code.VALIDATION_ERROR)
        self.assertEqual(result.http_status, 400)

    def test_ip_blocked_and_unknown_product(self):
        for status, code in ((403, Code.IP_BLOCKED), (404, Code.UNKNOWN_PRODUCT)):
            with self.subTest(code=code):
                server = self.start(self._error(status, code))
                self.assertFailure(self.make_client(server.url).validate(LICENSE_KEY), code)

    def test_internal_error_500(self):
        server = self.start(self._error(500, "internal_error"))
        result = self.make_client(server.url).validate(LICENSE_KEY)
        self.assertFailure(result, Code.INTERNAL_ERROR)
        self.assertNotIn("server text", result.message)

    def test_status_fallbacks_without_error_body(self):
        cases = ((429, Code.RATE_LIMITED), (500, Code.INTERNAL_ERROR), (503, Code.NETWORK_ERROR), (418, Code.INVALID_RESPONSE))
        for status, code in cases:
            with self.subTest(status=status):
                server = self.start(lambda request, status=status: Reply(status, b"oops"))
                self.assertFailure(self.make_client(server.url).validate(LICENSE_KEY), code)

    def test_gateway_status_mapping_follows_the_cross_sdk_rule(self):
        cases = (
            (502, b"<html>Bad Gateway</html>", Code.NETWORK_ERROR),
            (503, {"message": "Service Unavailable"}, Code.NETWORK_ERROR),
            (504, b"", Code.NETWORK_ERROR),
            (503, {"error": {"code": "internal_error"}}, Code.INTERNAL_ERROR),
            (502, {"error": {"code": "something_new"}}, Code.INTERNAL_ERROR),
            (413, b"", Code.PAYLOAD_TOO_LARGE),
            (415, b"<html>no</html>", Code.UNSUPPORTED_MEDIA_TYPE),
            (400, b"", Code.VALIDATION_ERROR),
        )
        for status, body, code in cases:
            with self.subTest(status=status, body=str(body)[:30]):
                server = self.start(lambda request, s=status, b=body: Reply(s, b))
                self.assertFailure(self.make_client(server.url).validate(LICENSE_KEY), code)

    def test_unsigned_codes_are_whitelisted(self):
        for status, code, expected in ((400, "ok", Code.VALIDATION_ERROR), (429, "license_valid", Code.RATE_LIMITED)):
            with self.subTest(code=code):
                body = {"ok": True, "error": {"code": code, "message": "ok"}}
                server = self.start(lambda request, s=status, b=body: Reply(s, b))
                self.assertFailure(self.make_client(server.url).validate(LICENSE_KEY), expected)

    def test_signed_envelope_on_error_status_is_not_trusted(self):
        server = self.start(lambda request: Reply(500, signed(request, "ok", ok=True).body))
        self.assertFailure(self.make_client(server.url).validate(LICENSE_KEY), Code.INTERNAL_ERROR)

    def test_redirect_not_followed(self):
        server = self.start(lambda request: Reply(307, b"", headers={"Location": "http://example.invalid/steal"}))
        result = self.make_client(server.url).validate(LICENSE_KEY)
        self.assertFailure(result, Code.INVALID_RESPONSE)
        self.assertEqual(result.http_status, 307)
        self.assertEqual(len(server.requests), 1)

    def test_oversized_response_rejected(self):
        server = self.start(lambda request: Reply(200, b"x" * (MAX_RESPONSE_BYTES + 1)))
        self.assertFailure(self.make_client(server.url).validate(LICENSE_KEY), Code.INVALID_RESPONSE)

    def test_timeout_is_network_error(self):
        server = self.start(lambda request: Reply(200, signed(request, "ok", ok=True).body, delay=5))
        client = self.make_client(server.url, timeout=0.5)
        started = time.monotonic()
        result = client.validate(LICENSE_KEY)
        self.assertFailure(result, Code.NETWORK_ERROR)
        self.assertLess(time.monotonic() - started, 4)

    def test_connection_refused_is_network_error(self):
        result = self.make_client(refused_url()).validate(LICENSE_KEY)
        self.assertFailure(result, Code.NETWORK_ERROR)
        self.assertIsNone(result.http_status)


class OfflineTests(ClientTestCase):
    def test_offline_fallback_with_stored_lease_and_fake_clock(self):
        clock = FakeClock(1767225600)
        store = MemoryStore()
        server = self.start(LicenseServerLogic(clock=clock, lease_seconds=86400))
        online = self.make_client(server.url, store=store, clock=clock)
        first = online.validate(LICENSE_KEY)
        self.assertTrue(first.ok, first)
        self.assertEqual(store.load(PRODUCT_ID).lease_token, first.lease.token)
        self.assertEqual(first.lease.expires_at, 1767225600 + 86400)

        offline = self.make_client(refused_url(), store=store, clock=clock)
        clock.advance(3600)
        result = offline.validate_with_offline_fallback(LICENSE_KEY)
        self.assertTrue(result.ok, result)
        self.assertTrue(result.offline)
        self.assertEqual(result.code, Code.OK)
        self.assertTrue(result.has_feature("export"))
        self.assertEqual(result.license.id, LICENSE_OBJ["id"])
        self.assertEqual(result.license.plan, "Monthly")
        self.assertEqual(result.activation.id, ACTIVATION_ID)
        self.assertEqual(result.lease.expires_at, 1767225600 + 86400)

        clock.advance(86400)
        expired = offline.validate_with_offline_fallback(LICENSE_KEY)
        self.assertFailure(expired, Code.LEASE_EXPIRED)
        self.assertTrue(expired.offline)
        self.assertIsNone(expired.http_status)
        self.assertFailure(offline.validate_offline(), Code.LEASE_EXPIRED)
        self.assertEqual(store.load(PRODUCT_ID).lease_token, first.lease.token)

    def test_gateway_outage_falls_back(self):
        clock = FakeClock(1767225600)
        store = MemoryStore()
        logic = LicenseServerLogic(clock=clock)
        server = self.start(logic)
        client = self.make_client(server.url, store=store, clock=clock)
        self.assertTrue(client.validate(LICENSE_KEY).ok)
        logic.override = lambda request: Reply(502, b"Bad Gateway")
        result = client.validate_with_offline_fallback(LICENSE_KEY)
        self.assertTrue(result.ok and result.offline, result)

    def test_no_fallback_on_business_failure(self):
        store = MemoryStore()
        logic = LicenseServerLogic()
        server = self.start(logic)
        client = self.make_client(server.url, store=store)
        self.assertTrue(client.validate(LICENSE_KEY).ok)
        logic.override = lambda request: signed(request, "license_revoked")
        result = client.validate_with_offline_fallback(LICENSE_KEY)
        self.assertFailure(result, Code.LICENSE_REVOKED)
        self.assertFalse(result.offline)
        self.assertFailure(client.validate_offline(), Code.NO_LEASE)

    def test_no_fallback_on_rate_limit_or_invalid_response(self):
        store = MemoryStore()
        logic = LicenseServerLogic()
        server = self.start(logic)
        client = self.make_client(server.url, store=store)
        self.assertTrue(client.validate(LICENSE_KEY).ok)
        replies = {
            Code.RATE_LIMITED: lambda request: Reply(429, {"error": {"code": "rate_limited"}}),
            Code.INVALID_RESPONSE: lambda request: signed(request, "ok", ok=True, seed=ms.WRONG_SEED),
            Code.VALIDATION_ERROR: lambda request: Reply(400, {"error": {"code": "validation_error"}}),
        }
        for code, reply in replies.items():
            with self.subTest(code=code):
                logic.override = reply
                result = client.validate_with_offline_fallback(LICENSE_KEY)
                self.assertFailure(result, code)
                self.assertFalse(result.offline)
        self.assertTrue(client.validate_offline().ok)

    def test_lease_dropped_for_exactly_the_binding_denial_set(self):
        binding = {
            "invalid_key",
            "license_expired",
            "license_suspended",
            "license_revoked",
            "license_banned",
            "device_revoked",
            "device_verification_failed",
            "device_limit_reached",
            "device_not_activated",
            "device_not_found",
            "blacklisted",
            "product_disabled",
        }
        self.assertEqual(set(LEASE_REVOKING_CODES), binding)
        for code in sorted(binding):
            with self.subTest(code=code):
                store = MemoryStore()
                logic = LicenseServerLogic()
                server = self.start(logic)
                client = self.make_client(server.url, store=store)
                self.assertTrue(client.validate(LICENSE_KEY).ok)
                self.assertTrue(client.validate_offline().ok)
                logic.override = lambda request, c=code: signed(request, c)
                self.assertFailure(client.validate(LICENSE_KEY), code)
                self.assertFailure(client.validate_offline(), Code.NO_LEASE)
                self.assertEqual(store.load(PRODUCT_ID).device_secret, DEVICE_SECRET)

    def test_lease_kept_on_non_definitive_signed_failures(self):
        store = MemoryStore()
        logic = LicenseServerLogic()
        server = self.start(logic)
        client = self.make_client(server.url, store=store)
        self.assertTrue(client.validate(LICENSE_KEY).ok)
        for code in (
            "product_paused",
            "outdated_version",
            "activation_rate_limited",
            "activations_disabled",
            "replay_detected",
            "trial_already_used",
        ):
            with self.subTest(code=code):
                logic.override = lambda request, c=code: signed(request, c)
                self.assertFailure(client.validate(LICENSE_KEY), code)
                self.assertTrue(client.validate_offline().ok)

    def test_free_trial_flag_online_and_offline(self):
        clock = FakeClock(1767225600)
        store = MemoryStore()
        logic = LicenseServerLogic(clock=clock)

        def trial_reply(request):
            now = int(clock())
            payload = base_payload(request.body, "validate", True, "ok", "License is valid.", server_time=now)
            payload["license"] = dict(LICENSE_OBJ, plan="Trial", trial=True)
            payload["activation"] = {"id": ACTIVATION_ID, "status": "active", "firstSeenAt": now, "deviceSecret": None}
            payload["lease"] = {"token": make_lease(now + 3600, trial=True), "expiresAt": now + 3600}
            return Reply(200, sign_envelope(payload))

        logic.override = trial_reply
        server = self.start(logic)
        client = self.make_client(server.url, store=store, clock=clock)
        online = client.validate(LICENSE_KEY)
        self.assertTrue(online.ok, online)
        self.assertTrue(online.is_trial)
        self.assertTrue(online.license.is_trial)

        clock.advance(60)
        offline = self.make_client(refused_url(), store=store, clock=clock).validate_with_offline_fallback(LICENSE_KEY)
        self.assertTrue(offline.ok and offline.offline, offline)
        self.assertTrue(offline.is_trial)

        logic.override = None
        paid = client.validate(LICENSE_KEY)
        self.assertTrue(paid.ok, paid)
        self.assertFalse(paid.is_trial)

    def test_non_boolean_trial_field_is_invalid(self):
        logic = LicenseServerLogic()
        logic.override = lambda request: signed(request, "ok", ok=True, license=dict(LICENSE_OBJ, trial="yes"))
        server = self.start(logic)
        self.assertFailure(self.make_client(server.url).validate(LICENSE_KEY), Code.INVALID_RESPONSE)

    def test_validate_offline_without_lease(self):
        client = self.make_client(refused_url())
        result = client.validate_offline()
        self.assertFailure(result, Code.NO_LEASE)
        self.assertTrue(result.offline)
        plain = client.validate(LICENSE_KEY)
        fallback = client.validate_with_offline_fallback(LICENSE_KEY)
        self.assertFailure(fallback, Code.NETWORK_ERROR)
        self.assertFalse(fallback.offline)
        self.assertIsNone(fallback.http_status)
        self.assertEqual(fallback.message, plain.message)

    def test_tampered_or_foreign_stored_lease_rejected(self):
        exp = int(time.time()) + 3600
        good = make_lease(exp)
        body, sig = good.split(".")
        cases = {
            "tampered": ms.encode_payload({"v": 1, "typ": "lease", "productId": PRODUCT_ID}) + "." + sig,
            "other device": make_lease(exp, hwid="someone-else-0001"),
            "other product": make_lease(exp, product_id="7c3e9a10-1b2c-4d5e-8f90-a1b2c3d4e5f6"),
            "wrong key": make_lease(exp, seed_b64=ms.WRONG_SEED),
            "not a lease": make_lease(exp, typ="session"),
        }
        for name, token in cases.items():
            with self.subTest(case=name):
                store = MemoryStore()
                store.save(PRODUCT_ID, StoredState(lease_token=token))
                client = self.make_client(refused_url(), store=store)
                result = client.validate_offline()
                self.assertFailure(result, Code.LEASE_INVALID)
                fallback = client.validate_with_offline_fallback(LICENSE_KEY)
                self.assertFailure(fallback, Code.LEASE_INVALID)
                self.assertTrue(fallback.offline)
                self.assertIsNone(fallback.http_status)
                self.assertEqual(store.load(PRODUCT_ID), StoredState(lease_token=token))
        store = MemoryStore()
        store.save(PRODUCT_ID, StoredState(lease_token=good))
        self.assertTrue(self.make_client(refused_url(), store=store).validate_offline().ok)

    def test_success_with_lease_for_other_device_is_rejected(self):
        # Simulates a license-sharing proxy: the signed lease belongs to another device.
        own_lease = make_lease(int(time.time()) + 3600)
        store = MemoryStore()
        store.save(PRODUCT_ID, StoredState(device_secret=DEVICE_SECRET, lease_token=own_lease))
        logic = LicenseServerLogic()

        def handler(request):
            exp = int(time.time()) + 7200
            return signed(
                request,
                "ok",
                ok=True,
                license=dict(LICENSE_OBJ),
                activation={"id": ACTIVATION_ID, "status": "active", "firstSeenAt": 1, "deviceSecret": "dsk_" + "Z" * 40},
                lease={"token": make_lease(exp, hwid="another-device-hwid"), "expiresAt": exp},
            )

        logic.override = handler
        server = self.start(logic)
        client = self.make_client(server.url, store=store)
        result = client.validate(LICENSE_KEY)
        self.assertFailure(result, Code.INVALID_RESPONSE)
        self.assertIn("different device", result.message)
        self.assertIsNone(result.license)
        self.assertEqual(store.load(PRODUCT_ID), StoredState(device_secret=DEVICE_SECRET, lease_token=own_lease))
        self.assertFailure(client.validate_with_offline_fallback(LICENSE_KEY), Code.INVALID_RESPONSE)

    def test_success_with_lease_for_other_product_is_rejected(self):
        logic = LicenseServerLogic()

        def handler(request):
            exp = int(time.time()) + 3600
            token = make_lease(exp, product_id="7c3e9a10-1b2c-4d5e-8f90-a1b2c3d4e5f6")
            return signed(request, "ok", ok=True, license=dict(LICENSE_OBJ), lease={"token": token, "expiresAt": exp})

        logic.override = handler
        server = self.start(logic)
        self.assertFailure(self.make_client(server.url).validate(LICENSE_KEY), Code.INVALID_RESPONSE)

    def test_own_but_expired_lease_is_accepted_and_not_stored(self):
        logic = LicenseServerLogic()
        store = MemoryStore()

        def handler(request):
            exp = int(time.time()) - 60
            return signed(request, "ok", ok=True, license=dict(LICENSE_OBJ), lease={"token": make_lease(exp), "expiresAt": exp})

        logic.override = handler
        server = self.start(logic)
        result = self.make_client(server.url, store=store).validate(LICENSE_KEY)
        self.assertTrue(result.ok, result)
        self.assertIsNone(store.load(PRODUCT_ID).lease_token)


# An IIS ARR gateway error page.
HTML_502 = (
    b"<!DOCTYPE html><html><head><title>502 - Web server received an invalid response while acting as a gateway "
    b"or proxy server.</title></head><body><h1>Server Error</h1></body></html>"
)

#: Unsigned 5xx answers: (description, reply, code and status plain validate() reports).
UNAVAILABLE_REPLIES = (
    (
        "500 Velsigil internal_error (database down)",
        lambda request: Reply(
            500, {"error": {"code": "internal_error", "message": "An unexpected error occurred.", "requestId": "rid-500"}}
        ),
        Code.INTERNAL_ERROR,
        500,
    ),
    ("503 empty body, Retry-After", lambda request: Reply(503, None, headers={"Retry-After": "30"}), Code.NETWORK_ERROR, 503),
    ("502 HTML from the proxy", lambda request: Reply(502, HTML_502, headers={"Content-Type": "text/html"}), Code.NETWORK_ERROR, 502),
    ("504 empty body", lambda request: Reply(504, b""), Code.NETWORK_ERROR, 504),
    (
        "503 Velsigil service_busy",
        lambda request: Reply(503, {"error": {"code": "service_busy", "message": "Busy."}}, headers={"Retry-After": "2"}),
        Code.INTERNAL_ERROR,
        503,
    ),
    ("503 Velsigil internal_error", lambda request: Reply(503, {"error": {"code": "internal_error"}}), Code.INTERNAL_ERROR, 503),
    ("500 HTML", lambda request: Reply(500, b"<html><body>Internal Server Error</body></html>"), Code.INTERNAL_ERROR, 500),
    ("500 empty body", lambda request: Reply(500, b""), Code.INTERNAL_ERROR, 500),
    ("500 garbled body", lambda request: Reply(500, b'\xff\xfe{"error": '), Code.INTERNAL_ERROR, 500),
    ("501 other 5xx", lambda request: Reply(501, b"Not Implemented"), Code.INTERNAL_ERROR, 501),
    ("599 other 5xx", lambda request: Reply(599, b""), Code.INTERNAL_ERROR, 599),
    ("500 naming a 4xx code", lambda request: Reply(500, {"error": {"code": "rate_limited"}}), Code.RATE_LIMITED, 500),
    ("500 carrying a signed ok envelope", lambda request: Reply(500, signed(request, "ok", ok=True).body), Code.INTERNAL_ERROR, 500),
    ("503 oversized body", lambda request: Reply(503, b"x" * (MAX_RESPONSE_BYTES + 1)), Code.INVALID_RESPONSE, 503),
)

#: Never fall back; the last field says whether the stored lease survives.
FINAL_REPLIES = (
    (
        "429 rate_limited, Retry-After",
        lambda request: Reply(429, {"error": {"code": "rate_limited", "requestId": "rid-429"}}, headers={"Retry-After": "30"}),
        Code.RATE_LIMITED,
        True,
    ),
    ("429 without body", lambda request: Reply(429, b""), Code.RATE_LIMITED, True),
    ("400 validation_error", lambda request: Reply(400, {"error": {"code": "validation_error"}}), Code.VALIDATION_ERROR, True),
    ("403 ip_blocked", lambda request: Reply(403, {"error": {"code": "ip_blocked"}}), Code.IP_BLOCKED, True),
    ("404 unknown_product", lambda request: Reply(404, {"error": {"code": "unknown_product"}}), Code.UNKNOWN_PRODUCT, True),
    ("404 HTML", lambda request: Reply(404, b"<html>Not Found</html>"), Code.INVALID_RESPONSE, True),
    ("307 redirect", lambda request: Reply(307, b"", headers={"Location": "http://127.0.0.1:9/x"}), Code.INVALID_RESPONSE, True),
    ("200 unsigned HTML", lambda request: Reply(200, b"<html>Captive portal</html>"), Code.INVALID_RESPONSE, True),
    ("200 bad signature", lambda request: signed(request, "ok", ok=True, seed=ms.WRONG_SEED), Code.INVALID_RESPONSE, True),
    ("200 oversized", lambda request: Reply(200, b"x" * (MAX_RESPONSE_BYTES + 1)), Code.INVALID_RESPONSE, True),
    ("signed product_paused", lambda request: signed(request, "product_paused"), Code.PRODUCT_PAUSED, True),
    ("signed license_revoked", lambda request: signed(request, "license_revoked"), Code.LICENSE_REVOKED, False),
    ("signed license_expired", lambda request: signed(request, "license_expired"), Code.LICENSE_EXPIRED, False),
)


class ServerUnavailableFallbackTests(ClientTestCase):
    """validate_with_offline_fallback uses the lease while the server is unavailable: no answer or any unsigned 5xx."""

    def setUp(self):
        self.clock = FakeClock(1767225600)
        self.logic = LicenseServerLogic(clock=self.clock, lease_seconds=86400)
        self.server = self.start(self.logic)

    def _client(self, with_lease=True, **options):
        store = MemoryStore()
        client = self.make_client(self.server.url, store=store, clock=self.clock, **options)
        if with_lease:
            self.logic.override = None
            first = client.validate(LICENSE_KEY)
            self.assertTrue(first.ok and first.lease is not None, first)
            self.assertIsNotNone(store.load(PRODUCT_ID).lease_token)
        return client, store

    def test_unsigned_5xx_falls_back_to_a_valid_lease(self):
        for name, reply, code, status in UNAVAILABLE_REPLIES:
            with self.subTest(case=name):
                client, store = self._client()
                stored = store.load(PRODUCT_ID)
                self.clock.advance(3600)
                self.logic.override = reply
                plain = client.validate(LICENSE_KEY)
                self.assertFailure(plain, code)
                self.assertEqual(plain.http_status, status)
                self.assertFalse(plain.offline)
                result = client.validate_with_offline_fallback(LICENSE_KEY)
                self.assertTrue(result.ok and result.offline, result)
                self.assertEqual(result.code, Code.OK)
                self.assertTrue(result.has_feature("pro"))
                self.assertEqual(result.license.id, LICENSE_OBJ["id"])
                self.assertEqual(result.activation.id, ACTIVATION_ID)
                self.assertIsNone(result.http_status)
                self.assertEqual(store.load(PRODUCT_ID), stored)

    def test_empty_503_is_network_error_for_validate(self):
        self.logic.override = lambda request: Reply(503, None, headers={"Retry-After": "30"})
        client, _store = self._client(with_lease=False)
        result = client.validate(LICENSE_KEY)
        self.assertFailure(result, Code.NETWORK_ERROR)
        self.assertEqual(result.http_status, 503)
        self.assertEqual(result.retry_after, 30)

    def test_fallback_results_carry_the_online_retry_after(self):
        busy = {"error": {"code": "service_busy", "message": "Busy."}}
        outages = (
            ("503 empty body", lambda request: Reply(503, None, headers={"Retry-After": "30"}), 30),
            ("503 Velsigil service_busy", lambda request: Reply(503, busy, headers={"Retry-After": "5"}), 5),
            ("503 without Retry-After", lambda request: Reply(503, None), None),
            (
                "500 with Retry-After",
                lambda request: Reply(500, {"error": {"code": "internal_error"}}, headers={"Retry-After": "30"}),
                None,
            ),
            ("502 with Retry-After", lambda request: Reply(502, HTML_502, headers={"Retry-After": "30"}), None),
        )
        for name, reply, retry_after in outages:
            with self.subTest(case=name, lease="usable"):
                client, _store = self._client()
                self.logic.override = reply
                result = client.validate_with_offline_fallback(LICENSE_KEY)
                self.assertTrue(result.ok and result.offline, result)
                self.assertEqual(result.retry_after, retry_after)
                direct = client.validate_offline()
                self.assertTrue(direct.ok and direct.offline, direct)
                self.assertIsNone(direct.retry_after)
            with self.subTest(case=name, lease="expired"):
                client, _store = self._client()
                self.clock.advance(86400)
                self.logic.override = reply
                result = client.validate_with_offline_fallback(LICENSE_KEY)
                self.assertFailure(result, Code.LEASE_EXPIRED)
                self.assertTrue(result.offline)
                self.assertEqual(result.retry_after, retry_after)
                direct = client.validate_offline()
                self.assertFailure(direct, Code.LEASE_EXPIRED)
                self.assertIsNone(direct.retry_after)
            with self.subTest(case=name, lease="invalid"):
                store = MemoryStore()
                foreign = make_lease(int(self.clock()) + 3600, hwid="someone-else-0001")
                store.save(PRODUCT_ID, StoredState(lease_token=foreign))
                client = self.make_client(self.server.url, store=store, clock=self.clock)
                self.logic.override = reply
                result = client.validate_with_offline_fallback(LICENSE_KEY)
                self.assertFailure(result, Code.LEASE_INVALID)
                self.assertEqual(result.retry_after, retry_after)
                self.assertIsNone(client.validate_offline().retry_after)
            with self.subTest(case=name, lease="none"):
                client, _store = self._client(with_lease=False)
                self.logic.override = reply
                result = client.validate_with_offline_fallback(LICENSE_KEY)
                self.assertFalse(result.ok or result.offline, result)
                self.assertEqual(result.retry_after, retry_after)
        client, store = self._client()
        refused = self.make_client(refused_url(), store=store, clock=self.clock)
        result = refused.validate_with_offline_fallback(LICENSE_KEY)
        self.assertTrue(result.ok and result.offline, result)
        self.assertIsNone(result.retry_after)
        self.logic.override = lambda request: Reply(429, {"error": {"code": "rate_limited"}}, headers={"Retry-After": "12"})
        limited = client.validate_with_offline_fallback(LICENSE_KEY)
        self.assertFailure(limited, Code.RATE_LIMITED)
        self.assertFalse(limited.offline)
        self.assertEqual(limited.retry_after, 12)

    def test_a_failing_date_parser_does_not_break_a_503(self):
        # Some 3.x email.utils releases raise more than ValueError on odd input.
        client, _store = self._client()
        self.logic.override = lambda request: Reply(503, None, headers={"Retry-After": "Thu, 01 Jan 2026 12.34.56.78"})
        with mock.patch.object(client_module, "parsedate_to_datetime", side_effect=UnboundLocalError("tz")):
            plain = client.validate(LICENSE_KEY)
            fallback = client.validate_with_offline_fallback(LICENSE_KEY)
        self.assertFailure(plain, Code.NETWORK_ERROR)
        self.assertEqual(plain.http_status, 503)
        self.assertIsNone(plain.retry_after)
        self.assertTrue(fallback.ok and fallback.offline, fallback)
        self.assertIsNone(fallback.retry_after)

    def test_unsigned_5xx_without_a_lease_returns_the_original_error(self):
        client, store = self._client(with_lease=False)
        for name, reply, code, status in UNAVAILABLE_REPLIES:
            with self.subTest(case=name):
                self.logic.override = reply
                plain = client.validate(LICENSE_KEY)
                result = client.validate_with_offline_fallback(LICENSE_KEY)
                self.assertFailure(result, code)
                self.assertEqual(result.http_status, status)
                self.assertFalse(result.offline)
                self.assertEqual(result.message, plain.message)
                self.assertEqual(result.retry_after, plain.retry_after)
                if name.startswith("500 Velsigil"):
                    self.assertEqual(result.request_id, "rid-500")
        self.assertEqual(store.load(PRODUCT_ID), StoredState())

    def test_unsigned_5xx_with_an_expired_lease_reports_lease_expired(self):
        for name, reply, _code, _status in UNAVAILABLE_REPLIES:
            with self.subTest(case=name):
                client, store = self._client()
                stored = store.load(PRODUCT_ID)
                self.clock.advance(86400)
                self.logic.override = reply
                result = client.validate_with_offline_fallback(LICENSE_KEY)
                self.assertFailure(result, Code.LEASE_EXPIRED)
                self.assertTrue(result.offline)
                self.assertIsNone(result.http_status)
                self.assertFailure(client.validate_offline(), Code.LEASE_EXPIRED)
                self.assertEqual(store.load(PRODUCT_ID), stored)

    def test_unsigned_5xx_with_an_unusable_lease_reports_lease_invalid(self):
        exp = int(self.clock()) + 3600
        _body, sig = make_lease(exp).split(".")
        leases = {
            "other device": make_lease(exp, hwid="someone-else-0001"),
            "tampered": ms.encode_payload({"v": 1, "typ": "lease", "productId": PRODUCT_ID}) + "." + sig,
        }
        for lease_name, token in leases.items():
            for name, reply, _code, _status in UNAVAILABLE_REPLIES:
                with self.subTest(lease=lease_name, case=name):
                    store = MemoryStore()
                    store.save(PRODUCT_ID, StoredState(lease_token=token))
                    client = self.make_client(self.server.url, store=store, clock=self.clock)
                    self.logic.override = reply
                    result = client.validate_with_offline_fallback(LICENSE_KEY)
                    self.assertFailure(result, Code.LEASE_INVALID)
                    self.assertTrue(result.offline)
                    self.assertIsNone(result.http_status)
                    self.assertEqual(store.load(PRODUCT_ID), StoredState(lease_token=token))

    def test_final_answers_never_fall_back(self):
        for name, reply, code, lease_kept in FINAL_REPLIES:
            with self.subTest(case=name):
                client, store = self._client()
                lease = store.load(PRODUCT_ID).lease_token
                self.logic.override = reply
                result = client.validate_with_offline_fallback(LICENSE_KEY)
                self.assertFailure(result, code)
                self.assertFalse(result.offline)
                if name.startswith("429 rate_limited"):
                    self.assertEqual(result.retry_after, 30)
                    self.assertEqual(result.request_id, "rid-429")
                if lease_kept:
                    self.assertEqual(store.load(PRODUCT_ID).lease_token, lease)
                    self.assertTrue(client.validate_offline().ok)
                else:
                    self.assertFailure(client.validate_offline(), Code.NO_LEASE)

    def test_transport_failures_still_fall_back(self):
        client, store = self._client(timeout=0.5)
        self.logic.override = lambda request: Reply(200, signed(request, "ok", ok=True).body, delay=5)
        result = client.validate_with_offline_fallback(LICENSE_KEY)
        self.assertTrue(result.ok and result.offline, result)
        refused = self.make_client(refused_url(), store=store, clock=self.clock)
        result = refused.validate_with_offline_fallback(LICENSE_KEY)
        self.assertTrue(result.ok and result.offline, result)

    def test_fallback_rule(self):
        unavailable = client_module._server_unavailable
        failure = lambda code, status=None, offline=False: VelsigilResult(  # noqa: E731
            ok=False, code=code, message="", http_status=status, offline=offline
        )
        self.assertTrue(unavailable(failure(Code.NETWORK_ERROR)))
        self.assertTrue(unavailable(failure(Code.NETWORK_ERROR, 503)))
        for status in (500, 501, 502, 503, 504, 599):
            self.assertTrue(unavailable(failure(Code.INTERNAL_ERROR, status)), status)
        self.assertTrue(unavailable(failure(Code.INVALID_RESPONSE, 503)))
        for status in (None, 200, 307, 400, 404, 429, 499, 600):
            self.assertFalse(unavailable(failure(Code.INVALID_RESPONSE, status)), status)
            self.assertFalse(unavailable(failure(Code.INTERNAL_ERROR, status)), status)
        self.assertFalse(unavailable(failure(Code.RATE_LIMITED, 429)))
        self.assertFalse(unavailable(failure(Code.LICENSE_REVOKED, 200)))
        self.assertFalse(unavailable(failure(Code.NETWORK_ERROR, 200)))
        self.assertFalse(unavailable(failure(Code.INTERNAL_ERROR, 200)))
        self.assertFalse(unavailable(failure(Code.LEASE_EXPIRED, offline=True)))
        self.assertFalse(unavailable(VelsigilResult(ok=True, code=Code.OK, message="", http_status=200)))


class DeviceBindingTests(ClientTestCase):
    """Signed answers to device-bound requests must describe this device."""

    OTHER_SECRET = "dsk_" + "Q" * 40

    def activation(self, hwid, secret=None):
        return {
            "id": ACTIVATION_ID,
            "status": "active",
            "firstSeenAt": 1767225600,
            "deviceSecret": secret,
            "hwidHash": hashlib.sha256(hwid.encode("utf-8")).hexdigest(),
        }

    def test_activation_of_this_device_is_accepted(self):
        store = MemoryStore()
        own = self.activation(TEST_HWID, DEVICE_SECRET)
        own["hwidHash"] = own["hwidHash"].upper()
        server = self.start(lambda request: signed(request, "ok", ok=True, license=dict(LICENSE_OBJ), activation=own))
        result = self.make_client(server.url, store=store).validate(LICENSE_KEY)
        self.assertTrue(result.ok, result)
        self.assertTrue(result.activation.device_secret_issued)
        self.assertEqual(store.load(PRODUCT_ID).device_secret, DEVICE_SECRET)

    def test_activation_of_other_device_is_rejected_for_every_device_bound_call(self):
        own_lease = make_lease(int(time.time()) + 3600)
        initial = StoredState(device_secret=DEVICE_SECRET, lease_token=own_lease)
        store = MemoryStore()
        store.save(PRODUCT_ID, initial)
        foreign = self.activation("another-device-hwid", self.OTHER_SECRET)

        def handler(request):
            type_ = request.path.rsplit("/", 1)[-1]
            fields = {"activation": foreign}
            if type_ == "download":
                fields["download"] = {
                    "url": "/api/download/x",
                    "expiresAt": 1,
                    "fileName": "a.zip",
                    "size": 1,
                    "sha256": "a" * 64,
                    "version": "1.0.0",
                }
            return signed(request, "ok", ok=True, type_=type_, license=dict(LICENSE_OBJ), **fields)

        server = self.start(handler)
        client = self.make_client(server.url, store=store)
        for name, call in (
            ("validate", lambda: client.validate(LICENSE_KEY)),
            ("download", lambda: client.get_download(LICENSE_KEY)),
            ("deactivate", lambda: client.deactivate(LICENSE_KEY)),
        ):
            with self.subTest(call=name):
                result = call()
                self.assertFailure(result, Code.INVALID_RESPONSE)
                self.assertIsNone(result.download)
                self.assertEqual(store.load(PRODUCT_ID), initial)
        self.assertTrue(client.validate_offline().ok)

    def test_malformed_activation_hwid_hash_is_rejected(self):
        bad = self.activation(TEST_HWID)
        bad["hwidHash"] = 42
        server = self.start(lambda request: signed(request, "ok", ok=True, license=dict(LICENSE_OBJ), activation=bad))
        self.assertFailure(self.make_client(server.url).validate(LICENSE_KEY), Code.INVALID_RESPONSE)

    def test_denial_about_other_device_does_not_revoke_the_lease(self):
        store = MemoryStore()
        store.save(PRODUCT_ID, StoredState(device_secret=DEVICE_SECRET, lease_token=make_lease(int(time.time()) + 3600)))
        foreign = self.activation("another-device-hwid")
        server = self.start(lambda request: signed(request, "device_revoked", activation=foreign))
        client = self.make_client(server.url, store=store)
        self.assertFailure(client.validate(LICENSE_KEY), Code.INVALID_RESPONSE)
        self.assertTrue(client.validate_offline().ok)


class OperationTests(ClientTestCase):
    def test_deactivate_sends_secret_and_clears_state(self):
        store = MemoryStore()
        server = self.start(LicenseServerLogic())
        client = self.make_client(server.url, store=store)
        self.assertTrue(client.validate(LICENSE_KEY).ok)
        result = client.deactivate(LICENSE_KEY)
        self.assertTrue(result.ok, result)
        body = server.bodies("/deactivate")[0]
        self.assertEqual(set(body), {"productId", "licenseKey", "hwid", "deviceSecret", "nonce", "timestamp"})
        self.assertEqual(body["deviceSecret"], DEVICE_SECRET)
        self.assertTrue(store.load(PRODUCT_ID).is_empty)

    def test_check_update(self):
        server = self.start(LicenseServerLogic())
        result = self.make_client(server.url).check_update("1.2.0")
        self.assertTrue(result.ok, result)
        self.assertEqual(result.update.latest_version, "1.4.0")
        self.assertIsNone(result.update.min_version)
        self.assertTrue(result.update.mandatory)
        body = server.bodies("/update-check")[0]
        self.assertEqual(set(body), {"productId", "version", "nonce", "timestamp"})

    def test_no_release(self):
        server = self.start(lambda request: signed(request, "no_release", ok=True, type_="update_check"))
        result = self.make_client(server.url).check_update()
        self.assertTrue(result.ok)
        self.assertEqual(result.code, Code.NO_RELEASE)
        self.assertIsNone(result.update)

    def test_get_download_and_verified_file(self):
        logic = LicenseServerLogic()
        server = self.start(logic)
        client = self.make_client(server.url)
        self.assertTrue(client.validate(LICENSE_KEY).ok)
        result = client.get_download(LICENSE_KEY, version="1.4.0")
        self.assertTrue(result.ok, result)
        self.assertEqual(result.download.url, server.url + "/api/download/tok_abc123")
        self.assertEqual(result.download.size, len(FILE_BYTES))
        self.assertNotIn("tok_abc123", repr(result))
        self.assertEqual(server.bodies("/download")[0]["deviceSecret"], DEVICE_SECRET)
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "app.zip")
            self.assertEqual(client.download_to_file(result.download, target), target)
            with open(target, "rb") as handle:
                self.assertEqual(handle.read(), FILE_BYTES)

            logic.file_bytes = FILE_BYTES[:-1] + b"!"  # same size, different content
            tampered_target = os.path.join(tmp, "tampered.zip")
            with self.assertRaises(DownloadError) as caught:
                client.download_to_file(result.download, tampered_target)
            self.assertEqual(caught.exception.code, Code.INTEGRITY_MISMATCH)
            self.assertFalse(os.path.exists(tampered_target))
            logic.file_bytes = FILE_BYTES + b"extra"
            with self.assertRaises(DownloadError) as caught:
                client.download_to_file(result.download, tampered_target)
            self.assertEqual(caught.exception.code, Code.INTEGRITY_MISMATCH)
            self.assertEqual(sorted(os.listdir(tmp)), ["app.zip"])

            logic.override = lambda request: Reply(410, {"error": {"code": "gone"}}) if request.method == "GET" else None
            with self.assertRaises(DownloadError) as caught:
                client.download_to_file(result.download, tampered_target)
            self.assertEqual(caught.exception.code, Code.DOWNLOAD_FAILED)
            with self.assertRaises(DownloadError) as caught:
                client.download_to_file("not a DownloadInfo", tampered_target)  # type: ignore[arg-type]
            self.assertEqual(caught.exception.code, Code.VALIDATION_ERROR)
            self.assertEqual(sorted(os.listdir(tmp)), ["app.zip"])

    def test_deactivate_device_not_found_clears_state(self):
        store = MemoryStore()
        logic = LicenseServerLogic()
        server = self.start(logic)
        client = self.make_client(server.url, store=store)
        self.assertTrue(client.validate(LICENSE_KEY).ok)
        logic.override = lambda request: signed(request, "device_not_found", type_="deactivate")
        self.assertFailure(client.deactivate(LICENSE_KEY), Code.DEVICE_NOT_FOUND)
        self.assertTrue(store.load(PRODUCT_ID).is_empty)

    def test_download_url_must_be_http_s(self):
        logic = LicenseServerLogic()
        server = self.start(logic)
        client = self.make_client(server.url)
        for url in ("file:///etc/passwd", "http://downloads.example.com/x", "https://user:pw@example.com/x"):
            with self.subTest(url=url):
                logic.download_url = url
                self.assertFailure(client.get_download(LICENSE_KEY), Code.INVALID_RESPONSE)
        logic.download_url = "https://cdn.example.com/api/download/tok"
        self.assertTrue(client.get_download(LICENSE_KEY).ok)


TRIAL_KEY = "DEMO-7K3QM-P9XWD-R4TNB-H2CFY-M8LJV"


class InAppTrialTests(ClientTestCase):
    """start_trial: POST /trial without a key."""

    def _started(self, request, now, **overrides):
        payload = base_payload(request.body, "trial", True, "ok", "Your free trial has started.", server_time=now)
        payload["license"] = dict(LICENSE_OBJ, plan="Trial", trial=True)
        payload["activation"] = {
            "id": ACTIVATION_ID,
            "status": "active",
            "firstSeenAt": now,
            "deviceSecret": DEVICE_SECRET,
            "hwidHash": hashlib.sha256(TEST_HWID.encode("utf-8")).hexdigest(),
        }
        exp = now + 3600
        payload["lease"] = {"token": make_lease(exp, hwid=TEST_HWID, trial=True), "expiresAt": exp}
        payload["trial"] = {"key": TRIAL_KEY}
        payload.update(overrides)
        return Reply(200, sign_envelope(payload))

    def test_start_trial_returns_the_key_and_stores_secret_and_lease(self):
        clock = FakeClock(1767225600)
        server = self.start(lambda request: self._started(request, int(clock())))
        store = MemoryStore()
        client = self.make_client(server.url, store=store, clock=clock)
        result = client.start_trial(version="1.2.0", device_name="Laptop")
        self.assertTrue(result.ok, result)
        self.assertEqual(result.trial_key, TRIAL_KEY)
        self.assertTrue(result.is_trial)
        self.assertTrue(result.activation.device_secret_issued)
        self.assertNotIn(TRIAL_KEY, repr(result))
        request = server.requests[-1]
        self.assertEqual(request.path, "/api/client/v1/trial")
        self.assertEqual(set(request.body), {"productId", "hwid", "version", "deviceName", "nonce", "timestamp"})
        state = store.load(PRODUCT_ID)
        self.assertEqual(state.device_secret, DEVICE_SECRET)
        self.assertIsNotNone(state.lease_token)
        self.assertNotIn(TRIAL_KEY, repr(state))
        clock.advance(60)
        offline = client.validate_offline()
        self.assertTrue(offline.ok, offline)
        self.assertTrue(offline.is_trial)
        self.assertIsNone(offline.trial_key)

    PAID_SECRET = "dsk_" + "P4idL1c3" * 5 + "abc"

    def _assert_refused_locally(self, state):
        clock = FakeClock(1767225600)
        server = self.start(lambda request: self._started(request, int(clock())))
        store = MemoryStore()
        store.save(PRODUCT_ID, state)
        client = self.make_client(server.url, store=store, clock=clock)
        result = client.start_trial(version="1.2.0")
        self.assertFailure(result, Code.ALREADY_LICENSED)
        self.assertEqual(Code.ALREADY_LICENSED, "already_licensed")
        self.assertIn("already holds a license for this product", result.message)
        self.assertIn("trial cannot replace it", result.message)
        self.assertIn("clear_stored_state()", result.message)
        self.assertIsNone(result.trial_key)
        self.assertEqual(server.requests, [])
        self.assertEqual(store.load(PRODUCT_ID), state)
        return client, server, store

    def test_refuses_locally_when_a_device_secret_is_stored(self):
        self._assert_refused_locally(StoredState(device_secret=self.PAID_SECRET))

    def test_refuses_locally_when_a_lease_is_stored(self):
        self._assert_refused_locally(StoredState(lease_token=make_lease(1767225600 + 7200, hwid=TEST_HWID)))

    def test_refuses_with_store_unavailable_when_the_store_cannot_be_read(self):
        clock = FakeClock(1767225600)
        server = self.start(lambda request: self._started(request, int(clock())))
        store = _FlakyStore(failures=1)
        store.save(PRODUCT_ID, StoredState(device_secret=self.PAID_SECRET))
        client = self.make_client(server.url, store=store, clock=clock)
        with self.assertLogs("velsigil_client", level="WARNING"):
            result = client.start_trial()
        self.assertFailure(result, Code.STORE_UNAVAILABLE)
        self.assertEqual(Code.STORE_UNAVAILABLE, "store_unavailable")
        self.assertIn("could not be read", result.message)
        self.assertIsNone(result.trial_key)
        self.assertEqual(server.requests, [])
        self.assertFailure(client.start_trial(), Code.ALREADY_LICENSED)
        self.assertEqual(server.requests, [])
        self.assertEqual(store.load(PRODUCT_ID).device_secret, self.PAID_SECRET)

    def test_days_left_right_after_the_start_is_the_trial_length(self):
        start = 1767225600
        clock = FakeClock(start - 2)  # the local clock lags the signed serverTime by 2 s
        license_obj = dict(LICENSE_OBJ, plan="Trial", trial=True, expiresAt=start + 14 * 86400)
        server = self.start(lambda request: self._started(request, start, license=license_obj))
        store = MemoryStore()
        trial = self.make_client(server.url, store=store, clock=clock).start_trial()
        self.assertTrue(trial.ok, trial)
        self.assertEqual(trial.days_remaining(), 14)
        self.assertEqual(trial.days_remaining(now=start + 14 * 86400 - 1), 1)
        self.assertEqual(trial.days_remaining(now=start + 14 * 86400), 0)
        # make_lease sets licenseExpiresAt to exp + 30 days: 31 days left at the check.
        offline = self.make_client(server.url, store=store, clock=clock).validate_offline()
        self.assertTrue(offline.ok, offline)
        self.assertEqual(offline.days_remaining(), 31)

    def test_refuses_locally_when_both_are_stored_and_starts_after_clearing(self):
        state = StoredState(device_secret=self.PAID_SECRET, lease_token=make_lease(1767225600 + 7200, hwid=TEST_HWID))
        client, server, store = self._assert_refused_locally(state)
        client.clear_stored_state()
        result = client.start_trial()
        self.assertTrue(result.ok, result)
        self.assertEqual(len(server.requests), 1)
        self.assertEqual(store.load(PRODUCT_ID).device_secret, DEVICE_SECRET)

    def test_signed_trial_failures_and_the_email_field(self):
        codes = (
            Code.TRIAL_ALREADY_USED,
            Code.TRIAL_UNAVAILABLE,
            Code.TRIAL_EMAIL_REQUIRED,
            Code.TRIAL_EMAIL_INVALID,
            Code.TRIAL_EMAIL_NOT_ACCEPTED,
            Code.TRIAL_CONFIRMATION_SENT,
        )
        current = {"code": codes[0]}
        server = self.start(lambda request: signed(request, current["code"], type_="trial"))
        client = self.make_client(server.url)
        for code in codes:
            with self.subTest(code=code):
                current["code"] = code
                result = client.start_trial(email=" jane@example.com ")
                self.assertFailure(result, code)
                self.assertIsNone(result.trial_key)
                self.assertNotIn(code, LEASE_REVOKING_CODES)
        self.assertEqual(server.requests[-1].body["email"], "jane@example.com")
        client.start_trial()
        self.assertNotIn("email", server.requests[-1].body)
        self.assertEqual(client.start_trial(email="a" * 250 + "@x.io").code, Code.VALIDATION_ERROR)

    def test_panel_too_old(self):
        server = self.start(lambda request: Reply(404, {"error": {"code": "not_found", "message": "Not found.", "requestId": "rid-old"}}))
        client = self.make_client(server.url)
        result = client.start_trial()
        self.assertFailure(result, Code.PANEL_TOO_OLD)
        self.assertIn("update the Velsigil panel", result.message)
        self.assertEqual(result.request_id, "rid-old")
        self.assertEqual(client.validate(LICENSE_KEY).code, Code.INVALID_RESPONSE)
        server.handler = lambda request: Reply(404, {"error": {"code": "unknown_product"}})
        self.assertEqual(client.start_trial().code, Code.UNKNOWN_PRODUCT)

    def test_rejects_missing_key_wrong_type_and_foreign_device(self):
        clock = FakeClock(1767225600)
        holder = {"overrides": {}}

        def handler(request):
            reply = self._started(request, int(clock()), **holder["overrides"])
            return reply

        server = self.start(handler)
        client = self.make_client(server.url, clock=clock)
        for overrides in (
            {"trial": None},
            {"trial": {"key": "bad key\n"}},
            {"type": "validate"},
            {"activation": {"id": ACTIVATION_ID, "status": "active", "firstSeenAt": int(clock()), "deviceSecret": None, "hwidHash": "f" * 64}},
        ):
            with self.subTest(overrides=list(overrides)):
                holder["overrides"] = overrides
                result = client.start_trial()
                self.assertFailure(result, Code.INVALID_RESPONSE)
                self.assertIsNone(result.trial_key)

    def test_never_reads_a_key_from_another_answer(self):
        def handler(request):
            payload = base_payload(request.body, "validate", True, "ok", "License is valid.")
            payload["license"] = dict(LICENSE_OBJ)
            payload["trial"] = {"key": TRIAL_KEY}
            return Reply(200, sign_envelope(payload))

        server = self.start(handler)
        result = self.make_client(server.url).validate(LICENSE_KEY)
        self.assertTrue(result.ok, result)
        self.assertIsNone(result.trial_key)


class _BrokenStore(LicenseStore):
    def load(self, product_id):
        raise OSError("disk unavailable")

    def save(self, product_id, state):
        raise OSError("disk unavailable")


class _FlakyStore(MemoryStore):
    """A MemoryStore whose loads fail: the next ``failures`` ones, or every one while it is -1."""

    def __init__(self, failures=0):
        super().__init__()
        self.failures = failures
        self.saves = 0

    def load(self, product_id):
        if self.failures:
            if self.failures > 0:
                self.failures -= 1
            raise OSError("resource busy")
        return super().load(product_id)

    def save(self, product_id, state):
        self.saves += 1
        super().save(product_id, state)


class SafetyTests(ClientTestCase):
    def test_an_unreadable_store_is_never_overwritten_with_nothing(self):
        paid = "dsk_" + "P4idL1c3" * 5 + "abc"
        logic = LicenseServerLogic()
        logic.secret_issued = True  # the answer issues no new secret
        server = self.start(logic)
        store = _FlakyStore()
        store.save(PRODUCT_ID, StoredState(device_secret=paid))
        store.failures, store.saves = -1, 0
        client = self.make_client(server.url, store=store)
        with self.assertLogs("velsigil_client", level="WARNING"):
            self.assertTrue(client.validate(LICENSE_KEY).ok)
        self.assertEqual(store.saves, 0)
        store.failures = 0
        self.assertEqual(store.load(PRODUCT_ID).device_secret, paid)
        logic.secret_issued = False
        store.failures = -1
        with self.assertLogs("velsigil_client", level="WARNING"):
            self.assertTrue(client.validate(LICENSE_KEY).ok)
        store.failures = 0
        self.assertEqual(store.load(PRODUCT_ID).device_secret, DEVICE_SECRET)

    def test_a_transient_read_failure_keeps_the_stored_secret(self):
        paid = "dsk_" + "P4idL1c3" * 5 + "abc"
        logic = LicenseServerLogic()
        logic.secret_issued = True
        server = self.start(logic)
        store = _FlakyStore()
        store.save(PRODUCT_ID, StoredState(device_secret=paid))
        store.failures = 1  # only the read before the request fails
        with self.assertLogs("velsigil_client", level="WARNING"):
            self.assertTrue(self.make_client(server.url, store=store).validate(LICENSE_KEY).ok)
        state = store.load(PRODUCT_ID)
        self.assertEqual(state.device_secret, paid)
        self.assertIsNotNone(state.lease_token)

    def test_store_failures_do_not_break_validation(self):
        server = self.start(LicenseServerLogic())
        client = self.make_client(server.url, store=_BrokenStore())
        with self.assertLogs("velsigil_client", level="WARNING"):
            self.assertTrue(client.validate(LICENSE_KEY).ok)
        self.assertTrue(client.validate(LICENSE_KEY).ok)
        self.assertEqual(server.bodies("/validate")[1]["deviceSecret"], DEVICE_SECRET)

    def test_secrets_never_logged_or_repr(self):
        logger = logging.getLogger("velsigil_client")
        records = []

        class Collect(logging.Handler):
            def emit(self, record):
                records.append(self.format(record))

        handler = Collect(level=logging.DEBUG)
        previous = logger.level
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        try:
            logic = LicenseServerLogic()
            server = self.start(logic)
            client = self.make_client(server.url, store=_BrokenStore())
            result = client.validate(LICENSE_KEY)
            logic.override = lambda request: signed(request, "ok", ok=True, seed=ms.WRONG_SEED)
            client.validate(LICENSE_KEY)
            logic.override = lambda request: Reply(500, b"")
            client.validate(LICENSE_KEY)
        finally:
            logger.removeHandler(handler)
            logger.setLevel(previous)
        self.assertTrue(records)
        text = "\n".join(records)
        for secret in (LICENSE_KEY, DEVICE_SECRET):
            self.assertNotIn(secret, text)
            self.assertNotIn(secret, repr(result))
            self.assertNotIn(secret, repr(client))
        self.assertNotIn(DEVICE_SECRET, repr(StoredState(device_secret=DEVICE_SECRET)))

    def test_concurrent_calls_share_one_device_secret(self):
        logic = LicenseServerLogic()
        server = self.start(logic)
        client = self.make_client(server.url)
        results = []
        threads = [threading.Thread(target=lambda: results.append(client.validate(LICENSE_KEY))) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertEqual(len(results), 8)
        self.assertTrue(all(r.ok for r in results))
        bodies = server.bodies("/validate")
        self.assertNotIn("deviceSecret", bodies[0])
        self.assertTrue(all(b.get("deviceSecret") == DEVICE_SECRET for b in bodies[1:]))


#: A random product key for non-loopback URLs, where the vector keys are refused.
PRODUCT_KEY = ms.generate_public_key_b64()


class ConfigurationTests(unittest.TestCase):
    def make(self, url="https://licenses.example.com", **options):
        options.setdefault("hwid", TEST_HWID)
        return VelsigilClient(url, PRODUCT_ID, PRODUCT_KEY, **options)

    def test_https_required_except_localhost(self):
        with self.assertRaises(ConfigurationError):
            self.make("http://licenses.example.com")
        for url in ("http://localhost:3000", "http://127.0.0.1", "http://[::1]:3000", "HTTP://LOCALHOST"):
            with self.subTest(url=url):
                self.make(url)
        self.make("http://licenses.example.com", allow_insecure_http=True)

    def test_rejected_urls(self):
        for url in ("", "licenses.example.com", "ftp://example.com", "https://user:pw@example.com",
                    "https://example.com/?x=1", "https://example.com/#frag", "https://example.com:99999", None):
            with self.subTest(url=url):
                with self.assertRaises(ConfigurationError):
                    self.make(url)  # type: ignore[arg-type]

    def test_api_url_normalisation(self):
        cases = {
            "https://licenses.example.com": "https://licenses.example.com/api/client/v1",
            "https://licenses.example.com/": "https://licenses.example.com/api/client/v1",
            "https://licenses.example.com/api/client/v1/": "https://licenses.example.com/api/client/v1",
            "https://example.com:8443/velsigil": "https://example.com:8443/velsigil/api/client/v1",
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(self.make(url).api_url, expected)

    def test_argument_validation(self):
        with self.assertRaises(ConfigurationError) as caught:
            VelsigilClient("https://x.example.com", "not-a-uuid", PRODUCT_KEY, hwid=TEST_HWID)
        self.assertEqual(caught.exception.code, Code.INVALID_CONFIGURATION)
        with self.assertRaises(ConfigurationError):
            VelsigilClient("https://x.example.com", PRODUCT_ID, "short", hwid=TEST_HWID)
        for options in ({"hwid": "short"}, {"hwid": "x" * 257}, {"timeout": 0}, {"timeout": True},
                        {"store": object()}, {"clock": 5}):
            with self.subTest(options=options):
                with self.assertRaises(ConfigurationError):
                    self.make(**options)
        upper = VelsigilClient("https://x.example.com", PRODUCT_ID.upper(), PRODUCT_KEY, hwid=TEST_HWID)
        self.assertEqual(upper.product_id, PRODUCT_ID)

    def test_insecure_ssl_context_rejected(self):
        import ssl

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with self.assertRaises(ConfigurationError):
            self.make(ssl_context=context)

    def test_default_hardware_id(self):
        try:
            expected = get_hardware_id()
        except HardwareIdError as exc:
            self.skipTest("no machine id on this host: %s" % exc)
        client = VelsigilClient("https://localhost", PRODUCT_ID, PUBLIC_KEY)  # the vector key: loopback only
        self.assertEqual(client.hwid, expected)
        self.assertEqual(VelsigilClient.get_hardware_id(), expected)
        self.assertEqual(client.key_id, ms.KEY_ID)


class PublishedTestKeyTests(unittest.TestCase):
    """The vector keys' private seeds are public: the client refuses them unless api_url is loopback."""

    MESSAGE = (
        "This is the public test key from the Velsigil SDK test vectors, whose private key is published: "
        "anyone could forge license answers for it. Use your product's public key "
        "(panel: Products > your product > Integration)."
    )
    TEST_KEYS = (ms.VECTORS["keys"]["publicKey"], ms.VECTORS["keys"]["wrongPublicKey"])

    @staticmethod
    def encodings(key):
        """Other accepted spellings of the same key bytes, including non-canonical base64."""
        spellings = [key, key.rstrip("="), "  " + key + "\n", " " + key.rstrip("=") + "\t"]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        body = key.rstrip("=")
        non_canonical = body[:-1] + alphabet[alphabet.index(body[-1]) ^ 1] + "="
        try:
            # Internal decoder: the public one refuses the test keys.
            if _decode_public_key(non_canonical) == _decode_public_key(key):
                spellings.append(non_canonical)
        except ConfigurationError:
            pass
        return tuple(spellings)

    def make(self, url, key, **options):
        options.setdefault("hwid", TEST_HWID)
        return VelsigilClient(url, PRODUCT_ID, key, **options)

    def test_test_keys_are_refused_on_non_loopback_urls(self):
        urls = (
            "https://licenses.example.com",
            "https://licenses.example.com:8443/velsigil",
            "https://localhost.example.com",
            "https://127.0.0.1.example.com",
            "https://10.0.0.5",
        )
        for key in self.TEST_KEYS:
            for spelling in self.encodings(key):
                for url in urls:
                    with self.subTest(key=spelling, url=url):
                        with self.assertRaises(ConfigurationError) as caught:
                            self.make(url, spelling)
                        self.assertEqual(str(caught.exception), self.MESSAGE)
                        self.assertEqual(caught.exception.code, Code.INVALID_CONFIGURATION)
                        self.assertIsInstance(caught.exception, ValueError)
                with self.subTest(key=spelling, url="http (allow_insecure_http)"):
                    with self.assertRaises(ConfigurationError) as caught:
                        self.make("http://licenses.example.com", spelling, allow_insecure_http=True)
                    self.assertEqual(str(caught.exception), self.MESSAGE)

    def test_refusal_takes_the_invalid_public_key_path(self):
        with self.assertRaises(ConfigurationError) as bad_key:
            self.make("https://licenses.example.com", "short")
        with self.assertRaises(ConfigurationError) as test_key:
            self.make("https://licenses.example.com", self.TEST_KEYS[0])
        self.assertIs(type(test_key.exception), type(bad_key.exception))
        self.assertEqual(test_key.exception.code, bad_key.exception.code)

    def test_test_keys_are_accepted_on_loopback_urls(self):
        urls = (
            "http://localhost:3000",
            "https://localhost",
            "HTTP://LOCALHOST",
            "http://127.0.0.1",
            "https://127.0.0.1:8443/velsigil",
            "http://[::1]:3000",
            "https://[::1]",
        )
        for key in self.TEST_KEYS:
            for spelling in self.encodings(key):
                for url in urls:
                    with self.subTest(key=spelling, url=url):
                        client = self.make(url, spelling)
                        self.assertEqual(client.key_id, hashlib.sha256(_decode_public_key(key)).hexdigest()[:16])

    def test_loopback_exemption_is_the_plain_http_rule(self):
        for host in sorted(client_module.LOCAL_HOSTS):
            netloc = "[%s]" % host if ":" in host else host
            for scheme in ("http", "https"):
                with self.subTest(host=host, scheme=scheme):
                    self.make("%s://%s:3000" % (scheme, netloc), self.TEST_KEYS[0])
        # https, so only the test-key guard can refuse it.
        with mock.patch.object(client_module, "_is_local_host", return_value=False):
            with self.assertRaises(ConfigurationError) as caught:
                self.make("https://localhost:3000", self.TEST_KEYS[0])
            self.assertEqual(str(caught.exception), self.MESSAGE)
        with mock.patch.object(client_module, "_is_local_host", return_value=True):
            self.make("https://licenses.example.com", self.TEST_KEYS[1])

    def test_real_keys_are_accepted_on_non_loopback_urls(self):
        for _ in range(3):
            key = ms.generate_public_key_b64()
            with self.subTest(key=key):
                self.assertNotIn(key, self.TEST_KEYS)
                client = self.make("https://licenses.example.com", key)
                self.assertEqual(client.key_id, key_id_for(key))
                self.assertEqual(client.api_url, "https://licenses.example.com/api/client/v1")

    def test_low_level_helpers_refuse_test_keys_even_where_the_client_allows_them(self):
        lease = make_lease(int(time.time()) + 3600)
        for key in self.TEST_KEYS:
            client = self.make("http://127.0.0.1:3000", key)
            calls = {
                "Ed25519Verifier": lambda: Ed25519Verifier(key),
                "key_id_for": lambda: key_id_for(key),
                "open_envelope": lambda: open_envelope(client._verifier, {}, "n", PRODUCT_ID, "validate"),
                "verify_lease": lambda: verify_lease(client._verifier, lease, PRODUCT_ID, TEST_HWID, time.time()),
            }
            for name, call in calls.items():
                with self.subTest(key=key, helper=name):
                    with self.assertRaises(ConfigurationError) as caught:
                        call()
                    self.assertEqual(str(caught.exception), self.MESSAGE)
                    self.assertEqual(caught.exception.code, Code.INVALID_CONFIGURATION)


class FileStoreTests(unittest.TestCase):
    def test_round_trip_atomic_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "nested", "license.json")
            store = FileStore(path)
            self.assertTrue(store.load(PRODUCT_ID).is_empty)
            store.save(PRODUCT_ID, StoredState(device_secret=DEVICE_SECRET, lease_token="a.b"))
            other = "7c3e9a10-1b2c-4d5e-8f90-a1b2c3d4e5f6"
            store.save(other, StoredState(lease_token="c.d"))
            reopened = FileStore(path)
            self.assertEqual(reopened.load(PRODUCT_ID), StoredState(DEVICE_SECRET, "a.b"))
            self.assertEqual(reopened.load(other), StoredState(None, "c.d"))
            self.assertEqual(os.listdir(os.path.dirname(path)), ["license.json"])
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode), 0o700)
            reopened.delete(PRODUCT_ID)
            self.assertTrue(FileStore(path).load(PRODUCT_ID).is_empty)
            self.assertEqual(FileStore(path).load(other).lease_token, "c.d")

    def test_corrupt_file_is_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "license.json")
            for content in (b"{not json", b"[]", b'{"products": 5}', b"\xff\xfe"):
                with self.subTest(content=content):
                    with open(path, "wb") as handle:
                        handle.write(content)
                    store = FileStore(path)
                    with self.assertLogs("velsigil_client", level="WARNING"):
                        self.assertTrue(store.load(PRODUCT_ID).is_empty)
                    store.save(PRODUCT_ID, StoredState(device_secret=DEVICE_SECRET))
                    self.assertEqual(store.load(PRODUCT_ID).device_secret, DEVICE_SECRET)

    def test_reads_pre_rename_location_until_next_write(self):
        other = "7c3e9a10-1b2c-4d5e-8f90-a1b2c3d4e5f6"
        legacy_document = {
            "version": 1,
            "products": {
                PRODUCT_ID: {"deviceSecret": DEVICE_SECRET, "leaseToken": "old.lease"},
                other: {"leaseToken": "c.d"},
            },
        }
        for new_dir, legacy_dir in (("Velsigil", "Veltrix"), ("velsigil", "veltrix")):
            with self.subTest(new_dir=new_dir), tempfile.TemporaryDirectory() as tmp:
                legacy_path = os.path.join(tmp, "My App", legacy_dir, "license.json")
                os.makedirs(os.path.dirname(legacy_path))
                with open(legacy_path, "w", encoding="utf-8") as handle:
                    json.dump(legacy_document, handle)
                path = os.path.join(tmp, "My App", new_dir, "license.json")

                store = FileStore(path)
                self.assertEqual(store.load(PRODUCT_ID), StoredState(DEVICE_SECRET, "old.lease"))
                self.assertFalse(os.path.exists(path))

                store.save(PRODUCT_ID, StoredState(DEVICE_SECRET, "new.lease"))
                self.assertTrue(os.path.isfile(path))
                reopened = FileStore(path)
                self.assertEqual(reopened.load(PRODUCT_ID), StoredState(DEVICE_SECRET, "new.lease"))
                self.assertEqual(reopened.load(other), StoredState(None, "c.d"))

                reopened.delete(PRODUCT_ID)
                self.assertTrue(FileStore(path).load(PRODUCT_ID).is_empty)

    def test_no_legacy_fallback_outside_the_default_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            legacy_path = os.path.join(tmp, "veltrix", "license.json")
            os.makedirs(os.path.dirname(legacy_path))
            with open(legacy_path, "w", encoding="utf-8") as handle:
                json.dump({"version": 1, "products": {PRODUCT_ID: {"deviceSecret": DEVICE_SECRET}}}, handle)
            self.assertTrue(FileStore(os.path.join(tmp, "custom", "license.json")).load(PRODUCT_ID).is_empty)

    def test_instances_on_the_same_path_share_one_lock(self):
        other = "7c3e9a10-1b2c-4d5e-8f90-a1b2c3d4e5f6"
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "license.json")
            first, second = FileStore(path), FileStore(os.path.join(tmp, ".", "license.json"))
            read_done, release = threading.Event(), threading.Event()
            original_read = first._read_all

            def slow_read():
                products = original_read()
                read_done.set()
                release.wait(5)  # hold the read-modify-write open
                return products

            first._read_all = slow_read
            writer = threading.Thread(target=first.save, args=(PRODUCT_ID, StoredState(device_secret=DEVICE_SECRET)))
            writer.start()
            self.assertTrue(read_done.wait(5))
            competitor = threading.Thread(target=second.save, args=(other, StoredState(lease_token="c.d")))
            competitor.start()
            competitor.join(0.3)  # with the shared lock it waits for the first save
            release.set()
            writer.join(5)
            competitor.join(5)
            reopened = FileStore(path)
            self.assertEqual(reopened.load(PRODUCT_ID).device_secret, DEVICE_SECRET)
            self.assertEqual(reopened.load(other).lease_token, "c.d")

    def test_memory_store(self):
        store = MemoryStore()
        store.save(PRODUCT_ID, StoredState(device_secret=DEVICE_SECRET))
        self.assertEqual(store.load(PRODUCT_ID).device_secret, DEVICE_SECRET)
        store.delete(PRODUCT_ID)
        self.assertTrue(store.load(PRODUCT_ID).is_empty)


if __name__ == "__main__":
    unittest.main()
