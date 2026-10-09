#!/usr/bin/env python3
"""Velsigil mock client API for SDK integration tests; never expose it to a network.

The license key selects the scenario:

  VX-OK       normal license: issues a device secret on first activation and afterwards requires it
              (strict device binding), returns an offline lease, supports deactivate and download
  VX-INVALID  signed invalid_key
  VX-NONCE    signed ok whose nonce does not echo the request
  VX-BADSIG   ok envelope with a corrupted signature
  VX-SKEW     server clock two hours ahead: clock_skew until the client corrects its offset
  VX-429      unsigned 429 rate_limited (with Retry-After)
  VX-400      unsigned 400 validation_error
  VX-500      unsigned 500 internal_error
  VX-503      503 with an empty body and Retry-After (the server while its database is unreachable)
  VX-503J     unsigned 503 service_busy with Retry-After (a busy database)
  VX-502      502 with an HTML body (a reverse proxy whose app is down)
  VX-504      504 with an empty body (a gateway timeout)
  VX-SLOW     answers after 3 seconds (client timeouts)
  VX-DLBAD    download descriptor whose sha256 does not match the served file
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PRODUCT_ID = "0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b"
KEY_ID = "c1e9dc98b077ab8b"
MAX_SKEW_SECONDS = 300
SKEW_AHEAD_SECONDS = 7200
LEASE_SECONDS = 24 * 3600
RELEASE_BYTES = bytes(range(256)) * 64  # 16 KiB, deterministic
RELEASE_SHA256 = hashlib.sha256(RELEASE_BYTES).hexdigest()
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
MAX_BODY_BYTES = 16 * 1024


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class MockState:
    def __init__(self, seed: bytes) -> None:
        self.key = Ed25519PrivateKey.from_private_bytes(seed)
        self.lock = threading.Lock()
        self.device_secrets: Dict[Tuple[str, str], str] = {}  # (license key, hwid) -> issued device secret
        self.seen_nonces: set = set()

    def envelope(self, payload: Dict[str, Any], tamper: bool = False) -> bytes:
        data = b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        signature = bytearray(self.key.sign(data.encode("ascii")))
        if tamper:
            signature[0] ^= 0x01
        return json.dumps({"data": data, "sig": b64url(bytes(signature)), "kid": KEY_ID}).encode("utf-8")

    def lease(self, hwid: str, now: int, license_expires_at: int) -> Dict[str, Any]:
        exp = min(now + LEASE_SECONDS, license_expires_at)
        claims = {
            "v": 1,
            "typ": "lease",
            "productId": PRODUCT_ID,
            "licenseId": "5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f",
            "activationId": "9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d",
            "hwidHash": hashlib.sha256(hwid.encode("utf-8")).hexdigest(),
            "plan": "Monthly",
            "features": ["pro", "export"],
            "licenseExpiresAt": license_expires_at,
            "iat": now,
            "exp": exp,
        }
        body = b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
        signature = b64url(self.key.sign(body.encode("ascii")))
        return {"token": body + "." + signature, "expiresAt": exp}


def base_payload(kind: str, request: Dict[str, Any], ok: bool, code: str, message: str, now: int) -> Dict[str, Any]:
    return {
        "v": 1,
        "type": kind,
        "ok": ok,
        "code": code,
        "message": message,
        "nonce": request["nonce"],
        "requestId": str(uuid.uuid4()),
        "serverTime": now,
        "productId": request["productId"],
        "license": None,
        "activation": None,
        "lease": None,
        "update": None,
    }


def license_info(now: int) -> Dict[str, Any]:
    return {
        "id": "5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f",
        "plan": "Monthly",
        "status": "active",
        "features": ["pro", "export"],
        "expiresAt": now + 30 * 86400,
        "maxDevices": 2,
        "devicesUsed": 1,
        "createdAt": now - 86400,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "VelsigilMock"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    @property
    def state(self) -> MockState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - signature from the base class
        # Request bodies (license keys, device secrets) are never logged.
        return

    def send_body(self, status: int, body: bytes, content_type: Optional[str] = "application/json",
                  extra: Optional[Dict[str, str]] = None) -> None:
        try:
            self.send_response(status)
            if content_type is not None:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            # The client gave up (timeout tests).
            self.close_connection = True

    def send_error_body(self, status: int, code: str, message: str, extra: Optional[Dict[str, str]] = None) -> None:
        body = json.dumps({"error": {"code": code, "message": message, "requestId": str(uuid.uuid4())}}).encode("utf-8")
        self.send_body(status, body, extra=extra)

    def read_request(self) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            return None, "invalid body length"
        if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
            return None, "content type must be application/json"
        try:
            request = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, "body is not JSON"
        if not isinstance(request, dict):
            return None, "body must be an object"
        if not isinstance(request.get("nonce"), str) or not NONCE_RE.match(request["nonce"]):
            return None, "invalid nonce"
        if not isinstance(request.get("timestamp"), int) or isinstance(request.get("timestamp"), bool):
            return None, "invalid timestamp"
        if not isinstance(request.get("productId"), str):
            return None, "invalid productId"
        return request, None

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        if self.path == "/files/release.bin":
            self.send_body(200, RELEASE_BYTES, "application/octet-stream")
        else:
            self.send_error_body(404, "not_found", "Not found.")

    def do_POST(self) -> None:  # noqa: N802 - http.server naming
        prefix = "/api/client/v1/"
        if not self.path.startswith(prefix):
            self.send_error_body(404, "not_found", "Not found.")
            return
        action = self.path[len(prefix):]
        if action not in ("validate", "deactivate", "update-check", "download"):
            self.send_error_body(404, "not_found", "Not found.")
            return
        request, error = self.read_request()
        if request is None:
            self.send_error_body(400, "validation_error", error or "Invalid request.")
            return
        if request["productId"] != PRODUCT_ID:
            self.send_error_body(404, "unknown_product", "Unknown product.")
            return

        key = request.get("licenseKey", "")
        if key == "VX-429":
            self.send_error_body(429, "rate_limited", "Too many requests.", {"Retry-After": "30"})
            return
        if key == "VX-400":
            self.send_error_body(400, "validation_error", "Invalid request body.")
            return
        if key == "VX-500":
            self.send_error_body(500, "internal_error", "Internal server error.")
            return
        if key == "VX-503":
            self.send_body(503, b"", None, {"Retry-After": "30"})
            return
        if key == "VX-503J":
            self.send_error_body(503, "service_busy", "The service is busy. Please try again shortly.", {"Retry-After": "5"})
            return
        if key == "VX-502":
            self.send_body(502, b"<html><head><title>502 Bad Gateway</title></head><body><h1>502 Bad Gateway</h1></body></html>",
                           "text/html")
            return
        if key == "VX-504":
            self.send_body(504, b"", None)
            return
        if key == "VX-SLOW":
            time.sleep(3)

        now = int(time.time()) + (SKEW_AHEAD_SECONDS if key == "VX-SKEW" else 0)
        kind = action.replace("-", "_")
        if abs(request["timestamp"] - now) > MAX_SKEW_SECONDS:
            payload = base_payload(kind, request, False, "clock_skew", "Request timestamp is outside the allowed window.", now)
            self.send_body(200, self.state.envelope(payload))
            return
        with self.state.lock:
            replay = (request["productId"], request["nonce"]) in self.state.seen_nonces
            self.state.seen_nonces.add((request["productId"], request["nonce"]))
        if replay:
            payload = base_payload(kind, request, False, "replay_detected", "Replay detected.", now)
            self.send_body(200, self.state.envelope(payload))
            return

        if action == "update-check":
            self.handle_update_check(request, now)
        elif key == "VX-INVALID" or key not in ("VX-OK", "VX-NONCE", "VX-BADSIG", "VX-SKEW", "VX-SLOW", "VX-DLBAD"):
            payload = base_payload(kind, request, False, "invalid_key", "License key not found.", now)
            self.send_body(200, self.state.envelope(payload))
        elif action == "validate":
            self.handle_validate(request, key, now)
        elif action == "deactivate":
            self.handle_deactivate(request, now)
        else:
            self.handle_download(request, key, now)

    def check_device(self, request: Dict[str, Any], kind: str, now: int, create: bool) -> Tuple[bool, Optional[str]]:
        """Returns (accepted, newly issued secret). Sends the failure response itself."""
        hwid = request.get("hwid")
        if not isinstance(hwid, str) or not 8 <= len(hwid) <= 256:
            self.send_error_body(400, "validation_error", "Invalid hwid.")
            return False, None
        with self.state.lock:
            device = (request.get("licenseKey", ""), hwid)
            stored = self.state.device_secrets.get(device)
            if stored is None:
                if not create:
                    payload = base_payload(kind, request, False, "device_not_activated", "Device not activated.", now)
                    self.send_body(200, self.state.envelope(payload))
                    return False, None
                secret = "dsk_" + b64url(uuid.uuid4().bytes + uuid.uuid4().bytes)
                self.state.device_secrets[device] = secret
                return True, secret
        if request.get("deviceSecret") != stored:
            payload = base_payload(kind, request, False, "device_verification_failed", "Device verification failed.", now)
            self.send_body(200, self.state.envelope(payload))
            return False, None
        return True, None

    def handle_validate(self, request: Dict[str, Any], key: str, now: int) -> None:
        accepted, issued = self.check_device(request, "validate", now, create=True)
        if not accepted:
            return
        payload = base_payload("validate", request, True, "ok", "License is valid.", now)
        payload["license"] = license_info(now)
        payload["activation"] = {"id": "9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d", "status": "active",
                                 "firstSeenAt": now, "deviceSecret": issued}
        payload["lease"] = self.state.lease(request["hwid"], now, payload["license"]["expiresAt"])
        if key == "VX-NONCE":
            payload["nonce"] = "a-different-nonce-0000000000"
        self.send_body(200, self.state.envelope(payload, tamper=key == "VX-BADSIG"))

    def handle_deactivate(self, request: Dict[str, Any], now: int) -> None:
        accepted, _ = self.check_device(request, "deactivate", now, create=False)
        if not accepted:
            return
        with self.state.lock:
            self.state.device_secrets.pop((request.get("licenseKey", ""), request["hwid"]), None)
        payload = base_payload("deactivate", request, True, "ok", "Device deactivated.", now)
        self.send_body(200, self.state.envelope(payload))

    def handle_download(self, request: Dict[str, Any], key: str, now: int) -> None:
        accepted, _ = self.check_device(request, "download", now, create=False)
        if not accepted:
            return
        host = self.headers.get("Host") or "127.0.0.1"
        payload = base_payload("download", request, True, "ok", "Download ready.", now)
        payload["download"] = {
            "url": "http://" + host + "/files/release.bin",
            "expiresAt": now + 600,
            "fileName": "release.bin",
            "size": len(RELEASE_BYTES),
            "sha256": ("0" * 64) if key == "VX-DLBAD" else RELEASE_SHA256,
            "version": "1.4.0",
        }
        self.send_body(200, self.state.envelope(payload))

    def handle_update_check(self, request: Dict[str, Any], now: int) -> None:
        if request.get("version") == "0.0.0":
            # Like the real server: ok is true for an update check with nothing published.
            payload = base_payload("update_check", request, True, "no_release", "No release has been published yet.", now)
        else:
            payload = base_payload("update_check", request, True, "ok", "Update information.", now)
            payload["update"] = {"latestVersion": "1.4.0", "minVersion": "1.0.0",
                                 "updateAvailable": request.get("version") != "1.4.0", "mandatory": False,
                                 "changelog": "Bug fixes and improvements."}
        self.send_body(200, self.state.envelope(payload))


def create_server(vectors_path: str, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    with open(vectors_path, "r", encoding="utf-8") as handle:
        vectors = json.load(handle)
    seed = base64.b64decode(vectors["keys"]["privateSeedBase64"])
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.state = MockState(seed)  # type: ignore[attr-defined]
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Velsigil mock client API (tests only)")
    parser.add_argument("--vectors", required=True, help="path to sdks/test-vectors.json")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    server = create_server(args.vectors, "127.0.0.1", args.port)
    print(f"mock Velsigil client API on http://127.0.0.1:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
