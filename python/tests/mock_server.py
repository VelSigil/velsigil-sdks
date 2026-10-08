"""Local mock of the Velsigil client API that signs responses like the server.

Uses ``http.server.ThreadingHTTPServer`` on an ephemeral 127.0.0.1 port and
``cryptography``'s Ed25519 with the fixed seed from ``test-vectors.json``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS_PATH = os.environ.get("VELSIGIL_TEST_VECTORS") or os.path.normpath(
    os.path.join(HERE, "..", "..", "test-vectors.json")
)


def load_vectors() -> Dict[str, Any]:
    with open(VECTORS_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


VECTORS = load_vectors()
PUBLIC_KEY = VECTORS["keys"]["publicKey"]
SEED = VECTORS["keys"]["privateSeedBase64"]
WRONG_SEED = VECTORS["keys"]["wrongPrivateSeedBase64"]
KEY_ID = VECTORS["keys"]["keyId"]
PRODUCT_ID = VECTORS["envelopes"][0]["productId"]
TEST_HWID = VECTORS["hwid"]["serverHashOfTestHwid"]["hwid"]


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def encode_payload(payload: Mapping[str, Any]) -> str:
    """Encode like the server: compact JSON (UTF-8, no ASCII escaping), base64url."""
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return b64url(text.encode("utf-8"))


def private_key(seed_b64: str = SEED) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(seed_b64))


def public_key_b64(seed_b64: str = SEED) -> str:
    raw = private_key(seed_b64).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def sign_text(text: str, seed_b64: str = SEED) -> str:
    return b64url(private_key(seed_b64).sign(text.encode("ascii")))


def sign_envelope(payload: Mapping[str, Any], seed_b64: str = SEED) -> Dict[str, str]:
    data = encode_payload(payload)
    return {"data": data, "sig": sign_text(data, seed_b64), "kid": KEY_ID}


def make_lease(
    exp: int,
    hwid: str = TEST_HWID,
    product_id: str = PRODUCT_ID,
    features: Optional[List[str]] = None,
    iat: Optional[int] = None,
    seed_b64: str = SEED,
    typ: str = "lease",
    trial: Any = None,
) -> str:
    claims: Dict[str, Any] = {
        "v": 1,
        "typ": typ,
        "productId": product_id,
        "licenseId": "5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f",
        "activationId": "9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d",
        "hwidHash": hashlib.sha256(hwid.encode("utf-8")).hexdigest(),
        "plan": "Monthly",
        "features": features if features is not None else ["pro", "export"],
        "licenseExpiresAt": exp + 30 * 86400,
        "iat": iat if iat is not None else exp - 86400,
        "exp": exp,
    }
    if trial is not None:  # free-trial lease (SPEC 9.7): the optional signed field
        claims["trial"] = trial
    body = encode_payload(claims)
    return body + "." + sign_text(body, seed_b64)


def base_payload(
    request: Mapping[str, Any],
    type_: str,
    ok: bool,
    code: str,
    message: str = "",
    server_time: Optional[int] = None,
) -> Dict[str, Any]:
    """A payload that echoes the request nonce and product id."""
    return {
        "v": 1,
        "type": type_,
        "ok": ok,
        "code": code,
        "message": message or code,
        "nonce": request.get("nonce"),
        "requestId": str(uuid.uuid4()),
        "serverTime": int(time.time()) if server_time is None else server_time,
        "productId": request.get("productId"),
        "license": None,
        "activation": None,
        "lease": None,
        "update": None,
    }


LICENSE_OBJ = {
    "id": "5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f",
    "plan": "Monthly",
    "status": "active",
    "features": ["pro", "export"],
    "expiresAt": 1769817600,
    "maxDevices": 2,
    "devicesUsed": 1,
    "createdAt": 1767139200,
}


class Reply:
    """What the mock returns: a JSON object, raw bytes, or nothing."""

    def __init__(
        self,
        status: int = 200,
        body: Any = None,
        headers: Optional[Dict[str, str]] = None,
        delay: float = 0.0,
    ) -> None:
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.delay = delay


class RecordedRequest:
    def __init__(self, method: str, path: str, headers: Dict[str, str], body: Any) -> None:
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body


Handler = Callable[[RecordedRequest], Reply]


class MockVelsigilServer:
    """Threaded mock server. ``handler`` maps each request to a :class:`Reply`."""

    def __init__(self, handler: Optional[Handler] = None) -> None:
        self.handler: Handler = handler or (lambda request: Reply(404, {"error": {"code": "not_found"}}))
        self.requests: List[RecordedRequest] = []
        self._lock = threading.Lock()
        self._closing = threading.Event()
        mock = self

        class _RequestHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _handle(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw.decode("utf-8")) if raw else None
                except ValueError:
                    body = raw
                request = RecordedRequest(method, self.path, dict(self.headers.items()), body)
                with mock._lock:
                    mock.requests.append(request)
                reply = mock.handler(request)
                if reply.delay:
                    mock._closing.wait(reply.delay)
                    if mock._closing.is_set():
                        return
                if isinstance(reply.body, (bytes, bytearray)):
                    payload = bytes(reply.body)
                    content_type = "application/octet-stream"
                elif reply.body is None:
                    payload = b""
                    content_type = "application/json"
                else:
                    payload = json.dumps(reply.body).encode("utf-8")
                    content_type = "application/json"
                try:
                    self.send_response(reply.status)
                    self.send_header("Content-Type", reply.headers.get("Content-Type", content_type))
                    self.send_header("Content-Length", str(len(payload)))
                    for name, value in reply.headers.items():
                        if name.lower() != "content-type":
                            self.send_header(name, value)
                    self.end_headers()
                    self.wfile.write(payload)
                except OSError:
                    pass

            def do_POST(self) -> None:  # noqa: N802
                self._handle("POST")

            def do_GET(self) -> None:  # noqa: N802
                self._handle("GET")

        class _Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request: Any, client_address: Any) -> None:
                return  # client disconnects during timeout tests are expected

        self._server = _Server(("127.0.0.1", 0), _RequestHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return "http://127.0.0.1:%d" % self._server.server_address[1]

    def bodies(self, suffix: str = "") -> List[Any]:
        with self._lock:
            return [r.body for r in self.requests if r.path.endswith(suffix)]

    def close(self) -> None:
        self._closing.set()
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> "MockVelsigilServer":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def refused_url() -> str:
    """A localhost URL on which nothing listens."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return "http://127.0.0.1:%d" % port


class FakeClock:
    """Settable clock for the client's ``clock`` option."""

    def __init__(self, now: float) -> None:
        self.now = float(now)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds
