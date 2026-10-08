#!/usr/bin/env python3
"""Runs an SDK HTTP test binary against an in-process Velsigil mock server.

Usage: run_http_tests.py --vectors path/to/test-vectors.json -- <test-binary> [args...]

The binary receives three extra arguments: the mock server base URL, a URL on which nothing
listens (connection refused), and the product public key from the test vectors.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mock_server import create_server  # noqa: E402 - path set up above


def closed_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("missing test command after --")

    with open(args.vectors, "r", encoding="utf-8") as handle:
        public_key = json.load(handle)["keys"]["publicKey"]

    server = create_server(args.vectors, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        refused_url = f"http://127.0.0.1:{closed_port()}"
        return subprocess.call(command + [base_url, refused_url, public_key], timeout=300)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
