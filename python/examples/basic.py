"""Example: validate a license, gate features and check for updates.

Set API_URL, PRODUCT_ID and PUBLIC_KEY below, then run::

    python examples/basic.py --license-key <key> [--download PATH] [--deactivate]
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import urllib.parse
from typing import Tuple

# Allow running from a source checkout without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from velsigil_client import (  # noqa: E402
    Code,
    DownloadError,
    FileStore,
    VelsigilClient,
    VelsigilError,
    default_store_path,
)

# Values from Products > your product > Integration. Hard-code them: never load them from user-editable config.
API_URL = "<your Velsigil server URL>"
PRODUCT_ID = "<your product id>"
PUBLIC_KEY = "<your product's public key>"
APP_VERSION = "1.2.0"

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
OVERRIDE_VARIABLES = ("VELSIGIL_API_URL", "VELSIGIL_PRODUCT_ID", "VELSIGIL_PUBLIC_KEY")

USAGE = (
    "Usage: set API_URL, PRODUCT_ID and PUBLIC_KEY at the top of examples/basic.py to your product's values\n"
    "from the Velsigil panel (Products > your product > Integration), then run\n"
    "  python examples/basic.py --license-key <your license key>\n"
    "Local testing only: VELSIGIL_API_URL, VELSIGIL_PRODUCT_ID and VELSIGIL_PUBLIC_KEY override them when the\n"
    "API URL is loopback (localhost, 127.0.0.1, [::1])."
)

FRIENDLY = {
    Code.INVALID_KEY: "That license key was not found.",
    Code.LICENSE_EXPIRED: "Your license has expired. Please renew it.",
    Code.LICENSE_SUSPENDED: "Your license is suspended. Please contact support.",
    Code.LICENSE_REVOKED: "This license has been revoked.",
    Code.LICENSE_BANNED: "This license has been banned.",
    Code.DEVICE_LIMIT_REACHED: "This license is already active on the maximum number of devices.",
    Code.DEVICE_VERIFICATION_FAILED: "This device could not be verified. Reset your devices in the customer portal.",
    Code.OUTDATED_VERSION: "This version is no longer supported. Please update.",
    Code.NETWORK_ERROR: "The license server could not be reached and no offline license is available.",
    Code.INTERNAL_ERROR: "The license server is temporarily unavailable and no offline license is available.",
    Code.LEASE_EXPIRED: "The license server could not be reached and the offline license has expired.",
    Code.LEASE_INVALID: "The license server could not be reached and the stored offline license is not valid here.",
    Code.RATE_LIMITED: "Too many attempts. Please wait a moment and try again.",
}


def is_placeholder(value: str) -> bool:
    value = value.strip()
    return not value or (value.startswith("<") and value.endswith(">"))


def is_loopback_url(url: str) -> bool:
    try:
        host = urllib.parse.urlsplit(url.strip()).hostname
    except ValueError:
        return False
    return (host or "").lower() in LOOPBACK_HOSTS


def configuration() -> Tuple[str, str, str]:
    """Local testing only: env overrides apply just for a loopback API URL. Remove in a real app."""
    api_url = os.environ.get("VELSIGIL_API_URL") or API_URL
    if not is_loopback_url(api_url):
        if any(os.environ.get(name) for name in OVERRIDE_VARIABLES):
            print(
                "Ignoring the VELSIGIL_* overrides: they apply only to a loopback API URL "
                "(localhost, 127.0.0.1, [::1]).",
                file=sys.stderr,
            )
        return API_URL, PRODUCT_ID, PUBLIC_KEY
    return (
        api_url,
        os.environ.get("VELSIGIL_PRODUCT_ID") or PRODUCT_ID,
        os.environ.get("VELSIGIL_PUBLIC_KEY") or PUBLIC_KEY,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Velsigil client example")
    parser.add_argument("--license-key", default=os.environ.get("VELSIGIL_LICENSE_KEY"), help="license key to validate")
    parser.add_argument("--download", metavar="PATH", help="download the latest release to PATH")
    parser.add_argument("--deactivate", action="store_true", help="release this device's activation")
    parser.add_argument("--verbose", action="store_true", help="show SDK log messages")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")

    api_url, product_id, public_key = configuration()
    if any(is_placeholder(value) for value in (api_url, product_id, public_key)):
        print(USAGE, file=sys.stderr)
        return 2

    license_key = args.license_key or input("License key: ").strip()

    try:
        client = VelsigilClient(
            api_url,
            product_id,
            public_key,
            store=FileStore(default_store_path("VelsigilExample")),
        )
    except VelsigilError as exc:
        print("Configuration problem: %s" % exc, file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2

    if args.deactivate:
        result = client.deactivate(license_key)
        print("Deactivated." if result.ok else "Deactivation failed: %s (%s)" % (result.message, result.code))
        return 0 if result.ok else 1

    result = client.validate_with_offline_fallback(license_key, version=APP_VERSION)
    if not result.ok:
        print(FRIENDLY.get(result.code, result.message), "[%s]" % result.code)
        if result.retry_after is not None:
            print("Try again in %d s." % result.retry_after)
        if result.request_id:
            print("Support reference: %s" % result.request_id)
        return 1

    lic = result.license
    print("License OK%s - plan %s" % (" (offline lease)" if result.offline else "", lic.plan if lic else "?"))
    if result.offline and result.retry_after is not None:
        print("The license server asks to retry in %d s." % result.retry_after)
    if result.is_lifetime:
        print("Never expires.")
    elif result.expires_at is not None:
        print("Expires %s (%s days left)" % (result.expires_at_datetime.isoformat(), result.days_remaining()))

    if result.has_feature("export"):
        print("Export feature enabled.")

    if not result.offline:
        update = client.check_update(APP_VERSION).update
        if update is not None and update.update_available:
            print("Update available: %s%s" % (update.latest_version, " (mandatory)" if update.mandatory else ""))
            if args.download:
                link = client.get_download(license_key, update.latest_version)
                if not link.ok or link.download is None:
                    print("Download not available: %s (%s)" % (link.message, link.code))
                    return 1
                try:
                    path = client.download_to_file(link.download, args.download)
                except DownloadError as exc:
                    print("Download failed: %s" % exc, file=sys.stderr)
                    return 1
                print("Saved %s (%d bytes, SHA-256 verified) to %s" % (link.download.file_name, link.download.size, path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
