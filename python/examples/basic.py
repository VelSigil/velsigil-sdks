"""Minimal Velsigil integration: validate at start-up, gate features, check updates.

Usage::

    python examples/basic.py --license-key VSG-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
    python examples/basic.py --license-key ... --download ./downloads/app.zip
    python examples/basic.py --deactivate --license-key ...

Set API_URL, PRODUCT_ID and PUBLIC_KEY below to the values from the product's
"Integration" tab in the Velsigil panel (Products > your product > Integration).
While any of them is still a placeholder, the example prints a usage message
and exits with code 2. They are deliberately constants in code: loading the
public key from a file or an environment variable would let a user swap in
their own key and sign their own "valid" responses.
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

# Replace these placeholders with your product's values (panel: Products > your product > Integration) and
# keep them compiled into your application. The public key is the trust anchor that makes forged server
# responses detectable: never load it from a file, an environment variable or the network.
API_URL = "<your Velsigil server URL>"  # e.g. "https://licenses.example.com"
PRODUCT_ID = "<your product id>"
PUBLIC_KEY = "<your product's public key>"
APP_VERSION = "1.2.0"

#: Hosts for which the local-testing environment overrides below are honoured (the SDK's loopback hosts).
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
OVERRIDE_VARIABLES = ("VELSIGIL_API_URL", "VELSIGIL_PRODUCT_ID", "VELSIGIL_PUBLIC_KEY")

USAGE = (
    "Usage: set API_URL, PRODUCT_ID and PUBLIC_KEY at the top of examples/basic.py to your product's values\n"
    "from the Velsigil panel (Products > your product > Integration), then run\n"
    "  python examples/basic.py --license-key <your license key>\n"
    "Local testing only: VELSIGIL_API_URL, VELSIGIL_PRODUCT_ID and VELSIGIL_PUBLIC_KEY override them when the\n"
    "API URL is loopback (localhost, 127.0.0.1, [::1])."
)

#: Human-friendly text for the codes an end user is most likely to see.
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
    """True for an empty value or one that still holds its "<...>" placeholder."""
    value = value.strip()
    return not value or (value.startswith("<") and value.endswith(">"))


def is_loopback_url(url: str) -> bool:
    try:
        host = urllib.parse.urlsplit(url.strip()).hostname
    except ValueError:
        return False
    return (host or "").lower() in LOOPBACK_HOSTS


def configuration() -> Tuple[str, str, str]:
    """The compiled-in API_URL, PRODUCT_ID and PUBLIC_KEY.

    Local testing only (remove this from a real application): the VELSIGIL_API_URL,
    VELSIGIL_PRODUCT_ID and VELSIGIL_PUBLIC_KEY environment variables override them ONLY when the
    resulting API URL is loopback (localhost, 127.0.0.1, [::1]), for example a panel dev server on
    http://localhost:3000. For any other server they are ignored, so the environment can never point
    the example at another server or make it trust another key.
    """
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
            # Persist the device secret and offline lease across restarts.
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
        if result.retry_after is not None:  # the server's Retry-After (429 or 503)
            print("Try again in %d s." % result.retry_after)
        if result.request_id:
            print("Support reference: %s" % result.request_id)
        return 1

    lic = result.license
    print("License OK%s - plan %s" % (" (offline lease)" if result.offline else "", lic.plan if lic else "?"))
    if result.offline and result.retry_after is not None:
        # The server answered 503 with Retry-After (e.g. its database is unreachable): when to try online again.
        print("The license server asks to retry in %d s." % result.retry_after)
    if result.is_lifetime:
        print("Never expires.")
    elif result.expires_at is not None:
        print("Expires %s (%s days left)" % (result.expires_at_datetime.isoformat(), result.days_remaining()))

    # Gate features on the *verified* result, and re-check in more than one place.
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
