"""Minimal Velsigil integration: validate at start-up, gate features, check updates.

Usage::

    python examples/basic.py --license-key VSG-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
    python examples/basic.py --license-key ... --download ./downloads/app.zip
    python examples/basic.py --deactivate --license-key ...

Replace API_URL, PRODUCT_ID and PUBLIC_KEY with the values from the product's
"Integration" tab in the Velsigil panel. The public key is deliberately a
constant in code: loading it from a file or environment variable would let a
user swap in their own key and sign their own "valid" responses. (The
``VELSIGIL_*`` environment overrides below exist only so the example can be
pointed at a test server; do not ship them.)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

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

API_URL = os.environ.get("VELSIGIL_API_URL", "https://licenses.example.com")
PRODUCT_ID = os.environ.get("VELSIGIL_PRODUCT_ID", "0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b")
PUBLIC_KEY = os.environ.get("VELSIGIL_PUBLIC_KEY", "I8lY1RS9MwgbPMa+7xrzLkdKhAGCoMbVmRApSuJjToI=")
APP_VERSION = "1.2.0"

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
    Code.RATE_LIMITED: "Too many attempts. Please wait a moment and try again.",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Velsigil client example")
    parser.add_argument("--license-key", default=os.environ.get("VELSIGIL_LICENSE_KEY"), help="license key to validate")
    parser.add_argument("--download", metavar="PATH", help="download the latest release to PATH")
    parser.add_argument("--deactivate", action="store_true", help="release this device's activation")
    parser.add_argument("--verbose", action="store_true", help="show SDK log messages")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")

    license_key = args.license_key or input("License key: ").strip()

    try:
        client = VelsigilClient(
            API_URL,
            PRODUCT_ID,
            PUBLIC_KEY,
            # Persist the device secret and offline lease across restarts.
            store=FileStore(default_store_path("VelsigilExample")),
            # Only for local test servers; never in production builds.
            allow_insecure_http=os.environ.get("VELSIGIL_ALLOW_INSECURE_HTTP") == "1",
        )
    except VelsigilError as exc:
        print("Configuration problem: %s" % exc, file=sys.stderr)
        return 2

    if args.deactivate:
        result = client.deactivate(license_key)
        print("Deactivated." if result.ok else "Deactivation failed: %s (%s)" % (result.message, result.code))
        return 0 if result.ok else 1

    result = client.validate_with_offline_fallback(license_key, version=APP_VERSION)
    if not result.ok:
        print(FRIENDLY.get(result.code, result.message), "[%s]" % result.code)
        if result.request_id:
            print("Support reference: %s" % result.request_id)
        return 1

    lic = result.license
    print("License OK%s - plan %s" % (" (offline lease)" if result.offline else "", lic.plan if lic else "?"))
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
