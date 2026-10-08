"""Official Python client for the Velsigil license server.

Quick start::

    from velsigil_client import VelsigilClient, FileStore, default_store_path

    client = VelsigilClient(
        "https://licenses.example.com",
        "0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b",
        "<your product's public key>",  # panel: Products > your product > Integration
        store=FileStore(default_store_path("MyApp")),
    )
    result = client.validate_with_offline_fallback(license_key, version="1.4.0")
    if not result.ok:
        print("License problem:", result.code, result.message)
"""

import logging as _logging

from .client import API_PATH, DEFAULT_TIMEOUT, LEASE_REVOKING_CODES, SDK_VERSION, VelsigilClient
from .crypto import Ed25519Verifier, key_id_for, open_envelope, verify_lease
from .errors import (
    Code,
    ConfigurationError,
    CryptoBackendError,
    DownloadError,
    EnvelopeError,
    HardwareIdError,
    LeaseError,
    StoreError,
    VelsigilError,
)
from .hwid import HWID_PREFIX, get_hardware_id, hwid_from_machine_id
from .models import (
    ActivationInfo,
    DownloadInfo,
    LeaseInfo,
    LicenseInfo,
    TRIAL_REF_PARAM,
    UpdateInfo,
    VelsigilResult,
    with_trial_ref,
)
from .store import FileStore, LicenseStore, MemoryStore, StoredState, default_store_path

__version__ = SDK_VERSION

# Library etiquette: stay silent unless the application configures logging.
# Log records never contain license keys, device secrets or lease tokens.
_logging.getLogger("velsigil_client").addHandler(_logging.NullHandler())

__all__ = [
    "__version__",
    "API_PATH",
    "DEFAULT_TIMEOUT",
    "LEASE_REVOKING_CODES",
    "VelsigilClient",
    "VelsigilResult",
    "LicenseInfo",
    "ActivationInfo",
    "LeaseInfo",
    "UpdateInfo",
    "DownloadInfo",
    "TRIAL_REF_PARAM",
    "with_trial_ref",
    "Code",
    "VelsigilError",
    "ConfigurationError",
    "CryptoBackendError",
    "HardwareIdError",
    "StoreError",
    "DownloadError",
    "EnvelopeError",
    "LeaseError",
    "LicenseStore",
    "MemoryStore",
    "FileStore",
    "StoredState",
    "default_store_path",
    "HWID_PREFIX",
    "get_hardware_id",
    "hwid_from_machine_id",
    "Ed25519Verifier",
    "key_id_for",
    "open_envelope",
    "verify_lease",
]
