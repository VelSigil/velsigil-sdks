"""Python client for the Velsigil license server."""

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

# Stay silent unless the application configures logging.
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
