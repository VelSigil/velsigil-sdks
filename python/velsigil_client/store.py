"""Persistence for the per-product device secret and offline lease.

The server issues a **device secret** once, when a device is first bound to
a license, and expects it back on every later request. Losing it makes the
server count a secret mismatch (and products with strict device binding
refuse the device until it is reset), so production apps should use a
persistent store such as :class:`FileStore`.

Implement :class:`LicenseStore` to keep this state somewhere else (OS
keychain, encrypted settings, ...). Implementations must be thread-safe.
"""

from __future__ import annotations

import abc
import json
import logging
import os
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union

from .errors import StoreError

_log = logging.getLogger("velsigil_client")

_FILE_FORMAT_VERSION = 1
_MAX_STORE_FILE_BYTES = 1024 * 1024

#: Directory names used by :func:`default_store_path`, mapped to the names used
#: before the product was renamed Veltrix -> Velsigil. Only read as a fallback
#: so an installed app keeps its device secret and offline lease after updating.
_LEGACY_DIR_NAMES = {"Velsigil": "Veltrix", "velsigil": "veltrix"}


@dataclass(frozen=True)
class StoredState:
    """What the client persists for one product."""

    device_secret: Optional[str] = None
    lease_token: Optional[str] = None

    def __repr__(self) -> str:  # never print the secret
        return "StoredState(device_secret=%s, lease_token=%s)" % (
            "<set>" if self.device_secret else None,
            "<set>" if self.lease_token else None,
        )

    @property
    def is_empty(self) -> bool:
        return not self.device_secret and not self.lease_token


class LicenseStore(abc.ABC):
    """Interface for persisting :class:`StoredState`, keyed by product id."""

    @abc.abstractmethod
    def load(self, product_id: str) -> StoredState:
        """Return the stored state (an empty :class:`StoredState` if none)."""

    @abc.abstractmethod
    def save(self, product_id: str, state: StoredState) -> None:
        """Persist ``state`` for ``product_id`` (replacing what was stored)."""

    def delete(self, product_id: str) -> None:
        """Forget everything stored for ``product_id``."""
        self.save(product_id, StoredState())


class MemoryStore(LicenseStore):
    """Process-local store. State is lost when the process exits."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: Dict[str, StoredState] = {}

    def load(self, product_id: str) -> StoredState:
        with self._lock:
            return self._data.get(product_id, StoredState())

    def save(self, product_id: str, state: StoredState) -> None:
        with self._lock:
            if state.is_empty:
                self._data.pop(product_id, None)
            else:
                self._data[product_id] = state

    def __repr__(self) -> str:
        return "MemoryStore()"


def _valid_text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


# One lock per store file for the whole process: every FileStore on the same
# path shares it, so two instances (for example one per product, both on
# default_store_path()) cannot interleave their read-modify-write of the one
# document that holds every product.
_PATH_LOCKS: Dict[str, threading.Lock] = {}
_PATH_LOCKS_GUARD = threading.Lock()


def _lock_for_path(path: str) -> threading.Lock:
    key = os.path.normcase(path)
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _PATH_LOCKS[key] = lock
        return lock


class FileStore(LicenseStore):
    """JSON file store with atomic writes and owner-only permissions.

    * Writes go to a temporary file in the same directory which is fsync'ed
      and then atomically renamed over the target (``os.replace``), so a
      crash never leaves a half-written file.
    * On POSIX the directory is created ``0700`` and the file ``0600``. On
      Windows the file inherits the ACL of its directory; keep it inside the
      user profile (see :func:`default_store_path`).
    * A corrupt or oversized file is treated as empty (fail closed: no
      lease) and is replaced on the next write.
    * Migration from SDK versions released under the former product name:
      when the file does not exist and its directory is named ``Velsigil``
      or ``velsigil`` (see :func:`default_store_path`), the same file name in
      the sibling ``Veltrix``/``veltrix`` directory is read instead. The next
      write goes to ``path``.

    Safe for concurrent use by multiple threads, also through several
    instances on the same path (they share one process-wide lock per file).
    Separate processes sharing one file are not coordinated: every write
    replaces the whole document, which holds every product, so a write for one
    product can drop another product's concurrent update. Keep one process per
    store file, or give each product its own file.
    """

    def __init__(self, path: Union[str, "os.PathLike[str]"]) -> None:
        self._path = os.path.abspath(os.fspath(path))
        self._lock = _lock_for_path(self._path)
        directory, file_name = os.path.split(self._path)
        legacy_dir = _LEGACY_DIR_NAMES.get(os.path.basename(directory))
        self._legacy_path: Optional[str] = (
            os.path.join(os.path.dirname(directory), legacy_dir, file_name) if legacy_dir else None
        )

    @property
    def path(self) -> str:
        return self._path

    def load(self, product_id: str) -> StoredState:
        with self._lock:
            entry = self._read_all().get(product_id)
        if not isinstance(entry, dict):
            return StoredState()
        return StoredState(
            device_secret=_valid_text(entry.get("deviceSecret")),
            lease_token=_valid_text(entry.get("leaseToken")),
        )

    def save(self, product_id: str, state: StoredState) -> None:
        with self._lock:
            products = self._read_all()
            if state.is_empty:
                if product_id not in products:
                    return
                del products[product_id]
            else:
                entry: Dict[str, str] = {}
                if state.device_secret:
                    entry["deviceSecret"] = state.device_secret
                if state.lease_token:
                    entry["leaseToken"] = state.lease_token
                products[product_id] = entry
            self._write_all(products)

    # -- internals ------------------------------------------------------------

    def _read_all(self) -> Dict[str, Any]:
        raw = self._read_raw(self._path)
        if raw is None and self._legacy_path is not None:
            # Pre-rename location; the next write migrates it to self._path.
            raw = self._read_raw(self._legacy_path)
        if raw is None:
            return {}
        if len(raw) > _MAX_STORE_FILE_BYTES:
            _log.warning("license store file is too large; ignoring its contents")
            return {}
        try:
            document = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            _log.warning("license store file is corrupt; ignoring its contents")
            return {}
        products = document.get("products") if isinstance(document, dict) else None
        if not isinstance(products, dict):
            _log.warning("license store file has an unexpected format; ignoring its contents")
            return {}
        return products

    @staticmethod
    def _read_raw(path: str) -> Optional[bytes]:
        """Up to ``_MAX_STORE_FILE_BYTES + 1`` bytes of ``path``, or None if it does not exist."""
        try:
            with open(path, "rb") as handle:
                return handle.read(_MAX_STORE_FILE_BYTES + 1)
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError as exc:
            raise StoreError("cannot read license store file") from exc

    def _write_all(self, products: Dict[str, Any]) -> None:
        directory = os.path.dirname(self._path)
        payload = json.dumps(
            {"version": _FILE_FORMAT_VERSION, "products": products},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            # mkstemp creates the file with mode 0600 and O_EXCL in the target
            # directory, so the rename below stays on one filesystem.
            fd, tmp_path = tempfile.mkstemp(prefix=".velsigil-", suffix=".tmp", dir=directory)
        except OSError as exc:
            raise StoreError("cannot create license store file") from exc
        try:
            handle = os.fdopen(fd, "wb")
        except OSError as exc:
            os.close(fd)
            self._unlink_quietly(tmp_path)
            raise StoreError("cannot write license store file") from exc
        try:
            with handle:
                if hasattr(os, "fchmod"):
                    os.fchmod(handle.fileno(), 0o600)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            self._replace(tmp_path)
        except OSError as exc:
            self._unlink_quietly(tmp_path)
            raise StoreError("cannot write license store file") from exc
        self._fsync_directory(directory)

    @staticmethod
    def _unlink_quietly(path: str) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    def _replace(self, tmp_path: str) -> None:
        # On Windows a concurrent reader or an antivirus scanner can hold the
        # target briefly; retry a few times before giving up.
        attempts = 5 if sys.platform.startswith("win") else 1
        for attempt in range(attempts):
            try:
                os.replace(tmp_path, self._path)
                return
            except PermissionError:
                if attempt == attempts - 1:
                    raise
                time.sleep(0.05 * (attempt + 1))

    @staticmethod
    def _fsync_directory(directory: str) -> None:
        """Best effort: make the rename durable (POSIX only)."""
        if not hasattr(os, "O_DIRECTORY"):
            return
        try:
            dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        except OSError:  # not supported by every filesystem
            pass
        finally:
            os.close(dir_fd)

    def __repr__(self) -> str:
        return "FileStore(%r)" % self._path


def default_store_path(app_name: str, file_name: str = "license.json") -> str:
    """Per-user location for a :class:`FileStore`.

    * Windows: ``%LOCALAPPDATA%\\<app_name>\\Velsigil\\license.json``
    * macOS:   ``~/Library/Application Support/<app_name>/Velsigil/license.json``
    * Linux:   ``$XDG_DATA_HOME/<app_name>/velsigil/license.json``
      (default ``~/.local/share``)

    A :class:`FileStore` at this path still reads the file that earlier SDK
    versions wrote to the ``Veltrix``/``veltrix`` directory until it saves.
    """
    if not app_name or any(sep in app_name for sep in ("/", "\\")) or app_name in (".", ".."):
        raise ValueError("app_name must be a simple directory name")
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
        return os.path.join(base, app_name, "Velsigil", file_name)
    if sys.platform == "darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
        return os.path.join(base, app_name, "Velsigil", file_name)
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, app_name, "velsigil", file_name)


__all__ = ["StoredState", "LicenseStore", "MemoryStore", "FileStore", "default_store_path"]
