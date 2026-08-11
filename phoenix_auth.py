"""First-party authentication helpers for the Phoenix local control API.

The control key authenticates clients to Phoenix itself.  It is deliberately
separate from third-party provider credentials such as ``GROQ_API_KEY``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Mapping, Optional, Union
from urllib.parse import urlparse


CONTROL_KEY_ENV = "PHOENIX_CONTROL_KEY"
CONTROL_KEY_ENV_ALIAS = "PHOENIX_API_KEY"
CONTROL_KEY_EXPIRES_ENV = "PHOENIX_CONTROL_KEY_EXPIRES_AT"
CONTROL_KEY_PREFIX = "phx_local_"
_KEY_PATTERN = re.compile(r"^phx_local_[A-Za-z0-9_-]{32,128}$")
_KEY_FILE_NAME = "phoenix_control_key.json"
_LOCK_FILE_NAME = ".phoenix_control_key.lock"
_FILE_VERSION = 2
CONTROL_KEY_TERM_DAYS = 30


class ControlKeyError(RuntimeError):
    """Raised when a Phoenix control key cannot be safely loaded or stored."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ControlKeyError("Control-key expiration metadata is missing")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ControlKeyError("Control-key expiration metadata is invalid") from exc
    if parsed.tzinfo is None:
        raise ControlKeyError("Control-key expiration metadata must include a timezone")
    return parsed.astimezone(timezone.utc)


def _is_valid_key(value: object) -> bool:
    return isinstance(value, str) and bool(_KEY_PATTERN.fullmatch(value))


def _fingerprint(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class ControlKeyStore:
    """Create, persist, authenticate, and rotate a Phoenix control key.

    ``env`` defaults to ``os.environ``.  Supplying ``PHOENIX_CONTROL_KEY``
    makes that key the active, environment-managed key and intentionally does
    not copy it to disk. Environment-managed keys must be rotated by updating
    the environment and restarting Phoenix.
    """

    def __init__(
        self,
        config_dir: Union[Path, str],
        env: Optional[Mapping[str, str]] = None,
        now=None,
    ) -> None:
        self._config_dir = Path(config_dir).expanduser()
        self._env = os.environ if env is None else env
        configured_values = {
            str(self._env.get(name, "") or "").strip()
            for name in (CONTROL_KEY_ENV, CONTROL_KEY_ENV_ALIAS)
            if str(self._env.get(name, "") or "").strip()
        }
        if len(configured_values) > 1:
            raise ValueError(
                f"{CONTROL_KEY_ENV} and {CONTROL_KEY_ENV_ALIAS} must match when both are set"
            )
        env_key = next(iter(configured_values), "")
        if env_key and not _is_valid_key(env_key):
            raise ValueError(
                f"{CONTROL_KEY_ENV} must use the {CONTROL_KEY_PREFIX}<urlsafe-random> format"
            )
        self._environment_key = env_key
        self._now = now or (lambda: datetime.now(timezone.utc))
        raw_environment_expiry = str(self._env.get(CONTROL_KEY_EXPIRES_ENV, "") or "").strip()
        if env_key and not raw_environment_expiry:
            raise ValueError(
                f"{CONTROL_KEY_EXPIRES_ENV} is required for an environment-managed monthly key"
            )
        try:
            self._environment_expires_at = _parse_utc(raw_environment_expiry) if env_key else None
        except ControlKeyError as exc:
            raise ValueError(str(exc)) from exc
        self._thread_lock = threading.RLock()

    @property
    def key_path(self) -> Path:
        """Return the path used for the persisted control-key record."""

        return self._config_dir / _KEY_FILE_NAME

    @property
    def _lock_path(self) -> Path:
        return self._config_dir / _LOCK_FILE_NAME

    def get_or_create_key(self) -> str:
        """Return the active key, generating and storing one on first run."""

        if self._environment_key:
            if self._now() >= self._environment_expires_at:
                raise ControlKeyError("Environment-managed control key has expired")
            return self._environment_key

        with self._thread_lock:
            self._ensure_config_dir()
            with self._exclusive_file_lock():
                record = self._read_record(required=False)
                if record is None:
                    record = self._new_record(previous=None)
                    self._write_record_atomic(record)
                elif self._record_expired(record):
                    record = self._new_record(previous=record)
                    self._write_record_atomic(record)
                elif record.get("version") != _FILE_VERSION or not record.get("expires_at"):
                    record = self._migrate_record(record)
                    if self._record_expired(record):
                        record = self._new_record(previous=record)
                    self._write_record_atomic(record)
                return record["key"]

    def authenticate(self, candidate: object) -> bool:
        """Return whether ``candidate`` exactly matches the active key."""

        if not isinstance(candidate, str) or not candidate:
            return False
        try:
            active_key = self.get_or_create_key()
        except ControlKeyError:
            return False
        return hmac.compare_digest(candidate, active_key)

    def rotate(self) -> str:
        """Replace the persisted key and return the new plaintext once."""

        if self._environment_key:
            raise ControlKeyError(
                f"Cannot rotate an environment-managed key; update {CONTROL_KEY_ENV} and restart Phoenix"
            )

        with self._thread_lock:
            self._ensure_config_dir()
            with self._exclusive_file_lock():
                previous = self._read_record(required=False)
                record = self._new_record(previous=previous)
                self._write_record_atomic(record)
                return record["key"]

    def metadata(self) -> dict:
        """Return non-secret metadata about the active key."""

        if self._environment_key:
            key = self._environment_key
            return {
                "configured": True,
                "source": "environment",
                "key_id": _fingerprint(key).split(":", 1)[1][:12],
                "fingerprint": _fingerprint(key),
                "created_at": None,
                "rotated_at": None,
                "expires_at": self._environment_expires_at.isoformat(timespec="seconds"),
                "active": self._now() < self._environment_expires_at,
                "term": "30 days",
            }

        self.get_or_create_key()
        with self._thread_lock:
            with self._exclusive_file_lock():
                record = self._read_record(required=True)
                key = record["key"]
        return {
            "configured": True,
            "source": "file",
            "key_id": _fingerprint(key).split(":", 1)[1][:12],
            "fingerprint": _fingerprint(key),
            "created_at": record["created_at"],
            "rotated_at": record["rotated_at"],
            "expires_at": record["expires_at"],
            "active": not self._record_expired(record),
            "term": "30 days",
            "key_path": str(self.key_path),
        }

    def _new_record(self, previous: Optional[dict]) -> dict:
        now = self._now().astimezone(timezone.utc)
        now_text = now.isoformat(timespec="seconds")
        return {
            "version": _FILE_VERSION,
            "key": self._generate_key(),
            "created_at": previous["created_at"] if previous else now_text,
            "rotated_at": now_text if previous else None,
            "expires_at": (now + timedelta(days=CONTROL_KEY_TERM_DAYS)).isoformat(timespec="seconds"),
        }

    def _migrate_record(self, record: dict) -> dict:
        issued = _parse_utc(record.get("rotated_at") or record.get("created_at"))
        migrated = dict(record)
        migrated["version"] = _FILE_VERSION
        migrated["expires_at"] = (
            issued + timedelta(days=CONTROL_KEY_TERM_DAYS)
        ).isoformat(timespec="seconds")
        return migrated

    def _record_expired(self, record: dict) -> bool:
        expiry = record.get("expires_at")
        if not expiry:
            issued = _parse_utc(record.get("rotated_at") or record.get("created_at"))
            expiry_time = issued + timedelta(days=CONTROL_KEY_TERM_DAYS)
        else:
            expiry_time = _parse_utc(expiry)
        return self._now() >= expiry_time

    @staticmethod
    def _generate_key() -> str:
        return CONTROL_KEY_PREFIX + secrets.token_urlsafe(32)

    def _ensure_config_dir(self) -> None:
        if self._config_dir.is_symlink():
            raise ControlKeyError("Refusing to use a symlink as the control-key directory")
        try:
            self._config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise ControlKeyError("Could not create the control-key directory") from exc
        if not self._config_dir.is_dir():
            raise ControlKeyError("Control-key path is not a directory")
        try:
            os.chmod(str(self._config_dir), 0o700)
        except OSError as exc:
            raise ControlKeyError("Could not secure the control-key directory") from exc

    @contextmanager
    def _exclusive_file_lock(self) -> Iterator[None]:
        """Serialize first-run creation and rotation across local processes."""

        flags = os.O_CREAT | os.O_RDWR
        try:
            descriptor = os.open(str(self._lock_path), flags, 0o600)
            os.chmod(str(self._lock_path), 0o600)
        except OSError as exc:
            raise ControlKeyError("Could not open the control-key lock") from exc

        try:
            if os.name == "nt":
                import msvcrt

                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def _read_record(self, required: bool) -> Optional[dict]:
        path = self.key_path
        if not path.exists():
            if required:
                raise ControlKeyError("Control-key file is missing")
            return None
        if path.is_symlink():
            raise ControlKeyError("Refusing to read a symlinked control-key file")

        try:
            file_stat = path.stat()
            if not stat.S_ISREG(file_stat.st_mode):
                raise ControlKeyError("Control-key path is not a regular file")
            os.chmod(str(path), 0o600)
            with path.open("r", encoding="utf-8") as handle:
                record = json.load(handle)
        except ControlKeyError:
            raise
        except (OSError, ValueError, TypeError) as exc:
            raise ControlKeyError("Control-key file is unreadable or corrupt") from exc

        if not isinstance(record, dict):
            raise ControlKeyError("Control-key file has an invalid structure")
        if record.get("version") not in {1, _FILE_VERSION}:
            raise ControlKeyError("Control-key file uses an unsupported version")
        if not _is_valid_key(record.get("key")):
            raise ControlKeyError("Control-key file contains an invalid key")
        if not isinstance(record.get("created_at"), str) or not record["created_at"]:
            raise ControlKeyError("Control-key file has invalid creation metadata")
        rotated_at = record.get("rotated_at")
        if rotated_at is not None and not isinstance(rotated_at, str):
            raise ControlKeyError("Control-key file has invalid rotation metadata")
        if record.get("version") == _FILE_VERSION:
            _parse_utc(record.get("expires_at"))
        return record

    def _write_record_atomic(self, record: dict) -> None:
        temporary_path: Optional[Path] = None
        descriptor = -1
        try:
            descriptor, raw_path = tempfile.mkstemp(
                prefix=".phoenix-control-key-",
                suffix=".tmp",
                dir=str(self._config_dir),
            )
            temporary_path = Path(raw_path)
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            else:  # pragma: no cover - Windows compatibility path
                os.chmod(str(temporary_path), 0o600)
            payload = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(str(temporary_path), str(self.key_path))
            temporary_path = None
            os.chmod(str(self.key_path), 0o600)
            self._fsync_config_dir()
        except OSError as exc:
            raise ControlKeyError("Could not atomically persist the control key") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass

    def _fsync_config_dir(self) -> None:
        if os.name == "nt":
            return
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        descriptor = os.open(str(self._config_dir), flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def extract_bearer(header: object) -> str:
    """Extract a single RFC-style Bearer token, or return an empty string."""

    if not isinstance(header, str):
        return ""
    parts = header.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    token = parts[1]
    if not token or any(character in token for character in "\r\n,;"):
        return ""
    return token


def valid_local_origin(host: object, origin: object, port: object) -> bool:
    """Validate the Host/Origin pair for the loopback-only Phoenix web API."""

    try:
        numeric_port = int(port)
    except (TypeError, ValueError):
        return False
    if not 1 <= numeric_port <= 65535 or not isinstance(host, str):
        return False

    normalized_host = host.strip().lower()
    allowed_hosts = {
        f"127.0.0.1:{numeric_port}",
        f"localhost:{numeric_port}",
        f"[::1]:{numeric_port}",
    }
    if normalized_host not in allowed_hosts:
        return False

    if origin is None:
        return True
    if not isinstance(origin, str):
        return False
    normalized_origin = origin.strip()
    if not normalized_origin:
        return True
    return normalized_origin in {
        f"http://127.0.0.1:{numeric_port}",
        f"http://localhost:{numeric_port}",
    }


def request_origin_mode(host: object, origin: object, port: object, trusted_origin: object = "") -> str:
    """Return ``local``, ``remote``, or an empty string for an invalid request."""

    if valid_local_origin(host, origin, port):
        return "local"
    if not isinstance(host, str) or not isinstance(trusted_origin, str):
        return ""
    configured = trusted_origin.strip().rstrip("/")
    try:
        parsed = urlparse(configured)
    except ValueError:
        return ""
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.port not in {None, 443}
    ):
        return ""
    expected_host = parsed.hostname.lower()
    normalized_host = host.strip().lower()
    if normalized_host not in {expected_host, f"{expected_host}:443"}:
        return ""
    if origin is None or (isinstance(origin, str) and not origin.strip()):
        return "remote"
    if not isinstance(origin, str) or origin.strip().rstrip("/") != configured:
        return ""
    return "remote"
