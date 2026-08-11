"""Private remote-access configuration for Phoenix Guardian."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Dict
from urllib.parse import urlparse


class RemoteAccessError(ValueError):
    """Raised when a remote-access configuration is unsafe or malformed."""


def normalize_trusted_origin(value: object) -> str:
    origin = str(value or "").strip().rstrip("/")
    if not origin:
        return ""
    parsed = urlparse(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise RemoteAccessError("Remote access requires an exact HTTPS origin.")
    if parsed.path or parsed.params or parsed.query or parsed.fragment:
        raise RemoteAccessError("Remote access origin cannot contain a path, query, or fragment.")
    if parsed.port not in {None, 443}:
        raise RemoteAccessError("Remote access origin must use the standard HTTPS port.")
    return f"https://{parsed.hostname.lower()}"


class RemoteAccessStore:
    def __init__(self, config_dir: Path) -> None:
        self.config_dir = Path(config_dir).expanduser()
        self.path = self.config_dir / "remote-access.json"

    def _prepare_directory(self) -> None:
        self.config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.config_dir.is_symlink():
            raise RemoteAccessError("Remote configuration directory cannot be a symbolic link.")
        try:
            self.config_dir.chmod(0o700)
        except OSError:
            pass

    def load(self) -> Dict[str, object]:
        self._prepare_directory()
        if not self.path.exists():
            return {"enabled": False, "provider": "", "trusted_origin": ""}
        if self.path.is_symlink():
            raise RemoteAccessError("Remote configuration cannot be a symbolic link.")
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RemoteAccessError(f"Could not read remote configuration: {exc}") from exc
        if not isinstance(payload, dict):
            raise RemoteAccessError("Remote configuration must be an object.")
        origin = normalize_trusted_origin(payload.get("trusted_origin"))
        enabled = bool(payload.get("enabled")) and bool(origin)
        provider = str(payload.get("provider", "") or "").strip().lower()
        if provider not in {"", "tailscale"}:
            raise RemoteAccessError("Unsupported remote-access provider.")
        return {"enabled": enabled, "provider": provider, "trusted_origin": origin}

    def save(self, trusted_origin: object, provider: str = "tailscale") -> Dict[str, object]:
        origin = normalize_trusted_origin(trusted_origin)
        provider = str(provider or "").strip().lower()
        if provider != "tailscale":
            raise RemoteAccessError("Only private Tailscale Serve access is supported.")
        payload: Dict[str, object] = {"enabled": True, "provider": provider, "trusted_origin": origin}
        self._prepare_directory()
        if self.path.exists() and self.path.is_symlink():
            raise RemoteAccessError("Remote configuration cannot be a symbolic link.")
        descriptor, temporary = tempfile.mkstemp(prefix="remote-access-", suffix=".tmp", dir=str(self.config_dir))
        temporary_path = Path(temporary)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(str(temporary_path), str(self.path))
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
        finally:
            if temporary_path.exists():
                temporary_path.unlink()
        return payload

    def disable(self) -> Dict[str, object]:
        self._prepare_directory()
        if self.path.exists() and self.path.is_symlink():
            raise RemoteAccessError("Remote configuration cannot be a symbolic link.")
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        return {"enabled": False, "provider": "", "trusted_origin": ""}
