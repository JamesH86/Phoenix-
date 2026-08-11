"""Validated, local organization profile for Phoenix Guardian."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping


DEFAULT_PROFILE = {
    "organization_name": "Your Organization",
    "business_unit": "Security Operations",
    "environment": "Production",
    "primary_domain": "",
    "security_contact": "",
    "asset_owner": "",
    "maintenance_window": "Organization policy",
    "data_region": "Local",
}

ALLOWED_ENVIRONMENTS = {"Production", "Staging", "Development", "Mixed"}
FIELD_LIMIT = 160
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class EnterpriseProfileError(ValueError):
    """Raised when an organization profile is unsafe or malformed."""


class EnterpriseProfileStore:
    def __init__(self, config_dir: Path) -> None:
        self.config_dir = Path(config_dir).expanduser()
        self.path = self.config_dir / "enterprise-profile.json"

    def _prepare_directory(self) -> None:
        self.config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.config_dir.is_symlink():
            raise EnterpriseProfileError("Enterprise configuration directory cannot be a symbolic link.")
        try:
            self.config_dir.chmod(0o700)
        except OSError:
            pass

    @staticmethod
    def validate(values: Mapping[str, Any]) -> Dict[str, str]:
        if not isinstance(values, Mapping):
            raise EnterpriseProfileError("Enterprise profile must be an object.")
        profile: Dict[str, str] = {}
        for field, default in DEFAULT_PROFILE.items():
            value = str(values.get(field, default) or "").strip()
            if len(value) > FIELD_LIMIT:
                raise EnterpriseProfileError(f"{field} exceeds {FIELD_LIMIT} characters.")
            if any(ord(char) < 32 for char in value):
                raise EnterpriseProfileError(f"{field} contains control characters.")
            profile[field] = value

        if not profile["organization_name"]:
            raise EnterpriseProfileError("Organization name is required.")
        if profile["environment"] not in ALLOWED_ENVIRONMENTS:
            raise EnterpriseProfileError("Environment must be Production, Staging, Development, or Mixed.")
        domain = profile["primary_domain"].lower().rstrip(".")
        if domain and not DOMAIN_RE.fullmatch(domain):
            raise EnterpriseProfileError("Primary domain must be a valid DNS name without a scheme or path.")
        profile["primary_domain"] = domain
        contact = profile["security_contact"]
        if contact and not EMAIL_RE.fullmatch(contact):
            raise EnterpriseProfileError("Security contact must be a valid email address.")
        return profile

    def load(self) -> Dict[str, str]:
        self._prepare_directory()
        if not self.path.exists():
            return dict(DEFAULT_PROFILE)
        if self.path.is_symlink():
            raise EnterpriseProfileError("Enterprise profile cannot be a symbolic link.")
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise EnterpriseProfileError(f"Could not read enterprise profile: {exc}") from exc
        return self.validate(payload)

    def save(self, values: Mapping[str, Any]) -> Dict[str, str]:
        profile = self.validate(values)
        self._prepare_directory()
        if self.path.exists() and self.path.is_symlink():
            raise EnterpriseProfileError("Enterprise profile cannot be a symbolic link.")
        fd, temporary = tempfile.mkstemp(prefix="enterprise-profile-", suffix=".tmp", dir=str(self.config_dir))
        temporary_path = Path(temporary)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(profile, stream, indent=2, sort_keys=True)
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
        return profile
