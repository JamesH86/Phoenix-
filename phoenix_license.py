"""Strict verification for signed, offline Phoenix license tokens.

Phoenix license tokens use this compact, canonical format::

    phxlic1.<base64url(canonical-json)>.<base64url(ed25519-signature)>

The signature covers the ASCII bytes ``phxlic1.<payload-segment>``.  The JSON
payload must contain exactly these fields:

``environment``, ``exp``, ``iat``, ``payment_reference_hash``, ``tier``,
``type``, and ``version``.

This verifier intentionally contains no signing API and accepts only a raw
Ed25519 *public* key encoded as ``ed25519:<unpadded-base64url>``.  Ed25519 is
not available in Python's standard library, so verification uses the optional
``cryptography`` package.  If that vetted backend is unavailable, licensing
fails closed with :class:`LicenseDependencyError`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from typing import Callable, Mapping, Optional

from phoenix_subscriptions import TIERS


TOKEN_PREFIX = "phxlic1"
PUBLIC_KEY_PREFIX = "ed25519:"
LICENSE_TYPE = "phoenix-license"
LICENSE_VERSION = 1
LICENSE_TERM_SECONDS = 30 * 24 * 60 * 60
DEFAULT_CLOCK_SKEW_SECONDS = 300
MAX_CLOCK_SKEW_SECONDS = 300
MAX_TOKEN_CHARS = 4096
MAX_PAYLOAD_BYTES = 2048
MIN_TIMESTAMP = 0
MAX_TIMESTAMP = 253402300799  # 9999-12-31T23:59:59Z

PUBLIC_KEY_ENV = "PHOENIX_LICENSE_PUBLIC_KEY"
ALLOW_SANDBOX_ENV = "PHOENIX_LICENSE_ALLOW_SANDBOX"

PAYMENT_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
CLAIM_FIELDS = frozenset(
    {
        "environment",
        "exp",
        "iat",
        "payment_reference_hash",
        "tier",
        "type",
        "version",
    }
)
_EMPTY_PAYMENT_REFERENCE_HASH = hashlib.sha256(b"").hexdigest()


class LicenseError(RuntimeError):
    """Base class for safe offline-license failures."""


class LicenseConfigurationError(LicenseError):
    """Raised when the verifier is not securely configured."""


class LicenseDependencyError(LicenseConfigurationError):
    """Raised when the vetted Ed25519 verification backend is unavailable."""


class LicenseFormatError(LicenseError):
    """Raised when a token is not in the canonical Phoenix format."""


class LicenseSignatureError(LicenseError):
    """Raised when an Ed25519 signature does not verify."""


class LicenseClaimError(LicenseError):
    """Raised when a signed license contains invalid claims."""


class LicenseExpiredError(LicenseClaimError):
    """Raised when a signed license has reached its expiration time."""


class LicenseNotYetValidError(LicenseClaimError):
    """Raised when a signed license was issued too far in the future."""


class LicenseEnvironmentError(LicenseClaimError):
    """Raised when a license belongs to an untrusted environment."""


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: object, label: str) -> bytes:
    if not isinstance(segment, str) or not BASE64URL_PATTERN.fullmatch(segment):
        raise LicenseFormatError(f"License {label} is not canonical base64url")
    try:
        decoded = base64.b64decode(
            segment + ("=" * (-len(segment) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise LicenseFormatError(f"License {label} is not valid base64url") from exc
    if not hmac.compare_digest(_b64url_encode(decoded), segment):
        raise LicenseFormatError(f"License {label} is not canonical base64url")
    return decoded


def _reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise LicenseFormatError("License payload contains a duplicate field")
        value[key] = item
    return value


def _reject_json_constant(_value: str):
    raise LicenseFormatError("License payload contains a non-standard JSON value")


def _parse_payload(payload_bytes: bytes) -> dict:
    if not payload_bytes or len(payload_bytes) > MAX_PAYLOAD_BYTES:
        raise LicenseFormatError("License payload has an invalid size")
    try:
        payload_text = payload_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise LicenseFormatError("License payload is not UTF-8 JSON") from exc
    try:
        payload = json.loads(
            payload_text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except LicenseFormatError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise LicenseFormatError("License payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise LicenseFormatError("License payload must be a JSON object")
    canonical = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if not hmac.compare_digest(canonical, payload_bytes):
        raise LicenseFormatError("License payload is not canonical JSON")
    return payload


def _parse_public_key(value: object) -> bytes:
    if not isinstance(value, str) or not value:
        raise LicenseConfigurationError("Phoenix license public key is not configured")
    if value != value.strip() or "PRIVATE KEY" in value.upper():
        raise LicenseConfigurationError("Phoenix requires a raw Ed25519 public key")
    if not value.startswith(PUBLIC_KEY_PREFIX):
        raise LicenseConfigurationError(
            "Phoenix license public key must use the ed25519: base64url format"
        )
    try:
        raw = _b64url_decode(value[len(PUBLIC_KEY_PREFIX) :], "public key")
    except LicenseFormatError as exc:
        raise LicenseConfigurationError(
            "Phoenix license public key is not canonical base64url"
        ) from exc
    if len(raw) != 32:
        raise LicenseConfigurationError("Phoenix Ed25519 public key must be 32 bytes")
    return raw


def _verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify with a vetted optional backend, or fail closed if unavailable."""

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise LicenseDependencyError(
            "Offline license verification requires the optional 'cryptography' "
            "package; install it before enabling signed licenses"
        ) from exc

    try:
        verifier = Ed25519PublicKey.from_public_bytes(public_key)
        verifier.verify(signature, message)
    except InvalidSignature:
        return False
    except (TypeError, ValueError) as exc:
        raise LicenseConfigurationError("Phoenix Ed25519 public key is invalid") from exc
    return True


def _utc_now(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise LicenseConfigurationError("License verification clock must be timezone-aware")
    return value.astimezone(timezone.utc)


def _timestamp(value: object, field: str) -> int:
    if type(value) is not int or not MIN_TIMESTAMP <= value <= MAX_TIMESTAMP:
        raise LicenseClaimError(f"License {field} must be a valid integer UTC timestamp")
    return value


class LicenseVerifier:
    """Verify Ed25519 Phoenix licenses and return subscription-compatible access."""

    def __init__(
        self,
        public_key: str,
        *,
        allow_sandbox: bool = False,
        now: Optional[Callable[[], datetime]] = None,
        clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> None:
        if type(allow_sandbox) is not bool:
            raise LicenseConfigurationError("allow_sandbox must be a boolean")
        if (
            type(clock_skew_seconds) is not int
            or clock_skew_seconds < 0
            or clock_skew_seconds > MAX_CLOCK_SKEW_SECONDS
        ):
            raise LicenseConfigurationError(
                f"clock_skew_seconds must be between 0 and {MAX_CLOCK_SKEW_SECONDS}"
            )
        self._public_key = _parse_public_key(public_key)
        self._allow_sandbox = allow_sandbox
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._clock_skew_seconds = clock_skew_seconds

    @classmethod
    def from_environment(
        cls,
        environment: Optional[Mapping[str, str]] = None,
        *,
        now: Optional[Callable[[], datetime]] = None,
        clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> "LicenseVerifier":
        """Load the public key and explicit Sandbox policy from environment."""

        source = os.environ if environment is None else environment
        public_key = source.get(PUBLIC_KEY_ENV, "")
        sandbox_setting = source.get(ALLOW_SANDBOX_ENV, "0")
        if sandbox_setting not in {"0", "1"}:
            raise LicenseConfigurationError(
                f"{ALLOW_SANDBOX_ENV} must be exactly 0 or 1"
            )
        return cls(
            public_key,
            allow_sandbox=sandbox_setting == "1",
            now=now,
            clock_skew_seconds=clock_skew_seconds,
        )

    def verify(self, token: object) -> dict:
        """Verify ``token`` and return a secret-free subscription entitlement."""

        if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_CHARS:
            raise LicenseFormatError("Phoenix license token has an invalid size")
        if token != token.strip():
            raise LicenseFormatError("Phoenix license token cannot contain surrounding whitespace")
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
            raise LicenseFormatError("Phoenix license token has an unsupported format")

        payload_segment = parts[1]
        payload_bytes = _b64url_decode(payload_segment, "payload")
        signature = _b64url_decode(parts[2], "signature")
        if len(signature) != 64:
            raise LicenseFormatError("Phoenix Ed25519 signature must be 64 bytes")
        payload = _parse_payload(payload_bytes)

        signing_input = f"{TOKEN_PREFIX}.{payload_segment}".encode("ascii")
        if not _verify_ed25519(self._public_key, signing_input, signature):
            raise LicenseSignatureError("Phoenix license signature is invalid")

        return self._entitlement(payload)

    def _entitlement(self, payload: dict) -> dict:
        if set(payload) != CLAIM_FIELDS:
            raise LicenseClaimError("License payload fields do not match version 1")
        if payload.get("type") != LICENSE_TYPE:
            raise LicenseClaimError("License type is invalid")
        if type(payload.get("version")) is not int or payload["version"] != LICENSE_VERSION:
            raise LicenseClaimError("License version is unsupported")

        tier = payload.get("tier")
        if not isinstance(tier, str) or tier not in TIERS:
            raise LicenseClaimError("License tier is invalid")

        license_environment = payload.get("environment")
        if license_environment not in {"production", "sandbox"}:
            raise LicenseEnvironmentError("License environment is invalid")
        if license_environment == "sandbox" and not self._allow_sandbox:
            raise LicenseEnvironmentError("Sandbox licenses are disabled")

        payment_hash = payload.get("payment_reference_hash")
        if (
            not isinstance(payment_hash, str)
            or not PAYMENT_HASH_PATTERN.fullmatch(payment_hash)
            or payment_hash == ("0" * 64)
            or hmac.compare_digest(payment_hash, _EMPTY_PAYMENT_REFERENCE_HASH)
        ):
            raise LicenseClaimError("License payment reference hash is invalid")

        issued_at = _timestamp(payload.get("iat"), "iat")
        expires_at = _timestamp(payload.get("exp"), "exp")
        if expires_at - issued_at != LICENSE_TERM_SECONDS:
            raise LicenseClaimError("License term must be exactly 30 days")

        now_timestamp = int(_utc_now(self._now()).timestamp())
        if issued_at > now_timestamp + self._clock_skew_seconds:
            raise LicenseNotYetValidError("License is not yet valid")
        if now_timestamp >= expires_at:
            raise LicenseExpiredError("License has expired")

        tier_definition = TIERS[tier]
        return {
            "authenticated": True,
            "kind": "subscription",
            "tier": tier,
            "tier_name": tier_definition["name"],
            "features": list(tier_definition["features"]),
            "expires_at": datetime.fromtimestamp(expires_at, timezone.utc).isoformat(
                timespec="seconds"
            ),
            "active": True,
        }


def verify_license_token(
    token: object,
    public_key: str,
    *,
    allow_sandbox: bool = False,
    now: Optional[Callable[[], datetime]] = None,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> dict:
    """Convenience wrapper around :class:`LicenseVerifier`."""

    return LicenseVerifier(
        public_key,
        allow_sandbox=allow_sandbox,
        now=now,
        clock_skew_seconds=clock_skew_seconds,
    ).verify(token)


__all__ = [
    "ALLOW_SANDBOX_ENV",
    "LICENSE_TERM_SECONDS",
    "LICENSE_TYPE",
    "LICENSE_VERSION",
    "LicenseClaimError",
    "LicenseConfigurationError",
    "LicenseDependencyError",
    "LicenseEnvironmentError",
    "LicenseError",
    "LicenseExpiredError",
    "LicenseFormatError",
    "LicenseNotYetValidError",
    "LicenseSignatureError",
    "LicenseVerifier",
    "PUBLIC_KEY_ENV",
    "PUBLIC_KEY_PREFIX",
    "TOKEN_PREFIX",
    "verify_license_token",
]
