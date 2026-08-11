"""Secure Square billing primitives for Phoenix Guardian.

This module deliberately keeps payment credentials, webhook secrets, and
plaintext claim tokens out of public status responses and the purchase
database.  It does not expose an arbitrary-price API: the paid Phoenix offers
are fixed here on the server.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import tempfile
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


SQUARE_VERSION = "2026-07-15"
CONFIG_FILE_ENV = "PHOENIX_SQUARE_CONFIG_FILE"


class SquareError(RuntimeError):
    """Base error for safe-to-display Square integration failures."""


class SquareConfigError(SquareError):
    """Raised when owner-private Square configuration is invalid."""


class SquareAPIError(SquareError):
    """Raised when Square rejects or returns an invalid API request."""


class SquarePurchaseError(SquareError):
    """Raised when a purchase, payment, or claim cannot be accepted."""


class SquareWebhookError(SquarePurchaseError):
    """Raised when a Square webhook is unsigned, malformed, or mismatched."""


@dataclass(frozen=True)
class Offer:
    tier: str
    name: str
    amount_cents: int
    currency: str = "USD"

    def public(self) -> dict:
        return {
            "tier": self.tier,
            "name": self.name,
            "amount_cents": self.amount_cents,
            "currency": self.currency,
            "term_days": 30,
        }


OFFERS: Mapping[str, Offer] = MappingProxyType(
    {
        "solo": Offer("solo", "Phoenix Guardian Solo Researcher", 5_000),
        "base": Offer("base", "Phoenix Guardian Base", 15_000),
        "enterprise": Offer("enterprise", "Phoenix Guardian Enterprise", 100_000),
        "government": Offer("government", "Phoenix Guardian Government", 150_000),
    }
)


def offer_catalog() -> list:
    """Return the fixed public offers without exposing billing credentials."""

    return [OFFERS[tier].public() for tier in ("solo", "base", "enterprise", "government")]


def _nonempty(value: object, label: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise SquareConfigError(f"Square {label} is required")
    if any(character in result for character in "\r\n\0"):
        raise SquareConfigError(f"Square {label} contains invalid characters")
    return result


@dataclass(frozen=True, repr=False)
class SquareConfig:
    """Owner-private Square configuration.

    ``load`` accepts a private JSON file and/or environment variables.  An
    environment value overrides the corresponding JSON field.  Secret values
    are intentionally omitted from ``repr`` and ``public_status``.
    """

    environment: str
    access_token: str
    application_id: str
    location_id: str
    webhook_signature_key: str = ""
    notification_url: str = ""

    _ENVIRONMENT_KEYS = MappingProxyType(
        {
            "environment": "PHOENIX_SQUARE_ENVIRONMENT",
            "access_token": "PHOENIX_SQUARE_ACCESS_TOKEN",
            "application_id": "PHOENIX_SQUARE_APPLICATION_ID",
            "location_id": "PHOENIX_SQUARE_LOCATION_ID",
            "webhook_signature_key": "PHOENIX_SQUARE_WEBHOOK_SIGNATURE_KEY",
            "notification_url": "PHOENIX_SQUARE_NOTIFICATION_URL",
        }
    )

    def __post_init__(self) -> None:
        environment = str(self.environment or "").strip().lower()
        if environment not in {"sandbox", "production"}:
            raise SquareConfigError("Square environment must be sandbox or production")
        object.__setattr__(self, "environment", environment)
        for name, label in (
            ("access_token", "access token"),
            ("application_id", "application ID"),
            ("location_id", "location ID"),
        ):
            object.__setattr__(self, name, _nonempty(getattr(self, name), label))
        signature_key = str(self.webhook_signature_key or "").strip()
        notification_url = str(self.notification_url or "").strip()
        if bool(signature_key) != bool(notification_url):
            raise SquareConfigError(
                "Square webhook signature key and notification URL must be configured together"
            )
        object.__setattr__(self, "webhook_signature_key", signature_key)
        object.__setattr__(self, "notification_url", notification_url)
        if notification_url:
            _nonempty(signature_key, "webhook signature key")
            _nonempty(notification_url, "notification URL")
            parsed = urlparse(notification_url)
            if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
                raise SquareConfigError("Square notification URL must be a public HTTPS URL")
            if parsed.fragment:
                raise SquareConfigError("Square notification URL cannot contain a fragment")

    def __repr__(self) -> str:
        return f"SquareConfig(environment={self.environment!r}, configured=True)"

    @property
    def api_base_url(self) -> str:
        if self.environment == "sandbox":
            return "https://connect.squareupsandbox.com"
        return "https://connect.squareup.com"

    @classmethod
    def load(
        cls,
        path: Optional[os.PathLike | str] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> "SquareConfig":
        environment = os.environ if env is None else env
        configured_path = path or str(environment.get(CONFIG_FILE_ENV, "") or "").strip() or None
        values: dict = {}
        if configured_path is not None:
            config_path = Path(configured_path).expanduser()
            cls._validate_private_file(config_path)
            try:
                loaded = json.loads(config_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise SquareConfigError("Could not read private Square configuration") from exc
            if not isinstance(loaded, dict):
                raise SquareConfigError("Private Square configuration must be a JSON object")
            values.update(loaded)
        for field, variable in cls._ENVIRONMENT_KEYS.items():
            candidate = str(environment.get(variable, "") or "").strip()
            if candidate:
                values[field] = candidate
        try:
            return cls(**{field: values.get(field, "") for field in cls._ENVIRONMENT_KEYS})
        except TypeError as exc:
            raise SquareConfigError("Private Square configuration is invalid") from exc

    @staticmethod
    def _validate_private_file(path: Path) -> None:
        if path.is_symlink():
            raise SquareConfigError("Square configuration cannot be a symbolic link")
        try:
            details = path.stat()
        except OSError as exc:
            raise SquareConfigError("Square configuration file is unavailable") from exc
        if not stat.S_ISREG(details.st_mode):
            raise SquareConfigError("Square configuration must be a regular file")
        if os.name != "nt" and stat.S_IMODE(details.st_mode) & 0o077:
            raise SquareConfigError("Square configuration permissions must be owner-only (0600)")

    def save_private(self, path: os.PathLike | str) -> Path:
        """Atomically save credentials in an owner-only JSON file."""

        destination = Path(path).expanduser()
        if destination.exists() and destination.is_symlink():
            raise SquareConfigError("Square configuration cannot be a symbolic link")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt":
            destination.parent.chmod(0o700)
        descriptor, temporary = tempfile.mkstemp(
            prefix="square-", suffix=".tmp", dir=str(destination.parent)
        )
        temporary_path = Path(temporary)
        payload = {
            "environment": self.environment,
            "access_token": self.access_token,
            "application_id": self.application_id,
            "location_id": self.location_id,
            "webhook_signature_key": self.webhook_signature_key,
            "notification_url": self.notification_url,
        }
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                json.dump(payload, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, destination)
            if os.name != "nt":
                destination.chmod(0o600)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_path.exists():
                temporary_path.unlink()
        return destination

    def public_status(self) -> dict:
        webhook_ready = bool(self.webhook_signature_key and self.notification_url)
        return {
            "configured": True,
            "environment": self.environment,
            "currency": "USD",
            "checkout_ready": True,
            "webhook_ready": webhook_ready,
            "checkout_enabled": True,
            "webhook_verification_enabled": webhook_ready,
            "square_version": SQUARE_VERSION,
            "offers": offer_catalog(),
        }


class SquareClient:
    """Minimal standard-library client for Square CreatePaymentLink."""

    def __init__(self, config: SquareConfig, opener: Callable = urlopen, timeout: int = 20) -> None:
        self.config = config
        self._opener = opener
        self._timeout = max(1, min(int(timeout), 60))

    def create_payment_link(
        self,
        tier: str,
        purchase_id: str,
        redirect_url: Optional[str] = None,
    ) -> dict:
        offer = _offer(tier)
        identifier = _identifier(purchase_id, "purchase ID")
        payload = {
            "idempotency_key": identifier,
            "quick_pay": {
                "name": f"{offer.name} - 30 days",
                "price_money": {"amount": offer.amount_cents, "currency": offer.currency},
                "location_id": self.config.location_id,
            },
            "payment_note": f"Phoenix Guardian purchase {identifier}",
        }
        if redirect_url:
            clean_redirect = str(redirect_url).strip()
            parsed = urlparse(clean_redirect)
            has_credentials = parsed.username is not None or parsed.password is not None
            clean = (
                bool(parsed.netloc)
                and not has_credentials
                and not parsed.fragment
                and not any(character in clean_redirect for character in "\r\n\0")
            )
            secure = parsed.scheme == "https"
            sandbox_loopback = (
                self.config.environment == "sandbox"
                and parsed.scheme == "http"
                and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
            )
            if not clean or not (secure or sandbox_loopback):
                raise SquarePurchaseError(
                    "Checkout redirect URL must use HTTPS, except clean Sandbox loopback URLs"
                )
            payload["checkout_options"] = {"redirect_url": clean_redirect}
        request = Request(
            f"{self.config.api_base_url}/v2/online-checkout/payment-links",
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.config.access_token}",
                "Square-Version": SQUARE_VERSION,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            response = self._opener(request, timeout=self._timeout)
            if hasattr(response, "__enter__"):
                with response as opened:
                    raw = opened.read()
            else:
                raw = response.read()
        except HTTPError as exc:
            raise SquareAPIError(f"Square checkout request failed with HTTP {exc.code}") from exc
        except (URLError, OSError, TimeoutError) as exc:
            raise SquareAPIError("Square checkout service is unavailable") from exc
        try:
            result = json.loads(raw.decode("utf-8"))
            link = result["payment_link"]
            link_id = _identifier(link["id"], "payment link ID")
            order_id = _identifier(link["order_id"], "Square order ID")
            checkout_url = str(link["url"])
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SquareAPIError("Square returned an invalid checkout response") from exc
        parsed_checkout = urlparse(checkout_url)
        if parsed_checkout.scheme != "https" or not parsed_checkout.netloc:
            raise SquareAPIError("Square returned an invalid checkout URL")
        return {
            "payment_link_id": link_id,
            "order_id": order_id,
            "checkout_url": checkout_url,
            "purchase_id": identifier,
            "tier": offer.tier,
            "amount_cents": offer.amount_cents,
            "currency": offer.currency,
        }


def square_webhook_signature(signature_key: str, notification_url: str, raw_body: bytes) -> str:
    """Compute Square's base64 HMAC-SHA256 webhook signature."""

    if not isinstance(raw_body, bytes):
        raise TypeError("Square webhook body must be raw bytes")
    key = _nonempty(signature_key, "webhook signature key").encode("utf-8")
    url = _nonempty(notification_url, "notification URL").encode("utf-8")
    return base64.b64encode(hmac.new(key, url + raw_body, hashlib.sha256).digest()).decode("ascii")


def verify_square_webhook(
    signature_key: str,
    notification_url: str,
    raw_body: bytes,
    supplied_signature: object,
) -> bool:
    """Verify Square's signature using the exact URL and raw request bytes."""

    if not isinstance(supplied_signature, str) or not supplied_signature.strip():
        return False
    expected = square_webhook_signature(signature_key, notification_url, raw_body)
    return hmac.compare_digest(expected, supplied_signature.strip())


def _offer(tier: object) -> Offer:
    normalized = str(tier or "").strip().lower()
    try:
        return OFFERS[normalized]
    except KeyError as exc:
        raise SquarePurchaseError("Unknown paid Phoenix tier") from exc


def _identifier(value: object, label: str) -> str:
    result = str(value or "").strip()
    if not result or len(result) > 192 or any(character in result for character in "\r\n\0"):
        raise SquarePurchaseError(f"Invalid {label}")
    return result


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class PurchaseStore:
    """Owner-private SQLite ledger for Square purchase and claim state."""

    def __init__(
        self,
        path: os.PathLike | str,
        location_id: str,
        now: Optional[Callable[[], str]] = None,
    ) -> None:
        self.path = Path(path).expanduser()
        self.location_id = _nonempty(location_id, "location ID")
        self._now = now or _utc_now
        self._setup_lock = threading.Lock()
        self._initialize()

    def _prepare_path(self) -> None:
        if self.path.exists() and self.path.is_symlink():
            raise SquarePurchaseError("Purchase database cannot be a symbolic link")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt":
            self.path.parent.chmod(0o700)

    def _connect(self) -> sqlite3.Connection:
        self._prepare_path()
        connection = sqlite3.connect(str(self.path), timeout=20, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 20000")
        if os.name != "nt":
            self.path.chmod(0o600)
        return connection

    def _initialize(self) -> None:
        with self._setup_lock, self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS purchases (
                    purchase_id TEXT PRIMARY KEY,
                    tier TEXT NOT NULL,
                    amount_cents INTEGER NOT NULL,
                    currency TEXT NOT NULL,
                    location_id TEXT NOT NULL,
                    claim_token_hash TEXT NOT NULL,
                    order_id TEXT UNIQUE,
                    payment_link_id TEXT UNIQUE,
                    checkout_url TEXT,
                    payment_id TEXT UNIQUE,
                    status TEXT NOT NULL CHECK(status IN ('created','pending_payment','paid','claimed')),
                    created_at TEXT NOT NULL,
                    paid_at TEXT,
                    claimed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS webhook_events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    payment_id TEXT NOT NULL,
                    body_hash TEXT NOT NULL,
                    processed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS purchases_order_idx ON purchases(order_id);
                """
            )
        if os.name != "nt":
            self.path.chmod(0o600)

    def create_purchase(self, tier: str, purchase_id: Optional[str] = None) -> dict:
        offer = _offer(tier)
        identifier = _identifier(purchase_id or str(uuid.uuid4()), "purchase ID")
        claim_token = f"phx_claim_{secrets.token_urlsafe(32)}"
        claim_hash = hashlib.sha256(claim_token.encode("utf-8")).hexdigest()
        created_at = str(self._now())
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """INSERT INTO purchases
                       (purchase_id,tier,amount_cents,currency,location_id,claim_token_hash,status,created_at)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (
                        identifier,
                        offer.tier,
                        offer.amount_cents,
                        offer.currency,
                        self.location_id,
                        claim_hash,
                        "created",
                        created_at,
                    ),
                )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise SquarePurchaseError("Purchase ID has already been used") from exc
        return {
            "purchase_id": identifier,
            "claim_token": claim_token,
            "tier": offer.tier,
            "amount_cents": offer.amount_cents,
            "currency": offer.currency,
            "status": "created",
        }

    def record_payment_link(self, purchase_id: str, link: Mapping[str, object]) -> dict:
        identifier = _identifier(purchase_id, "purchase ID")
        order_id = _identifier(link.get("order_id"), "Square order ID")
        link_id = _identifier(link.get("payment_link_id"), "payment link ID")
        checkout_url = str(link.get("checkout_url") or "").strip()
        parsed = urlparse(checkout_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise SquarePurchaseError("Invalid Square checkout URL")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM purchases WHERE purchase_id = ?", (identifier,)
            ).fetchone()
            if row is None:
                connection.rollback()
                raise SquarePurchaseError("Purchase was not found")
            if row["order_id"] is not None:
                if row["order_id"] != order_id or row["payment_link_id"] != link_id:
                    connection.rollback()
                    raise SquarePurchaseError("Purchase is already bound to another Square order")
            else:
                try:
                    connection.execute(
                        """UPDATE purchases SET order_id=?,payment_link_id=?,checkout_url=?,status='pending_payment'
                           WHERE purchase_id=? AND status='created'""",
                        (order_id, link_id, checkout_url, identifier),
                    )
                except sqlite3.IntegrityError as exc:
                    connection.rollback()
                    raise SquarePurchaseError("Square order or payment link has already been used") from exc
            connection.commit()
        result = self.public_status(identifier)
        result["checkout_url"] = checkout_url
        return result

    def begin_checkout(
        self,
        client: SquareClient,
        tier: str,
        redirect_url: Optional[str] = None,
    ) -> dict:
        purchase = self.create_purchase(tier)
        link = client.create_payment_link(tier, purchase["purchase_id"], redirect_url)
        recorded = self.record_payment_link(purchase["purchase_id"], link)
        recorded["claim_token"] = purchase["claim_token"]
        return recorded

    def process_webhook(
        self,
        raw_body: bytes,
        supplied_signature: object,
        config: SquareConfig,
    ) -> dict:
        if not config.webhook_signature_key or not config.notification_url:
            raise SquareWebhookError("Square webhook verification is not configured")
        if not verify_square_webhook(
            config.webhook_signature_key,
            config.notification_url,
            raw_body,
            supplied_signature,
        ):
            raise SquareWebhookError("Square webhook signature is invalid")
        try:
            event = json.loads(raw_body.decode("utf-8"))
            event_id = _identifier(event["event_id"], "Square event ID")
            event_type = str(event["type"])
            payment = event["data"]["object"]["payment"]
            payment_id = _identifier(payment["id"], "Square payment ID")
            status = _identifier(payment["status"], "Square payment status")
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SquareWebhookError("Square webhook body is invalid") from exc
        if event_type not in {"payment.created", "payment.updated"}:
            raise SquareWebhookError("Square webhook is not a payment event")
        body_hash = hashlib.sha256(raw_body).hexdigest()
        now = str(self._now())
        if status != "COMPLETED":
            duplicate = self._record_ignored_event(
                event_id, event_type, payment_id, body_hash, now
            )
            return {
                "accepted": True,
                "duplicate": duplicate,
                "ignored": True,
                "reason": "payment_not_completed",
                "event_id": event_id,
                "http_status": 200,
            }
        try:
            order_id = _identifier(payment["order_id"], "Square order ID")
            location_id = _identifier(payment["location_id"], "Square location ID")
            amount = payment["amount_money"]["amount"]
            currency = str(payment["amount_money"]["currency"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SquareWebhookError("Completed Square payment body is invalid") from exc
        if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
            raise SquareWebhookError("Square payment amount is invalid")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                "SELECT * FROM webhook_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if prior is not None:
                if not hmac.compare_digest(prior["body_hash"], body_hash):
                    connection.rollback()
                    raise SquareWebhookError("Square event ID was replayed with different content")
                connection.commit()
                return {
                    "accepted": True,
                    "duplicate": True,
                    "ignored": False,
                    "event_id": event_id,
                    "http_status": 200,
                }
            row = connection.execute(
                "SELECT * FROM purchases WHERE order_id = ?", (order_id,)
            ).fetchone()
            if row is None:
                connection.rollback()
                raise SquareWebhookError("Square order does not match a Phoenix purchase")
            if location_id != self.location_id or location_id != row["location_id"]:
                connection.rollback()
                raise SquareWebhookError("Square payment location does not match")
            if amount != row["amount_cents"] or currency != row["currency"]:
                connection.rollback()
                raise SquareWebhookError("Square payment total does not match the selected offer")
            if row["payment_id"] is not None and row["payment_id"] != payment_id:
                connection.rollback()
                raise SquareWebhookError("Phoenix purchase is already bound to another payment")
            try:
                connection.execute(
                    """UPDATE purchases SET payment_id=?,status='paid',paid_at=?
                       WHERE purchase_id=? AND status IN ('pending_payment','paid')""",
                    (payment_id, now, row["purchase_id"]),
                )
                connection.execute(
                    """INSERT INTO webhook_events
                       (event_id,event_type,payment_id,body_hash,processed_at) VALUES (?,?,?,?,?)""",
                    (event_id, event_type, payment_id, body_hash, now),
                )
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise SquareWebhookError("Square payment or event has already been used") from exc
            connection.commit()
        return {
            "accepted": True,
            "duplicate": False,
            "ignored": False,
            "event_id": event_id,
            "purchase_id": row["purchase_id"],
            "status": "paid",
            "http_status": 200,
        }

    def _record_ignored_event(
        self,
        event_id: str,
        event_type: str,
        payment_id: str,
        body_hash: str,
        now: str,
    ) -> bool:
        """Record a signed, non-completed payment event for idempotent 2xx acknowledgement."""

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                "SELECT * FROM webhook_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if prior is not None:
                if not hmac.compare_digest(prior["body_hash"], body_hash):
                    connection.rollback()
                    raise SquareWebhookError("Square event ID was replayed with different content")
                connection.commit()
                return True
            try:
                connection.execute(
                    """INSERT INTO webhook_events
                       (event_id,event_type,payment_id,body_hash,processed_at) VALUES (?,?,?,?,?)""",
                    (event_id, event_type, payment_id, body_hash, now),
                )
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise SquareWebhookError("Square event has already been used") from exc
            connection.commit()
        return False

    def claim(
        self,
        purchase_id: str,
        claim_token: object,
        subscription_store,
        customer_label: str = "Square customer",
    ) -> dict:
        identifier = _identifier(purchase_id, "purchase ID")
        candidate = str(claim_token or "")
        candidate_hash = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM purchases WHERE purchase_id = ?", (identifier,)
            ).fetchone()
            stored_hash = row["claim_token_hash"] if row is not None else "0" * 64
            if row is None or not hmac.compare_digest(stored_hash, candidate_hash):
                connection.rollback()
                raise SquarePurchaseError("Purchase or claim token is invalid")
            if row["status"] != "paid":
                connection.rollback()
                if row["status"] == "claimed":
                    raise SquarePurchaseError("This purchase has already been claimed")
                raise SquarePurchaseError("Square payment is not complete")
            try:
                issued = subscription_store.issue(row["tier"], customer_label)
            except Exception:
                connection.rollback()
                raise
            changed = connection.execute(
                """UPDATE purchases SET status='claimed',claimed_at=?
                   WHERE purchase_id=? AND status='paid'""",
                (str(self._now()), identifier),
            ).rowcount
            if changed != 1:
                connection.rollback()
                raise SquarePurchaseError("This purchase has already been claimed")
            connection.commit()
        return {"purchase": self.public_status(identifier), **issued}

    def public_status(self, purchase_id: str) -> dict:
        identifier = _identifier(purchase_id, "purchase ID")
        with self._connect() as connection:
            row = connection.execute(
                """SELECT purchase_id,tier,amount_cents,currency,status,created_at,paid_at,claimed_at
                   FROM purchases WHERE purchase_id = ?""",
                (identifier,),
            ).fetchone()
        if row is None:
            raise SquarePurchaseError("Purchase was not found")
        return dict(row)

    def authenticated_status(self, purchase_id: str, claim_token: object) -> dict:
        """Return purchase status only after its one-time claim secret authenticates."""

        identifier = _identifier(purchase_id, "purchase ID")
        candidate_hash = hashlib.sha256(str(claim_token or "").encode("utf-8")).hexdigest()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT claim_token_hash FROM purchases WHERE purchase_id = ?", (identifier,)
            ).fetchone()
        stored_hash = row["claim_token_hash"] if row is not None else "0" * 64
        if row is None or not hmac.compare_digest(stored_hash, candidate_hash):
            raise SquarePurchaseError("Purchase or claim token is invalid")
        return self.public_status(identifier)

    def event_count(self) -> int:
        """Return a non-secret count useful for owner diagnostics and tests."""

        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM webhook_events").fetchone()[0])


__all__ = [
    "CONFIG_FILE_ENV",
    "OFFERS",
    "SQUARE_VERSION",
    "Offer",
    "PurchaseStore",
    "SquareAPIError",
    "SquareClient",
    "SquareConfig",
    "SquareConfigError",
    "SquareError",
    "SquarePurchaseError",
    "SquareWebhookError",
    "offer_catalog",
    "square_webhook_signature",
    "verify_square_webhook",
]
