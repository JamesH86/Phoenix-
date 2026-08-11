import json
import os
import stat
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from phoenix_square import (
    OFFERS,
    SQUARE_VERSION,
    PurchaseStore,
    SquareClient,
    SquareConfig,
    SquareConfigError,
    SquarePurchaseError,
    SquareWebhookError,
    square_webhook_signature,
    verify_square_webhook,
)


class _Response:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


class _SubscriptionStore:
    def __init__(self):
        self.calls = []
        self.lock = threading.Lock()

    def issue(self, tier, customer_label=""):
        with self.lock:
            self.calls.append((tier, customer_label))
            number = len(self.calls)
        return {
            "control_key": f"phx_{tier}_test-key-{number}",
            "subscription": {"tier": tier, "customer_label": customer_label},
        }


class SquareBillingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.secret_token = "sandbox-secret-access-token-do-not-store-in-db"
        self.signature_key = "sandbox-webhook-signature-secret"
        self.config = SquareConfig(
            environment="sandbox",
            access_token=self.secret_token,
            application_id="sandbox-app-id",
            location_id="sandbox-location",
            webhook_signature_key=self.signature_key,
            notification_url="https://billing.example.test/api/square/webhook",
        )
        self.store = PurchaseStore(self.root / "purchases.sqlite3", self.config.location_id)

    def tearDown(self):
        self.temporary.cleanup()

    def _checkout(self, tier="base"):
        purchase = self.store.create_purchase(tier)
        link = {
            "order_id": f"order-{purchase['purchase_id']}",
            "payment_link_id": f"link-{purchase['purchase_id']}",
            "checkout_url": "https://square.link/u/example",
        }
        self.store.record_payment_link(purchase["purchase_id"], link)
        return purchase, link

    def _event(self, purchase, link, **overrides):
        payment = {
            "id": overrides.get("payment_id", "payment-1"),
            "order_id": overrides.get("order_id", link["order_id"]),
            "location_id": overrides.get("location_id", self.config.location_id),
            "status": overrides.get("status", "COMPLETED"),
            "amount_money": {
                "amount": overrides.get("amount", OFFERS[purchase["tier"]].amount_cents),
                "currency": overrides.get("currency", "USD"),
            },
        }
        payload = {
            "event_id": overrides.get("event_id", "event-1"),
            "type": overrides.get("event_type", "payment.updated"),
            "data": {"object": {"payment": payment}},
        }
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = square_webhook_signature(
            self.signature_key, self.config.notification_url, body
        )
        return body, signature

    def test_fixed_server_side_prices(self):
        self.assertEqual(OFFERS["solo"].amount_cents, 5_000)
        self.assertEqual(OFFERS["base"].amount_cents, 15_000)
        self.assertEqual(OFFERS["enterprise"].amount_cents, 100_000)
        self.assertEqual(OFFERS["government"].amount_cents, 150_000)
        self.assertTrue(all(offer.currency == "USD" for offer in OFFERS.values()))
        with self.assertRaises(SquarePurchaseError):
            self.store.create_purchase("demo")

    @unittest.skipIf(os.name == "nt", "POSIX permission assertion")
    def test_config_and_database_are_owner_private(self):
        path = self.config.save_private(self.root / "private" / "square.json")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        loaded = SquareConfig.load(path, env={})
        self.assertEqual(loaded.access_token, self.secret_token)
        self.store.create_purchase("solo")
        self.assertEqual(stat.S_IMODE(self.store.path.stat().st_mode), 0o600)
        path.chmod(0o644)
        with self.assertRaises(SquareConfigError):
            SquareConfig.load(path, env={})

    def test_config_environment_override_and_public_status_hide_secrets(self):
        env = {
            "PHOENIX_SQUARE_ENVIRONMENT": "sandbox",
            "PHOENIX_SQUARE_ACCESS_TOKEN": self.secret_token,
            "PHOENIX_SQUARE_APPLICATION_ID": "app-secretish-id",
            "PHOENIX_SQUARE_LOCATION_ID": "location-secretish-id",
            "PHOENIX_SQUARE_WEBHOOK_SIGNATURE_KEY": self.signature_key,
            "PHOENIX_SQUARE_NOTIFICATION_URL": self.config.notification_url,
        }
        loaded = SquareConfig.load(env=env)
        public = loaded.public_status()
        rendered = repr(loaded) + json.dumps(public)
        self.assertTrue(public["checkout_ready"])
        self.assertTrue(public["webhook_ready"])
        self.assertEqual(public["currency"], "USD")
        for secret in (
            self.secret_token,
            self.signature_key,
            "app-secretish-id",
            "location-secretish-id",
            self.config.notification_url,
        ):
            self.assertNotIn(secret, rendered)

    def test_sandbox_checkout_config_allows_webhook_pair_to_be_added_later(self):
        checkout_only = SquareConfig(
            environment="sandbox",
            access_token=self.secret_token,
            application_id="sandbox-app-id",
            location_id=self.config.location_id,
        )
        public = checkout_only.public_status()
        self.assertTrue(public["checkout_ready"])
        self.assertFalse(public["webhook_ready"])
        self.assertEqual(public["currency"], "USD")
        with self.assertRaises(SquareConfigError):
            SquareConfig(
                environment="sandbox",
                access_token=self.secret_token,
                application_id="sandbox-app-id",
                location_id=self.config.location_id,
                webhook_signature_key=self.signature_key,
            )
        with self.assertRaises(SquareConfigError):
            SquareConfig(
                environment="sandbox",
                access_token=self.secret_token,
                application_id="sandbox-app-id",
                location_id=self.config.location_id,
                notification_url=self.config.notification_url,
            )

    def test_create_payment_link_uses_pinned_version_and_fixed_amount(self):
        captured = {}

        def opener(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return _Response(
                {
                    "payment_link": {
                        "id": "link-1",
                        "order_id": "order-1",
                        "url": "https://square.link/u/checkout",
                    }
                }
            )

        result = SquareClient(self.config, opener=opener).create_payment_link(
            "enterprise", "purchase-1"
        )
        request = captured["request"]
        payload = json.loads(request.data)
        self.assertEqual(request.full_url, "https://connect.squareupsandbox.com/v2/online-checkout/payment-links")
        self.assertEqual(request.get_header("Square-version"), SQUARE_VERSION)
        self.assertEqual(request.get_header("Authorization"), f"Bearer {self.secret_token}")
        self.assertEqual(payload["quick_pay"]["price_money"], {"amount": 100_000, "currency": "USD"})
        self.assertEqual(payload["quick_pay"]["location_id"], self.config.location_id)
        self.assertEqual(result["order_id"], "order-1")

    def test_sandbox_allows_clean_loopback_redirect_but_production_does_not(self):
        captured = []

        def opener(request, timeout):
            captured.append(json.loads(request.data))
            return _Response(
                {
                    "payment_link": {
                        "id": f"link-{len(captured)}",
                        "order_id": f"order-{len(captured)}",
                        "url": "https://square.link/u/checkout",
                    }
                }
            )

        SquareClient(self.config, opener=opener).create_payment_link(
            "solo", "purchase-loopback", "http://127.0.0.1:8787/?purchase=ready"
        )
        self.assertEqual(
            captured[0]["checkout_options"]["redirect_url"],
            "http://127.0.0.1:8787/?purchase=ready",
        )
        production = SquareConfig(
            environment="production",
            access_token="production-token",
            application_id="production-app",
            location_id="production-location",
        )
        with self.assertRaises(SquarePurchaseError):
            SquareClient(production, opener=opener).create_payment_link(
                "solo", "purchase-production", "http://localhost:8787/"
            )
        with self.assertRaises(SquarePurchaseError):
            SquareClient(self.config, opener=opener).create_payment_link(
                "solo", "purchase-credentials", "http://user:password@localhost:8787/"
            )
        with self.assertRaises(SquarePurchaseError):
            SquareClient(self.config, opener=opener).create_payment_link(
                "solo", "purchase-fragment", "http://localhost:8787/#token"
            )

    def test_signature_uses_exact_url_and_raw_body(self):
        body = b'{"type":"payment.updated","space":"kept"}'
        signature = square_webhook_signature(
            self.signature_key, self.config.notification_url, body
        )
        self.assertTrue(
            verify_square_webhook(
                self.signature_key, self.config.notification_url, body, signature
            )
        )
        self.assertFalse(
            verify_square_webhook(
                self.signature_key, self.config.notification_url, body + b" ", signature
            )
        )
        self.assertFalse(
            verify_square_webhook(
                self.signature_key, self.config.notification_url + "/", body, signature
            )
        )

    def test_completed_payment_requires_exact_order_location_amount_and_currency(self):
        cases = (
            {"order_id": "wrong-order"},
            {"location_id": "wrong-location"},
            {"amount": 14_999},
            {"currency": "CAD"},
            {"event_type": "refund.updated"},
        )
        for index, overrides in enumerate(cases):
            with self.subTest(overrides=overrides):
                local_store = PurchaseStore(
                    self.root / f"wrong-{index}.sqlite3", self.config.location_id
                )
                purchase = local_store.create_purchase("base")
                link = {
                    "order_id": f"order-{index}",
                    "payment_link_id": f"link-{index}",
                    "checkout_url": "https://square.link/u/example",
                }
                local_store.record_payment_link(purchase["purchase_id"], link)
                body, signature = self._event(purchase, link, event_id=f"wrong-{index}", **overrides)
                with self.assertRaises(SquareWebhookError):
                    local_store.process_webhook(body, signature, self.config)
                self.assertEqual(local_store.public_status(purchase["purchase_id"])["status"], "pending_payment")

    def test_signed_noncompleted_payment_event_is_recorded_and_ignored(self):
        purchase, link = self._checkout()
        body, signature = self._event(purchase, link, status="PENDING")
        first = self.store.process_webhook(body, signature, self.config)
        second = self.store.process_webhook(body, signature, self.config)
        self.assertEqual(first["http_status"], 200)
        self.assertTrue(first["accepted"])
        self.assertTrue(first["ignored"])
        self.assertFalse(first["duplicate"])
        self.assertTrue(second["ignored"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(self.store.event_count(), 1)
        self.assertEqual(
            self.store.public_status(purchase["purchase_id"])["status"], "pending_payment"
        )

    def test_checkout_only_config_cannot_verify_webhooks(self):
        checkout_only = SquareConfig(
            environment="sandbox",
            access_token=self.secret_token,
            application_id="sandbox-app-id",
            location_id=self.config.location_id,
        )
        purchase, link = self._checkout()
        body, signature = self._event(purchase, link)
        with self.assertRaisesRegex(SquareWebhookError, "not configured"):
            self.store.process_webhook(body, signature, checkout_only)

    def test_duplicate_event_and_payment_are_idempotent(self):
        purchase, link = self._checkout()
        body, signature = self._event(purchase, link)
        first = self.store.process_webhook(body, signature, self.config)
        second = self.store.process_webhook(body, signature, self.config)
        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(self.store.event_count(), 1)
        self.assertEqual(self.store.public_status(purchase["purchase_id"])["status"], "paid")

        another_body, another_signature = self._event(
            purchase, link, event_id="event-2", payment_id="payment-1"
        )
        accepted = self.store.process_webhook(another_body, another_signature, self.config)
        self.assertTrue(accepted["accepted"])
        self.assertEqual(self.store.event_count(), 2)

    def test_tampered_signature_and_replayed_event_content_are_rejected(self):
        purchase, link = self._checkout()
        body, signature = self._event(purchase, link)
        with self.assertRaises(SquareWebhookError):
            self.store.process_webhook(body + b" ", signature, self.config)
        self.store.process_webhook(body, signature, self.config)
        altered, altered_signature = self._event(
            purchase, link, event_id="event-1", event_type="payment.created"
        )
        with self.assertRaises(SquareWebhookError):
            self.store.process_webhook(altered, altered_signature, self.config)

    def test_claim_is_exactly_once_under_concurrency_and_replay(self):
        purchase, link = self._checkout("government")
        body, signature = self._event(purchase, link)
        self.store.process_webhook(body, signature, self.config)
        subscriptions = _SubscriptionStore()

        def attempt():
            try:
                return self.store.claim(
                    purchase["purchase_id"], purchase["claim_token"], subscriptions
                )
            except SquarePurchaseError as exc:
                return str(exc)

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _index: attempt(), range(8)))
        successes = [result for result in results if isinstance(result, dict)]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(subscriptions.calls), 1)
        self.assertEqual(subscriptions.calls[0][0], "government")
        self.assertEqual(self.store.public_status(purchase["purchase_id"])["status"], "claimed")
        with self.assertRaisesRegex(SquarePurchaseError, "already been claimed"):
            self.store.claim(
                purchase["purchase_id"], purchase["claim_token"], subscriptions
            )

    def test_authenticated_status_requires_matching_claim_token(self):
        purchase, _link = self._checkout("enterprise")
        status = self.store.authenticated_status(
            purchase["purchase_id"], purchase["claim_token"]
        )
        self.assertEqual(status["tier"], "enterprise")
        self.assertNotIn("claim_token", status)
        self.assertNotIn("claim_token_hash", status)
        with self.assertRaisesRegex(SquarePurchaseError, "invalid"):
            self.store.authenticated_status(purchase["purchase_id"], "wrong-token")

    def test_database_never_contains_plaintext_tokens_or_square_credentials(self):
        purchase, _link = self._checkout("solo")
        raw = self.store.path.read_bytes()
        self.assertNotIn(purchase["claim_token"].encode("utf-8"), raw)
        self.assertNotIn(self.secret_token.encode("utf-8"), raw)
        self.assertNotIn(self.signature_key.encode("utf-8"), raw)
        status_payload = self.store.public_status(purchase["purchase_id"])
        status = json.dumps(status_payload)
        self.assertNotIn("claim_token", status_payload)
        self.assertNotIn("claim_token_hash", status_payload)
        self.assertNotIn(self.config.location_id, status)


if __name__ == "__main__":
    unittest.main()
