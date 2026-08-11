import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from phoenix_subscriptions import SubscriptionError, SubscriptionStore, catalog, owner_context


class SubscriptionStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.now = datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc)
        self.store = SubscriptionStore(Path(self.temporary.name), now=lambda: self.now)

    def tearDown(self):
        self.temporary.cleanup()

    def test_catalog_has_requested_prices_and_progressive_features(self):
        tiers = {item["id"]: item for item in catalog()["tiers"]}
        self.assertEqual(tiers["demo"]["price_monthly_usd"], 0)
        self.assertEqual(tiers["solo"]["price_monthly_usd"], 50)
        self.assertEqual(tiers["base"]["price_monthly_usd"], 150)
        self.assertEqual(tiers["enterprise"]["price_monthly_usd"], 1000)
        self.assertEqual(tiers["government"]["price_monthly_usd"], 1500)
        self.assertNotIn("autonomous_remediation", tiers["demo"]["features"])
        self.assertNotIn("web_audit", tiers["solo"]["features"])
        self.assertNotIn("bug_bounty", tiers["solo"]["features"])
        self.assertIn("bug_bounty", tiers["base"]["features"])
        self.assertIn("security_intelligence", tiers["base"]["features"])
        self.assertNotIn("browser_context", tiers["base"]["features"])
        self.assertIn("autonomous_remediation", tiers["enterprise"]["features"])
        self.assertIn("browser_context", tiers["enterprise"]["features"])
        self.assertIn("evidence_integrity", tiers["government"]["features"])

    def test_issue_stores_only_hash_and_authenticates(self):
        issued = self.store.issue("base", "Example Customer")
        key = issued["control_key"]
        self.assertRegex(key, r"^phx_base_[A-Za-z0-9_-]{43}$")
        raw_store = self.store.path.read_text(encoding="utf-8")
        self.assertNotIn(key, raw_store)
        context = self.store.authenticate(key)
        self.assertEqual(context["tier"], "base")
        self.assertIn("web_audit", context["features"])
        self.assertNotIn("autonomous_remediation", context["features"])

    def test_all_tiers_expire_after_thirty_days(self):
        keys = [self.store.issue(tier)["control_key"] for tier in ("demo", "solo", "base", "enterprise", "government")]
        self.now += timedelta(days=30)
        for key in keys:
            self.assertIsNone(self.store.authenticate(key))

    def test_revocation_invalidates_key(self):
        issued = self.store.issue("enterprise")
        key = issued["control_key"]
        self.store.revoke(issued["subscription"]["key_id"])
        self.assertIsNone(self.store.authenticate(key))

    def test_unknown_tier_and_plaintext_store_are_rejected(self):
        with self.assertRaises(SubscriptionError):
            self.store.issue("platinum")
        self.assertNotIn("control_key", json.dumps(self.store.list_records()))

    @unittest.skipIf(os.name == "nt", "POSIX permission assertion")
    def test_store_is_private(self):
        self.store.issue("demo")
        self.assertEqual(stat.S_IMODE(self.store.path.stat().st_mode), 0o600)

    def test_owner_context_has_all_features(self):
        context = owner_context()
        self.assertIn("owner_admin", context["features"])
        self.assertIn("evidence_integrity", context["features"])


if __name__ == "__main__":
    unittest.main()
