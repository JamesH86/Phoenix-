import stat
import tempfile
import unittest
from pathlib import Path

from phoenix_enterprise import DEFAULT_PROFILE, EnterpriseProfileError, EnterpriseProfileStore


class EnterpriseProfileStoreTests(unittest.TestCase):
    def test_defaults_are_company_neutral(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = EnterpriseProfileStore(Path(temporary)).load()
        self.assertEqual(profile, DEFAULT_PROFILE)
        self.assertEqual(profile["organization_name"], "Your Organization")
        self.assertEqual(profile["primary_domain"], "")

    def test_save_round_trip_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = EnterpriseProfileStore(Path(temporary))
            saved = store.save({
                **DEFAULT_PROFILE,
                "organization_name": "Northstar Industries",
                "primary_domain": "northstar.example",
                "security_contact": "security@northstar.example",
            })
            self.assertEqual(store.load(), saved)
            self.assertEqual(stat.S_IMODE(store.path.stat().st_mode), 0o600)

    def test_invalid_domain_and_environment_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = EnterpriseProfileStore(Path(temporary))
            with self.assertRaises(EnterpriseProfileError):
                store.save({**DEFAULT_PROFILE, "primary_domain": "https://company.example/path"})
            with self.assertRaises(EnterpriseProfileError):
                store.save({**DEFAULT_PROFILE, "environment": "Everything"})


if __name__ == "__main__":
    unittest.main()
