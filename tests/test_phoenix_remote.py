import stat
import tempfile
import unittest
from pathlib import Path

from phoenix_remote import RemoteAccessError, RemoteAccessStore, normalize_trusted_origin


class RemoteAccessTests(unittest.TestCase):
    def test_accepts_exact_https_origin(self):
        self.assertEqual(
            normalize_trusted_origin("https://phoenix.example.ts.net/"),
            "https://phoenix.example.ts.net",
        )

    def test_rejects_http_paths_credentials_and_custom_ports(self):
        invalid = [
            "http://phoenix.example.ts.net",
            "https://user@phoenix.example.ts.net",
            "https://phoenix.example.ts.net/path",
            "https://phoenix.example.ts.net:8443",
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(RemoteAccessError):
                normalize_trusted_origin(value)

    def test_private_round_trip_and_disable(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = RemoteAccessStore(Path(temporary))
            saved = store.save("https://phoenix.example.ts.net")
            self.assertTrue(saved["enabled"])
            self.assertEqual(store.load(), saved)
            self.assertEqual(stat.S_IMODE(store.path.stat().st_mode), 0o600)
            self.assertFalse(store.disable()["enabled"])
            self.assertFalse(store.load()["enabled"])


if __name__ == "__main__":
    unittest.main()
