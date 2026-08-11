import json
import os
import stat
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from phoenix_auth import (
    CONTROL_KEY_ENV,
    CONTROL_KEY_ENV_ALIAS,
    CONTROL_KEY_EXPIRES_ENV,
    ControlKeyError,
    ControlKeyStore,
    extract_bearer,
    request_origin_mode,
    valid_local_origin,
)


class ControlKeyStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.config_dir = Path(self.temporary_directory.name) / "PhoenixGuardian"
        self.store = ControlKeyStore(self.config_dir, env={})

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_first_run_generates_persists_and_reuses_key(self):
        first = self.store.get_or_create_key()
        second = self.store.get_or_create_key()
        independent_store = ControlKeyStore(self.config_dir, env={})

        self.assertEqual(first, second)
        self.assertEqual(first, independent_store.get_or_create_key())
        self.assertRegex(first, r"^phx_local_[A-Za-z0-9_-]{43}$")
        self.assertTrue(self.store.key_path.is_file())

    @unittest.skipIf(os.name == "nt", "Windows chmod does not expose POSIX mode bits")
    def test_directory_and_key_file_have_private_modes(self):
        self.store.get_or_create_key()

        self.assertEqual(stat.S_IMODE(self.config_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.store.key_path.stat().st_mode), 0o600)

    def test_authenticate_accepts_only_exact_active_key(self):
        key = self.store.get_or_create_key()

        self.assertTrue(self.store.authenticate(key))
        self.assertFalse(self.store.authenticate(""))
        self.assertFalse(self.store.authenticate(None))
        self.assertFalse(self.store.authenticate(key + "x"))
        self.assertFalse(self.store.authenticate(key.swapcase()))

    def test_rotate_invalidates_old_key_and_persists_new_key(self):
        old_key = self.store.get_or_create_key()
        new_key = self.store.rotate()

        self.assertNotEqual(old_key, new_key)
        self.assertFalse(self.store.authenticate(old_key))
        self.assertTrue(self.store.authenticate(new_key))
        self.assertEqual(new_key, ControlKeyStore(self.config_dir, env={}).get_or_create_key())
        self.assertIsNotNone(self.store.metadata()["rotated_at"])

    def test_rotate_before_first_read_creates_a_valid_key(self):
        key = self.store.rotate()

        self.assertRegex(key, r"^phx_local_[A-Za-z0-9_-]{43}$")
        self.assertTrue(self.store.authenticate(key))

    def test_metadata_never_exposes_plaintext_key(self):
        key = self.store.get_or_create_key()
        metadata = self.store.metadata()
        serialized = json.dumps(metadata, sort_keys=True)

        self.assertNotIn(key, serialized)
        self.assertTrue(metadata["configured"])
        self.assertEqual(metadata["source"], "file")
        self.assertRegex(metadata["key_id"], r"^[a-f0-9]{12}$")
        self.assertRegex(metadata["fingerprint"], r"^sha256:[a-f0-9]{16}$")
        self.assertEqual(metadata["key_path"], str(self.store.key_path))

    def test_environment_managed_key_is_not_written_to_disk(self):
        environment_key = "phx_local_" + "A" * 43
        expiry = "2099-01-01T00:00:00+00:00"
        store = ControlKeyStore(
            self.config_dir,
            env={CONTROL_KEY_ENV: environment_key, CONTROL_KEY_EXPIRES_ENV: expiry},
        )

        self.assertEqual(store.get_or_create_key(), environment_key)
        self.assertTrue(store.authenticate(environment_key))
        self.assertFalse(store.key_path.exists())
        self.assertEqual(store.metadata()["source"], "environment")
        self.assertNotIn(environment_key, json.dumps(store.metadata()))
        with self.assertRaises(ControlKeyError):
            store.rotate()

    def test_api_key_environment_alias_is_supported(self):
        environment_key = "phx_local_" + "B" * 43
        store = ControlKeyStore(
            self.config_dir,
            env={
                CONTROL_KEY_ENV_ALIAS: environment_key,
                CONTROL_KEY_EXPIRES_ENV: "2099-01-01T00:00:00+00:00",
            },
        )

        self.assertEqual(store.get_or_create_key(), environment_key)
        self.assertFalse(store.key_path.exists())

    def test_conflicting_environment_aliases_are_rejected(self):
        with self.assertRaises(ValueError):
            ControlKeyStore(
                self.config_dir,
                env={
                    CONTROL_KEY_ENV: "phx_local_" + "A" * 43,
                    CONTROL_KEY_ENV_ALIAS: "phx_local_" + "B" * 43,
                },
            )

    def test_invalid_environment_key_is_rejected(self):
        with self.assertRaises(ValueError):
            ControlKeyStore(self.config_dir, env={CONTROL_KEY_ENV: "not-a-phoenix-key"})

    def test_environment_key_requires_and_enforces_expiry(self):
        key = "phx_local_" + "C" * 43
        with self.assertRaises(ValueError):
            ControlKeyStore(self.config_dir, env={CONTROL_KEY_ENV: key})
        now = datetime(2026, 8, 8, tzinfo=timezone.utc)
        store = ControlKeyStore(
            self.config_dir,
            env={
                CONTROL_KEY_ENV: key,
                CONTROL_KEY_EXPIRES_ENV: (now + timedelta(days=30)).isoformat(),
            },
            now=lambda: now + timedelta(days=30),
        )
        self.assertFalse(store.authenticate(key))

    def test_file_key_rotates_automatically_after_thirty_days(self):
        now = datetime(2026, 8, 8, tzinfo=timezone.utc)
        store = ControlKeyStore(self.config_dir, env={}, now=lambda: now)
        old_key = store.get_or_create_key()
        expired_store = ControlKeyStore(
            self.config_dir,
            env={},
            now=lambda: now + timedelta(days=30),
        )
        new_key = expired_store.get_or_create_key()
        self.assertNotEqual(old_key, new_key)
        self.assertFalse(expired_store.authenticate(old_key))
        self.assertTrue(expired_store.authenticate(new_key))

    def test_corrupt_file_is_not_silently_replaced(self):
        self.config_dir.mkdir(mode=0o700)
        self.store.key_path.write_text("not json", encoding="utf-8")

        with self.assertRaises(ControlKeyError):
            self.store.get_or_create_key()
        self.assertEqual(self.store.key_path.read_text(encoding="utf-8"), "not json")

    def test_invalid_stored_key_is_rejected(self):
        self.config_dir.mkdir(mode=0o700)
        self.store.key_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "key": "bad",
                    "created_at": "2026-08-06T00:00:00+00:00",
                    "rotated_at": None,
                }
            ),
            encoding="utf-8",
        )

        with self.assertRaises(ControlKeyError):
            self.store.get_or_create_key()

    def test_symlinked_key_file_is_rejected(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks are unavailable")
        self.config_dir.mkdir(mode=0o700)
        target = self.config_dir / "other.json"
        target.write_text("{}", encoding="utf-8")
        try:
            self.store.key_path.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symlinks are unavailable: {exc}")

        with self.assertRaises(ControlKeyError):
            self.store.get_or_create_key()

    def test_concurrent_first_run_returns_one_shared_key(self):
        results = []
        failures = []
        barrier = threading.Barrier(8)

        def worker():
            try:
                barrier.wait(timeout=5)
                results.append(ControlKeyStore(self.config_dir, env={}).get_or_create_key())
            except Exception as exc:  # pragma: no cover - asserted below
                failures.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertFalse(failures)
        self.assertEqual(len(results), 8)
        self.assertEqual(len(set(results)), 1)


class BearerExtractionTests(unittest.TestCase):
    def test_extracts_case_insensitive_bearer_scheme(self):
        self.assertEqual(extract_bearer("Bearer abc_123-xyz"), "abc_123-xyz")
        self.assertEqual(extract_bearer("  bEaReR\tabc  "), "abc")

    def test_rejects_missing_ambiguous_or_injected_headers(self):
        invalid_headers = [
            None,
            "",
            "Basic abc",
            "Bearer",
            "Bearer one two",
            "Bearer abc,def",
            "Bearer abc;def",
            "Bearer abc\r\nX-Injected: yes",
        ]
        for header in invalid_headers:
            with self.subTest(header=header):
                self.assertEqual(extract_bearer(header), "")


class LocalOriginValidationTests(unittest.TestCase):
    PORT = 8787

    def test_accepts_loopback_hosts_with_empty_origin(self):
        accepted_hosts = ["127.0.0.1:8787", "localhost:8787", "LOCALHOST:8787", "[::1]:8787"]
        for host in accepted_hosts:
            with self.subTest(host=host):
                self.assertTrue(valid_local_origin(host, "", self.PORT))
                self.assertTrue(valid_local_origin(host, None, self.PORT))

    def test_accepts_only_exact_supported_http_origins(self):
        for host in ("127.0.0.1:8787", "localhost:8787"):
            for origin in ("http://127.0.0.1:8787", "http://localhost:8787"):
                with self.subTest(host=host, origin=origin):
                    self.assertTrue(valid_local_origin(host, origin, self.PORT))

    def test_rejects_dns_rebinding_and_nonlocal_origins(self):
        rejected = [
            ("evil.example:8787", "", self.PORT),
            ("localhost.evil.example:8787", "", self.PORT),
            ("127.0.0.1:9999", "", self.PORT),
            ("localhost:8787", "https://localhost:8787", self.PORT),
            ("localhost:8787", "http://localhost:8787/", self.PORT),
            ("localhost:8787", "http://evil.example:8787", self.PORT),
            ("localhost:8787", "null", self.PORT),
            ("localhost:8787", "http://localhost:8787.evil.example", self.PORT),
            ("localhost:8787", "http://localhost:8787", 0),
            ("localhost:8787", "http://localhost:8787", 70000),
            ("localhost:8787", "http://localhost:8787", "not-a-port"),
        ]
        for host, origin, port in rejected:
            with self.subTest(host=host, origin=origin, port=port):
                self.assertFalse(valid_local_origin(host, origin, port))

    def test_remote_mode_requires_one_exact_https_origin(self):
        trusted = "https://phoenix.example.ts.net"
        self.assertEqual(
            request_origin_mode("phoenix.example.ts.net", trusted, self.PORT, trusted),
            "remote",
        )
        self.assertEqual(
            request_origin_mode("phoenix.example.ts.net:443", None, self.PORT, trusted),
            "remote",
        )
        self.assertEqual(
            request_origin_mode("localhost:8787", "http://localhost:8787", self.PORT, trusted),
            "local",
        )

    def test_remote_mode_rejects_spoofed_hosts_and_origins(self):
        trusted = "https://phoenix.example.ts.net"
        rejected = [
            ("evil.example", trusted),
            ("phoenix.example.ts.net.evil.example", trusted),
            ("phoenix.example.ts.net", "https://evil.example"),
            ("phoenix.example.ts.net", "https://phoenix.example.ts.net/evil"),
        ]
        for host, origin in rejected:
            with self.subTest(host=host, origin=origin):
                self.assertEqual(request_origin_mode(host, origin, self.PORT, trusted), "")


if __name__ == "__main__":
    unittest.main()
