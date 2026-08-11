import base64
import builtins
import hashlib
import hmac
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import phoenix_license as license_module
from phoenix_license import (
    ALLOW_SANDBOX_ENV,
    LICENSE_TERM_SECONDS,
    LICENSE_TYPE,
    LICENSE_VERSION,
    LicenseClaimError,
    LicenseConfigurationError,
    LicenseDependencyError,
    LicenseEnvironmentError,
    LicenseExpiredError,
    LicenseFormatError,
    LicenseNotYetValidError,
    LicenseSignatureError,
    LicenseVerifier,
    PUBLIC_KEY_ENV,
    TOKEN_PREFIX,
    verify_license_token,
)
from phoenix_subscriptions import TIERS


try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class LicenseVerifierTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 8, 9, 16, 0, tzinfo=timezone.utc)
        self.now_timestamp = int(self.now.timestamp())
        self.public_key_bytes = bytes(range(32))
        self.public_key = f"ed25519:{_b64(self.public_key_bytes)}"
        self.claims = {
            "environment": "production",
            "exp": self.now_timestamp + LICENSE_TERM_SECONDS - 60,
            "iat": self.now_timestamp - 60,
            "payment_reference_hash": hashlib.sha256(
                b"square-payment-reference-verified-server-side"
            ).hexdigest(),
            "tier": "base",
            "type": LICENSE_TYPE,
            "version": LICENSE_VERSION,
        }

    def _fake_signature(self, signing_input):
        return hashlib.blake2b(
            self.public_key_bytes + signing_input,
            digest_size=64,
        ).digest()

    def _fake_verify(self, public_key, signing_input, signature):
        expected = hashlib.blake2b(public_key + signing_input, digest_size=64).digest()
        return hmac.compare_digest(expected, signature)

    def _token(self, claims=None, raw_payload=None, signature=None, prefix=TOKEN_PREFIX):
        if raw_payload is None:
            raw_payload = json.dumps(
                self.claims if claims is None else claims,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        payload_segment = _b64(raw_payload)
        signing_input = f"{prefix}.{payload_segment}".encode("ascii")
        signature = self._fake_signature(signing_input) if signature is None else signature
        return f"{prefix}.{payload_segment}.{_b64(signature)}"

    def _verify(self, token, *, allow_sandbox=False, now=None, skew=300):
        verifier = LicenseVerifier(
            self.public_key,
            allow_sandbox=allow_sandbox,
            now=lambda: self.now if now is None else now,
            clock_skew_seconds=skew,
        )
        with mock.patch("phoenix_license._verify_ed25519", side_effect=self._fake_verify):
            return verifier.verify(token)

    def test_valid_license_returns_subscription_compatible_secret_free_entitlement(self):
        entitlement = self._verify(self._token())

        self.assertEqual(
            set(entitlement),
            {
                "authenticated",
                "kind",
                "tier",
                "tier_name",
                "features",
                "expires_at",
                "active",
            },
        )
        self.assertTrue(entitlement["authenticated"])
        self.assertEqual(entitlement["kind"], "subscription")
        self.assertEqual(entitlement["tier"], "base")
        self.assertEqual(entitlement["tier_name"], TIERS["base"]["name"])
        self.assertEqual(entitlement["features"], TIERS["base"]["features"])
        self.assertTrue(entitlement["active"])
        serialized = json.dumps(entitlement)
        self.assertNotIn(self.claims["payment_reference_hash"], serialized)
        self.assertNotIn(self.public_key, serialized)
        self.assertNotIn(self._token(), serialized)

    def test_every_known_tier_maps_to_subscription_features(self):
        for tier, definition in TIERS.items():
            with self.subTest(tier=tier):
                claims = dict(self.claims, tier=tier)
                entitlement = self._verify(self._token(claims))
                self.assertEqual(entitlement["tier_name"], definition["name"])
                self.assertEqual(entitlement["features"], definition["features"])

    def test_signature_and_payload_tampering_are_rejected(self):
        token = self._token()
        prefix, payload, signature = token.split(".")
        signature_bytes = bytearray(base64.urlsafe_b64decode(signature + "=="))
        signature_bytes[-1] ^= 1
        tampered_signature = f"{prefix}.{payload}.{_b64(bytes(signature_bytes))}"
        with self.assertRaises(LicenseSignatureError):
            self._verify(tampered_signature)

        tampered_claims = dict(self.claims, tier="government")
        tampered_payload = _b64(
            json.dumps(
                tampered_claims, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
        )
        with self.assertRaises(LicenseSignatureError):
            self._verify(f"{prefix}.{tampered_payload}.{signature}")

    def test_noncanonical_and_duplicate_json_are_rejected_even_when_signed(self):
        noncanonical = json.dumps(self.claims, indent=2, sort_keys=False).encode("utf-8")
        with self.assertRaisesRegex(LicenseFormatError, "canonical JSON"):
            self._verify(self._token(raw_payload=noncanonical))

        duplicate = (
            b'{"environment":"production","environment":"sandbox","exp":1,'
            b'"iat":0,"payment_reference_hash":"' + (b"1" * 64) +
            b'","tier":"base","type":"phoenix-license","version":1}'
        )
        with self.assertRaisesRegex(LicenseFormatError, "duplicate"):
            self._verify(self._token(raw_payload=duplicate))

    def test_payload_must_have_exact_fields_type_version_and_tier(self):
        cases = []
        extra = dict(self.claims, customer="not-allowed")
        cases.append(extra)
        missing = dict(self.claims)
        missing.pop("payment_reference_hash")
        cases.append(missing)
        cases.append(dict(self.claims, type="other-license"))
        cases.append(dict(self.claims, version=2))
        cases.append(dict(self.claims, version=True))
        cases.append(dict(self.claims, tier="platinum"))
        cases.append(dict(self.claims, tier="Base"))
        for claims in cases:
            with self.subTest(claims=claims):
                with self.assertRaises(LicenseClaimError):
                    self._verify(self._token(claims))

    def test_payment_reference_hash_is_strict_lowercase_sha256(self):
        invalid_hashes = [
            "A" * 64,
            "1" * 63,
            "0" * 64,
            hashlib.sha256(b"").hexdigest(),
            123,
        ]
        for payment_hash in invalid_hashes:
            with self.subTest(payment_hash=payment_hash):
                claims = dict(self.claims, payment_reference_hash=payment_hash)
                with self.assertRaisesRegex(LicenseClaimError, "payment reference"):
                    self._verify(self._token(claims))

    def test_expiration_is_enforced_without_expiry_grace(self):
        claims = dict(
            self.claims,
            iat=self.now_timestamp - LICENSE_TERM_SECONDS,
            exp=self.now_timestamp,
        )
        with self.assertRaises(LicenseExpiredError):
            self._verify(self._token(claims))

        one_second_left = dict(claims, iat=claims["iat"] + 1, exp=claims["exp"] + 1)
        self.assertTrue(self._verify(self._token(one_second_left))["active"])

    def test_future_issuance_uses_only_bounded_clock_skew(self):
        within_skew = dict(
            self.claims,
            iat=self.now_timestamp + 300,
            exp=self.now_timestamp + 300 + LICENSE_TERM_SECONDS,
        )
        self.assertTrue(self._verify(self._token(within_skew))["active"])

        beyond_skew = dict(
            within_skew,
            iat=self.now_timestamp + 301,
            exp=self.now_timestamp + 301 + LICENSE_TERM_SECONDS,
        )
        with self.assertRaises(LicenseNotYetValidError):
            self._verify(self._token(beyond_skew))

    def test_timestamps_and_exact_thirty_day_term_are_strict(self):
        cases = [
            dict(self.claims, iat=True),
            dict(self.claims, exp=float(self.claims["exp"])),
            dict(self.claims, iat=-1, exp=LICENSE_TERM_SECONDS - 1),
            dict(self.claims, exp=self.claims["exp"] + 1),
            dict(self.claims, exp=self.claims["iat"]),
            dict(self.claims, exp=253402300800),
        ]
        for claims in cases:
            with self.subTest(iat=claims["iat"], exp=claims["exp"]):
                with self.assertRaises(LicenseClaimError):
                    self._verify(self._token(claims))

    def test_sandbox_is_rejected_by_default_and_requires_explicit_opt_in(self):
        token = self._token(dict(self.claims, environment="sandbox"))
        with self.assertRaisesRegex(LicenseEnvironmentError, "disabled"):
            self._verify(token)
        entitlement = self._verify(token, allow_sandbox=True)
        self.assertEqual(entitlement["tier"], "base")

        invalid = self._token(dict(self.claims, environment="staging"))
        with self.assertRaises(LicenseEnvironmentError):
            self._verify(invalid, allow_sandbox=True)

    def test_token_envelope_and_base64_are_strict(self):
        valid = self._token()
        prefix, payload, signature = valid.split(".")
        cases = [
            f" {valid}",
            f"{valid}\n",
            valid.replace(prefix, "phxlic2", 1),
            f"{valid}.extra",
            f"{prefix}.{payload}=.{signature}",
            f"{prefix}.{payload}*.{signature}",
            f"{prefix}.{payload}.{_b64(b'short')}",
            "x" * 4097,
        ]
        for token in cases:
            with self.subTest(token=token[:30]):
                with self.assertRaises(LicenseFormatError):
                    self._verify(token)

        non_object = self._token(raw_payload=b"[]")
        with self.assertRaises(LicenseFormatError):
            self._verify(non_object)

    def test_public_key_configuration_accepts_only_raw_public_key_format(self):
        invalid_keys = [
            "",
            self.public_key + " ",
            "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
            _b64(self.public_key_bytes),
            "ed25519:not+url-safe",
            f"ed25519:{_b64(b'short')}",
        ]
        for public_key in invalid_keys:
            with self.subTest(public_key=public_key[:20]):
                with self.assertRaises(LicenseConfigurationError):
                    LicenseVerifier(public_key)

        with self.assertRaises(LicenseConfigurationError):
            LicenseVerifier(self.public_key, allow_sandbox=1)
        with self.assertRaises(LicenseConfigurationError):
            LicenseVerifier(self.public_key, clock_skew_seconds=301)

    def test_environment_configuration_is_explicit(self):
        sandbox_token = self._token(dict(self.claims, environment="sandbox"))
        verifier = LicenseVerifier.from_environment(
            {PUBLIC_KEY_ENV: self.public_key, ALLOW_SANDBOX_ENV: "1"},
            now=lambda: self.now,
        )
        with mock.patch("phoenix_license._verify_ed25519", side_effect=self._fake_verify):
            self.assertTrue(verifier.verify(sandbox_token)["active"])

        with self.assertRaises(LicenseConfigurationError):
            LicenseVerifier.from_environment(
                {PUBLIC_KEY_ENV: self.public_key, ALLOW_SANDBOX_ENV: "true"}
            )
        with self.assertRaises(LicenseConfigurationError):
            LicenseVerifier.from_environment({})

    def test_clock_must_be_timezone_aware(self):
        with self.assertRaises(LicenseConfigurationError):
            self._verify(self._token(), now=datetime(2026, 8, 9, 16, 0))

    def test_convenience_function_has_same_verified_contract(self):
        with mock.patch("phoenix_license._verify_ed25519", side_effect=self._fake_verify):
            entitlement = verify_license_token(
                self._token(),
                self.public_key,
                now=lambda: self.now,
            )
        self.assertEqual(entitlement["kind"], "subscription")
        self.assertEqual(entitlement["tier"], "base")

    def test_missing_crypto_backend_fails_closed_without_exposing_material(self):
        token = self._token()
        verifier = LicenseVerifier(self.public_key, now=lambda: self.now)
        real_import = builtins.__import__

        def blocked_import(name, *args, **kwargs):
            if name == "cryptography" or name.startswith("cryptography."):
                raise ImportError("blocked for test")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=blocked_import):
            with self.assertRaises(LicenseDependencyError) as raised:
                verifier.verify(token)
        message = str(raised.exception)
        self.assertIn("cryptography", message)
        self.assertNotIn(token, message)
        self.assertNotIn(self.public_key, message)

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "optional cryptography package is not installed")
    def test_real_ed25519_round_trip_and_tamper_rejection(self):
        private_key = Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public_key = f"ed25519:{_b64(public_bytes)}"
        raw_payload = json.dumps(
            self.claims,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        payload_segment = _b64(raw_payload)
        signing_input = f"{TOKEN_PREFIX}.{payload_segment}".encode("ascii")
        signature = private_key.sign(signing_input)
        token = f"{TOKEN_PREFIX}.{payload_segment}.{_b64(signature)}"

        verifier = LicenseVerifier(public_key, now=lambda: self.now)
        self.assertEqual(verifier.verify(token)["tier"], "base")
        altered = bytearray(signature)
        altered[0] ^= 1
        with self.assertRaises(LicenseSignatureError):
            verifier.verify(f"{TOKEN_PREFIX}.{payload_segment}.{_b64(bytes(altered))}")


if __name__ == "__main__":
    unittest.main()
