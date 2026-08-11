import subprocess
import unittest
from unittest import mock

import phoenix_kali


class KaliBridgeTests(unittest.TestCase):
    def test_macos_reports_missing_runtime_honestly(self):
        with mock.patch("phoenix_kali.platform.system", return_value="Darwin"), mock.patch(
            "phoenix_kali.shutil.which", return_value=None
        ):
            status = phoenix_kali.runtime_status()
        self.assertFalse(status["ready"])
        self.assertIn("Docker", status["runtime"])

    def test_windows_requires_the_selected_wsl_distribution(self):
        result = subprocess.CompletedProcess([], 0, "Ubuntu\nkali-linux\n", "")
        with mock.patch("phoenix_kali.platform.system", return_value="Windows"), mock.patch(
            "phoenix_kali.shutil.which", return_value="wsl.exe"
        ), mock.patch("phoenix_kali._completed", return_value=result):
            status = phoenix_kali.runtime_status("kali-linux")
        self.assertTrue(status["ready"])
        self.assertEqual(status["provider"], "WSL2")

    def test_macos_container_is_ready_only_when_daemon_and_image_exist(self):
        completed = [
            subprocess.CompletedProcess([], 0, "29.0", ""),
            subprocess.CompletedProcess([], 0, "sha256:reviewed", ""),
        ]
        with mock.patch("phoenix_kali.platform.system", return_value="Darwin"), mock.patch(
            "phoenix_kali.shutil.which", side_effect=lambda name: f"/usr/local/bin/{name}"
        ), mock.patch("phoenix_kali._completed", side_effect=completed):
            status = phoenix_kali.runtime_status()
        self.assertTrue(status["ready"])
        self.assertEqual(status["image"], phoenix_kali.DEFAULT_KALI_IMAGE)

    def test_container_action_has_no_mounts_or_privilege_additions(self):
        ready = {
            "ready": True,
            "provider": "Kali container on macOS",
            "runtime": "ready",
            "setup": "ready",
        }
        captured = {}

        def fake_completed(args, timeout=12):
            captured["args"] = args
            return subprocess.CompletedProcess(args, 0, "verified", "")

        with mock.patch("phoenix_kali.runtime_status", return_value=ready), mock.patch(
            "phoenix_kali.shutil.which", return_value="/usr/local/bin/docker"
        ), mock.patch("phoenix_kali._completed", side_effect=fake_completed):
            output = phoenix_kali.run_registered("command -v nmap")
        self.assertEqual(output, "verified")
        self.assertNotIn("--privileged", captured["args"])
        self.assertNotIn("--cap-add", captured["args"])
        self.assertNotIn("-v", captured["args"])
        self.assertIn("no-new-privileges", captured["args"])

    def test_prepare_requires_a_container_runtime(self):
        with mock.patch("phoenix_kali.platform.system", return_value="Darwin"), mock.patch(
            "phoenix_kali.shutil.which", return_value=None
        ):
            result = phoenix_kali.prepare_container("/not-used")
        self.assertFalse(result["prepared"])
        self.assertIn("Docker Desktop or Colima", result["message"])


if __name__ == "__main__":
    unittest.main()
