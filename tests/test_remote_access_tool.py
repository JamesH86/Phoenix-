import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import phoenix_remote_access as remote_tool


class RemoteAccessToolTests(unittest.TestCase):
    def test_device_origin_comes_from_tailscale_status(self):
        result = subprocess.CompletedProcess(
            ["tailscale", "status", "--json"],
            0,
            stdout=json.dumps({"Self": {"DNSName": "phoenix.example.ts.net."}}),
            stderr="",
        )
        with mock.patch.object(remote_tool, "run_tailscale", return_value=result):
            self.assertEqual(remote_tool.device_origin(), "https://phoenix.example.ts.net")

    def test_enable_uses_exact_argv_and_persists_only_after_success(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(remote_tool, "config_root", return_value=Path(temporary)), \
             mock.patch.object(remote_tool, "local_server_ready", return_value=True), \
             mock.patch.object(remote_tool, "device_origin", return_value="https://phoenix.example.ts.net"), \
             mock.patch.object(remote_tool, "run_tailscale") as runner:
            result = remote_tool.enable(8787)
        runner.assert_called_once_with("serve", "--bg", "--https=443", "http://127.0.0.1:8787")
        self.assertTrue(result["enabled"])


if __name__ == "__main__":
    unittest.main()
