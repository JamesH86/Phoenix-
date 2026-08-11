import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from phoenix_orchestrator import RemediationManager
from phoenix_tier1 import Tier1SecurityManager


class Tier1SecurityManagerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.repo = base / "repo"
        self.repo.mkdir()
        self.state = base / "state"
        (self.repo / "app.py").write_text("def healthy():\n    return True\n", encoding="utf-8")
        for launcher in ("Launch Phoenix.command", "Launch Phoenix.bat", "launch_phoenix.sh"):
            (self.repo / launcher).write_text("launcher\n", encoding="utf-8")
        (self.repo / "requirements.txt").write_text("example==1.0.0\n", encoding="utf-8")
        self.remediation = RemediationManager(self.repo, state_root=base / "remediation")
        self.manager = Tier1SecurityManager(self.repo, self.state, self.remediation)

    def tearDown(self):
        self.temporary.cleanup()

    def test_inventory_and_coverage_are_honest_and_json_serializable(self):
        inventory = self.manager.inventory()
        self.assertEqual(inventory["asset"], "enrolled-local-application")
        self.assertIn("requirements.txt", inventory["dependency_manifests"])
        coverage = self.manager.coverage()
        self.assertEqual([item["function"] for item in coverage["functions"]], ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"])
        self.assertIn("not a replacement", coverage["claim"])
        json.dumps({"inventory": inventory, "coverage": coverage})

    def test_never_returns_secret_contents(self):
        secret = "SUPER-SECRET-VALUE-DO-NOT-RETURN"
        (self.repo / ".env").write_text(f"TOKEN={secret}\n", encoding="utf-8")
        serialized = json.dumps(self.manager.run_once())
        self.assertNotIn(secret, serialized)
        self.assertIn("Potential secret-bearing files", serialized)

    def test_apply_requires_authorization(self):
        result = self.manager.run_once(apply=True, authorization=False)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "authorization_required")

    def test_authorized_response_uses_registered_remediation_and_is_idempotent(self):
        first = self.manager.run_once(apply=True, authorization=True, idempotency_key="one-click")
        self.assertTrue(first["ok"])
        self.assertEqual(first["response"]["status"], "started")
        run_id = first["response"]["remediation"]["run_id"]
        finished = self.remediation.wait(run_id, timeout=10)
        self.assertEqual(finished["status"], "succeeded")
        replay = self.manager.run_once(apply=True, authorization=True, idempotency_key="one-click")
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["report_id"], first["report_id"])

    @unittest.skipIf(os.name == "nt", "POSIX mode assertion")
    def test_audit_is_owner_only(self):
        self.manager.run_once()
        mode = stat.S_IMODE(self.manager.audit_path.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_unpinned_dependency_is_prioritized(self):
        (self.repo / "requirements.txt").write_text("example>=1.0\n", encoding="utf-8")
        findings = self.manager.assess()
        match = next(item for item in findings if item["id"] == "PR.DEP.PIN")
        self.assertEqual(match["severity"], "medium")


if __name__ == "__main__":
    unittest.main()
