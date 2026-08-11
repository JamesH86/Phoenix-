import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from phoenix_orchestrator import MAX_OUTPUT_CHARS, RemediationManager


class RemediationManagerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.repo = base / "repo"
        self.state = base / "state"
        self.repo.mkdir()
        self.good_source = "def answer():\n    return 42\n"
        (self.repo / "app.py").write_text(self.good_source, encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def manager(self, node_path=None):
        return RemediationManager(self.repo, state_root=self.state, node_path=node_path)

    def test_plan_is_bounded_and_advisory_only(self):
        manager = self.manager(node_path="definitely-not-a-node-executable")
        result = manager.plan()
        self.assertTrue(result["ok"])
        self.assertEqual(result["planned_action"]["type"], "establish_or_update_known_good")
        self.assertTrue(result["assessment"]["healthy"])
        self.assertEqual(result["inventory"]["source_file_count"], 1)
        policy = result["preflight"]["policy"]
        self.assertFalse(policy["network"])
        self.assertFalse(policy["elevation"])
        self.assertFalse(policy["system_updates"])
        self.assertFalse(policy["deletion"])
        self.assertFalse(policy["shell_strings"])
        self.assertTrue(result["preflight"]["platform"]["advisory_only"])

    def test_rejects_outside_and_symlink_escape_assets(self):
        outside = self.repo.parent / "outside.py"
        outside.write_text("x = 1\n", encoding="utf-8")
        manager = self.manager()
        outside_result = manager.plan(outside)
        self.assertFalse(outside_result["ok"])
        self.assertEqual(outside_result["error"]["code"], "invalid_asset")

        link = self.repo / "escape.py"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links unavailable")
        link_result = manager.plan(link)
        self.assertFalse(link_result["ok"])
        self.assertEqual(link_result["error"]["code"], "invalid_asset")

        internal_target = self.repo / "app.py"
        internal_link = self.repo / "internal.py"
        try:
            internal_link.symlink_to(internal_target)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links unavailable")
        internal_result = manager.plan(internal_link)
        self.assertFalse(internal_result["ok"])
        self.assertEqual(internal_result["error"]["code"], "invalid_asset")

    def test_successful_run_records_known_good_and_audit(self):
        manager = self.manager()
        started = manager.start(idempotency_key="first")
        self.assertTrue(started["ok"])
        result = manager.wait(started["run_id"], timeout=10)
        self.assertEqual(result["status"], "succeeded")
        self.assertTrue(result["verification"]["healthy"])
        baseline = result["report"]["known_good_baseline"]
        self.assertIsNotNone(baseline)
        self.assertTrue(Path(baseline["manifest_path"]).is_file())

        audit_path = self.state / "audit.jsonl"
        events = [json.loads(line)["event"] for line in audit_path.read_text(encoding="utf-8").splitlines()]
        self.assertIn("run_created", events)
        self.assertIn("known_good_recorded", events)
        self.assertIn("run_finished", events)

    def test_failed_source_restores_baseline_and_rollback_restores_pre_heal(self):
        manager = self.manager()
        initial = manager.start(idempotency_key="baseline")
        initial_result = manager.wait(initial["run_id"], timeout=10)
        self.assertEqual(initial_result["status"], "succeeded")

        broken_source = "def answer(:\n    return 0\n"
        source_path = self.repo / "app.py"
        source_path.write_text(broken_source, encoding="utf-8")

        heal = manager.start(idempotency_key="heal")
        healed = manager.wait(heal["run_id"], timeout=10)
        self.assertEqual(healed["status"], "succeeded")
        self.assertEqual(healed["plan"]["planned_action"]["type"], "restore_last_known_good")
        self.assertEqual(source_path.read_text(encoding="utf-8"), self.good_source)
        self.assertEqual(len(healed["apply_result"]["changed_files"]), 1)
        self.assertTrue(Path(healed["snapshot"]["manifest_path"]).is_file())

        rollback = manager.rollback(heal["run_id"])
        self.assertTrue(rollback["ok"])
        self.assertEqual(source_path.read_text(encoding="utf-8"), broken_source)
        self.assertEqual(manager.get(heal["run_id"])["status"], "rolled_back")

    def test_rollback_preserves_post_run_user_edit(self):
        manager = self.manager()
        base_run = manager.start()
        manager.wait(base_run["run_id"], timeout=10)
        source_path = self.repo / "app.py"
        source_path.write_text("def broken(:\n", encoding="utf-8")
        heal = manager.start()
        healed = manager.wait(heal["run_id"], timeout=10)
        self.assertEqual(healed["status"], "succeeded")

        user_edit = "def answer():\n    return 99\n"
        source_path.write_text(user_edit, encoding="utf-8")
        rollback = manager.rollback(heal["run_id"])
        self.assertFalse(rollback["ok"])
        self.assertEqual(source_path.read_text(encoding="utf-8"), user_edit)
        self.assertEqual(len(rollback["conflicts"]), 1)

    def test_does_not_create_or_delete_source_files_during_restore(self):
        manager = self.manager()
        baseline_run = manager.start()
        manager.wait(baseline_run["run_id"], timeout=10)

        extra = self.repo / "new_bad.py"
        extra.write_text("def broken(:\n", encoding="utf-8")
        (self.repo / "app.py").write_text("def also_broken(:\n", encoding="utf-8")
        heal = manager.start()
        result = manager.wait(heal["run_id"], timeout=10)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(extra.exists())
        self.assertEqual((self.repo / "app.py").read_text(encoding="utf-8"), self.good_source)
        self.assertIsNone(result["report"]["known_good_baseline"])

    def test_idempotency_and_single_active_run(self):
        entered = threading.Event()
        release = threading.Event()

        class SlowManager(RemediationManager):
            def _preflight(self, asset):
                entered.set()
                release.wait(5)
                return super()._preflight(asset)

        manager = SlowManager(self.repo, state_root=self.state)
        first = manager.start(idempotency_key="same-key")
        self.assertTrue(entered.wait(2))
        replay = manager.start(idempotency_key="same-key")
        self.assertTrue(replay["ok"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["run_id"], first["run_id"])

        blocked = manager.start(idempotency_key="different-key")
        self.assertFalse(blocked["ok"])
        self.assertEqual(blocked["error"]["code"], "run_active")
        release.set()
        manager.wait(first["run_id"], timeout=10)

    def test_cancel_is_cooperative(self):
        entered = threading.Event()
        release = threading.Event()

        class SlowManager(RemediationManager):
            def _preflight(self, asset):
                entered.set()
                release.wait(5)
                return super()._preflight(asset)

        manager = SlowManager(self.repo, state_root=self.state)
        started = manager.start()
        self.assertTrue(entered.wait(2))
        cancelled = manager.cancel(started["run_id"])
        self.assertTrue(cancelled["cancel_effective"])
        release.set()
        result = manager.wait(started["run_id"], timeout=10)
        self.assertEqual(result["status"], "cancelled")

    def test_optional_node_check_uses_argv_and_bounds_output(self):
        (self.repo / "app.js").write_text("const answer = 42;\n", encoding="utf-8")
        manager = self.manager(node_path=sys.executable)
        huge = "x" * (MAX_OUTPUT_CHARS * 2)
        completed = subprocess.CompletedProcess(
            [sys.executable, "--check", str(self.repo / "app.js")],
            1,
            stdout="",
            stderr=huge,
        )
        with mock.patch("phoenix_orchestrator.subprocess.run", return_value=completed) as runner:
            plan = manager.plan()
        self.assertFalse(plan["assessment"]["healthy"])
        js_check = next(item for item in plan["assessment"]["checks"] if item["path"] == "app.js")
        self.assertLessEqual(len(js_check["output"]), MAX_OUTPUT_CHARS + 20)
        args, kwargs = runner.call_args
        self.assertIsInstance(args[0], list)
        self.assertEqual(args[0][1], "--check")
        self.assertNotIn("shell", kwargs)
        self.assertNotIn("NODE_OPTIONS", kwargs["env"])

    def test_all_public_results_are_json_serializable(self):
        manager = self.manager()
        payloads = [manager.status(), manager.plan(), manager.get("missing")]
        started = manager.start(apply=False)
        payloads.append(started)
        payloads.append(manager.wait(started["run_id"], timeout=10))
        for payload in payloads:
            json.dumps(payload)


if __name__ == "__main__":
    unittest.main()
