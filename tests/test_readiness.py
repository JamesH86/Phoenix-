import unittest
from unittest import mock

from tools.readiness import readiness


class ReadinessTests(unittest.TestCase):
    def test_required_runtime_is_real_and_optional_tools_are_not_simulated(self):
        with mock.patch("tools.readiness.shutil.which", return_value=None):
            report = readiness()
        self.assertTrue(report["ok"])
        self.assertTrue(all(report["required"].values()))
        self.assertFalse(any(report["optional"].values()))


if __name__ == "__main__":
    unittest.main()
