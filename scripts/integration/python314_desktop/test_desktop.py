# SPDX-License-Identifier: MIT
"""No Docker or GUI mutation: capacity and positive-result failure guards."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location('desktop_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


controller, checks = load('run'), load('checks')


class Safety(unittest.TestCase):
    def test_insufficient_capacity_refuses_before_provision(self):
        with tempfile.TemporaryDirectory() as root, patch.object(controller.shutil, 'disk_usage', return_value=SimpleNamespace(free=7*1024**3)):
            with self.assertRaisesRegex(ValueError, 'HOLD workspace capacity'):
                controller.capacity(Path(root))

    def test_capacity_records_actual_bound(self):
        with tempfile.TemporaryDirectory() as root, patch.object(controller.shutil, 'disk_usage', return_value=SimpleNamespace(free=9*1024**3)):
            result = controller.capacity(Path(root))
            self.assertEqual(result['minimum_bytes'], 8*1024**3)
            self.assertEqual(result['free_bytes'], 9*1024**3)

    def test_zero_exit_ancillary_error_is_not_success(self):
        for stdout, stderr in [('checking packages...\nerror: failed command\n',''),
                               ('','could not change the root directory (Operation not permitted)\n')]:
            with self.subTest(stderr=stderr), self.assertRaisesRegex(ValueError, 'ancillary error'):
                checks.clean_positive(stdout, stderr)

    def test_actual_downgrade_warning_is_not_an_error(self):
        checks.clean_positive('loading packages...\n', 'warning: downgrading package python (3.14.9-1 => 3.14.8-1.1)\n')


if __name__ == '__main__':
    unittest.main()
