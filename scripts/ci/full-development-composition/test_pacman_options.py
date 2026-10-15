#!/usr/bin/env python3
"""Check real read-only pacman parsing against an empty private database."""
import ast
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name('container.py')
spec = importlib.util.spec_from_file_location('composition_container', SOURCE)
trial = importlib.util.module_from_spec(spec); spec.loader.exec_module(trial)


def actual_prefix(conf):
    main = next(node for node in ast.parse(SOURCE.read_text()).body
                if isinstance(node, ast.FunctionDef) and node.name == 'main')
    assignment = next(node for node in ast.walk(main) if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == 'pacman' for target in node.targets))
    namespace = {'conf': conf, '__builtins__': {'str': str}}
    exec(compile(ast.Module(body=[assignment], type_ignores=[]), str(SOURCE), 'exec'), namespace)
    return namespace['pacman']


class PacmanOptions(unittest.TestCase):
    @unittest.skipUnless(shutil.which('pacman'), 'pacman CLI unavailable')
    def test_read_operations_use_valid_actual_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'db/local').mkdir(parents=True)
            conf = root / 'pacman.conf'
            conf.write_text('[options]\nArchitecture = auto\nDBPath = ' + str(root / 'db')
                            + '\nLogFile = ' + str(root / 'pacman.log') + '\n')
            prefix = actual_prefix(conf)
            for options, expected in ((['-Dk'], 0), (['-T', 'inert-missing-package'], 127),
                                      (['-Qkk', 'inert-missing-package'], 1),
                                      (['-Qqo', str(root / 'missing')], 1)):
                with self.subTest(operation=options[0]):
                    result = subprocess.run(prefix + options, text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertNotIn('invalid option', result.stderr)

    def test_install_retains_scriptlet_and_conflict_policy(self):
        prefix = actual_prefix(Path('/inert/pacman.conf'))
        expected = {'inert': '1-1'}
        with patch.object(trial, 'run', return_value='') as run, patch.object(trial, 'inventory', return_value=expected):
            self.assertEqual(trial.install(prefix, ['inert.pkg.tar.xz'], expected), expected)
        self.assertEqual(run.call_args.args[0], prefix +
                         ['--noconfirm', '--noscriptlet', '--ask', '4', '-U', 'inert.pkg.tar.xz'])
        self.assertNotIn('--noscriptlet', prefix)


if __name__ == '__main__':
    unittest.main()
