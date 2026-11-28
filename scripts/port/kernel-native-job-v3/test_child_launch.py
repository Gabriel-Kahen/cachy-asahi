# SPDX-License-Identifier: MIT
"""Exercise source custody with inert Python children."""
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from textwrap import dedent
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/port/kernel-native-job'))
import child_launch as launch
import packet
import runtime


class ChildCustodyTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory(prefix='kernel-child-custody-')
        self.addCleanup(directory.cleanup)
        python = patch.object(launch, 'PYTHON', (sys.executable, *launch.PYTHON[1:]))
        python.start()
        self.addCleanup(python.stop)
        self.root = Path(directory.name)
        self.output = self.root / 'out'
        self.rows = {}
        for modules in launch.MODULES.values():
            for path in modules.values():
                self.source(path, 'VALUE = "held"')
        self.source(launch.PRODUCER, """
            from pathlib import Path
            import sys
            import package_checks
            def sha(path):
                raise AssertionError('producer digest reopens source')
            def run(*args):
                raise AssertionError('producer driver was not bound')
            def main():
                print(package_checks.VALUE, sha(Path(__file__)), flush=True)
                root = Path(__file__).parents[2]
                for script in ('build', 'compare'):
                    log = root / script
                    run([sys.executable, str(root / 'scripts/build' / (script + '.py'))], log)
                    print(log.read_text().strip(), flush=True)
        """)
        self.source(launch.ACQUISITION, """
            from pathlib import Path
            import sys
            from common import module
            root = Path(__file__).parents[3]
            sys.path.insert(0, str(root))
            try:
                import unexpected_child_module
            except ModuleNotFoundError:
                pass
            else:
                raise AssertionError('unbound application import')
            assert module('kernel_acquisition_native', root / 'scripts/ci/native_arm.py').package_checks.VALUE == 'held'
            print(module('kernel_acquisition_harness', root / 'scripts/port/kernel-candidates/harness.py').VALUE)
        """)
        self.source(launch.STAGE, """
            from pathlib import Path
            import sys
            from image import module
            from runtime import Runner
            def main():
                out = Path(sys.argv[sys.argv.index('--output') + 1])
                helper = module('kernel_commit_config', out / 'private/code/scripts/ci/commit_image.py')
                print(helper.VALUE, Runner(30, {}, None)['GIT_NO_REPLACE_OBJECTS'])
        """)
        self.source(launch.BUILD, '''
            from package_checks import VALUE
            def main(*, entry_script):
                assert entry_script == b'# held shell entry'
                print(VALUE)
        ''')
        self.source(launch.BUILD_ENTRY, '# held shell entry')
        self.source(launch.COMPARE, 'from build import VALUE\nprint(VALUE)')
        self.source(launch.HARNESS, 'VALUE = "held"')
        self.source(launch.COMMIT, 'VALUE = "held"')
        self.source(packet.KERNEL + 'runtime.py', 'def Runner(seconds, env, logs): return env')
        self.source(packet.KERNEL + 'image.py', 'from common import module')
        self.source('unexpected_child_module.py', 'VALUE = "outside packet"')
        self.rows.pop('unexpected_child_module.py')

    def source(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(content))
        path.chmod(0o644)
        self.rows[name] = packet.row(*packet.capture(path))

    def bind(self, name):
        command = [*launch.PYTHON[:3], str(self.root / name), '--output', str(self.output)]
        return launch.bind(self.root, name, command, self.rows)

    def test_stage_and_parallel_children_execute_held_bytes_through_runner(self):
        env = {'PATH': '/usr/bin:/bin'}
        runner = runtime.Runner(30, env, self.root / 'logs')
        with (self.bind(launch.STAGE) as (stage, stage_fds),
              self.bind(launch.PRODUCER) as (producer, producer_fds),
              self.bind(launch.ACQUISITION) as (acquisition, acquisition_fds)):
            for name in self.rows:
                path = self.root / name
                path.write_text('def\n')
                path.chmod(0o755)
            with self.assertRaises(PermissionError):
                os.pwrite(producer_fds[0], b'changed', 0)
            produced, acquired = runner.run_many([producer, acquisition], 10, [None, None],
                                                 pass_fds=(producer_fds, acquisition_fds))
            controlled = runner.run(stage, timeout=10, pass_fds=stage_fds)
        for result in (produced, acquired, controlled):
            self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(produced.stdout, f"held {self.rows[launch.PRODUCER]['sha256']}\nheld\nheld\n".encode())
        self.assertEqual(acquired.stdout, b'held\n')
        self.assertEqual(controlled.stdout, b'held 1\n')
        for fd in (*producer_fds, *acquisition_fds, *stage_fds):
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_binding_refuses_mode_drift_in_entries_and_local_dependencies(self):
        for entry, member in ((launch.PRODUCER, launch.PRODUCER), (launch.PRODUCER, launch.BUILD),
                              (launch.PRODUCER, launch.BUILD_ENTRY),
                              (launch.ACQUISITION, launch.ACQUISITION), (launch.ACQUISITION, launch.HARNESS),
                              (launch.STAGE, launch.STAGE), (launch.STAGE, launch.COMMIT)):
            with self.subTest(entry=entry, member=member):
                path = self.root / member
                path.chmod(0o755)
                try:
                    with self.assertRaisesRegex(ValueError, '^child-source-pin$'), self.bind(entry):
                        self.fail('drift passed child binding')
                finally:
                    path.chmod(0o644)
