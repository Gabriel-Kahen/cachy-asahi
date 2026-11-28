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
        locked = ROOT / packet.RECIPES_LOCK
        self.reviews = packet.load(locked, packet.RECIPES_SHA)
        self.source(packet.RECIPES_LOCK, locked.read_text())
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
                builds = %r
                for recipe in builds:
                    command = [sys.executable, str(root / 'scripts/build/build.py'), str(root / recipe)]
                    if '--fixture-unknown-recipe' in sys.argv:
                        command[2] = str(root / 'packages/unknown-fixture')
                    if '--fixture-missing-review' not in sys.argv:
                        command += ['--reviewed-inputs', str(root / 'untrusted-review.json')]
                    log = root / 'build'
                    run(command, log)
                    print(log.read_text().strip(), flush=True)
                log = root / 'compare'
                run([sys.executable, str(root / 'scripts/build/compare.py')], log)
                print(log.read_text().strip(), flush=True)
        """ % sorted(self.reviews)[:2])
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
            import fcntl
            import json
            import os
            from pathlib import Path
            import sys
            from package_checks import VALUE
            def main(*, entry_script):
                assert entry_script == b'# held shell entry'
                path = sys.argv[sys.argv.index('--reviewed-inputs') + 1]
                assert path.startswith('/proc/self/fd/')
                fd = int(Path(path).name)
                assert fcntl.fcntl(fd, %d) & %d == %d
                assert not os.get_inheritable(fd)
                root = Path(__file__).parents[2]
                row = Path(sys.argv[1]).relative_to(root).as_posix()
                assert json.loads(Path(path).read_bytes()) == %r[row]
                print(VALUE)
        ''' % (launch.GET_SEALS, launch.SEALS, launch.SEALS, self.reviews))
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

    def bind(self, name, *options, recipe_pin=None):
        command = [*launch.PYTHON[:3], str(self.root / name), '--output', str(self.output), *options]
        if name == launch.PRODUCER:
            command.extend(('--recipes', str(self.root / packet.RECIPES_LOCK), '--recipes-sha256',
                            packet.RECIPES_SHA if recipe_pin is None else recipe_pin))
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
        self.assertEqual(produced.stdout, f"held {self.rows[launch.PRODUCER]['sha256']}\nheld\nheld\nheld\n".encode())
        self.assertEqual(acquired.stdout, b'held\n')
        self.assertEqual(controlled.stdout, b'held 1\n')
        for fd in (*producer_fds, *acquisition_fds, *stage_fds):
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_producer_binding_refuses_missing_or_mismatched_recipe_lock(self):
        original = self.rows.pop(packet.RECIPES_LOCK)
        with self.assertRaisesRegex(ValueError, '^child-source-pin$'), self.bind(launch.PRODUCER):
            self.fail('missing recipe lock entered the sealed payload')
        self.rows[packet.RECIPES_LOCK] = original
        with self.assertRaisesRegex(ValueError, '^child-recipe-review-pin$'), self.bind(launch.PRODUCER, recipe_pin='0' * 64):
            self.fail('mismatched producer review pin passed binding')
        self.source(packet.RECIPES_LOCK, '{}')
        with self.assertRaisesRegex(ValueError, '^child-recipe-review-pin$'), self.bind(launch.PRODUCER):
            self.fail('fixture lock with a matching local row replaced the frozen recipe lock')

    def test_builder_refuses_missing_review_argument_or_recipe_without_an_approved_map(self):
        for option in ('--fixture-missing-review', '--fixture-unknown-recipe'):
            with self.subTest(option=option):
                runner = runtime.Runner(30, {'PATH': '/usr/bin:/bin'}, self.root / option[2:])
                with self.bind(launch.PRODUCER, option) as (producer, fds):
                    result = runner.run(producer, timeout=10, pass_fds=fds)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('unbound builder reviewed inputs', (self.root / 'build').read_text())
                self.assertFalse((self.root / 'compare').exists())

    def test_binding_refuses_mode_drift_in_entries_and_local_dependencies(self):
        for entry, member in ((launch.PRODUCER, launch.PRODUCER), (launch.PRODUCER, launch.BUILD),
                              (launch.PRODUCER, launch.BUILD_ENTRY), (launch.PRODUCER, packet.RECIPES_LOCK),
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
