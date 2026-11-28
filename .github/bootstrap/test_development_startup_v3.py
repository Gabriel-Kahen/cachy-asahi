"""Source-only controls for authenticated controller startup and streaming."""

from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


FILES = Path(__file__).resolve().parent
ROOT = FILES.parents[1]
V3 = runpy.run_path(str(FILES / 'development-launcher-v3.py'))
LAUNCHER = SimpleNamespace(**runpy.run_path(str(FILES / 'development-launcher.py')))
BOOTSTRAP = SimpleNamespace(**runpy.run_path(str(FILES / 'development-bootstrap.py')))


class StartupTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix='v3-startup-test-')
        self.addCleanup(scratch.cleanup)
        self.base = Path(scratch.name)
        self.workspace = self.base / 'workspace'
        self.private = self.base / 'bootstrap'
        self.private.mkdir(mode=0o700)
        self.sources = self.workspace / V3['DEVELOPMENT']
        self.sources.mkdir(parents=True)
        self.owned = BOOTSTRAP.Owned()
        self.addCleanup(self.owned.dispose)
        self.deadline = time.monotonic()+30

    def capture(self, *, root=None, options=(), rows=None):
        workspace = self.workspace if root is None else root
        if rows is None:
            rows = {}
            for name in V3['CONTROLLER_MODULES']:
                path = V3['DEVELOPMENT'] + '/' + name + '.py'
                rows[path] = {'mode':0o644,'sha256':V3['digest']((workspace/path).read_bytes())}
        return V3['captured_controller'](LAUNCHER, BOOTSTRAP, {
            'paths': {'workspace':workspace,'bootstrap':self.private}, 'owned':self.owned,
        }, rows, options, self.deadline)

    def write_sources(self, controller):
        for name in V3['CONTROLLER_MODULES']:
            if name == 'controller':
                content = controller
            elif name == 'common':
                content = 'def value(): return "reviewed-common"\n'
            else:
                content = 'from common import value\nLABEL = "' + name + '"\n'
            path = self.sources/(name+'.py')
            path.write_text(content)
            path.chmod(0o644)

    def test_post_capture_workspace_replacements_are_never_imported_or_executed(self):
        self.write_sources('''
import sys
import common
import packet
import base_stages
import virtual_stage
import initial_artifacts
from pathlib import Path
assert vars(sys.modules['__main__']) is globals()
assert sys.argv == [__file__, '--fixture']
assert all(Path(module.__file__).parent == Path(__file__).parent
           for module in (common,packet,base_stages,virtual_stage,initial_artifacts))
assert common.value.__code__.co_filename == common.__file__
assert packet.value is common.value
print(common.value(), packet.LABEL, base_stages.LABEL, virtual_stage.LABEL, initial_artifacts.LABEL)
''')
        argv = self.capture(options=['--fixture'])
        for path in self.sources.glob('*.py'):
            path.write_text('raise RuntimeError("untrusted workspace file executed")\n')
        completed = subprocess.run(argv,cwd=self.workspace,check=True,capture_output=True,text=True)
        self.assertEqual(completed.stdout.strip(),'reviewed-common packet base_stages virtual_stage initial_artifacts')
        self.assertEqual(completed.stderr,'')

    def test_bundle_replacement_refuses_before_any_module_runs(self):
        self.write_sources('print("controller ran")\n')
        argv = self.capture()
        target = self.private/'controller-startup.json'
        original = target.read_bytes()
        # Same inode and mode, different bytes.
        target.write_bytes(original + b' ')
        completed = subprocess.run(argv,cwd=self.workspace,capture_output=True,text=True)
        self.assertNotEqual(completed.returncode,0)
        self.assertEqual(completed.stderr.strip(),'controller-startup-pin')
        self.assertEqual(completed.stdout,'')

    def test_source_drift_after_checkout_verification_refuses_before_bundle_write(self):
        self.write_sources('print("no actor")\n')
        rows = {path.relative_to(self.workspace).as_posix():{'mode':0o644,'sha256':V3['digest'](path.read_bytes())}
                for path in self.sources.glob('*.py')}
        (self.sources/'common.py').write_text('raise RuntimeError("replacement")\n')
        with self.assertRaisesRegex(V3['Refused'],'^controller-startup-source-drift$'):
            self.capture(rows=rows)
        self.assertFalse((self.private/'controller-startup.json').exists())

    def test_actual_controller_reaches_help_under_isolation(self):
        completed = subprocess.run(self.capture(root=ROOT,options=['--help']),cwd=ROOT,
                                   check=True,capture_output=True,text=True)
        self.assertIn('--original-source-root',completed.stdout)
        self.assertEqual(completed.stderr,'')

    def test_captured_controller_stream_has_no_git_stdout_cap_or_time_reserve(self):
        self.write_sources('import sys\nsys.stdout.buffer.write(b"x" * (4*1024**2+1))\n')
        argv = self.capture()
        owner = SimpleNamespace(verify=Mock())
        handed_off = Mock()
        end = time.monotonic()+8  # The Git runner's ten-second reserve would refuse.
        with (self.base/'publication.log').open('wb') as output, patch.object(sys,'stdout',output):
            code, reply = V3['run'](argv,{'GITHUB_WORKSPACE':str(self.workspace)},str(self.workspace),end,
                                     spawn_deadline=end-2,workspace_owner=owner,on_spawn=handed_off)
        self.assertEqual((code,reply),(0,b''))
        self.assertEqual((self.base/'publication.log').stat().st_size,4*1024**2+1)
        handed_off.assert_called_once_with()

    def test_failed_spawn_never_marks_handoff(self):
        self.write_sources('print("unstarted")\n')
        argv = self.capture()
        owner = SimpleNamespace(verify=Mock())
        handed_off = Mock()
        with patch.object(subprocess,'Popen',side_effect=OSError('modeled spawn refusal')):
            with self.assertRaisesRegex(OSError,'modeled spawn refusal'):
                V3['run'](argv,{'GITHUB_WORKSPACE':str(self.workspace)},str(self.workspace),self.deadline,
                          workspace_owner=owner,on_spawn=handed_off)
        handed_off.assert_not_called()


if __name__ == '__main__':
    unittest.main()
