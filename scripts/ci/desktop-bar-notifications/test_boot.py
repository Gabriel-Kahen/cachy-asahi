# SPDX-License-Identifier: MIT
"""Real isolated Python imports only; never run guest, GUI or native actors."""
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
ROOT=next((p for p in HERE.parents if (p/'scripts/ci/desktop-bar-notifications/session.py').is_file()),None)
if ROOT is None:raise RuntimeError('repository source root unavailable')
BASE=ROOT/'scripts/ci/desktop-bar-notifications'

STUB='''from pathlib import Path
import sys,types

def guard(_):raise AssertionError('guest guard must not execute')
def emit(*args,**kwargs):raise AssertionError('guest events must not execute')
def need(ok,reason):
    if not ok:raise ValueError(reason)
def main():
    import managed_session as registered
    assert Path(registered.__file__).resolve()==Path(__file__).with_name('managed_session.py').resolve()
    assert registered.ManagedSession is managed_session.ManagedSession
    modules=[c.cell_contents for c in phase.__closure__ if isinstance(c.cell_contents,types.ModuleType)]
    assert len(modules)==1 and modules[0].managed is registered
    assert str(Path(__file__).parent) not in sys.path
    assert sys.flags.isolated==1
    print('SOURCE_ONLY_ISOLATED_IMPORT_PASS')
    return 0
'''


def limits():
    resource.setrlimit(resource.RLIMIT_CPU,(3,3))
    resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))


class Boot(unittest.TestCase):
    def entry(self,original=False):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);fixture=root/'fixture';fixture.mkdir()
            source=(HERE/'desktop574_guest.py').read_text()
            if original:source=source.replace("    sys.modules['managed_session'] = api\n",'')
            (fixture/'guest.py').write_text(source);(fixture/'base_guest.py').write_text(STUB)
            for name in ('managed_session.py','session.py'):shutil.copyfile(BASE/name,fixture/name)
            foreign=root/'foreign';foreign.mkdir();(foreign/'managed_session.py').write_text("raise AssertionError('ambient module imported')\n")
            env=dict(PATH='/usr/bin:/bin',LC_ALL='C',PYTHONPATH=str(foreign),PYTHONDONTWRITEBYTECODE='1')
            row=subprocess.run([sys.executable,'-I','-B',str(fixture/'guest.py')],cwd=foreign,env=env,
                stdin=subprocess.DEVNULL,capture_output=True,timeout=5,preexec_fn=limits)
            self.assertLess(len(row.stdout)+len(row.stderr),65536)
            return row

    def test_isolated_entry_imports_the_exact_already_bound_managed_api(self):
        row=self.entry()
        self.assertEqual(row.returncode,0,row.stderr.decode(errors='replace'))
        self.assertEqual(row.stdout,b'SOURCE_ONLY_ISOLATED_IMPORT_PASS\n');self.assertEqual(row.stderr,b'')

    def test_old_adapter_reproduces_retained_import_failure_before_base_main(self):
        row=self.entry(original=True)
        self.assertNotEqual(row.returncode,0);self.assertEqual(row.stdout,b'')
        self.assertIn(b"ModuleNotFoundError: No module named 'managed_session'",row.stderr)
        self.assertNotIn(b'ambient module imported',row.stderr)


if __name__=='__main__':unittest.main()
