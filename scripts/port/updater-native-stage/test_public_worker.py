"""Inert authenticated fixture modules; no tools, network or native builds."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name('public_worker.py')
spec = importlib.util.spec_from_file_location('public_worker_fixture', SCRIPT)
w = importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
FIXTURE = b'''from pathlib import Path
import os
os.write(1,b'direct private stdout')
os.write(2,b'direct private stderr')
print("private module diagnostics")
def project_evidence(raw, output, materialized=None):
    output.mkdir(mode=0o700)
    (output/'projection.json').write_text('{"projection":"PASS"}')
    return {'projection':'PASS'}
def export_evidence(raw, output):
    output.mkdir(mode=0o700)
    (output/'receipt.json').write_text('{"evidence_export":"PASS"}')
    return {'evidence_export':'PASS'}
def bundle(raw):
    return b'bounded inert archive fixture'
'''


class PublicWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='public-worker-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name);self.root.chmod(0o700)
        for name in ('private/native', 'private/empty-raw', 'private/materialized'):
            (self.root/name).mkdir(parents=True, mode=0o700)
        for name in w.MODULES.values():
            path = self.root/'private/source'/name
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            path.write_bytes(FIXTURE)

    def values(self, operation):
        source = self.root/'private/source'/w.MODULES[operation]
        input_path = self.root / {'project':'private/native', 'guard':'projected', 'bundle':'guarded'}[operation]
        output = self.root / {'project':'projected', 'guard':'guarded', 'bundle':'public-evidence.tar.gz'}[operation]
        return [operation, source, hashlib.sha256(source.read_bytes()).hexdigest(), input_path, output, self.root]

    def execute(self, operation='project', **kwargs):
        return w.execute(*self.values(operation), **kwargs)

    def test_all_operations_and_no_bytecode(self):
        for operation in ('project', 'guard', 'bundle'):
            self.assertEqual(self.execute(operation), {'status':'PASS', 'operation':operation})
        output = self.root/'public-evidence.tar.gz'
        self.assertEqual(output.read_bytes(), b'bounded inert archive fixture')
        self.assertEqual(output.stat().st_mode & 0o7777, 0o600)
        self.assertEqual(output.stat().st_nlink, 1)
        self.assertFalse(list(self.root.rglob('*.pyc')))
        self.assertFalse(list(self.root.rglob('__pycache__')))
        self.assertFalse(list(self.root.glob('.public-bundle-*')))

    def test_wrong_hash_does_not_execute_module(self):
        values = self.values('project');values[2] = '0'*64
        with self.assertRaises(ValueError):w.execute(*values)
        self.assertFalse((self.root/'projected').exists())

    def test_wrong_module_and_input_output_paths_refused(self):
        for index, path in ((1,self.root/'private/source/other.py'), (3,self.root/'private/materialized'),
                            (4,self.root/'arbitrary-output'), (5,self.root/'private')):
            values = self.values('project');values[index] = path
            with self.subTest(index=index), self.assertRaises((OSError,ValueError)):w.execute(*values)
        self.assertFalse((self.root/'arbitrary-output').exists())

    def test_symlink_module_and_ancestor_refused(self):
        path = self.values('project')[1]
        actual = path.with_name('actual.py');path.rename(actual);path.symlink_to(actual)
        with self.assertRaises((OSError,ValueError)):self.execute()
        path.unlink();actual.rename(path)
        original = self.root/'private/native';original.rmdir();original.symlink_to(self.root/'private/empty-raw')
        with self.assertRaises((OSError,ValueError)):self.execute()

    def test_hardlinked_or_oversize_module_refused(self):
        path = self.values('project')[1]
        os.link(path, path.with_name('other.py'))
        with self.assertRaises(ValueError):self.execute()
        path.with_name('other.py').unlink()
        with patch.object(w, 'MODULE_LIMIT', 16), self.assertRaises(ValueError):self.execute()

    def test_private_stage_mode_and_writable_module_refused(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):self.execute()
        self.root.chmod(0o700)
        self.values('project')[1].chmod(0o666)
        with self.assertRaises(ValueError):self.execute()

    def test_fresh_outputs_never_overwrite_files_or_links(self):
        path = self.root/'projected';path.write_text('untouched')
        with self.assertRaises(ValueError):self.execute()
        self.assertEqual(path.read_text(), 'untouched')
        path.unlink();path.symlink_to(self.root/'absent')
        with self.assertRaises(ValueError):self.execute()
        self.assertTrue(path.is_symlink())

    def test_materialized_scoped_and_project_only(self):
        self.assertEqual(self.execute(materialized=self.root/'private/materialized')['status'], 'PASS')
        with self.assertRaises(ValueError):self.execute('guard',materialized=self.root/'private/materialized')

    def test_existing_bundle_and_size_bound(self):
        (self.root/'guarded').mkdir(mode=0o700)
        output = self.root/'public-evidence.tar.gz';output.write_bytes(b'untouched')
        with self.assertRaises(ValueError):self.execute('bundle')
        self.assertEqual(output.read_bytes(), b'untouched');output.unlink()
        with patch.object(w,'BUNDLE_LIMIT',8), self.assertRaises(ValueError):self.execute('bundle')
        self.assertFalse(output.exists())

    def test_atomic_publish_rejects_racing_destination(self):
        fd = w.directory(self.root,self.root)
        output = self.root/'public-evidence.tar.gz';output.write_bytes(b'untouched')
        try:
            with self.assertRaises(FileExistsError):w.atomic_bundle(fd,output.name,b'new')
        finally:os.close(fd)
        self.assertEqual(output.read_bytes(),b'untouched')
        self.assertFalse(list(self.root.glob('.public-bundle-*')))

    def test_public_input_symlinks_and_hardlinks_refused(self):
        public = self.root/'guarded';public.mkdir(mode=0o700)
        foreign = self.root/'private/private.json';foreign.write_text('untouched')
        entry = public/'receipt.json';entry.symlink_to(foreign)
        with self.assertRaises(ValueError):self.execute('bundle')
        entry.unlink();os.link(foreign,entry)
        with self.assertRaises(ValueError):self.execute('bundle')
        self.assertEqual(foreign.read_text(),'untouched')
        self.assertFalse((self.root/'public-evidence.tar.gz').exists())

    def cli(self, values, extras=()):
        keys = ('operation','module','module-sha256','input','output','stage-output')
        argv = [sys.executable,'-I','-B',str(SCRIPT)]
        for key,value in zip(keys,values):argv += ['--'+key,str(value)]
        return subprocess.run(argv+list(extras),capture_output=True,timeout=5)

    def test_cli_fixed_json_no_module_diagnostics_or_pyc(self):
        result = self.cli(self.values('project'))
        self.assertEqual(result.returncode,0)
        self.assertEqual(json.loads(result.stdout),{'status':'PASS','operation':'project'})
        self.assertEqual(result.stderr,b'')
        self.assertNotIn(b'private module',result.stdout)
        self.assertFalse(list(self.root.rglob('*.pyc')))

    def test_cli_failures_do_not_expose_arguments_or_module_errors(self):
        values = self.values('project');values[2] = '0'*64
        for extras in ((), ('--unknown-private-argument','secret')):
            result = self.cli(values,extras)
            self.assertEqual(result.returncode,1)
            self.assertEqual(json.loads(result.stdout)['status'],'FAIL')
            self.assertEqual(result.stderr,b'')
            self.assertNotIn(str(self.root).encode(),result.stdout)
            self.assertNotIn(b'secret',result.stdout)


if __name__ == '__main__':unittest.main()
