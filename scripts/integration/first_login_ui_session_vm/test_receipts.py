# SPDX-License-Identifier: MIT
"""Real temporary-file receipt/durability checks; no guest or package execution."""
import ast, json, os, stat, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import receipts as R
HERE=Path(__file__).resolve().parent
NONCE='a'*32;OWNER=(os.getuid(),os.getgid());VERSIONS={str(n):'1-1'for n in range(292)};INPUT='b'*64

def installed():
    return {'schema_version':1,'nonce':NONCE,'stage':'installed','inputs_sha256':INPUT,'inventory_sha256':R.inventory_sha256(VERSIONS),'baseline_count':164,'installed_count':292,'archive_count':128,'project_file_count':24,'trusted_ALPM_completed':True,'exact_inventory':True,'dependencies':True,'ownership':True,'project_hashes':True,'original_policy':True,'unrelated_user_file':True,'filesystem_synced':True}

class ReceiptControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.path=Path(self.temp.name)/'fixture';self.writer=R.Writer(self.path,NONCE,OWNER);self.signals=Path(self.temp.name)/'signals';self.signals.mkdir(mode=0o755)
    def gate(self):return R.installed_gate(self.path,NONCE,INPUT,VERSIONS,24,OWNER,signals=self.signals)
    def signal(self,value=None):
        p=self.signals/'installed.json';p.write_text(json.dumps(installed()if value is None else value));p.chmod(0o644)
    def forge(self,name,value):
        path=self.path/name;path.write_text(json.dumps(value)+'\n');path.chmod(0o600)
    def test_pending_and_completed_gate(self):
        self.assertIsNone(self.gate());self.writer.phase('trusted-install');self.assertIsNone(self.gate())
        self.writer.write('installed.json',installed());self.assertIsNone(self.gate());self.signal();self.assertEqual(self.gate(),installed())
    def test_failed_overrides_installed_immediately(self):
        self.writer.write('installed.json',installed());self.signal();self.writer.phase('waiting-user');failure=self.writer.failure('command-timeout')
        self.assertIsNone(self.gate())
        f=self.signals/'failure.json';f.write_text(json.dumps(failure));f.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError,'waiting-user-command-timeout'):self.gate()
    def test_stale_foreign_and_incomplete_installed_refused(self):
        for field,new in [('nonce','c'*32),('inputs_sha256','d'*64),('inventory_sha256','e'*64),('installed_count',291),('ownership',False),('trusted_ALPM_completed',1),('schema_version',True)]:
            value=installed();value[field]=new;self.forge('installed.json',value)
            with self.subTest(field=field),self.assertRaises(ValueError):self.gate()
        self.writer.write('installed.json',installed());(self.path/'installed.json').chmod(0o644)
        with self.assertRaises(ValueError):self.gate()
        (self.path/'installed.json').chmod(0o600)
        with self.assertRaises(ValueError):R.installed_gate(self.path,NONCE,INPUT,VERSIONS,24,(OWNER[0]+1,OWNER[1]))
    def test_links_and_foreign_directory_refused(self):
        path=self.path/'installed.json';path.symlink_to(self.path/'stage.json')
        with self.assertRaises((ValueError,OSError)):self.gate()
        path.unlink();self.writer.write('installed.json',installed());os.link(path,self.path/'other')
        with self.assertRaises(ValueError):self.gate()
        (self.path/'other').unlink();self.path.chmod(0o755)
        with self.assertRaises(ValueError):self.gate()
    def test_stale_pending_and_failure_refused(self):
        self.forge('stage.json',{'schema_version':1,'nonce':'f'*32,'stage':'trusted-install'})
        with self.assertRaises(ValueError):self.gate()
        self.forge('failure.json',{'schema_version':1,'nonce':'f'*32,'stage':'trusted-install','status':'HOLD','error_label':'command-failed'})
        with self.assertRaises(ValueError):self.gate()
    def test_file_replace_directory_fsync_order(self):
        events=[];fsync=os.fsync;replace=os.replace
        def flush(fd):events.append('directory-fsync'if stat.S_ISDIR(os.fstat(fd).st_mode)else 'file-fsync');return fsync(fd)
        def rename(*args,**kwargs):events.append('replace');return replace(*args,**kwargs)
        with patch.object(R.os,'fsync',flush),patch.object(R.os,'replace',rename):self.writer.write('installed.json',installed())
        self.assertEqual(events,['file-fsync','replace','directory-fsync']);self.assertIsNone(self.gate());self.signal();self.assertEqual(self.gate(),installed())
        self.assertFalse(any(p.name.endswith('.pending')for p in self.path.iterdir()))
    def test_private_visibility_cannot_signal_before_directory_fsync(self):
        fsync=os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('owned test directory fsync refusal')
            return fsync(fd)
        with patch.object(R.os,'fsync',fail_directory),self.assertRaises(OSError):self.writer.write('installed.json',installed())
        self.assertTrue((self.path/'installed.json').exists())
        self.assertIsNone(self.gate())
        wrong=installed();wrong['nonce']='f'*32;self.signal(wrong)
        with self.assertRaises(ValueError):self.gate()
        self.writer.write('installed.json',installed());self.signal();self.assertEqual(self.gate(),installed())
        (self.signals/'installed.json').chmod(0o666)
        with self.assertRaises(ValueError):self.gate()

    def test_commands_and_failures_cannot_persist_raw_fields(self):
        self.writer.phase('public-trust');self.writer.command('public-import','started');self.writer.command('public-import','failed',2,'command-failed')
        command=json.loads((self.path/'command-001.json').read_text());self.assertEqual(command['command_label'],'public-import');self.assertEqual(command['exit'],2)
        for field in ['stdout','stderr','argv','key','credential']:
            value={'schema_version':1,'nonce':NONCE,'stage':'public-trust',field:'private input'}
            with self.subTest(field=field),self.assertRaises(ValueError):self.writer.write('stage.json',value)
        with self.assertRaises(AssertionError):self.writer.command('arbitrary-output','started')
        with self.assertRaises(AssertionError):self.writer.failure('arbitrary-error')
    def test_source_gate_precedes_keyboard_and_signals_follow_durability(self):
        observer=(HERE/'observer.py').read_text();gate="wait(lambda:report.get('installed_gate')"
        self.assertLess(observer.index(gate),observer.index("frame('SEAT_LOGIN_READY'"))
        self.assertLess(observer.index(gate),observer.index("counter=keyboard.Releases()"))
        root=(HERE/'root_fixture.py').read_text()
        self.assertLess(root.index("writer.write('installed.json',receipt)"),root.index("publish('installed.json',receipt)"))
        self.assertLess(root.index('writer.failure(label)'),root.index("publish('failure.json',failure)"))
        self.assertNotIn("+'.stdout'",root);self.assertNotIn("+'.stderr'",root)
        self.assertIn('ui-receipts.py',(HERE/'prepare.py').read_text())

if __name__=='__main__':unittest.main()
