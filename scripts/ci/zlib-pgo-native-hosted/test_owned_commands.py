# SPDX-License-Identifier: MIT
"""Mocked PGO Commands adapter controls; no compiler, native or child runs."""
import ast,hashlib,importlib.util,json,os,socket,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];PACKET=ROOT.parent
SOURCE=ROOT/'pgo-source/packages/experiments/cachy-asahi-zlib-pgo-v1/supervisor.py'
spec=importlib.util.spec_from_file_location('_pgo_owned_commands',SOURCE);S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
BEGIN='# BEGIN EXACT OWNED_CHILD MODULE\n';END='# END EXACT OWNED_CHILD MODULE\n'
HOLD='a869fd555d8b0566f0a2942a90eb49974ccfa23bad74f3d63c7f6dcb4dbc073d'


def completed(row,code=0):row.update(exit=code,natural_exit=True,group_absent=True,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,ownership_lost=False,retirement='REAPED',forced_cleanup=False,cleanup_member_uids=[])


class PoisonProcess:
    def __getattribute__(self,name):raise AssertionError('borrowed process handle accessed: '+name)


class OwnedCommandsControls(unittest.TestCase):
    def setUp(self):
        root=PACKET/'evidence/tmp';root.mkdir(parents=True,exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(prefix='owned-commands-',dir=root);self.addCleanup(self.temp.cleanup);self.output=Path(self.temp.name)
        for name in('Popen','run','check_output'):self.enterContext(patch.object(subprocess,name,side_effect=AssertionError('process forbidden')))
        for name in('waitpid','waitid','killpg','kill'):self.enterContext(patch.object(os,name,side_effect=AssertionError('numeric child wait/probe/signal forbidden in adapter')))
        self.enterContext(patch.object(socket,'socket',side_effect=AssertionError('network forbidden')))
        self.enterContext(patch.object(S,'live_group',side_effect=AssertionError('legacy numeric group probe forbidden')))

    def row(self):return json.loads((self.output/'commands.json').read_text())[-1]

    def test_exact_body_and_twenty_unreplaced_legacy_nodes(self):
        prefix,rest=SOURCE.read_text().split(BEGIN);body,suffix=rest.split(END)
        self.assertEqual(body,(HERE/'owned_child.py').read_text());tree=ast.parse(prefix+suffix)
        values={n.name:ast.dump(n,include_attributes=False)for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name!='Commands'}
        node=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='Commands')
        values.update({'Commands.'+n.name:ast.dump(n,include_attributes=False)for n in node.body if isinstance(n,ast.FunctionDef)and n.name in('__init__','cancel')})
        self.assertEqual(hashlib.sha256(json.dumps(values,sort_keys=True,separators=(',',':')).encode()).hexdigest(),HOLD)
        for method in(n for n in node.body if isinstance(n,ast.FunctionDef)and n.name in('run','stop')):
            self.assertFalse({n.attr for n in ast.walk(method)if isinstance(n,ast.Attribute)}&{'wait','poll','communicate','pid','returncode','killpg','waitid','waitpid'})

    def test_owned_exit7_file_streams_log_and_forwarding(self):
        seen={}
        def child(argv,**kwargs):
            seen.update(kwargs);self.assertEqual(kwargs['stdin'].read(),b'input');kwargs['stdout'].write(b'output7');kwargs['stderr'].write(b'diagnostic\n');completed(kwargs['lifecycle'],7);kwargs['on_tick']();return subprocess.CompletedProcess(argv,7)
        command=S.Commands(self.output,seconds=30)
        with patch.object(S,'run',side_effect=child):self.assertEqual(command.run('build-control',['python3','helper.py'],cwd='/controlled',env={'ONLY':'controlled'},data=b'input',expected=7,timeout=5),b'output7')
        row=self.row();self.assertEqual((row['exit'],row['status'],row['log']),(7,'PASS','0000-build-control.log'));self.assertIs(row['exit_observed_via_waitpid'],True)
        self.assertEqual((self.output/row['log']).read_bytes(),b'diagnostic\noutput7');self.assertEqual(row['stdout_sha256'],hashlib.sha256(b'output7').hexdigest());self.assertEqual(row['stdout_bytes'],7)
        self.assertEqual(seen['cwd'],'/controlled');self.assertEqual(seen['env'],{'ONLY':'controlled'});self.assertIs(seen['check'],False);self.assertLessEqual(seen['timeout'],5)
        self.assertTrue(hasattr(seen['stdout'],'fileno'));self.assertTrue(hasattr(seen['stderr'],'fileno'));self.assertIsNone(command.active);command.stop(PoisonProcess(),row)

    def test_unexpected_nonzero_keeps_actual7_in_failed_row(self):
        def child(argv,**kwargs):completed(kwargs['lifecycle'],7);return subprocess.CompletedProcess(argv,7)
        with patch.object(S,'run',side_effect=child),self.assertRaises(ValueError):S.Commands(self.output).run('unexpected',['python3','helper.py'])
        self.assertEqual((self.row()['status'],self.row()['exit']),('FAIL',7));self.assertIs(self.row()['exit_observed_via_waitpid'],True)

    def test_lost_ownership_exception_is_unknown_and_never_zero(self):
        def child(argv,**kwargs):
            kwargs['lifecycle'].update(exit=None,ownership_lost=True,retirement='UNKNOWN',group_absent=False,exit_observed_via_waitpid=False);raise S.OwnershipLost('mock ECHILD after external reap')
        command=S.Commands(self.output)
        with patch.object(S,'run',side_effect=child),self.assertRaises(S.OwnershipLost):command.run('lost',['python3','helper.py'])
        row=self.row();self.assertEqual(row['status'],'FAIL');self.assertIsNone(row['exit']);self.assertIs(row['ownership_lost'],True);self.assertEqual(row['retirement'],'UNKNOWN');self.assertIs(row['group_absent'],False);self.assertIsNone(command.active)
        with self.assertRaises(ValueError):command.stop(PoisonProcess(),row)

    def test_returncode0_cannot_replace_missing_or_lost_waitpid_witness(self):
        def child(argv,**kwargs):
            completed(kwargs['lifecycle']);kwargs['lifecycle'].update(ownership_lost=True,exit_observed_via_waitpid=False,retirement='UNKNOWN',group_absent=False);return subprocess.CompletedProcess(argv,0)
        with patch.object(S,'run',side_effect=child),self.assertRaises(ValueError):S.Commands(self.output).run('false-zero',['python3','helper.py'])
        self.assertEqual(self.row()['status'],'FAIL');self.assertIsNone(self.row()['exit']);self.assertEqual(self.row()['retirement'],'UNKNOWN')

    def test_output_bound_fails_without_adapter_actuation(self):
        def child(argv,**kwargs):completed(kwargs['lifecycle']);kwargs['stdout'].seek(8*1024**2);kwargs['stdout'].write(b'x');kwargs['on_tick']()
        with patch.object(S,'run',side_effect=child),self.assertRaises(ValueError):S.Commands(self.output).run('oversized',['python3','helper.py'])
        self.assertEqual(self.row()['status'],'FAIL');self.assertIs(self.row()['exit_observed_via_waitpid'],True)

    def test_allowed_credentials_preserve_root_builder_compatibility_only(self):
        seen=[]
        def child(argv,**kwargs):seen.append(set(kwargs['allowed_uids']));completed(kwargs['lifecycle']);return subprocess.CompletedProcess(argv,0)
        command=S.Commands(self.output,builder_uid=1000)
        with patch.object(S,'run',side_effect=child),patch.object(os,'getuid',return_value=0),patch.object(os,'geteuid',return_value=0):command.run('root-builder',['python3','helper.py'])
        command=S.Commands(self.output,builder_uid=2000)
        with patch.object(S,'run',side_effect=child),patch.object(os,'getuid',return_value=1000),patch.object(os,'geteuid',return_value=1000):command.run('ordinary-builder',['python3','helper.py'])
        self.assertEqual(seen,[{0,1000},{1000}])


if __name__=='__main__':unittest.main()
