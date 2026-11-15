# SPDX-License-Identifier: MIT
"""Mocked PGO Commands adapter controls; no compiler, native or child runs."""
import ast,hashlib,importlib.util,json,os,socket,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];PACKET=ROOT.parent
SOURCE=ROOT/'pgo-source/packages/experiments/cachy-asahi-zlib-pgo-v1/supervisor.py'
spec=importlib.util.spec_from_file_location('_pgo_owned_commands',SOURCE);S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
BEGIN='# BEGIN EXACT OWNED_CHILD MODULE\n';END='# END EXACT OWNED_CHILD MODULE\n'
# raw-source-segment-v1: derived from byte-pinned original supervisor, not CI AST output.
HOLD={
  "Commands.__init__": "be239d10d1c8aacf462ea27df4eb3f26a39730667a8b80990985c5ac9a86afd1",
  "Commands.cancel": "fb062f326fe3bd3bda6129c550b0b64b2bfa2658f8b308fbe8fc92ba420a210e",
  "audit": "d70e8e22db154c648e8c661abe216c2688e5c3ea97cc699cfadb61b2150bd38c",
  "configured_flags": "5521f1036289e6e8cba48e048e23fce39d91b438409c1972cce41f3659ab4bd1",
  "flags": "ae6fedfee006836508884082a428c2bb503cf55cf1eff0e5a43e43ae0aceedd3",
  "inventory": "948f44f13c03960d84a29c9a266d0624d51bec896bba7fd84423db9989b5f46f",
  "live_group": "e0dd7dd329fd6c5f2d2f08676bf9a88bcb82e5ed51267c034c2082a5bd77d494",
  "main": "02aff18281a662f7108190fb8536c8132e6247b988a5df0223a27e867b12e266",
  "name": "917fe53e1a8f24ead34f26224bb93944f87fb71548b6f4fb7f300ed84fa740dc",
  "native_job": "6af36123258ef42e0a71fa9f883610379233fdfd9c62230a72693a191d81d84e",
  "need": "098b7ab9ef05c6267cec7bb1127e289155ed079b6b4e97dcc21dae0b9f8d9fb3",
  "package_members": "c0e56cdb2b696980940e151bbc040f86f8cd5eceb9d7d47ab7848f69bc6151e2",
  "prefix": "c392f96375565fe2691a81a4be304abf7b570fed45efc633d53066d9609109a6",
  "prepare": "64eec0d7002353217a8615d9e296cc9ee95c76af5b157f416374417ee84327c4",
  "read": "02705d2633fc7a4bebb176c07aced7c978638b1b100e7dc9fdbd70807dfca73d",
  "save": "3cbef960b16f8d7e498d29ce8c413e4925dced0bba63feea775820966d6b7548",
  "sha": "fc33541dab55897936faef1ad2869e455cbd6942f02508b99b41efdccc29be21",
  "source_material": "086d401280c9e1e04aea145f59c2c42a4839a44546e0fc0fb9d0870becb74f18",
  "verify_context": "116ed1fae539350edecff6a33e92319ba8753e798dd7e98f1f71d248adbafeab",
  "workload": "604f84d1746bfe56e0c079057c9f80fa2911e24d6a6d737c1f1ed039c60614ca"
}


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
        self.assertEqual(body,(HERE/'owned_child.py').read_text());held_source=prefix+suffix;tree=ast.parse(held_source)
        values={n.name:hashlib.sha256(ast.get_source_segment(held_source,n).encode()).hexdigest()for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name!='Commands'}
        node=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='Commands')
        values.update({'Commands.'+n.name:hashlib.sha256(ast.get_source_segment(held_source,n).encode()).hexdigest()for n in node.body if isinstance(n,ast.FunctionDef)and n.name in('__init__','cancel')})
        self.assertEqual(len(values),20);self.assertEqual(values,HOLD)
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
