# SPDX-License-Identifier: MIT
"""Inert ELF/files and mocked compiler children only; never compile or boot."""
import ast
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import capture
import guest
import recorder_adapter
import run
import support as s
import test_smoke as legacy


class NativeCapture(unittest.TestCase):
    setUp=legacy.Controls.setUp
    payload_fixture=legacy.Controls.payload_fixture
    report_fixture=legacy.Controls.report_fixture
    output=legacy.Controls.output
    final_fixture=legacy.Controls.final_fixture
    def test_adapter_preserves_all_other_ast_and_fixed_recorder_path(self):
        original=(legacy.ROOT/'packages/tools/cachy-asahi-fish-done/check-module.py').read_bytes()
        adapted=recorder_adapter.adapt(original)
        before=ast.parse(original);after=ast.parse(adapted)
        def without_prepare(tree):return [ast.dump(n,include_attributes=False) for n in tree.body if not isinstance(n,ast.FunctionDef) or n.name!='prepare']
        self.assertEqual(without_prepare(before),without_prepare(after));self.assertIn(b"shutil.copyfile('/fixtures/notify-recorder', shim)",adapted)
        with self.assertRaises(ValueError):recorder_adapter.adapt(original+b'\n')

    def test_compile_once_uses_existing_supervisor_and_saves_success_receipt(self):
        source=s.read(s.HERE/'notify_recorder.c');output=b'\x7fELF inert native output';saved=[];calls=[]
        real=s.read
        def read(path,cap=1024**2):
            path=Path(path)
            if path==Path('/usr/bin/cc').resolve():return b'inert compiler'
            if path==Path('/out/notify-recorder'):return output
            return real(path,cap)
        def command(argv,env,seconds):
            calls.append((argv,env,seconds));row=legacy.transport_fixture(self.report_fixture()[1]['files'])['native_build']['command']
            return row,b''
        file=SimpleNamespace(st_mode=0o100755,st_uid=guest.os.getuid(),st_nlink=1,st_size=len(output))
        lstat=Path.lstat
        def node(path,*args,**kwargs):return file if path==Path('/out/notify-recorder') else lstat(path,*args,**kwargs)
        with patch.object(s,'read',side_effect=read),patch.object(s,'save',side_effect=lambda path,value,cap:saved.append((path,copy.deepcopy(value)))),\
             patch.object(Path,'lstat',node):
            raw,build=capture.compile_recorder(self.root,'c'*40,SimpleNamespace(command=command,CommandFailure=guest.CommandFailure))
        self.assertEqual(raw,output);self.assertEqual(len(calls),1);self.assertEqual(calls[0][2],30)
        self.assertEqual(calls[0][0],s.COMPILE);self.assertEqual(calls[0][1],dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TMPDIR='/tmp'))
        self.assertEqual(build['source_sha256'],s.sha(source));self.assertEqual(build['binary_sha256'],s.sha(output))
        self.assertEqual(saved[0][0],'/out/recorder-build.json');self.assertEqual(saved[0][1]['status'],'BUILT_NATIVE_C_TEST_RECORDER')

    def test_compile_failure_is_saved_and_original_failure_reraised(self):
        error=guest.CommandFailure('original compiler failure',dict(exit=1,group_absent=True),b'compiler out',b'compiler error');saved=[];calls=[]
        real=s.read
        def read(path,cap=1024**2):return b'inert compiler' if Path(path)==Path('/usr/bin/cc').resolve() else real(path,cap)
        def command(*args,**kwargs):calls.append((args,kwargs));raise error
        with patch.object(s,'read',side_effect=read),patch.object(s,'save',side_effect=lambda path,value,cap:saved.append(copy.deepcopy(value))):
            with self.assertRaises(guest.CommandFailure) as caught:capture.compile_recorder(self.root,'c'*40,SimpleNamespace(command=command,CommandFailure=guest.CommandFailure))
        self.assertIs(caught.exception,error);self.assertEqual(len(calls),1);self.assertEqual(saved[0]['status'],'FAIL');self.assertEqual(saved[0]['command']['exit'],1)
        self.assertIn('stderr_base64',saved[0])

    def test_compile_identity_count_retirement_flags_and_hash_joins_are_required(self):
        _,receipt,_,_=self.report_fixture();self.assertEqual(s.test_transport(receipt),receipt['test_transport'])
        for field,bad in [('compile_count',2),('compile_count',True),('architecture','x86_64'),('source_commit','b'*40),('source_sha256','0'*64),('deadline_seconds',31)]:
            value=copy.deepcopy(receipt);value['test_transport']['native_build'][field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):s.test_transport(value)
        for field,bad in [('natural_exit',False),('group_absent',False),('pgid',1),('exit',1),('stderr_bytes',1)]:
            value=copy.deepcopy(receipt);value['test_transport']['native_build']['command'][field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):s.test_transport(value)
        value=copy.deepcopy(receipt);value['test_transport']['native_build']['command']['argv']=s.COMPILE[:-1]+['/foreign']
        with self.assertRaises(ValueError):s.test_transport(value)
        for field in ('original_fixture_sha256','adapted_fixture_sha256','recorder_source_sha256','adapter_sha256','recorder_binary_sha256'):
            value=copy.deepcopy(receipt);value['test_transport'][field]='0'*64
            with self.subTest(field=field),self.assertRaises(ValueError):s.test_transport(value)

    def test_parent_reproduces_adaptation_even_with_self_consistent_forged_hashes(self):
        import io,tarfile
        archive,receipt=self.payload_fixture();members=[]
        with tarfile.open(archive,'r:') as stream:
            for entry in stream:
                raw=stream.extractfile(entry).read()
                if entry.name==s.ADAPTED:
                    raw+=b'\n# forged change outside prepare\n';entry.size=len(raw);receipt['files'][entry.name].update(bytes=len(raw),sha256=s.sha(raw))
                members.append((entry,raw))
        receipt['test_transport']['adapted_fixture_sha256']=receipt['files'][s.ADAPTED]['sha256']
        with tarfile.open(archive,'w') as stream:
            for entry,raw in members:stream.addfile(entry,io.BytesIO(raw))
        receipt['archive']=dict(bytes=archive.stat().st_size,sha256=s.sha(archive.read_bytes()))
        with self.assertRaisesRegex(ValueError,'independently reproduced'):run.payload(archive,receipt,self.generic)

    def test_finalization_cannot_complete_old_or_unjoined_transport(self):
        args,report,_=self.final_fixture();report['capture']['test_transport']['native_build']['compile_count']=2
        s.save(args.output/'runtime.json',report)
        with patch.dict(guest.os.environ,RUNNER_TEMP=str(self.root)):result=run.finalize(args)
        self.assertEqual(result['status'],'FAIL');self.assertTrue(args.kernel_work.exists())

    def test_original_status_argv_scope_or_pid_count_cannot_pass_adapted_lane(self):
        value,receipt,nonce,release=self.report_fixture()
        for kind in ('status','argv','scope','pid','count','binary','fixture'):
            changed=copy.deepcopy(value)
            if kind=='status':changed['status']='PASS_GENERIC_16K_FISH_DONE_RECORDER_PTY_ONLY'
            elif kind=='argv':changed['commands'][0]['argv'][3]='/fixtures/done.py'
            elif kind=='scope':changed['notification_transport']='PRIVATE_NOTIFY_SEND_RECORDER_ONLY'
            elif kind=='pid':changed['native_recorder_cases']['foreground']['recorded_pids']=[0]
            elif kind=='count':changed['native_recorder_cases']['foreground']['notification_count']=1
            elif kind=='binary':changed['native_recorder_cases']['foreground']['recorder_sha256']='0'*64
            else:changed['test_transport']['original_fixture_execution']='PASS'
            with self.subTest(kind=kind),self.assertRaises(ValueError):run.guest_report(self.output(changed,nonce,release),0,nonce,release,receipt)


if __name__=='__main__':unittest.main()
