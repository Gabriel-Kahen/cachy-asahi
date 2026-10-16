"""Inert controls only: every editor/compiler/clipboard/compositor process is fake."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import terminal_workflow as T
import worker
import terminal_session as session
import contract


def client(pid=102):
    return dict(pid=pid, mapped=True, visible=True, hidden=False, xwayland=False,
                title=T.TITLE, **{'class':T.APP_ID}, at=[5,5], size=[1014,758])


class FakeProcess:
    def __init__(self,pid,code=None):self.pid=pid;self.returncode=code
    def poll(self):return self.returncode
    def wait(self,timeout):
        if self.returncode is None:raise AssertionError('fake child was not retired')
        return self.returncode


class WorkerBase:
    def __init__(self):
        self.emit=Mock();self.calls=[];self.owner=None;self.edits=True;self.native=T.OUTPUT
        self.clipboard=T.CLIPBOARD;self.bad_elf=False;self.paste_error=False;self.finish_error=False
        self.type_timeout=False;self.type_finish=False

    def command(self,argv,env,logs,name,timeout):
        self.calls.append((name,argv));output=''
        if name=='vim-edit' and self.edits:(logs/'main.c').write_bytes(T.EDITED)
        elif name=='compile':
            header=bytearray(64);header[:6]=b'\x7fELF\x02\x01';header[18:20]=(62 if self.bad_elf else 183).to_bytes(2,'little')
            (logs/'probe').write_bytes(header+b'INERT TEST ELF')
        elif name=='native-run':output=self.native.decode()
        elif name=='paste':
            if self.paste_error:raise ValueError('primary paste fault')
            self.owner.process.returncode=0;output=self.clipboard.decode()
        self.emit('process_exit',name=name,returncode=0,logs=[])
        return output

    def Logged(self,argv,name,logs,env,stdin=None):
        item=SimpleNamespace(process=FakeProcess(302 if name=='clipboard-owner' else 303,
                                                None if name=='clipboard-owner' else 0),finished=False)
        item.paths=[logs/(name+'.stdout'),logs/(name+'.stderr')]
        item.paths[0].write_text(T.MIME+'\n' if name.startswith('types-') else '')
        item.paths[1].write_text('')
        item.process.stdin=Mock()
        if name.startswith('types-') and self.type_timeout:
            item.process.wait=Mock(side_effect=TimeoutError('primary type readiness timeout'))
        item.healthy=lambda:T.need(item.process.poll() is None,'fake owner exited')
        def finish():
            item.finished=True;self.emit('process_exit',name=name,returncode=item.process.returncode,logs=[])
            if self.finish_error and name=='clipboard-owner':raise RuntimeError('secondary finish fault')
            if self.type_finish and name.startswith('types-'):raise RuntimeError('secondary type drain fault')
        item.finish=finish
        if name=='clipboard-owner':self.owner=item
        return item

    def terminate(self,process):
        if process.poll() is None:process.returncode=-15
        return process.returncode


def exercise(directory,base=None,stage='minimal',nonce='a'*32,pid=102):
    base=base or WorkerBase()
    with contextlib.redirect_stdout(io.StringIO()),patch.object(worker.platform,'machine',return_value='aarch64'),\
         patch.object(worker.os,'isatty',return_value=True):
        result=worker.exercise(base,directory,stage,nonce,pid,{},'/dev/pts/7')
    return result,base


class DataTests(unittest.TestCase):
    def test_owned_native_window_requires_identity_and_readable_onscreen_geometry(self):
        self.assertIsNotNone(T.window([client()],102))
        for change in (dict(hidden=True),dict(xwayland=True),dict(title='other'),dict(size=[100,100]),
                       dict(at=[1000,0]),{'class':'foreign'}):
            with self.subTest(change=change),self.assertRaises(ValueError):T.window([client()|change],102)
        with self.assertRaises(ValueError):T.window([client(),client()],102)
        self.assertIsNone(T.window([client()|dict(mapped=False)],102))
        self.assertIsNone(T.window([client()|dict(pid=True)],102))

    def test_result_publication_is_fresh_bounded_and_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);T.publish(root/'result',dict(one=1))
            with self.assertRaises(ValueError):T.publish(root/'result',dict(one=2))
            (root/'alias').symlink_to('result')
            with self.assertRaises(ValueError):T.read(root/'alias')
            (root/'large').write_bytes(b'12345')
            with self.assertRaises(ValueError):T.read(root/'large',4)

    def test_config_snapshot_preserves_symlinks_and_detects_changed_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'user').write_text('preserve');(root/'alias').symlink_to('user')
            before=T.snapshot(root);self.assertEqual(before,T.snapshot(root))
            (root/'user').write_text('changed');self.assertNotEqual(before,T.snapshot(root))
            self.assertEqual(before['alias']['target'],'user')

    def test_guard_refuses_before_worker_actions(self):
        fake=SimpleNamespace(guard=Mock(side_effect=ValueError('guest refused')))
        with patch.object(worker.argparse.ArgumentParser,'parse_args',return_value=SimpleNamespace()),\
             patch.object(worker,'load',return_value=fake),patch.object(worker,'exercise') as run:
            with self.assertRaisesRegex(ValueError,'guest refused'):worker.main()
            run.assert_not_called()

    def test_deadline_does_not_accept_late_success(self):
        with patch.object(session.time,'monotonic',side_effect=[0,1,4]):
            with self.assertRaisesRegex(ValueError,'deadline'):session.wait(lambda:True,lambda:None,3,'probe')

    def test_worker_identity_joins_uid_and_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'5').mkdir();path=root/'5/status'
            path.write_text('Name:\tpython3\nPPid:\t10\nUid:\t23001\t23001\t23001\t23001\n')
            self.assertEqual(session.worker_identity(5,10,root)['uid'],23001)
            with self.assertRaises(ValueError):session.worker_identity(5,11,root)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)

    def test_real_command_vectors_and_exact_edit_compile_clipboard_data(self):
        result,base=exercise(self.root)
        self.assertEqual((self.root/'main.c').read_bytes(),T.EDITED)
        self.assertNotEqual(result['source_before']['sha256'],result['source_after']['sha256'])
        self.assertEqual(result['native_stdout']['base64'],T.b64(T.OUTPUT))
        self.assertEqual(result['clipboard']['base64'],T.b64(T.CLIPBOARD))
        self.assertTrue(base.owner.finished);self.assertEqual(base.owner.process.returncode,0)
        base.owner.process.stdin.write.assert_called_once_with(T.CLIPBOARD)
        vim=base.calls[0][1];self.assertIn('NONE',vim);self.assertIn('--noplugin',vim)
        self.assertIn('-Werror',base.calls[1][1])
        self.assertEqual([r['name'] for r in result['processes']],['vim-edit','compile','native-run','types-0','paste','clipboard-owner'])
        self.assertIn('READY FOR OWNED QMP CAPTURE',result['transcript'])

    def test_noop_editor_is_not_a_successful_edit(self):
        base=WorkerBase();base.edits=False
        with self.assertRaisesRegex(ValueError,'Vim did not produce'):exercise(self.root,base)
        self.assertFalse((self.root/'probe').exists())

    def test_wrong_native_architecture_is_refused_before_execution(self):
        base=WorkerBase();base.bad_elf=True
        with self.assertRaisesRegex(ValueError,'not AArch64'):exercise(self.root,base)
        self.assertNotIn('native-run',[name for name,_ in base.calls])

    def test_exact_native_stdout_is_required(self):
        base=WorkerBase();base.native=b'wrong\n'
        with self.assertRaisesRegex(ValueError,'native C output differs'):exercise(self.root,base)
        self.assertIsNone(base.owner)

    def test_unicode_clipboard_mismatch_retires_owner(self):
        base=WorkerBase();base.clipboard=b'ascii replacement\n'
        with self.assertRaisesRegex(ValueError,'Unicode clipboard differs'):exercise(self.root,base)
        self.assertTrue(base.owner.finished);self.assertIsNotNone(base.owner.process.poll())

    def test_paste_primary_error_survives_cleanup_fault(self):
        base=WorkerBase();base.paste_error=True;base.finish_error=True
        with self.assertRaisesRegex(ValueError,'primary paste fault') as caught:exercise(self.root,base)
        self.assertTrue(base.owner.finished);self.assertEqual(base.owner.process.returncode,-15)
        self.assertIn('clipboard-owner',[r['name'] for r in caught.exception.workflow_diagnostics['processes']])

    def test_type_timeout_preserves_primary_and_retires_clipboard_owner(self):
        base=WorkerBase();base.type_timeout=True;base.type_finish=True
        with self.assertRaisesRegex(TimeoutError,'primary type readiness timeout'):exercise(self.root,base)
        self.assertTrue(base.owner.finished);self.assertEqual(base.owner.process.returncode,-15)

    def test_result_requires_terminal_pty_parent_payload_and_clean_child_records(self):
        result,_=exercise(self.root)
        for change in (dict(terminal_isatty=False),dict(terminal_pid=99),dict(architecture='x86_64')):
            with self.assertRaises(ValueError):T.validate_result(result|change,'minimal','a'*32,102)
        bad=copy.deepcopy(result);bad['processes'][0]['returncode']=1
        with self.assertRaises(ValueError):T.validate_result(bad,'minimal','a'*32,102)


class ClientProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)

    def helper(self,code=6,output=None,errors=b''):
        paths=[self.root/'probe.stdout',self.root/'probe.stderr']
        # Exact stdout retained from actual38871360375, independent of the matcher.
        observed="Hyprland IPC didn't respond in time\n\nCouldn't read (6)\n"
        paths[0].write_text(observed if output is None else output)
        paths[1].write_bytes(errors)
        probe=SimpleNamespace(process=FakeProcess(700,code),paths=paths,finish=Mock())
        base=SimpleNamespace(Logged=Mock(return_value=probe),terminate=Mock(),emit=Mock())
        return base,probe

    def test_observed_exit6_is_retired_and_reported_before_readiness_retry(self):
        base,probe=self.helper()
        with patch.object(session,'base',base):self.assertIsNone(session.startup_clients({},self.root,'owned'))
        base.terminate.assert_called_once_with(probe.process);probe.finish.assert_called_once()
        base.emit.assert_called_once_with('readiness_retry',scope='initial-terminal-mapping-only',probe='owned',
                                          reason='hyprctl-ipc-read-timeout',returncode=6)

    def test_other_exit_or_diagnostic_or_stderr_is_not_retryable(self):
        for options in (dict(code=1),dict(output='different IPC error\n'),dict(errors=b'other fault')):
            base,probe=self.helper(**options)
            with patch.object(session,'base',base),self.assertRaises(ValueError):session.startup_clients({},self.root,'owned')
            base.emit.assert_not_called();probe.finish.assert_called_once()

    def test_success_still_requires_valid_json(self):
        base,probe=self.helper(code=0,output='[]\n')
        with patch.object(session,'base',base):self.assertEqual(session.startup_clients({},self.root,'owned'),[])
        base,probe=self.helper(code=0,output='malformed')
        with patch.object(session,'base',base),self.assertRaises(ValueError):session.startup_clients({},self.root,'owned')

    def test_log_drain_failure_cannot_become_retry(self):
        base,probe=self.helper();probe.finish.side_effect=ValueError('drain failed')
        with patch.object(session,'base',base),self.assertRaisesRegex(ValueError,'drain failed'):
            session.startup_clients({},self.root,'owned')
        base.emit.assert_not_called()

    def test_wait_failure_preserves_primary_and_runs_both_cleanup_duties(self):
        base,probe=self.helper();probe.process.wait=Mock(side_effect=TimeoutError('primary wait failure'))
        base.terminate.side_effect=RuntimeError('secondary termination failure')
        with patch.object(session,'base',base),self.assertRaisesRegex(TimeoutError,'primary wait failure'):
            session.startup_clients({},self.root,'owned')
        probe.finish.assert_called_once();base.emit.assert_not_called()



if __name__=='__main__':unittest.main()
