# SPDX-License-Identifier: MIT
"""Full observer lifecycle under mocked VM/app actors; never types on a host."""
import base64
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from test_keyboard import board,setup_surface,startup_proof
import session as S
import keyboard as K


class Phase(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.config=self.root/'config';self.config.mkdir();(self.config/'sentinel').write_text('preserve')
        self.in_workspace=False;self.bad_workspace=False;self.startup=[];self.events=[];self.actors=[];self.observed=[];self.step=None;self.clock=0;self.workspace=None
        self.original_stat=Path.stat
        (self.root/'minimal.lua').write_text('declared minimal fixture')
        self.fail_close=self.config_drift=self.bad_input=self.bad_capture=self.gpio=self.bad_shell=self.diagnostic_fail=False
        self.terminal=dict(pid=100,uid=[23001]*4,starttime=5,executable='/usr/bin/alacritty')
        self.shell=dict(pid=101,uid=[23001]*4,starttime=6,executable='/usr/bin/bash',parent_pid=100)
        self.editor=dict(pid=102,uid=[23001]*4,starttime=7,executable='/usr/bin/vim',parent_pid=101)
        self.row=dict(pid=100,**{'class':'Alacritty'},mapped=True,visible=True,hidden=False,xwayland=False,focusHistoryID=0,at=[12,12],size=[1000,740])
        self.base=SimpleNamespace(HOME=self.root,RUNTIME=SimpleNamespace(glob=lambda _:
            [SimpleNamespace(name='wayland-0',is_socket=lambda:True)] if self.actors else []),
            Logged=self.launch,ipc=lambda stage,actor,env,logs:dict(env),command=self.command,emit=self.emit,terminate=self.terminate)
    def now(self):self.clock+=.2;return self.clock
    def launch(self,argv,name,logs,env):
        self.assertEqual(argv[0],'/usr/bin/Hyprland')
        actor=SimpleNamespace(process=SimpleNamespace(pid=90,returncode=None),finished=False)
        actor.process.poll=lambda:actor.process.returncode
        actor.process.wait=lambda timeout:K.need(actor.process.returncode is not None,'compositor not retired')
        actor.healthy=lambda:K.need(actor.process.returncode is None,'compositor exited')
        def finish():actor.finished=True;self.events.append(dict(event='process_exit',name=name,returncode=actor.process.returncode))
        actor.finish=finish;self.actors.append(actor);return actor
    def terminate(self,process):
        if process.returncode is None:process.returncode=-15
    def rows(self):
        if self.step is None:return copy.deepcopy(self.startup)
        if self.step=='close' and not self.fail_close:return []
        return [copy.deepcopy(self.row)]
    def command(self,argv,env,logs,label,timeout=20):
        if 'monitors' in argv:return json.dumps([dict(width=1024,height=768,scale=1)])
        if 'devices' in argv:return json.dumps(dict(keyboards=[dict(name='host' if self.bad_input else 'qemu-virtio-keyboard',layout='us',capsLock=False)]+([dict(name='gpio-keys',layout='us',capsLock=False,main=True)] if self.gpio else [])))
        if 'clients' in argv:
            if self.bad_capture and any(r['event']=='frame_ready' for r in self.events):raise ValueError('strict IPC capture failure')
            return json.dumps(self.rows())
        if argv[0]=='/usr/bin/busctl':
            if 'GetConnectionUnixUser' in argv:return 'u 23001\n'
            if 'GetConnectionUnixProcessID' in argv:return 'u 80\n'
            if 'GetUnit' in argv:return 'o "/org/freedesktop/systemd1/unit/default_2etarget"\n'
        if argv[-1]=='hl.dsp.exit()':self.actors[0].process.returncode=0;return 'ok\n'
        raise AssertionError(argv)
    def emit(self,event,**kw):
        if event=='keyboard_failure_diagnostic' and self.diagnostic_fail:raise RuntimeError('optional diagnostic failure')
        self.events.append(dict(event=event,**copy.deepcopy(kw)))
        if event!='keyboard_request':return
        self.step=kw['step'];self.workspace=self.root/('keyboard-minimal-'+kw['nonce'])
        if self.step=='workspace' and not self.bad_workspace:self.in_workspace=True
        if self.step in ('shell','editor-save','result'):
            name={'shell':'shell.txt','editor-save':'edit.txt','result':'result.txt'}[self.step]
            (self.workspace/name).write_bytes(b'observed wrong bytes\n' if self.bad_shell and name=='shell.txt' else K.expected(kw['nonce'])[name])
        if self.step=='result' and self.config_drift:(self.config/'sentinel').write_text('changed')
        if self.step=='editor-quit':next(p for p in self.observed if p.proof['pid']==102).retired=True
        if self.step=='close' and not self.fail_close:
            for p in self.observed:p.retired=True
    def readlink(self,path):
        if str(path).endswith('/fd/0'):return '/dev/pts/0'
        if str(path).endswith('/cwd'):return str(self.workspace) if self.in_workspace else '/'
        raise AssertionError(path)
    def observed_factory(self,pid,executable='/usr/bin/alacritty'):
        proof=next(p for p in (self.terminal,self.shell,self.editor) if p['pid']==pid)
        proof={k:v for k,v in proof.items() if k!='parent_pid'}
        obj=SimpleNamespace(proof=proof,retired=False,closed=False)
        obj.healthy=lambda:K.need(not obj.retired,'owned process retired')
        obj.wait=lambda seconds:K.need(obj.retired,'pidfd retirement deadline')
        def close():obj.closed=True;obj.retired=True
        obj.close=close;self.observed.append(obj);return obj
    def child(self,parent,exe):
        if exe=='/usr/bin/bash':return copy.deepcopy(self.shell)
        if self.step in ('editor-open','editor-type','editor-save'):return copy.deepcopy(self.editor)
        return None
    def guest_stat(self,path,*args,**kwargs):
        value=self.original_stat(path,*args,**kwargs)
        if path.name in ('shell.txt','edit.txt','result.txt'):
            import os
            fields=list(value);fields[4]=23001;return os.stat_result(fields)
        return value
    def run_phase(self):
        with patch.object(S,'base',self.base),patch.object(S,'ObservedTerminal',self.observed_factory),\
             patch.object(S.compositor_log,'launch',side_effect=lambda base,stage,config,logs,env:self.launch(['/usr/bin/Hyprland','--config',str(config)],stage,logs,env)),\
             patch.object(S,'input_device',return_value=dict(name='QEMU Virtio Keyboard',driver='virtio_input')),\
             patch.object(S,'board_input',return_value=board()),\
             patch.object(Path,'stat',lambda path,*a,**kw:self.guest_stat(path,*a,**kw)),\
             patch.object(Path,'lstat',lambda path,*a,**kw:self.guest_stat(path,follow_symlinks=False)),patch.object(S,'child',self.child),patch.object(S,'descendant',side_effect=lambda pid,parent,exe:startup_proof()['compositor'] if exe=='/usr/bin/Hyprland' else startup_proof([setup_surface(91)],True)['owner'] if exe=='/usr/bin/Xwayland' else self.editor),\
             patch.object(S.os,'readlink',side_effect=self.readlink),\
             patch.object(S.W,'startup_clients',side_effect=lambda *a:self.rows()),\
             patch.object(S.time,'monotonic',self.now),patch.object(S.time,'sleep',lambda _:None),\
             patch.dict(S.os.environ,{'CACHY_MANAGED_MANAGER_PID':'80'}):
            S.phase('minimal',self.root/'minimal.lua',dict(XDG_CONFIG_HOME=str(self.config)),self.root)
    def test_fixed_observer_inputs_three_captures_and_process_retirement(self):
        self.run_phase()
        self.assertEqual([r['step'] for r in self.events if r['event']=='keyboard_request'],list(K.STEPS))
        self.assertEqual([r['view'] for r in self.events if r['event']=='frame_ready'],list(K.VIEWS))
        self.assertEqual((self.config/'sentinel').read_text(),'preserve')
        self.assertTrue(all(p.closed and p.retired for p in self.observed))
        self.assertEqual(self.events[-1]['event'],'phase_pass');self.assertTrue(self.actors[0].finished)
    def test_failed_close_does_not_become_success_and_retires_all(self):
        self.fail_close=True
        with self.assertRaisesRegex(ValueError,'pidfd retirement'):self.run_phase()
        self.assertTrue(all(p.closed for p in self.observed));self.assertTrue(self.actors[0].finished)
        self.assertFalse(any(r['event']=='phase_pass' for r in self.events))
    def test_configuration_drift_fails_after_cleanup(self):
        self.config_drift=True
        with self.assertRaisesRegex(ValueError,'configuration changed'):self.run_phase()
        self.assertTrue(all(p.closed for p in self.observed));self.assertTrue(self.actors[0].finished)
    def test_host_named_keyboard_refused_before_launch(self):
        self.bad_input=True
        with self.assertRaisesRegex(ValueError,'unexpected or duplicate keyboard'):self.run_phase()
        self.assertFalse(any(r['event']=='keyboard_request' for r in self.events));self.assertTrue(self.actors[0].finished)
    def test_capture_ipc_failure_preserves_primary_and_cleans_owned(self):
        self.bad_capture=True
        with self.assertRaisesRegex(ValueError,'strict IPC capture'):self.run_phase()
        self.assertTrue(all(p.closed for p in self.observed));self.assertTrue(self.actors[0].finished)


    def test_actual_gpio_companion_reaches_all_unchanged_input_and_cleanup_gates(self):
        self.gpio=True;self.run_phase()
        ready=next(r for r in self.events if r['event']=='keyboard_ready')
        self.assertEqual(ready['board_device'],board());self.assertEqual(len(ready['keyboards']),2)
        self.assertEqual([r['step'] for r in self.events if r['event']=='keyboard_request'],list(K.STEPS))
        self.assertTrue(all(p.closed and p.retired for p in self.observed))


    def test_shell_deadline_preserves_known_file_bytes_and_optional_frame_request_before_cleanup(self):
        self.bad_shell=True
        with self.assertRaisesRegex(ValueError,'typed shell output deadline'):self.run_phase()
        diagnostic=next(r for r in self.events if r['event']=='keyboard_failure_diagnostic')
        self.assertEqual(diagnostic['last_step'],'shell');self.assertTrue(diagnostic['capture_requested'])
        self.assertTrue(diagnostic['diagnostic_only']);self.assertFalse(diagnostic['success_evidence'])
        row=diagnostic['files']['shell.txt'];self.assertEqual(row['status'],'READ')
        self.assertEqual(base64.b64decode(row['prefix_base64']),b'observed wrong bytes\n')
        self.assertEqual(row['sha256'],K.sha(b'observed wrong bytes\n'))
        self.assertEqual(diagnostic['files']['edit.txt'],dict(status='ABSENT'))
        self.assertLess(self.events.index(diagnostic),next(i for i,r in enumerate(self.events) if r['event']=='process_exit'))
        self.assertTrue(all(p.closed for p in self.observed));self.assertTrue(self.actors[0].finished)
        self.assertFalse(any(r['event'] in ('frame_ready','phase_pass') for r in self.events))

    def test_optional_diagnostic_failure_never_masks_original_or_skips_cleanup(self):
        self.bad_shell=True;self.diagnostic_fail=True
        with self.assertRaisesRegex(ValueError,'typed shell output deadline'):self.run_phase()
        self.assertTrue(all(p.closed for p in self.observed));self.assertTrue(self.actors[0].finished)
        self.assertEqual(self.events[-1]['detail'],'typed shell output deadline')

    def test_file_diagnostics_only_fixed_safe_bounded_leaves(self):
        workspace=self.root/'workspace';workspace.mkdir();(workspace/'unrequested.txt').write_text('private')
        (workspace/'shell.txt').write_bytes(b'x'*1000);(workspace/'edit.txt').write_bytes(b'y'*1025)
        (workspace/'result.txt').symlink_to(workspace/'unrequested.txt')
        with patch.object(Path,'lstat',lambda path,*a,**kw:self.guest_stat(path,follow_symlinks=False)):
            rows=S.failure_files(workspace)
        self.assertEqual(set(rows),{'shell.txt','edit.txt','result.txt'})
        self.assertEqual(rows['shell.txt']['prefix_bytes'],256);self.assertEqual(rows['shell.txt']['sha256'],K.sha(b'x'*1000))
        self.assertEqual(len(base64.b64decode(rows['shell.txt']['prefix_base64'])),256)
        self.assertEqual(rows['edit.txt']['status'],'OVERSIZED_NOT_READ')
        self.assertEqual(rows['result.txt']['status'],'UNSAFE_NOT_READ')
        self.assertNotIn('prefix_base64',rows['result.txt'])



    def test_generated_host_failure_capture_is_optional_nonce_bound_and_separate(self):
        import ast
        import prepare
        source=next(p for p in Path(__file__).resolve().parents if (p/'scripts/ci/maintained-desktop574-inputs.json').exists())
        runner=self.root/'runner';prepare.prepare(source,runner)
        tree=ast.parse((runner/'desktop574_runtime.py').read_text())
        node=next(n for n in ast.walk(tree) if isinstance(n,ast.If) and isinstance(n.test,ast.Compare) and
                  any(isinstance(v,ast.Constant) and v.value=='keyboard_failure_diagnostic' for v in n.test.comparators))
        code=compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),'<generated-failure-capture>','exec')
        fixture=self.root/'fixture';fixture.mkdir();frames=self.root/'frames';frames.mkdir()
        calls=[]
        def execute(name,args):
            calls.append((name,args));(fixture/'minimal-failure.ppm').write_bytes(b'synthetic pixels')
        env=dict(event=dict(event='keyboard_failure_diagnostic',stage='minimal',nonce='a'*32,last_step='shell',
                            diagnostic_only=True,success_evidence=False,capture_requested=True),
                 require=K.need,qmp=SimpleNamespace(execute=execute),keyboard_controller=SimpleNamespace(nonces=dict(minimal='a'*32)),
                 report=dict(status='FAIL',frames={}),fixture=fixture,frames=frames,
                 ppm=lambda path:dict(sha256=K.sha(path.read_bytes())),shutil=__import__('shutil'))
        exec(code,env)
        self.assertEqual(env['report']['frames'],{});self.assertEqual(set(env['report']['failure_frames']),{'minimal'})
        self.assertEqual(calls,[('screendump',dict(filename='/out/minimal-failure.ppm'))]);self.assertEqual(env['report']['status'],'FAIL')
        exec(code,env);self.assertEqual(len(calls),1);self.assertEqual(len(env['report']['failure_frame_errors']),1)
        env['report']=dict(status='FAIL',frames={});env['event']['nonce']='b'*32
        exec(code,env);self.assertEqual(len(calls),1);self.assertIn('failure_frame_errors',env['report'])
        env['event']['nonce']='a'*32;env['report']=dict(status='FAIL',frames={})
        def failed(*a):raise TimeoutError('optional QMP failure')
        env['qmp']=SimpleNamespace(execute=failed);exec(code,env)
        self.assertEqual(env['report']['status'],'FAIL');self.assertEqual(env['report']['frames'],{})
        self.assertIn('optional QMP failure',env['report']['failure_frame_errors'][0])



    def test_two_anonymous_owned_xwayland_records_allow_unchanged_workflow(self):
        self.startup=[setup_surface(90,'0x1'),setup_surface(90,'0x2')];self.run_phase()
        ready=next(r for r in self.events if r['event']=='keyboard_ready')
        self.assertEqual(ready['startup_windows']['records'],self.startup)
        self.assertEqual([r['step'] for r in self.events if r['event']=='keyboard_request'],list(K.STEPS))
        self.assertTrue(all(p.closed and p.retired for p in self.observed))

    def test_owned_xwayland_child_setup_records_allow_workflow(self):
        self.startup=[setup_surface(91,'0x1'),setup_surface(91,'0x2')];self.run_phase()
        ready=next(r for r in self.events if r['event']=='keyboard_ready')
        self.assertEqual(ready['startup_windows']['owner']['parent_pid'],90)
        self.assertTrue(self.actors[0].finished)

    def test_preexisting_mapped_or_named_application_refused_before_input(self):
        for change in (dict(mapped=True),dict(visible=True),{'class':'app'},dict(pid=200)):
            self.startup=[setup_surface()|change]
            with self.subTest(change=change),self.assertRaises(ValueError):self.run_phase()
            self.assertFalse(any(r['event']=='keyboard_request' for r in self.events));self.assertTrue(self.actors[-1].finished)
            self.events=[];self.actors=[]



    def test_workspace_cwd_barrier_precedes_output_command_and_stable_settle_is_recorded(self):
        self.run_phase()
        ready=next(r for r in self.events if r['event']=='keyboard_terminal')
        self.assertGreaterEqual(ready['initial_settle_ms'],10000)
        workspace=next(r for r in self.events if r['event']=='keyboard_workspace')
        self.assertEqual(workspace['method'],'passive-proc-cwd')
        self.assertEqual(workspace['cwd'],dict(status='READ',path=str(self.workspace)))
        self.assertLess(self.events.index(workspace),next(i for i,r in enumerate(self.events) if r['event']=='keyboard_request' and r['step']=='shell'))

    def test_wrong_cd_never_sends_outcome_command_or_retries_input(self):
        self.bad_workspace=True
        with self.assertRaisesRegex(ValueError,'typed workspace cd deadline'):self.run_phase()
        self.assertEqual([r['step'] for r in self.events if r['event']=='keyboard_request'],['launch','workspace'])
        self.assertFalse(any(r['event'] in ('frame_ready','phase_pass','keyboard_workspace') for r in self.events))
        diagnostic=next(r for r in self.events if r['event']=='keyboard_failure_diagnostic')
        self.assertEqual(diagnostic['last_step'],'workspace');self.assertEqual(diagnostic['shell_cwd'],dict(status='READ',path='/'))
        self.assertTrue(all(p.closed for p in self.observed));self.assertTrue(self.actors[0].finished)


if __name__=='__main__':unittest.main()
