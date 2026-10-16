# SPDX-License-Identifier: MIT
"""Full observer lifecycle under mocked VM/app actors; never types on a host."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from test_keyboard import board
import session as S
import keyboard as K


class Phase(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.config=self.root/'config';self.config.mkdir();(self.config/'sentinel').write_text('preserve')
        self.events=[];self.actors=[];self.observed=[];self.step=None;self.clock=0;self.workspace=None
        self.original_stat=Path.stat
        (self.root/'minimal.lua').write_text('declared minimal fixture')
        self.fail_close=self.config_drift=self.bad_input=self.bad_capture=self.gpio=False
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
        if self.step is None or self.step=='close' and not self.fail_close:return []
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
        self.events.append(dict(event=event,**copy.deepcopy(kw)))
        if event!='keyboard_request':return
        self.step=kw['step'];self.workspace=self.root/('keyboard-minimal-'+kw['nonce'])
        if self.step in ('shell','editor-save','result'):
            name={'shell':'shell.txt','editor-save':'edit.txt','result':'result.txt'}[self.step]
            (self.workspace/name).write_bytes(K.expected(kw['nonce'])[name])
        if self.step=='result' and self.config_drift:(self.config/'sentinel').write_text('changed')
        if self.step=='editor-quit':next(p for p in self.observed if p.proof['pid']==102).retired=True
        if self.step=='close' and not self.fail_close:
            for p in self.observed:p.retired=True
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
             patch.object(S,'input_device',return_value=dict(name='QEMU Virtio Keyboard',driver='virtio_input')),\
             patch.object(S,'board_input',return_value=board()),\
             patch.object(Path,'stat',lambda path,*a,**kw:self.guest_stat(path,*a,**kw)),patch.object(S,'child',self.child),patch.object(S,'descendant',return_value=self.editor),\
             patch.object(S.os,'readlink',return_value='/dev/pts/0'),\
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

if __name__=='__main__':unittest.main()
