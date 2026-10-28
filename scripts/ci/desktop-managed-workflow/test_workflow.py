"""Inert combined-app controls; all native actors and manager APIs are fake."""
import copy
import json
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import contract
import file_manager as F
import session
C = session.C
import prepare
from test_terminal_worker import exercise, FakeProcess
from test_managed_api import row, m

ROOT = Path(__file__).resolve().parents[3]


def client(pid, name):
    value=dict(pid=pid,address='0x'+format(pid,'x'),mapped=True,visible=True,hidden=False,xwayland=False,
        floating=False,at=[5,5],size=[1014,758],monitor=0,workspace=dict(id=1,name='1'))
    value.update(title=C.T.TITLE if name=='terminal' else 'Files - Thunar',
                 **{'class':C.T.APP_ID if name=='terminal' else 'thunar'})
    return value


def xml():
    return '<node><interface name="'+F.BUS+'">'+''.join('<method name="'+name+'">'+''.join(
        '<arg name="'+n+'" type="'+t+'" direction="in"/>' for n,t in args)+'</method>'
        for name,args in F.METHODS.items())+'</interface></node>'


class Combined(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.home=self.root/'home';self.home.mkdir();self.config=self.root/'config';self.config.mkdir()
        (self.config/'owned').write_text('preserve');self.actors=[];self.events=[];self.commands=[];self.rows={}
        self.clock=0;self.failure=None;self.finish_failure=False;self.config_change=False;self.bad_exit=False
        self.capture_fault=False;self.disappear=False;self.worker_fault=False
        self.manager_fault=False;self.bad_thunar=False;self.bad_compositor=False
        self.runtime=SimpleNamespace(glob=lambda pattern:[] if not self.actors else
            [SimpleNamespace(is_socket=lambda:True,name='wayland-0')])
        self.base=SimpleNamespace(HOME=self.home,RUNTIME=self.runtime,SHARE=Path('/guest/share'),
            Logged=self.launch,ipc=lambda *a:dict(a[2]),command=self.command,terminate=self.terminate,
            emit=lambda event,**kw:self.events.append(dict(event=event,**kw)))

    def launch(self,argv,name,logs,env):
        actor=SimpleNamespace(argv=argv,name=name,env=dict(env),finished=False,process=FakeProcess(100+len(self.actors)))
        def healthy():F.need(actor.process.poll() is None,'co-resident process exited')
        def finish():
            actor.finished=True
            if self.finish_failure and 'alacritty' in name:raise RuntimeError('secondary drain failure')
        actor.healthy,actor.finish=healthy,finish;self.actors.append(actor)
        if 'alacritty' in argv[0]:self.rows[actor.process.pid]=client(actor.process.pid,'terminal')
        if 'thunar' in argv[0]:self.rows[actor.process.pid]=client(actor.process.pid,'thunar')
        return actor

    def terminate(self,process):
        if process.returncode is None:process.returncode=-15

    def clients(self):return [v for pid,v in self.rows.items() if next(a for a in self.actors if a.process.pid==pid).process.poll() is None]
    def now(self):self.clock+=.2;return self.clock
    def publish(self,path,value):
        C.T_original_publish(path,value)
        if path.name=='start.json':
            result,_=exercise(path.parent,stage='minimal',nonce=value['nonce'],pid=value['terminal_pid'])
            if self.worker_fault:result['native_stdout']['sha256']='0'*64
            C.T_original_publish(path.parent/'result.json',result)
        if path.name=='release.json':self.actors[1].process.returncode=1 if self.bad_exit else 0

    def command(self,argv,env,logs,label,timeout=20):
        self.commands.append((argv,dict(env)))
        if argv[0]=='/usr/bin/busctl':
            if 'GetConnectionUnixUser' in argv:return 'u 23001\n'
            if 'GetConnectionUnixProcessID' in argv:return 'u 999\n' if self.manager_fault else 'u 422\n'
            if 'GetUnit' in argv:return 'o "/org/freedesktop/systemd1/unit/default_2etarget"\n'
        if '--method' in argv:
            method=argv[argv.index('--method')+1].split('.')[-1]
            if method==self.failure:raise ValueError('original app failure')
            if method=='ListNames':return "(['org.xfce.Xfconf','org.xfce.FileManager'],)"
            if method=='GetConnectionUnixProcessID':return '(uint32 103,)'
            work=next(self.home.glob('files-*'))
            if method=='CopyTo':
                (work/'Files/created.txt').write_bytes(F.CONTENT)
                if self.config_change:(self.config/'owned').write_text('changed')
            if method=='LaunchFiles':F.publish(work/'opened.json',dict(nonce=work.name.rsplit('-',1)[1],
                path=str(work/'Files/renamed.txt'),sha256=F.sha(F.CONTENT),bytes=len(F.CONTENT),uid=23001,pid=900))
            return '()'
        if 'introspect' in argv:return xml()
        if argv[0].endswith('/gio'):
            if argv[1]=='mime':return 'cachy-file-probe.desktop'
            Path(argv[-2]).rename(argv[-1]);return ''
        if 'monitors' in argv:return json.dumps([dict(width=1024,height=768,scale=1)])
        if 'clients' in argv:
            if any(e['event']=='file_manager_result' for e in self.events):
                if self.capture_fault:raise ValueError('strict capture IPC failure')
                if self.disappear:self.rows[101]['visible']=False
            return json.dumps(self.clients())
        if '--quit' in argv:self.actors[3].process.returncode=1 if self.bad_thunar else 0;return ''
        if 'dispatch' in argv:
            expression=argv[-1]
            if expression=='hl.dsp.exit()':self.actors[0].process.returncode=1 if self.bad_compositor else 0;return 'ok\n'
            address=re.search('address:(0x[0-9a-f]+)',expression)[1]
            value=next(r for r in self.rows.values() if r['address']==address)
            if '.float(' in expression:value['floating']=True
            else:
                x,y=map(int,re.search(r'x=([0-9]+),y=([0-9]+)',expression).groups())
                value['size' if '.resize(' in expression else 'at']=[x,y]
            return 'ok\n'
        raise AssertionError(argv)

    def run_phase(self):
        clock=SimpleNamespace(monotonic=self.now,sleep=lambda t:None)
        with patch.object(session,'base',self.base),patch.object(session,'time',clock),\
             patch.object(C.S,'time',clock),patch.object(C.S,'startup_clients',side_effect=lambda *a:self.clients()),\
             patch.object(session,'startup_clients',side_effect=lambda *a:self.clients()),\
             patch.object(C.S,'worker_identity',side_effect=lambda pid,parent:dict(pid=pid,parent_pid=parent,uid=23001)),\
             patch.object(C.T,'publish',side_effect=self.publish),\
             patch.dict(session.os.environ,CACHY_MANAGED_MANAGER_PID='422'):
            session.phase('minimal',self.root/'minimal.lua',dict(XDG_CONFIG_HOME=str(self.config),
                DBUS_SESSION_BUS_ADDRESS=m.ADDRESS,XDG_RUNTIME_DIR=str(m.RUNTIME)),self.root)

    def retired(self):self.assertTrue(all(a.finished and a.process.poll() is not None for a in self.actors))

    def test_both_real_workflows_share_bus_compositor_layout_and_capture(self):
        self.run_phase();self.retired()
        self.assertEqual([a.process.returncode for a in self.actors],[0,0,-15,0])
        self.assertEqual(sum(a.argv[0]=='/usr/bin/Hyprland' for a in self.actors),1)
        self.assertEqual([e['event'] for e in self.events],['terminal_workflow_result','file_manager_result','frame_ready','phase_pass'])
        frame=self.events[2];C.together([frame['terminal'],frame['thunar']],101,103)
        self.assertEqual(self.actors[1].env['DBUS_SESSION_BUS_ADDRESS'],self.actors[3].env['DBUS_SESSION_BUS_ADDRESS'])
        self.assertEqual(self.actors[1].env['WAYLAND_DISPLAY'],self.actors[3].env['WAYLAND_DISPLAY'])
        self.assertEqual((self.config/'owned').read_text(),'preserve')
        self.assertTrue(frame['co_resident']);self.assertGreaterEqual(frame['capture_after_ms'],5000)

    def test_app_failure_retires_both_apps_and_original_error_survives_drain_fault(self):
        self.failure='CopyTo';self.finish_failure=True
        with self.assertRaisesRegex(ValueError,'original app failure'):self.run_phase()
        self.retired();self.assertNotIn('frame_ready',[e['event'] for e in self.events])

    def test_nonzero_terminal_exit_refuses_phase_pass(self):
        self.bad_exit=True
        with self.assertRaisesRegex(ValueError,'terminal did not exit cleanly'):self.run_phase()
        self.retired();self.assertNotIn('phase_pass',[e['event'] for e in self.events])

    def test_nonzero_thunar_exit_refuses_phase_pass(self):
        self.bad_thunar=True
        with self.assertRaisesRegex(ValueError,'unclean Thunar exit'):self.run_phase()
        self.retired();self.assertNotIn('phase_pass',[e['event'] for e in self.events])

    def test_nonzero_compositor_exit_refuses_phase_pass(self):
        self.bad_compositor=True
        with self.assertRaisesRegex(ValueError,'unclean compositor exit'):self.run_phase()
        self.retired();self.assertNotIn('phase_pass',[e['event'] for e in self.events])

    def test_manager_pid_change_refuses_frame(self):
        self.manager_fault=True
        with self.assertRaisesRegex(ValueError,'manager bus owner PID differs'):self.run_phase()
        self.retired();self.assertNotIn('frame_ready',[e['event'] for e in self.events])

    def test_late_ipc_failure_stays_fatal_without_frame(self):
        self.capture_fault=True
        with self.assertRaisesRegex(ValueError,'strict capture IPC failure'):self.run_phase()
        self.retired();self.assertNotIn('frame_ready',[e['event'] for e in self.events])

    def test_disappearing_terminal_refuses_combined_capture(self):
        self.disappear=True
        with self.assertRaisesRegex(ValueError,'both owned apps'):self.run_phase()
        self.retired();self.assertNotIn('frame_ready',[e['event'] for e in self.events])

    def test_worker_payload_tamper_refuses_combined_result(self):
        self.worker_fault=True
        with self.assertRaisesRegex(ValueError,'native_stdout proof differs'):self.run_phase()
        self.retired();self.assertNotIn('frame_ready',[e['event'] for e in self.events])

    def test_existing_user_configuration_drift_prevents_acceptance(self):
        self.config_change=True
        with self.assertRaisesRegex(ValueError,'configuration changed'):self.run_phase()
        self.retired();self.assertNotIn('phase_pass',[e['event'] for e in self.events])

    def test_complete_combined_contract_and_mutation_controls(self):
        self.run_phase();first=self.events;second=copy.deepcopy(first)
        for e in second:
            e['stage']='overlay'
            if 'proof' in e:
                e['proof']['stage']='overlay'
                e['proof_sha256']=F.sha((json.dumps(e['proof'],sort_keys=True,indent=2)+'\n').encode())
        second[2]['terminal_proof_sha256']=second[0]['proof_sha256'];second[2]['workflow_proof_sha256']=second[1]['proof_sha256']
        identity=dict(address=m.ADDRESS,uid=23001,manager_pid=422,default_target='GetUnit-PASS')
        events=[dict(event='managed_session_ready',status='PASS',**identity,units={
            m.SESSIONS:row(m.SESSIONS,'active','exited'),m.DIRECTORY:row(m.DIRECTORY,'active','exited'),
            m.USER:row(m.USER,'active','running',422)}),dict(event='managed_user_ready',status='PASS',**identity)]+first+second+[
            dict(event='session_pass',status='PASS',co_resident=True,terminal='PASS',vim_edit='PASS',native_c='PASS',
                unicode_clipboard='PASS',thunar='PASS',dbus_copy='PASS',gio_rename='PASS',text_launch='PASS',
                managed_session='SELECTED_REAL_USER_MANAGER',physical_keyboard='NOT_RUN',rename_ui='NOT_RUN',editor_ui='NOT_RUN'),
            dict(event='managed_session_cleanup',status='PASS',units=[m.USER,m.DIRECTORY],
                unit_states={u:row(u) for u in (m.USER,m.DIRECTORY)},runtime_absent=True,owned_units_stopped=True),
            dict(event='complete',status='PASS')]
        self.assertEqual(contract.verify_result(events)['status'],'PASS')
        for field,value in (('manager_pid',999),('bus_address','unix:path=/tmp/private'),('co_resident',False),
                            ('terminal_proof_sha256','0'*64),('compositor_pid',101),('capture_after_ms',1)):
            bad=copy.deepcopy(events);bad[4][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):contract.verify_result(bad)
        for index in (0,1,-1,-2):
            bad=events.copy();bad.pop(index)
            with self.assertRaises(ValueError):contract.verify_result(bad)


class LayoutAndStage(unittest.TestCase):
    def test_layout_targets_exact_owned_addresses_and_refuses_foreign_identity(self):
        rows=[client(1,'terminal'),client(2,'thunar')];commands=[]
        command=lambda argv,label:(commands.append(argv) or 'ok\n')
        self.assertTrue(C.layout(command,rows,1,2));self.assertEqual(len(commands),6)
        rows[1]['class']='foreign';commands.clear()
        with self.assertRaises(ValueError):C.layout(command,rows,1,2)
        self.assertEqual(commands,[])
        rows[1]['class']='thunar';rows[0]['address']='0x1";escape'
        with self.assertRaises(ValueError):C.layout(command,rows,1,2)

    def test_together_requires_layout_workspace_monitor_and_native_windows(self):
        rows=[client(1,'terminal'),client(2,'thunar')]
        for name,r in zip(('terminal','thunar'),rows):r.update(at=C.RECTANGLES[name][0],size=C.RECTANGLES[name][1],floating=True)
        self.assertTrue(C.positioned(rows,1,2));C.together(rows,1,2)
        for change in (dict(monitor=1),dict(workspace=dict(id=2,name='2')),dict(floating=False),
                       dict(at=[12,20]),dict(visible=False),dict(xwayland=True)):
            bad=copy.deepcopy(rows);bad[1].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):C.together(bad,1,2)

    def test_prepare_exact_managed_transform_bounds_markers_and_zero_package_delta(self):
        with tempfile.TemporaryDirectory() as d:
            out=prepare.prepare(ROOT,Path(d)/'runner')
            guest=(out/'base_guest.py').read_text();runtime=(out/'desktop574_runtime.py').read_text()
            self.assertNotIn('dbus-run-session',guest);self.assertNotIn('runuser',guest)
            self.assertIn('managed_session.SETPRIV',guest);self.assertIn('session.wait(timeout=1080)',guest)
            self.assertIn('TimeoutStartSec=1200',(out/'desktop574_fixture.sh').read_text())
            for marker in ('managed_user','terminal_workflow','file_manager','managed_workflow'):
                self.assertIn('cachy_asahi_'+marker+'=1',runtime)
            self.assertIn('deadline = time.monotonic() + 1300',runtime)
            with self.assertRaises(ValueError):prepare.prepare(ROOT,out)
        proposal=json.loads(Path(__file__).with_name('package-inputs.json').read_text())
        installed={r['name']:r['version'] for r in proposal['closure_packages']}
        contract.verify_package_input(proposal,installed)
        with self.assertRaises(ValueError):contract.verify_package_input(proposal|dict(additional_packages=['x']),installed)


C.T_original_publish = C.T.publish
if __name__=='__main__':unittest.main()
