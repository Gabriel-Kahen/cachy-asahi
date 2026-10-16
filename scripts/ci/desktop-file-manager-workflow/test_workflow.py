"""Focused inert controls. No Thunar, compositor, D-Bus or native build actors."""
import copy
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import file_manager as T
import contract
import session


def xml():
    return '<node><interface name="'+T.BUS+'">'+''.join(
        '<method name="'+name+'">'+''.join('<arg name="'+n+'" type="'+t+'" direction="in"/>'
        for n,t in args)+'</method>' for name,args in T.METHODS.items())+'</interface></node>'


def window(pid=11):
    return dict(pid=pid,mapped=True,visible=True,hidden=False,xwayland=False,
                title='Files - Thunar',**{'class':'thunar'},size=[800,600],at=[0,0])


class Controls(unittest.TestCase):
    def test_exact_introspection_and_drift(self):
        self.assertEqual(T.introspection(xml()),T.METHODS)
        for bad in (xml().replace('source_filenames','sources'),xml().replace('type="as"','type="s"'),
                    '<node/>',xml().replace('CopyTo','Missing')):
            with self.assertRaises(ValueError):T.introspection(bad)

    def test_window_requires_owned_native_visible_unclipped_identity(self):
        good=window();self.assertEqual(T.window([good],11,'Files'),good)
        self.assertIsNone(T.window([good],12,'Files'))
        self.assertIsNone(T.window([good|dict(visible=False)],11,'Files'))
        for change in (dict(xwayland=True),dict(hidden=True),dict(title='elsewhere'),
                       dict(size=[1200,600]),dict(at=[-1,0]),{'class':'alacritty'}):
            with self.assertRaises(ValueError):T.window([good|change],11,'Files')
        with self.assertRaises(ValueError):T.window([good,good],11,'Files')

    def test_source_pins_and_zero_delta_inventory(self):
        root=Path(__file__).resolve().parents[3]
        contract.verify_source(root)
        proposal=json.loads(Path(__file__).with_name('package-inputs.json').read_text())
        installed={r['name']:r['version'] for r in proposal['closure_packages']}
        contract.verify_package_input(proposal,installed)
        for changed in (proposal|dict(additional_packages=['x']),proposal|dict(replacement_packages=['x'])):
            with self.assertRaises(ValueError):contract.verify_package_input(changed,installed)
        installed['thunar']='wrong'
        with self.assertRaises(ValueError):contract.verify_package_input(proposal,installed)

    def exercise(self, failure=None):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);home=root/'home';home.mkdir();runtime=root/'runtime';runtime.mkdir()
            config=root/'config';config.mkdir();(config/'owned').write_text('preserve')
            sock=socket.socket(socket.AF_UNIX);self.addCleanup(sock.close)
            events=[];actors=[];commands=[]
            class Actor:
                def __init__(self,argv,name,logs,env):
                    self.argv=argv;self.process=SimpleNamespace(pid=10+len(actors),returncode=0,
                        wait=lambda timeout:0);self.finished=False;self.paths=[];actors.append(self)
                def healthy(self):pass
                def finish(self):self.finished=True
            def emit(event,**values):events.append(dict(event=event,**values))
            def command(argv,env,logs,name,timeout=20):
                commands.append(argv)
                if '--method' in argv:
                    method=argv[argv.index('--method')+1].split('.')[-1]
                    if method==failure:raise ValueError('original operation failure')
                    if method=='ListNames':return "(['org.xfce.Xfconf', 'org.xfce.FileManager'],)"
                    if method=='GetConnectionUnixProcessID':return '(uint32 12,)'
                    work=next(home.glob('files-*'))
                    if method=='CopyTo':(work/'Files/created.txt').write_bytes(T.CONTENT)
                    if method=='LaunchFiles':
                        T.publish(work/'opened.json',dict(nonce=work.name.rsplit('-',1)[1],
                            path=str(work/'Files/renamed.txt'),sha256=T.sha(T.CONTENT),bytes=len(T.CONTENT),uid=23001,pid=99))
                    return '()'
                if 'introspect' in argv:return xml()
                if argv[0].endswith('/gio'):
                    if argv[1]=='mime':return 'cachy-file-probe.desktop'
                    Path(argv[-2]).rename(argv[-1]);return ''
                if 'monitors' in argv:return json.dumps([dict(width=1024,height=768,scale=1)])
                if 'clients' in argv:return '[]'
                if 'dispatch' in argv:return 'ok\n'
                return ''
            base=SimpleNamespace(HOME=home,RUNTIME=runtime,SHARE=root/'share',Logged=Actor,
                ipc=lambda *a:(sock.bind(str(runtime/'wayland-0')) or dict(a[2])),command=command,emit=emit,terminate=lambda p:None)
            ticks=iter(i*.5 for i in range(2000))
            with patch.object(session,'base',base),patch.object(session,'startup_clients',return_value=[window(12)]),\
                 patch.object(session,'time',SimpleNamespace(monotonic=lambda:next(ticks),sleep=lambda t:None)):
                # Strict capture queries and post-quit retirement use different client states.
                original=base.command
                def queries(argv,*args,**kwargs):
                    if 'clients' in argv and not any('--quit' in c for c in commands):return json.dumps([window(12)])
                    return original(argv,*args,**kwargs)
                base.command=queries
                if failure:
                    with self.assertRaisesRegex(ValueError,'original operation failure'):
                        session.phase('minimal',root/'minimal.lua',{'XDG_CONFIG_HOME':str(config)},root)
                else:session.phase('minimal',root/'minimal.lua',{'XDG_CONFIG_HOME':str(config)},root)
            self.assertTrue(all(a.finished for a in actors))
            self.assertEqual((config/'owned').read_text(),'preserve')
            return events,commands

    def test_owned_phase_app_operations_preservation_capture_clean_exit(self):
        events,commands=self.exercise()
        result=next(e for e in events if e['event']=='file_manager_result')
        T.validate(result['proof'],'minimal',12)
        self.assertEqual(events[-1]['event'],'phase_pass')
        self.assertTrue(any('org.xfce.FileManager.CopyTo' in c for c in commands))
        self.assertTrue(any('org.xfce.FileManager.LaunchFiles' in c for c in commands))
        self.assertTrue(any('/usr/bin/gio' in c and 'move' in c for c in commands))

    def test_app_operation_failure_retires_all_actors_preserves_primary(self):
        events,_=self.exercise('CopyTo')
        self.assertFalse(any(e['event']=='phase_pass' for e in events))

    def test_no_actor_on_import_and_handler_guard_before_file_read(self):
        spec=importlib.util.spec_from_file_location('inert_handler',Path(__file__).with_name('open_probe.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with patch.object(module.os,'getuid',return_value=0):
            with self.assertRaisesRegex(ValueError,'private guest'):module.main()

    def test_event_digest_order_and_app_attribution_fail_closed(self):
        first,_=self.exercise();second=copy.deepcopy(first)
        for event in second:
            event['stage']='overlay'
            if 'proof' in event:
                event['proof']['stage']='overlay'
                event['proof_sha256']=T.sha((json.dumps(event['proof'],sort_keys=True,indent=2)+'\n').encode())
        second[1]['workflow_proof_sha256']=second[0]['proof_sha256']
        events=first+second+[dict(event='session_pass',status='PASS',thunar='PASS',dbus_copy='PASS',
            gio_rename='PASS',text_launch='PASS',managed_session='UNSELECTED_NOT_RUN',physical_keyboard='NOT_RUN',
            rename_ui='NOT_RUN',editor_ui='NOT_RUN')]
        contract.verify_result(events)
        for mutate in ('digest','order','copy','rename_ui','owner','handler','settle'):
            bad=copy.deepcopy(events)
            if mutate=='digest':bad[1]['workflow_proof_sha256']='0'*64
            elif mutate=='order':bad[0],bad[1]=bad[1],bad[0]
            elif mutate=='copy':bad[0]['proof']['copy']='shell copy'
            elif mutate=='rename_ui':bad[2]['rename_ui']='PASS'
            elif mutate=='owner':bad[0]['proof']['bus_owner_pid']=1
            elif mutate=='handler':bad[0]['proof']['handler']['path']='/outside'
            elif mutate=='settle':bad[1]['capture_after_ms']=1
            with self.assertRaises(ValueError):contract.verify_result(bad)

    def test_startup_retry_only_exact_observed_fully_retired_failure(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);stdout=root/'out';stderr=root/'err';calls=[]
            class Probe:
                def __init__(self,*args):
                    self.paths=[stdout,stderr]
                    self.process=SimpleNamespace(returncode=6,wait=lambda timeout:None)
                def finish(self):calls.append('finished')
            base=SimpleNamespace(Logged=Probe,terminate=lambda p:calls.append('retired'),emit=lambda *a,**k:calls.append('retry'))
            stdout.write_text(session.IPC_READ_TIMEOUT+'\n');stderr.write_text('')
            with patch.object(session,'base',base):
                self.assertIsNone(session.startup_clients({},root,'probe'))
                self.assertEqual(calls,['retired','finished','retry'])
                for output,error in (('other',''),(session.IPC_READ_TIMEOUT,'warning')):
                    stdout.write_text(output);stderr.write_text(error)
                    with self.assertRaises(ValueError):session.startup_clients({},root,'probe')


if __name__=='__main__':unittest.main()
