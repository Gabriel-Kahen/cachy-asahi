# SPDX-License-Identifier: MIT
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import keyboard as K
import contract as C
import session as S



def board():
    return dict(name='gpio-keys',event='event1',node='/dev/input/event1',
        sysfs='/sys/devices/platform/gpio-keys/input/input1',driver='gpio-keys',major=13,minor=65,
        bus_type=25,of_node='/sys/firmware/devicetree/base/gpio-keys',compatible_hex='6770696f2d6b65797300',
        poweroff_linux_code_hex='00000074',key_bitmap='10000000000000 0')



def setup_surface(pid=90,address='0x1'):
    return dict(pid=pid,address=address,mapped=False,visible=False,hidden=False,xwayland=True,
        at=[0,0],size=[0,0],monitor=-1,workspace=dict(id=-1,name=''),focusHistoryID=-1,
        floating=False,pinned=False,fullscreen=0,fullscreenClient=0,**{'class':'','title':'','initialClass':'','initialTitle':''})


def startup_proof(rows=None,child=False):
    compositor=dict(pid=90,uid=[23001]*4,starttime=1,executable='/usr/bin/Hyprland',parent_pid=70)
    owner=dict(pid=91,uid=[23001]*4,starttime=2,executable='/usr/bin/Xwayland',parent_pid=90) if child else compositor
    return dict(compositor=compositor,owner=owner if rows else None,records=rows or [])


def events():
    # The accepted managed contract fixture is a modeled lifecycle, not a native run.
    unit=lambda name,sub,pid:dict(Id=name,LoadState='loaded',ActiveState='active',SubState=sub,Result='success',ExecMainStatus=0,MainPID=pid)
    bus=dict(address=C.M_ADDRESS,uid=23001,manager_pid=80,default_target='GetUnit-PASS')
    units={n:unit(n,sub,pid) for n,sub,pid in [('systemd-user-sessions.service','exited',0),('user-runtime-dir@23001.service','exited',0),('user@23001.service','running',80)]}
    result=[dict(event='managed_session_ready',status='PASS',units=units,**bus),dict(event='managed_user_ready',status='PASS',**bus)]
    def add(event,**kw):result.append(dict(event=event,**kw))
    for stage in ('minimal','overlay'):
        nonce=('a' if stage=='minimal' else 'b')*32
        proc=lambda pid,exe:dict(pid=pid,uid=[23001]*4,starttime=2,executable='/usr/bin/'+exe)
        terminal=proc(100,'alacritty');shell=proc(101,'bash')|dict(parent_pid=100,pty='/dev/pts/0');editor=proc(102,'vim')|dict(parent_pid=101)
        window=dict(pid=100,**{'class':'Alacritty'},mapped=True,visible=True,hidden=False,xwayland=False,focusHistoryID=0,at=[12,12],size=[1000,740])
        add('keyboard_ready',stage=stage,nonce=nonce,shortcut_policy='SHIPPED_UNCHANGED' if stage=='overlay' else 'DECLARED_MINIMAL_SUPER_RETURN_SUPER_Q',
            startup_windows=startup_proof(),kernel_device=dict(name='QEMU Virtio Keyboard',driver='virtio_input'),keyboards=[dict(name='qemu-virtio-keyboard',layout='us',capsLock=False)],configuration_sha256=json.loads((HERE/'source-pins.json').read_text())['packages/desktop/cachy-asahi-hyprland-settings/hyprland.lua'])
        file=lambda name:dict(name=name,bytes=len(K.expected(nonce)[name]),sha256=K.sha(K.expected(nonce)[name]))
        for step in K.STEPS:
            plan=K.plan(stage,nonce,step);pin=K.sha(K.encoded(plan))
            add('keyboard_request',stage=stage,step=step,nonce=nonce,plan_sha256=pin)
            add('qmp_keyboard_input',stage=stage,step=step,nonce=nonce,plan_sha256=pin,chords=len(plan),qmp_calls=len(plan),key_events=sum(2*len(c) for c in plan),
                all_keys_released=True,route='input-send-event/virtio-keyboard-pci',delivery_policy=dict(K.DELIVERY_POLICY))
            if step=='launch':add('keyboard_terminal',stage=stage,nonce=nonce,terminal=terminal,shell=shell,window=window,initial_settle_ms=10001)
            if step=='workspace':add('keyboard_workspace',stage=stage,nonce=nonce,shell=shell,
                cwd=dict(status='READ',path='/home/desktop574/keyboard-'+stage+'-'+nonce),method='passive-proc-cwd')
            if step in ('shell','editor-save','result'):
                view={'shell':'shell','editor-save':'editor','result':'result'}[step]
                proof=dict(shell=shell)
                if view=='result':proof['files']=[file(name) for name in K.expected(nonce)]
                else:proof['file']=file('shell.txt' if view=='shell' else 'edit.txt')
                if view=='editor':proof['editor']=editor
                add('frame_ready',stage=stage+'-'+view,phase=stage,view=view,nonce=nonce,terminal=window,terminal_identity=terminal,
                    capture_after_ms=5001,physical_input='NOT_RUN',hardware='NOT_RUN',managed_bus=bus,proof=proof)
            if step=='editor-quit':add('keyboard_editor_closed',stage=stage,nonce=nonce,editor=editor,pidfd_exited=True,exit='UNOBSERVED_NONCHILD')
        add('keyboard_closed',stage=stage,nonce=nonce,terminal=terminal,shell=shell,shell_pidfd_exited=True,exit='UNOBSERVED_NONCHILD',pidfd_exited=True,window_absent=True,method='SUPER_Q_QMP')
        add('process_exit',name=stage,returncode=0)
        add('compositor_log_summary',stage=stage,pid=90,returncode=0,overflow=False,drain_errors=0,
            drains_complete=True,streams=[dict(path='/home/desktop574/logs/'+stage+'.'+suffix,
                observed_bytes=100,limit_bytes=limit) for suffix,limit in [('stdout',2097152),('stderr',262144)]])
        add('phase_pass',stage=stage,nonce=nonce,configuration_preserved=True)
    scope=dict(status='PASS',virtual_keyboard='PASS',editor_ui='PASS_QMP_TYPED_VIM',physical_input='NOT_RUN',hardware='NOT_RUN')
    add('session_pass',**scope)
    cleanup_units=['user@23001.service','user-runtime-dir@23001.service']
    add('managed_session_cleanup',status='PASS',runtime_absent=True,owned_units_stopped=True,units=cleanup_units,
        unit_states={n:dict(Id=n,LoadState='loaded',ActiveState='inactive',SubState='dead',MainPID=0) for n in cleanup_units})
    add('complete',**scope)
    return result


class QMP:
    def __init__(self,fail=None):self.calls=[];self.fail=fail
    def execute(self,name,args=None):
        self.calls.append((name,args))
        if self.fail==len(self.calls):raise TimeoutError('uncertain reply')
        if name=='query-commands':return [dict(name='input-send-event')]
        if name=='query-status':return dict(status='running')
        return {}


class KeyboardTests(unittest.TestCase):
    def test_compositor_log_receipt_rejects_overflow_wrong_owner_or_missing(self):
        for change in ('missing','pid','overflow','drain_errors','cap','count','order'):
            rows=events();row=next(r for r in rows if r['event']=='compositor_log_summary')
            if change=='missing':rows.remove(row)
            elif change=='order':rows.remove(row);rows.insert(0,row)
            elif change=='cap':row['streams'][0]['limit_bytes']+=1
            elif change=='count':row['streams'][0]['observed_bytes']=2097153
            elif change=='pid':row['pid']=91
            elif change=='overflow':row['overflow']=True
            else:row['drain_errors']=1
            with self.subTest(change=change),self.assertRaises(ValueError):C.verify_result(rows)

    def test_fixed_shortcuts_and_nonce_data(self):
        self.assertEqual(K.plan('overlay','a'*32,'launch'),[['meta_l','ret']])
        self.assertEqual(K.plan('overlay','a'*32,'close'),[['meta_l','q']])
        for bad in ('a'*31,'x'*32,'a'*32+';poweroff'):
            with self.assertRaises(ValueError):K.plan('overlay',bad,'shell')
        with self.assertRaises(ValueError):K.qcodes('λ')
        self.assertEqual(K.qcodes('|'),['shift','backslash'])
        self.assertEqual(K.qcodes('\x1b'),['esc'])

    def test_send_batches_one_complete_chord_with_reverse_releases(self):
        q=QMP();self.assertEqual(K.send(q,[['meta_l','ret']],pause=lambda _:None),1)
        self.assertEqual(len(q.calls),1);name,args=q.calls[0];self.assertEqual(name,'input-send-event')
        self.assertEqual([e['data']['key']['data'] for e in args['events']],['meta_l','ret','ret','meta_l'])
        self.assertEqual([e['data']['down'] for e in args['events']],[True,True,False,False])

    def test_uncertain_batch_only_sends_emergency_key_ups_and_stays_failed(self):
        q=QMP(fail=1)
        with self.assertRaises(TimeoutError):K.send(q,[['meta_l','ret']],pause=lambda _:None)
        self.assertEqual(len(q.calls),2)
        self.assertEqual([e['data']['key']['data'] for e in q.calls[1][1]['events']],['ret','meta_l'])
        self.assertTrue(all(e['data']['down'] is False for e in q.calls[1][1]['events']))
        def both_fail(*args):
            raise TimeoutError('primary') if args[1]['events'][0]['data']['down'] else RuntimeError('secondary release')
        from types import SimpleNamespace
        with self.assertRaisesRegex(TimeoutError,'primary'):
            K.send(SimpleNamespace(execute=both_fail),[['c']],pause=lambda _:None)

    def test_controller_rejects_duplicate_reordered_changed_nonce(self):
        c=K.Controller();q=QMP()
        def request(step,nonce='a'*32):return dict(stage='minimal',step=step,nonce=nonce,plan_sha256=K.sha(K.encoded(K.plan('minimal',nonce,step))))
        with patch.object(K,'send',return_value=1):c.handle(q,request('launch'))
        for r in (request('launch'),request('result'),request('workspace','b'*32),request('workspace')|dict(plan_sha256='0'*64)):
            with self.assertRaises(ValueError):c.handle(q,r)

    def test_full_modeled_route_replays(self):
        self.assertEqual(C.verify_result(events())['frames'],6)

    def test_missing_qmp_or_nonce_and_faked_physical_claim_refused(self):
        for change in ('qmp','nonce','physical','driver','policy','file','pid','release','shell-close','vim-close','managed','process-exit'):
            rows=copy.deepcopy(events())
            if change=='qmp':rows.pop(next(i for i,r in enumerate(rows) if r['event']=='qmp_keyboard_input'))
            elif change=='nonce':next(r for r in rows if r['event']=='qmp_keyboard_input')['nonce']='c'*32
            elif change=='physical':next(r for r in rows if r['event']=='complete')['physical_input']='PASS'
            elif change=='driver':next(r for r in rows if r['event']=='keyboard_ready')['kernel_device']['driver']='host-evdev'
            elif change=='policy':next(r for r in rows if r.get('stage')=='overlay' and r['event']=='keyboard_ready')['shortcut_policy']='REPLACED'
            elif change=='file':next(r for r in rows if r['event']=='frame_ready')['proof']['file']['sha256']='0'*64
            elif change=='pid':next(r for r in rows if r['event']=='keyboard_terminal')['terminal']['uid']=[0]*4
            elif change=='release':next(r for r in rows if r['event']=='qmp_keyboard_input')['all_keys_released']=False
            elif change=='shell-close':next(r for r in rows if r['event']=='keyboard_closed')['shell_pidfd_exited']=False
            elif change=='vim-close':next(r for r in rows if r['event']=='keyboard_editor_closed')['pidfd_exited']=False
            elif change=='managed':next(r for r in rows if r['event']=='managed_session_cleanup')['runtime_absent']=False
            else:next(r for r in rows if r['event']=='process_exit')['returncode']=1
            with self.subTest(change=change),self.assertRaises(ValueError):C.verify_result(rows)

    def test_reordered_frame_or_shortcut_result_refused(self):
        rows=events();a=next(i for i,r in enumerate(rows) if r['event']=='frame_ready');b=next(i for i,r in enumerate(rows) if r['event']=='keyboard_request' and r['step']=='shell')
        rows[a],rows[b]=rows[b],rows[a]
        with self.assertRaises(ValueError):C.verify_result(rows)

    def test_observer_contains_no_payload_launch_or_pty_write(self):
        text=(HERE/'session.py').read_text()
        self.assertNotIn('Popen',text);self.assertNotIn('write_text',text);self.assertNotIn('atspi',text)
        self.assertNotIn("['/usr/bin/alacritty'",text);self.assertNotIn("['/usr/bin/vim'",text)
        self.assertIn("request('launch')",text);self.assertIn("request('close')",text)

    def test_prerequisites_are_existing_exact_input_packages(self):
        lock=json.loads((HERE/'prerequisites.json').read_text())
        self.assertEqual(lock['additional_binary_packages'],[])
        self.assertEqual([r['package']['name'] for r in lock['rows']],['qemu-system-aarch64','linux-aarch64'])
        config=(HERE/'upstream-kernel.config').read_text()
        for setting in ('CONFIG_INPUT=y','CONFIG_INPUT_EVDEV=y','CONFIG_VIRTIO_PCI=y','CONFIG_VIRTIO_INPUT=m'):self.assertIn(setting+'\n',config)



    def test_board_power_only_exception_accepts_actual_device_order(self):
        q=dict(name='qemu-virtio-keyboard',layout='us',capsLock=False,main=False)
        g=dict(name='gpio-keys',layout='us',capsLock=False,main=True)
        K.verify_keyboards([q,g],board());K.verify_keyboards([g,q],board())
        rows=events()
        for r in rows:
            if r['event']=='keyboard_ready':r['keyboards']=[q,g];r['board_device']=board()
        self.assertEqual(C.verify_result(rows)['frames'],6)

    def test_unknown_duplicate_or_unproved_board_keyboards_refused(self):
        q=dict(name='qemu-virtio-keyboard',layout='us',capsLock=False)
        g=dict(name='gpio-keys',layout='us',capsLock=False)
        for rows,proof in (([q,q],None),([q,g,g],board()),([g],board()),([q,dict(g,name='usb-keyboard')],board()),
                           ([q,g],None),([q],board()),([q,dict(g,layout='de')],board()),([dict(q,capsLock=True),g],board())):
            with self.subTest(rows=rows),self.assertRaises(ValueError):K.verify_keyboards(rows,proof)

    def test_gpio_identity_and_key_capability_are_replayed(self):
        q=dict(name='qemu-virtio-keyboard',layout='us',capsLock=False);g=dict(name='gpio-keys',layout='us',capsLock=False)
        for key,value in (('driver','virtio_input'),('sysfs','/sys/devices/usb/input/input1'),('bus_type',3),
                          ('of_node','/sys/firmware/devicetree/base/other'),('compatible_hex','00'),
                          ('poweroff_linux_code_hex','0000001e'),('key_bitmap','10000000000000 40000000'),
                          ('key_bitmap','0'),('key_bitmap','f'*257),('major',1),('node','/dev/input/event2')):
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):K.verify_keyboards([q,g],board()|{key:value})
        rows=events()
        for r in rows:
            if r['event']=='keyboard_ready':r['keyboards']=[q,g];r['board_device']=board()
        next(r for r in rows if r['event']=='keyboard_ready')['board_device']['key_bitmap']='1'
        with self.assertRaises(ValueError):C.verify_result(rows)

    def test_passive_board_sysfs_read_is_bounded_and_joins_character_node(self):
        import io,os,stat
        from types import SimpleNamespace
        device='/sys/devices/platform/gpio-keys/input/input1';platform='/sys/devices/platform/gpio-keys'
        of='/sys/firmware/devicetree/base/gpio-keys'
        data={device+'/name':b'gpio-keys\n','/fixture/event1/dev':b'13:65\n',device+'/id/bustype':b'0019\n',
              device+'/capabilities/key':b'10000000000000 0\n',of+'/compatible':b'gpio-keys\0',
              of+'/poweroff/linux,code':b'\0\0\0t'}
        resolved={'/fixture/event1/device':device,platform+'/driver':'/sys/bus/platform/drivers/gpio-keys',platform+'/of_node':of}
        def run():
            with patch.object(Path,'resolve',lambda path,*a,**kw:Path(resolved[str(path)])),\
                 patch.object(Path,'open',lambda path,*a,**kw:io.BytesIO(data[str(path)])),\
                 patch.object(Path,'stat',return_value=SimpleNamespace(st_mode=stat.S_IFCHR|0o600,st_rdev=os.makedev(13,65))):
                return S.board_input(SimpleNamespace(glob=lambda _: [Path('/fixture/event1')]))
        self.assertEqual(run(),board())
        data[device+'/capabilities/key']=b'1'*257
        with self.assertRaisesRegex(ValueError,'byte limit'):run()



    def test_only_owned_quiescent_xwayland_setup_records_are_admitted(self):
        for child in (False,True):
            pid=91 if child else 90
            for count in (0,1,2):K.verify_startup(startup_proof([setup_surface(pid,'0x'+str(i+1)) for i in range(count)],child))
        rows=events()
        for r in rows:
            if r['event']=='keyboard_ready':r['startup_windows']=startup_proof([setup_surface(90,'0x1'),setup_surface(90,'0x2')])
        self.assertEqual(C.verify_result(rows)['frames'],6)

    def test_preexisting_or_identified_windows_are_never_setup_exceptions(self):
        for key,value in (('mapped',True),('visible',True),('xwayland',False),('hidden',True),
                          ('class','Alacritty'),('title','app'),('initialClass','app'),('initialTitle','app'),
                          ('at',[1,0]),('size',[1,1]),('monitor',0),('workspace',dict(id=1,name='1')),
                          ('focusHistoryID',0),('pid',200),('fullscreen',1),('floating',True),('mapped',0)):
            with self.subTest(key=key),self.assertRaises(ValueError):K.verify_startup(startup_proof([setup_surface()|{key:value}]))
        with self.assertRaises(ValueError):K.verify_startup(startup_proof([setup_surface(),setup_surface(),setup_surface()]))
        with self.assertRaises(ValueError):K.verify_startup(startup_proof([setup_surface(),setup_surface()]))

    def test_foreign_setup_process_or_event_tamper_refused(self):
        for key,value in (('uid',[0]*4),('executable','/usr/bin/alacritty'),('parent_pid',123),('starttime',0)):
            proof=startup_proof([setup_surface(91)],True);proof['owner'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):K.verify_startup(proof)
        rows=events();next(r for r in rows if r['event']=='keyboard_ready')['startup_windows']=startup_proof([setup_surface()|dict(visible=True)])
        with self.assertRaises(ValueError):C.verify_result(rows)



    def test_explicit_vm_policy_paces_press_and_release_without_retries(self):
        q=QMP();pauses=[];K.send(q,[['c'],['d']],pause=pauses.append)
        self.assertEqual(pauses,[.5,.5]);self.assertEqual(len(q.calls),2)
        self.assertEqual(K.DELIVERY_POLICY,dict(name='vm-chord-batch-workspace-v1',batch='press-release',gap_ms=500,initial_settle_ms=10000))
        self.assertEqual(K.plan('minimal','a'*32,'workspace')[-1],['ret'])

    def test_cwd_policy_and_initial_settle_are_required_independent_evidence(self):
        for change in ('cwd','missing-cwd','shell-id','policy','settle','cwd-method','ordering'):
            rows=copy.deepcopy(events());workspace=next(r for r in rows if r['event']=='keyboard_workspace')
            if change=='cwd':workspace['cwd']['path']='/'
            elif change=='missing-cwd':rows.remove(workspace)
            elif change=='shell-id':workspace['shell']=dict(workspace['shell'],pid=999)
            elif change=='policy':next(r for r in rows if r['event']=='qmp_keyboard_input')['delivery_policy']['gap_ms']=40
            elif change=='settle':next(r for r in rows if r['event']=='keyboard_terminal')['initial_settle_ms']=3000
            elif change=='cwd-method':workspace['method']='injected chdir'
            else:
                a=rows.index(workspace);b=next(i for i,r in enumerate(rows) if r['event']=='keyboard_request' and r.get('step')=='shell')
                rows[a],rows[b]=rows[b],rows[a]
            with self.subTest(change=change),self.assertRaises(ValueError):C.verify_result(rows)


if __name__=='__main__':unittest.main()
