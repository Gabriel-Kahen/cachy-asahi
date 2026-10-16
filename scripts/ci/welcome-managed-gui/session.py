# SPDX-License-Identifier: MIT
"""Installed Welcome semantic GUI actions beside a real Doctor report terminal."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import time


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


C=load('welcome_phase_contract','gui_contract.py')
S=load('welcome_phase_startup','terminal_session.py')
M=load('welcome_phase_managed','managed_session.py')
O=load('welcome_phase_observed','observed.py')
L=load('welcome_phase_compositor_log','compositor_log.py')
base=None


def wait(probe,healthy,seconds,label):
    until=time.monotonic()+seconds
    while True:
        healthy();C.need(time.monotonic()<until,label+' deadline');value=probe()
        healthy();C.need(time.monotonic()<until,label+' deadline')
        if value is not None:return value
        time.sleep(.2)


def failure(stage,checkpoint,error,workspace):
    result=dict(stage=stage,status='FAIL',checkpoint=checkpoint,error_type=type(error).__name__,reason=str(error)[:512])
    try:
        path=workspace/'result.json'
        if not path.exists():result['doctor_result']=dict(status='ABSENT')
        else:
            raw=C.read(path);value=json.loads(raw)
            C.need(type(value) is dict,'Doctor diagnostic result shape differs')
            result['doctor_result']=dict(bytes=len(raw),sha256=C.sha(raw),
                **{name:str(value.get(name,''))[:cap] for name,cap in (('status',64),('error_type',64),('reason',512))})
    except BaseException as diagnostic:
        result['doctor_result']=dict(status='UNREADABLE',error_type=type(diagnostic).__name__)
    return result


def accessibility_result(raw,stderr,code,pid,operation,label=None,pending=False):
    if pending and code==75 and not stderr:
        try:value=json.loads(raw)
        except (ValueError,UnicodeError):value=None
        if value==dict(status='WAITING_FOR_OWNED_WELCOME'):return None
    C.need(code==0,'owned Welcome accessibility command failed: '+operation+' '+(label or '')+
           '; exit='+str(code)+'; stderr='+stderr.decode(errors='replace').strip()[:512])
    C.need(raw.strip(),'owned Welcome accessibility command returned empty JSON')
    try:value=json.loads(raw)
    except (ValueError,UnicodeError):raise ValueError('owned Welcome accessibility command returned malformed JSON') from None
    C.need(type(value) is dict and value.get('status')=='PASS' and value.get('pid')==pid,
           'owned Welcome accessibility operation failed')
    return value


def phase(stage,config,env,logs):
    compositor=doctor=welcome=settings=thunar=observed=None;first=None;sequence=0;selected=None
    checkpoint='startup'
    nonce=os.urandom(16).hex();workspace=base.HOME/('doctor-'+stage+'-'+nonce);workspace.mkdir(mode=0o700)
    for name in ('cache','data','state','thunar-config'):(workspace/name).mkdir(mode=0o700)
    protected=C.snapshot(Path(env['XDG_CONFIG_HOME']))
    (workspace/'alacritty.toml').write_text(C.T.ALACRITTY.replace('size = 12.0','size = 10.0').replace('x = 12, y = 12','x = 8, y = 8'))
    guides={view:C.sha(C.read(Path('/usr/share/doc/cachy-asahi-welcome')/(name+'.txt'),65536))
            for view,name in (('first-steps','first-run'),('updates','updates'),('recovery','recovery'))}

    def command(argv,label,timeout=20):
        nonlocal sequence
        sequence+=1;return base.command(argv,selected,logs,stage+'-gui-'+str(sequence)+'-'+label,timeout=timeout)

    def healthy():
        for actor in (compositor,doctor,welcome,settings,thunar):
            if actor:actor.healthy()
        if observed:observed.healthy()

    def clients(readiness=False):
        nonlocal sequence
        if readiness:
            S.base=base;sequence+=1
            return S.startup_clients(selected,logs,stage+'-gui-map-'+str(sequence))
        return json.loads(command(['/usr/bin/hyprctl','-j','clients','-a'],'clients'))

    def mapped(pid,kind,initial):
        rows=clients(initial)
        return C.window(rows,pid,kind,positioned=False) if rows is not None else None

    def place(pid,kind,target=None,initial=False):
        row=wait(lambda:mapped(pid,kind,initial),healthy,90,'visible '+kind)
        C.layout(command,row,target or kind)
        def ready():
            rows=clients();row=C.window(rows,pid,kind,positioned=False)
            at,size=C.RECTS[target or kind]
            return row if row and row.get('floating') is True and row.get('at')==at and row.get('size')==size else None
        return wait(ready,healthy,20,'positioned '+kind)

    def bus_identity():
        return M.bus_probe(lambda argv:command(argv,'managed-api'),int(os.environ['CACHY_MANAGED_MANAGER_PID']))

    def a11y(operation,label=None,pending=False):
        nonlocal sequence
        sequence+=1;argv=['/usr/local/bin/welcome-a11y',str(welcome.process.pid),operation]+([label] if label else [])
        actor=base.Logged(argv,stage+'-a11y-'+str(sequence),logs,selected);error=None
        try:actor.process.wait(timeout=25)
        except BaseException as caught:error=caught
        finally:
            for cleanup in (lambda:base.terminate(actor.process),actor.finish):
                try:cleanup()
                except BaseException as caught:
                    if error is None:error=caught
        if error is not None:raise error
        return accessibility_result(C.read(actor.paths[0]),C.read(actor.paths[1]),actor.process.returncode,
                                    welcome.process.pid,operation,label,pending)

    def page(view,text_sha=None,initial=False):
        def ready():
            value=a11y('snapshot',pending=initial)
            if value is None:return None
            try:summary=C.validate_snapshot(value,welcome.process.pid,view,text_sha)
            except C.ViewPending:return None
            return dict(summary=summary,snapshot=value,expected_text_sha256=text_sha,
                        snapshot_sha256=C.sha((json.dumps(value,sort_keys=True)+'\n').encode()))
        return wait(ready,healthy,45,'Welcome '+view+' accessibility state')

    def click(label):
        result=a11y('activate',label);method=C.validate_action(result,welcome.process.pid,label)
        base.emit('welcome_action',stage=stage,label=label,welcome_pid=welcome.process.pid,proof=result,
                  method=method,physical_input='NOT_RUN')

    def capture(view,semantic,action_pid=None,action_identity=None):
        started=time.monotonic()
        while time.monotonic()-started<5:healthy();time.sleep(.1)
        managed=bus_identity();windows=C.together(clients(),welcome.process.pid,doctor.process.pid,view,action_pid)
        worker=S.worker_identity(doctor_proof['worker_pid'],doctor.process.pid);healthy()
        base.emit('frame_ready',stage=stage,view=view,windows=windows,welcome_pid=welcome.process.pid,
            doctor_pid=doctor.process.pid,worker=worker,doctor_proof_sha256=doctor_sha,
            semantic=semantic,managed_identity=managed,compositor_pid=compositor.process.pid,
            action_identity=action_identity,capture_after_ms=int((time.monotonic()-started)*1000),
            physical_input='NOT_RUN',hardware='NOT_RUN',producer_lifecycle=lock['producer_lifecycle'])
        until=time.monotonic()+8
        while time.monotonic()<until:healthy();time.sleep(.1)
        C.need(bus_identity()==managed,'managed capture identity changed')
        C.together(clients(),welcome.process.pid,doctor.process.pid,view,action_pid)
        S.worker_identity(doctor_proof['worker_pid'],doctor.process.pid);healthy()

    try:
        C.need(not any(p.is_socket() for p in base.RUNTIME.glob('wayland-*')),'stale Wayland socket')
        compositor=L.launch(base,stage,config,logs,env)
        selected=base.ipc(stage,compositor,env,logs)
        monitors=json.loads(command(['/usr/bin/hyprctl','-j','monitors'],'monitors'))
        C.need(len(monitors)==1 and monitors[0].get('width')==1024 and monitors[0].get('height')==768 and monitors[0].get('scale')==1,
               'fixed generic monitor required')
        sockets=[p for p in base.RUNTIME.glob('wayland-*') if p.is_socket()];C.need(len(sockets)==1,'one managed Wayland socket required')
        selected.update(WAYLAND_DISPLAY=sockets[0].name,GDK_BACKEND='wayland',GSETTINGS_BACKEND='memory',HISTFILE='/dev/null',
            XDG_CACHE_HOME=str(workspace/'cache'),XDG_DATA_HOME=str(workspace/'data'),XDG_STATE_HOME=str(workspace/'state'))
        lock=json.loads(C.read(base.SHARE/'candidate-lock.json'))
        C.need(lock['status']=='VERIFIED_NATIVE_CANDIDATES' and lock['eligibility']=='PRIVATE_GUI_TRIAL_ONLY','verified candidates required')
        checkpoint='doctor-startup'
        doctor=base.Logged(['/usr/bin/alacritty','--config-file',str(workspace/'alacritty.toml'),'--class',C.DOCTOR_ID,
            '--title',C.DOCTOR_TITLE,'--working-directory',str(workspace),'--command','/usr/bin/python3','-I','-B',
            str(base.SHARE/'doctor_worker.py'),'--workspace',str(workspace),'--nonce',nonce,'--stage',stage],stage+'-doctor',logs,selected)
        checkpoint='doctor-window'
        place(doctor.process.pid,'doctor',initial=True);C.publish(workspace/'start.json',dict(nonce=nonce,terminal_pid=doctor.process.pid))
        def result():
            path=workspace/'result.json';return json.loads(C.read(path)) if path.exists() else None
        checkpoint='doctor-result';doctor_proof=wait(result,healthy,150,'installed Doctor report')
        checkpoint='doctor-validation'
        C.need(doctor_proof.get('status')=='PASS_INSTALLED_DOCTOR_REPORT','Doctor worker failed: '+str(doctor_proof.get('reason','invalid result'))[:512])
        C.validate_doctor(doctor_proof,stage,nonce,doctor.process.pid)
        checkpoint='doctor-report-file'
        report_path=workspace/'doctor-report.json';report_info=report_path.lstat();report_data=C.read(report_path)
        C.need(stat.S_ISREG(report_info.st_mode) and stat.S_IMODE(report_info.st_mode)==0o600 and report_info.st_uid==23001 and
               C.sha(report_data)==doctor_proof['report_sha256'] and json.loads(report_data)==doctor_proof['doctor'],
               'parent observed Doctor report file differs')
        checkpoint='doctor-worker-identity'
        doctor_sha=C.sha(C.read(workspace/'result.json'));S.worker_identity(doctor_proof['worker_pid'],doctor.process.pid)
        base.emit('doctor_result',stage=stage,proof=doctor_proof,proof_sha256=doctor_sha)
        # Accessibility bus is activated on the real managed user endpoint.
        checkpoint='accessibility-bus'
        address=ast.literal_eval(command(['/usr/bin/gdbus','call','--session','--dest','org.a11y.Bus','--object-path',
            '/org/a11y/bus','--method','org.a11y.Bus.GetAddress'],'accessibility-bus'))
        C.need(type(address) is tuple and len(address)==1 and type(address[0]) is str and
               re.fullmatch(r'unix:path=/run/user/23001/[A-Za-z0-9_./-]+(?:,guid=[0-9a-f]{32})?',address[0]),
               'managed local accessibility address required')
        socket=Path(address[0].split(',',1)[0].removeprefix('unix:path='));info=socket.lstat()
        C.need('..' not in socket.parts and not any(p.is_symlink() for p in socket.parents) and
               stat.S_ISSOCK(info.st_mode) and info.st_uid==23001,'owned accessibility socket required')
        selected['AT_SPI_BUS_ADDRESS']=address[0]
        checkpoint='welcome-gui'
        welcome=base.Logged(['/usr/bin/cachy-asahi-welcome'],stage+'-welcome',logs,selected)
        place(welcome.process.pid,'welcome',initial=True);home=page('home',initial=True);capture('home',home)
        baseline={r.get('pid') for r in clients()};click('Open Terminal')
        def launched_terminal():
            rows=[r for r in clients() if r.get('pid') not in baseline and r.get('class') in ('Alacritty','alacritty') and
                  r.get('mapped') is True and r.get('visible') is True]
            C.need(len(rows)<=1,'ambiguous Welcome-launched terminals');return rows[0] if rows else None
        row=wait(launched_terminal,healthy,60,'Welcome Terminal action');observed=O.ObservedTerminal(row['pid'])
        place(welcome.process.pid,'welcome','welcome-action');place(row['pid'],'terminal','action',initial=True)
        capture('terminal-action',page('terminal-action'),row['pid'],observed.proof)
        target='address:'+C.window(clients(),row['pid'],'terminal')['address']
        C.need(command(['/usr/bin/hyprctl','dispatch',f'hl.dsp.window.close({{window="{target}"}})'],'close-launched-terminal').strip()=='ok',
               'launched terminal close failed')
        observed.wait(15);terminal_identity=observed.proof;observed.close();observed=None
        wait(lambda:True if not any(c.get('pid')==terminal_identity['pid'] and c.get('mapped') for c in clients()) else None,
             healthy,15,'launched terminal window retirement')
        base.emit('welcome_terminal_retired',stage=stage,identity=terminal_identity,absence='PIDFD_EXITED',
                  exit_status='UNOBSERVED_NONCHILD',method='Welcome AT-SPI button; actual Alacritty window')
        private=dict(selected,XDG_CONFIG_HOME=str(workspace/'thunar-config'))
        settings=base.Logged(['/usr/lib/xfce4/xfconf/xfconfd'],stage+'-xfconfd',logs,private)
        def settings_ready():
            text=command(['/usr/bin/gdbus','call','--session','--dest','org.freedesktop.DBus','--object-path','/org/freedesktop/DBus',
                '--method','org.freedesktop.DBus.NameHasOwner','org.xfce.Xfconf'],'xfconf-owner')
            C.need(text.strip() in ('(true,)','(false,)'),'typed xfconf readiness required')
            return True if text.strip()=='(true,)' else None
        wait(settings_ready,healthy,20,'private owned xfconf')
        reply=command(['/usr/bin/gdbus','call','--session','--dest','org.freedesktop.DBus','--object-path','/org/freedesktop/DBus',
            '--method','org.freedesktop.DBus.GetConnectionUnixProcessID','org.xfce.Xfconf'],'xfconf-pid')
        C.need(reply.strip()==f'(uint32 {settings.process.pid},)','owned xfconf D-Bus PID differs')
        thunar=base.Logged(['/usr/bin/thunar','--daemon'],stage+'-thunar',logs,private)
        def thunar_ready():
            text=command(['/usr/bin/gdbus','call','--session','--dest','org.freedesktop.DBus','--object-path','/org/freedesktop/DBus',
                '--method','org.freedesktop.DBus.NameHasOwner','org.xfce.FileManager'],'thunar-owner')
            C.need(text.strip() in ('(true,)','(false,)'),'typed Thunar readiness required')
            return True if text.strip()=='(true,)' else None
        wait(thunar_ready,healthy,30,'owned Thunar bus');C.need(not any(r.get('pid')==thunar.process.pid for r in clients()),'Thunar window must start absent')
        click('Open Files');place(thunar.process.pid,'files','action',initial=True)
        reply=command(['/usr/bin/gdbus','call','--session','--dest','org.freedesktop.DBus','--object-path','/org/freedesktop/DBus',
            '--method','org.freedesktop.DBus.GetConnectionUnixProcessID','org.xfce.FileManager'],'thunar-pid')
        C.need(reply.strip()==f'(uint32 {thunar.process.pid},)','Welcome Files D-Bus owner differs')
        capture('files-action',page('files-action'),thunar.process.pid,dict(pid=thunar.process.pid,bus_owner='PASS',home_uri_intent=base.HOME.as_uri()))
        command(['/usr/bin/thunar','--quit'],'thunar-quit');thunar.process.wait(timeout=15)
        C.need(thunar.process.returncode==0,'unclean Thunar exit');base.terminate(settings.process);settings.finish();settings=None
        retired_files=thunar.process.pid;thunar.finish();thunar=None
        wait(lambda:True if not any(c.get('pid')==retired_files and c.get('mapped') for c in clients()) else None,
             healthy,15,'Files window retirement')
        base.emit('welcome_files_retired',stage=stage,pid=retired_files,exit_status=0,window_absent=True,
                  location_verification='VISUAL_REVIEW_REQUIRED')
        place(welcome.process.pid,'welcome');click('System')
        system_sha=C.sha(command(['/usr/bin/cachy-asahi-welcome','--status'],'welcome-status').encode())
        page('system',system_sha);click('Refresh system status');capture('system',page('system',system_sha))
        click('Welcome');page('home');click('First steps');page('first-steps',guides['first-steps'])
        for view in ('first-steps','updates','recovery'):
            if view!='first-steps':click(C.LABELS[view])
            capture(view,page(view,guides[view]))
        target='address:'+C.window(clients(),welcome.process.pid,'welcome')['address']
        C.need(command(['/usr/bin/hyprctl','dispatch',f'hl.dsp.window.close({{window="{target}"}})'],'close-welcome').strip()=='ok','Welcome close failed')
        welcome.process.wait(timeout=15);C.need(welcome.process.returncode==0,'unclean Welcome exit')
        C.publish(workspace/'release.json',dict(nonce=nonce));doctor.process.wait(timeout=15)
        C.need(doctor.process.returncode==0,'unclean Doctor terminal exit')
        wait(lambda:True if not any(c.get('pid') in (welcome.process.pid,doctor.process.pid) and c.get('mapped')
             for c in clients()) else None,compositor.healthy,15,'Welcome/Doctor window retirement')
        reply=command(['/usr/bin/hyprctl','dispatch','hl.dsp.exit()'],'compositor-exit',timeout=5)
        C.need(reply.strip()=='ok','compositor close failed');compositor.process.wait(timeout=10)
        C.need(compositor.process.returncode==0,'unclean compositor exit')
    except BaseException as error:first=error
    finally:
        if first is None:checkpoint='cleanup'
        if observed:
            try:observed.close()
            except BaseException as error:
                if first is None:first=error
        for actor in (welcome,thunar,settings,doctor,compositor):
            if actor:
                for cleanup in (lambda child=actor:base.terminate(child.process),actor.finish):
                    try:cleanup()
                    except BaseException as error:
                        if first is None:first=error
        try:C.need(C.snapshot(Path(env['XDG_CONFIG_HOME']))==protected,'existing user configuration changed')
        except BaseException as error:
            if first is None:first=error
    if first is not None:
        try:base.emit('welcome_phase_failed',**failure(stage,checkpoint,first,workspace))
        except BaseException:pass  # Diagnostics never replace the first failure or bypass cleanup.
        raise first
    base.emit('phase_pass',stage=stage,welcome_gui='PASS',doctor_report='PASS',guide_navigation='PASS',launch_actions='PASS',
              config_preserved=True,physical_input='NOT_RUN',hardware='NOT_RUN',terminal_action_exit='UNOBSERVED_NONCHILD')
