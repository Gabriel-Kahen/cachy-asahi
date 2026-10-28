# SPDX-License-Identifier: MIT
"""Observe a terminal and Vim reached only through QMP keyboard events."""
import base64
import json
import stat
import os
from pathlib import Path
import time
import keyboard as K
import compositor_log
import terminal_workflow as T
import terminal_session as W
import managed_session as M
from observed import ObservedTerminal,identity
base=None


def input_device(sysfs=Path('/sys/class/input')):
    found=[]
    for event in sysfs.glob('event*'):
        name=(event/'device/name').read_text().strip()
        if name!='QEMU Virtio Keyboard':continue
        device=(event/'device').resolve()
        drivers=[p/'driver' for p in (device,*device.parents) if (p/'driver').is_symlink()]
        K.need(any(p.resolve().name=='virtio_input' for p in drivers),'kernel input is not virtio_input')
        major,minor=map(int,(event/'dev').read_text().strip().split(':'))
        node=Path('/dev/input')/event.name;info=node.stat()
        import stat
        K.need(stat.S_ISCHR(info.st_mode) and info.st_rdev==os.makedev(major,minor),'input event device join differs')
        found.append(dict(name=name,event=event.name,sysfs=str(device),major=major,minor=minor,
                          driver='virtio_input',node=str(node)))
    K.need(len(found)==1,'exactly one QEMU Virtio Keyboard required')
    return found[0]



def board_input(sysfs=Path('/sys/class/input'),devices=Path('/dev/input')):
    """Bounded passive evidence for virt-11.1's separate GPIO power button."""
    def read(path,cap=256):
        with path.open('rb') as stream:raw=stream.read(cap+1)
        K.need(len(raw)<=cap,'board sysfs byte limit');return raw
    found=[];events=list(sysfs.glob('event*'))
    K.need(len(events)<=8,'board input enumeration limit')
    for event in events:
        device=(event/'device').resolve()
        if read(device/'name',64).decode().strip()!='gpio-keys':continue
        platform=device.parent.parent
        K.need((platform/'driver').resolve()==Path('/sys/bus/platform/drivers/gpio-keys'),
               'board input platform driver differs')
        of_node=(platform/'of_node').resolve()
        major,minor=map(int,read(event/'dev',32).decode().strip().split(':'))
        node=devices/event.name;info=node.stat()
        import stat
        K.need(stat.S_ISCHR(info.st_mode) and info.st_rdev==os.makedev(major,minor),'board event device differs')
        found.append(dict(name='gpio-keys',event=event.name,node='/dev/input/'+event.name,
            sysfs=str(device),driver='gpio-keys',major=major,minor=minor,
            bus_type=int(read(device/'id/bustype',16).decode().strip(),16),
            of_node=str(of_node),compatible_hex=read(of_node/'compatible',64).hex(),
            poweroff_linux_code_hex=read(of_node/'poweroff/linux,code',4).hex(),
            key_bitmap=read(device/'capabilities/key').decode().strip()))
    K.need(len(found)==1,'exactly one board GPIO input required')
    K.verify_keyboards([dict(name='qemu-virtio-keyboard',layout='us',capsLock=False),
                       dict(name='gpio-keys',layout='us',capsLock=False)],found[0])
    return found[0]


def descendant(pid,parent,executable):
    proof=identity(pid)
    fields=dict(line.split(':',1) for line in Path('/proc',str(pid),'status').read_text().splitlines() if ':' in line)
    K.need(proof['uid']==[23001]*4 and proof['executable']==executable and int(fields['PPid'])==parent,
           'terminal descendant UID/executable/parent differs')
    return proof|dict(parent_pid=parent)


def child(parent,executable):
    raw=Path('/proc',str(parent),'task',str(parent),'children').read_text()
    rows=[]
    for value in raw.split():
        try:
            if identity(int(value))['executable']==executable:rows.append(descendant(int(value),parent,executable))
        except FileNotFoundError:continue
    K.need(len(rows)<=1,'ambiguous owned child')
    return rows[0] if rows else None




def startup_clients(rows,compositor_pid):
    """Join setup surfaces to the owned process before admitting any input."""
    K.need(type(rows) is list and len(rows)<=2 and all(type(r) is dict for r in rows),'bounded startup client list required')
    compositor=descendant(compositor_pid,os.getpid(),'/usr/bin/Hyprland')
    owner=None
    if rows:
        pid=rows[0].get('pid')
        K.need(type(pid) is int and 0<pid<2**32,'startup owner PID required')
        owner=compositor if pid==compositor_pid else descendant(pid,compositor_pid,'/usr/bin/Xwayland')
    proof=dict(compositor=compositor,owner=owner,records=rows)
    K.verify_startup(proof);return proof



def shell_cwd(process):
    """Passive identity-checked cwd observation, never a chdir or PTY operation."""
    if process is None:return dict(status='UNAVAILABLE',reason='NO_OWNED_SHELL')
    try:
        process.healthy()
        value=os.readlink(Path('/proc',str(process.proof['pid']),'cwd'))
        process.healthy()
        K.need(value.startswith('/') and len(value)<=512,'bounded absolute shell cwd required')
        return dict(status='READ',path=value)
    except BaseException as error:return dict(status='UNAVAILABLE',reason=type(error).__name__)


def failure_files(workspace):
    """Only the three known nonce-workspace leaves; no enumeration or PTY read."""
    rows={}
    for name in ('shell.txt','edit.txt','result.txt'):
        path=workspace/name
        try:
            info=path.lstat()
            row=dict(bytes=info.st_size,uid=info.st_uid,mode=stat.S_IMODE(info.st_mode),links=info.st_nlink)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=23001 or info.st_nlink!=1:
                row['status']='UNSAFE_NOT_READ'
            elif info.st_size>1024:row['status']='OVERSIZED_NOT_READ'
            else:
                raw=T.read(path,1024)
                row.update(status='READ',sha256=K.sha(raw),prefix_bytes=min(len(raw),256),
                           prefix_base64=base64.b64encode(raw[:256]).decode())
            rows[name]=row
        except FileNotFoundError:rows[name]=dict(status='ABSENT')
        except BaseException as error:rows[name]=dict(status='READ_ERROR',error=type(error).__name__)
    return rows


def phase(stage,config,env,logs):
    nonce=os.urandom(16).hex();workspace=base.HOME/('keyboard-'+stage+'-'+nonce)
    workspace.mkdir(mode=0o700);before=T.snapshot(Path(env['XDG_CONFIG_HOME']))
    compositor=terminal=shell_process=editor_process=None;selected=None;sequence=0;first=None;last_step=None
    W.base=base
    def command(argv,label,timeout=20):
        nonlocal sequence
        sequence+=1
        return base.command(argv,selected,logs,stage+'-keyboard-'+str(sequence)+'-'+label,timeout=timeout)
    def healthy():
        compositor.healthy()
        if terminal:terminal.healthy()
    def wait(probe,description,seconds=120):return W.wait(probe,healthy,seconds,description)
    def clients(initial=False):
        nonlocal sequence
        if initial:
            sequence+=1
            return W.startup_clients(selected,logs,stage+'-keyboard-'+str(sequence)+'-initial')
        return json.loads(command(['/usr/bin/hyprctl','-j','clients','-a'],'clients'))
    def window(initial=False):
        rows=clients(initial)
        if rows is None:return None
        rows=[r for r in rows if r.get('mapped') is True and r.get('visible') is True]
        K.need(len(rows)<=1,'unexpected extra mapped window')
        if not rows:return None
        r=rows[0]
        K.need(r.get('class') in ('Alacritty','alacritty') and r.get('hidden') is False and r.get('xwayland') is False,
               'shortcut did not launch native Alacritty')
        K.need(type(r.get('pid')) is int and r['pid']>0,'terminal PID absent')
        K.need(r.get('focusHistoryID')==0,'typed terminal is not focused')
        at,size=r.get('at'),r.get('size')
        K.need(type(at) is list and type(size) is list and len(at)==len(size)==2 and
               all(type(v) is int for v in at+size) and size[0]>=640 and size[1]>=400 and
               min(at)>=0 and at[0]+size[0]<=1024 and at[1]+size[1]<=768,'terminal clipped/too small')
        if terminal:K.need(r['pid']==terminal.proof['pid'],'terminal PID changed')
        return r
    def request(step):
        nonlocal last_step
        last_step=step
        if step!='launch':K.need(window() is not None,'focused terminal missing before input')
        base.emit('keyboard_request',stage=stage,nonce=nonce,step=step,plan_sha256=K.sha(K.encoded(K.plan(stage,nonce,step))))
    def file_ready(name):
        p=workspace/name
        if not p.exists():return None
        data=T.read(p,1024)
        # Do not accept intermediate tee/Vim writes; only exact completed bytes qualify.
        K.need(p.stat().st_uid==23001 and p.stat().st_nlink==1,'typed output ownership differs')
        return dict(name=name,bytes=len(data),sha256=K.sha(data)) if data==K.expected(nonce)[name] else None
    def frame(view,proof):
        start=time.monotonic()
        while time.monotonic()-start<5:healthy();time.sleep(.1)
        current=window();K.need(current is not None,'terminal disappeared before capture')
        bus=M.bus_probe(lambda argv:command(argv,'managed-bus'),int(os.environ['CACHY_MANAGED_MANAGER_PID']))
        base.emit('frame_ready',stage=stage+'-'+view,phase=stage,view=view,nonce=nonce,
                  terminal=current,terminal_identity=terminal.proof,proof=proof,managed_bus=bus,
                  capture_after_ms=int((time.monotonic()-start)*1000),physical_input='NOT_RUN',hardware='NOT_RUN')
        until=time.monotonic()+8
        while time.monotonic()<until:healthy();time.sleep(.1)
        K.need(window() is not None,'terminal disappeared after capture')
        M.bus_probe(lambda argv:command(argv,'managed-bus'),int(os.environ['CACHY_MANAGED_MANAGER_PID']))
    try:
        K.need(not any(p.is_socket() for p in base.RUNTIME.glob('wayland-*')),'stale Wayland socket')
        device=input_device()
        compositor=compositor_log.launch(base,stage,config,logs,env)
        selected=base.ipc(stage,compositor,env,logs)
        sockets=[p for p in base.RUNTIME.glob('wayland-*') if p.is_socket()]
        K.need(len(sockets)==1,'one managed Wayland socket required');selected['WAYLAND_DISPLAY']=sockets[0].name
        monitors=json.loads(command(['/usr/bin/hyprctl','-j','monitors'],'monitors'))
        K.need(len(monitors)==1 and monitors[0].get('width')==1024 and monitors[0].get('height')==768 and monitors[0].get('scale')==1,'fixed monitor required')
        devices=json.loads(command(['/usr/bin/hyprctl','-j','devices'],'devices'))
        keyboards=devices.get('keyboards',[])
        K.need(type(keyboards) is list and all(type(k) is dict for k in keyboards),'typed keyboard rows required')
        board=board_input() if any(k.get('name')=='gpio-keys' for k in keyboards) else None
        K.verify_keyboards(keyboards,board)
        initial=wait(lambda:clients(initial=True),'initial clients snapshot',90)
        startup=startup_clients(initial,compositor.process.pid)
        base.emit('keyboard_ready',stage=stage,nonce=nonce,kernel_device=device,keyboards=keyboards,board_device=board,monitors=monitors,startup_windows=startup,
                  shortcut_policy='SHIPPED_UNCHANGED' if stage=='overlay' else 'DECLARED_MINIMAL_SUPER_RETURN_SUPER_Q',
                  user_configuration_sha256=K.sha(K.encoded(before)),configuration_sha256=K.sha(T.read(config)))
        request('launch')
        row=wait(lambda:window(initial=True),'shortcut terminal mapping',90)
        terminal=ObservedTerminal(row['pid'])
        shell=wait(lambda:child(row['pid'],'/usr/bin/bash'),'terminal bash child')
        tty=os.readlink(Path('/proc',str(shell['pid']),'fd/0'))
        K.need(tty.startswith('/dev/pts/') and tty.removeprefix('/dev/pts/').isdecimal(),'real terminal shell PTY required')
        shell.update(pty=tty)
        shell_process=ObservedTerminal(shell['pid'],'/usr/bin/bash')
        started=time.monotonic()
        until=started+K.DELIVERY_POLICY['initial_settle_ms']/1000
        while time.monotonic()<until:healthy();shell_process.healthy();time.sleep(.1)
        K.need(window() is not None,'focused terminal missing after initial settle')
        base.emit('keyboard_terminal',stage=stage,nonce=nonce,terminal=terminal.proof,shell=shell,window=row,
                  initial_settle_ms=int((time.monotonic()-started)*1000))
        request('workspace')
        def workspace_ready():
            value=shell_cwd(shell_process)
            return value if value==dict(status='READ',path=str(workspace)) else None
        cwd=wait(workspace_ready,'typed workspace cd')
        base.emit('keyboard_workspace',stage=stage,nonce=nonce,shell=shell,cwd=cwd,method='passive-proc-cwd')
        request('shell');shell_file=wait(lambda:file_ready('shell.txt'),'typed shell output')
        frame('shell',dict(shell=shell,file=shell_file))
        request('editor-open');editor=wait(lambda:child(shell['pid'],'/usr/bin/vim'),'interactive Vim child')
        editor_process=ObservedTerminal(editor['pid'],'/usr/bin/vim')
        # Child existence precedes Vim input readiness. Keep the real child alive during settle.
        until=time.monotonic()+3
        while time.monotonic()<until:healthy();K.need(descendant(editor['pid'],shell['pid'],'/usr/bin/vim')==editor,'Vim child changed');time.sleep(.1)
        request('editor-type');time.sleep(3);healthy();request('editor-save')
        edited=wait(lambda:file_ready('edit.txt'),'Vim typed and saved bytes')
        K.need(descendant(editor['pid'],shell['pid'],'/usr/bin/vim')==editor,'Vim retired before capture')
        frame('editor',dict(shell=shell,editor=editor,file=edited))
        request('editor-quit');editor_process.wait(20)
        base.emit('keyboard_editor_closed',stage=stage,nonce=nonce,editor=editor,pidfd_exited=True,exit='UNOBSERVED_NONCHILD')
        wait(lambda:True if child(shell['pid'],'/usr/bin/vim') is None else None,'Vim quit through keyboard')
        request('result');result=wait(lambda:file_ready('result.txt'),'typed result command output')
        frame('result',dict(shell=shell,files=[shell_file,edited,result]))
        request('close');terminal.wait(20);shell_process.wait(20)
        # healthy() deliberately cannot run once shortcut retirement is expected.
        W.wait(lambda:True if not any(c.get('pid')==row['pid'] and (c.get('mapped') or c.get('visible')) for c in clients()) else None,
               compositor.healthy,20,'shortcut window retirement')
        base.emit('keyboard_closed',stage=stage,nonce=nonce,terminal=terminal.proof,exit='UNOBSERVED_NONCHILD',
                  pidfd_exited=True,shell=shell,shell_pidfd_exited=True,window_absent=True,method='SUPER_Q_QMP')
        reply=command(['/usr/bin/hyprctl','dispatch','hl.dsp.exit()'],'exit',timeout=5)
        K.need(reply.strip()=='ok','compositor exit reply differs');compositor.process.wait(timeout=10)
        K.need(compositor.process.returncode==0,'unclean compositor exit')
    except BaseException as error:
        first=error
        try:
            capture=bool(terminal and compositor and compositor.process.poll() is None)
            base.emit('keyboard_failure_diagnostic',stage=stage,nonce=nonce,last_step=last_step,
                      reason=str(first)[:256],files=failure_files(workspace),shell_cwd=shell_cwd(shell_process),capture_requested=capture,
                      diagnostic_only=True,success_evidence=False)
            if capture:
                # Host observes this event before phase_failed and can capture the still-owned terminal.
                until=time.monotonic()+8
                while time.monotonic()<until:time.sleep(.1)
        except BaseException:
            pass  # The original workflow failure stays primary even if diagnostics fail.
    finally:
        for process in (editor_process,shell_process,terminal):
            if process:
                try:process.close()
                except BaseException as error:
                    if first is None:first=error
        if compositor:
            for cleanup in (lambda:base.terminate(compositor.process),compositor.finish):
                try:cleanup()
                except BaseException as error:
                    if first is None:first=error
        try:K.need(T.snapshot(Path(env['XDG_CONFIG_HOME']))==before,'user configuration changed')
        except BaseException as error:
            if first is None:first=error
    if first is not None:
        base.emit('phase_failed',stage=stage,error=type(first).__name__,detail=str(first)[:256]);raise first
    base.emit('phase_pass',stage=stage,nonce=nonce,configuration_preserved=True,virtual_keyboard='PASS',
              physical_input='NOT_RUN',hardware='NOT_RUN')
