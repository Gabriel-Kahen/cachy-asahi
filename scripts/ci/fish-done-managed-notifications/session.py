# SPDX-License-Identifier: MIT
"""Real installed Done -> notify-send -> managed bus -> normal Mako, two foreground cases and one watched job."""
import base64,hashlib,json,os,re,signal,stat,subprocess,time
from pathlib import Path
import bar_helpers as B
import managed_session as managed
import observation as O
import fish_terminal
import monitor
import installed

base=None
MAKO_NAMESPACE=B.MAKO_NAMESPACE


def trace_requested(words):
    O.need(B.TRACE_MARKER not in words.split(),'logging-enabled startup is outside this lane');return False


def trace_command(argv,enabled=False):
    O.need(enabled is False,'ordinary startup required');return list(argv)


def startup_layers(api,env,logs,name):
    """Only retired startup IPC timeouts become not-ready; no post-Notify retries."""
    logged=api.Logged(['/usr/bin/hyprctl','-j','layers'],name,logs,env)
    first=None;cleanup_ok=True
    try:logged.process.wait(timeout=7)
    except BaseException as error:first=error
    finally:
        for cleanup in (lambda:api.terminate(logged.process),logged.finish):
            try:cleanup()
            except BaseException as error:
                cleanup_ok=False
                if first is None:first=error
    if first is not None:
        if not (cleanup_ok and isinstance(first,subprocess.TimeoutExpired)):raise first
        reason='BOUNDED_STARTUP_PROBE_WAIT_TIMEOUT'
    else:
        out,err=(path.read_bytes() for path in logged.paths)
        if logged.process.returncode==0:return json.loads(out)
        O.need(logged.process.returncode==6 and
            out==b"Hyprland IPC didn't respond in time\n\nCouldn't read (6)\n" and not err,
            'command failed: '+name)
        reason='EXACT_HYPRCTL_IPC_READ_TIMEOUT_6'
    api.emit('startup_layers_retry',name=name,reason=reason,returncode=logged.process.returncode,
             probe_retired=True,budget='EXISTING_30_SECOND_PRETRIGGER_READINESS')
    return None


def normal_compositor_output(logged):
    """Retain already-captured normal output; enable no new service logging."""
    streams=[]
    for path in logged.paths:
        raw=path.read_bytes();O.need(len(raw)<=256*1024,'existing compositor output cap')
        streams.append(dict(path=str(path),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),raw_base64=base64.b64encode(raw).decode()))
    return dict(scope='DIAGNOSTIC_ONLY_EXISTING_NORMAL_UNLOGGED_OUTPUT',streams=streams)



def protocol_environment(selected,enabled=False):
    # One causal probe only: change the existing owned Mako client, no others.
    O.need('WAYLAND_DEBUG' not in selected,'ambient Wayland trace refused')
    O.need(type(enabled) is bool,'explicit boolean protocol probe required')
    return dict(selected,WAYLAND_DEBUG='client') if enabled else dict(selected)


def stopped_protocol_trace(logged):
    # Called after the original finally has reaped the process and joined drains.
    O.need(logged.process.poll()==0,'protocol trace requires normal owned Mako exit')
    streams=[]
    for path in logged.paths:
        info=path.lstat()
        O.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.geteuid() and
               info.st_size<=256*1024,'bounded ordinary owned existing Mako log required')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as stream:
            held=os.fstat(stream.fileno())
            O.need((held.st_dev,held.st_ino)==(info.st_dev,info.st_ino),'held protocol log differs')
            raw=stream.read(256*1024+1)
        after=path.lstat()
        O.need((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==
               (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and len(raw)==info.st_size,
               'retired Mako log changed')
        streams.append(dict(path=str(path),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),raw_base64=base64.b64encode(raw).decode()))
    return dict(scope='DIAGNOSTIC_ONLY_CLIENT_PROTOCOL_NOT_PRESENTATION',pid=logged.process.pid,exit=logged.process.returncode,
                environment=dict(WAYLAND_DEBUG='client'),streams=streams,acceptance='FORBIDDEN_FOR_THIS_PROBE')


def phase(stage,config,env,logs,**options):
    O.need(options.get('trace_waybar',False) is False and stage in O.CASES,'fixed ordinary Done phase required')
    B.base=base;first=None;compositor=bar=mako=terminal=observer=None;selected=None;sequence=0
    protocol_probe=O.diagnostic_policy()['mako_wayland_protocol_probe']
    before=B.snapshot(Path(env['XDG_CONFIG_HOME']));case,outcome=O.CASES[stage]
    kind='Watched job' if stage=='background' else 'Foreground command'
    def command(argv,label='query',timeout=7):
        nonlocal sequence
        sequence+=1;return base.command(argv,selected,logs,stage+'-done-'+str(sequence)+'-'+label,timeout=timeout)
    def dbus(destination,path,interface,method,*args):
        return command(B.BUS+[destination,path,interface,method,*args],'dbus')
    def bus(method,*args):return dbus('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus',method,*args)
    def healthy():
        for item in (compositor,bar,mako):
            if item is not None:item.healthy()
        if terminal is not None:
            O.need(terminal.process.poll() is None,'Fish exited before captured continuation');terminal.pump()
        if observer is not None:observer.rows()
    def identity():
        O.need(selected.get('DBUS_SESSION_BUS_ADDRESS')==managed.ADDRESS and selected.get('XDG_RUNTIME_DIR')==str(managed.RUNTIME),'real managed endpoint required')
        pid=os.environ.get('CACHY_MANAGED_MANAGER_PID','');O.need(re.fullmatch('[1-9][0-9]{0,9}',pid),'root-joined manager absent')
        return managed.bus_probe(lambda a:command(a,'manager'),int(pid))
    def layers(startup=False):
        nonlocal sequence
        if not startup:return json.loads(command(['/usr/bin/hyprctl','-j','layers'],'layers'))
        sequence+=1
        return startup_layers(base,selected,logs,stage+'-done-'+str(sequence)+'-layers')
    def owner_pid():return B.uint_reply(bus('GetConnectionUnixProcessID','s','org.freedesktop.Notifications'))
    def notices():return json.loads(command(['/usr/bin/makoctl','list','-j'],'mako-list'))
    try:
        O.need(not any(p.is_socket() for p in base.RUNTIME.glob('wayland-*')),'stale Wayland socket')
        compositor=base.Logged(['/usr/bin/Hyprland','--config',str(config)],stage,logs,env)
        selected=base.ipc(stage,compositor,env,logs);O.need('G_DBUS_DEBUG' not in selected,'normal unlogged startup required')
        managed_identity=identity();monitors=json.loads(command(['/usr/bin/hyprctl','-j','monitors'],'monitors'))
        O.need(base.usable_monitors(monitors) and len(monitors)==1 and (monitors[0]['width'],monitors[0]['height'],monitors[0].get('scale'))==(1024,768,1),'fixed generic monitor required')
        sockets=[p for p in base.RUNTIME.glob('wayland-*') if p.is_socket()];O.need(len(sockets)==1,'one owned Wayland socket required')
        selected.update(WAYLAND_DISPLAY=sockets[0].name,XDG_SESSION_TYPE='wayland',XDG_CURRENT_DESKTOP='Hyprland')
        activation=B.activate_environment(command,dbus,selected,managed_identity['manager_pid'])
        O.need(identity()==managed_identity and bus('NameHasOwner','s','org.freedesktop.Notifications').strip()=='b false','fresh owned managed notification service required')
        payload=installed.verify(lambda a:command(a,'installed'))
        bar=base.Logged(['/usr/bin/waybar','--config',str(B.TEMPLATES/'waybar.json'),'--style',str(B.TEMPLATES/'waybar.css')],stage+'-waybar',logs,B.waybar_environment(selected,False))
        if protocol_probe:base.emit('mako_wayland_protocol_probe',stage=stage,scope='DIAGNOSTIC_ONLY_NOT_NORMAL_STARTUP',acceptance='FORBIDDEN_FOR_THIS_PROBE')
        mako=base.Logged(['/usr/bin/mako','--config',str(B.TEMPLATES/'mako.conf')],stage+'-mako',logs,protocol_environment(selected,protocol_probe))
        def ready():
            answer=bus('NameHasOwner','s','org.freedesktop.Notifications').strip()
            O.need(answer in ('b false','b true'),'typed owner reply required')
            if answer=='b false':return None
            O.need(owner_pid()==mako.process.pid,'foreign notification owner')
            display=layers(startup=True)
            return B.owned_layer(display,'waybar',bar.process.pid) if display is not None else None
        B.wait_ready(ready,healthy,30,'normal bar/Mako readiness')
        O.need(notices()==[],'preexisting notification')
        owner_reply=bus('GetNameOwner','s','org.freedesktop.Notifications').strip();O.need(owner_reply.startswith('s '),'typed service owner required')
        owner=json.loads(owner_reply[2:]);O.need(re.fullmatch(r':[0-9]+\.[0-9]+',owner),'unique Mako recipient required')
        recipient=dict(service='org.freedesktop.Notifications',unique=owner,pid=owner_pid(),owner_reply=owner_reply)
        O.need(recipient['pid']==mako.process.pid,'actual recipient process differs')
        settled=time.monotonic()
        while time.monotonic()-settled<5:healthy();time.sleep(.1)
        O.need(identity()==managed_identity,'managed endpoint changed before trigger')
        observer=monitor.Monitor(selected)
        deadline=time.monotonic()+5
        while True:
            dbus('org.freedesktop.Notifications','/org/freedesktop/Notifications','org.freedesktop.Notifications','GetCapabilities')
            if any(r.get('member')=='GetCapabilities' for r in observer.rows()):break
            O.need(time.monotonic()<deadline,'real bus observer readiness');healthy();time.sleep(.1)
        O.need(O.notify(observer.rows(),owner,outcome,kind) is None,'unsolicited Done notification')
        terminal=(fish_terminal.BackgroundTerminal if stage=='background' else fish_terminal.Terminal)(selected);fish_pid=terminal.process.pid
        O.need(os.readlink('/proc/'+str(fish_pid)+'/exe')=='/usr/bin/fish','actual Fish executable differs')
        terminal.start(outcome);wire=None
        wait_started_ns=time.monotonic_ns();wait_cpu_started_ns=time.thread_time_ns();wait_iterations=0
        max_wait_step_wall_ns=max_wait_step_cpu_ns=last_wait_step_wall_ns=last_wait_step_cpu_ns=0
        deadline=time.monotonic()+15
        while wire is None:
            wait_iterations+=1;step_wall=time.monotonic_ns();step_cpu=time.thread_time_ns()
            healthy();wire=O.notify(observer.rows(),owner,outcome,kind)
            last_wait_step_wall_ns=time.monotonic_ns()-step_wall;last_wait_step_cpu_ns=time.thread_time_ns()-step_cpu
            max_wait_step_wall_ns=max(max_wait_step_wall_ns,last_wait_step_wall_ns);max_wait_step_cpu_ns=max(max_wait_step_cpu_ns,last_wait_step_cpu_ns)
            O.need(time.monotonic()<deadline,'real Done delivery deadline')
        delivery_wait=dict(scope='DIAGNOSTIC_ONLY_GUEST_PYTHON_MAIN_THREAD',iterations=wait_iterations,
                           wall_ns=time.monotonic_ns()-wait_started_ns,cpu_ns=time.thread_time_ns()-wait_cpu_started_ns,
                           max_step_wall_ns=max_wait_step_wall_ns,max_step_cpu_ns=max_wait_step_cpu_ns,
                           last_step_wall_ns=last_wait_step_wall_ns,last_step_cpu_ns=last_wait_step_cpu_ns)
        # Request immediately after real Notify/reply. Fresh visibility queries
        # follow emission; no host-capture acknowledgement is invented.
        timing=O.capture_timing_facts(wire,time.time_ns()//1000,time.monotonic_ns())
        request=dict(stage=stage,case=case,outcome=outcome,monitors=monitors,
            capture_after_ms=int((time.monotonic()-settled)*1000),notification_age_ms=timing['age_ms'],
            timing=timing,caller_pending=True,
            waybar_pid=bar.process.pid,mako_pid=mako.process.pid,compositor_pid=compositor.process.pid,
            fish_pid=fish_pid,managed_identity=managed_identity,activation='normal-shipped-config-no-reload',
            activation_environment=activation,notification_timeout_ms=3000,trace_waybar=False,
            wire=wire,recipient=recipient,installed=payload)
        base.emit('frame_ready',**request)
        request_sha=hashlib.sha256(json.dumps(dict(event='frame_ready',**request),sort_keys=True,separators=(',',':')).encode()).hexdigest()
        # This is after request emission, not a claimed host-capture ACK.
        visibility_queries=[];visibility_attempts=0
        def visible():
            nonlocal visibility_attempts
            visibility_attempts+=1
            clocks=dict(start_realtime_us=time.time_ns()//1000,start_monotonic_ns=time.monotonic_ns())
            row=O.listing(notices(),wire)
            clocks.update(list_return_realtime_us=time.time_ns()//1000,list_return_monotonic_ns=time.monotonic_ns())
            display=layers()
            clocks.update(layers_return_realtime_us=time.time_ns()//1000,layers_return_monotonic_ns=time.monotonic_ns())
            if len(visibility_queries)<16:visibility_queries.append(clocks)
            a=B.owned_layer(display,'waybar',bar.process.pid);b=B.owned_layer(display,B.MAKO_NAMESPACE,mako.process.pid)
            return dict(bar=a,mako=b,notification=row) if row and a and b else None
        current=B.wait_ready(visible,healthy,2,'Done natural-expiry visible notification')
        visibility=dict(current,request_sha256=request_sha,realtime_us=time.time_ns()//1000,monotonic_ns=time.monotonic_ns())
        base.emit('frame_visibility',stage=stage,case=case,wire=wire,visibility=visibility,capture_request_sha256=request_sha,managed_identity=managed_identity)
        continuation=terminal.continuation(outcome)
        O.need(owner_pid()==mako.process.pid,'recipient owner changed')
        post_identity=identity();O.need(post_identity==managed_identity,'managed endpoint changed')
        # Preserve the original first observation while allowing its natural
        # three-second expiry. No replacement screenshot or TTL override.
        until=time.monotonic()+3.5
        while time.monotonic()<until:healthy();time.sleep(.1)
        fish_result=terminal.finish();terminal.close();terminal=None
        monitor_result=observer.finish();observer.close();observer=None
        for row in notices():
            O.need(row.get('id')==wire['id'],'foreign retained notice')
            dbus('org.freedesktop.Notifications','/org/freedesktop/Notifications','org.freedesktop.Notifications','CloseNotification','u',str(wire['id']))
        O.need(installed.verify(lambda a:command(a,'installed-after'))==payload,'installed payload changed')
        B.clean_stop(bar,signal.SIGINT);B.clean_stop(mako,signal.SIGTERM)
        O.need(bus('NameHasOwner','s','org.freedesktop.Notifications').strip()=='b false','notification service survived owned stop')
        O.need(command(['/usr/bin/hyprctl','dispatch','hl.dsp.exit()'],'exit',5).strip()=='ok','compositor exit differs')
        compositor.process.wait(timeout=10);O.need(compositor.process.returncode==0,'normal compositor exit required')
    except BaseException as error:
        first=error
        try:
            base.emit('done_failure',stage=stage,case=case,error_type=type(error).__name__,reason=str(error)[:512],
                fish_pty_base64=base64.b64encode(bytes(terminal.output)).decode() if terminal is not None else None,
                bus_stdout_base64=base64.b64encode(bytes(observer.parts[0])).decode() if observer is not None else None,
                bus_stderr_base64=base64.b64encode(bytes(observer.parts[1])).decode() if observer is not None else None)
        except BaseException:pass
    finally:
        for item in (terminal,observer):
            if item is not None:
                try:item.close()
                except BaseException as error:
                    if first is None:first=error
        for logged in (mako,bar,compositor):
            if logged is not None:
                for cleanup in (lambda p=logged:base.terminate(p.process),lambda p=logged:p.finish()):
                    try:cleanup()
                    except BaseException as error:
                        if first is None:first=error
        try:O.need(B.snapshot(Path(env['XDG_CONFIG_HOME']))==before,'user configuration changed')
        except BaseException as error:
            if first is None:first=error
    if protocol_probe and mako is not None:
        try:base.emit('mako_wayland_protocol_trace',stage=stage,trace=stopped_protocol_trace(mako))
        except BaseException as error:
            if first is None:first=error
    if first is not None:raise first
    diagnostics=dict(scope='DIAGNOSTIC_ONLY_NO_PRESENTATION_OR_ACCEPTANCE_CREDIT',delivery_wait=delivery_wait,
                     visibility_queries=dict(attempts=visibility_attempts,clocks=visibility_queries,truncated=visibility_attempts>len(visibility_queries)),
                     notification_closed=O.closure_facts(base64.b64decode(monitor_result['raw_base64']),wire),
                     compositor_output=normal_compositor_output(compositor))
    base.emit('done_transport',stage=stage,case=case,wire=wire,diagnostics=diagnostics,monitor=monitor_result,fish=fish_result,caller=continuation,visibility=visibility,capture_request_sha256=request_sha,post_request_identity=post_identity,mako_exit=mako.process.returncode,payload_preserved=True,user_config_preserved=True)
    base.emit('phase_pass',stage=stage,waybar='PASS',mako='PASS',fish='PASS',case=case,config_preserved=True)
