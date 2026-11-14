#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One owned no-capability NM daemon/private SYSTEM bus software test."""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import signal
import socket
import stat
import subprocess
import time
import traceback

INPUT=Path('/opt/nm-private-bus')
OUT=Path('/out')
BUS='unix:path=/run/dbus/system_bus_socket'
UUID='e3140000-0000-4000-8000-000000000001'
IFACE='cachy-test0'
WRITABLE={'/run','/var/lib/NetworkManager','/etc/NetworkManager','/home/TEST','/tmp','/out'}
CONFIG=b'''[main]\nplugins=keyfile\nno-auto-default=*\ndns=none\nrc-manager=unmanaged\nhostname-mode=none\n[device-TEST]\nmatch-device=*\nmanaged=0\n[connectivity]\nenabled=false\n[logging]\nbackend=syslog\nlevel=INFO\n'''
USER=b'# TEST user configuration sentinel; must survive profile CRUD and restart\n'


def load(name):
    s=importlib.util.spec_from_file_location('private_bus_'+name,INPUT/(name+'.py'))
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def clean_env(caller):
    # No caller DBUS/G_BUS, loader, proxy, HOME or XDG value is inherited.
    return {'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8','HOME':'/home/TEST','XDG_CONFIG_HOME':'/home/TEST/config',
            'XDG_CACHE_HOME':'/home/TEST/cache','XDG_DATA_HOME':'/home/TEST/data','XDG_RUNTIME_DIR':'/run/user-TEST',
            'DBUS_SYSTEM_BUS_ADDRESS':BUS,'DBUS_SESSION_BUS_ADDRESS':BUS,'DBUS_STARTER_ADDRESS':BUS,'DBUS_STARTER_BUS_TYPE':'system'}


def main():
    p=argparse.ArgumentParser();p.add_argument('--allow-owned-private-system-bus',action='store_true');a=p.parse_args()
    if not a.allow_owned_private_system_bus or not __debug__:p.error('explicit opt-in/non-optimized Python required')
    if not(os.geteuid()==0 and platform.machine()=='x86_64'and Path('/.dockerenv').is_file()and os.environ.get('CACHY_ASAHI_PRIVATE_BUS_TEST')=='1'):
        p.error('exact disposable x86 container required')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(2*1024**2,2*1024**2))
    O=load('owned_process');R=load('repository');report={'schema_version':1,'status':'HOLD','scope':'x86 private daemon/settings software only','commands':[],'retirement':[],'native_ARM':'NOT RUN','M2':'NOT RUN','real_connectivity':'NOT RUN','suspend':'NOT RUN','release_acceptance':'HOLD'}
    children={};logs=[];counts={};env=clean_env(os.environ);deadline=time.monotonic()+120
    def call(label,argv,probe=False):
        remaining=deadline-time.monotonic()
        if remaining<=2:raise TimeoutError('120-second private daemon action deadline')
        O.prepare();child=subprocess.Popen([str(x)for x in argv],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        result=O.supervise(child,cap=min(8,remaining),retirement=1,grace=.2,max_output=1024**2)
        data=result.pop('output');path=OUT/(str(len(report['commands']))+'-'+label+'.log');path.write_bytes(data)
        report['commands'].append({'name':label,'argv':[str(x)for x in argv],'result':result,'log':path.name,'sha256':hashlib.sha256(data).hexdigest()})
        if not probe:assert result['passed'],(label,result)
        else:assert result['reaped']and not result['timeout']and result['error']is None,(label,result)
        return result['exit'],data.decode(errors='replace').strip()
    def start(role,argv):
        assert time.monotonic()<deadline
        counts[role]=counts.get(role,0)+1
        O.prepare();log=(OUT/(role+'-'+str(counts[role])+'.log')).open('wb');logs.append(log)
        children[role]=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    def retire(role):
        child=children.pop(role)
        # Exclusive, unreaped child retains PID custody across this normal TERM.
        terminal=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)
        if terminal is None:os.kill(child.pid,signal.SIGTERM)
        result=O.supervise(child,cap=8,retirement=2,grace=.25);result.pop('output')
        report['retirement'].append({'role':role,'normal_TERM_requested':terminal is None,'result':result})
        assert result['passed'],(role,result)
    def ready():
        until=min(deadline,time.monotonic()+15)
        while time.monotonic()<until:
            code,text=call('readiness',['nmcli','-g','RUNNING','general'],probe=True)
            if code==0 and text=='running':return
            terminal=os.waitid(os.P_PID,children['nm'].pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)
            assert terminal is None,('NetworkManager exited before readiness',terminal.si_status)
            time.sleep(.1)
        raise TimeoutError('private NM readiness')
    def daemon():
        start('nm',['/usr/bin/NetworkManager','--debug','--no-daemon','--config','/etc/NetworkManager/NetworkManager.conf','--pid-file','/run/NetworkManager/TEST.pid'])
        ready()
    try:
        caps=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if ':'in line)
        assert all(int(caps[k].strip(),16)==0 for k in R.CAP_FIELDS)and caps['NoNewPrivs'].strip()=='1'
        mounts=R.mounts(Path('/proc/self/mountinfo').read_text());assert 'ro'in mounts['/']['options']
        allowed={'/'}|set(R.STANDARD_MOUNTS)|R.RUNTIME_FILES|set(R.STANDARD_DEVICES)|{'/usr/bin/docker-init'}|WRITABLE
        assert set(mounts)<=allowed,sorted(set(mounts)-allowed)
        for path in WRITABLE:assert mounts[path]['fs']=='tmpfs'and {'rw','nosuid','nodev','noexec'}<=mounts[path]['options'],path
        for path in ['/sys','/sys/fs/cgroup','/proc/sys']:assert 'ro'in mounts[path]['options'],path
        assert set(x.name for x in Path('/sys/class/net').iterdir())=={'lo'}
        assert {x[1]for x in socket.if_nameindex()}=={'lo'}
        assert not any(Path(x).exists()for x in ['/run/dbus/system_bus_socket','/run/docker.sock','/var/run/docker.sock','/dev/net','/dev/dri','/dev/snd'])
        for path,(major,minor)in R.STANDARD_DEVICES.items():
            s=Path(path).stat();assert stat.S_ISCHR(s.st_mode)and(os.major(s.st_rdev),os.minor(s.st_rdev))==(major,minor)
        assert 'ro'in mounts['/usr/bin/docker-init']['options']
        caller_keys=['DBUS_SYSTEM_BUS_ADDRESS','DBUS_SESSION_BUS_ADDRESS','DBUS_STARTER_ADDRESS','G_BUS_ADDRESS']
        assert all(os.environ.get(k)=='unix:path=/FORBIDDEN-CALLER-BUS'for k in caller_keys)
        contract=json.loads((INPUT/'contract.json').read_text())
        for file,pin in contract['guest_source_pins'].items():assert hashlib.sha256((INPUT/file).read_bytes()).hexdigest()==pin
        report['input_contract']=contract
        baseline={x:hashlib.sha256(Path(x).read_bytes()).hexdigest()for x in R.RUNTIME_FILES}
        report['guard']={'capabilities':'ALL zero effective/permitted/bounding/inheritable/ambient','root':'readonly','writable':sorted(WRITABLE),'interfaces':['lo'],'caller_mounts':False,'caller_bus_overridden':{k:env[k]for k in env if k.startswith('DBUS_')},'bus_activation':'no service directories; root EXTERNAL only','network_activation':False}
        for path in ['/run/dbus','/run/NetworkManager','/run/user-TEST','/etc/NetworkManager/conf.d','/etc/NetworkManager/system-connections','/home/TEST/config','/home/TEST/cache','/home/TEST/data']:Path(path).mkdir(mode=0o700,parents=True,exist_ok=True)
        Path('/etc/NetworkManager/NetworkManager.conf').write_bytes(CONFIG)
        user=Path('/etc/NetworkManager/conf.d/70-TEST-user.conf');user.write_bytes(USER)
        busconfig=Path('/run/dbus/TEST.conf');busconfig.write_text('<busconfig><type>system</type><listen>'+BUS+'</listen><auth>EXTERNAL</auth><policy context="default"><allow user="root"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>\n')
        start('bus',['/usr/bin/dbus-daemon','--nofork','--nopidfile','--config-file='+str(busconfig)])
        until=time.monotonic()+5
        while not Path('/run/dbus/system_bus_socket').exists()and time.monotonic()<until:time.sleep(.02)
        node=Path('/run/dbus/system_bus_socket').lstat();assert stat.S_ISSOCK(node.st_mode)and node.st_uid==0
        _,busid=call('owned-bus-id',['gdbus','call','--system','--dest','org.freedesktop.DBus','--object-path','/org/freedesktop/DBus','--method','org.freedesktop.DBus.GetId'])
        busid_row=ast.literal_eval(busid);assert isinstance(busid_row,tuple)and len(busid_row)==1
        busid=busid_row[0];assert isinstance(busid,str)and len(busid)==32 and all(c in '0123456789abcdef'for c in busid)
        report['private_bus_id']=busid
        _,loopback_before=call('loopback-before-readonly',['ip','-j','address','show','dev','lo'])
        loopback=json.loads(loopback_before)
        daemon()
        _,version=call('running-version-state',['nmcli','-g','RUNNING,VERSION,STATE','general']);assert version.split(':')[:2]==['running','1.58.1'],version
        _,capabilities=call('running-capabilities',['gdbus','call','--system','--dest','org.freedesktop.NetworkManager','--object-path','/org/freedesktop/NetworkManager','--method','org.freedesktop.DBus.Properties.Get','org.freedesktop.NetworkManager','Capabilities'])
        report['daemon_queries']={'version_state':version,'capabilities':capabilities}
        call('create-absent-interface-profile',['nmcli','connection','add','type','ethernet','con-name','TEST-private-bus','ifname',IFACE,'connection.uuid',UUID,'connection.autoconnect','no','ipv4.method','disabled','ipv6.method','disabled'])
        call('modify-profile',['nmcli','connection','modify','uuid',UUID,'connection.id','TEST-private-bus-modified','connection.autoconnect','no'])
        _,profile=call('read-profile',['nmcli','-g','connection.id,connection.uuid,connection.interface-name,connection.autoconnect,ipv4.method,ipv6.method','connection','show','uuid',UUID]);assert profile.splitlines()==['TEST-private-bus-modified',UUID,IFACE,'no','disabled','disabled']
        files=[p for p in Path('/etc/NetworkManager/system-connections').glob('*')if p.is_file()and UUID.encode()in p.read_bytes()];assert len(files)==1
        saved=files[0].read_bytes();assert stat.S_IMODE(files[0].stat().st_mode)==0o600
        report['persisted_profile']={'path':str(files[0]),'sha256':hashlib.sha256(saved).hexdigest(),'activation':False,'absent_interface':IFACE}
        retire('nm');assert files[0].read_bytes()==saved and user.read_bytes()==USER
        daemon()
        script="import gi;gi.require_version('NM','1.0');from gi.repository import NM,Gio,GLib;c=NM.Client.new(None);assert c.get_nm_running();p=c.get_connection_by_uuid('"+UUID+"');assert p and not p.get_setting_connection().get_autoconnect();assert p.get_setting_connection().get_interface_name()=='"+IFACE+"';assert p.get_id()=='TEST-private-bus-modified';b=Gio.bus_get_sync(Gio.BusType.SYSTEM,None);v=b.call_sync('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetId',None,GLib.VariantType('(s)'),Gio.DBusCallFlags.NONE,2000,None);print(v.unpack()[0]);print(c.get_version())"
        _,gir=call('GIR-running-and-persisted-profile',['python3','-I','-c',script]);assert gir.splitlines()[0]==busid and gir.splitlines()[1]=='1.58.1'
        call('delete-profile',['nmcli','connection','delete','uuid',UUID])
        _,profiles=call('no-remaining-profiles',['nmcli','-g','UUID','connection','show']);assert UUID not in profiles
        assert not any(UUID.encode()in p.read_bytes()for p in Path('/etc/NetworkManager/system-connections').glob('*')if p.is_file())
        _,active=call('no-active-connections',['nmcli','-g','UUID','connection','show','--active']);assert not active
        assert user.read_bytes()==USER and {x[1]for x in socket.if_nameindex()}=={'lo'}
        retire('nm');retire('bus')
        assert not Path('/run/dbus/system_bus_socket').exists(),'owned bus socket left behind'
        _,loopback_after=call('loopback-after-readonly',['ip','-j','address','show','dev','lo'])
        assert json.loads(loopback_after)==loopback,'private loopback configuration drift'
        report['private_loopback_unchanged']=True;report['owned_bus_socket_removed']=True
        assert all(hashlib.sha256(Path(x).read_bytes()).hexdigest()==v for x,v in baseline.items())
        report.update(status='PASS_X86_OWNED_PRIVATE_SYSTEM_BUS_ONLY',profile_persisted_across_daemon_restart=True,profile_deleted=True,user_config_preserved=True,no_active_connections=True,container_Docker_metadata_unchanged=True,GIR=gir)
    except BaseException as error:report['failure']={'category':type(error).__name__,'message':str(error)[:2048],'traceback':traceback.format_exc(limit=8)[-4096:]}
    finally:
        for role in reversed(list(children)):
            try:retire(role)
            except BaseException as error:report.setdefault('cleanup_failures',[]).append(str(error)[:2048]);report['status']='HOLD_CLEANUP'
        for f in logs:f.close()
        report['platform_refusals']={p.name:[line for line in p.read_text(errors='replace').splitlines()if '<warn>'in line or '<error>'in line]for p in OUT.glob('nm-*.log')}
        report['platform_operations']='HOLD: sandbox link/sysctl refusals and missing auxiliary services are retained, no capability fallback'
        report['logs']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in OUT.glob('*.log')}
        (OUT/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');(OUT/'READY').touch()
        print(json.dumps({'status':report['status'],'failure':report.get('failure')}),flush=True)
        # Only the entry process remains; bounded live export from private tmpfs.
        until=time.monotonic()+45
        while not Path('/run/ALLOW_EXIT').exists()and time.monotonic()<until:time.sleep(.1)
    return 0 if report['status']=='PASS_X86_OWNED_PRIVATE_SYSTEM_BUS_ONLY'else 1


if __name__=='__main__':raise SystemExit(main())
