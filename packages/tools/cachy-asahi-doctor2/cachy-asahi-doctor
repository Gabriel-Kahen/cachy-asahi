#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Small read-only local diagnostic; observations never certify hardware health."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid

VERSION='0.2.0'
PACKAGES={
    'platform':('asahi-meta','linux-asahi','m1n1','uboot-asahi','asahi-alarm-keyring','asahi-firmware',
                'asahi-scripts','asahi-configs','asahi-audio','alsa-ucm-conf-asahi','speakersafetyd','mesa','mesa-asahi','libdrm'),
    'desktop':('hyprland','pipewire','pipewire-pulse','wireplumber'),
    'project':('cachy-asahi-hyprland-settings','cachy-asahi-fish-config','cachy-asahi-zsh-config','cachy-asahi-setup',
               'cachy-asahi-update','cachy-asahi-fdk-aac','cachy-asahi-ksmctl','cachy-asahi-topmem',
               'cachy-asahi-zsh-autosuggestions','cachy-asahi-fish-bang-bang','cachy-asahi-doctor','cachy-asahi-welcome')}
UNITS={'system':('speakersafetyd.service','asahi-audio.service','display-manager.service'),
       'user':('pipewire.service','pipewire-pulse.service','wireplumber.service',
               'xdg-desktop-portal.service','xdg-desktop-portal-hyprland.service')}
TOOLS=('pacman','systemctl','Hyprland','hyprctl','wpctl','pipewire','wireplumber','cachy-asahi-setup','cachy-asahi-update')
MODELS={'apple,j413':'MacBook Air 13-inch (M2)','apple,j415':'MacBook Air 15-inch (M2)'}
MAX_OUTPUT=65536
LIMITS={'command_seconds':2,'total_query_seconds':20,'command_output_bytes':MAX_OUTPUT,'device_tree_bytes':4096}


def item(name,state,value,note):return dict(check=name,state=state,value=value,note=note)


def fixed_read(path):
    try:
        with open(path,'rb') as source:data=source.read(4097)
        return data if len(data)<=4096 else None
    except OSError:return None


def available(name):return shutil.which(name,path='/usr/bin:/bin') is not None


def local_user_bus():
    # Never inherit a TCP/remote D-Bus address from the environment.
    path=Path('/run/user')/str(os.getuid())/'bus'
    try:
        info=path.lstat()
        return str(path) if stat.S_ISSOCK(info.st_mode) and info.st_uid==os.getuid() else None
    except OSError:return None


def query(argv,seconds,bus=None,*,audio=None):
    """Fixed read-only clients, capped output/time, no pager or inherited loader env."""
    env={'PATH':'/usr/bin:/bin','LC_ALL':'C','SYSTEMD_PAGER':'','SYSTEMD_COLORS':'0'}
    if bus:env.update(XDG_RUNTIME_DIR=str(Path(bus).parent),DBUS_SESSION_BUS_ADDRESS='unix:path='+bus)
    if audio:env.update(XDG_RUNTIME_DIR=audio,PIPEWIRE_RUNTIME_DIR=audio,PIPEWIRE_REMOTE='pipewire-0',
                        XDG_CONFIG_HOME='/nonexistent',XDG_CONFIG_DIRS='/etc/xdg',WIREPLUMBER_CONFIG_DIR='/usr/share/wireplumber')
    try:
        process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                 start_new_session=True,env=env)
    except FileNotFoundError:return ('unavailable',None,b'',b'')
    except OSError:return ('unknown',None,b'',b'')
    selector=None;parts=[bytearray(),bytearray()];state='checked';end=time.monotonic()+seconds
    try:
        selector=selectors.DefaultSelector()
        for index,stream in enumerate((process.stdout,process.stderr)):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,index)
        while selector.get_map() or os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
            remaining=end-time.monotonic()
            if remaining<=0:state='unknown';break
            for key,_ in selector.select(min(.1,remaining)):
                data=os.read(key.fd,8192)
                if not data:selector.unregister(key.fileobj);continue
                if sum(map(len,parts))+len(data)>MAX_OUTPUT:state='unknown';break
                parts[key.data].extend(data)
            if state!='checked':break
    except (OSError,ValueError):state='unknown'
    finally:
        # The child stays unreaped until the last group signal; never signal a
        # reused numeric process ID. systemctl/pacman are read-only clients here.
        try:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:process.wait(timeout=1)
            except subprocess.TimeoutExpired:state='unknown'
        finally:
            if selector is not None:selector.close()
            process.stdout.close();process.stderr.close()
    return state,process.returncode,bytes(parts[0]),bytes(parts[1])


def package_rows(result):
    names={n for group in PACKAGES.values() for n in group};found={};missing=set()
    state,code,out,err=result
    if state=='checked' and code in (0,1):
        try:
            for line in out.decode('ascii').splitlines():
                pair=line.split()
                if len(pair)!=2 or pair[0] not in names or pair[0] in found or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+~:@-]{0,127}',pair[1]):raise ValueError()
                found[pair[0]]=pair[1]
            for line in err.decode('ascii').splitlines():
                match=re.fullmatch(r"error: package '([a-z0-9+_.-]+)' was not found",line)
                if not match or match[1] not in names:raise ValueError()
                missing.add(match[1])
            if found.keys() & missing or code==0 and missing:raise ValueError()
        except (ValueError,UnicodeError):found={};missing=set();state='unknown'
    else:state='unavailable' if state=='unavailable' else 'unknown'
    return [item('package/'+name,'checked' if name in found or name in missing else state if state!='checked' else 'unknown',
            {'group':group,'presence':'present','version':found[name]} if name in found else
            {'group':group,'presence':'absent' if name in missing else 'unknown','version':None},
            'Installed version observed.' if name in found else 'Not installed; this reference list is not an installation plan.'
            if name in missing else 'Package query unavailable or incomplete; no absence was inferred.')
            for group,rows in PACKAGES.items() for name in rows]


def service_row(scope,unit,result):
    state,code,out,_=result;value=None
    if state=='checked' and code==0:
        try:
            rows={}
            for line in out.decode('ascii').splitlines():
                key,text=line.split('=',1)
                if key in rows or key not in {'LoadState','ActiveState','SubState'} or not re.fullmatch('[a-z-]{1,64}',text):raise ValueError()
                rows[key]=text
            if set(rows)!={'LoadState','ActiveState','SubState'}:raise ValueError()
            if rows['LoadState'] not in {'loaded','not-found','error','masked','bad-setting','merged','stub'} or rows['ActiveState'] not in {'active','reloading','inactive','failed','activating','deactivating','maintenance','refreshing'}:raise ValueError()
            value=rows
        except (ValueError,UnicodeError):state='unknown'
    elif state!='unavailable':state='unknown'
    note='Service state only; successful application/audio operation is not tested.'
    if value and value['LoadState']=='not-found':note='Unit is not installed. Some session launch methods do not use it.'
    elif value and value['ActiveState']=='failed':note='Unit reports failed. Diagnose it locally before changing or restarting services.'
    elif value and value['ActiveState']!='active':note='Unit is not active. Check from the affected graphical/audio session if expected.'
    elif not value:note='Could not query the local service manager; no service state was inferred.'
    return item(scope+'/'+unit,state,value,note)


def audio_socket(path=None):
    """Observe only the current user's private runtime and ordinary local socket.

    The optional internal path is a fixture seam, absent from CLI/environment.
    Checks before/after a query detect observed replacement, not hostile same-UID
    ABA races or the identity of the process serving the socket.
    """
    path=Path('/run/user')/str(os.getuid()) if path is None else Path(path)
    if not path.is_absolute() or '..' in path.parts:return None
    fd=None
    def identity(value):return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink)
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        directory=os.fstat(fd);socket=os.stat('pipewire-0',dir_fd=fd,follow_symlinks=False)
        if directory.st_uid!=os.getuid() or stat.S_IMODE(directory.st_mode)!=0o700:return None
        if not stat.S_ISSOCK(socket.st_mode) or socket.st_uid!=os.getuid() or socket.st_nlink!=1:return None
        return dict(path=str(path),directory=identity(directory),socket=identity(socket))
    except OSError:return None
    finally:
        if fd is not None:os.close(fd)


def audio_row(result):
    state,code,out,err=result
    value=None
    if state=='checked' and code==0 and not err and len(out)<=128:
        match=re.fullmatch(rb'Volume: (0|[1-9][0-9]{0,3})\.([0-9]{2})( \[MUTED\])?\n',out)
        if match:
            value=dict(displayed_volume=(match[1]+b'.'+match[2]).decode('ascii'),muted=bool(match[3]),default_sink_responded=True)
    if value:
        state='checked'
        if value['muted']:note='Default output is muted. Review mute and output selection in your audio controls; Doctor changed nothing.'
        elif value['displayed_volume']=='0.00':note='Default output volume is zero. Review volume and output selection in your audio controls; Doctor changed nothing.'
        else:note='Default output volume/mute observed. If sound is absent, review output selection and the audio graph; this does not test playback or speaker safety.'
    else:
        state='unavailable' if state=='unavailable' else 'unknown'
        note='Default output was not observed. Check output selection and run Doctor from the affected login session; active services alone do not establish an output.'
    return item('audio/default-output',state,value,note)


def collect(*,run=query,read=fixed_read,has=available,bus_check=local_user_bus,audio_check=audio_socket,machine=None,environ=None):
    env=os.environ if environ is None else environ
    machine=machine or dict(architecture=os.uname().machine,page_size_bytes=os.sysconf('SC_PAGE_SIZE'),kernel=os.uname().release)
    checks=[item('platform','checked',machine,'Observed running kernel/architecture/page size; no target compatibility test.')]
    compatible=read('/proc/device-tree/compatible');model=read('/proc/device-tree/model')
    try:identifiers=[] if compatible is None else compatible.decode('ascii').strip('\0').split('\0')
    except UnicodeError:identifiers=[]
    boards=sorted({text for text in identifiers if re.fullmatch('apple,j[0-9]{3,4}[a-z]?',text)})
    known=[text for text in boards if text in MODELS]
    identified=known[0] if len(boards)==len(known)==1 and machine['architecture']=='aarch64' else None
    checks.append(item('apple-model','checked' if identified else 'unavailable' if compatible is None else 'unknown',
        dict(identifier=identified,observed_board=boards[0] if len(boards)==1 else None,
             model=MODELS.get(identified),model_property_available=model is not None),
        'Device-tree compatible identifier observed; physical execution is not established.' if identified else
        'Apple model unknown. No model is inferred from the kernel name or generic architecture.'))
    session_type=env.get('XDG_SESSION_TYPE','')
    session=dict(type=session_type if session_type in ('wayland','x11','tty') else 'unknown',
        wayland_environment=bool(env.get('WAYLAND_DISPLAY')),hyprland_environment=bool(env.get('HYPRLAND_INSTANCE_SIGNATURE')))
    checks.append(item('session','checked' if session['type']!='unknown' else 'unknown',session,
                       'Environment hints only; compositor responsiveness and rendering are not tested.'))
    tools={name:has(name) for name in TOOLS}
    checks.append(item('tools','checked',tools,'Executable availability in /usr/bin:/bin; tools were not launched for this check.'))
    end=time.monotonic()+LIMITS['total_query_seconds'];bus=bus_check()
    def probe(argv,tool,*,user=False):
        if not tools[tool] or user and not bus:return ('unavailable',None,b'',b'')
        left=end-time.monotonic()
        if left<=0:return ('unknown',None,b'',b'')
        return run(argv,min(left,LIMITS['command_seconds']),bus if user else None)
    names=[name for group in PACKAGES.values() for name in group]
    checks.extend(package_rows(probe(['/usr/bin/pacman','-Q','--',*names],'pacman')))
    for scope,units in UNITS.items():
        for unit in units:
            argv=['/usr/bin/systemctl','--'+scope,'--no-pager','--no-ask-password','show',unit,'--property=LoadState,ActiveState,SubState']
            row=service_row(scope,unit,probe(argv,'systemctl',user=scope=='user'))
            if scope=='user' and not bus:row['note']='Local user bus unavailable. Run doctor from your affected login session.'
            checks.append(row)
    audio=audio_check() if tools['wpctl'] else None
    left=end-time.monotonic()
    result=('unavailable',None,b'',b'')
    if audio is not None:
        if left<=0:result=('unknown',None,b'',b'')
        elif audio_check()!=audio:result=('unknown',None,b'',b'')
        else:
            result=run(['/usr/bin/wpctl','get-volume','@DEFAULT_AUDIO_SINK@'],min(left,LIMITS['command_seconds']),None,audio=audio['path'])
            if audio_check()!=audio:result=('unknown',None,b'',b'')
    checks.append(audio_row(result))
    return dict(schema_version=1,tool='cachy-asahi-doctor',version=VERSION,collected_utc=datetime.now(timezone.utc).isoformat(),
        checks=checks,coverage={state:sum(r['state']==state for r in checks) for state in ('checked','unavailable','unknown')},
        limits=dict(LIMITS),scope='local observations only',
        limitations=['Fixed package/unit/tool selection; missing alternatives are not install instructions.',
                    'No journal, process arguments, home/key contents, network addresses or machine/serial IDs collected.',
                    'Default-output volume/mute is a rounded scalar observation, not playback, routing, audibility or speaker-safety proof.',
                    'No hardware, speaker safety, rendering, boot/recovery, performance or production-trust certification.'])


def publish(path,data):
    """Private complete JSON publication, atomic no-overwrite, no parent creation."""
    path=Path(os.path.abspath(path))
    if len(data)>128*1024:raise ValueError('report size refused')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY);temporary='.cachy-asahi-doctor-'+uuid.uuid4().hex+'.tmp'
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
        stream=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        try:
            os.fchmod(stream,0o600)
            pending=memoryview(data)
            while pending:
                count=os.write(stream,pending)
                if count<=0:raise OSError('report write stalled')
                pending=pending[count:]
            os.fsync(stream)
        finally:os.close(stream)
        os.link(temporary,path.name,src_dir_fd=fd,dst_dir_fd=fd,follow_symlinks=False)
        os.unlink(temporary,dir_fd=fd);os.fsync(fd)
    finally:
        try:os.unlink(temporary,dir_fd=fd)
        except FileNotFoundError:pass
        os.close(fd)


def human(report):
    lines=['cachy-asahi doctor '+VERSION+' — local read-only observations']
    for row in report['checks']:
        value=row['value'];name=row['check']
        if value is None:text='state unavailable'
        elif name=='platform':text=f"{value['architecture']}; {value['page_size_bytes']}-byte pages; kernel {value['kernel']}"
        elif name=='apple-model':text=(value['model'] or 'unknown model')+'; DT board '+(value['observed_board'] or 'unknown')
        elif name=='session':text=value['type']+'; Wayland environment '+str(value['wayland_environment'])+'; Hyprland environment '+str(value['hyprland_environment'])
        elif name=='audio/default-output':text='volume '+value['displayed_volume']+'; '+('muted' if value['muted'] else 'not muted')
        elif name=='tools':text='available: '+', '.join(n for n,present in value.items() if present)+'; unavailable: '+', '.join(n for n,present in value.items() if not present)
        elif name.startswith('package/'):text=value['version'] or value['presence']
        else:text=value['LoadState']+'; '+value['ActiveState']+'/'+value['SubState']
        lines.append('['+row['state']+'] '+name+': '+text)
        if row['state']!='checked' or name=='audio/default-output' or name.startswith(('system/','user/')):lines.append('  '+row['note'])
    lines.append('Coverage: '+', '.join(str(v)+' '+k for k,v in report['coverage'].items()))
    lines.extend(report['limitations'])
    lines.append('Exit 0 means the report was generated; it is not an all-healthy result.')
    return '\n'.join(lines)+'\n'


REPORT_BYTES=128*1024
STATES=('checked','unknown','unavailable')


def require(condition):
    if not condition:raise ValueError('unsupported or malformed doctor report')


def fields(value,names):
    require(type(value) is dict and set(value)==set(names.split()))


def token(value,pattern=r'[A-Za-z0-9][A-Za-z0-9._+~:@-]{0,127}'):
    return type(value) is str and re.fullmatch(pattern,value) is not None


def duplicate_free(pairs):
    result={}
    for key,value in pairs:
        require(key not in result);result[key]=value
    return result


def invalid_number(_):raise ValueError('unsupported number')


def read_report(path):
    """Read only bounded ordinary files; never follow symlinks or wait on a FIFO."""
    path=Path(os.path.abspath(path));fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        source=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        try:
            info=os.fstat(source)
            require(stat.S_ISREG(info.st_mode) and 0<info.st_size<=REPORT_BYTES)
            with os.fdopen(source,'rb',closefd=False) as stream:raw=stream.read(REPORT_BYTES+1)
            require(0<len(raw)<=REPORT_BYTES)
        finally:os.close(source)
    finally:os.close(fd)
    report=json.loads(raw.decode('utf-8'),object_pairs_hook=duplicate_free,
                      parse_constant=invalid_number,parse_float=invalid_number)
    return validate_report(report)


def validate_report(report):
    fields(report,'schema_version tool version collected_utc checks coverage limits scope limitations')
    require(type(report['schema_version']) is int and report['schema_version']==1)
    require(report['tool']=='cachy-asahi-doctor' and report['version'] in ('0.1.0','0.2.0'))
    require(report['scope']=='local observations only')
    stamp=report['collected_utc']
    require(type(stamp) is str and len(stamp)<=40)
    parsed=datetime.fromisoformat(stamp)
    require(parsed.tzinfo is not None and parsed.utcoffset().total_seconds()==0)
    fields(report['limits'],'command_seconds total_query_seconds command_output_bytes device_tree_bytes')
    require(all(type(v) is int and v==LIMITS[k] for k,v in report['limits'].items()))
    require(type(report['limitations']) is list and 1<=len(report['limitations'])<=8)
    require(all(type(s) is str and len(s)<=512 for s in report['limitations']))
    expected=['platform','apple-model','session','tools']
    groups={'package/'+name:group for group,names in PACKAGES.items() for name in names}
    expected.extend(groups)
    expected.extend(scope+'/'+unit for scope,units in UNITS.items() for unit in units)
    if report['version']=='0.2.0':expected.append('audio/default-output')
    require(type(report['checks']) is list and len(report['checks'])==len(expected))
    rows={}
    for row in report['checks']:
        fields(row,'check state value note');name=row['check'];state=row['state'];value=row['value']
        require(type(name) is str and name in expected and name not in rows)
        require(type(state) is str and state in STATES)
        require(type(row['note']) is str and len(row['note'])<=512)
        if name=='platform':
            fields(value,'architecture kernel page_size_bytes')
            require(state=='checked' and token(value['architecture']) and token(value['kernel']))
            size=value['page_size_bytes']
            require(type(size) is int and 1024<=size<=1048576 and size&(size-1)==0)
        elif name=='apple-model':
            fields(value,'identifier observed_board model model_property_available')
            identifier=value['identifier'];board=value['observed_board']
            require(type(value['model_property_available']) is bool)
            require(board is None or token(board,r'apple,j[0-9]{3,4}[a-z]?'))
            if state=='checked':require(type(identifier) is str and identifier in MODELS and board==identifier and value['model']==MODELS[identifier])
            else:require(identifier is None and value['model'] is None)
        elif name=='session':
            fields(value,'type wayland_environment hyprland_environment')
            require(value['type'] in ('wayland','x11','tty','unknown'))
            require(state==('unknown' if value['type']=='unknown' else 'checked'))
            require(all(type(value[k]) is bool for k in ('wayland_environment','hyprland_environment')))
        elif name=='tools':
            require(type(value) is dict and set(value)==set(TOOLS) and state=='checked')
            require(all(type(v) is bool for v in value.values()))
        elif name in groups:
            fields(value,'group presence version');presence=value['presence'];version=value['version']
            require(value['group']==groups[name])
            if state=='checked':require(presence=='present' and token(version) or presence=='absent' and version is None)
            else:require(presence=='unknown' and version is None)
        elif name=='audio/default-output':
            if state!='checked':require(value is None)
            else:
                fields(value,'displayed_volume muted default_sink_responded')
                require(token(value['displayed_volume'],r'(0|[1-9][0-9]{0,3})\.[0-9]{2}'))
                require(type(value['muted']) is bool and value['default_sink_responded'] is True)
        elif state!='checked':require(value is None)
        else:
            fields(value,'LoadState ActiveState SubState')
            require(all(token(v,r'[a-z-]{1,64}') for v in value.values()))
            require(value['LoadState'] in ('loaded','not-found','error','masked','bad-setting','merged','stub'))
            require(value['ActiveState'] in ('active','reloading','inactive','failed','activating','deactivating','maintenance','refreshing'))
        rows[name]={'state':state,'value':value}
    require(set(rows)==set(expected))
    if rows['apple-model']['state']=='checked':require(rows['platform']['value']['architecture']=='aarch64')
    fields(report['coverage'],'checked unknown unavailable')
    require(all(type(v) is int and v==sum(r['state']==k for r in rows.values()) for k,v in report['coverage'].items()))
    return dict(version=report['version'],collected_utc=stamp,rows=rows)


def compare_reports(before,after):
    old=before['rows'];new=after['rows']
    left=old['apple-model']['value']['identifier'];right=new['apple-model']['value']['identifier']
    if left is not None and right is not None and left!=right:raise ValueError('different known Apple models')
    changes=[]
    for name in sorted(old.keys()|new.keys()):
        a=old.get(name);b=new.get(name)
        if a==b:continue
        kind='check-added' if a is None else 'check-removed' if b is None else 'state-and-value' if a['state']!=b['state'] and a['value']!=b['value'] else 'state' if a['state']!=b['state'] else 'value'
        changes.append(dict(check=name,kind=kind,before=a,after=b))
    return dict(schema_version=1,tool='cachy-asahi-doctor-comparison',scope='supplied observations only',
        before={k:before[k] for k in ('version','collected_utc')},after={k:after[k] for k in ('version','collected_utc')},
        changed=bool(changes),change_count=len(changes),unchanged_count=sum(old[k]==new[k] for k in old.keys()&new.keys()),
        coverage={side:{state:sum(r['state']==state for r in report['rows'].values()) for state in STATES}
                  for side,report in (('before',before),('after',after))},
        changes=changes,limitations=['User-supplied reports are not authenticated; matching model labels do not identify the same machine.',
            'Unknown and unavailable describe missing knowledge; neither means absent or healthy.',
            'Observed changes do not establish update causation, health, regression, hardware behavior or performance.',
            'Check additions/removals describe report coverage; no new observations were collected.'])


def comparison_human(report):
    lines=['cachy-asahi doctor — offline observation comparison',str(report['change_count'])+' changed checks; '+str(report['unchanged_count'])+' unchanged.']
    for change in report['changes']:
        def describe(row):
            return 'not reported' if row is None else row['state']+' '+json.dumps(row['value'],sort_keys=True,separators=(',',':'))
        lines.append(change['check']+': '+describe(change['before'])+' -> '+describe(change['after']))
    if not report['changed']:lines.append('No observation changes.')
    lines.extend(report['limitations'])
    return '\n'.join(lines)+'\n'


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json',action='store_true',help='Print the same bounded JSON to stdout')
    parser.add_argument('--output',type=Path,help='Publish private JSON to a new file; parent must exist')
    parser.add_argument('--compare',nargs=2,type=Path,metavar=('BEFORE','AFTER'),help='Compare two supplied doctor JSON files offline; collect nothing')
    args=parser.parse_args(argv)
    if args.compare:
        try:report=compare_reports(*(read_report(path) for path in args.compare))
        except (OSError,ValueError,TypeError,KeyError,RecursionError,OverflowError):
            print('Comparison refused: use bounded ordinary schema-1 doctor reports from supported versions and matching known models.',file=sys.stderr)
            return 2
    else:report=collect()
    raw=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
    if args.output:
        try:publish(args.output,raw)
        except (OSError,ValueError):
            print('Could not publish report. Choose a new file in an existing ordinary directory; no existing file is replaced.',file=sys.stderr)
            return 2
    sys.stdout.write(raw.decode() if args.json else comparison_human(report) if args.compare else human(report))
    if args.output and not args.json:sys.stdout.write('Private JSON report written to the requested new file.\n')
    return 0


if __name__=='__main__':raise SystemExit(main())
