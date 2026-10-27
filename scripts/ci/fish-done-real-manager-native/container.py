#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Separate disposable native PID1 consumers: alarm build and installed Mako trial."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess
import sys
import tarfile
import time
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import closed as C
sys.path.insert(0,str(C.HERE.parents[2]/C.DATA))
import reserved_process as R

ALARM=1000
OUT=Path('/out')
BUILT=Path('/built')
PROTECTED=('/etc/pacman.conf','/etc/pacman.d','/etc/fish','/etc/zsh','/etc/skel',
           '/boot','/usr/lib/modules','/home/alarm','/root')
OLD18=('noninteractive','foreground','background','watch-rejection','disown','repeat-preserve',
       'command-data','transport-failure','transport-timeout','disable','existing-function',
       'existing-autoload','existing-variable','existing-wrapper','existing-public','no-bus','notify-send','timeout')
BUILD_LEAVES=('tools/sway','tools/swaymsg','libs/libwlroots-0.19.so','licenses/wlroots.MIT',
              'licenses/sway.MIT','native-build-result.json','commands.json','trial-inputs.json')

def sha(raw):return hashlib.sha256(raw).hexdigest()
def read_json(path):return json.loads(C.read(path))

def guard(phase):
    C.need(os.getpid()==1 and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'
        and Path('/.dockerenv').is_file() and os.environ.get('CACHY_FISH_DONE_REAL_MANAGER')=='1',
        'marked disposable native root PID1 required')
    user=pwd.getpwnam('alarm');C.need(user.pw_uid==user.pw_gid==ALARM,'exact alarm UID/GID1000 required')
    C.need(not any(Path(p).exists() for p in ('/dev/dri','/dev/input','/run/user')) and
        not any(os.environ.get(k) for k in ('DISPLAY','WAYLAND_DISPLAY','DBUS_SESSION_BUS_ADDRESS','LD_PRELOAD')),
        'private CPU-only consumer required')
    C.need([s.split(':')[0].strip() for s in Path('/proc/net/dev').read_text().splitlines()[2:]]==['lo'],
        'offline loopback-only consumer required')
    if phase=='build':C.need(os.statvfs('/').f_flag&os.ST_RDONLY,'readonly build root required')

def snapshot(path):
    path=Path(path)
    if not os.path.lexists(path):return None
    result,total,pending={},0,[path]
    while pending:
        p=pending.pop();s=p.lstat();name='.' if p==path else str(p.relative_to(path))
        row={k:getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
        if stat.S_ISDIR(s.st_mode):pending.extend(sorted(p.iterdir(),reverse=True))
        elif stat.S_ISREG(s.st_mode):
            total+=s.st_size;C.need(s.st_size<=16*1024**2 and total<=128*1024**2,'bounded snapshot bytes required')
            row['sha256']=sha(p.read_bytes())
        elif stat.S_ISLNK(s.st_mode):row['link']=os.readlink(p)
        else:row['special']=True
        result[name]=row;C.need(len(result)<=8192,'bounded snapshot nodes required')
    return result

def ordinary_processes():
    result=[];nodes=list(Path('/proc').iterdir());C.need(len(nodes)<1024,'bounded private process namespace required')
    for p in nodes:
        if not p.name.isdigit():continue
        try:status=(p/'status').read_text();raw=(p/'stat').read_text()
        except FileNotFoundError:continue
        line=next((s for s in status.splitlines() if s.startswith('Uid:')),'')
        if str(ALARM) in line.split()[1:]:
            fields=raw[raw.rfind(')')+2:].split()
            result.append(dict(pid=int(p.name),start_ticks=int(fields[19]),state=fields[0]))
    return sorted(result,key=lambda r:r['pid'])

def drain_adopted():
    # Only after the one synchronous subprocess child has already been waited.
    deadline,rows=time.monotonic()+2,[]
    while True:
        try:pid,status=os.waitpid(-1,os.WNOHANG)
        except ChildProcessError:return rows
        if pid:rows.append(dict(pid=pid,wait_status=status))
        elif time.monotonic()>=deadline:return rows
        else:time.sleep(.02)

class Commands:
    def __init__(self,output):self.output,self.rows=output,[]
    def __call__(self,argv,timeout=120):
        n=len(self.rows)+1;row=dict(argv=list(map(str,argv)),index=n);self.rows.append(row)
        with (self.output/f'command-{n}.stdout').open('xb') as out,(self.output/f'command-{n}.stderr').open('xb') as err:
            receipt=R.run(row['argv'],timeout,
                env=dict(PATH='/usr/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',PYTHONDONTWRITEBYTECODE='1'),
                stdout=out,stderr=err,term_seconds=3,kill_seconds=2)
            # The leader is now reaped, or ownership is explicitly unknown. Only
            # adopted-child waits and a /proc census are permitted afterward.
            row['adopted_reaping']=drain_adopted()
            R.refresh(receipt)
            row.update(pid=receipt['pid'],exit=receipt['exit'],
                group_absent=receipt['group_absent'],supervision=receipt)
            C.save(self.output/'commands.json',self.rows)
        for suffix in ('stdout','stderr'):
            path=self.output/f'command-{n}.{suffix}';C.need(path.stat().st_size<=2*1024**2,'bounded root command output required')
            row[suffix]=dict(bytes=path.stat().st_size,sha256=sha(path.read_bytes()))
        C.save(self.output/'commands.json',self.rows)
        C.need(receipt['completed'] is True and not receipt['timed_out'] and
            receipt['retirement']=='VERIFIED_ABSENT' and
            row['exit']==0 and row['group_absent'] is True,'root wrapper command failed or retirement unknown')
        R.assert_verified(receipt)
        return (self.output/f'command-{n}.stdout').read_text()

def alarm_command(argv,home,extra=()):
    return ['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i','PATH=/usr/bin','HOME='+str(home),
        'LANG=C.UTF-8','LC_ALL=C.UTF-8','PYTHONDONTWRITEBYTECODE=1',*extra,*map(str,argv)]

def validate_native_build(path,data):
    value=read_json(path/'native-build-result.json')
    C.need(value['status']=='PASS_NATIVE_AARCH64_HEADLESS_DEPENDENCY_BUILD_ONLY' and value['native_arch']=='aarch64'
        and value['installed_delivery']=='NOT_RUN' and not value['errors'] and value['context_sha256']==C.digest(data/'context.json'),
        'actual native build/context result required')
    C.need(value['commands'] and all(r['exit']==0 and r['group_absent'] is True for r in value['commands']),
        'all native build commands must retire')
    C.need(set(value['outputs'])==set(BUILD_LEAVES[:3]),'exact three native outputs required')
    native=C.load(data/'native_build.py','held_native_output_elf_gate')
    for name,row in value['outputs'].items():
        p=path/name;C.need(row['elf_machine']==183 and row['load_alignment']=='AT_LEAST_16384' and
            C.digest(p)==row['sha256'] and p.stat().st_size==row['bytes'],'native output identity differs')
        native.elf(C.read(p),aligned=True)
    for row in value['commands']:
        C.need(re.fullmatch(r'command-[1-9][0-9]{0,3}\.log',row['log']) and C.digest(path/row['log'])==row['sha256']
            and (path/row['log']).stat().st_size==row['bytes'],'native command log binding differs')
    return value

def export_files(files,output,success):
    output.mkdir(mode=0o755);mapping={};total=0
    for name,path in sorted(files.items()):
        C.need(not Path(name).is_absolute() and '..' not in Path(name).parts,'safe closed export path required')
        raw=C.read(path);total+=len(raw);C.need(len(mapping)<768 and total<=96*1024**2,'closed export caps')
        dest=output/name;dest.parent.mkdir(parents=True,exist_ok=True,mode=0o755);dest.write_bytes(raw)
        dest.chmod(0o555 if name.startswith('tools/') else 0o444);mapping[name]=dict(bytes=len(raw),sha256=sha(raw))
    C.save(output.parent/'export-map.json',mapping)
    C.save(output.parent/'export-status.json',dict(status='PASS' if success else 'FAIL_PARTIAL',files=len(mapping),bytes=total))
    return mapping

def verify_export(path,data):
    value=read_json(path.parent/'export-map.json') if (path.parent/'export-map.json').exists() else None
    # Trial receives only /built readonly, so the immutable map is retained inside it too.
    if value is None:value=read_json(path/'build-export-map.json')
    actual={str(p.relative_to(path)) for p in path.rglob('*') if p.is_file()}
    C.need(actual==set(value)|{'build-export-map.json'},'whole native export membership differs')
    allowed=set(value)|{'build-export-map.json'}
    directories={str(parent) for n in allowed for parent in Path(n).parents if parent!=Path('.')}
    C.need(all(not p.is_symlink() for p in path.rglob('*')) and
        {str(p.relative_to(path)) for p in path.rglob('*') if p.is_dir()}==directories,
        'native export directory alias/allowlist differs')
    for name,row in value.items():
        C.need(not Path(name).is_absolute() and '..' not in Path(name).parts and C.digest(path/name)==row['sha256']
            and (path/name).stat().st_size==row['bytes'],'native export byte binding differs')
    return validate_native_build(path,data)

def build(source,command,report):
    data=source/C.DATA;parent=OUT/'native';parent.mkdir(mode=0o755);os.chown(parent,ALARM,ALARM);error=None
    try:
        command(alarm_command(['/usr/bin/python','-I','-B',data/'native_build.py','--output',parent/'work'],
            parent,['CACHY_ASAHI_NATIVE_HEADLESS_BUILD=1']),1260)
        report['native_build']=validate_native_build(parent/'work',data)
        C.need(not ordinary_processes(),'ordinary compiler/tool process remained')
    except BaseException as caught:error=caught
    finally:
        work=parent/'work';names=[n for n in BUILD_LEAVES if (work/n).is_file()]
        logs=sorted(p.name for p in work.glob('command-*.log')) if work.exists() else []
        C.need(len(logs)<=256 and all(re.fullmatch(r'command-[1-9][0-9]{0,3}\.log',n) for n in logs),'closed command logs required')
        C.need(error is not None or set(names)==set(BUILD_LEAVES),'complete successful build export required')
        mapping=export_files({n:work/n for n in names+logs},OUT/'export',error is None)
        C.save(OUT/'export/build-export-map.json',mapping)
        mapping['build-export-map.json']=dict(bytes=(OUT/'export/build-export-map.json').stat().st_size,
            sha256=C.digest(OUT/'export/build-export-map.json'));C.save(OUT/'export-map.json',mapping)
    if error is not None:raise error
    report['status']='PASS_NATIVE_HEADLESS_BUILD'

def stage_trial_sources(data,lock):
    # Hosted checkout UID can differ from alarm. Preserve bytes in root-owned
    # readonly private inputs; unchanged constructor allows only root/caller owners.
    target=OUT/'inputs';target.mkdir(mode=0o755)
    mapping={}
    for name,digest in lock['delivery_files'].items():
        raw=C.read(data/'delivery'/name);C.need(sha(raw)==digest,'unchanged delivery source copy required')
        dest=target/'delivery'/name;dest.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
        dest.write_bytes(raw);dest.chmod(0o444);mapping['delivery/'+name]=dict(bytes=len(raw),sha256=sha(raw))
    for name in ('done.pkg.tar.xz','mako.conf'):
        raw=C.read(data/name);(target/name).write_bytes(raw);(target/name).chmod(0o444)
        mapping[name]=dict(bytes=len(raw),sha256=sha(raw))
    C.save(OUT/'input-copy-map.json',mapping)
    return target

def rebase_inputs(data,built,parent,lock,staged=None):
    staged=data if staged is None else staged
    value=read_json(built/'trial-inputs.json')
    C.need(set(value['tools'])=={'sway','swaymsg','mako','makoctl','fish','busctl','dbus_daemon',
        'notify_send','timeout','bwrap','sleep','shell','python','pacman'},'closed native tool set required')
    C.need(len(value['libraries'])==1,'one new native shared library required')
    for name in ('sway','swaymsg'):value['tools'][name]['path']=str(built/'tools'/name)
    value['libraries'][0]['path']=str(built/'libs/libwlroots-0.19.so')
    value['mako_config']['path']=str(staged/'mako.conf');value['done_archive']['path']=str(staged/'done.pkg.tar.xz')
    original=C.load(data/'delivery/run.py','held_native_input_rebase_gate')
    expected=dict(original.SYSTEM,mako='/usr/bin/mako',makoctl='/usr/bin/makoctl',
        sway=str(built/'tools/sway'),swaymsg=str(built/'tools/swaymsg'))
    C.need({name:row['path'] for name,row in value['tools'].items()}==expected,'fixed rebased native tool paths required')
    base=original.inherited()
    for name,row in value['tools'].items():
        aliases=('/usr/bin/fish','/usr/bin/fish_indent','/usr/bin/fish_key_reader') if name=='fish' else ()
        base.ordinary(row['path'],row['sha256'],32*1024**2,True,aliases,base.native_architecture())
    for row in [*value['libraries'],value['mako_config'],value['done_archive']]:
        C.need(C.digest(Path(row['path']))==row['sha256'],'rebased native input changed')
    for name,digest in lock['native_mako_payload'].items():
        C.need(C.digest(Path(name))==digest,'actual selected native Mako payload differs')
    target=parent/'inputs.json';C.save(target,value);target.chmod(0o600);os.chown(target,ALARM,ALARM)
    return target

def ordinary_export_files(parent,complete=False):
    C.need(set(p.name for p in parent.iterdir())<={'inputs.json','old18','work'},'ordinary root allowlist differs')
    if (parent/'old18').exists():
        actual=set(p.name for p in (parent/'old18').iterdir());expected=set(OLD18)|{'receipt.json'}
        C.need(actual<=expected and (not complete or actual==expected),'all18 private case partitions required')
    files,aliases,total={}, {},0
    for directory,dirs,names in os.walk(parent,followlinks=False):
        base=Path(directory)
        for name in list(dirs):C.need(not (base/name).is_symlink(),'ordinary directory alias refused')
        for name in names:
            p=base/name;s=p.lstat();relative=str(p.relative_to(parent))
            if stat.S_ISLNK(s.st_mode):
                C.need(p.parent.name=='bin' and name in ('sleep','sh','timeout','kill') and
                    os.readlink(p)=='/usr/bin/'+name,'only original old18 command aliases allowed')
                aliases[relative]=os.readlink(p);continue
            if not stat.S_ISREG(s.st_mode):
                C.need(not complete,'live socket/special ordinary node remained')
                continue  # Failed-phase metadata below records the special node; no PASS is possible.
            total+=s.st_size;C.need(s.st_size<=16*1024**2 and total<=64*1024**2,'ordinary raw byte caps')
            target=('delivery/'+relative.removeprefix('work/')) if relative.startswith('work/') else relative
            files[target]=p
            C.need(len(files)+len(aliases)<=1024,'bounded ordinary raw registry')
    C.save(OUT/'ordinary-aliases.json',aliases);C.save(OUT/'ordinary-state.json',snapshot(parent))
    files['ordinary-aliases.json']=OUT/'ordinary-aliases.json';files['ordinary-state.json']=OUT/'ordinary-state.json'
    return files

def trial_export(ordinary,success):
    files=ordinary_export_files(ordinary,complete=success) if ordinary.exists() else {}
    for name in ('alpm-observations.json','protected.json','orphan-reaping.json','pacman.conf','input-copy-map.json'):
        if (OUT/name).is_file():files[name]=OUT/name
    export_files(files,OUT/'export',success)

def finish_export(phase):
    output=OUT/'export'
    if not output.exists():output.mkdir(mode=0o755)
    mapping=read_json(OUT/'export-map.json') if (OUT/'export-map.json').exists() else {}
    for path in sorted(OUT.glob('command-*.*')):
        if re.fullmatch(r'command-[1-9][0-9]{0,3}\.(stdout|stderr)',path.name):
            target=output/'wrapper'/path.name;target.parent.mkdir(mode=0o755,exist_ok=True)
            target.write_bytes(C.read(path));target.chmod(0o444)
            mapping['wrapper/'+path.name]=dict(bytes=target.stat().st_size,sha256=C.digest(target))
    for name in ('commands.json','orphan-reaping.json'):
        if (OUT/name).is_file():
            target=output/'wrapper'/name;target.parent.mkdir(mode=0o755,exist_ok=True)
            target.write_bytes(C.read(OUT/name));target.chmod(0o444)
            mapping['wrapper/'+name]=dict(bytes=target.stat().st_size,sha256=C.digest(target))
    if phase=='build':
        inner={name:row for name,row in mapping.items() if name!='build-export-map.json'}
        C.save(output/'build-export-map.json',inner)
        (output/'build-export-map.json').chmod(0o444)
        mapping['build-export-map.json']=dict(bytes=(output/'build-export-map.json').stat().st_size,
            sha256=C.digest(output/'build-export-map.json'))
    C.need(len(mapping)<=768 and sum(r['bytes'] for r in mapping.values())<=96*1024**2,'closed final export caps')
    C.save(OUT/'export-map.json',mapping)

def trial(source,command,report):
    data=source/C.DATA;built=verify_export(BUILT,data)
    report['native_build_export']=dict(report_sha256=C.digest(BUILT/'native-build-result.json'),
        outputs=built['outputs'],map_sha256=C.digest(BUILT/'build-export-map.json'))
    lock=read_json(data/'build.lock.json');done=read_json(data/'delivery/done-lock.json')
    base=command(['/usr/bin/pacman','-Q']);C.need(base==C.read(data/'inventory574.lock').decode(),'exact574 starting inventory required')
    protected={name:snapshot(name) for name in PROTECTED};C.save(OUT/'protected.json',protected)
    command(['/usr/bin/pacman','-T','fish>=4.9.3','libnotify','coreutils','python','bubblewrap'])
    hooks=OUT/'hooks';hooks.mkdir();seen=set()
    for directory in ('/etc/pacman.d/hooks','/usr/share/libalpm/hooks','/builder-disabled-hooks'):
        for path in Path(directory).glob('*.hook'):
            C.need(re.fullmatch(r'[A-Za-z0-9_.@+-]+\.hook',path.name),'safe original hook name required')
            if path.name not in seen:(hooks/path.name).symlink_to('/dev/null');seen.add(path.name)
    conf=OUT/'pacman.conf';conf.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Optional\nHookDir = '+str(hooks)+'\n')
    report['masked_hooks']=sorted(seen)
    pacman=['/usr/bin/pacman','--config',str(conf),'--noconfirm','--noscriptlet']
    observations=report['alpm_observations']=[];expected=dict(line.split() for line in base.splitlines())
    command(pacman+['-U',str(data/'done.pkg.tar.xz')])
    installed=dict(line.split() for line in command(['/usr/bin/pacman','-Q']).splitlines())
    C.need(installed==expected|{done['name']:done['version']} and len(installed)==575,'exact575 installed inventory required')
    run=C.load(data/'delivery/run.py','unchanged_delivery_installed_gate')
    report['installed_payload']=run.installed(command,done);command(['/usr/bin/pacman','-Dk'])
    C.need({name:snapshot(name) for name in PROTECTED}==protected,'install changed protected configuration/platform')
    observations.append(dict(phase='install',inventory=installed,payload=report['installed_payload'],protected_preserved=True))
    C.save(OUT/'alpm-observations.json',observations)
    ordinary=OUT/'ordinary';ordinary.mkdir(mode=0o700);os.chown(ordinary,ALARM,ALARM)
    command(alarm_command(['/usr/bin/python','-I','-B',source/'packages/tools/cachy-asahi-fish-done/check-module.py',
        '--source','/usr/share/cachy-asahi/fish-done','--output',ordinary/'old18'],ordinary),100)
    old=read_json(ordinary/'old18/receipt.json')
    C.need(old['status']=='PASS' and old['machine']=='aarch64' and set(old['cases'])==set(OLD18) and
        old['wrapper_sha256']==done['payload']['usr/share/cachy-asahi/fish-done/opt-in.fish']['sha256'] and
        old['runtime_sha256']==done['payload']['usr/share/cachy-asahi/fish-done/done.fish']['sha256'],'all18 installed controls required')
    C.need(not ordinary_processes(),'old18 ordinary child/process remains')
    report['old18']=dict(status=old['status'],cases=18,receipt_sha256=C.digest(ordinary/'old18/receipt.json'))
    timeout_raw=C.read(ordinary/'old18/transport-timeout/notifications.jsonl')
    timeout_rows=[json.loads(line) for line in timeout_raw.splitlines()]
    C.need(len(timeout_rows)==1 and type(timeout_rows[0]['pid']) is int and timeout_rows[0]['pid']>0,
        'one original named timeout process required')
    timeout_pid=timeout_rows[0]['pid'];C.need(not Path('/proc',str(timeout_pid)).exists(),'timed-out named process remains')
    report['timeout_pid_proof']=dict(pid=timeout_pid,absent=True,raw_sha256=sha(timeout_raw))
    background=old['cases']['background']['proofs']
    C.need(any('Failed (7)' in row['argv'][6] for row in background) and
        any('Failed (143)' in row['argv'][6] for row in background),'actual background exit7/SIGTERM143 proofs required')
    staged=stage_trial_sources(data,lock);inputs=rebase_inputs(data,BUILT,ordinary,lock,staged)
    command(alarm_command(['/usr/bin/python','-I','-B',staged/'delivery/run.py','--inputs',inputs,
        '--inputs-sha256',C.digest(inputs),'--work-dir',ordinary/'work','--package-context','alpm-installed'],ordinary),210)
    replay=C.load(data/'delivery/replay.py','unchanged_real_manager_replay')
    result=read_json(ordinary/'work/result.json');report['real_manager_replay']=replay.validate(result)
    outer=read_json(ordinary/'work/outer.json')
    C.need(result['native_arch']=={'name':'aarch64','elf_machine':183} and result['package_context']=='alpm-installed'
        and outer['exit']==0 and outer['process_group_absent'] is True,'actual native installed12case context required')
    C.need(not ordinary_processes(),'real-manager ordinary child/process remains')
    report['real_manager']=dict(cases=12,notifications=4,receipt_sha256=C.digest(ordinary/'work/result.json'),outer_sha256=C.digest(ordinary/'work/outer.json'))
    C.need(run.installed(command,done)==report['installed_payload'],'installed payload changed after cases')
    before=snapshot(ordinary);command(pacman+['-R',done['name']])
    C.need(command(['/usr/bin/pacman','-Q'])==base and all(not os.path.lexists('/'+name) for name in done['payload']),
        'exact574 removal restoration required');command(['/usr/bin/pacman','-Dk'])
    C.need(snapshot(ordinary)==before and {name:snapshot(name) for name in PROTECTED}==protected,
        'removal changed ordinary files or protected configuration/platform')
    observations.append(dict(phase='remove',inventory=expected,protected_preserved=True,ordinary_before=before,ordinary_after=snapshot(ordinary)))
    C.save(OUT/'alpm-observations.json',observations)
    report.update(status='PASS_NATIVE_INSTALLED_REAL_MANAGER_12_AND_OLD18',protected_preserved=True,
        ordinary_absent=True,base_restored_sha256=sha(base.encode()),trust='UNSIGNED_LOCAL_TEST_PACKAGE_ONLY')

def execute(source,phase):
    guard(phase);C.verify(source)
    C.need(OUT.is_dir() and {p.name for p in OUT.iterdir()}<={'command.json','stdout','stderr'} and
        all(p.is_file() and not p.is_symlink() for p in OUT.iterdir()),'fresh explicit writable output required')
    C.need(not ordinary_processes(),'preexisting ordinary process refused')
    command=Commands(OUT)
    report=dict(status='FAIL_NATIVE_REAL_MANAGER_CONSUMER',phase=phase,machine='aarch64',ordinary_uid=ALARM,
        ordinary_absent=False,page_size=os.sysconf('SC_PAGE_SIZE'),errors=[],hardware='NOT_RUN',release='NOT_ADMITTED')
    try:(build if phase=='build' else trial)(source,command,report)
    except BaseException as error:report['errors'].append(type(error).__name__+': '+str(error))
    finally:
        report['commands']=command.rows;report['adopted_reaping']=[r for row in command.rows for r in row.get('adopted_reaping',[])]+drain_adopted()
        report['remaining_ordinary_processes']=ordinary_processes();report['ordinary_absent']=not report['remaining_ordinary_processes']
        if not report['ordinary_absent']:
            report['errors'].append('ordinary process remains; outer owned-container retirement required')
            report['status']='FAIL_NATIVE_REAL_MANAGER_CONSUMER'
        C.save(OUT/'orphan-reaping.json',dict(adopted=report['adopted_reaping'],remaining=report['remaining_ordinary_processes']))
        if phase=='trial':
            try:trial_export(OUT/'ordinary',not report['errors'])
            except BaseException as error:
                report['errors'].append('export '+type(error).__name__+': '+str(error));report['status']='FAIL_NATIVE_REAL_MANAGER_CONSUMER'
        try:finish_export(phase)
        except BaseException as error:
            report['errors'].append('final export '+type(error).__name__+': '+str(error));report['status']='FAIL_NATIVE_REAL_MANAGER_CONSUMER'
        C.save(OUT/'report.json',report)
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--phase',choices=('build','trial'),required=True);args=parser.parse_args()
    value=execute(C.safe(args.source.absolute()),args.phase)
    print(json.dumps(dict(status=value['status'],errors=value['errors'])));raise SystemExit(not value['status'].startswith('PASS_'))
