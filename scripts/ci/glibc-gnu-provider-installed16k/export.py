#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only debugfs readback after QEMU group retirement; no host filesystem mount."""
import os
import json
import hashlib
import resource
import stat
from pathlib import Path
import re
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

def diagnostic_metadata(text,cap):
    C.need(type(text) is str and len(text.encode())<=65536,'bounded debugfs stat')
    kind=re.search(r'\bType:\s+(\S+)',text);size=re.search(r'\bSize:\s+(\d+)',text);links=re.search(r'\bLinks:\s+(\d+)',text)
    C.need(kind is not None and kind[1]=='regular' and size is not None and links is not None and int(links[1])==1,'fixed ordinary singlelink diagnostic receipt')
    C.need(0<int(size[1])<=cap,'bounded original diagnostic bytes');return int(size[1])

def diagnostic_projection(raw):
    # No map, command argv, paths, keys, raw payload, or arbitrary exception object.
    value=C.decode(raw);C.need(type(value) is dict,'original worker report object');out={}
    status=value.get('status');out['original_status']=status if status in ('FAIL','PASS_GENERIC_ARM_SYSTEM_PROVIDER_LIFECYCLE') else 'UNKNOWN_OR_UNEXPECTED'
    error=value.get('error_type');out['error_type']=error if type(error) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,127}',error) else None
    error=value.get('error')
    if type(error) is str:
        encoded=error.encode('utf8');out['error_bytes']=len(encoded);out['error_sha256']=hashlib.sha256(encoded).hexdigest()
    commands=value.get('commands');out['recorded_commands']=len(commands) if type(commands) is list and len(commands)<=256 else None
    cases=value.get('cases');out['cases']={}
    if type(cases) is dict:
        for name in ('pristine','modified'):
            if type(cases.get(name)) is not dict:continue
            case=cases[name];status=case.get('status');row=dict(original_status=status if status in ('PASS_NORMAL_DISPOSABLE_PROVIDER_SEQUENCE','FAIL') else 'UNFINISHED_OR_UNRECORDED')
            failures=case.get('root_observation_failures')
            if type(failures) is dict:
                selected={}
                for phase in ('source-before','clone','before574','precommit-refused','provider574','reinstalled574','held574','source-after'):
                    item=failures.get(name+'-'+phase)
                    if type(item) is not dict:continue
                    counts=item.get('unsupported_counts')
                    if type(counts) is dict and len(counts)<=64 and all(type(k) is str and re.fullmatch('[a-z][a-z0-9-]{0,95}',k) and type(n) is int and 0<=n<=500000 for k,n in counts.items()) and type(item.get('complete')) is bool:selected[phase]=dict(complete=item['complete'],unsupported_counts=counts)
                row['observation_failures']=selected
            out['cases'][name]=row
    return out

def failure_capture():
    selection=C.decode(C.read('/selection/selection.json'));request=C.decode(C.read('/selection/failure-diagnostics.json'));owner=C.decode(C.read('/selection/owner.json',4*1024**2))
    C.need(set(request)=={'status','nonce','source_sha','qemu_command_index'} and request['status']=='FIXED_READONLY_DIAGNOSTICS_AFTER_QEMU_ABSENCE' and request['nonce']==selection['nonce']==owner['token'] and request['source_sha']==selection['source_sha'] and re.fullmatch('[0-9a-f]{32}',request['nonce']) and re.fullmatch('[0-9a-f]{40}',request['source_sha']),'exact owned source/nonce diagnostic request')
    number=request['qemu_command_index'];C.need(type(number) is int and 0<=number<len(owner['commands']),'one recorded QEMU command');row=owner['commands'][number]
    C.need(row['argv'][0]=='/usr/bin/qemu-system-aarch64' and row['group_absence_verified'] is True and row['time_limit']==10800 and row['output_limit']==16*1024**2,'diagnostic read only after original QEMU group absence')
    disk=Path('/disks/volume.raw');info=disk.lstat();C.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=24*C.GIB,'original bounded ordinary readonly data disk')
    result=dict(status='FIXED_READONLY_FAILURE_FACTS_NO_ACCEPTANCE',nonce=request['nonce'],source_sha=request['source_sha'],QEMU_group_absence_verified=True,acceptance='FORBIDDEN_DIAGNOSTIC_ONLY',files={})
    private=Path('/tmp/gnu-installed16k-diagnostic');C.need(not private.exists() and not private.is_symlink(),'fresh private raw readback directory');private.mkdir(mode=0o700);uncertain=False
    runtime=C.load('original_diagnostic_supervisor',Path('/source/scripts/ci/glibc-owned-runtime/runner.py'))
    for name,cap in (('result.json',8*1024**2),('pristine-guest-progress.log',65536)):
        destination=private/name;C.need(not destination.exists() and not destination.is_symlink(),'fresh temporary diagnostic readback');entry=dict(status='MISSING_PARTIAL_OR_UNREADABLE_NO_AUTHORITY');result['files'][name]=entry
        def command(operation):
            nonlocal uncertain
            script="import os,resource,sys;cap=int(sys.argv[1]);resource.setrlimit(resource.RLIMIT_FSIZE,(cap,cap));os.execv('/usr/bin/debugfs',['/usr/bin/debugfs','-R',sys.argv[2],sys.argv[3]])"
            observed,stdout,stderr,error=runtime.run_command(['/usr/bin/python3','-I','-B','-c',script,str(cap),operation,str(disk)],Path('/tmp'),dict(PATH='/usr/bin:/bin',HOME='/tmp',LANG='C',LC_ALL='C'),15,65536)
            if observed['group_absence_verified'] is not True:uncertain=True
            C.need(error is None and observed['exit_code']==0 and observed['group_absence_verified'] is True,'bounded readonly debugfs command and group retirement');return stdout.decode('utf8',errors='strict')
        try:
            before=command('stat /out/'+name);size=diagnostic_metadata(before,cap);command('dump /out/'+name+' '+str(destination));raw=C.read(destination,cap);C.need(len(raw)==size and command('stat /out/'+name)==before,'stable original readonly diagnostic receipt');entry.update(raw_bytes=len(raw),raw_sha256=C.sha(raw))
            if name=='result.json':entry['projection']=diagnostic_projection(raw)
            else:
                guest=C.load('trusted_progress_schema',Path(__file__).with_name('guest.py'));entry['progress']=guest.progress_value(raw,selection)
            entry['status']='READ_ORIGINAL_FIXED_RECEIPT_DIAGNOSTIC_ONLY'
        except Exception as error:entry['failure_type']=type(error).__name__ # Never serialize exception objects/messages.
        finally:
            if destination.exists() and not uncertain:C.need(destination.is_file() and not destination.is_symlink() and destination.stat().st_nlink==1,'own diagnostic temp only');destination.unlink()
        if uncertain:result['tool_retirement']='UNKNOWN_NO_AUTHORITY';break
    C.need(len(json.dumps(result,sort_keys=True,allow_nan=False).encode())<=96*1024,'bounded public failure facts');target=Path('/out/failure-diagnostics.json');C.need(not target.exists(),'fresh public diagnostic');C.save(target,result);os.chown(target,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))
    C.need(not uncertain,'diagnostic tool retirement unknown; original outer actor cleanup required')

def export_ids(environment,actual):
    raw=[environment.get(n) for n in ('OUTPUT_UID','OUTPUT_GID')]
    C.need(all(type(n) is str and n.isdecimal() and str(int(n))==n and 0<int(n)<2**31 for n in raw),'finite original ordinary export UID/GID')
    uid,gid=map(int,raw);C.need(actual==(uid,uid,gid,gid),'exact ordinary export real/effective UID/GID');return uid,gid

def export_identity():
    uid,gid=export_ids(os.environ,(os.getuid(),os.geteuid(),os.getgid(),os.getegid()));owner=C.decode(C.read('/selection/owner.json',4*1024**2));selection=C.decode(C.read('/selection/selection.json'))
    C.need(type(owner.get('output_uid')) is int and type(owner.get('output_gid')) is int and (owner['output_uid'],owner['output_gid'])==(uid,gid) and owner['token']==selection['nonce'] and owner['source_sha']==selection['source_sha'],'original retained owner/source/nonce export identity')
    for path,directory in ((Path('/out'),True),(Path('/disks'),True),(Path('/disks/volume.raw'),False)):
        info=path.lstat();C.need(not path.is_symlink() and info.st_uid==uid and info.st_gid==gid and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink==1),'original caller-owned export paths')
        C.need(stat.S_IMODE(info.st_mode) in ((0o700,0o755) if directory else (0o600,0o644)),'fixed caller-readable ordinary export modes')
    return uid,gid

def main():
    C.need(Path('/.dockerenv').is_file() and os.uname().machine=='aarch64' and os.environ.get('CAA_INSTALLED16K_PREPARE')=='1','owned offline export container only')
    export_identity()
    C.need({p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'offline export')
    if Path('/selection/failure-diagnostics.json').exists():failure_capture();return
    files=C.decode(C.read('/selection/guest-files.json'));C.need(len(files)<=256 and sum(r['bytes'] for r in files.values())<=512*1024**2,'bounded export manifest')
    target=Path('/out/guest');C.need(not target.exists(),'fresh public readback');target.mkdir(mode=0o700)
    for name,pin in files.items():
        C.need(re.fullmatch(r'(result\.json|isolation\.json|command-[0-9]{3}\.(stdout|stderr)|(pristine|modified)-[a-z0-9-]+(-root\.json\.gz|\.log))',name),'closed debugfs filename')
        result=subprocess.run(['/usr/bin/debugfs','-R','dump /out/'+name+' '+str(target/name),'/disks/volume.raw'],stdin=subprocess.DEVNULL,capture_output=True,timeout=120)
        C.need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=65536,'debugfs command failed');C.ref(target,dict(path=name,**pin),64*1024**2)
        os.chown(target/name,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))
    os.chown(target,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))

if __name__=='__main__':main()
