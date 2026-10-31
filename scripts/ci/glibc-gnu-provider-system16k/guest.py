# SPDX-License-Identifier: MIT
"""Held bootstrap supervises direct normal-interpreter clients in private /system."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import types


def need(ok,why):
    if not ok:raise ValueError(why)


def read(path,cap=64*1024**2):
    path=Path(path);info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and not info.st_mode&0o022 and info.st_size<=cap,'protected captured file required')
    raw=path.read_bytes();need(len(raw)<=cap,'guest byte cap');return raw


def load(path):
    spec=importlib.util.spec_from_file_location('system16k_supervisor',path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def preserved(manifest):
    for name,row in manifest['files'].items():
        path=Path('/')/name;raw=read(path);need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'] and stat.S_IMODE(path.stat().st_mode)==row['mode'],'captured bytes/mode changed: '+name)
    return True


def owned_absent():
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal() or int(path.name)==os.getpid():continue
        try:lines=(path/'status').read_text().splitlines()
        except FileNotFoundError:continue
        values=next(r.split()[1:] for r in lines if r.startswith('Uid:'));need('23001' not in values,'ordinary fixture descendant remains')
    return True


def run(nonce,release):
    need(re.fullmatch('[0-9a-f]{32}',nonce) and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and os.uname().release==release and os.sysconf('SC_PAGE_SIZE')==16384 and 'glibcsystem16k=1' in Path('/proc/cmdline').read_text().split(),'marked actual16K guest required')
    manifest=json.loads(read('/payload.json',1024**2));preserved(manifest);driver=load('/runtime/runner.py');root=Path('/system');fixture='tmp/provider-lifecycle';work=root/fixture/'run';work.mkdir(mode=0o700);os.chown(work,23001,23001)
    expected=dict(nodes={n.removeprefix('system/'):dict(type='file',sha256=r['sha256']) for n,r in manifest['files'].items() if n.startswith('system/')})
    def relative(name):need(name and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')),'closed runtime path');return name
    api=types.SimpleNamespace(need=need,sha=lambda raw:hashlib.sha256(raw).hexdigest(),read=read,relative=relative,ROLES={'loader':'usr/lib/ld-linux-aarch64.so.1','libc':'usr/lib/libc.so.6','libm':'usr/lib/libm.so.6'})
    namespace=dict(C=api,FIXTURE=fixture);exec(compile(read('/runtime/provider-validator.py'),'/runtime/provider-validator.py','exec'),namespace)
    roles=namespace['role_identities'](root,expected)
    report=dict(status='FAIL',commands=[],scope='DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION',architecture=os.uname().machine,kernel=release,page_size=os.sysconf('SC_PAGE_SIZE'),hardware='NOT_RUN',performance='NOT_MEASURED',security='NO_CREDIT',release='NOT_ADMITTED')
    commands=driver.Commands(Path('/tmp'),report);env=dict(driver.ENV,HOME='/tmp',TMPDIR='/tmp',PYTHONDONTWRITEBYTECODE='1')
    def inside(argv,seconds=30):return commands.call(['/usr/bin/python3','-I','-B','/enter-system.py',*argv],env,seconds)
    need(any(line.lower()=='c.utf8' for line in inside(['/usr/bin/locale','-a']).decode().splitlines()),'standard default locale directory unavailable')
    need(inside(['/usr/bin/iconv','-f','ISO-8859-1','-t','UTF-8','/'+fixture+'/latin1'])==b'A\xc3\xa9','default system gconv conversion differs')
    output=inside(['/'+fixture+'/smoke-normal',roles['loader']['path'],'/usr/lib','/'+fixture+'/plugin.so','/'+fixture+'/exec-child','/'+fixture+'/run'],60)
    records=[json.loads(line) for line in output.splitlines()];validated=namespace['validate_runtime'](records,root,roles,expected)
    identity=json.loads((work/'execution-identity.json').read_text());need(identity==dict(uid=23001,gid=23001,groups=[],program='/'+fixture+'/smoke-normal'),'actual pre-exec UID/GID/groups')
    verified=validated['verified_mappings']
    for name,row in verified.items():
        key='system/'+name.lstrip('/');need(key in manifest['files'] and manifest['files'][key]['sha256']==row['sha256'],'runtime mapped an uncaptured system file');row['bytes']=(root/name.lstrip('/')).stat().st_size
    need(owned_absent(),'ordinary descendant remains')
    held=all(hashlib.sha256(read('/'+r['path'])).hexdigest()==r['sha256'] for r in manifest['bootstrap_roles'].values());need(held,'intact held outer provider changed')
    report.update(status='PASS_CONVENTIONAL_GNU_SYSTEM_PATHS_GENERIC16K_RUNTIME',runtime=validated['result'],runtime_records=records,runtime_files=verified,roles=roles,cases=sorted(driver.CASES),uid=identity['uid'],gid=identity['gid'],groups=identity['groups'],normal_parent_and_child=True,owned_processes_absent=True,payload_preserved=preserved(manifest),held_preserved=held,normal_compile_receipts='REUSED_ORIGINAL_NOT_CURRENT_COMMANDS')
    raw=(json.dumps(report,sort_keys=True,separators=(',',':'))+'\n').encode();need(len(raw)<=512*1024,'guest UART receipt cap');print('SYSTEM16K REPORT '+nonce+' '+base64.b64encode(raw).decode(),flush=True)


if __name__=='__main__':
    try:run(*sys.argv[1:])
    except BaseException as error:
        diagnostics={}
        for number in (1,2,3):
            for suffix in ('stdout','stderr'):
                p=Path('/tmp')/('command-%02d.'%number+suffix)
                if p.is_file() and not p.is_symlink() and p.stat().st_size<=262144:
                    raw=p.read_bytes();diagnostics[str(number)+'.'+suffix]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),tail_base64=base64.b64encode(raw[-1024:]).decode())
        if diagnostics:print('SYSTEM16K-DIAGNOSTIC '+json.dumps(diagnostics,sort_keys=True),flush=True)
        print('SYSTEM16K ERROR '+type(error).__name__+' '+str(error)[:200],flush=True);raise
