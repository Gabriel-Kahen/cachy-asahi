# SPDX-License-Identifier: MIT
"""One explicit candidate-loader invocation inside the marked generic16K guest."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys


def need(ok,why):
    if not ok:raise ValueError(why)


def read(path,cap=64*1024**2):
    path=Path(path);info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and
        not info.st_mode&0o022 and info.st_size<=cap,'protected captured guest file required')
    raw=path.read_bytes();need(len(raw)<=cap,'guest input cap');return raw


def load(path):
    spec=importlib.util.spec_from_file_location('unchanged_glibc_runtime',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def owned_absent():
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal() or int(path.name)==os.getpid():continue
        try:rows=(path/'status').read_text().splitlines()
        except FileNotFoundError:continue
        uid=next(row.split()[1:] for row in rows if row.startswith('Uid:'))
        need('23001' not in uid,'owned runtime process remains')
    return True


def preserved(manifest):
    for name,row in manifest['files'].items():
        path=Path('/')/name;raw=read(path)
        need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'] and
             stat.S_IMODE(path.stat().st_mode)==row['mode'],'captured payload changed: '+name)
    return True


def run(nonce,release):
    need(re.fullmatch('[0-9a-f]{32}',nonce) and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and
         os.uname().release==release and os.sysconf('SC_PAGE_SIZE')==16384 and
         'glibc16k=1' in Path('/proc/cmdline').read_text().split(),'marked actual generic16K guest required')
    manifest=json.loads(read('/payload.json',1024**2));preserved(manifest)
    driver=load('/runtime/runner.py')
    compile_report=json.loads(read('/compile.json',1024**2))
    need(compile_report['status']=='COMPILED_ONCE_NOT_EXECUTED' and len(compile_report['commands'])==13 and
         all(r['exit_code']==0 and r['group_absence_verified'] for r in compile_report['commands']),'native13-command compile receipt')
    spec=driver.inputs(Path('/runtime-inputs.json'))
    before=driver.runtime_inventory(spec)
    binaries={}
    for name,row in compile_report['compiled_files'].items():
        path=Path('/work/clients')/name;actual=driver.identity(path)
        need(actual['sha256']==row['sha256'] and actual['bytes']==row['bytes'] and row['elf_machine']==183,'compiled client bytes changed')
        binaries[str(path)]=dict(actual,elf_machine=183)
    need(set(compile_report['compiled_files'])=={'smoke','exec-child','plugin.so'},'exact three precompiled clients')
    source_before={name:driver.identity(driver.HERE/name) for name in driver.SOURCES}
    work=Path('/tmp/glibc16k');work.mkdir(mode=0o700);os.chown(work,23001,23001)
    os.setgroups([]);os.setgid(23001);os.setuid(23001)
    need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==23001 and os.getgroups()==[],'ordinary fixture identity required')
    owned_absent()
    report=dict(compile_report,status='FAIL',scope='PRIVATE_LOADER_GNU243CAA1_3_GENERIC16K_ONLY',architecture=os.uname().machine,
        kernel=release,page_size=os.sysconf('SC_PAGE_SIZE'),uid=os.getuid(),gid=os.getgid(),groups=os.getgroups(),
        hardware='NOT_RUN',performance='NOT_MEASURED',installation='NOT_RUN',security='NO_CREDIT',release='NOT_ADMITTED')
    env=dict(driver.ENV,HOME=str(work),TMPDIR=str(work),GCONV_PATH=str(spec['gconv']),LOCPATH=str(spec['locale']))
    libraries=':'.join(map(str,spec['libraries']));commands=driver.Commands(work,report)
    out=commands.call([spec['roles']['loader'],'--inhibit-cache','--library-path',libraries,'/work/clients/smoke',
        spec['roles']['loader'],libraries,'/work/clients/plugin.so','/work/clients/exec-child',work],env,60)
    records=[json.loads(line) for line in out.splitlines()]
    verified,result=driver.validate_runtime(records,spec,before,binaries)
    need(result['page_size']==16384,'candidate runtime did not observe16K')
    need(driver.runtime_inventory(spec)==before,'candidate runtime tree changed')
    need({name:driver.identity(driver.HERE/name) for name in driver.SOURCES}==source_before,'unchanged runtime source modified')
    need(owned_absent(),'runtime process remained')
    report.update(status='PASS_PRIVATE_GLIBC_GENERIC16K_RUNTIME',runtime=result,cases=sorted(driver.CASES),
        runtime_files={name:row for name,row in verified.items()},runtime_records=records,
        owned_processes_absent=True,payload_preserved=preserved(manifest),candidate_preserved=True,sources_preserved=True)
    need(len(report['commands'])==14,'exact combined13+1 command receipt required')
    raw=(json.dumps(report,sort_keys=True,separators=(',',':'))+'\n').encode();need(len(raw)<=512*1024,'guest receipt UART cap')
    print('GLIBC16K REPORT '+nonce+' '+base64.b64encode(raw).decode(),flush=True)


if __name__=='__main__':
    try:run(*sys.argv[1:])
    except BaseException as error:
        diagnostics={}
        for suffix in ('stdout','stderr'):
            path=Path('/tmp/glibc16k/command-14.'+suffix)
            if path.is_file() and not path.is_symlink():
                info=path.stat()
                if info.st_uid==23001 and info.st_size<=262144:
                    raw=path.read_bytes();diagnostics[suffix]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),tail_base64=base64.b64encode(raw[-2048:]).decode())
        if diagnostics:print('GLIBC16K-DIAGNOSTIC '+json.dumps(diagnostics,sort_keys=True),flush=True)
        print('GLIBC16K ERROR '+type(error).__name__+' '+str(error)[:200],flush=True);raise
