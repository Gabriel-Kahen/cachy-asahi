#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned-container glibc runtime smoke. No installation or container creation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import time

HERE=Path(__file__).resolve().parent
SOURCES=('abi_smoke.c','exec_child.c','probe.c','probe.h','plugin.c','runner.py')
CASES={'allocation','dlopen_dlsym','pthread_tls_join','utf8_iconv_locale','numeric_math',
       'fd_stat_clock_random','numeric_address_lookup','fork_exec_wait'}
PROVIDERS={'malloc','pthread_create','iconv_open','snprintf','getaddrinfo','clock_gettime','getrandom','cos'}
ENV={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TZ':'UTC'}
LIMIT=262144


def need(value,code):
    if not value:raise ValueError(code)


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def identity(path):
    info=path.stat();need(stat.S_ISREG(info.st_mode),'regular-file-required')
    return {'sha256':sha(path),'bytes':info.st_size,'inode':info.st_ino,
            'device_major':os.major(info.st_dev),'device_minor':os.minor(info.st_dev)}


def safe(path):
    for value in (path,path.resolve(strict=True)):
        need(value.is_absolute() and not any(c.isspace() or c in ':\\' for c in str(value)),'absolute-simple-path-required')
    return path.resolve(strict=True)


def stage_path(root,name,directory=False):
    need(type(name) is str and name and not Path(name).is_absolute() and
         all(p not in ('','.','..') for p in name.split('/')),'stage-relative-path-required')
    path=safe(root/name);need(path.is_relative_to(root),'candidate-alias-escapes-stage')
    need(path.is_dir() if directory else path.is_file(),'candidate-path-type')
    return path


def inputs(path):
    need(path.stat().st_size<=65536,'input-bound');raw=path.read_bytes();value=json.loads(raw)
    need(set(value)=={'schema_version','stage_root','loader','libc','libm','library_directories','gconv_directory','locale_directory'} and
         value['schema_version']==1,'input-schema')
    root=safe(Path(value['stage_root']));need(root.is_dir(),'stage-directory-required')
    roles={}
    for role in ('loader','libc','libm'):
        row=value[role];need(set(row)=={'path','sha256'} and re.fullmatch('[0-9a-f]{64}',row['sha256']),'candidate-hash-required')
        file=stage_path(root,row['path']);need(sha(file)==row['sha256'],'candidate-input-hash-differs');roles[role]=file
    need(len(set(roles.values()))==3,'distinct-runtime-files-required')
    dirs=value['library_directories'];need(type(dirs) is list and 1<=len(dirs)<=4,'library-directory-bound')
    libraries=[stage_path(root,d,True) for d in dirs]
    need(all(roles[r].parent in libraries for r in ('libc','libm')),'candidate-libraries-outside-search-path')
    return {'root':root,'roles':roles,'libraries':libraries,'gconv':stage_path(root,value['gconv_directory'],True),
            'locale':stage_path(root,value['locale_directory'],True),'input_sha256':hashlib.sha256(raw).hexdigest()}


def runtime_inventory(spec):
    result={};total=0
    for directory in set(spec['libraries']+[spec['gconv'],spec['locale']]):
        for path in directory.rglob('*'):
            need(len(result)<8192,'runtime-file-count-bound')
            resolved=path.resolve(strict=True);need(resolved.is_relative_to(spec['root']),'runtime-tree-alias-escapes')
            if resolved.is_dir():continue
            if str(resolved) in result:continue
            row=identity(resolved);total+=row['bytes'];need(total<=2*1024**3,'runtime-tree-byte-bound')
            result[str(resolved)]=row
    for path in spec['roles'].values():result[str(path)]=identity(path)
    return result


def run_command(argv,work,env,seconds=30,cap=LIMIT):
    """Drain finite pipes; keep child unreaped until the final group signals."""
    proc=subprocess.Popen(list(map(str,argv)),cwd=work,env=env,stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    selector=None;parts=[bytearray(),bytearray()];failure=None
    started=time.monotonic();code=None;group_absent=False
    try:
        selector=selectors.DefaultSelector()
        for n,stream in enumerate((proc.stdout,proc.stderr)):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,n)
        while selector.get_map() or os.waitid(os.P_PID,proc.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
            need(time.monotonic()-started<seconds,'command-time-limit')
            for key,_ in selector.select(.05):
                data=os.read(key.fd,8192)
                if not data:selector.unregister(key.fileobj);continue
                need(sum(map(len,parts))+len(data)<=cap,'command-output-limit')
                parts[key.data].extend(data)
    except BaseException as error:failure=error
    finally:
        blocked=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
        try:
            for sig in (signal.SIGTERM,signal.SIGKILL):
                try:os.killpg(proc.pid,sig)
                except ProcessLookupError:pass
            code=proc.wait(timeout=5)
            try:os.killpg(proc.pid,0)
            except ProcessLookupError:group_absent=True
        finally:
            if selector:selector.close()
            proc.stdout.close();proc.stderr.close()
            try:signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
            except BaseException as error:failure=error
    row={'argv':list(map(str,argv)),'exit_code':code,'seconds':round(time.monotonic()-started,6),
         'time_limit':seconds,'output_limit':cap,'group_absence_verified':group_absent,
         'stdout_bytes':len(parts[0]),'stdout_sha256':hashlib.sha256(parts[0]).hexdigest(),
         'stderr_bytes':len(parts[1]),'stderr_sha256':hashlib.sha256(parts[1]).hexdigest()}
    return row,bytes(parts[0]),bytes(parts[1]),failure


class Commands:
    def __init__(self,work,report):self.work=work;self.report=report
    def call(self,argv,env=None,seconds=30):
        row,out,err,failure=run_command(argv,self.work,env or dict(ENV,HOME=str(self.work),TMPDIR=str(self.work)),seconds)
        n=len(self.report['commands']);self.report['commands'].append(row)
        (self.work/('command-%02d.stdout'%n)).write_bytes(out);(self.work/('command-%02d.stderr'%n)).write_bytes(err)
        if failure:raise failure
        need(row['exit_code']==0 and row['group_absence_verified'],'command-failed-or-session-remains')
        return out


def compile_suite(commands,work,spec=None):
    compiler=safe(Path('/usr/bin/gcc'));toolchain={'gcc':dict(path=str(compiler),**identity(compiler))}
    version=commands.call([compiler,'--version']).decode();toolchain['version']=version.splitlines()[0][:256]
    for tool in ('cc1','collect2','as','ld'):
        answer=commands.call([compiler,'-print-prog-name='+tool]).decode().strip()
        path=safe(Path(answer) if Path(answer).is_absolute() else Path(shutil.which(answer,path=ENV['PATH']) or '/missing'))
        toolchain[tool]=dict(path=str(path),**identity(path))
    flags=['-std=c11','-O2','-g0','-fno-builtin','-Wall','-Wextra','-Werror']
    binaries={};headers={}
    for name,sources,extra in (('plugin.so',['plugin.c'],['-shared','-fPIC']),
                              ('smoke',['abi_smoke.c','probe.c'],['-fPIE','-pie']),
                              ('exec-child',['exec_child.c','probe.c'],['-fPIE','-pie'])):
        binary=work/name;objects=[]
        for source in sources:
            obj=work/(name+'-'+source+'.o');dependency=work/(name+'-'+source+'.d')
            commands.call([compiler,*flags,*[f for f in extra if f in ('-fPIC','-fPIE')],
                           '-MD','-MF',dependency,'-c',HERE/source,'-o',obj])
            objects.append(obj)
            text=dependency.read_text().replace('\\\n',' ')
            for item in text.split(':',1)[1].split():
                path=safe(Path(item))
                need(path.stat().st_size<=2*1024**2 and (str(path) in headers or len(headers)<512),'bootstrap-header-bound')
                headers[str(path)]=identity(path)
        args=[compiler,*flags,*extra,*objects,'-o',binary,'-Wl,-z,max-page-size=16384']
        if name!='plugin.so':
            args+=['-pthread','-ldl','-Wl,--no-as-needed','-lm']
            if spec:args+=['-Wl,--dynamic-linker,'+str(spec['roles']['loader'])]
        commands.call(args)
        data=binary.read_bytes();need(data[:5]==b'\x7fELF\x02' and len(data)<=4*1024**2,'compiled-ELF-bound')
        row=identity(binary);row['elf_machine']=struct.unpack_from('<H',data,18)[0]
        if spec:need(row['elf_machine']==183,'compiled-not-aarch64')
        binaries[str(binary)]=row
    return toolchain,binaries,headers


def validate_runtime(records,spec,before,binaries):
    need(all(type(r) is dict for r in records),'runtime-record-shape')
    tests=[r for r in records if r.get('kind')=='test']
    need(len(tests)==9 and {r.get('name') for r in tests if r.get('process')=='parent'}==CASES and
         [r.get('name') for r in tests if r.get('process')=='child']==['exec_child'] and
         all(r.get('status')=='PASS' for r in tests),'complete-runtime-cases-required')
    results=[r for r in records if r.get('kind')=='result']
    need(len(results)==1 and results[0].get('status')=='PASS' and results[0].get('cases')==8 and
         type(results[0].get('page_size')) is int and results[0]['page_size']>0,'runtime-result')
    identities=[r for r in records if r.get('kind')=='identity']
    need(len(identities)==2 and {r.get('process') for r in identities}=={'parent','child'} and len(records)==12,'runtime-identity-set')
    known=before|binaries;verified={}
    for group in identities:
        need(group['executable'] in (str(spec['roles']['loader']),str(Path(next(iter(binaries))).parent/('smoke' if group['process']=='parent' else 'exec-child'))),'runtime-executable')
        for field in ('objects','mapped_files'):
            need(type(group[field]) is list and 1<=len(group[field])<=128,'mapping-count-bound')
            for row in group[field]:
                path=Path(row['path']).resolve(strict=True);key=str(path)
                need(key in known,'foreign-runtime-file-or-host-fallback')
                actual=identity(path);expected=known[key]
                need(actual=={k:expected[k] for k in actual} and
                     all(row[k]==actual[k] for k in ('inode','device_major','device_minor')),'runtime-file-hash-or-map-drift')
                verified[key]=actual
        paths={str(Path(row['path']).resolve(strict=True)) for row in group['objects']}
        need(all(str(p) in paths for p in spec['roles'].values()),'candidate-libc-loader-libm-not-all-loaded')
        if group['process']=='parent':
            need(any(Path(p).name=='plugin.so' for p in paths),'plugin-not-mapped')
            mapped={Path(row['path']).resolve(strict=True) for row in group['mapped_files']}
            need(any(p.is_relative_to(spec['gconv']) for p in mapped),'candidate-gconv-mapping-required')
            need(any(p.is_relative_to(spec['locale']) for p in mapped),'candidate-locale-mapping-required')
        providers=group['providers'];need(len(providers)==8 and {p['symbol'] for p in providers}==PROVIDERS,'symbol-provider-set')
        for provider in providers:
            desired=spec['roles']['libm' if provider['symbol']=='cos' else 'libc']
            need(Path(provider['path']).resolve(strict=True)==desired,'symbol-resolved-to-wrong-runtime')
    return verified,results[0]


def native_guard():
    need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0,'native-unprivileged-aarch64-required')
    need((Path('/.dockerenv').is_file() or Path('/run/.containerenv').is_file()) and
         os.environ.get('CACHY_ASAHI_GLIBC_RUNTIME_SMOKE')=='1','explicit-owned-container-required')
    need({p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'offline-container-required')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs',type=Path);parser.add_argument('--workspace',type=Path,required=True)
    modes=parser.add_mutually_exclusive_group();modes.add_argument('--execute',action='store_true');modes.add_argument('--host-compile-only',action='store_true')
    args=parser.parse_args()
    need(args.inputs is not None or args.host_compile_only,'explicit-runtime-inputs-required')
    need(not (args.host_compile_only and args.inputs),'host-compile-does-not-use-candidate')
    work=args.workspace.absolute();parent=safe(work.parent)
    need(not work.exists() and not work.is_symlink() and parent/work.name==work and
         work!=HERE and not HERE.is_relative_to(work),'fresh-workspace-required')
    work.mkdir(mode=0o700);need(work.stat().st_uid==os.getuid() and stat.S_IMODE(work.stat().st_mode)==0o700,'private-workspace-required')
    report={'schema_version':1,'status':'FAIL','mode':'HOST_COMPILE_ONLY' if args.host_compile_only else 'NATIVE_EXECUTE' if args.execute else 'INPUT_VALIDATION_ONLY',
            'commands':[],'hardware':'NOT RUN','performance':'NOT RUN','upstream_glibc_tests':'NOT REPLACED',
            'compile_headers':'recorded bootstrap headers, not candidate header ABI acceptance','host_architecture':platform.machine(),
            'sources':{name:identity(HERE/name) for name in SOURCES}}
    try:
        spec=inputs(safe(args.inputs)) if args.inputs else None
        if spec:
            need(not work.is_relative_to(spec['root']) and not spec['root'].is_relative_to(work),'stage-and-workspace-must-be-separate')
            before=runtime_inventory(spec);report['input_sha256']=spec['input_sha256']
            report['candidate_roles']={role:dict(path=path.relative_to(spec['root']).as_posix(),**identity(path)) for role,path in spec['roles'].items()}
        if args.execute:native_guard()
        if args.host_compile_only or args.execute:
            commands=Commands(work,report)
            report['toolchain'],binaries,report['bootstrap_headers']=compile_suite(commands,work,spec)
            report['compiled_files']={Path(path).name:row for path,row in binaries.items()}
        if args.execute:
            env=dict(ENV,HOME=str(work),TMPDIR=str(work),GCONV_PATH=str(spec['gconv']),LOCPATH=str(spec['locale']))
            libraries=':'.join(map(str,spec['libraries']))
            out=commands.call([spec['roles']['loader'],'--inhibit-cache','--library-path',libraries,work/'smoke',
                spec['roles']['loader'],libraries,work/'plugin.so',work/'exec-child',work],env,60)
            records=[json.loads(line) for line in out.splitlines()]
            verified,result=validate_runtime(records,spec,before,binaries)
            need(runtime_inventory(spec)==before,'candidate-tree-mutated-during-smoke')
            report['runtime_files']={('candidate/'+Path(path).relative_to(spec['root']).as_posix() if Path(path).is_relative_to(spec['root'])
                else 'workspace/'+Path(path).name):row for path,row in verified.items()}
            report['runtime']=result;report['cases']=sorted(CASES);report['status']='PASS_OWNED_CANDIDATE_GLIBC_RUNTIME_SMOKE'
        else:report['status']='HOST_COMPILE_ONLY_NOT_EXECUTED' if args.host_compile_only else 'INPUTS_VALIDATED_NOT_EXECUTED'
        need(all(identity(HERE/name)==row for name,row in report['sources'].items()),'source-mutated-during-check')
    except BaseException as error:
        report['status']='FAIL'
        report['error_kind']=type(error).__name__
        if isinstance(error,ValueError):report['error_code']=str(error)[:160]
    finally:
        raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();need(len(raw)<=2*1024**2,'receipt-bound')
        (work/'receipt.json').write_bytes(raw)
    print(json.dumps({'status':report['status'],'receipt':str(work/'receipt.json')}))
    return int(report['status']=='FAIL')


def interrupted(signum,frame):
    raise KeyboardInterrupt


if __name__=='__main__':
    for signum in (signal.SIGINT,signal.SIGTERM):signal.signal(signum,interrupted)
    raise SystemExit(main())
