#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile separate normal-interpreter clients inside owned574; never run them."""
import argparse,hashlib,importlib.util,json,os,platform,shutil,stat,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import provider_stage

HERE=Path(__file__).resolve().parent
SMOKE='e10336aef200731c7dd4b06546b718e095c1ecf7718e4a25fa57d6bbed6270a6'
SOURCES={'abi_smoke.c','exec_child.c','probe.c','probe.h','plugin.c','runner.py'}
BINARIES={'smoke-normal':'smoke','exec-child':'exec-child','plugin.so':'plugin.so'}
INTERPRETERS={'/lib/ld-linux-aarch64.so.1','/usr/lib/ld-linux-aarch64.so.1'}


def need(ok,why):
    if not ok:raise ValueError(why)


def data(path,cap=4*1024**2):
    need(not any(p.is_symlink() for p in (path,*path.parents)), 'ordinary normal-client input required')
    info=path.stat();need(stat.S_ISREG(info.st_mode) and info.st_size<=cap,'bounded normal-client file required')
    raw=path.read_bytes();need(len(raw)<=cap,'normal-client byte cap');return raw


def identity(path):
    raw=data(path);return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def policy():
    value=json.loads(data(HERE/'normal-client-policy.json',65536))
    need(value.get('status')=='BOUND_EXACT_NORMAL_CHILD_EXEC_SOURCE_PATCH' and
         value.get('runtime_manifest_sha256')==SMOKE and
         value.get('patch',{}).get('path')=='normal-child-exec.patch',
         'pending exact lifecycle normal-child source patch')
    need(identity(HERE/'normal-child-exec.patch')=={k:value['patch'][k] for k in ('bytes','sha256')},
         'normal-child patch bytes differ')
    return value


def interpreter(raw):
    provider_stage.elf(raw)  # AArch64, bounded tables and 16K load alignment.
    phoff=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54);found=[]
    for i in range(count):
        row=struct.unpack_from('<IIQQQQQQ',raw,phoff+i*size)
        if row[0]==3:
            need(0<row[5]<=256 and row[2]+row[5]<=len(raw),'bounded PT_INTERP segment required')
            value=raw[row[2]:row[2]+row[5]]
            need(0<len(value)<=256 and value.endswith(b'\0') and b'\0' not in value[:-1], 'one bounded PT_INTERP string required')
            found.append(value[:-1].decode('ascii'))
    need(len(found)<=1,'one normal PT_INTERP required');return found[0] if found else None


def validate(report,work,source_files):
    declared=policy()
    need(report['status']=='PASS_COMPILED_NORMAL_INTERPRETER_CLIENTS_NOT_EXECUTED' and
         report['policy_sha256']==identity(HERE/'normal-client-policy.json')['sha256'] and
         report['runtime_manifest_sha256']==SMOKE and len(report['commands'])==13 and
         all(r['exit_code']==0 and r['group_absence_verified'] is True for r in report['commands']) and
         report['source_patch_command']['exit_code']==0 and report['source_patch_command']['group_absence_verified'] is True and
         set(report['original_sources'])==set(report['sources'])==SOURCES and
         report['original_sources']=={n:source_files[n] for n in SOURCES} and
         report['sources']['abi_smoke.c']==declared['patched_abi_smoke'] and
         all(report['sources'][n]==report['original_sources'][n] for n in SOURCES-{'abi_smoke.c'}) and
         report['bootstrap_headers'] and set(report['compiled_files'])==set(BINARIES),
         'complete attributable normal-client compilation required')
    need(report['source_patch_tool']['bytes']>0 and len(report['source_patch_tool']['sha256'])==64,
         'actual normal-child patch tool identity required')
    need(set(report['toolchain'])=={'gcc','cc1','collect2','as','ld','version'} and
         all(report['toolchain'][n]['bytes']>0 and len(report['toolchain'][n]['sha256'])==64
             for n in ('gcc','cc1','collect2','as','ld')),
         'actual normal-client compiler/tool identities required')
    for name,row in report['compiled_files'].items():
        path=work/'bin'/name;raw=data(path)
        need(row['bytes']==len(raw) and row['sha256']==hashlib.sha256(raw).hexdigest() and
             row['elf_machine']==183 and row['artifact']=='bin/'+name,
             'normal-client artifact/compile identity differs')
        expected=None if name=='plugin.so' else row['interpreter']
        need(interpreter(raw)==expected and
             (name=='plugin.so' or expected in INTERPRETERS), 'normal client must use system PT_INTERP')
    return report


def compile_clients(runtime,work):
    need(os.environ.get('CACHY_ASAHI_GLIBC_BUILD')=='1' and platform.machine()=='aarch64' and
         os.getuid()==os.geteuid()>0 and not any(n.startswith('LD_') for n in os.environ),
         'owned native normal-client compile-only environment required')
    declared=policy()
    need(not work.exists() and runtime.is_dir(),'fresh normal-client workspace required')
    manifest=json.loads(data(runtime/'source-manifest.json',65536))
    need(identity(runtime/'source-manifest.json')['sha256']==SMOKE and SOURCES<=set(manifest['files']),
         'unchanged owned-runtime source manifest required')
    original={n:identity(runtime/n) for n in SOURCES}
    need(original=={n:manifest['files'][n] for n in SOURCES},'unchanged original runtime sources required')
    work.mkdir(mode=0o700);source=work/'src';source.mkdir();build=work/'build';build.mkdir();(work/'bin').mkdir()
    for name in SOURCES:shutil.copyfile(runtime/name,source/name)
    spec=importlib.util.spec_from_file_location('provider_normal_compile',runtime/'runner.py')
    driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver);driver.HERE=source
    env=dict(driver.ENV,HOME=str(work),TMPDIR=str(work))
    argv=['/usr/bin/patch','-Np1','--batch','--fuzz=0','--forward','-i',str(HERE/'normal-child-exec.patch')]
    patch_row,out,err,failure=driver.run_command(argv,source,env,30)
    (work/'patch.stdout').write_bytes(out);(work/'patch.stderr').write_bytes(err)
    need(failure is None and patch_row['exit_code']==0 and patch_row['group_absence_verified'] is True,'exact normal-child source patch failed')
    sources={n:identity(source/n) for n in SOURCES}
    need(sources['abi_smoke.c']==declared['patched_abi_smoke'] and
         all(sources[n]==original[n] for n in SOURCES-{'abi_smoke.c'}), 'only reviewed abi_smoke normal-child edit permitted')
    report=dict(status='FAIL',commands=[],original_sources=original,sources=sources,
                runtime_manifest_sha256=SMOKE,policy_sha256=identity(HERE/'normal-client-policy.json')['sha256'],
                source_patch_command=patch_row,source_patch_tool=driver.identity(Path('/usr/bin/patch')),
                scope='compile only; installed parent/child mappings and cases are a separate lifecycle gate',hardware='NOT RUN')
    report['toolchain'],binaries,report['bootstrap_headers']=driver.compile_suite(driver.Commands(build,report),build,None)
    report['compiled_files']={}
    for name,old in BINARIES.items():
        row=binaries[str(build/old)];destination=work/'bin'/name;shutil.move(build/old,destination)
        report['compiled_files'][name]=dict(row,artifact='bin/'+name,interpreter=interpreter(data(destination)))
    need(original=={n:identity(runtime/n) for n in SOURCES},'original runtime source changed')
    report['status']='PASS_COMPILED_NORMAL_INTERPRETER_CLIENTS_NOT_EXECUTED';validate(report,work,manifest['files'])
    (work/'receipt.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,required=True);parser.add_argument('--workspace',type=Path,required=True)
    args=parser.parse_args();print(compile_clients(args.runtime,args.workspace)['status'])
