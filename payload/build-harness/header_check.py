#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned native candidate-C-header compile check; never executes a candidate."""
import argparse,hashlib,json,os,shutil,subprocess
from pathlib import Path

HERE=Path(__file__).resolve().parent

def need(ok,message):
    if not ok:raise ValueError(message)

def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def command(argv):
    row=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                       env=dict(PATH='/usr/bin:/bin',LC_ALL='C',TZ='UTC'),timeout=60)
    need(len(row.stdout)+len(row.stderr)<=1024**2,'header compiler output bound')
    need(row.returncode==0,'header compiler failed: '+row.stderr.decode('utf-8','replace')[-1024:]);return row.stdout

def dependencies(raw,roots):
    need(len(raw)<=2*1024**2,'header dependency byte bound')
    # All supported absolute paths have no whitespace or make escaping. The
    # dependency target is fixed; any escaped/unexpected shape refuses.
    text=raw.replace('\\\n',' ');need(':' in text,'header dependency target absent')
    names=text.split(':',1)[1].split();need(1<=len(names)<=8192,'header dependency count bound')
    result={}
    for name in names:
        path=Path(name);need(path.is_absolute() and '\\' not in name,'absolute unescaped header dependency required')
        path=path.resolve(strict=True);need(path.is_file() and any(path.is_relative_to(root) for root in roots),'foreign/bootstrap libc header fallback')
        result[str(path)]=dict(bytes=path.stat().st_size,sha256=sha(path))
    need(sum(row['bytes'] for row in result.values())<=128*1024**2,'header dependency content bound');return result

def check(stage,work):
    need(os.getenv('CACHY_ASAHI_GLIBC_BUILD')=='1' and os.uname().machine=='aarch64' and os.getuid()!=0,'owned native header check required')
    stage=stage.resolve(strict=True);include=(stage/'usr/include').resolve(strict=True)
    need(include.is_relative_to(stage) and include.is_dir() and not work.exists(),'fresh candidate header paths required')
    work.mkdir(mode=0o700);kernel=work/'kernel';kernel.mkdir()
    total=0;count=0
    for name in ('linux','asm','asm-generic'):
        source=Path('/usr/include')/name;source=source.resolve(strict=True);need(source.is_dir(),'bootstrap kernel API headers required')
        for p in source.rglob('*'):
            count+=1;need(count<=8192,'kernel header count bound')
            resolved=p.resolve(strict=True);need(resolved.is_relative_to(source),'kernel header alias escapes source')
            if resolved.is_file():total+=resolved.stat().st_size;need(total<=128*1024**2,'kernel header byte bound')
        shutil.copytree(source,kernel/name,symlinks=False)
    builtin=Path(command(['/usr/bin/gcc','-print-file-name=include']).decode().strip()).resolve(strict=True)
    need(builtin.is_relative_to(Path('/usr/lib/gcc')) and builtin.is_dir(),'recorded compiler builtin headers required')
    source=work/'header_probe.c';shutil.copyfile(HERE/'header_probe.c',source)
    argv=['/usr/bin/gcc','-std=gnu2x','-O2','-Wall','-Wextra','-Werror','-fmax-errors=8','-nostdinc',
          '-isystem',include,'-isystem',builtin,'-isystem',kernel,'-fsyntax-only','-MD','-MF',work/'headers.d',source]
    command(argv)
    deps=dependencies((work/'headers.d').read_text(),(include,builtin,kernel,work))
    need(str(include/'features.h') in deps and any(p.startswith(str(include/'bits')+'/') for p in deps),'candidate features/bits headers not consumed')
    result=dict(schema_version=1,status='PASS_CANDIDATE_C_HEADERS_COMPILE_ONLY',candidate_include=str(include),
                bootstrap_libc_header_fallback=False,dependencies=deps,command=list(map(str,argv)),compiler_sha256=sha(Path('/usr/bin/gcc')),
                scope='declared C header surface compile; no C++/complete header ABI acceptance; no candidate execution')
    (work/'receipt.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');return result

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--stage',type=Path,required=True);parser.add_argument('--workspace',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(check(args.stage,args.workspace),sort_keys=True))
