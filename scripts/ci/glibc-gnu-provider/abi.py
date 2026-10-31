#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Static AArch64 public symbol/version compatibility against owned574 libc."""
import argparse,hashlib,json,os,re,selectors,signal,subprocess,time
from pathlib import Path

LIBRARIES=('ld-linux-aarch64.so.1','libc.so.6','libm.so.6','libresolv.so.2','libdl.so.2','libpthread.so.0','librt.so.1','libutil.so.1','libanl.so.1','libBrokenLocale.so.1','libthread_db.so.1')

def symbols(text):
    result=set()
    for line in text.splitlines():
        fields=line.split()
        if len(fields)<8 or fields[3] not in ('FUNC','OBJECT','IFUNC','TLS') or fields[4] not in ('GLOBAL','WEAK') or fields[5] not in ('DEFAULT','PROTECTED') or fields[6]=='UND':continue
        name=fields[7]
        if '@GLIBC_' in name and '@GLIBC_PRIVATE' not in name:result.add((name,fields[3],fields[4],fields[5],fields[2] if fields[3] in ('OBJECT','TLS') else None))
    if not result:raise ValueError('public versioned symbols absent')
    return result

def readelf(path,option):
    process=subprocess.Popen(['/usr/bin/readelf',option,'--wide',str(path)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             env=dict(PATH='/usr/bin:/bin',LC_ALL='C'),start_new_session=True)
    outputs=[bytearray(),bytearray()];deadline=time.monotonic()+30
    try:
        with selectors.DefaultSelector() as selector:
            for index,stream in enumerate((process.stdout,process.stderr)):
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,index)
            while selector.get_map():
                if time.monotonic()>=deadline:raise ValueError('readelf deadline')
                for key,_ in selector.select(min(0.1,max(0,deadline-time.monotonic()))):
                    data=os.read(key.fd,65536)
                    if not data:selector.unregister(key.fileobj);continue
                    index=key.data;outputs[index].extend(data)
                    if len(outputs[index])>(8*1024**2 if index==0 else 65536):raise ValueError('readelf output bound')
        if process.wait(timeout=max(0.01,deadline-time.monotonic())):raise ValueError('readelf failed')
        return outputs[0].decode('utf-8','strict')
    finally:
        if process.poll() is None:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
        process.stdout.close();process.stderr.close()


def compare(stage):
    if os.getenv('CACHY_ASAHI_GLIBC_BUILD')!='1' or os.uname().machine!='aarch64':raise ValueError('owned native ABI stage required')
    rows=[]
    for name in LIBRARIES:
        base=Path('/usr/lib')/name;candidate=Path(stage)/'usr/lib'/name
        if not base.is_file() or not candidate.is_file():raise ValueError('required ABI library absent: '+name)
        header=readelf(candidate,'--file-header')
        if not all(s in header for s in ('ELF64','little endian','AArch64')):raise ValueError('candidate ELF ABI differs')
        old=symbols(readelf(base,'--dyn-syms'));new=symbols(readelf(candidate,'--dyn-syms'));missing=sorted(old-new)
        rows.append(dict(library=name,baseline_symbols=len(old),candidate_symbols=len(new),missing=missing,
                         baseline_set_sha256=hashlib.sha256(repr(sorted(old)).encode()).hexdigest(),
                         candidate_set_sha256=hashlib.sha256(repr(sorted(new)).encode()).hexdigest()))
    return dict(schema_version=1,status='PASS_STATIC_PUBLIC_ABI' if all(not r['missing'] for r in rows) else 'FAIL_STATIC_PUBLIC_ABI',libraries=rows,
                scope='declared public dynsym name/type/binding/visibility/exact version-defaultness and OBJECT/TLS size only; runtime smoke separate',hardware='NOT RUN')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--stage',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();value=compare(args.stage);args.output.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n');raise SystemExit(value['status']!='PASS_STATIC_PUBLIC_ABI')
