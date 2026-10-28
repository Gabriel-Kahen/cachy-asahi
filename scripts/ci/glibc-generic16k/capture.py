#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile the accepted client sources once in owned574; never execute candidate code."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import sysconfig
import tarfile
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as c


def inventory():
    import subprocess
    result=subprocess.run(['/usr/bin/pacman','-Q'],env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},capture_output=True,timeout=20)
    c.need(result.returncode==0 and not result.stderr and len(result.stdout)<=65536,'native inventory query')
    raw=('\n'.join(sorted(result.stdout.decode().splitlines()))+'\n').encode()
    c.need(len(raw.splitlines())==574 and raw==c.read('/expected.lock',65536) and c.sha(raw)==c.LOCK,'exact574 inventory')
    return c.sha(raw)


def capture(root,image,source):
    c.need(os.environ.get('CACHY_GLIBC16K_CAPTURE')=='1' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and
           not any(k.startswith('LD_') for k in os.environ),'ordinary native capture required')
    state=Path('/proc/self/status').read_text();mounts=Path('/proc/self/mountinfo').read_text()
    c.need(re.search(r'^CapEff:\s*0+$',state,re.M) and re.search(r'^NoNewPrivs:\s*1$',state,re.M),'capture privilege contract')
    def readonly(name):
        rows=[(len(r[4]),r[5].split(',')) for line in mounts.splitlines() if len(r:=line.split())>=10 and
              (name==r[4] or name.startswith(r[4].rstrip('/')+'/'))]
        return bool(rows) and 'ro' in max(rows)[1]
    c.need(all(readonly(p) for p in ('/','/source','/repo','/runtime','/'+c.PREFIX,'/expected.lock','/var/lib/pacman')) and
           {p.name for p in Path('/sys/class/net').iterdir()}<={'lo'} and not Path('/dev/snd').exists(),'readonly offline capture required')
    c.check_source(root);before=inventory()
    driver=c.load(root,'scripts/ci/glibc-owned-runtime/runner.py')
    spec_path=Path('/work/inputs.json');c.save(spec_path,c.spec(),65536);spec=driver.inputs(spec_path)
    runtime_before=driver.runtime_inventory(spec)
    work=Path('/work/clients');work.mkdir(mode=0o700)
    report=dict(status='FAIL',commands=[],sources={name:driver.identity(driver.HERE/name) for name in driver.SOURCES},
                hardware='NOT_RUN',upstream_glibc_tests='ALREADY_ACCEPTED_NOT_RERUN',ABI='ALREADY_ACCEPTED_NOT_RERUN')
    commands=driver.Commands(work,report)
    report['toolchain'],binaries,report['bootstrap_headers']=driver.compile_suite(commands,work,spec)
    report['compiled_files']={Path(path).name:row for path,row in binaries.items()}
    c.need(driver.runtime_inventory(spec)==runtime_before,'private candidate changed during compilation')
    report['status']='COMPILED_ONCE_NOT_EXECUTED';c.compile_receipt(report)
    generic=c.load(root,'scripts/virtual/generic16k/fixture.py')
    probe=Path('/work/page-probe')
    argv=['/usr/bin/gcc','-nostdlib','-static','-O2','-fno-stack-protector','-fno-builtin','-Wl,-z,max-page-size=16384',
          '-Wl,-e,_start',str(root/'scripts/virtual/generic16k/smoke.c'),'-o',str(probe)]
    probe_row,out,err,failure=driver.run_command(argv,work,dict(driver.ENV,HOME=str(work),TMPDIR=str(work)),60)
    c.need(failure is None and probe_row['exit_code']==0 and probe_row['group_absence_verified'],'separate unchanged static page probe compile')
    report['page_probe_compile']=probe_row
    files={};rows={};elfs={};total=0
    def add(name,raw,mode,origin):
        nonlocal total
        c.relative(name);c.need(name not in files and len(files)<4096 and len(raw)<=64*1024**2,'capture member bound')
        total+=len(raw);c.need(total<=256*1024**2,'capture byte bound')
        files[name]=(mode,raw);rows[name]=dict(bytes=len(raw),sha256=c.sha(raw),mode=mode,origin=origin)
        if raw.startswith(b'\x7fELF'):elfs[name]=dict(c.aligned(raw,generic),scope='candidate' if name.startswith(c.PREFIX+'/') or name.startswith('work/clients/') else 'bootstrap')
    for directory in (Path('/'+c.PREFIX),):
        for path in sorted(directory.rglob('*')):
            if path.is_file():add(str(path).lstrip('/'),c.read(path,64*1024**2),stat.S_IMODE(path.stat().st_mode),'exact accepted private runtime')
    for name in driver.SOURCES:add('runtime/'+name,c.read(driver.HERE/name),0o644,'unchanged accepted runtime source')
    for name in c.CLIENTS:add('work/clients/'+name,c.read(work/name,4*1024**2),0o755,'compile-once client')
    add('smoke',c.read(probe),0o755,'unchanged freestanding page probe')
    add('runtime-inputs.json',(json.dumps(c.spec(),sort_keys=True)+'\n').encode(),0o644,'fixed private candidate role/data map')
    add('guest.py',c.read(c.HERE/'guest.py'),0o644,'new generic16K wrapper')
    add('compile.json',(json.dumps(report,sort_keys=True,indent=2)+'\n').encode(),0o644,'native13-command receipt')
    guest_spec=importlib.util.spec_from_file_location('glibc16k_guest_definitions_only',c.HERE/'guest.py')
    guest=importlib.util.module_from_spec(guest_spec);guest_spec.loader.exec_module(guest) # Definitions only; discover wrapper extension imports.
    stdlib=Path(sysconfig.get_path('stdlib')).resolve(strict=True)
    c.need(stdlib.is_relative_to(Path('/usr/lib')),'bootstrap stdlib path')
    for directory,children,names in os.walk(stdlib):
        children[:]=[n for n in children if n not in ('site-packages','__pycache__')]
        for name in sorted(names):
            if name.endswith('.py'):
                path=Path(directory)/name;c.need(not path.is_symlink(),'stdlib source alias');add(str(path).lstrip('/'),c.read(path,2*1024**2),0o644,'native574 Python source')
    pending=[('usr/bin/'+name,Path('/usr/bin')/name) for name in c.TOOLS]
    for module in list(sys.modules.values()):
        value=getattr(module,'__file__',None)
        if value and str(value).endswith('.so'):
            path=Path(value).resolve(strict=True)
            if path.is_relative_to(stdlib):pending.append((str(path).lstrip('/'),path))
    processed=set()
    while pending:
        name,path=pending.pop()
        if name in processed:continue
        processed.add(name);real=path.resolve(strict=True)
        c.need(real.is_relative_to(Path('/usr')),'bootstrap ELF outside/usr')
        if name not in files:add(name,c.read(real,64*1024**2),stat.S_IMODE(real.stat().st_mode)&0o755,'native574 ELF')
        row=elfs[name]
        if row['interpreter']:pending.append((row['interpreter'].lstrip('/'),Path(row['interpreter'])))
        for lib in row['needed']:
            found=next((Path(folder)/lib for folder in ('/usr/lib','/lib') if (Path(folder)/lib).is_file()),None)
            c.need(found is not None,'bootstrap DT_NEEDED absent: '+lib);pending.append((str(found).lstrip('/'),found))
    c.elf_closure(elfs,files)
    c.need(inventory()==before and driver.runtime_inventory(spec)==runtime_before,'native574/runtime changed')
    receipt=dict(status='CAPTURED_GLIBC_CLIENTS_NOT_EXECUTED',image_id=image,inventory_sha256=before,source_commit=source,
                 files=rows,elf=elfs,compile=report,pair_sha256=c.PACKAGE_SHA,capture_page_size=os.sysconf('SC_PAGE_SIZE'))
    archive=Path('/work/payload.tar')
    with tarfile.open(archive,'w') as stream:
        for name,(mode,raw) in sorted(files.items()):
            entry=tarfile.TarInfo(name);entry.mode=mode;entry.size=len(raw);entry.uid=entry.gid=entry.mtime=0;stream.addfile(entry,io.BytesIO(raw))
    receipt['archive']=dict(bytes=archive.stat().st_size,sha256=c.sha(c.read(archive,270*1024**2)))
    c.save('/work/capture.json',receipt,1024**2)
    return receipt['status']


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image',required=True);parser.add_argument('--source',required=True);args=parser.parse_args()
    print(capture(Path('/repo'),args.image,args.source))
