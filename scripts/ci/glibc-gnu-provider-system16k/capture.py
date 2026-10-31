#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reuse accepted normal clients, compile only the existing static page probe."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import sysconfig
import tarfile
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as c


def inventory():
    import subprocess
    row=subprocess.run(['/usr/bin/pacman','-Q'],capture_output=True,env=dict(PATH='/usr/bin:/bin',LC_ALL='C'),timeout=20)
    c.need(row.returncode==0 and not row.stderr and len(row.stdout)<=65536,'native inventory query')
    raw=('\n'.join(sorted(row.stdout.decode().splitlines()))+'\n').encode();c.need(raw==c.read('/expected.lock',65536) and c.sha(raw)==c.LOCK,'exact unchanged574 inventory');return c.sha(raw)


def capture(root,image,source):
    c.need(os.environ.get('CACHY_GLIBC_SYSTEM16K_CAPTURE')=='1' and os.uname().machine=='aarch64' and os.getuid()==os.geteuid()>0 and not any(k.startswith('LD_') for k in os.environ),'ordinary marked native capture required')
    status=Path('/proc/self/status').read_text();c.need(re.search(r'^CapEff:\s*0+$',status,re.M) and re.search(r'^NoNewPrivs:\s*1$',status,re.M),'no capabilities/no-new-privileges')
    mounts=Path('/proc/self/mountinfo').read_text().splitlines()
    for name in ('/','/source','/repo','/runtime','/system','/inputs','/expected.lock'):
        rows=[(len(p[4]),p[5].split(',')) for line in mounts if len(p:=line.split())>=10 and (name==p[4] or name.startswith(p[4].rstrip('/')+'/'))]
        c.need(rows and 'ro' in max(rows)[1],'readonly capture source required: '+name)
    c.need({p.name for p in Path('/sys/class/net').iterdir()}<={'lo'} and not Path('/dev/snd').exists(),'offline/nonhardware capture')
    c.check_source(root);index,_=c.pair(Path('/inputs'));before=inventory();generic=c.load(root,'scripts/virtual/generic16k/fixture.py');driver=c.load(root,'scripts/ci/glibc-owned-runtime/runner.py')
    probe=Path('/work/page-probe');argv=['/usr/bin/gcc','-nostdlib','-static','-O2','-fno-stack-protector','-fno-builtin','-Wl,-z,max-page-size=16384','-Wl,-e,_start',str(root/'scripts/virtual/generic16k/smoke.c'),'-o',str(probe)]
    command,out,err,failure=driver.run_command(argv,Path('/work'),dict(driver.ENV,HOME='/work',TMPDIR='/work'),60)
    Path('/work/page-probe.stdout').write_bytes(out);Path('/work/page-probe.stderr').write_bytes(err)
    c.need(failure is None and command['exit_code']==0 and command['group_absence_verified'],'unchanged static page-probe compile')
    files={};rows={};elfs={};total=0
    def add(name,raw,mode,origin):
        nonlocal total
        c.relative(name);c.need(name not in files and len(files)<4096 and len(raw)<=64*1024**2,'capture member bound');total+=len(raw);c.need(total<=256*1024**2,'capture total bytes')
        files[name]=(mode,raw);rows[name]=dict(bytes=len(raw),mode=mode,sha256=c.sha(raw),origin=origin)
        if raw.startswith(b'\x7fELF'):elfs[name]=dict(c.aligned(raw,generic),scope='candidate' if name.startswith('system/') else 'bootstrap')
    for path in sorted(Path('/system').rglob('*')):
        if path.is_file():add(str(path).lstrip('/'),c.read(path,64*1024**2),stat.S_IMODE(path.stat().st_mode),'accepted conventional provider runtime')
    for name,ref in index['probes'].items():add('system/'+c.FIXTURE+'/'+name,c.read(c.ref(Path('/inputs'),ref),4*1024**2),0o644 if name=='plugin.so' else 0o755,'accepted precompiled normal client')
    add('system/'+c.FIXTURE+'/latin1',b'A\xe9',0o644,'private conversion fixture')
    add('recovery/held-glibc.pkg.tar.xz',c.read(c.ref(Path('/inputs'),index['held'],256*1024**2),256*1024**2),0o444,'exact unchanged held rollback archive')
    add('runtime/runner.py',c.read(driver.HERE/'runner.py'),0o644,'unchanged process supervisor')
    add('runtime/provider-validator.py',c.validator_source(root).encode(),0o644,'exact lifecycle validator with page4096 to16384 only')
    for name in ('guest.py','enter-system.py'):add(name,c.read(c.HERE/name),0o644,'fixed system-root wrapper')
    add('smoke',c.read(probe),0o755,'unchanged page probe')
    normal={side:c.decode(c.read(c.ref(Path('/inputs'),c.NORMAL_REFS[side]),2*1024**2)) for side in ('a','b')}
    add('normal-compile.json',(json.dumps(normal,sort_keys=True)+'\n').encode(),0o644,'reused original native compiler receipts, NOT current commands')
    held=generic.Archive(c.ref(Path('/inputs'),index['held'],256*1024**2));bootstrap_roles={}
    try:
        for role,name in c.ROLES.items():
            raw=c.read((Path('/')/name).resolve(strict=True),64*1024**2);c.need(raw==held.read(name)[1],'held outer role differs: '+role);bootstrap_roles[role]=dict(path=name,sha256=c.sha(raw))
    finally:held.tar.close()
    spec=importlib.util.spec_from_file_location('system_guest_imports_only',c.HERE/'guest.py');guest=importlib.util.module_from_spec(spec);spec.loader.exec_module(guest)
    stdlib=Path(sysconfig.get_path('stdlib')).resolve(strict=True);c.need(stdlib.is_relative_to(Path('/usr/lib')),'bootstrap stdlib location')
    for directory,children,names in os.walk(stdlib):
        children[:]=[n for n in children if n not in ('site-packages','__pycache__')]
        for name in sorted(names):
            if name.endswith('.py'):
                path=Path(directory)/name;c.need(not path.is_symlink(),'stdlib alias');add(str(path).lstrip('/'),c.read(path,2*1024**2),0o644,'held574 Python source')
    pending=[('usr/bin/'+n,Path('/usr/bin')/n) for n in c.TOOLS]+[(n,Path('/')/n) for n in c.ROLES.values()]
    for module in list(sys.modules.values()):
        value=getattr(module,'__file__',None)
        if value and str(value).endswith('.so'):
            path=Path(value).resolve(strict=True)
            if path.is_relative_to(stdlib):pending.append((str(path).lstrip('/'),path))
    processed=set()
    while pending:
        name,path=pending.pop()
        if name in processed:continue
        processed.add(name);real=path.resolve(strict=True);c.need(real.is_relative_to(Path('/usr')),'bootstrap ELF root')
        if name not in files:add(name,c.read(real,64*1024**2),stat.S_IMODE(real.stat().st_mode)&0o755,'unchanged held574 ELF')
        row=elfs[name]
        if row['interpreter']:pending.append((row['interpreter'].lstrip('/'),Path(row['interpreter'])))
        for lib in row['needed']:
            found=next((Path(p)/lib for p in ('/usr/lib','/lib') if (Path(p)/lib).is_file()),None);c.need(found is not None,'held bootstrap dependency absent');pending.append((str(found).lstrip('/'),found))
    c.elf_closure(elfs,files);c.need(inventory()==before,'held inventory changed')
    report=dict(status='CAPTURED_CONVENTIONAL_PROVIDER_AND_PRECOMPILED_NORMAL_CLIENTS',image_id=image,source_commit=source,inventory_sha256=before,pair_sha256=c.PACKAGE_SHA,files=rows,elf=elfs,normal_compile=normal,page_probe_compile=command,bootstrap_roles=bootstrap_roles,capture_page_size=os.sysconf('SC_PAGE_SIZE'),scope='DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION')
    archive=Path('/work/payload.tar')
    with tarfile.open(archive,'w') as stream:
        for name,(mode,raw) in sorted(files.items()):
            info=tarfile.TarInfo(name);info.uid=info.gid=info.mtime=0;info.mode=mode;info.size=len(raw);stream.addfile(info,io.BytesIO(raw))
    report['archive']=dict(bytes=archive.stat().st_size,sha256=c.sha(c.read(archive,270*1024**2)));c.save('/work/capture.json',report,1024**2);return report['status']


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',required=True);p.add_argument('--source',required=True);a=p.parse_args();print(capture(Path('/repo'),a.image,a.source))
