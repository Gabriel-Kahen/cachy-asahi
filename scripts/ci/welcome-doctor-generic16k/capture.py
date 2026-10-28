# SPDX-License-Identifier: MIT
"""Read-only native574 byte capture; product payloads are unpacked, never installed."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import sysconfig
import tarfile
sys.path.insert(0,str(Path(__file__).resolve().parent))
import support as s


def readonly(path,mounts):
    rows=[]
    for line in mounts.splitlines():
        fields=line.split();s.need(len(fields)>=10 and ' - ' in line,'mountinfo shape')
        if path==fields[4] or path.startswith(fields[4].rstrip('/')+'/'):rows.append((len(fields[4]),fields[5].split(',')))
    return bool(rows) and 'ro' in max(rows)[1]


def guard():
    s.need(os.environ.get('CACHY_WELCOME16K_CAPTURE')=='1' and platform.machine()=='aarch64' and
           os.getuid()==os.geteuid()>0 and not any(k.startswith('LD_') for k in os.environ),'capture identity required')
    status=Path('/proc/self/status').read_text();mounts=Path('/proc/self/mountinfo').read_text()
    s.need(re.search(r'^CapEff:\s*0+$',status,re.M) and re.search(r'^NoNewPrivs:\s*1$',status,re.M),'capture privilege contract')
    s.need(all(readonly(p,mounts) for p in ('/','/source','/repo','/assets','/expected.lock','/var/lib/pacman')),
           'capture readonly mounts required')
    s.need({p.name for p in Path('/sys/class/net').iterdir()}<={'lo'} and not Path('/dev/snd').exists(),'capture offline required')
    s.need(Path('/out').is_dir() and not Path('/out').is_symlink(),'owned output required')


def inventory():
    row=subprocess.run(['/usr/bin/pacman','-Q'],env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},capture_output=True,timeout=20)
    s.need(row.returncode==0 and len(row.stdout)<=65536 and not row.stderr,'capture inventory command')
    lines=row.stdout.decode('ascii').splitlines();raw=('\n'.join(sorted(lines))+'\n').encode()
    s.need(len(lines)==len(set(lines))==574 and raw==s.read('/expected.lock',65536) and s.sha(raw)==s.LOCK,
           'exact574 inventory required');return s.sha(raw)


def import_only(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module


def capture(root,assets,image):
    guard();s.check_source(root);before=inventory();products=s.products(root,assets)
    generic=s.load(root,'scripts/virtual/generic16k/fixture.py');files={};rows={};total=0;elfs={}
    def add(name,data,mode,origin):
        nonlocal total
        s.need(name and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')) and
               name not in files and len(files)<4096 and len(data)<=64*1024**2,'payload member bound/path')
        total+=len(data);s.need(total<=256*1024**2,'payload byte bound')
        files[name]=(mode,data);rows[name]=dict(bytes=len(data),mode=mode,sha256=s.sha(data),origin=origin)
    for name,row in products.items():
        archive=assets/'packages'/(name+'-a')/row['archive'];seen=set()
        with tarfile.open(archive,'r:xz') as stream:
            for entry in stream:
                member=entry.name.removeprefix('./')
                if member not in row['payload']:continue
                expected=row['payload'][member]
                s.need(entry.isfile() and member not in seen and entry.size==expected['size'] and
                       entry.mode==expected['mode'],'product payload member differs')
                data=stream.extractfile(entry).read();s.need(s.sha(data)==expected['sha256'],'product payload bytes differ')
                add(member,data,entry.mode,'product/'+name);seen.add(member)
        s.need(seen==set(row['payload']),'complete exact product payload required')
    scratch=Path('/tmp/welcome16k-capture');scratch.mkdir(mode=0o700)
    doctor=scratch/'doctor.py';doctor.write_bytes(files['usr/bin/cachy-asahi-doctor'][1])
    import_only('welcome16k_doctor_import_only',doctor)  # Definitions/imports only; main is not called.
    import_only('welcome16k_guest_import_only',s.HERE/'guest.py')
    stdlib=Path(sysconfig.get_path('stdlib')).resolve(strict=True)
    s.need(stdlib.is_relative_to(Path('/usr/lib')),'native Python stdlib path differs')
    for directory,children,names in os.walk(stdlib):
        children[:]=[n for n in children if n not in ('site-packages','__pycache__')]
        for name in sorted(names):
            if not name.endswith('.py'):continue
            path=Path(directory)/name;s.need(not path.is_symlink(),'stdlib source alias refused')
            add(str(path).lstrip('/'),s.read(path,2*1024**2),0o644,'native574 Python stdlib')
    pending=[('usr/bin/'+name,Path('/usr/bin')/name) for name in ('bash','env','uname','getconf','mount','python3')]
    pending.append(('usr/bin/cachy-asahi-welcome',None))
    for module in list(sys.modules.values()):
        value=getattr(module,'__file__',None)
        if value and str(value).endswith('.so'):
            path=Path(value).resolve(strict=True)
            if path.is_relative_to(stdlib):pending.append((str(path).lstrip('/'),path))
    processed=set()
    while pending:
        name,path=pending.pop()
        if name in processed:continue
        processed.add(name)
        if name in files:data=files[name][1]
        else:
            resolved=path.resolve(strict=True);s.need(resolved.is_relative_to(Path('/usr')),'native ELF path outside/usr')
            data=s.read(resolved,64*1024**2);add(name,data,stat.S_IMODE(path.stat().st_mode)&0o755,str(resolved))
        interpreter,needed=s.aligned(data,generic);elfs[name]=dict(interpreter=interpreter,needed=needed)
        if interpreter:
            s.need(interpreter.startswith('/'),'absolute interpreter required');pending.append((interpreter.lstrip('/'),Path(interpreter)))
        for library in needed:
            source=next((Path(folder)/library for folder in ('/usr/lib','/lib') if (Path(folder)/library).is_file()),None)
            s.need(source is not None,'native574 ELF dependency missing: '+library);pending.append((str(source).lstrip('/'),source))
    for name,row in elfs.items():
        s.need(not row['interpreter'] or row['interpreter'].lstrip('/') in files,'closed interpreter missing')
        s.need(all(any(folder+lib in files for folder in ('usr/lib/','lib/')) for lib in row['needed']),'closed DT_NEEDED missing')
    add('guest.py',s.read(s.HERE/'guest.py'),0o644,'project original MIT guest script')
    s.need(inventory()==before,'native574 inventory changed')
    receipt=dict(schema_version=1,status='CAPTURED_UNPACKED_NATIVE574_PAYLOAD',image_id=image,inventory_sha256=before,
        architecture=platform.machine(),capture_page_size=os.sysconf('SC_PAGE_SIZE'),
        product_input_source=s.INPUT_SOURCE,index_sha256=s.INDEX,products=products,files=rows,elf=elfs,
        package_registration='NOT_INSTALLED_EXACT_PAYLOADS_UNPACKED_ONLY',GUI='NOT_RUN',hardware='NOT_RUN')
    archive=Path('/out/payload.tar')
    with tarfile.open(archive,'w') as stream:
        for name,(mode,data) in sorted(files.items()):
            entry=tarfile.TarInfo(name);entry.size=len(data);entry.mode=mode;entry.uid=entry.gid=entry.mtime=0
            stream.addfile(entry,io.BytesIO(data))
    receipt['archive']=dict(bytes=archive.stat().st_size,sha256=s.sha(s.read(archive,270*1024**2)))
    s.save('/out/capture.json',receipt,1024**2)
    return dict(status=receipt['status'],files=len(files),bytes=total)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image-id',required=True);args=parser.parse_args()
    s.need(re.fullmatch('sha256:[0-9a-f]{64}',args.image_id),'immutable image required')
    print(json.dumps(capture(Path('/repo'),Path('/assets'),args.image_id),sort_keys=True))
