# SPDX-License-Identifier: MIT
"""Read-only native574 byte capture; product payloads are unpacked, never installed."""
import argparse
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
import contract as C
import catalog
s=None


def capture(root,image,source_commit):
    global s
    C.verify_source(root);s=C.load('management16k_original_support',root/'scripts/ci/tools-generic16k/support.py')
    old=C.load('management16k_original_capture',root/'scripts/ci/tools-generic16k/capture.py')
    old.guard();C.need(old.readonly('/inputs',Path('/proc/self/mountinfo').read_text()),'readonly native packet mount required')
    before=old.inventory();packet=C.packet(Path('/inputs'))
    checks=C.load('management16k_package_checks',root/'scripts/checks/package_checks.py')
    products,origins=C.package_payload(Path('/inputs'),packet,checks)
    generic=s.load(root,'scripts/virtual/generic16k/fixture.py');files={};rows={};total=0;elfs={}
    def add(name,data,mode,origin):
        nonlocal total
        C.relative(name);C.need(name not in files and len(files)<4096 and len(data)<=64*1024**2,'payload member bound/path')
        total+=len(data);C.need(total<=256*1024**2,'payload byte bound')
        files[name]=(mode,data);rows[name]=dict(bytes=len(data),mode=mode,sha256=C.sha(data),origin=origin)
    for name,(mode,data) in products.items():add(name,data,mode,'actual native archive/'+origins[name])
    fixture,authority=catalog.create(root,products)
    add('fixtures/catalog.tar',fixture,0o444,'fresh isolated public signed TEST fixture')
    add('guest.py',C.read(C.HERE/'guest.py'),0o644,'source-pinned management guest')
    add('signature_observer.py',C.read(C.HERE/'signature_observer.py'),0o644,'failure-only public TEST signature observer')
    add('original_guest.py',C.read(root/'scripts/ci/tools-generic16k/guest.py'),0o644,'unchanged bounded command/preservation APIs')
    old.import_only('management16k_guest_import_only',C.HERE/'guest.py')
    stdlib=Path(sysconfig.get_path('stdlib')).resolve(strict=True)
    s.need(stdlib.is_relative_to(Path('/usr/lib')),'native Python stdlib path differs')
    for directory,children,names in os.walk(stdlib):
        children[:]=[n for n in children if n not in ('site-packages','__pycache__')]
        for name in sorted(names):
            if not name.endswith('.py'):continue
            path=Path(directory)/name;s.need(not path.is_symlink(),'stdlib source alias refused')
            add(str(path).lstrip('/'),s.read(path,2*1024**2),0o644,'native574 Python stdlib')
    pending=[('usr/bin/'+name,Path('/usr/bin')/name) for name in C.TOOLS]
    pending.append(('usr/lib/libalpm.so.16',Path('/usr/lib/libalpm.so.16')))
    def native_tree(directory):
        base=Path(directory);s.need(base.is_dir() and not base.is_symlink(),'native shell resources absent: '+directory)
        for path in sorted(base.rglob('*')):
            if path.is_dir():continue
            real=path.resolve(strict=True);s.need(real.is_relative_to(Path('/usr')),'native shell resource escape')
            name=str(path).lstrip('/');data=s.read(real,64*1024**2)
            if data.startswith(b'\x7fELF'):pending.append((name,real))
            else:add(name,data,0o644,'native574 shell resource/'+str(real))
    if Path('/usr/share/fish/functions').exists():native_tree('/usr/share/fish/functions')
    native_tree('/usr/share/zsh/functions')
    native_tree('/usr/lib/zsh')
    if Path('/usr/share/fish/config.fish').exists():add('usr/share/fish/config.fish',s.read('/usr/share/fish/config.fish'),0o644,'native574 Fish resource')
    for name in ('/usr/share/terminfo/x/xterm',):
        path=Path(name);real=path.resolve(strict=True)
        s.need(real.is_relative_to(Path('/usr')),'native shell data escape')
        add(name.lstrip('/'),s.read(real),0o644,'native574 shell data/'+str(real))
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
    s.need(old.inventory()==before,'native574 inventory changed')
    receipt=dict(schema_version=1,status='CAPTURED_NATIVE_MANAGEMENT_PRIVATE_RUNTIME',image_id=image,inventory_sha256=before,
        architecture=platform.machine(),capture_page_size=os.sysconf('SC_PAGE_SIZE'),source_commit=source_commit,
        packet_sha256=C.sha(C.checked(Path('/inputs'),C.policy()['packet_index'])),native_inputs=packet['packages'],files=rows,elf=elfs,
        fixture_authority=authority,fixture_archive_sha256=C.sha(fixture),package_registration=C.SCOPE,GUI='NOT_RUN',hardware='NOT_RUN')
    archive=Path('/out/payload.tar')
    with tarfile.open(archive,'w') as stream:
        for name,(mode,data) in sorted(files.items()):
            entry=tarfile.TarInfo(name);entry.size=len(data);entry.mode=mode;entry.uid=entry.gid=entry.mtime=0
            stream.addfile(entry,io.BytesIO(data))
    receipt['archive']=dict(bytes=archive.stat().st_size,sha256=s.sha(s.read(archive,270*1024**2)))
    s.save('/out/capture.json',receipt,1024**2)
    return dict(status=receipt['status'],files=len(files),bytes=total)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image-id',required=True);parser.add_argument('--source-commit',required=True);args=parser.parse_args()
    C.need(re.fullmatch('sha256:[0-9a-f]{64}',args.image_id),'immutable image required')
    C.need(re.fullmatch('[0-9a-f]{40}',args.source_commit),'exact source commit required')
    print(json.dumps(capture(Path('/repo'),args.image_id,args.source_commit),sort_keys=True))
