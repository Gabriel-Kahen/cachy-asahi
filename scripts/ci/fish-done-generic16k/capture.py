# SPDX-License-Identifier: MIT
"""Read-only native574 byte capture; product payloads are unpacked, never installed."""
import argparse
import base64
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
    s.need(os.environ.get('CACHY_DONE16K_CAPTURE')=='1' and platform.machine()=='aarch64' and
           os.getuid()==os.geteuid()>0 and not any(k.startswith('LD_') for k in os.environ),'capture identity required')
    status=Path('/proc/self/status').read_text();mounts=Path('/proc/self/mountinfo').read_text()
    s.need(re.search(r'^CapEff:\s*0+$',status,re.M) and re.search(r'^NoNewPrivs:\s*1$',status,re.M),'capture privilege contract')
    s.need(all(readonly(p,mounts) for p in ('/','/source','/repo','/expected.lock','/var/lib/pacman')),
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


def compile_recorder(root,source_commit,supervisor):
    """Exactly one compiler child inside the already owned read-only capture container."""
    s.need(not Path('/out/notify-recorder').exists(),'fresh native recorder output required')
    compiler=Path('/usr/bin/cc').resolve(strict=True)
    s.need(compiler.is_relative_to(Path('/usr/bin')),'native compiler escape')
    binary=s.read(compiler,64*1024**2);source=s.read(s.HERE/'notify_recorder.c')
    build=dict(status='FAIL',compile_count=1,architecture=platform.machine(),source_commit=source_commit,
        source_sha256=s.sha(source),deadline_seconds=30,output_cap=131072,
        compiler=dict(path='/usr/bin/cc',resolved=str(compiler),bytes=len(binary),sha256=s.sha(binary)))
    try:
        row,out=supervisor.command(s.COMPILE,dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TMPDIR='/tmp'),seconds=30)
        build['command']=row
        s.need(not out and row['stderr_bytes']==0,'native recorder compiler must be silent')
        path=Path('/out/notify-recorder');info=path.lstat()
        s.need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and not path.is_symlink(),
            'owned compiler output required')
        raw=s.read(path,1024**2);build.update(status='BUILT_NATIVE_C_TEST_RECORDER',binary_sha256=s.sha(raw))
        return raw,build
    except supervisor.CommandFailure as error:
        build.update(command=error.row,error_type=type(error).__name__,reason=str(error)[:160],
            stdout_base64=base64.b64encode(error.stdout).decode(),stderr_base64=base64.b64encode(error.stderr).decode())
        raise
    finally:s.save('/out/recorder-build.json',build,262144)


def capture(root,image,source_commit):
    guard();s.check_source(root);before=inventory();products=s.products(root)
    generic=s.load(root,'scripts/virtual/generic16k/fixture.py');files={};rows={};total=0;elfs={}
    def add(name,data,mode,origin):
        nonlocal total
        s.need(name and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')) and
               name not in files and len(files)<4096 and len(data)<=64*1024**2,'payload member bound/path')
        total+=len(data);s.need(total<=256*1024**2,'payload byte bound')
        files[name]=(mode,data);rows[name]=dict(bytes=len(data),mode=mode,sha256=s.sha(data),origin=origin)
    for name,row in products.items():
        for member,expected in row['payload'].items():
            data=s.read(root/expected['source']);s.need(len(data)==expected['bytes'] and s.sha(data)==expected['sha256'],'mapped source bytes differ')
            add(member,data,expected['mode'],'source-payload/'+name)
    for member,row in s.mapping()['fixtures'].items():
        add(member,s.read(root/row['source']),row['mode'],'unchanged project PTY fixture/'+row['source'])
        if member.endswith('.py'):import_only('done16k_fixture_'+s.sha(member.encode())[:16],root/row['source'])
    supervisor=import_only('done16k_guest_import_only',s.HERE/'guest.py')
    recorder,build=compile_recorder(root,source_commit,supervisor)
    add(s.RECORDER,recorder,0o755,'native574 one bounded C test-recorder compilation')
    adapter=s.load(root,'scripts/ci/fish-done-generic16k/recorder_adapter.py')
    adapted=adapter.adapt(files['fixtures/done.py'][1])
    add(s.ADAPTED,adapted,0o644,'prepare-only adaptation; original fixture separately retained')
    stdlib=Path(sysconfig.get_path('stdlib')).resolve(strict=True)
    s.need(stdlib.is_relative_to(Path('/usr/lib')),'native Python stdlib path differs')
    for directory,children,names in os.walk(stdlib):
        children[:]=[n for n in children if n not in ('site-packages','__pycache__')]
        for name in sorted(names):
            if not name.endswith('.py'):continue
            path=Path(directory)/name;s.need(not path.is_symlink(),'stdlib source alias refused')
            add(str(path).lstrip('/'),s.read(path,2*1024**2),0o644,'native574 Python stdlib')
    pending=[('usr/bin/'+name,Path('/usr/bin')/name) for name in s.TOOLS]
    def native_tree(directory):
        base=Path(directory);s.need(base.is_dir() and not base.is_symlink(),'native shell resources absent: '+directory)
        for path in sorted(base.rglob('*')):
            if path.is_dir():continue
            real=path.resolve(strict=True);s.need(real.is_relative_to(Path('/usr')),'native shell resource escape')
            name=str(path).lstrip('/');data=s.read(real,64*1024**2)
            if data.startswith(b'\x7fELF'):pending.append((name,real))
            else:add(name,data,0o644,'native574 shell resource/'+str(real))
    if Path('/usr/share/fish/functions').exists():native_tree('/usr/share/fish/functions')
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
    pending.append((s.RECORDER,Path('/out/notify-recorder')))
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
        source_commit=source_commit,payload_map_sha256=s.MAP_SHA,products=products,files=rows,elf=elfs,
        package_registration='NOT_INSTALLED_EXACT_SOURCE_PAYLOADS_COPIED_ONLY',GUI='NOT_RUN',hardware='NOT_RUN')
    receipt['test_transport']=dict(kind='NATIVE_C_RECORDER_PREPARE_ONLY',product_change='NONE',
        original_fixture_execution='NOT_RUN_UNCHANGED_CAPTURED_ONLY',original_case_bodies=18,
        transport_timeout='UNCHANGED_2S_TERM_1S_KILL',adaptation='ONLY_PREPARE_RECORDER_SUBSTITUTED',
        original_fixture_sha256=rows['fixtures/done.py']['sha256'],adapted_fixture_sha256=rows[s.ADAPTED]['sha256'],
        recorder_source_sha256=rows[s.SOURCE]['sha256'],adapter_sha256=rows[s.ADAPTER]['sha256'],
        recorder_binary_sha256=rows[s.RECORDER]['sha256'],native_build=build)
    s.test_transport(receipt)
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
    s.need(re.fullmatch('sha256:[0-9a-f]{64}',args.image_id),'immutable image required')
    s.need(re.fullmatch('[0-9a-f]{40}',args.source_commit),'exact source commit required')
    print(json.dumps(capture(Path('/repo'),args.image_id,args.source_commit),sort_keys=True))
