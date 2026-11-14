#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Finite host Cargo metadata replay on verified audio sources, never a build."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tarfile
import tempfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
PINS={'vendor':('scripts/port/platform-audio-vendor-audit/audit.py','94b1c5c9196326354ec84d11b81c3cd114a3e0b9ba4fa914802db309cdb37d37'),
      'runner':('scripts/port/fdk-native-stage/runtime.py','253494be99c21c83743b384b2c06cd1627023ffaf54f0cbbd271bde80572f70a')}
CARGO_SHA='a73b2c25573d251489101c0d8f19ad3702eb9761166de5ed8437b472b6c038ce'
RUSTC_SHA='4a84e05991ad6f2a84c1361c29b52b38c390365bd1fc269b1936c88d482a8928'
MAX_FILE=256*1024**2
MAX_RUNTIME=768*1024**2
TARGET='aarch64-unknown-linux-gnu'
DOCS=['https://doc.rust-lang.org/cargo/commands/cargo-metadata.html',
      'https://doc.rust-lang.org/cargo/reference/config.html',
      'https://doc.rust-lang.org/cargo/reference/build-scripts.html',
      'https://rust-lang.github.io/rustup/overrides.html']
PROOF_FIELDS={'noexec_source_vendor_workspace','executable_mapping_denied','source_elf_exec_denied','network_socket_denied',
    'new_user_namespace_denied','capabilities_zero','bootstrap_interpreter_removed','no_new_privs','seccomp'}
HOLDS=['RAW_CRATE_AUTHENTICITY_NOT_ESTABLISHED','ORIGINAL_NATIVE_BUILD_FLAGS_FEATURES_AND_COMPILER_NOT_PROVEN',
    'COMPILER_STD_LINKER_RUNTIME_SOURCES_HELD','LEGAL_AND_RELINKING_ACCEPTANCE_HELD']


class Requirement(ValueError):pass


def need(value,code):
    if not value:raise Requirement(code)


def digest(raw):return hashlib.sha256(raw).hexdigest()
def desc(raw):return dict(bytes=len(raw),sha256=digest(raw))
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def read(path,limit=MAX_FILE):
    path=Path(path);need(not path.is_symlink(),'ALIASED_RUNTIME_INPUT')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and 0<=before.st_size<=limit,'RUNTIME_FILE_BOUND_OR_TYPE')
        data=[];count=0
        while block:=os.read(fd,65536):
            count+=len(block);need(count<=limit,'RUNTIME_FILE_BOUND');data.append(block)
        identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(count==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.stat()),'CHANGED_RUNTIME_INPUT')
        return b''.join(data)
    finally:os.close(fd)


def module(name,path,pin):
    raw=read(path,1024**2);need(digest(raw)==pin,'FROZEN_PROJECT_API_DIFFERS')
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(path),'exec'),value.__dict__);return value


def elf_dependencies(raw):
    need(len(raw)>=64 and raw[:6]==b'\x7fELF\x02\x01','TRUSTED_ELF64_LITTLE_ENDIAN_REQUIRED')
    header=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
    need(header[2]==62 and header[9]==56 and header[11]==64,'HOST_X86_64_ELF_FORMAT_REQUIRED')
    need(0<header[10]<1024 and 0<header[12]<8192 and header[5]+56*header[10]<=len(raw)and header[6]+64*header[12]<=len(raw),'ELF_TABLE_BOUND')
    interpreter=[]
    for i in range(header[10]):
        p=struct.unpack_from('<IIQQQQQQ',raw,header[5]+i*56)
        if p[0]==3:
            need(p[2]+p[5]<=len(raw)and p[5]<=512,'ELF_INTERPRETER_BOUND')
            interpreter.append(raw[p[2]:p[2]+p[5]].rstrip(b'\0').decode())
    sections=[struct.unpack_from('<IIQQQQIIQQ',raw,header[6]+i*64)for i in range(header[12])];needed=[]
    for section in sections:
        if section[1]!=6:continue
        need(section[9]==16 and section[4]+section[5]<=len(raw)and section[6]<len(sections),'ELF_DYNAMIC_BOUND')
        strings=sections[section[6]];need(strings[4]+strings[5]<=len(raw),'ELF_STRING_BOUND');text=raw[strings[4]:strings[4]+strings[5]]
        for offset in range(section[4],section[4]+section[5],16):
            tag,value=struct.unpack_from('<qQ',raw,offset)
            if tag!=1:continue
            need(value<len(text)and b'\0'in text[value:value+512],'ELF_NEEDED_STRING_BOUND')
            name=text[value:].split(b'\0',1)[0].decode();need(name and '/'not in name and '\\'not in name,'ELF_NEEDED_NAME_REQUIRED');needed.append(name)
    return sorted(set(needed)),interpreter


def collect_tools(toolchain):
    """Read-only catalog constructor for review, never an automatic trust update."""
    toolchain=Path(toolchain).resolve();sources={};queue=[]
    def add(virtual,source):
        source=Path(source).resolve();need(source.is_relative_to(toolchain)or source.is_relative_to('/usr/lib')or str(source)in('/usr/bin/python3.14','/usr/bin/bwrap'),'RUNTIME_SOURCE_OUTSIDE_FIXED_ROOTS')
        if virtual in sources:
            need(sources[virtual]==source,'RUNTIME_ALIAS_AMBIGUOUS');return
        sources[virtual]=source
        raw=read(source)
        if raw.startswith(b'\x7fELF'):queue.append((virtual,source,raw))
    for name in ('cargo','rustc'):add('/tool/bin/'+name,toolchain/'bin'/name)
    add('/usr/bin/python3.14','/usr/bin/python3.14');add('/host/bwrap','/usr/bin/bwrap')
    stdlib=Path('/usr/lib/python3.14')
    for path in sorted(stdlib.rglob('*')):
        if {'site-packages','__pycache__'}&set(path.relative_to(stdlib).parts):continue
        if path.suffix not in('.py','.so'):continue
        if path.suffix=='.so'and not path.name.startswith(('_ctypes.','_struct.','_json.')):continue
        if path.is_file():add(path.as_posix(),path)
    seen=set()
    while queue:
        virtual,path,raw=queue.pop()
        if virtual in seen:continue
        seen.add(virtual)
        try:needed,interpreters=elf_dependencies(raw)
        except Requirement as error:raise Requirement(str(error)+':'+virtual)from None
        for interp in interpreters:
            need(interp in('/lib64/ld-linux-x86-64.so.2','/lib/ld-linux-x86-64.so.2','/usr/lib/ld-linux-x86-64.so.2'),'ELF_INTERPRETER_NOT_FIXED');add('/usr/lib/ld-linux-x86-64.so.2',interp)
        for name in needed:
            candidates=[toolchain/'lib'/name,Path('/usr/lib')/name]
            candidates=[p for p in candidates if p.is_file()]
            need(candidates,'RUNTIME_SHARED_LIBRARY_MISSING:'+name);selected=candidates[0]
            add(('/tool/lib/'if selected.is_relative_to(toolchain)else '/usr/lib/')+name,selected)
    rows={};total=0
    for virtual,path in sorted(sources.items()):
        raw=read(path);total+=len(raw);need(total<=MAX_RUNTIME and len(rows)<4096,'RUNTIME_CATALOG_BOUND')
        locator='toolchain/'+path.relative_to(toolchain).as_posix()if path.is_relative_to(toolchain)else path.as_posix()
        rows[virtual]=dict(origin=locator,**desc(raw),ELF=raw.startswith(b'\x7fELF'))
    need(rows['/tool/bin/cargo']['sha256']==CARGO_SHA and rows['/tool/bin/rustc']['sha256']==RUSTC_SHA,'EXACT_REVIEWED_DIRECT_TOOLCHAIN_REQUIRED')
    return dict(schema=1,purpose='finite-audio-host-cargo1961-runtime',host_arch='x86_64',toolchain_label='1.96.1',files=rows,
        bootstrap=desc(read(HERE/'namespace_child.py')),project_apis={key:dict(path=path,sha256=pin)for key,(path,pin)in PINS.items()})


def load_profile(checksum):
    raw=read(HERE/'trusted-tools.json',2*1024**2);need(digest(raw)==checksum,'TRUSTED_TOOLS_PROFILE_PIN_DIFFERS');value=json.loads(raw)
    need(value['schema']==1 and value['purpose']=='finite-audio-host-cargo1961-runtime'and value['host_arch']=='x86_64','TRUSTED_TOOLS_PROFILE_FORMAT')
    need(value['bootstrap']==desc(read(HERE/'namespace_child.py'))and value['project_apis']=={key:dict(path=path,sha256=pin)for key,(path,pin)in PINS.items()},'TRUSTED_SETUP_OR_API_PIN_DIFFERS')
    need(value['files']['/tool/bin/cargo']['sha256']==CARGO_SHA and value['files']['/tool/bin/rustc']['sha256']==RUSTC_SHA,'DIRECT_TOOLCHAIN_PINS_REQUIRED')
    return value


def put(root,key,raw,mode=0o444):
    need(not Path(key).is_absolute()and '..'not in Path(key).parts,'STAGED_PATH_REQUIRED')
    path=root/key;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb')as stream:stream.write(raw)


def excluded(name):
    return '.cargo'in Path(name).parts or Path(name).name in ('rust-toolchain','rust-toolchain.toml')


def stage_runtime(profile,toolchain,private):
    root=private/'runtime';root.mkdir(mode=0o700);toolchain=Path(toolchain).resolve();total=0
    for virtual,row in profile['files'].items():
        need(virtual.startswith(('/tool/','/usr/','/host/'))and '..'not in Path(virtual).parts,'RUNTIME_VIRTUAL_PATH_REQUIRED')
        origin=row['origin'];path=toolchain/origin[len('toolchain/'):]if origin.startswith('toolchain/')else Path(origin)
        need(path.is_file(),'TOOL_OR_SUPPORT_FILE_MISSING:'+virtual)
        raw=read(path);need(desc(raw)=={k:row[k]for k in ('bytes','sha256')},'TOOL_OR_SUPPORT_FILE_DIFFERS:'+virtual)
        if row['ELF']:elf_dependencies(raw)
        total+=len(raw);need(total<=MAX_RUNTIME,'RUNTIME_TOTAL_BOUND')
        put(root,virtual.lstrip('/'),raw,0o555 if virtual in('/tool/bin/cargo','/tool/bin/rustc','/usr/bin/python3.14','/host/bwrap','/usr/lib/ld-linux-x86-64.so.2')else 0o444)
    put(root,'bootstrap.py',read(HERE/'namespace_child.py'))
    return root


def stage_materials(a,materials,private):
    sources=private/'sources';vendor=private/'vendor';sources.mkdir(mode=0o700);vendor.mkdir(mode=0o700);omitted=[]
    raw=next(iter(materials.values()))['cargo-vendor-117.tar.xz'];_,files,_=a.vendor_data(raw)
    for name,body in files.items():
        key=name[len('vendor/'):]
        if excluded(key):omitted.append(dict(material='vendor/'+key,reason='SOURCE_CARGO_OR_TOOLCHAIN_CONTROL_EXCLUDED',**desc(body)));continue
        put(vendor,key,body,0o400)
    for name,bodies in sorted(materials.items()):
        files,root,links=a.source_data(bodies[a.PACKAGES[name]])
        for path,body in files.items():
            key=path[len(root)+1:]
            if excluded(key):omitted.append(dict(material='sources/'+name+'/'+key,reason='SOURCE_CARGO_OR_TOOLCHAIN_CONTROL_EXCLUDED',**desc(body)));continue
            put(sources,name+'/'+key,body,0o400)
        omitted.extend(dict(material='sources/'+name+'/'+path[len(root)+1:],reason='INERT_SOURCE_SYMLINK_NOT_MATERIALIZED',target=target)for path,target in sorted(links.items()))
    return omitted


def projection_state(private):
    rows={};total=0
    for base in ('sources','vendor'):
        for path in sorted((private/base).rglob('*')):
            need(not path.is_symlink(),'PROJECTED_LINK_REQUIRED_ABSENT')
            if path.is_dir():continue
            key=path.relative_to(private).as_posix()
            need(not excluded(key)and path.is_file()and not(path.stat().st_mode&0o111),'PROJECTED_SOURCE_CONTROL_OR_EXECUTABLE_PRESENT')
            raw=read(path,8*1024**2);rows[key]=desc(raw);total+=len(raw)
            need(len(rows)<=8192 and total<=128*1024**2,'PROJECTED_MATERIAL_BOUND')
    return dict(files=len(rows),bytes=total,manifest_sha256=digest(encoded(rows)))


def environment():
    return {'PATH':'/tool/bin','HOME':'/home','CARGO_HOME':'/home/cargo','RUSTC':'/tool/bin/rustc','CARGO_TARGET_DIR':'/work/target',
        'CARGO_NET_OFFLINE':'true','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC','TMPDIR':'/tmp','CARGO_BUILD_JOBS':'1'}


def command(runtime,private,operation):
    args=[str(runtime/'host/bwrap'),'--unshare-all','--uid','0','--gid','0','--die-with-parent','--new-session','--clearenv','--cap-drop','ALL',
        '--cap-add','CAP_SYS_ADMIN','--cap-add','CAP_SETPCAP','--ro-bind',str(runtime/'usr/lib'),'/usr/lib',
        '--ro-bind',str(runtime/'usr/bin/python3.14'),'/usr/bin/python3.14','--ro-bind',str(runtime/'tool'),'/tool',
        '--ro-bind',str(runtime/'bootstrap.py'),'/bootstrap.py','--symlink','usr/lib','/lib','--symlink','usr/lib','/lib64',
        '--proc','/proc','--dev','/dev','--ro-bind',str(private/'sources'),'/sources','--ro-bind',str(private/'vendor'),'/vendor']
    for name in ('work','home','tmp'):args.extend(['--bind',str(private/name),'/'+name])
    args.extend(['--chdir','/work'])
    for key,value in environment().items():args.extend(['--setenv',key,value])
    args.extend(['--','/usr/bin/python3.14','-I','-S','-B','/bootstrap.py',operation,str(os.stat('/proc/self/ns/net').st_ino)])
    return args


def parse_output(raw,returncode):
    # Runner preserves combined bounded output. Trusted metadata prints one JSON
    # document; non-JSON warnings are retained by digest, never executed/echoed.
    documents=[]
    for line in raw.splitlines():
        if not line.startswith(b'{'):continue
        try:document=json.loads(line)
        except (ValueError,UnicodeError):continue
        if type(document)is dict:documents.append(document)
    proofs=[d['metadata_isolation']for d in documents if 'metadata_isolation'in d]
    need(len(proofs)==1 and set(proofs[0])==PROOF_FIELDS and all(value is True for value in proofs[0].values()),'METADATA_ISOLATION_NOT_ESTABLISHED')
    need(returncode==0,'PINNED_TOOL_METADATA_OR_RUNTIME_REQUIREMENT')
    return documents,proofs[0]


def failure_requirements(raw):
    text=raw.decode('utf-8',errors='replace');found=[]
    patterns=[('VENDORED_PACKAGE_REQUIRED',r'no matching package named `([A-Za-z0-9_-]+)`'),
        ('DEPENDENCY_SOURCE_REQUIRED',r'failed to get `([A-Za-z0-9_-]+)` as a dependency'),
        ('PINNED_RUNTIME_SHARED_LIBRARY_REQUIRED',r'error while loading shared libraries: ([A-Za-z0-9_.+-]+)'),
        ('TRUSTED_BOOTSTRAP_MODULE_REQUIRED',r"No module named '([A-Za-z0-9_.]+)'")]
    for code,pattern in patterns:
        for match in re.finditer(pattern,text):found.append(dict(code=code,material=match[1]))
    if 'lock file'in text and 'needs to be updated'in text:found.append(dict(code='ORIGINAL_LOCKED_RESOLUTION_CANNOT_BE_REPLAYED'))
    if "can't find library"in text or 'no targets specified'in text:found.append(dict(code='MANIFEST_TARGET_SOURCE_REQUIRED'))
    if 'No permissions to create a new namespace'in text:found.append(dict(code='USER_NAMESPACE_CREATION_REQUIRED'))
    for line in raw.splitlines():
        try:value=json.loads(line)
        except (ValueError,UnicodeError):continue
        if type(value)is dict and value.get('metadata_isolation_refused')and type(value.get('requirement'))is str:
            if re.fullmatch('[A-Z_]+(?::/[a-z/]+)?',value['requirement']):found.append(dict(code=value['requirement']))
    return found


def normalize_graph(a,document,name,bodies,vendor):
    need(document.get('version')==1 and type(document.get('packages'))is list and type(document.get('resolve'))is dict,'CARGO_METADATA_SCHEMA_REQUIREMENT')
    files,root,_=a.source_data(bodies[a.PACKAGES[name]]);_,lock=a.lock_data(files[root+'/Cargo.lock']);root_identity=a.identity(a.toml(files[root+'/Cargo.toml']))
    packages={p['id']:p for p in document['packages']};resolve=document['resolve'];nodes={n['id']:n for n in resolve['nodes']}
    need(len(packages)==len(document['packages'])and len(nodes)==len(resolve['nodes'])and resolve['root']in nodes,'METADATA_IDENTITY_REQUIREMENT')
    pending=[resolve['root']];reachable=set()
    while pending:
        key=pending.pop()
        if key in reachable:continue
        need(key in nodes and key in packages,'METADATA_GRAPH_TARGET_REQUIREMENT');reachable.add(key)
        node=nodes[key]
        need(type(node['features'])is list and all(type(x)is str for x in node['features'])and type(node['dependencies'])is list and all(type(x)is str for x in node['dependencies']),'METADATA_NODE_FORMAT_REQUIREMENT')
        need(set(node['dependencies'])=={d['pkg']for d in node['deps']},'METADATA_EDGE_FORMS_DIFFER');pending.extend(node['dependencies'])
    identities={};rows=[]
    for key in sorted(packages):
        package=packages[key];identity=(package['name'],package['version'],package['source']or '')
        need(identity in lock,'RESOLVED_PACKAGE_NOT_IN_ORIGINAL_LOCK');manifest=package['manifest_path']
        if key==resolve['root']:
            need(identity[:2]==root_identity and identity[2]==''and manifest=='/sources/'+name+'/Cargo.toml','ROOT_METADATA_IDENTITY_DIFFERS')
            source_binding='sources/'+name
        else:
            matches=[(path,row)for path,row in vendor['crates'].items()if(row['name'],row['version'])==identity[:2]]
            need(len(matches)==1 and identity[2]==a.REGISTRY,'RESOLVED_SOURCE_REQUIRES_UNDELIVERED_MATERIAL')
            source_binding=matches[0][0];need(manifest=='/'+source_binding+'/Cargo.toml','RESOLVED_VENDOR_PATH_DIFFERS')
            need(matches[0][1]['package_checksum']==lock[identity]['checksum'],'RESOLVED_LOCK_VENDOR_CHECKSUM_DIFFERS')
        need(identity not in identities.values(),'DUPLICATE_RESOLVED_IDENTITY');identities[key]=identity
        if key in reachable:rows.append(dict(identity=list(identity),material=source_binding,features=sorted(nodes[key]['features'])))
    edges=[]
    for owner in sorted(reachable):
        for dep in nodes[owner]['deps']:
            target=dep['pkg'];need(target in identities,'METADATA_EDGE_OUTSIDE_CLOSED_GRAPH')
            need(all(k['kind']in(None,'dev','build')and(k['target']is None or type(k['target'])is str)for k in dep['dep_kinds']),'METADATA_DEPENDENCY_KIND_REQUIREMENT')
            edges.append(dict(owner=list(identities[owner]),target=list(identities[target]),alias=dep['name'],kinds=dep['dep_kinds']))
    return dict(status='NEW_HOST_DEFAULT_FEATURE_TARGET_METADATA_GRAPH',target=TARGET,root=list(identities[resolve['root']]),
        packages=sorted(rows,key=lambda r:r['identity']),edges=sorted(edges,key=lambda r:(r['owner'],r['target'],r['alias'])),
        reachable_packages=len(rows),reachable_edges=len(edges),unfiltered_package_records=len(packages),original_native_flags_or_features_proven=False,
        source_lock=desc(files[root+'/Cargo.lock']),source_manifest=desc(files[root+'/Cargo.toml']),
        complete_corresponding_source_accepted=False,legal_acceptance=False)


def run(handoff,index,pin,toolchain,tools_pin,output):
    a=module('cargo_replay_vendor',ROOT/PINS['vendor'][0],PINS['vendor'][1]);runtime_api=module('cargo_replay_runner',ROOT/PINS['runner'][0],PINS['runner'][1])
    audit,_=a.delivered(handoff,index,pin);need(not audit['errors'],'VENDOR_INTEGRITY_OR_COVERAGE_REQUIREMENT');intake=a.intake_module()
    native=intake.profile(intake.ordinary(Path(handoff)/'native-inputs.json'),pin);api=intake.load_api(native);materials={}
    for name in a.PACKAGES:
        raw=intake.ordinary(Path(handoff)/'sources'/name/'source.tar');_,materials[name]=api.verified(raw,digest(raw))
    profile=load_profile(tools_pin);report=dict(schema=1,purpose='finite-audio-host-cargo-metadata-replay',target=TARGET,
        source_handoff_index_sha256=index,native_profile_sha256=pin,trusted_tools_profile_sha256=tools_pin,prior_vendor_audit=desc(a.encoded(audit)),
        status='METADATA_REPLAY_REQUIREMENTS',tool_probes={},packages={},requirements=[],graph_evidence='NEW_HOST_TOOL_DEFAULT_FEATURE_METADATA_ONLY',
        holds=HOLDS,replay_sources={name:desc(read(HERE/name))for name in ('replay.py','namespace_child.py')},
        artifact_code_execution=False,build=False,install=False,network=False,native_execution=False,physical_m2=False,publication='NOT_RUN',
        complete_corresponding_source_accepted=False,legal_acceptance=False,official_command_references=DOCS)
    logs={}
    with tempfile.TemporaryDirectory(prefix='cachy-asahi-audio-metadata-')as directory:
        private=Path(directory);support=stage_runtime(profile,toolchain,private);report['omitted_source_controls']=stage_materials(a,materials,private)
        for name in ('work','home','tmp'):(private/name).mkdir(mode=0o700)
        put(private/'work','exec-probe',read(support/'tool/bin/cargo'),0o500)
        config=b'[source.crates-io]\nreplace-with="vendored-sources"\n[source.vendored-sources]\ndirectory="/vendor"\n[net]\noffline=true\n[registry]\nglobal-credential-providers=[]\n'
        put(private/'home','cargo/config.toml',config,0o400);report['generated_config']=desc(config);report['replay_environment']=environment()
        projected=projection_state(private);report['projected_material']=projected
        runner=runtime_api.Runner(180,{'LANG':'C','PATH':'/usr/bin'},private/'logs')
        with runtime_api.cancellation_handlers():
            for operation in ('cargo-version','rustc-version',*sorted(a.PACKAGES)):
                need(projection_state(private)==projected,'PROJECTED_MATERIAL_CHANGED')
                result=runner.run(command(support,private,operation),timeout=30,limit=4*1024**2,log=operation+'.log')
                logs[operation+'.log']=result.stdout
                record=dict(returncode=result.returncode,output=dict(path=operation+'.log',**desc(result.stdout)))
                try:
                    documents,proof=parse_output(result.stdout,result.returncode);record['isolation']=proof
                    if operation in a.PACKAGES:
                        graphs=[d for d in documents if d.get('version')==1 and 'packages'in d]
                        need(len(graphs)==1,'SINGLE_METADATA_DOCUMENT_REQUIRED')
                        record['graph']=normalize_graph(a,graphs[0],operation,materials[operation],audit['vendor'])
                    else:
                        record['version_output']=[line.decode('utf-8')for line in result.stdout.splitlines()if not line.startswith(b'{')]
                        expected='cargo 1.96.1 ('if operation=='cargo-version'else 'rustc 1.96.1 ('
                        need(record['version_output']and record['version_output'][0].startswith(expected),'TRUSTED_TOOL_VERSION_DIFFERS')
                except Requirement as error:
                    record['requirement']=str(error);record['observed_requirements']=failure_requirements(result.stdout)
                    report['requirements'].append(dict(operation=operation,code=str(error),observations=record['observed_requirements']))
                (report['packages']if operation in a.PACKAGES else report['tool_probes'])[operation]=record
                if operation in ('cargo-version','rustc-version')and 'requirement'in record:break
        for name,bodies in materials.items():
            source,root,_=a.source_data(bodies[a.PACKAGES[name]])
            need(read(private/'sources'/name/'Cargo.lock')==source[root+'/Cargo.lock'],'SOURCE_LOCK_CHANGED')
        for base in ('work','home','tmp'):
            for path in (private/base).rglob('*'):
                if not path.is_file()or path==private/'work/exec-probe':continue
                need(path.suffix not in('.rlib','.rmeta','.so','.o','.a')and not(path.stat().st_mode&0o111),'UNEXPECTED_BUILD_OR_EXECUTABLE_OUTPUT')
        report['source_locks_unchanged']=True;report['compiled_artifact_outputs_absent']=True
        need(projection_state(private)==projected,'PROJECTED_MATERIAL_CHANGED_AFTER_REPLAY')
        report['status']='NEW_HOST_DEFAULT_FEATURE_TARGET_GRAPHS_RECORDED'if not report['requirements']and len(report['packages'])==3 else 'METADATA_REPLAY_REQUIREMENTS'
    api.write_fresh(output,dict(logs,**{'metadata-replay.json':encoded(report)}))
    return report


def prerequisite_report(output,code):
    value=dict(schema=1,purpose='finite-audio-host-cargo-metadata-replay',status='METADATA_REPLAY_REQUIREMENTS',requirements=[dict(code=code)],
        actor_completion='NOT_ESTABLISHED',graph_evidence='NOT_ESTABLISHED',holds=HOLDS,artifact_code_execution=False,build=False,install=False,network=False,
        complete_corresponding_source_accepted=False,legal_acceptance=False,native_execution=False,physical_m2=False,publication='NOT_RUN')
    output=Path(output).absolute()
    need(not any(p.is_symlink()for p in(output,*output.parents)),'OUTPUT_PARENT_ALIAS_REFUSED')
    parent=output.parent.stat();need(parent.st_uid==os.getuid()and not(parent.st_mode&0o022),'OWNED_PRIVATE_OUTPUT_PARENT_REQUIRED')
    os.mkdir(output,0o700)
    fd=os.open(output/'metadata-replay.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as stream:stream.write(encoded(value))
    return value


def main():
    if not sys.flags.isolated:
        print('Python isolated mode (-I) is required',file=sys.stderr);return 2
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('handoff','index-sha256','profile-sha256','toolchain','tools-profile-sha256','output'):parser.add_argument('--'+key,required=True)
    args=parser.parse_args()
    try:
        report=run(Path(args.handoff),args.index_sha256,args.profile_sha256,Path(args.toolchain),args.tools_profile_sha256,Path(args.output))
        print(json.dumps(dict(status=report['status'],report=desc(encoded(report)),requirements=report['requirements'],artifact_code_execution=False,network=False,complete_corresponding_source_accepted=False)))
        return int(bool(report['requirements']))
    except (OSError,ValueError,KeyError,TypeError,tarfile.TarError)as error:
        code=str(error)if type(error)is Requirement else 'OUTPUT_ALREADY_EXISTS'if isinstance(error,FileExistsError)else 'MATERIAL_TOOL_OR_RUNTIME_REQUIREMENT'
        saved=False
        try:prerequisite_report(Path(args.output),code);saved=True
        except (OSError,ValueError):pass
        print(json.dumps(dict(status='METADATA_REPLAY_REQUIREMENTS',requirement=code,error_type=type(error).__name__,requirements_report_written=saved,
            artifact_code_execution=False,network=False,complete_corresponding_source_accepted=False,legal_acceptance=False)))
        return 2


if __name__=='__main__':sys.exit(main())
