#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Bounded isolated x86_64 source/package-function diagnostic, no native credit."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import sys
import tarfile
import tempfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
RECIPE=ROOT/'packages/port/bankstown-source-candidate'
METADATA='32f9f86ca8b4129b152afe2febed664517f2e7dc064e5654d0a5123344c754c1'
TARGET='x86_64-unknown-linux-gnu'
EXECUTABLES={'/usr/bin/cc','/usr/bin/gcc','/usr/bin/ld','/usr/bin/as','/usr/bin/bash','/usr/bin/install','/usr/bin/python3',
 '/usr/lib/gcc/x86_64-pc-linux-gnu/16/collect2','/usr/lib/gcc/x86_64-pc-linux-gnu/16/lto-wrapper',
 '/tool/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld','/tool/lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld'}
DRIVER=b'set -euo pipefail\nsource /recipe/PKGBUILD\nsrcdir=/work/package-source\npkgdir=/work/prefix\nCARCH=x86_64\nBANKSTOWN_HOST_DIAGNOSTIC=1\nexport srcdir pkgdir CARCH BANKSTOWN_HOST_DIAGNOSTIC\npackage\n'
PROOF_FIELDS={'source_vendor_readonly_noexec','one_writable_executable_build_workspace','network_denied','namespace_changes_denied',
 'capabilities_zero','seccomp','no_new_privs','audio_devices_absent','host_services_absent'}


def need(ok,code):
    if not ok:raise ValueError(code)


def desc(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def module(name,path,pin=None):
    raw=path.read_bytes();need(pin is None or desc(raw)['sha256']==pin,'FROZEN_BUILD_API_DIFFERS')
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);exec(compile(raw,str(path),'exec'),m.__dict__);return m


def metadata():return module('bankstown_held_metadata',ROOT/'scripts/port/platform-audio-cargo-metadata/replay.py',METADATA)


def collect_tools(toolchain):
    r=metadata();toolchain=Path(toolchain).resolve();profile=r.collect_tools(toolchain);files=profile['files'];queue=[]
    def add(virtual,path):
        path=Path(path).resolve();raw=r.read(path);origin='toolchain/'+path.relative_to(toolchain).as_posix()if path.is_relative_to(toolchain)else str(path)
        is_elf=raw.startswith(b'\x7fELF')and len(raw)>20 and struct.unpack_from('<H',raw,16)[0]in(2,3)
        row=dict(origin=origin,**desc(raw),ELF=is_elf)
        if virtual in files:need(files[virtual]==row,'HOST_SUPPORT_ALIAS_DIFFERS');return
        files[virtual]=row
        if is_elf:queue.append((virtual,raw))
        elif path.suffix in('.so','.a')and not raw.startswith(b'!<arch>'):
            # GNU development linker scripts contain further literal inputs;
            # preserve the public virtual path expected by the script.
            for name in re.findall(rb'/usr/lib/[A-Za-z0-9_.+-]+',raw):
                dependency=Path(name.decode());need(dependency.is_file(),'HOST_LINKER_SCRIPT_INPUT_REQUIRED:'+dependency.name)
                add(str(dependency),dependency)
            for name in re.findall(rb'(?<![/A-Za-z0-9_])lib[A-Za-z0-9_.+-]+\.so(?:\.[0-9]+)*',raw):
                dependency=Path('/usr/lib')/name.decode()
                if dependency.is_file():add(str(dependency),dependency)
    std=toolchain/'lib/rustlib/x86_64-unknown-linux-gnu/lib'
    need(std.is_dir(),'HELD_HOST_STANDARD_LIBRARY_REQUIRED')
    for path in sorted(std.rglob('*')):
        if path.is_file():add('/tool/lib/rustlib/x86_64-unknown-linux-gnu/lib/'+path.relative_to(std).as_posix(),path)
    for virtual in sorted(EXECUTABLES):add(virtual,toolchain/virtual[len('/tool/'):]if virtual.startswith('/tool/')else virtual)
    for path in Path('/usr/lib/python3.14/lib-dynload').glob('_hashlib.*.so'):add(str(path),path)
    gcc=Path('/usr/lib/gcc/x86_64-pc-linux-gnu/16')
    for path in gcc.iterdir():
        if path.is_file()and(path.name.startswith(('crt','libgcc'))or path.name in('specs','liblto_plugin.so')):add(str(path),path)
    for name in ('libc.so','libc_nonshared.a','libm.so','libm.a','libmvec.so','libpthread.a','libdl.a','librt.a','libutil.a','libresolv.so',
                 'crt1.o','Scrt1.o','rcrt1.o','crti.o','crtn.o'):
        path=Path('/usr/lib')/name
        if path.is_file():add(str(path),path)
    while queue:
        virtual,raw=queue.pop();needed,interpreters=r.elf_dependencies(raw)
        for name in needed:
            choices=[toolchain/'lib'/name,Path('/usr/lib')/name];choices=[p for p in choices if p.is_file()]
            need(choices,'HOST_LINKER_SUPPORT_REQUIRED:'+name);path=choices[0]
            add(('/tool/lib/'if path.is_relative_to(toolchain)else '/usr/lib/')+name,path)
    profile.update(purpose='bankstown-host-source-build1961',build_bootstrap=desc((HERE/'build_namespace.py').read_bytes()),
        package_driver=desc(DRIVER),host_linker=desc((HERE/'link-host.sh').read_bytes()),executables=sorted(EXECUTABLES),host_only=True,native_compiler_selected=False)
    return profile


def recipe_sources():
    info={}
    for line in (RECIPE/'.SRCINFO').read_text().splitlines():
        if ' = 'in line:
            key,value=line.strip().split(' = ',1);info.setdefault(key,[]).append(value)
    need(info['pkgname']==['bankstown']and info['pkgver']==['1.1.0']and info['pkgrel']==['5']and info['arch']==['aarch64'],'CANDIDATE_IDENTITY_REQUIRED')
    need(len(info['source'])==len(info['sha256sums']),'CANDIDATE_SOURCE_METADATA_REQUIRED')
    for name,pin in zip(info['source'],info['sha256sums']):need(desc((RECIPE/name).read_bytes())['sha256']==pin,'CANDIDATE_LOCAL_SOURCE_DIFFERS:'+name)
    return info


def source_projection(a,guard,private):
    guard.sources(RECIPE);sources=private/'sources';vendor=private/'vendor';sources.mkdir(mode=0o700);vendor.mkdir(mode=0o700)
    source=(RECIPE/'bankstown-1.1.0.tar.gz').read_bytes();files,root,links=a.source_data(source);need(not links,'BANKSTOWN_SOURCE_LINK_REQUIREMENT')
    for name,body in files.items():
        key=name[len(root)+1:];put(sources,'bankstown/'+key,body,0o400)
    raw=(RECIPE/'cargo-vendor-117.tar.xz').read_bytes();observed,files,ids=a.vendor_data(raw)
    for name,body in files.items():put(vendor,name[len('vendor/'):],body,0o400)
    components=json.loads((RECIPE/'COMPONENTS.json').read_bytes());report,_=a.audit_project(source,observed,files,ids,components)
    need(not report['errors'],'BANKSTOWN_LOCK_VENDOR_JOIN_REQUIRED')
    return observed,source


def put(root,key,raw,mode=0o444):
    path=root/key;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with path.open('xb')as stream:stream.write(raw)
    path.chmod(mode)


def environment():
    return dict(PATH='/tool/bin:/usr/bin',HOME='/home',CARGO_HOME='/home/cargo',RUSTC='/tool/bin/rustc',CARGO_TARGET_DIR='/work/target',
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER='/build-tools/cc',CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='1',
        CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1',SOURCE_DATE_EPOCH='1791748800',LC_ALL='C',LANG='C',TMPDIR='/tmp',
        RUSTFLAGS='-C target-cpu=x86-64 -C link-arg=-Wl,-z,max-page-size=16384')


def command(r,runtime,private,op):
    args=r.command(runtime,private,'bankstown');split=args.index('--');args=args[:split]
    args+=['--ro-bind',str(runtime/'usr/bin'),'/usr/bin','--ro-bind',str(runtime/'build_namespace.py'),'/build_namespace.py','--ro-bind',str(runtime/'package-driver.sh'),'/package-driver.sh',
        '--ro-bind',str(private/'recipe'),'/recipe','--ro-bind',str(runtime/'build-tools'),'/build-tools','--ro-bind',str(private/'work/exec-probe'),'/work/exec-probe']
    for key,value in environment().items():args+=['--setenv',key,value]
    return args+['--','/usr/bin/python3.14','-I','-S','-B','/build_namespace.py',op,str(os.stat('/proc/self/ns/net').st_ino)]


def isolation(raw,rc):
    proofs=[];documents=[]
    for line in raw.splitlines():
        if not line.startswith(b'{'):continue
        try:value=json.loads(line)
        except(ValueError,UnicodeError):continue
        if type(value)is not dict:continue
        if 'bankstown_build_isolation'in value:proofs.append(value['bankstown_build_isolation'])
        if value.get('version')==1 and 'packages'in value:documents.append(value)
    need(len(proofs)==1 and set(proofs[0])==PROOF_FIELDS and all(x is True for x in proofs[0].values()),'HOST_BUILD_ISOLATION_REQUIREMENT')
    need(rc==0,'HOST_SOURCE_BUILD_OR_PACKAGE_REQUIREMENT');return proofs[0],documents


def package_source(r,a,guard,private,artifact,tools_pin):
    source=private/'work/package-source';source.mkdir(mode=0o700)
    for name,body in a.tar_data((RECIPE/'bankstown-1.1.0.tar.gz').read_bytes()).items():put(source,name,body)
    for name,body in a.tar_data((RECIPE/'audio-rust-notices-v1.tar.xz').read_bytes()).items():put(source,name,body)
    for name in ('build_guard.py','native-rust-inputs.json','SOURCE-CANDIDATE.md','PACKAGING.LICENSE'):put(source,name,(RECIPE/name).read_bytes())
    put(source,'target/'+TARGET+'/release/libbankstown.so',artifact,0o555)
    receipt=guard.receipt(artifact,TARGET,tools_pin,'HOST_DIAGNOSTIC_ONLY');put(source,'build-inputs.json',guard.encoded(receipt),0o400)
    return receipt


def layout(prefix,guard,receipt):
    expected={f'usr/lib/lv2/bankstown.lv2/{name}':0o755 if name=='bankstown.so'else 0o644 for name in ('bankstown.so','bankstown.ttl','manifest.ttl')}
    expected.update({'usr/share/licenses/bankstown/'+name:0o644 for name in ('LICENSE','THIRD-PARTY.md','THIRD-PARTY-LICENSES.txt','SOURCE.md','PACKAGING.LICENSE')})
    expected.update({'usr/share/doc/bankstown/'+name:0o644 for name in ('SOURCE-CANDIDATE.md','BUILD-INPUTS.json')})
    files={};directories=set()
    for p in prefix.rglob('*'):
        need(not p.is_symlink(),'HOST_PACKAGE_LINK_REFUSED')
        if p.is_dir():
            need(stat.S_IMODE(p.stat().st_mode)==0o755,'HOST_PACKAGE_DIRECTORY_MODE_DIFFERS');directories.add(p.relative_to(prefix).as_posix())
        else:
            need(p.is_file(),'HOST_PACKAGE_SPECIAL_FILE_REFUSED');files[p.relative_to(prefix).as_posix()]=p
    need(set(files)==set(expected),'HOST_PACKAGE_PREFIX_COVERAGE_DIFFERS')
    parents={str(p)for name in expected for p in Path(name).parents if str(p)!='.'}
    need(directories==parents,'HOST_PACKAGE_DIRECTORY_COVERAGE_DIFFERS')
    rows={}
    for name,p in files.items():
        need(not p.is_symlink()and stat.S_IMODE(p.stat().st_mode)==expected[name],'HOST_PACKAGE_PREFIX_MODE_DIFFERS');rows[name]=dict(mode=expected[name],**desc(p.read_bytes()))
    guard.check_receipt(files['usr/lib/lv2/bankstown.lv2/bankstown.so'].read_bytes(),TARGET,receipt)
    need(json.loads(files['usr/share/doc/bankstown/BUILD-INPUTS.json'].read_bytes())==receipt,'HOST_PACKAGE_RECEIPT_DIFFERS')
    with tarfile.open(RECIPE/'bankstown-1.1.0.tar.gz')as archive:
        for source,target in [('LICENSE','usr/share/licenses/bankstown/LICENSE'),('manifest.ttl','usr/lib/lv2/bankstown.lv2/manifest.ttl'),('bankstown.ttl','usr/lib/lv2/bankstown.lv2/bankstown.ttl')]:
            need(files[target].read_bytes()==archive.extractfile('bankstown-1.1.0/'+source).read(),'HOST_PACKAGE_FIXED_SOURCE_COPY_DIFFERS')
    return rows


def run(toolchain,profile_pin,output):
    r=metadata();a=r.module('bankstown_source_vendor',ROOT/r.PINS['vendor'][0],r.PINS['vendor'][1]);runtime_api=r.module('bankstown_source_runner',ROOT/r.PINS['runner'][0],r.PINS['runner'][1])
    recipe_sources();guard=module('bankstown_candidate_guard',RECIPE/'build_guard.py');raw=(HERE/'host-tools.json').read_bytes();need(desc(raw)['sha256']==profile_pin,'HOST_BUILD_TOOLS_PROFILE_PIN_REQUIRED');profile=json.loads(raw)
    need(profile['purpose']=='bankstown-host-source-build1961'and profile['host_only']is True and profile['native_compiler_selected']is False,'HOST_DIAGNOSTIC_TOOL_CATALOG_REQUIRED')
    need(profile['build_bootstrap']==desc((HERE/'build_namespace.py').read_bytes())and profile['package_driver']==desc(DRIVER)
         and profile['host_linker']==desc((HERE/'link-host.sh').read_bytes()),'HOST_BUILD_SETUP_PIN_DIFFERS')
    report=dict(schema=1,status='HOST_SOURCE_DIAGNOSTIC_REQUIREMENTS',package='bankstown',version='1.1.0-5',host_compiler='1.96.1',intended_native_compiler='ALARM1:1.99.0-1',
        host_target=TARGET,host_tools_profile_sha256=profile_pin,recipe=desc((RECIPE/'PKGBUILD').read_bytes()),operations={},requirements=[],native_aarch64_execution='NOT_RUN',
        audio_plugin_loaded=False,audio_device_or_routing_action=False,host_install=False,package_archive_built=False,upstream_build_code_scope='CONFINED_HOST_BUILD_WORKSPACE',
        complete_corresponding_source_accepted=False,legal_acceptance=False,native_component_qualification='NOT_ADMITTED',physical_m2='NOT_RUN',publication='NOT_RUN',
        build_sources={name:desc((HERE/name).read_bytes())for name in ('build.py','build_namespace.py','link-host.sh')},environment=environment())
    intake=a.intake_module();api=intake.load_api(intake.profile((ROOT/'scripts/port/platform-audio-sources/native-inputs.json').read_bytes(),'e2ab9b6cc2810bf5d5b6454abdb9bcdeea6567797247c745b0d04541cb99c6c8'))
    bodies={};written=False
    with tempfile.TemporaryDirectory(prefix='cachy-asahi-bankstown-build-')as directory:
        private=Path(directory);runtime=r.stage_runtime(profile,toolchain,private)
        for name in EXECUTABLES:(runtime/name.lstrip('/')).chmod(0o555)
        put(runtime,'build_namespace.py',(HERE/'build_namespace.py').read_bytes());put(runtime,'package-driver.sh',DRIVER)
        put(runtime,'build-tools/cc',(HERE/'link-host.sh').read_bytes(),0o555)
        vendor,source=source_projection(a,guard,private)
        for name in ('work','home','tmp','recipe'):(private/name).mkdir(mode=0o700)
        for name in ('PKGBUILD',):put(private/'recipe',name,(RECIPE/name).read_bytes())
        put(private/'work','exec-probe',r.read(runtime/'tool/bin/cargo'),0o500)
        config=b'[source.crates-io]\nreplace-with="vendored-sources"\n[source.vendored-sources]\ndirectory="/vendor"\n[net]\noffline=true\n[registry]\nglobal-credential-providers=[]\n'
        put(private/'home','cargo/config.toml',config,0o400)
        runner=runtime_api.Runner(600,{'LANG':'C','PATH':'/usr/bin'},private/'logs')
        with runtime_api.cancellation_handlers():
            for op in ('metadata','build','package'):
                if op=='package':
                    artifact=r.read(private/'work/target'/TARGET/'release/libbankstown.so',16*1024**2)
                    receipt=package_source(r,a,guard,private,artifact,profile_pin);report['artifact']=guard.artifact(artifact,TARGET)
                result=runner.run(command(r,runtime,private,op),timeout=300 if op=='build'else 60,limit=4*1024**2,log=op+'.log')
                bodies[op+'.log']=result.stdout;row=dict(returncode=result.returncode,output=dict(path=op+'.log',**desc(result.stdout)))
                try:
                    proof,documents=isolation(result.stdout,result.returncode);row['isolation']=proof
                    if op=='metadata':
                        need(len(documents)==1,'HOST_PREFLIGHT_METADATA_REQUIRED')
                        graph=r.normalize_graph(a,documents[0],'bankstown',{a.PACKAGES['bankstown']:source},vendor)
                        graph.update(target=TARGET,status='HOST_SOURCE_BUILD_PREFLIGHT_METADATA');row['graph']=graph
                except ValueError as error:
                    row['requirement']=str(error);report['requirements'].append(dict(operation=op,code=str(error)));report['operations'][op]=row;break
                report['operations'][op]=row
            if not report['requirements']:
                report['layout']=layout(private/'work/prefix',guard,receipt)
                need(desc((private/'sources/bankstown/Cargo.lock').read_bytes())['sha256']==guard.LOCK,'HOST_SOURCE_LOCK_CHANGED')
                report['source_lock_unchanged']=True;report['status']='HOST_SOURCE_BUILD_AND_PACKAGE_FUNCTION_PREFIX_PASS'
                api.write_fresh(output,bodies);written=True
                shutil.copytree(private/'work/prefix',output/'prefix')
    bodies['host-build.json']=encoded(report)
    if written:
        fd=os.open(output/'host-build.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb')as stream:stream.write(bodies['host-build.json'])
    else:api.write_fresh(output,bodies)
    return report


def main():
    if not sys.flags.isolated:
        print('Python isolated mode (-I) is required',file=sys.stderr);return 2
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('toolchain','tools-sha256','output'):parser.add_argument('--'+key,required=True)
    args=parser.parse_args()
    try:
        report=run(Path(args.toolchain),args.tools_sha256,Path(args.output));print(json.dumps(dict(status=report['status'],report=desc(encoded(report)),requirements=report['requirements'],native_aarch64_execution='NOT_RUN',legal_acceptance=False)))
        return int(bool(report['requirements']))
    except (OSError,ValueError,KeyError,TypeError)as error:
        print(json.dumps(dict(status='HOST_SOURCE_DIAGNOSTIC_REQUIREMENTS',error_type=type(error).__name__,native_aarch64_execution='NOT_RUN',legal_acceptance=False)));return 2


if __name__=='__main__':sys.exit(main())
