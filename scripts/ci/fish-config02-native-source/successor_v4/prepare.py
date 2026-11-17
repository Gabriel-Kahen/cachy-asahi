#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Construct finite no-host-APT Source50 DATA; no grants, network or native actor."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
from types import ModuleType

HERE=Path(__file__).resolve().parent
PREFIX='scripts/ci/fish-config02-native-source/successor_v2/'
BASE='held-source32/scripts/ci/fish-config02-native-source/'
ORIGIN_MAP=dict(bytes=10226,sha256='33a9380a24c5cd0e233ae0a3ed6a937cbfdfeaccbe0622a6f27a7c5ae3800576')
ORIGIN_TREE='cf3c4c4cd4fa6f9dd17463bb033a3650256c7e6e'
ORIGIN_SOURCE='463377ba9c0b48c58dc112386c9b0203efd39b6e'
OVERLAYS=('data.py','hosted_owner.py','host_tools.py','host_context.py','payload.py','retain.py',
          'policy.json','README.md','admission.TEMPLATE.json','runtime.TEMPLATE.json')
OLD_WF='.github/workflows/native-arm-fish-config02-source-v2.yml'
NEW_WF='.github/workflows/native-arm-fish-config02-source-v4.yml'


def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encode(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
def row(raw):return dict(pin(raw),mode=0o644)


def read(path):
    path=Path(path)
    need(path.is_absolute() and path==path.resolve() and not path.is_symlink(),'canonical constructor input')
    before=path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o644 and
         0<before.st_size<=2*1024**2,'ordinary bounded exact0644 constructor body')
    ident=lambda s:tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        need(ident(before)==ident(os.fstat(fd)),'same constructor descriptor')
        with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(2*1024**2+1)
        need(len(raw)==before.st_size and ident(before)==ident(os.fstat(fd))==ident(path.lstat()),'unchanged whole constructor input')
        return raw
    finally:os.close(fd)


def module(raw,name,path):
    value=ModuleType(name);value.__file__=str(path)
    exec(compile(raw,str(path),'exec'),value.__dict__)
    return value


def namespace(root):
    found=set()
    for index,path in enumerate(Path(root).rglob('*')):
        need(index<256 and not path.is_symlink() and (path.is_file() or path.is_dir()),'bounded ordinary closed DATA namespace')
        if path.is_file():found.add(path.relative_to(root).as_posix())
    return found


def frozen(root,validator):
    raw=read(root/'source-map.json');need(pin(raw)==ORIGIN_MAP,'exact actual Source48 map')
    value=validator.decode(raw);expected=dict(value['files'],**{'source-map.json':row(raw)})
    need(value['kind']=='FISH02_OWNED_HOSTED_SOURCE_V2' and len(expected)==48 and
         all(v is None for v in value['actual'].values()) and namespace(root)==set(expected),'complete exact48 namespace')
    bodies={}
    for name,wanted in expected.items():
        need(not Path(name).is_absolute() and '..'not in Path(name).parts,'safe predecessor name')
        body=read(root/name);need(row(body)==wanted,'whole exact Source48 member/mode');bodies[name]=body
    need(sum(map(len,bodies.values()))==724556 and validator.git_tree(bodies)==ORIGIN_TREE,'exact actual48 bytes/tree')
    return bodies,value


def construct(base,output):
    base,output=map(Path,(base,output))
    need(base.is_absolute() and base==base.resolve() and output.is_absolute() and output==output.resolve() and
         output.parent.is_dir() and not output.exists() and not output.is_relative_to(base) and not base.is_relative_to(output),
         'fresh disjoint closed DATA output')
    validator=module(read(HERE/'data.py'),'fish_v4_constructor_data',HERE/'data.py')
    original,prior=frozen(base,validator);bodies=dict(original)
    xz=module(read(HERE/'xz_projection.py'),'fish_v4_xz_projection',HERE/'xz_projection.py')
    for name in OVERLAYS:bodies[PREFIX+name]=read(HERE/name)
    for name in ('host_prerequisites.py','trust_diagnostic.py'):del bodies[PREFIX+name]
    workflow=bodies.pop(OLD_WF)
    need(workflow.count(b'native-arm-fish-config02-source-v2')==2,'exact inherited workflow name/group seams')
    # Register a new workflow while retaining the shared Fish serialization lane.
    workflow=workflow.replace(b'name: native-arm-fish-config02-source-v2\n',b'name: native-arm-fish-config02-source-v4\n')
    need(b'group: native-arm-fish-config02-source-v2\n' in workflow,'preserved shared Fish concurrency group')
    workflow=workflow.replace(b'Admitted Ubuntu24 libarchive prerequisite then owned current Fish02 pair',b'Existing native host tools then owned current Fish02 XZ pair')
    workflow=workflow.replace(b'fish02-owned-v2',b'fish02-no-host-apt-v4')
    bodies[NEW_WF]=workflow
    recipe_name=BASE+'recipe/PKGBUILD';recipe=original[recipe_name]
    need(b'PKGEXT='not in recipe,'literal package extension must be absent in predecessor')
    bodies[recipe_name]=recipe.replace(b"pkgrel=2\n",b"pkgrel=2\nPKGEXT='.pkg.tar.xz'\n")
    need(b"PKGEXT='.pkg.tar.xz'"in bodies[recipe_name] and bodies[recipe_name]!=recipe,'one literal XZ recipe seam')
    reviewed_name=BASE+'reviewed-inputs.json';reviewed=validator.decode(original[reviewed_name])
    reviewed['PKGBUILD']=pin(bodies[recipe_name])['sha256'];bodies[reviewed_name]=encode(reviewed)
    contract_name=BASE+'contract.py';contract=xz.projected_contract(original[contract_name])
    for old,new in ((b'ROOT_FISH02_HOSTED_ADMISSION_V1',b'ROOT_FISH02_NO_HOST_APT_ADMISSION_V4'),
                    (b'ROOT_FISH02_HOSTED_RUNTIME_V1',b'ROOT_FISH02_NO_HOST_APT_RUNTIME_V4')):
        need(contract.count(old)==1,'one inherited base admission kind seam');contract=contract.replace(old,new)
    bodies[contract_name]=contract
    projected=module(contract,'fish_v4_derived_contract',base/contract_name)
    bodies[BASE+'runtime/scripts/build/build_fish02.py']=projected.projected_build(original[BASE+'runtime/scripts/build/build_v2.py'])
    bodies[BASE+'runtime/scripts/build/compare_fish_xz.py']=xz.projected_compare(original[BASE+'runtime/scripts/build/compare_v2.py'])
    entry_name=BASE+'entry.py';entry=original[entry_name]
    before=b"('python3','docker','gpg','bsdtar','zstd')";after=b"('python3','docker','gpg','zstd')"
    need(entry.count(before)==1,'one inherited existing-tool requirement seam')
    entry=entry.replace(before,after).replace(b'Python/Docker/GPG/libarchive/zstd',b'Python/Docker/GPG/zstd')
    bodies[entry_name]=entry
    finish_name=BASE+'finish_pair.py';bodies[finish_name]=xz.projected_finisher(original[finish_name])
    profile_name=BASE+'profile.json';profile=validator.decode(original[profile_name])
    profile['finisher']=pin(bodies[finish_name]);profile['held_inputs']['recipe/PKGBUILD'].update(pin(bodies[recipe_name]))
    profile['held_inputs']['runtime/scripts/build/compare_fish_xz.py']=dict(pin(bodies[BASE+'runtime/scripts/build/compare_fish_xz.py']),
                                                                       source_path='derived from pinned runtime/scripts/build/compare_v2.py')
    bodies[profile_name]=encode(profile)
    base_map_name=BASE+'source-map.json';base_map=validator.decode(original[base_map_name])
    base_map['files']={n[len('held-source32/'):]:row(raw) for n,raw in sorted(bodies.items()) if n.startswith('held-source32/') and n!=base_map_name}
    bodies[base_map_name]=encode(base_map)
    base_rows={n:raw for n,raw in bodies.items() if n.startswith('held-source32/')}
    binding=dict(kind='FISH02_DERIVED_BASE33_BINDING_V4',map=pin(bodies[base_map_name]),files=len(base_rows),bytes=sum(map(len,base_rows.values())),actual=None)
    need(binding['files']==33,'derived base33 computed count');bodies[PREFIX+'base-binding.json']=encode(binding)
    program_name=PREFIX+'owner-program.json';inverse_name=PREFIX+'source48-inverse.json'
    # The two outer manifests depend on this proof: omit their after-pins only.
    before={n:raw.decode('utf-8') for n,raw in original.items() if n not in bodies or bodies[n]!=raw}
    before['source-map.json']=original['source-map.json'].decode();before[program_name]=original[program_name].decode()
    added=sorted((set(bodies)-set(original))|{inverse_name})
    excluded={'source-map.json',program_name,inverse_name}
    after={n:row(raw) for n,raw in sorted(bodies.items()) if n not in excluded and (n in added or n in before)}
    proof=dict(kind='FISH02_COMPLETE_SOURCE48_INVERSE_V4',actual=None,
               origin=dict(source=ORIGIN_SOURCE,map=ORIGIN_MAP,tree=ORIGIN_TREE,files=48,bytes=724556),
               before_utf8=before,after=after,added=added)
    bodies[inverse_name]=encode(proof)
    program=validator.decode(original[program_name]);program['base_source_map_sha256']=binding['map']['sha256']
    program['files']={n:row(raw) for n,raw in sorted(bodies.items()) if not n.startswith('held-source32/') and n not in ('source-map.json',program_name)}
    bodies[program_name]=encode(program)
    source=dict(prior,kind='FISH02_NO_HOST_APT_SOURCE_V4',files={n:row(raw) for n,raw in sorted(bodies.items()) if n!='source-map.json'})
    bodies['source-map.json']=encode(source)
    need(len(bodies)==50 and sum(map(len,bodies.values()))<2*1024**2,'finite complete computed Source50')
    # Pure full predecessor reconstruction before any output write.
    validator.inverse_source48(None,bodies)
    output.mkdir(mode=0o700)
    for name,raw in sorted(bodies.items()):
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb')as stream:stream.write(raw)
        path.chmod(0o644)
    validator.source(output,pin(bodies['source-map.json'])['sha256'])
    return dict(kind='FISH02_NO_HOST_APT_SOURCE50_CONSTRUCTION_DATA_V4',files=len(bodies),bytes=sum(map(len,bodies.values())),
                source_map=pin(bodies['source-map.json']),tree=validator.git_tree(bodies),owner_program=pin(bodies[program_name]),
                policy=pin(bodies[PREFIX+'policy.json']),base_binding=binding,predecessor=dict(source=ORIGIN_SOURCE,map=ORIGIN_MAP,tree=ORIGIN_TREE,files=48,bytes=724556),
                changed=sorted(n for n in original if n not in bodies or original[n]!=bodies[n]),added=added,
                derived_base_files=33,original_source48_reconstructed=True,host_package_mutations=0,
                actual_source=None,actual_grants=None,actual_run=None,Root_acceptance=None)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(construct(args.base,args.output),sort_keys=True,indent=2))
