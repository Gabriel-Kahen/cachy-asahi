#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure DATA export for the first genuine original libgit2 native build pair."""
import argparse
import importlib.util
import io
import json
from pathlib import Path
import stat
import tarfile

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('libgit2_contract',HERE/'base/contract.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)
PREFIX='scripts/ci/libgit2-reference-native-source/'
WORKFLOW='.github/workflows/native-arm-libgit2-reference-source.yml'
BASE=PREFIX+'base/'
OWNER=PREFIX+'owner/'
FROZEN_FRAMEWORK = Path('scripts/ci/llhttp-minimal-native-source-data/fixtures/Source95/held-source'
                        '/scripts/ci/llhttp-reference-native-source/base')
FROZEN_FRAMEWORK_INPUTS = (
    'runtime/scripts/build/build_v2.py',
    'runtime/scripts/build/compare_v2.py',
    'runtime/scripts/checks/package_checks.py',
    'runtime/scripts/maintenance/source_cache.py',
)

def encoded(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()

def held_framework_body(root, name, row):
    if name in FROZEN_FRAMEWORK_INPUTS:
        # Source95 retains the exact historical inputs pinned by the libgit2 profile.
        C.need(row['source_path'] == name.removeprefix('runtime/'), 'exact original framework role required: ' + name)
        source = root / FROZEN_FRAMEWORK / name
    else:
        source = root / row['source_path']
    body = C.read(source)
    C.need(C.pin(body) == {key: row[key] for key in ('bytes', 'sha256')}, 'exact held framework dependency: ' + name)
    return body

def archive_closure(raw,proof):
    C.need(C.pin(raw)=={k:proof['archive'][k] for k in ('bytes','sha256')},'exact generated upstream archive')
    members={};total=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
        for item in archive:
            C.need(not Path(item.name).is_absolute() and '..' not in Path(item.name).parts and not item.islnk(),'safe complete source archive')
            C.need(item.name not in members and len(members)<16384 and item.size<=1024**2,'finite unique source closure')
            row=dict(mode=item.mode)
            if item.isdir():row.update(type='directory',bytes=0)
            elif item.issym():
                C.need(not Path(item.linkname).is_absolute() and '..' not in Path(item.linkname).parts,'safe pinned fixture symlink DATA')
                row.update(type='symlink',bytes=0,linkname=item.linkname)
            else:
                C.need(item.isfile(),'source archive ordinary entries or exact pinned fixture symlink')
                body=archive.extractfile(item).read();total+=len(body);C.need(total<24*1024**2,'bounded complete source')
                row.update(type='file',**C.pin(body))
            members[item.name]=row
    C.need(members==proof['members'],'every source/license/member/mode/link byte pinned')
    return members

def construct(root,recipe_root,archive_path,output,*,dependency_paths=None,dependency_expected=None,consumer_root=None):
    root,recipe_root,archive_path,output=map(C.ordinary,(root,recipe_root,archive_path,output))
    C.need(not output.exists() and all(not output.is_relative_to(p) for p in (root,recipe_root)),'fresh disjoint Source output')
    C.need(dependency_paths is not None and dependency_expected is not None,'explicit Root-accepted PROJECT TEST llhttp tuple required; no default')
    T=C.module(HERE/'project_test.py','libgit2_project_test')
    C.need(consumer_root is not None,'explicit frozen consumer interface root required')
    dependency=T.validate_compatible_tuple(dependency_paths,dependency_expected,consumer_root=consumer_root)
    derivation=C.load(HERE/'derivation.json')
    C.need(derivation['base_commit']=='7770823e19115eeba2bbb81f1abf5643cc4258c6','exact frozen integration framework')
    for name,row in derivation['files'].items():
        original=C.read(root/row['source_path']);C.need(C.pin(original)==row['original'],'held framework original: '+name)
        text=original.decode()
        for change in row['changes']:
            C.need(change['before'] in text,'whole finite derivation anchor');text=text.replace(change['before'],change['after'])
        actual=C.read(HERE/name);C.need(actual==text.encode() and C.pin(actual)==row['projected'],'whole reviewed derived framework: '+name)
    recipe=C.load(HERE/'recipe-pin.json');proof=recipe['upstream'];raw=C.read(archive_path,cap=8*1024**2)
    archive_closure(raw,proof)
    expected=set(recipe['files']);base=recipe_root/recipe['recipe_path']
    found={str(p.relative_to(base)) for p in base.rglob('*') if p.is_file() or p.is_symlink()}
    C.need(found==expected,'complete original recipe namespace')
    recipe_bodies={}
    for name,pin in recipe['files'].items():
        body=C.read(base/name);C.need(C.pin(body)==pin,'exact original libgit2 recipe: '+name);recipe_bodies[name]=body
    C.need(b"PKGEXT='.pkg.tar.xz'" in recipe_bodies['PKGBUILD'],'literal original recipe pins XZ-only package format')
    recipe_bodies[proof['archive']['filename']]=raw
    profile=C.load(HERE/'base/profile.json');C.need(all(v is None for v in profile['actual'].values()),'unissued selectors')
    local=('contract.py','entry.py','finish_pair.py','profile.json','admission.TEMPLATE.json','runtime.TEMPLATE.json')
    base_bodies={BASE+n:C.read(HERE/'base'/n) for n in local}
    for name,row in profile['held_inputs'].items():
        base_bodies[BASE+name]=held_framework_body(root, name, row)
    for name,body in recipe_bodies.items():base_bodies[BASE+'recipe/'+name]=body
    for name in ('project_test.py','dependency.py','consumer_bridge.py','consumer-interface-pin.json'):base_bodies[BASE+name]=C.read(HERE/name)
    B=C.module(HERE/'consumer_bridge.py','libgit2_consumer_constructor');_,consumer_pin=B.interface(consumer_root)
    for name,wanted in consumer_pin['files'].items():
        body=C.read(Path(consumer_root)/name);C.need(C.pin(body)==wanted,'unchanged frozen consumer helper custody');base_bodies[BASE+'consumer-v1/'+name]=body
    evidence_root=Path(dependency_paths['native_receipt']).parent
    for name,wanted in dependency['consumer']['files'].items():
        body=C.read(evidence_root/name);C.need(C.pin(body)==wanted,'complete source/native dependency evidence custody');base_bodies[BASE+'dependency-evidence/'+name]=body
    operand_names={name:(dependency_expected['filename'] if name=='package' else dependency_expected['filename']+'.sig' if name=='signature' else name) for name in T.KEYS}
    for name,path in dependency_paths.items():base_bodies[BASE+('dependency-evidence/' if name=='native_receipt' else 'project-test/')+operand_names[name]]=C.read(path,cap=8*1024**2)
    dependency_record=dict(paths=operand_names,expected=dependency_expected,project_test_tuple_sha256=dependency['tuple_sha256'],project_test_root_receipt_sha256=dependency_expected['pins']['root_receipt']['sha256'])
    base_bodies[BASE+'project-test.json']=encoded(dependency_record)
    X=C.module(HERE/'dependency.py','libgit2_dependency')
    base_bodies[BASE+'expected350.lock']=X.expected350(base_bodies[BASE+'expected349.lock'])
    base_bodies[BASE+'recipe-pin.json']=C.read(HERE/'recipe-pin.json')
    base_bodies[BASE+'reviewed-inputs.json']=encoded({n:C.pin(b)['sha256'] for n,b in sorted(recipe_bodies.items())})
    base_bodies[BASE+'runtime/scripts/build/build_libgit2-reference.py']=C.projected_build(base_bodies[BASE+'runtime/scripts/build/build_v2.py'])
    base_bodies[BASE+'runtime/scripts/build/compare_libgit2.py']=C.projected_compare(base_bodies[BASE+'runtime/scripts/build/compare_v2.py'])
    base_bodies['LICENSE']=C.read(root/'LICENSE')
    base_map=encoded(dict(kind='LIBGIT2_REFERENCE_MINIMAL_HOSTED_SOURCE_MAP_V1',files={n:dict(C.pin(b),mode=0o644) for n,b in sorted(base_bodies.items())},actual=profile['actual']))
    base_bodies[BASE+'source-map.json']=base_map
    bodies={'held-source/'+n:b for n,b in base_bodies.items()}
    for n in ('admit.py','data.py','hosted_owner.py','host_tools.py','payload.py','retain.py','policy.json','admission.TEMPLATE.json','runtime.TEMPLATE.json'):bodies[OWNER+n]=C.read(HERE/'owner'/n)
    for n in ('README.md','derivation.json','recipe-pin.json'):bodies[PREFIX+n]=C.read(HERE/n)
    bodies[WORKFLOW]=C.read(root/WORKFLOW);bodies['LICENSE']=C.read(root/'LICENSE')
    binding=dict(map=C.pin(base_map),files=len(base_bodies),bytes=sum(map(len,base_bodies.values())))
    bodies[OWNER+'base-binding.json']=encoded(binding)
    program=encoded(dict(schema=1,base_source_map_sha256=C.pin(base_map)['sha256'],files={n:dict(C.pin(b),mode=0o644) for n,b in sorted(bodies.items()) if not n.startswith('held-source/')}))
    bodies[OWNER+'owner-program.json']=program
    value=dict(kind='LIBGIT2_REFERENCE_OWNED_HOSTED_SOURCE_V2',files={n:dict(C.pin(b),mode=0o644) for n,b in sorted(bodies.items())},actual=dict(source=None,ref=None,run=None,job=None,Root_admission=None,runtime=None,image=None,owner_domain=None,daemon_domain=None))
    bodies['source-map.json']=encoded(value)
    C.need(32<len(bodies)<512 and sum(map(len,bodies.values()))<128*1024**2,'finite complete libgit2 Source')
    output.mkdir(mode=0o700)
    for n,b in bodies.items():
        path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(b)
        path.chmod(0o644)
    D=C.module(HERE/'owner/data.py','libgit2_owner_data');sha=C.pin(bodies['source-map.json'])['sha256'];D.source(output,sha)
    C.verify_source(output/'held-source',C.pin(base_map)['sha256'])
    return dict(files=len(bodies),bytes=sum(map(len,bodies.values())),source_map=C.pin(bodies['source-map.json']),owner_program=C.pin(program),bootstrap_resource_domain=C.pin(bodies[OWNER+'policy.json']),actual=value['actual'],native_build='NOT RUN')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('root','recipe-root','archive','output','dependency-paths','dependency-expected','consumer-root'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();print(json.dumps(construct(a.root,a.recipe_root,a.archive,a.output,dependency_paths={k:Path(v) for k,v in C.load(a.dependency_paths).items()},dependency_expected=C.load(a.dependency_expected),consumer_root=a.consumer_root),indent=2,sort_keys=True))
