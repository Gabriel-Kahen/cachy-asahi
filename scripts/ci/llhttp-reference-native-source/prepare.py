#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Prepare the original llhttp recipe for a separately admitted native pair."""
import argparse
import importlib.util
import io
import json
from pathlib import Path
import stat
import tarfile

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('llhttp_contract',HERE/'base/contract.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)
PREFIX='scripts/ci/llhttp-reference-native-source/'
WORKFLOW='.github/workflows/native-arm-llhttp-reference-source.yml'
BASE=PREFIX+'base/'
OWNER=PREFIX+'owner/'

ARTIFACT_BINDINGS = {
    'build_llhttp-reference.py': (
        "bind_artifact(report['metadata'], result, report['input_sha256']['PKGBUILD'])",
        "bind_llhttp_artifact(report['metadata'], result, report['input_sha256']['PKGBUILD'], paths[0], bind_artifact)",
    ),
    'compare_llhttp.py': (
        "bind_artifact(record['recipe_metadata'], report, record['recipe_inputs']['PKGBUILD'])",
        "bind_llhttp_artifact(record['recipe_metadata'], report, record['recipe_inputs']['PKGBUILD'], item, bind_artifact)",
    ),
}

def encoded(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()

def project_artifact_binding(name, raw):
    """Replace only the llhttp artifact binding after generic package inspection."""
    checks = "sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'checks'))"
    imports = checks + "\nsys.path.insert(0, str(Path(__file__).resolve().parents[3]))\nfrom package_metadata import bind_llhttp_artifact"
    edits = [(checks, imports), ARTIFACT_BINDINGS[name]]
    projected = raw.decode()
    for before, after in edits:
        C.need(projected.count(before) == 1 and after not in projected, 'one exact llhttp binding seam')
        projected = projected.replace(before, after)
    restored = projected
    for before, after in reversed(edits):
        C.need(restored.count(after) == 1, 'one exact llhttp binding inverse')
        restored = restored.replace(after, before)
    C.need(restored.encode() == raw, 'whole unchanged llhttp command inverse')
    return projected.encode()

def archive_closure(raw,proof):
    C.need(C.pin(raw)=={k:proof['archive'][k] for k in ('bytes','sha256')},'exact generated upstream archive')
    members={};total=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
        for item in archive:
            C.need(not Path(item.name).is_absolute() and '..' not in Path(item.name).parts and not item.issym() and not item.islnk(),'safe complete source archive')
            C.need(item.isdir() or item.isfile(),'source archive ordinary entries only')
            if item.isdir():continue
            C.need(item.name not in members and len(members)<64 and item.size<=1024**2,'finite unique source closure')
            body=archive.extractfile(item).read();total+=len(body);C.need(total<2*1024**2,'bounded full generated source')
            members[item.name]=dict(C.pin(body),mode=item.mode)
    C.need(members==proof['members'],'every upstream source/license byte and mode pinned')
    return members

def construct(root,recipe_root,archive_path,output,*,historical_source=False):
    root,recipe_root,archive_path,output=map(C.ordinary,(root,recipe_root,archive_path,output))
    C.need(not output.exists() and all(not output.is_relative_to(p) for p in (root,recipe_root)),'fresh disjoint Source output')
    derivation=C.load(HERE/'derivation.json')
    C.need(derivation['base_commit']=='44234c090fd93909aea8f6c54b4ef4f949eb0aef','exact audited Main framework')
    for name,row in derivation['files'].items():
        original=C.read(root/row['source_path']);C.need(C.pin(original)==row['original'],'held framework original: '+name)
        text=original.decode()
        for change in row['changes']:
            C.need(change['before'] in text,'whole finite derivation anchor');text=text.replace(change['before'],change['after'])
        actual=C.read(HERE/name);C.need(actual==text.encode() and C.pin(actual)==row['projected'],'whole reviewed derived framework: '+name)
    removed=derivation['no_host_apt_seam']['deleted_original_host_prerequisite']
    C.need(C.pin(C.read(root/removed['source_path']))=={k:removed[k] for k in ('bytes','sha256')},'exact original prerequisite removed only from new operation')
    recipe=C.load(HERE/'recipe-pin.json');proof=recipe['upstream'];raw=C.read(archive_path)
    archive_closure(raw,proof)
    expected=set(recipe['files']);base=recipe_root/recipe['recipe_path']
    found={str(p.relative_to(base)) for p in base.rglob('*') if p.is_file() or p.is_symlink()}
    C.need(found==expected,'complete original recipe namespace')
    recipe_bodies={}
    for name,pin in recipe['files'].items():
        body=C.read(base/name);C.need(C.pin(body)==pin,'exact original llhttp recipe: '+name);recipe_bodies[name]=body
    C.need(b"PKGEXT='.pkg.tar.xz'" in recipe_bodies['PKGBUILD'],'literal original recipe pins XZ-only package format')
    recipe_bodies[proof['archive']['filename']]=raw
    profile=C.load(HERE/'base/profile.json');C.need(all(v is None for v in profile['actual'].values()),'unissued selectors')
    local=('contract.py','entry.py','finish_pair.py','profile.json','admission.TEMPLATE.json','runtime.TEMPLATE.json')
    base_bodies={BASE+n:C.read(HERE/'base'/n) for n in local}
    for name,row in profile['held_inputs'].items():
        body=C.read(root/row['source_path']);C.need(C.pin(body)=={k:row[k] for k in ('bytes','sha256')},'exact held framework dependency: '+name);base_bodies[BASE+name]=body
    for name,body in recipe_bodies.items():base_bodies[BASE+'recipe/'+name]=body
    base_bodies[BASE+'recipe-pin.json']=C.read(HERE/'recipe-pin.json')
    base_bodies[BASE+'reviewed-inputs.json']=encoded({n:C.pin(b)['sha256'] for n,b in sorted(recipe_bodies.items())})
    base_bodies[BASE+'runtime/scripts/build/build_llhttp-reference.py']=C.projected_build(base_bodies[BASE+'runtime/scripts/build/build_v2.py'])
    base_bodies[BASE+'runtime/scripts/build/compare_llhttp.py']=C.projected_compare(base_bodies[BASE+'runtime/scripts/build/compare_v2.py'])
    if not historical_source:
        base_bodies[BASE+'package_metadata.py']=C.read(HERE/'base/package_metadata.py')
        for name in ARTIFACT_BINDINGS:
            path=BASE+'runtime/scripts/build/'+name
            base_bodies[path]=project_artifact_binding(name,base_bodies[path])
    base_bodies['LICENSE']=C.read(root/'LICENSE')
    base_map=encoded(dict(kind='LLHTTP_REFERENCE_MINIMAL_HOSTED_SOURCE_MAP_V1',files={n:dict(C.pin(b),mode=0o644) for n,b in sorted(base_bodies.items())},actual=profile['actual']))
    base_bodies[BASE+'source-map.json']=base_map
    bodies={'held-source/'+n:b for n,b in base_bodies.items()}
    for n in ('admit.py','data.py','hosted_owner.py','host_tools.py','payload.py','retain.py','policy.json','admission.TEMPLATE.json','runtime.TEMPLATE.json'):bodies[OWNER+n]=C.read(HERE/'owner'/n)
    for n in ('README.md','derivation.json','recipe-pin.json'):bodies[PREFIX+n]=C.read(HERE/n)
    bodies[WORKFLOW]=C.read(root/WORKFLOW);bodies['LICENSE']=C.read(root/'LICENSE')
    binding=dict(map=C.pin(base_map),files=len(base_bodies),bytes=sum(map(len,base_bodies.values())))
    bodies[OWNER+'base-binding.json']=encoded(binding)
    program=encoded(dict(schema=1,base_source_map_sha256=C.pin(base_map)['sha256'],files={n:dict(C.pin(b),mode=0o644) for n,b in sorted(bodies.items()) if not n.startswith('held-source/')}))
    bodies[OWNER+'owner-program.json']=program
    value=dict(kind='LLHTTP_REFERENCE_OWNED_HOSTED_SOURCE_V2',files={n:dict(C.pin(b),mode=0o644) for n,b in sorted(bodies.items())},actual=dict(source=None,ref=None,run=None,job=None,Root_admission=None,runtime=None,image=None,owner_domain=None,daemon_domain=None))
    bodies['source-map.json']=encoded(value)
    C.need(32<len(bodies)<80 and sum(map(len,bodies.values()))<2*1024**2,'finite complete llhttp Source')
    output.mkdir(mode=0o700)
    for n,b in bodies.items():
        path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(b)
        path.chmod(0o644)
    D=C.module(HERE/'owner/data.py','llhttp_owner_data');sha=C.pin(bodies['source-map.json'])['sha256'];D.source(output,sha)
    C.verify_source(output/'held-source',C.pin(base_map)['sha256'])
    return dict(files=len(bodies),bytes=sum(map(len,bodies.values())),source_map=C.pin(bodies['source-map.json']),owner_program=C.pin(program),bootstrap_resource_domain=C.pin(bodies[OWNER+'policy.json']),actual=value['actual'],native_build='NOT RUN')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('root','recipe-root','archive','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--historical-source',action='store_true',help='recreate the locked Source62 for historical controls')
    a=p.parse_args();print(json.dumps(construct(a.root,a.recipe_root,a.archive,a.output,historical_source=a.historical_source),indent=2,sort_keys=True))
