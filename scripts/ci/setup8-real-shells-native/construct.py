#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy held6/154 DATA and exact accepted infrastructure; emit source-only workflow."""
import argparse
import ast
import json
from pathlib import Path
import re
import shlex
import shutil
import sys
import zipfile
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import closed as C

ZIP_SHA='2f27ac455f2a1bd1961d2b9c4021849eac7ecf1d24c01e35147298f2f35f25ba'
CONTEXT_SHA='3e1e1bf9ea6c3967b1cf3c1cee934641143eb909596ac6676b3ff5e36954c755'
INFRA=('scripts/ci/maintained_desktop574.py','scripts/ci/maintained-desktop574-inputs.json',
 'scripts/ci/welcome-native/run.py','scripts/ci/welcome-native/ci/caller.py','scripts/ci/tools-native/job.py',
 'scripts/ci/setup8-native/contract.py','scripts/ci/setup8-native/lifecycle.py')
HELPERS=tuple('scripts/ci/setup6-retained-helpers/'+n for n in ('prepare.py','legacy_prefill.py','legacy-prefill-profile.json','carrier-profile.json','LICENSE','NOTICE.md'))
OWN=('closed.py','producer.py','run.py','job.py','container.py','construct.py','test_route.py','workflow.in','README.md','held-pins.json')


def construct(packet,held_source,accepted_zip,output):
    for p in (packet,held_source,accepted_zip,output):C.safe(p)
    C.need(not output.exists() and output.parent.is_dir(),'fresh separate source tree required')
    C.need(not any(output.is_relative_to(p) or p.is_relative_to(output) for p in (packet,held_source)),'output must be disjoint from held inputs')
    C.need(C.digest(packet/'context.json')==CONTEXT_SHA,'exact sealed154 context required')
    import hashlib
    with accepted_zip.open('rb') as stream:archive_sha=hashlib.file_digest(stream,'sha256').hexdigest()
    C.need(archive_sha==ZIP_SHA,'existing accepted original ZIP identity differs')
    pins=json.loads(C.read(C.HERE/'held-pins.json'))
    C.need(set(pins)=={'common.py','construct.py','trial.py','native.py','test_context.py','README.md'},'exact six held source files required')
    C.need({p.name for p in held_source.iterdir() if p.is_file()}==set(pins),'closed held source set differs')
    for n,row in pins.items():C.need(C.pin(C.read(held_source/n))==row,'exact held source file differs: '+n)
    module=C.load(held_source/'common.py','exact_held_context_gate');meta=module.verify_context(packet)
    C.need(len(meta['files'])==154,'exact154 DATA file registry required')
    output.mkdir(mode=0o755)
    def put(name,raw):
        p=output/name;p.parent.mkdir(parents=True,exist_ok=True,mode=0o755);p.write_bytes(raw)
    for name in sorted(meta['files']):put(C.DATA+'/'+name,C.read(packet/name))
    put(C.DATA+'/context.json',C.read(packet/'context.json'))
    for name,row in meta['stage_tree'].items():(output/C.DATA/'stage'/name).chmod(row['mode'])
    module.verify_context(output/C.DATA)
    for n in pins:put(C.HELD+'/'+n,C.read(held_source/n))
    for n in OWN:put('scripts/ci/setup8-real-shells-native/'+n,C.read(C.HERE/n))
    with zipfile.ZipFile(accepted_zip) as z:
        for n in (*INFRA,*HELPERS):
            info=z.getinfo('source-context/'+n);C.need(info.file_size<=2*1024**2,'bounded accepted source member required')
            put(n,z.read(info))
        put('LICENSE',z.read('source/cachy-asahi-setup8/LICENSE'))
    # Acyclic source manifest + fully rendered workflow and registered alias.
    package_dirs=ast.literal_eval(next(n.value for n in ast.parse(C.read(held_source/'common.py')).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PACKAGES' for t in n.targets)))
    licenses={}
    for component,row in meta['packages'].items():
        text=C.read(packet/row['source']/'PKGBUILD').decode();match=re.search(r'^license=\((.*?)\)',text,re.M|re.S)
        C.need(match is not None,'declared package licenses required');licenses[row['package']]=shlex.split(match[1])
    association=dict(actual=None,authority='HASHED_DATA_ONLY; SOURCE_QUALIFIED_CODE_ALIASES_NEVER_NATIVE_RESULT_AUTHORITY',accepted_setup_run=40490674681,accepted_setup_source='5d0f5ae6331807704a8ebafc7922972629e0b96f',files={})
    source_rows={}
    for component,row in meta['packages'].items():
        for path in (packet/row['source']).iterdir():source_rows.setdefault(C.digest(path),[]).append((package_dirs[component]+'/'+path.name,row['package']))
    for name in (*meta['files'],'context.json'):
        raw=C.read(packet/name);sources=[];package='cachy-asahi-setup';grant=['MIT']
        if name.startswith('sources/'):
            part=Path(name).parts[1];component=next(k for k,r in meta['packages'].items() if Path(r['source']).name==part)
            package=meta['packages'][component]['package'];sources=[package_dirs[component]+'/'+Path(name).name];grant=licenses[package]
        elif name.startswith('stage/'):
            relative=name.removeprefix('stage/')
            candidates=source_rows.get(C.pin(raw)['sha256'],[])
            if candidates:
                sources=[r[0] for r in candidates];packages={r[1] for r in candidates};grant=sorted({g for p in packages for g in licenses[p]});package=sorted(packages)
            else:sources=['accepted_setup_archive::'+relative]
        elif name in ('common.py','trial.py','native.py'):sources=[C.HELD+'/'+name]
        elif name.startswith('setup-source/'):sources=['packages/tools/cachy-asahi-setup8/'+Path(name).name]
        elif name=='setup8.pkg.tar.xz':sources=['accepted_setup_run40490674681::packages/cachy-asahi-setup8-a/cachy-asahi-setup-0.3.0-1-any.pkg.tar.xz']
        elif name=='context.json':sources=[C.HELD+'/construct.py']
        else:raise ValueError('unclassified DATA leaf: '+name)
        association['files'][name]=dict(pin=C.pin(raw),source_association=sources,package=package,license=grant,authority='DATA_ONLY')
    put('scripts/ci/setup8-real-shells-native/data-association.json',(json.dumps(association,sort_keys=True,indent=2)+'\n').encode())
    put('source-only.json',(json.dumps(dict(actual_source=None,actual_ref=None,actual_run=None,native='NOT_RUN',physical_M2='NOT_RUN',signed_release='NOT_RUN',purpose='FINITE_SETUP8_REAL_SHELLS_NATIVE_CONSTRUCTION'),indent=2)+'\n').encode())
    manifest=dict(schema_version=1,actual_source=None,actual_ref=None,actual_run=None,held_context_sha256=CONTEXT_SHA,components=list(meta['components']),files=C.files(output),infrastructure_source='5d0f5ae6331807704a8ebafc7922972629e0b96f',retained574='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad',data_files=155,held_sources=6)
    C.save(output/C.MANIFEST,manifest);raw=C.read(output/C.MANIFEST)
    template=C.read(output/C.TEMPLATE).decode();rendered=template.replace('@MANIFEST_SHA256@',C.pin(raw)['sha256']).replace('@JOB_SHA256@',manifest['files']['scripts/ci/setup8-real-shells-native/job.py']['sha256'])
    for n in C.WORKFLOWS:put(n,rendered.encode())
    C.verify(output)
    return dict(status='PASS_CLOSED_NATIVE_SOURCE_CONSTRUCTED',source_files=len(C.files(output)),manifest_sha256=C.digest(output/C.MANIFEST),context_sha256=CONTEXT_SHA,actual_source=None,actual_ref=None,actual_run=None,native='NOT_RUN')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('packet','held-source','accepted-zip','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();print(json.dumps(construct(*(C.safe(getattr(a,n).absolute()) for n in ('packet','held_source','accepted_zip','output'))),indent=2))
