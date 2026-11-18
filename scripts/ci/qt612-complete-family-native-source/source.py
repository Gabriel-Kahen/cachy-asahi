# SPDX-License-Identifier: MIT
"""Finite DATA construction for five matching Qt6.12 providers; no build actor."""
import argparse
import importlib.util
from pathlib import Path
import re
import shlex
import sys
import tarfile

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('family_common',HERE/'common.py')
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
M,P,need=C.M,C.P,C.need


def project_builder(raw,key,filename):
    body=P.project_builder(raw).decode();edits=[]
    def change(old,new):
        nonlocal body
        need(body.count(old)==1 and new not in body,'EXACT_FAMILY_BUILDER_SEAM')
        body=body.replace(old,new);edits.append((old,new))
    change("'cachy-qt612-reference-' + os.environ['CACHY_QT612_REFERENCE_NONCE'] + '-' + os.environ['CACHY_QT612_REFERENCE_ATTEMPT']",
           "'cachy-qt612-family-' + os.environ['CACHY_QT612_REFERENCE_NONCE'] + '-"+key+"-' + os.environ['CACHY_QT612_REFERENCE_ATTEMPT']")
    change("r'cachy-qt612-reference-[0-9a-f]{32}-[12]'","r'cachy-qt612-family-[0-9a-f]{32}-"+key+"-[12]'")
    change(P.PACKAGE,filename)
    change('from qt612_actor_gate import require_actual_capacity\n    require_actual_capacity()',
           "from qt612_family_gate import require_actual_family\n    require_actual_family('"+key+"')")
    # A single exact mount supplies only the pinned finite proof collector.
    change("                   '--cap-drop=ALL',", "                   '--mount', 'type=bind,src=' + str(Path(__file__).resolve().parents[4] / 'scripts/ci/qt612-complete-family-native-source') + ',dst=/family,readonly',\n                   '--cap-drop=ALL',")
    for old,new in (('qt612-stage-contract.json','family-stage.json'),('qt612-configuration.json','family-configuration.json'),
                    ('qt612-source-notices.json','family-notices.json'),('qt612-dependencies.missing','family-dependencies.missing')):
        change(old,new)
    change("'family-stage.json',", "'family-build-proof.json', 'family-stage.json',")
    if key=='shadertools':change("'family-build-proof.json',", "'family-shader-smoke.json', 'family-build-proof.json',")
    inverse=body
    for old,new in reversed(edits):need(inverse.count(new)==1,'FAMILY_BUILDER_INVERSE');inverse=inverse.replace(new,old)
    need(inverse.encode()==P.project_builder(raw),'WHOLE_PARENT_BUILDER_INVERSE')
    compile(body,'build_family.py','exec');return body.encode()


def project_entry(raw,key,row):
    requirements=sum((row['metadata'].get(k,[]) for k in ('depends','makedepends','checkdepends')),[])
    parent=P.project_entry(raw,requirements).decode()
    before='''python /inputs/source.py configuration --build src/build --profile /inputs/configure.cmake > /out/qt612-configuration.json
python /inputs/source.py verify --root src/qtbase-everywhere-src-6.12.0 --policy /inputs/source-notices.json > /out/qt612-source-notices.json'''
    config=' '.join(shlex.quote(x) for x in row['config_args'])
    notices=' '.join(shlex.quote(x) for x in row['notice_args'])
    source='src/'+row['archive']['filename'].removesuffix('.tar.xz')
    after=('python /inputs/source.py configuration --build src/build '+config+' > /out/qt612-configuration.json\n'
           'python /inputs/source.py verify --root '+shlex.quote(source)+' --policy /inputs/source-notices.json '+notices+' > /out/qt612-source-notices.json\n'
           'python /family/proof.py capture --component '+key+' --build src/build --contract /inputs/family-contract.json'+
           (' --shader-output src/smoke-output' if key=='shadertools' else '')+' > /out/family-build-proof.json'+
           ('\ncp -- src/shader-smoke.json /out/family-shader-smoke.json' if key=='shadertools' else ''))
    need(parent.count(before)==1,'EXACT_COMPONENT_PROOF_SEAM')
    body=parent.replace(before,after);need(body.replace(after,before)==parent,'WHOLE_ENTRY_PROOF_INVERSE')
    for old,new in (('qt612-stage-contract.json','family-stage.json'),('qt612-configuration.json','family-configuration.json'),
                    ('qt612-source-notices.json','family-notices.json'),('qt612-dependencies.missing','family-dependencies.missing')):
        body=body.replace(old,new)
    return body.encode()


def selected_notices(archive,policy,observed):
    expected={n:h for n,h in policy['source_notices'].items() if n in
              ('LICENSES/LGPL-3.0-only.txt','LICENSES/GPL-3.0-only.txt','LICENSES/Qt-GPL-exception-1.0.txt','REUSE.toml')}
    need(expected,'AUDITED_UPSTREAM_LICENSE_EVIDENCE_REQUIRED')
    found={};count=total=0
    with tarfile.open(archive,'r|xz') as source:
        for member in source:
            count+=1;total+=member.size
            need(count<=100000 and 0<=member.size<=128*1024**2 and total<=2*1024**3,'FINITE_SOURCE_ARCHIVE_SCAN')
            name=member.name.split('/',1)[-1]
            if name in expected:
                need(member.isfile() and name not in found and 0<member.size<=4*1024**2,'ORDINARY_SOURCE_NOTICE')
                raw=source.extractfile(member).read(member.size+1)
                need(len(raw)==member.size and C.pin(raw)['sha256']==expected[name],'PINNED_UPSTREAM_NOTICE_BYTES')
                found[name]=raw
            source.members.clear()
    need(set(found)==set(expected),'COMPLETE_SELECTED_NOTICE_SET');M.unchanged(observed)
    return found


def prepare_source(*,framework,providers,archives,base_provider,candidate_map,md4c,output,consumer_root=None):
    lock=C.load_lock();observed={};out=M.ordinary(output);framework=M.ordinary(framework)
    need(set(providers)==set(archives)==set(C.ORDER),'EXACT_FIVE_SELECTED_SOURCE_INPUTS')
    roots=[framework]+[M.ordinary(providers[k]) for k in C.ORDER]
    if consumer_root is not None:
        roots.append(M.ordinary(consumer_root))
    need(not out.exists() and all(not out.is_relative_to(p) and not p.is_relative_to(out) for p in roots),'FRESH_DISJOINT_FAMILY_SOURCE')
    dependency_lock=P.selected(C.PARENT/'dependency-candidates.lock.json',P.DEPENDENCIES,observed)
    base=P.validate_base_provider(base_provider,dependency_lock,observed) if base_provider else None
    deps=P.dependency_inputs(candidate_map=candidate_map,md4c=md4c,lock=dependency_lock,observed=observed) if candidate_map else None
    complete=base is not None and deps is not None and deps['complete'] is True
    profile_path='scripts/ci/llhttp-reference-native-source/base/profile.json'
    profile=M.decode(M.stream(framework/profile_path,lock['framework_files'][profile_path],observed,collect=True))
    writer=M.Writer(out);files={};component_inputs={}
    def put(name,raw):files[name]=writer.put(name,raw=raw);return files[name]
    try:
        for name,pin in lock['parents'].items():
            files['scripts/ci/qt612-reference-native-source/'+name]=writer.put('scripts/ci/qt612-reference-native-source/'+name,source=C.PARENT/name,expected=pin,observed=observed)
        for name in ('common.py','source.py','pipeline.py','proof.py','qualify.py','lifecycle.py',
                     'consumer.py','consumer_worker.py',
                     'family.lock.json','dependency-audit.DATA.json','README.md'):
            put('scripts/ci/qt612-complete-family-native-source/'+name,M.stream(HERE/name,None,observed,collect=True,cap=4*1024**2))
        raw_builder=M.stream(framework/'scripts/build/build_v2.py',lock['framework_files']['scripts/build/build_v2.py'],observed,collect=True)
        raw_entry=M.stream(framework/'scripts/build/container-entry-v2.sh',lock['framework_files']['scripts/build/container-entry-v2.sh'],observed,collect=True)
        for key in C.ORDER:
            row=lock['components'][key];root=M.ordinary(providers[key])/row['recipe_path'];inputs={}
            for name,pin in row['recipe_inputs'].items():
                raw=M.stream(root/name,{k:pin[k] for k in ('bytes','sha256')},observed,collect=True)
                if name=='PKGBUILD':put('inverse/'+key+'/PKGBUILD',raw);raw=C.project_pkgbuild(raw,key)
                written=put('recipes/'+key+'/'+name,raw);inputs[name]=written['sha256']
            for name,pin in row['contracts'].items():
                raw=M.stream(root/name,{k:pin[k] for k in ('bytes','sha256')},observed,collect=True)
                put('contracts/'+key+'/'+name,raw)
            contract=M.stream(root/'BUILD-CONTRACT.json',{k:row['contracts']['BUILD-CONTRACT.json'][k] for k in ('bytes','sha256')},observed,collect=True)
            inputs['family-contract.json']=put('recipes/'+key+'/family-contract.json',contract)['sha256']
            put('reviewed/'+key+'.json',C.encoded(inputs));component_inputs[key]=inputs
            archive=M.ordinary(archives[key]);archive_pin={k:row['archive'][k] for k in ('bytes','sha256')}
            files['archives/'+key+'/'+row['archive']['filename']]=writer.put('archives/'+key+'/'+row['archive']['filename'],source=archive,expected=archive_pin,observed=observed,cap=128*1024**2)
            policy=M.decode(M.stream(root/'source-notices.json',None,observed,collect=True));notices=selected_notices(archive,policy,observed)
            evidence=[]
            for i,(name,raw) in enumerate(sorted(notices.items())):
                path='notices/'+str(i)+'.txt';put('materials/'+key+'/'+path,raw)
                evidence.append(dict(id='notice-'+str(i),path=path,**C.pin(raw)))
            catalog=dict(schema_version=1,purpose='source-cache-inputs',sources=[dict(material=dict(id=key,path=row['archive']['filename'],**archive_pin),url=row['archive']['url'],revision=row['upstream_revision'],license='Pinned per-file Qt and third-party grants; selected upstream evidence only; legal HELD',license_evidence=evidence)])
            catalog_raw=C.encoded(catalog);put('materials/'+key+'/catalog.json',catalog_raw)
            plan=dict(schema_version=1,purpose='offline-build-sources',recipe_inputs=inputs,catalog_sha256=C.pin(catalog_raw)['sha256'],sources=[dict(source=row['archive']['url'],id=key,revision=row['upstream_revision'])])
            put('materials/'+key+'/plan.json',C.encoded(plan))
            for name,pin in profile['held_inputs'].items():
                if name.startswith('runtime/') and name not in ('runtime/scripts/build/build_v2.py','runtime/scripts/build/container-entry-v2.sh'):
                    target='runtime/'+key+'/'+name.removeprefix('runtime/')
                    files[target]=writer.put(target,source=framework/pin['source_path'],expected={k:pin[k] for k in ('bytes','sha256')},observed=observed)
            put('runtime/'+key+'/scripts/build/build_family.py',project_builder(raw_builder,key,row['filename']))
            put('runtime/'+key+'/scripts/build/container-entry-v2.sh',project_entry(raw_entry,key,row))
            gate="from pathlib import Path\nimport sys\n_root=Path(__file__).resolve().parents[4]\nsys.path.insert(0,str(_root/'scripts/ci/qt612-complete-family-native-source'))\nfrom pipeline import require_actual_family as _require\ndef require_actual_family(component):\n    return _require(component,source=str(_root),actor_argv=sys.argv[1:])\n"
            put('runtime/'+key+'/scripts/build/qt612_family_gate.py',gate.encode())
        inputs=dict(base_provider=base_provider,dependencies=deps,complete=complete,baseline_packages=349,derived_packages=356 if complete else None,GPG='NOT_RUN',Root_acceptance=None)
        put('family-inputs.DATA.json',C.encoded(inputs))
        if complete:
            inventory=dict(base['inventory']);inventory.update({n:r['version'] for n,r in deps['packages'].items()})
            need(len(inventory)==356,'UNCHANGED349_PLUS7')
            put('expected356.lock',''.join(n+' '+v+'\n' for n,v in sorted(inventory.items())).encode())
        consumer_pin=None
        if consumer_root is not None:
            desktop=lock['consumer']
            path=M.ordinary(consumer_root)/desktop['source_path']
            for name,pin in desktop['files'].items():
                raw=M.stream(path/name,pin,observed,collect=True,mode=0o644)
                put('consumer/'+name,raw)
            interface=M.decode(M.stream(path/'INTERFACE.DATA.json',desktop['files']['INTERFACE.DATA.json'],observed,collect=True))
            need(interface['provider_sources']=={k:v['commit'] for k,v in lock['components'].items()},'MATCHING_CONSUMER_PROVIDER_RECIPES')
            consumer_pin=desktop['commit']
        plan=C.local('pipeline').family_plan(lock,complete=complete,consumer_selected=consumer_pin is not None)
        put('family-plan.DATA.json',C.encoded(plan))
        mapping=dict(schema=1,kind='QT612_COMPLETE_FAMILY_SOURCE_DATA_V1',files=files,components=component_inputs,
                     input_plan_complete=complete,desktop_consumer=consumer_pin,actual=dict.fromkeys(M.ACTUAL),Root_acceptance=None)
        raw=C.encoded(mapping);writer.put('source-map.json',raw=raw);M.unchanged(observed)
        C.read_source(out,C.pin(raw)['sha256'])
        return dict(status='PREPARED_FAMILY_DATA_ONLY' if complete else 'HOLD_MISSING_FAMILY_DEPENDENCIES',
                    source_map=C.pin(raw),files=len(files)+1,baseline_files=base['files'] if base else 0,
                    additional_pairs=deps['available_packages'] if deps else 0,
                    missing_roles=([] if base else ['complete517 baseline provider'])+
                    (['signed7 dependency references'] if deps is None else deps['missing_roles']),
                    Root_acceptance=None)
    finally:writer.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request',type=Path,required=True)
    parser.add_argument('--request-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();sys.addaudithook(M.fence)
    request=M.load(args.request,dict(bytes=args.request.lstat().st_size,sha256=args.request_sha256),{})
    required={'framework','providers','archives','base_provider','candidate_map','md4c'}
    need(set(request) in (required,required|{'consumer_root'}),'EXACT_PREPARATION_REQUEST')
    print(C.encoded(prepare_source(**request,output=args.output)).decode(),end='')


def prepare_cache(*,source,source_map_sha256,output):
    C.read_source(source,source_map_sha256);source=M.ordinary(source);out=M.ordinary(output)
    need(not out.is_relative_to(source) and not source.is_relative_to(out),'DISJOINT_FAMILY_CACHE')
    observed={};writer=M.Writer(out)
    try:
        writer.directory(out/'.partial');writer.put('FORMAT',raw=b'cachy-asahi-source-cache-v1\n',mode=0o600)
        for key,row in C.load_lock()['components'].items():
            raw=M.stream(source/'materials'/key/'catalog.json',None,observed,collect=True);record=M.decode(raw)['sources'][0]
            pin=record['material'];name='objects/'+pin['sha256']
            writer.put(name,source=source/'archives'/key/row['archive']['filename'],expected={k:pin[k] for k in ('bytes','sha256')},observed=observed,cap=128*1024**2,mode=0o600)
            receipt=dict(schema_version=1,purpose='source-cache-receipt',inputs_sha256=C.pin(raw)['sha256'],source=record,object_path=name,legal_acceptance=False,source_completeness_accepted=False)
            writer.put('receipts/'+C.pin(raw)['sha256']+'-'+key+'.json',raw=C.encoded(receipt),mode=0o600)
        M.unchanged(observed);return dict(status='PREPARED_OFFLINE_CACHE_DATA_ONLY',Root_acceptance=None)
    finally:writer.close()


if __name__=='__main__':
    main()
