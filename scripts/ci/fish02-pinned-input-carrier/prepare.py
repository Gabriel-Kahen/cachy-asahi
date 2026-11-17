#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Exact Source62 Fish carrier preparation; no Root runtime or private fetch."""
import argparse
import ast
import base64
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('frozen_fish_v8',HERE.parent/'fish-config02-native-source/successor_v8/prepare.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
PREFIX=P.PREFIX
SOURCE62=dict(files=62,bytes=1220725,tree='3c8a238723718c6c6534f6adc5cf020e2275ecc4',map=dict(bytes=13251,sha256='399d833c468d1d932d1e689cc634ca0be50cd0b32dd674fce3e9b0ce17dd66b3'))
OLD_WF='.github/workflows/native-arm-fish-config02-source-v4.yml';NEW_WF='.github/workflows/native-arm-fish02-pinned-input-source.yml'
HELPER=PREFIX+'native349_carrier_case.py';REMOVED=PREFIX+'README.md';MARKER=PREFIX+'source-ro-binding.json'
LOCK='held-source32/scripts/ci/fish-config02-native-source/runtime/scripts/ci/inputs.lock.json'
LOCK_PIN=dict(bytes=328101,sha256='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f')
CORE_PIN=dict(bytes=81606,sha256='f4ea405229a60c74a97fc7ce82709a5c92980bf8dd86d6b250d898ae1db252bb')


def parent_bodies(root):
    root=Path(root);bodies={}
    for path in root.rglob('*'):
        P.need(not path.is_symlink()and(path.is_file()or path.is_dir()),'ordinary frozen62 tree')
        if path.is_file():P.need(path.stat().st_mode&0o777==0o644,'whole62 modes');bodies[str(path.relative_to(root))]=P.read(path)
    validate_parent(bodies);return bodies


def data(bodies):return P.load_bytes(bodies[PREFIX+'data.py'],'inert_exact_fish_source',HERE/'data.py')


def validate_parent(bodies):
    P.need(P.pin(bodies['source-map.json'])==SOURCE62['map']and len(bodies)==62 and sum(map(len,bodies.values()))==SOURCE62['bytes'],'whole frozen62 map/count/bytes')
    rows=json.loads(bodies['source-map.json']);P.need(set(bodies)==set(rows['files'])|{'source-map.json'}and all(dict(P.pin(bodies[n]),mode=0o644)==r for n,r in rows['files'].items())and all(v is None for v in rows['actual'].values()),'complete62 closure and NULL selectors')
    d=data(bodies);P.need(d.git_tree(bodies)==SOURCE62['tree']and P.pin(bodies[LOCK])==LOCK_PIN,'whole62 tree/exact all501 lock')
    d.inverse_source48(None,d.inverse_source50(d.inverse_source53(d.inverse_source57(d.inverse_source60(bodies)))))


def helper():
    core=P.read(HERE/'native349_carrier.FROZEN.py');P.need(P.pin(core)==CORE_PIN,'whole pinned strict native349 helper')
    raw=P.read(HERE/'case.py').decode();anchor="CORE=(HERE/'native349_carrier.FROZEN.py').read_bytes()";P.need(raw.count(anchor)==1,'one whole helper embed')
    raw=raw.replace(anchor,'CORE=base64.b64decode('+repr(base64.b64encode(core).decode())+',validate=True)');ast.parse(raw);return raw.encode()


def assemble(old):
    validate_parent(old);new=dict(old);seams={}
    def replace(name,before,after):
        text=new[name].decode();P.need(text.count(before)==1 and after not in text,'one exact Fish carrier seam');new[name]=text.replace(before,after).encode();seams.setdefault(name,[]).append(dict(before=before,after=after))
    host=PREFIX+'hosted_owner.py';payload=PREFIX+'payload.py';d=PREFIX+'data.py'
    for name in(host,payload):
        anchor="HERE=Path(__file__).resolve().parent"if name==host else"HERE = Path(__file__).resolve().parent"
        replace(name,anchor,anchor+"\ns=importlib.util.spec_from_file_location('fish02_exact_carrier',HERE/'native349_carrier_case.py');N=importlib.util.module_from_spec(s);s.loader.exec_module(N)")
    replace(host,"    for name in ('root','output'):parser.add_argument('--'+name,type=Path,required=True)","    for name in ('root','output','carrier-root'):parser.add_argument('--'+name,type=Path,required=True)")
    anchor="        daemon,available,disk=owner.setup();volume=a.output/'volume';work=volume/'work';marker=work/'actual-owner.json'"
    replace(host,anchor,anchor+"\n        report['pinned_input_carrier']=N.stage(a.carrier_root,work/'native349-pinned-inputs',a.runner_uid,a.runner_gid)")
    replace(host,"                    marker=str(marker),output=str(work/'fish02-native'))","                    marker=str(marker),output=str(work/'fish02-native'),pinned_inputs=str(work/'native349-pinned-inputs'))")
    replace(payload,"    namespace = dict(__name__='fish02_v2_held_entry',__file__=str(entry_path))","    namespace = dict(__name__='fish02_v2_held_entry',__file__=str(entry_path),PINNED_CARRIER=N,PINNED_INPUTS=Path(config['pinned_inputs']))")
    replace(payload,"    exec(compile(D.projected_entry(D.read(entry_path)),str(entry_path),'exec'),namespace)","    exec(compile(N.project_entry(D.projected_entry(D.read(entry_path))),str(entry_path),'exec'),namespace)")
    replace(d,"value['kind']=='FISH02_EXPLICIT_SOURCE_READONLY_SOURCE_V8' and len(rows)==61","value['kind']=='FISH02_EXACT_PINNED_INPUT_CARRIER_SOURCE_V1' and len(rows)==61")
    replace(d,"    inverse_source48(root,inverse_source50(inverse_source53(inverse_source57(inverse_source60(bodies)))))","    inverse_source48(root,inverse_source50(inverse_source53(inverse_source57(inverse_source60(inverse_source62(bodies))))))")
    for name,parts in seams.items():
        reverse=new[name].decode()
        for part in reversed(parts):reverse=reverse.replace(part['after'],part['before'])
        P.need(reverse.encode()==old[name],'whole operational Fish seam inverse')
    new[d]+=b'\n'+P.read(HERE/'inverse.py')
    new[HELPER]=helper();new[NEW_WF]=P.read(HERE/'workflow.yml.in');del new[OLD_WF];del new[REMOVED]
    policy=json.loads(old[PREFIX+'policy.json']);policy['private_pinned_input_carrier']=dict(kind='ONLY_EXACT_MISSING182_BEFORE_UNCHANGED_ALL501',original_lock=LOCK_PIN,files=182,bytes=544634853,largest=104330276,strict_helper=CORE_PIN,case_projection='five exact reversible Fish operands',fetch_tools=['git','ssh','ssh-keygen'],fetch_seconds=180,fetch_process_AS_bytes=2*1024**3,fetch_CPU_seconds=45,fetch_staging_bytes=2*544634853+64*1024**2,original_controller_resources_changed=False,host_package_mutations=0,private_key_scope='fetch step only;0600;key and credential home deleted before controller',agent_used=False,credential_forwarded=False,all501_required=True,canonical_GPG_required=True,URL_overrides=False,new_workflow=NEW_WF,Root_registration=None,carrier_actual_commit=None,Root_authority=None)
    new[PREFIX+'policy.json']=P.encode(policy)
    changed={n:raw.decode()for n,raw in old.items()if n not in new or new[n]!=raw};changed['source-map.json']=old['source-map.json'].decode();changed[PREFIX+'owner-program.json']=old[PREFIX+'owner-program.json'].decode();changed[MARKER]=old[MARKER].decode()
    excluded={'source-map.json',PREFIX+'owner-program.json',MARKER};added=sorted(set(new)-set(old))
    new[MARKER]=P.encode(dict(kind='FISH02_COMPLETE_SOURCE62_CARRIER_INVERSE_V1',origin=SOURCE62,before_utf8=changed,after={n:dict(P.pin(raw),mode=0o644)for n,raw in new.items()if n not in excluded and(n in changed or n in added)},added=added,actual=None))
    program=json.loads(old[PREFIX+'owner-program.json']);program['files']={n:dict(P.pin(raw),mode=0o644)for n,raw in sorted(new.items())if not n.startswith('held-source32/')and n not in('source-map.json',PREFIX+'owner-program.json')};new[PREFIX+'owner-program.json']=P.encode(program)
    rows=dict(json.loads(old['source-map.json']),kind='FISH02_EXACT_PINNED_INPUT_CARRIER_SOURCE_V1',files={n:dict(P.pin(raw),mode=0o644)for n,raw in sorted(new.items())if n!='source-map.json'});new['source-map.json']=P.encode(rows)
    return new


def inverse(bodies):
    proof=json.loads(bodies[MARKER]);P.need(proof['origin']==SOURCE62,'whole fixed62 inverse domain')
    before=proof['before_utf8'];raw=before['source-map.json'].encode();P.need(P.pin(raw)==SOURCE62['map'],'whole frozen62 inverse map')
    rows=dict(json.loads(raw)['files'],**{'source-map.json':dict(SOURCE62['map'],mode=0o644)})
    old={n:before[n].encode()if n in before else bodies[n]for n in rows}
    # Hash every original body against its immutable map before loading code.
    validate_parent(old);P.need(bodies==assemble(old),'whole literal Fish carrier successor');return old


def construct(parent,output):
    parent,output=map(Path,(parent,output));P.need(output.is_absolute()and output==output.resolve()and output.parent.is_dir()and not output.exists()and not output.is_relative_to(parent)and not parent.is_relative_to(output),'fresh disjoint Source output')
    new=assemble(parent_bodies(parent));inverse(new);P.need(len(new)==62 and sum(map(len,new.values()))<2*1024**2,'same62 count/2MiB bound')
    output.mkdir(mode=0o700)
    for name,raw in new.items():
        p=output/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o644)
    d=data(new);d.source(output,P.pin(new['source-map.json'])['sha256'])
    return dict(status='FISH02_PINNED_INPUT_CARRIER_SOURCE_UNISSUED',files=len(new),bytes=sum(map(len,new.values())),tree=d.git_tree(new),source_map=P.pin(new['source-map.json']),policy=P.pin(new[PREFIX+'policy.json']),owner_program=P.pin(new[PREFIX+'owner-program.json']),helper=P.pin(new[HELPER]),frozen_helper=CORE_PIN,workflow_path=NEW_WF,workflow=P.pin(new[NEW_WF]),original_lock=LOCK_PIN,source_inverse_counts=[62,60,57,53,50,48],actual=json.loads(new['source-map.json'])['actual'],Root_registration=None,Root_authority=None,private_fetch='NOT RUN',native_pair='NOT RUN')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in('parent','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();print(json.dumps(construct(a.parent,a.output),sort_keys=True,indent=2))
