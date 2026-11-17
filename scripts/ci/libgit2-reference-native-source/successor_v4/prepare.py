#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite Source-readonly namespace successor; actual Source remains unbound."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import stat
import types

HERE=Path(__file__).resolve().parent
PREDECESSOR_PREPARE=dict(bytes=16768,sha256='4f1ada516c9d9c244468a4d6e18e7418cb52fd42749b4417e29cbe5ab75a4089')
PREDECESSOR_PIN=dict(bytes=2791,sha256='ee71cd4f4583713d63cb9086fb06060eadea2306859d9f5958e5a0a791126c16')

def need(value,why):
    if not value:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def load(path,name,expected):
    path=Path(path);before=path.lstat()
    need(path.is_absolute() and path==path.resolve() and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary helper path')
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and not before.st_mode&0o022 and 0<before.st_size<8*1024**2,'bounded ordinary immutable helper')
    raw=path.read_bytes();after=path.lstat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(identity(before)==identity(after) and pin(raw)==expected,'whole immutable helper byte pin before import')
    value=types.ModuleType(name);value.__file__=str(path);exec(compile(raw,str(path),'exec'),value.__dict__);return value

P3=load(HERE.parent/'successor_v3/prepare.py','libgit2_source_readonly_v4_predecessor',PREDECESSOR_PREPARE)
PREFIX=P3.PREFIX
NEXT='scripts/ci/libgit2-reference-native-source/successor_v4/'
CHANGED=tuple(PREFIX+n for n in ('hosted_owner.py','policy.json','owner-program.json'))
HELPERS=('source_readonly_shared.py','source_readonly.py')
MARKER='source-readonly-v4.json'
ADDED={PREFIX+n for n in HELPERS}|{MARKER,NEXT+'README.md',NEXT+'predecessor-pin.json'}
HELPER_PINS={
    'source_readonly_shared.py':dict(bytes=3052,sha256='55c58b6e15a73339f0c901a6d379f468e39e90e81a6602651942f35162a8e9d8'),
    'source_readonly.py':dict(bytes=1766,sha256='8078d7cdbae5d4a91470170f51160887d9810e84c5dad14dd5a4d6f9888beee7'),
}
encode=P3.encode
ordinary=P3.ordinary
read=P3.read
tree=P3.tree

def proof():
    raw=read(HERE/'predecessor-pin.json');need(pin(raw)==PREDECESSOR_PIN,'immutable complete v4 predecessor manifest')
    value=json.loads(raw)
    need(value['author']=='cbcaba9e98ab96c512ca1d9c6540a830844ff78c' and value['corresponding_llhttp']=='9d82f079490803f20f0810096e4611e42ab28a3c','exact public predecessor/corresponding source revisions')
    need(value['predecessor_prepare']==dict(source_path='scripts/ci/libgit2-reference-native-source/successor_v3/prepare.py',**PREDECESSOR_PREPARE) and value['helpers']==HELPER_PINS,'whole predecessor and helper joins')
    need(all(value[n] is None for n in ('actual_parent_Source','actual_parent_map','actual_dependency_tuple')),'actual dynamic Source and dependency tuple remain unbound')
    for name,wanted in HELPER_PINS.items():need(pin(read(HERE/name))==wanted,'immutable shared helper or namespace adapter: '+name)
    return value

def helpers():
    proof()
    Q=load(HERE/'source_readonly.py','libgit2_source_readonly_v4_namespace',HELPER_PINS['source_readonly.py'])
    Q.project(read(HERE/'source_readonly_shared.py'))
    return Q

def projections(old):
    key=PREFIX+'hosted_owner.py';owner=old[key].decode();seams={}
    def replace(before,after):
        nonlocal owner
        need(owner.count(before)==1 and before!=after and after not in owner,'one exact Source-readonly seam')
        seams.setdefault(key,[]).append(dict(before=before,after=after));owner=owner.replace(before,after)
    anchor="s=importlib.util.spec_from_file_location('libgit2_failed_retirement_v3',HERE/'namespace_adapter.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)"
    replace(anchor,anchor+"\ns=importlib.util.spec_from_file_location('libgit2_source_readonly_v4',HERE/'source_readonly.py');Q=importlib.util.module_from_spec(s);s.loader.exec_module(Q)")
    anchor="        argv.insert(3,'--description=cachy-libgit2-reference-owned-'+self.nonce+'-'+kind)"
    replace(anchor,anchor+'\n        argv=Q.project_service(argv,self.root,self.out,self.nonce,kind)')
    restored=owner
    for seam in reversed(seams[key]):
        need(restored.count(seam['after'])==1,'one whole Source-readonly inverse seam');restored=restored.replace(seam['after'],seam['before'])
    need(restored.encode()==old[key],'whole original controller inverse; all guards and old bodies retained')
    functions=lambda text:{n.name:ast.dump(n,include_attributes=False) for n in ast.walk(ast.parse(text)) if isinstance(n,ast.FunctionDef) and n.name!='start'}
    need(functions(old[key])==functions(owner),'all other controller functions, custody, limits and outcomes unchanged')
    return {key:owner.encode()},seams

def validate_parent(bodies,parent_map_sha256):
    need(re.fullmatch('[0-9a-f]{64}',parent_map_sha256 or '') is not None,'independently selected complete parent map SHA required')
    raw=bodies['source-map.json'];need(pin(raw)['sha256']==parent_map_sha256,'independent complete v3 parent map pin')
    value=json.loads(raw);rows=value['files']
    need(value['kind']=='LIBGIT2_REFERENCE_OWNED_HOSTED_SOURCE_V2' and 32<len(rows)<512 and all(v is None for v in value['actual'].values()),'closed unissued v3 parent Source')
    need(set(bodies)==set(rows)|{'source-map.json'} and sum(map(len,bodies.values()))<128*1024**2,'bounded complete v3 parent namespace and bytes')
    for name,row in rows.items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts and dict(pin(bodies[name]),mode=0o644)==row,'whole v3 parent byte/mode pin: '+name)
    P3.inverse(bodies)
    return value

def parent_bodies(parent,parent_map_sha256):
    proof();parent=ordinary(parent)
    need(re.fullmatch('[0-9a-f]{64}',parent_map_sha256 or '') is not None,'independent exact parent map SHA required before reads')
    raw=read(parent/'source-map.json');need(pin(raw)['sha256']==parent_map_sha256 and stat.S_IMODE((parent/'source-map.json').stat().st_mode)==0o644,'externally pinned ordinary v3 parent map')
    value=json.loads(raw);rows=value['files']
    need(32<len(rows)<512 and sum(row['bytes'] for row in rows.values())<128*1024**2,'finite dynamic parent census before body reads')
    found={str(p.relative_to(parent)) for p in parent.rglob('*') if p.is_file() or p.is_symlink()}
    need(found==set(rows)|{'source-map.json'},'closed physical v3 parent namespace')
    bodies={'source-map.json':raw}
    for name,row in rows.items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts,'relative parent leaf')
        path=parent/name;bodies[name]=read(path);need(stat.S_IMODE(path.stat().st_mode)==row['mode']==0o644,'ordinary exact parent mode')
    validate_parent(bodies,parent_map_sha256)
    D=load(parent/PREFIX/'data.py','libgit2_source_readonly_v4_parent_source',P3.P2.proof()['static_source_files'][PREFIX+'data.py']);D.source(parent,parent_map_sha256)
    return bodies,value

def marker(old,seams):
    return dict(kind='LIBGIT2_EXACT_SOURCE_READONLY_NAMESPACE_V4',parent_author=proof()['author'],parent_Source='UNBOUND',parent_map=pin(old['source-map.json']),parent_tree=tree(old),parent_files=len(old),parent_bytes=sum(map(len,old.values())),helpers=HELPER_PINS,seams=seams,source_audit_scope='SOURCE_AUDITED_MISSING_BIND',actual_namespace_effect='NOT RUN',actual=None,actual_dependency_tuple=None,Root_roles=None,Root_output=None,native_pair='NOT RUN',Root_acceptance=None,qualification='SOURCE DATA ONLY; NOT RUN',old_failure_evidence='UNCHANGED; FAILURE/HOLD remains FAILURE/HOLD')

def inverse(bodies,expected_parent_map_sha256=None):
    proof();need(len(bodies)<512 and sum(map(len,bodies.values()))<128*1024**2,'finite complete v4 Source')
    previous={'previous-v3/'+n for n in (*CHANGED,'source-map.json')}
    need({n for n in bodies if n.startswith('previous-v3/')}==previous,'exact four complete v3 before-bodies')
    old={n:b for n,b in bodies.items() if n not in ADDED and not n.startswith('previous-v3/')}
    for name in (*CHANGED,'source-map.json'):old[name]=bodies['previous-v3/'+name]
    recorded=json.loads(bodies[MARKER]);expected=expected_parent_map_sha256 or recorded['parent_map']['sha256']
    validate_parent(old,expected)
    code,seams=projections(old);need(all(bodies[n]==raw for n,raw in code.items()),'whole exact Source-readonly controller projection')
    need(bodies[MARKER]==encode(marker(old,seams)),'complete unissued v4 marker and original physical parent tree')
    Q=helpers();policy=json.loads(bodies[PREFIX+'policy.json'])
    need(policy.pop('source_readonly_namespace')==Q.DECLARATION and policy==json.loads(old[PREFIX+'policy.json']),'only exact shared Source-readonly declaration; all old predicates and resources unchanged')
    for name,wanted in HELPER_PINS.items():need(bodies[PREFIX+name]==read(HERE/name) and pin(bodies[PREFIX+name])==wanted,'whole shared helper/adapter Source pins')
    for name in ('README.md','predecessor-pin.json'):need(bodies[NEXT+name]==read(HERE/name),'exact v4 review inputs')
    base_sha=json.loads(old[PREFIX+'owner-program.json'])['base_source_map_sha256']
    need(bodies[PREFIX+'owner-program.json']==P3.P2.program(bodies,base_sha),'complete canonical v4 owner-program closure')
    need(bodies['source-map.json']==encode(dict(json.loads(old['source-map.json']),files={n:dict(pin(b),mode=0o644) for n,b in sorted(bodies.items()) if n!='source-map.json'})),'complete canonical v4 Source map, namespace and NULL actuals')
    return old

def construct(parent,parent_map_sha256,out):
    parent,out=map(ordinary,(parent,out));need(not out.exists() and not out.is_relative_to(parent) and not parent.is_relative_to(out),'fresh disjoint successor output')
    old,prior=parent_bodies(parent,parent_map_sha256)
    need(not (set(old)&ADDED) and not any(n.startswith('previous-v3/') for n in old),'fresh v4 namespace; no overwritten predecessor body')
    bodies=dict(old);code,seams=projections(old);bodies.update(code)
    Q=helpers();policy=json.loads(old[PREFIX+'policy.json'])
    need('source_readonly_namespace' not in policy,'no inherited Source-readonly exception')
    policy['source_readonly_namespace']=Q.DECLARATION;bodies[PREFIX+'policy.json']=encode(policy)
    for name in HELPERS:bodies[PREFIX+name]=read(HERE/name)
    for name in ('README.md','predecessor-pin.json'):bodies[NEXT+name]=read(HERE/name)
    for name in (*CHANGED,'source-map.json'):bodies['previous-v3/'+name]=old[name]
    bodies[MARKER]=encode(marker(old,seams))
    bodies[PREFIX+'owner-program.json']=P3.P2.program(bodies,json.loads(old[PREFIX+'owner-program.json'])['base_source_map_sha256'])
    bodies.pop('source-map.json');bodies['source-map.json']=encode(dict(prior,files={n:dict(pin(b),mode=0o644) for n,b in sorted(bodies.items())}))
    inverse(bodies,parent_map_sha256)
    out.mkdir(mode=0o700)
    for name,body in bodies.items():
        path=out/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(body)
        path.chmod(0o644)
    D=load(out/PREFIX/'data.py','libgit2_source_readonly_v4_complete_source',P3.P2.proof()['static_source_files'][PREFIX+'data.py']);D.source(out,pin(bodies['source-map.json'])['sha256'])
    return dict(status='SOURCE_DATA_ONLY',files=len(bodies),bytes=sum(map(len,bodies.values())),tree=tree(bodies),source_map=pin(bodies['source-map.json']),owner_program=pin(bodies[PREFIX+'owner-program.json']),policy=pin(bodies[PREFIX+'policy.json']),parent_map=pin(old['source-map.json']),parent_Source='UNBOUND',actual=prior['actual'],actual_dependency_tuple=None,Root_roles=None,Root_output=None,source_audit_scope='SOURCE_AUDITED_MISSING_BIND',actual_namespace_effect='NOT RUN',native_pair='NOT RUN',Root_acceptance=None)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--parent',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--parent-map-sha256',required=True);a=p.parse_args();print(json.dumps(construct(a.parent,a.parent_map_sha256,a.output),indent=2,sort_keys=True))
