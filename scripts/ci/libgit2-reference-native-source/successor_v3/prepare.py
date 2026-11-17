#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite diagnostic/failed-owner Source successor; no actual Source selected."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import stat
import types

HERE=Path(__file__).resolve().parent
PREDECESSOR_PREPARE=dict(bytes=13272,sha256='7d4d6eafda7e59ea0748c0c04144339ddad64e5eda8372e514f9c30d0d1ae2be')
PREDECESSOR_PIN=dict(bytes=1644,sha256='e1387cba4e805efb9c9c3065ff8473a507d437644d4b60ea0ee6a618281cb55f')

def need(value,why):
    if not value:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def load(path,name,expected):
    path=Path(path);before=path.lstat()
    need(path.is_absolute() and path==path.resolve() and not any(p.is_symlink() for p in (path,*path.parents)), 'ordinary helper path')
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and not before.st_mode&0o022 and 0<before.st_size<8*1024**2,'bounded ordinary immutable helper')
    raw=path.read_bytes();after=path.lstat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(identity(before)==identity(after) and pin(raw)==expected,'whole immutable helper byte pin before import')
    value=types.ModuleType(name);value.__file__=str(path);exec(compile(raw,str(path),'exec'),value.__dict__);return value

P2=load(HERE.parent/'successor_v2/prepare.py','libgit2_payload_v3_predecessor',PREDECESSOR_PREPARE)
PREFIX=P2.PREFIX
NEXT='scripts/ci/libgit2-reference-native-source/successor_v3/'
CHANGED=tuple(PREFIX+n for n in ('hosted_owner.py','payload.py','policy.json','owner-program.json'))
HELPERS=('payload_diagnostic.py','failed_retirement.py','namespace_adapter.py')
MARKER='payload-retirement-v3.json'
ADDED={PREFIX+n for n in HELPERS}|{MARKER,NEXT+'README.md',NEXT+'predecessor-pin.json'}
HELPER_PINS={
    'payload_diagnostic.py':dict(bytes=1564,sha256='18592a89eb5c6cc7fd182167a37d566dbfa098647167e2a67180083927f1517a'),
    'failed_retirement.py':dict(bytes=4165,sha256='95fc52f8a6c610ae165eecfe959cc696c210fa0fd3238bd9b24c9d5ffbcf9df1'),
    'namespace_adapter.py':dict(bytes=1772,sha256='f6705b83b0c7daeb11bf385f48c32ae6e9549439602d6410b8e03d28fd6b029a'),
}
encode=P2.encode
ordinary=P2.ordinary
read=P2.read
tree=P2.tree

PHASE_ANCHORS=(
('entry',"    D.need(sys.flags.isolated and __debug__ and os.getuid() == os.geteuid() > 0, 'ordinary isolated payload')"),
('launch-data',"    config_path = Path(sys.argv[1]); config = D.decode(D.read(config_path)); config_path.unlink()"),
('environment',"    os.environ.clear(); os.environ.update(config['environment'])"),
('admission',"    a,r = D.admission(root,map_sha,config['admission_raw'].encode(),config['runtime_raw'].encode(),"),
('owner-AS',"    policy = D.decode(D.read(HERE/'policy.json'))"),
('marker-wait',"    end = time.monotonic()+30; marker = Path(config['marker'])"),
('marker-read',"    raw = D.read(marker); observed = D.decode(raw)"),
('owner-observation',"    D.observation(observed,a,map_sha,policy,os.getpid(),int(fields[19]),group[3:])"),
('owner-kernel',"    own = Path('/sys/fs/cgroup'+group[3:])"),
('dispatch-context',"    D.need(observed['run'] == os.environ['GITHUB_RUN_ID'] and observed['attempt'] == 1"),
('daemon-identity',"    daemon=observed['daemon']; daemon_fields=Path('/proc/'+str(daemon['pid'])+'/stat').read_text().rpartition(')')[2].split()"),
('daemon-kernel',"    parent=Path('/sys/fs/cgroup'+daemon['cgroup'])"),
('socket-identity',"    socket=Path(observed['endpoint'][7:]).stat()"),
('readonly-filesystem',"    D.need(not os.access('/tmp',os.W_OK) and not os.access('/var/tmp',os.W_OK) and not os.access(root,os.W_OK),'actual owner writable filesystem restricted to quota work domain')"),
('held-entry',"    base = root/'held-source'; entry_path = base/D.BASE_PREFIX/'entry.py'"),
('inner-pair',"    report = namespace['execute'](base,Path(config['output']),map_sha,a,r)"),
)
STOP='''def stop(self,kind):
        if kind not in self.units:return dict(submitted=False)
        row=self.show(kind);owned=self.units[kind]
        if row.get('LoadState')!='not-found':
            D.need(row.get('Description')=='cachy-libgit2-reference-owned-'+self.nonce+'-'+kind,'owned unit before stop')
            if owned.get('cgroup'):D.need(row.get('ControlGroup') in ('',owned['cgroup']),'same unit cgroup before stop')
            self.run([self.tool('systemctl'),'stop',D.unit(self.nonce,kind)],20)
        censuses=[]
        for _ in range(2):
            current=self.show(kind)
            D.need(current.get('ActiveState') in ('inactive','failed') or current.get('LoadState')=='not-found','owned service absent')
            cgroup=owned.get('cgroup') or '/system.slice/'+D.unit(self.nonce,kind)
            snapshot=F.empty_snapshot(Path('/sys/fs/cgroup'+cgroup));exited=False
            if kind in self.pidfds:
                exited=F.pidfd_exited(self.pidfds[kind],owned.get('original_pidfd_identity'))
                D.need(exited,'original service PIDFD exited')
            censuses.append(dict(cgroup=cgroup,pidfd_exited=exited,**snapshot));time.sleep(.05)
        if current.get('Result')not in(None,'success')and current.get('LoadState')!='not-found':
            return F.retire_failed(kind,self.nonce,owned,row,current,self.pidfds.get(kind),censuses)
        D.need(current.get('Result') in (None,'success') or current.get('LoadState')=='not-found','no forced/timeout service retirement')
        return dict(unit=D.unit(self.nonce,kind),empty_twice=True,pidfd_exited=kind in self.pidfds,
                    state=current.get('ActiveState'),result=current.get('Result'))'''


def proof():
    raw=read(HERE/'predecessor-pin.json');need(pin(raw)==PREDECESSOR_PIN,'immutable complete v3 predecessor manifest')
    value=json.loads(raw)
    need(value['author']=='48d83dd40424793232a321db37d3887722ccc21e' and value['corresponding_llhttp']=='8667d0a1912bc141416e1ab954cfe94adba835e4','exact public predecessor/corresponding source revisions')
    need(value['predecessor_prepare']==dict(source_path='scripts/ci/libgit2-reference-native-source/successor_v2/prepare.py',**PREDECESSOR_PREPARE) and value['helpers']==HELPER_PINS,'whole predecessor and helper joins')
    need(value['actual_parent_Source'] is None and value['actual_parent_map'] is None,'actual dynamic Source remains unbound')
    for name,wanted in HELPER_PINS.items():need(pin(read(HERE/name))==wanted,'immutable shared helper or namespace adapter: '+name)
    return value

def helpers():
    proof()
    X=load(HERE/'payload_diagnostic.py','libgit2_payload_v3_diagnostics',HELPER_PINS['payload_diagnostic.py'])
    F=load(HERE/'namespace_adapter.py','libgit2_payload_v3_namespace',HELPER_PINS['namespace_adapter.py'])
    F.project(read(HERE/'failed_retirement.py'))
    return X,F

def projections(old):
    owner=old[PREFIX+'hosted_owner.py'].decode();payload=old[PREFIX+'payload.py'].decode();seams={}
    def replace(text,before,after,key):
        need(text.count(before)==1 and before!=after and after not in text,'one exact successor seam: '+key)
        seams.setdefault(key,[]).append(dict(before=before,after=after));return text.replace(before,after)
    key=PREFIX+'hosted_owner.py'
    anchor="s=importlib.util.spec_from_file_location('libgit2_go_cli_va_v2',HERE/'go_cli_va.py');V=importlib.util.module_from_spec(s);s.loader.exec_module(V)"
    owner=replace(owner,anchor,anchor+"\ns=importlib.util.spec_from_file_location('libgit2_failed_retirement_v3',HERE/'namespace_adapter.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)",key)
    anchor='                self.units[kind].update(actual);return actual'
    owner=replace(owner,anchor,'                self.units[kind].update(actual);self.units[kind].update(original_pidfd=fd,original_pidfd_identity=F.pidfd_identity(fd));return actual',key)
    nodes=[n for n in ast.walk(ast.parse(owner)) if isinstance(n,ast.FunctionDef) and n.name=='stop'];need(len(nodes)==1,'one original stop method')
    owner=replace(owner,ast.get_source_segment(owner,nodes[0]),STOP,key)
    key=PREFIX+'payload.py'
    anchor="s = importlib.util.spec_from_file_location('libgit2-reference_v2_data',HERE/'data.py');D=importlib.util.module_from_spec(s);s.loader.exec_module(D)"
    payload=replace(payload,anchor,anchor+"\ns = importlib.util.spec_from_file_location('libgit2_payload_diagnostic_v3',HERE/'payload_diagnostic.py');X=importlib.util.module_from_spec(s);s.loader.exec_module(X)",key)
    for phase,anchor in PHASE_ANCHORS:payload=replace(payload,anchor,"    X.phase('"+phase+"')\n"+anchor,key)
    payload=replace(payload,"        print('HOLD_PAYLOAD: '+type(error).__name__,file=sys.stderr);raise SystemExit(2)","        print(X.record(error),file=sys.stderr);raise SystemExit(2)",key)
    code={PREFIX+'hosted_owner.py':owner.encode(),PREFIX+'payload.py':payload.encode()}
    for name,edits in seams.items():
        restored=code[name].decode()
        for seam in reversed(edits):
            need(restored.count(seam['after'])==1,'one whole inverse projection seam');restored=restored.replace(seam['after'],seam['before'])
        need(restored.encode()==old[name],'all original guard bodies retained byte for byte')
    before,after=ast.parse(old[PREFIX+'hosted_owner.py']),ast.parse(owner)
    functions=lambda t:{n.name:ast.dump(n,include_attributes=False) for n in ast.walk(t) if isinstance(n,ast.FunctionDef) and n.name not in ('start','stop')}
    need(functions(before)==functions(after),'all other controller functions, custody, limits and outcome unchanged')
    return code,seams

def validate_parent(bodies,map_sha):
    need(re.fullmatch('[0-9a-f]{64}',map_sha or '') is not None,'independently selected complete parent map SHA required')
    raw=bodies['source-map.json'];need(pin(raw)['sha256']==map_sha,'independent complete parent map pin')
    value=json.loads(raw);rows=value['files']
    need(value['kind']=='LIBGIT2_REFERENCE_OWNED_HOSTED_SOURCE_V2' and 32<len(rows)<512 and all(v is None for v in value['actual'].values()),'closed unissued v2 parent Source')
    need(set(bodies)==set(rows)|{'source-map.json'} and sum(map(len,bodies.values()))<128*1024**2,'bounded complete v2 parent namespace and bytes')
    for name,row in rows.items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts and dict(pin(bodies[name]),mode=0o644)==row,'whole v2 parent byte/mode pin: '+name)
    P2.inverse(bodies)
    return value

def parent_bodies(parent,map_sha):
    proof();parent=ordinary(parent)
    need(re.fullmatch('[0-9a-f]{64}',map_sha or '') is not None,'independent exact parent map SHA required before reads')
    raw=read(parent/'source-map.json');need(pin(raw)['sha256']==map_sha and stat.S_IMODE((parent/'source-map.json').stat().st_mode)==0o644,'externally pinned ordinary parent map')
    value=json.loads(raw);rows=value['files']
    need(32<len(rows)<512 and sum(row['bytes'] for row in rows.values())<128*1024**2,'finite parent census before body reads')
    found={str(p.relative_to(parent)) for p in parent.rglob('*') if p.is_file() or p.is_symlink()}
    need(found==set(rows)|{'source-map.json'},'closed physical v2 parent namespace')
    bodies={'source-map.json':raw}
    for name,row in rows.items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts,'relative parent leaf')
        path=parent/name;bodies[name]=read(path);need(stat.S_IMODE(path.stat().st_mode)==row['mode']==0o644,'ordinary exact parent mode')
    validate_parent(bodies,map_sha)
    D=load(parent/PREFIX/'data.py','libgit2_payload_v3_parent_source',P2.proof()['static_source_files'][PREFIX+'data.py']);D.source(parent,map_sha)
    return bodies,value

def marker(old,seams):
    return dict(kind='LIBGIT2_PAYLOAD_DIAGNOSTICS_FAILED_RETIREMENT_V3',parent_author=proof()['author'],parent_Source='UNBOUND',parent_map=pin(old['source-map.json']),parent_tree=tree(old),parent_files=len(old),parent_bytes=sum(map(len,old.values())),helpers=HELPER_PINS,seams=seams,actual=None,native_pair='NOT RUN',Root_acceptance=None,qualification='CORRESPONDING DEFINITION IMPLEMENTED; NOT RUN',historical_v2_requirements='RETAINED BEFORE-BODY; corresponding definitions implemented, qualification NOT RUN',payload_success_required=True,old_failure_evidence='UNCHANGED; FAILURE/HOLD remains FAILURE/HOLD')

def inverse(bodies,expected_parent_map_sha256=None):
    proof();need(len(bodies)<512 and sum(map(len,bodies.values()))<128*1024**2,'finite complete v3 Source')
    previous={'previous-v2/'+n for n in (*CHANGED,'source-map.json')}
    need({n for n in bodies if n.startswith('previous-v2/')}==previous,'exact five complete v2 before-bodies')
    old={n:b for n,b in bodies.items() if n not in ADDED and not n.startswith('previous-v2/')}
    for name in (*CHANGED,'source-map.json'):old[name]=bodies['previous-v2/'+name]
    recorded=json.loads(bodies[MARKER]);expected=expected_parent_map_sha256 or recorded['parent_map']['sha256']
    validate_parent(old,expected)
    code,seams=projections(old);need(all(bodies[n]==raw for n,raw in code.items()),'whole exact diagnostic/controller projections')
    need(bodies[MARKER]==encode(marker(old,seams)),'complete unissued v3 marker and original physical parent tree')
    X,F=helpers();policy=json.loads(bodies[PREFIX+'policy.json'])
    need(policy.pop('payload_diagnostics')==X.DECLARATION and policy.pop('failed_owner_retirement')==F.DECLARATION and policy==json.loads(old[PREFIX+'policy.json']),'only two exact shared declarations; all resources and old predicates unchanged')
    for name,wanted in HELPER_PINS.items():need(bodies[PREFIX+name]==read(HERE/name) and pin(bodies[PREFIX+name])==wanted,'whole shared helper/adapter Source pins')
    for name in ('README.md','predecessor-pin.json'):need(bodies[NEXT+name]==read(HERE/name),'exact v3 review inputs')
    base_sha=json.loads(old[PREFIX+'owner-program.json'])['base_source_map_sha256']
    need(bodies[PREFIX+'owner-program.json']==P2.program(bodies,base_sha),'complete canonical v3 owner-program closure')
    need(bodies['source-map.json']==encode(dict(json.loads(old['source-map.json']),files={n:dict(pin(b),mode=0o644) for n,b in sorted(bodies.items()) if n!='source-map.json'})),'complete canonical v3 Source map, namespace and NULL actuals')
    return old

def construct(parent,parent_map_sha256,output):
    parent,output=map(ordinary,(parent,output));need(not output.exists() and not output.is_relative_to(parent) and not parent.is_relative_to(output),'fresh disjoint successor output')
    old,prior=parent_bodies(parent,parent_map_sha256);bodies=dict(old);code,seams=projections(old);bodies.update(code)
    X,F=helpers();policy=json.loads(old[PREFIX+'policy.json'])
    need('payload_diagnostics' not in policy and 'failed_owner_retirement' not in policy,'no inherited diagnostic/retirement waiver')
    policy['payload_diagnostics']=X.DECLARATION;policy['failed_owner_retirement']=F.DECLARATION;bodies[PREFIX+'policy.json']=encode(policy)
    for name in HELPERS:bodies[PREFIX+name]=read(HERE/name)
    for name in ('README.md','predecessor-pin.json'):bodies[NEXT+name]=read(HERE/name)
    for name in (*CHANGED,'source-map.json'):bodies['previous-v2/'+name]=old[name]
    bodies[MARKER]=encode(marker(old,seams))
    bodies[PREFIX+'owner-program.json']=P2.program(bodies,json.loads(old[PREFIX+'owner-program.json'])['base_source_map_sha256'])
    bodies.pop('source-map.json');bodies['source-map.json']=encode(dict(prior,files={n:dict(pin(b),mode=0o644) for n,b in sorted(bodies.items())}))
    inverse(bodies,parent_map_sha256)
    output.mkdir(mode=0o700)
    for name,body in bodies.items():
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(body)
        path.chmod(0o644)
    D=load(output/PREFIX/'data.py','libgit2_payload_v3_complete_source',P2.proof()['static_source_files'][PREFIX+'data.py']);D.source(output,pin(bodies['source-map.json'])['sha256'])
    return dict(status='SOURCE_DATA_ONLY',files=len(bodies),bytes=sum(map(len,bodies.values())),tree=tree(bodies),source_map=pin(bodies['source-map.json']),owner_program=pin(bodies[PREFIX+'owner-program.json']),policy=pin(bodies[PREFIX+'policy.json']),parent_map=pin(old['source-map.json']),parent_Source='UNBOUND',actual=prior['actual'],native_pair='NOT RUN',Root_acceptance=None)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('parent','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--parent-map-sha256',required=True);a=p.parse_args();print(json.dumps(construct(a.parent,a.parent_map_sha256,a.output),indent=2,sort_keys=True))
