#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Source-only diagnostics and stopped/empty failed-owner successor to exact68."""
import argparse
import ast
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('llhttp_v3_source_data',HERE.parent/'successor_v2/prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
PREFIX=P.PREFIX
PARENT_MAP=dict(bytes=14771,sha256='00a7b3ced2bbf21303734d32cf9dde10e7db5e724b0c1b4857f7ab7e5a685998')
PARENT_TREE='ff40c38eb5062ace3b46cb2f2c4c8c32fc010a00'
CHANGED=(PREFIX+'hosted_owner.py',PREFIX+'payload.py',PREFIX+'policy.json',PREFIX+'owner-program.json')
HELPERS=('payload_diagnostic.py','failed_retirement.py')
MARKER='payload-retirement-v3.json'
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
            D.need(row.get('Description')=='cachy-llhttp-reference-owned-'+self.nonce+'-'+kind,'owned unit before stop')
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

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def projections(old):
    owner=old[PREFIX+'hosted_owner.py'].decode();payload=old[PREFIX+'payload.py'].decode();seams={}
    def replace(text,before,after,key):
        P.need(text.count(before)==1 and before!=after,'one exact successor seam: '+key);seams.setdefault(key,[]).append(dict(before=before,after=after));return text.replace(before,after)
    key=PREFIX+'hosted_owner.py'
    anchor="s=importlib.util.spec_from_file_location('llhttp_go_cli_va_v2',HERE/'go_cli_va.py');V=importlib.util.module_from_spec(s);s.loader.exec_module(V)"
    owner=replace(owner,anchor,anchor+"\ns=importlib.util.spec_from_file_location('llhttp_failed_retirement_v3',HERE/'failed_retirement.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)",key)
    anchor="                self.units[kind].update(actual);return actual"
    owner=replace(owner,anchor,"                self.units[kind].update(actual);self.units[kind].update(original_pidfd=fd,original_pidfd_identity=F.pidfd_identity(fd));return actual",key)
    node=next(n for n in ast.walk(ast.parse(owner))if isinstance(n,ast.FunctionDef)and n.name=='stop');before=ast.get_source_segment(owner,node);owner=replace(owner,before,STOP,key)
    key=PREFIX+'payload.py';anchor="s = importlib.util.spec_from_file_location('llhttp-reference_v2_data',HERE/'data.py');D=importlib.util.module_from_spec(s);s.loader.exec_module(D)"
    payload=replace(payload,anchor,anchor+"\ns = importlib.util.spec_from_file_location('llhttp_payload_diagnostic_v3',HERE/'payload_diagnostic.py');X=importlib.util.module_from_spec(s);s.loader.exec_module(X)",key)
    for phase,anchor in PHASE_ANCHORS:payload=replace(payload,anchor,"    X.phase('"+phase+"')\n"+anchor,key)
    payload=replace(payload,"        print('HOLD_PAYLOAD: '+type(error).__name__,file=sys.stderr);raise SystemExit(2)","        print(X.record(error),file=sys.stderr);raise SystemExit(2)",key)
    return {PREFIX+'hosted_owner.py':owner.encode(),PREFIX+'payload.py':payload.encode()},seams

def parent_bodies(parent):
    parent=P.ordinary(parent);raw=P.read(parent/'source-map.json');P.need(P.pin(raw)==PARENT_MAP,'whole exact public68 map')
    value=json.loads(raw);found={str(n.relative_to(parent))for n in parent.rglob('*')if n.is_file()or n.is_symlink()}
    P.need(found==set(value['files'])|{'source-map.json'}and len(found)==68 and all(v is None for v in value['actual'].values()),'whole ordinary public68 namespace and NULL selectors')
    bodies={n:P.read(parent/n)for n in sorted(found)}
    P.need(all(dict(P.pin(bodies[n]),mode=(parent/n).stat().st_mode&0o777)==row for n,row in value['files'].items())and sum(map(len,bodies.values()))==980464 and P.tree(bodies)==PARENT_TREE,'complete68 byte/mode/Git tree')
    P.inverse(bodies);return bodies,value

def inverse(bodies):
    old={n:b for n,b in bodies.items()if n not in ('source-map.json',MARKER)and not n.startswith('previous-v2/')and n not in {PREFIX+h for h in HELPERS}}
    for n in CHANGED:old[n]=bodies['previous-v2/'+n]
    old['source-map.json']=bodies['previous-v2/source-map.json'];P.need(P.pin(old['source-map.json'])==PARENT_MAP,'complete retained68 map')
    rows=json.loads(old['source-map.json'])['files'];P.need(set(old)==set(rows)|{'source-map.json'}and len(old)==68 and sum(map(len,old.values()))==980464 and P.tree(old)==PARENT_TREE,'complete68 inverse namespace/bytes/tree')
    P.need(all(dict(P.pin(old[n]),mode=0o644)==row for n,row in rows.items()),'whole68 inverse bodies/modes')
    code,_=projections(old);P.need(all(bodies[n]==raw for n,raw in code.items()),'whole unchanged guard-body projections')
    policy=json.loads(bodies[PREFIX+'policy.json']);policy.pop('payload_diagnostics');policy.pop('failed_owner_retirement');P.need(policy==json.loads(old[PREFIX+'policy.json']),'all previous resources/VA/zero-APT predicates unchanged')
    return old

def construct(parent,output):
    parent,output=map(P.ordinary,(parent,output));P.need(not output.exists()and not output.is_relative_to(parent),'fresh disjoint successor output')
    bodies,prior=parent_bodies(parent);old=dict(bodies);code,seams=projections(old);bodies.update(code)
    X=load(HERE/'payload_diagnostic.py','llhttp_v3_diagnostic_policy');F=load(HERE/'failed_retirement.py','llhttp_v3_retirement_policy')
    policy=json.loads(old[PREFIX+'policy.json']);policy['payload_diagnostics']=X.DECLARATION;policy['failed_owner_retirement']=F.DECLARATION;bodies[PREFIX+'policy.json']=P.encode(policy)
    for n in HELPERS:bodies[PREFIX+n]=P.read(HERE/n)
    for n in(*CHANGED,'source-map.json'):bodies['previous-v2/'+n]=old[n]
    bodies[MARKER]=P.encode(dict(kind='LLHTTP_PAYLOAD_DIAGNOSTICS_FAILED_RETIREMENT_V3',parent_source='4c3de228552a910ea9b0762e71bf81d14c630bd2',parent_map=PARENT_MAP,parent_tree=PARENT_TREE,parent_files=68,parent_bytes=980464,actual=None,native_pair='NOT RUN',actual84_remains='FAILURE; payload and cleanup HOLD',seams=seams))
    bodies.pop('source-map.json');bodies.pop(PREFIX+'owner-program.json')
    program=P.encode(dict(schema=1,base_source_map_sha256=json.loads(old[PREFIX+'owner-program.json'])['base_source_map_sha256'],files={n:dict(P.pin(b),mode=0o644)for n,b in sorted(bodies.items())if not n.startswith('held-source/')}));bodies[PREFIX+'owner-program.json']=program
    value=dict(prior,files={n:dict(P.pin(b),mode=0o644)for n,b in sorted(bodies.items())});bodies['source-map.json']=P.encode(value)
    inverse(bodies);P.need(len(bodies)<80 and sum(map(len,bodies.values()))<2*1024**2,'finite successor below unchanged Source namespace cap')
    output.mkdir(mode=0o700)
    for name,raw in bodies.items():
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb')as stream:stream.write(raw)
        path.chmod(0o644)
    D=load(output/PREFIX/'data.py','llhttp_v3_closed_source');D.source(output,P.pin(bodies['source-map.json'])['sha256'])
    return dict(status='SOURCE_DATA_ONLY',files=len(bodies),bytes=sum(map(len,bodies.values())),tree=P.tree(bodies),source_map=P.pin(bodies['source-map.json']),policy=P.pin(bodies[PREFIX+'policy.json']),program=P.pin(program),actual=prior['actual'],native_pair='NOT RUN')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in('parent','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();print(json.dumps(construct(a.parent,a.output),indent=2,sort_keys=True))
