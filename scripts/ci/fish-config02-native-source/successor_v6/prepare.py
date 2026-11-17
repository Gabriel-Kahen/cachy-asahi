#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Construct a bounded Fish payload-diagnostic/failed-owner-retirement Source successor."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
from types import ModuleType

HERE=Path(__file__).resolve().parent
PREFIX='scripts/ci/fish-config02-native-source/successor_v2/'
def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encode(v):return(json.dumps(v,indent=2,sort_keys=True)+'\n').encode()
def row(raw):return dict(pin(raw),mode=0o644)


def read(path):
    path=Path(path);need(path.is_absolute()and path==path.resolve()and not path.is_symlink(),'canonical operand')
    info=path.lstat();need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and not info.st_mode&0o022 and
                         0<info.st_size<=2*1024**2,'bounded ordinary operand')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    identity=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
    try:
        need(identity(info)==identity(os.fstat(fd)),'same operand descriptor')
        with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(2*1024**2+1)
        need(len(raw)==info.st_size and identity(info)==identity(os.fstat(fd))==identity(path.lstat()),'whole stable operand')
        return raw
    finally:os.close(fd)


def load_bytes(raw,name,path):
    m=ModuleType(name);m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);return m


def origin():
    m=load_bytes(read(HERE/'inverse.py'),'inert_inverse',HERE/'inverse.py');return m.SOURCE53



UPSTREAM_PIN={'bytes': 1559, 'sha256': 'd4ec9ef7e42f3659d24ed55b53508c536ffd2563636f766cf23eea61152378c0'}
PHASE_ANCHORS=(
    ('entry', "    D.need(sys.flags.isolated and __debug__ and os.getuid() == os.geteuid() > 0, 'ordinary isolated payload')"),
    ('launch-data', '    config_path = Path(sys.argv[1]); config = D.decode(D.read(config_path)); config_path.unlink()'),
    ('environment', "    os.environ.clear(); os.environ.update(config['environment'])"),
    ('admission', "    a,r = D.admission(root,map_sha,config['admission_raw'].encode(),config['runtime_raw'].encode(),"),
    ('owner-AS', "    policy = D.decode(D.read(HERE/'policy.json'))"),
    ('marker-wait', "    end = time.monotonic()+30; marker = Path(config['marker'])"),
    ('marker-read', '    raw = D.read(marker); observed = D.decode(raw)'),
    ('owner-observation', '    D.observation(observed,a,map_sha,policy,os.getpid(),int(fields[19]),group[3:])'),
    ('owner-kernel', "    own = Path('/sys/fs/cgroup'+group[3:])"),
    ('dispatch-context', "    D.need(observed['run'] == os.environ['GITHUB_RUN_ID'] and observed['attempt'] == 1"),
    ('daemon-identity', "    daemon=observed['daemon']; daemon_fields=Path('/proc/'+str(daemon['pid'])+'/stat').read_text().rpartition(')')[2].split()"),
    ('daemon-kernel', "    parent=Path('/sys/fs/cgroup'+daemon['cgroup'])"),
    ('socket-identity', "    socket=Path(observed['endpoint'][7:]).stat()"),
    ('readonly-filesystem', "    D.need(not os.access('/tmp',os.W_OK) and not os.access('/var/tmp',os.W_OK) and not os.access(root,os.W_OK),'actual owner writable filesystem restricted to quota work domain')"),
    ('held-entry', "    base = root/'held-source32'; entry_path = base/D.BASE_PREFIX/'entry.py'"),
    ('inner-pair', "    report = namespace['execute'](base,Path(config['output']),map_sha,a,r)"),
)
STOP="""def stop(self,kind):
        if kind not in self.units:return dict(submitted=False)
        row=self.show(kind);owned=self.units[kind]
        if row.get('LoadState')!='not-found':
            D.need(row.get('Description')=='cachy-fish02-owned-'+self.nonce+'-'+kind,'owned unit before stop')
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
                    state=current.get('ActiveState'),result=current.get('Result'))"""


def frozen(base):
    base=Path(base);expected=origin();raw=read(base/'source-map.json');need(pin(raw)==expected['map'],'exact Source53 map')
    manifest=json.loads(raw);rows=dict(manifest['files'],**{'source-map.json':row(raw)});found=set()
    need(len(rows)==53 and manifest['kind']=='FISH02_FINITE_DOCKER_VA_SOURCE_V5'and
         all(v is None for v in manifest['actual'].values()),'exact frozen53 schema')
    for index,p in enumerate(base.rglob('*')):
        need(index<256 and not p.is_symlink()and(p.is_dir()or p.is_file()),'bounded closed Source53')
        if p.is_file():found.add(p.relative_to(base).as_posix())
    need(found==set(rows),'complete Source53 namespace')
    bodies={}
    for name,wanted in rows.items():
        need(not Path(name).is_absolute()and '..'not in Path(name).parts,'safe Source53 member')
        body=read(base/name);need(row(body)==wanted and stat.S_IMODE((base/name).stat().st_mode)==0o644,'whole Source53 member/mode');bodies[name]=body
    d=load_bytes(bodies[PREFIX+'data.py'],'verified_source53_data',base/PREFIX/'data.py')
    need(sum(map(len,bodies.values()))==expected['bytes']and d.git_tree(bodies)==expected['tree'],'complete53 bytes/tree')
    d.source(base,expected['map']['sha256'])
    return bodies,manifest,d


def helpers():
    raw=read(HERE/'UPSTREAM.json');need(pin(raw)==UPSTREAM_PIN,'exact helper provenance binding')
    value=json.loads(raw);bodies={}
    need(value['upstream_commit']=='8667d0a1912bc141416e1ab954cfe94adba835e4'and
         all(value[k]is None for k in ('actual_source','actual_run','Root_authority','role_label')),'immutable helper commit and NULL roles')
    for name in ('payload_diagnostic.py','failed_retirement.py'):
        body=read(HERE/name);need(pin(body)==value['files'][name]['result'],'whole pinned diagnostic/retirement helper');bodies[name]=body
    return bodies,value


def projections(original):
    owner=original[PREFIX+'hosted_owner.py'].decode();payload=original[PREFIX+'payload.py'].decode();seams={}
    def replace(text,before,after,key):
        need(text.count(before)==1 and before!=after,'one exact successor seam: '+key)
        seams.setdefault(key,[]).append(dict(before=before,after=after));return text.replace(before,after)
    key=PREFIX+'hosted_owner.py'
    anchor="s=importlib.util.spec_from_file_location('fish_go_cli_va_v5',HERE/'go_cli_va.py');V=importlib.util.module_from_spec(s);s.loader.exec_module(V)"
    owner=replace(owner,anchor,anchor+"\ns=importlib.util.spec_from_file_location('fish02_failed_retirement_v6',HERE/'failed_retirement.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)",key)
    anchor="                self.units[kind].update(actual);return actual"
    owner=replace(owner,anchor,"                self.units[kind].update(actual);self.units[kind].update(original_pidfd=fd,original_pidfd_identity=F.pidfd_identity(fd));return actual",key)
    node=next(n for n in ast.walk(ast.parse(owner))if isinstance(n,ast.FunctionDef)and n.name=='stop')
    owner=replace(owner,ast.get_source_segment(owner,node),STOP,key)
    key=PREFIX+'payload.py';anchor="s = importlib.util.spec_from_file_location('fish02_v2_data',HERE/'data.py');D=importlib.util.module_from_spec(s);s.loader.exec_module(D)"
    payload=replace(payload,anchor,anchor+"\ns = importlib.util.spec_from_file_location('fish02_payload_diagnostic_v6',HERE/'payload_diagnostic.py');X=importlib.util.module_from_spec(s);s.loader.exec_module(X)",key)
    for phase,anchor in PHASE_ANCHORS:payload=replace(payload,anchor,"    X.phase('"+phase+"')\n"+anchor,key)
    payload=replace(payload,"        print('HOLD_PAYLOAD: '+type(error).__name__,file=sys.stderr);raise SystemExit(2)","        print(X.record(error),file=sys.stderr);raise SystemExit(2)",key)
    for body in (owner,payload):ast.parse(body)
    return {PREFIX+'hosted_owner.py':owner.encode(),PREFIX+'payload.py':payload.encode()},seams


def projected_data(raw):
    text=raw.decode();old="value['kind']=='FISH02_FINITE_DOCKER_VA_SOURCE_V5' and len(rows)==52"
    need(text.count(old)==1,'one finite outer Source frame seam')
    text=text.replace(old,"value['kind']=='FISH02_PAYLOAD_RETIREMENT_SOURCE_V6' and len(rows)==56")
    call='    inverse_source48(root,inverse_source50(bodies))\n';need(text.count(call)==1,'one predecessor inverse call')
    text=text.replace(call,'    inverse_source48(root,inverse_source50(inverse_source53(bodies)))\n')
    return text.encode()+b'\n'+read(HERE/'inverse.py')


def construct(base,output):
    base,output=map(Path,(base,output))
    need(output.is_absolute()and output==output.resolve()and output.parent.is_dir()and not output.exists()and
         not output.is_relative_to(base)and not base.is_relative_to(output),'fresh disjoint successor output')
    original,manifest,d=frozen(base);operands,upstream=helpers()
    X=load_bytes(operands['payload_diagnostic.py'],'pinned_diagnostic',HERE/'payload_diagnostic.py')
    F=load_bytes(operands['failed_retirement.py'],'pinned_retirement',HERE/'failed_retirement.py')
    code,seams=projections(original);bodies=dict(original);bodies.update(code)
    before=json.loads(original[PREFIX+'policy.json']);policy=dict(before)
    need('payload_diagnostics'not in policy and 'failed_owner_retirement'not in policy,'new explicit policy declarations')
    policy.update(payload_diagnostics=X.DECLARATION,failed_owner_retirement=F.DECLARATION)
    restored=dict(policy);restored.pop('payload_diagnostics');restored.pop('failed_owner_retirement')
    need(restored==before,'all original resource/VA/zero-APT policy fields unchanged')
    bodies[PREFIX+'policy.json']=encode(policy);bodies[PREFIX+'data.py']=projected_data(original[PREFIX+'data.py'])
    bodies[PREFIX+'README.md']=read(HERE/'README.md')
    for name,body in operands.items():bodies[PREFIX+name]=body
    binding=PREFIX+'payload-retirement-binding.json';inverse=PREFIX+'source53-inverse.json';program=PREFIX+'owner-program.json'
    bodies[binding]=encode(dict(kind='FISH02_PINNED_PAYLOAD_RETIREMENT_PROJECTION_V6',upstream=upstream,seams=seams,actual=None))
    changed={n:raw.decode()for n,raw in original.items()if bodies[n]!=raw}
    changed['source-map.json']=original['source-map.json'].decode();changed[program]=original[program].decode()
    added=sorted((set(bodies)-set(original))|{inverse});excluded={'source-map.json',program,inverse}
    proof=dict(kind='FISH_COMPLETE_SOURCE53_INVERSE_V6',origin=origin(),before_utf8=changed,
               after={n:row(raw)for n,raw in bodies.items()if n not in excluded and(n in changed or n in added)},added=added,actual=None)
    bodies[inverse]=encode(proof)
    p=json.loads(original[program]);p['files']={n:row(raw)for n,raw in sorted(bodies.items())if not n.startswith('held-source32/')and n not in('source-map.json',program)}
    bodies[program]=encode(p)
    value=dict(manifest,kind='FISH02_PAYLOAD_RETIREMENT_SOURCE_V6',files={n:row(raw)for n,raw in sorted(bodies.items())if n!='source-map.json'})
    bodies['source-map.json']=encode(value)
    validator=load_bytes(bodies[PREFIX+'data.py'],'staged_successor_validator',base/PREFIX/'data.py')
    restored=validator.inverse_source53(bodies);restored=validator.inverse_source50(restored);validator.inverse_source48(None,restored)
    need(len(bodies)==57 and sum(map(len,bodies.values()))<2*1024**2,'bounded computed successor57')
    output.mkdir(mode=0o700)
    for name,body in sorted(bodies.items()):
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb')as stream:stream.write(body)
        path.chmod(0o644)
    validator.source(output,pin(bodies['source-map.json'])['sha256'])
    return dict(files=57,bytes=sum(map(len,bodies.values())),source_map=pin(bodies['source-map.json']),
                policy=pin(bodies[PREFIX+'policy.json']),owner_program=pin(bodies[program]),tree=d.git_tree(bodies),
                original53_inverse=True,original50_inverse=True,original48_inverse=True,
                helpers={name:pin(body)for name,body in operands.items()},actual_source=None,Root_authority=None,actual_run=None,role_label=None)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(construct(a.base,a.output),indent=2,sort_keys=True))
