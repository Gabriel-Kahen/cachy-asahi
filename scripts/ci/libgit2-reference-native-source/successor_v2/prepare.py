#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite Docker CLI VA successor to a separately pinned complete83 Source."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import types

HERE=Path(__file__).resolve().parent
PREFIX='scripts/ci/libgit2-reference-native-source/owner/'
BASE='scripts/ci/libgit2-reference-native-source/base/'
NEXT='scripts/ci/libgit2-reference-native-source/successor_v2/'
CHANGED=tuple(PREFIX+n for n in ('hosted_owner.py','policy.json','owner-program.json'))
MARKER='go-cli-va-v2.json'
HELPER=dict(bytes=1996,sha256='3b2feba315f3a0e4cfed2498160e75591d64c7b8f0e8f5c11b46321b04b5eff3')
PREDECESSOR_PIN=dict(bytes=16138,sha256='be1f4e0429f296eee08a1846325ddf2d6c0cd82c429b7b57c1499d03f178aaca')
ADDED={PREFIX+'go_cli_va.py',MARKER,NEXT+'README.md',NEXT+'predecessor-pin.json'}
FUTURE=['Root payload ValueError correction','Root failed-unit cleanup correction; no retirement waiver']

def need(value,why):
    if not value:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encode(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()

def ordinary(path):
    path=Path(path);need(path.is_absolute() and path==path.resolve() and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute DATA path');return path

def read(path,cap=8*1024**2):
    path=ordinary(path);before=path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and not before.st_mode&0o022 and 0<before.st_size<=cap,'bounded ordinary Source DATA')
    raw=path.read_bytes();identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(identity(before)==identity(path.lstat()) and len(raw)==before.st_size,'stable complete Source DATA');return raw

def module(path,name,expected=None):
    raw=read(path)
    if expected is not None:need(pin(raw)==expected,'immutable helper byte pin')
    value=types.ModuleType(name);value.__file__=str(path);exec(compile(raw,str(path),'exec'),value.__dict__);return value

def tree(bodies):
    def oid(kind,raw):return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).digest()
    def walk(prefix):
        names={n[len(prefix):].split('/')[0] for n in bodies if n.startswith(prefix)};rows=[]
        for name in names:
            path=prefix+name;leaf=path in bodies;mode=b'100644' if leaf else b'40000';digest=oid('blob',bodies[path]) if leaf else walk(path+'/')
            rows.append(((name if leaf else name+'/').encode(),mode+b' '+name.encode()+b'\0'+digest))
        return oid('tree',b''.join(row for _,row in sorted(rows)))
    return walk('').hex()

def proof():
    raw=read(HERE/'predecessor-pin.json');need(pin(raw)==PREDECESSOR_PIN,'immutable complete predecessor manifest')
    value=json.loads(raw)
    need(value['author']=='83d95b33210483887fc0f423ec12008208cbc0be' and value['helper']==dict(source_commit='b156e3886a12f95cb3d364b84fc3a946bb7d2967',source_path='scripts/ci/llhttp-reference-native-source/successor_v2/go_cli_va.py',**HELPER),'exact immutable predecessor and shared helper')
    need(pin(read(HERE/'go_cli_va.py'))==HELPER,'exact shared helper; no local variant')
    return value

def validate_bodies(bodies,expected):
    raw=bodies['source-map.json'];need(re.fullmatch('[0-9a-f]{64}',expected or '') and pin(raw)['sha256']==expected,'independently selected complete predecessor map SHA required')
    value=json.loads(raw);rows=value['files']
    need(value['kind']=='LIBGIT2_REFERENCE_OWNED_HOSTED_SOURCE_V2' and 32<len(rows)<512 and all(v is None for v in value['actual'].values()),'unissued complete83 predecessor Source')
    need(set(bodies)==set(rows)|{'source-map.json'} and sum(map(len,bodies.values()))<128*1024**2,'complete bounded predecessor namespace/bytes')
    for name,row in rows.items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts and dict(pin(bodies[name]),mode=0o644)==row,'whole predecessor byte/mode pin: '+name)
    for name,wanted in proof()['static_source_files'].items():need(name in rows and pin(bodies[name])==wanted,'whole immutable83 Source producer body: '+name)
    return value

def parent_bodies(parent,map_sha):
    parent=ordinary(parent);raw=read(parent/'source-map.json');value=json.loads(raw)
    need(stat.S_IMODE((parent/'source-map.json').stat().st_mode)==0o644,'exact predecessor Source map mode')
    need(pin(raw)['sha256']==map_sha and len(value.get('files',{}))<512,'external predecessor map pin before body reads')
    need(sum(row['bytes'] for row in value['files'].values())<128*1024**2,'bounded predecessor body census')
    found={str(p.relative_to(parent)) for p in parent.rglob('*') if p.is_file() or p.is_symlink()}
    need(found==set(value['files'])|{'source-map.json'},'complete closed predecessor namespace, no extras')
    bodies={'source-map.json':raw}
    for name,row in value['files'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts,'relative predecessor Source leaf')
        path=parent/name;bodies[name]=read(path);need(stat.S_IMODE(path.stat().st_mode)==row['mode']==0o644,'exact predecessor mode')
    validate_bodies(bodies,map_sha)
    D=module(parent/PREFIX/'data.py','libgit2_va_parent_outer',proof()['static_source_files'][PREFIX+'data.py']);D.source(parent,map_sha)
    C=module(parent/'held-source'/BASE/'contract.py','libgit2_va_parent_inner',proof()['static_source_files']['held-source/'+BASE+'contract.py'])
    C.verify_source(parent/'held-source',json.loads(bodies[PREFIX+'base-binding.json'])['map']['sha256'])
    return bodies,value

EDITS=(
 ("s=importlib.util.spec_from_file_location('libgit2-reference_v2_host_tools',HERE/'host_tools.py');H=importlib.util.module_from_spec(s);s.loader.exec_module(H)",
  "s=importlib.util.spec_from_file_location('libgit2-reference_v2_host_tools',HERE/'host_tools.py');H=importlib.util.module_from_spec(s);s.loader.exec_module(H)\ns=importlib.util.spec_from_file_location('libgit2_go_cli_va_v2',HERE/'go_cli_va.py');V=importlib.util.module_from_spec(s);s.loader.exec_module(V)"),
 ("        child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,",
  "        D.need(resource.getrlimit(resource.RLIMIT_AS)==V.controller_limit(self.policy),'same finite controller soft/hard VA ceiling before launch')\n        address_space=V.child_plan(args,self.tools,self.policy)\n        child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=V.child_limits(address_space),"),
 ("self.commands.append(dict(argv=args,retirement=row,output=D.pin(body)))","self.commands.append(dict(argv=args,address_space=address_space,retirement=row,output=D.pin(body)))"),
 ("resource.setrlimit(resource.RLIMIT_AS,(policy['controller']['AS_bytes'],policy['controller']['AS_bytes']))","resource.setrlimit(resource.RLIMIT_AS,V.controller_limit(policy))"),
)

def project(raw):
    need(pin(raw)==proof()['static_source_files'][PREFIX+'hosted_owner.py'],'whole immutable83 controller before projection')
    text=raw.decode()
    for before,after in EDITS:need(text.count(before)==1 and after not in text,'one exact finite VA seam');text=text.replace(before,after)
    inverse=text
    for before,after in reversed(EDITS):need(inverse.count(after)==1,'one exact inverse VA seam');inverse=inverse.replace(after,before)
    need(inverse.encode()==raw,'whole unchanged controller inverse');return text.encode()

def program(bodies,base_sha):
    return encode(dict(schema=1,base_source_map_sha256=base_sha,files={n:dict(pin(b),mode=0o644) for n,b in sorted(bodies.items()) if not n.startswith('held-source/') and n not in ('source-map.json',PREFIX+'owner-program.json')}))

def inverse(bodies,expected_parent_map_sha256=None):
    marker=json.loads(bodies[MARKER]);raw=bodies['previous-v1/source-map.json']
    need(marker['kind']=='LIBGIT2_DOCKER_CLI_FINITE_VA_SUCCESSOR_V2' and marker['actual'] is None and marker['Root_acceptance'] is None and marker['native_build']=='NOT RUN','unissued DATA successor; no actual native/Root claims')
    need(marker['required_future_integration']==FUTURE,'separate payload/retirement corrections remain required')
    expected=expected_parent_map_sha256 or marker['parent_map']['sha256']
    need(pin(raw)==marker['parent_map'] and marker['parent_author']==proof()['author'] and marker['helper']==HELPER,'complete retained predecessor/helper join')
    previous={'previous-v1/'+n for n in (*CHANGED,'source-map.json')}
    need({n for n in bodies if n.startswith('previous-v1/')}==previous,'exact four before-bodies only')
    original={n:b for n,b in bodies.items() if n not in ADDED and not n.startswith('previous-v1/')}
    for name in (*CHANGED,'source-map.json'):original[name]=bodies['previous-v1/'+name]
    validate_bodies(original,expected)
    need(len(original)==marker['parent_files'] and sum(map(len,original.values()))==marker['parent_bytes'] and tree(original)==marker['parent_tree'],'complete predecessor inverse census/modes/physical Git tree')
    V=module(HERE/'go_cli_va.py','libgit2_va_inverse',HELPER)
    need(bodies[PREFIX+'go_cli_va.py']==read(HERE/'go_cli_va.py') and project(original[PREFIX+'hosted_owner.py'])==bodies[PREFIX+'hosted_owner.py'],'exact helper/controller projection')
    need(marker['changes']=={n:dict(before=pin(original[n]),after=pin(bodies[n])) for n in CHANGED if not n.endswith('owner-program.json')},'whole finite controller/policy change pins')
    policy=json.loads(bodies[PREFIX+'policy.json']);need(policy.pop('docker_cli_address_space')==V.DECLARATION and policy==json.loads(original[PREFIX+'policy.json']),'only declared finite VA policy addition')
    for name in ('README.md','predecessor-pin.json'):need(bodies[NEXT+name]==read(HERE/name),'exact successor review inputs')
    base_sha=json.loads(original[PREFIX+'owner-program.json'])['base_source_map_sha256']
    need(bodies[PREFIX+'owner-program.json']==program(bodies,base_sha),'whole updated owner-program closure')
    need(bodies['source-map.json']==encode(dict(json.loads(raw),files={n:dict(pin(b),mode=0o644) for n,b in sorted(bodies.items()) if n!='source-map.json'})),'whole canonical successor Source map/namespace/actuals')
    return original

def construct(parent,parent_map_sha256,output):
    parent,output=map(ordinary,(parent,output));need(not output.exists() and not output.is_relative_to(parent) and not parent.is_relative_to(output),'fresh disjoint successor output')
    original,oldmap=parent_bodies(parent,parent_map_sha256);bodies=dict(original)
    V=module(HERE/'go_cli_va.py','libgit2_va_constructor',HELPER)
    bodies[PREFIX+'hosted_owner.py']=project(original[PREFIX+'hosted_owner.py'])
    policy=json.loads(original[PREFIX+'policy.json']);need('docker_cli_address_space' not in policy,'no inherited exception');policy['docker_cli_address_space']=V.DECLARATION;bodies[PREFIX+'policy.json']=encode(policy)
    bodies[PREFIX+'go_cli_va.py']=read(HERE/'go_cli_va.py')
    for name in ('README.md','predecessor-pin.json'):bodies[NEXT+name]=read(HERE/name)
    for name in (*CHANGED,'source-map.json'):bodies['previous-v1/'+name]=original[name]
    bodies[MARKER]=encode(dict(kind='LIBGIT2_DOCKER_CLI_FINITE_VA_SUCCESSOR_V2',parent_author=proof()['author'],parent_map=pin(original['source-map.json']),parent_tree=tree(original),parent_files=len(original),parent_bytes=sum(map(len,original.values())),helper=HELPER,changes={n:dict(before=pin(original[n]),after=pin(bodies[n])) for n in CHANGED if not n.endswith('owner-program.json')},actual=None,native_build='NOT RUN',Root_acceptance=None,required_future_integration=FUTURE))
    bodies[PREFIX+'owner-program.json']=program(bodies,json.loads(original[PREFIX+'owner-program.json'])['base_source_map_sha256'])
    bodies.pop('source-map.json');bodies['source-map.json']=encode(dict(oldmap,files={n:dict(pin(b),mode=0o644) for n,b in sorted(bodies.items())}))
    inverse(bodies,parent_map_sha256);need(len(bodies)<512 and sum(map(len,bodies.values()))<128*1024**2,'finite complete successor Source')
    output.mkdir(mode=0o700)
    for name,body in bodies.items():
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(body)
        path.chmod(0o644)
    D=module(output/PREFIX/'data.py','libgit2_va_successor_outer',proof()['static_source_files'][PREFIX+'data.py']);D.source(output,pin(bodies['source-map.json'])['sha256'])
    return dict(status='SOURCE_DATA_ONLY',files=len(bodies),bytes=sum(map(len,bodies.values())),tree=tree(bodies),source_map=pin(bodies['source-map.json']),owner_program=pin(bodies[PREFIX+'owner-program.json']),policy=pin(bodies[PREFIX+'policy.json']),parent_map=pin(original['source-map.json']),actual=oldmap['actual'],native_build='NOT RUN',Root_acceptance=None)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('parent','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--parent-map-sha256',required=True);a=p.parse_args();print(json.dumps(construct(a.parent,a.parent_map_sha256,a.output),indent=2,sort_keys=True))
