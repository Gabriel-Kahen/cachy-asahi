#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure DATA successor to exact public Source62; no actor or authority issuance."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
PREFIX='scripts/ci/llhttp-reference-native-source/owner/'
PARENT_MAP=dict(bytes=13601,sha256='d6240a8a32bd363e75542e3e5896356e24d28e010f99e24edfff380b67afa050')
PARENT_TREE='d09f9b9870f6b7b9c9eba9c6418178c775a54d43'
CHANGED=(PREFIX+'hosted_owner.py',PREFIX+'policy.json',PREFIX+'owner-program.json')
MARKER='go-cli-va-v2.json'

def need(ok,why):
    if not ok:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def encode(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()

def ordinary(path):
    path=Path(path);need(path.is_absolute()and path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary canonical path');return path

def read(path,cap=2*1024**2):
    path=ordinary(path);before=path.lstat();need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and not before.st_mode&0o022 and 0<before.st_size<=cap,'bounded ordinary Source DATA')
    raw=path.read_bytes();identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(identity(before)==identity(path.lstat())and len(raw)==before.st_size,'stable whole Source DATA');return raw

def tree(bodies):
    def oid(kind,body):return hashlib.sha1(kind.encode()+b' '+str(len(body)).encode()+b'\0'+body).digest()
    def walk(prefix):
        names={n[len(prefix):].split('/')[0]for n in bodies if n.startswith(prefix)};rows=[]
        for name in names:
            path=prefix+name;leaf=path in bodies;mode=b'100644'if leaf else b'40000';digest=oid('blob',bodies[path])if leaf else walk(path+'/')
            rows.append(((name if leaf else name+'/').encode(),mode+b' '+name.encode()+b'\0'+digest))
        return oid('tree',b''.join(row for key,row in sorted(rows)))
    return walk('').hex()

def parent_bodies(parent):
    parent=ordinary(parent);raw=read(parent/'source-map.json');need(pin(raw)==PARENT_MAP,'whole exact public Source62 map')
    value=json.loads(raw);need(len(value['files'])==61 and all(v is None for v in value['actual'].values()),'exact unissued62 namespace')
    found={str(p.relative_to(parent))for p in parent.rglob('*')if p.is_file()or p.is_symlink()};need(found==set(value['files'])|{'source-map.json'},'whole ordinary62 namespace; no Git/cache extras')
    bodies={}
    for name,row in value['files'].items():
        body=read(parent/name);need(dict(pin(body),mode=stat.S_IMODE((parent/name).stat().st_mode))==row and row['mode']==0o644,'whole pinned Source62 body/mode: '+name);bodies[name]=body
    bodies['source-map.json']=raw;need(len(bodies)==62 and sum(map(len,bodies.values()))==928551 and tree(bodies)==PARENT_TREE,'complete62 census and physical Git tree')
    return bodies,value

EDITS=(
("s=importlib.util.spec_from_file_location('llhttp-reference_v2_host_tools',HERE/'host_tools.py');H=importlib.util.module_from_spec(s);s.loader.exec_module(H)",
 "s=importlib.util.spec_from_file_location('llhttp-reference_v2_host_tools',HERE/'host_tools.py');H=importlib.util.module_from_spec(s);s.loader.exec_module(H)\ns=importlib.util.spec_from_file_location('llhttp_go_cli_va_v2',HERE/'go_cli_va.py');V=importlib.util.module_from_spec(s);s.loader.exec_module(V)"),
("        child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,",
 "        D.need(resource.getrlimit(resource.RLIMIT_AS)==V.controller_limit(self.policy),'same finite controller soft/hard VA ceiling before launch')\n        address_space=V.child_plan(args,self.tools,self.policy)\n        child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=V.child_limits(address_space),"),
("self.commands.append(dict(argv=args,retirement=row,output=D.pin(body)))", "self.commands.append(dict(argv=args,address_space=address_space,retirement=row,output=D.pin(body)))"),
("resource.setrlimit(resource.RLIMIT_AS,(policy['controller']['AS_bytes'],policy['controller']['AS_bytes']))", "resource.setrlimit(resource.RLIMIT_AS,V.controller_limit(policy))"),
)

def project(raw):
    text=raw.decode()
    for before,after in EDITS:need(text.count(before)==1 and after not in text,'one exact finite controller VA seam');text=text.replace(before,after)
    inverse=text
    for before,after in reversed(EDITS):need(inverse.count(after)==1,'one exact VA inverse seam');inverse=inverse.replace(after,before)
    need(inverse.encode()==raw,'whole unchanged controller inverse');return text.encode()

def inverse(bodies):
    original={name:body for name,body in bodies.items()if name not in ('source-map.json',MARKER)and not name.startswith('previous-v1/')and name!=PREFIX+'go_cli_va.py'}
    raw=bodies['previous-v1/source-map.json'];need(pin(raw)==PARENT_MAP,'whole retained original62 map')
    for name in CHANGED:original[name]=bodies['previous-v1/'+name]
    original['source-map.json']=raw;rows=json.loads(raw)['files']
    need(set(original)==set(rows)|{'source-map.json'}and len(original)==62 and sum(map(len,original.values()))==928551,'complete62 inverse namespace/bytes')
    need(all(dict(pin(original[n]),mode=0o644)==row for n,row in rows.items())and tree(original)==PARENT_TREE,'whole62 inverse byte/mode/Git tree')
    need(project(original[PREFIX+'hosted_owner.py'])==bodies[PREFIX+'hosted_owner.py'],'whole projected controller matches inverse')
    old=json.loads(original[PREFIX+'policy.json']);new=json.loads(bodies[PREFIX+'policy.json']);new.pop('docker_cli_address_space');need(new==old,'all prior cgroups/AS-soft/resources/zero-APT policy unchanged')
    return original

def construct(parent,output):
    parent,output=map(ordinary,(parent,output));need(not output.exists()and not output.is_relative_to(parent),'fresh disjoint successor output')
    bodies,oldmap=parent_bodies(parent);original=dict(bodies)
    spec=importlib.util.spec_from_file_location('llhttp_va_policy_data',HERE/'go_cli_va.py');V=importlib.util.module_from_spec(spec);spec.loader.exec_module(V)
    bodies[PREFIX+'hosted_owner.py']=project(original[PREFIX+'hosted_owner.py'])
    policy=json.loads(original[PREFIX+'policy.json']);need('docker_cli_address_space'not in policy,'no old exception');policy['docker_cli_address_space']=V.DECLARATION;bodies[PREFIX+'policy.json']=encode(policy)
    bodies[PREFIX+'go_cli_va.py']=read(HERE/'go_cli_va.py')
    for name in(*CHANGED,'source-map.json'):bodies['previous-v1/'+name]=original[name]
    marker=dict(kind='LLHTTP_DOCKER_CLI_FINITE_VA_SUCCESSOR_V2',parent_source='b36a1a6dba7dd42d55646582f3d1fa2002d78d5f',parent_tree=PARENT_TREE,parent_map=PARENT_MAP,parent_files=62,parent_bytes=928551,actual=None,
                changes={n:dict(before=pin(original[n]),after=pin(bodies[n]))for n in CHANGED if not n.endswith('owner-program.json')},new_helper=pin(bodies[PREFIX+'go_cli_va.py']),preserved='ALL cgroup memory/CPU/PIDs/swap,normal child AS,owner2GiB AS,bytes/time/retirement,ordinary executable checks,zero-APT,signatures/dependencies',native_ARM_startup='NOT RUN')
    bodies[MARKER]=encode(marker);bodies.pop('source-map.json');bodies.pop(PREFIX+'owner-program.json')
    base_map=json.loads(original[PREFIX+'owner-program.json'])['base_source_map_sha256']
    program=encode(dict(schema=1,base_source_map_sha256=base_map,files={n:dict(pin(b),mode=0o644)for n,b in sorted(bodies.items())if not n.startswith('held-source/')}));bodies[PREFIX+'owner-program.json']=program
    value=dict(oldmap,files={n:dict(pin(b),mode=0o644)for n,b in sorted(bodies.items())});bodies['source-map.json']=encode(value)
    inverse(bodies);need(len(bodies)<80 and sum(map(len,bodies.values()))<2*1024**2,'finite successor closure')
    output.mkdir(mode=0o700)
    for name,body in bodies.items():
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb')as stream:stream.write(body)
        path.chmod(0o644)
    spec=importlib.util.spec_from_file_location('llhttp_va_outer_data',output/PREFIX/'data.py');D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D);D.source(output,pin(bodies['source-map.json'])['sha256'])
    return dict(status='SOURCE_DATA_ONLY',files=len(bodies),bytes=sum(map(len,bodies.values())),tree=tree(bodies),source_map=pin(bodies['source-map.json']),owner_program=pin(program),policy=pin(bodies[PREFIX+'policy.json']),actual=oldmap['actual'],native_ARM_startup='NOT RUN')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(construct(a.parent,a.output),indent=2,sort_keys=True))
