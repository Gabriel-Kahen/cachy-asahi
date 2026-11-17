# SPDX-License-Identifier: MIT
"""Read only retained public package JSON and fixed db5.3 tar members; no Raw/actor.

Projection covers all top-level shared-library package nodes and complete alias
closures, independent of the observed r90 cache contents.
"""
import base64,hashlib,importlib.util,json,posixpath,tarfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
S=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-perl-initialized-fullscan-trial-r1/actor-output/decoder-output/scan')
ARCHIVE=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/platform/baseline-acquisition-20261012/cache/db5.3-5.3.28-7-aarch64.pkg.tar.xz')
PINS={'namespace.json':dict(bytes=13619268,sha256='9ce5346df993be2e56ca88a477f3c64731800a38ae6ce6dae7e34d272a4231c9'),'ownership.json':dict(bytes=9984197,sha256='2b44340a338d699cee6638e15e1ebcbb1e6f691d4ea7780bc1324dc53a24b19b'),'alpm-records.json':dict(bytes=1385366,sha256='e3a19ffd3a8c2b732e4cc63d576612385dbace531bf35798a39a25c733e81af6')}
def need(v,why):
 if not v:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def put(name,v):(HERE/name).write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
def collect():
 loaded={}
 for name,p in PINS.items():
  b=(S/name).read_bytes();need(pin(b)==p,'whole public evidence input pin');loaded[name]=json.loads(b)
 ns=loaded['namespace.json'];ownership=loaded['ownership.json'];versions={}
 for name,body in loaded['alpm-records.json'].items():
  if name.endswith('/desc'):
   def value(k):return body.split('%'+k+'%\n',1)[1].split('\n',1)[0]
   versions[value('NAME')]=value('VERSION')
 names={p for p in ns if p.startswith('usr/lib/')and p.count('/')==2 and '.so'in p.rsplit('/',1)[1]and ns[p]['type']in('file','symlink')};pending=list(names)
 while pending:
  p=pending.pop();r=ns[p]
  if r['type']=='symlink':
   t=base64.b64decode(r['target_b64'],validate=True).decode('ascii');q=posixpath.normpath(t.lstrip('/')if t.startswith('/')else posixpath.join(posixpath.dirname(p),t));need(q.startswith('usr/lib/')and q in ns,'complete public alias closure')
   if q not in names:names.add(q);pending.append(q)
 nodes={}
 for p in sorted(names):
  n=ns[p];owned=ownership[p];need(len(owned['owners'])==1,'unique ALPM library ownership');owner=owned['owners'][0]
  need(all(n[k]==v for k,v in owned['inode'].items()),'whole namespace/ALPM ownership correspondence')
  fields=('type','mode','uid','gid','size','sha256')if n['type']=='file'else('type','mode','uid','gid','size','target_b64')
  nodes[p]=dict(**{k:n[k]for k in fields},owners=[owner],package=dict(name=owner,version=versions[owner]))
 archive=ARCHIVE.read_bytes();expected=dict(bytes=1044852,sha256='0a787f952c0f7dd1493db437ab0dc3ffda6053cb6affa4ebf91caff185e586b4');need(pin(archive)==expected,'exact retained db5.3 archive')
 spec=importlib.util.spec_from_file_location('public_db_elf_soname',HERE/'elf.py');E=importlib.util.module_from_spec(spec);spec.loader.exec_module(E);db={};sonames={};members={}
 with tarfile.open(ARCHIVE,'r:xz')as tar:
  allmembers=tar.getmembers();need(len({m.name for m in allmembers})==len(allmembers),'unique package members')
  for name in('libdb-5.3.so','libdb_cxx-5.3.so','libdb_stl-5.3.so'):
   p='usr/lib/'+name;m=tar.getmember(p);need(m.isfile()and m.uid==m.gid==0 and m.mode==0o755 and 0<m.size<=4194304,'ordinary fixed package ELF member');body=tar.extractfile(m).read();need(len(body)==m.size,'whole fixed public member');sonames[name]=E.soname(body);members[p]=pin(body);db[p]=dict(type='file',mode=m.mode,uid=m.uid,gid=m.gid,size=m.size,sha256=pin(body)['sha256'],owners=['db5.3'],package=dict(name='db5.3',version='5.3.28-7'))
 return dict(kind='PINNED_PUBLIC_CACHE_PROVIDER_PROJECTION_V1',source_files={name:dict(path=str(S/name),**p)for name,p in PINS.items()},baseline_nodes=nodes,db_archive=dict(path=str(ARCHIVE),**expected),db_members=members,db_nodes=db,db_elf_sonames=sonames,Root_acceptance=None,lifecycle_acceptance=None)
if __name__=='__main__':
 v=collect();put('providers.DATA.json',v);print(json.dumps(dict(baseline_nodes=len(v['baseline_nodes']),db_elf_sonames=v['db_elf_sonames']),sort_keys=True))
