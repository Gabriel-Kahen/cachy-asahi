# SPDX-License-Identifier: MIT
"""Project original public carrier DATA locally; original signer admission is required."""
import argparse,hashlib,json,os,stat
from pathlib import Path
PLAN='scripts/ci/gui-fresh-test-signer/input-contract.json'
PLAN_PIN={'bytes':81278,'sha256':'f0160e53afea8d7116f0b7552514f753f6fd95ae2d58d1b30d4d3fe6d5b5ceda'}
CARRIER_PIN={'bytes':64881,'sha256':'a094844ceeda04429deaa169dba01d5762fa63053afc1cfae87d579c497f6795'}
DOCUMENTS_PIN={'bytes':10878,'sha256':'bd64a09f3aedd1f22cf0632f5254425061be95070029d09a5d1b57b699503862'}
EXPECTED={'held77':('77bd2c6ecf2e5c28a04116c3da85c45f70d1cc90',98,8815289),'native73':('1057f6b5494adc71c469e8867d14fb0db01ce02f',226,2945559),'renewal7cf7':('7cf7fb81d0b70b1b7421dc85788fabd45ec5adfc',7,75006)}
FILES=331
BYTES=11835854
CAP=16*1024**2

def need(v,why):
 if not v:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def obj(b):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate public transport JSON field');out[k]=v
  return out
 v=json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite public transport JSON'));need(type(v)is dict,'public transport object');return v

def ordinary(value):
 p=Path(value);need(p.is_absolute()and p==p.resolve()and not any(q.is_symlink()for q in(p,*p.parents)),'canonical no-alias public transport path');return p

def relative(name):
 need(type(name)is str and name and not name.startswith('/')and '\\'not in name and all(q not in('','.','..')for q in name.split('/'))and all(32<=ord(c)!=127 for c in name),'closed public transport member');return name

def identity(v):return tuple(getattr(v,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,cap=CAP):
 p=ordinary(path);fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o644 and 0<=st.st_size<=cap,'bounded single-link0644 public transport input');raw=bytearray()
  while block:=os.read(fd,min(65536,st.st_size+1-len(raw))):raw.extend(block);need(len(raw)<=st.st_size,'public transport growth refused')
  need(len(raw)==st.st_size and identity(st)==identity(os.fstat(fd))==identity(p.lstat()),'whole stable public transport FD/path');return bytes(raw)
 finally:os.close(fd)

def namespace(root,rows):
 root=ordinary(root);need(root.is_dir(),'public carrier directory');files=set();dirs=set()
 for base,names,members in os.walk(root):
  for n in names:
   p=Path(base)/n;need(not p.is_symlink()and p.is_dir(),'ordinary public carrier directories');dirs.add(p.relative_to(root).as_posix())
  for n in members:files.add((Path(base)/n).relative_to(root).as_posix())
 need(files==set(rows),'whole original public carrier namespace');need(dirs=={p.as_posix()for n in rows for p in Path(n).parents if p.as_posix()!='.'},'no foreign public carrier empty directory')

def plan(source):
 raw=read(source/PLAN,1024**2);need(pin(raw)==PLAN_PIN,'exact unchanged six-body input contract');v=obj(raw);need(pin(enc(v['carriers']))==CARRIER_PIN and pin(enc(v['documents']))==DOCUMENTS_PIN,'complete original331 maps and six body contracts');need(set(v['carriers'])==set(EXPECTED),'exact three original carriers')
 rows={}
 for alias,c in v['carriers'].items():
  need((c['source'],len(c['files']),sum(w['bytes']for w in c['files'].values()))==EXPECTED[alias],'original source/file/byte carrier identity')
  for name,w in c['files'].items():rows[alias+'/'+relative(name)]=w
 need(len(rows)==FILES and sum(w['bytes']for w in rows.values())==BYTES,'complete bounded original331 public DATA');return v,rows

def project(source,output):
 source=ordinary(source);out=ordinary(output);temporary=ordinary(os.environ['RUNNER_TEMP']);need(out==temporary/'gui-signer-inputs'and not os.path.lexists(out)and temporary.is_dir(),'fresh fixed RUNNER_TEMP public carrier destination');st=temporary.stat();need(st.st_uid==os.getuid()and not st.st_mode&0o022,'owned non-writable transport parent');need(not out.is_relative_to(source)and not source.is_relative_to(out),'carrier output disjoint from executable Source');v,rows=plan(source);carrier=source/'public-carriers';namespace(carrier,rows);held={}
 for name,w in sorted(rows.items()):
  raw=read(carrier/relative(name));need(pin(raw)==w,'entire original public carrier bytes '+name);held[name]=raw
 need(sum(map(len,held.values()))==BYTES,'finite whole public projection snapshot');namespace(carrier,rows);out.mkdir(mode=0o700)
 # Partial DATA remains outside Source if writing fails. There is no retry/deletion.
 for name,raw in held.items():
  p=out/relative(name);p.parent.mkdir(parents=True,exist_ok=True,mode=0o700);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644)
  try:
   os.fchmod(fd,0o644)
   with os.fdopen(os.dup(fd),'wb')as f:need(f.write(raw)==len(raw),'whole projected DATA write');f.flush();os.fsync(f.fileno())
  finally:os.close(fd)
 namespace(out,rows)
 for name,w in rows.items():need(pin(read(out/name))==w,'complete projected original DATA')
 return dict(schema_version=1,status='PASS_EXACT_ORIGINAL331_PUBLIC_INPUT_DATA_ONLY',files=FILES,bytes=BYTES,carrier_contract=CARRIER_PIN,six_documents=DOCUMENTS_PIN,carriers={a:dict(source=c['source'],ref=c['ref'],files=len(c['files']),bytes=sum(w['bytes']for w in c['files'].values()))for a,c in v['carriers'].items()},retry=False,authentication='ORIGINAL_ROUTE_SOURCE_CHECK_AND_FULL_NATIVE_SIGNATURE_GATES_REQUIRED',GPG='NOT_RUN',native='NOT_RUN',acceptance=False,actual=None)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(project(a.source,a.output),sort_keys=True))
if __name__=='__main__':main()
