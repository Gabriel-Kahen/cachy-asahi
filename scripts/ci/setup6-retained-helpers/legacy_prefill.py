# SPDX-License-Identifier: MIT
"""Two fixed public carriers; full immutable Git/source proof before original cache DATA."""
import hashlib,importlib.util,json,os,stat,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes':1510,'sha256':'9cc82d4e0947415ecad9d40094a4c0a2709d01be54513e78af8c739fd76fb696'}
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def identity(s):return tuple(getattr(s,n)for n in FIELDS)
def tick(deadline):need(type(deadline)in(int,float)and time.monotonic()<deadline,'original prefill deadline exhausted')
def read(path,deadline,cap=128*1024**2):
 tick(deadline);p=Path(path);need(p.is_absolute()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary explicit proof path');before=p.lstat();need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded singlelink proof leaf');raw=p.read_bytes();need(len(raw)==before.st_size and identity(before)==identity(p.lstat()),'stable whole proof leaf');tick(deadline);return raw

def git(git_dir,deadline,*args):
 tick(deadline);path=Path(git_dir);need(path.is_absolute()and path.is_dir()and not any(q.is_symlink()for q in(path,*path.parents)),'explicit ordinary existing Git directory')
 env={'PATH':os.defpath,'LANG':'C','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_NO_REPLACE_OBJECTS':'1','GIT_OPTIONAL_LOCKS':'0','GIT_NO_LAZY_FETCH':'1','GIT_TERMINAL_PROMPT':'0'}
 result=subprocess.run(['/usr/bin/git','--git-dir='+str(path),'-c','protocol.allow=never',*args],capture_output=True,timeout=max(.001,deadline-time.monotonic()),env=env,check=False)
 need(result.returncode==0 and not result.stderr,'read-only exact Git object proof');tick(deadline);return result.stdout

def tree_oid(table):
 root={}
 for name,row in table.items():
  node=root;parts=name.split('/')
  for part in parts[:-1]:
   node=node.setdefault(part,{})
   need(type(node)is dict,'Git leaf/directory collision')
  need(parts[-1]not in node,'unique Git tree leaf');node[parts[-1]]=row
 def digest(node):
  out=b''
  for name,value in sorted(node.items(),key=lambda item:(item[0]+('/'if 'oid'not in item[1]else'')).encode()):
   directory='oid'not in value;mode='40000'if directory else value['mode'];oid=digest(value)if directory else value['oid'];out+=mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(oid)
  return hashlib.sha1(b'tree '+str(len(out)).encode()+b'\0'+out).hexdigest()
 return digest(root)

def prove(carrier,git_dir,profile,deadline):
 carrier=Path(carrier);need(carrier.is_absolute()and carrier.is_dir()and not any(q.is_symlink()for q in(carrier,*carrier.parents)),'explicit ordinary carrier root');expected=profile['files'];actual={};directories=set()
 for p in carrier.rglob('*'):
  relative=p.relative_to(carrier)
  if relative.parts[0]=='.git':continue
  need(not p.is_symlink(),'no carrier aliases')
  if p.is_dir():directories.add(relative.as_posix())
  else:actual[relative.as_posix()]=pin(read(p,deadline))
 expected_dirs={parent.as_posix()for n in expected for parent in Path(n).parents if parent!=Path('.')}
 need(actual==expected and directories==expected_dirs,'entire exact external carrier filesystem closure')
 source=profile['source'];commit=git(git_dir,deadline,'cat-file','commit',source);need(hashlib.sha1(b'commit '+str(len(commit)).encode()+b'\0'+commit).hexdigest()==source,'exact immutable commit object');lines=commit.split(b'\n');need(lines[0].startswith(b'tree ')and len(lines[0])==45,'one exact commit root tree');tree=lines[0][5:].decode();table={}
 for raw in git(git_dir,deadline,'ls-tree','-rz','--full-tree',source).split(b'\0'):
  if not raw:continue
  header,name=raw.split(b'\t',1);mode,kind,oid=header.decode().split();name=name.decode();need(kind=='blob'and mode in('100644','100755')and name in expected and name not in table,'complete ordinary Git tree membership');table[name]=dict(mode=mode,oid=oid)
 need(set(table)==set(expected)and tree_oid(table)==tree,'all Git tree objects close to exact immutable commit')
 for name,want in expected.items():
  body=git(git_dir,deadline,'cat-file','blob',source+':'+name);physical=read(carrier/name,deadline);need(pin(body)==want and body==physical and hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()==table[name]['oid'],'each full Git/blob/filesystem join');need(bool((carrier/name).stat().st_mode&0o111)==(table[name]['mode']=='100755'),'exact Git executable mode')
 tick(deadline);return dict(source=source,ref=profile['ref'],files=len(expected),blob_joins=len(table),tree=tree,status='WHOLE_IMMUTABLE_SOURCE_GIT_JOIN_NO_NATIVE_AUTHORITY')

def prefill(carrier,cache,v,deadline,*,git_dir,profile_dir=HERE):
 raw=read(HERE/'legacy-prefill-profile.json',deadline,65536);need(pin(raw)==PROFILE,'whole fixed prefill capability profile');profile=json.loads(raw);n=len(v['files']);selected=[(name,row)for name,row in profile['carriers'].items()if n in row['prefill_counts']];need(len(selected)==1,'only exact32/20/8 or compiler6 policies');name,row=selected[0];raw=read(Path(profile_dir)/name,deadline,2*1024**2);need(pin(raw)==row['profile'],'whole pinned maintained carrier profile');external=json.loads(raw);need(external['source']==row['source']and external['ref']==row['ref']and len(external['files'])==row['files']and external['actual']is None,'exact source-only maintained carrier binding')
 proof=prove(Path(carrier),git_dir,external,deadline);helper=HERE/row['helper'];need(pin(read(helper,deadline,65536))==row['helper_pin'],'unchanged proven original prefill helper');spec=importlib.util.spec_from_file_location('_exact_original_legacy_prefill',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);result=module.prefill(carrier,cache,v,deadline);return dict(result,carrier_source_proof=proof)
