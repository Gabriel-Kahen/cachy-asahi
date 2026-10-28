# SPDX-License-Identifier: MIT
"""Finite local source/custody checks; no Git, network, or actor execution."""
import hashlib,json,os,re,stat
from pathlib import Path
RECIPE='2e58341f6fa25de5167fd8a59566b3dd7f066fe3'
PAIR='5bbf9b2078d67d5543d01a849144fbd5696fa677'
PAIR_REF='codex/apps14-pair-native-v1'
RUN=39788418793
NAME='cachy-asahi-apps'
VERSION='0.1.0-14'
ROLES={'runtime':'cachy-asahi-repository-runtime','apps':'cachy-asahi-apps','client':'cachy-asahi-repository-client-v2'}
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def read(p,cap=16*1024**2):
 p=Path(p).absolute();need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary exact input ancestry');s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=cap,'ordinary bounded singlelink input');raw=p.read_bytes();t=p.lstat();need(len(raw)==s.st_size and all(getattr(s,k)==getattr(t,k)for k in FIELDS),'stable whole input read');return raw
def decode(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate JSON key');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def obj(p):return decode(read(p))
def member(n):need(type(n)is str and n and not n.startswith('/')and all(p not in('','.','..','.git')for p in n.split('/')),'contained ordinary carrier role');return n
def table(root):
 root=Path(root).absolute();out={}
 for b,ds,fs in os.walk(root):
  if Path(b)==root:ds[:]=[n for n in ds if n!='.git'];fs=[n for n in fs if n!='.git']
  for n in ds:need(not(Path(b)/n).is_symlink(),'ordinary source directory')
  for n in fs:out[(Path(b)/n).relative_to(root).as_posix()]=pin(read(Path(b)/n,128*1024**2))
 return out
def closed(root,rows):need(table(root)==rows,'whole exact closed input/source map');return rows

def index_check(index,files,recipe_map,acceptance):
 need(index['status']=='EXACT_ACCEPTED_APPS14_PAIR_INPUT_DATA_ONLY'and index['actual']is None,'Apps14 input DATA only')
 need(index['source']==PAIR and index['ref']==PAIR_REF and index['run']==RUN and index['recipe_source']==RECIPE,'exact Apps14 native pair/recipe source and run')
 need(index['GUI']==index['installed_current606']==index['hardware']=='NOT_RUN','no pair acceptance transfer')
 recipe_prefix=member(index['recipe_prefix']);need(recipe_prefix=='recipe-source','exact public whole42 recipe namespace')
 need({n.removeprefix(recipe_prefix+'/'):w for n,w in files.items()if n.startswith(recipe_prefix+'/')}==recipe_map,'all42 original public recipe leaves')
 archives=index['archives'];need(type(archives)is list and len(archives)==2 and len({r['path']for r in archives})==2,'two distinct original Apps14 build roles')
 pins=[]
 for row in archives:
  path=member(row['path']);w={k:row[k]for k in('bytes','sha256')};need(path.endswith('/cachy-asahi-apps-0.1.0-14-any.pkg.tar.xz')and type(w['bytes'])is int and 0<w['bytes']<=16*1024**2 and re.fullmatch('[a-f0-9]{64}',w['sha256'])and files[path]==w,'exact accepted Apps14 any archive body');pins.append(w)
 need(pins[0]==pins[1],'complete byte-identical Apps14 native pair')
 need(acceptance['source']==PAIR and acceptance['ref']==PAIR_REF and acceptance['run']==RUN and acceptance['status']=='ROOT_ACCEPTED_APPS14_NATIVE_BUILD_PAIRS_AND_FINITE_INSTALLED_LIFECYCLE','genuine matching Root Apps14 finite acceptance required')
 # Root selects the explicit archive-pin field from its original decision. Never
 # infer acceptance from a successful CI result or a historical Apps7 receipt.
 authority=acceptance
 for key in index['acceptance_archive_pointer']:
  need(type(key)in(str,int),'typed Root archive-pin pointer');authority=authority[key]
 need(type(authority)is dict and all(authority[k]==pins[0][k]for k in('bytes','sha256')),'original Root decision authorizes this exact native archive')
 need(files[member(index['acceptance'])]==pin(enc(acceptance)),'canonical original Root decision bytes')
 for role in('LICENSE','NOTICE.md'):
  need(role in files,'public source/license closure required')
 return dict(name=NAME,version=VERSION,archive=Path(archives[0]['path']).name,size=pins[0]['bytes'],sha256=pins[0]['sha256'])
