"""Whole source inverse and held reader predicates before actual parsing."""
import ast,base64,hashlib,json,re,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE_SHA='622d60b21f0404ff2c12c0ec0339cb6a6b9a0a6b0e7dff9f29ad652c5e54162b'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def read(p,cap=2*1024**2):
 p=Path(p).absolute();need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary custody source');a=p.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink custody source');b=p.read_bytes();need(len(b)==a.st_size,'custody length drift');return b
def normalize(raw):
 lines=raw.decode().splitlines(keepends=True);tree=ast.parse(raw);found=set()
 for n in tree.body:
  if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('SOURCE','REF','RUN'):
   key=n.targets[0].id;v=ast.literal_eval(n.value);need(n.lineno==n.end_lineno and key not in found,'one finite Root metadata literal');found.add(key)
   need(v is None or type(v)is str and re.fullmatch({'SOURCE':'[0-9a-f]{40}','REF':'codex/[a-z0-9-]+','RUN':'[1-9][0-9]{0,19}'}[key],v),'typed Root metadata only')
   lines[n.lineno-1]=key+(' = None\n'if key=='RUN'else'=None\n')
 need(found=={'SOURCE','REF','RUN'},'three declared metadata seams');return ''.join(lines).encode()
def inverse(raw,row,before):
 need(pin(raw)==row['proposed'],'whole proposed source/reader pin')
 for e in reversed(row['edits']):
  a,b=e['start'],e['end'];new=base64.b64decode(e['new'],validate=True);old=base64.b64decode(e['old'],validate=True);need(type(a)is int and type(b)is int and 0<=a<=b<=len(raw)and raw[a:b]==new,'exact finite inverse span');raw=raw[:a]+old+raw[b:]
 need(pin(raw)==row['before']and raw==before,'whole original after inverse');return raw
def check(source):
 source=Path(source).absolute();raw=read(HERE/'custody-profile.json');need(pin(raw)['sha256']==PROFILE_SHA,'pinned source/reader inverse profile');p=json.loads(raw)
 actual=set()
 for f in source.rglob('*'):
  need(not f.is_symlink()and(f.is_file()or f.is_dir()),'ordinary source closure')
  if f.is_file():actual.add(f.relative_to(source).as_posix())
 need(len(actual)==20 and actual==set(p['source_files'])and not p['removed']and p['added']==['scripts/ci/gnu-verity-kernel-native/domain.py'],'exact20 finite source closure')
 for n,v in p['source_files'].items():need(pin(read(source/n))==v,'whole source differs: '+n)
 for n,row in p['source_changed'].items():inverse(read(source/n),row,read(HERE/'source-before'/n))
 for n,row in p['reader_changed'].items():
  raw=read(HERE/n);raw=normalize(raw)if n=='replay.py'else raw;inverse(raw,row,read(HERE/'reader-before'/n))
 for n,v in p['reader_held'].items():need(pin(read(HERE/n))==v,'held collector/positive/failure parser: '+n)
 for n,v in p.get('new_reader_held',{}).items():need(pin(read(HERE/n))==v,'source calibration code: '+n)
 old=json.loads(read(HERE/'source-before/scripts/ci/gnu-verity-kernel-native/fixtures/configuration-rules.json'));rules=json.loads(read(source/'scripts/ci/gnu-verity-kernel-native/fixtures/configuration-rules.json'))
 need({k:v for k,v in old.items()if k!='inactive_bool_tristate_domain'}=={k:v for k,v in rules.items()if k!='inactive_bool_tristate_domain'},'active14/already-enabled/authority metadata whole held')
 def funcs(raw):return{n.name:ast.get_source_segment(raw.decode(),n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
 old=funcs(read(HERE/'source-before/scripts/ci/gnu-verity-kernel-native/lane.py'));now=funcs(read(source/'scripts/ci/gnu-verity-kernel-native/lane.py'));need(set(old)==set(now)and {n for n in old if old[n]!=now[n]}=={'preflight'},'delta/build/retention/command/cleanup functions whole held')
 return dict(status='PASS_SOURCE20_DOMAIN_INVERSE_ONLY_NO_NATIVE_ACCEPTANCE',files=20,active_changes=14,inactive_domain=189,actual_run=None,acceptance='NOT_GRANTED')
