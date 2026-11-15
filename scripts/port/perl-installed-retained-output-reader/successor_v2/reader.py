#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Math-only trusted preload for the unchanged exact252 passive Reader."""
import argparse,hashlib,importlib.util,json,re,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PARENT_PROFILE='c10f724f69c4a2cd5f4a243ea5057edd9acfc628caacbc7c41c347426936f08c'
REVISION='RETAINED_OUTPUT_READER_V2_EXPLICIT_STDLIB_MATH_PRELOAD'
MODULES=frozenset(('argparse','hashlib','importlib.util','io','json','math','os','pathlib','re','stat','sys','tarfile','types'))
SOURCE={
 'hosted/reader.py':('c25379514eb494c4a1541aebb102e47c3897b6c27183b69d7bfa210ad07e8be2',('argparse','hashlib','importlib.util','json','pathlib','types'),('sys',)),
 'hosted/common.py':('bd45167f147fc6bf2b40fc878c5253b2bfe2d4b23fe74c322e838fc24f8957ee',('hashlib','importlib.util','os','json','math','pathlib','re','stat','sys'),()),
 'hosted/capsule.py':('354ce106cc89bba186f4d9f62fddb10c55b86632a07ebd53a63ea22784d99b34',('hashlib','json','pathlib','tarfile'),()),
 'hosted/image_probe.py':('a8962c92041a5beb7b6adfd27a6bad64d15d3e62bbb9cad3f6e8ed6940fd55ba',('hashlib','json','os','pathlib','re','stat','sys'),()),
 'lifecycle-code/read_result.py':('2dff5d7be09239bfede23acc5d04d29b6eb67dafacfe26df10140d2757079086',('argparse','importlib.util','io','re','pathlib','tarfile'),('sys',)),
 'lifecycle-code/common.py':('bf3868cdc89665c5ee79bad9eee260a21737abc70b55b31d6eedc16bee131ba6',('hashlib','importlib.util','json','os','pathlib','re','stat','sys'),())}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path,cap=2*1024**2):
 p=Path(path);need(p.is_absolute()and p==p.resolve()and not any(q.is_symlink()for q in(p,*p.parents)),'canonical trusted code input')
 before=p.stat();need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size<=cap,'bounded single-link trusted code')
 raw=p.read_bytes();state=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 need(len(raw)==before.st_size and state(before)==state(p.stat()),'stable trusted code');return raw

def parent():
 root=HERE.parent;raw=read(root/'profile.json');need(pin(raw)['sha256']==PARENT_PROFILE,'whole frozen v1 profile')
 for name,row in json.loads(raw)['files'].items():
  p=root/name;need(pin(read(p))=={k:row[k]for k in('bytes','sha256')}and stat.S_IMODE(p.stat().st_mode)==row['mode'],'whole frozen v1 member '+name)
 spec=importlib.util.spec_from_file_location('retained_output_v1_pinned',root/'reader.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
LEGACY=parent();BASE=LEGACY.F.Fence

def declarations(raw):
 # This scanner describes six WHOLE-PINNED simple sources, not arbitrary Python.
 # Any body change is independently rejected by the fixed SHA below.
 text=raw.decode();declared=[]
 for line in text.splitlines():
  s=line.strip()
  if s.startswith('import '):declared.extend(part.strip()for part in s[7:].split(','))
  elif s.startswith('from '):declared.append(s.split()[1])
 dynamic=tuple(re.findall(r"__import__\(['\"]([^'\"]+)['\"]\)",text))
 need(not any('__import__'in line and not re.search(r"__import__\(['\"]sys['\"]\)",line)for line in text.splitlines()),'unreviewed dynamic import expression')
 need(set(declared)|set(dynamic)<=MODULES,'unlisted passive module declaration')
 return tuple(declared),dynamic

def code_contract(code):
 by_hash={v[0]:(n,v[1],v[2])for n,v in SOURCE.items()};seen=set()
 for name,raw in code.items():
  declared,dynamic=declarations(raw);digest=pin(raw)['sha256'];need(digest in by_hash,'changed or nonpassive code body');logical,want,explicit=by_hash[digest]
  need((declared,dynamic)==(want,explicit)and logical not in seen,'exact finite Source import declarations');seen.add(logical)
 need(seen==set(SOURCE),'exact six passive modules, no missing/extra body')

def preload_math():
 # Sole new preload. -I selects the Root-reviewed Python standard library.
 # No Source, package, Original, plugin or arbitrary module is an operand.
 need(sys.flags.isolated and sys.dont_write_bytecode,'isolated no-bytecode preload')
 import math
 spec=math.__spec__;need(spec is not None and spec.name=='math','exact CPython math module')
 if spec.origin=='built-in':
  need('math'in sys.builtin_module_names and (spec.loader.__module__,spec.loader.__name__)==('_frozen_importlib','BuiltinImporter')and not hasattr(math,'__file__'),'literal builtin math implementation')
  p=Path(sys.executable).resolve();return dict(module='math',kind='BUILTIN_IN_SELECTED_PYTHON',origin='built-in',python=str(p),**pin(read(p,64*1024**2)))
 need((type(spec.loader).__module__,type(spec.loader).__name__)==('_frozen_importlib_external','ExtensionFileLoader'),'ordinary CPython math extension')
 p=Path(spec.origin);need(p==p.resolve()and p.is_relative_to(Path(sys.base_prefix).resolve()),'math belongs to selected Python standard-library prefix')
 return dict(module='math',kind='SELECTED_PYTHON_STDLIB_EXTENSION',origin=str(p),**pin(read(p,16*1024**2)))

class Fence(BASE):
 def __init__(self,reads,code,writes,dirs):
  code_contract(code);self.math_preload=preload_math();super().__init__(reads,code,writes,dirs)
  need('math'in self.imports,'math available before the unchanged passive fence')


def review(a):
 LEGACY.F.Fence=Fence
 try:result=LEGACY.review(a)
 finally:LEGACY.F.Fence=BASE
 result['reader_revision']=dict(kind=REVISION,parent_profile_sha256=PARENT_PROFILE,preloads=['math'],math=preload_math(),finite_passive_modules=sorted(MODULES),Source_and_original_unchanged=True)
 return result

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('binding','binding-sha256','hosted-binding','hosted-binding-sha256','source-root','evidence','output'):p.add_argument('--'+n,required=True)
 try:print(json.dumps(review(p.parse_args()),sort_keys=True,indent=2))
 except(ValueError,KeyError,TypeError,OSError,RuntimeError)as e:print(json.dumps(dict(status='REFUSED_RETAINED_OUTPUT_DATA',reason=type(e).__name__+': '+str(e)[:1800],acceptance=False,Root_decision=None)));raise SystemExit(2)
