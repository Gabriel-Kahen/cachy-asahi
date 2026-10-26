# SPDX-License-Identifier: MIT
"""Separate Apps6 baseline607 projection; fixed fresh607 source stays immutable."""
import ast,json,types
from pathlib import Path
import common as C
MATERIALIZER_EDITS=[('len(held)==599','len(held)==600'),('exact599 held original604','exact600 held original604'),('len(sign)==8','len(sign)==7'),('exact607/eight current TEST signature operands','exact607/seven current TEST signature operands'),('fresh607=dict(','baseline607=dict('),('held_original604=599,incoming_exact_archives=8','held_original604=600,incoming_exact_archives=7'),('fresh_TEST_signatures=8','fresh_TEST_signatures=7')]
def source(fresh):
 fresh=C.safe(fresh);__import__('namespace_context').fresh(fresh);p=C.profile();C.need(type(p['fresh_source_files'])is dict and C.rows(fresh)==p['fresh_source_files'],'whole immutable fixed-target fresh607 source')
 return C.load('_latest607_baseline_original_common',fresh/'implementation/common.py')
def profile(fresh):
 p=source(fresh).profile();C.need(p['target']==C.profile()['after']and p['incoming']==C.profile()['incoming'],'same complete fixed607 source input ledger');p=dict(p,incoming={n:r for n,r in p['incoming'].items()if n!='cachy-asahi-apps'},target=C.profile()['before']);C.need(len(p['incoming'])==7 and set(p['incoming'])=={'cachy-asahi-doctor','cachy-asahi-ksmctl','cachy-asahi-setup','cachy-asahi-welcome','cachy-asahi-boot-report','cachy-asahi-dns','cachy-asahi-sysctl'},'only seven non-Apps incoming products')
 return p

def derive(raw):
 text=raw.decode();ledger=[]
 for before,after in MATERIALIZER_EDITS:C.need(text.count(before)==1,'one finite Apps6 baseline materializer seam '+before);text=text.replace(before,after,1);ledger.append(dict(before=before,after=after))
 restored=text
 for row in reversed(ledger):C.need(restored.count(row['after'])==1,'one counted baseline inverse');restored=restored.replace(row['after'],row['before'],1)
 C.need(restored.encode()==raw,'whole fixed fresh607 materializer inverse; signer/verifier/copy/order held');compile(text,'<separate-baseline607-materializer>','exec');return text.encode(),ledger

def module(fresh):
 fresh=C.safe(fresh);original=source(fresh);projected=types.ModuleType('common');projected.__dict__.update(vars(original));projected.profile=lambda:profile(fresh);raw,ledger=derive(C.read(fresh/'implementation/materialize.py'));m=types.ModuleType('_latest607_baseline607_materializer');m.__file__=str(fresh/'implementation/materialize.py')
 saved=__import__('sys').modules.get('common')
 try:__import__('sys').modules['common']=projected;exec(compile(raw,m.__file__,'exec'),vars(m))
 finally:
  if saved is None:__import__('sys').modules.pop('common',None)
  else:__import__('sys').modules['common']=saved
 return m,ledger

def selection(fresh,base):
 m,_=module(fresh);held,expected,lock=m.selection(base);C.need(len(held)==600 and expected==C.locks()[0]and C.pin(lock)==C.profile()['before'],'exact Apps6 baseline607; not an accepted installed state');return held,expected,lock

def prepare(fresh,ready,public,producer,target,**apis):
 # Caller must first satisfy Root's independent fresh607 AND baseline607 gates.
 m,_=module(fresh);return m.prepare(ready,public,producer,target,**apis)
