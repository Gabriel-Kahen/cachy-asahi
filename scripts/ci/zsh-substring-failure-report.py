#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded readonly failure facts before static's private fixture cleanup."""
import argparse,base64,hashlib,json,os,re,stat
from pathlib import Path
CASES=('noninteractive','editing','preexisting-function','preexisting-widget','preexisting-private')
CHECKER='f79eb322f34617d43ae13deaaac057f431e8e81f11a23e8a79876158c37dff00'
CAP=65536

def need(ok,why):
 if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False)+'\n').encode()
def decode(raw):
 def pairs(rows):
  value={}
  for k,v in rows:need(k not in value,'duplicate JSON key');value[k]=v
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def read(path):
 path=Path(path).absolute();need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary path');a=path.stat();need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==os.getuid() and 0<=a.st_size<=CAP,'ordinary owned bounded single-link file')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as stream:raw=stream.read(CAP+1);b=os.fstat(stream.fileno())
 identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 need(identity(a)==identity(b)==identity(path.stat()) and len(raw)==a.st_size,'input drift');return raw

def original(path,name,tail=False):
 result=dict(filename=name,status='UNAVAILABLE')
 try:
  raw=read(path);result.update(status='HASH_ONLY',bytes=len(raw),sha256=sha(raw))
  if tail:
   value=raw[-4096:];result.update(status='BOUNDED_FAILED_TERMINAL_TAIL',tail_bytes=len(value),tail_sha256=sha(value),tail_base64=base64.b64encode(value).decode(),truncated=len(raw)>len(value))
  return result,raw
 except (OSError,ValueError) as e:result['error_type']=type(e).__name__;return result,None

def report(work,checker):
 result=dict(status='STATIC_ZSH_FAILURE_DIAGNOSTIC_ONLY',acceptance_authority=False,tests=[],checker_source='UNVERIFIED_REASON_HASH_ONLY')
 try:
  work=Path(work).absolute();need(not any(p.is_symlink() for p in (work,*work.parents)),'ordinary owned fixture root');s=work.stat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700,'original private fixture root')
  checked,_=original(checker,'check-module.py');result['checker']=checked;trusted=checked.get('sha256')==CHECKER
  if trusted:result['checker_source']='EXACT_PINNED_ORIGINAL_CHECKER'
  receipt,raw=original(work/'receipt.json','receipt.json');result['receipt']=receipt
  try:
   need(raw is not None,'original receipt unavailable');value=decode(raw)
   need(type(value)is dict and value.get('status')in('FAIL','PASS_HOST_ZSH_PTY_CONTROLS') and type(value.get('tests'))is list and all(type(r)is dict for r in value['tests']) and [r.get('name') for r in value['tests']]==list(CASES),'original finite five-case receipt')
   tests=[]
   for row in value['tests']:
    need(row['status']in('PASS','FAIL'),'typed case status');r=dict(case=row['name'],status=row['status'])
    if row['status']=='FAIL':
     kind=row['error_type'];reason=row['reason'];need(type(kind)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',kind) and type(reason)is str and len(reason)<=256,'original finite failure type/reason')
     data=reason.encode();r.update(error_type=kind,reason_bytes=len(data),reason_sha256=sha(data),reason_projection='HASH_ONLY')
     if trusted and reason.isprintable():r.update(reason=reason,reason_projection='SOURCE_KNOWN_SAFE_PRINTABLE_REASON')
     r['terminal']=original(work/row['name']/'terminal.log',row['name']+'/terminal.log',True)[0]
    tests.append(r)
   result.update(receipt_status=value['status'],tests=tests)
  except (ValueError,KeyError,TypeError,UnicodeError,RecursionError) as e:
   result['receipt']['status']='UNAVAILABLE_OR_MALFORMED_HASH_ONLY';result['receipt']['error_type']=type(e).__name__
   # Missing/malformed receipt never authorizes raw terminal projection.
   result['terminal_hashes']=[original(work/c/'terminal.log',c+'/terminal.log')[0] for c in CASES]
 except (OSError,ValueError,TypeError) as e:result.update(status='STATIC_ZSH_FAILURE_DIAGNOSTIC_UNAVAILABLE',error_type=type(e).__name__)
 need(len(encoded(result))<=CAP,'bounded complete public diagnostic');return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--work',type=Path,required=True);p.add_argument('--checker',type=Path,required=True);a=p.parse_args();print(encoded(report(a.work,a.checker)).decode(),end='')
