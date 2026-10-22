# SPDX-License-Identifier: MIT
"""Bounded DATA-only wrapper: original public member names remain untouched inside ZIP."""
import base64,hashlib,json,re,stat,zipfile
from pathlib import Path
MAX=512*1024**2
ROLES=('source-proof.json','runtime-terminal.json','ordered-cleanup.json','input-preparation.json','gui/runtime.json','gui/runtime-image.log','gui/qemu-image.log','runtime-child.log')
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def name(n):
 p=Path(n);need(type(n)is str and n and p.as_posix()==n and not p.is_absolute()and not{'.','..'}&set(n.split('/')),'contained original public member');return n
def read(p,cap):
 p=Path(p);need(p.is_absolute()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary public evidence ancestry');a=p.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink public evidence');b=p.read_bytes();z=p.lstat();fields=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns');need(len(b)==a.st_size and all(getattr(a,k)==getattr(z,k)for k in fields),'public evidence changed during read');return b
def pack(public,out,proof):
 public,out=Path(public),Path(out);need(public.is_absolute()and out.is_absolute()and public.is_dir()and not out.exists()and not(out.is_relative_to(public)or public.is_relative_to(out)),'fresh disjoint owned transport output');need(re.fullmatch('[a-f0-9]{40}',proof['source'])and type(proof['run'])is int and proof['run']>0 and proof['attempt']==1 and proof['case']in tuple(p+'-'+m for p in('minimal','overlay')for m in('generic4k','generic16k'))and re.fullmatch('[a-f0-9]{16}',proof['job_token']),'fixed actual source/case/nonce fields');out.mkdir(mode=0o700)
 bound={k:proof[k]for k in('source','run','attempt','case','job_token')};diagnostic=dict(status='SOURCE_OWNED_PUBLIC_FAILURE_DATA_NOT_ACCEPTANCE',**bound,roles={},errors=[],actual_authority=False)
 for n in ROLES:
  p=public/n
  if not p.exists():continue
  try:
   b=read(p,16*1024**2);tail=b[-16384:];diagnostic['roles'][n]=dict(original=pin(b),tail_offset=len(b)-len(tail),tail=pin(tail),base64=base64.b64encode(tail).decode())
  except Exception as error:diagnostic['errors'].append(n+': '+str(error)[:200])
 raw=enc(diagnostic);need(len(raw)<=256*1024,'bounded fixed-role diagnostic DATA');(out/'failure-data.json').write_bytes(raw)
 index=dict(status='FAILURE_DIAGNOSTIC_PACKED_NOT_ACCEPTANCE',**bound,diagnostic=pin(raw),evidence=None,member_count=None,uncompressed_bytes=None,error=None,actual_authority=False)
 try:
  retention_raw=read(public/'retention.json',2*1024**2);retention=json.loads(retention_raw);need(retention['status']in('FAIL_OR_INCOMPLETE','PASS_ONE_CURRENT606_WELCOME8_GUI_METADATA_PIXELS_PENDING_ROOT')and retention['case']==proof['case'],'original positive or incomplete retention DATA only');wanted=retention['files'];actual={p.relative_to(public).as_posix()for p in public.rglob('*')if p.is_file()or p.is_symlink()};need(actual==set(wanted)|{'retention.json'} and len(actual)<=1024 and not any(p.is_symlink()for p in public.rglob('*')),'exact original public closure before wrapping');total=0;dest=out/'evidence.zip'
  with zipfile.ZipFile(dest,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6,allowZip64=True)as z:
   for n in sorted(actual):
    name(n);body=read(public/n,96*1024**2 if n.startswith('generated/')else 16*1024**2);total+=len(body);need(total<=MAX,'unchanged whole512MiB public bound')
    if n!='retention.json':need(pin(body)==wanted[n],'whole retained public member '+n)
    z.writestr(n,body)
  need(dest.stat().st_size<=MAX and retention['total_bytes']==total-len(retention_raw),'whole original retention bytes and transport cap');index.update(status='PACKED_PUBLIC_EVIDENCE_DATA_ONLY',evidence=pin(read(dest,MAX)),member_count=len(actual),uncompressed_bytes=total)
 except Exception as error:
  index['error']=type(error).__name__+': '+str(error)[:256]
  # A partial archive never becomes an alternative positive ingress.
  if(out/'evidence.zip').exists():(out/'evidence.zip').unlink()
 (out/'index.json').write_bytes(enc(index));return index
