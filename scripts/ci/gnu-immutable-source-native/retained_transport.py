#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed full574 raw DATA transport; fetched code, hooks and filters never run."""
import argparse,base64,hashlib,math,os,re,signal,stat,sys,time,types
from pathlib import Path
sys.dont_write_bytecode=True
LANE='scripts/ci/gnu-immutable-source-native'
API_SHA='ae044c80a3c40ee6bd0cb49cf7c5c78040a7703e7b09a35d1485f7d0828a67bf'
EVIDENCE_SHA='dc415a8e01e086c805b98b43c880c0aaad2d8afb35bc9a8be068d5a90d78f355'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def absolute(path):
 p=Path(path);need(p.is_absolute()and p==p.resolve()and not any(q.is_symlink()for q in(p,*p.parents)),'absolute ordinary DATA path');return p

def read(path,cap):
 p=absolute(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=cap,'ordinary bounded DATA file');out=bytearray()
  while len(out)<=before.st_size:
   part=os.read(fd,min(1024**2,before.st_size-len(out)+1))
   if not part:break
   out.extend(part)
  need(len(out)==before.st_size and key(before)==key(os.fstat(fd))==key(p.lstat()),'stable whole DATA file');return bytes(out)
 finally:os.close(fd)
def load(path,digest,name):
 body=read(path,128*1024);need(pin(body)['sha256']==digest,'source-owned whole helper hardpin');m=types.ModuleType(name);m.__file__=str(path);exec(compile(body,str(path),'exec'),vars(m));return m
E=load(Path(__file__).resolve().parent/'retained_transport_evidence.py',EVIDENCE_SHA,'_gnu_retained_transport_evidence')
def api(root):
 root=absolute(root);need(Path(__file__).resolve()==root/LANE/'retained_transport.py','adapter own exact Source root');return load(root/'scripts/maintenance/retained_git_transport.py',API_SHA,'_gnu_retained_rawblob_api')
def profile(root,R):
 raw=read(root/LANE/'retained-carrier-profile.json',2*1024**2);v=R.profile_check(raw,E.PROFILE,E.CARRIER);need(len(v['files'])==E.FILES and sum(r['bytes']for r in v['files'].values())==E.BYTES,'all unchanged1154/1046432165 materials');return raw,v
def binding(root):
 e=os.environ;source=e.get('SOURCE_SHA','');ref=e.get('GITHUB_REF_NAME','');run=e.get('GITHUB_RUN_ID','')
 need(re.fullmatch('[a-f0-9]{40}',source)and source==e.get('WORKFLOW_SHA')==e.get('GITHUB_SHA')and re.fullmatch('[1-9][0-9]{0,19}',run)and re.fullmatch('codex/[a-z0-9-]+',ref)and e.get('GITHUB_RUN_ATTEMPT')=='1'and e.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and e.get('GITHUB_EVENT_NAME')=='workflow_dispatch'and e.get('RUNNER_ARCH')=='ARM64','same genuine first native source/ref/run environment')
 temp=absolute(e['RUNNER_TEMP']);need(temp.is_dir()and temp.stat().st_uid==os.getuid()and not temp.stat().st_mode&0o022,'owned RUNNER_TEMP parent');need(not temp.is_relative_to(root)and not root.is_relative_to(temp),'DATA parent disjoint executable Source')
 path=temp/'gnu-immutable-parent/selection/private-inputs/policy.json';raw=read(path,2*1024**2);s=path.stat();need(s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)==0o600,'actual private source-owned selection');v=E.obj(raw);nonce=v['broker']['nonce'];need(type(nonce)is str and re.fullmatch('[a-f0-9]{32}',nonce)and v['bootstrap']['nonce']==nonce and v['actual_source']==source and v['actual_ref']==ref and type(v['actual_run'])is str and v['actual_run']==run,'same source/ref/run/fresh selected broker nonce')
 own=dict(source=source,ref=ref,run_id=int(run),attempt=1,selection_nonce=nonce,selection_policy=pin(raw));E.binding_check(own);return own,temp/'gnu-retained-transport'

def verify_existing(carrier,source_root,deadline):
 """Current full DATA/commit/tree/blob proof; no actor or acquisition."""
 root=absolute(source_root);R=api(root);_,p=profile(root,R);own,destination=binding(root);carrier=absolute(carrier);need(carrier==destination/'data','same fixed external DATA carrier');need(type(deadline)in(int,float)and math.isfinite(deadline)and time.monotonic()<deadline<=time.monotonic()+480,'finite caller-owned proof deadline')
 raw=read(destination/'receipt.json',E.RECEIPT_CAP);receipt=E.obj(raw);table=E.validate_receipt(receipt,p,str(carrier));need(E.obj(read(destination/'binding.json',65536))==own,'same selected nonce/source/ref/run/attempt transport owner');delivery=R.Delivery(destination,deadline,R.reference_policy())
 try:
  for row in receipt['commands']:
   if'stdout_material'in row:
    name=row['raw_stdout'][5:];v=delivery.file_pin(carrier/name,p['files'][name]['bytes'],blob=True);need(v=={k:row['stdout_material'][k]for k in('bytes','sha256','git_blob')},'every current rawbody full Gitblob/SHA256 join')
   else:need(pin(delivery.read(destination/row['raw_stdout'],R.MAX_LOG))==row['stdout_pin'],'complete current metadata stdout')
   need(pin(delivery.read(destination/row['raw_stderr'],R.MAX_LOG))==row['stderr_pin'],'complete current raw stderr')
  commit=delivery.read(destination/receipt['commands'][3]['raw_stdout'],65536);need(hashlib.sha1(b'commit '+str(len(commit)).encode()+b'\0'+commit).hexdigest()==E.CARRIER and commit.split(b'\n',1)[0]==b'tree '+receipt['tree'].encode(),'whole current rawcommit source and tree');actual={}
  for row in delivery.read(destination/receipt['commands'][4]['raw_stdout'],R.MAX_LOG).split(b'\0'):
   if row:
    h,n=row.split(b'\t',1);mode,kind,oid=h.decode().split();name=n.decode();need(kind=='blob'and name not in actual,'whole current recursive tree');actual[name]=dict(mode=mode,oid=oid)
  need(actual==table,'every current tree/mode/blob join')
  for i in(2,len(receipt['commands'])-1):need(delivery.read(destination/receipt['commands'][i]['raw_stdout'],128)==(E.CARRIER+'\n').encode(),'current fetched/detached DATA source')
  need(read(carrier/'.git/HEAD',128)==(E.CARRIER+'\n').encode(),'current detached DATA HEAD');R.namespace(delivery,p['files'],table);delivery.tick()
 finally:os.close(delivery.fd)
 return dict(status='PASS_CURRENT_COMPLETE_RETAINED_DATA_ONLY',binding=own,source=E.CARRIER,files=E.FILES,bytes=E.BYTES,blob_joins=E.FILES,tree=receipt['tree'],profile_sha256=E.PROFILE,receipt=pin(raw),native='NOT_RUN',signature_authentication='NOT_RUN',source_code_execution='NOT_RUN')

def run(root):
 root=absolute(root);R=api(root);raw,_=profile(root,R);own,destination=binding(root);need(not os.path.lexists(destination),'fresh one-shot transport, no adoption/retry')
 previous={};cancelled=[]
 def cancel(number,frame):
  cancelled.append(number)
  if len(cancelled)==1:raise InterruptedError('outer transport cancellation; owned supervisor must retire current child')
 try:
  for number in(signal.SIGTERM,signal.SIGINT):previous[number]=signal.signal(number,cancel)
  return R.deliver(url='https://github.com/Gabriel-Kahen/cachy-asahi.git',expected_source=E.CARRIER,profile_raw=raw,profile_sha256=E.PROFILE,destination=destination,executable_root=root,policy=R.reference_policy(),binding_raw=E.encoded(own))
 finally:
  for number,handler in previous.items():signal.signal(number,handler)
def evidence(root,exit_code):
 root=absolute(root);R=api(root);profile_raw,p=profile(root,R);own,destination=binding(root);need(type(exit_code)is int and 0<=exit_code<=255,'actual outer-wrapper exit code');v=dict(schema=1,binding=own,wrapper_exit=exit_code,transport=None,raw_diagnostics={},diagnostics_complete=True,error=None)
 try:
  receipt=E.obj(read(destination/'receipt.json',E.RECEIPT_CAP));v['transport']=receipt;need(E.obj(read(destination/'binding.json',65536))==own,'same pre-actor binding');names=[]
  for row in receipt['commands']:
   i=row['number'];names.append(row['raw_stderr'])
   # Interrupted blobs may lack stdout_material. Never print blob stdout.
   if i<5 or i>=E.FILES+5:names.append(row['raw_stdout'])
  total=0
  for name in names:
   need(re.fullmatch('logs/[0-9]{4}\\.(stdout|stderr)',name),'numbered nonmaterial diagnostics only');raw=read(destination/name,R.MAX_LOG);total+=len(raw);need(total<=E.DIAGNOSTIC_CAP,'aggregate nonmaterial diagnostic cap');v['raw_diagnostics'][name]=dict(**pin(raw),base64=base64.b64encode(raw).decode())
  if exit_code==0:E.positive(v,profile_raw,own)
 except(Exception,KeyboardInterrupt)as error:
  v['diagnostics_complete']=False;v['error']=type(error).__name__+': '+str(error)[:1000]
  # Missing receipt after wrapper kill is UNKNOWN. Keep stderr plus the first
  # five metadata stdout slots only; never package/blob stdout.
  total=sum(row['bytes']for row in v['raw_diagnostics'].values())
  for path in sorted((destination/'logs').glob('*')):
   name=path.relative_to(destination).as_posix();match=re.fullmatch('logs/([0-9]{4})\\.(stdout|stderr)',name)
   if not match or name in v['raw_diagnostics']or(match[2]=='stdout'and int(match[1])>=5):continue
   try:
    raw=read(path,R.MAX_LOG);total+=len(raw)
    if total>E.DIAGNOSTIC_CAP:break
    v['raw_diagnostics'][name]=dict(**pin(raw),base64=base64.b64encode(raw).decode())
   except OSError:continue
 return v

def public_frame(value):
 try:return E.frame(value)
 except ValueError:
  raw=E.encoded(value)
  if len(raw)<=E.EVIDENCE_CAP:raise
  # Keep an explicit incomplete frame even when the public body bound fails.
  # The complete local receipt remains retained and receives no acceptance.
  reduced=dict(value,transport=None,diagnostics_complete=False,error='PUBLIC_EVIDENCE_LIMIT: full payload '+str(pin(raw))+' retained locally; no acceptance')
  return E.frame(reduced)

def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('run','emit'));parser.add_argument('--source-root',type=Path,required=True);parser.add_argument('--exit-code',type=int);a=parser.parse_args(argv)
 if a.action=='emit':
  v=evidence(a.source_root,a.exit_code);framed=public_frame(v);sys.stdout.buffer.write(framed);return 0 if v['diagnostics_complete']and E.parse_framed(framed)['diagnostics_complete']else 1
 need(a.exit_code is None,'run cannot predeclare a wrapper result');run(a.source_root);return 0
if __name__=='__main__':raise SystemExit(main())
