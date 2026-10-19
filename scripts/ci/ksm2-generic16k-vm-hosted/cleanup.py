# SPDX-License-Identifier: MIT
"""Failure retirement only after saved direct-group absence; unknown disks retained."""
import json,os,re,stat,time
from pathlib import Path
import hosted as O

def groups(work):
 rows=[]
 for name in ('commands.json','prepare/commands.json'):
  p=work/name
  if p.exists():
   values=O.decode(O.read(p));O.need(type(values)is list,'saved bounded command rows');rows+=values
 p=work/'runtime/qemu.json'
 if p.exists():rows.append(O.decode(O.read(p)))
 state=work/'owner-result.json'
 if state.exists()and O.decode(O.read(state)).get('phase')=='VM':O.need(p.exists(),'QEMU launch/wait outcome missing; retain producer and disks')
 O.need(rows and all(type(r)is dict and r.get('group_absence_verified')is True for r in rows),'all saved direct child groups must be absent before failure cleanup');return rows

def run(root,work,proof):
 root=Path(root);work=Path(work);st=work.lstat();lease=O.decode(O.read(work/'owner-lease.json'));O.need(lease==dict(source=proof['source'],run=proof['run'],identity=[st.st_dev,st.st_ino,st.st_uid])and st.st_uid==os.getuid()and stat.S_IMODE(st.st_mode)==0o700,'same owned private workspace')
 held=groups(work);R=O.load('_ksm_failure_supervisor',root/'runtime/borrowed/runtime.py');end=time.monotonic()+330;records=[];env=dict(PATH='/usr/bin:/bin',LC_ALL='C',HOME=str(work))
 def command(argv,allow=False,limit=30):
  seconds=min(limit,end-time.monotonic());O.need(seconds>0,'original bounded330 cleanup envelope');row,out,err,error=R.run_command(argv,work,env,seconds,2*1024**2);records.append(row);n=str(len(records)).zfill(2);(work/('cleanup-'+n+'.stdout')).write_bytes(out);(work/('cleanup-'+n+'.stderr')).write_bytes(err);(work/'cleanup-commands.json').write_bytes(O.encoded(records));O.need(error is None and row['group_absence_verified']is True and(allow or row['exit_code']==0),'cleanup command/group refusal');return row,out,err
 selection=work/'selection.json';actor='NOT_CREATED_BEFORE_SELECTION'
 if selection.exists():
  s=O.decode(O.read(selection));O.need(s['VM_source']==proof['source']and s['VM_run']==proof['run']and re.fullmatch('[a-f0-9]{32}',s['nonce']),'actual selection lease');name='caa-ksm2-vm-'+s['nonce']+'-prepare'
  row,out,err=command(['/usr/bin/docker','container','inspect',name],True)
  if row['exit_code']==0:
   values=O.decode(out);producer=O.decode(O.read(work/'producer/report.json'));O.need(len(values)==1,'one owned preparer');v=values[0];O.need(v['Name']=='/'+name and v['Image']==producer['image']and v['Config']['Labels'].get('org.cachy-asahi.ksm2-vm.prepare')==s['nonce']and re.fullmatch('[a-f0-9]{64}',v['Id']),'exact owned consumer before retirement');command(['/usr/bin/docker','rm','-f',v['Id']]);row,out,err=command(['/usr/bin/docker','container','inspect',name],True)
  O.need(row['exit_code']==1 and name.encode()in out+err and b'No such'in out+err,'unambiguous owned preparer absence');actor='ABSENCE_VERIFIED'
 producer='NOT_STARTED'
 if (work/'producer/report.json').exists():
  # Unmodified producer refuses uncertain builds and foreign image references.
  row,out,err=command(['/usr/bin/python3','-I','-B',str(root/'runtime/borrowed/maintained_desktop574.py'),'cleanup','--inputs',str(root/'runtime/borrowed/maintained574-inputs.json'),'--output',str(work/'producer'),'--job-token',proof['job_token']],True,330)
  producer='PASS_ORIGINAL_PRODUCER_RETIREMENT'if row['exit_code']==0 else'UNKNOWN_PRESERVED_BY_ORIGINAL_PRODUCER'
 result=dict(status='PASS_KNOWN_ACTORS_RETIRED_PRIVATE_DISKS_RETAINED'if producer in('NOT_STARTED','PASS_ORIGINAL_PRODUCER_RETIREMENT')else'UNKNOWN_RETAINED',groups=len(held),preparer=actor,producer=producer,disks='RETAINED_ON_FAILURE_NO_UNPROVEN_INODE_DELETION',commands=records)
 (work/'failure-cleanup.json').write_bytes(O.encoded(result));return result
