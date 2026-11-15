#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Six fixed independent observer checks and bounded private diagnostic receipts."""
import hashlib,json,os,re,stat
from pathlib import Path
NAMES={'bus-credentials','logind-session','process-vt','keyboard-record','gpu-record','seat-status'}

def bus(user,cred):
 return cred['UnixUserID']==1000 and cred['ProcessID']==user['pid'],{'expected_pid':user['pid'],'actual_uid':cred.get('UnixUserID'),'actual_pid':cred.get('ProcessID'),'actual_group_ids':cred.get('UnixGroupIDs')}
def session(props):
 ok=props['Seat'][0]=='seat0' and props['Active'] is True and props['Name']=='builder' and props['TTY']=='tty1' and props['User'][0]==1000
 return ok,{'actual':{k:props.get(k) for k in ('Id','Name','User','Active','Class','Type','Remote','Service','TTY','Seat','Leader')}}
def process(user,sid,vt):
 return sid==user['process_session'] and vt=='tty1',{'pid':user['pid'],'expected_process_session':user['process_session'],'actual_process_session':sid,'actual_foreground_VT':vt,'logind_leader':user['logind']['Leader'],'leader_session_equality_required':False}
def record(before,after,accepted):
 changed=sorted(k for k in before.keys()|after.keys() if before.get(k)!=after.get(k))
 details={'changed_fields':changed,'accepted':bool(accepted),'before':before,'after':after,'property_changes':{}}
 for key in ('properties','parent_properties'):
  if key not in changed:continue
  def props(value):
   result={}
   for line in value.splitlines():
    if '=' in line:
     k,v=line.split('=',1);result[k]=v
   return result
  a,b=props(before.get(key,'')),props(after.get(key,''))
  details['property_changes'][key]=sorted(k for k in a.keys()|b.keys() if a.get(k)!=b.get(k))
 return before==after and accepted,details

def publish(directory,nonce,name,passed,evidence,public):
 if name not in NAMES or not re.fullmatch('[0-9a-f]{32}',nonce):raise ValueError('fixed independent check/nonce required')
 directory=Path(directory);st=directory.stat()
 if directory.is_symlink() or not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o700:raise ValueError('private owned receipt directory required')
 body={'schema_version':1,'nonce':nonce,'check':name,'passed':bool(passed),'evidence':evidence}
 raw=(json.dumps(body,sort_keys=True)+'\n').encode()
 if len(raw)>65536:raise ValueError('independent check receipt64KiB bound')
 fd=os.open(directory/('observer-check-'+name+'.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 summary={'passed':bool(passed),'receipt_bytes':len(raw),'receipt_sha256':hashlib.sha256(raw).hexdigest()}
 if 'changed_fields' in evidence:summary.update(changed_fields=evidence['changed_fields'],property_changes=evidence['property_changes'],accepted=evidence['accepted'])
 else:summary['actual']=evidence
 public[name]=summary
 if not passed:raise AssertionError('independent-'+name)
