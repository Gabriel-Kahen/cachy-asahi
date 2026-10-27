"""PID1 owns fixed proc15/dev-null4096 leases; ordinary controls never call mount."""
import os,stat
from pathlib import Path
import lease_table as T
ORDER=('probe',)+('pristine',)*4+('modified',)*4

class Leases:
 def __init__(self,proc,pid1):
  self.proc=proc;self.pid1=pid1;self.base=None;self.active=None;self.registered={};self.sequence=0;self.records=[]
 def inventory(self):return ('\n'.join(self.proc.inventory())+'\n').encode()
 def validate(self,base,current):
  self.pid1();T.transition(base,current,self.registered);return True
 def open(self,case):
  self.pid1();P=self.proc;P.need(self.active is None and self.sequence<len(ORDER)and case==ORDER[self.sequence],'one ordered original proc/dev lease')
  before=self.inventory();P.need(not self.registered,'no unretired mount rows');self.base=before;held=[];record=dict(case=case,status='FAIL',calls=[],cleanup='NOT_RETIRED');self.records.append(record)
  self.active=dict(case=case,held=held,targets=[],created=[],record=record)
  # Reserve lifetime before any creation/syscall so partial failures retain it.
  root=Path('/work/.gnu-readonly-proc-probe')if case=='probe'else Path('/work')/case/'root'
  if case=='probe':
   parent_fd,parent_info=P.ordinary(Path('/work'));held.append((Path('/work'),parent_fd,parent_info));os.mkdir(root.name,0o700,dir_fd=parent_fd);self.active['created'].append(root)
  for path in((root,)if case=='probe'else(root,root/'proc',root/'dev')):
   fd,info=P.ordinary(path);held.append((path,fd,info))
  proc=root if case=='probe'else root/'proc';P.need(not os.listdir(next(fd for p,fd,_ in held if p==proc))and not P.mounted(proc),'fresh empty owned proc target')
  targets=[(proc,False)]
  if case!='probe':
   target=root/'dev/null';P.need(not target.exists()and not target.is_symlink()and not P.mounted(target),'absent dev/null placeholder');devfd=next(fd for p,fd,_ in held if p==root/'dev')
   fd=os.open('null',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=devfd);os.close(fd);self.active['created'].append(target);fd,info=P.ordinary(target,False);held.append((target,fd,info));targets.append((target,True))
  null_fd=os.open('/dev/null',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);null_info=os.fstat(null_fd);held.append((Path('/dev/null'),null_fd,null_info));P.need(stat.S_ISCHR(null_info.st_mode)and null_info.st_rdev==os.makedev(1,3)and null_info.st_uid==null_info.st_gid==0,'actual harmless root-owned dev/null');source_row=P.source_mount()
  for target,bind in targets:
   for path,fd,info in held:
    covered=[row for target,row in self.active['targets']if target==path]
    if covered:
     P.need(path==proc and bind is True and len(covered)==1 and P.mounted(path)==covered,'only exact registered proc may cover held target')
     P.need(P.identity(os.fstat(fd))==P.identity(info),'owned covered proc descriptor identity')
     P.need(P.verify_mount(path)['mount_row']==covered[0],'fresh owned proc cover matches registered row')
    else:P.stable(path,fd,info)
   T.transition(before,self.inventory(),self.registered);target_fd=next(fd for p,fd,_ in held if p==target)
   # Kernel targets an owned pinned inode, not a worker-swappable pathname.
   result=P.invoke(Path('/proc/self/fd')/str(target_fd),bind=bind);record['calls'].append(dict(target=str(target),**result));P.need(result['returncode']==0,'exact original mount call failed')
   after=self.inventory();added=T.lease_rows(before,after,[str(t)for t,_ in targets[:len(self.registered)+1]])
   self.registered=added;self.active['targets'].append((target,added[next(k for k,v in added.items()if v.split()[4]==os.fsencode(target))].decode()))
   record['dev_null'if bind else'proc']=P.verify_bind(target,null_info,source_row)if bind else P.verify_mount(target)
  self.sequence+=1;record['status']='ACTIVE_PID1_OWNED_FIXED_LEASE';return dict(case=case,sequence=self.sequence,mounts={str(k):v.decode()for k,v in self.registered.items()},purpose='GNU_PID1_PRIVATE_RUNTIME_MOUNTS_V1')
 def close(self,case):
  self.pid1();P=self.proc;P.need(self.active is not None and self.active['case']==case,'exact active lease required');state=self.active;T.transition(self.base,self.inventory(),self.registered)
  for target,row in reversed(state['targets']):
   P.need(P.mounted(target)==[row],'only exact registered mount may unmount');result=P.invoke(target,unmount=True);state['record']['calls'].append(dict(target=str(target),**result));P.need(result['returncode']==0 and not P.mounted(target),'original umount0/absence');ident=int(row.split()[0]);del self.registered[ident];T.transition(self.base,self.inventory(),self.registered)
  for path,fd,info in state['held']:P.stable(path,fd,info)
  for path in reversed(state['created']):
   fd=next(fd for p,fd,_ in state['held']if p==path);P.need(P.identity(os.fstat(fd))==P.identity(path.lstat()),'owned placeholder/probe identity');path.rmdir()if path.is_dir()else path.unlink()
  P.need(self.inventory()==self.base,'complete original mount inventory restored')
  for _,fd,_ in reversed(state['held']):os.close(fd)
  state['record'].update(status='PASS_PID1_OWNED_FIXED_LEASE',cleanup='EXACT_MOUNTS_ABSENT_PLACEHOLDERS_REMOVED');self.active=None;return state['record']
 def retired(self):
  self.pid1();self.proc.need(self.active is None and not self.registered,'all leases strictly retired');return dict(leases=self.sequence,records=self.records,status='NO_ACTIVE_PID1_RUNTIME_MOUNTS')
