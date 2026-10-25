"""Exact lease-aware successor of broker Context; live DM predicate held."""
import inspect,textwrap,types,os,stat
import inputs,map_join
P,C,_,_=inputs.broker()
old=inspect.getsource(C.Context.check)
anchor='R.mount_table()==self.mounts';replacement='self.leases.validate(self.mounts,R.mount_table())'
P.need(old.count(anchor)==1,'one exact full-mount predicate');text=old.replace(anchor,replacement);space=dict(vars(C));exec(compile(textwrap.dedent(text),'<explicit-pid1-lease-transition>','exec'),space)
P.need(text.replace(replacement,anchor)==old,'exact original Context.check inverse')
class Context(C.Context):
 check=space['check']
 def __init__(self,value,root,work,limits,leases,native):
  self.leases=leases;self.disposal_control=-1;super().__init__(value,root,work,limits)
  try:
   mounted=P.unpack(P.decode(P.index_bytes(self.index,self.index_pin)));self.map_join=map_join.join(native,mounted)
   self.disposal_control=os.open('/dev/mapper/control',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC);info=os.fstat(self.disposal_control);P.need(stat.S_ISCHR(info.st_mode)and info.st_rdev==os.makedev(10,236),'PID1 private disposal control')
  except BaseException:self.close();raise

 def close_source(self):super().close()
 def close(self):
  super().close()
  if getattr(self,'disposal_control',-1)>=0:os.close(self.disposal_control);self.disposal_control=-1
