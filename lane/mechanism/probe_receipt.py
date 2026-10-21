# SPDX-License-Identifier: MIT
"""One fixed mechanism receipt; never systemd/native-build acceptance."""
import json
FIELDS={'schema','status','mode','parent_namespace','child_namespace','mapping','retained_capabilities','before_chroot','after_chroot','original_child1','chroot','retirement','checks','systemd_test','native_ARM'}
def parse(raw,mode):
 if type(raw)is not bytes or not 0<len(raw)<=4096 or not raw.endswith(b'\n')or len(raw.splitlines())!=1 or mode not in('mechanism','native-preflight'):raise ValueError('one bounded fixed-mode probe record')
 def pairs(items):
  result={}
  for k,v in items:
   if k in result:raise ValueError('duplicate field')
   result[k]=v
  return result
 def constant(_):raise ValueError('nonfinite field')
 value=json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)
 if type(value)is not dict or set(value)!=FIELDS:raise ValueError('exact probe schema')
 expected=dict(schema=1,status='PASS_OWNED_USERNS_CHROOT_MECHANISM_ONLY',mode=mode,parent_namespace='UNCHANGED',child_namespace='USER_ONLY',mapping='SELF_ONLY',retained_capabilities='SYS_CHROOT_ONLY',before_chroot=[True,True],after_chroot=[False,False],original_child1=True,chroot='/usr',retirement='BOTH_OWNED_CHILDREN_REAPED',checks=53 if mode=='mechanism'else 58,systemd_test='NOT_EXECUTED',native_ARM='NOT_ESTABLISHED_BY_THIS_PROBE')
 if value!=expected or type(value['schema'])is not int or type(value['checks'])is not int or type(value['original_child1'])is not bool or any(type(item)is not bool for n in('before_chroot','after_chroot')for item in value[n]):raise ValueError('all before/after/namespace/capability/retirement facts required')
 return value
