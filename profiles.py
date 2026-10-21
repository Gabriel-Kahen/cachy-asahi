# SPDX-License-Identifier: MIT
"""Only exact additive syscall rules over immutable Moby28.0.4 default."""
import copy,hashlib,json
from pathlib import Path
CLONE_NEWUSER=0x10000000
USER_RULE=dict(names=['unshare'],action='SCMP_ACT_ALLOW',args=[dict(index=0,value=CLONE_NEWUSER,op='SCMP_CMP_EQ')])
CHROOT_RULE=dict(names=['chroot'],action='SCMP_ACT_ALLOW')
def selected(base,kind):
 assert kind in('default','user-only','user-and-chroot');p=copy.deepcopy(base)
 if kind!='default':p['syscalls'].append(copy.deepcopy(USER_RULE))
 if kind=='user-and-chroot':p['syscalls'].append(copy.deepcopy(CHROOT_RULE))
 assert {k:v for k,v in p.items()if k!='syscalls'}=={k:v for k,v in base.items()if k!='syscalls'}and p['syscalls'][:len(base['syscalls'])]==base['syscalls'];return p
