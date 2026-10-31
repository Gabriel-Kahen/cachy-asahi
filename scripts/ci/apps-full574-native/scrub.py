#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Dispose entire bound private copies/TEST authority only after actor absence."""
import os,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C

def main():
 C.need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CACHY_APPS574_LIFECYCLE')=='1' and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'owned offline scrub actor required')
 C.source(Path('/source'));value=C.decode(C.read(Path('/inputs/scrub.json')))
 C.need(value['token']==os.environ['OWNER_TOKEN'] and value['status']=='ALL_EARLIER_CONSUMERS_ABSENCE_VERIFIED' and value['actors'] and all(r['status']=='PASS_ABSENCE_VERIFIED' for r in value['actors']),'earlier actor absence receipt required')
 T=C.load('original_disposer',Path('/source/scripts/apps/transaction.py'))
 for name in ('work','authority'):
  root=Path('/'+name);C.need(root.is_mount() and T.inode(root)==value[name] and root.stat().st_mode&0o777==0o700,'exact bound owned private mount')
  budget=T.F.Limits(deadline=time.monotonic()+60,max_nodes=510001);fd=T.F._open_root(root)
  try:
   mount=T.F._mount_id(fd,budget);T.LIFETIME._empty(fd,mount,budget,[0],depth=-1)
   C.need(not list(root.iterdir()) and T.inode(root)==value[name],'complete exact private tree disposal')
   os.fchown(fd,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))
  finally:os.close(fd)
 C.save(Path('/out/disposal.json'),dict(status='PASS_WHOLE_OWNED_COPIES_AND_AUTHORITY_DISPOSED_AFTER_ACTOR_ABSENCE',rollback='NOT_CLAIMED',lock_handling='NO_STALE_LOCK_RELEASE_OR_RAW_LOCK_DELETION_API_WHOLE_PRIVATE_TREE_DISPOSAL_ONLY',prior_actors=value['actors']))
 os.chown('/out/disposal.json',int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))
if __name__=='__main__':main()
