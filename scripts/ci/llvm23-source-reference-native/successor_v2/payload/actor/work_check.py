#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only nonroot pre-entry observation; creates no work-volume marker."""
import hashlib,json,os,stat
from pathlib import Path

def verify(value,initialized,actual,uid,gid,writable,empty):
 if value['schema']!=1 or value['outer_operation']!='llvm23-source-reference-native-v2'or value['inner_operation']!='llvm23-source-reference-native-v1'or value['native_acceptance']is not False:raise ValueError('explicit outer/inner delegation required')
 if value['expected_owner']!={'uid':1001,'gid':1001,'mode':0o700}or uid!=1001 or gid!=1001 or actual!=initialized['after']or actual['uid']!=1001 or actual['gid']!=1001 or actual['mode']!=0o700 or not writable or not empty:raise ValueError('actual initialized1001:1001/0700 empty writable work volume required')
 if initialized['status']!='INITIALIZED_EMPTY_WORK_VOLUME'or initialized['after']!=actual or initialized['binding']!=value['binding']:raise ValueError('same source/token-bound initializer receipt required')

def main():
 raw=Path('/inputs/volume-admission.json').read_bytes()
 if len(raw)>16384 or hashlib.sha256(raw).hexdigest()!=os.environ.get('WORK_VOLUME_ADMISSION_SHA256'):raise ValueError('exact separately reviewed volume admission')
 value=json.loads(raw);receipt=Path('/inputs/volume-initialization.json').read_bytes()
 if len(receipt)>16384:raise ValueError('bounded actual initializer receipt')
 initialized=json.loads(receipt);p=Path('/work');s=p.lstat()
 if not stat.S_ISDIR(s.st_mode)or p.is_symlink()or Path.cwd()!=p:raise ValueError('ordinary exact work root')
 actual=dict(device=s.st_dev,inode=s.st_ino,uid=s.st_uid,gid=s.st_gid,mode=stat.S_IMODE(s.st_mode))
 if not(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1001):raise ValueError('all actual nonroot1001 credentials')
 verify(value,initialized,actual,os.getuid(),os.getgid(),os.access(p,os.W_OK|os.X_OK,effective_ids=True)and not os.statvfs(p).f_flag&os.ST_RDONLY,not any(p.iterdir()))
 print(json.dumps(dict(status='NONROOT_WORK_VOLUME_VERIFIED',binding=value['binding'],actual=actual,write_probe=False),sort_keys=True))
if __name__=='__main__':main()
