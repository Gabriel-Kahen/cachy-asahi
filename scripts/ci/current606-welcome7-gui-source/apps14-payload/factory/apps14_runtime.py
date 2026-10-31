# SPDX-License-Identifier: MIT
"""Actual ordinary-user installed Apps14 payload and shared Runtime1 identity."""
import hashlib,json,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def observe(root=Path('/')):
 profile=json.loads((HERE/'apps14-installed-profile.json').read_bytes());rows={};wanted={**profile['payload'],**profile['runtime']}
 for n,w in wanted.items():
  p=root/n;need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary installed Apps14/Runtime input');s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size==w['bytes'],'exact installed Apps14/Runtime leaf');raw=p.read_bytes();after=p.lstat();fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');need(all(getattr(s,k)==getattr(after,k)for k in fields)and pin(raw)==w,'stable exact installed Apps14/Runtime bytes')
  if n in profile['modes']:need(stat.S_IMODE(s.st_mode)==profile['modes'][n],'exact packaged Apps14 mode')
  rows[n]=w
 return dict(status='ACTUAL_INSTALLED_APPS14_AND_UNCHANGED_RUNTIME1_SOURCE_BYTES',version=profile['version'],recipe_source=profile['recipe_source'],files=rows,inventory_limit_seconds=30,GUI_command_limit_seconds=35,required_fresh_scans=2)

def validate(before,after):
 profile=json.loads((HERE/'apps14-installed-profile.json').read_bytes());wanted={**profile['payload'],**profile['runtime']}
 need(before==after and before['status']=='ACTUAL_INSTALLED_APPS14_AND_UNCHANGED_RUNTIME1_SOURCE_BYTES'and before['version']=='0.1.0-14'and before['recipe_source']==profile['recipe_source']and before['files']==wanted and before['inventory_limit_seconds']==30 and before['GUI_command_limit_seconds']==35 and before['required_fresh_scans']==2,'whole actual Apps14/Runtime1 identity around original inventory command')
 return before
