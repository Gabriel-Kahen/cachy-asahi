# SPDX-License-Identifier: MIT
"""Only Setup5/6 changes on the exact accepted Apps6 baseline606."""
import hashlib
LOCK='3a586c1e3400391f56bd281ac9c16aba85d94d0fca002770e77ee1802c5d9fd1'
PRODUCTS=(('setup','cachy-asahi-setup','0.1.0-5','0.1.0-6'),)
NAME=PRODUCTS[0][1];RUNTIME='cachy-asahi-repository-runtime'
BOUNDS=dict(component=3000,consumer=4800,owner=9600,transaction=90,real_fixture=240,case=30,cleanup=60)
PHASES=(('install6','0.1.0-6'),('same-version6','0.1.0-6'),('rollback5','0.1.0-5'),('forward6','0.1.0-6'),('remove6',None),('reinstall6','0.1.0-6'),('restore-original5','0.1.0-5'))
def need(ok,why):
 if not ok:raise ValueError(why)
def inventory_bytes(value):return ''.join(n+' '+v+'\n'for n,v in sorted(value.items())).encode()
def product(role):need(role=='setup','only Setup selected');return PRODUCTS[0]
def baseline(value):
 need(type(value)is dict and len(value)==606 and hashlib.sha256(inventory_bytes(value)).hexdigest()==LOCK and value[NAME]=='0.1.0-5'and value['cachy-asahi-apps']=='0.1.0-6'and value[RUNTIME]=='0.1.0-1','exact genuine Apps6 baseline606/Setup5/Runtime1');return dict(value)
def transitions(value):
 current=baseline(value);out=[]
 for phase,version in PHASES:
  before=dict(current)
  if version is None:current.pop(NAME)
  else:current[NAME]=version
  need({n:v for n,v in before.items()if n!=NAME}=={n:v for n,v in current.items()if n!=NAME}and len(current)==(605 if version is None else 606),'all other605 fixed')
  out.append(dict(phase=phase,before=before,after=dict(current),version=version,archive_role=None if version is None else'original1'if version=='0.1.0-5'else'new2'))
 need(current==value and len(out)==7,'exact606 restoration');return out
