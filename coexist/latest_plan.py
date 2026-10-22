# SPDX-License-Identifier: MIT
"""Exact Apps6/7 and Setup5/6 transitions; every other604 version stays fixed."""
import hashlib
LOCK='3a586c1e3400391f56bd281ac9c16aba85d94d0fca002770e77ee1802c5d9fd1'
PRODUCTS=(('apps','cachy-asahi-apps','0.1.0-6','0.1.0-7'),('setup','cachy-asahi-setup','0.1.0-5','0.1.0-6'))
RUNTIME='cachy-asahi-repository-runtime'
# Fifteen boundaries,29 full graphs,14 signed transactions, four unchanged240s
# Setup real suites. This is a separate larger lane; no old timer is relabeled.
BOUNDS=dict(component=7200,consumer=9000,owner=13800,transaction=90,real_fixture=240,apps_fixture=150,case=30,cleanup=60,job_minutes=300)
PHASES=(('install-apps7','apps','0.1.0-7'),('install-setup6','setup','0.1.0-6'),('same-apps7','apps','0.1.0-7'),('same-setup6','setup','0.1.0-6'),('rollback-apps6','apps','0.1.0-6'),('rollback-setup5','setup','0.1.0-5'),('forward-apps7','apps','0.1.0-7'),('forward-setup6','setup','0.1.0-6'),('remove-apps7','apps',None),('reinstall-apps7','apps','0.1.0-7'),('remove-setup6','setup',None),('reinstall-setup6','setup','0.1.0-6'),('restore-apps6','apps','0.1.0-6'),('restore-setup5','setup','0.1.0-5'))
REAL_PHASES=frozenset(('install-setup6','same-setup6','forward-setup6','reinstall-setup6'))
def need(ok,why):
 if not ok:raise ValueError(why)
def inventory_bytes(value):return ''.join(n+' '+v+'\n'for n,v in sorted(value.items())).encode()
def product(role):
 found=[r for r in PRODUCTS if r[0]==role];need(len(found)==1,'only exact Apps/Setup selected roles');return found[0]
def baseline(value):
 need(type(value)is dict and len(value)==606 and hashlib.sha256(inventory_bytes(value)).hexdigest()==LOCK and all(value[name]==old for _,name,old,_ in PRODUCTS)and value[RUNTIME]=='0.1.0-1','exact genuine original606 Apps6/Setup5/Runtime1');return dict(value)
def transitions(value):
 current=baseline(value);fixed={n:v for n,v in current.items()if n not in{r[1]for r in PRODUCTS}};out=[]
 for phase,role,version in PHASES:
  _,name,old,new=product(role);before=dict(current)
  if version is None:current.pop(name)
  else:current[name]=version
  need({n:v for n,v in current.items()if n not in{r[1]for r in PRODUCTS}}==fixed and len(fixed)==604,'all other604 exact versions')
  need({n:v for n,v in before.items()if n!=name}=={n:v for n,v in current.items()if n!=name},'one selected package per signed transaction')
  out.append(dict(phase=phase,role=role,name=name,before=before,after=dict(current),version=version,archive_role=None if version is None else'original'if version==old else'new',real_setup=phase in REAL_PHASES))
 need(current==value and len(out)==14 and sum(e['real_setup']for e in out)==4,'whole original606 restoration/four joint real suites');return out
