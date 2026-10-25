# SPDX-License-Identifier: MIT
"""Six finite tools; same606 baseline/607 peak, exact32 one-package transactions."""
import hashlib,json
LOCK='3a586c1e3400391f56bd281ac9c16aba85d94d0fca002770e77ee1802c5d9fd1'
PRODUCTS=(('apps','cachy-asahi-apps','0.1.0-6','0.1.0-16'),('doctor','cachy-asahi-doctor','0.1.0-1','0.2.0-1'),('ksm','cachy-asahi-ksmctl','0.1.0-1','0.1.0-2'),('welcome','cachy-asahi-welcome','0.1.0-4','0.1.0-8'),('boot','cachy-asahi-boot-report',None,'0.1.0-1'),('setup','cachy-asahi-setup','0.1.0-5','0.1.0-6'))
RUNTIME='cachy-asahi-repository-runtime'
BOUNDS=dict(consumer=4200,owner=6600,component=3600,transaction=90,fixture=100,real_module_suite=240,cleanup=60)
TRANSACTIONS=32;GRAPHS=65;AUXILIARY=33
REAL_PHASES={'upgrade-setup':'install6','same-version-setup':'same-version6','forward-setup':'forward6','reinstall-setup':'reinstall6'}
def need(ok,why):
 if not ok:raise ValueError(why)
def inventory_bytes(rows):return ''.join(n+' '+v+'\n'for n,v in sorted(rows.items())).encode()
def product(role):
 need(type(role)is str,'fixed product role');rows=[r for r in PRODUCTS if r[0]==role];need(len(rows)==1,'one of six fixed products');return rows[0]
def baseline(value):
 need(type(value)is dict and len(value)==606 and all(type(n)is type(v)is str for n,v in value.items())and hashlib.sha256(inventory_bytes(value)).hexdigest()==LOCK,'whole original606 inventory lock');need(value.get(RUNTIME)=='0.1.0-1'and all(value.get(name)==old for _,name,old,_ in PRODUCTS),'exact five selected baseline versions/Boot absence/protected Runtime1');return dict(value)
def transitions(original):
 current=baseline(original);events=[]
 def step(role,action,version):
  nonlocal current
  _,name,old,new=product(role);before=dict(current);after=dict(before)
  if version is None:need(name in after,'explicit installed selected removal');after.pop(name)
  else:need(version in(old,new),'finite original/latest selected version');after[name]=version
  need({k:v for k,v in before.items()if k!=name}=={k:v for k,v in after.items()if k!=name}and before[RUNTIME]==after[RUNTIME]=='0.1.0-1','all nonacted versions and Runtime1 held');need(len(before)in(606,607)and len(after)in(606,607),'bounded one-removal composition count')
  events.append(dict(phase=action+'-'+role,role=role,name=name,action=action,before=before,after=after,version=version,archive_role=None if version is None else'original'if version==old else'latest',unaffected_count=len(before)-(name in before)));current=after
 for role,_,old,new in PRODUCTS:step(role,'install'if old is None else'upgrade',new)
 for role,_,_,new in PRODUCTS:step(role,'same-version',new)
 step('setup','rollback','0.1.0-5');step('setup','forward','0.1.0-6')
 for role,_,_,new in PRODUCTS:step(role,'remove',None);step(role,'reinstall',new)
 for role,_,old,_ in reversed(PRODUCTS):step(role,'restore-original',old)
 need(len(events)==TRANSACTIONS and current==original and len({e['phase']for e in events})==TRANSACTIONS,'all32 signed transitions/final original606')
 need(set(REAL_PHASES)=={e['phase']for e in events if e['role']=='setup'and e['version']=='0.1.0-6'},'four unchanged real-module suite phases')
 return events

def physical_domain(graph):
 rows=graph['packages'];need(type(rows)is list and len(rows)==606 and len({r['name']for r in rows})==606,'whole initial606 rawDB graph');selected={name for _,name,old,_ in PRODUCTS if old is not None};wanted={r['name']:r for r in rows if r['name']not in selected};need(len(selected)==5 and len(wanted)==601 and RUNTIME in wanted and 'cachy-asahi-boot-report'not in wanted,'derived606 minus5 selected=601 inclRuntime1; Boot initially absent');return wanted
