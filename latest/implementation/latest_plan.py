# SPDX-License-Identifier: MIT
"""Exactly five selected tools on original606; finite one-package operations."""
import hashlib,json
LOCK='3a586c1e3400391f56bd281ac9c16aba85d94d0fca002770e77ee1802c5d9fd1'
PRODUCTS=(('apps','cachy-asahi-apps','0.1.0-6','0.1.0-7'),('doctor','cachy-asahi-doctor','0.1.0-1','0.2.0-1'),('ksm','cachy-asahi-ksmctl','0.1.0-1','0.1.0-2'),('welcome','cachy-asahi-welcome','0.1.0-4','0.1.0-7'),('boot','cachy-asahi-boot-report',None,'0.1.0-1'))
RUNTIME='cachy-asahi-repository-runtime'
BOUNDS=dict(consumer=4200,owner=6600,transaction=90,fixture=100,cleanup=60)
def need(ok,why):
 if not ok:raise ValueError(why)
def inventory_bytes(rows):return ''.join(n+' '+v+'\n'for n,v in sorted(rows.items())).encode()
def product(role):
 need(type(role)is str,'fixed product role');rows=[row for row in PRODUCTS if row[0]==role];need(len(rows)==1,'one of five fixed products');return rows[0]
def baseline(value):
 need(type(value)is dict and len(value)==606 and all(type(n)is type(v)is str for n,v in value.items())and hashlib.sha256(inventory_bytes(value)).hexdigest()==LOCK,'whole original606 inventory lock')
 need(value.get(RUNTIME)=='0.1.0-1'and all(value.get(name)==old for _,name,old,_ in PRODUCTS),'exact selected original versions and protected Runtime1')
 return dict(value)
def transitions(original):
 current=baseline(original);events=[]
 def step(role,action,version):
  nonlocal current
  _,name,old,new=product(role);before=dict(current);after=dict(before)
  if version is None:need(name in after,'explicit installed selected removal');after.pop(name)
  else:need(version in(old,new),'finite original/latest selected version');after[name]=version
  need({k:v for k,v in before.items()if k!=name}=={k:v for k,v in after.items()if k!=name}and before[RUNTIME]==after[RUNTIME]=='0.1.0-1','all nonacted versions and Runtime1 held')
  need(len(before)in(606,607)and len(after)in(606,607),'bounded one-removal composition counts')
  events.append(dict(phase=action+'-'+role,role=role,name=name,action=action,before=before,after=after,version=version,archive_role=None if version is None else'original'if version==old else'latest',unaffected_count=len(before)-(name in before)))
  current=after
 for role,_,old,new in PRODUCTS:step(role,'install'if old is None else'upgrade',new)
 for role,_,_,new in PRODUCTS:step(role,'same-version',new)
 for role,_,_,new in PRODUCTS:step(role,'remove',None);step(role,'reinstall',new)
 for role,_,old,_ in reversed(PRODUCTS):step(role,'restore-original',old)
 need(len(events)==25 and current==original,'exact final original606 versions; no selected physical restoration claim')
 return events
