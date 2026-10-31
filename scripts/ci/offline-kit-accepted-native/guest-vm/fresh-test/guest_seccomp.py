# SPDX-License-Identifier: MIT
"""Finite Source77 Moby-profile compiler. No native actions occur on import."""
import ctypes as C
import hashlib,json,re
from pathlib import Path
POLICY_SHA='c3f3a00be01ff6d855bfe5d6f31ed5f4e5fa31f2e84efd87e7270202b19e076a'
LIBRARY='/usr/lib/libseccomp.so.2.6.0'
LIBRARY_SHA='bb30f1c00ccfa041ada09a6276eb7d76e937ce58b27a9c7a02684b50a840f8a8'
LIBRARY_BYTES=198584
OPS={'SCMP_CMP_NE':1,'SCMP_CMP_LT':2,'SCMP_CMP_LE':3,'SCMP_CMP_EQ':4,'SCMP_CMP_GE':5,'SCMP_CMP_GT':6,'SCMP_CMP_MASKED_EQ':7}

def need(v,why):
 if not v:raise ValueError(why)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def decode(raw):
 def unique(rows):
  d={}
  for k,v in rows:need(k not in d,'duplicate seccomp key');d[k]=v
  return d
 return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:need(False,'nonfinite seccomp JSON'))

def version(v):
 need(type(v)is str,'literal kernel version');m=re.match(r'([0-9]+)\.([0-9]+)',v);need(m,'kernel major/minor');return tuple(map(int,m.groups()))

def applicable(row,kernel):
 for kind in('excludes','includes'):
  f=row.get(kind,{})
  need(set(f)<={'arches','caps','minKernel'},'finite Moby condition')
  if kind=='excludes':
   if 'arm64'in f.get('arches',[]):return False
   if f.get('minKernel')and version(kernel)>=version(f['minKernel']):return False
  else:
   if f.get('arches')and 'arm64'not in f['arches']:return False
   if f.get('caps'):return False # Every phase has the empty bounding set.
   if f.get('minKernel')and version(kernel)<version(f['minKernel']):return False
 return True

def action(name,errno=None):
 if name=='SCMP_ACT_ALLOW':return 0x7fff0000
 need(name=='SCMP_ACT_ERRNO'and type(errno)is int and 0<=errno<=4095,'finite ALLOW/ERRNO action');return 0x00050000|errno

def plan(raw,phase,kernel):
 need(phase in('produce','receive','candidate')and len(raw)==20575 and sha(raw)==POLICY_SHA,'exact Source77 policy and finite phase')
 value=decode(raw);need(value['defaultAction']=='SCMP_ACT_ERRNO'and value['defaultErrnoRet']==1 and len(value['syscalls'])==42,'exact42-rule source profile')
 arm=[r for r in value['archMap']if r['architecture']=='SCMP_ARCH_AARCH64'];need(len(arm)==1 and arm[0]['subArchitectures']==['SCMP_ARCH_ARM'],'exact AARCH64/ARM architecture map')
 selected=value['syscalls'][:31]if phase!='candidate'else value['syscalls'];rules=[]
 for row in selected:
  if not applicable(row,kernel):continue
  args=[]
  for a in row.get('args',[]):
   need(set(a)<={'index','op','value','valueTwo'}and type(a['index'])is int and 0<=a['index']<=5 and a['op']in OPS,'finite scalar comparator')
   for key in('value','valueTwo'):need(type(a.get(key,0))is int and 0<=a.get(key,0)<2**64,'unsigned64 seccomp argument')
   args.append((a['index'],OPS[a['op']],a['value'],a.get('valueTwo',0)))
  act=action(row['action'],row.get('errnoRet'))
  for name in row['names']:need(type(name)is str and re.fullmatch('[a-z0-9_]+',name),'literal syscall name');rules.append(dict(name=name,action=act,args=args))
 return dict(default=action('SCMP_ACT_ERRNO',1),arches=['aarch64','arm'],source_rule_count=len(selected),rules=rules,policy_sha256=POLICY_SHA,phase=phase,outer_bounding_capabilities=[])

class Comparison(C.Structure):_fields_=[('arg',C.c_uint),('op',C.c_int),('datum_a',C.c_uint64),('datum_b',C.c_uint64)]

def library(reader):
 raw=reader(Path(LIBRARY),LIBRARY_BYTES);need(len(raw)==LIBRARY_BYTES and sha(raw)==LIBRARY_SHA,'pinned original574 libseccomp ELF')
 lib=C.CDLL(LIBRARY,use_errno=True)
 for name,args,result in [('seccomp_init',[C.c_uint32],C.c_void_p),('seccomp_arch_resolve_name',[C.c_char_p],C.c_uint32),('seccomp_arch_exist',[C.c_void_p,C.c_uint32],C.c_int),('seccomp_arch_add',[C.c_void_p,C.c_uint32],C.c_int),('seccomp_syscall_resolve_name',[C.c_char_p],C.c_int),('seccomp_rule_add_array',[C.c_void_p,C.c_uint32,C.c_int,C.c_uint,C.POINTER(Comparison)],C.c_int),('seccomp_attr_set',[C.c_void_p,C.c_uint,C.c_uint32],C.c_int),('seccomp_load',[C.c_void_p],C.c_int),('seccomp_release',[C.c_void_p],None)]:
  f=getattr(lib,name);f.argtypes=args;f.restype=result
 need(reader(Path(LIBRARY),LIBRARY_BYTES)==raw,'libseccomp ELF stable after load');return lib

def install(selected,lib):
 ctx=lib.seccomp_init(selected['default']);need(ctx,'seccomp_init')
 try:
  for name in selected['arches']:
   arch=lib.seccomp_arch_resolve_name(name.encode());need(arch!=0,'known seccomp architecture')
   present=lib.seccomp_arch_exist(ctx,arch)
   if present!=0:need(present==-17 and lib.seccomp_arch_add(ctx,arch)==0,'exact extra architecture') # -EEXIST means absent in this API.
  for row in selected['rules']:
   number=lib.seccomp_syscall_resolve_name(row['name'].encode());need(number!=-1,'known syscall in pinned libseccomp')
   args=(Comparison*len(row['args']))(*(Comparison(*v)for v in row['args']))
   need(lib.seccomp_rule_add_array(ctx,row['action'],number,len(args),args)==0,'exact seccomp rule addition')
  need(lib.seccomp_attr_set(ctx,3,1)==0,'libseccomp NNP control')
  need(lib.seccomp_load(ctx)==0,'loaded exact finite seccomp program')
 finally:lib.seccomp_release(ctx)
 return dict(status='INSTALLED_SOURCE77_MOBY_PHASE_POLICY',phase=selected['phase'],source_rule_count=selected['source_rule_count'],policy_sha256=selected['policy_sha256'],architectures=selected['arches'])
