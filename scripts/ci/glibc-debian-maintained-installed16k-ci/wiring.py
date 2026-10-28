#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite adapter of existing interrupted16K CI assembly; no new actor machinery."""
import argparse,ast,hashlib,json,sys,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
SHARED='scripts/ci/glibc-gnu-provider-installed16k-interruption/ci/wiring.py'
LANE='scripts/ci/glibc-debian-maintained-installed16k'
NEXT='scripts/ci/glibc-debian-maintained-native-lifecycle-next'
RULES=(
 ("LANE='scripts/ci/glibc-gnu-provider-installed16k-interruption'","LANE='"+LANE+"'",1),
 ('native_interruption','native_lifecycle',2),('normal_installed16k','system16k',2),
 ('len(files)==115','len(files)==146',1),('finite original106 plus adapter5 plus CI4 source closure','finite maintained installed/native/CI146 source closure',1),
 ('len(actual)==124','len(actual)==153',1),('closed106+15+adaptation+2 source bundle','closed119+31+adaptation+2 source bundle',1),
 ('source_files=106,derived_files=15,bundle_files=124','source_files=119,derived_files=31,bundle_files=153',1),
 ('interrupted16k_generator','maintained_installed16k_generator',1),('interrupted16k_contract','maintained_installed16k_contract',1),
 ('import argparse,hashlib,importlib.util,json,os,re,stat,subprocess','import argparse,hashlib,importlib.util,json,os,re,stat,subprocess,sys',1),
 ('mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)','mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mod;spec.loader.exec_module(mod)',1))
def need(ok,why):
 if not ok:raise ValueError(why)
def derive(root):
 p=root/SHARED;need(not any(x.is_symlink() for x in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and p.stat().st_size<=2*1024**2,'ordinary shared CI source');raw=p.read_bytes();rows=json.loads((HERE/'integration-manifest.json').read_bytes())['files'];need(rows[SHARED]==dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),'exact shared CI source pin');text=raw.decode();counts=[]
 for before,after,n in RULES:need(text.count(before)==n,'counted shared CI anchor: '+before);text=text.replace(before,after);counts.append(n)
 ast.parse(text);return text,dict(source=SHARED,source_sha256=hashlib.sha256(raw).hexdigest(),counted_edits=sum(counts),unchanged_shared_validation='ALL_OTHER_CODE_BYTE_IDENTICAL')

def implementation(root):
 text,receipt=derive(root);W=types.ModuleType('_maintained_installed_ci');W.__file__=str(HERE/'wiring.py');sys.modules[W.__name__]=W;exec(compile(text,SHARED+'#maintained-installed-adapter','exec'),W.__dict__);original=W.preflight
 def native_packet():
  policy=W.decode(W.read(HERE/'policy.json',65536));P=W.load('next_native_source',root/NEXT/'prepare.py');S,pure,_,_=P.helpers(root);G=pure(root,S.GATE);expected=P.binding(dict(schema_version=1,status='ROOT_BOUND_IMMUTABLE_PROVIDER_PACKET',candidate=policy.get('candidate'),packet=policy.get('native_packet')),G);actual=P.binding(W.decode(W.read(root/NEXT/'policy.json',65536)),G);W.need(expected==actual,'exact Root published native packet must join current native owner policy');return P
 def preflight(source,inputs,env):
  value=original(source,inputs,env);native_packet();return value
 W.preflight=preflight;W.native_packet=native_packet;W.derivation=receipt;return W

def native_source(W,root,vm_source,output,inputs,env):
 W.preflight(root,inputs,env);C=W.load('current_installed_contract',vm_source/LANE/'contract.py');C.check_source(vm_source);C.gate(vm_source/LANE/'prerequisites');policy=W.decode(W.read(HERE/'policy.json',65536));effective=W.decode(W.read(vm_source/LANE/'input-policy.json'))
 for kind in W.KINDS:
  row=policy['binding'][kind];W.need(effective['binding'][kind]==dict(path=kind+'.json',**{k:row[k] for k in ('bytes','sha256')}),'VM actual decision bytes join current Root policy')
 P=W.native_packet();return P.emit(types.SimpleNamespace(repo=root,output=output))

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('preflight','assemble','native-source','export'));p.add_argument('--workspace',type=Path,required=True);p.add_argument('--output',type=Path);p.add_argument('--public',type=Path);p.add_argument('--native-decision-root',type=Path);p.add_argument('--normal-decision-root',type=Path);p.add_argument('--vm-source',type=Path);a=p.parse_args();W=implementation(a.workspace)
 import os
 if a.action=='export':W.public_check(a.public)
 else:
  inputs={k:W.decode(os.environ.get(k.upper()+'_DECISION','null')) for k in W.KINDS}
  if a.action=='preflight':
   value=W.preflight(a.workspace,inputs,os.environ)
   with open(os.environ['GITHUB_OUTPUT'],'a') as stream:
    for k,row in value.items():stream.write(k+'_ref='+row['ref']+'\n')
  elif a.action=='assemble':print(json.dumps(W.assemble(a.workspace,a.output,dict(native_lifecycle=a.native_decision_root,system16k=a.normal_decision_root),inputs,os.environ,a.public),sort_keys=True))
  else:print(json.dumps(native_source(W,a.workspace,a.vm_source,a.output,inputs,os.environ),sort_keys=True))
