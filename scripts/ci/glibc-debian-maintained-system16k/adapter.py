#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source-only adaptation; shared controller/kernel/normal proofs are reused."""
import argparse,ast,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/glibc-gnu-provider-system16k';NEW='scripts/ci/glibc-debian-maintained-system16k';SHARED='scripts/ci/glibc-debian-maintained-lifecycle/candidate_gate.py'
def need(ok,message):
 if not ok:raise ValueError(message)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
RULES={
'common.py':{'GLIBC_SYSTEM16K_SOURCE_ROOT':('DEBIAN_MAINTAINED_SYSTEM16K_SOURCE_ROOT',2),'system16k_':('debian_maintained_system16k_',1),'ROOT_ACCEPTED_PROVIDER_LIFECYCLE_INPUTS':('ROOT_ACCEPTED_PROVIDER_STAGED16K_INPUTS',1),'PASS_CONVENTIONAL_GNU_SYSTEM_PATHS_GENERIC16K_RUNTIME':('PASS_DEBIAN_MAINTAINED_SYSTEM_PATHS_GENERIC16K_RUNTIME',1),'2.43.caa1-1':('2.43.caa3-1',1)},
'run.py':{b'SYSTEM16K ':(b'DEBIANMAINTAINEDSYSTEM16K ',1),'--env=CACHY_GLIBC_SYSTEM16K_CAPTURE=1':('--env=CACHY_DEBIAN_MAINTAINED_SYSTEM16K_CAPTURE=1',1),'SYSTEM16K':('DEBIANMAINTAINEDSYSTEM16K',1),'glibcsystem16k=1':('glibcdebianmaintainedsystem16k=1',1),'org.cachy-asahi.glibc-system16k.job':('org.cachy-asahi.glibc-debian-maintained-system16k.job',1),'glibcsystem16k-capture-':('glibcdebianmaintainedsystem16k-capture-',1),'PASS_GNU_SYSTEM_PATHS_GENERIC16K_AND_ORDERED_CLEANUP':('PASS_DEBIAN_MAINTAINED_SYSTEM_PATHS_GENERIC16K_AND_ORDERED_CLEANUP',2),'org.cachy-asahi.glibc-system16k.job=':('org.cachy-asahi.glibc-debian-maintained-system16k.job=',1),'accepted_system16k_controller':('accepted_debian_maintained_system16k_controller',1),'SYSTEM16K REPORT ':('DEBIANMAINTAINEDSYSTEM16K REPORT ',1),'SYSTEM16K PASS ':('DEBIANMAINTAINEDSYSTEM16K PASS ',1),'SYSTEM16K BOOT ':('DEBIANMAINTAINEDSYSTEM16K BOOT ',1)},
'capture.py':{'CACHY_GLIBC_SYSTEM16K_CAPTURE':('CACHY_DEBIAN_MAINTAINED_SYSTEM16K_CAPTURE',1)},
'guest.py':{'system16k_supervisor':('debian_maintained_system16k_supervisor',1),'PASS_CONVENTIONAL_GNU_SYSTEM_PATHS_GENERIC16K_RUNTIME':('PASS_DEBIAN_MAINTAINED_SYSTEM_PATHS_GENERIC16K_RUNTIME',1),'glibcsystem16k=1':('glibcdebianmaintainedsystem16k=1',1),'SYSTEM16K REPORT ':('DEBIANMAINTAINEDSYSTEM16K REPORT ',1),'SYSTEM16K-DIAGNOSTIC ':('DEBIANMAINTAINEDSYSTEM16K-DIAGNOSTIC ',1),'SYSTEM16K ERROR ':('DEBIANMAINTAINEDSYSTEM16K ERROR ',1)},
'enter-system.py':{'glibcsystem16k=1':('glibcdebianmaintainedsystem16k=1',1)},
'gate.py':{'SYSTEM16K_BOUND_PROVIDER_PROBES_CACHE_GATE=PASS execution=NOT_RUN':('DEBIAN_MAINTAINED_SYSTEM16K_BOUND_GATE=PASS execution=NOT_RUN',1),'glibc-system16k:':('glibc-debian-maintained-system16k:',1)}}
COMMON='''
# First16K phase wraps the unchanged original package/normal/runtime proofs.
PAIR_IDENTITY=None
def phase():return load(SOURCE,'scripts/ci/glibc-debian-maintained-system16k/phase_gate.py')
_bindings_original=bindings
def bindings(value=None):
    result=_bindings_original(value);phase().shared(sys.modules[__name__]).identity(result.get('candidate'))
    need(result['scope']=='DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION','distinct staged-only policy');return result
_pair_original=pair
def pair(root):
    global PAIR_IDENTITY
    value,packages=_pair_original(root);PAIR_IDENTITY=phase().validate(sys.modules[__name__],root,value);return value,packages
_guest_receipt_original=guest_receipt
def guest_receipt(value):
    _guest_receipt_original(value);phase().provenance(sys.modules[__name__],value);need(len(value['runtime_files'])==19,'all19actual normal runtime mapping identities required')
'''
RUN='''
_guest_report_original=guest_report
def guest_report(uart,code,nonce,release,capture):
    value=_guest_report_original(uart,code,nonce,release,capture)
    c.need(value['candidate']==capture['candidate']==c.INDEX['candidate'] and value['native_pair']==capture['native_pair']==c.PAIR_IDENTITY and value['source_authority']==capture['source_authority']==c.INDEX['source_authority'],'new actual packet/capture/guest provenance join')
    return value
'''
def source(root):
 value=json.loads((HERE/'source-pins.json').read_bytes())
 for n,row in value['files'].items():
  p=root/n;need(not any(x.is_symlink() for x in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and p.stat().st_size<=2*1024**2 and pin(p.read_bytes())==row,'exact current source helper differs: '+n)
 return value

def adapt(raw,name):
 text=raw.decode();tree=ast.parse(text);lines=text.splitlines(True);changes=[];counts={k:0 for k in RULES[name]}
 def offset(node):return sum(len(line) for line in lines[:node.lineno-1])+node.col_offset
 for node in ast.walk(tree):
  if isinstance(node,ast.Constant) and type(node.value) in (str,bytes) and node.value in RULES[name]:
   after,_=RULES[name][node.value];counts[node.value]+=1;start=offset(node);changes.append((start,start+len(ast.get_source_segment(text,node)),repr(after)))
 need(all(counts[k]==row[1] for k,row in RULES[name].items()),'exact finite identity/version/phase anchors: '+name)
 if name in ('capture.py','guest.py'):
  target='capture' if name=='capture.py' else 'run';function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==target);rows=[n for n in ast.walk(function) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='report' for t in n.targets)];need(len(rows)==1 and isinstance(rows[0].value,ast.Call) and isinstance(rows[0].value.func,ast.Name) and rows[0].value.func.id=='dict','one report metadata constructor')
  extra="candidate=c.INDEX['candidate'],native_pair=c.PAIR_IDENTITY,source_authority=c.INDEX['source_authority']," if name=='capture.py' else "candidate=manifest['candidate'],native_pair=manifest['native_pair'],source_authority=manifest['source_authority'],"
  start=offset(rows[0].value)+5;changes.append((start,start,extra))
 for a,b,value in sorted(changes,reverse=True):text=text[:a]+value+text[b:]
 wrapper=COMMON if name=='common.py' else RUN if name=='run.py' else ''
 if wrapper:
  anchor="\nif __name__=='__main__':"
  if anchor in text:need(text.count(anchor)==1,'single CLI main');text=text.replace(anchor,wrapper+anchor)
  else:text+=wrapper
 ast.parse(text);return text.encode(),len(changes)

def emit(root,output):
 root=root.absolute();output=output.absolute();held=source(root);need(not output.exists() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary source output');target=output/NEW;target.mkdir(parents=True,mode=0o700);edits={}
 for name in RULES:
  raw,count=adapt((root/OLD/name).read_bytes(),name);(target/name).write_bytes(raw);edits[name]=count
 (target/'phase_gate.py').write_bytes((HERE/'phase_gate.py').read_bytes())
 tree=ast.parse((root/SHARED).read_bytes());node=next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='EXPECTED' for t in n.targets));need(isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='dict' and not node.args and all(k.arg for k in node.keywords),'finite keyword-only candidate descriptor');candidate={k.arg:ast.literal_eval(k.value) for k in node.keywords}
 need(candidate['pkgbuild_sha256']=='9d6d5e688c95febe85321abc69fbfe1b7781a02e318771ae43851d8c29f68bb8','current Root source-key-alias recipe required, not obsolete5b')
 policy=dict(schema_version=1,status='UNBOUND_CURRENT_NATIVE_PAIR_NORMAL_PROBES_HELD_AUTHORITY',binding=None,candidate=candidate,scope='DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION',required_before_binding=['Root accepted new maintained caa3 native pair and measured payload traits','Matching new original normal compiler receipts and precompiled probes','Exact held rollback archive and independent maintained source authority','Root-frozen staged-phase immutable packet; NO prior16K receipt'])
 (target/'input-policy.json').write_bytes(encoded(policy));deps=dict(held['files']);(target/'dependencies.json').write_bytes(encoded(dict(schema_version=1,files=deps)))
 own={p.relative_to(output).as_posix():pin(p.read_bytes()) for p in target.iterdir() if p.is_file()};manifest=dict(schema_version=1,scope=policy['scope'],provider_inputs=policy['status'],files=deps|own);(target/'source-manifest.json').write_bytes(encoded(manifest))
 result=dict(status='SOURCE_ONLY_MAINTAINED_FIRST_SYSTEM16K_INPUTS_UNBOUND',candidate=candidate,shared_source_files=len(deps),literal_metadata_edits=edits,files={p.relative_to(output).as_posix():pin(p.read_bytes()) for p in target.iterdir() if p.is_file()},scope=policy['scope'],native='NOT_RUN',generic16k='NOT_RUN',ALPM_installation='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
 (output/'adaptation.json').write_bytes(encoded(result));return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(emit(a.source,a.output),sort_keys=True))
