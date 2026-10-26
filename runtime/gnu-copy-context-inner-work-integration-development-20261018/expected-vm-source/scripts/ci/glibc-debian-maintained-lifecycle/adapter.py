#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite caa3 source emitter over exact GNU case bodies; no actors or acceptance."""
import argparse,ast,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
NEW='scripts/ci/glibc-debian-maintained-provider-'
OLD='scripts/ci/glibc-gnu-provider-'
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def source(root):
 value=json.loads((HERE/'source-pins.json').read_bytes());need(len(value['files'])==82,'finite exact original source closure')
 for name,row in value['files'].items():
  p=root/name;need(not any(x.is_symlink() for x in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and pin(p.read_bytes())==row,'exact source helper differs: '+name)
 return value

def adapt(raw,role,owner=False):
 text=raw.decode();tree=ast.parse(text);changes=[]
 # Exact identity assignments only; all caps/mounts/profile/checks/budgets stay intact.
 rules={'VERSION':('2.43.caa1-1','2.43.caa3-1'),'LABEL':('org.cachy-asahi.glibc-gnu-provider-'+role,'org.cachy-asahi.glibc-debian-maintained-provider-'+role)}
 if owner:rules={'LANE':(OLD+role,NEW+role),'LABEL':('org.cachy-asahi.glibc-provider-'+role+'-owner','org.cachy-asahi.glibc-debian-maintained-provider-'+role+'-owner'),'INNER_LABEL':('org.cachy-asahi.glibc-gnu-provider-'+role,'org.cachy-asahi.glibc-debian-maintained-provider-'+role)}
 for name,(before,after) in rules.items():
  rows=[n for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name];need(len(rows)==1 and ast.literal_eval(rows[0].value)==before,'one exact identity anchor: '+name)
  original=ast.get_source_segment(text,rows[0].value);start=sum(len(l) for l in text.splitlines(True)[:rows[0].value.lineno-1])+rows[0].value.col_offset;changes.append((start,start+len(original),repr(after)))
 if owner:
  binding=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='materialize')
  rows=[n for n in ast.walk(binding) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='dict' and any(k.arg=='version' for k in n.keywords)];need(len(rows)==1,'one exact private binding constructor')
  version=next(k.value for k in rows[0].keywords if k.arg=='version');need(ast.literal_eval(version)=='2.43.caa1-1','held private version anchor');start=sum(len(l) for l in text.splitlines(True)[:version.lineno-1])+version.col_offset;changes.append((start,start+len(ast.get_source_segment(text,version)),repr('2.43.caa3-1')))
  node=rows[0];start=sum(len(l) for l in text.splitlines(True)[:node.lineno-1])+node.col_offset+len('dict(');changes.append((start,start,"candidate=packet_value['candidate'],source_authority=packet_value['source_authority'],"))
 for start,end,value in sorted(changes,reverse=True):text=text[:start]+value+text[end:]
 ast.parse(text);return text.encode(),len(changes)

INNER='''
# Additional candidate gates; all original configuration and runtime checks run.
def require_candidate(value):
    return load('maintained_candidate_gate',HERE/'candidate_gate.py').identity(value)
def validate_candidate_inputs(root,value,candidate=None):
    return load('maintained_candidate_gate',HERE/'candidate_gate.py').validate(sys.modules[__name__],root,value,candidate)
_configuration_original=configuration
def configuration(inputs,pin):
    value,base,candidate,old=_configuration_original(inputs,pin)
    validate_candidate_inputs(inputs,value,candidate)
    return value,base,candidate,old
'''
OUTER='''
# Same original owner/packet/snapshot/lease/AppArmor/copy/cleanup implementation.
_selection_original=selection
def selection(workspace):
    value=_selection_original(workspace)
    common=load('maintained_selection_identity',workspace/LANE/'common.py')
    common.require_candidate(value.get('candidate'))
    return value
_packet_original=packet
def packet(workspace,root):
    directory,value=_packet_original(workspace,root)
    common=load('maintained_packet_candidate',workspace/LANE/'common.py')
    common.validate_candidate_inputs(directory,value)
    return directory,value
'''

def emit(root,output):
 root=root.absolute();output=output.absolute();held=source(root)
 need(not output.exists() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary source output')
 output.mkdir(mode=0o700);receipts={}
 gate=(HERE/'candidate_gate.py').read_bytes();identity={};exec(compile(ast.Module(body=[n for n in ast.parse(gate).body if isinstance(n,ast.Assign)],type_ignores=[]),'<constant-candidate>','exec'),identity)
 candidate=identity['EXPECTED']
 for role in ('lifecycle','interruption'):
  prior=root/(OLD+role);target=output/(NEW+role);target.mkdir(parents=True);rows={};edits={}
  runtime=('container.py','run.py','scrub.py','dependencies.json','normal-exec-change.json','smoke-normal.c','input-policy.json')+(('interruption.py','alpm-semantics.json') if role=='interruption' else ())
  for name in runtime:raw=(prior/name).read_bytes();(target/name).write_bytes(raw);rows[name]=pin(raw)
  raw,count=adapt((prior/'common.py').read_bytes(),role);raw+=INNER.encode();(target/'common.py').write_bytes(raw);rows['common.py']=pin(raw);edits['common.py']=count
  (target/'candidate_gate.py').write_bytes(gate);rows['candidate_gate.py']=pin(gate)
  (target/'source-manifest.json').write_bytes(encoded(dict(schema_version=1,status='SOURCE_ONLY_CAA3_NATIVE_INPUTS_UNBOUND',files=rows)))
  oldowner=root/(OLD+role+'-owner');owner=output/(NEW+role+'-owner');owner.mkdir(parents=True)
  for name in ('snapshot.py','capability_snapshot.py'):(owner/name).write_bytes((oldowner/name).read_bytes())
  raw,count=adapt((oldowner/'job.py').read_bytes(),role,owner=True)
  # Wrappers precede __main__, so imported and CLI entry points both use them.
  text=raw.decode();anchor="\nif __name__=='__main__':";need(text.count(anchor)==1,'one owner main anchor');(owner/'job.py').write_text(text.replace(anchor,OUTER+anchor));edits['owner/job.py']=count
  policy=dict(schema_version=1,status='UNBOUND_CAA3_ACTUAL_NATIVE_PAIR_AND_PACKET',packet=None,candidate=candidate,needed='Root actual caa3 pair/current normal-probe/private16K receipts and immutable packet; no old caa1/caa2 or source-only carrier acceptance')
  (owner/'policy.json').write_bytes(encoded(policy))
  manifest=json.loads((oldowner/'integration-manifest.json').read_bytes());files=dict(manifest['files'])
  for folder in (target,owner):
   for path in folder.iterdir():
    if path.is_file():files[path.relative_to(output).as_posix()]=pin(path.read_bytes())
  (owner/'integration-manifest.json').write_bytes(encoded(dict(schema_version=1,status='SOURCE_ONLY_CAA3_NATIVE_INPUTS_UNBOUND',files=files)))
  receipts[role]=dict(source=OLD+role,source_owner=OLD+role+'-owner',output=NEW+role,output_owner=NEW+role+'-owner',identity_edits=edits,cases='UNCHANGED_PRISTINE_AND_MODIFIED',native='NOT_RUN')
 for path in output.rglob('*.py'):ast.parse(path.read_bytes(),filename=str(path))
 result=dict(status='EMITTED_SOURCE_ONLY_CAA3_PAIR_PACKET_UNBOUND',candidate=candidate,original_source_files=len(held['files']),roles=receipts,files={p.relative_to(output).as_posix():pin(p.read_bytes()) for p in sorted(output.rglob('*')) if p.is_file()},hardware='NOT_RUN',release='NOT_ADMITTED')
 (output/'adaptation.json').write_bytes(encoded(result));return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(emit(a.source,a.output),sort_keys=True))
