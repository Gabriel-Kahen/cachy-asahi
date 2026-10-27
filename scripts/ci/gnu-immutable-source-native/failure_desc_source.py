# SPDX-License-Identifier: MIT
"""Mandatory complete775 inverse and diagnostic-only selected-runtime gate."""
import json,sys,tempfile
from pathlib import Path
LANE='scripts/ci/gnu-immutable-source-native'
MANIFEST=LANE+'/source-manifest.json'
PROFILE=LANE+'/failure-desc-export-profile.json'
WFS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-gnu-immutable-source.yml')
def footer(pin):return('\n# FAILURE_DESC_EXPORT_SOURCE\n_FAILURE_DESC_EXPORT_PROFILE_PIN='+repr(pin)+"\ndef source(root=ROOT):\n return load('_failure_desc_source',Path(root)/LANE/'failure_desc_source.py').check(root)\n").encode()
def reseal(values,D):
 m=D.obj(values[MANIFEST]);m['files']={n:D.pin(b)for n,b in values.items()if n not in(MANIFEST,*WFS)};values[MANIFEST]=D.encoded(m);workflow=values[LANE+'/workflow.yml.in'].decode().replace('@ENTRY_SHA@',D.pin(values[LANE+'/entry.py'])['sha256']).replace('@MANIFEST_SHA@',D.pin(values[MANIFEST])['sha256']).encode()
 for n in WFS:values[n]=workflow
def check(root):
 import deploy as D
 root=Path(root);raw=D.read(root/PROFILE,4*1024**2);q=D.obj(raw);D.need(D.pin(raw)==D._FAILURE_DESC_EXPORT_PROFILE_PIN and q['parent_source']=='8a6b9b7d5cb1def4ed95c2fd739d1354db292405','exact failure export parent/profile');D.need(q['scope']=='FAILED_RUN_FIXED_RAW_DESC_DATA_ONLY_NO_PREDICATE_CHANGE'and all(q[n]is None for n in('actual_source','actual_ref','actual_run','Root_acceptance')),'diagnostic-only NULL authority')
 current={}
 for p in root.rglob('*'):
  if p.relative_to(root).parts[0]=='.git':continue
  D.need(not p.is_symlink()and(p.is_file()or p.is_dir()),'closed ordinary failure export source')
  if p.is_file():current[p.relative_to(root).as_posix()]=D.read(p,16*1024**2)
 D.need(len(current)==778 and set(current)==set(q['before'])|set(q['payload'])|{PROFILE},'complete child778 namespace');D.need(all(D.pin(current[n])==w for n,w in q['payload'].items()),'whole source-owned export helper and guard')
 before={n:current[n]for n in q['before']};name=LANE+'/interruption_case.py';suffix=q['render_append'].encode();D.need(suffix and before[name].endswith(suffix),'exact append-only render inverse');before[name]=before[name][:-len(suffix)];name=LANE+'/deploy.py';tail=footer(D.pin(raw));D.need(before[name].endswith(tail),'exact source guard footer inverse');before[name]=before[name][:-len(tail)];reseal(before,D);D.need({n:D.pin(b)for n,b in before.items()}==q['before']and len(before)==775,'every original775 source byte recovered')
 sealed=dict(current);reseal(sealed,D);D.need(sealed==current,'complete current manifest and both workflow stamps')
 held={n[8:]:b for n,b in before.items()if n.startswith('runtime/')};D.need(len(held)==667 and all(current['runtime/'+n]==b for n,b in held.items()),'all667 raw runtime source bytes held')
 import extraction_case as X,interruption_case as I,fixed_case as F,descriptor_failure_export as E
 for case in I.CASES:
  D.need(X.render(held,case,F,'normal')==F.render(held,case),'normal/default runtime byteexact')
  for operation in('remove-interruption',X.OPERATION):
   selected,ledger=X.render(held,case,F,operation);D.need({n:D.pin(b)for n,b in selected.items()}==q['runtime_profiles'][operation][case],'complete selected diagnostic runtime profile');D.need(len(selected)==667,'unchanged runtime member count');back=I.inverse(selected,ledger);expected=F.render(held,case)[0]if operation=='remove-interruption'else I.render(held,case,F,'remove-interruption')[0];back['runtime-source.json']=expected['runtime-source.json'];D.need(back==expected,'whole selected operation inverse, all predicates held')
   for name in E.RUNTIME_PATHS:D.need(E.inverse(selected[name],E.derive(before['runtime/'+name],case)[1])==before['runtime/'+name],'whole original export body inverse')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='failure-desc-whole775-')as td:
   old=Path(td)/'source';old.mkdir()
   for n,b in before.items():p=old/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
   for p in old.rglob('*.py'):sys.modules.pop(p.stem,None)
   sys.path.insert(0,str(old/LANE));entry=D.load('_failure_desc_original775_entry',old/LANE/'entry.py');parent=entry.source(old);D.need(parent['files']==775 and parent['actual_run']is None,'complete original775 SOURCE entry executes')
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 return dict(parent,files=778,whole_failure_export_parent775=parent,raw_descriptor_failure_retention='IMPLEMENTED_SOURCE_ONLY',database_postconditions='UNCHANGED',native='NOT_RUN',Root_acceptance=None)
