# SPDX-License-Identifier: MIT
"""Exact parent771 inverse and source-owned raw descriptor evidence gate."""
import json,sys,tempfile
from pathlib import Path
LANE='scripts/ci/gnu-immutable-source-native';MANIFEST=LANE+'/source-manifest.json';WFS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-gnu-immutable-source.yml')
def check(root):
 import deploy as D
 root=Path(root);raw=D.read(root/LANE/'recovery-database-profile.json',4*1024**2);q=D.obj(raw);D.need(D.pin(raw)==D._RECOVERY_DATABASE_PROFILE_PIN and q['parent_source']=='4b2f8502655d2f4b65a20691247d1a54052089f3','exact recovery evidence source profile/parent');D.need(all(q[n]is None for n in('actual_source','actual_ref','actual_run','Root_acceptance')),'new raw evidence source-only selectors NULL');current={}
 for p in root.rglob('*'):
  if p.relative_to(root).parts[0]=='.git':continue
  D.need(not p.is_symlink()and(p.is_file()or p.is_dir()),'whole ordinary recovery evidence source')
  if p.is_file():current[p.relative_to(root).as_posix()]=D.read(p,16*1024**2)
 D.need(set(current)==set(q['before'])|set(q['added'])|{LANE+'/recovery-database-profile.json'},'exact source closure with every new helper/guard/test/profile')
 for n,w in q['added'].items():D.need(D.pin(current[n])==w,'whole new evidence helper/guard/test')
 before={n:current[n]for n in q['before']}
 for n,steps in q['source_edits'].items():
  for row in reversed(steps):
   a,b=row['before'].encode(),row['after'].encode()
   if row.get('append'):D.need(before[n].endswith(b),'whole appended source loader inverse');before[n]=before[n][:-len(b)]
   else:D.need(before[n].count(b)==row['count'],'counted whole4b2 source inverse');before[n]=before[n].replace(b,a,row['count'])
 footer='\n# RECOVERY_DATABASE_SOURCE\n_RECOVERY_DATABASE_PROFILE_PIN='+repr(D.pin(raw))+"\ndef source(root=ROOT):\n return load('_recovery_database_source',Path(root)/LANE/'recovery_database_source.py').check(root)\n";n=LANE+'/deploy.py';D.need(before[n].endswith(footer.encode()),'one exact recovery database footer');before[n]=before[n][:-len(footer.encode())]
 def seal(values):
  m=D.obj(values[MANIFEST]);m['files']={n:D.pin(b)for n,b in values.items()if n not in(MANIFEST,*WFS)};values[MANIFEST]=D.encoded(m);workflow=values[LANE+'/workflow.yml.in'].decode().replace('@ENTRY_SHA@',D.pin(values[LANE+'/entry.py'])['sha256']).replace('@MANIFEST_SHA@',D.pin(values[MANIFEST])['sha256']).encode()
  for n in WFS:values[n]=workflow
 seal(before);D.need({n:D.pin(b)for n,b in before.items()}==q['before']and len(before)==771,'EVERY original4b2 source byte recovered');sealed=dict(current);seal(sealed);D.need(sealed==current,'whole current manifest and both workflow seals')
 import extraction_case as X,interruption_case as I,fixed_case as F
 base={n[8:]:b for n,b in before.items()if n.startswith('runtime/')};D.need(len(base)==667 and all(current['runtime/'+n]==b for n,b in base.items()),'all original667 raw runtime bytes held')
 for case in F.CASES:D.need(X.render(base,case,F,'normal')==F.render(base,case),'normal/default runtime byteexact')
 for op in('remove-interruption',X.OPERATION):
  for case in I.CASES:
   after,ledger=X.render(base,case,F,op);D.need({n:D.pin(b)for n,b in after.items()}==q['runtime_profiles'][op][case],'whole raw evidence source-owned interrupted runtime');profile=I.profile(case,F.profile(case))if op=='remove-interruption'else X.profile(case,F);D.need(profile['recovery_database_evidence']=='REQUIRED_BOUNDED_RAW_DESC_V1','new evidence flag required')
   restored=I.inverse(after,ledger);expected=F.render(base,case)[0]if op=='remove-interruption'else I.render(base,case,F,'remove-interruption')[0];restored['runtime-source.json']=expected['runtime-source.json'];D.need(restored==expected,'whole selected normal/REMOVE runtime inverse')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='raw-db-whole4b2-')as td:
   previous=Path(td)/'source';previous.mkdir()
   for n,b in before.items():p=previous/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
   for p in previous.rglob('*.py'):sys.modules.pop(p.stem,None)
   sys.path.insert(0,str(previous/LANE));entry=D.load('_recovery_database_complete4b2_entry',previous/LANE/'entry.py');parent=entry.source(previous);D.need(parent['files']==771 and parent['actual_run']is None,'complete original4b2 source entry actually executes')
 finally:
  sys.path[:]=paths
  for name in set(sys.modules)-set(saved):sys.modules.pop(name,None)
  sys.modules.update(saved)
 return dict(parent,files=len(current),whole_recovery_database_parent771=parent,recovery_database_evidence='REQUIRED_BOUNDED_RAW_DESC_V1',recovery_database_native='NOT_RUN',Root_acceptance=None)
