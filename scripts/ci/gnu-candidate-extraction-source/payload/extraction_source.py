# SPDX-License-Identifier: MIT
"""Complete current source plus exact cc04 parent inverse; source only."""
import json,sys,tempfile
from pathlib import Path
LANE='scripts/ci/gnu-immutable-source-native';MANIFEST=LANE+'/source-manifest.json';WFS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-gnu-immutable-source.yml')

def check(root):
 import deploy as D
 root=Path(root);raw=D.read(root/LANE/'candidate-extraction-profile.json',4*1024**2);q=D.obj(raw);D.need(D.pin(raw)==D._CANDIDATE_EXTRACTION_PROFILE_PIN and q['parent_source']=='cc04fe3a57bac24a516004dfb670a172e76ac517','exact candidate source profile/parent')
 D.need(all(q[n]is None for n in('actual_source','actual_ref','actual_run','Root_acceptance')),'source-only extraction selectors NULL');current={}
 for p in root.rglob('*'):
  if p.relative_to(root).parts[0]=='.git':continue
  D.need(not p.is_symlink()and(p.is_file()or p.is_dir()),'whole ordinary extraction source')
  if p.is_file():current[p.relative_to(root).as_posix()]=D.read(p,16*1024**2)
 D.need(set(current)==set(q['before'])|set(q['added'])|{LANE+'/candidate-extraction-profile.json'},'exact source closure: complete current extraction namespace')
 for n,w in q['added'].items():D.need(D.pin(current[n])==w,'whole added extraction code/test')
 before={n:current[n]for n in q['before']}
 for n,steps in q['source_edits'].items():
  for row in reversed(steps):
   a,b=row['before'].encode(),row['after'].encode();D.need(before[n].count(b)==row['count'],'counted complete cc04 inverse');before[n]=before[n].replace(b,a,row['count'])
 footer='\n# CANDIDATE_EXTRACTION_SOURCE\n_CANDIDATE_EXTRACTION_PROFILE_PIN='+repr(D.pin(raw))+"\ndef source(root=ROOT):\n return load('_candidate_extraction_source',Path(root)/LANE/'extraction_source.py').check(root)\n"
 n=LANE+'/deploy.py';D.need(before[n].endswith(footer.encode()),'one exact extraction guard footer');before[n]=before[n][:-len(footer.encode())]
 def seal(values):
  m=D.obj(values[MANIFEST]);m['files']={n:D.pin(b)for n,b in values.items()if n not in(MANIFEST,*WFS)};values[MANIFEST]=D.encoded(m);workflow=values[LANE+'/workflow.yml.in'].decode().replace('@ENTRY_SHA@',D.pin(values[LANE+'/entry.py'])['sha256']).replace('@MANIFEST_SHA@',D.pin(values[MANIFEST])['sha256']).encode()
  for n in WFS:values[n]=workflow
 seal(before);D.need({n:D.pin(b)for n,b in before.items()}==q['before']and len(before)==766,'EVERY original cc04 byte recovered')
 sealed=dict(current);seal(sealed);D.need(sealed==current,'complete current manifest/workflow seals')
 import extraction_case as X,interruption_case as I,fixed_case as F
 base={n[8:]:b for n,b in before.items()if n.startswith('runtime/')}
 for case in F.CASES:D.need(X.render(base,case,F,'normal')==I.render(base,case,F,'normal'),'normal/default runtime unchanged')
 for case in I.CASES:
  D.need(X.render(base,case,F,'remove-interruption')==I.render(base,case,F,'remove-interruption'),'REMOVE operation unchanged');after,ledger=X.render(base,case,F,X.OPERATION);D.need({n:D.pin(b)for n,b in after.items()}==q['runtime_profiles'][case],'whole source-owned extraction runtime');restored=I.inverse(after,ledger);restored['runtime-source.json']=I.render(base,case,F,'remove-interruption')[0]['runtime-source.json'];D.need(restored==I.render(base,case,F,'remove-interruption')[0],'whole REMOVE runtime inverse')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='candidate-whole-cc04-')as td:
   previous=Path(td)/'source';previous.mkdir()
   for n,b in before.items():p=previous/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
   for p in previous.rglob('*.py'):sys.modules.pop(p.stem,None)
   sys.path.insert(0,str(previous/LANE));entry=D.load('_candidate_complete_cc04_entry',previous/LANE/'entry.py');parent=entry.source(previous);D.need(parent['files']==766 and parent['actual_run']is None,'full original source-only cc04 entry')
 finally:
  sys.path[:]=paths
  for name in set(sys.modules)-set(saved):sys.modules.pop(name,None)
  sys.modules.update(saved)
 return dict(parent,files=len(current),whole_candidate_parent766=parent,operation='EXPLICIT_CANDIDATE_EXTRACTION_NORMAL_AND_REMOVE_HELD',candidate_extraction_native='NOT_RUN',automatic_rollback='NOT_CLAIMED',automatic_configuration_preservation='NOT_CLAIMED',Root_acceptance=None)
