# SPDX-License-Identifier: MIT
"""Closed current source AND entire exact749 parent; never an actual result."""
import sys,tempfile
from pathlib import Path
LANE='scripts/ci/gnu-immutable-source-native'
def check(root):
 import deploy as D
 root=Path(root);fact=D._IMMUTABLE_NODE_MAP_PREVIOUS_SOURCE(root)
 raw=D.read(root/LANE/'interruption-profile.json',4*1024**2);q=D.obj(raw)
 D.need(D.pin(raw)==D._REMOVE_INTERRUPTION_PROFILE_PIN,'exact interruption profile')
 D.need(q['scope']=='SELECTED_REMOVE_INTERRUPTION_RECOVERY_GENERIC16K'and all(q[n]is None for n in('actual_source','actual_ref','actual_run','Root_acceptance')),'source-only interruption authority NULL')
 D.need(q['parent']==dict(source='de1aab259df6bda8ad36f959392e3fc4eb35b622',ref='codex/gnu-fixed-case-cleanup600-v1',files=749),'exact public749 parent')
 before=q['before'];current={}
 for p in root.rglob('*'):
  if p.relative_to(root).parts[0]=='.git':continue
  D.need(not p.is_symlink()and(p.is_file()or p.is_dir()),'complete ordinary interruption source')
  if p.is_file():current[p.relative_to(root).as_posix()]=D.read(p,16*1024**2)
 D.need(set(current)==set(before)|set(q['added'])|{LANE+'/interruption-profile.json'},'whole current source namespace')
 D.need(all(D.pin(current[n])==w for n,w in q['added'].items()),'whole added helper/test/normal-record DATA')
 bodies={n:current[n]for n in before}
 for n,steps in q['source_edits'].items():
  text=bodies[n].decode()
  for row in reversed(steps):
   D.need(text.count(row['after'])==row['count'],'one counted source operation inverse');text=text.replace(row['after'],row['before'],row['count'])
  bodies[n]=text.encode()
 footer='\n# SELECTED_REMOVE_INTERRUPTION_SOURCE\n_REMOVE_INTERRUPTION_PROFILE_PIN='+repr(D.pin(raw))+"\ndef source(root=ROOT):\n return load('_gnu_remove_source',Path(root)/LANE/'interruption_source.py').check(root)\n"
 n=LANE+'/deploy.py';D.need(bodies[n].endswith(footer.encode()),'one exact current guard binding');bodies[n]=bodies[n][:-len(footer)]
 # Reconstruct only deterministic seals; no old source tree/code blob stored.
 n=LANE+'/source-manifest.json';m=D.obj(bodies[n]);m['files']={name:D.pin(b)for name,b in bodies.items()if name not in(n,'.github/workflows/native-arm-build.yml','.github/workflows/native-arm-gnu-immutable-source.yml')};bodies[n]=D.encoded(m)
 workflow=bodies[LANE+'/workflow.yml.in'].decode().replace('@ENTRY_SHA@',D.pin(bodies[LANE+'/entry.py'])['sha256']).replace('@MANIFEST_SHA@',D.pin(bodies[n])['sha256']).encode()
 for n in('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-gnu-immutable-source.yml'):bodies[n]=workflow
 D.need({n:D.pin(b)for n,b in bodies.items()}==before,'whole exact749 byte inverse')
 H=D.load('_gnu_selected_remove_helper',root/LANE/'interruption_case.py');F=D.load('fixed_case',root/LANE/'fixed_case.py');runtime={n[8:]:b for n,b in bodies.items()if n.startswith('runtime/')}
 for case in F.CASES:
  D.need(H.render(runtime,case,F,'normal')==F.render(runtime,case),'ALL original normal/default rendering exact')
 for case in H.CASES:
  after,ledger=H.render(runtime,case,F);D.need({n:D.pin(b)for n,b in after.items()}==q['runtime_profiles'][case],'whole selected10stage/five-runtime667 product')
  back=H.inverse(after,ledger);back['runtime-source.json']=F.render(runtime,case)[0]['runtime-source.json'];D.need(back==F.render(runtime,case)[0],'complete normal selected inverse')
 record={n:D.obj(current[LANE+'/normal-record/'+n])for n in('decision.json','record-scope.json')}
 D.need(record['decision.json']['status']=='ROOT_ACCEPTED_PAIRED_GNU_PROVIDER_NORMAL_GENERIC16K_LIFECYCLE'and record['record-scope.json']['status']=='RETAIN_EXISTING_ROOT_PAIRED_NORMAL16K_DECISION','prior acceptance restricted to normal; no interruption transfer')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='gnu-remove-whole749-')as td:
   old=Path(td)/'source';old.mkdir()
   for n,b in bodies.items():p=old/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
   for p in old.rglob('*.py'):sys.modules.pop(p.stem,None)
   sys.path.insert(0,str(old/LANE));entry=D.load('_gnu_remove_whole749_entry',old/LANE/'entry.py');parent=entry.source(old)
   D.need(parent['files']==749 and parent['whole_lifetime_parent747']['files']==747,'whole749/747 and all older runtime/security source predicates')
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 return dict(fact,whole_remove_parent749=parent,operation='EXPLICIT_REMOVE_INTERRUPTION_NORMAL_DEFAULT_HELD',required_acceptance='BOTH_SEPARATE_SAME_SOURCE_INTERRUPTION_CASES',interruption_native='NOT_RUN',fit='NOT_ESTABLISHED',hardware='NOT_RUN')
