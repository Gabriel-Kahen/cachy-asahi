"""Portable full-source emitter and original emitted controls; never native evidence."""
import ast,importlib.util,json,os,re,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;LANE='scripts/ci/current604-public-pair-updater16k'
sys.path.insert(0,str(HERE));import copywalk_text as X,optional_io as O
F=X.F;PARENT=Path(os.environ['UPDATER_TEXT_PARENT']).absolute();EXPECTED=Path(os.environ['UPDATER_TEXT_EXPECTED']).absolute()
class Controls(unittest.TestCase):
 def test_exact_full489_cli_and_six483_closure(self):
  p=X.profile();self.assertEqual((p['parent_source'],p['expected_source']),('2ef64d460aedeed8f40909d32f4a074e8c3c546b','b21a5864d5a4610b9181a1c270ac8821d8448a17'));self.assertEqual(F.pins(F.tree(PARENT,checkout=True)),p['before']);self.assertEqual(F.pins(F.tree(EXPECTED,checkout=True)),p['after']);self.assertEqual(len(p['changed']),6)
  for n in p['before']:
   if n not in p['changed']:self.assertEqual((PARENT/n).read_bytes(),(EXPECTED/n).read_bytes())
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';r=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'copywalk_text.py'),'--parent',str(PARENT),'--output',str(out)],capture_output=True,timeout=30,check=True);v=json.loads(r.stdout);self.assertEqual(r.stderr,b'');self.assertEqual((v['status'],v['files'],v['changed'],v['held'],v['acceptance'],v['native_fit']),('SOURCE_ONLY',489,6,483,False,'UNQUALIFIED'));self.assertEqual(F.tree(out),F.tree(EXPECTED,checkout=True))
   for n in('adapter.py','test_lane.py'):ast.parse((out/LANE/n).read_bytes())
  r=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'copywalk_text.py'),'--help'],capture_output=True,timeout=10,check=True);self.assertIn(b'--parent',r.stdout);self.assertEqual(r.stderr,b'')
 def test_checkout_metadata_only_is_excluded(self):
  with tempfile.TemporaryDirectory()as td:
   parent=Path(td)/'parent';shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));(parent/'.git').mkdir();(parent/'.git/config').write_text('SOURCE_CONTROL_METADATA_NOT_EMITTED\n');out=Path(td)/'out';X.emit(parent,out);self.assertEqual(F.pins(F.tree(out)),X.profile()['after']);self.assertFalse((out/'.git').exists())
 def test_parent_drift_missing_extra_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);parent=root/'parent';shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));leaf=parent/'LICENSE';original=leaf.read_bytes()
   for mode in('drift','missing','extra'):
    if mode=='drift':leaf.write_bytes(original+b'x')
    elif mode=='missing':leaf.unlink()
    else:leaf.write_bytes(original);(parent/'foreign').write_bytes(b'x')
    out=root/mode
    with self.assertRaisesRegex(ValueError,'whole pinned copywalk'):X.emit(parent,out)
    self.assertFalse(out.exists())
    if mode in('drift','missing'):leaf.write_bytes(original)
 def test_payload_membership_and_profile_drift_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);payload=factory/'copywalk-text-payload';leaf=next(p for p in payload.rglob('*')if p.is_file());original=leaf.read_bytes()
   with patch.object(X,'HERE',factory):
    for mode in('drift','missing','extra'):
     if mode=='drift':leaf.write_bytes(original+b'x')
     elif mode=='missing':leaf.unlink()
     else:leaf.write_bytes(original);(payload/'foreign').write_bytes(b'x')
     out=root/mode
     with self.assertRaisesRegex(ValueError,'whole six copywalk'):X.emit(PARENT,out)
     self.assertFalse(out.exists())
     if mode in('drift','missing'):leaf.write_bytes(original)
    (payload/'foreign').unlink();(factory/'copywalk-text-profile.json').write_bytes(b'{}')
    with self.assertRaisesRegex(ValueError,'whole copywalk text profile'):X.emit(PARENT,root/'profile')
    self.assertFalse((root/'profile').exists())
 def test_source_output_and_file_alias_refusals(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);link=root/'source-link';link.symlink_to(PARENT,target_is_directory=True)
   with self.assertRaisesRegex(ValueError,'ordinary source/output'):X.emit(link,root/'out')
   with self.assertRaisesRegex(ValueError,'fresh output'):X.emit(PARENT,PARENT)
   with self.assertRaisesRegex(ValueError,'disjoint output'):X.emit(PARENT,PARENT/'never-created')
   with self.assertRaisesRegex(ValueError,'disjoint output'):X.emit(PARENT,HERE/'never-created')
   holder=root/'owned-alias-data';holder.write_bytes((PARENT/'LICENSE').read_bytes())
   for mode in('symlink','hardlink'):
    parent=root/mode;shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));leaf=parent/'LICENSE';leaf.unlink()
    if mode=='symlink':leaf.symlink_to(holder)
    else:os.link(holder,leaf)
    try:
     with self.assertRaisesRegex(ValueError,'ordinary single-link'):X.emit(parent,root/(mode+'-output'))
     self.assertFalse((root/(mode+'-output')).exists())
    finally:leaf.unlink()
 def test_historical_default_profiles_and_optional_output_held(self):
  # Reconstruct the exact108 parent from the complete2ef fixture using the
  # unchanged default payload; no additional checkout or invented source bytes.
  default=F.profile();optional=O.profile();self.assertEqual((default['parent_source'],default['expected_source']),('5c7e4c9a1b807cfb24542b024bf34af9bb15dba1','108eea03755d605e2fec0e5226f8ed38aa56c5bb'));self.assertEqual((optional['parent_source'],optional['expected_source']),('108eea03755d605e2fec0e5226f8ed38aa56c5bb','2ef64d460aedeed8f40909d32f4a074e8c3c546b'))
  rows=F.tree(PARENT,checkout=True)|F.tree(HERE/'payload');self.assertEqual(F.pins(rows),default['after']);self.assertEqual(default['after'],optional['before'])
  with tempfile.TemporaryDirectory()as td:
   before=Path(td)/'original108';before.mkdir()
   for name,raw in rows.items():p=before/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
   out=Path(td)/'optional';O.emit(before,out);self.assertEqual(F.tree(out),F.tree(PARENT,checkout=True))
 def test_all106_actual_emitted_source_controls_via_discovery(self):
  with tempfile.TemporaryDirectory()as td:
   source=Path(td)/'trusted-source';X.emit(PARENT,source);self.assertEqual(F.pins(F.tree(source)),X.profile()['after']);env=dict(os.environ,PUBLIC_PAIR_UPDATER16K_SOURCE=str(source),PUBLIC_PAIR_UPDATER_SOURCE=str(source),PYTHONDONTWRITEBYTECODE='1')
   argv=[sys.executable,'-I','-B','-Werror','-m','unittest','discover','-s',str(source/LANE),'-p','test_*.py','-v'];r=subprocess.run(argv,cwd=td,env=env,capture_output=True,timeout=180)
   # Preserve the entire subprocess report in the maintained test receipt.
   sys.stderr.buffer.write(r.stdout+r.stderr);self.assertEqual(r.returncode,0);self.assertRegex(r.stderr,rb'Ran 106 tests in ');self.assertNotRegex(r.stderr,rb'\b(?:skipped|FAILED|ERROR|FAIL)\b');self.assertEqual(F.pins(F.tree(source)),X.profile()['after'])
if __name__=='__main__':unittest.main(verbosity=2)
