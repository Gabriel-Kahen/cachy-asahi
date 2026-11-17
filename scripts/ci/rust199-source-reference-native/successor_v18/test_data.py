# SPDX-License-Identifier: MIT
"""Source-only exact367 delta/inverses; synthetic signed inputs remain MODEL."""
import ast,importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.dont_write_bytecode=True

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=module('v18_constructor_DATA',HERE/'prepare.py');T=module('v18_parent_MODEL',HERE.parent/'successor_v17/test_data.py');C=module('v18_input_MODEL',HERE/'test_dependencies.py')
def parent_model():
 before=T.parent_model()
 with patch.object(T.P,'PARENT',T.P.identity(before)):return T.P.render(before)
def payload_model(base):
 files=P.fs.snapshot(HERE/'payload');row=C.archive(base/'MODEL.pkg.tar.xz',C.package());body=(base/'MODEL.pkg.tar.xz').read_bytes();sig=b'MODEL_SIGNATURE_NOT_AUTHENTIC';row['signature']=P.fs.pin(sig);policy=P.encode(C.policy(row));files['hosted/build-dependencies.json']=(policy,0o644)
 raw,mode=files['hosted/build_dependencies.py'];files['hosted/build_dependencies.py']=(raw.replace(b'POLICY_PIN=None',b'POLICY_PIN='+repr(P.fs.pin(policy)).encode()),mode)
 files['build-dependencies/'+row['filename']]=(body,0o644);files['build-dependencies/'+row['filename']+'.sig']=(sig,0o644)
 for name,pin in C.D.provenance_inputs(row).items():
  body=C.RECIPE if name.endswith('/PKGBUILD')else C.LICENSE;assert P.fs.pin(body)==pin;files[name]=(body,0o644)
 target=base/'constructor';target.mkdir();P.fs.publish(files,target/'payload');return target,files
class Source(unittest.TestCase):
 def test_unavailable_real_package_tuple_refuses_before_source_construction(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'payload').mkdir()
   with patch.object(P,'HERE',root),self.assertRaisesRegex(ValueError,'HOLD'):P.payload()
 def test_complete_MODEL_inverse_and_every_unaffected_byte_mode(self):
  before=parent_model()
  with tempfile.TemporaryDirectory()as td:
   target,view=payload_model(Path(td))
   with patch.object(P,'HERE',target),patch.object(P,'PARENT',P.identity(before)):
    after=P.render(before);self.assertEqual(P.undo(after),before);self.assertEqual(len(after)-len(before),11)
    for n,row in before.items():
     if n not in P.REPLACED|{'source-map.json'}:self.assertEqual(after[n],row,n)
    m=json.loads(after[P.MARKER][0]);self.assertIsNone(m['Root_grants']);self.assertTrue(m['makepkg_dependency_checks_preserved']);self.assertFalse(m['authority_changed']);self.assertFalse(m['resources_changed'])
    for n in('recipe/PKGBUILD','actor/entry.py','admission.py','hosted/phase_transfer.py','frozen/bootstrap349.py','resource-policy.json','contract.json'):self.assertEqual(after[n],before[n],n)
 def test_only_exact_dependency_context_and_qualification_joins_admitted(self):
  before=parent_model();view=P.fs.snapshot(HERE/'payload');P.check_delta(before,view)
  for n,old,new in(('hosted/bootstrap.py',b'dependencies.prepare_context',b'dependencies.skip_context'),('hosted/qualification.py',b'dependencies.validate_observation',b'print'),('actor/qualify.py',b'native=True',b'native=False')):
   bad=dict(view);self.assertIn(old,bad[n][0]);bad[n]=(bad[n][0].replace(old,new),0o644)
   with self.subTest(n=n),self.assertRaises(ValueError):P.check_delta(before,bad)
  old_ast=ast.parse(before['hosted/bootstrap.py'][0]);new_ast=ast.parse(view['hosted/bootstrap.py'][0])
  for name in('normal_dockerfile','build_base','inventory','retire'):
   old=next(n for n in old_ast.body if isinstance(n,ast.FunctionDef)and n.name==name);new=next(n for n in new_ast.body if isinstance(n,ast.FunctionDef)and n.name==name);self.assertEqual(ast.dump(old),ast.dump(new),name)
 def test_MODEL_inverse_rejects_map_archive_input_body_mode_and_extra_namespace(self):
  before=parent_model()
  with tempfile.TemporaryDirectory()as td:
   target,_=payload_model(Path(td))
   with patch.object(P,'HERE',target),patch.object(P,'PARENT',P.identity(before)):
    after=P.render(before)
    for n in(P.MARKER,'source-map.json','hosted/build_dependencies.py','hosted/build-dependencies.json',P.ARCHIVE+'hosted/bootstrap.py'):
     bad=dict(after);bad[n]=(bad[n][0]+b'TAMPER',0o644)
     with self.subTest(n=n),self.assertRaises(ValueError):P.undo(bad)
    with self.assertRaises(ValueError):P.undo(dict(after,EXTRA=(b'MODEL',0o644)))
    bad=dict(after);bad['hosted/bootstrap.py']=(bad['hosted/bootstrap.py'][0],0o755)
    with self.assertRaises(ValueError):P.undo(bad)
 def test_prospective_constructor_does_not_emit_on_missing_policy_or_profile(self):
  before=parent_model()
  with tempfile.TemporaryDirectory()as td:
   base=Path(td);empty=base/'empty';empty.mkdir();(empty/'payload').mkdir();output=base/'NEVER'
   with patch.object(P,'HERE',empty),self.assertRaisesRegex(ValueError,'HOLD'):P.construct(base/'parent',output,'a'*64)
   self.assertFalse(output.exists())
   target,_=payload_model(base)
   with patch.object(P,'HERE',target),self.assertRaisesRegex(ValueError,'HOLD.*profile'):P.construct(base/'parent',output,'a'*64)
   self.assertFalse(output.exists())
 def test_payload_requires_complete_provenance_and_source_namespace(self):
  for missing in('dependency-provenance/libgit2/PKGBUILD','dependency-provenance/libgit2/licenses/COPYING'):
   with self.subTest(missing=missing),tempfile.TemporaryDirectory()as td:
    target,_=payload_model(Path(td));(target/'payload'/missing).unlink()
    with patch.object(P,'HERE',target),self.assertRaises(ValueError):P.payload()
 def test_MODEL_constructor_requires_external_profile_pin_and_preserves_exact_inverse(self):
  before=parent_model()
  with tempfile.TemporaryDirectory()as td:
   base=Path(td);target,_=payload_model(base);parent=base/'parent';P.fs.publish(before,parent)
   with patch.object(P,'HERE',target),patch.object(P,'PARENT',P.identity(before)):
    profile=dict(schema=18,scope=P.SCOPE,parent=P.PARENT,actual=P.ACTUAL,Root_review=None,accepted=None,unadmitted=True,constructor_files=P.inputs(),**P.identity(P.render(before)));raw=P.encode(profile);(target/'constructor-profile.json').write_bytes(raw)
    with self.assertRaisesRegex(ValueError,'external whole'):P.construct(parent,base/'WRONG','f'*64)
    self.assertFalse((base/'WRONG').exists());result=P.construct(parent,base/'MODEL_SOURCE',P.fs.pin(raw)['sha256']);after=P.fs.snapshot(base/'MODEL_SOURCE');self.assertEqual(P.identity(after),P.identity(P.render(before)));self.assertEqual(P.undo(after),before);self.assertTrue(result['unadmitted']);self.assertEqual(result['native'],'NOT RUN')
 def test_actual367_and_full367_364_361_355_351_344_340_inverses(self):
  path=os.environ.get('RUST199_V18_PARENT')
  if not path:self.skipTest('set RUST199_V18_PARENT for genuine367 DATA closure')
  current=P.capture(Path(path))
  P.check_delta(current,P.fs.snapshot(HERE/'payload'))
  with tempfile.TemporaryDirectory()as td:
   target,_=payload_model(Path(td))
   with patch.object(P,'HERE',target):self.assertEqual(P.undo(P.render(current)),current)
  for version,count in((17,364),(16,361),(15,355),(14,351),(13,344),(12,340)):
   q=module('v18_actual_inverse_'+str(version),HERE.parent/('successor_v'+str(version))/'prepare.py');prior=current;current=q.undo(prior);self.assertEqual(len(current),count);self.assertEqual(q.render(current),prior)
if __name__=='__main__':unittest.main(verbosity=2)
