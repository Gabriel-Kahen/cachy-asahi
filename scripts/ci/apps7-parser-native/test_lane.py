# SPDX-License-Identifier: MIT
"""Private fixtures only: no Docker, host database, hardware or accepted result fixture."""
import ast,hashlib,importlib.util,json,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import sys
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import contract as C,worker as W,run as R,prepare as P
SOURCES={r:(HERE/(r+'-inventory.py')).read_bytes()for r in('baseline','candidate')}
class Controls(unittest.TestCase):
 def fixture(self,root,values=(b'%FILES%\na\nb\n',b'')):
  db=root/'db/local';db.mkdir(parents=True);(db/'ALPM_DB_VERSION').write_bytes(b'9\n');lock=root/'lock';lock.write_text(''.join('p'+str(i)+' 1-1\n'for i in range(len(values))))
  for i,raw in enumerate(values):(db/('p'+str(i)+'-1-1')).mkdir();(db/('p'+str(i)+'-1-1')/'files').write_bytes(raw)
  return db,lock
 def no_clocks(self):return patch.multiple(W.time,perf_counter_ns=lambda:(_ for _ in()).throw(AssertionError('clock reached')),process_time_ns=lambda:(_ for _ in()).throw(AssertionError('clock reached')))
 def test_default_NULL_before_actors(self):
  with tempfile.TemporaryDirectory()as d,patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   root=Path(d);(root/'input-policy.json').write_bytes((HERE/'default-input-policy.json').read_bytes())
   with patch.object(C,'HERE',root),self.assertRaisesRegex(ValueError,'authority'):R.execute(root,root/'base',root/'out','a'*32)
   self.assertFalse((root/'out').exists())
 def test_original_helper_whole_pin_and_eight_controls(self):
  self.assertEqual(C.pin((HERE/'apps_inventory_parser.py').read_bytes()),dict(bytes=8708,sha256='425800d46abf90534c48664d199b8ad14b4e2b47b1272b9a2a4b5c81cd1cba8b'))
  self.assertEqual(len(W.control_cases()),8)
  for raw,allowed in W.control_cases():self.assertEqual(W.B.outcome(W.B.parser(SOURCES['baseline'],'a'),raw,allowed),W.B.outcome(W.B.parser(SOURCES['candidate'],'b'),raw,allowed))
 def test_declared_profile_from_both_production_sources(self):
  p=W.production_profile(SOURCES);self.assertEqual((p['max_record_bytes'],p['max_FILES_values'],p['max_corpus_bytes']),(4194304,32768,67108864))
  for old,new in((b'MAX_RECORD=4*1024**2',b'MAX_RECORD=8*1024**2'),(b'len(paths)<=32768',b'len(paths)<=65536')):
   with self.assertRaises(ValueError):W.production_profile(dict(SOURCES,candidate=SOURCES['candidate'].replace(old,new)))
 def test_real_parsers_fileless_and_ordered_balanced_samples(self):
  v=W.measure(SOURCES,[b'',b'%FILES%\nb\na\n\n%BACKUP%\nx\n'],0,2);self.assertEqual(v['equivalence']['records'],2);self.assertEqual([(r['repeat'],r['role'])for r in v['timing']['samples']],[(0,'baseline'),(0,'candidate'),(1,'candidate'),(1,'baseline')]);self.assertTrue(all(type(r['wall_ns'])is int and type(r['process_ns'])is int for r in v['timing']['samples']))
 def test_FILES_exact_native_edge_without_quadratic_baseline(self):
  raw=b'%FILES%\n'+b''.join(('f'+str(i)+'\n').encode()for i in range(32768));value=W.B.outcome(W.B.parser(SOURCES['candidate'],'b'),raw,('FILES','BACKUP'));self.assertEqual(len(dict(value['value'])['FILES']),32768)
  with self.no_clocks(),self.assertRaisesRegex(ValueError,'ownership bound'):W.measure(SOURCES,[raw+b'excess\n'],0,2)
 def test_refused_or_different_parser_before_clocks(self):
  with self.no_clocks(),self.assertRaises(ValueError):W.measure(SOURCES,[b'%FILES%\na\na\n'],0,2)
  changed=SOURCES['candidate'].replace(b'return result',b'return {}')
  self.assertNotEqual(changed,SOURCES['candidate'])
  with self.no_clocks(),self.assertRaises(ValueError):W.measure(dict(SOURCES,candidate=changed),[b'%FILES%\na\n'],0,2)
 def test_complete_private_corpus_identity(self):
  with tempfile.TemporaryDirectory()as d:
   db,lock=self.fixture(Path(d));data,v,paths,raw=W.corpus(db,lock,2);self.assertEqual(data,[b'%FILES%\na\nb\n',b'']);self.assertEqual(v['records'],2);self.assertEqual(v['bytes'],sum(map(len,data)));self.assertEqual(v['lock'],C.pin(raw));self.assertEqual(len(paths),2)
 def test_record_cap_exact_and_over(self):
  with tempfile.TemporaryDirectory()as d:
   db,lock=self.fixture(Path(d),(b'x'*W.NATIVE_RECORD,));self.assertEqual(len(W.corpus(db,lock,1)[0][0]),W.NATIVE_RECORD)
   (db/'p0-1-1/files').write_bytes(b'x'*(W.NATIVE_RECORD+1))
   with self.assertRaises(ValueError):W.corpus(db,lock,1)
 def test_aggregate_cap(self):
  with tempfile.TemporaryDirectory()as d:
   db,lock=self.fixture(Path(d),(b'abcd',b'efgh'))
   with patch.object(W,'MAX_CORPUS',7),self.assertRaises(ValueError):W.corpus(db,lock,2)
 def test_missing_extra_and_symlink_corpus_refused(self):
  with tempfile.TemporaryDirectory()as d:
   db,lock=self.fixture(Path(d));(db/'extra').mkdir()
   with self.assertRaises(ValueError):W.corpus(db,lock,2)
   (db/'extra').rmdir();path=db/'p0-1-1/files';path.unlink();path.symlink_to(db/'p1-1-1/files')
   with self.assertRaises((ValueError,OSError)):W.corpus(db,lock,2)
 def test_lock_even_dangling_and_wrong_version_refused(self):
  with tempfile.TemporaryDirectory()as d:
   db,lock=self.fixture(Path(d));(db.parent/'db.lck').symlink_to('absent')
   with self.assertRaises(ValueError):W.corpus(db,lock,2)
   (db.parent/'db.lck').unlink();(db/'ALPM_DB_VERSION').write_bytes(b'8\n')
   with self.assertRaises(ValueError):W.corpus(db,lock,2)
 def test_cap0_readonly_argv_single_actor(self):
  with patch.object(C,'policy',return_value=json.loads((HERE/'input-policy.json').read_bytes())):
   a=R.argv(Path('/source'),'sha256:'+'a'*64,'cachy-asahi-product-'+'b'*32,'c'*32)
  for value in('--network=none','--cap-drop=ALL','--read-only','--security-opt=no-new-privileges','--memory=1073741824','--cpus=1','--pids-limit=64'):self.assertIn(value,a)
  self.assertEqual(a.count('--mount'),1);self.assertIn('type=bind,src=/source/scripts/ci/apps7-parser-native,dst=/inputs,readonly',a);self.assertFalse(any('cap-add' in x or 'docker.sock'in x for x in a))
 def test_nonidentifying_export_surface(self):
  source=(HERE/'worker.py').read_text();self.assertNotIn('B.benchmark(',source);self.assertNotIn('os.uname().nodename',source)
  with self.assertRaises(ValueError):C.metrics(dict(hostname='forbidden'))
 def test_runtime_source_proof_holds_and_tamper_fails(self):
  # Emitted view only; NULL remains separate from exact source proof.
  manifest=HERE/'source-manifest.json'
  if not manifest.exists():return
  source=HERE.parents[2]
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):C.verify_source(source,bound=False)
  rows=json.loads(manifest.read_bytes())['files'];self.assertEqual(rows['scripts/ci/tools-native/job.py'],json.loads((HERE/'infrastructure-pins.json').read_bytes())['scripts/ci/tools-native/job.py'])
  with patch.object(C,'pin',return_value={}):
   with self.assertRaises(ValueError):C.verify_source(source,bound=False)
 def test_emitter_selection_refuses_wrong_or_partial(self):
  with tempfile.TemporaryDirectory()as d:
   for selection in({},dict(status='ROOT_SELECTED_PUBLIC_PARSER_CODE',baseline='0'*40,candidate='1'*40)):
    with self.assertRaises(ValueError):P.emit(Path(d),Path(d)/'output',selection)
    self.assertFalse((Path(d)/'output').exists())
if __name__=='__main__':unittest.main()
