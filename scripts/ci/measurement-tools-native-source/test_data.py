#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New finite factory DATA controls; deny all process/network actors."""
import argparse,hashlib,importlib.util,json,os,shutil,sys,tempfile,unittest
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
parser=argparse.ArgumentParser();parser.add_argument('--basis',type=Path,required=True);parser.add_argument('--result',type=Path,required=True);args=parser.parse_args()
ACTORS=[]
def deny(event,arguments):
 if event in ('subprocess.Popen','os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','pty.spawn') or event.startswith('socket.'):
  ACTORS.append(event);raise RuntimeError('workload actor denied: '+event)
sys.addaudithook(deny)
spec=importlib.util.spec_from_file_location('measurement_factory_data',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
class DataControls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
 def test_01_full199_map198_and_rawparent(self):
  value,before,after=F.render(args.basis.absolute());self.assertEqual((len(before),len(after)),(191,199));self.assertEqual(F.git_tree(before),value['parent_tree']);self.assertEqual(len(json.loads(after['native/source-map.json'][0])['files']),198)
 def test_02_full191_inverse(self):
  value,before,after=F.render(args.basis.absolute());inverse=dict(after)
  for name in value['payload']:
   if name in before:inverse[name]=before[name]
   else:del inverse[name]
  self.assertEqual(F.rows(inverse),F.rows(before));self.assertEqual(F.git_tree(inverse),value['parent_tree'])
 def test_03_actual_emission_and_existing_output_refusal(self):
  output=self.root/'trial';stage=F.emit(args.basis.absolute(),output);self.assertEqual(stage['group_admission'],'NOT_ADMITTED');self.assertEqual(len(F.tree(output/'source')),199)
  held=(output/'stage.json').read_bytes()
  with self.assertRaises(ValueError):F.emit(args.basis.absolute(),output)
  self.assertEqual((output/'stage.json').read_bytes(),held)
 def test_04_no_group_admission_or_runtime_claim(self):
  value=F.profile();self.assertEqual(value['group_admission'],'NOT_ADMITTED');self.assertTrue(all(v is None for v in value['actual'].values()))
  payload=F.tree(HERE/'payload');self.assertEqual(payload['.github/workflows/native-arm-build.yml'],payload['.github/workflows/native-arm-developer-workflows.yml'])
  raw=payload['.github/workflows/native-arm-build.yml'][0];self.assertIn(b'group: native-arm-measurement-tools\n  cancel-in-progress: false\n  queue: max',raw);self.assertIn(b'options: [measurement-tools-alpm-v1]',raw)
 def test_05_fixed_payload_tamper_refused(self):
  copy=self.root/'factory';shutil.copytree(HERE,copy);(copy/'payload/native/measurement-contract-v1.json').write_bytes(b'{}\n');old=F.HERE
  try:
   F.HERE=copy
   with self.assertRaises(ValueError):F.render(args.basis.absolute())
  finally:F.HERE=old
 def test_06_wrong_actualparent_refused(self):
  copy=self.root/'factory';shutil.copytree(HERE,copy);p=copy/'parent-commit.raw';p.write_bytes(p.read_bytes()+b'change');old=F.HERE
  try:
   F.HERE=copy
   with self.assertRaises(ValueError):F.render(args.basis.absolute())
  finally:F.HERE=old
 def test_07_ordinary_alias_special_and_mode_refusals(self):
  original=self.root/'file';original.write_bytes(b'ordinary');alias=self.root/'alias';alias.symlink_to(original)
  with self.assertRaises(ValueError):F.read(alias)
  alias.unlink();os.link(original,alias)
  with self.assertRaises(ValueError):F.read(original)
  alias.unlink();os.mkfifo(alias)
  with self.assertRaises(ValueError):F.read(alias)
 def test_08_unchanged_default200_bound(self):
  self.assertEqual(F.MAX_FILES,200);source=self.root/'source';source.mkdir()
  for number in range(201):(source/str(number)).write_bytes(b'x')
  with self.assertRaises(ValueError):F.tree(source)
 def test_09_no_packagecheck_narrowing(self):
  contract=json.loads((HERE/'payload/native/measurement-contract-v1.json').read_text());self.assertEqual(contract['recipe']['expected_test_counts'],[8]);self.assertEqual(len(contract['recipe']['source_files']),18);self.assertEqual(len(contract['recipe']['payload_files']),14)
  self.assertEqual(contract['candidate_profile']['sha256'],'24692e6754b466c9172343c80883733fe14b240b18d15b87b109aed397c14ec0')
 def test_10_zero_actor_attempts(self):self.assertEqual(ACTORS,[])
result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(DataControls))
args.result.write_text(json.dumps(dict(schema=1,status='PASS_DATA_ONLY' if result.wasSuccessful() else 'FAIL',tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skips=len(result.skipped),actor_attempts=ACTORS,native='NOT_RUN',build='NOT_RUN',GPG='NOT_RUN',ALPM='NOT_RUN',namespace_support='UNKNOWN'),sort_keys=True,indent=2)+'\n')
sys.exit(0 if result.wasSuccessful() else 1)
