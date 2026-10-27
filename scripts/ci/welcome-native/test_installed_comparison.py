# SPDX-License-Identifier: MIT
"""Hosted tempfile/source controls only; not installed native evidence."""
import contextlib,copy,hashlib,importlib.util,json,os,shutil,socket,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('installed_comparison_under_test',HERE/'installed_comparison.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
_relative=Path('packages/tools/cachy-asahi-doctor2/cachy-asahi-doctor')
SOURCE=next(path for path in [HERE.parent/'source'/_relative,*[parent/_relative for parent in HERE.parents]]if path.is_file())
class InstalledComparison(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  self.tool=self.root/'cachy-asahi-doctor';shutil.copyfile(SOURCE,self.tool);self.tool.chmod(0o755);self.pin=M.sha(self.tool)
  guard=patch.object(M,'INSTALLED',self.tool);guard.start();self.addCleanup(guard.stop)
 def user(self,home,argv,expected=0):
  if argv[0]=='/usr/bin/python3':
   self.assertEqual(argv[1:4],['-I','-B',str(M.RUNNER)]);self.assertEqual(argv[4],'--guarded')
   return json.dumps(M.guarded(argv[5],argv[6:]))
  result=subprocess.run([sys.executable,'-B',*argv],capture_output=True,text=True,timeout=5,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
  self.assertEqual(result.returncode,expected,result.stderr);self.assertLess(len(result.stdout)+len(result.stderr),65536);return result.stdout
 def test_full_host_tempfile_source_exercise(self):
  home=self.root/'product-home-fresh';home.mkdir();output=self.root/'output';output.mkdir()
  result=M.run_comparisons(self.user,home,output,self.pin,'install')
  self.assertEqual(result['fixture_scope'],'SYNTHETIC_SUPPLIED_REPORTS_NOT_COLLECTED_OBSERVATIONS');self.assertEqual(len(result['cases']),12)
  self.assertEqual([r['case']for r in result['cases']],list(M.CASE_NAMES));self.assertEqual(result['direct_executable_cases'],9)
  import contract as C
  native_shape=copy.deepcopy(result);native_shape['installed_path']='/usr/bin/cachy-asahi-doctor' # Host source fixture path is never installed evidence.
  C.validate_installed_comparison(native_shape,self.pin,'install','product-home-fresh')
  fixture_root=output/'comparison-install';before=M.snapshot(fixture_root);M.preserve(fixture_root,before)
  (fixture_root/'new-comparison.json').write_text('CHANGED')
  with self.assertRaisesRegex(ValueError,'not preserved'):M.preserve(fixture_root,before)
 def test_oracle_fixture_is_valid_and_exact(self):
  loaded=__import__('runpy').run_path(str(self.tool),run_name='source_fixture_oracle');before,unchanged,changed,unsupported=M.fixtures()
  for after in (unchanged,changed):self.assertEqual(loaded['compare_reports'](loaded['validate_report'](before),loaded['validate_report'](after)),M.expected_comparison(before,after))
  with self.assertRaises(ValueError):loaded['validate_report'](unsupported)
 def test_guarded_code_uses_real_function_globals_and_denies_each_actor(self):
  for expression in ['collect()','query([] ,1)','fixed_read("/proc/device-tree/model")','available("pacman")','local_user_bus()','audio_socket()',
                     'subprocess.Popen(["never"])','socket.socket()','socket.create_connection(("never",1))','socket.getaddrinfo("never",1)','urllib.request.urlopen("http://never")','os.system("never")','os.fork()','os.posix_spawn()']:
   with self.subTest(expression=expression):
    self.tool.write_text('import subprocess,socket,os,urllib.request\ndef collect(): return 1\ndef query(*a): return 1\ndef fixed_read(*a): return 1\ndef available(*a): return 1\ndef local_user_bus(): return 1\ndef audio_socket(): return 1\ndef main(argv): return '+expression+'\n')
    with self.assertRaisesRegex(AssertionError,'attempted collection/process/network'):M.guarded(M.sha(self.tool),[])
 def test_audit_denies_each_process_network_event(self):
  for event in M.AUDIT_EVENTS:
   with self.subTest(event=event):
    self.tool.write_text('import sys\ndef main(argv):\n sys.audit('+repr(event)+',())\n return 0\n')
    with self.assertRaisesRegex(AssertionError,'attempted collection/process/network'):M.guarded(M.sha(self.tool),[])
 def test_isolated_guard_cli_argument_transport(self):
  helper=self.root/'guard.py';helper.write_text((HERE/'installed_comparison.py').read_text().replace("INSTALLED=Path('/usr/bin/cachy-asahi-doctor')",'INSTALLED=Path('+repr(str(self.tool))+')'))
  before=self.root/'before.json';before.write_text(json.dumps(M.fixture()));after=self.root/'after.json'
  for data,expected in [(before.read_text(),0),('{"SYNTHETIC":',2)]:
   after.write_text(data)
   result=subprocess.run([sys.executable,'-I','-B',str(helper),'--guarded',self.pin,'--compare',str(before),str(after),'--json'],capture_output=True,text=True,timeout=5)
   self.assertEqual(result.returncode,0,result.stderr);receipt=json.loads(result.stdout);self.assertEqual(receipt['returncode'],expected);self.assertEqual(receipt['forbidden_calls'],0)
 def test_guard_payload_drift_rejected(self):
  with self.assertRaisesRegex(ValueError,'payload differs'):M.guarded('0'*64,[])
 def test_finite_label_and_output_freshness(self):
  home=self.root/'product-home-fresh';home.mkdir();out=self.root/'out';out.mkdir()
  with self.assertRaisesRegex(ValueError,'finite lifecycle phase'):M.run_comparisons(self.user,home,out,self.pin,'../escape')
  (out/'comparison-install').mkdir()
  with self.assertRaises(FileExistsError):M.run_comparisons(self.user,home,out,self.pin,'install')
 def test_snapshot_refuses_extra_directory_or_special_entries(self):
  root=self.root/'fixtures';root.mkdir();(root/'nested').mkdir()
  with self.assertRaisesRegex(ValueError,'fixture file/link'):M.snapshot(root)
 def test_changed_installed_payload_rejected(self):
  self.tool.write_text(self.tool.read_text()+'\n# changed\n');home=self.root/'product-home-fresh';home.mkdir();out=self.root/'out';out.mkdir()
  with self.assertRaisesRegex(ValueError,'executable differs'):M.run_comparisons(self.user,home,out,self.pin,'install')
 def test_input_mutation_detected(self):
  home=self.root/'product-home-fresh';home.mkdir();out=self.root/'out';out.mkdir()
  def malicious(home,argv,expected=0):
   raw=self.user(home,argv,expected);Path(argv[2]).chmod(0o644);return raw
  with self.assertRaisesRegex(ValueError,'preservation differs'):M.run_comparisons(malicious,home,out,self.pin,'install')
if __name__=='__main__':unittest.main(verbosity=2)
