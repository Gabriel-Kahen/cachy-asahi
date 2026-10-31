# SPDX-License-Identifier: MIT
import ast,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import prepare as P
ROOT=Path(os.environ.get('APPS6_LIFECYCLE_ROOT',Path(__file__).resolve().parents[3]));FRESH=Path(os.environ.get('APPS6_FRESH_ROOT',ROOT))
def load(n,p):
 spec=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(spec);sys.modules[n]=m;spec.loader.exec_module(m);return m
class Selected(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory(prefix='apps6-updater-source-');cls.base=Path(cls.tmp.name);cls.output=cls.base/'implementation'
  with patch.object(subprocess,'Popen',side_effect=AssertionError('all actors forbidden')):P.emit(ROOT,FRESH,cls.output)
  cls.C=load('apps6_control_contract',cls.output/P.NEW/'contract.py');cls.A=cls.C.scoped('apps6_control_adapter',cls.output/P.NEW/'adapter.py',{'contract':cls.C});cls.held=cls.C.read(ROOT/'scripts/ci/expanded600-root-upgrade/held-pins.json');cls.codes={};cls.original={}
  # The existing immutable caller closures are source inputs, not executed actors.
  for case,row in cls.held.items():
   source=cls.base/('source-'+case);source.mkdir()
   for n,pin in row['pins'].items():
    p=source/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(subprocess.check_output(['git','-C',str(ROOT),'show',row['source']+':'+n],timeout=15))
   with patch.object(subprocess,'Popen',side_effect=AssertionError('all actors forbidden')):
    code=cls.base/('apps6-'+case);cls.A.prepare(source,code,case,git=False,implementation=ROOT);cls.codes[case]=code
    old=cls.base/('held-'+case);cls.A.prior.prepare(source,old,case,git=False,implementation=ROOT);cls.original[case]=old
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def test_exact_apps_only604_locks_and_preserved_setup5(self):
  before,after=self.C.locks();self.assertEqual(after,before|{'cachy-asahi-apps':'0.1.0-6'});self.assertEqual(before['cachy-asahi-apps'],'0.1.0-5');self.assertEqual(before['cachy-asahi-setup'],after['cachy-asahi-setup']);self.assertEqual(len(set(before)-{'cachy-asahi-apps'}),603)
 def test_unbound_first_gate_all_cases_before_output(self):
  gate=self.C.scoped('apps6_control_gate',self.output/P.NEW/'gate.py',{'contract':self.C})
  for case in self.C.SOURCES:
   with patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden')),self.assertRaisesRegex(ValueError,'UNBOUND'):gate.main(['--implementation',str(self.base/'absent'),'--source','a'*40,'--workflow-sha','a'*40,'--case',case,'--preflight'])
  self.assertFalse((self.base/'absent').exists())
 def test_all_three_complete_source_pin_alias_and_budget_checks(self):
  for case,code in self.codes.items():
   row=self.C.read(code/'upgrade-config.json');old=self.C.read(self.original[case]/'upgrade-config.json')
   self.assertEqual(row['scale']|{'before_lock_sha256':old['scale']['before_lock_sha256'],'after_lock_sha256':old['scale']['after_lock_sha256']},old['scale'])
   for key in old:
    if key not in ('purpose','scale','release','code_pins','external_pins'):self.assertEqual(row[key],old[key],key)
   for n,digest in row['code_pins'].items():self.assertEqual(self.C.sha(code/n),digest)
   if case!='normal':
    folder='full-root-failed-update' if case.startswith('pre') else 'full-root-postcommit-failure';self.assertEqual((code/'scripts/ci/full-root-upgrade-caller/upgrade_hook.py').read_bytes(),(code/'scripts/ci'/folder/'caller.py').read_bytes())
 def test_original_runtime_crypto_aux_caps_copy_and_checkpoint_unchanged(self):
  names=('scripts/update/full_root.py','scripts/update/bound_update.py','scripts/update/linked_runtime.py','scripts/update/aux_runtime.py','scripts/update/aux_checkpoint.py','scripts/update/aux_initialize.py','scripts/update/aux_copy.py','scripts/update/supervision.py','scripts/client/client.py','scripts/release/release.py','scripts/ci/full-root-upgrade-caller/persistent_scope.py')
  for case,code in self.codes.items():
   for n in names:self.assertEqual((code/n).read_bytes(),(self.original[case]/n).read_bytes(),n)
 def test_selected_constants_no_numeric_budget_changes(self):
  for case,code in self.codes.items():
   for n in self.A.SELECTED:
    if not (code/n).exists():continue
    nums=lambda raw:[v.value for v in ast.walk(ast.parse(raw)) if isinstance(v,ast.Constant) and type(v.value) in (int,float)]
    raw=(self.original[case]/n).read_bytes()
    if n.endswith('/construct_repository.py'):raw=raw.replace(b"source['project_url']",b"pkg['url'][0]").replace(b"'inventory_count': 574",b"'inventory_count': 575").replace(b"['inventory_count'] == 574",b"['inventory_count'] == 575")
    self.assertEqual(nums((code/n).read_bytes()),nums(raw),n)
   text=(code/'scripts/ci/full-root-upgrade/root_upgrade.py').read_text();self.assertIn("NAME = 'cachy-asahi-apps'",text);self.assertIn("{NAME: '0.1.0-6'}",text);self.assertIn("NAME + '-0.1.0-5'",text);self.assertIn("NAME + '-0.1.0-6'",text)
 def test_new_constructor_uses_actual575_build_metadata_and_recipe_url(self):
  for case,code in self.codes.items():
   M=load('apps6_constructor_'+case,code/'scripts/ci/full-root-upgrade/construct_repository.py')
   row=M.convert_provenance({'arch':['any'],'license':['MIT'],'url':['https://github.com/Gabriel-Kahen/cachy-asahi']},{'image_id':'sha256:'+'1'*64},{'native-build-1.json':'2'*64,'native-build-2.json':'3'*64},{},'inventory-sha256:'+self.C.BEFORE)
   self.assertEqual(row['package'],{'name':'cachy-asahi-apps','version':'0.1.0-6','arch':'any'});self.assertEqual(row['build']['inventory_count'],575);self.assertEqual(row['build']['inventory_sha256'],'66c46d4645fa443d23df0e97765905555fe5bc2607787dca3f30ee2084cf597f');self.assertEqual(row['sources'][0]['url'],'https://github.com/Gabriel-Kahen/cachy-asahi/tree/'+self.C.NATIVE)
 def test_packet_member_real_hash_link_and_path_refusals(self):
  H=load('apps6_control_selected',self.output/P.NEW/'selected_package.py')
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);(root/'row').write_bytes(b'actual-byte-input');r=dict(path='row',**P.pin(b'actual-byte-input'));self.assertEqual(H.member(root,r),root/'row')
   for n in ('../row','/row','a//row','a/./row','a/../row','a\\row'):
    with self.assertRaises(ValueError):H.member(root,dict(r,path=n))
   with self.assertRaises(ValueError):H.member(root,dict(r,sha256='0'*64))
   os.link(root/'row',root/'alias')
   with self.assertRaises(ValueError):H.member(root,r)
 def test_source_drift_and_wrong_before_refuse(self):
  with patch.object(P,'pin',return_value={}),self.assertRaisesRegex(ValueError,'pinned updater source'):P.sources(ROOT)
  for case,code in self.codes.items():
   H=load('apps6_control_locks_'+case,code/self.A.PREFIX/'selected_package.py');self.assertEqual(H.locks(code)[2],self.C.locks()[0]);p=code/'scripts/ci/full-development-composition/expected-updater-v2.lock';p.write_bytes(p.read_bytes()+b'\n')
   with self.assertRaisesRegex(ValueError,'exact Apps5'):H.locks(code)
if __name__=='__main__':unittest.main(verbosity=2)
