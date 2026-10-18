# SPDX-License-Identifier: MIT
"""Portable, actor-blocked source/three-case/authority controls; no Git/network."""
import ast,hashlib,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import prepare as P
HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('PUBLIC_PAIR_UPDATER_SOURCE',HERE.parents[2]));FRESH=Path(os.environ.get('PUBLIC_PAIR_UPDATER_FRESH',ROOT))
def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.tmp.cleanup);cls.base=Path(cls.tmp.name);cls.output=cls.base/'emitted'
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actors or Git')):P.emit(ROOT,FRESH,cls.output)
  cls.C=load('public_pair_updater_controls',cls.output/P.NEW/'contract.py');cls.A=cls.C.scoped('public_pair_updater_adapter',cls.output/P.NEW/'adapter.py',{'contract':cls.C});cls.codes={};cls.old={}
  fixtures={'scripts/ci/full-root-upgrade-caller/upgrade-config.json':'normal-upgrade-config.json','scripts/ci/full-root-failed-update/lane-config.json':'precommit-lane-config.json','scripts/install/local_transaction.py':'local_transaction.py'}
  for case,row in cls.C.read(cls.output/'scripts/ci/expanded600-root-upgrade/held-pins.json').items():
   source=cls.base/('source-'+case);source.mkdir()
   for name,ref in row['pins'].items():
    original=cls.output/name
    if not original.is_file() or P.pin(original.read_bytes())!=ref:original=HERE/'fixtures'/fixtures[name]
    raw=original.read_bytes();cls.C.need(P.pin(raw)==ref,'exact historical held test operand');p=source/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
   with patch.object(subprocess,'Popen',side_effect=AssertionError('no actors or Git')):
    code=cls.base/('candidate-'+case);cls.A.prepare(source,code,case,git=False,implementation=cls.output);cls.codes[case]=code
    old=cls.base/('prior-'+case);cls.A.prior.prepare(source,old,case,git=False,implementation=cls.output);cls.old[case]=old
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def test_complete_closed_source_and_exact_bound_composition(self):
  value=self.C.read(self.output/P.NEW/'source-manifest.json')
  for n,row in value['files'].items():self.assertEqual(P.pin((self.output/n).read_bytes()),row,n)
  fresh=self.C.read(self.output/P.FRESH/'source-manifest.json');self.assertEqual(hashlib.sha256((self.output/P.FRESH/'source-manifest.json').read_bytes()).hexdigest(),'5f4dbc150a5f8ca6a85843b783e7b5472251a4b0761e75e65f7d82b165a7b629')
  for n,row in fresh['files'].items():self.assertEqual(P.pin((self.output/n).read_bytes()),row,n)
  controls=self.C.read(HERE/'source-pins.json')['fresh_control_inputs'];self.assertEqual(len(controls),9)
  for n,row in controls.items():self.assertEqual(P.pin((self.output/n).read_bytes()),row,n);self.assertEqual(fresh['files'][n],row,n)
  selected=self.C.read(HERE/'source-pins.json')['selected_fresh_source'];self.assertEqual(selected['source_sha'],'bd0cf1891083d011b70edab10501c317d3720b78');self.assertEqual(selected['status'],'SOURCE_BOUND_FRESH_TRIAL_ONLY_NOT_ACCEPTANCE')
  self.assertEqual(self.C.read(self.output/P.FRESH/'input-policy.json')['status'],'ROOT_BOUND_PUBLIC_PAIRS_APPS6_CURRENT604_NATIVE_ACCEPTANCE')
  self.assertEqual(P.NATIVE604,'b0154bd3b60434e45d4411b558f3ffda9e415640');self.assertEqual(self.C.read(self.output/P.COMP/'input-policy.json')['status'],'ROOT_BOUND_PUBLIC_PAIRS_APPS6_CURRENT604_NATIVE_INPUTS')
 def test_unbound_three_cases_before_output_or_actor(self):
  G=self.C.scoped('public_updater_gate_controls',self.output/P.NEW/'gate.py',{'contract':self.C})
  for case in self.C.SOURCES:
   with patch.object(subprocess,'Popen',side_effect=AssertionError('no actors')),self.assertRaisesRegex(ValueError,'UNBOUND'):G.main(['--implementation',str(self.base/'never'),'--source','a'*40,'--workflow-sha','a'*40,'--case',case,'--preflight'])
  self.assertFalse((self.base/'never').exists());policy=self.C.policy(bound=False);self.assertIsNone(policy['prerequisites']['native604']);self.assertIsNone(policy['prerequisites']['fresh604']);self.assertIsNone(policy['installer_source']);self.assertIsNone(policy['decision_source'])
 def test_exact_apps_only_change_and_original_baseline(self):
  before,after=self.C.locks();self.assertEqual(len(before),604);self.assertEqual(after,before|{'cachy-asahi-apps':'0.1.0-6'});self.assertEqual(before['cachy-asahi-setup'],after['cachy-asahi-setup']);self.assertEqual(self.C.NATIVE,'c5481ad6bfd1539ab9a289bc9541133b979858f7')
  policy=self.C.policy(bound=False);self.assertEqual(policy['baseline_source'],'ed776a706fc711c5bcc4d933f38e88e7791bc9f6');self.assertEqual(policy['apps6']['carrier_source'],'65950a7e3ca82d97e21a65556844dab1cfd1a7f7');self.assertNotIn('apps6_native_source',policy['installer_inputs']);self.assertEqual(policy['installer_inputs']['apps6_authority_source'],policy['apps6']['authority_source'])
 def test_five_declared_module_derivations_reversible(self):
  for n in P.MODULES:
   raw,ledger=P.adapt((self.output/P.OLD/n).read_bytes(),n);self.assertEqual(raw,(self.output/P.NEW/n).read_bytes());text=raw.decode()
   for row in reversed(ledger):self.assertEqual(text.count(row['after']),row['count']);text=text.replace(row['after'],row['before'])
   self.assertEqual(text.encode(),(self.output/P.OLD/n).read_bytes())
 def test_all_three_original_transaction_crypto_copy_recovery_bodies_unchanged(self):
  for case,code in self.codes.items():
   old=self.old[case]
   for p in old.rglob('*'):
    if not p.is_file():continue
    n=p.relative_to(old).as_posix()
    if n=='scripts/ci/full-root-upgrade/construct_repository.py' or n.startswith(self.A.PREFIX) or n in ('upgrade-config.json','adapter.json'):continue
    if n=='scripts/update/linked_runtime.py':
     H=self.C.load('exact_linked_auxiliary_controls',HERE/'aux_transition.py');expected,_=H.derive_linked(p.read_bytes());self.assertEqual((code/n).read_bytes(),expected,case+':'+n)
    elif n=='scripts/update/aux_runtime.py':
     H=self.C.load('exact_apps_auxiliary_controls',HERE/'aux_transition.py');expected,_=H.derive(p.read_bytes());self.assertEqual((code/n).read_bytes(),expected,case+':'+n)
    else:self.assertEqual((code/n).read_bytes(),p.read_bytes(),case+':'+n)
 def test_all_three_config_resources_and_complete_code_pins(self):
  for case,code in self.codes.items():
   config=self.C.read(code/'upgrade-config.json');old=self.C.read(self.old[case]/'upgrade-config.json')
   for key,value in old.items():
    if key not in ('code_pins','release'):self.assertEqual(config[key],value,key)
   for n,digest in config['code_pins'].items():self.assertEqual(self.C.sha(code/n),digest)
   self.assertEqual(self.C.read(code/'adapter.json')['raw_Q_lock'],'NOT_PRESENT_NOT_FABRICATED')
 def test_typed_public_evidence_constructor_seams_and_provenance_scope(self):
  for case,code in self.codes.items():
   path='scripts/ci/full-root-upgrade/construct_repository.py';self.assertEqual((code/path).read_bytes(),self.A.constructor((self.old[case]/path).read_bytes()));M=load('constructor_'+case,code/path)
   value=M.convert_provenance({'arch':['any'],'license':['MIT'],'url':['https://github.com/Gabriel-Kahen/cachy-asahi']},{'image_id':'sha256:'+'1'*64},{'native-build-1.json':'2'*64,'native-build-2.json':'3'*64},{},'inventory-sha256:'+self.C.BEFORE)
   self.assertEqual(value['build']['inventory_count'],575);self.assertEqual(value['build']['raw_pacman_Q_lock'],'NOT_PRESENT_NOT_FABRICATED');self.assertEqual(value['build']['inventory_evidence'],'PUBLIC_ROOT_PAIR_AUTHORITY_AND_COMPLETE_BUILDINFO');self.assertEqual(value['sources'][0]['url'],'https://github.com/Gabriel-Kahen/cachy-asahi/tree/'+self.C.NATIVE)
 def test_source_drift_missing_and_alias_refuse_before_output(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);out=root/'out'
   for kind in ('missing','wrong','alias'):
    src=root/kind;src.mkdir();file=src/'probe'
    if kind=='wrong':file.write_bytes(b'wrong')
    if kind=='alias':file.symlink_to(HERE/'README.md')
    descriptor=root/'pins.json';descriptor.write_text(json.dumps({'groups':{'updater':{'probe':P.pin(b'wanted')},'fresh':{'probe':P.pin(b'wanted')}}}))
    fake=root/'definition';fake.mkdir(exist_ok=True);(fake/'source-pins.json').write_bytes(descriptor.read_bytes())
    with patch.object(P,'HERE',fake),patch.object(subprocess,'Popen',side_effect=AssertionError('no actors')),self.assertRaises((ValueError,FileNotFoundError)):P.emit(src,src,out)
    self.assertFalse(out.exists())
 def test_historical_raw223_binding_and_wrong_public_authority_refuse(self):
  helper=self.C.load('public_authority_control',self.output/P.COMP/'apps_inputs.py');current=self.C.policy(bound=False)['apps6'];self.assertEqual(helper.require(self.C,current),current)
  for key,value in (('status','ROOT_BOUND_APPS6_NATIVE_V4'),('carrier_source','a'*40),('authority_source','b'*40)):
   with self.assertRaisesRegex(ValueError,'UNBOUND'):helper.require(self.C,dict(current,**{key:value}))
 def test_workflow_owner_manifest_authority_and_bounds_exact(self):
  rows=self.C.read(HERE/'source-pins.json')['groups']['updater'];expected=P.workflow((self.output/'.github/workflows/native-arm-expanded604-apps6-updater.yml').read_bytes(),rows,self.C.sha(self.output/P.NEW/'run.py'),self.C.sha(self.output/P.NEW/'source-manifest.json'));self.assertEqual((self.output/P.WF).read_bytes(),expected);text=expected.decode();self.assertNotIn('--apps6-native-source',text);self.assertEqual(text.count('--apps6-authority-source'),2)
  run=(self.output/P.NEW/'run.py').read_text();self.assertIn("old.command(argv+['--entrypoint=/usr/bin/python3',image,'-I','-B','/runner.py'],public/'transaction.log',3900)",run)
 def test_emitted_genuine_setup_recipe_full_source_helper_license_closure(self):
  recipe=P.setup_recipe(self.output);self.assertEqual(len(recipe['input_sha256']),12);self.assertEqual(recipe['metadata']['pkgname'],['cachy-asahi-setup']);self.assertEqual(recipe['metadata']['pkgrel'],['5'])
  required=self.C.read(HERE/'source-pins.json')['setup_recipe_guard_inputs'];self.assertEqual(len(required),14)
  for n,row in required.items():self.assertEqual(P.pin((self.output/n).read_bytes()),row,n)
  # Run the REAL original recipe guard on a closed disposable source subset.
  with tempfile.TemporaryDirectory() as td:
   root=Path(td)
   for n in (*required,'scripts/ci/setup5-native/contract.py','scripts/checks/package_checks.py'):
    p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((self.output/n).read_bytes())
   self.assertEqual(P.setup_recipe(root),recipe)
   for n in required:
    p=root/n;raw=p.read_bytes();p.unlink()
    try:
     with self.assertRaises(FileNotFoundError):P.setup_recipe(root)
    finally:p.write_bytes(raw)
   p=root/'scripts/setup/setup.py';p.write_bytes(p.read_bytes()+b'\n')
   with self.assertRaisesRegex(ValueError,'provenance'):P.setup_recipe(root)

 def test_real_client_fresh_window_crosses_original_expiry_without_relaxing_guard(self):
  from datetime import datetime,timezone,timedelta
  client=load('fresh_metadata_real_client',self.output/'scripts/client/client.py')
  now=datetime(2026,10,18,0,5,26,tzinfo=timezone.utc)
  class Clock(datetime):
   @classmethod
   def now(cls,tz):return now
  args=SimpleNamespace(issued_utc='2026-10-16T00:00:00Z',expires_utc='2026-10-18T00:00:00Z')
  for case,code in self.codes.items():
   M=load('fresh_constructor_'+case,code/'scripts/ci/full-root-upgrade/construct_repository.py')
   with patch.object(client,'datetime',Clock):issued,expires=M.fresh_test_metadata_window(SimpleNamespace(client=client),args)
   self.assertEqual(issued,'2026-10-18T00:05:26Z');self.assertEqual(expires,'2026-10-20T00:05:26Z')
   value=dict(schema_version=1,type=client.TYPE,scope=client.SCOPE,namespace='cachy-asahi-test-window',sequence=1,signer='A'*40,synthetic=False,release_id='inert-clock-control',repo_name='inert',targets={},issued_utc=args.issued_utc,expires_utc=args.expires_utc)
   with self.assertRaisesRegex(client.Error,'expired or issued in the future'):client.validate_envelope(value,now)
   value.update(issued_utc=issued,expires_utc=expires);client.validate_envelope(value,now)
   for observed in (now-timedelta(seconds=1),now+timedelta(seconds=172800)):
    with self.assertRaisesRegex(client.Error,'expired or issued in the future'):client.validate_envelope(value,observed)
 def test_exact_fixture_lifetime_constructor_and_signature_refusals_remain(self):
  client=load('fresh_metadata_refusal_client',self.output/'scripts/client/client.py');api=SimpleNamespace(client=client)
  for case,code in self.codes.items():
   M=load('fresh_refusal_constructor_'+case,code/'scripts/ci/full-root-upgrade/construct_repository.py')
   for issued,expires in (('2026-10-16T00:00:00Z','2026-10-19T00:00:00Z'),('2026-10-17T00:00:00Z','2026-10-19T00:00:00Z'),('bad','2026-10-18T00:00:00Z')):
    with self.assertRaisesRegex(ValueError,'exact original TEST fixture'):M.fresh_test_metadata_window(api,SimpleNamespace(issued_utc=issued,expires_utc=expires))
   raw=(self.old[case]/'scripts/ci/full-root-upgrade/construct_repository.py').read_bytes()
   with self.assertRaisesRegex(ValueError,'exact whole Apps6 constructor'):self.A.constructor(raw+b' ')
  from datetime import datetime,timezone
  for status in ('EXPKEYSIG','KEYEXPIRED','REVKEYSIG','BADSIG','SIGEXPIRED'):
   with self.assertRaisesRegex(client.Error,'invalid/expired/revoked'):client.signature_status(('[GNUPG:] '+status+'\n').encode(),'A'*40,datetime(2026,10,18,tzinfo=timezone.utc))
 def test_metadata_stage_changes_only_immediate_issuance_operands(self):
  for case,code in self.codes.items():
   tree=ast.parse((code/'scripts/ci/full-root-upgrade/construct_repository.py').read_bytes());stage=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='stage')
   issuance=[n for n in stage.body if isinstance(n,ast.Assign)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Name)and n.value.func.id=='fresh_test_metadata_window'];self.assertEqual(len(issuance),1);stage.body.remove(issuance[0])
   for n in ast.walk(stage):
    if isinstance(n,ast.keyword)and n.arg in ('issued_utc','expires_utc'):
     self.assertIsInstance(n.value,ast.Name);self.assertEqual(n.value.id,n.arg);n.value=ast.Attribute(value=ast.Name(id='args',ctx=ast.Load()),attr=n.arg,ctx=ast.Load())
   self.assertEqual(hashlib.sha256(ast.dump(stage,include_attributes=False).encode()).hexdigest(),'122d9842b6f76631782da012ebd199e9e0bab7d917ff67c814d4f15fc8f71cf7')

if __name__=='__main__':unittest.main(verbosity=2)
