"""Owned local DATA fixtures only; no Source imports, HTTP or package actors."""
import ast,copy,hashlib,json,os,runpy,socket,subprocess,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent;EMITTED=Path(os.environ['CORE622_RESILIENCE_SOURCE']).resolve()
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
class CheckpointControls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='checkpoint-control-',dir=D);self.root=Path(self.tmp.name);self.code=(D/'runner-checkpoint.py.in').read_bytes();self.C=types.ModuleType('_checkpoint_data_fixture');self.C.__file__=str(D/'runner-checkpoint.py.in');exec(compile(self.code,self.C.__file__,'exec'),vars(self.C));C=self.C;source='6'*40;run='1234567';ref='codex/checkpoint-data-control';identity=dict(source=source,ref=ref,run=int(run),attempt=1);nonce=hashlib.sha256(('current607-core622:'+source+':'+run).encode()).hexdigest()[:32];self.env=dict(RUNNER_TEMP=str(self.root),GITHUB_OUTPUT=str(self.root/'step-output'),GITHUB_SHA=source,SOURCE_SHA=source,WORKFLOW_SHA=source,GITHUB_RUN_ID=run,GITHUB_RUN_ATTEMPT='1',GITHUB_REF_NAME=ref,GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',RUNNER_ARCH='ARM64',ORIGINAL_BUILD_OUTCOME='success',FDK_PAIR_OUTCOME='success');(self.root/'step-output').write_bytes(b'');image='sha256:'+'a'*64;lock='b'*64;self.put('native-evidence/result.json',dict(status='native-builds-and-byte-comparison-pass',mode='build',native_build='PASS',reviewed_inputs_sha256=C.INPUTS,reviewed_recipes_sha256=C.RECIPES,bootstrap_script_sha256=C.DRIVER));self.put('native-evidence/runner.json',dict(run_id=run,commit=C.BUILDER,repository=self.env['GITHUB_REPOSITORY'],runner_arch=None,docker_server_arch='aarch64',bootstrap_script_sha256=C.DRIVER));self.put('native-evidence/bootstrap.json',dict(status='image-provisioned',image_id=image,packages_lock_sha256=lock,inputs_sha256=C.INPUTS));self.put('fdk-evidence/result.txt',b'FDK_PAIR=PASS\nEXIT=0\n');reviewed=dict(PKGBUILD=C.FDK_RECIPE,LICENSE='c'*64);self.put('fdk-evidence/template-inputs.json',reviewed);self.put('fdk-evidence/reviewed-inputs.json',reviewed)
  for folder,label,prefix in C.PAIRS:
   artifact=label+'-1-1-any.pkg.tar.xz';checksum='d'*64;compare=dict(status='contents-reproduced',errors=[],packages={artifact:dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=False)});self.put(folder+'/'+(prefix+'-compare.json'if prefix else'compare.json'),compare)
   for i in(1,2):
    base=folder+'/'+(prefix+'-'+str(i)if prefix else'build-'+str(i));validation=dict(errors=[],artifacts=[dict(artifact=artifact,sha256=checksum,errors=[],private_ignored='/private/SECRET_VALIDATION')]);raw=enc(validation);self.put(base+'/validation.json',raw);p=dict(status='built-package-static-pass',exit_code=0,mode='native',network='none',image=image,image_id=image,expected_packages_sha256=lock,source_date_epoch=1791748800,recipe_inputs=reviewed if label=='fdk'else dict(PKGBUILD='e'*64),recipe_metadata={'name':label},entry_script_sha256='f'*64,clean_environment_id='cachy-asahi-'+('%016x'%i),files={'validation.json':C.pin(raw)['sha256']},artifacts={artifact:checksum},command=['DO_NOT_EXPORT','/private/SECRET_COMMAND']);self.put(base+'/provenance.json',p)
 def tearDown(self):self.tmp.cleanup()
 def put(self,name,value):
  p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(value if type(value)is bytes else enc(value))
 def mutate(self,name,call):
  p=self.root/name;v=json.loads(p.read_bytes());call(v);p.write_bytes(enc(v))
 def value(self):return self.C.projection(self.root,self.env)
 def stage(self):
  with patch.dict(os.environ,self.env,clear=True):self.C.stage()
 def test_valid_finite_projection_has_no_private_content_or_actor(self):
  with patch.object(socket,'socket',side_effect=AssertionError('network actor denied')),patch.object(subprocess,'Popen',side_effect=AssertionError('process actor denied')),patch.object(os,'system',side_effect=AssertionError('shell actor denied')):
   value=self.value();self.stage()
  self.assertEqual(set(value['source_roles']),set(self.C.ROLES));self.assertEqual(len(value['source_roles']),31);self.assertFalse(value['acceptance']);self.assertEqual(value['original_metadata_bodies'],'NOT_CARRIED_HASHES_AND_FINITE_PROJECTION_ONLY');raw=(self.root/'core622-pre-installer-public/checkpoint.json').read_bytes();self.assertNotIn(b'SECRET',raw);self.assertNotIn(b'/private',raw);export=json.loads((self.root/'core622-pre-installer-public/export.json').read_bytes());self.assertEqual(export['files'],{'checkpoint.json':self.C.pin(raw)});self.assertEqual({p.name for p in(self.root/'core622-pre-installer-public').iterdir()},{'checkpoint.json','export.json'});self.assertEqual((self.root/'step-output').read_bytes(),b'ready=true\n')
 def test_identity_outcome_original_source_refusals(self):
  for kind in('source','run','attempt','step','builder','driver','rawarch'):
   env=copy.deepcopy(self.env);original=(self.root/'native-evidence/runner.json').read_bytes()
   if kind=='source':env['SOURCE_SHA']='7'*40
   elif kind=='run':env['GITHUB_RUN_ID']='1234568'
   elif kind=='attempt':env['GITHUB_RUN_ATTEMPT']='2'
   elif kind=='step':env['FDK_PAIR_OUTCOME']='failure'
   elif kind=='builder':self.mutate('native-evidence/runner.json',lambda v:v.update(commit='8'*40))
   elif kind=='driver':self.mutate('native-evidence/runner.json',lambda v:v.update(bootstrap_script_sha256='9'*64))
   elif kind=='rawarch':self.mutate('native-evidence/runner.json',lambda v:v.update(runner_arch='x86_64'))
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.C.projection(self.root,env)
   self.put('native-evidence/runner.json',original)
 def test_whole_validation_pin_and_pair_equality_refusals(self):
  cases=[('native-evidence/result.json',lambda v:v.update(native_build='NOT RUN')),('fdk-evidence/compare.json',lambda v:next(iter(v['packages'].values())).update(bytes_equal=False)),('native-evidence/'+self.C.NAMES[0]+'-2/provenance.json',lambda v:v.update(clean_environment_id='cachy-asahi-0000000000000001')),('fdk-evidence/build-1/validation.json',lambda v:v.update(ignored_change=True)),('fdk-evidence/build-1/provenance.json',lambda v:v.update(artifacts={'forged':'0'*64})),('fdk-evidence/reviewed-inputs.json',lambda v:v.update(PKGBUILD='0'*64))]
  for name,change in cases:
   before=(self.root/name).read_bytes();self.mutate(name,change)
   with self.subTest(role=name),self.assertRaises(ValueError):self.value()
   self.put(name,before)
 def test_missing_alias_and_size_refusals(self):
  name='native-evidence/result.json';p=self.root/name;raw=p.read_bytes();p.unlink()
  with self.assertRaises(FileNotFoundError):self.value()
  outside=self.root/'outside-private';outside.write_bytes(raw);p.symlink_to(outside)
  with self.assertRaises(ValueError):self.value()
  p.unlink();os.link(outside,p)
  with self.assertRaises(ValueError):self.value()
  p.unlink();outside.unlink();self.put(name,raw)
  with p.open('r+b')as f:f.truncate(4*1024**2+1)
  with self.assertRaises(ValueError):self.value()
 def test_strict_json_duplicate_and_nonfinite_refusals(self):
  for raw in(b'{"native_build":"PASS","native_build":"PASS"}',b'{"v":NaN}',b'{"v":Infinity}',b'{"v":1e999}'):
   self.put('native-evidence/result.json',raw)
   with self.subTest(raw=raw),self.assertRaises(ValueError):self.value()
 def test_baseline_has_no_clock_dependency_or_fabricated_receipts(self):
  self.assertFalse((self.root/'core622-job-clock.json').exists());value=self.value();self.assertEqual(value['schema'],2);self.assertEqual(value['version'],'core622-maintained-prerequisite-metadata-v1');self.assertEqual(value['baseline_source'],'ad09020a776c93fad3c2625c836a99cbde0c83b9');self.assertIs(value['job_clock_available'],False);self.assertIsNone(value['job_clock']);self.assertIs(value['native_phase_clock_available'],False);self.assertEqual((value['workflow_job_timeout_minutes'],value['installer_timeout_seconds'],value['installer_kill_grace_seconds'],value['installer_step_timeout_minutes']),(350,15600,60,270));self.assertNotIn(b'core622-job-clock.json',self.code);self.assertNotIn(b'core622-native-phase.json',self.code)
  self.put('core622-job-clock.json',b'NOT_A_CLOCK_PRIVATE');self.put('core622-native-phase.json',b'NOT_A_PHASE_PRIVATE');self.assertEqual(self.value(),value)
 def test_aggregate_cap_and_no_false_ready(self):
  for name in self.C.ROLES[:5]:
   p=self.root/name;raw=p.read_bytes();p.write_bytes(raw+b' '*(4*1024**2-len(raw)))
  with self.assertRaises(ValueError):self.stage()
  self.assertEqual((self.root/'step-output').read_bytes(),b'');self.assertFalse((self.root/'core622-pre-installer-public').exists())
 def test_extra_private_inputs_not_read_and_extra_staged_file_refuses(self):
  self.put('native-evidence/context/DO_NOT_READ',b'PRIVATE_CONTEXT_SECRET');self.put('native-evidence/DO_NOT_READ.log',b'PRIVATE_LOG_SECRET');seen=[];old=self.C.stable
  def read(path,cap):seen.append(Path(path).relative_to(self.root).as_posix());return old(path,cap)
  with patch.object(self.C,'stable',side_effect=read):self.value()
  self.assertEqual(set(seen),set(self.C.ROLES));oldwrite=self.C.write
  def write(path,raw):
   oldwrite(path,raw)
   if path.name=='export.json':(path.parent/'UNDECLARED').write_bytes(b'no')
  with patch.object(self.C,'write',side_effect=write),self.assertRaises(ValueError):self.stage()
  self.assertEqual((self.root/'step-output').read_bytes(),b'')
 def test_existing_target_and_invalid_result_never_ready(self):
  target=self.root/'core622-pre-installer-public';target.mkdir();sentinel=target/'BORROWED';sentinel.write_bytes(b'keep')
  with self.assertRaises(ValueError):self.stage()
  self.assertEqual(sentinel.read_bytes(),b'keep');sentinel.unlink();target.rmdir();self.put('fdk-evidence/result.txt',b'FDK_PAIR=PASS\nEXIT=1\n')
  with self.assertRaises(ValueError):self.stage()
  self.assertFalse(target.exists());self.assertEqual((self.root/'step-output').read_bytes(),b'')
 def test_inline_code_exact_and_actor_denied_ast(self):
  text=(EMITTED/'workflow.yml.in').read_text();start="          python3 -I -B - <<'PYCHECKPOINT'\n";part=text.split(start,1)[1].split('          PYCHECKPOINT\n',1)[0];code=''.join(line[10:]+'\n'for line in part.splitlines());self.assertEqual(code.encode(),self.code);tree=ast.parse(code);imports={n.module for n in ast.walk(tree)if isinstance(n,ast.ImportFrom)}|{a.name for n in ast.walk(tree)if isinstance(n,ast.Import)for a in n.names};self.assertEqual(imports,{'hashlib','json','math','os','re','stat','sys','pathlib'});self.assertFalse(any(isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id in('exec','eval','compile','__import__')for n in ast.walk(tree)))
 def reader(self):
  module=types.ModuleType('_maintained_checkpoint_contract');path=D/'checkpoint_contract.py';module.__file__=str(path);exec(compile(path.read_bytes(),str(path),'exec'),vars(module));return module
 def test_reader_closed2_source_reported_scope_and_exact_pins(self):
  self.stage();R=self.reader();folder=self.root/'core622-pre-installer-public';bodies={n:(folder/n).read_bytes()for n in('checkpoint.json','export.json')};identity=dict(source=self.env['GITHUB_SHA'],ref=self.env['GITHUB_REF_NAME'],run=int(self.env['GITHUB_RUN_ID']),attempt=1);result=R.validate(bodies,identity);self.assertEqual(result['status'],'SOURCE_REPORTED_COMPLETED_PREREQUISITE_METADATA_DATA_ONLY');self.assertFalse(result['acceptance']);self.assertFalse(result['native_acceptance']);self.assertEqual(result['installer_acceptance'],'NOT_ESTABLISHED');self.assertEqual(result['original_metadata_bodies'],'NOT_CARRIED_NOT_INDEPENDENTLY_REPLAYED');self.assertEqual(set(R.ROLES),set(self.C.ROLES))
  for kind in('extra','missing','pin','identity'):
   bad=dict(bodies);expected=dict(identity)
   if kind=='extra':bad['PRIVATE.log']=b'secret'
   elif kind=='missing':bad.pop('checkpoint.json')
   elif kind=='pin':bad['checkpoint.json']+=b' '
   else:expected['source']='7'*40
   with self.subTest(kind=kind),self.assertRaises(ValueError):R.validate(bad,expected)
 def test_reader_semantic_refusals_even_when_export_pin_is_recomputed(self):
  self.stage();R=self.reader();folder=self.root/'core622-pre-installer-public';original={n:(folder/n).read_bytes()for n in('checkpoint.json','export.json')};identity=dict(source=self.env['GITHUB_SHA'],ref=self.env['GITHUB_REF_NAME'],run=int(self.env['GITHUB_RUN_ID']),attempt=1)
  for kind in('schema','baseline','clock','phase','caps','role','reports','private','scope','nonce','overflow'):
   value=json.loads(original['checkpoint.json']);export=json.loads(original['export.json'])
   if kind=='schema':value['schema']=1
   elif kind=='baseline':value['baseline_source']='25d7'+'0'*36
   elif kind=='clock':value['job_clock_available']=True;value['job_clock']={'FAKE':'clock'}
   elif kind=='phase':value['native_phase_clock_available']=True
   elif kind=='caps':value['installer_timeout_seconds']+=1
   elif kind=='role':value['source_roles']['native-evidence/PRIVATE.log']=value['source_roles'].pop('native-evidence/result.json')
   elif kind=='reports':value['source_reports']['fdk']['package_count']=True
   elif kind=='private':value['private_path']='/private/SECRET'
   elif kind=='scope':value['native_acceptance']=True
   elif kind=='nonce':value['nonce']='0'*32
   raw=enc(value)
   if kind=='overflow':raw=raw.replace(b'"source_metadata_bytes": ',b'"source_metadata_bytes": 1e999,"IGNORED": ',1)
   export['files']['checkpoint.json']=R.pin(raw);export['bytes']=len(raw);bad={'checkpoint.json':raw,'export.json':enc(export)}
   with self.subTest(kind=kind),self.assertRaises(ValueError):R.validate(bad,identity)
def run_controls():
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CheckpointControls));value=dict(status='PASS'if result.wasSuccessful()else'FAIL',tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),scope='LOCAL_DATA_AND_WORKFLOW_CONSTRUCTION_ONLY',Source_imports=0,HTTP=0,native=0,acceptance=False)
 if not result.wasSuccessful():raise AssertionError(value)
 return value
def main():
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CheckpointControls));return int(not result.wasSuccessful())
if __name__=='__main__':raise SystemExit(main())

if __name__=='__main__':
 value=run_controls();print(json.dumps(value,sort_keys=True))
