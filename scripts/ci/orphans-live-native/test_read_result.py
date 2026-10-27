#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic offline reader controls; no archives built, actors or acquisition."""
import copy,hashlib,importlib.util,json,os,shutil,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('orphans03_result_reader_controls',HERE/'read_result.py');R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
GOOD_LOG='==> Starting check()\n'+''.join('Ran '+str(n)+' tests in 0.1s\nOK\n' for n in (20,25,8,24,25,7))

class Reader(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)/'originals';self.root.mkdir();self.reviewed=Path(self.tmp.name)/'reviewed';self.reviewed.mkdir()
 def write(self,name,value):
  path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(value if type(value) is bytes else R.encoded(value));return path
 def source(self):
  data={R.RECIPE+'/'+n:('synthetic source-only '+n+'\n').encode() for n in R.PRODUCT_FILES}
  data.update({R.LANE+'/job.py':b'synthetic job\n',R.LANE+'/workflow.yml':b'@JOB_SHA256@ @MANIFEST_SHA256@\n','scripts/build/container-entry.sh':b'synthetic entry\n',R.LANE+'/read_result.py':b'synthetic source-only reader\n',R.LANE+'/fixture/PKGBUILD':b'synthetic inert recipe\n',R.LANE+'/fixture/LICENSE':b'synthetic inert license\n'})
  leaf={n:dict(bytes=len(v),sha256=hashlib.sha256(v).hexdigest()) for n,v in data.items()}
  manifest=dict(schema_version=1,files=leaf,actual_source=None,actual_ref=None,actual_run=None)
  data[R.LANE+'/source-manifest.json']=R.encoded(manifest);rendered=data[R.LANE+'/workflow.yml'].decode().replace('@JOB_SHA256@',leaf[R.LANE+'/job.py']['sha256']).replace('@MANIFEST_SHA256@',hashlib.sha256(data[R.LANE+'/source-manifest.json']).hexdigest()).encode()
  for name in R.WORKFLOWS:data[name]=rendered
  files={n:dict(bytes=len(v),sha256=hashlib.sha256(v).hexdigest(),mode='100644') for n,v in data.items()}
  for name,value in data.items():
   self.write('source/'+('source-manifest.json' if name==R.LANE+'/source-manifest.json' else name),value);p=self.reviewed/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(value)
  self.auth=dict(source_sha='a'*40,tree=R.git_tree(files,data.__getitem__),files=files);self.manifest=manifest;self.files=files
  self.write('source-mode-map.json',{n:r['mode'] for n,r in files.items()});self.write('source-tree.json',dict(tree=self.auth['tree'],files=len(files),source_map_sha256=hashlib.sha256(R.encoded(files)).hexdigest()))
  return files
 def seal(self):
  files={p.relative_to(self.root).as_posix():dict(bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in self.root.rglob('*') if p.is_file() and p.name!='retention.json'}
  return self.write('retention.json',dict(status=R.RETENTION,scope=R.SCOPE,files=files,total_bytes=sum(r['bytes'] for r in files.values()),errors=[],hardware='NOT_RUN',release='NOT_ADMITTED',actual_source=None,actual_ref=None,actual_run=None))
 def test_exact109_log_and_old53_missing_skip_failure_refusal(self):
  p=self.write('log',GOOD_LOG.encode());self.assertEqual(R.check_log(p)['count'],109)
  for bad in (GOOD_LOG[:GOOD_LOG.index('Ran 24')],GOOD_LOG.replace('Ran 24','Ran 23'),GOOD_LOG+'OK (skipped=1)\n',GOOD_LOG+'FAILED\n',GOOD_LOG.replace('OK\n','',1)):
   p.write_text(bad)
   with self.assertRaises(ValueError):R.check_log(p)
 def test_git_tree_uses_real_blob_modes_and_directory_order(self):
  self.assertEqual(R.git_tree({},lambda _:b''),'4b825dc642cb6eb9a060e54bf8d69288fbee4904')
  data={'a.z':b'one','a/x':b'two'};files={n:dict(mode='100644') for n in data};normal=R.git_tree(files,data.__getitem__);files['a/x']['mode']='100755';self.assertNotEqual(normal,R.git_tree(files,data.__getitem__))
 def test_complete_index_refuses_missing_extra_tampered_and_hardlinks(self):
  p=self.write('raw',b'inert');self.seal();R.verify_index(self.root)
  p.write_bytes(b'changed')
  with self.assertRaises(ValueError):R.verify_index(self.root)
  p.write_bytes(b'inert');self.seal();self.write('unindexed',b'extra')
  with self.assertRaises(ValueError):R.verify_index(self.root)
  (self.root/'unindexed').unlink();self.seal();(self.root/'alias').hardlink_to(p)
  with self.assertRaises(ValueError):R.verify_index(self.root)
 def test_index_refuses_duplicate_nonfinite_and_unsafe_names(self):
  for bad in (b'{"status":1,"status":2}',b'{"x":NaN}'):
   self.write('retention.json',bad)
   with self.assertRaises(ValueError):R.verify_index(self.root)
  for name in ('../escape','/absolute','a//b','a/./b','.git/config','.'):
   with self.assertRaises(ValueError):R.ordinary(name)
 def test_exact_source20_modes_tree_and_aliases_join_external_authorization(self):
  self.source();R.verify_source(self.root,self.auth,'a'*40)
  p=self.root/'source-mode-map.json';value=R.read(p);value[next(iter(value))]='100755';p.write_bytes(R.encoded(value))
  with self.assertRaises(ValueError):R.verify_source(self.root,self.auth,'a'*40)
 def test_resealed_source_tamper_cannot_change_trusted_authorization(self):
  self.source();p=R.source_path(self.root,R.RECIPE+'/live.py');p.write_bytes(b'forged source');self.seal()
  with self.assertRaises(ValueError):R.verify_source(self.root,self.auth,'a'*40)
 def test_missing_product_file_and_old_version_path_refuse(self):
  self.source();auth=copy.deepcopy(self.auth);auth['files'].pop(R.RECIPE+'/live.py')
  with self.assertRaises(ValueError):R.verify_source(self.root,auth,'a'*40)
  auth=copy.deepcopy(self.auth);auth['files']['packages/tools/cachy-asahi-orphans/PKGBUILD']=auth['files'].pop(R.RECIPE+'/PKGBUILD')
  with self.assertRaises((ValueError,OSError)):R.verify_source(self.root,auth,'a'*40)
 def test_reviewed_helper_copy_must_match_published_source(self):
  self.source();R.verify_reviewed_source(self.reviewed,self.files);path=self.reviewed/R.LANE/'read_result.py';saved=path.read_bytes();path.write_bytes(b'changed')
  with self.assertRaises(ValueError):R.verify_reviewed_source(self.reviewed,self.files)
  path.write_bytes(saved);(self.reviewed/'unreviewed.py').write_text('never imported')
  with self.assertRaises(ValueError):R.verify_reviewed_source(self.reviewed,self.files)
 def fixture(self):
  self.source();spec=importlib.util.spec_from_file_location('reader_real_lifecycle_fixture',HERE/'test_lifecycle.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture);self.actor=fixture.M;life=fixture.fixture_result()
  def node(kind='file',mode=0o644,sha='1'*64):return dict(kind=kind,dev=1,ino=2,mode=mode,uid=0,gid=0,links=1,bytes=1,mtime_ns=1,ctime_ns=1,**({'sha256':sha} if kind=='file' else {}))
  configured=node(mode=0o640);life['configuration_before']=configured;life['installed_backend']['sha256']=self.files[R.RECIPE+'/live.py']['sha256']
  before={'.':node('directory',0o700),'etc/operator-owned.conf':configured,'usr/share/orphans3-fixture/caa-orphans3-leaf-a.txt':node(),'usr/share/licenses/caa-orphans3-leaf-a/LICENSE':node(),'var/lib/pacman/local/caa-orphans3-leaf-a-1-1/desc':node()};after={k:v for k,v in before.items() if k not in self.actor.positive_removed(before)}
  for name,row in life['maps'].items():
   rows=after if name in ('positive-after','final-target') else before;p=self.write('runtime/lifecycle-output/'+row['path'],rows);row.update(sha256=R.digest(p),nodes=len(rows))
  packages=[dict(name='base-'+str(n),version='1-1') for n in range(574)];base_map=dict(packages=packages,nodes={'held':{'sha256':'1'*64}})
  for field in ('base_before','base_after'):
   row=life[field];p=self.write('runtime/lifecycle-output/'+row['path'],base_map);row.update(sha256=R.digest(p),nodes=1)
  life['base_preservation_sha256']=hashlib.sha256(json.dumps(base_map,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  policy=life['policy_contract'];self.write('runtime/lifecycle-output/'+policy['path'],policy['value'])
  for event in life['events']:
   if event['durable_result'] is not None:self.write('runtime/lifecycle-output/'+event['durable_result'],event['result'])
  self.actor.validate_lifecycle(life);self.life=life;self.write('runtime/lifecycle-output/lifecycle.json',life)
  base_inventory={row['name']:row['version'] for row in packages};lock=''.join(n+' '+v+'\n' for n,v in sorted(base_inventory.items())).encode();self.base_pin=hashlib.sha256(lock).hexdigest();self.write('base/installed-packages.lock',lock);self.write('runtime/lifecycle-inputs/base.json',base_inventory)
  self.identity=dict(source_sha='a'*40,run_id='123',job_id='456',run_attempt='1',artifact_name='orphans03-explicit-target-123-1',run_conclusion='success',job_conclusion='success')
  job=hashlib.sha256(('product-build-pair:123:1:'+'a'*40).encode()).hexdigest()[:16];consumer=hashlib.sha256(('orphans03-consumer:123:1:'+'a'*40).encode()).hexdigest()[:32];image='sha256:'+'b'*64
  proof=dict(status='SOURCE_PROOF_PASS',source_sha='a'*40,workflow_sha='a'*40,run_id='123',run_attempt='1',artifact_name=self.identity['artifact_name'],source_files=len(self.manifest['files']),source_total_files=len(self.files),source_tree=self.auth['tree'],source_map_sha256=hashlib.sha256(R.encoded(self.files)).hexdigest(),manifest_sha256=R.digest(self.root/'source/source-manifest.json'),job_token=job,consumer_token=consumer);self.write('source-proof.json',proof)
  cleanup=dict(status='PASS',build='COMPLETED',probe=dict(name='cachy-asahi-574-probe-'+job,cid='c'*64,absence_verified=True),image=dict(id=image,absence_verified=True));base=dict(status='PASS_NATIVE_OFFLINE_574_TRANSACTION',image=image,acquired=1153,failures=[],ownership=dict(token=job),owned_cleanup=cleanup);self.write('base/report.json',base);self.write('base/retained-inputs.json',dict(status='SYNTHETIC_TRANSPORT_ONLY'))
  self.comparison=dict(status='contents-reproduced',errors=[],packages={R.PRODUCT+'-0.3.0-1-any.pkg.tar.zst':dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)})
  self.payload={str(n):dict(mode=0o644) for n in range(12)};self.inputs={n.removeprefix(R.RECIPE+'/'):r['sha256'] for n,r in self.files.items() if n.startswith(R.RECIPE+'/')};self.metadata=dict(pkgname=[R.PRODUCT],pkgver=['0.3.0'],pkgrel=['1'],arch=['any'],source=sorted(set(R.PRODUCT_FILES)-{'PKGBUILD','.SRCINFO'}));self.package_version='0.3.0-1'
  def package(path):
   name=Path(path).name.split('-1-1-any.pkg.tar.',1)[0]
   if name in self.actor.FIXTURES:
    member=dict(type='0',mode=0o644,uid=0,gid=0,sha256=self.files[R.LANE+'/fixture/LICENSE']['sha256'])
    return dict(sha256=R.digest(path),errors=[],elf=[],metadata={'.PKGINFO':dict(pkgname=[name],pkgver=['1-1'],arch=['any'])},members={'usr/share/orphans3-fixture/'+name+'.txt':member,'usr/share/licenses/'+name+'/LICENSE':member})
   return dict(sha256=R.digest(path),errors=[],elf=[],metadata={'.PKGINFO':dict(pkgname=[R.PRODUCT],pkgver=[self.package_version],arch=['any']),'.BUILDINFO':{}},members=copy.deepcopy(self.payload))
  self.package=package
  def pair_gate(value):R.need(value.get('status')=='contents-reproduced' and value.get('errors')==[] and all(all(row.get(k) is True for k in ('installed_contents_equal','pkginfo_equal','bytes_equal','buildinfo_equal')) for row in value['packages'].values()),'pair failed')
  C=SimpleNamespace(recipe=lambda *_:dict(metadata=self.metadata,input_sha256=self.inputs),BASE=self.base_pin,LABEL='org.cachy-asahi.orphans03-native.job',CONSUMER_TOKEN_PREFIX='orphans03-consumer:',FIXTURES=self.actor.FIXTURES,check_log=lambda p,_:R.check_log(p),payload=lambda *_:copy.deepcopy(self.payload),pair_gate=pair_gate)
  self.helpers=(C,SimpleNamespace(package=package),SimpleNamespace(bind_artifact=lambda m,p,_:[] if p['metadata']['.PKGINFO']['pkgver']==['0.3.0-1'] else ['old package']),SimpleNamespace(compare=lambda *_:copy.deepcopy(self.comparison)),self.actor,SimpleNamespace(validate_transport=lambda _,value:dict(status='SYNTHETIC_TRANSPORT_REPLAY') if value.get('status')=='SYNTHETIC_TRANSPORT_ONLY' else R.need(False,'missing transport')))
  actors=['cachy-asahi-product-'+c*32 for c in ('1','2','3')]+['cachy-asahi-product-lifecycle-'+'4'*32];self.actors=actors
  retired=dict(ownership='RETIRED',leader_reaped=True,observed_returncode=0,log_drained=True,log_error=None,error=None);commands=[];builds=[]
  for side,container in zip(('a','b'),actors):
   prefix='runtime/'+R.PRODUCT+'-'+side;name=R.PRODUCT+'-0.3.0-1-any.pkg.tar.zst';p=self.write(prefix+'/artifacts/'+name,b'SYNTHETIC_NOT_AN_ARCHIVE');digest=R.digest(p);command=['docker','run','--name',container,'--network=none','--pull=never','--platform=linux/arm64','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--user','1001:1001']
   record=dict(status='built-package-static-pass',mode='native',image=image,image_id=image,recipe_inputs=self.inputs,recipe_metadata=self.metadata,clean_environment_id=container,command=command,expected_packages_sha256=self.base_pin,entry_script_sha256=self.files['scripts/build/container-entry.sh']['sha256'],artifacts={name:digest})
   self.write(prefix+'/provenance.json',record);self.write(prefix+'/expected-packages.lock',lock);self.write(prefix+'/artifacts/packages.lock',lock);self.write(prefix+'/artifacts/environment.txt',b'Linux synthetic aarch64 GNU/Linux\n4096\nsynthetic fixture\n');self.write(prefix+'/build.log',GOOD_LOG.encode())
   for n in self.inputs:self.write(prefix+'/inputs/'+n,(self.reviewed/R.RECIPE/n).read_bytes())
   validation=dict(package=package(p),payload=self.payload,tests=R.check_log(self.root/prefix/'build.log'),errors=[]);self.write(prefix+'/validation.json',validation);commands.append(dict(argv=command,log=R.PRODUCT+'-'+side+'/build.log',exitcode=0,retirement=retired));builds.append(dict(archive=name,sha256=digest,tests=validation['tests']))
  commands.extend([dict(argv=['synthetic'],log=n,exitcode=0,retirement=retired) for n in ('fixtures/build.log','lifecycle.log')]);runtime=dict(status=R.RUNTIME,lifecycle=life,base_image=image,base_count=574,ownership_token=consumer,base_lock_sha256=self.base_pin,commands=commands,pair=dict(builds=builds,comparison=self.comparison));self.write('runtime/report.json',runtime);self.write('runtime/comparison.json',self.comparison)
  self.write('runtime/owner.json',dict(schema_version=1,image=image,label=C.LABEL,token=consumer,containers=actors));self.write('ordered-cleanup.json',dict(status='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP',authority='PASS_ABSENT_AFTER_ACTORS_AND_PRODUCER',producer=cleanup,consumer=dict(status='PASS_CONSUMERS_RETIRED',containers=[dict(container=n,status='PASS',absence_verified=True) for n in reversed(actors)])))
  candidate=builds[0];self.write('runtime/lifecycle-inputs/'+candidate['archive'],b'SYNTHETIC_NOT_AN_ARCHIVE');self.write('runtime/lifecycle-inputs/'+candidate['archive']+'.sig',b'SYNTHETIC_SIGNATURE')
  fixtures={}
  for n in self.actor.FIXTURES:
   name=n+'-1-1-any.pkg.tar.zst';p=self.write('runtime/lifecycle-inputs/'+name,b'SYNTHETIC_FIXTURE');self.write('runtime/lifecycle-inputs/'+name+'.sig',b'SYNTHETIC_SIGNATURE');fixtures[n]=dict(archive=name,sha256=R.digest(p))
  self.write('runtime/lifecycle-inputs/control.json',dict(signer='A'*40,candidate={k:candidate[k] for k in ('archive','sha256')},fixtures=fixtures));self.write('runtime/authority.json',dict(directory='test-signing',mode=0o700,signer='A'*40))
  runtime=R.read(self.root/'runtime/report.json');runtime['fixtures']=fixtures;self.write('runtime/report.json',runtime);self.write('runtime/fixtures/fixture-packages.json',fixtures);self.write('runtime/fixtures/expected-packages.lock',lock);self.write('runtime/fixtures/artifacts/packages.lock',lock)
  for n in ('PKGBUILD','LICENSE'):self.write('runtime/fixtures/inputs/'+n,(self.reviewed/R.LANE/'fixture'/n).read_bytes())
  for row in fixtures.values():self.write('runtime/fixtures/artifacts/'+row['archive'],b'SYNTHETIC_FIXTURE')
  self.seal()
 def validate(self):
  with patch.object(R,'_helpers',return_value=self.helpers):return R.validate(self.root,authorization=self.auth,identity=self.identity,source_sha='a'*40,run_id='123',job_id='456',run_attempt='1',reviewed_source=self.reviewed)
 def update(self,name,change):
  value=R.read(self.root/name);change(value);self.write(name,value);self.seal()
 def test_complete_offline_reader_replays_raw_joins_with_real_lifecycle_gate(self):
  self.fixture();result=self.validate();self.assertEqual(result['package_checks_per_build'],109);self.assertEqual(result['product_files'],20);self.assertEqual(result['hardware'],'NOT_RUN');self.assertEqual(result['host_live_target_removal'],'NOT_PROVEN')
 def test_missing_failed_or_mismatched_original_identity_refuses(self):
  self.fixture()
  for key,value in (('job_conclusion',None),('run_conclusion','failure'),('job_id','999'),('artifact_name','old0.1')):
   original=self.identity[key];self.identity[key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):self.validate()
   self.identity[key]=original
 def test_wrong_proof_tree_map_artifact_or_attempt_refuses(self):
  self.fixture();path='source-proof.json';original=R.read(self.root/path)
  for key,value in (('source_tree','b'*40),('source_map_sha256','0'*64),('artifact_name','old'),('run_attempt','2')):
   changed=copy.deepcopy(original);changed[key]=value;self.write(path,changed);self.seal()
   with self.subTest(key=key),self.assertRaises(ValueError):self.validate()
  self.write(path,original)
 def test_unknown_command_retirement_and_missing_authority_refuse(self):
  self.fixture();self.update('runtime/report.json',lambda v:v['commands'][0]['retirement'].update(ownership='UNKNOWN',observed_returncode=None))
  with self.assertRaises(ValueError):self.validate()
  self.fixture_reset()
  self.update('ordered-cleanup.json',lambda v:v.update(authority='PRESERVED_OR_UNCERTAIN'))
  with self.assertRaises(ValueError):self.validate()
 def fixture_reset(self):
  shutil.rmtree(self.root);shutil.rmtree(self.reviewed);self.root.mkdir();self.reviewed.mkdir();self.fixture()
 def test_old_archive_version_and_53_checks_are_not0_3_evidence(self):
  self.fixture();self.update('runtime/'+R.PRODUCT+'-a/provenance.json',lambda v:v.update(artifacts={R.PRODUCT+'-0.1.0-2-any.pkg.tar.zst':'0'*64}))
  with self.assertRaises(ValueError):self.validate()
  self.fixture_reset();self.write('runtime/'+R.PRODUCT+'-a/build.log',GOOD_LOG[:GOOD_LOG.index('Ran 24')].encode());self.seal()
  with self.assertRaises(ValueError):self.validate()
 def test_duplicate_builder_or_extra_recipe_input_refuses(self):
  self.fixture();path='runtime/'+R.PRODUCT+'-b/provenance.json';value=R.read(self.root/path);value['clean_environment_id']=self.actors[0];value['command'][3]=self.actors[0];self.write(path,value);runtime=R.read(self.root/'runtime/report.json');runtime['commands'][1]['argv']=value['command'];self.write('runtime/report.json',runtime);self.seal()
  with self.assertRaises(ValueError):self.validate()
  self.fixture_reset();self.write('runtime/'+R.PRODUCT+'-a/inputs/unreviewed',b'extra');self.seal()
  with self.assertRaises(ValueError):self.validate()
 def test_durable_result_and_complete_negative_set_cannot_be_summary_only(self):
  self.fixture();self.update('runtime/lifecycle-output/reports/positive/result.json',lambda v:v.update(packages_committed='UNKNOWN'))
  with self.assertRaises(ValueError):self.validate()
  self.fixture_reset();life=R.read(self.root/'runtime/lifecycle-output/lifecycle.json');life['events'].pop();self.write('runtime/lifecycle-output/lifecycle.json',life);runtime=R.read(self.root/'runtime/report.json');runtime['lifecycle']=life;self.write('runtime/report.json',runtime);self.seal()
  with self.assertRaises(ValueError):self.validate()
 def test_forged_map_config_consistency_and_native_environment_refuse(self):
  self.fixture();name=next(iter(self.life['maps']));row=self.life['maps'][name];rows=R.read(self.root/'runtime/lifecycle-output'/row['path']);rows['etc/operator-owned.conf']['sha256']='f'*64;p=self.write('runtime/lifecycle-output/'+row['path'],rows);life=R.read(self.root/'runtime/lifecycle-output/lifecycle.json');life['maps'][name]['sha256']=R.digest(p);self.write('runtime/lifecycle-output/lifecycle.json',life);runtime=R.read(self.root/'runtime/report.json');runtime['lifecycle']=life;self.write('runtime/report.json',runtime);self.seal()
  with self.assertRaises(ValueError):self.validate()
  self.fixture_reset();self.write('runtime/'+R.PRODUCT+'-a/artifacts/environment.txt',b'Linux synthetic x86_64 GNU/Linux\n4096\nfixture\n');self.seal()
  with self.assertRaises(ValueError):self.validate()
 def test_wrong_payload_old_metadata_or_producer_absence_refuses(self):
  self.fixture();self.payload.pop('0')
  with self.assertRaises(ValueError):self.validate()
  self.fixture_reset();self.package_version='0.1.0-2'
  with self.assertRaises(ValueError):self.validate()
  self.fixture_reset();self.update('base/report.json',lambda v:v['owned_cleanup']['image'].update(absence_verified=False));ordered=R.read(self.root/'ordered-cleanup.json');ordered['producer']=R.read(self.root/'base/report.json')['owned_cleanup'];self.write('ordered-cleanup.json',ordered);self.seal()
  with self.assertRaises(ValueError):self.validate()
  self.fixture_reset();self.write('runtime/fixtures/inputs/LICENSE',b'changed fixture license');self.seal()
  with self.assertRaises(ValueError):self.validate()
  self.fixture_reset();candidate=R.read(self.root/'runtime/lifecycle-inputs/control.json')['candidate']['archive'];(self.root/'runtime/lifecycle-inputs'/(candidate+'.sig')).unlink();self.seal()
  with self.assertRaises((OSError,ValueError)):self.validate()

if __name__=='__main__':unittest.main()
