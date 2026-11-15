# SPDX-License-Identifier: MIT
"""Fenced DATA/model controls; never enter a Reader or Source actor role."""
import argparse,contextlib,copy,hashlib,importlib.util,io,json,os,stat,tarfile,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;SOURCE_ROOT=None
s=importlib.util.spec_from_file_location('retained_tests_reader',HERE/'reader.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P);S=P.S;R=P.R;D=P.D

def encoded(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def model():
 b=dict(source='a'*40,ref='refs/heads/codex/MODELED-r3',run='123',job='456',image='sha256:'+'b'*64,producer_report_sha256=None);domain=json.loads((SOURCE_ROOT/'lifecycle-code/domain.json').read_bytes());contract=json.loads((SOURCE_ROOT/'contract.json').read_bytes());a=dict(image=b['image'],source_map_sha256=contract['capsule']['source_map_sha256'],run='123-456',container='cachy-perl-lifecycle-123-456',base_labels={'MODELED':'OWNER'},inputs='/MODELED/inputs');ar=encoded(a);sha=D.pin(ar)['sha256'];cid='c'*64
 labels=dict(a['base_labels'],**{'cachy-asahi.perl-lifecycle.operation':'perl5423-installed-lifecycle-v1','cachy-asahi.perl-lifecycle.admission':sha,'cachy-asahi.perl-lifecycle.source':a['source_map_sha256']})
 conf=dict(NanoCpus=2000000000,Memory=2147483648,MemorySwap=2147483648,PidsLimit=128,ReadonlyRootfs=False,NetworkMode='none',Init=True,CapDrop=['ALL'],CapAdd=['CAP_'+v for v in domain['cap_add']],SecurityOpt=['no-new-privileges'],Privileged=False,Devices=[],Tmpfs=domain['tmpfs'])
 row=dict(Id=cid,Image=a['image'],Name='/'+a['container'],State=dict(Running=False,Pid=0,Status='exited',ExitCode=0,OOMKilled=False),HostConfig=conf,Config=dict(Labels=labels,User='0:0',Hostname='perl-installed-lifecycle',Entrypoint=['/usr/bin/python3'],Cmd=['-I','-B','/inputs/actor.py','--admission-sha256',sha,'--source-map-sha256',a['source_map_sha256']]),Mounts=[dict(Type='bind',Destination='/inputs',Source=a['inputs'],RW=False)])
 before=copy.deepcopy(row);before['State']['Status']='created';actor=dict(retained_output=copy.deepcopy(S.RETENTION),source_map_sha256=a['source_map_sha256'],admission_sha256=sha,status='PASS_FINITE_NATIVE_ARM4K_PERL_INSTALLED_LIFECYCLE',first_failure=None)
 data={'inner-admission.json':ar};rows=[];steps=['image','daemon-architecture','daemon-storage','create','inspect-before','run','inspect-after','export','cleanup-inspect','remove-owned']
 argv=[R.DOCKER+['image','inspect',b['image']],R.DOCKER+['info','--format','{{.Architecture}}'],R.DOCKER+['info','--format','{{.DockerRootDir}}'],R.create_argv(a,ar,sha,domain),R.DOCKER+['inspect',cid],R.DOCKER+['start','--attach',cid],R.DOCKER+['inspect',cid],R.DOCKER+['cp',cid+':'+S.RETENTION['path'],'-'],R.DOCKER+['inspect',cid],R.DOCKER+['rm',cid]]
 life=dict(natural_exit=True,forced_cleanup=False,retirement='REAPED',group_absent=True,ownership_lost=False,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,exit=0,elapsed_seconds=.1)
 for step,args in zip(steps,argv):
  data['installed/'+step+'.stdout']=encoded([before if step=='inspect-before'else row])if step in('inspect-before','inspect-after','cleanup-inspect')else(cid+'\n').encode()if step=='create'else b'';data['installed/'+step+'.stderr']=b'';rows.append(dict(step=step,argv=args,lifecycle=copy.deepcopy(life),returncode=0,success=True))
 report=dict(commands=rows,status='PASS_PRODUCED_PERL_INSTALLED_LIFECYCLE_DATA_REQUIRES_INDEPENDENT_ROOT_REVIEW',first_failure=None,source_map_sha256=a['source_map_sha256'],admission_sha256=sha,cleanup=dict(status='OWNED_CONTAINER_REMOVED',natural=True),container_id=cid)
 def finish():
  raw=encoded(actor);buf=io.BytesIO()
  with tarfile.open(fileobj=buf,mode='w')as t:
   n=tarfile.TarInfo('result');n.type=tarfile.DIRTYPE;n.mode=0o700;t.addfile(n);n=tarfile.TarInfo('result/report.json');n.mode=0o600;n.size=len(raw);t.addfile(n,io.BytesIO(raw))
  data['installed/export.stdout']=buf.getvalue();data['installed/data/report.json']=raw;report['actor_report']=D.pin(raw)
  for row in rows:
   for k in('stdout','stderr'):row[k]=D.pin(data['installed/'+row['step']+'.'+k])
  raw=encoded(report);data['installed/producer-report.json']=raw;b['producer_report_sha256']=D.pin(raw)['sha256'];return data
 finish();return dict(data=data,b=b,domain=domain,contract=contract,actor=actor,report=report,rows=rows,finish=finish)

class Controls(unittest.TestCase):
 def setUp(self):
  stack=contextlib.ExitStack();self.addCleanup(stack.close)
  for n in('subprocess.run','subprocess.Popen','socket.socket','socket.create_connection','fcntl.flock','os.pidfd_open','os.fork','os.system','ctypes.CDLL'):stack.enter_context(patch(n,side_effect=AssertionError('operational boundary forbidden'),create=True))
  stack.enter_context(patch.object(P,'review',side_effect=AssertionError('operational Reader forbidden')));stack.enter_context(patch.object(P,'delegate',side_effect=AssertionError('actual passive Source import forbidden')))
 def run_model(self,f):
  data=f['finish']()
  def get(n,cap=16*D.MIB):D.need(len(data[n])<=cap,'modeled DATA cap');return data[n]
  return R.review(get,f['b'],f['contract'],f['domain'])
 def test_actual252_whole_source_and241_232_original200_inverse(self):self.assertEqual(len(S.review(SOURCE_ROOT)[0]),252)
 def test_changed_or_missing_archived_actor_refuses(self):
  files,_,_=S.review(SOURCE_ROOT)
  for mode in('missing','changed'):
   bad=dict(files)
   if mode=='missing':bad.pop('previous-v2/lifecycle-code-actor.py')
   else:bad['previous-v2/lifecycle-code-actor.py']=(b'changed',0o644)
   with self.subTest(mode=mode),self.assertRaises((ValueError,KeyError)):S.inverse(bad,3)
 def test_NULL_binding_and_closed241_refuse(self):
  v=json.loads((HERE/'binding.TEMPLATE.json').read_bytes())
  with self.assertRaises(ValueError):P.binding(v)
  v['binding'].update(source='b4079a8a478afb0df8e634b555b3d2955a97bb9b',ref='refs/heads/codex/old',run='1',job='2',approval='a'*64,image='sha256:'+'b'*64,producer_report_sha256='c'*64)
  with patch.object(P,'SOURCE',v['binding']['source']),patch.object(P,'REF',v['binding']['ref']),self.assertRaises(ValueError):P.binding(v)
 def test_complete_ten_commands_plain_tar_and_retention_join(self):
  v=self.run_model(model());self.assertEqual(v['status'],'PASS_RETAINED_OUTPUT_DATA_JOINS_ONLY');self.assertFalse(v['package_runtime_acceptance']);self.assertIn('BOOLEAN_ASSERTION',v['proof_boundary'])
 def test_missing_old_or_changed_output_assertion_refuses(self):
  for key,value in [('path','/work/result'),('parent','/work'),('uid',1),('uid',False),('gid',1),('mode',0o755),('storage','TMPFS'),('parent_absent_before_entry',False),('same_filesystem_as_parent_root',False)]:
   f=model();f['actor']['retained_output'][key]=value
   with self.subTest(key=key,value=value),self.assertRaises(ValueError):self.run_model(f)
  f=model();f['actor'].pop('retained_output')
  with self.assertRaises(KeyError):self.run_model(f)
 def test_old_stopped_export_path_and_wrong_id_refuse(self):
  for path in('/work/result','f'*64+':'+S.RETENTION['path']):
   f=model();f['rows'][7]['argv'][-2]=f['report']['container_id']+':'+path if path.startswith('/')else path
   with self.subTest(path=path),self.assertRaises(ValueError):self.run_model(f)
 def test_reordered_export_before_stop_refuses(self):
  f=model();f['rows'][6],f['rows'][7]=f['rows'][7],f['rows'][6]
  with self.assertRaises(ValueError):self.run_model(f)
 def test_forced_nonzero_or_failure_report_refuses(self):
  for mode in('forced','exit','failure'):
   f=model()
   if mode=='forced':f['rows'][5]['lifecycle']['forced_cleanup']=True
   elif mode=='exit':f['rows'][7]['returncode']=1
   else:f['report']['status']='FAIL'
   with self.subTest(mode=mode),self.assertRaises(ValueError):self.run_model(f)
 def test_wrong_source_capsule_run_job_or_admission_refuses(self):
  for key,value in [('source_map_sha256','f'*64),('admission_sha256','f'*64)]:
   f=model();f['report'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):self.run_model(f)
  f=model();f['b']['job']='999'
  with self.assertRaises(ValueError):self.run_model(f)
 def test_container_owner_input_mount_or_resource_widening_refuses(self):
  for mode in('label','mount','network','caps','root_ro'):
   f=model();row=json.loads(f['data']['installed/inspect-after.stdout'])[0]
   if mode=='label':row['Config']['Labels']={}
   elif mode=='mount':row['Mounts'][0]['RW']=True
   elif mode=='network':row['HostConfig']['NetworkMode']='host'
   elif mode=='caps':row['HostConfig']['CapAdd'].append('CAP_SYS_ADMIN')
   else:row['HostConfig']['ReadonlyRootfs']=True
   f['data']['installed/inspect-after.stdout']=encoded([row])
   with self.subTest(mode=mode),self.assertRaises(ValueError):self.run_model(f)
 def test_zero_container_PID_and_exit_types_are_exact(self):
  for key in('Pid','ExitCode'):
   f=model();rows=json.loads(f['data']['installed/inspect-after.stdout']);rows[0]['State'][key]=False;f['data']['installed/inspect-after.stdout']=encoded(rows)
   with self.subTest(key=key),self.assertRaises(ValueError):self.run_model(f)
 def test_raw_export_report_must_join_retained_report(self):
  f=model();f['finish']();original=f['finish']
  def changed():v=original();v['installed/data/report.json']+=b' ';return v
  f['finish']=changed
  with self.assertRaises(ValueError):self.run_model(f)
 def test_fence_exact_capsule_write_modes_and_actor_denial(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);p=root/'payload';p.write_bytes(b'x');out=root/'out';file=out/'member';g=P.F.Fence({str(p)},{str(p):b'x'},{str(file):0o444},{str(out)});g.enabled=True
   g.check('open',(str(p),'r',os.O_RDONLY));g.check('open',(str(file),'x',os.O_WRONLY|os.O_CREAT|os.O_EXCL));g.check('os.mkdir',(str(out),0o700,-1));g.check('os.chmod',(str(file),0o444,-1))
   for event,args in [('open',(str(root/'foreign'),'w',os.O_WRONLY|os.O_CREAT)),('open',(str(file),'a',os.O_WRONLY|os.O_APPEND)),('os.chmod',(str(file),0o755,-1)),('subprocess.Popen',()),('socket.connect',()),('ctypes.dlopen',()),('compile',(b'actor',str(file))),('exec',(compile('pass',str(file),'exec'),))]:
    with self.subTest(event=event),self.assertRaises(PermissionError):g.check(event,args)
 def test_source_only_code_projection_is_exact(self):
  files,contract,inner=S.review(SOURCE_ROOT)
  for name,digest in P.PASSIVE.items():self.assertEqual(D.pin(files[name][0])['sha256'],digest)
  for name in('common.py','read_result.py'):self.assertEqual(inner[name][0],files['lifecycle-code/'+name][0])

 def zip_fixture(self):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);root=Path(tmp.name);evidence=root/'decoded';evidence.mkdir(mode=0o700);f=evidence/'hosted.json';f.write_bytes(b'{"MODELED":true}');f.chmod(0o644);z=root/'Original.zip'
  with zipfile.ZipFile(z,'w')as archive:
   item=zipfile.ZipInfo('hosted.json');item.create_system=3;item.external_attr=(stat.S_IFREG|0o644)<<16;archive.writestr(item,f.read_bytes())
  body=D.pin(z.read_bytes());b=dict(source='a'*40,ref='refs/heads/codex/MODELED-r3',run='123');metadata=dict(id=1,size_in_bytes=body['bytes'],digest='sha256:'+body['sha256'],name=P.OP+'-123-1',expired=False,workflow_run=dict(id=123,head_sha=b['source'],head_branch=b['ref'].removeprefix('refs/heads/')))
  rows={'hosted.json':dict(**D.pin(f.read_bytes()),mode=0o644)};material=dict(issuer='Root',source_unchanged=True,source_ZIP=body,Reader_calls=0,network_GETs=0,files=rows,uncompressed_bytes=f.stat().st_size)
  refs={}
  for name,v in [('metadata',metadata),('materialization',material)]:
   q=root/(name+'.json');q.write_bytes(encoded(v));refs[name]=dict(path=str(q),**D.pin(q.read_bytes()))
  env=dict(Original=dict(path=str(z),**body),artifact_metadata=refs['metadata'],materialization=refs['materialization']);return env,evidence,b,root
 def test_synthetic_opaque_ZIP_CRC_hash_mode_and_whole_manifest_join(self):
  env,root,b,_=self.zip_fixture();self.assertEqual(set(P.original(env,root,b)),{'hosted.json'})
 def test_ZIP_original_body_or_Source_metadata_tamper_refuses(self):
  env,root,b,tmp=self.zip_fixture();env['Original']['sha256']='f'*64
  with self.assertRaises(ValueError):P.original(env,root,b)
  env,root,b,tmp=self.zip_fixture();v=json.loads((tmp/'metadata.json').read_bytes());v['workflow_run']['head_sha']='e'*40;(tmp/'metadata.json').write_bytes(encoded(v));env['artifact_metadata'].update(D.pin((tmp/'metadata.json').read_bytes()))
  with self.assertRaises(ValueError):P.original(env,root,b)
 def test_ZIP_decoded_content_mode_or_extra_members_refuse(self):
  for mode in('content','mode','extra'):
   env,root,b,tmp=self.zip_fixture()
   if mode=='content':(root/'hosted.json').write_bytes(b'changed')
   elif mode=='mode':(root/'hosted.json').chmod(0o600)
   else:(root/'extra').write_bytes(b'changed')
   with self.subTest(mode=mode),self.assertRaises(ValueError):P.original(env,root,b)
 def test_actual_published_binding_exact_positive_and_wrong_Source_ref_negatives(self):
  v=json.loads((HERE/'binding.TEMPLATE.json').read_bytes());b=v['binding'];self.assertEqual(b['source'],P.SOURCE);self.assertEqual(b['ref'],P.REF);b.update(run='1',job='2',approval='b'*64,image='sha256:'+'c'*64,producer_report_sha256='d'*64)
  self.assertEqual(P.binding(v),b)
  for key,val in [('source','f'*40),('source','b4079a8a478afb0df8e634b555b3d2955a97bb9b'),('source','71246ca38e58f9f410d1f3eea15f5ddf174bb1bf'),('ref','refs/heads/codex/native-arm-perl5423-installed-lifecycle-v1-20261115-r2'),('source_map_sha256','e'*64),('operation','different'),('job',None)]:
   bad=copy.deepcopy(v);bad['binding'][key]=val
   with self.subTest(key=key,value=val),self.assertRaises(ValueError):P.binding(bad)

 def test_pinned_loader_real_API_avoids_bytecode_and_denies_changed_compile(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);path=root/'passive_fixture.py';raw=b'VALUE = 7\n';path.write_bytes(raw);guard=P.F.Fence({str(path)},{str(path):raw},{},{str(root)})
   with guard:
    spec=guard.spec('pure_DATA_loader_fixture',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);self.assertEqual(module.VALUE,7)
    with self.assertRaises(PermissionError):compile(b'VALUE = 8',str(path),'exec')
   self.assertFalse((root/'__pycache__').exists())

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);a=p.parse_args();SOURCE_ROOT=a.source.resolve();r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls));raise SystemExit(not r.wasSuccessful())
