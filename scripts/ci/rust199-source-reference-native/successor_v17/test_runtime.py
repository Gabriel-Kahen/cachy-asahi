# SPDX-License-Identifier: MIT
"""Fenced real exporter/local ZIP/import control; no HTTP, Docker or native role."""
import copy,hashlib,importlib.util,inspect,json,os,sys,tempfile,time,unittest,zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.dont_write_bytecode=True

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
T=module('v17_transfer_MODEL',HERE/'payload/hosted/phase_transfer.py')
OLD=module('v17_held_transfer_MODEL',HERE.parent/'successor_v10/payload/hosted/phase_transfer.py')
V4=module('v17_export_fixture_MODEL',HERE.parent/'successor_v4/test_transfer.py')
M=module('v17_zip_directory_MODEL',HERE.parent/'successor_v10/payload/hosted/materials.py')
ACTUAL=json.loads((HERE/'fixtures/public-failure.ACTUAL364.json').read_bytes())

def fence(event,args):
 if event.startswith(('socket.','subprocess.'))or event in('os.system','os.fork','os.exec','os.posix_spawn','fcntl.flock'):raise AssertionError('MODEL attempted operational role '+event)
sys.addaudithook(fence)

def value_shape(shape):
 # Public DATA omits original strings; MODEL placeholders cannot assert native joins.
 if type(shape)is dict and set(shape)<= {'type','observed_value'} and 'type'in shape:
  return shape.get('observed_value',{'str':'MODEL', 'int':0,'bool':False,'NoneType':None}.get(shape['type']))
 if type(shape)is dict:return {k:value_shape(v)for k,v in shape.items()}
 if type(shape)is list:return [value_shape(v)for v in shape]
 raise AssertionError('unexpected public shape')

class Transfer(unittest.TestCase):
 def exported(self,base):
  source=base/'proofs';source.mkdir();d,p,delivered,b,q=V4.Controls().fixture(source,empty_log=True)
  q.update(value_shape(ACTUAL['actual_qualification_result_shape']))
  q['files']={'native_qualification':V4.pin(source/'qual-proof.json'),'empty':V4.pin(source/'probe-0.stderr')}
  q['proof_path']=str(source/'qual-proof.json')
  b['normal_phase_deadline']=getattr(self,'observation',ACTUAL['actual_normal_image_report_shape']['normal_phase_deadline']['observed_value'])
  work=base/'export';work.mkdir();command=V4.Commands(b['image'],b['owner'])
  # Model only qualification proof validation; exercise unmodified actual exporter.
  with patch.object(OLD,'context',return_value=b['owner']),patch.object(OLD.resource,'getrlimit',return_value=(-1,-1)),patch.object(OLD.resource,'setrlimit',lambda *a:None),patch.dict(os.environ,{},clear=True):out=OLD.export(HERE,work,d,p,delivered,b,q,command)
  return d,p,delivered,b,q,out
 def archive(self,base,mutate=None,body_mutate=None):
  d,p,delivered,b,q,out=self.exported(base);bundle=Path(out['directory']);manifest=json.loads((bundle/'manifest.json').read_bytes())
  if mutate:mutate(manifest)
  raw=T.encode(manifest)
  if body_mutate:raw=body_mutate(raw)
  archive=base/'phase.zip'
  with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_STORED)as z:
   for leaf in bundle.rglob('*'):
    if leaf.is_file():z.writestr(leaf.relative_to(bundle).as_posix(),raw if leaf.name=='manifest.json'else leaf.read_bytes())
  return d,p,delivered,b,q,out,archive,raw
 def budget(self):return T.Budget(SimpleNamespace(deadline=time.monotonic()+60,cancelled=[False],on_tick=None),60)
 def test_real_old_export_preserves_actual_retained_timings_old_extract_fails_new_passes(self):
  with tempfile.TemporaryDirectory()as td:
   base=Path(td);*_,archive,raw=self.archive(base)
   with self.assertRaisesRegex(ValueError,'noninteger/nonfinite'):OLD.extract(archive,base/'old',hashlib.sha256(raw).hexdigest(),self.budget(),M)
   self.assertFalse((base/'old').exists());got=T.extract(archive,base/'new',hashlib.sha256(raw).hexdigest(),self.budget(),M)
   self.assertEqual((base/'new/manifest.json').read_bytes(),raw)
   for row in ACTUAL['actual_qualification_float_fields']:
    item=got
    for key in row['path'].split('/')[1:]:item=item[int(key)]if type(item)is list else item[key]
    self.assertIs(type(item),float);self.assertEqual(item,row['value'])
   self.assertEqual(got['metadata']['boot']['normal_phase_deadline'],2998.514152847)
   for name,row in got['files'].items():
    leaf=base/'new'/name;self.assertEqual(leaf.stat().st_mode&0o777,0o444);self.assertEqual(hashlib.sha256(leaf.read_bytes()).hexdigest(),row['sha256'])
 def test_whole_public_schema_has_only_ten_source_backed_observational_floats(self):
  meta={'boot':value_shape(ACTUAL['actual_normal_image_report_shape']),'qual':value_shape(ACTUAL['actual_qualification_result_shape'])}
  got=T.decode_manifest(T.encode({'metadata':meta}));self.assertEqual(got['metadata'],meta)
  observed=[]
  def walk(v,path=()):
   if type(v)is float:observed.append(path)
   elif type(v)is dict:
    for k,x in v.items():walk(x,path+(k,))
   elif type(v)is list:
    for i,x in enumerate(v):walk(x,path+(i,))
  walk(got);self.assertEqual(len(observed),10);self.assertFalse(ACTUAL['actual_manifest_retained'])
 def test_authority_decoder_unchanged_and_float_rejection_everywhere_else(self):
  self.assertEqual(inspect.getsource(T.decode),inspect.getsource(OLD.decode))
  for path in [('schema',),('source','job'),('metadata','boot','schema'),('metadata','qual','owned_work_bind','workspace_node','uid'),('metadata','qual','owned_work_bind','nonce'),('files','image.tar','bytes'),('files','image.tar','mode'),('metadata','qual','probe_receipts',0,'returncode'),('metadata','qual','probe_receipts',0,'lifecycle','exit'),('metadata','qual','probe_receipts',9,'lifecycle','elapsed_seconds'),('metadata','delivered','elapsed_seconds'),('resources','seconds')]:
   value=0.0
   for key in reversed(path):value=[value]if key==0 else([{}]*key+[value]if type(key)is int else {key:value})
   with self.subTest(path=path),self.assertRaises(ValueError):T.decode_manifest(T.encode(value))
  for raw in (b'{"schema":4.0}',b'{"deadline":0.01}'):
   with self.assertRaises(ValueError):T.decode(raw)
 def test_nonfinite_overflow_duplicates_negative_and_nonnumeric_observations_refuse(self):
  for token in ('NaN','Infinity','-Infinity','1e400','-0.1','true','null','"0.1"','{}','[]'):
   raw=('{"metadata":{"boot":{"normal_phase_deadline":'+token+'}}}').encode()
   with self.subTest(token=token),self.assertRaises(ValueError):T.decode_manifest(raw)
  for raw in (b'{"metadata":{},"metadata":{}}',b'{"metadata":{"boot":{"normal_phase_deadline":0.1,"normal_phase_deadline":0.2}}}',b'[]',b'{}'+b' '*(4*T.MIB)):
   with self.assertRaises(ValueError):T.decode_manifest(raw)
 def test_hash_mode_aggregate_cancellation_and_deadline_guards_retained(self):
  mutations=[lambda m:m['files']['image.tar'].update(mode=0o644),lambda m:m['files']['image.tar'].update(sha256='0'*64),lambda m:m['files']['image.tar'].update(bytes=T.IMAGE_CAP+1)]
  for i,mutate in enumerate(mutations):
   with self.subTest(i=i),tempfile.TemporaryDirectory()as td:
    base=Path(td);*_,archive,raw=self.archive(base,mutate)
    with self.assertRaises(ValueError):T.extract(archive,base/'out',hashlib.sha256(raw).hexdigest(),self.budget(),M)
  with tempfile.TemporaryDirectory()as td:
   base=Path(td);*_,archive,raw=self.archive(base)
   with self.assertRaisesRegex(ValueError,'manifest SHA'):T.extract(archive,base/'wrong-hash','0'*64,self.budget(),M)
   for cancelled in (True,False):
    b=self.budget();b.command.cancelled[0]=cancelled
    if not cancelled:b.deadline=time.monotonic()-1
    with self.assertRaisesRegex(ValueError,'cancellation/deadline'):T.extract(archive,base/('cancel'if cancelled else'timeout'),hashlib.sha256(raw).hexdigest(),b,M)
   with patch.object(T,'DATA_CAP',0),self.assertRaises(ValueError):T.extract(archive,base/'overbudget',hashlib.sha256(raw).hexdigest(),self.budget(),M)
 def test_import_rejects_misplaced_float_before_first_image_load_and_valid_timings_reach_load(self):
  for malformed,observed in ((False,0.000001),(False,1e200),(True,2998.514152847)):
   self.observation=observed
   with self.subTest(malformed=malformed,observation=observed),tempfile.TemporaryDirectory()as td:
    base=Path(td)
    mutate=(lambda m:m['files']['image.tar'].update(mode=292.0))if malformed else None
    d,p,delivered,b,q,out,archive,raw=self.archive(base,mutate)
    image_pin={k:json.loads(raw)['files']['image.tar'][k]for k in('bytes','sha256')}
    current=copy.deepcopy(p);current['phase']='build';current['source']['job']='102'
    image=b['image'];args=SimpleNamespace(bootstrap_artifact_id='999',bootstrap_job_id='101',bootstrap_artifact_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),bootstrap_manifest_sha256=hashlib.sha256(raw).hexdigest())
    artifact=dict(id=999,expired=False,size_in_bytes=archive.stat().st_size,name='rust199-qualified-transfer-v4-100-1',workflow_run=dict(id=100,head_sha='f'*40))
    job=dict(id=101,run_id=100,head_sha='f'*40,status='completed',conclusion='success',name='rust199-bootstrap-v4')
    def fetch(url,target,*args,**kwargs):
     body=archive.read_bytes()if url.endswith('/zip')else T.encode(artifact if '/artifacts/'in url else job if '/jobs/'in url else {})
     target.write_bytes(body);return dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
    authorization=dict(policy_pin=T.POLICY_PIN,selected_host='MODEL.blob.core.windows.net',binding=dict(image_id=image,image_pin=image_pin))
    work=base/'import';work.mkdir();command=V4.Commands(image,b['owner'],present=False);current_deadline=command.deadline
    # Explicit MODEL seams for HTTP/provider policy/qualification validation.
    # Actual manifest parsing, file membership/pins/modes, restoration, image
    # binding, preexisting image checks and load ordering run unchanged.
    with patch.object(T,'fetch',fetch),patch.object(T,'authorize_transfer',return_value=authorization),patch.object(T,'context',return_value=b['owner']),patch.object(T,'load',return_value=M):
     if malformed:
      with self.assertRaisesRegex(ValueError,'float outside'):T.import_phase(HERE,work,d,current,args,command)
     else:
      result=T.import_phase(HERE,work,d,current,args,command);self.assertTrue(result['boot']['imported_from_bootstrap']);self.assertEqual(result['boot']['normal_phase_deadline'],observed)
    loaded=any(row[:2]==['image','load']for row in command.events);self.assertEqual(loaded,not malformed);self.assertEqual(command.deadline,current_deadline)
 def test_all_preload_and_compiler_actor_paths_byte_identical(self):
  for name in ('import_phase','image_binding','provider_check','validate_policy','authorize_transfer','context','collect','fetch','export'):
   old=inspect.getsource(getattr(OLD,name));new=inspect.getsource(getattr(T,name));self.assertEqual(old,new,name)

if __name__=='__main__':unittest.main(verbosity=2)
