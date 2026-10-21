"""Real original public bytes in explicitly synthetic partial-export controls."""
import ast,base64,copy,hashlib,importlib.util,io,json,os,sys,tarfile,tempfile,time,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent;sys.dont_write_bytecode=True;sys.path.insert(0,str(D))
OLD=D/'retention-fixtures/latest_transport561.py'
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
O=load('_original561_failed_transport',OLD);N=load('_new563_failed_transport',D/'retention-fixtures/latest_transport563.py');F=sys.modules['failure_retention']
ENV=dict(GITHUB_ACTIONS='true',GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_JOB='native',GITHUB_WORKFLOW='native-arm-current607-latest-tools',RUNNER_ARCH='ARM64',GITHUB_SHA='a'*40,CAA_EVIDENCE_SOURCE_SHA='a'*40,CAA_EVIDENCE_WORKFLOW_SHA='a'*40,GITHUB_RUN_ID='123456',GITHUB_RUN_ATTEMPT='1')
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir=D);self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.refs=json.loads((D/'retention-fixtures/input-references.json').read_bytes());self.policy=N.LATEST607_POLICY;self.nonce=N.encoded(dict(purpose='SOURCE_CONTROL_ONLY_NOT_NATIVE_EVIDENCE',nonce='b'*32));self.files={'input-summary.json':N.encoded(dict(summary={'source_control_only':True},retention=self.refs)),'report.json':N.encoded(dict(status='FAIL',error='SOURCE_CONTROL_ONLY_UNKNOWN_ACTUAL_CAUSE',export_error='SOURCE_CONTROL_ONLY_PARTIAL_EXPORT',cleanup=[dict(status='UNKNOWN_NO_NATIVE_CREDIT')])),'latest607-selection.json':self.nonce}
  for i,ref in enumerate(self.refs):
   name='inputs/'+ref['root']+'/'+ref['ref']['path'];self.files[name]=(D/'retention-fixtures'/('input-'+str(i)+'.bin')).read_bytes()
 def packets(self,files,where):
  where.mkdir(mode=0o700);part=where/'part-0001';part.mkdir();rows={}
  for i,(name,raw)in enumerate(sorted(files.items()),1):
   chunks=[]
   if raw:
    chunk='chunk-%04d.bin'%i;(part/chunk).write_bytes(raw);chunks=[dict(packet=part.name,path=chunk,**N.pin(raw))]
   rows[name]=dict(**N.pin(raw),chunks=chunks)
  index=where/'part-0000';index.mkdir();(index/'retention.json').write_bytes(N.encoded(dict(files=rows,bytes=sum(map(len,files.values())),cap=N.TOTAL,packet_raw_cap=N.PACKET,packet_count=1,reconstruction=N.RECONSTRUCTION,scope=N.SCOPE)));return where
 def incomplete(self):
  files=dict(self.files);ref=self.refs[-1];files.pop('inputs/'+ref['root']+'/'+ref['ref']['path']);return files
 def archive(self,output,receipt):
  raw=io.BytesIO()
  with zipfile.ZipFile(raw,'w',compression=zipfile.ZIP_STORED)as z:
   for n in('transport.json','retention-step.txt'):z.writestr(n,(output/n).read_bytes())
  path=self.root/'artifact.zip';path.write_bytes(raw.getvalue());expected=receipt['context'];run=dict(id=123456,run_attempt=1,head_sha='a'*40,repository=dict(full_name=self.policy['repository']),path=self.policy['workflow_path'],name=self.policy['workflow_name'],event='workflow_dispatch',status='completed',conclusion='failure');job=dict(id=44,name='native',run_id=123456,status='completed',head_sha='a'*40,run_attempt=1,labels=['ubuntu-24.04-arm'],steps=[dict(name=self.policy['step_name'],status='completed',conclusion='success',number=51)]);jobs=dict(total_count=1,jobs=[job]);artifact=dict(id=45,name='native-framed-evidence-123456-1-native',size_in_bytes=path.stat().st_size,digest='sha256:'+N.pin(path.read_bytes())['sha256'],expired=False,workflow_run=dict(id=123456,head_sha='a'*40));return path,expected,run,jobs,artifact
 def test_whole_original_positive_functions_and_exact_structural_prefix_held(self):
  before=OLD.read_text();after=(D/'retention-fixtures/latest_transport563.py').read_text();functions=lambda raw:{n.name:ast.get_source_segment(raw,n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)};a,b=functions(before),functions(after)
  self.assertEqual(set(b)-set(a),{'reconstruct_bytes','verify_failure_zip'});self.assertEqual({n for n in a if a[n]!=b[n]},{'capture'})
  prefix=a['reconstruct'].split(" report=obj(values['report.json'])if 'report.json'in values else {}")[0].replace('def reconstruct(packets):','def reconstruct_bytes(packets):',1)+' return raw,values';self.assertEqual(b['reconstruct_bytes'],prefix)
 def test_actual_shaped_old_refuses_no_output_new_captures_exact_raw_once_strict_refuses(self):
  files=self.incomplete();packets=self.packets(files,self.root/'packets');out=self.root/'old-output'
  with self.assertRaisesRegex(ValueError,'whole original retained input closure'):O.capture(packets,out,D/'retention-fixtures/log_evidence.py',self.policy,ENV)
  self.assertFalse(out.exists());out=self.root/'new-output';opening=tarfile.open;writes=[]
  def tracked(*a,**k):
   if k.get('mode')=='w:gz':writes.append(1)
   return opening(*a,**k)
  with patch.object(tarfile,'open',tracked):step,receipt=N.capture(packets,out,D/'retention-fixtures/log_evidence.py',self.policy,ENV)
  self.assertEqual(len(writes),2);self.assertEqual((out/'retention-step.txt').read_bytes(),step);self.assertEqual(receipt['status'],'ORIGINAL_PUBLIC_FRAMED_FAILURE_DATA_ONLY');self.assertEqual(receipt['context']['nonce'],'b'*32);self.assertEqual(receipt['clock']['time_limit'],90)
  decoded,_=N.decode_step(step);_,raw=N.reconstruct_bytes(decoded);self.assertEqual(raw,files)
  with self.assertRaisesRegex(ValueError,'whole original retained input closure'):N.reconstruct(decoded)
  args=self.archive(out,receipt)
  with self.assertRaisesRegex(ValueError,'whole source-owned capture receipt/context'):N.verify_zip(*args,self.policy)
  verified,retained=N.verify_failure_zip(*args,self.policy);self.assertEqual(retained,files);self.assertEqual(verified['acceptance'],'NOT_GRANTED');self.assertEqual(verified['original_conclusion'],'failure');mismatch=receipt['semantic_failure']['input_closure']['mismatches'];self.assertEqual(len(mismatch),1);self.assertIsNone(mismatch[0]['actual'])
 def test_complete_transport_still_uses_original_complete_receipt(self):
  packets=self.packets(self.files,self.root/'complete');step,receipt=N.capture(packets,self.root/'out',D/'retention-fixtures/log_evidence.py',self.policy,ENV);self.assertEqual(receipt['status'],'COMPLETE_ORIGINAL_FRAMED_TRANSPORT_ONLY');self.assertNotIn('semantic_failure',receipt);self.assertEqual(N.reconstruct(N.decode_step(step)[0])[1],self.files)
  with self.assertRaisesRegex(ValueError,'failure DATA receipt/context'):N.verify_failure_zip(*self.archive(self.root/'out',receipt),self.policy)
 def test_malformed_chunk_and_source_context_refuse_without_diagnostic_output(self):
  packets=self.packets(self.incomplete(),self.root/'bad');path=packets/'part-0001/chunk-0001.bin';path.write_bytes(path.read_bytes()+b'changed')
  with self.assertRaisesRegex(ValueError,'whole original chunk'):N.capture(packets,self.root/'refused',D/'retention-fixtures/log_evidence.py',self.policy,ENV)
  self.assertFalse((self.root/'refused').exists())
  with self.assertRaisesRegex(ValueError,'genuine native workflow context'):N.capture(packets,self.root/'refused',D/'retention-fixtures/log_evidence.py',self.policy,dict(ENV,RUNNER_ARCH='X64'))
 def test_hash_drift_and_missing_nonce_still_keep_strict_failure(self):
  files=dict(self.files);ref=self.refs[-1];name='inputs/'+ref['root']+'/'+ref['ref']['path'];files[name]+=b'changed-source-control-only';packets=self.packets(files,self.root/'drift');out=self.root/'drift-output';_,receipt=N.capture(packets,out,D/'retention-fixtures/log_evidence.py',self.policy,ENV);row=receipt['semantic_failure']['input_closure']['mismatches'][0];self.assertIsNotNone(row['actual']);self.assertNotEqual(row['actual'],row['expected']);self.assertEqual(N.verify_failure_zip(*self.archive(out,receipt),self.policy)[1],files)
  files=dict(self.files);files.pop('latest607-selection.json');packets=self.packets(files,self.root/'missing-nonce');fixed=Path('/tmp/cachy-asahi-expanded604-123456-1/latest607-selection.json');read=N.read
  def absent(p,*a,**k):
   if Path(p)==fixed:raise FileNotFoundError('SOURCE_CONTROL_ONLY')
   return read(p,*a,**k)
  out=self.root/'missing-nonce-output'
  with patch.object(N,'read',absent):_,receipt=N.capture(packets,out,D/'retention-fixtures/log_evidence.py',self.policy,ENV)
  self.assertIsNone(receipt['context']['nonce']);self.assertEqual(receipt['status'],'ORIGINAL_PUBLIC_FRAMED_FAILURE_DATA_ONLY');N.verify_failure_zip(*self.archive(out,receipt),self.policy)
 def test_only_fixed_original_owner_public_nonce_fallback_then_unknown(self):
  files=self.incomplete();files.pop('latest607-selection.json');packets=self.packets(files,self.root/'no-indexed-nonce');fixed=Path('/tmp/cachy-asahi-expanded604-123456-1/latest607-selection.json');nonce=self.root/'owner-public-nonce.json';nonce.write_bytes(self.nonce);nonce.chmod(0o600);read=N.read;stat=Path.stat
  def mapped_read(p,*a,**k):return read(nonce if Path(p)==fixed else p,*a,**k)
  def mapped_stat(p,*a,**k):return stat(nonce if Path(p)==fixed else p,*a,**k)
  out=self.root/'fallback'
  with patch.object(N,'read',mapped_read),patch.object(Path,'stat',mapped_stat):step,receipt=N.capture(packets,out,D/'retention-fixtures/log_evidence.py',self.policy,ENV)
  self.assertEqual(receipt['context']['nonce'],'b'*32);self.assertEqual(receipt['nonce_reference']['origin'],'ORIGINAL_OWNER_PUBLIC_NONCE_FILE');self.assertEqual(base64.b64decode(receipt['nonce_reference']['raw_base64']),self.nonce);self.assertEqual(N.verify_failure_zip(*self.archive(out,receipt),self.policy)[1],files)
  def absent(p,*a,**k):
   if Path(p)==fixed:raise FileNotFoundError('SOURCE_CONTROL_ONLY')
   return read(p,*a,**k)
  out=self.root/'unknown'
  with patch.object(N,'read',absent):_,receipt=N.capture(packets,out,D/'retention-fixtures/log_evidence.py',self.policy,ENV)
  self.assertIsNone(receipt['context']['nonce']);self.assertEqual(receipt['nonce_reference']['status'],'UNAVAILABLE_UNKNOWN_NOT_AUTHORITY');self.assertEqual(N.verify_failure_zip(*self.archive(out,receipt),self.policy)[1],files)
if __name__=='__main__':unittest.main(verbosity=2)
