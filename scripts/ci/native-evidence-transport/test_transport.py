# SPDX-License-Identifier: MIT
"""Ordinary-file transport controls only; no synthetic native/runtime acceptance."""
import copy,io,json,os,shutil,sys,tarfile,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import transport as T
ROOT=Path(os.environ.get('NATIVE_EVIDENCE_REPOSITORY',Path(__file__).resolve().parents[3]));ENCODER=ROOT/'scripts/ci/log_evidence.py'
POLICY=T.obj((Path(__file__).with_name('apps-policy.json')).read_bytes())
class Controls(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
 def environment(self):return dict(GITHUB_ACTIONS='true',GITHUB_REPOSITORY=POLICY['repository'],GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_JOB='native',GITHUB_WORKFLOW=POLICY['workflow_name'],RUNNER_ARCH='ARM64',GITHUB_SHA='0'*40,CAA_EVIDENCE_SOURCE_SHA='0'*40,CAA_EVIDENCE_WORKFLOW_SHA='0'*40,GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1')
 def packets(self):
  root=self.root/'packets';root.mkdir();a=root/'part-0000';b=root/'part-0001';a.mkdir();b.mkdir();nonce=T.encoded(dict(nonce='a'*32,scope='PRIVATE_INERT_TRANSPORT_CONTROL_NOT_NATIVE'));data=b'private ordinary transport control\n';files={};total=0
  for n,(name,raw)in enumerate((('plan/bridge-selection.json',nonce),('private.txt',data)),1):
   chunk='chunk-%04d.bin'%n;(b/chunk).write_bytes(raw);files[name]=dict(**T.pin(raw),chunks=[dict(packet='part-0001',path=chunk,**T.pin(raw))]);total+=len(raw)
  index=dict(files=files,bytes=total,cap=T.TOTAL,packet_raw_cap=T.PACKET,packet_count=1,reconstruction=T.RECONSTRUCTION,scope=T.SCOPE);(a/'retention.json').write_bytes(T.encoded(index));return root
 def captured(self):
  root=self.packets();output=self.root/'captured';step,receipt=T.capture(root,output,ENCODER,POLICY,self.environment());return root,output,step,receipt
 def metadata(self,receipt,raw):
  expected=receipt['context'];run=dict(id=1,run_attempt=1,head_sha='0'*40,repository=dict(full_name=POLICY['repository']),path=POLICY['workflow_path'],name=POLICY['workflow_name'],event='workflow_dispatch',status='completed',conclusion='failure')
  jobs=dict(total_count=1,jobs=[dict(id=2,name='native',run_id=1,run_attempt=1,head_sha='0'*40,status='completed',conclusion='failure',steps=[dict(name=POLICY['step_name'],number=3,status='completed',conclusion='success')])]);artifact=dict(id=4,size_in_bytes=len(raw),digest='sha256:'+T.pin(raw)['sha256'],expired=False,name='native-framed-evidence-1-1-native',workflow_run=dict(id=1,head_sha='0'*40));return expected,run,jobs,artifact
 def archive(self,output,extra=None):
  path=self.root/('artifact-'+str(len(list(self.root.glob('artifact-*'))))+'.zip')
  with zipfile.ZipFile(path,'w')as z:
   for p in output.iterdir():z.writestr(p.name,p.read_bytes())
   if extra:z.writestr(*extra)
  return path
 def test_exact_encoder_once_original_stdout_and_passive_failure_remains_transport_only(self):
  calls=[];original=tarfile.open
  def opened(*a,**kw):
   if kw.get('mode')=='w:gz':calls.append(True)
   return original(*a,**kw)
  with patch.object(tarfile,'open',side_effect=opened):root,output,step,receipt=self.captured()
  self.assertEqual(len(calls),2);self.assertEqual((output/'retention-step.txt').read_bytes(),step);self.assertEqual(receipt['stdout'],T.pin(step));path=self.archive(output);expected,run,jobs,artifact=self.metadata(receipt,path.read_bytes());value,files=T.verify_zip(path,expected,run,jobs,artifact,POLICY);self.assertEqual(value['acceptance'],'NOT_GRANTED');self.assertEqual(value['original_conclusion'],'failure');self.assertEqual(files['private.txt'],b'private ordinary transport control\n')
 def test_missing_alias_hardlink_unknown_chunks_and_stale_encoder_refuse_without_output(self):
  for kind in('missing-nonce','alias','hardlink','unknown','encoder'):
   with self.subTest(kind=kind):
    folder=self.root/kind;folder.mkdir();oldroot=self.root;self.root=folder
    try:
     root=self.packets();child=root/'part-0001/chunk-0001.bin';encoder=ENCODER
     if kind=='missing-nonce':value=T.obj((root/'part-0000/retention.json').read_bytes());value['files']['plan/foreign-selection.json']=value['files'].pop('plan/bridge-selection.json');(root/'part-0000/retention.json').write_bytes(T.encoded(value))
     if kind=='alias':child.unlink();child.symlink_to(root/'part-0001/chunk-0002.bin')
     if kind=='hardlink':os.link(child,self.root/'other')
     if kind=='unknown':(root/'part-0001/foreign').write_bytes(b'no')
     if kind=='encoder':encoder=self.root/'encoder.py';encoder.write_bytes(ENCODER.read_bytes()+b'\n')
     with self.assertRaises((ValueError,OSError)):T.capture(root,self.root/'never',encoder,POLICY,self.environment())
     self.assertFalse((self.root/'never').exists())
    finally:self.root=oldroot
 def test_wrong_source_attempt_job_workflow_refuses_before_output(self):
  root=self.packets()
  for key,value in(('CAA_EVIDENCE_SOURCE_SHA','1'*40),('GITHUB_RUN_ATTEMPT','2'),('GITHUB_JOB','other'),('GITHUB_WORKFLOW','foreign'),('RUNNER_ARCH','X64')):
   env=self.environment();env[key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):T.capture(root,self.root/'never',ENCODER,POLICY,env)
   self.assertFalse((self.root/'never').exists())
 def test_frame_hash_end_bounds_and_index_closure_refuse(self):
  _,_,step,_=self.captured()
  for raw in(step[:-10],step.replace(b'CACHY_ASAHI_EVIDENCE_BEGIN',b'BROKEN',1),step.replace(b'sha256=',b'sha256=0',1),step+step):
   with self.assertRaises((ValueError,UnicodeError)):T.decode_step(raw)
  packets,_=T.decode_step(step);bad=copy.deepcopy(packets);bad['part-0001']['chunk-9999.bin']=b'unreferenced'
  with self.assertRaises(ValueError):T.reconstruct(bad)
 def test_original_artifact_member_path_closure_and_api_digest_refuse(self):
  _,output,_,receipt=self.captured()
  for extra in(('../payload',b'bad'),('unexpected',b'bad'),('transport.json',b'{}')):
   path=self.archive(output,extra);expected,run,jobs,artifact=self.metadata(receipt,path.read_bytes())
   with self.assertRaises(ValueError):T.verify_zip(path,expected,run,jobs,artifact,POLICY)
  path=self.archive(output);expected,run,jobs,artifact=self.metadata(receipt,path.read_bytes());artifact['digest']='sha256:'+'f'*64
  with self.assertRaises(ValueError):T.verify_zip(path,expected,run,jobs,artifact,POLICY)
 def test_genuine_context_operands_and_retention_step_cannot_be_substituted(self):
  _,output,_,receipt=self.captured();path=self.archive(output);metadata=self.metadata(receipt,path.read_bytes())
  for kind in('run','nonce','step','job','expired','role'):
   expected,run,jobs,artifact=copy.deepcopy(metadata)
   if kind=='run':run['head_sha']='f'*40
   if kind=='nonce':expected['nonce']='b'*32
   if kind=='step':jobs['jobs'][0]['steps'][0]['conclusion']='failure'
   if kind=='job':jobs['jobs'][0]['name']='other'
   if kind=='expired':artifact['expired']=True
   if kind=='role':artifact['name']='different'
   with self.subTest(kind=kind),self.assertRaises(ValueError):T.verify_zip(path,expected,run,jobs,artifact,POLICY)
 def test_duplicate_nonfinite_and_private_output_reuse_refuse(self):
  for raw in(b'{"x":1,"x":2}',b'{"x":NaN}'):
   with self.assertRaises(ValueError):T.obj(raw)
  root,output,_,_=self.captured()
  with self.assertRaises(ValueError):T.capture(root,output,ENCODER,POLICY,self.environment())
 def test_original_encoder_wire_bytes_remain_independently_readable(self):
  import base64,gzip,hashlib,re
  _,_,step,_=self.captured();lines=step.decode().splitlines();at=0;names=[]
  while at<len(lines):
   header=re.fullmatch(r'CACHY_ASAHI_EVIDENCE_BEGIN (part-[0-9]{4}) sha256=([a-f0-9]{64}) bytes=([0-9]+)',lines[at]);self.assertIsNotNone(header);label,digest,size=header.groups();at+=1;body=[]
   while not lines[at].startswith('CACHY_ASAHI_EVIDENCE_END '):body.append(lines[at]);at+=1
   self.assertEqual(lines[at],'CACHY_ASAHI_EVIDENCE_END '+label);at+=1;raw=base64.b64decode(''.join(body),validate=True);self.assertEqual(len(raw),int(size));self.assertEqual(hashlib.sha256(raw).hexdigest(),digest)
   with tarfile.open(fileobj=io.BytesIO(gzip.decompress(raw)),mode='r:')as archive:
    for row in archive:self.assertTrue(row.isfile());self.assertTrue(row.name.startswith(label+'/'));names.append(row.name)
  self.assertEqual(set(names),{'part-0000/retention.json','part-0001/chunk-0001.bin','part-0001/chunk-0002.bin'})
 def test_original_report_advertised_closure_refusal(self):
  root=self.packets();packet=root/'part-0001';raw=T.encoded(dict(public_files={},retention=dict(files=0,bytes=0,cap=64*T.M),status='INERT_NOT_NATIVE'));(packet/'chunk-0003.bin').write_bytes(raw);index=T.obj((root/'part-0000/retention.json').read_bytes());index['files']['report.json']=dict(**T.pin(raw),chunks=[dict(packet='part-0001',path='chunk-0003.bin',**T.pin(raw))]);index['bytes']+=len(raw);(root/'part-0000/retention.json').write_bytes(T.encoded(index))
  with self.assertRaisesRegex(ValueError,'advertised'):T.capture(root,self.root/'never',ENCODER,POLICY,self.environment())
if __name__=='__main__':unittest.main(verbosity=2)
