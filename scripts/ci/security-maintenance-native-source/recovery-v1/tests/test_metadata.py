"""New metadata behavior only. Temp files and unbound reference DATA, no reader."""
import copy,hashlib,importlib,os,sys,tempfile,unittest
from pathlib import Path
P=Path(__file__).resolve().parents[1];sys.path.insert(0,str(P/'overlay/native'))
M=importlib.import_module('security_recovery_metadata');F=importlib.import_module('security_recovery_fs');S=importlib.import_module('security_recovery_state')
BIND=dict(source='c'*40,ref='refs/heads/codex/unbound-new-recovery',run='9000000000007',attempt=1,map_sha256='d'*64,token='e'*24)
def desc(date):return ('%NAME%\n'+S.NAME+'\n\n%VERSION%\n0.1.0-2\n\n%INSTALLDATE%\n'+str(date)+'\n\n%REASON%\n0\n\n%UNKNOWN_PRESERVED%\nexact text\n\n').encode()
def content(r):return {k:v for k,v in r.items()if k not in('dev','ino','nlink')}
def authority():return dict(**{n:dict(bytes=1,sha256='0'*64)for n in('archive','signature','config','keyring')},signer='AB'*20,binding=BIND)
class Metadata(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);self.policy=S.RecoveryPolicy(BIND['source'],BIND['ref'],BIND['run'],('bin/security',),os.geteuid(),os.getegid());self.d=self.root/'var/lib/pacman/local'/S.NEW;self.d.mkdir(parents=True);self.d.chmod(0o755);(self.root/'usr/bin').mkdir(parents=True);self.write('desc',desc(1001));self.write('files',b'%FILES%\nbin/security\n\n');self.write('mtree',b'fixed binary\x00data');self.snapshot=self.snap();self.expected={n:content(r)for n,r in self.snapshot['db'].items()};self.raw={n:(self.root/'var/lib/pacman/local'/n).read_bytes()for n,r in self.snapshot['db'].items()if r['kind']=='file'};self.reference=M.MetadataReference(self.raw,self.expected,dict(started_epoch=1000,finished_epoch=1002),authority());self.normalizer=M.MetadataNormalizer(self.reference)
 def tearDown(self):os.close(self.fd);self.tmp.cleanup()
 def write(self,name,data):p=self.d/name;p.write_bytes(data);p.chmod(0o644)
 def snap(self):return F.snapshot(self.fd,self.policy.payload_names,owner_uid=os.geteuid(),owner_gid=os.getegid())
 def normalize(self):return self.normalizer.normalize(self.fd,self.snap(),self.expected,self.policy,dict(started_epoch=2000,finished_epoch=2002))
 def test_only_installdate_value_changes(self):
  self.write('desc',desc(2001));expected,evidence=self.normalize();self.assertEqual(expected[S.NEW+'/desc']['sha256'],hashlib.sha256(desc(2001)).hexdigest());self.assertEqual(expected[S.NEW+'/files'],self.expected[S.NEW+'/files']);self.assertEqual(evidence['field'],'INSTALLDATE');self.assertEqual(evidence['file_evidence'][S.NEW+'/desc']['normalized'],M.pin(M.normalize_desc(desc(1001),self.reference.install_window)[0]))
 def test_duplicate_field_rejected(self):
  with self.assertRaises(ValueError):M.normalize_desc(desc(1001)+b'%INSTALLDATE%\n1001\n\n',self.reference.install_window)
 def test_extra_value_rejected(self):
  with self.assertRaises(ValueError):M.normalize_desc(desc(1001).replace(b'1001\n\n',b'1001\n1002\n\n'),self.reference.install_window)
 def test_wrong_name_or_version_rejected(self):
  for token in(S.NAME.encode(),b'0.1.0-2'):
   with self.subTest(token=token),self.assertRaises(ValueError):M.normalize_desc(desc(1001).replace(token,b'wrong'),self.reference.install_window)
 def test_other_field_drift_rejected(self):
  self.write('desc',desc(2001).replace(b'exact text',b'changed'))
  with self.assertRaises(ValueError):self.normalize()
 def test_reordered_sections_not_normalized(self):
  self.write('desc',desc(2001).replace(b'%REASON%\n0\n\n',b'')+b'%REASON%\n0\n\n')
  with self.assertRaises(ValueError):self.normalize()
 def test_mtree_drift_rejected(self):
  self.write('desc',desc(2001));self.write('mtree',b'changed')
  with self.assertRaises(ValueError):self.normalize()
 def test_date_outside_actual_interval_rejected(self):
  self.write('desc',desc(1999))
  with self.assertRaises(ValueError):self.normalize()
 def test_boolean_or_backward_window_rejected(self):
  for w in(dict(started_epoch=True,finished_epoch=1002),dict(started_epoch=1002,finished_epoch=1000),dict(started_epoch=1000,finished_epoch=1186)):
   with self.subTest(w=w),self.assertRaises(ValueError):M.normalize_desc(desc(1001),w)
 def test_reference_raw_pin_mismatch_rejected(self):
  raw=dict(self.raw);raw[S.NEW+'/files']=b'changed'
  with self.assertRaises(ValueError):M.MetadataReference(raw,self.expected,self.reference.install_window,authority()).validate()
 def test_reference_record_round_trip(self):self.assertEqual(M.MetadataReference.from_record(self.reference.record()).record(),self.reference.record())
 def test_noncanonical_encoded_reference_rejected(self):
  record=self.reference.record();record['files'][S.NEW+'/desc']['base64']+='\n'
  with self.assertRaises(Exception):M.MetadataReference.from_record(record)
 def test_boolean_reference_byte_count_rejected(self):
  record=self.reference.record();record['files'][S.NEW+'/desc']['bytes']=True
  with self.assertRaises(ValueError):M.MetadataReference.from_record(record)
 def test_snapshot_inode_mismatch_rejected(self):
  self.write('desc',desc(2001));snapshot=self.snap();snapshot['db'][S.NEW+'/desc']['ino']+=1
  with self.assertRaises(ValueError):self.normalizer.normalize(self.fd,snapshot,self.expected,self.policy,dict(started_epoch=2000,finished_epoch=2002))
 def test_wrong_episode_binding_rejected(self):
  self.write('desc',desc(2001));bad=S.RecoveryPolicy('f'*40,BIND['ref'],BIND['run'],('bin/security',),os.geteuid(),os.getegid())
  with self.assertRaises(ValueError):self.normalizer.normalize(self.fd,self.snap(),self.expected,bad,dict(started_epoch=2000,finished_epoch=2002))
 def test_unknown_fields_must_remain_literal(self):
  normalized,_=M.normalize_desc(desc(1001),self.reference.install_window);self.assertIn(b'%UNKNOWN_PRESERVED%\nexact text\n\n',normalized)
if __name__=='__main__':unittest.main(verbosity=2)
