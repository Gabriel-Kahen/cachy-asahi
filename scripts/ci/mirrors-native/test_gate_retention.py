# SPDX-License-Identifier: MIT
"""Pure public retention fixtures: no container, GPG, pacman or API actors."""
import copy,importlib.util,json,os,shutil,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import gate_diagnostics as D
HERE=Path(__file__).resolve().parent
CONTRACT=HERE/'contract.py'

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
with patch.dict(sys.modules,{'contract':load('retention_fixture_contract',CONTRACT)}):J=load('retention_fixture_job',HERE/'job.py')


class Retention(unittest.TestCase):
 def make(self,temp,count=1,status='FAIL'):
  writer=D.Diagnostics(Path(temp)/'runtime'/'signature-verification')
  for n in range(count):writer.capture(['/usr/bin/gpg','--list-keys'],'public-%02d'%n,0,b'public stdout',b'public stderr',n,n+1)
  commands=[]
  for row in writer.commands:
   held={k:row[k] for k in ('operation','exit','started_epoch','finished_epoch')}
   held.update({role:{k:row[role][k] for k in ('bytes','sha256')} for role in ('stdout','stderr')});commands.append(held)
  gate=dict(status=status,commands=commands,cleanup={'verifier_removed':True})
  gate['diagnostics']=dict(directory='signature-verification',index=writer.checkpoint(status,gate))
  return writer,gate
 def root(self,temp):
  (Path(temp)/'runtime').mkdir(mode=0o700)
 def save_index(self,writer,index):
  (writer.root/'index.json').write_text(json.dumps(index,indent=2,sort_keys=True)+'\n')
 def test_failed_partial_retained_before_acceptance_and_survives_source_removal(self):
  with tempfile.TemporaryDirectory() as temp:
   self.root(temp);writer,gate=self.make(temp);retained=Path(temp)/'retained';retained.mkdir();names=[];errors=[]
   def retain(path,name,cap):
    self.assertLessEqual(path.stat().st_size,cap);target=retained/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target);names.append(name)
   result=J.retain_diagnostics(writer.root,retain,errors)
   self.assertEqual(errors,[]);self.assertEqual(names[0],'signature-verification/index.json');self.assertEqual(len(names),3)
   self.assertEqual(result[1],gate['diagnostics']['index']);shutil.rmtree(writer.root)
   self.assertEqual((retained/'signature-verification/000.stderr').read_bytes(),b'public stderr')
 def test_positive_exact_gate_and_thirteen_commands_join(self):
  with tempfile.TemporaryDirectory() as temp:
   self.root(temp);writer,gate=self.make(temp,13,'PASS_TEST_SIGNATURE_VERIFIED_BEFORE_CANDIDATE_OBSERVATION');index,pin=J.diagnostic_index(writer.root)
   J.join_diagnostics(index,pin,gate)
   wrong=copy.deepcopy(gate);wrong['commands'][0]['stderr']['sha256']='0'*64
   with self.assertRaises(ValueError):J.join_diagnostics(index,pin,wrong)
   wrong=copy.deepcopy(gate);wrong['diagnostics']['index']['sha256']='0'*64
   with self.assertRaises(ValueError):J.join_diagnostics(index,pin,wrong)
   changed=copy.deepcopy(index);changed['gate']['cleanup']['verifier_removed']=False
   with self.assertRaises(ValueError):J.join_diagnostics(changed,pin,gate)
   for kind in ('pin','time','exit','incomplete','error','combined-cap'):
    changed=copy.deepcopy(index);row=changed['commands'][0];joined_gate=gate
    if kind=='pin':row['stderr']['sha256']='0'*64
    elif kind=='time':row['finished_epoch']+=1
    elif kind=='exit':row['exit']=1
    elif kind=='incomplete':row['complete']=False
    elif kind=='error':row['error']='TimeoutExpired'
    else:
     row['stdout']['bytes']=D.CAP;row['stderr']['bytes']=1
     changed['gate']['commands'][0]['stdout']['bytes']=D.CAP;changed['gate']['commands'][0]['stderr']['bytes']=1
     joined_gate=copy.deepcopy(gate);joined_gate['commands']=changed['gate']['commands']
    with self.subTest(kind=kind),self.assertRaises(ValueError):J.join_diagnostics(changed,pin,joined_gate)
 def test_truncated_failure_prefix_allowed_but_cannot_positive_join(self):
  with tempfile.TemporaryDirectory() as temp:
   self.root(temp);writer,gate=self.make(temp,13,'PASS_TEST_SIGNATURE_VERIFIED_BEFORE_CANDIDATE_OBSERVATION');index,pin=J.diagnostic_index(writer.root)
   index['commands'][0]['stdout'].update(observed_bytes=D.CAP+1,complete=False);index['commands'][0]['complete']=False
   self.save_index(writer,index);index,pin=J.diagnostic_index(writer.root);gate['diagnostics']['index']=pin
   with self.assertRaises(ValueError):J.join_diagnostics(index,pin,gate)
 def test_raw_tamper_aliases_and_unlisted_files_refused(self):
  for kind in ('tamper','oversize','symlink','hardlink','extra','index-hardlink'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
    self.root(temp);writer,gate=self.make(temp);path=writer.root/'000.stdout'
    if kind=='tamper':path.write_bytes(b'tampered')
    elif kind=='oversize':path.write_bytes(b'x'*(D.CAP+1))
    elif kind=='symlink':path.unlink();path.symlink_to(writer.root/'000.stderr')
    elif kind=='hardlink':path.unlink();os.link(writer.root/'000.stderr',path)
    elif kind=='extra':(writer.root/'unlisted').write_bytes(b'extra')
    else:os.link(writer.root/'index.json',Path(temp)/'other-index')
    with self.assertRaises(ValueError):J.diagnostic_index(writer.root)
 def test_fixed_names_caps_and_typed_counts_refused(self):
  for kind in ('escape','commands','stream','aggregate','boolean-pin','duplicate'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
    self.root(temp);writer,gate=self.make(temp);index,pin=J.diagnostic_index(writer.root)
    if kind=='escape':index['commands'][0]['stdout']['file']='../outside'
    elif kind=='commands':index['commands']*=21
    elif kind=='stream':index['commands'][0]['stdout']['bytes']=D.CAP+1
    elif kind=='aggregate':index['total_bytes']=D.TOTAL+1
    elif kind=='boolean-pin':index['files']['000.stdout']['bytes']=True
    else:
     path=writer.root/'index.json';path.write_text(path.read_text().replace('"schema_version": 1','"schema_version": 1, "schema_version": 1'))
    if kind!='duplicate':self.save_index(writer,index)
    with self.assertRaises(ValueError):J.diagnostic_index(writer.root)
 def test_malformed_bounded_index_preserved_and_errors_prevent_acceptance(self):
  with tempfile.TemporaryDirectory() as temp:
   self.root(temp);writer,gate=self.make(temp);(writer.root/'index.json').write_bytes(b'not JSON');copied=[];errors=[]
   self.assertIsNone(J.retain_diagnostics(writer.root,lambda path,name,cap:copied.append((name,path.read_bytes())),errors))
   self.assertEqual(copied,[('signature-verification/index.json',b'not JSON')]);self.assertTrue(errors)
 def test_index_cap_and_hardlink_rejected_before_copy(self):
  for kind in ('oversize','hardlink'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
    self.root(temp);writer,gate=self.make(temp);path=writer.root/'index.json'
    if kind=='oversize':path.write_bytes(b'x'*(J.DIAGNOSTIC_INDEX_CAP+1))
    else:os.link(path,Path(temp)/'other')
    copied=[];errors=[];self.assertIsNone(J.retain_diagnostics(writer.root,lambda *args:copied.append(args),errors))
    self.assertEqual(copied,[]);self.assertTrue(errors)

if __name__=='__main__':unittest.main()
