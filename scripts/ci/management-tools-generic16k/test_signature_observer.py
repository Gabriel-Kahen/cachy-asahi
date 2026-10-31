# SPDX-License-Identifier: MIT
"""Inert clock/packet/diagnostic controls. No key signing or GPG execution."""
import ast,base64,copy,importlib.util,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
sys.path.insert(0,str(HERE))
import signature_observer as D
spec=importlib.util.spec_from_file_location('signature_test_contract',ROOT/'scripts/ci/management-tools-generic16k/contract.py');C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C);sys.modules['contract']=C
spec=importlib.util.spec_from_file_location('signature_test_runner',HERE/'run.py');R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
def packet(tag,raw):
 assert len(raw)<192
 return bytes([0xc0|tag,len(raw)])+raw
def sig(created=123,expiry=86400):
 hashed=b'\x05\x02'+created.to_bytes(4,'big')+b'\x05\x09'+expiry.to_bytes(4,'big')
 return bytes([4,0x13,22,8])+len(hashed).to_bytes(2,'big')+hashed+b'\0\0\0\0'
def public():return packet(6,b'\x04'+(120).to_bytes(4,'big')+b'\x16TEST')+packet(2,sig())
class Failure(Exception):
 def __init__(self,row,out,err):self.row,self.stdout,self.stderr=row,out,err
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name)
  block=patch.object(subprocess,'Popen',side_effect=AssertionError('no native actors'));block.start();self.addCleanup(block.stop)
 def fixture(self):
  directory=self.work/'apps/public/bundle';directory.mkdir(parents=True)
  for name,raw in {'public.gpg':public(),'bundle/release.json':b'{"synthetic":true}\n','bundle/release.json.sig':packet(2,sig()),'catalog.json':b'{}\n','catalog.json.sig':packet(2,sig())}.items():(self.work/'apps/public'/name).write_bytes(raw)
 def observe(self):
  self.fixture();self.original=Failure(dict(argv=['/usr/bin/cachy-asahi-apps'],exit=1),b'original',b'')
  out=b'[GNUPG:] ERRSIG TEST\n';err=b'gpg: modeled diagnostic only\n'
  row=dict(argv=['/usr/bin/gpg'],exit=2,expected_exit=-256,natural_exit=True,pid=9,pgid=9,group_absent=True,seconds=.1,stdout_bytes=len(out),stdout_sha256=D.sha(out),stderr_bytes=len(err),stderr_sha256=D.sha(err))
  def command(argv,env,expected,seconds):
   self.assertEqual((expected,seconds),(-256,30));self.argv=argv;self.env=env;row['argv']=argv;raise Failure(row,out,err)
  original=SimpleNamespace(command=Mock(side_effect=command),CommandFailure=Failure,owned_absent=Mock(return_value=True))
  value=D.observe(original,self.work,{'PATH':'/usr/bin:/bin'},self.original);self.assertEqual(original.command.call_count,1);return value
 def test_v4_public_and_signature_clock_metadata_only(self):
  value=D.clocks(public(),packet(2,sig()));self.assertEqual(value['key_created_epoch'],120);self.assertEqual(value['detached']['created_epoch'],123);self.assertEqual(value['public_key_signature_packets'][0]['key_lifetime_seconds'],86400)
 def test_unsupported_truncated_partial_and_oversize_packets_refuse(self):
  for raw in (b'',b'bad',b'\xc6\xe1',b'\xc6\xff\0',public()[:-1],b'x'*(D.MAX_PUBLIC+1)):
   with self.subTest(raw=raw[:10]),self.assertRaises(ValueError):D.packets(raw)
 def test_failure_observation_keeps_raw_status_stderr_inputs_and_clock(self):
  value=self.observe();D.validate(value);self.assertFalse(value['acceptance_credit']);self.assertEqual(self.original.stdout,b'original');self.assertEqual(self.original.row,dict(argv=['/usr/bin/cachy-asahi-apps'],exit=1))
  self.assertIn('--no-autostart',self.argv);self.assertIn('--no-auto-key-retrieve',self.argv);self.assertNotIn('--ignore-time-conflict',self.argv);self.assertNotIn('--faked-system-time',self.argv)
  self.assertEqual(self.env['LC_ALL'],'C');self.assertEqual(base64.b64decode(value['commands'][0]['stderr']['sample_base64']),b'gpg: modeled diagnostic only\n')
 def test_public_hash_sample_scope_or_group_forgery_refuse(self):
  value=self.observe()
  for mutate in (lambda x:x.update(acceptance_credit=True),lambda x:x['public_files']['public.gpg'].update(sha256='0'*64),lambda x:x['commands'][0]['stderr'].update(sample_base64=base64.b64encode(b'wrong').decode()),lambda x:x['commands'][0]['command'].update(group_absent=False)):
   changed=copy.deepcopy(value);mutate(changed)
   with self.assertRaises(ValueError):D.validate(changed)
 def test_alias_and_aggregate_public_caps_refuse(self):
  target=self.work/'ordinary';target.write_bytes(b'data');alias=self.work/'alias';alias.symlink_to(target)
  with self.assertRaises(ValueError):D.public_read(alias)
  target.write_bytes(b'x'*(D.MAX_PUBLIC+1))
  with self.assertRaises(ValueError):D.public_read(target)
 def test_sample_cap_retains_full_hash_and_does_not_claim_complete(self):
  raw=b'x'*(D.MAX_SAMPLE+1);row=D.sample(raw);self.assertEqual(row['sha256'],D.sha(raw));self.assertFalse(row['sample_complete']);self.assertEqual(len(base64.b64decode(row['sample_base64'])),D.MAX_SAMPLE)
 def test_guest_original_fail_is_raised_after_failure_only_observation(self):
  tree=ast.parse((HERE/'guest.py').read_bytes());exercise=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='exercise');call=next(n for n in exercise.body if isinstance(n,ast.FunctionDef) and n.name=='call');handler=next(n for n in ast.walk(call) if isinstance(n,ast.ExceptHandler))
  self.assertIsInstance(handler.body[-1],ast.Raise);self.assertIsNone(handler.body[-1].exc);self.assertIn("name == 'apps-plan-install'",ast.unparse(handler));self.assertIn('original.command(argv, env, expected, 30)',ast.unparse(call))
 def test_partial_parser_retains_one_bound_diagnostic_only_after_original_failure(self):
  value=self.observe();nonce='a'*32;success=dict(case='apps-inventory-install',command=dict(stdout_bytes=2,stdout_sha256=D.sha(b'{}'),stderr_bytes=0),stdout_base64=base64.b64encode(b'{}').decode())
  failed=dict(case='apps-plan-install',command=self.original.row|dict(stdout_bytes=8,stdout_sha256=D.sha(b'original'),stderr_bytes=0,stderr_sha256=D.sha(b'')),stdout_base64=base64.b64encode(b'original').decode(),stderr_base64='')
  value['original_command_sha256']=D.sha(D.encoded(failed['command']))
  prefix=b'MANAGEMENT16K_COMMAND '+nonce.encode()+b' '+D.encoded(success)+b'\nMANAGEMENT16K_COMMAND_FAILURE '+nonce.encode()+b' '+D.encoded(failed)+b'\n';line=b'MANAGEMENT16K_SIGNATURE_FAILURE '+nonce.encode()+b' '+D.encoded(value)+b'\n'
  with patch.object(C,'HERE',HERE):
   parsed=R.partial_commands(prefix+line,nonce);self.assertFalse(parsed['acceptance_credit']);self.assertEqual(len(parsed['signature_observations']),1)
   for raw in (line,prefix+line+line,prefix+line.replace(nonce.encode(),b'b'*32)):
    with self.assertRaises(ValueError):R.partial_commands(raw,nonce)
if __name__=='__main__':unittest.main(verbosity=2)
