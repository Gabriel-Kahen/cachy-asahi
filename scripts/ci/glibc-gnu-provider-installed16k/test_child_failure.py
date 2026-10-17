# SPDX-License-Identifier: MIT
"""Original stdout/stderr/retirement preservation in pure PID1 source controls."""
import ast,base64,hashlib,io,json,subprocess,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
NONCE='a'*32

def need(ok,why):
 if not ok:raise ValueError(why)
def functions(path):
 tree=ast.parse(path.read_bytes());return {n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
def guest(row,stdout,stderr,error=None):
 events=[]
 C=NS(need=need,decode=json.loads,read=lambda p:json.dumps(dict(nonce=NONCE,kernel={'release':'test-kernel'},kernel_profile_sha256='b'*64)).encode(),load=lambda *a:NS(run_command=lambda *a:(row,stdout,stderr,error)),PASS='TEST_PASS')
 scope=dict(C=C,json=json,base64=base64,hashlib=hashlib,Path=Path,ctypes=NS(CDLL=lambda *a,**k:NS(prctl=lambda *a:0)),os=NS(getpid=lambda:1,getuid=lambda:0,geteuid=lambda:0,sysconf=lambda n:16384,uname=lambda:NS(release='test-kernel'),path=NS(ismount=lambda p:False)),emit=lambda nonce,value:events.append((nonce,value)))
 funcs=functions(HERE/'guest.py');exec(compile(ast.Module(body=[funcs[n] for n in ('child_failure','run')],type_ignores=[]),'<exact-proposed-guest>','exec'),scope)
 return scope,events

def row(stdout=b'',stderr=b'',**values):
 result=dict(argv=['original-child','worker'],exit_code=1,group_absence_verified=True,seconds=1.25,time_limit=10500,output_limit=512*1024,
  stdout_bytes=len(stdout),stdout_sha256=hashlib.sha256(stdout).hexdigest(),stderr_bytes=len(stderr),stderr_sha256=hashlib.sha256(stderr).hexdigest());result.update(values);return result
class Controls(unittest.TestCase):
 def test_original_exit_and_group_failures_emit_before_unchanged_refusal(self):
  out=b'original stdout\x00\xff';err=b'actual worker traceback\n';original=row(out,err)
  for changed in (original,dict(original,exit_code=0,group_absence_verified=False)):
   scope,events=guest(changed,out,err)
   with self.assertRaisesRegex(ValueError,'lifecycle child exit/group retirement failed'):scope['run']()
   self.assertEqual([v['event'] for _,v in events],['boot','child-failure']);self.assertEqual(events[-1][0],NONCE)
   diagnostic=events[-1][1];self.assertIs(diagnostic['supervisor_record'],changed)
   for name,raw in (('stdout',out),('stderr',err)):
    self.assertEqual(base64.b64decode(diagnostic[name]['preview_base64']),raw);self.assertEqual(diagnostic[name]['sha256'],hashlib.sha256(raw).hexdigest());self.assertFalse(diagnostic[name]['truncated'])
 def test_original_error_full_hash_preview_and_output_caps(self):
  out=b'x'*(400*1024);err=b'y'*(112*1024);error=ValueError('original supervisor failure');scope,events=guest(row(out,err,exit_code=0),out,err,error)
  with self.assertRaisesRegex(ValueError,'lifecycle child'):scope['run']()
  value=events[-1][1]
  for key,raw in (('stdout',out),('stderr',err)):
   self.assertEqual(value[key]['bytes'],len(raw));self.assertEqual(value[key]['preview_bytes'],65536);self.assertTrue(value[key]['truncated']);self.assertEqual(base64.b64decode(value[key]['preview_base64']),raw[:65536]);self.assertEqual(value[key]['sha256'],hashlib.sha256(raw).hexdigest())
  self.assertEqual(value['error']['type'],'ValueError');self.assertEqual(value['error']['sha256'],hashlib.sha256(str(error).encode()).hexdigest());self.assertLess(len(json.dumps(value)),512*1024)
  with self.assertRaisesRegex(ValueError,'capture bound'):scope['child_failure']({},out+b'x',err,None,'test')
 def test_closed_worker_failure_is_diagnostic_and_still_refuses(self):
  out=('GNU_INSTALLED16K '+NONCE+' {}\n').encode();err=b'unexpected stderr';scope,events=guest(row(out,err,exit_code=0),out,err)
  with self.assertRaisesRegex(ValueError,'one closed worker result only'):scope['run']()
  self.assertEqual(events[-1][1]['phase'],'closed-worker-result');self.assertEqual(events[-1][1]['status'],'FAIL')
 def test_valid_worker_has_no_extra_record_and_original_success_bytes(self):
  out=('GNU_INSTALLED16K '+NONCE+' {"event":"result","original":"unchanged"}\n').encode();scope,events=guest(row(out,exit_code=0),out,b'');capture=io.StringIO()
  with patch.object(subprocess,'run',return_value=NS(returncode=0)),patch('sys.stdout',capture):scope['run']()
  self.assertEqual(capture.getvalue().encode(),out);self.assertEqual([v['event'] for _,v in events],['boot','exit']);self.assertNotIn('child-failure',capture.getvalue())
 def test_identity_literal_counts_budgets_and_worker_body_unchanged(self):
  root=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file());original=root/'scripts/ci/glibc-gnu-provider-installed16k/guest.py';raw=original.read_text();new=(HERE/'guest.py').read_text()
  for text,count in (('/installed16k',5),('GNU_INSTALLED16K',3),('caa_gnu_installed16k=1',1)):self.assertEqual(new.count(text),count)
  self.assertEqual(hashlib.sha256(ast.dump(functions(HERE/'guest.py')['worker'],include_attributes=False).encode()).hexdigest(),'5e6afcf6b623cce9da0ebaa847ca097ba9e12a3dca3971c9cbbd983ed7492a67')
  self.assertIn(',10500,512*1024)',new);self.assertIn("len(raw)<=512*1024",new)
if __name__=='__main__':unittest.main(verbosity=2)
