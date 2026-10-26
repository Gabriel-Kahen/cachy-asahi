# SPDX-License-Identifier: MIT
"""Short real owned-process controls; no Docker, namespaces, network or cleanup authority."""
import ast,base64,hashlib,importlib.util,json,os,signal,stat,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('CACHY_ASAHI_TEST_SOURCE',HERE.parents[2]))
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
D=load('retirement_diagnostic',HERE/'retain.py')
S_PATH=ROOT/'scripts/ci/orphans-full574-native/supervise.py'
S=load('original_job_retirement',S_PATH)
IDENTITY=dict(source_sha='a'*40,trial='full574-signed-repair',proof_sha256='b'*64,consumer_token='c'*32,producer_token='d'*16,case='repair-bytes')
PINS={'manifest':D.pin(b'inert-control-manifest'),'files':{'scripts/ci/orphans-full574-native/supervise.py':D.pin(S_PATH.read_bytes())}}
CHILD='import os,signal,subprocess,sys,time\nfrom pathlib import Path\nr=Path(sys.argv[1]);mode=sys.argv[2];received=[]\ndef leave(n,f):received.append(n)\nfor n in (signal.SIGINT,signal.SIGTERM):signal.signal(n,signal.SIG_IGN if mode==\'ignore\' else leave)\nif mode==\'tree\':\n code="""import os,signal,time\nfrom pathlib import Path\nr=Path("""+repr(str(r))+""");received=[]\ndef leave(n,f):received.append(n)\nfor n in (signal.SIGINT,signal.SIGTERM):signal.signal(n,leave)\n(r/\'grand-ready\').write_text(str(os.getpid()))\nwhile not received:time.sleep(.01)\nsignal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})\n(r/\'grand-signal\').write_text(str(received[0]))\n"""\n grand=subprocess.Popen([sys.executable,\'-c\',code]);end=time.monotonic()+2\n while not (r/\'grand-ready\').exists() and time.monotonic()<end:time.sleep(.01)\n(r/\'ready\').write_text(str(os.getpid()))\nwhile not received:time.sleep(.02)\n# No wait or I/O in a Python signal handler: a second cancellation must not\n# reenter Popen.wait while its non-reentrant waitpid lock is already held.\nsignal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})\n(r/\'forwarded\').write_text(str(received[0]))\nif mode==\'tree\':grand.wait(timeout=1)\nraise SystemExit(0)\n'
LAUNCH="""import importlib.util,json,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('S',sys.argv[1]);S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
v=S.handoff([sys.executable,'-c',sys.argv[2],sys.argv[3],sys.argv[4]],Path(sys.argv[3])/'handoff.json',json.loads(sys.argv[5]));raise SystemExit(128+v['cancellation_signal'] if v['cancellation_signal'] else v['exit_code'])
"""
class Retention(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory(prefix='job-retirement-control-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.path=self.root/'handoff.json'
 def write(self,value):self.path.write_bytes(D.encoded(value));self.path.chmod(0o600)
 def row(self):return dict(schema_version=1,status='RUNNING_NOT_CLEANUP_AUTHORITY',identity=IDENTITY,job=None,group_absent=False,direct_reaped=False,inner_actors=D.INNER)
 def capture(self):return D.diagnostic(self.path,IDENTITY,PINS)
 def test_missing_partial_malformed_and_foreign_stay_diagnostic_only(self):
  self.assertEqual(self.capture()['handoff_state'],'MISSING');self.write(self.row());v=self.capture();self.assertEqual(v['handoff_state'],'COMPLETE_TYPED');self.assertFalse(v['cleanup_authority']);self.assertEqual(base64.b64decode(v['raw_base64']),self.path.read_bytes())
  for change in ({'private':'DO_NOT_EXPORT'},{'error':'secret /private/name'},{'group_absent':'true'}):
   self.write(self.row()|change);v=self.capture();self.assertEqual(v['handoff_state'],'PARTIAL_TYPED_HASH_ONLY');self.assertIsNone(v['raw_base64']);self.assertNotIn('DO_NOT_EXPORT',D.encoded(v).decode());self.assertNotIn('/private/name',D.encoded(v).decode())
  self.write(self.row()|{'identity':IDENTITY|{'case':'repair-missing'}});self.assertEqual(self.capture()['handoff_state'],'IDENTITY_OR_SCHEMA_MISMATCH_HASH_ONLY')
  self.path.write_bytes(b'{"status":');self.assertEqual(self.capture()['handoff_state'],'MALFORMED_HASH_ONLY');self.path.write_bytes(b'{"a":1,"a":2}');self.assertEqual(self.capture()['handoff_state'],'MALFORMED_HASH_ONLY')
 def test_safe_input_output_and_drift_refusals(self):
  self.write(self.row());self.path.chmod(0o644);self.assertEqual(self.capture()['handoff_state'],'UNSAFE_OR_UNSTABLE_NOT_READ');self.path.chmod(0o600)
  alias=self.root/'alias';alias.symlink_to(self.path);self.assertEqual(D.diagnostic(alias,IDENTITY,PINS)['handoff_state'],'UNSAFE_OR_UNSTABLE_NOT_READ');alias.unlink();os.link(self.path,alias);self.assertEqual(self.capture()['handoff_state'],'UNSAFE_OR_UNSTABLE_NOT_READ');alias.unlink()
  original=D.os.read
  def changed(fd,n):
   raw=original(fd,n);self.path.write_bytes(b'changed');return raw
  with patch.object(D.os,'read',side_effect=changed):self.assertEqual(self.capture()['handoff_state'],'UNSAFE_OR_UNSTABLE_NOT_READ')
  self.write(self.row());dest=self.root/'diagnostic.json';D.save_diagnostic(dest,self.capture());self.assertEqual(stat.S_IMODE(dest.stat().st_mode),0o600)
  with self.assertRaises(FileExistsError):D.save_diagnostic(dest,self.capture())
  self.path.write_bytes(b'x'*(D.CAP+1));self.assertEqual(self.capture()['handoff_state'],'UNSAFE_OR_UNSTABLE_NOT_READ')
 def test_source_manifest_and_original_predicate_are_required(self):
  base=self.root/'source';base.mkdir();leaf=base/'helper.py';leaf.write_bytes(b'inert');manifest=base/'manifest.json';manifest.write_bytes(D.encoded({'files':{'helper.py':D.pin(b'inert')}}));rows=D.sources(base,manifest,['helper.py']);self.assertEqual(rows['files']['helper.py'],D.pin(b'inert'));leaf.write_bytes(b'drift')
  with self.assertRaisesRegex(ValueError,'exact source manifest'):D.sources(base,manifest,['helper.py'])
  self.write(self.row());D.save_diagnostic(self.root/'diag',self.capture())
  with self.assertRaises(ValueError):S.check(self.path,IDENTITY)
  with self.assertRaises(ValueError):S.check(self.path,IDENTITY,True)
 def test_verified_separate_export_and_wrong_source_refusal(self):
  E=load('retirement_export',HERE/'export.py');source=self.root/'source';source.mkdir();rows={}
  for name in E.NAMES:
   path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'inert-source-'+name.encode());rows[name]=D.pin(path.read_bytes())
  manifest=source/'scripts/ci/apps-full574-repair-native/source-manifest.json';manifest.write_bytes(D.encoded({'files':rows}));proof=self.root/'proof.json';raw=D.encoded(dict(source_sha=IDENTITY['source_sha'],consumer_token=IDENTITY['consumer_token'],job_token=IDENTITY['producer_token'],case=IDENTITY['case']));proof.write_bytes(raw);expected=IDENTITY|{'proof_sha256':D.pin(raw)['sha256']};self.write(self.row()|{'identity':expected});records=D.sources(source,manifest,E.NAMES);value=D.diagnostic(self.path,expected,records);diagnostic=self.root/'private.json';D.save_diagnostic(diagnostic,value)
  env={key:expected['source_sha'] for key in ('SOURCE_SHA','GITHUB_SHA','GITHUB_WORKFLOW_SHA')};env['REPAIR_CASE']=expected['case']
  with patch.dict(os.environ,env):
   output=self.root/'public';observed=E.export(source,proof,diagnostic,output);self.assertEqual(observed,value);self.assertEqual((output/'outer-handoff-diagnostic.json').read_bytes(),diagnostic.read_bytes());self.assertEqual(sorted(p.name for p in output.iterdir()),['outer-handoff-diagnostic.json'])
   (source/E.NAMES[0]).write_bytes(b'drift')
   with self.assertRaisesRegex(ValueError,'exact source manifest'):E.export(source,proof,diagnostic,self.root/'refused')
   self.assertFalse((self.root/'refused').exists())
 def test_public_replay_rejects_raw_projection_or_authority_tampering(self):
  self.write(self.row());value=self.capture();D.verify(value)
  for change in ({'cleanup_authority':True},{'raw_sha256':'0'*64},{'public':value['public']|{'group_absent':True}},{'extra':'secret'}):
   with self.assertRaises(ValueError):D.verify(value|change)
 def test_real_SIGINT_and_SIGTERM_forwarded_reaped_and_joined(self):
  for n in (signal.SIGINT,signal.SIGTERM):
   with self.subTest(signal=n):self.run_owned('tree',n,False)
 def test_real_process_tree_SIGINT_and_ignored_TERM_are_bounded(self):
  self.run_owned('tree',signal.SIGINT,True);self.run_owned('ignore',signal.SIGTERM,False)
 def test_real_second_signal_inside_grandchild_wait_is_not_reentrant(self):
  # Force a real second cancellation exactly inside Popen's waitpid lock.
  # This is fixture-only scheduling, not a mocked retirement or wait result.
  seam="if mode=='tree':grand.wait(timeout=1)"
  replacement="""if mode=='tree':
 original_try_wait=grand._try_wait
 signalled=[False]
 def signal_during_wait(flags):
  if not signalled[0]:signalled[0]=True;os.kill(os.getpid(),signal.SIGTERM)
  return original_try_wait(flags)
 grand._try_wait=signal_during_wait
 grand.wait(timeout=1)"""
  self.assertEqual(CHILD.count(seam),1)
  with patch.dict(globals(),CHILD=CHILD.replace(seam,replacement)):
   self.run_owned('tree',signal.SIGINT,True)
 def run_owned(self,mode,number,whole_tree):
  with tempfile.TemporaryDirectory(dir=self.root) as td:
   work=Path(td);p=subprocess.Popen([sys.executable,'-I','-B','-c',LAUNCH,str(S_PATH),CHILD,str(work),mode,json.dumps(IDENTITY)],start_new_session=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   child_pid=None
   try:
    end=time.monotonic()+3
    while not (work/'ready').exists() and p.poll() is None and time.monotonic()<end:time.sleep(.01)
    self.assertTrue((work/'ready').exists());child_pid=int((work/'ready').read_text());start=time.monotonic()
    if whole_tree:os.killpg(child_pid,number)
    os.kill(p.pid,number);out,err=p.communicate(timeout=7);self.assertFalse(err,err.decode());self.assertEqual(p.returncode,128+number)
    elapsed=time.monotonic()-start;receipt=work/'handoff.json'
    # Preserve the real receipt before the timing assertion can discard the
    # temporary fixture. This is DATA even when a later assertion fails.
    observed=D.diagnostic(receipt,IDENTITY,PINS)
    print('OWNED_PROCESS_OBSERVATION '+json.dumps(dict(mode=mode,signal=int(number),whole_tree=whole_tree,communicate_seconds=round(elapsed,6),actual_wait_returncode=p.returncode,diagnostic=observed,assertions_pending=True,host_only=True),sort_keys=True),flush=True)
    self.assertLess(elapsed,6);S.check(receipt,IDENTITY);v=D.diagnostic(receipt,IDENTITY,PINS);self.assertEqual(v['handoff_state'],'COMPLETE_TYPED');self.assertFalse(v['cleanup_authority']);self.assertTrue(v['public']['direct_reaped']);self.assertTrue(v['public']['group_absent']);D.save_diagnostic(work/'diagnostic.json',v)
    if mode=='tree':self.assertEqual((work/'grand-signal').read_text(),str(number))
    else:self.assertEqual(v['public']['exit_code'],-signal.SIGKILL)
    summary=dict(mode=mode,signal=int(number),whole_tree=whole_tree,seconds=round(time.monotonic()-start,6),actual_wait_returncode=p.returncode,original=v['public'],host_only=True)
    print('OWNED_PROCESS_CONTROL '+json.dumps(summary,sort_keys=True),flush=True)
   finally:
    if p.poll() is None:
     for pid in (child_pid,p.pid):
      if pid:
       try:os.killpg(pid,signal.SIGKILL)
       except ProcessLookupError:pass
     p.wait(timeout=1)
    p.stdout.close();p.stderr.close()
class Source(unittest.TestCase):
 def test_original_supervisor_hash_and_no_actor_authority(self):
  self.assertEqual(D.pin(S_PATH.read_bytes()),dict(bytes=8227,sha256='524118fb285107def1453bc7c4e9db505223611186ed952adf9fdfdd0e794171'))
  for name in ('retain.py','export.py'):
   tree=ast.parse((HERE/name).read_text());self.assertFalse(any(isinstance(n,ast.Import) and any(a.name in ('subprocess','signal') for a in n.names) for n in ast.walk(tree)));self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in ('kill','killpg','execv','Popen','rmtree') for n in ast.walk(tree)))
if __name__=='__main__':unittest.main(verbosity=2)
