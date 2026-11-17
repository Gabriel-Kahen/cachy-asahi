# SPDX-License-Identifier: MIT
"""Ordinary temporary-tree guard and Root-boundary controls; no actor or raw."""
import copy,hashlib,importlib.util,json,os,re,shlex,subprocess,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
LIFECYCLE=HERE.parent/'arm16k_perl_initialized_lifecycle_vm'
LEGACY=HERE.parent/'arm16k_warm_control/source/arm16k_perl5423_vm'
ACTUAL=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-initialized-successor-readiness-20261117-r1/constructed-source')
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=module('guard_proposal',HERE/'proposal.py');T=module('original_guest_fixture',LIFECYCLE/'test_guest.py')
OLD={n:(ACTUAL/n).read_bytes()for n in P.PINS};NEW,MAP=P.transform(OLD)
GUARD=re.compile(r'PERL5423_INITIALIZED_GUARD_DIAGNOSTIC_V1 CHECK=(I0|E0|R[1-9][0-9]?) INDEX=(0|[1-9]|1[0-4])')
STAGE=re.compile(r'PERL5423_POST_METADATA_DIAGNOSTIC_V1 STAGE=([A-Z0-9_]+)')
class Controls(unittest.TestCase):
 def fixture(self):
  f=T.Guest('test_preserves_existing_nodes_and_repeated_capture_cannot_reset');f.setUp();self.addCleanup(f.doCleanups)
  (f.root/'home/builder').mkdir(parents=True);return f
 def shell(self,f,body,instrumented=True,missing_console=False):
  console=f.d/('missing/console'if missing_console else'console')
  helper=f.d/'guard-helper.sh';helper.write_bytes((NEW if instrumented else OLD)['guest/initialized-state.sh'].replace(b'/dev/ttyAMA0',shlex.quote(str(console)).encode()))
  prefix='set -Eeuo pipefail\n. '+shlex.quote(str(helper))+'\nD='+shlex.quote(str(f.d))+'\nnonce='+T.NONCE+'\nroot_ssh_target='+shlex.quote(str(f.root/'root/.ssh'))+'\n'
  result=subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c',prefix+body],capture_output=True,text=True,timeout=20)
  text=console.read_text()if console.exists()else''
  for line in text.splitlines():
   if not line:continue
   match=GUARD.fullmatch(line)
   if match:self.assertIn(match[1],{'I0','E0'}|{r['check']for r in MAP['returns']})
   else:
    match=STAGE.fullmatch(line);self.assertIsNotNone(match,line);self.assertIn(match[1],P.STAGES)
  self.assertLess(len(text),8192);self.assertNotIn('PRIVATE_SENTINEL',text)
  return result,text
 def original_guard(self,mutation,instrumented=True,missing_console=False):
  f=self.fixture();body=f.capture()+mutation(f)+'\n_initialized_guard\n'
  result,text=self.shell(f,body,instrumented,missing_console);return f,result,text
 def test_generated_files_mapping_complete_inverse_and_unchanged_Root_commands(self):
  for name,body in NEW.items():
   self.assertEqual((HERE/name).read_bytes(),body)
   self.assertEqual(subprocess.run(['/usr/bin/bash','-n'],input=body,capture_output=True,timeout=5).returncode,0)
  self.assertEqual(P.inverse(OLD,NEW,MAP),OLD)
  # Independently remove every return observation and implicit diagnostic seam.
  text=NEW['guest/initialized-state.sh'].decode().split('# Initialized-state equality only:',1)[1]
  text='# SPDX-License-Identifier: MIT\n# Initialized-state equality only:'+text
  for row in MAP['returns']:
   code,index,status=row['check'],row['index'],row['return_code']
   added=('{ _ig_diagnostic '+code+' "'+index+'";return 2; }'if status==2 else
          '{ local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic '+code+' "'+index+'";fi;return "$_ig_diagnostic_rc"; }')
   self.assertEqual(text.count(added),1);text=text.replace(added,'return 2'if status==2 else'return')
  for row in MAP['implicit'].values():self.assertEqual(text.count(row['after']),1);text=text.replace(row['after'],row['before'])
  self.assertEqual(text.encode(),OLD['guest/initialized-state.sh'])
  root=re.sub(r'^ *_ig_substage [A-Z0-9_]+\n','',NEW['guest/root.sh'].decode(),flags=re.M)
  self.assertEqual(root.encode(),OLD['guest/root.sh'])
  saved=json.loads((HERE/'mapping.DATA.json').read_bytes());self.assertEqual(saved['returns'],MAP['returns'])
  self.assertEqual(tuple(saved['public_nodes']),T.PATHS)
  for row in MAP['returns']:self.assertEqual(OLD['guest/initialized-state.sh'].decode().splitlines()[row['line']-1],row['original'])
 def test_changed_predecessor_or_diagnostic_body_refuses(self):
  wrong=dict(OLD);wrong['guest/root.sh']+=b'\n'
  with self.assertRaises(ValueError):P.transform(wrong)
  wrong=dict(NEW);wrong['guest/initialized-state.sh']+=b'\n'
  with self.assertRaises(ValueError):P.inverse(OLD,wrong,MAP)
 def test_repeated_capture_and_success_have_no_guard_failure_markers(self):
  f=self.fixture();before=T.descriptor(f.root);result,text=self.shell(f,f.capture()+f.capture()+'_initialized_guard\n')
  self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(text,'');self.assertEqual(T.descriptor(f.root),before)
 def test_each_of_all14_public_nodes_reports_precise_index_and_same_exit(self):
  for index,path in enumerate(T.PATHS):
   def change(f,path=path):
    q=f.root/path
    return ('rm -- '+shlex.quote(str(q))+'\nln -s -- ../usr/lib/PRIVATE_SENTINEL '+shlex.quote(str(q))if q.is_symlink()else'chmod '+format((q.stat().st_mode&0o777)^0o020,'o')+' -- '+shlex.quote(str(q)))
   with self.subTest(index=index,path=path):
    _,before,_=self.original_guard(change,instrumented=False);_,after,text=self.original_guard(change)
    self.assertEqual((before.returncode,after.returncode),(2,2),after.stderr)
    self.assertIn('CHECK=R21 INDEX='+str(index)+'\n',text)
 def test_cache_content_change_remains_HOLD_without_repair(self):
  mutation=lambda f:'printf PRIVATE_SENTINEL > '+shlex.quote(str(f.root/'etc/ld.so.cache'))
  _,before,_=self.original_guard(mutation,instrumented=False);f,after,text=self.original_guard(mutation)
  self.assertEqual((before.returncode,after.returncode),(2,2));self.assertIn('CHECK=R21 INDEX=5',text)
  self.assertEqual((f.root/'etc/ld.so.cache').read_text(),'PRIVATE_SENTINEL')
 def test_xattrs_and_descriptor_identity_report_distinct_unchanged_checks(self):
  for instrumented in(False,True):
   f,result,text=self.original_guard(lambda f:'setfattr -n user.test -v PRIVATE_SENTINEL '+shlex.quote(str(f.root/'etc/.updated')),instrumented)
   self.assertEqual(result.returncode,2,result.stderr)
   if instrumented:self.assertIn('CHECK=R23 INDEX=1',text)
  f,result,text=self.original_guard(lambda f:'printf PRIVATE_SENTINEL >> '+shlex.quote(str(f.context)))
  self.assertEqual(result.returncode,2,result.stderr);self.assertIn('CHECK=R18 INDEX=14',text)
 def test_nonempty_SSH_refuses_before_xattrs_and_never_emits_child_name_or_body(self):
  f=self.fixture();secret=f.root/'root/.ssh/PRIVATE_SENTINEL';secret.write_text('PRIVATE_BODY')
  result,text=self.shell(f,'_initialized_attrs() { printf ATTR_VISIT >&2;return 37; }\n'+f.capture())
  self.assertNotEqual(result.returncode,0);self.assertIn('CHECK=E0 INDEX=13',text)
  self.assertNotIn('ATTR_VISIT',result.stderr);self.assertNotIn('PRIVATE_BODY',text+result.stdout+result.stderr)
 def test_command_status_and_unavailable_console_preserve_refusal(self):
  for instrumented in(False,True):
   _,result,text=self.original_guard(lambda f:'_initialized_attrs() { return 37; }',instrumented)
   self.assertEqual(result.returncode,37)
   if instrumented:self.assertIn('CHECK=R22 INDEX=0',text)
  _,result,text=self.original_guard(lambda f:'chmod 664 '+shlex.quote(str(f.root/'etc/.updated')),missing_console=True)
  self.assertEqual(result.returncode,2);self.assertEqual(text,'')
 def test_missing_selected_node_preserves_native_status_and_public_index(self):
  mutation=lambda f:'rm -- '+shlex.quote(str(f.root/'etc/.updated'))
  _,before,_=self.original_guard(mutation,instrumented=False);_,after,text=self.original_guard(mutation)
  self.assertEqual((before.returncode,after.returncode),(1,1))
  self.assertIn('CHECK=I0 INDEX=1',text);self.assertIn('CHECK=R20 INDEX=1',text)
 def functions(self,f,instrumented):
  text=(NEW if instrumented else OLD)['guest/root.sh'].decode();text=text[text.index('user_snapshot() ('):text.index('payload_snapshot() (')]
  expected='/home/builder /root';self.assertEqual(text.count(expected),3)
  return text.replace(expected,shlex.quote(str(f.root/'home/builder'))+' '+shlex.quote(str(f.root/'root')))
 def post(self,f,instrumented,mutation=''):
  root=(NEW if instrumented else OLD)['guest/root.sh'].decode()
  start=root.index('verify_installed_metadata "$D" "$O/installed-metadata"\n')+len('verify_installed_metadata "$D" "$O/installed-metadata"\n')
  tail=root[start:root.index('checkpoint_phase probe_wait',start)]
  tail=tail.replace('-o1000 -g1000','-o'+str(os.getuid())+' -g'+str(os.getgid()))
  out=f.d/'output';state=out/'root';metadata=out/'installed-metadata';metadata.mkdir(parents=True);state.mkdir();(metadata/'added.paths').write_text('PUBLIC_FIXTURE\n')
  code='. '+shlex.quote(str(LEGACY/'guest/case.sh'))+'\nO='+shlex.quote(str(out))+'\nS='+shlex.quote(str(state))+'\n'+self.functions(f,instrumented)
  code+=f.capture()+'user_snapshot "$S/user-before"\n'
  if instrumented:code+=': > '+shlex.quote(str(f.d/'console'))+'\n'
  code+=mutation+'\n'+tail
  return self.shell(f,code,instrumented),state
 def test_post_metadata_copy_remove_users_and_marker_success_boundaries(self):
  for instrumented in(False,True):
   f=self.fixture();(result,text),state=self.post(f,instrumented)
   self.assertEqual(result.returncode,0,result.stderr);self.assertEqual((state/'added.paths').read_text(),'PUBLIC_FIXTURE\n')
   if instrumented:
    stages=STAGE.findall(text);self.assertEqual(stages[:4],['METADATA_RETURNED','COPY_DONE','REMOVE_DONE','ASSERT_USERS_ENTER'])
    self.assertIn('ASSERT_USERS_DONE',stages);self.assertEqual(stages[-2:],['USER_DIR_DONE','INSTALLED_MARKER_DONE'])
 def test_post_metadata_real_cache_mutation_stops_before_any_private_inventory(self):
  for instrumented in(False,True):
   f=self.fixture();(result,text),state=self.post(f,instrumented,'printf PRIVATE_SENTINEL > '+shlex.quote(str(f.root/'etc/ld.so.cache')))
   self.assertEqual(result.returncode,2,result.stderr);self.assertFalse((state/'user-current.meta').exists())
   if instrumented:
    self.assertIn('CHECK=R21 INDEX=5',text);self.assertIn('STAGE=SNAPSHOT_ENTER',text)
    self.assertNotIn('STAGE=SNAPSHOT_GUARD1_DONE',text);self.assertNotIn('STAGE=ASSERT_USERS_DONE',text)
 def test_post_metadata_copy_and_rm_errors_keep_status_and_last_boundary(self):
  for kind,expected in(('copy',1),('rm',37)):
   for instrumented in(False,True):
    f=self.fixture();mutation=('command rm -- "$O/installed-metadata/added.paths"'if kind=='copy'else'rm() { return 37; }')
    (result,text),_=self.post(f,instrumented,mutation);self.assertEqual(result.returncode,expected,result.stderr)
    if instrumented:
     self.assertIn('STAGE=METADATA_RETURNED',text);self.assertNotIn('STAGE=ASSERT_USERS_ENTER',text)
     self.assertEqual('STAGE=COPY_DONE'in text,kind=='rm')
 def test_user_inventory_change_is_not_mislabeled_as_initialized_guard_failure(self):
  f=self.fixture();(result,text),_=self.post(f,True,'printf PRIVATE_SENTINEL > '+shlex.quote(str(f.root/'home/builder/PRIVATE_SENTINEL')))
  self.assertEqual(result.returncode,1,result.stderr);self.assertNotIn('CHECK=',text)
  self.assertIn('STAGE=USERS_SNAPSHOT_DONE',text);self.assertNotIn('STAGE=USERS_META_MATCHED',text)
 def test_arbitrary_data_rejected_and_five_field_protocol_unchanged(self):
  f=self.fixture();result,text=self.shell(f,'_ig_diagnostic "R21 PRIVATE_SENTINEL" 5\n_ig_diagnostic R21 "5 PRIVATE_SENTINEL"\n_ig_diagnostic R999 5\n_ig_diagnostic R21 15\n_ig_substage PRIVATE_SENTINEL\n_ig_substage COPY_DONE\n')
  self.assertEqual(result.returncode,0);self.assertEqual(text,'\nPERL5423_POST_METADATA_DIAGNOSTIC_V1 STAGE=COPY_DONE\n')
  protocol=module('unchanged_guard_protocol',LEGACY/'protocol.py');nonce=T.NONCE
  frame=f'PERL5423_RESTORED_BEGIN {nonce}\nSTATUS=HOLD\nFAILED_PHASE=installed_metadata\nEXIT_STATUS=2\nPERL5423_RESTORED_END {nonce}\n'
  self.assertEqual(protocol.frame((text+frame).encode(),nonce,'RESTORED'),dict(STATUS='HOLD',FAILED_PHASE='installed_metadata',EXIT_STATUS='2'))
if __name__=='__main__':unittest.main(verbosity=2)
