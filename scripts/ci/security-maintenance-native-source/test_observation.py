#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""NEW observer DATA/schema and preservation controls; no ALPM/process mocks."""
import ast,copy,hashlib,json,os,re,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
DENIED={'subprocess.Popen','os.system','os.fork','os.forkpty','os.posix_spawn','os.exec',
        'os.kill','os.killpg','socket.__new__','socket.connect','socket.bind','socket.getaddrinfo','ctypes.dlopen'}
def no_actors(event,args):
 if event in DENIED:raise AssertionError('NEW_DATA_ONLY_ACTOR_DENIED:'+event)
if __name__=='__main__':sys.addaudithook(no_actors)
def need(v,s):
 if not v:raise ValueError(s)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
contract=json.loads((HERE/'overlay/native/security-contract-v1.json').read_bytes());policy=contract['upgrade']['observation']
tree=ast.parse((HERE/'overlay/native/security_reader_v1.py').read_bytes())
namespace=dict(need=need,pin=pin,json=json,re=re)
functions=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in('_cleanup_require','_cleanup_pin','validate_observation')]
exec(compile(ast.Module(body=functions,type_ignores=[]),'maintained-new-observer-validator','exec'),namespace)
validate=namespace['validate_observation']
def fixture():
 # Deliberately unbound schema DATA only; this is not a pacman transaction mock.
 point=dict(type='FIRST_UPGRADE_ZERO',pid=202,ppid=101,event=1,percent=0,howmany=1,current=1,
   old_only_errno=2,new_only_errno=2,old_desc_errno=2,new_desc_errno=2,
   lock=dict(dev=55,ino=123,mode=0o100000,uid=0,gid=0,nlink=1,bytes=0),
   pacman_inode=[55,201],libalpm_inode=[55,202],symbol_object_verified=1)
 end=dict(type='END',pid=202,registrations=1,hits=1,errors=0);rows=[point,end]
 raw=''.join(json.dumps(r,separators=(',',':'))+'\n'for r in rows)
 retirement=dict(pid=203,exit=0,natural_exit=True,group_absent=True,leader_held_until_group_inspection=True,
   exit_observed_via_waitpid=True,ownership_lost=False,retirement='REAPED',forced_cleanup=False,cleanup_member_uids=[],elapsed_seconds=0.1)
 return dict(schema=1,protocol=policy['protocol'],phase=policy['phase'],observer_source=policy['source_pin'],
   observer_compiled=pin(b'unbound new compiled-observer DATA'),compiler_retirement=retirement,raw_pin=pin(raw.encode()),
   raw_ascii=raw,records=rows,runtime=dict(pacman=dict(pin(b'UNBOUND pacman DATA'),inode=[55,201]),
   libalpm=dict(bytes=4096,sha256=policy['libalpm_sha256'],inode=[55,202])),owner_pid=101,
   witness_paths={k:policy[k]for k in('old_only','new_only')},source_binary_correspondence='OPEN',interruption='NOT_RUN',recovery='NOT_RUN')
def refresh(v):
 v['raw_ascii']=''.join(json.dumps(r,separators=(',',':'))+'\n'for r in v['records']);v['raw_pin']=pin(v['raw_ascii'].encode())
class Observation(unittest.TestCase):
 def refuses(self,change,raw=False):
  v=fixture();change(v)
  if raw:refresh(v)
  with self.assertRaises((ValueError,KeyError,TypeError,UnicodeError)):validate(v,policy)
 def test_new_unbound_complete_schema_only(self):self.assertEqual(validate(fixture(),policy),fixture())
 def test_missing_observation_cannot_reuse_v6(self):self.refuses(lambda v:v.pop('records'))
 def test_extra_claim_refused(self):self.refuses(lambda v:v.update(recovered=True))
 def test_wrong_phase_refused(self):self.refuses(lambda v:v.update(phase='INTACT_OLD_DATABASE'))
 def test_midcommit_credit_refused(self):self.refuses(lambda v:v.update(interruption='PASS'))
 def test_recovery_credit_refused(self):self.refuses(lambda v:v.update(recovery='PASS'))
 def test_source_binary_credit_refused(self):self.refuses(lambda v:v.update(source_binary_correspondence='VERIFIED'))
 def test_observer_source_drift_refused(self):self.refuses(lambda v:v.update(observer_source=pin(b'changed source')))
 def test_raw_digest_mismatch_refused(self):self.refuses(lambda v:v.update(raw_pin=pin(b'other callback DATA')))
 def test_raw_parsed_record_mismatch_refused(self):self.refuses(lambda v:v['records'][0].update(percent=1))
 def test_duplicate_callback_field_refused(self):
  v=fixture();v['raw_ascii']=v['raw_ascii'].replace('"event":1','"event":1,"event":1');v['raw_pin']=pin(v['raw_ascii'].encode())
  with self.assertRaises(ValueError):validate(v,policy)
 def test_unbounded_raw_refused(self):self.refuses(lambda v:v.update(raw_ascii='x'*16385))
 def test_later_callback_refused(self):self.refuses(lambda v:v['records'][0].update(percent=1),True)
 def test_remove_phase_refused(self):self.refuses(lambda v:v['records'][0].update(event=4),True)
 def test_wrong_transaction_count_refused(self):self.refuses(lambda v:v['records'][0].update(howmany=2),True)
 def test_helper_process_refused(self):self.refuses(lambda v:v['records'][0].update(ppid=303),True)
 def test_unverified_loaded_object_refused(self):self.refuses(lambda v:v['records'][0].update(symbol_object_verified=0),True)
 def test_wrong_runtime_binary_refused(self):self.refuses(lambda v:v['runtime']['libalpm'].update(sha256='0'*64))
 def test_callback_library_inode_drift_refused(self):self.refuses(lambda v:v['records'][0].update(libalpm_inode=[55,999]),True)
 def test_unknown_filesystem_error_refused(self):self.refuses(lambda v:v['records'][0].update(old_only_errno=13),True)
 def test_old_payload_still_present_refused(self):self.refuses(lambda v:v['records'][0].update(old_only_errno=0),True)
 def test_new_payload_already_extracted_refused(self):self.refuses(lambda v:v['records'][0].update(new_only_errno=0),True)
 def test_old_db_desc_still_present_refused(self):self.refuses(lambda v:v['records'][0].update(old_desc_errno=0),True)
 def test_new_db_desc_already_written_refused(self):self.refuses(lambda v:v['records'][0].update(new_desc_errno=0),True)
 def test_lock_alias_refused(self):self.refuses(lambda v:v['records'][0]['lock'].update(nlink=2),True)
 def test_lock_type_mode_refused(self):self.refuses(lambda v:v['records'][0]['lock'].update(mode=0o100600),True)
 def test_missing_exit_record_refused(self):self.refuses(lambda v:v['records'].pop(),True)
 def test_rebinding_refused(self):self.refuses(lambda v:v['records'][1].update(registrations=2),True)
 def test_missing_hit_refused(self):self.refuses(lambda v:v['records'][1].update(hits=0),True)
 def test_observation_error_refused(self):self.refuses(lambda v:v['records'][1].update(errors=1),True)
 def test_lost_compiler_ownership_refused(self):self.refuses(lambda v:v['compiler_retirement'].update(ownership_lost=True))
 def test_compiler_descendants_not_absent_refused(self):self.refuses(lambda v:v['compiler_retirement'].update(group_absent=False))
 def test_forced_compiler_retirement_refused(self):self.refuses(lambda v:v['compiler_retirement'].update(forced_cleanup=True))
 def test_compiler_elapsed_nonfinite_refused(self):self.refuses(lambda v:v['compiler_retirement'].update(elapsed_seconds=float('nan')))
 def test_bool_callback_integer_refused(self):self.refuses(lambda v:v['records'][0].update(event=True),True)
 def test_named_serialized_observation_role_cap(self):
  v=fixture();v['compiler_retirement']['elapsed_seconds']='x'*32768
  with self.assertRaisesRegex(ValueError,'serialized observation role'):validate(v,policy)
 def test_observer_source_has_no_interruption_or_command_actor(self):
  src=policy['source'];self.assertEqual(pin(src.encode()),policy['source_pin'])
  for forbidden in ('SIGSTOP','SIGKILL','kill(','killpg(','abort(','_exit(','system(','popen(','execve('):self.assertNotIn(forbidden,src)
  self.assertIn('if(original) original(original_ctx, event, pkg, percent, howmany, current);',src)
  self.assertIn('errno = saved_errno;',src);self.assertIn('dladdr((void *)real',src)
  self.assertIn('alpm_option_get_progresscb_ctx',src);self.assertIn('if(!cb)',src)
  self.assertIn('if(!hits && eligible()',src);self.assertIn('s.st_size + n > 16384',src)
if __name__=='__main__':
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Observation))
 if len(sys.argv)==2:
  with Path(sys.argv[1]).open('x')as f:json.dump(dict(status='PASS'if result.wasSuccessful()else'FAIL',controls=result.testsRun,failures=len(result.failures),errors=len(result.errors),actor_network_denied=True,pacman_mocks=False,Source_emissions=0,old_suite_replays=0),f,indent=2);f.write('\n')
 raise SystemExit(not result.wasSuccessful())
