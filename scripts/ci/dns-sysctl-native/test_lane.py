# SPDX-License-Identifier: MIT
"""Inert emission/refusal plus original ownership controls; never native acceptance fixtures."""
import ast,copy,hashlib,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import adapter as A
import contract as C
import run as R
import job as J
import selection as S
import rules
ROOT=A.ROOT

def function(raw,name):return ast.dump(next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name==name),include_attributes=False)

class Source(unittest.TestCase):
 def test_template_source_closure_does_not_authorize_run(self):
  with patch('subprocess.Popen',side_effect=AssertionError('process forbidden')):
   result=S.verify_source(ROOT,False);self.assertEqual(result['actual_run'],None)
   with tempfile.TemporaryDirectory()as tmp:
    root=Path(tmp);value=S.policy(False);value['status']='UNBOUND_SOURCE_TEMPLATE';value['candidate_source']=None
    (root/'input-policy.json').write_text(json.dumps(value));out=root/'out'
    with patch.object(S,'HERE',root),self.assertRaisesRegex(ValueError,'UNBOUND'):R.execute(ROOT,root/'base',out,'1'*32)
    self.assertFalse(out.exists())
 def test_source_template_binding_or_unknown_scope_refuses(self):
  policy=S.read(S.HERE/'input-policy.json')
  for key,value in [('actual_run','123'),('actual_source','a'*40),('actual_ref','branch'),('candidate_source','branch')]:
   bad=copy.deepcopy(policy);bad[key]=value
   with self.subTest(key=key),patch.object(S,'read',return_value=bad),self.assertRaises(ValueError):S.policy(False)
  with self.assertRaises(ValueError):rules.validate({'status':'PASS_DNS_SYSCTL_SIGNED_PRIVATE_LIFECYCLE'})
 def test_complete_original_pins_and_streams_reject_tamper(self):
  for name in json.loads((A.HERE/'original-pins.json').read_bytes()):A.read(ROOT,name)
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);target=root/'scripts/ci/tools-native/run.py';target.parent.mkdir(parents=True);target.write_text('changed')
   with self.assertRaises(ValueError):A.read(root,'scripts/ci/tools-native/run.py')
  with self.assertRaises(ValueError):A.replace('two two','two','three')
 def test_security_command_budgets_and_comparison_held(self):
  old=A.read(ROOT,'scripts/ci/tools-native/run.py');new=A.text(ROOT,'run.py')
  self.assertEqual(function(old,'pair_gate'),function(new,'pair_gate'))
  for marker in ('signal.setitimer(signal.ITIMER_REAL,2350)','limit=16*1024**2',"out/'lifecycle.log',600",'return plain_docker(*args,**kwargs)'):
   self.assertIn(marker,new)
  original=A.read(ROOT,'scripts/ci/welcome-native/run.py')
  self.assertIn("execute(argv,directory/'build.log',240)",original)
  self.assertIn("'--network=none'",original);self.assertIn("'--cap-drop=ALL'",original)
  self.assertIn('len(self)<7',new)
  job=A.text(ROOT,'job.py');self.assertIn('MAX_TOTAL=192*1024**2',job)
  self.assertEqual(function(A.read(ROOT,'scripts/ci/tools-native/job.py'),'cleanup'),function(job,'cleanup'))
 def test_runner_emission_exact_installed_load_and_held_signing_helpers(self):
  with tempfile.TemporaryDirectory()as tmp:
   path=A.runner(ROOT,Path(tmp));text=(path/'test_dns_installed.py').read_text()
   original=(ROOT/'packages/tools/cachy-asahi-dns/test_dns.py').read_text()
   self.assertEqual(text,original.replace("str(HERE/'cachy-asahi-dns')","'/usr/bin/cachy-asahi-dns'"))
   self.assertEqual((path/'installed.py').read_bytes(),(ROOT/'scripts/ci/apps-cache-native/installed.py').read_bytes())
   self.assertEqual((path/'accepted/lifecycle.py').read_bytes(),(ROOT/'scripts/ci/welcome-native/lifecycle.py').read_bytes())
   for child in path.rglob('*.py'):compile(child.read_bytes(),str(child),'exec')
   closure=json.loads((Path(tmp)/'runner-derivations.json').read_bytes())['files']
   self.assertEqual(set(closure),{p.relative_to(path).as_posix()for p in path.rglob('*')if p.is_file()})
 def test_real_recipe_metadata_and_dependency_providers(self):
  value=S.policy(False)
  rows={r['name']:r for r in json.loads((ROOT/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())['packages']}
  self.assertEqual(len(rows),574);self.assertEqual(rows['networkmanager']['version'],'1.58.1-2');self.assertEqual(rows['python']['version'],'3.14.8-1')
  checks=C.load('dns_sysctl_real_metadata',ROOT/'scripts/checks/package_checks.py')
  for name,product in value['products'].items():
   report=checks.recipe(ROOT/'packages/tools'/name/'PKGBUILD');self.assertEqual(report['errors'],[])
   self.assertEqual(report['metadata']['pkgver'],['0.1.0']);self.assertEqual(report['metadata']['pkgrel'],['1'])
   self.assertEqual(report['input_sha256'],{k:r['sha256']for k,r in product['source_files'].items()})
   for relation in report['metadata']['depends']:self.assertIn(relation.split('>=')[0],rows)
 def test_installed_fixture_has_no_live_mutation_cli(self):
  raw=(A.HERE/'fixture_checks.py').read_text();tree=ast.parse(raw)
  # Only the fixed help/keys commands execute installed products; model tests load byte-joined code.
  self.assertIn("command([str(program),'--help'])",raw)
  self.assertIn("command(['/usr/bin/cachy-asahi-sysctl','keys'])",raw)
  self.assertNotIn("'/proc/sys",raw);self.assertNotIn("'device'",raw)
  life=(A.HERE/'lifecycle.py').read_text();self.assertIn("I.guard(L,'lifecycle')",life)
  self.assertEqual(life.count("pacman+['-R',*reversed(C.NAMES)]"),2)
  self.assertIn('I.preserve_base(L,state)==base_digest',life)

class PrivateProfile(unittest.TestCase):
 def test_supervision_receipts_refuse_unknown_parent_or_daemon_binding(self):
  for value in ({},{'supervision':{}},{'supervision':{'route':'ORIGINAL_SIX_CAP_SUPERVISOR_ZERO_CAP_NM_WORKER'}}):
   with self.assertRaises(ValueError):rules.supervision(value)
  for value in ({},{'Pid':'1','PPid':'0'},{'Pid':'2','PPid':'1','CapEff':'db'}):
   with self.assertRaises(ValueError):rules.frame(value,pid=2,ppid=1)
 def test_worker_rejects_parent_caps_missing_nnp_or_changed_bounding_set(self):
  module=C.load('profile_worker_frames',A.HERE/'profile_actor.py')
  zero=dict(CapInh='0',CapPrm='0',CapEff='0',CapAmb='0',CapBnd='db',NoNewPrivs='1')
  for key,value in(('CapInh','1'),('CapPrm','db'),('CapEff','db'),('CapAmb','1'),('CapBnd','fff'),('NoNewPrivs','0')):
   changed=dict(zero);changed[key]=value;self.assertFalse(module.zero_frame(changed))
  with patch.object(module.os,'getuid',return_value=0),patch.object(module.os,'geteuid',return_value=0),patch.object(module.os,'getpid',return_value=2),patch.object(module.os,'getppid',return_value=9),self.assertRaisesRegex(ValueError,'container PID1'):module.worker_guard('1'*32)
 def test_fixed_worker_capset_and_exec_guards_not_host_mutation(self):
  raw=(A.HERE/'profile_actor.py').read_text();self.assertIn('Header(0x20080522,0)',raw);self.assertIn('data=(Data*2)()',raw);self.assertIn('libc.prctl(38,1,0,0,0)',raw);self.assertIn('libc.prctl(47,4,0,0,0)',raw)
  self.assertIn("os.execve('/usr/bin/python3'",raw);self.assertIn('os.waitpid(pid,0)',raw);self.assertIn("binding['frame']==observed",raw);self.assertIn("namespace_frame(pid)",raw);self.assertNotIn('NET_ADMIN',raw)
  fixture=(A.HERE/'private_profile.py').read_text();self.assertIn("observed['PPid']==str(os.getpid())",fixture);self.assertIn('zero_frame(observed)',fixture)
 def test_isolated_entry_loads_trusted_siblings_before_native_guard(self):
  import subprocess
  with tempfile.TemporaryDirectory()as tmp:
   runner=Path(tmp);(runner/'profile_actor.py').write_bytes((A.HERE/'profile_actor.py').read_bytes())
   (runner/'installed.py').write_text("def apis(): raise ValueError('TRUSTED_SIBLING_REACHED')\n")
   (runner/'private_profile.py').write_text('')
   result=subprocess.run([os.sys.executable,'-I','-B',str(runner/'profile_actor.py')],capture_output=True,timeout=5)
   self.assertEqual(result.returncode,1);self.assertIn(b'TRUSTED_SIBLING_REACHED',result.stderr);self.assertNotIn(b'ModuleNotFoundError',result.stderr)
 def test_flat_export_is_bounded_exclusive_readable_and_retires_private_work(self):
  module=C.load('profile_export_control',A.HERE/'profile_actor.py')
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);directory=root/'private';directory.mkdir();out=root/'out';out.mkdir()
   for name in ('receipt.json','NetworkManager.log','dbus.log'):(directory/name).write_bytes(name.encode())
   with patch.object(module.os,'fstat',wraps=os.fstat),patch.object(module.os,'getuid',return_value=0):
    # Local test files belong to the current user; all ownership observations are projected to0 only in this model.
    import types
    original_stat=Path.stat;original_fstat=os.fstat
    def owner(s):return types.SimpleNamespace(**{n:(0 if n=='st_uid'else getattr(s,n))for n in ('st_uid','st_nlink','st_mode','st_size','st_dev','st_ino','st_mtime_ns','st_ctime_ns')})
    with patch.object(Path,'stat',lambda p,*a,**k:owner(original_stat(p,*a,**k))),patch.object(module.os,'fstat',side_effect=lambda fd:owner(original_fstat(fd))):
     module.export_results(directory,out)
     private=root/'private2';private.mkdir();(private/'receipt.json').symlink_to(out/'receipt.json')
     with self.assertRaises(OSError):module.export_results(private,out)
   self.assertFalse(directory.exists())
   for name in ('receipt.json','NetworkManager.log','dbus.log'):
    self.assertEqual((out/name).read_bytes(),name.encode());self.assertEqual((out/name).stat().st_mode&0o777,0o644)
 def test_fixture_refuses_host_before_output_and_native_rules_reject_x86(self):
  F=C.load('profile_host_refusal',A.HERE/'private_profile.py')
  with tempfile.TemporaryDirectory()as tmp,patch('subprocess.Popen',side_effect=AssertionError('host process forbidden')):
   out=Path(tmp)/'absent'
   with self.assertRaisesRegex(ValueError,'dedicated root'):F.run(out)
   self.assertFalse(out.exists())
  for value in ({},{'status':'PASS_REAL_PRIVATE_STORED_PROFILE_INTEGRATION','architecture':'x86_64'}):
   with self.assertRaises(ValueError):rules.validate_profile(value,'0'*64)
 def test_real_staged_command_bytes_mode_and_original_six_cap_frame_without_actor(self):
  module=C.load('profile_actual_stage_control',A.HERE/'profile_actor.py')
  shared=C.load('profile_original_docker_frame',ROOT/'scripts/ci/welcome-native/run.py')
  program=ROOT/'packages/tools/cachy-asahi-dns/cachy-asahi-dns';captured=[]
  product={'payload':{'usr/bin/cachy-asahi-dns':{'sha256':C.digest(program),'mode':0o755}},'sha256':'0'*64,'version':'0.1.0-1'}
  class StagedBeforeAnyActor(Exception):pass
  def stop(argv,log,seconds):captured.append(argv);raise StagedBeforeAnyActor()
  with tempfile.TemporaryDirectory()as tmp:
   out=Path(tmp);(out/'base-inventory.log').write_text('fixture-only 0-1\n')
   with patch('subprocess.Popen',side_effect=AssertionError('actor forbidden')),self.assertRaises(StagedBeforeAnyActor):
    module.launch(C,ROOT,out,'INERT_NO_DAEMON_MODEL',{'cachy-asahi-dns':product},shared.docker,stop,[])
   staged=out/'profile-inputs/dns-command';self.assertEqual(staged.read_bytes(),program.read_bytes());self.assertEqual(staged.stat().st_mode&0o777,0o755)
   self.assertEqual((out/'private-profile-actor').stat().st_mode&0o777,0o703)
   self.assertEqual([a for a in captured[0]if a.startswith('--cap-add=')],['--cap-add='+c for c in('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID')]);self.assertIn('--cap-drop=ALL',captured[0]);self.assertIn('--network=none',captured[0])
   self.assertIn('type=bind,src='+str(staged)+',dst=/usr/bin/cachy-asahi-dns,readonly',captured[0])
 def test_supervisor_keeps_only_original_six_caps_and_preserves_other_guards(self):
  actor=(A.HERE/'profile_actor.py').read_text();self.assertNotIn("[a for a in argv if a not in caps]",actor);self.assertIn('drop_capabilities()',actor)
  self.assertIn("I.preserve_base(L,state)==before",actor);self.assertIn("after==network",actor)
  self.assertIn("os.uname().machine=='aarch64'",actor)
  self.assertIn("out/'private-profile.log',600",actor)
  emitted=A.text(ROOT,'run.py');self.assertIn('profile.launch(C,source,out,image,products,docker,command,containers)',emitted)
  self.assertEqual(emitted.count("'--env=CACHY_ASAHI_APPS_CACHE_OPERATION=lifecycle'"),1)

# Reuse eight original cleanup controls, original source/refusal controls and exact byte pair gate.
original=C.load('dns_sysctl_original_controls',ROOT/'scripts/ci/tools-native/test_native.py')
# Patch the derived modules' function-global namespaces in the inherited mock-only controls.
original.J=J.m;original.R=R.m;original.C=C.m
Cleanup=original.Cleanup
SourceProof=original.SourceProof
class Comparison(unittest.TestCase):
 test_byte_comparison_is_required_beyond_installed_contents=original.Acceptance.test_byte_comparison_is_required_beyond_installed_contents

if __name__=='__main__':unittest.main(verbosity=2)
