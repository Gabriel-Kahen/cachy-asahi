# SPDX-License-Identifier: MIT
"""Finite source/emission/refusal controls, no synthetic successful native evidence."""
import ast,hashlib,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import adapter as A
import contract as C
import job as J
import run as R
import selection as S
import rules

def function(raw,name):return ast.dump(next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name==name),include_attributes=False)

class DNSUpgrade(unittest.TestCase):
 def test_fixed_worker_capset_and_exec_guards_not_host_mutation(self):
  raw=(A.HERE/'profile_actor.py').read_text();self.assertIn('Header(0x20080522,0)',raw);self.assertIn('data=(Data*2)()',raw);self.assertIn('libc.prctl(38,1,0,0,0)',raw);self.assertIn('libc.prctl(47,4,0,0,0)',raw)
  self.assertIn("os.execve('/usr/bin/python3'",raw);self.assertIn('os.waitpid(pid,0)',raw);self.assertIn("binding['frame']==observed",raw);self.assertIn("namespace_frame(pid)",raw);self.assertNotIn('NET_ADMIN',raw)
  fixture=(A.HERE/'private_profile.py').read_text();self.assertIn("observed['PPid']==str(os.getpid())",fixture);self.assertIn('zero_frame(observed)',fixture)

 def test_worker_rejects_parent_caps_missing_nnp_or_changed_bounding_set(self):
  module=C.load('profile_worker_frames',A.HERE/'profile_actor.py')
  zero=dict(CapInh='0',CapPrm='0',CapEff='0',CapAmb='0',CapBnd='db',NoNewPrivs='1')
  for key,value in(('CapInh','1'),('CapPrm','db'),('CapEff','db'),('CapAmb','1'),('CapBnd','fff'),('NoNewPrivs','0')):
   changed=dict(zero);changed[key]=value;self.assertFalse(module.zero_frame(changed))
  with patch.object(module.os,'getuid',return_value=0),patch.object(module.os,'geteuid',return_value=0),patch.object(module.os,'getpid',return_value=2),patch.object(module.os,'getppid',return_value=9),self.assertRaisesRegex(ValueError,'container PID1'):module.worker_guard('1'*32)

 def test_supervision_receipts_refuse_unknown_parent_or_daemon_binding(self):
  for value in ({},{'supervision':{}},{'supervision':{'route':'ORIGINAL_SIX_CAP_SUPERVISOR_ZERO_CAP_NM_WORKER'}}):
   with self.assertRaises(ValueError):rules.supervision(value)
  for value in ({},{'Pid':'1','PPid':'0'},{'Pid':'2','PPid':'1','CapEff':'db'}):
   with self.assertRaises(ValueError):rules.frame(value,pid=2,ppid=1)

 def test_entire_source_python_files_compile(self):
  for p in A.ROOT.rglob('*.py'):compile(p.read_bytes(),str(p),'exec')
 def test_default_null_source_refuses_before_any_actor_or_output(self):
  self.assertEqual(set(S.policy(False)[k]for k in('actual_source','actual_ref','actual_run')),{None})
  with tempfile.TemporaryDirectory()as tmp,patch('subprocess.Popen',side_effect=AssertionError('no actor')):
   root=Path(tmp);output=root/'absent';policy=S.policy(False);policy['status']='UNBOUND_SOURCE_TEMPLATE';policy['candidate_source']=None;(root/'input-policy.json').write_text(json.dumps(policy))
   with patch.object(S,'HERE',root),self.assertRaisesRegex(ValueError,'UNBOUND'):R.execute(A.ROOT,root/'base',output,'1'*32)
   self.assertFalse(output.exists())
 def test_exact_source_preflight_and_original_complete_owner(self):
  with patch('subprocess.Popen',side_effect=AssertionError('source only')):self.assertEqual(S.verify_source(A.ROOT,False)['actual_run'],None)
  for n in json.loads((A.HERE/'original-pins.json').read_bytes()):A.read(A.ROOT,n)
  with self.assertRaises(ValueError):A.replace('two two','two','replacement')
 def test_roles_have_same_actual_pkgname_exact_distinct_versions(self):
  policy=S.policy(False);checks=C.load('dns_upgrade_real_metadata',A.ROOT/'scripts/checks/package_checks.py')
  for role,version,count in zip(S.NAMES,('0.1.0-1','0.1.0-2'),(21,27)):
   product=policy['products'][role];report=checks.recipe(A.ROOT/'packages/tools'/role/'PKGBUILD')
   self.assertEqual(report['errors'],[]);self.assertEqual(report['metadata']['pkgname'],['cachy-asahi-dns']);self.assertEqual(report['metadata']['pkgver'][0]+'-'+report['metadata']['pkgrel'][0],version)
   self.assertEqual(product['package_name'],'cachy-asahi-dns');self.assertEqual(product['version'],version);self.assertEqual(product['check_markers'],['Ran '+str(count)+' tests','\nOK'])
   self.assertEqual(report['input_sha256'],{p:r['sha256']for p,r in product['source_files'].items()})
 def test_original_builder_pair_gate_cleanup_and_budgets_held(self):
  original=A.read(A.ROOT,'scripts/ci/tools-native/run.py');emitted=A.text(A.ROOT,'run.py')
  self.assertEqual(function(original,'pair_gate'),function(emitted,'pair_gate'))
  self.assertEqual(function(A.read(A.ROOT,'scripts/ci/tools-native/job.py'),'cleanup'),function(A.text(A.ROOT,'job.py'),'cleanup'))
  for marker in('signal.setitimer(signal.ITIMER_REAL,2350)','len(self)<7',"out/'lifecycle.log',600",'limit=16*1024**2'):self.assertIn(marker,emitted)
  self.assertIn("execute(argv,directory/'build.log',240)",A.read(A.ROOT,'scripts/ci/welcome-native/run.py'));self.assertIn('MAX_TOTAL=192*1024**2',A.text(A.ROOT,'job.py'))
 def test_retainer_uses_actual_archive_name_not_recipe_alias(self):
  job=A.text(A.ROOT,'job.py');self.assertIn("name=C.package_name(product)+'-'+version+'-any.pkg.tar.'",job);self.assertIn("expected=C.package_name(product)+'-'+C.version(source,product)+'-any.pkg.tar.'",job);self.assertIn("basename.startswith(C.package_name(product)+'-')",job)
  self.assertNotIn("expected=product+'-'+C.version",job)
 def test_lifecycle_has_one_package_exact_upgrade_and_removal(self):
  raw=(A.HERE/'lifecycle.py').read_text();tree=ast.parse(raw);compile(tree,'lifecycle','exec')
  self.assertIn("('install-v1',C.NAMES[0]),('upgrade-v1-to-v2',C.NAMES[1])",raw);self.assertEqual(raw.count("pacman+['-R',actual]"),2)
  self.assertIn("base|{actual:row['version']}",raw);self.assertIn('I.payloads(L,{actual:row})',raw);self.assertIn('L.snapshot(trust)==trust_before',raw);self.assertIn('I.preserve_base(L,state)==base_digest',raw)
  self.assertNotIn('pacman+[\'-R\',*',raw)
 def test_installed_runner_exact_v1_and_v2_fixture_derivation(self):
  with tempfile.TemporaryDirectory()as tmp:
   runner=A.runner(A.ROOT,Path(tmp))
   for role,label in zip(S.NAMES,('v1','v2')):
    original=(A.ROOT/'packages/tools'/role/'test_dns.py').read_text();self.assertEqual((runner/('test_dns_'+label+'_installed.py')).read_text(),original.replace("str(HERE/'cachy-asahi-dns')","'/usr/bin/cachy-asahi-dns'"))
   for p in runner.rglob('*.py'):compile(p.read_bytes(),str(p),'exec')
   receipt=json.loads((Path(tmp)/'runner-derivations.json').read_bytes());self.assertEqual(set(receipt['files']),{p.relative_to(runner).as_posix()for p in runner.rglob('*')if p.is_file()})
 def test_private_supervisor_stages_candidate_native_payload_only_and_keeps_original_six_caps(self):
  M=C.load('dns_upgrade_actor',A.HERE/'profile_actor.py');shared=C.load('dns_upgrade_original_frame',A.ROOT/'scripts/ci/welcome-native/run.py');program=A.ROOT/'packages/tools/cachy-asahi-dns2/cachy-asahi-dns';captured=[]
  product=dict(payload={'usr/bin/cachy-asahi-dns':dict(sha256=C.digest(program),mode=0o755)},sha256='0'*64,version='0.1.0-2')
  class BeforeActor(Exception):pass
  def stop(argv,*args):captured.append(argv);raise BeforeActor()
  with tempfile.TemporaryDirectory()as tmp,patch('subprocess.Popen',side_effect=AssertionError('no actor')):
   out=Path(tmp);(out/'base-inventory.log').write_text('inert-only 0-1\n')
   with self.assertRaises(BeforeActor):M.launch(C,A.ROOT,out,'INERT',{'cachy-asahi-dns2':product},shared.docker,stop,[])
   self.assertEqual((out/'profile-inputs/dns-command').read_bytes(),program.read_bytes());self.assertEqual((out/'private-profile-actor').stat().st_mode&0o777,0o703)
   self.assertIn('--cap-drop=ALL',captured[0]);self.assertIn('--network=none',captured[0]);self.assertEqual([x for x in captured[0]if x.startswith('--cap-add=')],['--cap-add='+c for c in('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID')]);self.assertIn('-I',captured[0])
 def test_source_host_profile_refusal_and_no_old_lifecycle_credit(self):
  F=C.load('dns_upgrade_host_refusal',A.HERE/'private_profile.py')
  with tempfile.TemporaryDirectory()as tmp,patch('subprocess.Popen',side_effect=AssertionError('no host process')):
   out=Path(tmp)/'absent'
   with self.assertRaisesRegex(ValueError,'dedicated root'):F.run(out)
   self.assertFalse(out.exists())
  for value in ({},{'status':'PASS_DNS_SYSCTL_SIGNED_PRIVATE_LIFECYCLE'},{'status':'PASS_DNS2_UPGRADE_SIGNED_PRIVATE_LIFECYCLE','installed_count':576}):
   with self.assertRaises(ValueError):rules.validate(value)
  with self.assertRaises(ValueError):rules.validate_profile({'architecture':'x86_64'},'0'*64)

original=C.load('dns_upgrade_original_controls',A.ROOT/'scripts/ci/tools-native/test_native.py');original.J=J.m;original.R=R.m;original.C=C.m
Cleanup=original.Cleanup
SourceProof=original.SourceProof
class Comparison(unittest.TestCase):test_byte_comparison_is_required_beyond_installed_contents=original.Acceptance.test_byte_comparison_is_required_beyond_installed_contents
if __name__=='__main__':unittest.main(verbosity=2)
