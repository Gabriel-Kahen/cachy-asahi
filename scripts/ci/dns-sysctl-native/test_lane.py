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
  self.assertIn('len(self)<6',new)
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

# Reuse eight original cleanup controls, original source/refusal controls and exact byte pair gate.
original=C.load('dns_sysctl_original_controls',ROOT/'scripts/ci/tools-native/test_native.py')
# Patch the derived modules' function-global namespaces in the inherited mock-only controls.
original.J=J.m;original.R=R.m;original.C=C.m
Cleanup=original.Cleanup
SourceProof=original.SourceProof
class Comparison(unittest.TestCase):
 test_byte_comparison_is_required_beyond_installed_contents=original.Acceptance.test_byte_comparison_is_required_beyond_installed_contents

if __name__=='__main__':unittest.main(verbosity=2)
