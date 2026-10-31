# SPDX-License-Identifier: MIT
"""Whole public210 emission, finite inverse and real pre-output drift controls."""
import ast,importlib.util,json,os,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
import correctness9000 as C
F=C.F
BASE=Path(os.environ.get('REPAIR_CORRECTNESS_BASE_SOURCE',str(F.HERE.parents[2]/'.ci-inputs/repair210-cost'))).absolute()
EXPECTED=Path(os.environ.get('REPAIR_CORRECTNESS_EXPECTED_SOURCE',str(F.HERE.parents[2]/'.ci-inputs/repair210-correctness9000'))).absolute()
def functions(raw):return {n.name:ast.dump(n,include_attributes=False)for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def adapter():
 spec=importlib.util.spec_from_file_location('_correctness9000_emitted_adapter',EXPECTED/F.ADAPTER);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
class Factory(unittest.TestCase):
 def test_complete_public210_emission_NULL_and_failed_history(self):
  p=C.inputs();self.assertEqual(F.files(BASE),p['before']);self.assertEqual(F.files(EXPECTED),p['after'])
  with tempfile.TemporaryDirectory()as t,patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS_API_GIT')):
   out=Path(t)/'source';value=C.prepare(BASE,out,C.NAME);self.assertEqual(F.files(out),F.files(EXPECTED));self.assertEqual(F.files(BASE),p['before']);self.assertEqual(value['expected_fixture_source'],'6402dd1cfbcc2eebb17ff511d0c1c4694bb53dda');self.assertIsNone(value['source']);self.assertIsNone(value['ref']);self.assertTrue(all(x is None for x in value['run_ids'].values()));self.assertTrue(value['old4800_fit'].startswith('FAILED_'));self.assertTrue(value['old6000_fit'].startswith('FAILED_'));self.assertEqual(value['correctness9000'],'NATIVE_PENDING');self.assertEqual(value['performance'],'NOT_CLAIMED')
 def test_complete_inverse_original_methods_and_host_clocks_held(self):
  p=C.inputs();self.assertEqual(sum(p['before'][n]==p['after'][n]for n in p['before']),203)
  for name in(F.ADAPTER,F.TEST,C.GUEST):
   before=F.read(BASE/name);after=C.derive(name,before);self.assertEqual(F.pin(after),p['after'][name]);text=after.decode().replace('9000','4800').replace('9010','4810').replace('GUEST_COPY_CORRECTNESS_4800','GUEST_COPY_COLD_VALIDATION_4800');self.assertEqual(text.encode(),before)
  for n,allowed in [(F.ADAPTER,{'rendered_backend'}),(C.GUEST,{'capacity_clock'})]:
   a,b=functions(F.read(BASE/n)),functions(F.read(EXPECTED/n));self.assertEqual(a.keys(),b.keys());self.assertEqual({k for k in a if a[k]!=b[k]},allowed)
  for name in('job_clock.py','vm.py','disk.py','native_prepare.py','job.py'):self.assertEqual(F.read(BASE/F.BRIDGE/name),F.read(EXPECTED/F.BRIDGE/name))
  clock=F.read(EXPECTED/F.BRIDGE/'job_clock.py').decode();self.assertIn('JOB=21000;POST=1260;ADMISSION=120;KILL=30;OWNER_MARGIN=90',clock);self.assertIn('seconds=min(18000,',clock);self.assertIn('seconds=min(18550,',clock)
 def test_real_capacity_and_backend_calls_hold_original_routing(self):
  A=adapter();env={};exec(A.CAPACITY_BIND,env);seen=[]
  def original(args=None):seen.append(args);return 300 if args is None else 600
  wrapped=env['_vm_capacity_wrap'](original);self.assertEqual(wrapped(),300)
  for action,want in [('prepare-copy',9000),('apply',600),('dispose-copy',600),('inspect',600)]:
   args=types.SimpleNamespace(action=action);self.assertEqual(wrapped(args),want);self.assertIs(seen[-1],args)
  for invalid in(True,600.,599,601,None):
   with self.assertRaises(ValueError):env['_vm_capacity_wrap'](lambda _:invalid)(types.SimpleNamespace(action='prepare-copy'))
  class Calls:
   def call(self,argv,*,seconds=610,expected=0):seen.append((self,argv,seconds,expected));return 'ORIGINAL_RESULT'
  env={'C':types.SimpleNamespace(),'H':types.SimpleNamespace(Calls=Calls),'types':types};exec(A.BACKEND_NOTE,env);obj=Calls();api=types.SimpleNamespace(run_command=lambda *a,**k:None);obj.api=api;command=['/usr/bin/python3','-I','-B','/execution/scripts/ci/apps7-full574-repair-native/transaction.py','prepare-copy']
  for argv,seconds,want in[(command,610,9010),(command,611,611),([*command[:4],'apply'],610,610),(['/usr/bin/false'],610,610)]:self.assertEqual(obj.call(argv,seconds=seconds,expected=7),'ORIGINAL_RESULT');self.assertEqual(seen[-1],(obj,argv,want,7));self.assertIs(obj.api,api)
 def test_implicit_foreign_profile_refuses_before_inputs(self):
  with tempfile.TemporaryDirectory()as t,patch.object(C,'inputs',side_effect=AssertionError('implicit profile read')):
   for value in(None,'cost-data-lifetime210','correctness6000','correctness9001'):
    with self.assertRaisesRegex(ValueError,'explicit --profile'):C.prepare(Path('/not-opened'),Path(t)/'out',value)
    self.assertFalse((Path(t)/'out').exists())
 def test_actual_drift_alias_existing_and_late_source_change_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);base=root/'base';shutil.copytree(BASE,base);out=root/'out';leaf=base/'scripts/update/measure_copy.py';held=leaf.read_bytes();leaf.write_bytes(held+b'drift')
   with self.assertRaisesRegex(ValueError,'whole exact'):C.prepare(base,out,C.NAME)
   self.assertFalse(out.exists());leaf.write_bytes(held);(base/'extra').write_bytes(b'unknown')
   with self.assertRaisesRegex(ValueError,'whole exact'):C.prepare(base,out,C.NAME)
   self.assertFalse(out.exists());(base/'extra').unlink();(base/'alias').symlink_to(leaf)
   with self.assertRaises(ValueError):C.prepare(base,out,C.NAME)
   self.assertFalse(out.exists());(base/'alias').unlink();derive=C.derive
   def mutate(name,raw):
    value=derive(name,raw)
    if name==F.TEST:leaf.write_bytes(held+b'late foreign edit')
    return value
   with patch.object(C,'derive',mutate),self.assertRaisesRegex(ValueError,'full physical input reread'):C.prepare(base,out,C.NAME)
   self.assertFalse(out.exists());leaf.write_bytes(held);out.mkdir();(out/'sentinel').write_bytes(b'preserve')
   with self.assertRaisesRegex(ValueError,'fresh separate'):C.prepare(base,out,C.NAME)
   self.assertEqual((out/'sentinel').read_bytes(),b'preserve')
 def test_profile_helper_drift_and_actual_CLI_full_emission(self):
  read=F.read
  for target,why in[(C.HERE/'correctness9000-profile.json','profile pin'),(C.HERE/'cost210.py','helper pin')]:
   with patch.object(F,'read',side_effect=lambda p:read(p)+b'drift'if Path(p)==target else read(p)),self.assertRaisesRegex(ValueError,why):C.inputs()
  with tempfile.TemporaryDirectory()as t:
   out=Path(t)/'source';auth=Path(t)/'authorization.json';subprocess.run([sys.executable,'-B','-W','error',str(C.HERE/'correctness9000.py'),'--profile',C.NAME,'--base-root',str(BASE),'--output',str(out),'--authorization',str(auth)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.assertEqual(F.files(out),F.files(EXPECTED));self.assertEqual(json.loads(auth.read_bytes())['guest_copy_seconds'],[9000,9010])
if __name__=='__main__':unittest.main(verbosity=2)
