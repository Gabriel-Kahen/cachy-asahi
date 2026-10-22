# SPDX-License-Identifier: MIT
"""Exact emission/inverses, complete emitted controls and real drift refusals."""
import ast,importlib.util,json,os,re,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import postcopy_cli as P
F=P.F
BASE=Path(os.environ.get('REPAIR_POSTCOPY_BASE_SOURCE',str(F.HERE.parents[2]/'.ci-inputs/repair210-correctness9000'))).absolute()
EXPECTED=Path(os.environ.get('REPAIR_POSTCOPY_EXPECTED_SOURCE',str(F.HERE.parents[2]/'.ci-inputs/repair210-postcopy-cli'))).absolute()
def functions(raw):return {n.name:ast.dump(n,include_attributes=False)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
class Factory(unittest.TestCase):
 def test_exact210_emission_and_NULL_results(self):
  p,_=P.inputs();self.assertEqual(F.files(BASE),p['before']);self.assertEqual(F.files(EXPECTED),p['after'])
  with tempfile.TemporaryDirectory()as td,patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS_API_GIT')):
   out=Path(td)/'source';v=P.prepare(BASE,out,P.NAME);self.assertEqual(F.files(out),F.files(EXPECTED));self.assertEqual(v['expected_fixture_source'],'c44b4ae622e77e4a5a8ba27fa5966619b96e8beb');self.assertIsNone(v['source']);self.assertIsNone(v['ref']);self.assertTrue(all(x is None for x in v['run_ids'].values()));self.assertEqual(v['clocks'],'UNCHANGED');self.assertEqual(v['actual_CLI_error'],'UNEXPORTED_UNKNOWN');self.assertEqual(v['correctness9000_result'],'FAILED_POSTCOPY_CLI_CAUSE_UNEXPORTED');self.assertEqual(v['native_fit'],'UNKNOWN')
 def test_full_inverses_and_original_clocks_security_held(self):
  p,bodies=P.inputs();self.assertEqual(sum(p['before'][n]==p['after'][n]for n in p['before']),203)
  for name in(F.ADAPTER,P.GUEST,F.TEST):self.assertEqual(P.derive(name,F.read(BASE/name),bodies),F.read(EXPECTED/name))
  old=F.read(BASE/F.ADAPTER).decode();new=F.read(EXPECTED/F.ADAPTER).decode();assignment=lambda text:next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and any(isinstance(x,ast.Name)and x.id=='BACKEND_NOTE'for x in n.targets));a,b=assignment(old),assignment(new);v=ast.literal_eval(b.value);v=F.once(v,bodies['postcopy_cli_capture.py.in'].decode(),'');v=F.once(v,P.INSERT,'');self.assertEqual(v,ast.literal_eval(a.value));self.assertEqual(F.once(F.read(EXPECTED/P.GUEST).decode(),P.PROMOTE,''),F.read(BASE/P.GUEST).decode());self.assertEqual(F.once(F.read(EXPECTED/F.TEST).decode(),bodies['postcopy_cli_tests.py.in'].decode(),''),F.read(BASE/F.TEST).decode())
  aa,bb=functions(old),functions(new);self.assertEqual(aa.keys(),bb.keys());self.assertEqual({n for n in aa if aa[n]!=bb[n]},{'lifecycle'});self.assertEqual(F.once(bb['lifecycle'],ast.dump(ast.parse(P.ALLOW_AFTER).body[0].value,include_attributes=False),ast.dump(ast.parse(P.ALLOW_BEFORE).body[0].value,include_attributes=False)),aa['lifecycle'])
  for name in('job_clock.py','vm.py','disk.py','native_prepare.py','job.py','input-policy.json','source-pins.json'):self.assertEqual(F.read(BASE/F.BRIDGE/name),F.read(EXPECTED/F.BRIDGE/name))
 def test_entire_emitted57_lane_and6_CI_controls_in_private_NULL_view(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)/'source';P.prepare(BASE,root,P.NAME);(root/F.BRIDGE/'input-policy.json').write_bytes(F.enc(dict(schema_version=1,status='UNBOUND_NEW_NATIVE_REPAIR_CASES_AND_ACCEPTED_KERNEL',binding=None)));old=F.pin(F.read(root/F.MF))['sha256']
   for lane in(F.BRIDGE,F.CI):
    f=root/lane/'source-manifest.json';v=json.loads(F.read(f));v['files']={n:F.pin(F.read(root/n))for n in v['files']};f.write_bytes(F.enc(v))
   new=F.pin(F.read(root/F.MF))['sha256']
   for n in F.WORKFLOWS:
    f=root/n;s=f.read_text();f.write_text(F.once(s,old,new))
   for file,count in((F.TEST,57),(F.CI+'/test_ci.py',6)):
    r=subprocess.run([sys.executable,'-I','-B','-W','error',str(root/file)],cwd=td,capture_output=True,timeout=120);self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));self.assertRegex(r.stderr.decode(),rf'Ran {count} tests in [0-9.]+s\s+OK');print('complete emitted source controls:',file,count,'PASS',file=sys.stderr)
 def test_missing_implicit_and_foreign_profiles_refuse_before_inputs(self):
  with tempfile.TemporaryDirectory()as td,patch.object(P,'inputs',side_effect=AssertionError('must refuse before input')):
   for value in(None,'correctness9000','postcopy-cli','postcopy-cli211'):
    with self.assertRaisesRegex(ValueError,'explicit --profile'):P.prepare(Path('/not-read'),Path(td)/'out',value)
    self.assertFalse((Path(td)/'out').exists())
 def test_whole_early_late_extra_missing_link_drift_refuses_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);base=root/'base';shutil.copytree(BASE,base);leaf=base/P.GUEST;raw=leaf.read_bytes();out=root/'out'
   for variant in('bytes','extra','missing','symlink','hardlink'):
    if variant=='bytes':leaf.write_bytes(raw+b'drift')
    elif variant=='extra':(base/'extra').write_bytes(b'foreign')
    elif variant=='missing':leaf.unlink()
    elif variant=='symlink':leaf.unlink();leaf.symlink_to(root/'holder');(root/'holder').write_bytes(raw)
    else:leaf.unlink();(root/'holder').write_bytes(raw);os.link(root/'holder',leaf)
    with self.subTest(variant=variant),self.assertRaises(ValueError):P.prepare(base,out,P.NAME)
    self.assertFalse(out.exists())
    if leaf.exists()or leaf.is_symlink():leaf.unlink()
    leaf.write_bytes(raw)
    if(base/'extra').exists():(base/'extra').unlink()
    if(root/'holder').exists():(root/'holder').unlink()
   derive=P.derive
   def changed(name,data,bodies):
    result=derive(name,data,bodies)
    if name==F.TEST:leaf.write_bytes(raw+b'late')
    return result
   with patch.object(P,'derive',changed),self.assertRaisesRegex(ValueError,'full physical input reread'):P.prepare(base,out,P.NAME)
   self.assertFalse(out.exists());leaf.write_bytes(raw);out.mkdir();(out/'sentinel').write_bytes(b'held')
   with self.assertRaisesRegex(ValueError,'fresh separate'):P.prepare(base,out,P.NAME)
   self.assertEqual((out/'sentinel').read_bytes(),b'held')
 def test_profile_existing_helpers_and_used_template_drift_refuse(self):
  read=F.read
  for name in('postcopy-cli-profile.json','cost210.py','correctness9000.py','postcopy_cli_capture.py.in','postcopy_cli_tests.py.in'):
   target=P.HERE/name
   with self.subTest(name=name),patch.object(F,'read',side_effect=lambda p:read(p)+b'drift'if Path(p)==target else read(p)),self.assertRaises(ValueError):P.inputs()
 def test_isolated_real_CLI_full_emission(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);out=root/'source';auth=root/'authorization.json';env=dict(os.environ);env.pop('PYTHONPATH',None);r=subprocess.run([sys.executable,'-I','-B','-W','error',str(P.HERE/'postcopy_cli.py'),'--profile',P.NAME,'--base-root',str(BASE),'--output',str(out),'--authorization',str(auth)],cwd=td,env=env,capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));self.assertEqual(F.files(out),F.files(EXPECTED));v=json.loads(auth.read_bytes());self.assertEqual(v['files'],F.files(EXPECTED));self.assertEqual(v['clocks'],'UNCHANGED');self.assertIsNone(v['source'])
if __name__=='__main__':unittest.main(verbosity=2)
