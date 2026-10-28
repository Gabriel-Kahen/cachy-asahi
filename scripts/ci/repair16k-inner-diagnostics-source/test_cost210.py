# SPDX-License-Identifier: MIT
"""Exact public fixtures, closed source emission and real identity refusals."""
import ast,hashlib,json,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import cost210 as F
BASE=Path(os.environ.get('REPAIR_COPY_COST_BASE_SOURCE',str(F.HERE.parents[2]/'.ci-inputs/repair210-copy-cost-base'))).absolute()
EXPECTED=Path(os.environ.get('REPAIR_COPY_COST_EXPECTED_SOURCE',str(F.HERE.parents[2]/'.ci-inputs/repair210-copy-cost-expected'))).absolute()
class Factory(unittest.TestCase):
 def test_exact_complete210_emission_and_all_actuals_null(self):
  p,_=F.inputs();before=F.files(BASE);self.assertEqual(before,p['before']);self.assertEqual(F.files(EXPECTED),p['after'])
  with tempfile.TemporaryDirectory()as t,patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/API/Git')):
   out=Path(t)/'source';v=F.prepare(BASE,out,F.NAME);self.assertEqual(F.files(out),F.files(EXPECTED));self.assertEqual(F.files(BASE),before);self.assertEqual(v['expected_fixture_source'],'62c7a42c5288d83d23291a7f042ad8fa97a98bce');self.assertIsNone(v['source']);self.assertIsNone(v['ref']);self.assertTrue(all(x is None for x in v['run_ids'].values()));self.assertEqual(v['deadline_fit'],'NOT_ESTABLISHED');self.assertEqual(v['maximum_diagnostic_cases'],1)
 def test_default_and_wrong_profile_refuse_before_source_reads_or_output(self):
  with tempfile.TemporaryDirectory()as t,patch.object(F,'inputs',side_effect=AssertionError('implicit diagnostic accessed profile')):
   out=Path(t)/'unallocated'
   for profile in(None,'deadline-fix','cost-data-lifetime211'):
    with self.assertRaisesRegex(ValueError,'explicit --profile'):F.prepare(Path('/not-opened'),out,profile)
    self.assertFalse(out.exists())
 def test_real_changed_extra_alias_and_existing_output_refusals(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);base=root/'base';shutil.copytree(BASE,base,ignore=shutil.ignore_patterns('.git'));p=base/'scripts/update/measure_copy.py';before=p.read_bytes();p.write_bytes(before+b'drift')
   with self.assertRaisesRegex(ValueError,'whole exact'):F.prepare(base,root/'output',F.NAME)
   self.assertFalse((root/'output').exists());p.write_bytes(before);(base/'extra').write_bytes(b'unknown')
   with self.assertRaisesRegex(ValueError,'whole exact'):F.prepare(base,root/'output',F.NAME)
   (base/'extra').unlink();(base/'alias').symlink_to(p)
   with self.assertRaisesRegex(ValueError,'ordinary absolute'):F.prepare(base,root/'output',F.NAME)
   (base/'alias').unlink();out=root/'output';out.mkdir();(out/'sentinel').write_bytes(b'preserve')
   with self.assertRaisesRegex(ValueError,'fresh separate'):F.prepare(base,out,F.NAME)
   self.assertEqual((out/'sentinel').read_bytes(),b'preserve')
 def test_exact_helpers_referenced_and_original_runtime_clocks_bodies_held(self):
  p,bodies=F.inputs();self.assertEqual(len(p['before']),210);self.assertEqual(set(p['changed']),{F.ADAPTER,F.TEST,F.BM,F.MF,*F.WORKFLOWS})
  for name in p['before']:
   if name not in p['changed']:self.assertEqual(p['before'][name],p['after'][name])
  original=F.read(BASE/F.ADAPTER);after,_=F.derive(original,bodies);self.assertEqual(F.pin(after),p['after'][F.ADAPTER])
  def values(raw):return {t.id:n.value for n in ast.parse(raw).body if isinstance(n,ast.Assign)for t in n.targets if isinstance(t,ast.Name)}
  a,b=values(original),values(after)
  for key in('MASK','ENV_BEFORE','ENV_AFTER','CAPACITY_BIND','BACKEND_NOTE'):self.assertEqual(ast.dump(a[key],include_attributes=False),ast.dump(b[key],include_attributes=False))
  self.assertEqual(ast.literal_eval(b['FRESH_QUERY']).encode(),bodies['cost210_lifetime.py']);fused=ast.parse(ast.literal_eval(b['FUSED_OBSERVER']));calls=[n for n in fused.body if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Name)and n.value.func.id=='exec'];self.assertEqual(ast.literal_eval(calls[0].value.args[0].args[0]).encode(),bodies['cost210_diagnostics.py'])
  read=F.read
  with patch.object(F,'read',side_effect=lambda p:read(p)+b'drift'if Path(p)==F.HERE/'cost210_lifetime.py'else read(p)),self.assertRaisesRegex(ValueError,'helper pin'):F.inputs()
 def test_real_stale_atime_read_hardlink_symlink_and_rebound_leaf_refusals(self):
  with tempfile.TemporaryDirectory(dir='/dev/shm',prefix='repair-cost-source-')as t:
   root=Path(t);p=root/'source';p.write_bytes(b'whole source');s=p.stat();os.utime(p,ns=(1,s.st_mtime_ns));before=p.stat();self.assertEqual(F.read(p),b'whole source');after=p.stat();self.assertNotEqual(after.st_atime_ns,before.st_atime_ns);self.assertEqual(F.KEY(before),F.KEY(after));alias=root/'alias';alias.symlink_to(p)
   with self.assertRaisesRegex(ValueError,'ordinary absolute'):F.read(alias)
   alias.unlink();os.link(p,alias)
   with self.assertRaisesRegex(ValueError,'single-link'):F.read(p)
   alias.unlink();read=os.read;changed=False
   def rebound(fd,count):
    nonlocal changed
    raw=read(fd,count)
    if not changed:p.rename(root/'old');p.write_bytes(b'foreign body');changed=True
    return raw
   with patch.object(F.os,'read',rebound),self.assertRaisesRegex(ValueError,'stable whole'):F.read(p)
if __name__=='__main__':unittest.main(verbosity=2)
