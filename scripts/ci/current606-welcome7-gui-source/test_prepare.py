#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable exact-source and primary-code controls; no package/GPG/VM/native execution."""
import argparse,ast,copy,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('_current606_GUI_source_factory',HERE/'prepare.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
PREDECESSOR=None
class Factory(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.home=Path(self.temp.name);self.out=self.home/'out'
 def test_exact_repeat_emission_and_original_identities(self):
  fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');ident=lambda:{n:tuple(getattr((PREDECESSOR/n).stat(),k)for k in fields)for n in P.profile()['predecessor']['files']};before=ident();fact=P.prepare(PREDECESSOR,self.out);other=self.home/'repeat';P.prepare(PREDECESSOR,other);self.assertEqual({n:P.pin(b)for n,b in P.files(self.out).items()},P.profile()['output']['files']);self.assertEqual(P.files(self.out),P.files(other));self.assertEqual(before,ident());self.assertEqual(fact['files'],540)
  for k in('actual_source','actual_ref','actual_run'):self.assertIsNone(fact[k])
 def test_real_primary_loader_and_held_FDK_probe_cleanup_bodies(self):
  P.prepare(PREDECESSOR,self.out);sys.path.insert(0,str(self.out/'factory'));factory=__import__('factory');old_here=factory.HERE;factory.HERE=self.out/'factory'
  try:
   profile=factory.source(self.out/'original');stage=factory.load('_portable_exact_kernel_stage',self.out/'factory/kernel_stage.py');self.assertEqual(stage.source_support()['source_revision'],'94fb23346d522edf53722357c426a3e58030beea');self.assertEqual(profile['versions']['cachy-asahi-doctor'],'0.2.0-1')
   for n in('context606.py','install606.py','factory.py','hwcap_probe.c','user_hwcap.py','run.py'):self.assertEqual((self.out/'factory'/n).read_bytes(),(PREDECESSOR/'factory'/n).read_bytes())
   source=factory.obj(self.out/'original/scripts/ci/maintained-desktop574-inputs.json');before={r['name']:r['version']for r in source['packages']};after=dict(l.split()for l in(self.out/'factory/expected606.lock').read_text().splitlines());self.assertEqual(set(before)-set(after),{'libfdk-aac'});self.assertEqual(len(set(before)&set(after)),573);self.assertEqual(len(set(after)-set(before)),33)
  finally:factory.HERE=old_here;sys.path.remove(str(self.out/'factory'))
 def test_original_fdk_comparator_and_bootstrap_gate_schema(self):
  P.prepare(PREDECESSOR,self.out);name='cachy-asahi-fdk-aac-3.0.0-1-aarch64.pkg.tar.xz';raw=(self.out/'bootstrap-code/scripts/build/compare.py').read_text();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='compare');text=(self.out/'bootstrap2.py').read_text();calls=[n for n in ast.walk(ast.parse(text))if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='need'and len(n.args)==2 and isinstance(n.args[1],ast.Constant)and n.args[1].value=='complete original FDK comparison'];self.assertEqual(len(calls),1);gate=compile(ast.Expression(calls[0]),'<source-held FDK gate>','eval')
  record=dict(clean_environment_id='fixture-one',**{k:'held'for k in('image','image_id','mode','source_date_epoch','recipe_inputs','recipe_metadata','expected_packages_sha256','entry_script_sha256')});other=dict(record,clean_environment_id='fixture-two');report=dict(members={'usr/lib/libfdk-aac.so':{'mode':493}},metadata={'.PKGINFO':{'pkgname':['cachy-asahi-fdk-aac']},'.BUILDINFO':{'builddate':['1791748800']}},sha256='a'*64);second=copy.deepcopy(report);reports=iter([(record,{name:report}),(other,{name:second})]);space={'Path':Path,'PACKAGE_METADATA':{'.PKGINFO','.BUILDINFO','.MTREE'},'verify':lambda _:next(reports)};exec(compile(ast.Module(body=[node],type_ignores=[]),'<whole source-held comparator>','exec'),space);value=space['compare'](self.home/'build-1',self.home/'build-2');self.assertNotIn('bytes_equal',value)
  with self.assertRaises(KeyError):eval("comparison['bytes_equal']",{'comparison':value})
  def check(v):return eval(gate,{'A':P,'comparison':v,'path':Path('/owned/artifacts')/name})
  check(value)
  for flag in('bytes_equal','installed_contents_equal','pkginfo_equal','buildinfo_equal'):
   for bad in(False,1,'true',None):
    v=copy.deepcopy(value);v['packages'][name][flag]=bad
    with self.subTest(flag=flag,value=bad),self.assertRaises(ValueError):check(v)
  for packages in({},dict(value['packages'],unexpected=value['packages'][name]),{'wrong':value['packages'][name]}):
   v=copy.deepcopy(value);v['packages']=packages
   with self.assertRaises(ValueError):check(v)
  self.assertIn("fdk/'build-2','--require-bytes'",text)
 def test_predecessor_drift_refused_before_output(self):
  for kind in('changed','missing','extra'):
   copied=self.home/kind;shutil.copytree(PREDECESSOR,copied);leaf=next(iter(P.profile()['predecessor']['files']))
   if kind=='changed':(copied/leaf).write_bytes(b'changed')
   elif kind=='missing':(copied/leaf).unlink()
   else:(copied/'extra').write_bytes(b'extra')
   with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'complete genuine media536'):P.prepare(copied,self.out)
   self.assertFalse(self.out.exists())
 def test_profile_drift_refused_before_output(self):
  old=P.HERE;altered=self.home/'profile';altered.mkdir();(altered/'source.json').write_bytes((HERE/'source.json').read_bytes()+b' ');P.HERE=altered
  try:
   with self.assertRaisesRegex(ValueError,'whole frozen GUI'):P.prepare(PREDECESSOR,self.out)
   self.assertFalse(self.out.exists())
  finally:P.HERE=old
 def test_alias_fifo_existing_and_overlapping_outputs_refused(self):
  real=self.home/'real';real.write_bytes(b'held');link=self.home/'link';link.symlink_to(real)
  with self.assertRaises(OSError):P.ordinary(link)
  link.unlink();os.link(real,link)
  with self.assertRaisesRegex(ValueError,'single-link'):P.ordinary(real)
  fifo=self.home/'fifo';os.mkfifo(fifo)
  with self.assertRaisesRegex(ValueError,'ordinary'):P.ordinary(fifo)
  self.out.mkdir();sentinel=self.out/'held';sentinel.write_bytes(b'held')
  with self.assertRaisesRegex(ValueError,'fresh disjoint'):P.prepare(PREDECESSOR,self.out)
  self.assertEqual(sentinel.read_bytes(),b'held')
  with self.assertRaisesRegex(ValueError,'fresh disjoint'):P.prepare(PREDECESSOR,PREDECESSOR/'forbidden-generated-child')
 def test_exact_isolated_CLI_and_independent_runtime_axes(self):
  done=subprocess.run([sys.executable,'-I','-B',HERE/'prepare.py','--predecessor-root',PREDECESSOR,'--output',self.out],capture_output=True,text=True,timeout=30);self.assertEqual(done.returncode,0,done.stderr);fact=json.loads(done.stdout);self.assertEqual(fact['profiles'],['minimal','overlay']);self.assertEqual(fact['page_modes'],['generic4k','generic16k']);self.assertEqual(fact['acceptance'],'NOT_GRANTED');self.assertEqual((self.out/'.github/workflows/native-arm-build.yml').read_bytes(),(self.out/'.github/workflows/native-arm-current606-welcome7-gui.yml').read_bytes());routes=json.loads((self.out/'extension-input-profile.json').read_bytes());self.assertEqual(len(routes['files']),26);self.assertEqual(set(routes['carriers']),{'retained574','compiler6','official3','legacy2'})
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--predecessor-root',type=Path,required=True);a,rest=p.parse_known_args();PREDECESSOR=a.predecessor_root.absolute();unittest.main(argv=[__file__,*rest])
