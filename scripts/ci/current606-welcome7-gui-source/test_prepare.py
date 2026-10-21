#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable exact-source and primary-code controls; no package/GPG/VM/native execution."""
import argparse,ast,copy,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('_current606_GUI_source_factory',HERE/'prepare.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
PREDECESSOR=None
WELCOME8=None
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
class Welcome8Factory(unittest.TestCase):
 def setUp(self):
  if WELCOME8 is None:self.skipTest('--welcome8-predecessor-root required')
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.home=Path(self.temp.name);self.out=self.home/'out'
 def test_exact544_repeat_and_complete_original_admission(self):
  fact=P.prepare_welcome8(WELCOME8,self.out);other=self.home/'repeat';P.prepare_welcome8(WELCOME8,other);self.assertEqual(P.files(self.out),P.files(other));self.assertEqual({n:P.pin(b)for n,b in P.files(self.out).items()},P.profile()['welcome8']['output']['files']);self.assertEqual(fact['files'],544);self.assertIsNone(fact['actual_run']);self.assertEqual(fact['acceptance'],'NOT_GRANTED')
  s=importlib.util.spec_from_file_location('_portable_welcome8_full_admission',self.out/'admission.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);proof=m.prove(self.out);self.assertEqual((proof['files'],proof['original348'],proof['published_factory53']),(544,348,53))
  old=dict(l.split()for l in(WELCOME8/'factory/expected606.lock').read_text().splitlines());new=dict(l.split()for l in(self.out/'factory/expected606.lock').read_text().splitlines());self.assertEqual({n for n in old if old[n]!=new[n]},{'cachy-asahi-welcome'});self.assertEqual(new['cachy-asahi-welcome'],'0.1.0-8')
 def test_changed_missing_extra_predecessor_refused_before_output(self):
  for kind in('changed','missing','extra'):
   copied=self.home/kind;shutil.copytree(WELCOME8,copied);name=next(iter(P.profile()['welcome8']['predecessor']['files']))
   if kind=='changed':(copied/name).write_bytes(b'drift')
   elif kind=='missing':(copied/name).unlink()
   else:(copied/'extra').write_bytes(b'extra')
   with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'complete genuine corrective540'):P.prepare_welcome8(copied,self.out)
   self.assertFalse(self.out.exists())
 def test_role_specific_real_sized_metadata_and_original_cleanup_body(self):
  P.prepare_welcome8(WELCOME8,self.out);s=(self.out/'factory/context606.py').read_text();node=next(n for n in ast.walk(ast.parse(s))if isinstance(n,ast.IfExp)and ast.unparse(n.test)=="name == 'original-latest-input-plan.json'");cap=lambda name:eval(compile(ast.Expression(node),'<exact named metadata cap>','eval'),{'name':name,'M':1024**2});spec=importlib.util.spec_from_file_location('_portable_welcome8_metadata',self.out/'factory/context606.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);leaf=self.home/'metadata';leaf.write_bytes(b'0'*3285022);self.assertEqual(len(m.read(leaf,cap('original-latest-input-plan.json'))),3285022)
  with self.assertRaises(ValueError):m.read(leaf,cap('original604-manifest.json'))
  alias=self.home/'hardlink';os.link(leaf,alias)
  with self.assertRaises(ValueError):m.read(leaf,cap('original-latest-input-plan.json'))
  def cleanup(root):
   s=(root/'factory/run.py').read_text();return ast.get_source_segment(s,next(n for n in ast.parse(s).body if isinstance(n,ast.FunctionDef)and n.name=='cleanup'))
  self.assertEqual(cleanup(self.out),cleanup(WELCOME8));self.assertIn("factory();out=state/'ordered-cleanup.json'",(self.out/'native.py').read_text())
 def test_explicit_isolated_Welcome8_CLI_no_actual_authority(self):
  done=subprocess.run([sys.executable,'-I','-B',HERE/'prepare.py','--welcome8','--predecessor-root',WELCOME8,'--output',self.out],capture_output=True,text=True,timeout=30);self.assertEqual(done.returncode,0,done.stderr);v=json.loads(done.stdout);self.assertEqual(v['files'],544);self.assertEqual(v['acceptance'],'NOT_GRANTED');self.assertIsNone(v['actual_source']);self.assertIn('welcome8_stop.exercise',(self.out/'factory/extend_welcome8.py').read_text());self.assertEqual((self.out/'.github/workflows/native-arm-build.yml').read_bytes(),(self.out/'.github/workflows/native-arm-current606-welcome8-gui.yml').read_bytes())
class Transport(unittest.TestCase):
 def setUp(self):
  if TRANSPORT is None:self.skipTest('explicit source544 fixture required')
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.home=Path(self.temp.name);self.out=self.home/'out'
 def test_exact546_repeat_full_admission_and539_held(self):
  fact=P.prepare_transport(TRANSPORT,self.out);other=self.home/'again';P.prepare_transport(TRANSPORT,other);self.assertEqual(P.files(self.out),P.files(other));self.assertEqual({n:P.pin(b)for n,b in P.files(self.out).items()},P.profile()['transport']['output']['files']);self.assertEqual(fact['files'],546);self.assertEqual(fact['acceptance'],'NOT_GRANTED');self.assertIsNone(fact['actual_run']);self.assertEqual(fact['runtime_image_failure'],'UNRESOLVED_REQUIRES_GENUINE_ERROR_BYTES')
  spec=importlib.util.spec_from_file_location('_portable_whole546_admission',self.out/'admission.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);proof=m.prove(self.out);self.assertEqual((proof['files'],proof['original348'],proof['published_factory53']),(546,348,53))
  changed=set(P.profile()['transport']['changed']);self.assertEqual(len(changed),5)
  for n in set(P.profile()['transport']['predecessor']['files'])-changed:self.assertEqual((self.out/n).read_bytes(),(TRANSPORT/n).read_bytes())
 def test_transport_predecessor_drift_refused_before_output(self):
  for kind in('changed','missing','extra'):
   copied=self.home/kind;shutil.copytree(TRANSPORT,copied);leaf=next(iter(P.profile()['transport']['predecessor']['files']))
   if kind=='changed':(copied/leaf).write_bytes(b'drift')
   elif kind=='missing':(copied/leaf).unlink()
   else:(copied/'extra').write_bytes(b'extra')
   with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'complete genuine544'):P.prepare_transport(copied,self.out)
   self.assertFalse(self.out.exists())
 def test_explicit_CLI_mutual_exclusion_and_old_function_bodies_held(self):
  done=subprocess.run([sys.executable,'-I','-B',HERE/'prepare.py','--transport','--predecessor-root',TRANSPORT,'--output',self.out],capture_output=True,text=True,timeout=30);self.assertEqual(done.returncode,0,done.stderr);self.assertEqual(json.loads(done.stdout)['source_authority'],'ac70245709f336d2c670b2b511bec40c99248370')
  refused=subprocess.run([sys.executable,'-I','-B',HERE/'prepare.py','--transport','--welcome8','--predecessor-root',TRANSPORT,'--output',self.home/'forbidden'],capture_output=True,text=True,timeout=30);self.assertEqual(refused.returncode,2);self.assertFalse((self.home/'forbidden').exists())
  text=(HERE/'prepare.py').read_text();functions={n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  self.assertEqual(P.pin(functions['prepare'].encode())['sha256'],'692658e23db894163ad617417b1dd288c90f896e792ead457e9b3213e70d2ce6');self.assertEqual(P.pin(functions['prepare_welcome8'].encode())['sha256'],'ad97ab861c65b05c3d53490cd171ffa1e62b75c32de8ece2c32f8c9f385b7174')
 def test_emitted_transport_real_zip_keeps_literal_colon_data(self):
  import zipfile
  P.prepare_transport(TRANSPORT,self.out);spec=importlib.util.spec_from_file_location('_portable_exact_transport',self.out/'transport.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);public=self.home/'public';public.mkdir();name='generated/qemu-context/packages/dtc-1:1.8.1-1-aarch64.pkg.tar.xz';leaf=public/name;leaf.parent.mkdir(parents=True);leaf.write_bytes(b'SYNTHETIC public route DATA, not a package');raw=leaf.read_bytes();(public/'retention.json').write_bytes(P.encoded(dict(status='FAIL_OR_INCOMPLETE',case='minimal-generic4k',files={name:P.pin(raw)},total_bytes=len(raw))));wrapped=self.home/'wrapped';value=m.pack(public,wrapped,dict(source='0'*40,run=1,attempt=1,case='minimal-generic4k',job_token='0'*16));self.assertFalse(value['actual_authority']);self.assertEqual(value['status'],'PACKED_PUBLIC_EVIDENCE_DATA_ONLY');self.assertTrue(all(':'not in p.name for p in wrapped.iterdir()))
  with zipfile.ZipFile(wrapped/'evidence.zip')as z:self.assertEqual(z.read(name),raw);self.assertIsNone(z.testzip())

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--predecessor-root',type=Path,required=True);p.add_argument('--welcome8-predecessor-root',type=Path);p.add_argument('--transport-predecessor-root',type=Path);a,rest=p.parse_known_args();TRANSPORT=a.transport_predecessor_root.absolute()if a.transport_predecessor_root else None;WELCOME8=a.welcome8_predecessor_root.absolute()if a.welcome8_predecessor_root else None;PREDECESSOR=a.predecessor_root.absolute();unittest.main(argv=[__file__,*rest])
