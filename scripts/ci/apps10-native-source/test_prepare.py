# SPDX-License-Identifier: MIT
"""Portable exact-source tests; no native, network, Git or historical reader replay."""
import hashlib,importlib.util,json,os,re,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE));import prepare as F
PARENT=Path(os.environ['APPS9_NATIVE_SOURCE']).absolute();RECIPE=Path(os.environ['APPS10_RECIPE_SOURCE']).absolute();EXPECTED=Path(os.environ['APPS10_NATIVE_SOURCE']).absolute();LANE='scripts/ci/apps10-client-native'
class Controls(unittest.TestCase):
 def test_exact_full115_actual_isolated_cli_and_original_dependency_pins(self):
  p=F.profile();self.assertEqual(F.pins(F.tree(PARENT,True)),p['parent']);self.assertEqual(F.pins(F.tree(RECIPE,True)),p['recipe']);self.assertEqual(F.pins(F.tree(EXPECTED,True)),p['after'])
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';r=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--parent',str(PARENT),'--recipe',str(RECIPE),'--output',str(out)],cwd=td,capture_output=True,check=True,timeout=30)
   self.assertEqual(r.stderr,b'');v=json.loads(r.stdout);self.assertEqual(v['files'],115);self.assertEqual(v['expected_source'],p['expected_source']);self.assertIsNone(v['actual_source']);self.assertIsNone(v['actual_run']);self.assertFalse(v['acceptance']);self.assertEqual(F.tree(out),F.tree(EXPECTED,True))
   policy=json.loads((out/LANE/'input-policy.json').read_bytes());self.assertEqual(policy['products']['apps']['source_sha'],p['recipe_source'])
   for role in ('runtime','client'):self.assertEqual(policy['products'][role]['source_sha'],'9f9eae97843531a41b201655100f13984d9ac01e')
  r=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--help'],capture_output=True,check=True,timeout=10);self.assertIn(b'--recipe',r.stdout)
 def test_full_original_bound_writer_and_five_readable_inverse_payloads(self):
  v=F.profile();old=F.tree(PARENT,True)
  for name,edits in v['edits'].items():
   before=old[name.replace('apps10','apps9')].decode()
   for a,b in [('apps9','apps10'),('Apps9','Apps10'),('APPS9','APPS10'),('0.1.0-9','0.1.0-10')]:before=before.replace(a,b)
   after=before
   for a,b,count in edits:self.assertEqual(after.count(a),count);after=after.replace(a,b,count)
   self.assertEqual(after.encode(),F.read(HERE/'payload'/name));inverse=after
   for a,b,count in reversed(edits):self.assertEqual(inverse.count(b),count);inverse=inverse.replace(b,a,count)
   self.assertEqual(inverse,before)
  self.assertEqual(F.pins(F.tree(HERE/'payload')),v['payload'])
 def test_parent_recipe_profile_payload_changes_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);parent=root/'parent';recipe=root/'recipe';factory=root/'factory';shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));shutil.copytree(RECIPE,recipe,ignore=shutil.ignore_patterns('.git'));shutil.copytree(HERE,factory)
   for key,base,leaf in [('parent',parent,'scripts/ci/apps9-client-native/rules.py'),('recipe',recipe,'packages/tools/cachy-asahi-apps10/inventory.py'),('payload',factory/'payload',LANE+'/rules.py')]:
    path=base/leaf;held=path.read_bytes()
    for mode in ('changed','missing','extra'):
     if mode=='changed':path.write_bytes(held+b'\n')
     elif mode=='missing':path.unlink()
     else:path.write_bytes(held);(base/'foreign').write_bytes(b'drift')
     out=root/(key+'-'+mode)
     with patch.object(F,'HERE',factory),self.assertRaises(ValueError):F.emit(parent,recipe,out)
     self.assertFalse(out.exists())
     if mode in ('changed','missing'):path.write_bytes(held)
    (base/'foreign').unlink()
   (factory/'profile.json').write_bytes(b'{}')
   with patch.object(F,'HERE',factory),self.assertRaisesRegex(ValueError,'profile'):F.emit(parent,recipe,root/'badprofile')
   self.assertFalse((root/'badprofile').exists())
 def test_checkout_metadata_only_and_all_source_output_aliases(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);parent=root/'parent';shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));(parent/'.git').mkdir();(parent/'.git/config').write_text('NOT_EXECUTED_METADATA');F.emit(parent,RECIPE,root/'good')
   self.assertFalse((root/'good/.git').exists());(parent/'foreign').mkdir();(parent/'foreign/.git').write_text('NOT_TOPLEVEL_METADATA')
   with self.assertRaises(ValueError):F.emit(parent,RECIPE,root/'badextra')
   shutil.rmtree(parent/'foreign');alias=root/'alias';alias.symlink_to(parent,target_is_directory=True)
   for before,recipe,out in [(alias,RECIPE,root/'badalias'),(parent,RECIPE,parent/'nested'),(parent,RECIPE,HERE/'nested'),(parent,alias,root/'badrecipe')]:
    with self.assertRaises(ValueError):F.emit(before,recipe,out)
   for mode in ('symlink','hardlink'):
    leaf=parent/'scripts/ci/apps9-client-native/rules.py';raw=leaf.read_bytes();other=root/('external-'+mode);other.write_bytes(raw);leaf.unlink()
    if mode=='symlink':leaf.symlink_to(other)
    else:os.link(other,leaf)
    try:
     with self.assertRaises(ValueError):F.emit(parent,RECIPE,root/('bad-'+mode))
    finally:leaf.unlink();leaf.write_bytes(raw)
 def test_exact_registered_alias_template_and_every_checksum_command(self):
  rows=F.render(PARENT,RECIPE);self.assertEqual(rows['.github/workflows/native-arm-build.yml'],rows['.github/workflows/native-arm-apps10-client.yml'])
  template=rows[LANE+'/workflow.yml'].decode().replace('@JOB_SHA256@',F.pin(rows[LANE+'/job.py'])['sha256']).replace('@MANIFEST_SHA256@',F.pin(rows[LANE+'/source-manifest.json'])['sha256']);self.assertEqual(template.encode(),rows['.github/workflows/native-arm-build.yml'])
  commands=re.findall(r'^\s+(printf[^\n]+sha256sum --check)\s*$',template,re.M);self.assertTrue(commands)
  with tempfile.TemporaryDirectory()as td:
   source=Path(td)/'source';F.emit(PARENT,RECIPE,source)
   for command in commands:
    r=subprocess.run(['bash','-euo','pipefail','-c',command],cwd=source,env=dict(os.environ,SLICE=str(source/LANE)),capture_output=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr)
 def test_source_preflight_and_whole14plus4_controls(self):
  with tempfile.TemporaryDirectory()as td:
   source=Path(td)/'source';F.emit(PARENT,RECIPE,source)
   r=subprocess.run([sys.executable,'-I','-B','-Werror',str(source/LANE/'preflight.py'),'--source',str(source)],cwd=td,capture_output=True,timeout=30,check=True);v=json.loads(r.stdout);self.assertEqual(v['files'],112);self.assertTrue(v['bound']);self.assertIsNone(v['run_id'])
   for name,count in [('test_lane.py',14),('test_retained.py',4)]:
    r=subprocess.run([sys.executable,'-B','-Werror',str(source/LANE/name)],cwd=td,capture_output=True,timeout=60);sys.stderr.buffer.write(r.stdout+r.stderr);self.assertEqual(r.returncode,0);self.assertRegex(r.stderr,('Ran '+str(count)+' tests in ').encode());self.assertNotRegex(r.stderr,rb'\b(?:FAILED|skipped|ERROR|FAIL)\b')
   self.assertEqual(F.pins(F.tree(source)),F.profile()['after'])
 def test_fresh_atime_and_actual_source_drift_still_checked(self):
  with tempfile.TemporaryDirectory(dir='/dev/shm')as td:
   p=Path(td)/'source';p.write_bytes(b'whole');s=p.stat();os.utime(p,ns=(1,s.st_mtime_ns));self.assertEqual(F.read(p),b'whole');self.assertGreater(p.stat().st_atime_ns,1)
   original=F.os.fstat;calls=[]
   def altered(fd):
    calls.append(True)
    if len(calls)==2:p.write_bytes(b'changed')
    return original(fd)
   with patch.object(F.os,'fstat',altered),self.assertRaises(ValueError):F.read(p)
if __name__=='__main__':unittest.main(verbosity=2)
