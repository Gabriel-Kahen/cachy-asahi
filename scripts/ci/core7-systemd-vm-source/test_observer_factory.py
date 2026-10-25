# SPDX-License-Identifier: MIT
"""Portable observer factory controls; immutable fixture paths are explicit."""
import argparse,ast,base64,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;p=argparse.ArgumentParser()
for n in('expected','parent'):p.add_argument('--'+n,type=Path,required=True)
a,rest=p.parse_known_args();EXPECTED=a.expected.absolute();PARENT=a.parent.absolute()
def load(n,p):s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
F=load('_maintained_Core_observer_factory',HERE/'prepare.py')
def command(args):return subprocess.run([sys.executable,'-I','-B','-Werror',*map(str,args)],capture_output=True,cwd='/',timeout=90)
class Factory(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup);cls.root=Path(cls.temp.name);cls.p,cls.bodies=F.observer_inputs()
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def test_exact_known_NULL_source_and_receipt_authority(self):
  self.assertEqual(F.source(EXPECTED,self.p['after']),self.bodies)
  for null in(False,True):
   out=self.root/('mode'+str(null));auth=self.root/('mode'+str(null)+'.json');v=F.emit_observer(out,null,auth);self.assertEqual(F.source(out,self.p['after']),self.bodies);self.assertEqual(json.loads(auth.read_bytes()),v);self.assertIsNone(v['actual']);self.assertFalse(v['acceptance']);self.assertEqual(v['source'],None if null else self.p['source_after'])
 def test_source_entry_real_isolated_CLI_and_fresh_output(self):
  for null in(False,True):
   args=[HERE/'prepare.py','--observer-efficient']+(['--unbound']if null else[]);r=command([*args,'--source-only']);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertIsNone(json.loads(r.stdout)['actual']);out=self.root/('cli'+str(null));auth=self.root/('cli'+str(null)+'.json');r=command([*args,'--output',out,'--authorization',auth]);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(json.loads(r.stdout),json.loads(auth.read_bytes()));self.assertEqual(F.source(out,self.p['after']),self.bodies);r=command([out/'entry.py','source']);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertIsNone(json.loads(r.stdout)['actual']);r=command([*args,'--output',out]);self.assertNotEqual(r.returncode,0)
 def test_old_Core41_route_and_default_unchanged(self):
  p,bodies=F.tpm_acl_inputs();self.assertEqual(F.source(PARENT,p['stages']['41']['after']),bodies)
  for null in(False,True):
   out=self.root/('old'+str(null));args=[HERE/'prepare.py','--tpm-default-acl','--output',out]+(['--unbound']if null else[]);r=command(args);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(F.source(out,p['stages']['41']['after']),bodies)
  r=command([HERE/'prepare.py','--source-only']);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(json.loads(r.stdout)['files'],34)
  text=(HERE/'prepare.py').read_text();functions={n.name:F.pin(ast.get_source_segment(text,n).encode())for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for n,w in self.p['held_factory_functions'].items():self.assertEqual(functions[n],w,n)
 def test_alias_paths_modes_receipt_overlap_and_conflicting_routes(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);alias=root/'alias';alias.symlink_to(root,target_is_directory=True)
   for out in(alias/'never',root/'missing/../never',HERE/'never',HERE,root):
    with self.assertRaises(ValueError):F.emit_observer(out)
   for auth in(HERE/'never.json',alias/'never.json',root/'unmade/../never.json',root/'out/receipt.json'):
    with self.assertRaises(ValueError):F.emit_observer(root/'out',False,auth)
    self.assertFalse((root/'out').exists())
   for mode in(None,0,1,'unbound'):
    with self.assertRaises(ValueError):F.emit_observer(root/'never',mode)
   for flag in('--tpm-default-acl','--fresh-graph','--gzip1','--module-indexes','--host-clock','--virtio20','--automatic-rollback'):
    r=command([HERE/'prepare.py','--observer-efficient',flag,'--output',root/'never']);self.assertNotEqual(r.returncode,0);self.assertFalse((root/'never').exists())
 def test_observer_payload_profile_parent_support_drift_before_writes(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);out=root/'never'
   for name in('observer.py','observer-profile.json','tpm-acl-profile.json','tpm-default-acl/41/acl_policy.py'):
    leaf=factory/name;raw=leaf.read_bytes();leaf.write_bytes(raw+b'drift');r=command([factory/'prepare.py','--observer-efficient','--output',out]);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists());leaf.write_bytes(raw)
   for name in self.p['payload']:
    leaf=factory/'observer-payload'/name;raw=leaf.read_bytes();leaf.write_bytes(raw+b'drift');r=command([factory/'prepare.py','--observer-efficient','--output',out]);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists());leaf.write_bytes(raw)
 def test_late_real_parent_support_mutation_before_any_write(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);G=load('_late_observer_factory',factory/'prepare.py');real=G.tpm_acl_inputs;calls=0;out=root/'never'
   def late():
    nonlocal calls
    calls+=1
    if calls==2:
     leaf=factory/'tpm-default-acl/41/acl_policy.py';leaf.write_bytes(leaf.read_bytes()+b'drift')
    return real()
   with patch.object(G,'tpm_acl_inputs',side_effect=late),self.assertRaises(ValueError):G.emit_observer(out)
   self.assertEqual(calls,2);self.assertFalse(out.exists())
 def test_whole37_held_caps_schema_and_documented_host_measurements(self):
  p=self.p;self.assertEqual(len(p['before']),41);self.assertEqual(len(p['after']),41);self.assertEqual(len(p['held']),37);self.assertEqual({n:w for n,w in p['before'].items()if p['after'].get(n)==w},p['held']);self.assertEqual(p['root_cap'],600);self.assertEqual(p['native_hotspot'],'UNKNOWN');self.assertEqual(p['native_fit'],'UNKNOWN');self.assertEqual((p['focused_groups_each_python'],p['prior_controls_each_python']),(7,64))
  self.assertEqual(set(p['before'])-set(p['held']),{'acl_policy.py','source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml'})
  for label,row in p['benchmark'].items():
   self.assertIn(label,('312','314'));self.assertEqual(row['machine'],'x86_64');self.assertFalse(row['acceptance']);self.assertEqual(row['native_root600_fit'],'UNKNOWN');self.assertEqual(row['baseline'],p['before']['acl_policy.py']);self.assertEqual(row['candidate'],p['after']['acl_policy.py'])
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
