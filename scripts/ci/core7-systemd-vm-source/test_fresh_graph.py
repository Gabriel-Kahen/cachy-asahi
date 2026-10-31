# SPDX-License-Identifier: MIT
"""Exact explicit39 route and all prior output/body preservation, no actors."""
import argparse,ast,importlib.util,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_fresh_graph_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
class Factory(unittest.TestCase):
 def test_all_prior_profiles_whole_output_and_function_bodies_held(self):
  calls=[(F.inputs,F.emit),(F.virtio20_inputs,F.emit_virtio20),(F.rollback_inputs,F.emit_rollback),(lambda:F.host_clock_inputs(False),lambda p:F.emit_host_clock(p,False)),(lambda:F.host_clock_inputs(True),lambda p:F.emit_host_clock(p,True)),(F.module_index_inputs,F.emit_module_indexes),(F.gzip1_inputs,F.emit_gzip1)]
  with tempfile.TemporaryDirectory()as td:
   for i,(inputs,emit)in enumerate(calls):
    profile,bodies=inputs();output=Path(td)/str(i);emit(output);self.assertEqual({n:F.pin(b)for n,b in F.source(output,profile['result']['files']).items()},profile['result']['files']);self.assertEqual({n:F.pin(b)for n,b in bodies.items()},profile['result']['files'])
  profile,_=F.fresh_graph_inputs();text=(HERE/'prepare.py').read_text();tree=ast.parse(text);actual={n.name:F.pin(ast.get_source_segment(text,n).encode())for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in profile['held_function_bodies']};self.assertEqual(actual,profile['held_function_bodies'])
 def test_actual_isolated_fresh_graph_cli_exact39_and_seals(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';p=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--fresh-graph','--output',str(out)],cwd='/',capture_output=True,timeout=30);self.assertEqual((p.returncode,p.stderr),(0,b''));result=json.loads(p.stdout);self.assertIsNone(result['actual']);self.assertEqual(result['files'],39)
   profile,_=F.fresh_graph_inputs();self.assertEqual(F.source(out,profile['result']['files']),F.source(EXPECTED,profile['result']['files']));self.assertEqual((out/'.github/workflows/native-arm-build.yml').read_bytes(),(out/'.github/workflows/native-arm-core7-real-systemd.yml').read_bytes())
   p=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--fresh-graph','--source-only'],cwd='/',capture_output=True,timeout=30);self.assertEqual((p.returncode,p.stderr),(0,b''));self.assertEqual(json.loads(p.stdout)['files'],39)
 def test_profile_payload_alias_conflict_and_reuse_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);copy=root/'factory';shutil.copytree(HERE,copy);out=root/'absent'
   for name in('fresh-graph-profile.json','fresh-graph/graph_api.py'):
    p=copy/name;before=p.read_bytes();p.write_bytes(before+b'\n');v=subprocess.run([sys.executable,'-I','-B',str(copy/'prepare.py'),'--fresh-graph','--output',str(out)],capture_output=True,timeout=30);self.assertNotEqual(v.returncode,0);self.assertFalse(out.exists());p.write_bytes(before)
   for flag in('--gzip1','--module-indexes','--virtio20','--host-clock','--automatic-rollback'):
    v=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--fresh-graph',flag,'--output',str(out)],capture_output=True,timeout=30);self.assertNotEqual(v.returncode,0);self.assertFalse(out.exists())
   (root/'alias').symlink_to(root,target_is_directory=True)
   with self.assertRaises(ValueError):F.emit_fresh_graph(root/'alias/absent')
   with self.assertRaises(ValueError):F.emit_fresh_graph(root/'factory/../traversal-output')
   self.assertFalse((root/'traversal-output').exists())
   with self.assertRaises(ValueError):F.emit_fresh_graph(HERE/'nested-output')
   out.mkdir()
   with self.assertRaises(ValueError):F.emit_fresh_graph(out)
 def test_all51_original_and_fresh_graph_emitted_source_controls(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';F.emit_fresh_graph(out);total=0
   for name in('test_case.py','test_emission.py','test_host.py','test_initramfs.py','test_protocol.py','test_route.py','test_sources.py'):
    argv=[sys.executable,'-I','-B','-Werror',str(out/name)]
    if name in('test_route.py','test_sources.py'):argv+=['--vm-source',str(VM)]
    if name=='test_sources.py':argv+=['--core-source',str(CORE),'--kernel-carrier',str(KERNEL)]
    p=subprocess.run(argv,capture_output=True,timeout=90);self.assertEqual(p.returncode,0,p.stderr[-4096:].decode(errors='replace'));counts=__import__('re').findall(rb'Ran ([0-9]+) tests? in',p.stderr);self.assertEqual(len(counts),1);total+=int(counts[0])
   self.assertEqual(total,51)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('expected','core-source','vm-source','kernel-carrier'):p.add_argument('--'+n,type=Path,required=True)
 a,rest=p.parse_known_args();EXPECTED=a.expected.absolute();CORE=a.core_source.absolute();VM=a.vm_source.absolute();KERNEL=a.kernel_carrier.absolute();unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
