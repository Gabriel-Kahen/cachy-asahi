#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact opt-in Apps9 source emission; no native or signing actors."""
import argparse,ast,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--parent',type=Path,required=True);p.add_argument('--carrier',type=Path,required=True);p.add_argument('--apps9-carrier',type=Path,required=True);p.add_argument('--expected',type=Path,required=True);a,rest=p.parse_known_args();P,I,N,E=map(lambda q:q.absolute(),(a.parent,a.carrier,a.apps9_carrier,a.expected));s=importlib.util.spec_from_file_location('_finite_Apps9_source_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)
HELD={'correction_inputs': {'bytes': 1110, 'sha256': '2de6d35902fe9dc09bc01cd4d61a88fb91a4a1bd87e2b554cd280ce96a753b22'}, 'emit': {'bytes': 1066, 'sha256': 'e6f06557b67b7af7539fed8b1fb2c5385c179bc6209eb74fe2caf576eb820aa4'}, 'emit_carrier_env': {'bytes': 1207, 'sha256': '7c3a964827abe78907b07a5174003007f54872e0113f51e69950fa7db5f36167'}, 'inputs': {'bytes': 1721, 'sha256': '75eae843bfe5383559c93e513a2f0c41845697921ff6b919c186d27173d57065'}, 'need': {'bytes': 50, 'sha256': 'a8ebc8f5f3a23b40b0c85a9adaa7e6f5bb29fcb122a2f824dc2f25deed384a8a'}, 'ordinary': {'bytes': 183, 'sha256': '20bdd50e404a145a765dc5c5d87f4feff220c0e8b07b763998d7e4cd05b55efe'}, 'pin': {'bytes': 79, 'sha256': 'f71b81de3a25bf17c4f69ffdebe13551b8d55744df3da3469a5b12a9b5ae1076'}, 'read': {'bytes': 664, 'sha256': '9eee27849f82e76a02dd1f889de8f4bf72196db9d509a939b401cff42d289797'}, 'source': {'bytes': 850, 'sha256': 'eb718ac2be3b4470b0e62d4e82b1841bedb13c3b54c4a07c4fa8c22b8ce525fe'}}
def command(out):return[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--apps9','--parent',str(P),'--carrier',str(I),'--apps9-carrier',str(N),'--output',str(out)]
class Controls(unittest.TestCase):
 def test_complete_isolated_cli_exact389_and_all_seven_emitted_source_controls(self):
  p,before,carrier,after,payload=F.apps9_inputs();F.source(E,after);F.source(N,carrier)
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';r=subprocess.run(command(out),capture_output=True,cwd='/tmp',timeout=30);self.assertEqual(r.returncode,0,r.stderr);v=json.loads(r.stdout);self.assertEqual((v['source'],v['files'],v['held'],v['changed'],v['added']),('51399738e2cb98551fbb84c930156022fd734029',389,364,16,9));self.assertIsNone(v['actual']);self.assertEqual(v['native'],'NOT_RUN');self.assertEqual(F.source(out,after),F.source(E,after))
   for tail in(('apps9/entry.py','--source-only'),('apps9/test_source.py',)):
    r=subprocess.run([sys.executable,'-I','-B','-Werror',str(out/tail[0]),*tail[1:]],capture_output=True,cwd='/tmp',timeout=80);self.assertEqual(r.returncode,0,r.stderr)
    if len(tail)==1:self.assertIn(b'Ran 7 tests',r.stderr)
    else:self.assertEqual(json.loads(r.stdout)['parent_files'],380)
 def test_all_original_function_bodies_and_unchanged_default_authorities(self):
  text=(HERE/'prepare.py').read_text();functions={n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for n,w in HELD.items():self.assertEqual(F.pin(functions[n].encode()),w,n)
  _,_,_,old,_=F.inputs();_,previous,corrected,_=F.correction_inputs();_,before,_,after,_=F.apps9_inputs();self.assertEqual(old,previous);self.assertEqual(corrected,before);self.assertEqual(len(after),389)
 def test_every_profile_map_legal_and_readable_payload_drift_refuses_before_output(self):
  p,_,_,_,_=F.apps9_inputs();read=F.read
  names=['apps9-profile.json','apps9-maps.json','apps9-NOTICE.md',*['apps9-payload/'+n for n in p['payload']]]
  with tempfile.TemporaryDirectory()as td:
   for i,name in enumerate(names):
    out=Path(td)/str(i);target=HERE/name
    def drift(path):
     raw=read(path);return raw+b'\n'if Path(path).absolute()==target.absolute()else raw
    with self.subTest(name=name),patch.object(F,'read',side_effect=drift),self.assertRaises(ValueError):F.emit_apps9(P,I,N,out)
    self.assertFalse(out.exists())
 def test_new_carrier_full_namespace_and_alias_refusals_before_output(self):
  for kind in('changed','missing','extra','empty-directory','symlink','hardlink'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory()as td:
    root=Path(td);carrier=root/'carrier';shutil.copytree(N,carrier,ignore=shutil.ignore_patterns('.git'));leaf=carrier/'index.json'
    if kind=='changed':leaf.write_bytes(leaf.read_bytes()+b' ')
    elif kind=='missing':leaf.unlink()
    elif kind=='extra':(carrier/'foreign').write_bytes(b'foreign')
    elif kind=='empty-directory':(carrier/'foreign-empty').mkdir()
    elif kind=='symlink':leaf.unlink();leaf.symlink_to(N/'index.json')
    else:os.link(leaf,root/'hardlink')
    out=root/'never'
    with self.assertRaises((ValueError,FileNotFoundError)):F.emit_apps9(P,I,carrier,out)
    self.assertFalse(out.exists())
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);alias=root/'alias';alias.symlink_to(N,target_is_directory=True)
   with self.assertRaises(ValueError):F.emit_apps9(P,I,alias,root/'never')
   self.assertFalse((root/'never').exists())
   with self.assertRaises(ValueError):F.emit_apps9(P,I,N,N/'never-output')
   self.assertFalse((N/'never-output').exists())
 def test_required_explicit_selection_and_mutually_exclusive_routes(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'never';base=command(out)
   for argv in([v for i,v in enumerate(base)if i not in(base.index('--apps9-carrier'),base.index('--apps9-carrier')+1)],[v for v in base if v!='--apps9'],[*base,'--carrier-env-correction']):
    r=subprocess.run(argv,capture_output=True,cwd='/tmp',timeout=15);self.assertEqual(r.returncode,2,r.stderr);self.assertFalse(out.exists())
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
