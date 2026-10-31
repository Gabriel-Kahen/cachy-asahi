# SPDX-License-Identifier: MIT
"""Exact840 factory, isolated entry and refusals before any source output."""
import argparse,importlib.util,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--expected',type=Path,required=True);args,rest=p.parse_known_args();SOURCE=args.source.absolute();EXPECTED=args.expected.absolute()
s=importlib.util.spec_from_file_location('_sixcap_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)
class Controls(unittest.TestCase):
 def test_whole_exact_output_and_old_four_route_bodies_held(self):
  v,p,wanted,_=F.sixcap_inputs();self.assertEqual(wanted,F.files(EXPECTED));self.assertEqual(len(p['before']),838)
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';receipt=F.emit_sixcap(SOURCE,out);self.assertEqual(F.files(out),wanted);self.assertEqual(receipt['files'],wanted);self.assertIsNone(receipt['actual']);self.assertEqual(receipt['native'],'NOT_RUN')
  # Existing emit remains the original four-route API; this new route is explicit.
  with self.assertRaisesRegex(ValueError,'explicit corrected finite graph profile'):F.emit(SOURCE,Path('/never-output'),'sixcap840')
 def test_actual_isolated_cli_whole_source_and_authorization(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';auth=Path(td)/'authorization.json';r=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--source',str(SOURCE),'--output',str(out),'--authorization',str(auth),'--profile','sixcap840'],capture_output=True,timeout=60,cwd='/tmp');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(F.files(out),F.files(EXPECTED));self.assertEqual(json.loads(auth.read_bytes())['files'],F.files(EXPECTED))
 def test_missing_extra_drift_and_alias_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);real=F.files
   for mode in('missing','extra','drift'):
    def changed(path):
     value=real(path)
     if Path(path)==SOURCE:
      if mode=='missing':value.pop(next(iter(value)))
      elif mode=='extra':value['foreign']={'bytes':0,'sha256':'0'*64}
      else:value[next(iter(value))]={'bytes':1,'sha256':'0'*64}
     return value
    out=root/mode
    with patch.object(F,'files',side_effect=changed),self.assertRaisesRegex(ValueError,'genuine838'):F.emit_sixcap(SOURCE,out)
    self.assertFalse(out.exists())
   with self.assertRaisesRegex(ValueError,'fresh separate'):F.emit_sixcap(SOURCE,SOURCE)
   link=root/'alias';link.symlink_to(SOURCE,target_is_directory=True)
   with self.assertRaisesRegex(ValueError,'ordinary explicit'):F.emit_sixcap(link,root/'alias-output')
   self.assertFalse((root/'alias-output').exists())
 def test_support_drift_is_refused_before_cli_output_or_receipt(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);copy=root/'factory';shutil.copytree(HERE,copy);q=copy/'sixcap840/sixcap_successor.py';q.write_bytes(q.read_bytes()+b'\n# drift\n');out=root/'out';auth=root/'auth';r=subprocess.run([sys.executable,'-I','-B',str(copy/'prepare.py'),'--source',str(SOURCE),'--output',str(out),'--authorization',str(auth),'--profile','sixcap840'],capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertIn(b'whole sixcap support before output',r.stderr);self.assertFalse(out.exists());self.assertFalse(auth.exists())
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
