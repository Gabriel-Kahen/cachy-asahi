# SPDX-License-Identifier: MIT
"""Pure routing regression; modeled frames provide no runtime acceptance."""
import ast,base64,importlib.util,json,unittest
from pathlib import Path
from types import SimpleNamespace as NS
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('fixed_staged_adapter',HERE/'adapter.py');A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A)
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
def need(ok,why):
 if not ok:raise ValueError(why)
class Protocol(unittest.TestCase):
 def parser(self,raw):
  functions=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='guest_report'];self.assertEqual(len(functions),2);self.calls=[];self.expected=dict(candidate={'control':'not runtime'},native_pair={'control':'not runtime'},source_authority={'control':'not runtime'})
  c=NS(need=need,decode=json.loads,guest_receipt=lambda value:self.calls.append(value),INDEX={'candidate':self.expected['candidate'],'source_authority':self.expected['source_authority']},PAIR_IDENTITY=self.expected['native_pair']);scope=dict(c=c,base64=base64)
  exec(compile(ast.Module(body=[functions[0]],type_ignores=[]),'frozen guest_report routing','exec'),scope);scope['_guest_report_original']=scope['guest_report'];exec(compile(ast.Module(body=[functions[1]],type_ignores=[]),'candidate wrapper routing','exec'),scope);return scope['guest_report']
 def frames(self,prefix=b'DEBIANMAINTAINEDSYSTEM16K '):
  value=dict(self.expected,kernel='synthetic-kernel',runtime_files={});raw=base64.b64encode(json.dumps(value).encode());return b'\n'.join([b'SMOKE16K: mmap,mprotect,file-offset PASS',prefix+b'BOOT nonce 16384',prefix+b'REPORT nonce '+raw,prefix+b'PASS nonce'])+b'\n',dict(self.expected,files={})
 def test_actual_original_prefix_defect_and_exact_successor_routing(self):
  original=(ROOT/A.OLD/'run.py').read_bytes();fixed,count=A.adapt(original,'run.py');self.assertEqual(count,13);parser=self.parser(fixed);uart,capture=self.frames();result=parser(uart,0,'nonce','synthetic-kernel',capture);self.assertEqual(self.calls,[result]);self.assertEqual(result['candidate'],self.expected['candidate'])
  # Reconstruct precisely the frozen emitted bug; it must fail this same frame.
  broken=fixed.replace(b"b'DEBIANMAINTAINEDSYSTEM16K '",b"b'SYSTEM16K '");parser=self.parser(broken)
  with self.assertRaisesRegex(ValueError,'complete ordered'):parser(uart,0,'nonce','synthetic-kernel',capture)
  self.assertEqual(self.calls,[])
 def test_oldprefix_badnonce_nonzero_and_missing_pageprobe_refuse(self):
  fixed,_=A.adapt((ROOT/A.OLD/'run.py').read_bytes(),'run.py')
  for prefix,nonce,code,pageprobe in [(b'SYSTEM16K ','nonce',0,True),(b'DEBIANMAINTAINEDSYSTEM16K ','different',0,True),(b'DEBIANMAINTAINEDSYSTEM16K ','nonce',1,True),(b'DEBIANMAINTAINEDSYSTEM16K ','nonce',0,False)]:
   parser=self.parser(fixed);uart,capture=self.frames(prefix)
   if not pageprobe:uart=uart.replace(b'SMOKE16K: mmap,mprotect,file-offset PASS',b'NO_PROBE')
   with self.subTest(prefix=prefix,nonce=nonce,code=code,pageprobe=pageprobe),self.assertRaises(ValueError):parser(uart,code,nonce,'synthetic-kernel',capture)
   self.assertEqual(self.calls,[])
if __name__=='__main__':unittest.main()
