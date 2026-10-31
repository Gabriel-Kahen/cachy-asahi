# SPDX-License-Identifier: MIT
"""Original-byte preparation and inert full-matrix controls; no ARM execution."""
import base64,copy,importlib.util,json,os,subprocess,sys,tempfile,unittest,zlib
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import prepare as P,runtime as R,adapter as A
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())
INPUT_ROOT=Path(os.environ.get('ARM16K_INPUT_ROOT',str(ROOT))).absolute()
GENERIC=A.load(ROOT,'scripts/virtual/generic16k/fixture.py')
class Controls(unittest.TestCase):
 def setUp(self):
  no=patch.object(subprocess,'Popen',side_effect=AssertionError('no runtime/build/container actor'));no.start();self.addCleanup(no.stop)
 def selected(self,name='ARM-C01'):
  files,receipt=P.select(INPUT_ROOT,name,GENERIC);return {n.removeprefix('experiments/'):v[1] for n,v in files.items()},receipt
 def fake(self,argv,data):
  if argv[0].endswith('/example'):code,out=0,b'example completed'
  elif argv[-1] in ('-1','-6','-9'):
   value=zlib.compressobj(int(argv[-1][1:]),zlib.DEFLATED,31);code,out=0,value.compress(data)+value.flush()
  else:
   value=zlib.decompressobj(31)
   try:out=value.decompress(data)+value.flush();code=0 if value.eof or not argv[0].endswith('/strict-gzip') else 2
   except zlib.error:code,out=(2 if argv[0].endswith('/strict-gzip') else 1),b''
  return code,out,dict(argv=R.fixed_argv(argv),exit_code=code,group_absence_verified=True,stdout_bytes=len(out),stdout_sha256=R.pin(out)['sha256'])
 def test_actual_four_original_archives_all_members_selected_ELF_and_corpus(self):
  for name in P.BUNDLES:
   with self.subTest(experiment=name):
    files,receipt=P.select(INPUT_ROOT,name,GENERIC);self.assertEqual(len(files),30);self.assertEqual(len(receipt['elf']),12);self.assertEqual(len(receipt['builds']),4);self.assertFalse(any('training' in b for b in receipt['builds']));self.assertTrue(all(v['interpreter']=='/lib/ld-linux-aarch64.so.1' for v in receipt['elf'].values()))
 def test_full_468_command_matrix_336_crossdecodes_32_strict_rejects(self):
  files,receipt=self.selected();result=R.suite(receipt,files.__getitem__,self.fake);R.validate_records(receipt,result['commands']);self.assertEqual(len(result['commands']),468);self.assertEqual(sum(c['kind']=='cross-decode' for c in result['checks']),336);self.assertEqual(sum(c['kind']=='strict-reject' for c in result['checks']),32);self.assertEqual(sum(c['kind']=='sample-truncation' and c['rejection_acceptance']=='NOT_CLAIMED' for c in result['checks']),4)
 def test_mutated_corpus_refused_before_execution(self):
  files,receipt=self.selected();files['corpus/empty.bin']=b'changed'
  with self.assertRaisesRegex(ValueError,'original corpus identity'):R.suite(receipt,files.__getitem__,lambda *a:self.fail('must refuse before execute'))
 def test_wrong_decoded_bytes_and_group_retirement_refuse(self):
  files,receipt=self.selected()
  def bad(argv,data):
   code,out,row=self.fake(argv,data)
   if argv[-1]=='-d':out+=b'changed'
   return code,out,row
  with self.assertRaisesRegex(ValueError,'cross-decoded'):R.suite(receipt,files.__getitem__,bad)
  with self.assertRaisesRegex(ValueError,'owned group absence'):R.suite(receipt,files.__getitem__,lambda *a:(0,b'',dict(group_absence_verified=False)))
 def test_strict_invalid_cannot_become_sample_truncation_acceptance(self):
  files,receipt=self.selected()
  def bad(argv,data):
   code,out,row=self.fake(argv,data)
   if argv[0].endswith('/strict-gzip') and code==2:code=0
   return code,out,row
  with self.assertRaisesRegex(ValueError,'exact exit'):R.suite(receipt,files.__getitem__,bad)
 def test_normal_loader_closure_is_required(self):
  _,receipt=self.selected()
  with self.assertRaisesRegex(ValueError,'ordinary loader'):P.closure({},receipt)
  with self.assertRaisesRegex(ValueError,'needed runtime'):P.closure({'lib/ld-linux-aarch64.so.1':None},receipt)
 def test_input_aliases_and_old_or_unknown_experiment_refuse(self):
  for n in ('/absolute','../escape','a//b','a/./b','a\\b'):
   with self.subTest(name=n),self.assertRaises(ValueError):P.relative(n)
  with self.assertRaises(ValueError):P.select(INPUT_ROOT,'ARM-C05',GENERIC)
 def test_unbound_actor_free_controller_refuses_first(self):
  with self.assertRaisesRegex(ValueError,'UNBOUND'):A.trial(NS())
 def test_uart_bytes_nonce_page_and_retirement_are_exact(self):
  files,receipt=self.selected();value=R.suite(receipt,files.__getitem__,self.fake);value.update(page_size=16384,kernel='exact-kernel',uid=23001,groups=[],caps='ALL_ZERO',no_new_privs=1,original_inputs_preserved=True);nonce='a'*32
  def wire(v,n=nonce):return b'SMOKE16K: mmap,mprotect,file-offset PASS\nARM_EXPERIMENTS16K '+n.encode()+b' '+base64.b64encode(json.dumps(v).encode())+b'\nTOOLS16K PASS '+nonce.encode()+b'\n'
  A.observed(wire(value),0,nonce,'exact-kernel',receipt)
  with self.assertRaises(ValueError):A.observed(wire(value,'b'*32),0,nonce,'exact-kernel',receipt)
  for key,item in [('page_size',4096),('caps','NONZERO'),('commands',value['commands'][:-1])]:
   bad=copy.deepcopy(value);bad[key]=item
   with self.subTest(key=key),self.assertRaises(ValueError):A.observed(wire(bad),0,nonce,'exact-kernel',receipt)
  for kind in ('argv','stdin','stdout','group'):
   bad=copy.deepcopy(value);command=bad['commands'][1]
   if kind=='argv':command['supervisor']['argv']=['/lib/ld-linux-aarch64.so.1','substitution']
   elif kind=='stdin':command['stdin']['sha256']='0'*64
   elif kind=='stdout':command['stdout']['sha256']='0'*64
   else:command['supervisor']['group_absence_verified']=False
   with self.subTest(kind=kind),self.assertRaises(ValueError):A.observed(wire(bad),0,nonce,'exact-kernel',receipt)
if __name__=='__main__':unittest.main()
