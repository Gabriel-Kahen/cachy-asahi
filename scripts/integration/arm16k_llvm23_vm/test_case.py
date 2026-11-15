# SPDX-License-Identifier: MIT
"""Fenced case wiring/ELF controls. No package, compiler, ALPM or VM execution."""
import ast,copy,ctypes,hashlib,importlib.util,json,os,struct,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def load(name):
 s=importlib.util.spec_from_file_location('case_controls_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
A=load('adapter');K=A.K;P=load('protocol');R=load('proof');M=load('test_contracts')
def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):raise RuntimeError('case DATA control fence: '+event)
sys.addaudithook(fence)
N='a'*32

def image(align=16384,machine=183):
 raw=bytearray(120);raw[:6]=b'\x7fELF\x02\x01';struct.pack_into('<HHI',raw,16,2,machine,1);struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,1);struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0x400000,0,120,120,align);return bytes(raw)
def restored(c,cxx):
 f=dict(P.RESTORED,BASE_SHA256='b'*64,FINAL_SHA256='b'*64,C_SHA256=hashlib.sha256(c).hexdigest(),CXX_SHA256=hashlib.sha256(cxx).hexdigest(),HOST_BOOT_UTC='1794750000',GUEST_BEFORE_CRYPTO_UTC='1794750001',RTC_BEFORE_CRYPTO_UTC='1794750001');return f
def summary(fields,nonce=N):return('LLVM23_RESTORED_BEGIN '+nonce+'\n'+''.join(k+'='+v+'\n'for k,v in fields.items())+'LLVM23_RESTORED_END '+nonce+'\n').encode()
class Controls(unittest.TestCase):
 def test_unissued_case_refuses_before_packet_output(self):
  case=K.load(HERE/'case.TEMPLATE.json')
  with self.assertRaises(ValueError):K.validate(case,{},None,None,None,None,None)
 def test_packet_has_fixed_trust_and_no_package_body_copy(self):
  args=M.modeled();case=args[0];cert=dict(zip(K.EVIDENCE,args[2:]));rows=A.contents(case,cert,dict(bytes=1,sha256='c'*64),N)
  self.assertNotIn(A.PKG,rows);self.assertIn('SigLevel = Required TrustedOnly',rows['pacman.conf'][0].decode());self.assertIn('LocalFileSigLevel = Required TrustedOnly',rows['pacman.conf'][0].decode());self.assertNotIn('[core]',rows['pacman.conf'][0].decode())
  env=rows['case.env'][0].decode().splitlines();self.assertEqual(len(env),13);self.assertIn('nonce='+N,env);self.assertIn('guest_output_cap_bytes='+str(args[4]['guest_output_cap_bytes']),env)
  self.assertIn('base-tools MODEL-1',rows['expected-base.lock'][0].decode());self.assertNotIn('111',rows['expected-base.lock'][0].decode())
 def test_duplicate_resolved_runtime_paths_cannot_hide_conflicting_hashes(self):
  # A valid certificate must resolve every alias to one actual file identity.
  args=M.modeled();runtime=args[3];same=copy.deepcopy(next(iter(runtime['files'].values())));same['resolved']=runtime['files'][runtime['loader']]['resolved'];same['sha256']='f'*64;runtime['files']['/usr/bin/MODELED-alias']=same
  cert=dict(zip(K.EVIDENCE,args[2:]))
  with self.assertRaises(ValueError):A.contents(args[0],cert,dict(bytes=1,sha256='c'*64),N)
 def output_fixture(self,root,c=None,cxx=None):
  c=image()if c is None else c;cxx=image()if cxx is None else cxx;fields=restored(c,cxx)
  values={'smoke':c,'unwind':cxx,'outputs.sha256':(fields['C_SHA256']+'  smoke\n'+fields['CXX_SHA256']+'  unwind\n').encode(),'summary.env':summary(fields)}
  for name,raw in values.items():(root/name).write_bytes(raw);(root/name).chmod(0o600)
  return fields
 def check(self,root,fields,nonce=N):return R.outputs(root,fields,'b'*64,1794750000,1794750002,65536,nonce)
 def test_passive_durable_two_ELFs_data_only(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);fields=self.output_fixture(root);r=self.check(root,fields);self.assertEqual(r['status'],'PASS_DURABLE_LLVM23_OUTPUT_DATA_ONLY');self.assertIsNone(r['VM_acceptance']);self.assertIsNone(r['Root_acceptance'])
 def test_4K_wrong_arch_nonELF_or_ETREL_outputs_refuse(self):
  for kind in('4K','arch','text','rel'):
   raw=image(4096)if kind=='4K'else image(machine=62)if kind=='arch'else b'not an ELF'if kind=='text'else bytearray(image())
   if kind=='rel':struct.pack_into('<H',raw,16,1);raw=bytes(raw)
   with tempfile.TemporaryDirectory()as d,self.subTest(kind=kind):
    root=Path(d);fields=self.output_fixture(root,c=raw)
    with self.assertRaises(ValueError):self.check(root,fields)
 def test_hash_membership_nonce_or_receipt_drift_refuse(self):
  for kind in('hash','extra','nonce','receipt'):
   with tempfile.TemporaryDirectory()as d,self.subTest(kind=kind):
    root=Path(d);fields=self.output_fixture(root)
    if kind=='hash':(root/'smoke').write_bytes(image()+b'changed')
    elif kind=='extra':(root/'extra').write_bytes(b'unknown')
    elif kind=='nonce':(root/'summary.env').write_bytes(summary(fields,'d'*32))
    else:
     bad=dict(fields,C_SHA256='0'*64);(root/'summary.env').write_bytes(summary(bad))
    with self.assertRaises(ValueError):self.check(root,fields)
 def test_closed_Source_lock_and_member_tampering(self):
  if not(HERE/'source.lock.json').exists():self.skipTest('Source lock generated after authoring')
  sha=hashlib.sha256((HERE/'source.lock.json').read_bytes()).hexdigest();self.assertEqual(A.source(sha)['sha256'],sha)
  with self.assertRaises(ValueError):A.source('0'*64)
  original=A.K.pin
  def changed(path,*args,**kw):
   value=original(path,*args,**kw)
   return dict(value,sha256='0'*64)if Path(path).name=='protocol.py'else value
  with patch.object(A.K,'pin',side_effect=changed),self.assertRaises(ValueError):A.source(sha)
 def test_no_host_VM_ALPM_compiler_Reader_entrypoint(self):
  tree=ast.parse((HERE/'adapter.py').read_bytes());calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)]
  self.assertFalse(any(isinstance(n.func,ast.Attribute)and n.func.attr in('Popen','run','system','execv')for n in calls))
  for e in('subprocess.Popen','socket.__new__','ctypes.dlopen','fcntl.flock'):
   with self.assertRaises(RuntimeError):sys.audit(e)
if __name__=='__main__':unittest.main(verbosity=2)
