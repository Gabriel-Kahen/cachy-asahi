"""Real ordinary IPC/private files only. No successful PID1/verity fixture."""
import array,fcntl,os,socket,struct,subprocess,tempfile,unittest
from pathlib import Path
import protocol as P,context as C,client,broker
class Controls(unittest.TestCase):
 def pair(self):
  a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC)
  self.addCleanup(a.close);self.addCleanup(b.close);P.channel(a);P.channel(b);return a,b
 def test_real_kernel_credentials_and_owned_descriptor_transfer(self):
  a,b=self.pair();self.assertEqual(P.peer(a),(os.getpid(),os.getuid(),os.getgid()))
  with tempfile.TemporaryDirectory()as td:
   fd=os.open(td,os.O_RDONLY|os.O_DIRECTORY);idx=P.sealed(b'INERT_NOT_AUTHORITY');self.addCleanup(os.close,fd);self.addCleanup(os.close,idx)
   P.send(a,{'ordinary_transport':'NOT_PID1_AUTHORITY'},(fd,idx));v,received=P.receive(b,(os.getpid(),os.getuid(),os.getgid()),2)
   try:self.assertEqual(v,{'ordinary_transport':'NOT_PID1_AUTHORITY'});self.assertEqual(os.fstat(received[0]).st_ino,os.fstat(fd).st_ino);self.assertEqual(P.index_bytes(received[1],P.pin(b'INERT_NOT_AUTHORITY')),b'INERT_NOT_AUTHORITY');self.assertFalse(os.get_inheritable(received[0]))
   finally:
    for x in received:os.close(x)
 def test_wrong_credential_issuer_refuses_and_closes_received_fds(self):
  a,b=self.pair();fd=P.sealed(b'NOT_AUTHORITY');self.addCleanup(os.close,fd);before=len(list(Path('/proc/self/fd').iterdir()));P.send(a,{},(fd,))
  with self.assertRaisesRegex(ValueError,'credentials'):P.receive(b,(1,0,0),1)
  self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),before)
 def test_actual_child_sender_differs_from_socketpair_creator(self):
  a,b=self.pair();pid=os.fork()
  if pid==0:
   try:
    a.close();P.send(b,{'child':'DATA_NOT_AUTHORITY'});os._exit(0)
   except BaseException:os._exit(2)
  try:
   v,received=P.receive(a,(pid,os.getuid(),os.getgid()),0);self.assertEqual(v,{'child':'DATA_NOT_AUTHORITY'});self.assertEqual(P.peer(a)[0],os.getpid())
  finally:
   _,status=os.waitpid(pid,0);self.assertEqual(status,0)
  with self.assertRaises(ProcessLookupError):os.kill(pid,0)
 def test_truncation_wrong_rights_duplicate_nonfinite_and_extra_ancillary_refuse(self):
  for raw in(b'x'*(P.MAX_FRAME+1),b'{"x":1,"x":2}',b'{"x":NaN}'):
   a,b=self.pair();a.send(raw)
   with self.assertRaises((ValueError,)):P.receive(b,(os.getpid(),os.getuid(),os.getgid()),0)
  a,b=self.pair();fd=P.sealed(b'NOT_AUTHORITY');self.addCleanup(os.close,fd);P.send(a,{},(fd,))
  with self.assertRaises(ValueError):P.receive(b,(os.getpid(),os.getuid(),os.getgid()),0)
 def test_seals_are_real_and_unsealed_or_tampered_pins_refuse(self):
  fd=P.sealed(b'index');self.addCleanup(os.close,fd)
  for write in(lambda:os.pwrite(fd,b'!',0),lambda:os.ftruncate(fd,0)):
   with self.assertRaises(OSError):write()
  with self.assertRaisesRegex(ValueError,'hash'):P.index_bytes(fd,P.pin(b'foreign'))
  with tempfile.TemporaryFile()as f:
   f.write(b'index');f.flush()
   with self.assertRaises((ValueError,OSError)):P.index_bytes(f.fileno(),P.pin(b'index'))
 def test_exact_typed_map_roundtrip_and_reserved_alias_refuse(self):
  value={'observation':{'hardlink_groups':[{'members':('a','b')}]},'capabilities':{'a':b'\0\1'},'physical':{'a':(1,2,3)},'auxiliary':{'unchanged':True},'nodes':{}}
  raw=P.encode(P.pack(value));self.assertEqual(P.unpack(P.decode(raw)),value)
  with self.assertRaises(ValueError):P.pack({'$gnu_tuple':[]})
  for v in({'$gnu_tuple':[],'extra':1},{'$gnu_unknown':1},{'$gnu_bytes':3}):
   with self.assertRaises(ValueError):P.unpack(v)
 def test_default_gate_and_actual_host_refuse_before_devices(self):
  value=P.decode((C.D/'selection.template.json').read_bytes())
  with self.assertRaises(ValueError):C.selection(value)
  with self.assertRaisesRegex(ValueError,'PID1'):C.pid1()
  with self.assertRaises(ValueError):client.restricted()
  a,b=self.pair()
  with self.assertRaises(ValueError):client.Client(a,'1'*32)
  with self.assertRaises(ValueError):broker.pair()
 def test_complete_shape_still_requires_absent_upstream_authorities(self):
  value=P.decode((C.D/'selection.template.json').read_bytes());value['nonce']='1'*32
  for n in('source_authority','kernel_authority','producer_retirement','native_readback'):value[n]=P.pin(b'INERT_NOT_ACCEPTED')
  with self.assertRaisesRegex(ValueError,'UNSUPPLIED'):C.selection(value)
 def test_original_observers_are_loaded_only_from_whole_pinned_sources(self):
  api,modules=C.source_api();self.assertIn('raw_maps',api)
  for name,module in modules.items():self.assertIn('expected-vm-source',str(Path(module.__file__)))
  self.assertEqual(P.WORKER_MASK,0x800400fb);self.assertEqual(P.WORKER_MASK^0x800400db,1<<5)
 def test_exact_bootstrap_derivative_conserves_every_other_function(self):
  import ast,integration
  _,raw=C.trusted('gnu-verity-bootstrap-development-20261018/bootstrap.py');after=integration.derive(raw)
  def funcs(b):
   text=b.decode();return{n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  a,b=funcs(raw),funcs(after);self.assertEqual(set(a),set(b));self.assertEqual({n for n in a if a[n]!=b[n]},{'drop_worker','prepare_pid1'})
  self.assertIn(b'broker_context=SOURCE_BROKER.Context',after);self.assertIn(b'SOURCE_CLIENT.restricted()',after)
  with self.assertRaises(ValueError):integration.derive(raw+b'\n')
 def test_no_legacy_scope_or_mutable_walk_substitution(self):
  import ast,scope
  text=Path(scope.__file__).read_text();tree=ast.parse(text);fn=next(n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='mutable');body=ast.get_source_segment(text,fn)
  self.assertIn("self.api['observe'](self.modules,root,limits)",body);self.assertIn("modules['aux_checkpoint'].checkpoint",body)
  self.assertNotIn('self.client.source(',body)
 def test_real_complete_private_maps_survive_wire_and_fresh_drifts_remain_visible(self):
  import time
  api,modules=C.source_api();F=modules['full_root']
  def raw(root):return api['raw_maps'](modules,root,F.Limits(deadline=time.monotonic()+30,max_nodes=1000,max_bytes=1024**2,max_file_bytes=65536))
  for kind in('inode','rawdb','mode','hardlink','xattr'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory()as td:
    root=Path(td);(root/'var/lib/pacman/local/pkg-1').mkdir(parents=True);p=root/'var/lib/pacman/local/pkg-1/desc';p.write_bytes(b'%NAME%\npkg\n');os.link(p,root/'alias')
    before=raw(root);wire=P.encode(P.pack(before));self.assertEqual(P.unpack(P.decode(wire)),before)
    if kind=='inode':
     p.unlink();p.write_bytes(b'%NAME%\npkg\n')
    elif kind=='rawdb':p.write_bytes(b'%NAME%\nother\n')
    elif kind=='mode':p.chmod(0o600)
    elif kind=='hardlink':(root/'alias').unlink()
    else:os.setxattr(p,'user.broker-private',b'INERT')
    try:after=raw(root)
    except ValueError:continue
    self.assertNotEqual((before['nodes'],before['physical'],before['capabilities']),(after['nodes'],after['physical'],after['capabilities']))
 def test_real_child_original_service_fence_allows_only_inherited_request_route(self):
  import ast,ctypes,errno
  api,modules=C.source_api();root=Path(modules['full_root'].__file__).parents[2];path=root/'scripts/install/local_transaction.py';raw=path.read_bytes()
  # Whole source was pinned by source_api; only these exact original functions
  # and constant assignment are compiled for the ordinary x86 child probe.
  names={'architecture_profile','block_service_ipc'};nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name in names or isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='LIBRARY_SHA'for t in n.targets)]
  space={'C':ctypes,'os':os,'need':P.need};exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),space)
  a,b=self.pair();pid=os.fork()
  if pid==0:
   try:
    a.close();space['block_service_ipc']('x86_64')
    try:P.send(b,{'forbidden':'sendmsg'})
    except PermissionError:pass
    else:os._exit(3)
    P.request(b,{'ordinary_fenced_request':'NOT_PID1_AUTHORITY'});v,fds=P.receive(b,(os.getppid(),os.getuid(),os.getgid()),1)
    try:P.index_bytes(fds[0],P.pin(b'INERT'))
    finally:
     for fd in fds:os.close(fd)
    os._exit(0)
   except BaseException:os._exit(4)
  try:
   v,_=P.receive(a,(pid,os.getuid(),os.getgid()),0);self.assertEqual(v,{'ordinary_fenced_request':'NOT_PID1_AUTHORITY'});fd=P.sealed(b'INERT')
   try:P.send(a,{'ordinary_reply':'NOT_AUTHORITY'},(fd,))
   finally:os.close(fd)
  finally:
   _,status=os.waitpid(pid,0);self.assertEqual(status,0)
  with self.assertRaises(ProcessLookupError):os.kill(pid,0)
if __name__=='__main__':unittest.main(verbosity=2)
