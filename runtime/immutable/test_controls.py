"""Inert mount DATA + real private maps/processes, never a PID1/DM/574 fixture."""
import ast,copy,json,os,shutil,socket,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import inputs,map_join,lease_table,supervisor,disk_adapter,runtime_policy
P,C,_,_=inputs.broker()
class Controls(unittest.TestCase):
 def snapshot(self,root):
  api,modules=C.source_api();F=modules['full_root'];v=api['raw_maps'](modules,root,F.Limits(deadline=time.monotonic()+30,max_nodes=1000,max_bytes=1024**2,max_file_bytes=65536))
  v['auxiliary']={n:{}for n in('helper','configs','aliases','scan','targets','caches')};v['auxiliary'].update(main_bytes=b'INERT_CACHE_NOT574',aux_bytes=b'INERT_AUX_NOT574',closure=(),scan_directories=());return v
 def tree(self,root):
  (root/'var/lib/pacman/local/inert-1').mkdir(parents=True);p=root/'var/lib/pacman/local/inert-1/desc';p.write_bytes(b'%NAME%\ninert\n');os.link(p,root/'alias');(root/'link').symlink_to('alias');return p
 def test_real_map_crossimage_logical_join_and_physical_reanchor(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)/'source';root.mkdir();self.tree(root);target=Path(td)/'copied';shutil.copytree(root,target,symlinks=True,copy_function=shutil.copy2)
   # copytree doesn't preserve hardlinks; explicitly construct real alias.
   (target/'alias').unlink();os.link(target/'var/lib/pacman/local/inert-1/desc',target/'alias')
   a,b=self.snapshot(root),self.snapshot(target);result=map_join.join(a,b);self.assertEqual(result['nodes'],len(a['nodes']));self.assertNotEqual(a['physical'],b['physical']);self.assertEqual(a['nodes'],b['nodes'])
   wire=P.unpack(P.decode(P.encode(P.pack(a))));self.assertEqual(map_join.join(wire,b)['nodes'],len(a['nodes']))
 def test_every_actual_private_drift_and_uncovered_field_refuses(self):
  for kind in('rawdb','mode','mtime','links','xattr'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory()as td:
    root=Path(td);p=self.tree(root);a=self.snapshot(root)
    if kind=='rawdb':p.write_bytes(b'%NAME%\nforeign\n')
    elif kind=='mode':p.chmod(0o600)
    elif kind=='mtime':os.utime(p,ns=(1,1))
    elif kind=='links':(root/'alias').unlink()
    else:os.setxattr(p,'user.immutable-inert',b'not574')
    try:b=self.snapshot(root)
    except ValueError:continue
    with self.assertRaises(ValueError):map_join.join(a,b)
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);self.tree(root);a=self.snapshot(root);b=copy.deepcopy(a);b['observation']['UNDECLARED']='changed'
   with self.assertRaises(ValueError):map_join.join(a,b)
 def test_aux_bytes_identity_and_hardlink_codec_refusals(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);p=self.tree(root);a=self.snapshot(root)
   for mutate in(lambda b:b['auxiliary'].__setitem__('aux_bytes',b'TAMPER'),lambda b:b['auxiliary']['configs'].__setitem__('foreign',dict(node={},inode=(999,999))),lambda b:b['observation']['hardlink_groups']['alias'].__setitem__('members',('alias','alias'))):
    b=copy.deepcopy(a);mutate(b)
    with self.assertRaises(ValueError):map_join.join(a,b)
 def test_exact_registered_mount_transition_no_ignored_rows(self):
  base=b'1 0 8:1 / / ro - ext4 /dev/root ro\n2 1 253:0 / /held ro - ext4 /dev/dm-0 ro\n3 1 8:2 /work /work rw - ext4 /dev/vdb rw\n'
  proc=b'4 3 0:9 / /work/pristine/root/proc ro,nosuid,nodev,noexec - proc proc ro\n'
  dev=b'5 3 0:10 /null /work/pristine/root/dev/null rw,nosuid - tmpfs tmpfs rw\n'
  registered=lease_table.lease_rows(base,base+proc+dev,['/work/pristine/root/proc','/work/pristine/root/dev/null']);self.assertTrue(lease_table.transition(base,base+proc+dev,registered))
  for after in(base+proc,base.replace(b'/held ro',b'/held rw')+proc+dev,base+proc+dev+proc.replace(b'4 3',b'6 3'),b'\n'.join(reversed(base.splitlines()))+b'\n'+proc+dev):
   with self.assertRaises(ValueError):lease_table.transition(base,after,registered)
  with self.assertRaises(ValueError):lease_table.lease_rows(base,base+proc,['/unapproved'])
 def test_default_gate_before_pid1_devices_or_process(self):
  value=P.decode((inputs.D/'policy.json').read_bytes())
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')),patch.object(C,'pid1',side_effect=AssertionError('PID1')):
   import owner
   with self.assertRaisesRegex(ValueError,'NULL'):owner.run(value)
  self.assertTrue(all(value[k]is None for k in('kernel_build_decision','kernel_boot_decision','actual_run','native_map')))
 def test_exact_derivative_functions_and_no_budget_drift(self):
  import runtime_context,worker,dispose
  original=inputs.original('_inert_runner','scripts/ci/glibc-owned-runtime/runner.py');raw=Path(original.__file__).read_bytes();text,proof=supervisor.derive(raw)
  a={n.name:ast.get_source_segment(raw.decode(),n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)};b={n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)};self.assertEqual({n for n in a if a[n]!=b[n]},{'run_command'});self.assertEqual(proof['edits'],4)
  self.assertEqual(runtime_policy.BOUNDS,dict(observer=600,copy=2400,cleanup=120,worker=10500,QEMU=10800,memory_mib=4096,CPUs=2));self.assertEqual(runtime_context.text.replace(runtime_context.replacement,runtime_context.anchor),runtime_context.old)
  path=inputs.D.parent/'gnu-verity-bootstrap-development-20261018/dm.py';self.assertIn('os.dup(self._retained_control)',dispose.request_source(path.read_bytes()))
 def test_real_original_supervisor_poll_and_retirement_with_inert_channel(self):
  original=inputs.original('_inert_supervisor','scripts/ci/glibc-owned-runtime/runner.py');text,proof=supervisor.derive(Path(original.__file__).read_bytes());space=dict(vars(original));exec(compile(text,'<inert-original-supervisor>','exec'),space)
  class Inert:
   def __init__(self):
    self.sock,self.peer=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);self.pid=None
    try:P.channel(self.sock);P.channel(self.peer)
    except BaseException:self.sock.close();self.peer.close();raise
   def pass_fds(self):return(self.peer.fileno(),)
   def begin(self,pid):self.pid=pid;self.peer.close()
   def eof(self):return self.sock.recv(1,socket.MSG_PEEK)==b''
   def once(self):value,_=P.receive(self.sock,(self.pid,os.getuid(),os.getgid()),0);P.send(self.sock,{'inert':'NOT_PID1_AUTHORITY'})
  s=Inert();fd=s.peer.fileno();script="import os,socket; s=socket.socket(fileno="+str(fd)+");os.write(s.fileno(),b'{\"inert\":true}');s.settimeout(5);s.recv(4096);print('INERT_NOT_NATIVE_ACCEPTANCE')"
  try:row,out,err,error=space['run_command']([sys.executable,'-I','-B','-c',script],Path('/tmp'),dict(PATH='/usr/bin:/bin'),5,1024,service=s)
  finally:s.sock.close()
  self.assertIsNone(error,(row,out,err));self.assertEqual(row['exit_code'],0);self.assertTrue(row['group_absence_verified']);self.assertEqual(err,b'');self.assertEqual(out,b'INERT_NOT_NATIVE_ACCEPTANCE\n')
  retired=row['worker_group_retirement'];self.assertTrue(retired['leader_reaped']);self.assertEqual(retired['wait_ownership'],'REAPED');self.assertEqual(retired['proof_status'],'PRE_REAP_RESERVED_LEADER_ONLY');self.assertEqual(retired['raw_wait']['raw_exit'],0);self.assertEqual(retired['raw_wait']['reserved_exit'],0);self.assertEqual(len(retired['pre_reap_scans']),2);self.assertTrue(all(scan['count']==1 for scan in retired['pre_reap_scans']))
 def test_preparer_init_and_four_disk_QEMU_source_controls(self):
  prepare=inputs.original('_inert_prepare','scripts/ci/glibc-debian-maintained-installed16k/prepare.py');raw=Path(prepare.__file__).read_bytes();init,proof=disk_adapter.init(raw);self.assertIn('mount -t proc -o ro,nosuid,nodev,noexec proc /proc',init);self.assertNotIn('/volume/held',init);self.assertIn('/immutable/entry.py',init);self.assertIn('runtime_stage.execute',disk_adapter.preparer(raw))
  run=inputs.original('_inert_qemu','scripts/ci/glibc-debian-maintained-installed16k/run.py');argv=disk_adapter.qemu(run.qemu,'Image','boot','work','source','hash');self.assertEqual(sum(x=='-drive'for x in argv),4);self.assertIn('if=none,id=source,format=raw,readonly=on,file=source',argv);self.assertIn('if=none,id=hash,format=raw,readonly=on,file=hash',argv)
  with self.assertRaises(ValueError):disk_adapter.qemu(lambda *_:['BAD'],'Image','boot','work','source','hash')
 def test_composed_source_native_controller_bootstrap_stage_and_default(self):
  import runtime_check,native_controller,native_prepare
  result=runtime_check.check();self.assertEqual(result['status'],'PASS_PROCESS_BLOCKED_COMPOSED_SOURCE_ONLY');self.assertEqual(result['inputs'],413)
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   with self.assertRaisesRegex(ValueError,'NULL'):native_controller.execute(None,P.decode((inputs.D/'policy.json').read_bytes()))
 def test_boot_availability_is_never_mapping_integrity_or_lifecycle(self):
  import prerequisites
  with self.assertRaises(ValueError):prerequisites.boot({},dict(bytes=1,sha256='0'*64))
  for scope in ('verity_mapping','integrity','lifecycle'):
   value=dict(purpose='GNU_VERITY_KERNEL_BOOT_AVAILABILITY_ONLY_V1',source='0'*40,run='1',kernel_build_decision=dict(bytes=1,sha256='0'*64),scope=list(prerequisites.BOOT_SCOPE),page_size=16384,PID1=True,DM_VERSION=True,verity_target=True,poweroff='NATURAL',verity_mapping='NOT_QUALIFIED',integrity='NOT_QUALIFIED',lifecycle='NOT_QUALIFIED');value[scope]='PASS'
   with self.assertRaises(ValueError):prerequisites.boot(value,dict(bytes=1,sha256='0'*64))
 def test_new_protocol_never_accepts_old_or_partial_results(self):
  import native_controller
  for raw in (b'',b'GNU_INSTALLED16K foreign {}',b'{"purpose":"GNU_IMMUTABLE_RUNTIME_V1"}\n{}\n'):
   with self.assertRaises((ValueError,KeyError)):native_controller.protocol(raw,{})
 def test_closed_factory_git_metadata_only_and_extra_alias_refusal(self):
  import factory
  with tempfile.TemporaryDirectory(dir=inputs.D)as td:
   out=Path(td)/'bundle';proof=factory.emit(out);self.assertEqual(proof['runtime_vm'],dict(held=226,supplement=1,total=227));self.assertEqual(factory.check(out)['source_files'],667)
   (out/'.git').mkdir();(out/'.git/config').write_text('INERT_GIT_METADATA');self.assertEqual(factory.check(out)['source_files'],667)
   (out/'unexpected').write_text('REFUSE')
   with self.assertRaises(ValueError):factory.check(out)
   (out/'unexpected').unlink();(out/'alias').symlink_to(out/'runtime-vm',target_is_directory=True)
   with self.assertRaises(ValueError):factory.check(out)
if __name__=='__main__':unittest.main(verbosity=2)
