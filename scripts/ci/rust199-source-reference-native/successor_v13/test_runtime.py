# SPDX-License-Identifier: MIT
"""MODEL kernel rows and ACTUAL API-only projection. No actor/kernel observation."""
import ast,copy,hashlib,importlib.util,io,json,os,stat,sys,tempfile,unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
M=module('v13_kernel_MODEL',HERE/'payload/actor/mount_proof.py')
V12=module('v12_RUNTIME_FENCED',HERE.parent/'successor_v12/test_runtime.py')
Q=module('v13_qualification_FENCED',HERE/'payload/hosted/qualification.py')
P=V12.load('v13_API_FENCED',HERE/'payload/hosted/producer.py')
E=module('v13_actor_entry_FENCED',HERE/'payload/actor/entry.py')
A=module('v13_actor_qualify_FENCED',HERE/'payload/actor/qualify.py')

def fence(event,args):
 if event.startswith(('socket.','subprocess.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit'):raise AssertionError('FENCED no actor/network/lease '+event)
sys.addaudithook(fence)

def context(phase='qualification-probe'):
 return dict(source=dict(sha='a'*40,ref='refs/heads/codex/FENCED_MODEL',map_sha256='b'*64,approval='c'*64,run='101',job='201'),dispatch_sha256='d'*64,input_admission_sha256='e'*64,image_id='sha256:'+'f'*64,volume_token='a'*24,phase=phase)

def raw(aliases=True,root='/filesystem-relative/owned-volume',device='8:1'):
 rows=['1 999 0:1 / / ro - overlay overlay rw','2 1 '+device+' '+root+' /work rw,nosuid - ext4 /dev/MODEL rw,relatime']
 if aliases:rows+=['3 1 '+device+' '+root+'/build/stage0 /stage0 ro,nosuid - ext4 /dev/MODEL rw,relatime','4 2 '+device+' '+root+'/build/stage0 /work/build/stage0 ro,nosuid - ext4 /dev/MODEL rw,relatime']
 return ('\n'.join(rows)+'\n').encode()

def proof(data=None,ctx=None):
 return M.verify(raw()if data is None else data,ctx or context(),'kernel-mountinfo-qualification-probe.raw',M.pin(Path(M.__file__).read_bytes())['sha256'])

class Runtime(unittest.TestCase):
 def test_actual_API_fixture_is_pinned_not_a_kernel_proof(self):
  data=(HERE/'fixtures/probe-mount.ACTUAL.json').read_bytes();self.assertEqual(len(data),6302);self.assertEqual(hashlib.sha256(data).hexdigest(),'e8cf3b1f7dbefc763f93fc91c501e6d28d9a79e0d83cde6a57e9c180d83edf74');row=json.loads(data)['projection'];self.assertNotIn('Env',row.get('Config',{}))
  mounts=row['HostConfig']['Mounts'];expected=copy.deepcopy(mounts)
  for want in expected:
   want.setdefault('ReadOnly',False)
   if 'VolumeOptions'in want:want['VolumeOptions'].pop('DriverConfig',None)
  volume=mounts[0]['Source'];path=Path(next(x['Source']for x in row['Mounts']if x['Destination']=='/work'))
  old=V12.load('v12_old_API',HERE.parent/'successor_v12/payload/hosted/producer.py')
  with self.assertRaises(ValueError):old.inspect_mounts(row,expected,volume,path)
  with self.assertRaises(ValueError):P.inspect_mounts(row,expected,volume,path)
  P.inspect_mounts(row,expected,volume,path,kernel_proof_required=True)
  bad=copy.deepcopy(row);next(x for x in bad['Mounts']if x['Destination']=='/stage0')['Source']='/foreign'
  with self.assertRaises(ValueError):P.inspect_mounts(bad,expected,volume,path,kernel_proof_required=True)
 def test_model_filesystem_relative_roots_not_Docker_host_path(self):
  for root in('/volume','/','/relative-root-with\\040space'):
   data=raw(root=root.rstrip('/')or'/');data=data.replace(b'//build',b'/build');p=proof(data);self.assertEqual(p['mounts']['/stage0']['root'],p['alias_root']);self.assertFalse(p['native_acceptance']);self.assertTrue(p['holds_preserved'])
 def test_all_six_actor_actions_have_fixed_profile(self):
  for phase in M.PHASES:
   aliases=phase in('qualification-probe','makepkg','build','package');ctx=context(phase);data=raw(aliases);p=M.verify(data,ctx,'kernel-mountinfo-'+phase+'.raw','a'*64);self.assertEqual(p['profile'],'stage0-aliases'if aliases else'work-only')
   with self.assertRaises(ValueError):M.verify(raw(not aliases),ctx,'kernel-mountinfo-'+phase+'.raw','a'*64)
 def test_wrong_root_device_filesystem_source_and_parent_refuse(self):
  for a,b in[(b'/owned-volume/build/stage0',b'/owned-volume'),(b'3 1 8:1',b'3 1 8:2'),(b'3 1 8:1',b'3 2 8:1'),(b'4 2 8:1',b'4 1 8:1'),(b'/stage0 ro,nosuid - ext4',b'/stage0 ro,nosuid - xfs'),(b'/stage0 ro,nosuid - ext4 /dev/MODEL',b'/stage0 ro,nosuid - ext4 /dev/FOREIGN')]:
   with self.subTest(a=a),self.assertRaises(ValueError):proof(raw().replace(a,b,1))
 def test_work_and_superblock_writable_aliases_readonly_are_mandatory(self):
  for a,b in[(b'/work rw,nosuid',b'/work ro,nosuid'),(b'/stage0 ro,nosuid',b'/stage0 rw,nosuid'),(b'/dev/MODEL rw,relatime',b'/dev/MODEL ro,relatime'),(b'/work/build/stage0 ro,nosuid',b'/work/build/stage0 rw,nosuid')]:
   with self.subTest(a=a),self.assertRaises(ValueError):proof(raw().replace(a,b,1))
 def test_shadow_duplicate_ambiguous_paths_escapes_and_missing_rows_refuse(self):
  for data in(raw()+raw().splitlines(True)[1],raw()+b'7 2 8:1 /foreign /work/build rw - ext4 /dev/MODEL rw\n',raw()+b'7 3 8:1 /foreign /stage0/child ro - ext4 /dev/MODEL rw\n',raw().replace(b'/work rw',b'/work/../work rw'),raw().replace(b'/work rw',b'//work rw'),raw().replace(b'/filesystem-relative',b'/bad\\057path'),raw().replace(b'/filesystem-relative',b'/bad\\134040path'),raw().split(b'4 2')[0]):
   with self.subTest(data=data[-60:]),self.assertRaises(ValueError):proof(data)
 def test_byte_line_row_and_truncation_bounds(self):
  for data in(b'',raw()[:-1],b'x'*(M.MAX_BYTES+1),raw()+b'5 1 0:1 / /extra rw '+b'x'*8192+b' - tmpfs tmpfs rw\n'):
   with self.assertRaises(ValueError):proof(data)
 def test_changed_fixed_proc_observation_refuses_without_workspace_write(self):
  # Fixed reader seam only: no real /proc or native process is observed.
  with patch.object(M,'read_kernel',return_value=raw()),patch.object(M.Path,'read_bytes',return_value=b'MODEL helper'):
   data,p=M.observe(context(),'kernel-mountinfo-qualification-probe.raw');self.assertEqual(p['mountinfo']['sha256'],M.pin(data)['sha256'])
  with patch.object(M,'read_kernel',return_value=raw(False)),patch('sys.stderr',new_callable=io.StringIO)as stderr:
   with self.assertRaises(ValueError):M.observe(context(),'kernel-mountinfo-qualification-probe.raw')
   failure=json.loads(stderr.getvalue());self.assertEqual(failure['status'],'HOLD_KERNEL_MOUNTINFO_PREENTRY');self.assertNotIn('PASS',failure['status'])
 def test_fixed_proc_reader_rejects_changed_second_snapshot_and_oversize(self):
  info=SimpleNamespace(st_mode=stat.S_IFREG|0o444,st_dev=1,st_ino=2)
  for blocks in([raw(),b'',raw(False),b''],[b'x'*(M.MAX_BYTES+1)]):
   with patch.object(M.os,'open',return_value=123)as opened,patch.object(M.os,'read',side_effect=blocks),patch.object(M.os,'fstat',return_value=info),patch.object(M.os,'close'):
    with self.assertRaises(ValueError):M.read_kernel()
    self.assertEqual(opened.call_args.args[0],'/proc/self/mountinfo')
 def test_receipt_context_raw_helper_and_order_cannot_be_forged(self):
  data=raw();p=proof(data);M.validate(data,p,context())
  for key in('context','helper_sha256','order','mounts','mountinfo'):
   bad=copy.deepcopy(p);bad[key]={}if type(bad[key])is dict else'0'*64
   with self.subTest(key=key),self.assertRaises((KeyError,ValueError)):M.validate(data,bad,context())
  with self.assertRaises(ValueError):M.validate(data+b'changed',p,context())
 def test_source_enforced_preentry_and_every_command_digest_seams(self):
  q=(HERE/'payload/actor/qualify.py').read_text();e=(HERE/'payload/actor/entry.py').read_text()
  for text in(q,e):ast.parse(text);self.assertLess(text.index('mount.observe('),text.index('OUT.mkdir('));self.assertIn('kernel_mount_proof_sha256',text)
  self.assertLess(e.index('mount.observe('),e.index("if action=='prepare':prepare_layout(n)"));self.assertLess(q.index('mount.observe('),q.index("(WORK/'stage0-unpack').mkdir()"))
  host=(HERE/'payload/hosted/qualification.py').read_text();self.assertIn("row['kernel_mount_proof_sha256']==kernel['qualification-probe']",host);self.assertIn("r['kernel_mount_proof_sha256']==result['qualification-data']",host)
 def test_every_actual_actor_entry_refuses_before_tools_or_workspace_mutation(self):
  fail=SimpleNamespace(observe=lambda *args:(_ for _ in()).throw(ValueError('MODEL_KERNEL_REFUSAL')))
  with tempfile.TemporaryDirectory(prefix='FENCED-v13-preentry-')as temporary:
   root=Path(temporary);ctx=context();p=dict(provider=dict(source=ctx['source'],dispatch_sha256=ctx['dispatch_sha256']),image_id=ctx['image_id'],volume_owner=dict(token=ctx['volume_token']))
   for phase in('data','probe'):
    with patch.object(A,'plan',return_value=(p,None,None)),patch.object(A,'kernel'),patch.object(A,'load',return_value=fail),patch.dict(os.environ,QUALIFICATION_SHA256='e'*64),patch.object(A,'WORK',root/'work'),patch.object(A,'OUT',root/'out'):
     with self.assertRaisesRegex(ValueError,'MODEL_KERNEL_REFUSAL'):A.run(phase)
     self.assertFalse((root/'work').exists());self.assertFalse((root/'out').exists())
   actor=dict(source=ctx['source'],authorization=dict(dispatch=dict(sha256=ctx['dispatch_sha256'])),image=dict(id=ctx['image_id']))
   for action in('prepare','makepkg','build','package'):
    phase=SimpleNamespace(kernel_guard=lambda *args:(_ for _ in()).throw(AssertionError('must refuse earlier')))
    with patch.object(E,'gate',return_value=(actor,None,phase,None,None,dict(binding=dict(token=ctx['volume_token'])),None)),patch.object(E,'load',return_value=fail),patch.object(E,'read',return_value=b'MODEL'),patch.object(E,'WORK',root/'work'),patch.object(E,'OUT',root/'out'):
     with self.assertRaisesRegex(ValueError,'MODEL_KERNEL_REFUSAL'):E.execute(action,{'ROOT_ADMISSION_SHA256':'e'*64})
     self.assertFalse((root/'work').exists());self.assertFalse((root/'out').exists())
 def test_host_replays_complete_raw_proofs_before_and_after_relocation(self):
  with tempfile.TemporaryDirectory(prefix='FENCED-v13-host-')as temporary:
   root=Path(temporary);ctx=context();provider=dict(source=ctx['source'],dispatch_sha256=ctx['dispatch_sha256']);boot=dict(image=ctx['image_id'],rootfs_tree_sha256='1'*64)
   plan=dict(provider=provider,image_id=boot['image'],rootfs_tree_sha256=boot['rootfs_tree_sha256'],qualification_allowed=True,holds_preserved=True,volume_owner=dict(token=ctx['volume_token']))
   def put(name,data):
    (root/name).write_bytes(data);return dict(file=name,**M.pin(data))
   planraw=M.encode(plan);value=dict(qualification_plan=put('qualification-plan.json',planraw),kernel_mount_proofs={});digests={}
   for phase in('qualification-data','qualification-probe'):
    c=dict(ctx,phase=phase,input_admission_sha256=M.pin(planraw)['sha256']);data=raw(phase=='qualification-probe');name='kernel-mountinfo-'+phase+'.raw';p=M.verify(data,c,name,M.pin(Path(M.__file__).read_bytes())['sha256']);ref=put('kernel-mount-proof-'+phase+'.json',M.encode(p));value['kernel_mount_proofs'][phase]=dict(receipt=ref,mountinfo=put(name,data));digests[phase]=ref['sha256']
   life=dict(natural_exit=True,forced_cleanup=False,group_absent=True,retirement='REAPED',ownership_lost=False,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,exit=0)
   commands=[dict(returncode=0,lifecycle=life,kernel_mount_proof_sha256=digests['qualification-data'])for _ in range(5)];value['data_commands']=put('data-commands.json',M.encode(commands));self.assertEqual(Q.kernel_proofs(value,provider,boot,root),digests)
   value['files']={'qualification_'+p.name:dict(local_path=str(p),**M.pin(p.read_bytes()))for p in root.iterdir()};self.assertEqual(Q.kernel_proofs(value,provider,boot),digests)
   with self.assertRaises((KeyError,ValueError)):Q.kernel_proofs({},provider,boot)
   commands[0]['kernel_mount_proof_sha256']='0'*64;value['data_commands']=put('data-commands.json',M.encode(commands))
   with self.assertRaises(ValueError):Q.kernel_proofs(value,provider,boot,root)

if __name__=='__main__':unittest.main(verbosity=2)
