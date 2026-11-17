# SPDX-License-Identifier: MIT
"""Passive source/model controls; never execute a tool, actor, syscall or lease."""
import ast,copy,hashlib,importlib.util,json,sys,types,unittest
from datetime import datetime,timezone
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(name,p):
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn'))or event in('os.system','os.kill','os.killpg','fcntl.flock','resource.setrlimit'):raise AssertionError('no execution, syscall, socket or lease in passive controls')
 if event=='open'and args and isinstance(args[0],(str,bytes)):
  name=str(args[0])
  if name.endswith(('.raw','credentials.canonical.private.json','collection.lock'))or 'private-keys-v1.d'in name:raise AssertionError('no backing body, credential, key or lease read')
sys.addaudithook(fence)
R=load('baseline_request',HERE/'recovery.py');D=load('baseline_derivative',HERE/'derive.py')
OLD={n:(HERE/'predecessor'/n).read_bytes()for n in D.PINS};NEW=D.apply(OLD)
def as_module(name,raw,filename):
 m=types.ModuleType(name);m.__file__=str(filename);exec(compile(raw,str(filename),'exec'),m.__dict__);return m
ENGINE=as_module('baseline_engine',NEW['run_metadata.py'],HERE/'virtual-capsule/run_metadata.py')
LIMITER=as_module('baseline_limiter',NEW['exec_limiter.py'],HERE/'virtual-capsule/exec_limiter.py')
def frame(row):
 seconds=row['mtime'];ns=row['mtime_ns'];stamp=datetime.fromtimestamp(seconds,timezone.utc).strftime('%a %b %e %H:%M:%S %Y');kind='regular'if row['type']=='file'else'directory'
 return (f'debugfs 1.47.4 (29-Mar-2025)\nInode: {row["inode"]}   Type: {kind}    Mode:  {row["mode"]:04o}   Flags: 0x0\nUser: {row["uid"]}   Group: {row["gid"]}    Size: {row["size"]}\nLinks: {row["links"]}   Blockcount: 8\n ctime: 0x{seconds:08x}:{ns<<2:08x} -- {stamp}\n atime: 0x{seconds:08x}:{ns<<2:08x} -- {stamp}\n mtime: 0x{seconds:08x}:{ns<<2:08x} -- {stamp}\n').encode()
class Controls(unittest.TestCase):
 def setUp(self):
  self.request=json.loads((HERE/'request.TEMPLATE.json').read_bytes());self.baseline=json.loads((HERE/'baseline-public.DATA.json').read_bytes());self.frames={}
  for path,label in [('etc','etc'),('etc/ld.so.cache','cache')]:
   self.frames[label+'-before']=self.frames[label+'-after']=frame(self.baseline['nodes'][path])
 def test_default_NULL_request_refuses_before_any_process(self):
  R.declared(self.request);self.assertIsNone(self.request['accepted']);self.assertIsNone(self.request['issued_by']);self.assertIsNone(self.request['output'])
  with self.assertRaisesRegex(ValueError,'Root must separately'):R.plan(self.request)
 def test_exact_five_debugfs_readonly_commands_and_no_raw_output(self):
  rows=R.fixed_plan();self.assertEqual(len(rows),5);self.assertEqual([r['label']for r in rows],list(R.LABELS))
  self.assertEqual([r['argv'][2]for r in rows],['stat /etc/ld.so.cache','stat /etc','dump /etc/ld.so.cache /output/cache.bin','stat /etc/ld.so.cache','stat /etc'])
  self.assertTrue(all(r['argv'][0]=='/usr/bin/debugfs'and r['argv'][1]=='-R'and r['argv'][-1]=='/prepared/guest.raw'and r['seconds']==10 for r in rows))
  self.assertFalse(any('-w'in r['argv']or'qemu'in str(r)or'observation.raw'in str(r)for r in rows))
 def test_overlay_other_backing_tool_or_resource_field_refuses(self):
  for change in('overlay','backing','tool','resource'):
   value=copy.deepcopy(self.request)
   if change=='overlay':value['overlay']={}
   elif change=='backing':value['backing']['pin']['sha256']='a'*64
   elif change=='tool':value['tools']['/usr/bin/qemu-img']={}
   else:value['resources']['memory_bytes']+=1
   with self.subTest(change=change),self.assertRaises(ValueError):R.declared(value)
 def test_strict_public_metadata_positive_and_repeat_refusals(self):
  nodes=R.metadata(self.frames,self.baseline);self.assertEqual(nodes['etc/ld.so.cache']['size'],17551)
  value=copy.deepcopy(self.frames);row=copy.deepcopy(self.baseline['nodes']['etc/ld.so.cache']);row['inode']+=1;value['cache-after']=frame(row)
  with self.assertRaisesRegex(ValueError,'unchanged metadata'):R.metadata(value,self.baseline)
  value['cache-before']=value['cache-after']
  with self.assertRaisesRegex(ValueError,'same fixed prepared'):R.metadata(value,self.baseline)
 def test_unknown_body_is_not_fabricated_as_positive_expected_hash(self):
  self.assertEqual(R.CACHE,dict(bytes=17551,sha256='0128a732a8b926232b5065374176194ea4a1f5c1628728037109bbdbb3d53215'))
  for body in(b'',b'x'*17551,b'x'*(1048576+1)):
   with self.assertRaisesRegex(ValueError,'baseline cache body SHA256'):R.decode_outputs(self.frames,body,self.baseline)
 def test_no_private_or_additional_path_decoder_scope(self):
  for path in('root','.ssh','etc/shadow','etc/ld.so.preload'):
   with self.subTest(path=path),self.assertRaises(ValueError):R.S.request(path)
  with self.assertRaises(ValueError):R.S.parse_stat(self.frames['cache-before']+b'PRIVATE_CHILD\n','etc/ld.so.cache')
 def test_exact_predecessor_inverse_and_critical_core_equalities(self):
  self.assertEqual(D.inverse(OLD,NEW),OLD)
  a=D.functions(OLD['run_metadata.py'].decode());b=D.functions(NEW['run_metadata.py'].decode())
  for name in D.CORE:self.assertEqual(a[name],b[name],name)
  old=D.functions(OLD['exec_limiter.py'].decode());new=D.functions(NEW['exec_limiter.py'].decode());self.assertEqual(old,new)
  old=D.functions(OLD['Root-enter.DRAFT.py'].decode());new=D.functions(NEW['Root-enter.DRAFT.py'].decode())
  for name in('limits','census','module','main'):self.assertEqual(old[name],new[name],name)
 def test_corrupt_preimage_or_unreviewed_generated_code_refuses(self):
  rows=dict(OLD);rows['run_metadata.py']+=b'\n'
  with self.assertRaises(ValueError):D.apply(rows)
  rows=dict(NEW);rows['run_metadata.py']+=b'\n'
  with self.assertRaises(ValueError):D.inverse(OLD,rows)
 def test_single_RO_backing_exact_five_mounts_and_fourMiB_FSIZE(self):
  c=dict(nonce='a'*32,qualification_authority=dict(path='/MODEL/request.json',sha256='b'*64));f=dict(input_raw=dict(path='/MODEL/prepared'),prior_packet=dict(path='/MODEL/code/packet.json'),image=R.IMAGE)
  argv=ENGINE.create_argv(c,f,Path('/MODEL/output'),'c'*64,1000);mounts=[argv[i+1]for i,v in enumerate(argv)if v=='--mount']
  self.assertEqual(len(mounts),5);self.assertEqual(sum(',readonly'not in p for p in mounts),1);self.assertTrue(any('dst=/prepared/guest.raw,readonly'in p for p in mounts));self.assertFalse(any('overlay'in p for p in mounts));self.assertIn('fsize=4194304:4194304',argv)
  self.assertEqual(LIMITER.LIMITS['FSIZE'],[4194304,4194304]);self.assertEqual(argv[argv.index('--memory')+1],'536870912');self.assertEqual(argv[argv.index('--pids-limit')+1],'64')
 def test_output_membership_caps_and_default_outer_gate(self):
  c=dict(qualification_authority=dict(bytes=1,sha256='a'*64));files={n:dict(bytes=1,sha256='a'*64)for n in R.artifact_names()};files['cache.bin']=R.CACHE
  value=dict(kind='OBSERVED_BASELINE_PUBLIC_LDCACHE_DATA_V1',status='BASELINE_CACHE_BODY_ONLY_NOT_TRANSITION_ACCEPTANCE',Source_lock=R.SOURCE,request=c['qualification_authority'],tools_reverified=True,commands=5,all_tools_naturally_reaped=True,files=files,cache_observation=dict(cache=R.CACHE),**dict.fromkeys(('Root_acceptance','VM_acceptance','lifecycle_acceptance','M2','release')))
  ENGINE.validate_observation(value,c,dict(source_lock=R.SOURCE))
  for change in('raw','oversize','fake'):
   v=copy.deepcopy(value)
   if change=='raw':v['files']['observation.raw']=dict(bytes=1,sha256='a'*64)
   elif change=='oversize':v['files']['cache-before.log']['bytes']=16385
   else:v['lifecycle_acceptance']=True
   with self.subTest(change=change),self.assertRaises(ValueError):ENGINE.validate_observation(v,c,dict(source_lock=R.SOURCE))
  with self.assertRaisesRegex(ValueError,'fresh explicit Root'):ENGINE.require_issued(json.loads((HERE/'outer-input.TEMPLATE.json').read_bytes()),{})
 def test_executor_receipts_precede_natural_gate_and_only_small_relocation(self):
  text=(HERE/'observe_initialized.py').read_text();self.assertLess(text.index("put(scan/(command['label']+'.retirement.json')"),text.index("need(row['passed']"))
  self.assertIn("for name in('cache.bin',):",text);self.assertNotIn("'convert'",text);self.assertNotIn("'chain'",text);self.assertNotIn('observation.raw',text)
  self.assertIn('signal.getitimer(signal.ITIMER_REAL)',text);self.assertNotIn('setitimer(',text);self.assertIn('RUSAGE_CHILDREN',text)
if __name__=='__main__':unittest.main(verbosity=2)
