# SPDX-License-Identifier: MIT
"""Pure/source-shaped tests; none boot, install, contact a daemon, or claim ARM."""
import ast,copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,boot,guest_guard,host,media,effects

class CaseTests(unittest.TestCase):
 def test_unbound_before_output(self):
  with self.assertRaisesRegex(ValueError,'binding required'):
   C.selection(dict(schema=1,scope='CORE7_AUTOMATIC_HOOKS_ACTUAL_SYSTEMD_PID1_GENERIC16K',actual=None,nonce='a'*32,kernel={},source_profiles={},budgets=C.BUDGET))
 def test_bootstrap_actual_unit_route(self):
  raw=boot.bootstrap('a'*32);r=subprocess.run(['/usr/bin/bash','-n'],input=raw,capture_output=True);self.assertEqual((r.returncode,r.stderr),(0,b''))
  text=raw.decode();self.assertIn('exec /usr/lib/systemd/systemd --system --unit=caa-core.target',text);self.assertNotIn('exec /usr/bin/python3',text);self.assertNotIn('mknod',text);self.assertNotIn('umount /dev',text)
  self.assertLess(text.index('guest.py bootstrap'),text.index('exec /usr/lib/systemd/systemd'));self.assertIn('mount -t cgroup2',text)
  units={n:C.read(C.HERE/'units'/n).decode()for n in boot.UNITS};self.assertIn('Requires=caa-core-worker.service',units['caa-core-probe.service']);self.assertIn('After=caa-core-probe.service',units['caa-core-observer.service']);self.assertNotIn('RemainAfterExit',str(units));self.assertIn('Type=exec',units['caa-core-observer.service']);self.assertIn('Type=oneshot',units['caa-core-worker.service'])
  guest=ast.parse(C.read(C.HERE/'guest.py'));self.assertTrue(any(isinstance(n,ast.FunctionDef)and n.name=='observer'for n in guest.body))
 def test_qemu_two_boots_same_media_no_network(self):
  a=host.qemu('/k/Image','/owned/boot.raw','/owned/data.raw','b'*32,1,1792659524);b=host.qemu('/k/Image','/owned/boot.raw','/owned/data.raw','b'*32,2,1792659524)
  self.assertEqual([i for i,(x,y)in enumerate(zip(a,b))if x!=y],[a.index('-append')+1]);self.assertIn('caa_core_phase=1',a[a.index('-append')+1]);self.assertIn('none',a);self.assertNotIn('-virtfs',a);self.assertIn('virtio-blk-pci,drive=boot,serial='+C.disk_serial('b'*32,'boot'),a)
 def test_nonce_and_phase_reject_before_guest_actor(self):
  for raw in('caa_core_vm='+'a'*32+' caa_core_vm='+'b'*32+' caa_core_phase=1','caa_core_vm='+'a'*32+' caa_core_phase=3','caa_core_phase=1'):
   with self.assertRaises(ValueError):guest_guard.kernel_fields(raw)
 def test_no_prefix_tmpfiles_allowance(self):
  rules=effects.tmpfiles_rules(b'd /var/lib/caa 0700 root root -\nZ /var/lib/foreign 0700 root root -\nd /var/lib/caa/* 0700 root root -\n',{'root':0},{'root':0});self.assertEqual(rules,{'var/lib/caa':dict(type='directory',mode=0o700,uid=0,gid=0)});self.assertNotIn('var/lib/foreign',rules)
 def test_literal_tmpfiles_original_create_only_and_trailing_slash(self):
  raw=b'd /run/varlink/registry/ 0755 root root -\nd- /root :0700 root :root -\nd /root/.ssh :0700 root :root -\nd /var/lib/exact/ 0750 root root -\n'
  rows=effects.tmpfiles_rules(raw,{'root':0},{'root':0});self.assertEqual(set(rows),{'root','root/.ssh','var/lib/exact'});self.assertEqual(rows['root'],dict(type='directory',mode=0o700,uid=0,gid=0,create_only=True));self.assertEqual(rows['var/lib/exact'],dict(type='directory',mode=0o750,uid=0,gid=0))
 def test_whole_baseline_overlay_join_no_implicit_exemption(self):
  nonce='a'*32;nodes={};overlay={}
  for name,row in boot.overlay(nonce).items():overlay[name]=dict(before=None,after=dict(type='file',mode=row['mode'],uid=0,gid=0,**C.pin(row['data'])))
  for name in('etc/pacman.conf','etc/systemd/system.conf'):
   node=dict(type='file',mode=0o644,uid=0,gid=0,**C.pin(b'original'));nodes[name]=node;overlay[name]=dict(before=node,after=dict(node,**C.pin(b'original\nowned config')))
  expected=boot.expected_baseline(nodes,overlay);self.assertEqual(expected['etc/pacman.conf'],overlay['etc/pacman.conf']['after']);bad=copy.deepcopy(overlay);bad['etc/pacman.conf']['before']['sha256']='0'*64
  with self.assertRaisesRegex(ValueError,'before node'):boot.expected_baseline(nodes,bad)
 def test_graph_source_and_caps_body_held(self):
  # Finite derivation runs on the real source in author controls, with the full
  # copy function still present. The installed/source CLI supplies exact root.
  self.assertEqual(C.BUDGET['boot']*2,C.BUDGET['vm_shared']);self.assertEqual(C.BUDGET['transaction'],90)
  with self.assertRaises(ValueError):boot.bootstrap('a'*31+';')
class SerialControls(unittest.TestCase):
 def test_full128_role_derivation_and_GET_ID_boundary(self):
  import base64,hashlib
  nonce='0'*32;seen=set()
  for bits in [0,*[1<<i for i in range(128)]]:
   n=f'{bits:032x}'
   for role in('boot','data'):
    value=C.disk_serial(n,role);self.assertEqual(len(value.encode('ascii')),20);self.assertNotIn(',',value);self.assertNotIn('\0',value);self.assertEqual(value.encode()[:20],value.encode());self.assertEqual(base64.b85decode(value),hashlib.sha256(b'cachy-asahi/core7/virtio-blk/serial-v1\0'+role.encode()+b'\0'+bytes.fromhex(n)).digest()[:16]);self.assertNotIn(value,seen);seen.add(value)
  n2='0'*31+'1'
  for role in('boot','data'):
   old=lambda n:('core7-'+('data-'if role=='data'else'')+n).encode()
   self.assertEqual(old(nonce)[:20],old(n2)[:20]);self.assertNotEqual(old(nonce)[:20],old(nonce));self.assertNotEqual(C.disk_serial(nonce,role),C.disk_serial(n2,role))
  for nonce,role in((None,'boot'),('a'*31,'boot'),('A'*32,'data'),('a'*31+';','boot'),('a'*32,'foreign')):
   with self.assertRaises(ValueError):C.disk_serial(nonce,role)
 def test_actual_emitted_bootstrap_success_and_ERR_line_without_mount_actors(self):
  import shlex
  nonce='f'*32;text=boot.bootstrap(nonce).decode();self.assertIn(shlex.quote(C.disk_serial(nonce,'boot')),text);self.assertIn(shlex.quote(C.disk_serial(nonce,'data')),text)
  # Whole emitted bootstrap. Only OS actor adapters and console endpoint are
  # inert; all literal guards, sequence, trap and exact shell quoting execute.
  functions='''id(){ printf '0\\n'; }
uname(){ printf 'aarch64\\n'; }
mount(){ :; }; mkdir(){ :; }; umount(){ :; }; rmdir(){ :; }
grep(){ :; }
cat(){ case "$1" in */vda/serial) printf '%s\\n' "$BOOT_ID";; */vdb/serial) printf '%s\\n' "$DATA_ID";; *) return 88;; esac; }
'''
  original='/usr/bin/python3 -I -B /workspace/guest.py bootstrap';finish='exec /usr/lib/systemd/systemd --system --unit=caa-core.target --log-target=console --log-level=info --show-status=yes';self.assertEqual(text.count(original),1);self.assertEqual(text.count(finish),1);self.assertEqual(text.count('>/dev/console'),1)
  for wrong in(None,'boot','data'):
   with tempfile.TemporaryDirectory()as td:
    console=Path(td)/'console';body=text.replace('#!/usr/bin/bash\n','#!/usr/bin/bash\n'+functions).replace('>/dev/console','>'+shlex.quote(str(console))).replace(original,': # inert guest actor').replace(finish,"printf 'INERT_SYSTEMD_EXEC_REACHED\\n'")
    ids={r:C.disk_serial(nonce,r)for r in('boot','data')}
    if wrong:ids[wrong]=('core7-'+nonce)[:20]
    import os
    env=dict(os.environ,BOOT_ID=ids['boot'],DATA_ID=ids['data']);p=subprocess.run(['/usr/bin/bash','-s'],input=body.encode(),env=env,capture_output=True,timeout=5)
    if wrong:
     self.assertEqual(p.returncode,1);self.assertNotIn(b'INERT_SYSTEMD_EXEC_REACHED',p.stdout);raw=console.read_bytes();line=next(i for i,v in enumerate(body.splitlines(),1)if v.startswith('test ')and('/vda/serial)'if wrong=='boot'else'/vdb/serial)')in v);self.assertEqual(raw,('CORE7_BOOTSTRAP_FAILURE_DATA line='+str(line)+' rc=1\n').encode());self.assertLess(len(raw),128)
    else:self.assertEqual((p.returncode,p.stderr,p.stdout),(0,b'',b'INERT_SYSTEMD_EXEC_REACHED\n'));self.assertFalse(console.exists())
 def test_every_live_boundary_uses_same_serial_and_full_nonce(self):
  nonce='b'*32;argv=host.qemu('/k/Image','/owned/boot.raw','/owned/data.raw',nonce,1,1792659524)
  for role in('boot','data'):self.assertIn('virtio-blk-pci,drive='+role+',serial='+C.disk_serial(nonce,role),argv)
  self.assertIn('caa_core_vm='+nonce,argv[argv.index('-append')+1]);self.assertIn('panic=1',argv[argv.index('-append')+1]);self.assertEqual(boot.overlay(nonce)['etc/machine-id']['data'],(nonce+'\n').encode())
  for name in('guest_guard.py','guest.py','controller.py','validate.py'):
   source=C.read(C.HERE/name).decode();self.assertIn("C.disk_serial(",source);self.assertNotIn("serial='core7-'+",source);self.assertNotIn("=='core7-'+",source)
  import test_protocol as T
  s,expected,value=T.fixture();value['pid1']['root']['serial']=('core7-'+s['nonce'])[:20]
  with self.assertRaisesRegex(ValueError,'persistent root'):C.protocol(T.frames(value),s,1,expected)
 def test_panic_or_early_exit_cannot_be_positive(self):
  import test_protocol as T
  s,expected,value=T.fixture()
  for raw in(b'Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000100\n',b'CORE7_BOOTSTRAP_FAILURE_DATA line=10 rc=1\n',b'',T.frames(value)+b'Kernel panic - not syncing: failure\n',T.frames(value)+b'CORE7_BOOTSTRAP_FAILURE_DATA line=10 rc=1\n'):
   with self.assertRaisesRegex(ValueError,'final observer frame|panic or bootstrap failure'):C.protocol(raw,s,1,expected)
  self.assertEqual(C.BUDGET,dict(owner=14400,producer=2300,assembly=1070,media=1900,vm_shared=7200,boot=3600,transaction=90,cleanup=60))


class WallclockControls(unittest.TestCase):
 def sample(self,phase=1):
  import clock as W
  return dict(schema=1,source=W.ORIGIN,nonce='a'*32,phase=phase,epoch_seconds=1792659524,host_monotonic_ns=100)
 def record(self,phase=1):
  import clock as W
  return dict(schema=1,source=W.ORIGIN,nonce='a'*32,phase=phase,epoch_seconds=1792659524,previous_realtime_ns=1790293564*10**9,initialized_realtime_ns=1792659524*10**9,monotonic_before_ns=10,monotonic_after_ns=11)
 def cmdline(self,phase=1):return 'caa_core_vm='+'a'*32+' caa_core_phase='+str(phase)+' caa_core_realtime=1792659524'
 def test_host_sample_exact_current_source_and_qemu_operand(self):
  import clock as W
  from unittest.mock import patch
  with patch.object(W.time,'time_ns',return_value=1792659524987654321),patch.object(W.time,'monotonic_ns',return_value=100):self.assertEqual(W.host_sample('a'*32,1),self.sample())
  argv=host.qemu('/k','/owned/b','/owned/d','a'*32,1,self.sample()['epoch_seconds']);self.assertEqual(argv[argv.index('-append')+1].split()[-1],'caa_core_realtime=1792659524');self.assertEqual(W.kernel_epoch(argv[argv.index('-append')+1],'a'*32,1),1792659524)
  for value in(True,1792659524.0,-1,0,4102444800,'1792659524'):
   with self.assertRaises(ValueError):host.qemu('/k','/owned/b','/owned/d','a'*32,1,value)
 def test_full_guarded_initialize_and_real_clock_readback_with_inert_clock_syscall_only(self):
  import clock as W
  from unittest.mock import patch
  calls=[];s=dict(nonce='a'*32)
  with patch.object(guest_guard,'guard',return_value=(1,{})),patch.object(W.time,'time_ns',side_effect=[1790293564*10**9,1792659524*10**9]),patch.object(W.time,'monotonic_ns',side_effect=[10,11]),patch.object(W.time,'clock_settime',side_effect=lambda clock,seconds:calls.append((clock,seconds))):value=W.initialize(s,1,self.cmdline())
  self.assertEqual(value,self.record());self.assertEqual(calls,[(W.time.CLOCK_REALTIME,1792659524)]);self.assertEqual(W.validate(value,'a'*32,1,self.sample()),value)
  with patch.object(guest_guard,'guard',side_effect=ValueError('original bootstrap guard')),patch.object(W.time,'clock_settime')as setter:
   with self.assertRaisesRegex(ValueError,'original bootstrap guard'):W.initialize(s,1,self.cmdline())
   setter.assert_not_called()
 def test_entire_guest_main_bootstrap_orders_source_before_clock_before_save(self):
  import guest,clock as W,types
  from unittest.mock import patch
  route=[];s=dict(nonce='a'*32);record=self.record()
  def guard(*args):route.append('original-bootstrap-guard');return 1,{}
  def setter(clock,seconds):route.append('real-clock-syscall-boundary');self.assertEqual((clock,seconds),(W.time.CLOCK_REALTIME,1792659524))
  with patch.object(sys,'argv',['guest.py','bootstrap']),patch.object(C,'read',return_value=C.encoded(s)),patch.object(guest.G,'guard',side_effect=guard),patch.object(guest,'sources',side_effect=lambda selected:route.append('whole-source-closure')),patch.object(Path,'read_text',return_value=self.cmdline()),patch.object(W.time,'time_ns',side_effect=[record['previous_realtime_ns'],record['initialized_realtime_ns']]),patch.object(W.time,'monotonic_ns',side_effect=[10,11]),patch.object(W.time,'clock_settime',side_effect=setter),patch.object(guest,'save',side_effect=lambda name,value:route.append(('retained-clock',name,value))):self.assertEqual(guest.main(),0)
  self.assertEqual(route,['original-bootstrap-guard','whole-source-closure','original-bootstrap-guard','real-clock-syscall-boundary',('retained-clock','phase1-wallclock.json',record)])
 def test_kernel_clock_duplicate_missing_wrong_nonce_and_phase_refuse(self):
  import clock as W
  for raw in(self.cmdline()+' caa_core_realtime=1792659524',self.cmdline().replace(' caa_core_realtime=1792659524',''),self.cmdline().replace('1792659524','+1792659524'),self.cmdline().replace('1792659524','1792659524.0'),self.cmdline().replace('a'*32,'b'*32),self.cmdline(2)):
   with self.assertRaises(ValueError):W.kernel_epoch(raw,'a'*32,1)
 def test_clock_custody_missing_drift_nonfinite_bool_and_wrong_host_refused(self):
  import clock as W
  self.assertEqual(W.validate(self.record(),'a'*32,1,self.sample()),self.record())
  for kind in('missing','nonce','phase','host','realtime','monotonic','bool','extra'):
   value=copy.deepcopy(self.record());sample=self.sample()
   if kind=='missing':value.pop('source')
   elif kind=='nonce':value['nonce']='b'*32
   elif kind=='phase':value['phase']=2
   elif kind=='host':sample['epoch_seconds']+=1
   elif kind=='realtime':value['initialized_realtime_ns']=value['previous_realtime_ns']
   elif kind=='monotonic':value['monotonic_after_ns']+=6*10**9
   elif kind=='bool':value['epoch_seconds']=True
   else:value['faketime']='FORBIDDEN'
   with self.subTest(kind=kind),self.assertRaises(ValueError):W.validate(value,'a'*32,1,sample)
 def test_full_protocol_requires_initialized_wallclock_and_exact_host_sample(self):
  import test_protocol as T
  s,expected,value=T.fixture();self.assertEqual(C.protocol(T.frames(value),s,1,expected),value)
  for kind in('missing','host','clock'):
   changed=copy.deepcopy(value);want=copy.deepcopy(expected)
   if kind=='missing':changed['custody'].pop('wallclock')
   elif kind=='host':want['host_clock']['epoch_seconds']+=1
   else:changed['custody']['wallclock']['initialized_realtime_ns']=1790293564*10**9
   with self.assertRaises(ValueError):C.protocol(T.frames(changed),s,1,want)
 def test_whole_host_two_boot_body_samples_each_launch_and_retains_nonce_clock_join(self):
  import clock as W,test_protocol as T,types
  from unittest.mock import patch
  selected,expected,value=T.fixture();samp=[self.sample(1),self.sample(2)];calls=[];identity={n:dict(identity=[1,2+i,3,size],bytes=size,sha256='e'*64)for i,(n,size)in enumerate((('boot.raw',16*1024**3),('data.raw',24*1024**3)))};previous=[]
  def run(argv,output,env,seconds,cap):
   phase=len(calls)+1;calls.append(argv);v=copy.deepcopy(value);v['phase']=phase;v['custody']['phase']=phase;v['custody']['wallclock']=self.record(phase);v['pid1']['boot_id']=('11111111'if phase==1 else'22222222')+'-1111-1111-1111-111111111111';v['previous']=None if phase==1 else C.pin(C.encoded(previous[0]));v['custody']['previous']=v['previous'];previous.append(v['custody']);raw=T.frames(v);row=dict(argv=argv,exit_code=0,group_absence_verified=True,time_limit=seconds,seconds=.1,output_limit=cap,stdout_bytes=len(raw),stdout_sha256=C.pin(raw)['sha256'],stderr_bytes=0,stderr_sha256=C.pin(b'')['sha256']);return row,raw,b'',None
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);media_root=root/'media';media_root.mkdir()
   for n in identity:(media_root/n).write_bytes(b'owned inert disk lease')
   (media_root/'core-media.json').write_bytes(C.encoded(dict(status='PREPARED_CORE7_REAL_SYSTEMD_MEDIA_NOT_BOOTED',nonce=selected['nonce'],budgets=C.BUDGET,files={n:{k:r[k]for k in('bytes','sha256')}for n,r in identity.items()})))
   with patch.object(host,'disk',side_effect=lambda path,size:identity[Path(path).name]),patch.object(W,'host_sample',side_effect=samp):result=host.two_boots(selected,media_root,'/kernel',root/'boots',types.SimpleNamespace(run_command=run),expected)
   self.assertEqual(len(calls),2);self.assertEqual([r['host_clock']for r in result['boots']],samp)
   self.assertEqual([C.decode(C.read(root/'boots'/('launch-'+str(phase)+'.json')))for phase in(1,2)],samp)
   for phase,row in enumerate(result['boots'],1):self.assertEqual(row['qemu']['argv'],host.qemu('/kernel',media_root/'boot.raw',media_root/'data.raw',selected['nonce'],phase,samp[phase-1]['epoch_seconds']))
 def test_no_monotonic_budget_or_gpg_waiver_and_whole_bootstrap_held(self):
  import clock as W
  self.assertEqual(C.BUDGET,dict(owner=14400,producer=2300,assembly=1070,media=1900,vm_shared=7200,boot=3600,transaction=90,cleanup=60));source=C.read(C.HERE/'clock.py').decode();self.assertNotIn('--faked-system-time',source);self.assertNotIn('gpg',source);self.assertNotIn('ignore-time-conflict',source);self.assertIn("sources(s);value=W.initialize",C.read(C.HERE/'guest.py').decode());self.assertLess(C.read(C.HERE/'guest.py').decode().index("report['wallclock']=W.current"),C.read(C.HERE/'guest.py').decode().index('keys,packages=core.T.public_keys'))
 def test_entire_worker_refuses_stale_walltime_before_any_public_key_actor(self):
  import guest,clock as W,types
  from unittest.mock import patch,Mock
  selected=dict(nonce='a'*32);receipt=self.record();public=Mock(side_effect=AssertionError('no GPG before current clock'));core=types.SimpleNamespace(C=types.SimpleNamespace(configuration=lambda *args:({'token':'a'*32},)),T=types.SimpleNamespace(public_keys=public),api={});saved=[]
  def read(path,*args):return C.encoded({}if str(path)=='/inputs/lifecycle-input.json'else receipt)
  with patch.object(guest,'sources',return_value=core),patch.object(C,'read',side_effect=read),patch.object(Path,'read_text',return_value=self.cmdline()),patch.object(W.time,'time_ns',return_value=receipt['previous_realtime_ns']),patch.object(guest,'save',side_effect=lambda name,value:saved.append((name,value))):
   with self.assertRaisesRegex(ValueError,'actual worker wallclock'):guest.worker(selected,1,{})
  public.assert_not_called();self.assertEqual(saved[0][0],'phase1-custody.json');self.assertEqual(saved[0][1]['status'],'FAIL');self.assertEqual(saved[0][1]['commands'],[])
  with patch.object(W.time,'time_ns',return_value=receipt['initialized_realtime_ns']):self.assertEqual(W.current(receipt,selected,1,self.cmdline()),receipt)
  with patch.object(W.time,'time_ns',return_value=receipt['initialized_realtime_ns']+(C.BUDGET['boot']+1)*10**9):
   with self.assertRaises(ValueError):W.current(receipt,selected,1,self.cmdline())
if __name__=='__main__':unittest.main()
