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
  a=host.qemu('/k/Image','/owned/boot.raw','/owned/data.raw','b'*32,1);b=host.qemu('/k/Image','/owned/boot.raw','/owned/data.raw','b'*32,2)
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
  nonce='b'*32;argv=host.qemu('/k/Image','/owned/boot.raw','/owned/data.raw',nonce,1)
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

if __name__=='__main__':unittest.main()
