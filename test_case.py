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
  self.assertEqual([i for i,(x,y)in enumerate(zip(a,b))if x!=y],[a.index('-append')+1]);self.assertIn('caa_core_phase=1',a[a.index('-append')+1]);self.assertIn('none',a);self.assertNotIn('-virtfs',a);self.assertIn('virtio-blk-pci,drive=boot,serial=core7-'+'b'*32,a)
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
if __name__=='__main__':unittest.main()
