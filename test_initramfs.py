# SPDX-License-Identifier: MIT
"""Finite cache/output routing and failure shutdown controls; no native actors."""
import ast,copy,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,initramfs as J,boot,effects,media
class Initramfs(unittest.TestCase):
 def test_only_exact_new_indexes_all_original_nodes_and_idempotence(self):
  before={J.PREFIX+f'kernel/{i}.ko':dict(type='file',mode=0o644,uid=0,gid=0,**C.pin(str(i).encode()))for i in range(3655)}
  after={**before,**{n:dict(type='file',mode=0o644,uid=0,gid=0,**C.pin(n.encode()))for n in J.INDEXES}}
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)/'stage/boot';root.mkdir(parents=True);calls=[]
   with patch.object(J,'nodes',side_effect=[before,after,after]):result=J.initialize(root,lambda argv,seconds:calls.append((argv,seconds)))
   self.assertEqual(set(result),set(J.INDEXES));self.assertEqual(calls,[(['/usr/bin/depmod','-b',str(root),'-a',J.KERNEL],60)]*2);self.assertTrue(all(row['before']is None for row in result.values()))
   for bad in({**before,J.INDEXES[0]:after[J.INDEXES[0]]},{n:v for n,v in before.items()if n!=next(iter(before))}):
    with patch.object(J,'nodes',return_value=bad),self.assertRaises(ValueError):J.initialize(root,lambda *_:self.fail('refusal before command'))
   for bad in({**after,'usr/lib/modules/foreign':{}},{**after,next(iter(before)):dict(before[next(iter(before))],sha256='0'*64)}):
    with patch.object(J,'nodes',side_effect=[before,bad]),self.assertRaisesRegex(ValueError,'original module nodes'):J.initialize(root,lambda *_:None)
   changed=copy.deepcopy(after);changed[J.INDEXES[0]]['sha256']='0'*64
   with patch.object(J,'nodes',side_effect=[before,after,changed]),self.assertRaisesRegex(ValueError,'idempotence'):J.initialize(root,lambda *_:None)
 def test_index_overlay_mode_owner_and_old_node_refuse(self):
  value={n:dict(before=None,after=dict(type='file',mode=0o644,uid=0,gid=0,**C.pin(b'index')))for n in J.INDEXES};self.assertEqual(J.validate_overlay(value),value)
  for field,bad in (('mode',0o666),('uid',1000),('gid',1000),('bytes',True),('sha256','0'*63)):
   row=copy.deepcopy(value);row[J.INDEXES[0]]['after'][field]=bad
   with self.assertRaises(ValueError):J.validate_overlay(row)
  row=copy.deepcopy(value);row[J.INDEXES[0]]['before']={}
  with self.assertRaises(ValueError):J.validate_overlay(row)
 def test_full_original_preset_hooks_and_kernel_assets_stay_active(self):
  self.assertEqual(J.GENERATE,('/usr/bin/mkinitcpio','-p','linux-aarch64'));self.assertEqual(effects.GENERATED[J.ARTIFACT],J.GENERATE);self.assertEqual(len(effects.GENERATED),3)
  text=C.read(C.HERE/'boot.py').decode();self.assertNotIn('ALL_kver',text);self.assertNotIn('HOOKS=',text);self.assertIn('result.update(J.initialize(root,command))',text)
  self.assertIn('BOOT.apply(boot,s[\'nonce\'],command)',C.read(C.HERE/'media.py').decode());self.assertIn('*J.INDEXES',text)
  tree=ast.parse(C.read(C.HERE/'guest.py'));fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='transact');raw=ast.get_source_segment(C.read(C.HERE/'guest.py').decode(),fn);self.assertIn("'/usr/bin/pacman','--debug'",raw);self.assertIn("'NO_NOHOOKS_NO_NOSCRIPTLET_NO_PRELOAD'",raw);self.assertEqual(C.BUDGET['transaction'],90)
 def test_failure_poweroff_only_after_original_receipt_writer_exits(self):
  raw=C.read(C.HERE/'units/caa-core-worker.service').decode();self.assertEqual(raw.count('FailureAction=poweroff'),1);self.assertLess(raw.index('FailureAction=poweroff'),raw.index('[Service]'));self.assertIn('Type=oneshot',raw);self.assertIn('TimeoutStartSec=3300',raw);self.assertIn('TimeoutStopSec=60',raw)
  text=C.read(C.HERE/'guest.py').decode();self.assertIn("save('phase%d-custody.json'%phase,report)",text);self.assertNotIn('poweroff',ast.get_source_segment(text,next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='worker')))
  import test_protocol as T
  s,e,value=T.fixture();value['custody']['status']='FAIL'
  with self.assertRaises(ValueError):C.protocol(T.frames(value),s,1,e)

class Compression(unittest.TestCase):
 def test_exact_vm_gzip_flags_actual_shell_and_original_budgets(self):
  import subprocess
  value=J.compression_profile();self.assertEqual(value['options'],['-1','-n']);self.assertEqual(C.pin(J.COMPRESSION_DATA),value['data'])
  p=subprocess.run(['/usr/bin/bash','--noprofile','--norc','-eu','-c','source /dev/stdin; [[ "$COMPRESSION" == gzip && ${#COMPRESSION_OPTIONS[@]} == 2 && ${COMPRESSION_OPTIONS[0]} == -1 && ${COMPRESSION_OPTIONS[1]} == -n ]]'],input=J.COMPRESSION_DATA,capture_output=True,timeout=10);self.assertEqual((p.returncode,p.stdout,p.stderr),(0,b'',b''))
  self.assertEqual(J.GENERATE,('/usr/bin/mkinitcpio','-p','linux-aarch64'));self.assertEqual(C.BUDGET,dict(owner=14400,producer=2300,assembly=1070,media=1900,vm_shared=7200,boot=3600,transaction=90,cleanup=60))
  self.assertNotIn(b'HOOKS=',J.COMPRESSION_DATA);self.assertNotIn(b'MODULES=',J.COMPRESSION_DATA);self.assertNotIn(b'cat',J.COMPRESSION_DATA)
 def test_actual_owned_stage_no_main_config_codec_or_foreign_dropin_waiver(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)/'stage/boot';root.mkdir(parents=True);folder=root/'etc/mkinitcpio.conf.d';folder.mkdir(parents=True)
   profile=copy.deepcopy(J.compression_profile());values={n:('original '+n).encode()for n in profile['original_files']};profile['original_files']={n:C.pin(raw)for n,raw in values.items()}
   for n,raw in values.items():p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
   with patch.object(J,'compression_profile',return_value=profile):
    self.assertEqual(J.compression_inputs(root),dict(mode=0o644,data=J.COMPRESSION_DATA));self.assertFalse((root/J.COMPRESSION_PATH).exists())
    p=root/'etc/mkinitcpio.conf';p.write_bytes(values['etc/mkinitcpio.conf']+b'drift')
    with self.assertRaisesRegex(ValueError,'whole original'):J.compression_inputs(root)
    p.write_bytes(values['etc/mkinitcpio.conf']);(folder/'foreign.conf').write_bytes(b'COMPRESSION=cat\n')
    with self.assertRaisesRegex(ValueError,'no override'):J.compression_inputs(root)
    (folder/'foreign.conf').unlink();p=root/'usr/bin/gzip';p.unlink();p.symlink_to(root/'etc/mkinitcpio.conf')
    with self.assertRaises((ValueError,OSError)):J.compression_inputs(root)
    with self.assertRaisesRegex(ValueError,'owned disposable'):J.compression_inputs(Path('/'))
 def test_exact_graph_overlay_content_and_unknown_nodes_still_refuse(self):
  row=dict(before=None,after=dict(type='file',mode=0o644,uid=0,gid=0,**C.pin(J.COMPRESSION_DATA)));overlay={J.COMPRESSION_PATH:row};self.assertEqual(J.validate_compression_overlay(overlay),row)
  for field,value in [('mode',0o666),('uid',1000),('gid',1000),('bytes',True),('sha256','0'*64)]:
   bad=copy.deepcopy(overlay);bad[J.COMPRESSION_PATH]['after'][field]=value
   with self.assertRaises(ValueError):J.validate_compression_overlay(bad)
  bad=copy.deepcopy(overlay);bad[J.COMPRESSION_PATH]['before']={}
  with self.assertRaises(ValueError):J.validate_compression_overlay(bad)
  text=C.read(C.HERE/'effects.py').decode();self.assertIn("proof['first']==proof['second']==after.get(name)",text);self.assertIn("core.C.changes(before,after,packages,versions,allowed)",text)
  text=C.read(C.HERE/'boot.py').decode();self.assertIn('J.validate_compression_overlay(overlay)',text);self.assertIn('*J.INDEXES,J.COMPRESSION_PATH',text)

if __name__=='__main__':unittest.main(verbosity=2)
