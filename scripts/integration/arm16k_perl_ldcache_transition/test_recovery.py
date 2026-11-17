#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure request/chain/two-path decoder controls; no tool, actor or disk invocation."""
import copy,importlib.util,json,struct,unittest
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('ldcache_passive_recovery',HERE/'recovery.py');R=importlib.util.module_from_spec(s);s.loader.exec_module(R)
def frame(kind='regular',inode=20,mode='0644',size=23,links=1):
 stamp=datetime.fromtimestamp(0,timezone.utc).strftime('%a %b %e %H:%M:%S %Y')
 return (f'debugfs 1.47.4 (29-Mar-2025)\nInode: {inode}   Type: {kind}    Mode:  {mode}   Flags: 0x0\nUser: 0   Group: 0    Size: {size}\nLinks: {links}   Blockcount: 8\n ctime: 0x00000000:00000000 -- {stamp}\n atime: 0x00000000:00000000 -- {stamp}\n mtime: 0x00000000:00000000 -- {stamp}\n').encode()
class Controls(unittest.TestCase):
 def setUp(self):
  self.request=json.loads((HERE/'request.TEMPLATE.json').read_bytes())
  self.body=b'glibc-ld.so.cache1.1TEST'
  self.cache=frame(size=len(self.body));self.etc=frame('directory',16,'0755',4096,38)
  self.frames={'cache-before':self.cache,'cache-after':self.cache,'etc-before':self.etc,'etc-after':self.etc}
  self.baseline={'nodes':{'etc':dict(inode=16,type='directory',mode=0o755,uid=0,gid=0,links=38,size=4096,mtime=0,mtime_ns=0),'etc/ld.so.cache':dict(inode=19,type='file',mode=0o644,uid=0,gid=0,links=1,size=len(self.body),mtime=0,mtime_ns=0,sha256=R.pin(self.body)['sha256'])}}
  self.chain=[{'filename':'/inputs/overlay.qcow2','format':'qcow2','virtual-size':R.RAW_BYTES,'backing-filename':'/prepared/guest.raw','full-backing-filename':'/prepared/guest.raw','backing-filename-format':'raw','format-specific':{'data':{'corrupt':False}}},{'filename':'/prepared/guest.raw','format':'raw','virtual-size':R.RAW_BYTES}]
 def test_unissued_default_refuses_without_actor(self):
  with patch('subprocess.Popen',side_effect=AssertionError('process forbidden')),patch('socket.socket',side_effect=AssertionError('socket forbidden')):
   R.declared(self.request)
   with self.assertRaises(ValueError):R.plan(self.request)
 def test_literal_root_plan_has_only_two_public_paths_no_write_or_shell(self):
  q=copy.deepcopy(self.request);q['accepted']=True;q['overlay']['pin']={'bytes':125*1024**2,'sha256':'a'*64};q['output']='/MODEL/fresh-observation'
  rows=R.plan(q);self.assertEqual(len(rows),7)
  cmds=[r['argv'][2]for r in rows if r['argv'][0]=='/usr/bin/debugfs'];self.assertEqual(set(cmds),{'stat /etc','stat /etc/ld.so.cache','dump /etc/ld.so.cache /output/cache.bin'})
  self.assertTrue(all('-w'not in r['argv']and'sh'not in r['argv']for r in rows))
 def test_missing_overlay_pin_and_resource_drift_refuse(self):
  q=copy.deepcopy(self.request);q['accepted']=True;q['output']='/MODEL/new'
  with self.assertRaises(ValueError):R.plan(q)
  q['resources']['whole_seconds']+=1
  with self.assertRaises(ValueError):R.declared(q)
 def test_exact_chain_only(self):self.assertEqual(R.chain(json.dumps(self.chain).encode())['status'],'EXACT_TWO_NODE_CHAIN_METADATA_ONLY')
 def test_extra_backing_rebase_encryption_dirty_and_size_refuse(self):
  for key,value in [('backing-filename','/different'),('dirty-flag',True),('encrypted',True),('virtual-size',R.RAW_BYTES+1),('data-file','/secret')]:
   q=copy.deepcopy(self.chain);q[0][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):R.chain(json.dumps(q).encode())
  q=copy.deepcopy(self.chain);q.append(q[-1])
  with self.assertRaises(ValueError):R.chain(json.dumps(q).encode())
 def test_public_decoder_hashes_bytes_and_reports_only_changed_fields(self):
  row=R.decode_outputs(self.frames,self.body,self.baseline)
  self.assertEqual(row['baseline_changed_fields']['etc/ld.so.cache'],['inode']);self.assertEqual(row['baseline_changed_fields']['etc'],[])
  self.assertEqual(row['cache'],R.pin(self.body));self.assertIsNone(row['lifecycle_acceptance']);self.assertIn('NOT_OBSERVED',row['xattrs'])
 def test_metadata_changed_across_dump_refuses(self):
  q=dict(self.frames,**{'cache-after':frame(inode=99,size=len(self.body))})
  with self.assertRaises(ValueError):R.decode_outputs(q,self.body,self.baseline)
 def test_size_mode_owner_link_and_alias_refuse(self):
  for body in (frame(size=999),frame(mode='0600',size=len(self.body)),frame(kind='symlink',size=len(self.body)),frame(links=2,size=len(self.body))):
   q=dict(self.frames,**{'cache-before':body,'cache-after':body})
   with self.assertRaises(ValueError):R.decode_outputs(q,self.body,self.baseline)
 def test_private_or_other_path_and_unknown_stat_fields_refuse(self):
  for name in('root','.ssh','etc/shadow','etc/ld.so.preload'):
   with self.assertRaises(ValueError):R.S.request(name)
  with self.assertRaises(ValueError):R.S.parse_stat(self.cache+b'PRIVATE CHILD NAME\n','etc/ld.so.cache')
 def test_missing_duplicate_or_incomplete_frames_refuse(self):
  with self.assertRaises(ValueError):R.decode_outputs({'cache-before':self.cache},self.body,self.baseline)
  with self.assertRaises(ValueError):R.S.parse_stat(self.cache+b'Links: 1   Blockcount: 8\n','etc/ld.so.cache')
 def test_dump_cap_and_no_semantic_or_root_acceptance(self):
  with self.assertRaises(ValueError):R.decode_outputs(self.frames,b'x'*(1048576+1),self.baseline)
  row=R.decode_outputs(self.frames,self.body,self.baseline)
  self.assertEqual(row['cache_header'],'GLIBC_NEW_1_1');self.assertIn('PENDING',row['provider_correspondence']);self.assertIsNone(row['Root_acceptance'])
if __name__=='__main__':unittest.main()
