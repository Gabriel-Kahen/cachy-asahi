# SPDX-License-Identifier: MIT
"""Inert input/staging/refusal controls; no native graphics actors or ALPM needed."""
import hashlib,importlib.util,io,json,os,struct,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('native_graphics_run',HERE/'run.py');R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
STYLE=b'background-color=#20242c\ntext-color=#eceff4\nborder-color=#88c0d0\nborder-size=2\ndefault-timeout=5000\n'

class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
 def file(self,name,data,mode=0o644):
  q=self.root/name;q.write_bytes(data);q.chmod(mode);return {'path':str(q),'sha256':R.sha(data)}
 def valid(self):
  binary=bytearray(64);binary[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',binary,18,62)
  tools={n:self.file(n,bytes(binary),0o755) for n in R.TOOLS}
  payload=b'inert payload';name='usr/share/cachy-asahi/fish-done/done.fish';buf=io.BytesIO()
  with tarfile.open(fileobj=buf,mode='w:xz') as stream:
   member=tarfile.TarInfo(name);member.mode=0o644;member.size=len(payload);stream.addfile(member,io.BytesIO(payload))
  raw=buf.getvalue();lock={'bytes':len(raw),'sha256':R.sha(raw),'payload':{name:{'size':len(payload),'mode':0o644,'sha256':R.sha(payload)}}}
  lockraw=R.encoded(lock);self.file('done-lock.json',lockraw)
  value={'schema_version':1,'tools':tools,'libraries':[],'done_archive':self.file('done.tar.xz',raw),'mako_config':self.file('mako.conf',STYLE),'render_node':'/dev/dri/renderD128','source_metadata':{'scope':'inert test data, never execution evidence'}}
  self.file('inputs.json',R.encoded(value));return value,{'done-lock.json':R.sha(lockraw)}
 def execute_preflight(self,value,pins):
  q=self.root/'inputs.json';q.write_bytes(R.encoded(value))
  with patch.object(R,'HERE',self.root),patch.object(R,'SOURCE_PINS',pins),patch.object(R,'SYSTEM',{k:value['tools'][k]['path'] for k in R.SYSTEM}),patch.object(R,'system_aliases'),patch.object(R,'host') as host,patch.object(R.subprocess,'Popen',side_effect=AssertionError('actor before prerequisites')):
   plan=R.preflight(str(q),R.sha(q.read_bytes()),str(self.root/'fresh-work'));host.assert_called_once_with('/dev/dri/renderD128');return plan
 def test_complete_inert_preflight_and_stage_without_actor(self):
  value,pins=self.valid();plan=self.execute_preflight(value,pins);self.assertFalse(plan['work'].exists());R.stage(plan)
  self.assertEqual((plan['work']/'mako.conf').read_bytes(),STYLE);self.assertEqual((plan['work']/'done/usr/share/cachy-asahi/fish-done/done.fish').read_bytes(),b'inert payload');self.assertEqual((plan['work']/'runtime').stat().st_mode&0o777,0o700)
 def test_wrong_binary_hash_refuses_before_actor_and_work(self):
  value,pins=self.valid();value['tools']['mako']['sha256']='0'*64
  with self.assertRaisesRegex(ValueError,'hash/drift'):self.execute_preflight(value,pins)
  self.assertFalse((self.root/'fresh-work').exists())
 def test_existing_work_refused(self):
  value,pins=self.valid();(self.root/'fresh-work').mkdir()
  with self.assertRaisesRegex(ValueError,'fresh work'):self.execute_preflight(value,pins)
 def test_symlink_file_and_ancestor_refused(self):
  row=self.file('file',b'plain');link=self.root/'link';link.symlink_to(self.root/'file')
  with self.assertRaisesRegex(ValueError,'symlink'):R.ordinary(str(link),row['sha256'])
  parent=self.root/'parent';parent.symlink_to(self.root,target_is_directory=True)
  with self.assertRaisesRegex(ValueError,'symlink'):R.path(str(parent/'file'))
 def test_hardlink_and_input_alias_refused(self):
  row=self.file('file',b'plain');os.link(self.root/'file',self.root/'alias')
  with self.assertRaisesRegex(ValueError,'single-link'):R.ordinary(row['path'],row['sha256'])
  value,pins=self.valid();value['tools']['makoctl']=value['tools']['mako']
  with self.assertRaisesRegex(ValueError,'aliased'):self.execute_preflight(value,pins)
 def test_only_complete_explicit_three_link_multicall_group_allowed(self):
  row=self.file('fish-fixture',b'inert');a=self.root/'fish_indent';b=self.root/'fish_key_reader';os.link(row['path'],a);os.link(row['path'],b)
  self.file('other',b'other');aliases=(row['path'],str(a),str(b));R.ordinary(row['path'],row['sha256'],known_links=aliases)
  with self.assertRaisesRegex(ValueError,'alias group'):R.ordinary(row['path'],row['sha256'],known_links=(row['path'],str(a),str(self.root/'other')))
 def test_duplicate_and_non_x86_header_rejected(self):
  with self.assertRaisesRegex(ValueError,'duplicate'):R.decode(b'{"a":1,"a":2}')
  row=self.file('wrong-architecture',b'\x7fELF\x02\x01'+b'\0'*58,0o755)
  with self.assertRaisesRegex(ValueError,'native x86_64'):R.ordinary(row['path'],row['sha256'],executable=True)
 def test_original_runtime_helper_pins_and_unchanged_bounds(self):
  for name,expected in R.SOURCE_PINS.items():self.assertEqual(R.sha((HERE/name).read_bytes()),expected)
  source=(HERE/'controller.py').read_text();self.assertNotIn('artifacts/development/',source);self.assertIn('15,\'original Done delivery15s\'',source);self.assertIn("2,'original natural-expiry readiness2s'",source);self.assertIn('time.monotonic()+3.5',source);self.assertIn('<=2000000',source)
  self.assertEqual(R.sha(STYLE),R.STYLE)
 def test_archive_rejects_traversal_and_unknown_payload(self):
  for name in ['../escape','usr/unexpected']:
   buf=io.BytesIO()
   with tarfile.open(fileobj=buf,mode='w:xz') as stream:
    m=tarfile.TarInfo(name);m.size=1;m.mode=0o644;stream.addfile(m,io.BytesIO(b'x'))
   with self.assertRaises(ValueError):R.archive(buf.getvalue(),{'payload':{}})

if __name__=='__main__':unittest.main()
