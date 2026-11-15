#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable DATA controls only: no VM, Docker, package or namespace execution."""
import ast,contextlib,ctypes,gzip,hashlib,importlib.util,json,os,socket,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent


def load(name):
 spec=importlib.util.spec_from_file_location('c01_test_'+name,HERE/(name+'.py'))
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


I=load('inputs');B=load('boot')
NONCE='a'*32


def fields():
 result={'STATUS':'PASS','BASELINE_PACKAGES':'111','INSTALLED_PACKAGES':'113','FINAL_PACKAGES':'111','ARCH':'aarch64','PAGESIZE':'16384','WORKLOAD_UID':'1000','PROBES':'2','ENCODES':'42','CROSS_DECODES':'84','INDEPENDENT_DECODES':'42','STRICT_REJECTIONS':'6','EXCLUSIVE_PAYLOAD_ABSENT':'yes','PRIVATE_TEST_TRUST_REMOVED':'yes','ORDINARY_HOOKS_SCRIPTLETS':'unsuppressed','PERFORMANCE':'NOT_MEASURED','NATIVE16K':'NOT_RUN','M2':'NOT_RUN','USER_BEFORE':'b'*64,'USER_FINAL':'b'*64}
 for key in ('meta','hash','db','xattr'):result['BASE_'+key]=result['FINAL_'+key]='c'*64
 return result


def frame(values):
 return ('ARM16K_PROJECT_BEGIN '+NONCE+'\n'+''.join(k+'='+v+'\n' for k,v in values.items())+'ARM16K_PROJECT_END '+NONCE).encode()


class Controls(unittest.TestCase):
 def test_complete_frame(self):self.assertEqual(B.parse_lifecycle(frame(fields()),NONCE),fields())
 def test_every_exact_invariant_refuses(self):
  for key in fields():
   if key.startswith(('BASE_','FINAL_')) or key.startswith('USER_'):continue
   with self.subTest(key=key):
    values=fields();values[key]='wrong'
    with self.assertRaises(ValueError):B.parse_lifecycle(frame(values),NONCE)
 def test_each_preservation_category_refuses(self):
  for key in ('FINAL_meta','FINAL_hash','FINAL_db','FINAL_xattr','USER_FINAL'):
   with self.subTest(key=key):
    values=fields();values[key]='d'*64
    with self.assertRaises(ValueError):B.parse_lifecycle(frame(values),NONCE)
 def test_duplicate_frame_refuses(self):
  with self.assertRaises(ValueError):B.parse_lifecycle(frame(fields())*2,NONCE)
 def test_stale_nonce_refuses(self):
  with self.assertRaises(ValueError):B.parse_lifecycle(frame(fields()),'e'*32)
 def test_extra_field_refuses(self):
  values=fields();values['UNREVIEWED']='yes'
  with self.assertRaises(ValueError):B.parse_lifecycle(frame(values),NONCE)
 def test_hold_is_not_pass(self):self.assertEqual(B.parse_lifecycle(frame({'STATUS':'HOLD','FAILED_PHASE':'trust'}),NONCE)['STATUS'],'HOLD')
 def test_missing_frame_refuses(self):
  with self.assertRaises(ValueError):B.parse_lifecycle(b'',NONCE)
 def test_unsigned_or_incomplete_material_namespace_refuses(self):
  with tempfile.TemporaryDirectory() as tmp:
   with self.assertRaisesRegex(ValueError,'namespace'):I.closure(Path(tmp),{'base_packages':[]})
 def test_material_symlink_refuses(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);(p/'a').write_bytes(b'x');(p/'b').symlink_to('a')
   with self.assertRaises(ValueError):I.pin(p/'b')
 def test_material_tamper_refuses(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'material';p.write_bytes(b'x');before=I.pin(p);p.write_bytes(b'y')
   with self.assertRaises(ValueError):I.checked(p,before)
 def test_unresolved_trust_refuses(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'report.json';p.write_text('{"status":"HOLD"}')
   with self.assertRaisesRegex(ValueError,'HOLD'):I.trust_prerequisite(p,I.pin(p)['sha256'])
 def test_exact_root_trust_success_required(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'report.json';r={'status':'PASS_EMULATED_ARM16K_SIGNED_PROJECT_INSTALL_REMOVE_ONLY','project':{'STATUS':'PASS','BASELINE_PACKAGES':'111','FINAL_PACKAGES':'111','PRIVATE_TEST_TRUST_REMOVED':'yes','ORDINARY_HOOKS_SCRIPTLETS':'unsuppressed'}};p.write_text(json.dumps(r))
   self.assertEqual(I.trust_prerequisite(p,I.pin(p)['sha256']),I.pin(p))
   r['project']['ORDINARY_HOOKS_SCRIPTLETS']='suppressed';p.write_text(json.dumps(r))
   with self.assertRaises(ValueError):I.trust_prerequisite(p,I.pin(p)['sha256'])
 def test_wrong_trust_receipt_hash_refuses(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'report.json';p.write_text('{}')
   with self.assertRaises(ValueError):I.trust_prerequisite(p,'0'*64)
 def test_fixture_corpus_boundaries(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);pins=I.fixtures(p)
   self.assertEqual([pins['corpus-'+str(i)]['bytes'] for i in range(7)],[0,1,114688,262144,16383,16384,16385])
   self.assertEqual(len(pins),12);self.assertIn(b'\0',(p/'corpus-3').read_bytes())
 def test_invalid_fixtures_reject_independently(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);I.fixtures(p)
   for i in range(3):
    with self.subTest(i=i),self.assertRaises((OSError,EOFError)):gzip.decompress((p/('invalid-'+str(i))).read_bytes())
 def test_fixture_no_replace(self):
  with tempfile.TemporaryDirectory() as tmp:
   I.fixtures(Path(tmp))
   with self.assertRaises(FileExistsError):I.fixtures(Path(tmp))
 def test_wrong_elf_architecture_refuses(self):
  raw=bytearray(64);raw[:6]=b'\x7fELF\x02\x01'
  with self.assertRaises(ValueError):I.elf_geometry(raw)
 def test_existing_custody_and_trust_guards_held(self):
  prep=(HERE/'prepare.py').read_text();boot=(HERE/'boot.py').read_text();guest=(HERE/'guest-root.sh').read_text()
  self.assertLess(prep.index('I.trust_prerequisite('),prep.index('out.mkdir('))
  self.assertLess(boot.index('I.trust_prerequisite('),boot.index("marker.open('x')"))
  self.assertIn('reference.main()',boot);self.assertNotIn('qemu-system',boot)
  self.assertIn('Required TrustedOnly',prep);self.assertIn('pacman --config',guest)
  for forbidden in ('--nodeps','--assume-installed','--noscriptlet','--ignore-time-conflict','--faked-system-time','SigLevel = Never'):self.assertNotIn(forbidden,prep+guest)
  self.assertNotIn('pacman -U',boot)
 def test_source_syntax(self):
  for p in HERE.glob('*.py'):ast.parse(p.read_text(),filename=str(p))


if __name__=='__main__':
 # Any accidental actor call fails these controls; pure DATA/file checks remain.
 with contextlib.ExitStack() as stack:
  for module,names in ((subprocess,('Popen',)),(socket,('socket','create_connection')),(ctypes,('CDLL',)),(os,('system','fork','forkpty','posix_spawn','posix_spawnp','execv','execve','execvp','execvpe'))):
   for name in names:
    if hasattr(module,name):stack.enter_context(patch.object(module,name,side_effect=AssertionError('actor fenced: '+name)))
  unittest.main()
