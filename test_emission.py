# SPDX-License-Identifier: MIT
"""Real isolated CLI/emission and exact emitted checksum stanza; no actors."""
import os,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,adapter,entry,prepare
class Emission(unittest.TestCase):
 def test_exact_source_and_isolated_entries(self):
  for argv in([sys.executable,'-I','-B',str(C.HERE/'entry.py'),'--help'],[sys.executable,'-I','-B',str(C.HERE/'entry.py'),'source'],[sys.executable,'-I','-B',str(C.HERE/'prepare.py'),'--source-only']):
   p=subprocess.run(argv,cwd='/',capture_output=True,timeout=20);self.assertEqual((p.returncode,p.stderr),(0,b''))
  with tempfile.TemporaryDirectory()as t:
   out=Path(t)/'exact';result=prepare.emit(C.HERE,out);self.assertIsNone(result['actual']);self.assertEqual(adapter.source_rows(C.HERE),adapter.source_rows(out))
 def test_drift_and_alias_refuse_before_new_output(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);source=root/'source';prepare.emit(C.HERE,source);(source/'guest.py').write_bytes(C.read(source/'guest.py')+b'\n# drift\n')
   with self.assertRaisesRegex(ValueError,'closed whole'):prepare.emit(source,root/'not-created')
   self.assertFalse((root/'not-created').exists())
   with self.assertRaisesRegex(ValueError,'fresh disjoint'):prepare.emit(C.HERE,C.HERE/'forbidden-output')
 def test_real_emitted_checksum_and_shell_source(self):
  raw=C.read(C.HERE/entry.WORKFLOWS[0]).decode();line=next(x.strip()for x in raw.splitlines()if '@ENTRY_SHA@'not in x and '"$CASE/entry.py"'in x and x.strip().startswith('printf'))
  self.assertNotIn('\\\\n',line);p=subprocess.run(['/usr/bin/bash','-eu','-c',line],env=dict(PATH='/usr/bin:/bin',CASE=str(C.HERE)),capture_output=True,timeout=20);self.assertEqual((p.returncode,p.stderr),(0,b''));self.assertEqual(p.stdout.count(b': OK\n'),2)
  for n in('entry.py','prepare.py','media.py','guest.py'):
   p=subprocess.run([sys.executable,'-I','-B',str(C.HERE/n),'--help'],cwd='/',capture_output=True,timeout=20);self.assertEqual((p.returncode,p.stderr),(0,b''))
 def test_closed_members_missing_extra_refused(self):
  with tempfile.TemporaryDirectory()as t:
   out=Path(t)/'source';prepare.emit(C.HERE,out);(out/'foreign').write_bytes(b'foreign')
   with self.assertRaisesRegex(ValueError,'closed whole'):entry.source(out)
   (out/'foreign').unlink();(out/'hook.py').unlink()
   with self.assertRaisesRegex(ValueError,'closed whole'):entry.source(out)
if __name__=='__main__':unittest.main()
