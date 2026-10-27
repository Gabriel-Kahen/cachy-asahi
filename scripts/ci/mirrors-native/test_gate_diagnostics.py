# SPDX-License-Identifier: MIT
"""Focused raw-output durability/caps tests; no GPG, pacman or native actors."""
import json,os,stat,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import gate_diagnostics as D


class Diagnostics(unittest.TestCase):
 def test_failed_command_bytes_survive_caller_assertion_and_hash_index(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp)/'public';record=D.Diagnostics(root)
   try:
    row=record.capture(['/usr/bin/pacman','--config','/tmp/public.conf'],'reject-missing',1,b'public stdout\n',b'actual diagnostic\n',10,11)
    raise ValueError('semantic assertion after captured output')
   except ValueError:pass
   self.assertTrue(row['complete']);self.assertEqual((root/row['stderr']['file']).read_bytes(),b'actual diagnostic\n')
   result=record.checkpoint('FAILED',dict(status='FAIL',diagnostics={'index':'must not self-reference'}))
   self.assertEqual(result,D.pin((root/'index.json').read_bytes()))
   index=json.loads((root/'index.json').read_bytes());self.assertEqual(index['commands'][0],row);self.assertNotIn('diagnostics',index['gate'])
   self.assertEqual(set(index['files']),{'000.stdout','000.stderr'})
   for name,pin in index['files'].items():self.assertEqual(pin,D.pin((root/name).read_bytes()))
   self.assertEqual(stat.S_IMODE(root.stat().st_mode),0o700)
   self.assertEqual(root.stat().st_uid,Path(temp).stat().st_uid)
   self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in root.iterdir()))
 def test_stream_cap_explicit_truncation_is_recorded_before_rejection(self):
  with tempfile.TemporaryDirectory() as temp:
   record=D.Diagnostics(Path(temp)/'public');body=b'x'*(D.CAP+7)
   row=record.capture(['gpg'],'verify',0,body,b'',1,2)
   self.assertFalse(row['complete']);self.assertFalse(row['stdout']['complete']);self.assertEqual(row['stdout']['observed_bytes'],len(body));self.assertEqual(row['stdout']['bytes'],D.CAP)
   self.assertEqual(D.pin((record.root/'000.stdout').read_bytes()),D.pin(body[:D.CAP]))
   self.assertEqual(json.loads((record.root/'index.json').read_bytes())['commands'][0],row)
 def test_aggregate_cap_keeps_bounded_prefixes_and_complete_flags(self):
  with tempfile.TemporaryDirectory() as temp,patch.object(D,'CAP',4),patch.object(D,'TOTAL',6):
   record=D.Diagnostics(Path(temp)/'public');row=record.capture(['gpg'],'verify',0,b'abcd',b'efgh',1,2)
   self.assertEqual(record.bytes,6);self.assertEqual((record.root/'000.stderr').read_bytes(),b'ef');self.assertFalse(row['complete'])
   next_row=record.capture(['gpg'],'verify-again',2,b'nonempty',b'',2,3)
   self.assertEqual(next_row['stdout']['bytes'],0);self.assertEqual(next_row['stdout']['observed_bytes'],8);self.assertFalse(next_row['complete']);self.assertEqual(record.bytes,6)
 def test_existing_directory_and_symlink_ancestry_are_preserved(self):
  with tempfile.TemporaryDirectory() as temp:
   parent=Path(temp);existing=parent/'existing';existing.mkdir();(existing/'sentinel').write_bytes(b'preserve')
   with self.assertRaises(ValueError):D.Diagnostics(existing)
   link=parent/'alias';link.symlink_to(existing,target_is_directory=True)
   with self.assertRaises(ValueError):D.Diagnostics(link/'new')
   broken=parent/'broken';broken.symlink_to('absent')
   with self.assertRaises(ValueError):D.Diagnostics(broken)
   self.assertEqual((existing/'sentinel').read_bytes(),b'preserve');self.assertFalse((existing/'new').exists())
 def test_foreign_temporary_is_not_overwritten(self):
  with tempfile.TemporaryDirectory() as temp:
   record=D.Diagnostics(Path(temp)/'public');partial=record.root/'index.partial';partial.write_bytes(b'preserve partial')
   with self.assertRaises(FileExistsError):record.checkpoint('FAILED')
   self.assertEqual(partial.read_bytes(),b'preserve partial')
 def test_index_alias_never_writes_through_to_existing_body(self):
  with tempfile.TemporaryDirectory() as temp:
   record=D.Diagnostics(Path(temp)/'public');target=Path(temp)/'sentinel';target.write_bytes(b'preserve')
   (record.root/'index.json').unlink();(record.root/'index.json').symlink_to(target)
   with self.assertRaises(ValueError):record.checkpoint('FAILED')
   self.assertEqual(target.read_bytes(),b'preserve')
 def test_exact_modes_ignore_restrictive_umask_and_same_owner_needs_no_chown(self):
  with tempfile.TemporaryDirectory() as temp,patch.object(os,'chown',side_effect=AssertionError('unexpected chown')),patch.object(os,'fchown',side_effect=AssertionError('unexpected fchown')):
   previous=os.umask(0o777)
   try:
    record=D.Diagnostics(Path(temp)/'public');record.capture(['gpg'],'verify',0,b'public',b'',1,2)
   finally:os.umask(previous)
   self.assertEqual(stat.S_IMODE(record.root.stat().st_mode),0o700)
   self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in record.root.iterdir()))
 def test_import_has_no_filesystem_or_process_actors(self):
  source=Path(D.__file__).read_text()
  with patch.object(os,'open',side_effect=AssertionError('import opened file')),patch.object(Path,'mkdir',side_effect=AssertionError('import created directory')),patch.object(os,'system',side_effect=AssertionError('import executed command')):
   exec(compile(source,D.__file__,'exec'),{'__name__':'diagnostics_import_only'})
 def test_finite_commands_bound_preserves_last_complete_index(self):
  with tempfile.TemporaryDirectory() as temp,patch.object(D,'MAX_COMMANDS',2):
   record=D.Diagnostics(Path(temp)/'public')
   for i in range(2):record.capture(['gpg'],'verify',i,b'',b'',i,i)
   before=(record.root/'index.json').read_bytes()
   with self.assertRaises(ValueError):record.capture(['gpg'],'third',1,b'',b'',3,3)
   self.assertEqual((record.root/'index.json').read_bytes(),before);self.assertEqual(len(record.commands),2)


if __name__=='__main__':unittest.main()
