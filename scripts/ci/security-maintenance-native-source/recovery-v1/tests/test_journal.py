"""New durable temporary-file journal controls, no commands or native actors."""
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

P=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(P/'overlay/native'))
J=importlib.import_module('security_recovery_journal')
B=dict(source='a'*40,ref='refs/heads/codex/unbound-journal',run='9000000000123',attempt=1,
       map_sha256='b'*64,token='c'*24)

class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='recovery-journal-')
        self.path=Path(self.tmp.name)/'journal.jsonl'
    def tearDown(self):self.tmp.cleanup()
    def test_complete_forward_hashchain(self):
        with J.Journal.create(self.path,B)as j:
            for phase in J.PHASES[1:]:j.append(phase,{'fixture':True})
        result=J.load(self.path,B)
        self.assertTrue(result['complete']);self.assertFalse(result['resume_allowed'])
        self.assertEqual(result['phase'],'FINALIZED')
    def test_cannot_reopen_writer(self):
        J.Journal.create(self.path,B).close()
        with self.assertRaises(FileExistsError):J.Journal.create(self.path,B)
    def test_pending_command_blocks_other_effects_and_resume(self):
        with J.Journal.create(self.path,B)as j:
            j.append('BASELINE_RECORDED',{})
            j.append('COMMAND_INTENT',dict(step='warm-install',argv=['/fixture/not-executed'],seconds=30,output_cap=1024))
            with self.assertRaises(ValueError):j.append('REFERENCE_READY',{})
        r=J.load(self.path,B);self.assertEqual(r['pending_command'],'warm-install');self.assertFalse(r['resume_allowed'])
    def test_command_pair_keeps_effective_phase(self):
        with J.Journal.create(self.path,B)as j:
            j.append('BASELINE_RECORDED',{})
            j.append('COMMAND_INTENT',dict(step='query',argv=['/fixture'],seconds=30,output_cap=1024))
            with self.assertRaises(ValueError):j.append('COMMAND_COMPLETED',dict(step='other'))
            j.append('COMMAND_COMPLETED',dict(step='query',exit=0))
            self.assertEqual(j.phase,'BASELINE_RECORDED')
            self.assertIsNone(j.pending)
    def test_wrong_phase_and_terminal_are_refused(self):
        with J.Journal.create(self.path,B)as j:
            with self.assertRaises(ValueError):j.append('INTERRUPTED_RETIRED',{})
            j.append('FAILED',{'partial':True})
            with self.assertRaises(ValueError):j.append('BASELINE_RECORDED',{})
        self.assertEqual(J.load(self.path,B)['phase'],'FAILED')
    def test_partial_tail_is_uncertain_not_resumable(self):
        J.Journal.create(self.path,B).close()
        with self.path.open('ab')as f:f.write(b'{"partial":')
        with self.assertRaises(ValueError):J.load(self.path,B)
    def test_hash_or_binding_substitution_refused(self):
        J.Journal.create(self.path,B).close()
        other=dict(B,run='9000000000124')
        with self.assertRaises(ValueError):J.load(self.path,other)
        raw=self.path.read_bytes().replace(b'CREATED',b'FAILED ')
        self.path.write_bytes(raw)
        with self.assertRaises(ValueError):J.load(self.path,B)
    def test_journal_caps_are_before_write(self):
        with J.Journal.create(self.path,B)as j:
            before=self.path.read_bytes()
            with self.assertRaises(ValueError):j.append('BASELINE_RECORDED',{'too-large':'x'*70000})
            self.assertEqual(self.path.read_bytes(),before)

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(JournalTests))
    (P/'result-journal.json').write_text(json.dumps(dict(status='PASS'if result.wasSuccessful()else'FAIL',
        tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),
        scope='TEMPORARY_FSYNCED_JOURNAL_ONLY',actual_commands_native_GET_reader_calls=0),sort_keys=True,indent=2)+'\n')
    raise SystemExit(not result.wasSuccessful())
