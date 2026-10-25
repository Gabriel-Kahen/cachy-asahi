"""Private sysfs-like fixtures only: no actual /sys or host database writes."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
loader = importlib.machinery.SourceFileLoader('ksm_experiment_test', str(HERE / 'cachy-asahi-ksm-experiment'))
spec = importlib.util.spec_from_loader(loader.name, loader)
E = importlib.util.module_from_spec(spec); loader.exec_module(E)


class Experiment(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ksm-private-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'ksm'; self.root.mkdir(mode=0o700)
        self.boot = self.base / 'boot'; self.boot.mkdir(mode=0o700)
        self.run = self.root / 'run'; self.run.write_bytes(b'1\n'); self.run.chmod(0o644)
        (self.boot / 'boot_id').write_text('11111111-2222-4333-8444-555555555555\n')
        self.state = self.base / 'state'
        self.control = E.Control(self.root, self.boot, model=True)

    def preview(self, name='trial', desired=0):
        return E.preview(self.control, self.state, name, desired)['plan_sha256']

    def operate(self, action, digest=None, name='trial', control=None):
        return E.operate(control or self.control, self.state, name, action, digest)

    def journal(self):
        return json.loads((self.state / 'trial/journal.json').read_bytes())

    def test_pause_inspect_undo_repeat_and_baseline(self):
        digest = self.preview()
        self.assertEqual(self.run.read_bytes(), b'1\n')
        self.assertEqual(self.journal()['phase'], 'PLANNED')
        self.assertTrue(self.operate('apply', digest)['kernel_write'])
        self.assertEqual(self.run.read_bytes(), b'0\n')
        self.assertFalse(self.operate('apply', digest)['kernel_write'])
        self.assertEqual(self.operate('inspect')['current'], 0)
        self.assertTrue(self.operate('undo', digest)['kernel_write'])
        self.assertEqual(self.run.read_bytes(), b'1\n')
        self.assertFalse(self.operate('undo', digest)['kernel_write'])
        self.assertEqual(json.loads((self.state/'trial/plan.json').read_bytes())['baseline'], 1)
        with self.assertRaises(ValueError): self.operate('apply', digest)

    def test_resume_and_noop(self):
        self.run.write_bytes(b'0\n'); digest = self.preview(desired=1)
        self.operate('apply', digest); self.assertEqual(self.run.read_bytes(), b'1\n')
        self.operate('undo', digest); self.assertEqual(self.run.read_bytes(), b'0\n')
        digest = self.preview(name='noop', desired=0)
        self.assertFalse(self.operate('apply', digest, 'noop')['kernel_write'])

    def test_global_scope_serializes_named_experiments(self):
        a = self.preview('trial'); b = self.preview('other')
        self.operate('apply', a)
        with self.assertRaises(ValueError): self.operate('apply', b, 'other')
        self.operate('undo', a)
        self.operate('apply', b, 'other')

    def test_sysfs_attribute_size_is_not_value_length(self):
        original = os.fstat
        inode = self.run.stat().st_ino
        def sized(fd):
            row = original(fd)
            if row.st_ino != inode: return row
            values = list(row); values[6] = 4096
            return os.stat_result(values)
        # st_size may be PAGE_SIZE while read returns only the complete scalar.
        with patch.object(E.os, 'fstat', side_effect=sized), patch.object(E.os, 'ftruncate', side_effect=AssertionError('never truncate sysfs')):
            digest = self.preview(); self.operate('apply', digest); self.operate('undo', digest)
        self.assertEqual(self.run.read_bytes(), b'1\n')

    def test_sysfs_single_store_no_truncate_or_write_retry(self):
        digest = self.preview(); original = os.write; writes = []
        def write(fd, raw):
            if os.fstat(fd).st_ino == self.run.stat().st_ino:
                self.assertEqual(self.journal()['phase'], 'APPLY_INTENT')
                writes.append(raw)
            return original(fd, raw)
        with patch.object(E.os, 'write', side_effect=write), patch.object(E.os, 'ftruncate', side_effect=AssertionError('invalid sysfs operation')):
            self.operate('apply', digest)
        self.assertEqual(writes, [b'0\n'])

    def test_interrupted_after_store_retains_durable_intent_undo_recovers(self):
        digest = self.preview(); original = self.control.write
        def interrupted(*args):
            original(*args)
            raise InterruptedError('injected after real scalar write')
        with patch.object(self.control, 'write', side_effect=interrupted):
            with self.assertRaises(InterruptedError): self.operate('apply', digest)
        self.assertEqual(self.journal()['phase'], 'APPLY_INTENT')
        self.assertTrue(self.operate('inspect')['intent_uncertain'])
        self.assertEqual(self.run.read_bytes(), b'0\n')
        self.operate('undo', digest)
        self.assertEqual(self.run.read_bytes(), b'1\n')

    def test_write_failure_has_no_completed_claim_and_can_undo(self):
        digest = self.preview()
        with patch.object(self.control, 'write', side_effect=PermissionError('injected')):
            with self.assertRaises(PermissionError): self.operate('apply', digest)
        self.assertEqual(self.journal()['phase'], 'APPLY_INTENT')
        self.assertEqual(self.run.read_bytes(), b'1\n')
        self.operate('undo', digest)
        self.assertEqual(self.journal()['phase'], 'UNDONE')

    def test_real_process_death_after_write_preserves_recoverable_intent(self):
        digest = self.preview()
        child = os.fork()
        if child == 0:
            original = self.control.write
            def die(*args):
                original(*args)
                os.kill(os.getpid(), signal.SIGKILL)
            self.control.write = die
            self.operate('apply', digest)
            os._exit(99)
        waited, status = os.waitpid(child, 0)
        self.assertEqual(waited, child)
        self.assertTrue(os.WIFSIGNALED(status)); self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
        self.assertEqual(self.journal()['phase'], 'APPLY_INTENT')
        self.assertEqual(self.run.read_bytes(), b'0\n')
        self.operate('undo', digest)
        self.assertEqual(self.run.read_bytes(), b'1\n')

    def test_failed_before_write_journal_never_changes_control(self):
        digest = self.preview(); original = E.save
        def fail(*args, **kwargs):
            if args[1] == 'journal.json' and args[2]['phase'] == 'APPLY_INTENT':
                raise OSError('injected journal failure')
            return original(*args, **kwargs)
        with patch.object(E, 'save', side_effect=fail):
            with self.assertRaises(OSError): self.operate('apply', digest)
        self.assertEqual(self.run.read_bytes(), b'1\n')
        self.assertEqual(self.journal()['phase'], 'PLANNED')

    def test_failed_completed_journal_retains_intent_and_restores(self):
        digest = self.preview(); original = E.save
        def fail(*args, **kwargs):
            if args[1] == 'journal.json' and args[2]['phase'] == 'APPLIED':
                raise OSError('injected final journal failure')
            return original(*args, **kwargs)
        with patch.object(E, 'save', side_effect=fail):
            with self.assertRaises(OSError): self.operate('apply', digest)
        self.assertEqual(self.run.read_bytes(), b'0\n')
        self.assertEqual(self.journal()['phase'], 'APPLY_INTENT')
        self.operate('undo', digest)
        self.assertEqual(self.run.read_bytes(), b'1\n')

    def test_intent_changed_before_control_write_refuses(self):
        digest = self.preview(); original = E.save
        def changed(*args, **kwargs):
            raw = original(*args, **kwargs)
            if args[1] == 'journal.json' and args[2]['phase'] == 'APPLY_INTENT':
                (self.state/'trial/journal.json').write_bytes(raw + b' ')
            return raw
        with patch.object(E, 'save', side_effect=changed):
            with self.assertRaises(ValueError): self.operate('apply', digest)
        self.assertEqual(self.run.read_bytes(), b'1\n')

    def test_short_write_is_not_retried(self):
        digest = self.preview(); original = os.write; calls = []
        def short(fd, raw):
            if os.fstat(fd).st_ino == self.run.stat().st_ino:
                calls.append(raw); return original(fd, raw[:1])
            return original(fd, raw)
        with patch.object(E.os, 'write', side_effect=short):
            with self.assertRaises(ValueError): self.operate('apply', digest)
        self.assertEqual(calls, [b'0\n']); self.assertEqual(self.journal()['phase'], 'APPLY_INTENT')
        self.operate('undo', digest)

    def test_readback_failure_retains_intent(self):
        digest = self.preview(); original = self.control.write
        def changed(fd, current, before, after):
            original(fd, current, before, after)
            self.run.write_bytes(b'2\n')
            E.need(current() == after, 'readback differs')
        with patch.object(self.control, 'write', side_effect=changed):
            with self.assertRaises(ValueError): self.operate('apply', digest)
        self.assertEqual(self.journal()['phase'], 'APPLY_INTENT')
        with self.assertRaises(ValueError): self.operate('undo', digest)
        self.assertEqual(self.run.read_bytes(), b'2\n')

    def test_observed_external_change_conflicts_before_apply_and_undo(self):
        digest = self.preview(); self.run.write_bytes(b'0\n')
        with self.assertRaises(ValueError): self.operate('apply', digest)
        self.run.write_bytes(b'1\n'); self.operate('apply', digest); self.run.write_bytes(b'1\n')
        with self.assertRaises(ValueError): self.operate('undo', digest)
        self.assertEqual(self.run.read_bytes(), b'1\n')

    def test_run_unmerge_unknown_or_noncanonical_refused_without_write(self):
        for raw in (b'2\n', b'3\n', b'01\n', b'1', b'1\nextra', b'', b'1'*70):
            with self.subTest(raw=raw):
                self.run.write_bytes(raw)
                with self.assertRaises(ValueError): self.preview()
                self.assertEqual(self.run.read_bytes(), raw)
                if self.state.exists():
                    import shutil
                    shutil.rmtree(self.state)
        with self.assertRaises(ValueError): E.preview(self.control, self.state, 'trial', 2)

    def test_stale_boot_refuses(self):
        digest = self.preview(); (self.boot/'boot_id').write_text('99999999-2222-4333-8444-555555555555\n')
        with self.assertRaises(ValueError): self.operate('apply', digest)
        self.assertEqual(self.run.read_bytes(), b'1\n')

    def test_symlink_hardlink_or_replaced_run_refuses(self):
        digest = self.preview(); raw = self.run.read_bytes(); self.run.rename(self.root/'saved')
        self.run.symlink_to(self.root/'saved')
        with self.assertRaises(OSError): self.operate('apply', digest)
        self.run.unlink(); os.link(self.root/'saved', self.run)
        with self.assertRaises(ValueError): self.operate('apply', digest)
        self.run.unlink(); self.run.write_bytes(raw)
        with self.assertRaises(ValueError): self.operate('apply', digest)

    def test_ancestor_alias_or_permissions_refuse(self):
        alias = self.base/'alias'; alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError): E.preview(E.Control(alias, self.boot, model=True), self.state, 'trial', 0)
        self.root.chmod(0o777)
        with self.assertRaises(ValueError): self.preview()

    def test_ancestor_swap_before_write_refuses(self):
        digest = self.preview(); original = E.save
        def save(*args, **kwargs):
            raw = original(*args, **kwargs)
            if args[1] == 'journal.json' and args[2]['phase'] == 'APPLY_INTENT':
                self.root.rename(self.base/'old-ksm'); self.root.mkdir(mode=0o700)
                self.run.write_bytes(b'1\n')
            return raw
        with patch.object(E, 'save', side_effect=save):
            with self.assertRaises(ValueError): self.operate('apply', digest)
        self.assertEqual((self.base/'old-ksm/run').read_bytes(), b'1\n')
        self.assertEqual(self.run.read_bytes(), b'1\n')

    def test_plan_and_journal_malformed_or_aliased_refuse(self):
        digest = self.preview(); plan = self.state/'trial/plan.json'; raw = plan.read_bytes()
        for bad in (b'{"name":1,"name":2}', b'[]', b'{"x":NaN}', raw.replace(b'"baseline": 1', b'"baseline": true')):
            plan.write_bytes(bad)
            with self.assertRaises((ValueError, TypeError, KeyError)): self.operate('apply', digest)
        plan.write_bytes(raw); os.link(plan, self.base/'plan-alias')
        with self.assertRaises(ValueError): self.operate('apply', digest)
        (self.base/'plan-alias').unlink(); plan.chmod(0o644)
        with self.assertRaises(ValueError): self.operate('apply', digest)
        self.assertEqual(self.run.read_bytes(), b'1\n')

    def test_wrong_digest_name_and_unexpected_refs_refuse(self):
        digest = self.preview()
        for name in ('../escape', 'a/b', '', 'bad\nname', 'x'*49):
            with self.assertRaises(ValueError): self.operate('apply', digest, name)
        with self.assertRaises(ValueError): self.operate('apply', '0'*64)
        (self.state/'trial/unexpected').write_bytes(b'x')
        with self.assertRaises(ValueError): self.operate('apply', digest)
        self.assertEqual(self.run.read_bytes(), b'1\n')

    def test_state_lock_contention_or_alias_refuses(self):
        digest = self.preview()
        with E.store(self.state, 'trial', model=True):
            with self.assertRaises(BlockingIOError): self.operate('apply', digest)
        os.link(self.state/'.lock', self.base/'lock-alias')
        with self.assertRaises(ValueError): self.operate('apply', digest)

    def test_active_preview_refusal_does_not_leave_empty_record(self):
        digest = self.preview(); self.operate('apply', digest)
        with self.assertRaises(ValueError): self.preview('blocked')
        self.assertFalse((self.state/'blocked').exists())
        self.operate('undo', digest)

    def test_state_record_bound_and_safe_error_text(self):
        self.preview()
        for n in range(63): (self.state/f'record{n}').mkdir(mode=0o700)
        with self.assertRaises(ValueError): self.preview('overflow')
        self.assertFalse((self.state/'overflow').exists())
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            self.assertEqual(E.main(['inspect', 'unsafe\nforged-line'], control=self.control, state=self.state), 1)
        self.assertNotIn('forged-line', error.getvalue())
        self.assertEqual(len(error.getvalue().splitlines()), 1)

    def test_cli_scope_help_and_real_fixture_flow(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(E.main(['preview', 'trial', '--pause'], control=self.control, state=self.state), 0)
        digest = json.loads(output.getvalue())['plan_sha256']
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(E.main(['apply', 'trial', '--plan-sha256', digest, '--confirm', 'CHANGE_GLOBAL_KSM_SCANNING'], control=self.control, state=self.state), 0)
            self.assertEqual(E.main(['undo', 'trial', '--plan-sha256', digest, '--confirm', 'RESTORE_KSM_SCANNING_BASELINE'], control=self.control, state=self.state), 0)
        self.assertEqual(self.run.read_bytes(), b'1\n')
        with contextlib.redirect_stdout(io.StringIO()):
            with patch.object(E.Control, 'opened', side_effect=AssertionError('help must not open kernel')):
                with self.assertRaises(SystemExit) as result: E.main(['--help'])
                self.assertEqual(result.exception.code, 0)

    def test_no_fixture_path_cli_or_nonfixed_live_control(self):
        with self.assertRaises(ValueError): E.Control(self.root, self.boot)
        with self.assertRaises(ValueError): E.Control(Path('/sys/kernel/mm/ksm'), self.boot, model=True)
        for magic in (0x9fa0, 0x62656572):
            with patch.object(E, 'filesystem', return_value=magic):
                with self.assertRaises(ValueError): self.preview()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit): E.main(['--root', str(self.root), 'preview', 'x', '--pause'])


if __name__ == '__main__':
    unittest.main()
