"""New real-temp-filesystem sequence tests with a fake command adapter only."""
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

P = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P / 'candidate'))
R = importlib.import_module('security_recovery')
S = importlib.import_module('security_recovery_state')
F = importlib.import_module('security_recovery_fs')
SIGNER = 'AB' * 20
STATUS = ('[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 0123456789ABCDEF TEST ONLY\n'
          f'[GNUPG:] VALIDSIG {SIGNER} 2026-11-08 1794100000 0 4 0 22 8 00 {SIGNER}\n').encode()


def pin(raw):
    return R.Pin(len(raw), hashlib.sha256(raw).hexdigest())


def natural(exit=0):
    return dict(exit=exit, error=None, timeout=False, forced_retirement=False,
                passed=True, reaped=True, group_absent=True, pid_reserved_until_retirement=True)


class Fixture:
    def __init__(self, root):
        self.root = Path(root)
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        self.policy = S.RecoveryPolicy('b' * 40, 'refs/heads/codex/unbound-recovery-sequence',
            '9000000000111', ('bin/security', 'share/security-old', 'share/security-new'),
            os.geteuid(), os.getegid())
        self.local = self.root / 'var/lib/pacman/local'
        self.local.mkdir(parents=True)
        self.inventory = {}
        for i in range(349):
            version = '1:1-1' if i == 0 else '1-1'
            name = 'base%03d' % i
            d = self.local / (name + '-' + version)
            d.mkdir(); d.chmod(0o755)
            (d / 'desc').write_bytes(b'frozen baseline'); (d / 'desc').chmod(0o644)
            self.inventory[name] = version
        (self.root / 'usr/bin').mkdir(parents=True)
        (self.root / 'usr/share').mkdir()
        self.baseline = self.snapshot()
        (self.local / S.NEW).mkdir(); (self.local / S.NEW).chmod(0o755)
        lock = self.root / 'var/lib/pacman/db.lck'
        lock.write_bytes(b''); lock.chmod(0)
        self.interrupted = self.snapshot()
        self.evidence = dict(protocol=S.PROTOCOL, binding=self.policy.binding(),
            baseline_sha256=S.snapshot_sha256(self.baseline), checkpoint=dict(
                type='FIRST_UPGRADE_ZERO', phase=S.PHASE, package=S.NAME,
                pid=101, ppid=100, starttime=1234567, event=1, percent=0, howmany=1, current=1,
                prepared_directory=copy.deepcopy(self.interrupted['db'][S.NEW]),
                lock=copy.deepcopy(self.interrupted['lock'])), retirement=dict(
                pid=101, starttime=1234567, method='OWNED_PIDFD_INTERRUPT', signal=9,
                reaped=True, group_absent=True, descendants_absent=True,
                pid_reserved_until_retirement=True, checkpoint_blocked_until_interrupt=True))
        self.data = {R.ARCHIVE: b'UNBOUND fake archive', R.ARCHIVE + '.sig': b'UNBOUND fake signature',
                     R.KEYRING: b'UNBOUND public keyring',
                     R.CONFIG: ('[options]\n' + ''.join(f'{k} = {v}\n' for k, v in R.OPTIONS.items())).encode()}
        for name, body in self.data.items():
            self.write(name, body, 0o600)
        self.inputs = R.Inputs(*(pin(self.data[n]) for n in
                               (R.ARCHIVE, R.ARCHIVE + '.sig', R.CONFIG, R.KEYRING)), SIGNER)
        content = lambda kind, mode, body=None: dict(kind=kind, mode=mode,
            uid=self.policy.owner_uid, gid=self.policy.owner_gid,
            **({} if kind == 'dir' else dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())))
        self.expected_db = {S.NEW: content('dir', 0o755),
            S.NEW + '/desc': content('file', 0o644, b'independently expected fixture desc'),
            S.NEW + '/files': content('file', 0o644, b'independently expected fixture files')}
        self.expected_payload = {'bin/security': content('file', 0o755, b'candidate executable'),
                                'share/security-old': None,
                                'share/security-new': content('file', 0o644, b'candidate marker')}

    def close(self):
        os.close(self.fd)

    def snapshot(self):
        return F.snapshot(self.fd, self.policy.payload_names,
                          owner_uid=self.policy.owner_uid, owner_gid=self.policy.owner_gid)

    def write(self, name, body, mode):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body); target.chmod(mode)

    def install(self, wrong_payload=False):
        self.write('var/lib/pacman/local/' + S.NEW + '/desc', b'independently expected fixture desc', 0o644)
        (self.local / S.NEW).chmod(0o755)
        self.write('var/lib/pacman/local/' + S.NEW + '/files', b'independently expected fixture files', 0o644)
        self.write('usr/bin/security', b'bad' if wrong_payload else b'candidate executable', 0o755)
        self.write('usr/share/security-new', b'candidate marker', 0o644)

    def recover(self, runner):
        return R.recover(self.fd, self.baseline, self.policy, self.evidence, self.inputs,
                         self.expected_db, self.expected_payload, runner)


class FakeRunner:
    """Never starts a process; changes only the supplied temporary fixture."""
    def __init__(self, fixture, behavior='success'):
        self.fixture, self.behavior, self.calls = fixture, behavior, []

    def run(self, command):
        self.calls.append(command)
        f = self.fixture
        if command.step == 'verify-signature':
            if self.behavior == 'db-drift':
                f.write('var/lib/pacman/local/base001-1-1/desc', b'changed', 0o644)
            status = STATUS
            if self.behavior == 'expired':
                status += b'[GNUPG:] EXPKEYSIG 0123456789ABCDEF TEST ONLY\n'
            if self.behavior == 'wrong-signer':
                status = status.replace(SIGNER.encode(), b'CD' * 20)
            retirement = natural()
            if self.behavior == 'forced':
                retirement['forced_retirement'] = True
            return R.CommandResult(status, retirement)
        if command.step == 'signed-candidate-install':
            if self.behavior == 'install-failure':
                return R.CommandResult(b'fixture failure', natural(1))
            f.install(self.behavior == 'wrong-payload')
            return R.CommandResult(b'fixture install', natural())
        if command.step == 'verify-recovered':
            inventory = dict(f.inventory, **{S.NAME: '0.1.0-2'})
            if self.behavior == 'wrong-inventory':
                inventory[S.NAME] = '0.1.0-1'
            return R.CommandResult(''.join(n + ' ' + v + '\n' for n, v in sorted(inventory.items())).encode(), natural())
        raise AssertionError('unexpected command')


class Sequence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='security-recovery-sequence-')
        self.f = Fixture(self.temp.name)

    def tearDown(self):
        self.f.close(); self.temp.cleanup()

    def test_complete_sequence_real_cleanup_and_fake_commands(self):
        runner = FakeRunner(self.f)
        result = self.f.recover(runner)
        self.assertEqual(result['status'], 'VERIFIED_RECOVERY_SEQUENCE_WITH_CALLER_OWNED_ADAPTER')
        self.assertEqual([c.step for c in runner.calls], ['verify-signature', 'signed-candidate-install', 'verify-recovered'])
        self.assertEqual(runner.calls[1].argv[-4:], ('--noconfirm', '--noscriptlet', '-U', '/' + R.ARCHIVE))
        self.assertFalse((self.f.root / 'var/lib/pacman/db.lck').exists())

    def test_invalid_signatures_do_not_clean_database_or_lock(self):
        for behavior in ('expired', 'wrong-signer', 'forced'):
            with self.subTest(behavior=behavior):
                with self.assertRaises(R.RecoveryFailure): self.f.recover(FakeRunner(self.f, behavior))
                self.assertEqual(self.f.snapshot(), self.f.interrupted)

    def test_input_pin_mismatch_precedes_all_commands(self):
        self.f.write(R.ARCHIVE, b'wrong', 0o600); runner = FakeRunner(self.f)
        with self.assertRaises(R.RecoveryFailure): self.f.recover(runner)
        self.assertEqual(runner.calls, [])
        self.assertEqual(self.f.snapshot(), self.f.interrupted)

    def test_optional_signature_config_rejected_even_with_matching_pin(self):
        body = self.f.data[R.CONFIG].replace(b'SigLevel = Required', b'SigLevel = Optional')
        self.f.write(R.CONFIG, body, 0o600)
        self.f.inputs = R.Inputs(self.f.inputs.archive, self.f.inputs.signature, pin(body), self.f.inputs.keyring, SIGNER)
        runner = FakeRunner(self.f)
        with self.assertRaises(R.RecoveryFailure): self.f.recover(runner)
        self.assertEqual(runner.calls, [])
        self.assertEqual(self.f.snapshot(), self.f.interrupted)

    def test_database_drift_after_signature_prevents_cleanup(self):
        with self.assertRaises(R.RecoveryFailure) as caught:
            self.f.recover(FakeRunner(self.f, 'db-drift'))
        self.assertEqual(caught.exception.phase, 'orphan-cleanup')
        self.assertIn(S.NEW, self.f.snapshot()['db'])
        self.assertIsNotNone(self.f.snapshot()['lock'])

    def test_invalid_expected_database_rejected_before_mutation(self):
        self.f.expected_db.pop(S.NEW + '/desc'); runner = FakeRunner(self.f)
        with self.assertRaises(R.RecoveryFailure): self.f.recover(runner)
        self.assertEqual(runner.calls, [])
        self.assertEqual(self.f.snapshot(), self.f.interrupted)

    def test_install_failure_is_partial_and_never_retried(self):
        runner = FakeRunner(self.f, 'install-failure')
        with self.assertRaises(R.RecoveryFailure) as caught: self.f.recover(runner)
        self.assertEqual(caught.exception.completed, ('verify-signature', 'orphan-cleanup'))
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(self.f.snapshot(), self.f.baseline)

    def test_wrong_recovered_payload_is_retained_not_automatically_removed(self):
        runner = FakeRunner(self.f, 'wrong-payload')
        with self.assertRaises(R.RecoveryFailure) as caught: self.f.recover(runner)
        self.assertEqual(caught.exception.phase, 'verify-recovered')
        self.assertEqual(len(runner.calls), 3)
        self.assertEqual((self.f.root / 'usr/bin/security').read_bytes(), b'bad')

    def test_wrong_inventory_refused(self):
        with self.assertRaises(R.RecoveryFailure): self.f.recover(FakeRunner(self.f, 'wrong-inventory'))

    def test_completed_recovery_is_not_another_cleanup_authorization(self):
        self.f.recover(FakeRunner(self.f)); runner = FakeRunner(self.f)
        with self.assertRaises(R.RecoveryFailure): self.f.recover(runner)
        self.assertEqual(runner.calls, [])


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Sequence))
    report = dict(status='PASS' if result.wasSuccessful() else 'FAIL', tests=result.testsRun,
                  failures=len(result.failures), errors=len(result.errors),
                  fixture='REAL_TEMP_FILESYSTEM_UNBOUND_FAKE_GPG_PACMAN_COMMAND_ADAPTER',
                  actual_GPG_pacman_native_Git_API_reader_callback_GET_calls=0)
    (P / 'result-sequence.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    raise SystemExit(not result.wasSuccessful())
