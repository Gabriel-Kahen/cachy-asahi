"""Fake-only producer DATA join; never execute native commands or capsule readers."""
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import sys
import unittest

P = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(P / 'overlay/native'), str(P / 'tests')]
T = importlib.import_module('test_native_adapter')
A, R, F, S = T.A, T.R, T.F, T.S
J = importlib.import_module('security_recovery_journal')
V = importlib.import_module('security_recovery_reader')
M = importlib.import_module('security_recovery_metadata')


def natural_receipt(pid):
    return dict(T.retired(), descendants_absent=True, pid=pid, starttime=123456,
        method='OWNED_NATURAL_COMMAND', signal=None, checkpoint_blocked_until_interrupt=False,
        natural_exit=True, leader_held_until_group_inspection=True,
        exit_observed_via_waitpid=True, ownership_lost=False, retirement='REAPED',
        forced_cleanup=False, cleanup_member_uids=[], elapsed_seconds=0.01)


class JoinFake(T.Fake):
    def run(self, argv, **kwargs):
        result = super().run(argv, **kwargs)
        result['retirement'] = natural_receipt(81200 + len(self.calls))
        if argv == list(A.CMD_INSTALL) and sum(a == list(A.CMD_INSTALL) for a, _ in self.calls) == 2:
            self.f.write('var/lib/pacman/local/' + S.NEW + '/desc', T.desc(T.NOW + 1), 0o644)
            result['retirement']['wall_finished'] = T.NOW + 1
        if argv == list(A.CMD_QUERY):
            result['stdout'] = b''.join(sorted(
                [('base%03d 1-1\n' % i).encode() for i in range(349)]
                + [(S.NAME + ' 0.1.0-2\n').encode()]))
        return result


def rewrite_journal(raw, change):
    """Rehash a deliberate DATA perturbation, so refusal is semantic."""
    rows = [json.loads(line) for line in raw.splitlines()]
    change(rows)
    previous = '0' * 64
    for i, row in enumerate(rows):
        row.update(sequence=i, previous=previous)
        payload = {k: v for k, v in row.items() if k != 'sha256'}
        row['sha256'] = hashlib.sha256(S.encoded(payload)).hexdigest()
        previous = row['sha256']
    return b''.join(S.encoded(row) + b'\n' for row in rows).decode('ascii')


def validate_join(value):
    """Only the two passive lower DATA validators plus explicit producer joins."""
    installs = V.validate_commands(value['commands'], value['binding'], T.SIGNER)
    data = V.journal_data(value['journal'], value['binding'])
    V.need(tuple(data['phases']) == V.PHASES, 'all exact high phases')
    V.need(data['phases'] == value['expected_phases'], 'producer phase DATA joins')
    V.need(installs == value['windows'], 'both signed installs own timestamp windows')
    V.need([phase for phase, _, _ in data['commands']] ==
        ['BASELINE_RECORDED'] * 3 + ['REFERENCE_READY', 'NORMAL_EPISODE_PASSED']
        + ['RECOVERY_BASELINE_RESTORED'] * 3 + ['INTERRUPTED_RETIRED'] * 2
        + ['RECOVERY_INSTALL_INTENT', 'RECOVERY_INSTALLED'], 'exact adapter command phases')
    V.need([record for _, _, record in data['commands']] == value['commands'],
        'every adapter completion joins journal')
    for _, intent, record in data['commands']:
        V.need(all(record.get(k) == v for k, v in intent.items()), 'command intent joins completion')
    V.need(data['resume_allowed'] is False, 'passive verification cannot authorize resume')
    return data


class AdapterJournalJoin(unittest.TestCase):
    def setUp(self):
        self.f = T.Fixture()

    def tearDown(self):
        self.f.close()

    def exercise(self):
        f = self.f
        journal = J.Journal.create(f.root / 'join.jsonl', f.binding)
        f.fake = JoinFake(f)
        adapter = A.NativeCommandAdapter.for_test(f.fd, f.binding, f.sentinel, f.inputs,
            f.fake, journal=journal)
        snap = lambda: F.snapshot(f.fd, ('bin/security',), owner_uid=os.geteuid(), owner_gid=os.getegid())
        baseline_pin = dict(snapshot_sha256=F.snapshot_sha256(f.baseline))
        expected = dict(CREATED={}, BASELINE_RECORDED=baseline_pin)
        try:
            journal.append('BASELINE_RECORDED', baseline_pin)
            ref = adapter.capture_reference(('bin/security',), f.baseline)
            expected['REFERENCE_READY'] = dict(reference=V.pin(S.encoded(ref['reference'].record())),
                snapshot_sha256=F.snapshot_sha256(ref['snapshot']), install_window=ref['install_window'])
            expected['BASELINE_RESTORED'] = baseline_pin

            # Simulate the already completed legacy episode without adding adapter roles.
            for name, raw in ref['reference'].raw_files.items():
                f.write('var/lib/pacman/local/' + name, raw, 0o644)
            (f.local / S.NEW).chmod(0o755)
            f.write('usr/bin/security', b'candidate', 0o755)
            normal = dict(status='FAKE_LEGACY_EPISODE_COMPLETE', snapshot_sha256=F.snapshot_sha256(snap()))
            journal.append('NORMAL_EPISODE_PASSED', normal)
            expected['NORMAL_EPISODE_PASSED'] = normal
            adapter.remove_candidate(f.baseline)
            journal.append('RECOVERY_BASELINE_RESTORED', baseline_pin)
            expected['RECOVERY_BASELINE_RESTORED'] = baseline_pin
            adapter.install_prior(T.pin(b'prior archive'), T.pin(b'prior signature'))
            expected['PRIOR_INSTALLED'] = dict(snapshot_sha256=F.snapshot_sha256(snap()))
            journal.append('PRIOR_INSTALLED', expected['PRIOR_INSTALLED'])

            # A fake pre-extraction checkpoint replaces prior state with empty NEW + lock.
            nonce = 'e' * 32
            intent = dict(argv=list(A.CMD_INSTALL), nonce_sha256=V.pin(nonce.encode())['sha256'])
            journal.append('INTERRUPT_INTENT', intent)
            expected['INTERRUPT_INTENT'] = intent
            shutil.rmtree(f.local / S.OLD)
            (f.root / 'usr/bin/security').unlink()
            (f.local / S.NEW).mkdir(mode=0o755)
            f.write('var/lib/pacman/db.lck', b'', 0)
            interrupted = snap()
            policy = S.RecoveryPolicy(f.binding['source'], f.binding['ref'], f.binding['run'],
                ('bin/security',), os.geteuid(), os.getegid())
            cp = dict(type='FIRST_UPGRADE_ZERO', phase=S.PHASE, package=S.NAME, pid=81234,
                ppid=81233, starttime=123456, event=1, percent=0, howmany=1, current=1,
                prepared_directory=interrupted['db'][S.NEW], lock=interrupted['lock'])
            retirement = dict(pid=cp['pid'], starttime=cp['starttime'], method='OWNED_PIDFD_INTERRUPT',
                signal=9, reaped=True, group_absent=True, descendants_absent=True,
                pid_reserved_until_retirement=True, checkpoint_blocked_until_interrupt=True)
            evidence = dict(protocol=S.PROTOCOL, binding=policy.binding(),
                baseline_sha256=baseline_pin['snapshot_sha256'], checkpoint=cp, retirement=retirement)
            plan = S.classify_recovery(f.baseline, interrupted, policy, evidence)
            expected['CHECKPOINT_VERIFIED'] = dict(snapshot_sha256=plan.interrupted_sha256,
                checkpoint=cp, observation_sha256=V.pin(S.encoded(dict(fake_checkpoint=True)))['sha256'])
            journal.append('CHECKPOINT_VERIFIED', expected['CHECKPOINT_VERIFIED'])
            full_retirement = dict(natural_receipt(cp['pid']), **{
                **retirement, 'exit': -9, 'natural_exit': False})
            receipt = dict(retirement=full_retirement,
                channel=dict(protocol='RECOVERY_BLOCK_V1', nonce=nonce,
                    sender=dict(pid=cp['pid'], uid=os.geteuid(), gid=os.getegid()),
                    record=V.pin(S.encoded(dict(fake_checkpoint=True)) + b'\n')),
                verified=dict(snapshot_sha256=plan.interrupted_sha256, checkpoint=cp),
                stdout=V.pin(b''), stderr=V.pin(b''))
            expected['INTERRUPTED_RETIRED'] = dict(retirement=full_retirement,
                evidence_sha256=V.pin(S.encoded(evidence))['sha256'], receipt=V.pin(S.encoded(receipt)))
            journal.append('INTERRUPTED_RETIRED', expected['INTERRUPTED_RETIRED'])
            result = R.recover(f.fd, f.baseline, policy, evidence, f.inputs,
                ref['candidate_db'], ref['candidate_payload'], adapter,
                metadata_normalizer=M.MetadataNormalizer(ref['reference']), journal=journal)
            final = dict(snapshot_sha256=result['snapshot_sha256'])
            journal.append('FINALIZED', final)
            expected.update(CLEANUP_INTENT=dict(snapshot_sha256=plan.interrupted_sha256),
                CLEANUP_COMPLETED=dict(snapshot_sha256=plan.after_unlock_sha256),
                RECOVERY_INSTALL_INTENT=dict(archive_sha256=f.inputs.archive.sha256),
                RECOVERY_INSTALLED=dict(window=adapter.install_window),
                RECOVERY_VERIFIED=final, FINALIZED=final)
        finally:
            journal.close()
        return dict(binding=f.binding, commands=copy.deepcopy(adapter.records),
            journal=(f.root / 'join.jsonl').read_text('ascii'), expected_phases=expected,
            windows=[ref['install_window'], adapter.install_window], result=result)

    def test_complete_fake_adapter_driver_and_passive_data_join(self):
        value = self.exercise()
        data = validate_join(value)
        self.assertEqual(len(data['commands']), 12)
        self.assertEqual(value['result']['completed'],
            ['verify-signature', 'orphan-cleanup', 'signed-candidate-install', 'verify-recovered'])
        field = value['result']['normalization']['file_evidence'][S.NEW + '/desc']
        self.assertEqual(field['actual_installdate'] - field['reference_installdate'], 1)
        self.assertTrue(all('HOME' not in kwargs['env'] for _, kwargs in self.f.fake.calls))

    def test_incomplete_or_forced_natural_retirement_refused(self):
        good = self.exercise()
        for key, bad in [('descendants_absent', False), ('natural_exit', False),
                         ('forced_cleanup', True), ('starttime', 0)]:
            value = copy.deepcopy(good)
            value['commands'][2]['retirement'][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_join(value)

    def test_rehashed_wrong_phase_and_missing_finalization_refused(self):
        good = self.exercise()
        def wrong_phase(rows):
            next(r for r in rows if r['event'] == 'RECOVERY_BASELINE_RESTORED')['event'] = 'PRIOR_INSTALLED'
        for change in (wrong_phase, lambda rows: rows.pop()):
            value = copy.deepcopy(good)
            value['journal'] = rewrite_journal(value['journal'], change)
            with self.subTest(change=change.__name__), self.assertRaises(ValueError):
                validate_join(value)

    def test_role_and_independently_valid_journal_record_drift_refused(self):
        good = self.exercise()
        value = copy.deepcopy(good)
        value['commands'][7]['step'] = 'signed-candidate-install'
        with self.assertRaises(ValueError):
            validate_join(value)
        value = copy.deepcopy(good)
        def drift(rows):
            next(r for r in rows if r['event'] == 'COMMAND_COMPLETED')['data']['stderr']['sha256'] = '0' * 64
        value['journal'] = rewrite_journal(value['journal'], drift)
        V.journal_data(value['journal'], value['binding'])
        V.validate_commands(value['commands'], value['binding'], T.SIGNER)
        with self.assertRaisesRegex(ValueError, 'completion joins journal'):
            validate_join(value)


if __name__ == '__main__':
    unittest.main(verbosity=2)
