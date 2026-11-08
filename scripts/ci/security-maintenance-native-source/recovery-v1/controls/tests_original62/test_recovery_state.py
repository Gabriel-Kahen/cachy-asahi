"""New synthetic recovery-state controls. No actor, filesystem or old-role replay."""
import copy
from dataclasses import FrozenInstanceError
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'overlay/native'))
import security_recovery_state as S


def node(ino, kind='dir', data=b'', mode=None, nlink=None):
    r = dict(kind=kind, dev=36, ino=ino, mode=(0o755 if kind == 'dir' else 0o644) if mode is None else mode,
             uid=1000, gid=1000, nlink=(2 if kind == 'dir' else 1) if nlink is None else nlink)
    if kind == 'file':
        r.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    return r


def fixture():
    policy = S.RecoveryPolicy('a'*40, 'refs/heads/codex/unbound-recovery-fixture', '9000000000001',
                              ('bin/security', 'share/security-old', 'share/security-new'), 1000, 1000)
    db = {}
    for i in range(349):
        name = 'baseline%03d-1-1' % i
        db[name] = node(1000+3*i)
        db[name+'/desc'] = node(1001+3*i, 'file', b'baseline desc')
        db[name+'/files'] = node(1002+3*i, 'file', b'baseline files')
    baseline = dict(db=db, payload={n: None for n in policy.payload_names}, lock=None)
    interrupted = copy.deepcopy(baseline)
    interrupted['db'][S.NEW] = node(7000, nlink=1)
    interrupted['lock'] = node(8000, 'file', mode=0)
    checkpoint = dict(type='FIRST_UPGRADE_ZERO', phase=S.PHASE, package=S.NAME,
                      pid=286, ppid=7, starttime=123456, event=1, percent=0, howmany=1, current=1,
                      prepared_directory=copy.deepcopy(interrupted['db'][S.NEW]),
                      lock=copy.deepcopy(interrupted['lock']))
    retirement = dict(pid=286, starttime=123456, method='OWNED_PIDFD_INTERRUPT', signal=9,
                      reaped=True, group_absent=True, descendants_absent=True,
                      pid_reserved_until_retirement=True, checkpoint_blocked_until_interrupt=True)
    evidence = dict(protocol=S.PROTOCOL, binding=policy.binding(), baseline_sha256=S.snapshot_sha256(baseline),
                    checkpoint=checkpoint, retirement=retirement)
    return baseline, interrupted, policy, evidence


def recovered_fixture():
    baseline, interrupted, policy, evidence = fixture()
    recovered = copy.deepcopy(baseline)
    recovered['db'].update({S.NEW: node(9000, nlink=1), S.NEW+'/desc': node(9001, 'file', b'candidate desc'),
                            S.NEW+'/files': node(9002, 'file', b'candidate files')})
    recovered['payload']['bin/security'] = node(9100, 'file', b'new executable', 0o755)
    recovered['payload']['share/security-new'] = node(9101, 'file', b'new marker')
    content = lambda r: {k: v for k, v in r.items() if k not in ('dev', 'ino', 'nlink')}
    expected_db = {n: content(r) for n, r in recovered['db'].items() if n == S.NEW or n.startswith(S.NEW+'/')}
    expected_payload = {n: content(r) if r is not None else None for n, r in recovered['payload'].items()}
    return baseline, recovered, policy, expected_db, expected_payload


class RecoveryState(unittest.TestCase):
    def setUp(self):
        self.baseline, self.interrupted, self.policy, self.evidence = fixture()

    def classify(self):
        return S.classify_recovery(self.baseline, self.interrupted, self.policy, self.evidence)

    def refused(self):
        with self.assertRaises(S.RecoveryRefusal):
            self.classify()

    def test_exact_empty_prepared_state_and_cleanup_step_pins(self):
        plan = self.classify()
        self.assertEqual(plan.empty_directory.ino, 7000)
        self.assertEqual(plan.stale_lock.ino, 8000)
        self.assertEqual(plan.interrupted_sha256, S.snapshot_sha256(self.interrupted))
        after_dir = copy.deepcopy(self.interrupted)
        after_dir['db'].pop(S.NEW)
        self.assertEqual(plan.after_directory_sha256, S.snapshot_sha256(after_dir))
        after_dir['lock'] = None
        self.assertEqual(plan.after_unlock_sha256, S.snapshot_sha256(after_dir))
        self.assertEqual(plan.cleanup_order, ('var/lib/pacman/local/'+S.NEW, 'var/lib/pacman/db.lck'))
        with self.assertRaises(FrozenInstanceError):
            plan.status = 'mutated'

    def test_epoch_colon_and_package_at_sign_are_ordinary_names(self):
        for suffix in ('', '/desc', '/files'):
            old, new = 'baseline012-1-1' + suffix, 'less@host-1:690-1' + suffix
            self.baseline['db'][new] = self.baseline['db'].pop(old)
            self.interrupted['db'][new] = self.interrupted['db'].pop(old)
        self.evidence['baseline_sha256'] = S.snapshot_sha256(self.baseline)
        self.assertEqual(self.classify().empty_directory.ino, 7000)

    def test_overlay_directory_nlink_one_is_supported(self):
        self.assertEqual(self.classify().empty_directory.nlink, 1)

    def test_nonempty_prepared_directory_is_not_repairable(self):
        self.interrupted['db'][S.NEW+'/desc'] = node(7001, 'file', b'partial')
        self.refused()

    def test_partial_candidate_payload_is_not_repairable(self):
        self.interrupted['payload']['share/security-new'] = node(7002, 'file', b'partial')
        self.refused()

    def test_surviving_old_payload_is_not_repairable(self):
        self.interrupted['payload']['share/security-old'] = node(7003, 'file', b'old')
        self.refused()

    def test_unrelated_database_drift_is_not_repairable(self):
        self.interrupted['db']['baseline012-1-1/desc']['sha256'] = 'b'*64
        self.refused()

    def test_missing_baseline_database_file_is_not_repairable(self):
        del self.interrupted['db']['baseline012-1-1/files']
        self.refused()

    def test_old_database_remaining_is_not_gnu_recovery(self):
        self.interrupted['db'][S.OLD] = node(7111)
        self.refused()

    def test_baseline_cannot_hide_another_security_version(self):
        for suffix in ('', '/desc', '/files'):
            old, new = 'baseline012-1-1' + suffix, S.NAME + '-0.0.9-1' + suffix
            self.baseline['db'][new] = self.baseline['db'].pop(old)
        self.refused()

    def test_multiple_versions_do_not_count_as_distinct_packages(self):
        for suffix in ('', '/desc', '/files'):
            old, new = 'baseline012-1-1' + suffix, 'baseline011-2-1' + suffix
            self.baseline['db'][new] = self.baseline['db'].pop(old)
            self.interrupted['db'][new] = self.interrupted['db'].pop(old)
        self.evidence['baseline_sha256'] = S.snapshot_sha256(self.baseline)
        self.refused()

    def test_database_epoch_colon_does_not_allow_invalid_git_ref(self):
        policy = S.RecoveryPolicy(self.policy.source, 'refs/heads/codex/recovery:epoch',
                                  self.policy.run, self.policy.payload_names, 1000, 1000)
        self.evidence['binding'] = policy.binding()
        with self.assertRaisesRegex(S.RecoveryRefusal, 'Git ref'):
            S.classify_recovery(self.baseline, self.interrupted, policy, self.evidence)

    def test_lock_inode_replacement_refused(self):
        self.interrupted['lock']['ino'] += 1
        self.refused()

    def test_nonempty_stale_lock_refused(self):
        self.interrupted['lock'].update(bytes=1, sha256=hashlib.sha256(b'x').hexdigest())
        self.evidence['checkpoint']['lock'] = copy.deepcopy(self.interrupted['lock'])
        self.refused()

    def test_nonprivate_lock_mode_refused(self):
        self.interrupted['lock']['mode'] = 0o644
        self.evidence['checkpoint']['lock'] = copy.deepcopy(self.interrupted['lock'])
        self.refused()

    def test_symlink_and_hardlink_metadata_refused(self):
        self.interrupted['lock']['kind'] = 'symlink'
        self.refused()
        self.setUp()
        self.interrupted['lock']['nlink'] = 2
        self.refused()

    def test_boolean_numeric_metadata_refused(self):
        self.interrupted['lock']['dev'] = True
        self.refused()
        self.setUp()
        self.evidence['checkpoint']['event'] = True
        self.refused()

    def test_checkpoint_must_have_blocked_until_owned_interruption(self):
        self.evidence['retirement']['checkpoint_blocked_until_interrupt'] = False
        self.refused()

    def test_live_descendant_or_unreaped_owner_refused(self):
        self.evidence['retirement']['group_absent'] = False
        self.refused()
        self.setUp()
        self.evidence['retirement']['reaped'] = False
        self.refused()

    def test_reused_pid_with_different_starttime_refused(self):
        self.evidence['retirement']['starttime'] += 1
        self.refused()

    def test_normal_end_or_old_protocol_refused(self):
        self.evidence['retirement']['method'] = 'NATURAL_END'
        self.refused()
        self.setUp()
        self.evidence['protocol'] = 'first-real-upgrade-zero-observation-v1'
        self.refused()

    def test_consumed_normal_observation_sources_refused(self):
        for source in S.OLD_OBSERVATION_SOURCES:
            policy = S.RecoveryPolicy(source, self.policy.ref, self.policy.run, self.policy.payload_names, 1000, 1000)
            with self.assertRaises(S.RecoveryRefusal):
                S.classify_recovery(self.baseline, self.interrupted, policy, self.evidence)

    def test_wrong_actual_binding_refused(self):
        self.evidence['binding']['run'] = '9000000000002'
        self.refused()

    def test_missing_payload_union_member_refused(self):
        self.interrupted['payload'].pop('share/security-old')
        self.refused()

    def test_empty_baseline_requires_349_package_directories(self):
        self.baseline['db'] = {}
        self.refused()

    def test_prepared_directory_identity_and_mode_refused(self):
        self.interrupted['db'][S.NEW]['ino'] += 1
        self.refused()
        self.setUp()
        self.interrupted['db'][S.NEW]['mode'] = 0o700
        self.evidence['checkpoint']['prepared_directory'] = copy.deepcopy(self.interrupted['db'][S.NEW])
        self.refused()

    def test_recovered_state_verified_without_cleanup_replay(self):
        args = recovered_fixture()
        result = S.verify_recovered(*args)
        self.assertEqual(result.status, 'VERIFIED_RECOVERED_STATE_DATA_ONLY')
        self.assertFalse(hasattr(result, 'cleanup_order'))
        with self.assertRaises(S.RecoveryRefusal):
            S.classify_recovery(args[0], args[1], args[2], self.evidence)

    def test_recovered_partial_metadata_or_stale_lock_refused(self):
        args = list(recovered_fixture())
        args[1]['lock'] = node(9999, 'file', mode=0)
        with self.assertRaises(S.RecoveryRefusal):
            S.verify_recovered(*args)
        args = list(recovered_fixture())
        args[3].pop(S.NEW+'/files')
        with self.assertRaises(S.RecoveryRefusal):
            S.verify_recovered(*args)

    def test_recovered_metadata_and_payload_content_are_not_assumed(self):
        args = list(recovered_fixture())
        args[1]['db'][S.NEW+'/desc']['sha256'] = 'b'*64
        with self.assertRaises(S.RecoveryRefusal):
            S.verify_recovered(*args)
        args = list(recovered_fixture())
        args[1]['payload']['bin/security']['mode'] = 0o777
        with self.assertRaises(S.RecoveryRefusal):
            S.verify_recovered(*args)

    def test_boolean_expected_content_does_not_equal_integer(self):
        args = list(recovered_fixture())
        args[3][S.NEW]['mode'] = True
        with self.assertRaises(S.RecoveryRefusal):
            S.verify_recovered(*args)


if __name__ == '__main__':
    unittest.main()
