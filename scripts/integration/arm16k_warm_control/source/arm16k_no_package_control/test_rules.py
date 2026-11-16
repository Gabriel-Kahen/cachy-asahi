# SPDX-License-Identifier: MIT
"""Bounded policy models only: no raw images, private bodies or actor entry."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def module(name, directory=HERE):
    spec = importlib.util.spec_from_file_location('no_package_rules_'+name, directory/(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


R = module('rules')


def row(kind='d', mode=0o755):
    return dict(kind=kind, mode=mode, uid=0, gid=0)


def projection(rollback=False, absent=False):
    old = '/'+R.DB+'/perl-5.40.2-1'
    return dict(candidate_namespace={'/usr': row(), '/usr/bin': row(), '/usr/bin/perl': row('f')},
        baseline_namespace={'/usr': row(), '/etc': row(), '/etc/profile.d': row(),
            '/etc/profile.d/perlbin.sh': row('f', 0o644)} if rollback else {},
        dependency_transaction={},
        restoration_allowances=dict(install_date_path=old+'/desc' if rollback else None,
            database_timestamp_paths=['/'+R.DB]+([old, old+'/desc', old+'/files'] if rollback else []),
            payload_directory_timestamps=True, normal_pacman_log='/'+R.LOG,
            pacman_log_before=None if absent else dict(bytes=1, sha256='a'*64),
            cache_directory_timestamps=['/var/cache', '/var/cache/ldconfig']))


def inventory(rollback=False):
    return dict(model='1', **({'perl': '5.40.2-1'} if rollback else {}))


class Rules(unittest.TestCase):
    def test_exact_public_directory_sets_do_not_include_var_or_implicit_ancestors(self):
        p = projection()
        p['candidate_namespace']['/usr/share/model'] = row()
        result = R.review_policy(p, inventory())
        self.assertEqual(result['eligible_directory_timestamp_paths'],
            ['usr', 'usr/bin', 'usr/share/model', 'var/cache', 'var/cache/ldconfig', R.DB])
        self.assertNotIn('var', result['eligible_directory_timestamp_paths'])
        self.assertNotIn('usr/share', result['eligible_directory_timestamp_paths'])
        self.assertEqual(result['fixture_directory_timestamp_prefix'], R.DATA)
        self.assertFalse(result['control_acceptance_waiver'])

    def test_rollback_and_absent_log_paths_are_exact(self):
        p = projection(rollback=True, absent=True)
        p['dependency_transaction'] = dict(namespace={'/usr/lib/model': row()})
        result = R.review_policy(p, inventory(True))
        old = R.DB+'/perl-5.40.2-1'
        self.assertEqual(result['database_timestamp_paths'], [R.DB, old, old+'/desc', old+'/files'])
        self.assertEqual(result['install_date']['path'], old+'/desc')
        self.assertTrue(result['normal_log']['initially_absent'])
        self.assertEqual(result['normal_log']['absent_baseline_receipt'],
            dict(path=R.DATA+'receipts/pacman-log-after', type='file', mode=0o600, uid=0, gid=0,
                 nonempty=True, exact_size_and_sha256=True))
        self.assertEqual(result['normal_log']['final_existing_shape']['forbidden_mode_bits'], 0o6002)
        self.assertEqual(result['directory_timestamp_paths_require_before_type'], 'directory')
        self.assertEqual(result['nondirectory_timestamp_normalization_exact'],
            [R.DB, old, old+'/desc', old+'/files', R.LOG])
        self.assertTrue({'etc', 'etc/profile.d', 'usr/lib/model', 'var/log'} <= set(result['eligible_directory_timestamp_paths']))
        self.assertNotIn('var/lib', result['eligible_directory_timestamp_paths'])
        self.assertNotIn('etc/profile.d/perlbin.sh', result['eligible_directory_timestamp_paths'])

    def test_comparison_counts_include_owned_private_keys_without_export(self):
        before = ['root', 'root/MODEL_PRIVATE_NAME', 'home/builder', 'home/builder/MODEL_PRIVATE_NAME',
            'etc', 'etc/public-model', R.DB, R.DATA+'trust', R.DATA+'receipts/model',
            R.LOG, 'usr/model', 'var', 'var/MODEL_PRIVATE_NAME']
        owned = ['usr/model', 'var']
        result = R.review_policy(projection(), inventory(), owned, before)
        compared = result['compared']
        self.assertEqual((compared['owned_paths'], compared['before_paths'], compared['union_paths'],
            compared['second_loop_paths']), (2, 13, 11, 10))
        self.assertNotIn('MODEL_PRIVATE_NAME', json.dumps(result))
        self.assertEqual(compared['prefixes'], list(R.COMPARE_PREFIXES))
        self.assertNotIn('etc', compared['exact'])
        self.assertEqual(compared['second_loop_skip_exact'], R.DATA+'trust')

    def test_exact_residue_prefixes_have_literal_bare_name_quirk(self):
        result = R.review_policy(projection(), inventory())
        denied = tuple(result['residue']['denied_new_prefixes'])
        for prefix in ('root/', 'home/builder/', 'usr/', 'etc/', R.DB+'/', 'var/log/'):
            self.assertIn(prefix, denied)
            self.assertTrue((prefix+'model').startswith(denied))
            self.assertFalse(prefix[:-1].startswith(denied))
        self.assertFalse(('var/model').startswith(denied))
        self.assertFalse(result['residue']['bare_prefix_names_denied_by_this_loop'])

    def test_strict_root_and_etc_gates_keep_inode_links_and_mtime(self):
        gates = R.review_policy(projection(), inventory())['strict_parents']
        self.assertEqual(gates['paths'], ['etc', 'etc/audit', 'etc/udev', 'root'])
        self.assertEqual(gates['fields'], list(R.STRICT_FIELDS))
        self.assertEqual(gates['final_absent_paths'], list(R.ABSENCES)+['root/.ssh'])
        self.assertTrue(gates['absence_includes_descendants'])

    def test_all_namespace_roles_reject_nonpublic_directory_waivers(self):
        for role in ('candidate_namespace', 'baseline_namespace', 'dependency_transaction'):
            for name in ('/var', '/root', '/etc/audit', '/usr/local/model', '/usr/..model'):
                with self.subTest(role=role, name=name):
                    p = projection(rollback=role == 'baseline_namespace')
                    target = p[role] if role != 'dependency_transaction' else {}
                    target[name] = row()
                    if role == 'dependency_transaction':
                        p[role] = dict(namespace=target)
                    with self.assertRaises(ValueError):
                        R.review_policy(p, inventory(role == 'baseline_namespace'))

    def test_baseline_exact_etc_classes_are_not_general_etc_permission(self):
        for name, kind in (('/etc', 'f'), ('/etc/profile.d', 'f'), ('/etc/profile.d/perlbin.sh', 'd')):
            p = projection(True)
            p['baseline_namespace'][name] = row(kind)
            with self.assertRaises(ValueError):
                R.review_policy(p, inventory(True))
        for role in ('candidate_namespace', 'dependency_transaction'):
            p = projection()
            if role == 'candidate_namespace':
                p[role]['/etc'] = row()
            else:
                p[role] = dict(namespace={'/etc': row()})
            with self.assertRaises(ValueError):
                R.review_policy(p, inventory())

    def test_namespace_metadata_classes_and_unknown_fields_are_bounded(self):
        for bad in (dict(mode=True), dict(mode=0o4775), dict(mode=0o777), dict(uid=1),
                    dict(gid=False), dict(kind='directory'), dict(body='MODEL_NEVER_READ')):
            p = projection()
            p['candidate_namespace']['/usr'].update(bad)
            with self.assertRaises(ValueError):
                R.review_policy(p, inventory())
        p = projection()
        p['candidate_namespace']['/usr/model-link'] = row('l', 0o777)
        self.assertNotIn('usr/model-link', R.review_policy(p, inventory())['eligible_directory_timestamp_paths'])

    def test_allowance_fields_cannot_add_waivers_or_coerce_types(self):
        changes = [dict(cache_directory_timestamps=['/var']), dict(database_timestamp_paths=['/'+R.DB, '/var']),
            dict(normal_pacman_log='/var/log/model'), dict(install_date_path='/etc/model'),
            dict(payload_directory_timestamps=1), dict(extra=True),
            dict(pacman_log_before=dict(bytes=True, sha256='a'*64))]
        for bad in changes:
            p = projection()
            p['restoration_allowances'].update(bad)
            with self.assertRaises(ValueError):
                R.review_policy(p, inventory())

    def test_projection_and_key_input_limits_do_not_echo_private_names(self):
        p = projection()
        p['MODEL_PRIVATE_NAME'] = True
        with self.assertRaisesRegex(ValueError, '^exact policy projection keys required$'):
            R.review_policy(p, inventory())
        for keys in (['root/../MODEL_PRIVATE_NAME'], ['root/MODEL_PRIVATE_NAME']*2,
                     ['root/'+'x'*4097], ['root/\x00MODEL_PRIVATE_NAME'], [True],
                     ['public']*(R.MAX_PATHS+1)):
            with self.assertRaises(ValueError) as caught:
                R.review_policy(projection(), inventory(), (), keys)
            self.assertNotIn('MODEL_PRIVATE_NAME', str(caught.exception))
        with self.assertRaises(ValueError):
            R.review_policy(projection(), inventory(), ['root/model'], [])

    def test_inventory_namespace_join_and_safe_version_are_required(self):
        for p, inv in ((projection(), inventory(True)), (projection(True), inventory()),
                       (projection(), {}), (projection(True), dict(perl='MODEL/PRIVATE_VERSION'))):
            with self.assertRaises(ValueError):
                R.review_policy(p, inv)

    def test_review_does_not_mutate_supplied_metadata(self):
        p, inv = projection(True), inventory(True)
        original = copy.deepcopy((p, inv))
        R.review_policy(p, inv, ['var'], ['root', 'var'])
        self.assertEqual((p, inv), original)


class ActualSource65ImagePolicy(unittest.TestCase):
    """Exercise unchanged repository image.preserve on wholly owned MODEL data."""
    @classmethod
    def setUpClass(cls):
        cls.image = module('image', HERE.parent/'arm16k_perl5423_vm')

    def model(self):
        log = b'public MODEL log\n'
        p = projection()
        p['restoration_allowances']['pacman_log_before'] = dict(bytes=len(log), sha256=hashlib.sha256(log).hexdigest())
        records = {R.DB+'/model-1/desc': '%NAME%\nmodel\n\n%VERSION%\n1\n\n',
            R.DB+'/model-1/files': '%FILES%\nusr/\nusr/bin/\nusr/share/\nvar/\nvar/log/\n\n'}
        nodes = {name: dict(type='directory', mode=0o755, uid=0, gid=0, xattrs={}, mtime=10, mtime_ns=0)
                 for name in ('usr', 'usr/bin', 'usr/share', 'var', 'var/log', R.DB)}
        for name, body in dict(records, **{R.LOG: log.decode()}).items():
            nodes[name] = dict(type='file', mode=0o644, uid=0, gid=0, xattrs={}, mtime=10, mtime_ns=0,
                size=len(body.encode()), sha256=hashlib.sha256(body.encode()).hexdigest())
        before = dict(nodes=nodes, records=records, log_data_b64=base64.b64encode(log).decode())
        return p, before, copy.deepcopy(before)

    def test_owned_var_timestamp_drift_fails_actual_source65(self):
        p, before, after = self.model()
        self.image.preserve(before, after, inventory(), p)
        after['nodes']['var'].update(mtime=11, mtime_ns=1)
        with self.assertRaisesRegex(ValueError, 'unrelated baseline timestamp drift: var$'):
            self.image.preserve(before, after, inventory(), p)
        self.assertNotIn('var', R.review_policy(p, inventory())['eligible_directory_timestamp_paths'])

    def test_declared_directory_passes_but_undeclared_parent_fails(self):
        p, before, after = self.model()
        after['nodes']['usr/bin']['mtime_ns'] = 1
        result = self.image.preserve(before, after, inventory(), p)
        self.assertEqual(result['normal_timestamp_differences'], ['usr/bin'])
        p['candidate_namespace']['/usr/share/model'] = row()
        after['nodes']['usr/share']['mtime_ns'] = 1
        with self.assertRaisesRegex(ValueError, 'unrelated baseline timestamp drift: usr/share$'):
            self.image.preserve(before, after, inventory(), p)

    def test_actual_new_residue_rule_is_a_literal_prefix_not_global_equality(self):
        p, before, after = self.model()
        for allowed in ('etc', 'var/public-model'):
            after['nodes'][allowed] = dict(type='directory')
        self.image.preserve(before, after, inventory(), p)
        after['nodes']['etc/public-model'] = dict(type='directory')
        with self.assertRaisesRegex(ValueError, 'unreviewed user/payload/database/log residue'):
            self.image.preserve(before, after, inventory(), p)


if __name__ == '__main__':
    unittest.main(verbosity=2)
