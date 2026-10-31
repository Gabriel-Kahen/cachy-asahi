#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New Security factory and upgrade DATA controls; no package/runtime actors."""
import argparse
import ast
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PARENT = None
SOURCE_ROOTS = []
DENIED = {'subprocess.Popen', 'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn',
          'os.exec', 'os.kill', 'os.killpg', 'socket.__new__', 'socket.connect',
          'socket.bind', 'socket.getaddrinfo', 'socket.gethostbyname'}


def no_actors(event, arguments):
    if event in DENIED:
        raise AssertionError('Security DATA control actor/network forbidden: ' + event)
    if event == 'exec' and arguments:
        filename = getattr(arguments[0], 'co_filename', '')
        if filename and any(Path(filename).is_relative_to(root) for root in SOURCE_ROOTS):
            raise AssertionError('Supplied/emitted Source is DATA, never executable')


sys.addaudithook(no_actors)
spec = importlib.util.spec_from_file_location('security_source_factory', HERE / 'prepare.py')
F = importlib.util.module_from_spec(spec)
# The parent coordinator finishes this maintained module before controls run.
if (HERE / 'prepare.py').exists():
    spec.loader.exec_module(F)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def tree_files(root):
    return {p.relative_to(root).as_posix(): dict(pin(p.read_bytes()), mode=stat.S_IMODE(p.stat().st_mode))
            for p in root.rglob('*') if p.is_file()}


def function(tree, name):
    matches = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(matches) != 1:
        raise AssertionError('one exact function required: ' + name)
    return matches[0]


class Factory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parent = PARENT
        cls.policy = F.profile()
        cls.before = tree_files(cls.parent)
        if len(cls.before) != 200:
            raise AssertionError('the supplied genuine v5 parent must contain exactly200 files')
        SOURCE_ROOTS.append(cls.parent)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='security-factory-data-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.output = self.root / 'candidate'
        SOURCE_ROOTS.append(self.output)
        self.addCleanup(SOURCE_ROOTS.remove, self.output)

    def parent_copy(self):
        root = self.root / 'parent'
        shutil.copytree(self.parent, root)
        SOURCE_ROOTS.append(root)
        self.addCleanup(SOURCE_ROOTS.remove, root)
        return root

    def factory_copy(self):
        root = self.root / 'factory'
        shutil.copytree(HERE, root)
        return root

    def refuses(self, parent=None):
        with self.assertRaises((ValueError, OSError)):
            F.assemble(self.parent if parent is None else parent, self.output)
        self.assertFalse(self.output.exists())

    def emitted_source(self):
        receipt = F.assemble(self.parent, self.output)
        source = self.output / 'source' if (self.output / 'source').is_dir() else self.output
        return receipt, source

    def test_complete_finite_emission_modes_and_null_actuals(self):
        receipt, source = self.emitted_source()
        rows = tree_files(source)
        self.assertEqual(len(rows), 200)
        manifest = json.loads((source / 'native/source-map.json').read_bytes())
        self.assertEqual(manifest['files'], {name: row for name, row in rows.items()
                                            if name != 'native/source-map.json'})
        self.assertEqual(len(manifest['files']), 199)
        self.assertEqual(manifest['actual'], dict(source=None, ref=None, run=None))
        self.assertEqual([name for name, row in rows.items() if row['mode'] == 0o755],
                         [name for name, row in self.before.items() if row['mode'] == 0o755])
        self.assertTrue(all(row['mode'] in (0o644, 0o755) for row in rows.values()))
        self.assertEqual(tree_files(self.parent), self.before)
        self.assertNotIn('PASS_NATIVE', receipt.get('status', ''))
        for value in receipt.get('actual', {}).values():
            self.assertIsNone(value)

    def test_parent_body_mutation_refuses_before_output(self):
        parent = self.parent_copy()
        path = parent / 'native/security_native_v1.py'
        path.write_bytes(path.read_bytes() + b'\n# changed source DATA\n')
        self.refuses(parent)

    def test_parent_mode_mutation_refuses_before_output(self):
        parent = self.parent_copy()
        (parent / 'native/security_native_v1.py').chmod(0o755)
        self.refuses(parent)

    def test_missing_parent_member_refuses_before_output(self):
        parent = self.parent_copy()
        (parent / 'native/security_native_v1.py').unlink()
        self.refuses(parent)

    def test_extra_parent_member_refuses_before_output(self):
        parent = self.parent_copy()
        (parent / 'native/foreign.py').write_bytes(b'raise AssertionError("never execute")\n')
        self.refuses(parent)

    def test_changed_parent_map_refuses_before_output(self):
        parent = self.parent_copy()
        path = parent / 'native/source-map.json'
        value = json.loads(path.read_bytes())
        value['actual']['source'] = '0' * 40
        path.write_text(json.dumps(value))
        self.refuses(parent)

    def test_parent_directory_alias_refuses_before_output(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.parent, target_is_directory=True)
        self.refuses(alias)

    def test_parent_member_alias_refuses_before_output(self):
        parent = self.parent_copy()
        path = parent / 'native/security_native_v1.py'
        path.unlink()
        path.symlink_to(self.parent / 'native/security_native_v1.py')
        self.refuses(parent)

    def test_hardlinked_parent_member_refuses_before_output(self):
        parent = self.parent_copy()
        os.link(parent / 'native/security_native_v1.py', self.root / 'hardlink')
        self.refuses(parent)

    def test_changed_overlay_refuses_before_output(self):
        local = self.factory_copy()
        path = local / 'overlay/native/security_native_v1.py'
        path.write_bytes(path.read_bytes() + b'\n# changed maintained operand\n')
        with patch.object(F, 'HERE', local):
            self.refuses()

    def test_missing_overlay_refuses_before_output(self):
        local = self.factory_copy()
        (local / 'overlay/native/security_reader_v1.py').unlink()
        with patch.object(F, 'HERE', local):
            self.refuses()

    def test_extra_overlay_refuses_before_output(self):
        local = self.factory_copy()
        (local / 'overlay/native/foreign.py').write_bytes(b'INERT DATA\n')
        with patch.object(F, 'HERE', local):
            self.refuses()

    def test_stale_profile_refuses_before_parent_read(self):
        local = self.factory_copy()
        (local / 'profile.json').write_bytes(b'{}\n')
        with patch.object(F, 'HERE', local), self.assertRaisesRegex(ValueError, 'profile'):
            F.assemble(self.root / 'missing-parent', self.output)
        self.assertFalse(self.output.exists())

    def test_existing_output_remains_unchanged(self):
        self.output.mkdir()
        sentinel = self.output / 'caller-data'
        sentinel.write_bytes(b'preserve caller DATA\n')
        with self.assertRaises((ValueError, OSError)):
            F.assemble(self.parent, self.output)
        self.assertEqual(sentinel.read_bytes(), b'preserve caller DATA\n')
        self.assertEqual(list(self.output.iterdir()), [sentinel])

    def test_unique_queue_only_changes_legacy_scheduling_block(self):
        _, source = self.emitted_source()
        aliases = ('.github/workflows/native-arm-build.yml',
                   '.github/workflows/native-arm-developer-workflows.yml')
        left, right = [(source / name).read_bytes() for name in aliases]
        self.assertEqual(left, right)
        before = b'concurrency:\n  group: native-arm-developer-workflows\n  cancel-in-progress: false\njobs:\n'
        after = b'concurrency:\n  group: native-arm-security-maintenance\n  cancel-in-progress: false\n  queue: max\njobs:\n'
        self.assertEqual(left.count(after), 1)
        self.assertNotIn(b'cancel-in-progress: true', left)
        for name in aliases:
            old = (self.parent / name).read_bytes()
            self.assertEqual(old.count(before), 1)
            # The workflow common checksum may be rebound only when common.py changes.
            old_common = hashlib.sha256((self.parent / 'native/common.py').read_bytes()).hexdigest().encode()
            new_common = hashlib.sha256((source / 'native/common.py').read_bytes()).hexdigest().encode()
            restored = (source / name).read_bytes().replace(after, before, 1).replace(new_common, old_common)
            self.assertEqual(restored, old)

    def test_current_main_producer_and_matching_strict_observer(self):
        _, source = self.emitted_source()
        expected = {'bootstrap/scripts/ci/native_arm.py': '8e71ba83e7d5037c6f7772401ec3b872684ccfa8472d855d8d6d3052cb1f41ba',
                    'native/failure_retention.py': 'cdb50b755f3e76d0229278bb89476752702544f3c31947e74676c82b213a8dc7'}
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((source / name).read_bytes()).hexdigest(), digest)
        observer = (source / 'native/failure_retention.py').read_bytes()
        self.assertIn(expected['bootstrap/scripts/ci/native_arm.py'].encode(), observer)
        self.assertNotIn(b'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898', observer)

    def test_original_default_source_guard_and_reader_chain_are_held(self):
        _, source = self.emitted_source()
        self.assertEqual((source / 'native/common.py').read_bytes(),
                         (self.parent / 'native/common.py').read_bytes())
        self.assertIn(b'len(rows) <= 200', (source / 'native/common.py').read_bytes())
        self.assertEqual((source / 'native/reader.py').read_bytes(),
                         (self.parent / 'native/reader.py').read_bytes())
        for leaf in ('native/capsule.py', 'native/transport_proof.py', 'native/retained_transport.py'):
            self.assertEqual((source / leaf).read_bytes(), (self.parent / leaf).read_bytes())


def upgrade_namespace():
    """Execute only maintained passive DATA function AST, never a native entry."""
    tree = ast.parse((HERE / 'overlay/native/security_reader_v1.py').read_text())
    functions = {'_cleanup_require', '_cleanup_pin', 'validate_observation', 'validate_upgrade', 'validate_result'}
    constants = {'UPGRADE_PROTOCOL', 'UPGRADE_FLAGS', 'UPGRADE_STEPS', 'STATUS', 'PAIR', 'LIFECYCLE'}
    selected = [node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name in functions
                or isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in node.targets)]
    def need(condition, message):
        if not condition:
            raise ValueError(message)
    namespace = dict(base64=base64, re=re, pin=pin, need=need, Path=Path,json=json,
                     __file__=str(HERE / 'overlay/native/security_reader_v1.py'))
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<maintained-security-passive-DATA-validators>', 'exec'), namespace)
    return namespace


def observation_controls():
    name='_maintained_security_new_observation_controls'
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,HERE/'test_observation.py')
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return sys.modules[name]


class UpgradeData(unittest.TestCase):
    """Synthetic UNBOUND record-schema controls; no pacman or package simulation."""
    @classmethod
    def setUpClass(cls):
        cls.api = upgrade_namespace()
        cls.observation=staticmethod(observation_controls().fixture)
        cls.contract = json.loads((HERE / 'overlay/native/security-contract-v1.json').read_bytes())['upgrade']
        cls.baseline = (PARENT / 'native/expected349.lock').read_bytes()
        cls.validate = staticmethod(cls.api['validate_upgrade'])

    def data(self):
        # These literal bytes are explicitly a UNIT DATA marker, not an old release
        # or a package. Native archive construction/ALPM never occurs in controls.
        archive = b'UNIT_DATA_ONLY_NOT_A_PACKAGE_OR_NATIVE_RESULT\n'
        empty = pin(b'')
        def record(step):
            negative = {'unknown-key-refusal', 'required-untrusted-install-refusal',
                        'upgrade-signature-refusal', 'decline-upgrade-precommit'}
            return dict(step=step, exit=1 if step in negative else 0,
                        stdout=dict(empty), stderr=dict(empty))
        ordered = ('prior-required-install', 'prior-inventory', 'upgrade-signature-refusal',
                   'refusal-prior-inventory', 'decline-upgrade-precommit', 'declined-prior-inventory',
                   'compile-upgrade-observer', 'required-install', 'installed-inventory', 'repeat-current', 'repeated-inventory',
                   'remove', 'removed-inventory', 'reinstall-current', 'reinstalled-inventory',
                   'remove-reinstalled', 'final-removed-inventory')
        commands = [record('unknown-key-refusal'), record('required-untrusted-install-refusal')]
        commands += [record(name) for name in ordered]
        for name, count in (('prior-owner',27), ('refused-prior-owner',27), ('declined-prior-owner',27),
                            ('candidate-owner',29), ('repeated-owner',29), ('reinstalled-owner',29)):
            commands += [record(name) for _ in range(count)]
        prior = pin(b''.join(sorted(self.baseline.splitlines(keepends=True) +
                                   [b'cachy-asahi-security-maintenance 0.1.0-1\n'])))
        current = pin(b''.join(sorted(self.baseline.splitlines(keepends=True) +
                                     [b'cachy-asahi-security-maintenance 0.1.0-2\n'])))
        inventories = {name: pin(self.baseline) for name in ('baseline', 'removed', 'final')}
        inventories.update({name: dict(prior) for name in ('prior_installed', 'after_refusal', 'after_decline')})
        inventories.update({name: dict(current) for name in ('upgraded', 'repeated', 'reinstalled')})
        payload = {'usr/'+name: {key: row[key] for key in ('bytes','sha256')}
                   for name, row in self.contract['prior_payload_files'].items()}
        payload.update({name: pin(b'UNIT_METADATA_DATA_ONLY') for name in ('.PKGINFO','.BUILDINFO','.MTREE')})
        flags = ('prior_clean_checked', 'prior_installed', 'prior_payload_owned',
                 'tampered_signature_refused', 'declined_precommit_preserved', 'version_upgrade',
                 'candidate_payload_owned', 'old_payload_absent', 'repeat_same_version_reinstalled',
                 'user_data_preserved', 'removed', 'reinstalled', 'final_removed')
        upgrade = dict(schema=1, protocol='signed-prior-to-current-v1', from_version='0.1.0-1',
                       to_version='0.1.0-2', prior_source={name: copy.deepcopy(self.contract['prior_'+name])
                       for name in ('bundle','profile','adapter')}, prior_archive=pin(archive),
                       prior_archive_base64=base64.b64encode(archive).decode(), prior_payload=payload,
                       flags={name: True for name in flags}, inventories=inventories,
                       abort_scope='OPERATOR_DECLINED_BEFORE_COMMIT; NOT_SIGNAL_OR_POWERLOSS',
                       repeat_scope='SAME_VERSION_REINSTALL', upgrade_scope='ONE_PACKAGE_VERSION_TRANSITION_ONLY',
                       decline_input=pin(b'n\n'),observation=self.observation())
        return dict(upgrade=upgrade, commands=commands)

    def refuses(self, data, contract=None, baseline=None):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.validate(data, self.contract if contract is None else contract,
                          self.baseline if baseline is None else baseline)

    def test_unbound_synthetic_upgrade_schema_positive_control_only(self):
        data = self.data()
        self.assertIs(self.validate(data, self.contract, self.baseline), data['upgrade'])

    def test_legacy_report_without_upgrade_refuses(self):
        self.refuses(dict(commands=self.data()['commands']))

    def test_wrong_or_reversed_version_refuses(self):
        for field, value in (('from_version','0.1.0-2'), ('to_version','0.1.0-1')):
            data = self.data(); data['upgrade'][field] = value
            with self.subTest(field=field): self.refuses(data)

    def test_each_upgrade_flag_must_be_exact_true(self):
        for field in self.data()['upgrade']['flags']:
            for value in (False, None, 1):
                data = self.data(); data['upgrade']['flags'][field] = value
                with self.subTest(flag=field, value=value): self.refuses(data)

    def test_upgrade_extra_field_and_missing_field_refuse(self):
        data = self.data(); data['upgrade']['unreviewed'] = True; self.refuses(data)
        data = self.data(); del data['upgrade']['inventories']; self.refuses(data)

    def test_genuine_prior_source_pins_are_mandatory(self):
        for role in ('bundle','profile','adapter'):
            data = self.data(); data['upgrade']['prior_source'][role]['sha256'] = '0'*64
            with self.subTest(role=role): self.refuses(data)

    def test_prior_native_archive_bytes_and_full_payload_pins_bind(self):
        data = self.data(); data['upgrade']['prior_archive']['sha256'] = '0'*64; self.refuses(data)
        data = self.data(); data['upgrade']['prior_archive_base64'] = '!bad'; self.refuses(data)
        data = self.data(); data['upgrade']['prior_archive_base64'] = ''; data['upgrade']['prior_archive'] = pin(b''); self.refuses(data)
        data = self.data(); data['upgrade']['prior_payload']['.BUILDINFO'] = pin(b''); self.refuses(data)
        data = self.data(); del data['upgrade']['prior_payload'][next(iter(data['upgrade']['prior_payload']))]; self.refuses(data)
        data = self.data(); key = next(name for name in data['upgrade']['prior_payload'] if name.startswith('usr/'))
        data['upgrade']['prior_payload'][key]['sha256'] = '0'*64; self.refuses(data)

    def test_all_inventory_transitions_are_required(self):
        for phase in self.data()['upgrade']['inventories']:
            data = self.data(); data['upgrade']['inventories'][phase] = pin(b'wrong inventory\n')
            with self.subTest(phase=phase): self.refuses(data)

    def test_midcommit_or_powerloss_claim_refuses(self):
        data = self.data(); data['upgrade']['abort_scope'] = 'MIDCOMMIT_POWERLOSS_RECOVERY'; self.refuses(data)
        data = self.data(); data['upgrade']['repeat_scope'] = 'VERSION_UPGRADE'; self.refuses(data)
        data = self.data(); data['upgrade']['upgrade_scope'] = 'M9_COMPLETE'; self.refuses(data)
        data = self.data(); data['upgrade']['decline_input'] = pin(b'y\n'); self.refuses(data)

    def test_missing_reordered_or_duplicated_transaction_command_refuses(self):
        for change in ('missing','reorder','duplicate'):
            data = self.data(); rows = data['commands']; index = next(i for i,row in enumerate(rows) if row['step']=='repeat-current')
            if change == 'missing': rows.pop(index)
            elif change == 'reorder': rows[index],rows[index+1] = rows[index+1],rows[index]
            else: rows.insert(index, copy.deepcopy(rows[index]))
            with self.subTest(change=change): self.refuses(data)

    def test_refusal_and_success_exit_semantics_are_required(self):
        for step, code in (('upgrade-signature-refusal',0), ('decline-upgrade-precommit',0),
                           ('required-install',1), ('remove-reinstalled',1),
                           ('upgrade-signature-refusal',2), ('decline-upgrade-precommit',2)):
            data = self.data(); next(row for row in data['commands'] if row['step']==step)['exit'] = code
            with self.subTest(step=step): self.refuses(data)

    def test_each_version_ownership_count_is_required(self):
        for step in ('prior-owner','refused-prior-owner','declined-prior-owner',
                     'candidate-owner','repeated-owner','reinstalled-owner'):
            data = self.data(); index = next(i for i,row in enumerate(data['commands']) if row['step']==step); data['commands'].pop(index)
            with self.subTest(step=step): self.refuses(data)

    def test_full_positive_result_validator_requires_upgrade(self):
        archive = b'UNIT_CURRENT_ARCHIVE_DATA_ONLY'
        value = dict(status=self.api['STATUS'], architecture='aarch64', source_map_sha256='1'*64,
                     packages=pin(self.baseline), physical_M2='NOT_RUN', native_16K='NOT_QUALIFIED',
                     release='NOT_ADMITTED', remediation='NOT_ESTABLISHED',
                     pair=dict(archive_equal=True,payload_equal=True,buildinfo_equal=True,pkginfo_equal=True,
                               checks='ORIGINAL_CHECK_BOTH',one=pin(archive),two=pin(archive),
                               archives={label:base64.b64encode(archive).decode() for label in ('one','two')}),
                     lifecycle={name:True for name in self.api['LIFECYCLE']},
                     workflows=dict(installed='PASS_OFFLINE_SECURITY_WORKFLOWS',moved='PASS_OFFLINE_SECURITY_WORKFLOWS'))
        self.api['read'] = lambda path: self.baseline
        self.api['load'] = lambda path: dict(upgrade=self.contract)
        with self.assertRaisesRegex(ValueError, 'upgrade'):
            self.api['validate_result'](value,'1'*64,pin(self.baseline))

    def test_real_prior_recipe_pins_and_three_checked_stage_contract(self):
        self.assertEqual(self.contract['from_version'],'0.1.0-1')
        self.assertEqual(self.contract['to_version'],'0.1.0-2')
        self.assertEqual(self.contract['prior_bundle'],dict(bytes=419840,sha256='07cff9cd5929500466b894a47e71e7658f0fecb2346d8c84a30b017d45a86918'))
        self.assertEqual(self.contract['prior_profile'],dict(bytes=5149,sha256='ec01a83c444e045ded65c598fbc33a8a53bb6c2793fff3e98c1e38ee71f64c88'))
        self.assertEqual(self.contract['prior_adapter'],dict(bytes=10373,sha256='359c9c7fe80399f1cd640c59d8d5d095eb87febcd9f664e82bd76ef71c1e05ec'))
        self.assertEqual(pin(base64.b64decode(self.contract['prior_bundle_base64'],validate=True)),self.contract['prior_bundle'])
        self.assertEqual(pin(base64.b64decode(self.contract['prior_profile_base64'],validate=True)),self.contract['prior_profile'])
        recipe_pin = dict(bytes=5885,mode=420,sha256='449832932b43091117aff02fc513659c03780038c96b28dd3b99a9db5c134c9c')
        self.assertEqual(self.contract['prior_recipe_files']['PKGBUILD'],recipe_pin)
        profile = json.loads(base64.b64decode(self.contract['prior_profile_base64'],validate=True))
        self.assertEqual(profile['files']['PKGBUILD'],recipe_pin)
        with tarfile.open(fileobj=io.BytesIO(base64.b64decode(self.contract['prior_bundle_base64'],validate=True)),mode='r:') as archive:
            info = archive.getmember('recipe/PKGBUILD')
            recipe = archive.extractfile(info).read()
        self.assertEqual(pin(recipe),{key:recipe_pin[key] for key in ('bytes','sha256')})
        self.assertIn(b'pkgver=0.1.0',recipe)
        self.assertIn(b'pkgrel=1',recipe)
        native = ast.parse((HERE/'overlay/native/security_native_v1.py').read_text())
        body = ast.get_source_segment((HERE/'overlay/native/security_native_v1.py').read_text(),function(native,'dockerfile'))
        self.assertIn("for label in ('one','two'):",body)
        self.assertIn('AS security-prior-build',body)
        self.assertEqual(body.count('makepkg --check --cleanbuild --nosign --noconfirm'),2)
        self.assertNotIn('--nocheck',body)
        self.assertEqual(len(self.contract['prior_payload_files']),27)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-source', type=Path, required=True)
    parser.add_argument('--results', type=Path)
    args = parser.parse_args()
    PARENT = args.parent_source.absolute()
    if not PARENT.is_dir() or PARENT != PARENT.resolve():
        parser.error('--parent-source must be an ordinary exact local Source directory')
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(observation_controls()))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if args.results:
        report = dict(status='PASS_NEW_ACTOR_DENIED_FACTORY_PROTOCOL_DATA_CONTROLS_ONLY' if result.wasSuccessful() else 'FAIL_NEW_FACTORY_PROTOCOL_DATA_CONTROLS',
                      controls=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                      parent_source=str(PARENT), tests=[cls.__name__+'.'+name for cls in (Factory, UpgradeData) for name in unittest.defaultTestLoader.getTestCaseNames(cls)],
                      audit_denied_events=sorted(DENIED), native_GPG_VM_Source_actors=0, network_requests=0,
                      old_suite_replays=0, real_package_builds=0, mocked_pacman=False, Root_acceptance=None)
        with args.results.open('x') as stream:
            json.dump(report, stream, sort_keys=True, indent=2); stream.write('\n')
    raise SystemExit(not result.wasSuccessful())
