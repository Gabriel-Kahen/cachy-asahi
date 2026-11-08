#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic DATA maps and hostile scratch metadata; no Source constructor."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('source_v2_factory', HERE / 'assemble_source_v2.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def descriptors(files):
    return m.descriptors(files)


def fixture():
    """No genuine Source or native body is read; all source bodies are inert."""
    parent = {name: (('INERT_PARENT:' + name).encode(), 0o644) for name in m.SEAMS}
    parent['native/source_tools_reader_v1.py'] = (b'INERT_FROZEN_V1_READER\n', 0o644)
    parent['native/source-tools-contract-v1.json'] = (b'INERT_FROZEN_V1_CONTRACT\n', 0o644)
    common = b'# SYNTHETIC COMMON DATA\n    '+m.COMMON_BEFORE+b'\n'
    parent['native/common.py'] = (common, 0o644)
    before_invocation = dict(actual=dict(source=None, ref=None, run=None), argv=['INERT'],
        operations={'default': 'source184', 'source-tools-alpm-v1': dict(actual=dict(source=None, ref=None, run=None),
            argv_extra=['--operation', 'source-tools-alpm-v1'], matching_reader='native/source_tools_reader_v1.py',
            prerequisite='HELD')})
    parent['native/invocation.json'] = (m.encoded(before_invocation), 0o644)
    before_workflow = (b'on:\n  workflow_dispatch:\n    inputs:\n      operation:\n'
        b'        options: [source184, source-tools-alpm-v1]\nconcurrency:\n'
        b'  group: native-arm-source-tools\n  cancel-in-progress: false\n  queue: max\n'
        b'jobs:\n  native:\n    timeout-minutes: 135\nproof: '+m.pin(common)['sha256'].encode()+b' native/common.py\n')
    for name in m.WORKFLOWS: parent[name] = (before_workflow, 0o644)
    while len(parent) < 200:
        name = 'held/file-%03d.data' % len(parent)
        parent[name] = (('INERT_HELD:' + name).encode(), 0o644)
    parent[m.MAP] = (m.encoded(dict(schema=1, actual=dict(source=None, ref=None, run=None),
        files={name: row for name, row in descriptors(parent).items() if name != m.MAP})), 0o644)
    overlay = {name: (('INERT_V2:' + name).encode(), 0o644) for name in m.ADDITIONS}
    overlay['native/owner.py'] = (b'INERT_OWNER_V2\n', 0o644)
    overlay['native/common.py'] = (common.replace(m.COMMON_BEFORE, m.COMMON_AFTER, 1), 0o644)
    invocation = copy.deepcopy(before_invocation)
    invocation['operations'][m.OPERATION] = dict(actual=dict(source=None, ref=None, run=None),
        argv_extra=['--operation', m.OPERATION], matching_reader='native/source_tools_reader_v2.py',
        prerequisite='ROOT_GENUINE_CLASSIFICATION_BEFORE_DISPATCH')
    overlay['native/invocation.json'] = (m.encoded(invocation), 0o644)
    for name in m.WORKFLOWS:
        overlay[name] = (before_workflow.replace(b'[source184, source-tools-alpm-v1]',
            b'[source184, source-tools-alpm-v1, source-tools-alpm-v2]').replace(
                m.pin(common)['sha256'].encode(),m.pin(overlay['native/common.py'][0])['sha256'].encode()), 0o644)
    recipe = {name: ('INERT_RECIPE:' + name).encode() for name in m.RECIPE_FILES}
    payload = {'usr/bin/cachy-asahi-source-tools': dict(**m.pin(recipe['cachy-asahi-source-tools']), mode=0o755),
        'usr/lib/cachy-asahi/source-tools/scripts/release/source_mirror_catalog.py':
            dict(**m.pin(recipe['source_mirror_catalog.py']), mode=0o644)}
    while len(payload) < 17:
        payload['usr/share/inert-%02d.data' % len(payload)] = dict(**m.pin(b'INERT'), mode=0o644)
    own = 'usr/share/doc/cachy-asahi-source-tools/payload-map.json'
    recipe['payload-map.json'] = m.encoded(dict(schema_version=1, package='cachy-asahi-source-tools', self=own, files=payload))
    payload = {**payload, own: dict(**m.pin(recipe['payload-map.json']), mode=0o644)}
    pins = {name: dict(**m.pin(raw), mode=0o755 if name == 'cachy-asahi-source-tools' else 0o644)
            for name, raw in recipe.items()}
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(recipe):
            node = tarfile.TarInfo('recipe/' + name); node.mode = pins[name]['mode']; node.size = len(recipe[name])
            archive.addfile(node, io.BytesIO(recipe[name]))
    bundle = buffer.getvalue(); overlay['native/source-tools-sources-v2.tar'] = (bundle, 0o644)
    config = b"CARCH='aarch64'\nBUILDENV=(!distcc !color !ccache check !sign)\n"
    overlay['native/source-tools-makepkg-v2.conf'] = (config, 0o644)
    selection = dict(schema=2, purpose='source-tools-current-recipe-selection',
        package=dict(name='cachy-asahi-source-tools', version='0.2.0-1', arch='any', license='MIT'),
        recipe=dict(sources=sorted(m.RECIPE_FILES-{'PKGBUILD', '.SRCINFO'}), files=pins, payload_files=payload),
        checks=dict(m.CHECKS))
    contract = dict(schema=1, operation=m.OPERATION, actual=dict(source=None, ref=None, run=None, job=None, artifact=None),
        recipe=dict(version='0.2.0-1', archive='cachy-asahi-source-tools-0.2.0-1-any.pkg.tar.zst',
            expected_test_count=28, source_files=pins, payload_files=payload), checks=dict(m.CHECKS),
        current_recipe_selection=selection,
        bundle=dict(path='native/source-tools-sources-v2.tar', members=16, max_bytes=1024**2, **m.pin(bundle)),
        makepkg_config=dict(path='native/source-tools-makepkg-v2.conf', **m.pin(config)))
    for field, name in (('current_package_module', 'native/source_tools_current_package_v2.py'),
                        ('current_check_module', 'native/source_tools_current_check_v2.py')):
        contract[field] = dict(path=name, **m.pin(overlay[name][0]))
    overlay['native/source-tools-contract-v2.json'] = (m.encoded(contract), 0o644)
    value = dict(schema=1, purpose='source-tools-current-native-overlay-v2', genuine_parent=m.GENUINE_PARENT,
        parent_tree=m.tree(parent), parent_files=descriptors(parent), overlay={}, source_map_sha256='',
        prospective_tree='', operation=m.OPERATION, actual=dict(source=None, ref=None, run=None),
        main_base='1'*40, source_files=212)
    finalize(parent, overlay, value)
    constants = dict(PARENT_TREE=m.tree(parent), PARENT_MAP_SHA256=m.pin(parent[m.MAP][0])['sha256'],
        PRIVATE_SHA256=pins['private-source.tar.gz']['sha256'], PROVENANCE_SHA256=pins['source-provenance.json']['sha256'])
    return parent, overlay, value, constants


def finalize(parent, overlay, value):
    producers = dict(schema=1, purpose='source-tools-current-producer-pins',
        files={name: dict(**m.pin(overlay[name][0]), mode=overlay[name][1]) for name in m.PRODUCERS})
    overlay['native/source-tools-producers-v2.json'] = (m.encoded(producers), 0o644)
    final = {**parent, **overlay}
    final[m.MAP] = (m.encoded(dict(schema=1, source_tools_operation=m.OPERATION, actual=dict(source=None, ref=None, run=None),
        files={name: row for name, row in descriptors(final).items() if name != m.MAP})), 0o644)
    overlay[m.MAP] = final[m.MAP]
    value.update(overlay=descriptors(overlay), source_map_sha256=m.pin(final[m.MAP][0])['sha256'],
        prospective_tree=m.tree(final))


class FactoryDataControls(unittest.TestCase):
    def setUp(self):
        self.parent, self.overlay, self.value, constants = fixture()
        for name, value in constants.items():
            patched = patch.object(m, name, value); patched.start(); self.addCleanup(patched.stop)
        for name in ('assemble', 'publish'):
            patched = patch.object(m, name, side_effect=AssertionError('genuine constructor forbidden in DATA controls'))
            guard = patched.start(); self.addCleanup(patched.stop); self.addCleanup(guard.assert_not_called)

    def policy(self):
        raw = m.encoded(self.value)
        return m.profile(raw, m.pin(raw)['sha256'])

    def refused(self, refresh=False):
        if refresh: finalize(self.parent, self.overlay, self.value)
        with self.assertRaises((ValueError, KeyError, TypeError, tarfile.TarError)):
            m.validate_delta(self.parent, self.overlay, self.policy())

    def change_contract(self, change):
        name = 'native/source-tools-contract-v2.json'; value = m.decode(self.overlay[name][0])
        change(value); self.overlay[name] = (m.encoded(value), 0o644)

    def test_synthetic_profile_and_pure_delta_preserve_all_v1_rows(self):
        final = m.validate_delta(self.parent, self.overlay, self.policy())
        self.assertEqual(len(final), 212)
        self.assertEqual(len(m.decode(final[m.MAP][0])['files']), 211)
        self.assertTrue(all(final[name] == row for name, row in self.parent.items() if name not in m.SEAMS))
        self.assertEqual(final['native/source_tools_reader_v1.py'], self.parent['native/source_tools_reader_v1.py'])

    def test_profile_pin_schema_counts_and_actual_selector_refuse(self):
        raw = m.encoded(self.value)
        with self.assertRaises(ValueError):m.profile(raw, '0'*64)
        for key, value in (('schema', True), ('source_files', 211), ('actual', dict(source='forbidden', ref=None, run=None)),
                           ('operation', 'source-tools-alpm-v1'), ('main_base', 'not-a-sha')):
            original = self.value[key]; self.value[key] = value
            with self.assertRaises(ValueError):self.policy()
            self.value[key] = original

    def test_profile_closed_overlay_namespace_and_typed_rows_refuse(self):
        self.value['overlay']['native/unlisted.py'] = self.value['overlay'].pop('native/source_tools_reader_v2.py')
        with self.assertRaises(ValueError):self.policy()
        self.value['overlay'] = descriptors(self.overlay)
        self.value['overlay']['native/owner.py']['bytes'] = True
        with self.assertRaises(ValueError):self.policy()

    def test_retained_raw_commit_requires_exact_body_and_single_tree(self):
        raw = (b'tree '+m.PARENT_TREE.encode()+b'\nparent '+b'2'*40+
            b'\nauthor Synthetic <synthetic@invalid> 1 +0000\ncommitter Synthetic <synthetic@invalid> 1 +0000\n\nINERT\n')
        with patch.object(m, 'GENUINE_PARENT', m.oid(b'commit',raw).hex()):
            m.parent_commit(raw)
            with self.assertRaises(ValueError):m.parent_commit(raw+b'changed')
        duplicate=raw.replace(b'\nparent ',b'\ntree '+m.PARENT_TREE.encode()+b'\nparent ',1)
        with patch.object(m,'GENUINE_PARENT',m.oid(b'commit',duplicate).hex()):
            with self.assertRaises(ValueError):m.parent_commit(duplicate)

    def test_genuine_parent_body_or_mode_change_refuses(self):
        self.parent['native/source_tools_reader_v1.py'] = (b'CHANGED', 0o644);self.refused()

    def test_v1_path_cannot_be_added_to_overlay(self):
        self.overlay['native/source_tools_reader_v1.py'] = (b'CHANGED', 0o644)
        self.value['overlay'] = descriptors(self.overlay)
        with self.assertRaises(ValueError):self.policy()

    def test_changed_overlay_or_missing_addition_refuses(self):
        self.overlay['native/source_tools_guest_v2.py'] = (b'CHANGED', 0o644);self.refused()
        self.overlay.pop('native/source_tools_guest_v2.py');self.refused()

    def test_final_map_extra_row_and_false_actual_refuse(self):
        raw = m.decode(self.overlay[m.MAP][0]);raw['actual']['run'] = 'forbidden'
        self.overlay[m.MAP] = (m.encoded(raw), 0o644)
        self.value['overlay'] = descriptors(self.overlay)
        self.value['source_map_sha256'] = m.pin(self.overlay[m.MAP][0])['sha256']
        self.refused()

    def test_stale_contract_and_waived_current_checks_refuse_after_repinning(self):
        for change in (lambda v:v['recipe'].update(version='0.1.0-1'),
                       lambda v:v['recipe'].update(expected_test_count=17),
                       lambda v:v['checks'].update(catalog_tests=0),
                       lambda v:v['actual'].update(source='forbidden')):
            parent, overlay, value, _ = fixture()
            self.parent, self.overlay, self.value = parent, overlay, value
            self.change_contract(change);self.refused(refresh=True)

    def test_noncanonical_or_incomplete_recipe_bundle_refuses_after_repinning(self):
        name = 'native/source-tools-sources-v2.tar';raw = self.overlay[name][0]+b'EXTRA'
        self.overlay[name] = (raw, 0o644)
        self.change_contract(lambda value:value['bundle'].update(m.pin(raw)))
        self.refused(refresh=True)

    def test_exact_nine_producer_map_excludes_self_reader_and_projection(self):
        final = m.validate_delta(self.parent, self.overlay, self.policy())
        value = m.decode(final['native/source-tools-producers-v2.json'][0])
        self.assertEqual(set(value['files']), m.PRODUCERS)
        self.assertEqual(len(value['files']), 9)
        name = 'native/source-tools-producers-v2.json'
        value['files']['native/source_tools_reader_v2.py'] = dict(**m.pin(b'bad'), mode=0o644)
        self.overlay[name] = (m.encoded(value), 0o644)
        self.value.update(overlay=descriptors(self.overlay))
        final = {**self.parent, **self.overlay};final[m.MAP] = (m.encoded(dict(schema=1,source_tools_operation=m.OPERATION,
            actual=dict(source=None, ref=None, run=None),files={n:r for n,r in descriptors(final).items() if n!=m.MAP})),0o644)
        self.overlay[m.MAP] = final[m.MAP];self.value.update(overlay=descriptors(self.overlay),
            source_map_sha256=m.pin(final[m.MAP][0])['sha256'],prospective_tree=m.tree(final))
        self.refused()

    def test_workflow_group_cap_or_other_byte_change_refuses(self):
        for name in m.WORKFLOWS:
            self.overlay[name] = (self.overlay[name][0].replace(b'timeout-minutes: 135', b'timeout-minutes: 136'),0o644)
        self.refused(refresh=True)

    def test_only_explicit_v2_uses_exact211_and_legacy_cap200_stays_strict(self):
        for count in (0,1,199,200):
            m.check_row_bound(dict(files={'row%d'%n:None for n in range(count)}))
        for marker in (None,'source-tools-alpm-v1','source-tools-alpm-v3'):
            with self.assertRaises(ValueError):
                m.check_row_bound(dict(source_tools_operation=marker,files={'row%d'%n:None for n in range(201)}))
        for count in (0,199,200,210,212,256):
            with self.assertRaises(ValueError):
                m.check_row_bound(dict(source_tools_operation=m.OPERATION,files={'row%d'%n:None for n in range(count)}))
        m.check_row_bound(dict(source_tools_operation=m.OPERATION,files={'row%d'%n:None for n in range(211)}))

    def test_common_generalized_cap_raise_or_unrelated_change_refuses(self):
        common,mode=self.overlay['native/common.py']
        self.overlay['native/common.py']=(common.replace(b'else len(rows) <= 200',b'else len(rows) <= 211'),mode)
        for name in m.WORKFLOWS:
            raw,mode=self.overlay[name]
            self.overlay[name]=(raw.replace(m.pin(common)['sha256'].encode(),
                m.pin(self.overlay['native/common.py'][0])['sha256'].encode()),mode)
        self.refused(refresh=True)

    def test_v1_invocation_change_or_nonnull_v2_route_refuses(self):
        name = 'native/invocation.json';value = m.decode(self.overlay[name][0])
        value['operations']['source-tools-alpm-v1']['prerequisite'] = 'CHANGED'
        self.overlay[name] = (m.encoded(value),0o644);self.refused(refresh=True)

    def test_duplicate_json_keys_and_noninteger_profile_json_refuse(self):
        for raw in (b'{"schema":1,"schema":1}',b'{"schema":NaN}',b'{"schema":1.0}'):
            with self.assertRaises(ValueError):m.decode(raw)

    def test_scratch_snapshot_private_modes_and_ordinary_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);path = root/'input.data';path.write_bytes(b'INERT');path.chmod(0o600)
            self.assertEqual(m.snapshot(root), {'input.data':(b'INERT',0o644)})
            path.chmod(0o700);self.assertEqual(m.snapshot(root), {'input.data':(b'INERT',0o755)})

    def test_scratch_symlinks_hardlinks_empty_dirs_and_special_files_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);target=root/'file';target.write_bytes(b'INERT');target.chmod(0o644)
            link=root/'link';link.symlink_to(target)
            with self.assertRaises((ValueError,OSError)):m.snapshot(root)
            link.unlink();os.link(target,link)
            with self.assertRaises(ValueError):m.snapshot(root)
            link.unlink();empty=root/'empty';empty.mkdir()
            with self.assertRaises(ValueError):m.snapshot(root)
            empty.rmdir();os.mkfifo(root/'fifo')
            with self.assertRaises(ValueError):m.snapshot(root)


if __name__ == '__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(FactoryDataControls)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps(dict(status='PASS' if result.wasSuccessful() else 'FAIL',tests=result.testsRun,
        failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),
        evidence='SYNTHETIC_DATA_ONLY_NOT_SOURCE419_OR_NATIVE',genuine_Source_constructor_calls=0,
        Source_publication='NOT_RUN',native='NOT_RUN',actual_reader='NOT_RUN'),sort_keys=True))
    raise SystemExit(not result.wasSuccessful() or bool(result.skipped))
