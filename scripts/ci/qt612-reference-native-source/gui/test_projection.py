# SPDX-License-Identifier: MIT
"""Positive MODEL and refusal controls; no build, actor, GPG, or publication."""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('gui_projection_controls', HERE/'projection.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)
P = G.load_parent()
M = P.M
sys.addaudithook(M.fence)
CONTRACT = M.decode((HERE/'fixtures/BUILD-CONTRACT.json').read_bytes())
POLICY = M.load(HERE.parent/'resource-EXPERIMENTAL.json', P.EXPERIMENTAL, {})
DEPS = M.load(HERE.parent/'dependency-candidates.lock.json', P.DEPENDENCIES, {})


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class Controls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='qt612-gui-MODEL-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def model(self):
        inventory = dict(line.split(' ', 1) for line in
            (HERE.parents[3]/'scripts/ci/hyprland03-native-source-v1/fixtures/expected349.lock').read_text().splitlines())
        recipe = dict(contract=copy.deepcopy(CONTRACT), active_files=CONTRACT['native_recipe_files'],
            source_refs=[{}]*13, provenance=dict(recipe_commit=G.COMMIT, handoff_seal='UNBOUND'))
        base = dict(kind='QT612_COMPLETE517_INPUT_DATA_ONLY', files=517, inventory=inventory, Root_acceptance=None)
        packages = {n: dict(name=n, version=r['version'], arch=r['arch'], filename=r['filename'])
                    for n, r in DEPS['additional'].items()}
        packages['md4c'] = dict(name='md4c', version='0.5.3-1', arch='aarch64', filename='md4c-0.5.3-1-aarch64.pkg.tar.xz')
        deps = dict(kind='QT612_INCREMENTAL_SIGNED_INPUT_DATA_ONLY', packages=packages, complete=True,
                    missing_roles=[], Root_acceptance=None, GPG='NOT_RUN')
        return recipe, base, deps

    def finisher(self):
        for name, path in (('gui_stage', HERE/'stage.py'), ('gui_checker', HERE/'fixtures/check_stage.py')):
            self.addCleanup(lambda n=name, old=sys.modules.get(name): sys.modules.pop(n, None) if old is None else sys.modules.__setitem__(n, old))
            sys.modules[name] = module(name, path)
        value = types.ModuleType('gui_finisher_MODEL')
        exec(G.project_finisher((HERE.parent/'finish_pair.py').read_bytes(), parent=P), value.__dict__)
        return value

    def pair(self):
        reviewed = {n: r['sha256'] for n, r in CONTRACT['native_recipe_files'].items()}
        reviewed[CONTRACT['upstream']['archive']['filename']] = CONTRACT['upstream']['archive']['sha256']
        expected = dict(image='sha256:'+'a'*64, inventory_sha256='b'*64, recipe_inputs=reviewed,
            nonce='c'*32, contract=copy.deepcopy(CONTRACT), notice_policy=M.decode((HERE/'fixtures/source-notices.json').read_bytes()))
        records = [dict(status='built-package-static-pass', exit_code=0, mode='native', image_id=expected['image'],
            image=expected['image'], expected_packages_sha256=expected['inventory_sha256'], recipe_inputs=reviewed,
            builder_host_arch='aarch64', clean_environment_id='cachy-qt612-gui-reference-'+expected['nonce']+'-'+str(i),
            artifacts={G.PACKAGE: 'd'*64}, source_date_epoch=1792021458, recipe_metadata={}, entry_script_sha256='e'*64) for i in (1, 2)]
        comparison = dict(status='contents-reproduced', errors=[], packages={G.PACKAGE: dict.fromkeys(
            ('installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal', 'bytes_equal'), True)})
        return records, comparison, expected

    def stage(self):
        files, links, elf = {}, {}, {}
        def file(name):
            files[name] = dict(bytes=1, sha256='a'*64, mode=0o755)
        def binary(name, soname=None):
            file(name)
            elf[name] = dict(type=3, machine=183, soname=soname, interpreter=None, needed=[], version_needs=None,
                version_definitions=None, load_segments=[dict(offset=0, virtual_address=0, file_bytes=1,
                memory_bytes=1, alignment=16384)], geometry_16k=True, metadata_scope='ELF_BYTES_ONLY_NO_NATIVE_OR_PROVIDER_ACCEPTANCE')
        profile = CONTRACT['expected_stage']
        for name in profile['public_modules']+profile['private_modules']:
            base = 'usr/lib/libQt6'+name
            binary(base+'.so.6.12.0', 'libQt6'+name+'.so.6')
            for suffix, target in (('.so.6', 'libQt6'+name+'.so.6.12.0'), ('.so', 'libQt6'+name+'.so.6')):
                links[base+suffix] = dict(target=target)
            if name in profile['public_modules']:
                for n in ('usr/include/qt6/Qt'+name+'/Qt'+name, 'usr/lib/pkgconfig/Qt6'+name+'.pc',
                          'usr/lib/cmake/Qt6'+name+'/Qt6'+name+'Config.cmake'):
                    file(n)
            elif name in profile['private_headers']:
                file('usr/include/qt6/Qt'+name+'/6.12.0/Qt'+name+'/private/'+profile['private_headers'][name])
                file('usr/lib/cmake/Qt6'+name+'Private/Qt6'+name+'PrivateConfig.cmake')
        for name in profile['tools_required']+['usr/lib/qt6/plugins/'+p for p in profile['plugins_required']]:
            binary(name)
        return dict(status='PASS_QT612_GUI_DESTDIR_CONTRACT_ONLY', architecture='aarch64',
            evidence_scope='STAGED_AARCH64_ELF_16K_GEOMETRY_ONLY', files=files, symlinks=links, elf=elf,
            directories={}, payload_bytes=len(files), license_policy_pin=CONTRACT['source_notices']['policy'],
            native_execution='NOT_ESTABLISHED', installation='NOT_ESTABLISHED', hardware='NOT_ESTABLISHED',
            provider_transaction=None, native_acceptance=None)

    def test_complete_gui_model_is_distinct_and_unissued(self):
        result = G.admit_complete_preparation(*self.model(), POLICY, parent=P)
        self.assertEqual(result['status'], 'COMPLETE_QT612_GUI_PRODUCER_INPUTS_DATA_ONLY')
        self.assertEqual(len(result['inventory']), 356)
        self.assertFalse(result['actor_enabled'])
        self.assertIsNone(result['Root_capacity'])
        self.assertEqual(result['normal_dependency_transaction'], 'NOT_RUN')
        self.assertEqual(result['handoff_seal'], 'UNBOUND')

    def test_parent_f69_cannot_admit_gui_tuple(self):
        recipe, base, deps = self.model()
        recipe['source_ref13'] = recipe['source_refs']
        with self.assertRaisesRegex(ValueError, 'FROZEN_F_PRODUCER_TUPLE'):
            P.admit_complete_preparation(recipe, base, deps, POLICY)

    def test_gui_refuses_f69_commit_and_contract(self):
        recipe, base, deps = self.model()
        recipe['provenance']['recipe_commit'] = P.F_COMMIT
        with self.assertRaisesRegex(ValueError, 'GUI_FROZEN_RECIPE'):
            G.admit_complete_preparation(recipe, base, deps, POLICY, parent=P)
        recipe['provenance']['recipe_commit'] = G.COMMIT
        recipe['contract']['configuration']['settings']['FEATURE_wayland'] = 'OFF'
        with self.assertRaisesRegex(ValueError, 'GUI_FROZEN_RECIPE'):
            G.admit_complete_preparation(recipe, base, deps, POLICY, parent=P)

    def test_missing_graphics_or_wrong_version_refuses(self):
        for name in G.GUI_BASE:
            with self.subTest(name=name):
                recipe, base, deps = self.model()
                base['inventory'][name] = 'MODEL-wrong'
                with self.assertRaisesRegex(ValueError, 'GUI_BASE_GRAPHICS'):
                    G.admit_complete_preparation(recipe, base, deps, POLICY, parent=P)

    def test_missing_md4c_and_md4c06_refuse(self):
        recipe, base, deps = self.model()
        deps['packages']['md4c']['version'] = '0.6.0-2'
        with self.assertRaisesRegex(ValueError, 'GUI_COMPLETE_NORMAL'):
            G.admit_complete_preparation(recipe, base, deps, POLICY, parent=P)
        del deps['packages']['md4c']
        with self.assertRaisesRegex(ValueError, 'GUI_COMPLETE_NORMAL'):
            G.admit_complete_preparation(recipe, base, deps, POLICY, parent=P)

    def test_unwidened_full_policy_pin(self):
        for key in ('storage_bytes', 'cleanup_seconds'):
            policy = copy.deepcopy(POLICY)
            policy[key] += 1
            with self.assertRaisesRegex(ValueError, 'UNWIDENED'):
                G.admit_complete_preparation(*self.model(), policy, parent=P)

    def test_builder_separate_package_and_actor_entry_refuses(self):
        raw = (HERE.parents[3]/'scripts/build/build_v2.py').read_bytes()
        projected = G.project_builder(raw, parent=P)
        compile(projected, 'MODEL_GUI_builder', 'exec')
        for token in (G.PACKAGE.encode(), b'cachy-qt612-gui-reference-', b'CACHY_QT612_GUI_REFERENCE_',
                      b'GUI_ROOT_CAPACITY_UNISSUED_NO_ACTOR_ENTRY', b'qt612-gui-stage-contract.json', b"'--read-only'"):
            self.assertIn(token, projected)
        self.assertNotIn(b'gui-gui', projected)
        self.assertNotIn(b'from qt612_actor_gate', projected)
        self.assertNotIn(P.PACKAGE.encode(), projected)

    def test_normal_dependencies_and_retained_gui_stage_export(self):
        raw = (HERE.parents[3]/'scripts/build/container-entry-v2.sh').read_bytes()
        text = G.project_entry(raw, CONTRACT['dependencies']['runtime']+CONTRACT['dependencies']['build'], parent=P)
        for token in (b'pacman -T', b'wayland>=1.15', b'libglvnd', b'mesa', b'qt612-gui-stage-contract.json',
                      b'makepkg --verifysource', b'makepkg --cleanbuild --force'):
            self.assertIn(token, text)
        self.assertNotIn(b'--nodeps', text)
        self.assertNotIn(b'--nocheck', text)
        self.assertNotIn(b'--cleanbuild --clean', text)

    def test_gui_dependency_image_plan_keeps_normal_signature_policy(self):
        plan = G.dependency_image_plan('sha256:'+'a'*64, *self.model(), POLICY,
            builder_uid=1000, builder_gid=1000, parent=P)
        self.assertEqual(plan['recipe_commit'], G.COMMIT)
        self.assertEqual(plan['normal_dependency_transaction'], 'NOT_RUN')
        self.assertIn('LocalFileSigLevel = Required TrustedOnly', plan['pacman_config'])
        self.assertIn('-U --noconfirm --noscriptlet', plan['dockerfile'])
        self.assertFalse(plan['actor_enabled'])
        self.assertIsNone(plan['Root_capacity'])

    def test_pair_commands_are_gui_only_and_unissued(self):
        plan = G.pair_commands(self.root/'source', self.root/'output', 'sha256:'+'a'*64,
                              dict(bytes=1, sha256='b'*64), nonce='c'*32, parent=P)
        self.assertIn('build_qt612_gui.py', plan['builds'][0]['argv'][3])
        self.assertEqual(set(plan['builds'][0]['env']), {'CACHY_QT612_GUI_REFERENCE_NONCE', 'CACHY_QT612_GUI_REFERENCE_ATTEMPT'})
        self.assertTrue(plan['serial'])
        self.assertFalse(plan['actor_enabled'])
        self.assertFalse(plan['callable_actor_entry'])

    def test_positive_gui_pair_receipt_model_and_parent_refusal(self):
        records, comparison, expected = self.pair()
        self.assertEqual(self.finisher().validate_pair_records(*records, comparison, expected=expected), G.PACKAGE)
        with self.assertRaisesRegex(ValueError, 'EXACT_F_CONTRACT'):
            P.module('finish_pair').validate_pair_records(*records, comparison, expected=expected)

    def test_f69_identity_or_marker_cannot_be_gui(self):
        records, comparison, expected = self.pair()
        q = self.finisher()
        self.assertEqual(q.MARKER, CONTRACT['smoke']['marker'].encode())
        records[0]['clean_environment_id'] = records[0]['clean_environment_id'].replace('-gui-', '-')
        with self.assertRaisesRegex(ValueError, 'EXACT_SUCCESSFUL_NATIVE'):
            q.validate_pair_records(*records, comparison, expected=expected)
        with self.assertRaisesRegex(ValueError, 'GUI_PINNED_FINISHER'):
            G.project_finisher((HERE.parent/'finish_pair.py').read_bytes()+b'\n', parent=P)

    def test_gui18_stage_model_and_missing_added_modules_refuse(self):
        stage = self.stage()
        q = self.finisher()
        q.gui_stage.validate_stage_receipt(stage, CONTRACT)
        for name in CONTRACT['expected_stage']['added_modules']:
            with self.subTest(module=name):
                bad = copy.deepcopy(stage)
                del bad['elf']['usr/lib/libQt6'+name+'.so.6.12.0']
                with self.assertRaisesRegex(ValueError, 'GUI_REQUIRED_MODULE'):
                    q.gui_stage.validate_stage_receipt(bad, CONTRACT)

    def test_gui_stage_wrong_geometry_plugin_or_authority_refuses(self):
        stage, q = self.stage(), self.finisher()
        bad = copy.deepcopy(stage)
        bad['elf'][next(iter(bad['elf']))]['load_segments'][0]['alignment'] = 4096
        with self.assertRaisesRegex(ValueError, 'GUI_ALL_LOAD'):
            q.gui_stage.validate_stage_receipt(bad, CONTRACT)
        bad = copy.deepcopy(stage)
        bad['files']['usr/lib/qt6/plugins/wayland-shell-integration/libextra.so'] = dict(bytes=0, sha256='a'*64, mode=0o755)
        with self.assertRaisesRegex(ValueError, 'GUI_DISABLED_PLUGIN'):
            q.gui_stage.validate_stage_receipt(bad, CONTRACT)
        bad = copy.deepcopy(stage)
        bad['native_acceptance'] = True
        with self.assertRaisesRegex(ValueError, 'GUI_PASSIVE_STAGE'):
            q.gui_stage.validate_stage_receipt(bad, CONTRACT)

    def test_receipt_custody_checks_preserved_in_projection(self):
        result = G.project_finisher((HERE.parent/'finish_pair.py').read_bytes(), parent=P)
        for token in (b'SAME_ARCHIVE_FD_AFTER_PIN', b'STABLE_COMPLETE_CURRENT_XZ_ARCHIVE', b'CURRENT_RETAINED_RECEIPT_HASH',
                      b'EXACT_CURRENT_ARCHIVE_STAGE_BINDING', b'ALL173_ACTUAL_ARCHIVE_LICENSE_BYTES', b'gui_stage.enrich_elf'):
            self.assertIn(token, result)
        self.assertIn(b'qt612-gui-stage-contract.json', result)
        self.assertNotIn(b"MARKER = b'PASS_QT612_OFFSCREEN_API_SMOKE_ONLY'", result)

    def test_frozen_fixture_pins(self):
        selected = G.lock(P, {})
        for name in ('BUILD-CONTRACT.json', 'module-source-contract.DATA.json', 'check_stage.py', 'source-notices.json'):
            M.stream(HERE/'fixtures'/name, selected['references'][name], {}, mode=0o644)


if __name__ == '__main__':
    unittest.main()
