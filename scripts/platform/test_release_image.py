#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure recipe/publication controls. Inert services model no native qualification."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().with_name('release_image.py')
release = types.ModuleType('_release_image_under_test')
release.__file__ = str(PATH)
exec(compile(PATH.read_bytes(), str(PATH), 'exec'), release.__dict__)


class RecipeImageControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='release-image-pure-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.events = []
        self.image = dict(bytes=11, sha256=release.sha(b'MODEL_IMAGE'), uuid='model-only')
        self.values = dict(selection={'packages': [dict(identity=dict(name=n, version=v, arch='aarch64'))
            for n, v in [('networkmanager', '1.58.1-1'), ('perl', '5.42.2-2')]]},
            authentication={'model_authentication': 'NO_CRYPTO_ACTOR'},
            tool_pins={'schema_version': 2, 'model': True},
            metadata_pins={'schema_version': 2, 'model': True},
            root_policy=dict(mode=0o755, uid=0, gid=0, acl=None, xattrs={}))
        self.recipe = dict(schema_version=1, kind=release.KIND, epoch=1700000000, inputs={})
        for name, value in self.values.items():
            path = self.directory / (name + '.json')
            raw = release.encoded(value)
            path.write_bytes(raw)
            self.recipe['inputs'][name] = dict(path=str(path), sha256=release.sha(raw))
        self.recipe_path = self.directory / 'recipe.json'
        self.write_recipe()
        self.bridge = types.SimpleNamespace(SOURCE_PINS={'model': ('model.py', 'a'*64)},
            exact_selection=self.exact_selection, run=self.pipeline, check_sources=self.check_sources)
        self.services = patch.object(release, 'load_services', side_effect=self.load_services)
        self.services.start()
        self.addCleanup(self.services.stop)
        self.readback_patch = patch.object(release, 'readback', side_effect=self.readback)
        self.readback_patch.start()
        self.addCleanup(self.readback_patch.stop)
        # Any accidental child dispatch is a failure, even on a developer machine.
        self.actor_guard = patch.object(subprocess, 'Popen', side_effect=AssertionError('native actor in pure controls'))
        self.actor_guard.start()
        self.addCleanup(self.actor_guard.stop)

    def write_recipe(self, recipe=None, raw=None):
        if raw is None:
            raw = release.encoded(self.recipe if recipe is None else recipe)
        self.recipe_path.write_bytes(raw)
        self.recipe_sha = release.sha(raw)
        return self.recipe_sha

    def replace_input(self, name, value):
        path = Path(self.recipe['inputs'][name]['path'])
        raw = release.encoded(value)
        path.write_bytes(raw)
        self.recipe['inputs'][name]['sha256'] = release.sha(raw)
        self.write_recipe()

    def exact_selection(self, selection):
        self.events.append('selection')
        release.need(selection == self.values['selection'], 'model-exact-selection-required')

    def load_services(self):
        self.events.append('load-services')
        return self.bridge, {'model': 'NO_NATIVE_SERVICES'}

    def pipeline(self, selection, authentication, tools, metadata, root_policy, output, epoch):
        self.events.append('pipeline')
        self.assertEqual((selection, authentication, tools, metadata, root_policy, epoch),
                         (*[self.values[n] for n in release.INPUTS], self.recipe['epoch']))
        output.mkdir(mode=0o700)
        (output / 'empty-directory').mkdir(mode=0o700)
        (output / 'model-image').write_bytes(b'MODEL_IMAGE')
        (output / 'receipt.json').write_bytes(release.encoded({'status': 'MODEL_CHILD_ONLY'}))
        return dict(status='PASS_EXACT_TWO_DIRECT_METADATA_GATED_EXT4',
                    acceptance={'native_arm': False, 'scriptlet_state': False, 'release': False},
                    filesystem={'image': copy.deepcopy(self.image)})

    def readback(self, prepared, pipeline):
        self.events.append('readback')
        self.assertEqual((pipeline / 'model-image').read_bytes(), b'MODEL_IMAGE')
        return copy.deepcopy(self.image)

    def check_sources(self):
        self.events.append('check-sources')

    def assemble(self, name='output'):
        output = self.directory / name
        result = release.run(self.recipe_path, self.recipe_sha, output)
        return output, result

    def receipt(self, output):
        return json.loads((output / 'receipt.json').read_bytes())

    def verify(self, output, result):
        return release.verify(self.recipe_path, self.recipe_sha, output, result['receipt_sha256'])

    def test_plan_has_deterministic_raw_and_canonical_binding_without_dispatch(self):
        first = release.plan(self.recipe_path, self.recipe_sha)
        second = release.plan(self.recipe_path, self.recipe_sha)
        self.assertEqual(first, second)
        self.assertEqual(first['binding']['inputs'], {
            name: self.recipe['inputs'][name]['sha256'] for name in release.INPUTS})
        self.assertEqual(first['binding']['recipe_sha256'], self.recipe_sha)
        self.assertEqual(first['binding_sha256'], release.sha(release.encoded(first['binding'])))
        self.assertEqual(first['binding']['payload_state'], release.STATE)
        self.assertNotIn('pipeline', self.events)
        self.assertNotIn('readback', self.events)
        self.assertNotIn('check-sources', self.events)

    def test_equivalent_json_has_same_canonical_hash_but_distinct_raw_recipe_binding(self):
        compact = release.plan(self.recipe_path, self.recipe_sha)
        self.write_recipe(raw=json.dumps(self.recipe, indent=2).encode())
        spaced = release.plan(self.recipe_path, self.recipe_sha)
        self.assertEqual(compact['binding']['recipe_canonical_sha256'], spaced['binding']['recipe_canonical_sha256'])
        self.assertNotEqual(compact['binding_sha256'], spaced['binding_sha256'])

    def test_strict_recipe_schema_and_installed_state_refuse_before_services(self):
        for updates in ({'kind': 'installed-system-ext4-v1'}, {'schema_version': True},
                        {'schema_version': 2}, {'extra': 'forbidden'}):
            with self.subTest(updates=updates):
                recipe = copy.deepcopy(self.recipe)
                recipe.update(updates)
                self.write_recipe(recipe)
                self.events.clear()
                with self.assertRaisesRegex(ValueError, 'pristine-payload-recipe-required'):
                    release.prepare(self.recipe_path, self.recipe_sha)
                self.assertEqual(self.events, [])

    def test_epoch_bounds_and_bool_refuse_before_services(self):
        for epoch in (-1, 2147483648, True, 1.5, '1700000000'):
            with self.subTest(epoch=epoch):
                recipe = copy.deepcopy(self.recipe)
                recipe['epoch'] = epoch
                self.write_recipe(recipe)
                self.events.clear()
                with self.assertRaisesRegex(ValueError, 'epoch-bound'):
                    release.prepare(self.recipe_path, self.recipe_sha)
                self.assertEqual(self.events, [])

    def test_input_closure_and_unpinned_or_relative_references_refuse(self):
        for change in ('missing', 'extra', 'relative', 'unpinned'):
            with self.subTest(change=change):
                recipe = copy.deepcopy(self.recipe)
                if change == 'missing':
                    del recipe['inputs']['selection']
                elif change == 'extra':
                    recipe['inputs']['extra'] = recipe['inputs']['selection']
                elif change == 'relative':
                    recipe['inputs']['selection']['path'] = 'relative.json'
                else:
                    del recipe['inputs']['selection']['sha256']
                self.write_recipe(recipe)
                self.events.clear()
                with self.assertRaises(ValueError):
                    release.prepare(self.recipe_path, self.recipe_sha)
                self.assertEqual(self.events, [])

    def test_duplicate_keys_and_nonfinite_json_refuse(self):
        for raw in (b'{"schema_version":1,"schema_version":1}',
                    b'{"outer":{"same":1,"same":2}}', b'{"number":NaN}', b'{"number":Infinity}'):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, 'duplicate-json-key|nonfinite-json'):
                release.decode(raw)
        self.write_recipe(raw=b'{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ValueError, 'duplicate-json-key'):
            release.prepare(self.recipe_path, self.recipe_sha)
        self.assertEqual(self.events, [])

    def test_bad_input_pin_and_recipe_pin_predispatch(self):
        for target in ('recipe', 'selection'):
            with self.subTest(target=target):
                if target == 'recipe':
                    digest = '0'*64
                else:
                    recipe = copy.deepcopy(self.recipe)
                    recipe['inputs']['selection']['sha256'] = '0'*64
                    self.write_recipe(recipe)
                    digest = self.recipe_sha
                self.events.clear()
                with self.assertRaisesRegex(ValueError, 'input-or-source-pin'):
                    release.run(self.recipe_path, digest, self.directory / target)
                self.assertFalse((self.directory / target).exists())
                self.assertEqual(self.events, [])

    def test_changed_bridge_pin_is_checked_before_source_execution(self):
        self.services.stop()
        directory = self.directory / 'source'
        directory.mkdir()
        (directory / 'metadata_gated_ext4.py').write_text("raise AssertionError('unchecked source executed')\n")
        with patch.object(release, 'BASE', directory), self.assertRaisesRegex(ValueError, 'input-or-source-pin'):
            release.load_services()

    def test_old_or_boolean_dependency_profile_and_noncanonical_root_refuse(self):
        for name, value in [('tool_pins', {'schema_version': 1}),
                            ('metadata_pins', {'schema_version': True}),
                            ('root_policy', dict(mode=0o755, uid=True, gid=0, acl=None, xattrs={})),
                            ('root_policy', dict(mode=0o700, uid=0, gid=0, acl=None, xattrs={}))]:
            with self.subTest(name=name, value=value):
                self.replace_input(name, value)
                with self.assertRaisesRegex(ValueError, 'profiles-v2|unsupported-new-root-policy'):
                    release.prepare(self.recipe_path, self.recipe_sha)
                self.assertNotIn('pipeline', self.events)
                self.replace_input(name, self.values[name])

    def test_subset_selection_refuses_without_pipeline_output(self):
        self.replace_input('selection', {'packages': self.values['selection']['packages'][:1]})
        with self.assertRaisesRegex(ValueError, 'model-exact-selection-required'):
            release.run(self.recipe_path, self.recipe_sha, self.directory / 'output')
        self.assertNotIn('pipeline', self.events)
        self.assertFalse((self.directory / 'output').exists())

    def test_input_symlink_and_hardlink_refusal_predispatch(self):
        original = Path(self.recipe['inputs']['selection']['path'])
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind):
                link = self.directory / ('selection-' + kind)
                if kind == 'symlink':
                    link.symlink_to(original)
                else:
                    os.link(original, link)
                recipe = copy.deepcopy(self.recipe)
                recipe['inputs']['selection']['path'] = str(link)
                self.write_recipe(recipe)
                self.events.clear()
                with self.assertRaisesRegex(ValueError, 'symlink|ordinary-file-bound'):
                    release.prepare(self.recipe_path, self.recipe_sha)
                self.assertEqual(self.events, [])
                link.unlink()

    def test_existing_output_is_preserved_before_any_service(self):
        output = self.directory / 'output'
        output.mkdir()
        marker = output / 'keep'
        marker.write_bytes(b'UNRELATED')
        with self.assertRaisesRegex(ValueError, 'existing-output-refused'):
            release.run(self.recipe_path, self.recipe_sha, output)
        self.assertEqual(marker.read_bytes(), b'UNRELATED')
        self.assertEqual(self.events, [])

    def test_resume_requires_existing_completed_output_and_external_pin(self):
        with self.assertRaisesRegex(ValueError, 'resume-requires-existing-completed-output'):
            release.run(self.recipe_path, self.recipe_sha, self.directory / 'missing', 'a'*64)
        self.assertEqual(self.events, [])
        output, result = self.assemble()
        with self.assertRaisesRegex(ValueError, 'input-or-source-pin'):
            release.run(self.recipe_path, self.recipe_sha, output, '0'*64)
        self.assertEqual(self.receipt(output)['status'], result['status'])

    def test_completed_verify_and_pinned_resume_do_not_rerun_pipeline(self):
        output, result = self.assemble()
        before = release.ledger(output)
        self.events.clear()
        verified = self.verify(output, result)
        resumed = release.run(self.recipe_path, self.recipe_sha, output, result['receipt_sha256'])
        self.assertEqual(verified, resumed)
        self.assertFalse(verified['actors_rerun'])
        self.assertEqual(self.events.count('readback'), 2)
        self.assertNotIn('pipeline', self.events)
        self.assertEqual(before, release.ledger(output))
        self.assertEqual(verified['payload_state']['scriptlets'], 'NOT_RUN')

    def test_failure_after_completed_child_cannot_publish_parent(self):
        original = self.bridge.run
        def child_then_fail(*args):
            original(*args)
            raise ValueError('modeled-child-cleanup-failure')
        self.bridge.run = child_then_fail
        output = self.directory / 'failed'
        with self.assertRaisesRegex(ValueError, 'modeled-child-cleanup-failure'):
            release.run(self.recipe_path, self.recipe_sha, output)
        self.assertTrue((output / 'pipeline/receipt.json').is_file())
        self.assertFalse((output / 'receipt.json').exists())
        self.assertTrue((output / 'INCOMPLETE.json').is_file())
        self.assertEqual(json.loads((output / 'failure.json').read_bytes())['status'], 'REFUSED_NOT_ACCEPTED')
        with self.assertRaisesRegex(ValueError, 'incomplete-output-cannot-resume'):
            release.run(self.recipe_path, self.recipe_sha, output, 'a'*64)

    def test_failed_readback_retains_child_without_parent_pass(self):
        with patch.object(release, 'readback', side_effect=ValueError('model-readback-refusal')):
            with self.assertRaisesRegex(ValueError, 'model-readback-refusal'):
                release.run(self.recipe_path, self.recipe_sha, self.directory / 'failed')
        output = self.directory / 'failed'
        self.assertTrue((output / 'pipeline/receipt.json').is_file())
        self.assertFalse((output / 'receipt.json').exists())
        self.assertTrue((output / 'INCOMPLETE.json').exists())

    def test_child_acceptance_or_image_mismatch_cannot_publish(self):
        original = self.bridge.run
        for changed in ('acceptance', 'image'):
            def altered(*args):
                value = original(*args)
                if changed == 'acceptance':
                    value['acceptance']['release'] = True
                else:
                    value['filesystem']['image']['bytes'] = 99
                return value
            self.bridge.run = altered
            output = self.directory / changed
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'pipeline-result-boundary|pipeline-image-binding'):
                release.run(self.recipe_path, self.recipe_sha, output)
            self.assertFalse((output / 'receipt.json').exists())
            self.assertTrue((output / 'INCOMPLETE.json').exists())

    def test_changed_source_after_child_success_blocks_parent_publication(self):
        self.bridge.check_sources = lambda: (_ for _ in ()).throw(ValueError('modeled-source-drift'))
        output = self.directory / 'failed'
        with self.assertRaisesRegex(ValueError, 'modeled-source-drift'):
            release.run(self.recipe_path, self.recipe_sha, output)
        self.assertTrue((output / 'pipeline/receipt.json').is_file())
        self.assertFalse((output / 'receipt.json').exists())

    def test_input_drift_after_child_success_blocks_parent_publication(self):
        original = self.bridge.run
        def changed(*args):
            result = original(*args)
            Path(self.recipe['inputs']['authentication']['path']).write_bytes(b'{}\n')
            return result
        self.bridge.run = changed
        output = self.directory / 'failed'
        with self.assertRaisesRegex(ValueError, 'input-or-source-pin'):
            release.run(self.recipe_path, self.recipe_sha, output)
        self.assertFalse((output / 'receipt.json').exists())
        self.assertTrue((output / 'pipeline/receipt.json').exists())

    def test_recipe_binding_drift_during_final_check_blocks_publication(self):
        original = self.bridge.run
        def changed(*args):
            result = original(*args)
            self.bridge.SOURCE_PINS['model'] = ('model.py', 'b'*64)
            return result
        self.bridge.run = changed
        with self.assertRaisesRegex(ValueError, 'recipe-or-source-drift'):
            release.run(self.recipe_path, self.recipe_sha, self.directory / 'failed')
        self.assertFalse((self.directory / 'failed/receipt.json').exists())

    def test_ledger_rejects_tamper_added_removed_and_mode_changes(self):
        for change in ('tamper', 'add', 'remove', 'mode', 'empty-directory'):
            output, result = self.assemble(change)
            if change == 'tamper':
                (output / 'pipeline/model-image').write_bytes(b'CHANGED')
            elif change == 'add':
                (output / 'extra').write_bytes(b'ADDED')
            elif change == 'remove':
                (output / 'pipeline/model-image').unlink()
            elif change == 'mode':
                (output / 'inputs/selection.json').chmod(0o644)
            else:
                (output / 'pipeline/empty-directory').rmdir()
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'artifact-ledger-mismatch'):
                self.verify(output, result)

    def test_ledger_refuses_symlink_hardlink_and_fifo_without_blocking(self):
        for change in ('symlink', 'hardlink', 'fifo'):
            output, result = self.assemble(change)
            leaf = output / 'extra'
            if change == 'symlink':
                leaf.symlink_to(output / 'pipeline/model-image')
            elif change == 'hardlink':
                os.link(output / 'pipeline/model-image', leaf)
            else:
                os.mkfifo(leaf)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'symlink|ordinary-file-bound'):
                self.verify(output, result)

    def test_incomplete_marker_and_unpinned_modified_receipt_cannot_resume(self):
        output, result = self.assemble()
        (output / 'INCOMPLETE.json').write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'incomplete-output-cannot-resume'):
            self.verify(output, result)
        (output / 'INCOMPLETE.json').unlink()
        with (output / 'receipt.json').open('ab') as stream:
            stream.write(b' ')
        with self.assertRaisesRegex(ValueError, 'input-or-source-pin'):
            self.verify(output, result)

    def test_external_pin_does_not_override_recipe_or_payload_state_binding(self):
        for field in ('binding', 'binding_sha256', 'payload_state', 'artifacts_sha256'):
            output, result = self.assemble(field)
            receipt = self.receipt(output)
            receipt[field] = {} if field in ('binding', 'payload_state') else '0'*64
            raw = release.encoded(receipt)
            (output / 'receipt.json').write_bytes(raw)
            result['receipt_sha256'] = release.sha(raw)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'receipt-recipe-binding|artifact-ledger-binding'):
                self.verify(output, result)

    def direct_readback_fixture(self, name):
        pipeline = self.directory / name
        (pipeline / 'staging').mkdir(parents=True)
        (pipeline / 'encoded').mkdir()
        body = b'TINY_MODEL_IMAGE_NOT_EXT4'
        (pipeline / 'encoded/root.ext4').write_bytes(body)
        manifest = {'output_nodes': {'model-file': {'type': 'file'}}}
        meta = {'model': 'NO_NATIVE_METADATA_CLAIM'}
        inventory = {'nodes': {'model-file': {'model': True}}}
        result = dict(image=dict(bytes=len(body), sha256=release.sha(body), uuid='model-uuid'),
                      inventory_sha256=release.sha(release.encoded(inventory)))
        for relative, value in [('staging/assembly.json', manifest), ('inode-metadata.json', meta),
                                ('encoded/result.json', result)]:
            (pipeline / relative).write_bytes(release.encoded(value))
        encoder = types.SimpleNamespace(readback=Mock(return_value=inventory), check_inventory=Mock())
        prepared = dict(modules={'encoder': encoder}, recipe={'epoch': 1700000000})
        return pipeline, prepared, encoder, manifest, meta, inventory, result

    def test_direct_readback_binds_full_image_before_model_inventory(self):
        self.readback_patch.stop()
        pipeline, prepared, encoder, manifest, meta, inventory, result = self.direct_readback_fixture('direct')
        self.assertEqual(release.readback(prepared, pipeline), result['image'])
        encoder.readback.assert_called_once_with(pipeline / 'encoded/root.ext4')
        encoder.check_inventory.assert_called_once_with(inventory, manifest['output_nodes'], meta,
            1700000000, result['image']['uuid'], result['image']['bytes'])

    def test_direct_readback_refuses_changed_bytes_and_declared_size_or_hash_before_reader(self):
        self.readback_patch.stop()
        for change in ('same-size-bytes', 'declared-size', 'declared-hash'):
            pipeline, prepared, encoder, _, _, _, result = self.direct_readback_fixture(change)
            if change == 'same-size-bytes':
                image = pipeline / 'encoded/root.ext4'
                body = image.read_bytes()
                image.write_bytes(b'X' + body[1:])
            elif change == 'declared-size':
                result['image']['bytes'] += 1
            else:
                result['image']['sha256'] = '0'*64
            (pipeline / 'encoded/result.json').write_bytes(release.encoded(result))
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'image-full-byte-binding'):
                release.readback(prepared, pipeline)
            encoder.readback.assert_not_called()
            encoder.check_inventory.assert_not_called()

    def test_direct_readback_refuses_inventory_digest_mismatch(self):
        self.readback_patch.stop()
        pipeline, prepared, encoder, _, _, _, result = self.direct_readback_fixture('inventory')
        result['inventory_sha256'] = '0'*64
        (pipeline / 'encoded/result.json').write_bytes(release.encoded(result))
        with self.assertRaisesRegex(ValueError, 'fresh-readback-inventory-binding'):
            release.readback(prepared, pipeline)
        encoder.readback.assert_called_once()
        encoder.check_inventory.assert_called_once()

    def test_publication_fsync_failure_after_rename_leaves_incomplete_and_refuses_resume(self):
        output = self.directory / 'fsync-failure'
        original = release.sync_directory
        def fail_after_rename(directory):
            if directory == output and (output / 'receipt.json').exists():
                raise OSError('modeled-final-directory-fsync-failure')
            original(directory)
        with patch.object(release, 'sync_directory', side_effect=fail_after_rename):
            with self.assertRaisesRegex(OSError, 'modeled-final-directory-fsync-failure'):
                release.run(self.recipe_path, self.recipe_sha, output)
        self.assertTrue((output / 'receipt.json').exists())
        self.assertTrue((output / 'INCOMPLETE.json').exists())
        self.assertTrue((output / 'failure.json').exists())
        digest = release.sha((output / 'receipt.json').read_bytes())
        with self.assertRaisesRegex(ValueError, 'incomplete-output-cannot-resume'):
            release.run(self.recipe_path, self.recipe_sha, output, digest)

    def test_two_fresh_destinations_share_recipe_binding_and_model_image(self):
        left, a = self.assemble('first')
        right, b = self.assemble('second')
        self.assertEqual(a['binding_sha256'], b['binding_sha256'])
        self.assertEqual(a['image'], b['image'])
        self.assertEqual(self.receipt(left)['artifacts'], self.receipt(right)['artifacts'])
        self.assertEqual(a['receipt_sha256'], b['receipt_sha256'])
        self.assertEqual(self.events.count('pipeline'), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
