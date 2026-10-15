"""Source packet regressions using real isolated files and mocked read-only Git."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('development_packet_tested', Path(__file__).with_name('packet.py'))
packet = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(packet)
COMMIT = 'c' * 40


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'; self.root.mkdir()
        self.tripwire = patch.object(packet.subprocess, 'run', side_effect=AssertionError('unmocked host command forbidden'))
        self.tripwire.start(); self.addCleanup(self.tripwire.stop)
        self.make_source()
        # Unit-only authority for these explicit synthetic files. Production
        # constants stay pinned; no actual checkout/native receipt is admitted.
        for name, value in (('BASELINE_INITIAL', self.initial_sha),
                            ('BASELINE_INPUTS', self.pins['scripts/ci/inputs.lock.json'])):
            binding = patch.object(packet, name, value)
            binding.start(); self.addCleanup(binding.stop)

    def write(self, name, data=None, mode=0o644):
        path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if data is not None else ('reviewed ' + name + '\n').encode())
        path.chmod(mode)
        return path

    def json(self, name, value):
        path = self.write(name, (json.dumps(value, sort_keys=True) + '\n').encode())
        return digest(path.read_bytes())

    def make_source(self):
        for name in packet.ROOTS:
            (self.root / name).mkdir()
        for name in (*packet.INITIAL_FILES, packet.WORKFLOW):
            self.write(name)
        for directory, names in (('scripts/integration', ('fixtures', 'lifecycle', 'repository', 'onboarding', 'desktop')),
                                 ('scripts/ci', ('integration', 'integration_export', 'sign_fixture', 'installed_handoff',
                                                 'source_suites', 'verify_derived', 'lifecycle_inventory', 'commit_image', 'repository_projection'))):
            for name in names:
                for prefix in ('', 'test_'):
                    self.write(directory + '/' + prefix + name + '.py')
        recipe = {}
        for name in ('PKGBUILD', 'reviewed.log', 'reviewed.pkg.tar.gz'):
            path = self.write('packages/example/' + name)
            recipe[name] = digest(path.read_bytes())
        self.json('scripts/ci/recipes.lock.json', {'packages/example': recipe})
        self.json('scripts/ci/inputs.lock.json', {'schema_version': 1})
        for name in ('stage', 'arm_c01', 'corpus', 'test_stage', 'test_arm_c01', 'test_corpus'):
            self.write('scripts/experiments/' + name + '.py')
        self.json('scripts/experiments/stage.lock.json', {
            'source_files': {p.name: packet.read(p)[1] for p in (self.root / 'scripts/experiments').glob('*.py')},
            'exporter': {'path': 'scripts/ci/integration_export.py', **packet.read(self.root / 'scripts/ci/integration_export.py')[1]}})
        for name in ('controller.py', 'test_controller.py', 'gbm_probe.c'):
            self.write('scripts/virtual/' + name)
        virtual_sha = self.json('scripts/virtual/tooling.lock.json', {
            'base_inputs_lock_sha256': digest((self.root / 'scripts/ci/inputs.lock.json').read_bytes())})
        self.json('scripts/virtual/tooling-audit.json', {'tooling_lock_sha256': virtual_sha})
        for name in ('client.py', 'stage.py', 'test_client.py', 'test_stage.py'):
            self.write('scripts/client/' + name)
        for name in ('packet.py', 'test_packet.py', 'common.py', 'controller.py'):
            self.write(packet.DEVELOPMENT + '/' + name)
        reviewed = {}
        for name in packet.KSM_FILES:
            path = self.write(packet.KSM + '/' + name, mode=0o755 if name == 'cachy-asahi-ksmctl' else 0o644)
            reviewed[name] = digest(path.read_bytes())
        self.json('manifests/reviewed/ksmctl.json', reviewed)
        locked, unused = packet.recipe_paths(self.root)
        self.initial = {'schema_version': 1, 'purpose': packet.INITIAL_PURPOSE, 'development_only': True,
                        'selected_for_release': False, 'hardware_validation': 'NOT RUN', 'recipe_source_commit': 'd' * 40,
                        'recipes_sha256': digest((self.root / 'scripts/ci/recipes.lock.json').read_bytes()), 'source_date_epoch': 1,
                        'source_files': packet.rows(self.root, packet.initial_paths(self.root, locked)),
                        'generated_fixture_files': {'baseline/source': {'sha256': 'e' * 64, 'mode': 0o644}}}
        self.initial_sha = self.json(packet.INITIAL, self.initial)
        self.pins = {name: digest((self.root / name).read_bytes()) for name in packet.PINS}

    def freeze(self):
        self.packet_path = self.root / packet.LOCK
        self.packet_sha = packet.freeze(self.root, self.packet_path, self.root / packet.INITIAL, self.initial_sha, self.pins)
        self.value = json.loads(self.packet_path.read_bytes())
        return self.value

    def git_fixture(self, root=None):
        root = root or self.root
        names = set(self.value['source_files']) | {packet.LOCK}
        self.blobs, self.tree = {}, {}
        for name in names:
            path = root / name; data = path.read_bytes()
            oid = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            self.blobs[oid] = data
            self.tree[name] = ['100' + format(stat.S_IMODE(path.stat().st_mode), '03o'), 'blob', oid]
        self.git_calls = []
        self.git_type, self.git_head = b'commit\n', COMMIT
        def run(command, **kwargs):
            self.assertEqual(command[:4], ['git', '--no-optional-locks', '--no-replace-objects', '-C'])
            self.assertEqual(command[4], str(root)); self.git_calls.append(command[5:])
            self.assertEqual(kwargs['timeout'], 30)
            self.assertEqual(kwargs['env']['GIT_NO_REPLACE_OBJECTS'], '1')
            self.assertEqual(kwargs['env']['GIT_CONFIG_GLOBAL'], '/dev/null')
            args = command[5:]
            if args == ['cat-file', '-t', COMMIT]:
                data = self.git_type
            elif args == ['rev-parse', 'HEAD']:
                data = self.git_head.encode() + b'\n'
            elif args == ['ls-tree', '-rz', '--full-tree', COMMIT]:
                data = b''.join((' '.join(self.tree[name]) + '\t' + name).encode() + b'\0' for name in sorted(self.tree))
            elif args[:2] == ['cat-file', 'blob']:
                data = self.blobs[args[2]]
            else:
                raise AssertionError('unexpected Git read operation')
            kwargs['stdout'].write(data)
            return subprocess.CompletedProcess(command, 0)
        return patch.object(packet.subprocess, 'run', side_effect=run)


class FreezeTests(Base):
    def test_source_descriptor_refuses_replacement_symlink_fifo_or_inode(self):
        target = self.root / 'scripts/client/client.py'
        original = target.read_bytes()
        real_open = os.open
        for kind in ('symlink', 'fifo', 'inode'):
            if target.exists() or target.is_symlink():
                target.unlink()
            target.write_bytes(original); target.chmod(0o644)
            def replaced(path, flags):
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertTrue(flags & os.O_NONBLOCK)
                target.unlink()
                if kind == 'symlink':
                    target.symlink_to(self.root / 'README.md')
                elif kind == 'fifo':
                    os.mkfifo(target)
                else:
                    target.write_bytes(original); target.chmod(0o644)
                return real_open(path, flags)
            with self.subTest(kind=kind), patch.object(packet.os, 'open', side_effect=replaced), self.assertRaises(packet.PacketError):
                packet.read(target)
            target.unlink()

    def test_read_descriptor_closes_after_nonregular_replacement_refusal(self):
        target = self.root / 'scripts/client/client.py'
        real_open, descriptors = os.open, []
        def replaced(path, flags):
            target.unlink(); os.mkfifo(target)
            value = real_open(path, flags); descriptors.append(value)
            return value
        with patch.object(packet.os, 'open', side_effect=replaced), self.assertRaises(packet.PacketError):
            packet.read(target)
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])

    def test_complete_map_initial_plus_extensions_metadata_and_exact_ksm(self):
        value = self.freeze()
        self.assertEqual(value['initial_source_files'], self.initial['source_files'])
        self.assertEqual(value['generated_fixture_files'], self.initial['generated_fixture_files'])
        expected = set(self.initial['source_files']) | packet.PINS | {packet.WORKFLOW}
        for subtree in (*packet.EXTRA_ROOTS, packet.DEVELOPMENT, packet.KSM):
            expected |= {p.relative_to(self.root).as_posix() for p in (self.root / subtree).rglob('*') if p.is_file() and p != self.packet_path}
        self.assertEqual(set(value['source_files']), expected)
        self.assertNotIn(packet.LOCK, value['source_files'])
        self.assertEqual(len([name for name in expected if name.startswith(packet.KSM + '/')]), 15)
        self.assertEqual(value['metadata_pins'], self.pins)

    def test_new_initial_executable_is_detected_without_importing_it(self):
        self.write('scripts/ci/unreviewed.py', b'raise RuntimeError("must not execute")\n', 0o755)
        with self.assertRaisesRegex(packet.PacketError, 'initial-source-map-drift'):
            self.freeze()

    def test_new_python_stages_are_included_and_unreviewed_shell_stage_refused(self):
        self.write(packet.DEVELOPMENT + '/new_stage.py')
        self.assertIn(packet.DEVELOPMENT + '/new_stage.py', self.freeze()['source_files'])
        self.packet_path.unlink()
        self.write(packet.DEVELOPMENT + '/shell_stage.sh', mode=0o755)
        with self.assertRaisesRegex(packet.PacketError, 'unreviewed-development-file'):
            self.freeze()

    def test_initial_namespace_exclusions_and_recipe_log_archive_exceptions(self):
        for name in ('scripts/port/future.py', 'scripts/platform/future.py', 'packages/libraries/future/PKGBUILD',
                     'packages/tools/other/PKGBUILD', 'scripts/ci/unreviewed.log'):
            self.write(name)
        value = self.freeze()
        for name in ('scripts/port/future.py', 'scripts/platform/future.py', 'packages/libraries/future/PKGBUILD',
                     'packages/tools/other/PKGBUILD', 'scripts/ci/unreviewed.log'):
            self.assertNotIn(name, value['source_files'])
        self.assertIn('packages/example/reviewed.log', value['source_files'])
        self.assertIn('packages/example/reviewed.pkg.tar.gz', value['source_files'])

    def test_executable_log_and_python_cache_cannot_evade_source_packet(self):
        self.write('scripts/ci/hidden_stage.log', mode=0o755)
        with self.assertRaisesRegex(packet.PacketError, 'ignored-executable-source-refused'):
            self.freeze()
        (self.root / 'scripts/ci/hidden_stage.log').unlink()
        self.write('scripts/client/hidden.pyc')
        with self.assertRaisesRegex(packet.PacketError, 'source-python-cache-refused'):
            self.freeze()
        (self.root / 'scripts/client/hidden.pyc').unlink()
        (self.root / 'scripts/client/__pycache__').mkdir()
        with self.assertRaisesRegex(packet.PacketError, 'source-python-cache-refused'):
            self.freeze()

    def test_new_ksm_file_missing_file_or_reviewed_hash_drift_refused(self):
        self.write(packet.KSM + '/unreviewed.py')
        with self.assertRaises(packet.PacketError):
            self.freeze()
        (self.root / packet.KSM / 'unreviewed.py').unlink()
        (self.root / packet.KSM / 'policy.py').write_bytes(b'changed')
        with self.assertRaisesRegex(packet.PacketError, 'reviewed-ksm-input-drift'):
            self.freeze()

    def test_links_fifo_unreviewed_modes_and_source_bounds_refused(self):
        path = self.root / 'scripts/client/client.py'
        original = path.read_bytes()
        path.unlink(); path.symlink_to(self.root / 'README.md')
        with self.assertRaises(packet.PacketError):
            self.freeze()
        path.unlink(); os.link(self.root / 'README.md', path)
        with self.assertRaises(packet.PacketError):
            self.freeze()
        path.unlink(); os.mkfifo(path)
        with self.assertRaises(packet.PacketError):
            self.freeze()
        path.unlink(); path.write_bytes(original); path.chmod(0o600)
        with self.assertRaises(packet.PacketError):
            self.freeze()
        path.chmod(0o644)
        with patch.object(packet, 'FILE_LIMIT', 16), self.assertRaises(packet.PacketError):
            self.freeze()

    def test_symlink_extension_directory_and_package_init_refused(self):
        self.write(packet.DEVELOPMENT + '/__init__.py')
        with self.assertRaises(packet.PacketError):
            self.freeze()
        (self.root / packet.DEVELOPMENT / '__init__.py').unlink()
        (self.root / 'scripts/client/nested').symlink_to(self.root / 'tests', target_is_directory=True)
        with self.assertRaises(packet.PacketError):
            self.freeze()

    def test_metadata_pin_stage_source_and_virtual_audit_drift_refused(self):
        self.pins['scripts/virtual/tooling-audit.json'] = 'f' * 64
        with self.assertRaises(packet.PacketError):
            self.freeze()
        self.pins['scripts/virtual/tooling-audit.json'] = self.json('scripts/virtual/tooling-audit.json', {'tooling_lock_sha256': 'f' * 64})
        with self.assertRaisesRegex(packet.PacketError, 'virtual-metadata-binding-drift'):
            self.freeze()

    def test_candidate_cannot_overwrite_initial_or_existing_packet(self):
        self.freeze()
        with self.assertRaises(packet.PacketError):
            self.freeze()
        with self.assertRaises(packet.PacketError):
            packet.freeze(self.root, self.root / 'unreviewed.lock.json', self.root / packet.INITIAL, self.initial_sha, self.pins)


class PreflightTests(Base):
    def setUp(self):
        super().setUp(); self.freeze()

    def check(self, root=None):
        root = root or self.root
        return packet.preflight(root, root / packet.LOCK, self.packet_sha, COMMIT, self.pins)

    def test_git_bound_preflight_hashes_all_source_blobs_and_packet(self):
        with self.git_fixture():
            self.assertEqual(self.check(), self.value)
        blob_calls = [args for args in self.git_calls if args[:2] == ['cat-file', 'blob']]
        self.assertEqual(len(blob_calls), len(self.value['source_files']) + 1)

    def test_copied_preflight_reads_actual_isolated_file_bytes_and_modes(self):
        copied = Path(self.temp.name) / 'copied'
        packet.snapshot(self.root, copied, self.value)
        self.assertEqual((copied / 'scripts/virtual/gbm_probe.c').read_bytes(), (self.root / 'scripts/virtual/gbm_probe.c').read_bytes())
        with self.git_fixture(copied):
            self.assertEqual(self.check(copied), self.value)
        (copied / 'scripts/client/client.py').write_bytes(b'changed after copy')
        with self.assertRaisesRegex(packet.PacketError, 'packet-source-map-drift'):
            self.check(copied)

    def test_untracked_new_executable_or_modified_bytes_modes_block_execution(self):
        self.write('scripts/client/new_stage.py', mode=0o755)
        with self.assertRaisesRegex(packet.PacketError, 'packet-source-map-drift'):
            self.check()
        (self.root / 'scripts/client/new_stage.py').unlink()
        (self.root / 'scripts/client/client.py').chmod(0o755)
        with self.assertRaisesRegex(packet.PacketError, 'packet-source-map-drift'):
            self.check()

    def test_initial_and_generated_maps_cannot_be_substituted_in_packet(self):
        self.value['generated_fixture_files']['baseline/source']['sha256'] = 'f' * 64
        self.packet_sha = self.json(packet.LOCK, self.value)
        with self.assertRaisesRegex(packet.PacketError, 'packet-initial-lock-binding-drift'):
            self.check()

    def test_full_commit_and_exact_runtime_pins_required(self):
        for commit in ('main', COMMIT[:-1], 'C' * 40, None):
            with self.subTest(commit=commit), self.assertRaisesRegex(packet.PacketError, 'full-github-sha-required'):
                packet.preflight(self.root, self.packet_path, self.packet_sha, commit)
        pins = dict(self.pins); pins['scripts/ci/inputs.lock.json'] = 'f' * 64
        with self.assertRaisesRegex(packet.PacketError, 'runtime-metadata-pins-drift'):
            packet.preflight(self.root, self.packet_path, self.packet_sha, COMMIT, pins)

    def test_noncommit_object_or_different_checkout_head_refused(self):
        for kind in ('type', 'head'):
            with self.subTest(kind=kind), self.git_fixture():
                if kind == 'type':
                    self.git_type = b'tree\n'
                else:
                    self.git_head = 'd' * 40
                with self.assertRaisesRegex(packet.PacketError, 'github-checkout-commit-drift'):
                    self.check()

    def test_boolean_schema_is_not_an_integer_protocol_version(self):
        self.value['schema_version'] = True
        self.packet_sha = self.json(packet.LOCK, self.value)
        with self.assertRaisesRegex(packet.PacketError, 'packet-contract-refused'):
            self.check()

    def test_extra_missing_and_changed_git_tree_modes_or_blobs_refused(self):
        for kind in ('extra', 'missing', 'mode', 'blob', 'symlink', 'packet'):
            with self.subTest(kind=kind):
                with self.git_fixture():
                    name = 'scripts/client/client.py'
                    if kind == 'extra':
                        self.tree['scripts/client/omitted.py'] = self.tree[name]
                    elif kind == 'missing':
                        del self.tree[name]
                    elif kind == 'mode':
                        self.tree[name][0] = '100755'
                    elif kind == 'blob':
                        self.blobs[self.tree[name][2]] = b'Git source differs'
                    elif kind == 'symlink':
                        self.tree[name][0] = '120000'
                    else:
                        self.blobs[self.tree[packet.LOCK][2]] = b'uncommitted packet'
                    with self.assertRaises(packet.PacketError):
                        self.check()

    def test_readonly_git_failure_timeout_is_sanitized(self):
        for error in (OSError('PRIVATE PATH'), subprocess.TimeoutExpired('PRIVATE COMMAND', 30)):
            with patch.object(packet.subprocess, 'run', side_effect=error), self.assertRaises(packet.PacketError) as failure:
                self.check()
            self.assertNotIn('PRIVATE', str(failure.exception))

    def test_git_helper_refuses_mutation_or_unbounded_output_before_command(self):
        for args in (['checkout', 'main'], ['fetch'], ['cat-file', 'blob', 'main'], ['rev-parse', '--all']):
            with self.subTest(args=args), self.assertRaisesRegex(packet.PacketError, 'readonly-git-query-required'):
                packet.git(self.root, args)
        with self.assertRaises(packet.PacketError):
            packet.git(self.root, ['rev-parse', 'HEAD'], packet.FILE_LIMIT + 1)

    def test_packet_mode_and_missing_git_packet_binding_refused(self):
        with self.git_fixture():
            del self.tree[packet.LOCK]
            with self.assertRaisesRegex(packet.PacketError, 'git-packet-binding-drift'):
                self.check()
        self.packet_path.chmod(0o755)
        with self.assertRaisesRegex(packet.PacketError, 'runtime-packet-path-required'):
            self.check()

    def test_git_override_environment_not_used(self):
        with patch.dict(os.environ, {'GIT_DIR': '/private', 'GIT_REPLACE_REF_BASE': 'private'}), self.git_fixture():
            self.check()

    def test_snapshot_rejects_source_drift_and_unsafe_targets(self):
        with self.assertRaises(packet.PacketError):
            packet.snapshot(self.root, self.root / 'copied', self.value)
        (self.root / 'scripts/client/client.py').write_bytes(b'drift')
        with self.assertRaisesRegex(packet.PacketError, 'snapshot-source-drift'):
            packet.snapshot(self.root, Path(self.temp.name) / 'copy', self.value)

    def test_duplicate_json_and_private_path_errors_have_bounded_codes(self):
        for data in (b'{"x":1,"x":2}', b'{"x":{"y":1,"y":2}}', b'NaN'):
            with self.assertRaises(packet.PacketError):
                packet.decode(data)
        for name in ('../PRIVATE', '/private/path', 'scripts/.gnupg/PRIVATE', 'scripts/a\nPRIVATE'):
            with self.assertRaises(packet.PacketError) as failure:
                packet.relative(name)
            self.assertNotIn('PRIVATE', str(failure.exception))


class ComposedTests(Base):
    """Current maintained261 source fixtures; historical159 is refusal-only."""
    def setUp(self):
        super().setUp()
        recipes=packet.decode(packet.read(self.root/'scripts/ci/recipes.lock.json')[0])
        for directory,count in (('packages/two',23),('packages/three',23),('packages/four',23)):
            recipes[directory]={}
            for number in range(count):
                name='input-'+str(number);path=self.write(directory+'/'+name)
                recipes[directory][name]=digest(path.read_bytes())
        self.json('scripts/ci/recipes.lock.json',recipes)
        self.write('scripts/ci/native_arm.py', b'# SYNTHETIC SOURCE ONLY; never executed\n')
        locked,_=packet.recipe_paths(self.root)
        original=packet.initial_paths(self.root,locked)
        for number in range(161-len(original)):
            original.add(self.write('examples/filler-'+str(number)).relative_to(self.root).as_posix())
        self.initial.update(source_files=packet.rows(self.root,original),
            recipes_sha256=digest((self.root/'scripts/ci/recipes.lock.json').read_bytes()),
            generated_fixture_files={'baseline/file-'+str(number):{'sha256':'e'*64,'mode':0o644} for number in range(127)})
        self.initial_sha=self.json(packet.INITIAL,self.initial)
        for name in packet.COMPOSED_EXTRA:
            if not (self.root/name).exists():self.write(name)
        for path,prefix in packet.COMPOSED_MAPS.items():
            names={packet.relative(name).name for name in packet.COMPOSED_EXTRA
                   if name.startswith(prefix+'/') and name.endswith('.py')}
            self.json(path,{name:packet.read(self.root/prefix/name)[1] for name in names})
        self.json(packet.GENERIC_POLICY,{'supported_models':[],'platform_scope':'generic-builder-only','review_status':'ACCEPTED'})
        baseline = dict(packet.BASELINE_DECLARATION,
            integration_sha256=self.initial_sha,
            inputs_sha256=digest((self.root/'scripts/ci/inputs.lock.json').read_bytes()),
            recipes_sha256=digest((self.root/'scripts/ci/recipes.lock.json').read_bytes()),
            native_sha256=digest((self.root/'scripts/ci/native_arm.py').read_bytes()),
            inventory_sha256=digest((self.root/packet.BASELINE_INVENTORY).read_bytes()))
        self.json(packet.BASELINE_CONTRACT, baseline)
        packet.BASELINE_INITIAL = self.initial_sha
        for name, value in (('BASELINE_DECLARATION', baseline),
                            ('BASELINE_PACKAGES', baseline['inventory_sha256'])):
            binding = patch.object(packet, name, value)
            binding.start(); self.addCleanup(binding.stop)
        self.pins={name:digest((self.root/name).read_bytes()) for name in packet.COMPOSED_PINS | {packet.BASELINE_CONTRACT, packet.BASELINE_INVENTORY}}

    def freeze(self):
        self.packet_path=self.root/packet.LOCK
        self.packet_sha=packet.freeze_composed(self.root,self.packet_path,self.root/packet.INITIAL,self.initial_sha,self.pins)
        self.value=packet.decode(self.packet_path.read_bytes());return self.value

    def check(self):
        return packet.preflight_composed(self.root,self.packet_path,self.packet_sha,COMMIT,self.pins)

    def test_exact_union_and_git_copy_allow_separate_unexecuted_installer(self):
        value=self.freeze()
        self.assertEqual(len(value['source_files']),261);self.assertEqual(len(value['initial_source_files']),161)
        self.assertEqual(len(value['generated_fixture_files']),127);self.assertEqual(len(value['metadata_pins']),14)
        self.write('scripts/install/local_transaction.py',b'UNSELECTED NO ACTOR')
        with self.git_fixture():self.assertEqual(self.check(),value)
        copied=Path(self.temp.name)/'copy';packet.snapshot(self.root,copied,value)
        self.assertFalse((copied/'scripts/install').exists())
        self.assertEqual(packet.rows(copied,value['source_files']),value['source_files'])

    def test_historical159_and_prior160_do_not_fall_back_into_current_baseline(self):
        for count, fixture_count in ((159,125),(160,125)):
            legacy = dict(self.initial,
                source_files=dict(list(self.initial['source_files'].items())[:count]),
                generated_fixture_files=dict(list(self.initial['generated_fixture_files'].items())[:fixture_count]))
            with self.subTest(count=count), self.assertRaises(packet.PacketError):
                packet.composed_paths(legacy)

    def test_legacy_scan_still_refuses_expanded_root(self):
        with self.assertRaisesRegex(packet.PacketError,'initial-source-map-drift'):packet.scan(self.root,self.initial)

    def test_selected_map_or_source_drift_refuses(self):
        self.freeze();target=self.root/'scripts/virtual/image_decode_report.py';target.write_bytes(b'changed')
        with self.assertRaisesRegex(packet.PacketError,'packet-source-map-drift'):self.check()
        with self.assertRaisesRegex(packet.PacketError,'snapshot-source-drift'):
            packet.snapshot(self.root,Path(self.temp.name)/'copy',self.value)

    def test_map_omitted_extra_or_altered_row_refuses(self):
        for omitted in ('initial','extra','map'):
            with self.subTest(omitted=omitted):
                if (self.root/packet.LOCK).exists():(self.root/packet.LOCK).unlink()
                self.freeze();value=packet.decode(self.packet_path.read_bytes())
                if omitted=='map':
                    name=next(iter(packet.COMPOSED_MAPS));data=packet.decode((self.root/name).read_bytes())
                    member=next(iter(data));data[member]['sha256']='a'*64
                    with self.assertRaisesRegex(packet.PacketError,'composed-map-binding-drift'):
                        packet.composed_bindings(self.root,{**value['source_files'],name:{'mode':0o644,'sha256':self.json(name,data)}},
                                                {**self.pins,name:digest((self.root/name).read_bytes())})
                    return
                del value['source_files'][next(iter(self.initial['source_files'])) if omitted=='initial' else 'scripts/virtual/image_decode_report.py']
                self.packet_sha=self.json(packet.LOCK,value)
                with self.assertRaises(packet.PacketError):self.check()

    def test_unknown_mode_legacy_schema_and_pin_set_refuse(self):
        self.freeze()
        for mutate in (lambda value:value.update(schema_version=1),lambda value:value.update(composition='repository-svg-zsh'),
                       lambda value:value['metadata_pins'].pop(packet.GENERIC_POLICY)):
            value=packet.decode(self.packet_path.read_bytes());mutate(value);self.packet_sha=self.json(packet.LOCK,value)
            with self.assertRaises(packet.PacketError):self.check()
            self.packet_path.unlink();self.freeze()

    def test_git_missing_selected_row_mode_or_blob_drift_refuses(self):
        self.freeze()
        for kind in ('missing','mode','blob'):
            with self.subTest(kind=kind),self.git_fixture():
                name='scripts/virtual/image_decode_probe.c'
                if kind=='missing':del self.tree[name]
                elif kind=='mode':self.tree[name][0]='100755'
                else:self.blobs[self.tree[name][2]]=b'drift'
                with self.assertRaises(packet.PacketError):self.check()

    def test_cache_or_extra_packet_row_and_fixture_drift_refuse(self):
        self.freeze()
        for key,change in (('source_files',lambda value:value.update({'scripts/install/local_transaction.py':{'sha256':'a'*64,'mode':0o644}})),
                           ('generated_fixture_files',lambda value:value.pop(next(iter(value))))):
            value=packet.decode(self.packet_path.read_bytes());change(value[key]);self.packet_sha=self.json(packet.LOCK,value)
            with self.assertRaises(packet.PacketError):self.check()
            self.packet_path.unlink();self.freeze()
        self.write('scripts/virtual/unknown.pyc',b'cache')
        with self.assertRaisesRegex(packet.PacketError,'source-python-cache-refused'):self.check()


if __name__ == '__main__':
    unittest.main()
