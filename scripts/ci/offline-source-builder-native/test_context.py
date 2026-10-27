# SPDX-License-Identifier: MIT
"""Focused source/cache/predicate controls; no native builder or Git executes."""
import copy
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent; ROOT = HERE.parents[2]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path); value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value); return value
O = module('_offline_context_owner', HERE / 'owner.py')
D = module('_offline_driver_predicate', HERE / 'execute_builder.py')

class ContextControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.work = Path(self.temp.name)
        self.feature = Path(os.environ.get('OFFLINE_FEATURE_TEST_ROOT',
            str(Path(os.environ.get('RUNNER_TEMP', '/not-selected')) / 'offline-source-feature-code')))

    def test_exact_closed_source_aliases_and_original_recipe_correspondence(self):
        manifest = O.source(ROOT, O.sha(O.read(HERE / 'source-map.json')))
        self.assertEqual(O.read(ROOT / O.ALIASES[0]), O.read(ROOT / O.ALIASES[1]))
        self.assertEqual(len(O.load(HERE / 'reviewed11.json')), 11)
        self.assertEqual(O.sha(O.read(HERE / 'bootstrap-source52-map.json')),
                         '719d3306bbd9a72566f93b517798e2cec2cff2806910dcc164802cdb3fb70555')
        plan = O.load(HERE / 'source-plan.json')
        self.assertEqual(plan['recipe_inputs'], O.load(HERE / 'recipe-inputs.json'))
        self.assertEqual(plan['catalog_sha256'], O.sha(O.read(HERE / 'source-inputs.json')))
        self.assertIn('scripts/ci/native_arm.py', manifest['files'])

    def test_context_extra_leaf_or_alias_change_refuses(self):
        root = self.work / 'source'; shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns('.git'))
        (root / 'extra').write_text('unselected')
        with self.assertRaises(ValueError): O.source(root, O.sha(O.read(HERE / 'source-map.json')))
        (root / 'extra').unlink(); (root / O.ALIASES[1]).write_text('changed')
        with self.assertRaises(ValueError): O.source(root, O.sha(O.read(HERE / 'source-map.json')))

    def test_all_seven_future_feature_files_are_required_without_running_them(self):
        self.assertEqual(len(O.feature_files(self.feature)), 7)
        root = self.work / 'feature'
        for name in {**O.feature_files(self.feature), **O.held_helpers(self.feature)}:
            target = root / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.feature / name, target)
        path = root / 'scripts/build/build_v2.py'; path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'selected feature code differs'): O.feature_files(root)

    def test_original_builder_bytes_remain_held_beside_versioned_execution_files(self):
        self.assertEqual(len(O.held_helpers(self.feature)), 3)
        root = self.work / 'held-feature'
        for name in {**O.feature_files(self.feature), **O.held_helpers(self.feature)}:
            target = root / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.feature / name, target)
        target = root / 'scripts/build/build.py'; target.write_bytes(target.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'original builder bytes changed'): O.feature_files(root)

    def test_actual_versioned_entrypoint_imports_and_cli_help_need_no_native_actor(self):
        for name, option in (('build_v2.py', '--source-plan-sha256'), ('compare_v2.py', '--require-bytes')):
            result = subprocess.run([sys.executable, '-I', '-S', '-B',
                str(self.feature / 'scripts/build' / name), '--help'], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(option, result.stdout)

    def test_actual_offline_cache_import_verifies_with_zero_python_socket_operations(self):
        events = []
        def deny(event, args):
            if event.startswith('socket.'):
                events.append(event); raise AssertionError('source import attempted network')
        sys.addaudithook(deny)
        path = O.seed_source_cache(self.feature, self.work); before = O.cache_snapshot(path)
        self.assertEqual(len(before), 3); self.assertEqual(events, [])
        origin = O.load(self.work / 'source-cache-origin.json')
        self.assertEqual(origin['status'], 'IMPORTED_RETAINED_PINNED_BYTES_OFFLINE')
        self.assertFalse(origin['legal_acceptance'])
        self.assertEqual(origin['verified']['sources'][0]['status'], 'verified')
        self.assertEqual(before, O.cache_snapshot(path))

    def test_tampered_retained_archive_refuses_before_cache_creation(self):
        lane = self.work / 'lane'; shutil.copytree(HERE, lane)
        path = lane / 'zlib-1.3.2.tar.gz'; path.write_bytes(b'X' + path.read_bytes()[1:])
        with patch.object(O, 'HERE', lane), self.assertRaisesRegex(ValueError, 'retained zlib object mismatch'):
            O.seed_source_cache(self.feature, self.work)
        self.assertFalse((self.work / 'source-cache').exists())

    def fixture(self):
        out = self.work / 'attempt-1'; feature = self.work / 'feature'
        observation = dict(name='cachy-asahi-' + 'a' * 16, image='sha256:' + 'b' * 64,
                           output=str(out), feature_root=str(feature), user='1001:1001')
        mounts = [dict(Destination=dst, Source=src, RW=rw, Type='bind') for dst, src, rw in
            [('/inputs', str(out / 'inputs'), False), ('/out', str(out / 'artifacts'), True),
             ('/builder-entry.sh', str(feature / 'scripts/build/container-entry-v2.sh'), False),
             ('/expected-packages.lock', str(out / 'expected-packages.lock'), False),
             ('/offline-sources', str(out / 'source-material/srcdest'), False)]]
        row = dict(Name='/' + observation['name'], Image=observation['image'], Mounts=mounts,
            Config=dict(User='1001:1001', Env=['CACHY_ASAHI_OFFLINE_SOURCES=1']),
            HostConfig=dict(NetworkMode='none', ReadonlyRootfs=True, AutoRemove=True, Privileged=False,
                PidsLimit=512, Memory=4 * 1024**3, NanoCpus=4_000_000_000, CapDrop=['ALL'], CapAdd=[],
                SecurityOpt=['no-new-privileges'], Tmpfs={'/tmp': 'rw,nosuid,nodev,exec,size=4g'}))
        return observation, row

    def test_synthetic_daemon_predicate_refuses_network_writable_source_cache_mount_and_capability(self):
        observation, row = self.fixture(); D.check_inspection(row, observation)
        changed = copy.deepcopy(row); changed['HostConfig']['NetworkMode'] = 'bridge'
        with self.assertRaises(ValueError): D.check_inspection(changed, observation)
        changed = copy.deepcopy(row); changed['Mounts'][-1]['RW'] = True
        with self.assertRaises(ValueError): D.check_inspection(changed, observation)
        changed = copy.deepcopy(row); changed['Mounts'].append(dict(Destination='/cache', Source='/source-cache', RW=False, Type='bind'))
        with self.assertRaises(ValueError): D.check_inspection(changed, observation)
        changed = copy.deepcopy(row); changed['HostConfig']['CapAdd'] = ['SYS_ADMIN']
        with self.assertRaises(ValueError): D.check_inspection(changed, observation)

    def test_native_admission_and_missing_feature_sha_refuse_before_actor_calls(self):
        with self.assertRaises(ValueError): O.admitted(SimpleNamespace(execute=False))
        args = SimpleNamespace(source_root=ROOT, manifest_sha256=O.sha(O.read(HERE / 'source-map.json')),
            source_sha='a' * 40, feature_code_sha=None)
        env = dict(GITHUB_SHA=args.source_sha, GITHUB_WORKFLOW_SHA=args.source_sha,
            GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi', GITHUB_EVENT_NAME='workflow_dispatch',
            GITHUB_RUN_ATTEMPT='1', GITHUB_RUN_ID='123',
            GITHUB_WORKFLOW_REF='Gabriel-Kahen/cachy-asahi/.github/workflows/native-arm-build.yml@fixture')
        with patch.dict(os.environ, env, clear=True), patch.object(O.subprocess, 'check_output') as command:
            with self.assertRaisesRegex(ValueError, 'mandatory exact canonical feature SHA'): O.binding(args, first=True)
            command.assert_not_called()

    def test_one_or_reused_pair_record_cannot_qualify(self):
        outputs = [self.work / 'one', self.work / 'two']
        for path in outputs:
            path.mkdir(); O.save(path / 'provenance.json', dict(clean_environment_id='same'))
        for selected in (outputs[:1], outputs):
            with self.assertRaisesRegex(ValueError, 'two distinct actual fresh builder containers'):
                O.validate_pair_records(selected, 'sha256:' + 'b' * 64)

    def test_observation_update_failure_preserves_initial_cleanup_identity(self):
        path = self.work / 'observation.json'; initial = dict(name='cachy-asahi-' + 'a' * 16)
        D.save(path, initial)
        with patch.object(D.os, 'replace', side_effect=OSError('synthetic interrupted publication')):
            with self.assertRaises(OSError): D.save(path, dict(name='changed'))
        self.assertEqual(O.load(path), initial)
        self.assertEqual(list(self.work.iterdir()), [path])

    def test_presecret_feature_failure_retains_explicit_failure_without_native_admission(self):
        manifest = O.source(ROOT, O.sha(O.read(HERE / 'source-map.json'))); proof = self.work / 'proof.json'
        O.save(proof, dict(status='SYNTHETIC_CONTEXT_PROOF')); own = dict(feature_code_sha='a' * 40)
        args = SimpleNamespace(work=self.work, proof=proof, public=self.work / 'public', manifest_sha256='b' * 64)
        def binding(args, **kwargs):
            if kwargs.get('feature_required') is False: return manifest, own
            raise ValueError('synthetic missing presecret feature proof')
        with patch.object(O, 'binding', side_effect=binding), patch.object(O, 'native_cleanup') as native:
            O.cleanup(args); native.assert_not_called(); self.assertEqual(O.retain(args), 1)
        receipt = O.load(args.public / 'receipt.json')
        self.assertEqual(receipt['status'], 'FAIL_OR_PARTIAL_TOOL_COMPONENT')
        self.assertEqual(receipt['native_component'], 'NOT QUALIFIED')
        self.assertIn('feature_proof_error', receipt)

if __name__ == '__main__':
    unittest.main(verbosity=2)
