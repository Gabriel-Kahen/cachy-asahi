# SPDX-License-Identifier: MIT
"""Synthetic data/ownership fixtures; native builds, Docker and hardware NOT RUN."""
import copy
import builtins
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import ModuleType, SimpleNamespace
import unittest

HERE = Path(__file__).parent
ROOT = HERE.resolve().parents[2]


def module(name):
    result = ModuleType(name)
    result.__file__ = str(HERE / (name + '.py'))
    exec(compile((HERE / (name + '.py')).read_bytes(), result.__file__, 'exec'), result.__dict__)
    return result


c, consumer, public = (module(name) for name in ('executor_contract', 'consumer', 'public'))
CONTRACT_DIR = HERE.parent / 'ksm-lifecycle'
contract = ModuleType('held_contract_fixture')
contract.__file__ = str(CONTRACT_DIR / 'contract.py')
exec(compile((CONTRACT_DIR / 'contract.py').read_bytes(), contract.__file__, 'exec'), contract.__dict__)
fixture_module = ModuleType('held_contract_fixtures')
fixture_module.__file__ = str(CONTRACT_DIR / 'test_contract.py')
def fixture_import(name, *args, **kwargs):
    return contract if name == 'contract' else builtins.__import__(name, *args, **kwargs)
fixture_module.__dict__['__builtins__'] = {**vars(builtins), '__import__': fixture_import}
exec(compile((CONTRACT_DIR / 'test_contract.py').read_bytes(), fixture_module.__file__, 'exec'), fixture_module.__dict__)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


class ExecutorContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.producer = self.root / 'producer'
        self.image = 'sha256:' + 'a' * 64
        self.binding = dict(source_commit='b' * 40, run_id='123', packet_sha256='c' * 64,
                            uid=1000, gid=1000, runner_arch='ARM64', docker_endpoint='unix:///run/docker.sock',
                            daemon_id='daemon-id', nonce='d' * 32)
        paths = ['scripts/ci/inputs.lock.json', 'scripts/ci/recipes.lock.json', 'scripts/ci/native_arm.py']
        self.files = {name: (ROOT / name).read_bytes() for name in paths}
        self.snapshot = SimpleNamespace(files=self.files, provenance={'commit': self.binding['source_commit'],
                                                                     'packet_sha256': self.binding['packet_sha256']})
        result = dict(mode='build', status='native-builds-and-byte-comparison-pass', native_build='PASS',
                      hardware_validation='NOT RUN', verified_signed_packages=248, reviewed_inputs_sha256=c.INPUTS_SHA,
                      reviewed_recipes_sha256=c.RECIPES_SHA, bootstrap_script_sha256=c.PRODUCER_SHA)
        boot = dict(status='image-provisioned', image_id=self.image, inputs_sha256=c.INPUTS_SHA,
                    packages_lock_sha256=c.PACKAGES_SHA)
        self.runner = dict(repository='Gabriel-Kahen/cachy-asahi', commit=self.binding['source_commit'], run_id='123',
                           uid=1000, gid=1000, runner_arch='ARM64', runner_os='Linux', kernel=dict(system='Linux', machine='aarch64'),
                           docker_server_arch='aarch64', docker_endpoint='unix:///run/docker.sock', bootstrap_script_sha256=c.PRODUCER_SHA)
        self.lock = (ROOT / 'scripts/port/refreshed-desktop/proposed-builder-inventory.lock').read_bytes()
        for name, data in [('result.json', encoded(result)), ('bootstrap.json', encoded(boot)), ('runner.json', encoded(self.runner)),
                           ('image-id', (self.image + '\n').encode()), ('inputs.lock.json', self.files[paths[0]]), ('packages.lock', self.lock)]:
            write(self.producer / name, data)
        self.names = []
        recipes = json.loads(self.files['scripts/ci/recipes.lock.json'])
        for recipe_path, recipe in recipes.items():
            filename = Path(recipe_path).name + '-fixture-any.pkg.tar.gz'
            for index in (1, 2):
                name = 'cachy-asahi-' + f'{len(self.names)+1:016x}'
                self.names.append(name)
                root = self.producer / (Path(recipe_path).name + f'-{index}')
                fields = {}
                for field in ('build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock',
                              'artifacts/generated.SRCINFO', 'artifacts/environment.txt', 'artifacts/config.sha256',
                              'artifacts/makepkg.conf', 'artifacts/pacman.conf', 'artifacts/' + filename):
                    data = self.lock if field.endswith('packages.lock') else b'fixture'
                    if field == 'validation.json':
                        data = encoded({'errors': [], 'artifacts': [{'errors': []}]})
                    fields[field] = write(root / field, data)
                for field in recipe:
                    data = (ROOT / recipe_path / field).read_bytes()
                    write(root / 'inputs' / field, data)
                provenance = dict(schema_version=1, status='built-package-static-pass', mode='native', network='none',
                                  image=self.image, image_id=self.image, exit_code=0, hardware_status='NOT RUN',
                                  expected_packages_sha256=c.PACKAGES_SHA, entry_script_sha256=c.ENTRY_SHA,
                                  recipe_inputs=recipe, builder_host_arch='aarch64', source_date_epoch=1791748800,
                                  clean_environment_id=name, command=['docker', 'run', '--name', name, '--user', '1000:1000',
                                                                    self.image, '/builder-entry.sh'],
                                  files=fields, artifacts={filename: fields['artifacts/' + filename]})
                write(root / 'provenance.json', encoded(provenance))
            comparison = dict(status='contents-reproduced', errors=[], hardware_status='NOT RUN', independence_limit='fixture',
                              packages={filename: dict.fromkeys(('installed_contents_equal', 'pkginfo_equal', 'bytes_equal', 'buildinfo_equal'), True)})
            write(self.producer / (Path(recipe_path).name + '-compare.json'), encoded(comparison))
        self.rows = self.journal(self.names)

    def journal(self, names, final=False):
        def row(event, phase='producer', **fields):
            return dict(event=event, phase=phase, nonce=self.binding['nonce'], **fields)
        def operation(arguments, phase='producer', output=b'', code=0):
            return [row('docker-operation-reserved', phase, argv=['docker', '--host=' + self.binding['docker_endpoint'], *arguments]),
                    row('docker-operation-completed', phase, returncode=code, stdout_bytes=len(output), stdout_sha256=c.sha(output))]
        rows = [row('opened', docker_sha256='f'*64, docker_socket_device=7, docker_socket_inode=99,
                    **{k: v for k, v in self.binding.items() if k not in {'nonce', 'runner_arch'}}),
                row('docker-operation-reserved', argv=['docker', '--host=' + self.binding['docker_endpoint'], 'info', '--format', '{{.ID}}']),
                row('docker-operation-completed', returncode=0, stdout_bytes=9, stdout_sha256=c.sha(b'daemon-id')),
                row('image-reserved', context_sha256='e'*64, tag='ksm-native-' + self.binding['nonce'])]
        rows += operation(['build', '/fixture/context'])
        rows += [row('image-bound', context_sha256='e'*64, id=self.image)]
        for index, name in enumerate(['ksm-inventory-' + self.binding['nonce']] + names):
            phase = 'producer' if index <= 8 else f'ksm-{index - 8}'
            ident = f'{index+1:064x}'
            rows += [row('container-reserved', phase, name=name, image=self.image)]
            rows += operation(['create', '--name', name], phase, (ident + '\n').encode())
            rows += [row('container-bound', phase, name=name, id=ident), row('container-start-reserved', phase, name=name, id=ident)]
            rows += operation(['start', '--attach', ident], phase)
            rows += [
                     row('container-exited', phase, name=name, id=ident, status='exited', exit_code=0, oom_killed=False),
                     row('container-removal-reserved', phase, name=name, id=ident)]
            rows += operation(['rm', '--force', '--volumes', ident], phase)
            for selector in ('name=^/' + name + '$', 'id=' + ident):
                rows += operation(['container', 'ls', '--all', '--quiet', '--no-trunc', '--filter', selector], phase)
            rows += [row('container-absent', phase, name=name, id=ident)]
        if final:
            absent = ('Error response from daemon: No such image: ' + self.image).encode()
            rows += [row('image-removal-reserved', 'ksm-2', id=self.image)]
            rows += operation(['image', 'rm', '--no-prune', self.image], 'ksm-2')
            for selector in ('reference=ksm-native-' + self.binding['nonce'], 'label=org.cachy-asahi.ksm-job=' + self.binding['nonce']):
                rows += operation(['image', 'ls', '--quiet', '--no-trunc', '--filter', selector], 'ksm-2')
            rows += [
                     row('docker-operation-reserved', 'ksm-2', argv=['docker', '--host=' + self.binding['docker_endpoint'], 'image', 'inspect', self.image]),
                     row('docker-operation-completed', 'ksm-2', returncode=1, stdout_bytes=len(absent), stdout_sha256=c.sha(absent)),
                     row('image-absent', 'ksm-2', id=self.image),
                     row('cleanup-result', 'ksm-2', status='PASS', containers_absent=True, owned_image_absent=True,
                         legacy_build_cache_absence='NOT ESTABLISHED')]
        return rows

    def accept(self, **kwargs):
        return c.validate_producer(self.snapshot, self.producer, 0, self.binding, self.rows, consumer=consumer, **kwargs)

    def test_complete_fixture_is_immutable_and_preserves_exact_bytes(self):
        bundle = self.accept()
        self.assertEqual(bundle['image_id'], self.image)
        self.assertEqual(len(bundle['builds']), 8)
        self.assertEqual(bundle['data']['packages.lock'], self.lock)
        with self.assertRaises(TypeError):
            bundle['data']['packages.lock'] = b'changed'

    def test_exit_bool_nonzero_or_signal_refused(self):
        for code in (False, 1, -15):
            with self.assertRaises(ValueError):
                c.validate_producer(self.snapshot, self.producer, code, self.binding, self.rows, consumer=consumer)

    def test_foreign_runner_job_gid_or_arch_refused(self):
        for field, wrong in [('run_id', '124'), ('gid', 1001), ('uid', False), ('runner_arch', 'X64'), ('docker_server_arch', 'x86_64')]:
            changed = {**self.runner, field: wrong}
            write(self.producer / 'runner.json', encoded(changed))
            with self.assertRaises(ValueError):
                self.accept()
        write(self.producer / 'runner.json', encoded(self.runner))

    def test_endpoint_alias_requires_actual_same_socket_observations(self):
        alias = 'unix:///var/run/docker.sock'
        write(self.producer / 'runner.json', encoded({**self.runner, 'docker_endpoint': alias}))
        with self.assertRaises(ValueError):
            self.accept()
        good = {endpoint: {'device': 7, 'inode': 99} for endpoint in (alias, self.binding['docker_endpoint'])}
        self.assertEqual(self.accept(endpoint_observations=good)['runner_endpoint'], alias)
        good[alias]['inode'] = 100
        with self.assertRaises(ValueError):
            self.accept(endpoint_observations=good)

    def test_pending_unknown_failed_and_duplicate_immutable_id_refused(self):
        examples = [self.rows[:-1], self.rows + [{**self.rows[-1], 'event': 'request-failed'}],
                    self.rows + [{**self.rows[-1], 'event': 'unknown'}]]
        duplicate = copy.deepcopy(self.rows)
        bound = [row for row in duplicate if row['event'] == 'container-bound']
        bound[1]['id'] = bound[0]['id']
        examples.append(duplicate)
        for rows in examples:
            with self.assertRaises(ValueError):
                c.validate_journal(rows, self.binding, self.image, self.names)

    def test_exited_bool_oom_signal_or_pending_start_refused(self):
        for change in [{'exit_code': False}, {'exit_code': -15}, {'oom_killed': True}, {'status': 'running'}]:
            rows = copy.deepcopy(self.rows)
            next(row for row in rows if row['event'] == 'container-exited').update(change)
            with self.assertRaises(ValueError):
                c.validate_journal(rows, self.binding, self.image, self.names)

    def test_all_ten_owned_builds_final_image_absence_required(self):
        names = self.names + ['cachy-asahi-' + f'{index:016x}' for index in (9, 10)]
        rows = self.journal(names, final=True)
        self.assertTrue(c.validate_journal(rows, self.binding, self.image, names, final=True)['image_absent'])
        for shortened in (rows[:-1], rows[:-2], rows[:-3]):
            with self.assertRaises(ValueError):
                c.validate_journal(shortened, self.binding, self.image, names, final=True)

    def test_final_journal_refuses_image_removal_without_no_prune_or_with_force(self):
        names=self.names+['cachy-asahi-'+f'{index:016x}' for index in (9,10)]
        for replacement in (['image','rm',self.image],['image','rm','--force','--no-prune',self.image]):
            rows=self.journal(names,final=True)
            removal=next(row for row in rows if row['event']=='docker-operation-reserved' and row['argv'][2:4]==['image','rm'])
            removal['argv']=removal['argv'][:2]+replacement
            with self.assertRaises(ValueError):c.validate_journal(rows,self.binding,self.image,names,final=True)

    def test_valid_final_removal_cannot_hide_an_extra_pruning_operation(self):
        names=self.names+['cachy-asahi-'+f'{index:016x}' for index in (9,10)]
        for arguments in (['image','rm',self.image],['rmi',self.image],['image','prune'],['system','prune'],
                          ['--debug','image','rm',self.image],['--log-level=debug','system','prune'],
                          ['image','--debug','rm',self.image],['image','remove',self.image]):
            rows=self.journal(names,final=True)
            index=next(i for i,row in enumerate(rows) if row['event']=='docker-operation-reserved' and row['argv'][2:4]==['image','rm'])
            reserved=copy.deepcopy(rows[index]);reserved['argv']=reserved['argv'][:2]+arguments
            completed=copy.deepcopy(rows[index+1]);rows[index:index]=[reserved,completed]
            with self.assertRaises(ValueError):c.validate_journal(rows,self.binding,self.image,names,final=True)

    def test_original_build_artifact_and_recipe_hash_drift_refused(self):
        first = next(self.producer.glob('*-1'))
        artifact = next((first / 'artifacts').glob('*.pkg.tar.*'))
        original = artifact.read_bytes()
        artifact.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.accept()
        artifact.write_bytes(original)
        (first / 'inputs/NOTICE').write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.accept()

    def test_original_buildinfo_comparison_false_refused(self):
        path = next(self.producer.glob('*-compare.json'))
        record = json.loads(path.read_bytes())
        next(iter(record['packages'].values()))['buildinfo_equal'] = False
        path.write_bytes(encoded(record))
        with self.assertRaises(ValueError):
            self.accept()

    def test_capture_refuses_parent_link_leaf_link_hardlink_and_special(self):
        data = self.root / 'regular'; data.write_bytes(b'fixture')
        leaf = self.root / 'link'; leaf.symlink_to(data)
        parent = self.root / 'parent'; parent.symlink_to(self.producer, target_is_directory=True)
        fifo = self.root / 'fifo'; os.mkfifo(fifo)
        for path in (leaf, parent / 'result.json', fifo):
            with self.assertRaises((ValueError, OSError)):
                c.capture(path)
        hard = self.root / 'hard'; os.link(data, hard)
        with self.assertRaises(ValueError):
            c.capture(data)

    def test_duplicate_and_nonfinite_json_refused(self):
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(ValueError):
                c.decode(data)

    def ksm_fixture(self):
        fixture = fixture_module.ContractTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for number, root in enumerate(fixture.roots, 9):
            record = fixture.record(root)
            record['clean_environment_id'] = 'cachy-asahi-' + f'{number:016x}'
            command = record['command']
            command[command.index('--name') + 1] = record['clean_environment_id']
            command[command.index('--user') + 1] = '1000:1000'
            fixture.write_record(record, root)
        names = self.names + [fixture.record(root)['clean_environment_id'] for root in fixture.roots]
        paths = ['scripts/client/stage.py', 'scripts/ci/source_suites.py', 'scripts/port/ksm-lifecycle/stage.py',
                 'scripts/port/ksm-lifecycle/worker.py', 'scripts/port/ksm-lifecycle/contract.py']
        self.files.update({name: (ROOT / name).read_bytes() for name in paths})
        self.files.update({'packages/tools/cachy-asahi-ksmctl/' + name: (ROOT / 'packages/tools/cachy-asahi-ksmctl' / name).read_bytes()
                           for name in contract.INPUTS})
        producer = self.accept()
        pair = c.validate_ksm_pair(self.snapshot, producer, fixture.roots, [0, 0], fixture.map,
                                   self.journal(names), contract=contract, consumer=consumer)
        return producer, pair, names, fixture

    def test_held_contract_decodes_two_captured_fixture_builds(self):
        _, pair, _, fixture = self.ksm_fixture()
        self.assertEqual(pair['archive_bytes'], fixture.data)
        self.assertEqual(pair['package']['native_execution'], 'controller-receipt-required')
        self.assertEqual(len(pair['provenance_sha256']), 2)

    def test_ksm_requires_observed_exit_and_same_job_distinct_environment(self):
        producer, _, names, fixture = self.ksm_fixture()
        for exits in ([0, False], [0, -15]):
            with self.assertRaises(ValueError):
                c.validate_ksm_pair(self.snapshot, producer, fixture.roots, exits, fixture.map,
                                     self.journal(names), contract=contract, consumer=consumer)
        with self.assertRaises(ValueError):
            c.validate_ksm_pair(self.snapshot, producer, [fixture.roots[0]] * 2, [0, 0], fixture.map,
                                 self.journal(names), contract=contract, consumer=consumer)

    def public_fixture(self):
        producer, pair, names, _ = self.ksm_fixture()
        package = c.plain(pair['package'])
        pins = {name: c.sha(self.files[name]) for name in ('scripts/client/stage.py', 'scripts/ci/source_suites.py',
                'scripts/port/ksm-lifecycle/stage.py', 'scripts/port/ksm-lifecycle/worker.py', 'scripts/port/ksm-lifecycle/contract.py')}
        lifecycle = {key: self.binding[key] for key in ('source_commit', 'run_id', 'daemon_id', 'docker_endpoint')}
        lifecycle.update(image_id=self.image, status='PASS', source_sha256=pins, package=package,
                         hardware='NOT RUN', management='NOT RUN', published=False, private_artifacts_retained=False,
                         controller_tmp_removed='PASS', docker_boundary_closed='PASS', coordinator_uid=1000, coordinator_gid=1000,
                         runner_sha256=producer['sha256']['runner.json'], bootstrap_sha256=producer['sha256']['bootstrap.json'],
                         packages_sha256=c.PACKAGES_SHA, current_inputs_sha256=c.INPUTS_SHA,
                         docker_cli_sha256='f'*64, docker_socket_device=7, docker_socket_inode=99,
                         phases=[dict(phase=phase, status='PASS', container_cleanup='PASS',
                                      container_state=dict(status='exited', exit_code=0, oom_killed=False)) for phase in ('sign', 'lifecycle')])
        comparison = dict(status='contents-reproduced', errors=[], hardware_status='NOT RUN', independence_limit='synthetic',
                          packages={package['filename']: dict.fromkeys(('installed_contents_equal', 'pkginfo_equal', 'bytes_equal', 'buildinfo_equal'), True)})
        return producer, pair, names, lifecycle, comparison

    def test_public_exact_allowlist_after_all_actual_observation_fixtures(self):
        producer, pair, names, lifecycle, comparison = self.public_fixture()
        data, binding = c.public_acceptance(self.snapshot, producer, pair, comparison, 0, lifecycle, 0,
                                          self.journal(names, final=True), consumer=consumer, public=public)
        value = public.validate(data, binding, c.plain(pair['archives']))
        self.assertEqual(value['cleanup'], {'status': 'PASS', 'absence_verified': True})
        self.assertNotIn('source_commit', value['producer'])
        self.assertNotIn('worker', data.decode())

    def test_public_refuses_controller_signal_lifecycle_gid_and_uncertain_cleanup(self):
        producer, pair, names, lifecycle, comparison = self.public_fixture()
        for code in (False, -15, 1):
            with self.assertRaises(ValueError):
                c.public_acceptance(self.snapshot, producer, pair, comparison, 0, lifecycle, code,
                                    self.journal(names, final=True), consumer=consumer, public=public)
        lifecycle['coordinator_gid'] = 1001
        with self.assertRaises(ValueError):
            c.public_acceptance(self.snapshot, producer, pair, comparison, 0, lifecycle, 0,
                                self.journal(names, final=True), consumer=consumer, public=public)
        lifecycle['coordinator_gid'] = 1000
        rows = self.journal(names, final=True)
        rows[-1]['owned_image_absent'] = False
        with self.assertRaises(ValueError):
            c.public_acceptance(self.snapshot, producer, pair, comparison, 0, lifecycle, 0,
                                rows, consumer=consumer, public=public)

    def test_public_refuses_changed_observed_cli_or_socket(self):
        producer, pair, names, lifecycle, comparison = self.public_fixture()
        for key, changed in [('docker_cli_sha256', 'e'*64), ('docker_socket_inode', 100), ('docker_socket_device', False)]:
            bad = {**lifecycle, key: changed}
            with self.assertRaises(ValueError):
                c.public_acceptance(self.snapshot, producer, pair, comparison, 0, bad, 0,
                                    self.journal(names, final=True), consumer=consumer, public=public)

    def test_broker_opened_job_or_facade_pin_drift_refused(self):
        for key, wrong in [('packet_sha256', 'e'*64), ('daemon_id', 'other-daemon'), ('docker_socket_inode', False),
                           ('docker_sha256', 'bad'), ('nonce', 'a'*32)]:
            rows = copy.deepcopy(self.rows)
            rows[0][key] = wrong
            with self.assertRaises(ValueError):
                c.validate_journal(rows, self.binding, self.image, self.names)

    def test_pairing_pending_malformed_or_nonzero_operations_refused(self):
        cases = []
        for key, bad in [('returncode', False), ('returncode', 1), ('stdout_bytes', False), ('stdout_sha256', 'bad')]:
            rows = copy.deepcopy(self.rows)
            rows[2][key] = bad
            cases.append(rows)
        cases.append(self.rows[:2] + self.rows[3:])
        cases.append(self.rows + [self.rows[1]])
        rows = copy.deepcopy(self.rows); rows[1]['argv'][1] = '--host=tcp://remote'; cases.append(rows)
        for rows in cases:
            with self.assertRaises(ValueError):
                c.validate_journal(rows, self.binding, self.image, self.names)

    def test_only_exact_bound_image_absence_nonzero_is_accepted(self):
        names = self.names + ['cachy-asahi-' + f'{index:016x}' for index in (9, 10)]
        for changed in [{'stdout_sha256': c.sha(b'not found')}, {'stdout_bytes': False}, {'returncode': -15}]:
            rows = self.journal(names, final=True)
            next(row for row in rows if row['event'] == 'docker-operation-completed' and row['returncode'] == 1).update(changed)
            with self.assertRaises(ValueError):
                c.validate_journal(rows, self.binding, self.image, names, final=True)

    def test_actual_broker_fixture_eleven_environment_sequence_consumed(self):
        fixtures = module('test_broker')
        fixture = fixtures.BrokerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        response = fixture.owner.request(['docker', 'context', 'inspect'])
        self.assertEqual(response.returncode, 0)
        self.assertEqual(json.loads(response.stdout)[0]['Endpoints']['docker']['Host'], fixture.backend.endpoint)
        self.assertEqual(fixture.backend.calls[-1], ['docker', '--host=' + fixture.backend.endpoint, 'context', 'inspect'])
        fixture.test_eight_original_and_two_ksm_builds_have_distinct_journaled_environments()
        rows = fixture.rows()
        opened = rows[0]
        binding = {key: opened[key] for key in ('source_commit', 'run_id', 'packet_sha256', 'uid', 'gid', 'docker_endpoint', 'daemon_id', 'nonce')}
        binding['runner_arch'] = 'ARM64'
        names = [row['name'] for row in rows if row['event'] == 'container-reserved' and row['name'].startswith('cachy-asahi-')]
        self.assertEqual(len(names), 10)
        verdict = c.validate_journal(rows, binding, fixture.backend.image, names, final=True)
        self.assertTrue(verdict['image_absent'])
        self.assertEqual(rows[-1]['legacy_build_cache_absence'], 'NOT ESTABLISHED')

    def test_folded_empty_json_and_exact_image_diagnostic_variants(self):
        names = self.names + ['cachy-asahi-' + f'{index:016x}' for index in (9, 10)]
        for separator in ('', ' '):
            error = ('Error response from daemon: No such image:' + separator + self.image).encode()
            for value in (error, b'[]\n' + error, error + b'\n[]'):
                for output in (value, value + b'\n'):
                    rows = self.journal(names, final=True)
                    completion = next(row for row in rows if row['event'] == 'docker-operation-completed' and row['returncode'] == 1)
                    completion.update(stdout_bytes=len(output), stdout_sha256=c.sha(output))
                    self.assertTrue(c.validate_journal(rows, self.binding, self.image, names, final=True)['image_absent'])

    def test_declared_absence_without_actual_removal_operation_refused(self):
        rows = copy.deepcopy(self.rows)
        index = next(index for index, row in enumerate(rows) if row['event'] == 'docker-operation-reserved' and row['argv'][2] == 'rm')
        del rows[index:index+2]
        with self.assertRaises(ValueError):
            c.validate_journal(rows, self.binding, self.image, self.names)


if __name__ == '__main__':
    unittest.main()
