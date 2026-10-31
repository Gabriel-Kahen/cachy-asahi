#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure offline admission controls; no builder is executed."""
import copy
import importlib.util
import io
import json
import shutil
import tarfile
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('build_batch.py')
spec = importlib.util.spec_from_file_location('build_batch', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
PLANNER = m.ROOT / 'scripts/maintenance/rebuild_plan.py'
if not PLANNER.is_file():
    PLANNER = m.ROOT / 'artifacts/development/repository-rebuild-planner-20261027/proposal/scripts/maintenance/rebuild_plan.py'
PACKET = next((p for p in SCRIPT.parents if (p / 'evidence/baseline.json').is_file()), None)


def artifact(name):
    return ('HOST FAKE ARTIFACT: ' + name + '\n').encode()


class Fixture:
    def __init__(self, path, graph=None):
        self.path = path
        self.graph = graph or dict(alpha=[], beta=['alpha'], gamma=['beta'], independent=[])
        self.source = dict(schema_version=1, metadata_role='pre-change-release', release_id='HOST-FAKE-ONLY',
            snapshot_id='HOST-FAKE-BASE', packages=[], sources=[], build_dependencies=[],
            changed=dict(sources=sorted(self.graph), toolchains=[], advisories=[]),
            capacity=dict(native_aarch64_slots=2, owner='fixture-builder', reference='SIMULATION ONLY'))
        self.config = dict(schema_version=1, owner='fixture-owner', review='HOST FAKE review only',
            max_parallel=2, cpu_budget=8, memory_gib_budget=8, max_wall_seconds=10, max_attempts=3, tasks=[])
        for name, requires in sorted(self.graph.items()):
            recipe = path / 'recipes' / name
            recipe.mkdir(parents=True)
            (recipe / 'payload').write_text('fixture payload\n')
            checksum = m.digest(recipe / 'payload')
            deps = ' '.join(repr(p) for p in requires)
            (recipe / 'PKGBUILD').write_text(f"pkgname={name}\npkgver=1\npkgrel=1\narch=('aarch64')\nlicense=('MIT')\ndepends=({deps})\nsource=('payload')\nsha256sums=('{checksum}')\npackage() {{ :; }}\n")
            inputs = {p.name: m.digest(p) for p in sorted(recipe.iterdir())}
            reviewed = path / (name + '.reviewed.json')
            reviewed.write_bytes(m.encoded(inputs))
            lock = path / (name + '.lock')
            closure, pending = set(), list(requires)
            while pending:
                dependency = pending.pop()
                if dependency not in closure:
                    closure.add(dependency)
                    pending.extend(self.graph.get(dependency, []))
            lock.write_text(''.join(p + ' 1-1\n' for p in sorted((closure - {name}) | {'fixture-base'})))
            self.source['packages'].append(dict(name=name, version='1-1', arch='aarch64', depend=requires, provides=[]))
            self.source['sources'].append(dict(id=name, recipe_sha256=inputs['PKGBUILD'], sources=[dict(url='payload', sha256=checksum)]))
            self.source['build_dependencies'].append(dict(package=name, source_id=name, makedepend=[], checkdepend=[],
                toolchain=[], disposition='build', owner='fixture-owner', hold_reason=None))
            self.config['tasks'].append(dict(package=name, owner='fixture-owner', recipe=str(recipe),
                reviewed_inputs=str(reviewed), reviewed_inputs_sha256=m.digest(reviewed),
                expected_packages=str(lock), expected_packages_sha256=m.digest(lock), image='sha256:' + 'a' * 64,
                mode='native', source_date_epoch=0, timeout=2, prerequisite_artifacts={p: m.sha(artifact(p)) for p in requires},
                image_dependency_review='FAKE preexisting image/artifact association; no real image'))
        self.input = path / 'input.json'
        self.configuration = path / 'config.json'

    def write(self):
        self.input.write_bytes(m.encoded(self.source))
        self.configuration.write_bytes(m.encoded(self.config))

    def admit(self):
        self.write()
        return m.admission(self.input, m.digest(self.input), self.configuration, m.digest(self.configuration), PLANNER, m.digest(PLANNER))

    def task(self, name):
        return next(p for p in self.config['tasks'] if p['package'] == name)

    def arguments(self):
        self.write()
        return ['--input', str(self.input), '--input-sha256', m.digest(self.input),
                '--config', str(self.configuration), '--config-sha256', m.digest(self.configuration),
                '--planner', str(PLANNER), '--planner-sha256', m.digest(PLANNER)]


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='batch-test-', dir=PACKET / 'evidence' if PACKET else None)
        self.addCleanup(self.temp.cleanup)
        self.fixture = Fixture(Path(self.temp.name))

    def reject(self, fragment):
        with self.assertRaisesRegex(ValueError, fragment):
            self.fixture.admit()

    def test_deterministic_without_builder(self):
        before = {str(p): m.digest(p) for p in self.fixture.path.rglob('*') if p.is_file()}
        a, b = self.fixture.admit(), self.fixture.admit()
        self.assertEqual(m.encoded(a), m.encoded(b))
        self.assertEqual(a['status'], 'ADMISSION_ONLY_NOT_BUILT')
        self.assertEqual(a['hardware_status'], 'NOT RUN')
        self.assertEqual(a['max_parallel'], 2)
        self.assertEqual(before, {p: m.digest(p) for p in before})
        self.assertEqual(a['tasks']['gamma']['prerequisites'], ['beta'])

    def test_resource_slot_limit(self):
        self.fixture.config.update(max_parallel=9, cpu_budget=4, memory_gib_budget=12)
        self.assertEqual(self.fixture.admit()['max_parallel'], 1)

    def test_zero_capacity_holds_all(self):
        self.fixture.source['capacity']['native_aarch64_slots'] = 0
        result = self.fixture.admit()
        self.assertEqual(result['max_parallel'], 0)
        self.assertTrue(all(g['held'] for g in result['groups']))

    def test_owner_mismatch(self):
        self.fixture.task('alpha')['owner'] = 'other-owner'
        self.reject('ownership')

    def test_missing_task(self):
        self.fixture.config['tasks'].pop()
        self.reject('task coverage')

    def test_duplicate_task(self):
        self.fixture.config['tasks'].append(copy.deepcopy(self.fixture.task('alpha')))
        self.reject('duplicate')

    def test_unplanned_task(self):
        self.fixture.task('alpha')['package'] = 'unknown'
        self.reject('unplanned')

    def test_tagged_image(self):
        self.fixture.task('alpha')['image'] = 'example:latest'
        with self.assertRaises(Exception):
            self.fixture.admit()

    def test_recipe_drift(self):
        path = Path(self.fixture.task('alpha')['recipe']) / 'PKGBUILD'
        path.write_text(path.read_text() + '# changed\n')
        self.reject('recipe input mismatch')

    def test_review_file_drift(self):
        Path(self.fixture.task('alpha')['reviewed_inputs']).write_text('{}')
        self.reject('checksum mismatch')

    def test_recipe_pin_mismatch(self):
        self.fixture.source['sources'][0]['recipe_sha256'] = 'b' * 64
        self.reject('source recipe pin')

    def test_source_descriptor_mismatch(self):
        self.fixture.source['sources'][0]['sources'][0]['sha256'] = 'b' * 64
        self.reject('source descriptors')

    def test_version_mismatch(self):
        self.fixture.source['packages'][0]['version'] = '2-1'
        self.reject('version differs')

    def test_graph_mismatch(self):
        self.fixture.source['packages'][1]['depend'] = []
        self.reject('graph metadata')

    def test_arch_mismatch(self):
        self.fixture.source['packages'][0]['arch'] = 'any'
        self.reject('architecture')

    def test_lock_drift(self):
        Path(self.fixture.task('alpha')['expected_packages']).write_text('other 1-1\n')
        self.reject('lock checksum')

    def test_prerequisite_version_mismatch(self):
        task = self.fixture.task('beta')
        Path(task['expected_packages']).write_text('alpha 2-1\nfixture-base 1-1\n')
        task['expected_packages_sha256'] = m.digest(task['expected_packages'])
        self.reject('wrong version')

    def test_prerequisite_pin_missing(self):
        self.fixture.task('beta')['prerequisite_artifacts'] = {}
        self.reject('exact prerequisite')

    def exact_alpha_fixture(self):
        task = self.fixture.task('beta')
        recipe = Path(task['recipe']) / 'PKGBUILD'
        recipe.write_text(recipe.read_text().replace("depends=('alpha')", "depends=('alpha=1-1')"))
        reviewed = {p.name: m.digest(p) for p in recipe.parent.iterdir()}
        Path(task['reviewed_inputs']).write_bytes(m.encoded(reviewed))
        task['reviewed_inputs_sha256'] = m.digest(task['reviewed_inputs'])
        next(p for p in self.fixture.source['sources'] if p['id'] == 'beta')['recipe_sha256'] = reviewed['PKGBUILD']
        next(p for p in self.fixture.source['packages'] if p['name'] == 'beta')['depend'] = ['alpha=1-1']

    def test_transitive_image_member_missing_is_refused(self):
        self.exact_alpha_fixture()
        task = self.fixture.task('gamma')
        Path(task['expected_packages']).write_text('beta 1-1\nfixture-base 1-1\n')
        task['expected_packages_sha256'] = m.digest(task['expected_packages'])
        self.reject('dependency closure input absent/wrong version in image lock: alpha')

    def test_transitive_image_member_wrong_version_is_refused(self):
        self.exact_alpha_fixture()
        task = self.fixture.task('gamma')
        Path(task['expected_packages']).write_text('alpha 99-1\nbeta 1-1\nfixture-base 1-1\n')
        task['expected_packages_sha256'] = m.digest(task['expected_packages'])
        self.reject('dependency closure input absent/wrong version in image lock: alpha')

    def test_transitive_image_members_exact_versions_are_admitted(self):
        self.exact_alpha_fixture()
        result = self.fixture.admit()
        gamma = result['tasks']['gamma']
        self.assertEqual(Path(gamma['expected_packages']).read_text(), 'alpha 1-1\nbeta 1-1\nfixture-base 1-1\n')
        self.assertFalse(next(g for g in result['groups'] if 'gamma' in g['packages'])['held'])
        self.assertEqual(gamma['prerequisites'], ['beta'])
        self.assertEqual(gamma['prerequisite_artifacts'], {'beta': m.sha(artifact('beta'))})

    def test_duplicate_lock_name(self):
        task = self.fixture.task('alpha')
        Path(task['expected_packages']).write_text('fixture-base 1-1\nfixture-base 1-1\n')
        task['expected_packages_sha256'] = m.digest(task['expected_packages'])
        self.reject('malformed package lock')

    def test_symlink_recipe(self):
        task = self.fixture.task('alpha')
        link = self.fixture.path / 'recipe-link'
        link.symlink_to(task['recipe'], target_is_directory=True)
        task['recipe'] = str(link)
        self.reject('nonsymlink')

    def test_unknown_config_field(self):
        self.fixture.config['shell'] = 'echo no'
        self.reject('unexpected/missing fields')

    def test_boolean_resource_count(self):
        self.fixture.config['max_parallel'] = True
        self.reject('integer')

    def test_duplicate_nonfinite_json(self):
        for raw in (b'{"a": 1, "a": 2}', b'{"a": NaN}'):
            with self.assertRaises(ValueError):
                m.decode(raw)

    def test_selected_pins(self):
        self.fixture.write()
        for input_sha, planner_sha in [('0' * 64, m.digest(PLANNER)), (m.digest(self.fixture.input), '0' * 64)]:
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                m.admission(self.fixture.input, input_sha, self.fixture.configuration, m.digest(self.fixture.configuration), PLANNER, planner_sha)

    def test_cli_determinism_and_execution_pin(self):
        arguments = self.fixture.arguments()
        a = subprocess.run([sys.executable, '-B', str(SCRIPT), 'plan'] + arguments, capture_output=True)
        b = subprocess.run([sys.executable, '-B', str(SCRIPT), 'plan'] + arguments, capture_output=True)
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertEqual(a.stdout, b.stdout)
        out = self.fixture.path / 'must-not-exist'
        refused = subprocess.run([sys.executable, '-B', str(SCRIPT), 'execute'] + arguments + ['--output', str(out)], capture_output=True)
        self.assertEqual(refused.returncode, 2)
        self.assertFalse(out.exists())

    def test_production_command(self):
        task = self.fixture.admit()['tasks']['alpha']
        with patch.object(m.subprocess, 'Popen') as popen:
            m.Builder().start(task, self.fixture.path / 'build', None, 9)
        command = popen.call_args.args[0]
        self.assertEqual(command[:3], [sys.executable, '-B', str(m.ROOT / 'scripts/build/build.py')])
        self.assertEqual(command[command.index('--network') + 1], 'none')
        self.assertEqual(popen.call_args.kwargs['pass_fds'], (9,))


class ProviderImageTests(unittest.TestCase):
    """Pure synthetic provider/image admission; never starts Docker or a builder."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='provider-image-',dir=PACKET/'evidence' if PACKET else None)
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)
        self.fixture=Fixture(self.path,dict(base_a=[],base_b=[],base_consumer=['shared>=2'],app=['base_consumer'],independent=[]))
        self.planner=SCRIPT.with_name('rebuild_plan.py')
        if not self.planner.exists():
            packet=next(p for p in SCRIPT.parents if(p/'evidence/input-pins.json').is_file())
            self.planner=packet/'proposal/scripts/maintenance/rebuild_plan.py'
        self.core=m.module('provider_image_control_planner',self.planner)
        self.witness='sha256:'+'c'*64
        self.fixture.source['changed']['sources']=['app']
        for row in self.fixture.source['build_dependencies']:
            if row['package'].startswith('base_'):row['disposition']='external'
        packages={p['name']:p for p in self.fixture.source['packages']}
        packages['base_a']['provides']=['shared=2'];packages['base_b']['provides']=['shared=3']
        self.external=''.join(name+' 1-1\n'for name in ('base_a','base_b','base_consumer'))
        task=self.fixture.task('app');lock=Path(task['expected_packages']);lock.write_text(self.external)
        task.update(expected_packages_sha256=m.digest(lock),image=self.witness,prerequisite_artifacts={})
        self.fixture.config['tasks']=[task]
        context=self.core.provider_context('base_consumer','depend','shared>=2',['base_a','base_b'],packages)
        self.selection=dict(package='base_consumer',field='depend',dependency='shared>=2',provider='base_a',evidence=dict(
            kind='INSTALLED_ALPM_CACHE_QUERY_V1',image=self.witness,inventory_sha256=m.sha(self.external.encode()),
            capture_sha256='d'*64,metadata_sha256=m.sha(self.core.pins.encoded(context))))
        self.fixture.source['provider_selections']=[self.selection]

    def admit(self):
        self.fixture.write()
        return m.admission(self.fixture.input,m.digest(self.fixture.input),self.fixture.configuration,m.digest(self.fixture.configuration),self.planner,m.digest(self.planner))

    def test_same_lock_different_image_is_refused(self):
        task=self.fixture.task('app');task['image']='sha256:'+'a'*64
        self.assertEqual(task['expected_packages_sha256'],self.selection['evidence']['inventory_sha256'])
        with self.assertRaisesRegex(ValueError,'reachable provider witness image differs from task image: base_consumer'):self.admit()

    def test_binding_reached_through_another_baseline_layer_is_checked(self):
        # app -> base_middle -> base_consumer -> shared providers.
        task=self.fixture.task('app');recipe=Path(task['recipe'])/'PKGBUILD'
        recipe.write_text(recipe.read_text().replace("depends=('base_consumer')","depends=('base_middle')"))
        reviewed={p.name:m.digest(p)for p in recipe.parent.iterdir()}
        Path(task['reviewed_inputs']).write_bytes(m.encoded(reviewed));task['reviewed_inputs_sha256']=m.digest(task['reviewed_inputs'])
        next(p for p in self.fixture.source['sources']if p['id']=='app')['recipe_sha256']=reviewed['PKGBUILD']
        next(p for p in self.fixture.source['packages']if p['name']=='app')['depend']=['base_middle']
        self.fixture.source['packages'].append(dict(name='base_middle',version='1-1',arch='any',depend=['base_consumer'],provides=[]))
        self.fixture.source['sources'].append(dict(id='base_middle',recipe_sha256='a'*64,sources=[dict(url='https://example.invalid/SYNTHETIC/middle',sha256='b'*64)]))
        self.fixture.source['build_dependencies'].append(dict(package='base_middle',source_id='base_middle',makedepend=[],checkdepend=[],toolchain=[],disposition='external',owner='fixture-owner',hold_reason=None))
        lock=Path(task['expected_packages']);lock.write_text(self.external+'base_middle 1-1\n')
        task['expected_packages_sha256']=m.digest(lock);self.selection['evidence']['inventory_sha256']=m.digest(lock)
        task['image']='sha256:'+'a'*64
        with self.assertRaisesRegex(ValueError,'reachable provider witness image differs'):self.admit()

    def test_same_image_exact_inventory_capture_are_bound_to_task(self):
        value=self.admit();task=value['tasks']['app']
        self.assertEqual(task['image'],self.witness)
        self.assertEqual(task['expected_packages_sha256'],self.selection['evidence']['inventory_sha256'])
        self.assertEqual(task['provider_selections'],[self.selection])
        self.assertEqual(task['provider_selections'][0]['evidence']['capture_sha256'],'d'*64)
        self.assertFalse(value['groups'][0]['held'])

    def test_same_image_different_complete_lock_is_refused(self):
        task=self.fixture.task('app');lock=Path(task['expected_packages']);lock.write_text(self.external+'extra 1-1\n')
        task['expected_packages_sha256']=m.digest(lock)
        with self.assertRaisesRegex(ValueError,'reachable provider witness inventory differs from task lock: base_consumer'):self.admit()

    def test_repository_digest_cannot_masquerade_as_observed_image_id(self):
        self.fixture.task('app')['image']='registry.example.invalid/builder@'+self.witness
        with self.assertRaisesRegex(ValueError,'reachable provider witness image differs'):self.admit()

    def test_unrelated_task_keeps_its_independent_image_and_lock(self):
        # The binding consumer is transitive from app, but unreachable from independent.
        recipe=self.path/'recipes/independent';review=self.path/'independent.reviewed.json';lock=self.path/'independent.lock'
        task=dict(package='independent',owner='fixture-owner',recipe=str(recipe),reviewed_inputs=str(review),reviewed_inputs_sha256=m.digest(review),
            expected_packages=str(lock),expected_packages_sha256=m.digest(lock),image='sha256:'+'b'*64,mode='native',source_date_epoch=0,timeout=2,
            prerequisite_artifacts={},image_dependency_review='SYNTHETIC independent image, no provider binding in closure')
        self.fixture.source['changed']['sources'].append('independent');self.fixture.config['tasks'].append(task)
        value=self.admit()
        self.assertEqual(value['tasks']['independent']['image'],task['image'])
        self.assertNotIn('provider_selections',value['tasks']['independent'])
        self.assertFalse(any(g['held']for g in value['groups']))

    def test_no_selection_keeps_ordinary_repository_digest_behavior(self):
        del self.fixture.source['provider_selections']
        self.fixture.task('app')['image']='registry.example.invalid/builder@sha256:'+'a'*64
        value=self.admit()
        self.assertNotIn('provider_selections',value['tasks']['app'])
        self.assertTrue(value['groups'][0]['held'])  # Original unresolved ambiguity remains held.

    def test_valid_binding_does_not_clear_an_unrelated_owner_hold(self):
        next(p for p in self.fixture.source['build_dependencies']if p['package']=='base_b')['owner']=None
        value=self.admit();self.assertTrue(value['groups'][0]['held'])
        self.assertEqual(value['tasks']['app']['provider_selections'],[self.selection])


class BuilderBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='batch-boundary-', dir=PACKET / 'evidence' if PACKET else None)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        fixture = Fixture(self.path)
        self.task = fixture.admit()['tasks']['alpha']
        self.output = self.path / 'owned-build'
        self.output.mkdir()
        self.name = 'cachy-asahi-' + 'b' * 16
        self.mounts = [dict(Source=str(self.output / 'inputs'), Destination='/inputs', RW=False),
                       dict(Source=str(self.output / 'artifacts'), Destination='/out', RW=True),
                       dict(Source=str(m.ROOT / 'scripts/build/container-entry.sh'), Destination='/builder-entry.sh', RW=False),
                       dict(Source=str(self.output / 'expected-packages.lock'), Destination='/expected-packages.lock', RW=False)]
        for row in self.mounts:
            row['Type'] = 'bind'
        command = ['docker', 'run', '--rm', '--name', self.name]
        for row in self.mounts:
            command += ['--mount', 'type=bind,src=' + row['Source'] + ',dst=' + row['Destination'] + ('' if row['RW'] else ',readonly')]
        command += [self.task['image'], '/builder-entry.sh']
        self.record = dict(clean_environment_id=self.name, image=self.task['image'], command=command)
        self.live = dict(Name='/' + self.name, Config=dict(Image=self.task['image']), Mounts=self.mounts)
        self.save()

    def save(self):
        (self.output / 'provenance.json').write_bytes(m.encoded(self.record))

    def result(self, code=0, output=''):
        return subprocess.CompletedProcess([], code, stdout=output, stderr='synthetic daemon message')

    def cleanup(self, responses):
        with patch.object(m.subprocess, 'run', side_effect=responses) as calls:
            m.Builder().cleanup(self.task, self.output)
        return calls

    def test_confirmed_removal(self):
        calls = self.cleanup([self.result(output=json.dumps([self.live])), self.result()])
        self.assertEqual(calls.call_args_list[-1].args[0], ['docker', 'rm', '-f', self.name])

    def test_confirmed_absence(self):
        calls = self.cleanup([self.result(1), self.result()])
        self.assertEqual(calls.call_args_list[-1].args[0][:3], ['docker', 'ps', '-aq'])

    def test_failed_removal_cannot_release_capacity(self):
        with self.assertRaisesRegex(ValueError, 'absence not established'):
            self.cleanup([self.result(output=json.dumps([self.live])), self.result(1), self.result(output='still-running')])

    def test_daemon_error_does_not_mean_absence(self):
        with self.assertRaisesRegex(ValueError, 'absence not established'):
            self.cleanup([self.result(1), self.result(1)])

    def test_failed_removal_with_confirmed_absence_is_safe(self):
        self.cleanup([self.result(output=json.dumps([self.live])), self.result(1), self.result()])

    def test_recorded_mount_mismatch_does_not_call_docker(self):
        self.record['command'][6] = 'type=bind,src=/another/attempt,dst=/inputs,readonly'
        self.save()
        with patch.object(m.subprocess, 'run') as calls:
            with self.assertRaisesRegex(ValueError, 'command/image/mount mismatch'):
                m.Builder().cleanup(self.task, self.output)
        calls.assert_not_called()

    def test_live_mount_mismatch_does_not_remove_other_container(self):
        self.live['Mounts'][0]['Source'] = '/another/attempt'
        with patch.object(m.subprocess, 'run', return_value=self.result(output=json.dumps([self.live]))) as calls:
            with self.assertRaisesRegex(ValueError, 'live container ownership'):
                m.Builder().cleanup(self.task, self.output)
        self.assertEqual(calls.call_count, 1)

    def test_expected_tmpfs_mount_is_accepted(self):
        self.live['Mounts'].append(dict(Type='tmpfs', Source='', Destination='/tmp', RW=True))
        self.cleanup([self.result(output=json.dumps([self.live])), self.result()])

    def test_extra_foreign_bind_mount_is_refused(self):
        self.live['Mounts'].append(dict(Type='bind', Source='/foreign', Destination='/foreign', RW=True))
        with self.assertRaisesRegex(ValueError, 'live container ownership'):
            self.cleanup([self.result(output=json.dumps([self.live]))])

    def evidence(self):
        shutil.copytree(self.task['recipe'], self.output / 'inputs')
        artifacts = self.output / 'artifacts'
        artifacts.mkdir()
        build = m.module('test_batch_build', m.ROOT / 'scripts/build/build.py')
        metadata = build.recipe(Path(self.task['recipe']) / 'PKGBUILD')['metadata']
        archive = artifacts / 'alpha-1-1-aarch64.pkg.tar.gz'
        entries = {'.PKGINFO': b'pkgname = alpha\npkgbase = alpha\npkgver = 1-1\narch = aarch64\nlicense = MIT\n',
            '.BUILDINFO': ('format = 2\npkgname = alpha\npkgver = 1-1\npkgarch = aarch64\npkgbuild_sha256sum = ' + self.task['recipe_inputs']['PKGBUILD'] + '\n').encode(),
            '.MTREE': b'synthetic mtree', 'usr/share/alpha/data': b'HOST synthetic package'}
        with tarfile.open(archive, 'w:gz') as stream:
            for name, data in entries.items():
                item = tarfile.TarInfo(name)
                item.mode, item.size = 0o644, len(data)
                stream.addfile(item, io.BytesIO(data))
        for name in ('environment.txt', 'config.sha256', 'makepkg.conf', 'pacman.conf', 'generated.SRCINFO'):
            (artifacts / name).write_text('HOST synthetic evidence\n')
        lock = Path(self.task['expected_packages']).read_bytes()
        (artifacts / 'packages.lock').write_bytes(lock)
        (self.output / 'expected-packages.lock').write_bytes(lock)
        (self.output / 'build.log').write_text('HOST synthetic builder log\n')
        (self.output / 'validation.json').write_bytes(m.encoded(dict(errors=[])))
        self.record.update(status='built-package-static-pass', mode=self.task['mode'], network='none',
            source_date_epoch=self.task['source_date_epoch'], recipe_inputs=self.task['recipe_inputs'], recipe_metadata=metadata,
            expected_packages_sha256=self.task['expected_packages_sha256'],
            entry_script_sha256=m.digest(m.ROOT / 'scripts/build/container-entry.sh'),
            artifacts={archive.name: m.digest(archive)}, files={})
        self.record['files'] = {str(p.relative_to(self.output)): m.digest(p) for p in self.output.rglob('*')
            if p.is_file() and p.name != 'provenance.json' and not p.is_relative_to(self.output / 'inputs')}
        self.save()
        return archive

    def test_production_verifier_reuses_actual_archive_checks(self):
        archive = self.evidence()
        self.assertEqual(m.Builder().verify(self.task, self.output), m.digest(archive))

    def test_wrong_mode_record_refused_by_production_verifier(self):
        self.evidence()
        self.record['mode'] = 'emulated'
        self.save()
        with self.assertRaisesRegex(ValueError, 'admitted build inputs'):
            m.Builder().verify(self.task, self.output)

    def test_tampered_archive_refused(self):
        archive = self.evidence()
        archive.write_text('tampered')
        with self.assertRaises(ValueError):
            m.Builder().verify(self.task, self.output)


if __name__ == '__main__':
    unittest.main()
