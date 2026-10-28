#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Original tiny DATA fixtures; real offline CLIs, no build actors or downloads."""
import copy
import gzip
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('security_campaign.py')
spec = importlib.util.spec_from_file_location('security_campaign_tested', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
NOW = '2026-10-27T12:00:00Z'
NAMES = ('seed', 'middle', 'app', 'other')


class Fixture:
    def __init__(self, root):
        self.root = root
        self.batch = m.module('security_fixture_batch', 'scripts/maintenance/build_batch_v2.py')
        payload = b'Original MIT licensed security campaign TEST DATA; no upstream advisory.\n'
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as archive:
            info = tarfile.TarInfo('FIXTURE.txt'); info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        body = gzip.compress(stream.getvalue(), mtime=0)
        self.material = m.a.pin(body)
        (root / 'fixture.tar.gz').write_bytes(body)
        (root / 'LICENSE').write_bytes(payload)
        row = dict(material=dict(id='original-fixture', path='fixture.tar.gz', **m.a.pin(body)),
                   url='https://example.invalid/ORIGINAL-FIXTURE.tar.gz', revision='ORIGINAL TEST DATA 1',
                   license='MIT; original fixture only',
                   license_evidence=[dict(id='license', path='LICENSE', **m.a.pin(payload))])
        self.catalog = self.put('catalog.json', dict(schema_version=1, purpose='source-cache-inputs', sources=[row]))
        cache = self.batch.SM.cache
        self.cache = root / 'cache'; cache.initialize(self.cache.absolute())
        self.object = self.cache / 'objects' / self.material['sha256']
        self.object.write_bytes(body); self.object.chmod(0o600)
        receipt = dict(schema_version=1, purpose='source-cache-receipt', inputs_sha256=m.c.digest(self.catalog), source=row,
                       object_path='objects/' + self.material['sha256'], legal_acceptance=False, source_completeness_accepted=False)
        path = self.cache / 'receipts' / (m.c.digest(self.catalog) + '-original-fixture.json')
        path.write_bytes(cache.encoded(receipt)); path.chmod(0o600)
        self.graph = dict(schema_version=1, metadata_role='pre-change-release', release_id='ORIGINAL-TEST-RELEASE',
                          snapshot_id='ORIGINAL-TEST-SNAPSHOT', packages=[], sources=[], build_dependencies=[],
                          changed=dict(sources=[], toolchains=[], advisories=[]),
                          capacity=dict(native_aarch64_slots=1, owner='TEST owner', reference='TEST claim; unmeasured'))
        self.config = dict(schema_version=1, owner='TEST owner', review='Original fixture; no real image/build approval',
                           max_parallel=1, cpu_budget=4, memory_gib_budget=4, max_wall_seconds=10, max_attempts=2, tasks=[])
        self.sources = dict(schema_version=1, builder_interface='offline-build-v2', tasks={})
        lock = root / 'packages.lock'
        lock.write_text('middle 1-1\nseed 1-2\n')
        for name in NAMES:
            depend = {'middle': ['virtual-seed>=1'], 'app': ['middle']}.get(name, [])
            provides = ['virtual-seed=1'] if name == 'seed' else []
            recipe = root / ('recipe-' + name); recipe.mkdir()
            def recipe_text(version):
                return (f"pkgname={name}\npkgver=1\npkgrel={version}\npkgdesc='Original TEST fixture'\narch=('aarch64')\nlicense=('MIT')\n"
                        + ('depends=(' + ' '.join(repr(p) for p in depend) + ')\n' if depend else '')
                        + ('provides=(' + ' '.join(repr(p) for p in provides) + ')\n' if provides else '')
                        + "source=('https://example.invalid/ORIGINAL-FIXTURE.tar.gz')\nsha256sums=('" + self.material['sha256'] + "')\n"
                        + 'package() {\n install -Dm644 "$srcdir/FIXTURE.txt" "$pkgdir/usr/share/$pkgname/FIXTURE.txt"\n}\n')
            pkgbuild = recipe / 'PKGBUILD'; pkgbuild.write_text(recipe_text(1))
            old_pin = m.c.digest(pkgbuild)
            if name == 'seed': pkgbuild.write_text(recipe_text(2))
            (recipe / '.SRCINFO').write_text('pkgname = ' + name + '\npkgver = 1\npkgrel = ' + ('2' if name == 'seed' else '1')
                + '\narch = aarch64\nlicense = MIT\nsource = ' + row['url'] + '\nsha256sums = ' + self.material['sha256'] + '\n'
                + ''.join('depends = ' + p + '\n' for p in depend) + ''.join('provides = ' + p + '\n' for p in provides))
            build = self.batch.B.module('original_fixture_static', m.ROOT / 'scripts/build/build_v2.py')
            report = build.recipe(pkgbuild)
            if report['errors']: raise AssertionError(report['errors'])
            self.graph['packages'].append(dict(name=name, version='1-1', arch='aarch64', depend=depend, provides=provides,
                                                sha256=m.c.sha(('TEST old archive ' + name).encode())))
            self.graph['sources'].append(dict(id=name, recipe_sha256=old_pin,
                                              sources=[dict(url=row['url'], sha256=self.material['sha256'])]))
            self.graph['build_dependencies'].append(dict(package=name, source_id=name, makedepend=[], checkdepend=[],
                                                         toolchain=[], disposition='build', owner='TEST owner', hold_reason=None))
            if name == 'other': continue
            reviewed = self.put(name + '-review.json', report['input_sha256'])
            plan = self.put(name + '-source-plan.json', dict(schema_version=1, purpose='offline-build-sources',
                            recipe_inputs=report['input_sha256'], catalog_sha256=m.c.digest(self.catalog),
                            sources=[dict(source=row['url'], id='original-fixture', revision=row['revision'])]))
            prereq = {'middle': 'seed', 'app': 'middle'}.get(name)
            self.config['tasks'].append(dict(package=name, owner='TEST owner', recipe=str(recipe), reviewed_inputs=str(reviewed),
                reviewed_inputs_sha256=m.c.digest(reviewed), expected_packages=str(lock), expected_packages_sha256=m.c.digest(lock),
                image='sha256:' + 'a' * 64, mode='emulated', source_date_epoch=1793102400, timeout=3,
                prerequisite_artifacts={prereq: m.c.sha(('TEST future archive ' + prereq).encode())} if prereq else {},
                image_dependency_review='TEST preexisting image claim; not measured, built or available'))
            self.sources['tasks'][name] = dict(source_plan=str(plan), source_plan_sha256=m.c.digest(plan),
                                              source_catalog=str(self.catalog), source_cache=str(self.cache))
        self.candidate = copy.deepcopy(self.graph)
        self.candidate['packages'][0]['version'] = '1-2'
        self.candidate['sources'][0]['recipe_sha256'] = m.c.digest(root / 'recipe-seed/PKGBUILD')
        self.inventory = [{key: p[key] for key in ('name', 'version', 'arch', 'provides')} for p in self.graph['packages']]
        self.advisories = [dict(name='AVG-1', packages=['seed'], status='Fixed', severity='High', type='ORIGINAL TEST ONLY',
                               affected='1-1', fixed='1-2', issues=['CVE-2026-12345'], advisories=['ASA-202610-1'])]
        self.selection = dict(schema_version=1, operation_id='ORIGINAL-TEST', as_of=NOW, max_age_hours=24, inputs={}, import_bundle=None)
        self.store = m.c.Store(root / 'operation')
        self.write()

    def put(self, name, value):
        path = self.root / name; path.write_bytes(m.encoded(value)); return path

    def ref(self, path): return dict(path=str(path), sha256=m.c.digest(path))

    def write(self):
        for key, value in (('inventory', self.inventory), ('advisories', self.advisories), ('graph', self.graph), ('candidate_graph', self.candidate)):
            self.selection['inputs'][key] = self.ref(self.put(key + '.json', value))
        provenance = dict(url=m.a.URL, retrieved_at=NOW, **m.a.pin((self.root / 'advisories.json').read_bytes()))
        self.selection['inputs']['provenance'] = self.ref(self.put('provenance.json', provenance))
        self.selected = self.put('selection.json', self.selection)
        config, sources = self.put('config.json', self.config), self.put('sources.json', self.sources)
        self.batch_selected = self.put('batches.json', dict(schema_version=1, batches=[dict(config=self.ref(config), sources=self.ref(sources),
                                output=str(self.root / ('batch-' + str(i)))) for i in (1, 2)]))

    def prepare(self): return m.prepare(self.store, self.ref(self.selected))

    def batches(self, retry=False):
        with self.store.lock(): return m.plan_builds(self.store, self.ref(self.batch_selected), retry)

    def cli(self, action, selection=None, retry=False):
        command = [sys.executable, '-B', str(SCRIPT), action, '--operation', str(self.store.path)]
        if selection: command += ['--selection', str(selection), '--selection-sha256', m.c.digest(selection)]
        if retry: command += ['--retry']
        result = subprocess.run(command, capture_output=True, timeout=60)
        return command, result

    def import_retained(self):
        """Invoke the current importer on original release/metadata DATA."""
        rows = [dict(name=p['name'], version=p['version'], arch=p['arch'], sha256=p['sha256'],
                     depends=p['depend'], provides=p['provides'], conflicts=[], replaces=[], license=['MIT'])
                for p in self.graph['packages']]
        (self.root / 'release.lock').write_text(''.join(p['name'] + ' ' + p['version'] + '\n' for p in sorted(rows, key=lambda p:p['name'])))
        self.put('manifest.json', dict(packages=rows, projects=[]))
        self.put('metadata.json', rows)
        def relative(name): return dict(path=name, sha256=m.c.digest(self.root / name))
        selection = self.put('import-selection.json', dict(schema_version=1, release_id='ORIGINAL-IMPORTED',
            snapshot_id='ORIGINAL-IMPORTED-SNAPSHOT', inventory=relative('release.lock'), manifest=relative('manifest.json'),
            extension_profile=None, metadata=[dict(file=relative('metadata.json'), select=[], format='lock')],
            archives=[], recipes=[], changed=dict(sources=[], toolchains=[], advisories=[])))
        command = [sys.executable, '-B', str(m.ROOT / 'scripts/maintenance/import_release_graph.py'), '--root', str(self.root),
                   '--selection', str(selection), '--selection-sha256', m.c.digest(selection), '--output', 'bundle']
        result = subprocess.run(command, capture_output=True, timeout=60)
        if result.returncode: raise AssertionError(result.stderr)
        bundle = json.loads(result.stdout)
        self.graph, self.inventory = bundle['graph'], bundle['inventory']
        self.candidate = copy.deepcopy(self.graph)
        self.selection['import_bundle'] = self.ref(self.put('import-bundle.json', bundle))
        self.write()
        return command, result


class Controls(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='security-original-'); self.addCleanup(temp.cleanup)
        self.f = Fixture(Path(temp.name))

    def test_transitive_old_impact_candidate_order_and_security_gates(self):
        state = self.f.prepare(); op = self.f.store.value(state['security_operation'])
        self.assertEqual(state['required_packages'], ['app', 'middle', 'seed'])
        self.assertEqual(op['graph_unaffected'], ['other'])
        self.assertEqual(op['unknown_advisory_packages'], ['app', 'middle', 'other'])
        self.assertEqual(state['build_holds'], [])
        self.assertEqual(state['phases']['security_review'], 'BLOCKED')
        self.assertEqual(op['gates']['recovery'], 'NOT_ESTABLISHED')
        groups = self.f.store.value(state['build_plan'])['groups']
        self.assertEqual([g['packages'] for g in groups], [['seed'], ['middle'], ['app']])
        self.assertEqual(groups[2]['prerequisites'], [groups[1]['id']])
        self.assertEqual(self.f.graph['changed']['advisories'], [])

    def test_removed_candidate_offer_cannot_erase_prior_consumer(self):
        self.f.candidate['packages'][1]['depend'] = []
        self.f.write(); state = self.f.prepare()
        self.assertEqual(state['required_packages'], ['app', 'middle', 'seed'])

    def test_no_match_noop_retains_unknown_not_unaffected_security(self):
        self.f.advisories[0]['packages'] = ['absent']
        self.f.candidate = copy.deepcopy(self.f.graph); self.f.write()
        state = self.f.prepare(); op = self.f.store.value(state['security_operation'])
        self.assertEqual(state['required_packages'], [])
        self.assertEqual(op['status'], 'NO_REBUILD_FROM_SUPPLIED_ROOTS')
        self.assertEqual(op['gates']['arm_affectedness'], 'UNKNOWN')
        self.assertEqual(len(op['unknown_advisory_packages']), 4)
        with self.assertRaisesRegex(ValueError, 'no declared'): self.f.batches()

    def test_real_pair_admission_and_exact_emitted_plan_commands(self):
        self.f.prepare(); state = self.f.batches()
        receipt = self.f.store.value(state['security_batches'])
        self.assertEqual(len(receipt['batches']), 2)
        for row in receipt['batches']:
            result = subprocess.run(row['plan_command'], capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(m.c.sha(result.stdout), row['admission'])
            self.assertFalse(Path(row['output']).exists())
            self.assertIn('--admission-sha256', row['execute_command'])
        self.assertEqual(state['phases']['outputs'], 'NOT_RUN')
        self.assertEqual(state['phases']['hardware'], 'NOT_RUN')

    def test_missing_source_failure_is_durable_and_explicit_retry_recovers(self):
        self.f.prepare(); raw = self.f.object.read_bytes(); self.f.object.unlink()
        with self.assertRaises(ValueError): self.f.batches()
        state = self.f.store.state()
        self.assertEqual(state['phases']['batch_planning'], 'FAILED')
        self.assertIsNone(state['security_batches'])
        with self.assertRaisesRegex(ValueError, '--retry'): self.f.batches()
        self.f.object.write_bytes(raw); self.f.object.chmod(0o600)
        state = self.f.batches(retry=True)
        self.assertEqual(state['phases']['batch_planning'], 'COMPLETE')
        self.assertEqual(state['security_attempts'], 2)
        self.assertTrue(any(e['state']['phases'].get('batch_planning') == 'FAILED' for e in self.f.store.history()))

    def test_source_drift_never_repaired_and_no_actor_or_network(self):
        self.f.prepare(); self.f.object.write_bytes(b'wrong')
        with patch.object(self.f.batch.SM.cache, 'transport', side_effect=AssertionError('network')), \
             patch.object(self.f.batch.Builder, 'start', side_effect=AssertionError('no actor')):
            with self.assertRaises(ValueError): self.f.batches()
        self.assertEqual(self.f.object.read_bytes(), b'wrong')
        self.assertEqual(self.f.store.state()['phases']['batch_planning'], 'FAILED')

    def test_missing_archive_identity_and_input_mismatch_refuse_before_store(self):
        del self.f.graph['packages'][0]['sha256']; self.f.write()
        with self.assertRaisesRegex(ValueError, 'archive identity'): self.f.prepare()
        self.assertFalse(self.f.store.path.exists())

    def test_snapshot_mismatch_refused(self):
        self.f.candidate['snapshot_id'] = 'other'; self.f.write()
        with self.assertRaisesRegex(ValueError, 'snapshot'): self.f.prepare()

    def test_held_capacity_and_provider_do_not_emit_commands(self):
        self.f.graph['capacity']['native_aarch64_slots'] = None
        self.f.candidate['capacity']['native_aarch64_slots'] = None
        self.f.candidate['packages'][1]['depend'] = ['missing-provider']; self.f.write()
        state = self.f.prepare()
        self.assertTrue(state['build_holds'])
        with self.assertRaisesRegex(ValueError, 'held'): self.f.batches()
        self.assertIsNone(self.f.store.state()['security_batches'])

    def test_old_at_arch_fixed_reference_still_reviews(self):
        self.f.advisories[0]['fixed'] = '1-1'; self.f.write()
        state = self.f.prepare()
        review = self.f.store.value(state['update_plan'])
        row = next(p for p in review['package_reviews'] if p['name'] == 'seed')
        self.assertEqual(row['findings'][0]['version_relation'], 'AT_OR_ABOVE_ARCH_FIXED_REFERENCE')
        self.assertEqual(state['phases']['security_review'], 'BLOCKED')

    def test_real_import_bundle_unknowns_retained_and_mismatch_refused(self):
        self.f.import_retained()
        state = self.f.prepare(); op = self.f.store.value(state['security_operation'])
        self.assertTrue(op['imported_holds']['global_holds'])
        self.assertEqual(len(op['imported_holds']['packages']), 4)
        self.assertTrue(state['build_holds'])
        with self.assertRaisesRegex(ValueError, 'held'): self.f.batches()
        raws = {key:m.select(ref) for key, ref in self.f.selection['inputs'].items()}
        bundle = json.loads(m.select(self.f.selection['import_bundle']))
        bundle['graph']['snapshot_id'] = 'different'
        with self.assertRaisesRegex(ValueError, 'bundle differs'):
            m.compose(self.f.selection, raws, m.encoded(bundle))

    def test_stale_advisory_and_explicit_holds_survive_composition(self):
        self.f.selection['as_of'] = '2026-10-29T12:00:00Z'
        self.f.candidate['build_dependencies'][0].update(disposition='hold', hold_reason='TEST source review incomplete')
        self.f.write(); state = self.f.prepare()
        review = self.f.store.value(state['update_plan'])
        self.assertIn('STALE_ADVISORY_CACHE', [h['code'] for h in review['global_holds']])
        self.assertTrue(state['build_holds'])
        with self.assertRaisesRegex(ValueError, 'held'): self.f.batches()

    def test_unchanged_installed_provider_witness_retained_exactly(self):
        graph = self.f.graph
        for name in ('ext-user', 'ext-a', 'ext-b'):
            graph['packages'].append(dict(name=name, version='1-1', arch='aarch64',
                depend=['ext-virtual'] if name == 'ext-user' else [],
                provides=[] if name == 'ext-user' else ['ext-virtual'], sha256=m.c.sha(name.encode())))
            graph['sources'].append(dict(id=name, recipe_sha256='c' * 64,
                sources=[dict(url='https://example.invalid/ORIGINAL', sha256='d' * 64)]))
            graph['build_dependencies'].append(dict(package=name, source_id=name, makedepend=[], checkdepend=[],
                toolchain=[], owner='TEST external owner', disposition='external', hold_reason=None))
        packages = {p['name']:p for p in graph['packages']}
        context = m.b.provider_context('ext-user', 'depend', 'ext-virtual', ['ext-a', 'ext-b'], packages)
        witness = dict(package='ext-user', field='depend', dependency='ext-virtual', provider='ext-a',
            evidence=dict(kind='INSTALLED_ALPM_CACHE_QUERY_V1', image='sha256:' + 'a' * 64,
                inventory_sha256=m.c.sha(b'ext-a 1-1\next-b 1-1\next-user 1-1\n'),
                capture_sha256='e' * 64, metadata_sha256=m.c.sha(m.b.pins.encoded(context))))
        graph['provider_selections'] = [witness]
        self.f.candidate = copy.deepcopy(graph)
        self.f.inventory = [{key:p[key] for key in ('name', 'version', 'arch', 'provides')} for p in graph['packages']]
        self.f.write(); state = self.f.prepare()
        self.assertEqual(self.f.store.value(state['build_plan'])['provider_selections'], [witness])
        bad = copy.deepcopy(graph); bad['provider_selections'][0]['evidence']['metadata_sha256'] = '0' * 64
        with self.assertRaisesRegex(m.b.r.Error, 'metadata differs'): m.b.plan(bad)

    def test_input_digest_alias_and_inventory_mismatch_fail_closed(self):
        self.f.selection['inputs']['graph']['sha256'] = '0' * 64
        self.f.put('selection.json', self.f.selection)
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'): self.f.prepare()
        self.f.write(); self.f.inventory[0]['version'] = '99-1'; self.f.write()
        with self.assertRaisesRegex(ValueError, 'version/architecture mismatch'): self.f.prepare()
        self.assertFalse(self.f.store.path.exists())

    def test_pair_output_alias_refused_without_commands(self):
        self.f.prepare()
        value = json.loads(self.f.batch_selected.read_bytes())
        value['batches'][1]['output'] = value['batches'][0]['output']
        self.f.put('batches.json', value)
        with self.assertRaisesRegex(ValueError, 'overlap'): self.f.batches()
        self.assertIsNone(self.f.store.state()['security_batches'])

    def test_prepare_interruption_and_exact_input_retry(self):
        original = m.c.Store.commit
        def fail_second(store, state):
            if state.get('security_operation'): raise OSError('original TEST interruption')
            return original(store, state)
        with patch.object(m.c.Store, 'commit', fail_second), self.assertRaises(OSError): self.f.prepare()
        with self.assertRaisesRegex(ValueError, 'preparation interrupted'): m.checked(self.f.store)
        original_candidate = copy.deepcopy(self.f.candidate)
        self.f.candidate['changed']['advisories'] = [dict(package='seed', reference='https://security.archlinux.org/AVG-1')]
        self.f.write()
        with self.assertRaisesRegex(ValueError, 'original selection/adapter differs'):
            m.prepare(self.f.store, self.f.ref(self.f.selected), retry=True)
        self.f.candidate = original_candidate; self.f.write()
        digest = m.c.digest
        with patch.object(m.c, 'digest', side_effect=lambda p: 'f' * 64 if Path(p).resolve() == SCRIPT.resolve() else digest(p)), \
             self.assertRaisesRegex(ValueError, 'original selection/adapter differs|implementation drift'):
            m.prepare(self.f.store, self.f.ref(self.f.selected), retry=True)
        state = m.prepare(self.f.store, self.f.ref(self.f.selected), retry=True)
        self.assertTrue(state['security_operation'])
        with self.assertRaisesRegex(ValueError, 'only recovers'): m.prepare(self.f.store, self.f.ref(self.f.selected), retry=True)

    def test_pair_admission_drift_before_command_commit_refuses(self):
        self.f.prepare()
        admission, module = self.f.batch.admission, m.module
        calls = []
        def changed(*args, **kwargs):
            result = admission(*args, **kwargs); calls.append(result)
            if len(calls) == 2: self.f.object.write_bytes(b'changed after second admission')
            return result
        with patch.object(m, 'module', side_effect=lambda name, path: self.f.batch if name == 'security_existing_batch' else module(name, path)), \
             patch.object(self.f.batch, 'admission', side_effect=changed), \
             self.assertRaisesRegex(ValueError, 'input changed before command commit'):
            self.f.batches()
        self.assertEqual(self.f.store.state()['phases']['batch_planning'], 'FAILED')
        self.assertIsNone(self.f.store.state()['security_batches'])

    def test_objects_hold_after_originals_removed_and_corruption_refuses(self):
        state = self.f.prepare()
        for ref in self.f.selection['inputs'].values(): Path(ref['path']).unlink()
        self.assertEqual(m.checked(self.f.store)['required_packages'], state['required_packages'])
        self.f.store.object_path(state['security_operation']).write_bytes(b'{}\n')
        with self.assertRaisesRegex(ValueError, 'object drift'): m.checked(self.f.store)

    def test_real_cli_and_clean_digest_refusal(self):
        command, result = self.f.cli('prepare', self.f.selected)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['required_packages'], ['app', 'middle', 'seed'])
        _, result = self.f.cli('status')
        self.assertEqual(result.returncode, 0, result.stderr)
        command[command.index('--operation') + 1] += '-refused'
        command[-1] = '0' * 64
        result = subprocess.run(command, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'')
        self.assertNotIn(b'Traceback', result.stderr)


def demo(directory):
    directory.mkdir()
    f = Fixture(directory)
    steps = []
    def call(action, selection=None, retry=False, expected=0):
        command, result = f.cli(action, selection, retry)
        index = len(steps) + 1
        (directory / f'{index:02d}-{action}.stdout').write_bytes(result.stdout)
        (directory / f'{index:02d}-{action}.stderr').write_bytes(result.stderr)
        steps.append(dict(argv=command, exit_code=result.returncode, expected=expected))
        if result.returncode != expected: raise AssertionError(result.stderr)
        return json.loads(result.stdout) if result.returncode == 0 else None
    call('prepare', f.selected)
    raw = f.object.read_bytes(); f.object.unlink()
    call('plan-builds', f.batch_selected, expected=2)
    call('status')
    f.object.write_bytes(raw); f.object.chmod(0o600)
    value = call('plan-builds', f.batch_selected, retry=True)
    for row in value['commands']['batches']:
        result = subprocess.run(row['plan_command'], capture_output=True, timeout=60)
        if result.returncode or m.c.sha(result.stdout) != row['admission']: raise AssertionError(result.stderr)
        (directory / ('admission-' + str(row['pair_member']) + '.json')).write_bytes(result.stdout)
        steps.append(dict(argv=row['plan_command'], exit_code=result.returncode, expected=0))
    call('status')
    noop = directory / 'noop'; noop.mkdir(); nf = Fixture(noop)
    nf.advisories[0]['packages'] = ['absent']; nf.candidate = copy.deepcopy(nf.graph); nf.write()
    command, result = nf.cli('prepare', nf.selected)
    if result.returncode: raise AssertionError(result.stderr)
    (directory / 'noop.stdout').write_bytes(result.stdout)
    steps.append(dict(argv=command, exit_code=0, expected=0))
    held = directory / 'imported-held'; held.mkdir(); hf = Fixture(held)
    command, result = hf.import_retained()
    (directory / 'import-bundle.stdout').write_bytes(result.stdout)
    steps.append(dict(argv=command, exit_code=result.returncode, expected=0))
    command, result = hf.cli('prepare', hf.selected)
    if result.returncode: raise AssertionError(result.stderr)
    (directory / 'imported-held.stdout').write_bytes(result.stdout)
    steps.append(dict(argv=command, exit_code=result.returncode, expected=0))
    (directory / 'demonstration.json').write_bytes(m.encoded(dict(status='HOST_OFFLINE_CLI_ONLY', steps=steps,
        builds='NOT_RUN', native='NOT_RUN', installed='NOT_RUN', hardware='NOT_RUN', remediation='NOT_ESTABLISHED')))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--demo-directory': demo(Path(sys.argv[2]).absolute())
    else: unittest.main()
