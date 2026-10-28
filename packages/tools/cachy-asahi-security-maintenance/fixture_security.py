#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Original TEST DATA derived from integrated test_security_campaign.py.

The bound implementation is the explicitly staged package runtime, never a checkout.
"""
import copy
import gzip
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile


def bind(runtime):
    global SCRIPT, m
    SCRIPT = Path(runtime) / 'scripts/maintenance/security_campaign.py'
    spec = importlib.util.spec_from_file_location('package_fixture_campaign', SCRIPT)
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

