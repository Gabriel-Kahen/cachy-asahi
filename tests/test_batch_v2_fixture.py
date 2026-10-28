# SPDX-License-Identifier: MIT
"""Real C01 recipe/source bytes with explicitly synthetic build-environment data."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'scripts/build/build_v2.py').is_file())
SAVED = Path(__file__).resolve().parent / 'fixtures/offline-build-v2-c01'
FIXTURE_MANIFEST_SHA256 = '912927ea9f0a488588e9bdb640fdcf42be0dc4a64913d4845598d5e10cb226c8'
NAMES = ('cachy-asahi-zlib-baseline', 'cachy-asahi-zlib-lto')
INTERFACE = 'offline-build-v2'


class Fixture:
    def __init__(self, module, path):
        self.m, self.path = module, path
        manifest_raw = (SAVED / 'fixture-files.json').read_bytes()
        if self.m.B.sha(manifest_raw) != FIXTURE_MANIFEST_SHA256:
            raise AssertionError('retained C01 fixture manifest changed')
        for name, row in json.loads(manifest_raw)['files'].items():
            body = (SAVED / name).read_bytes()
            if len(body) != row['bytes'] or self.m.B.sha(body) != row['sha256']:
                raise AssertionError('retained C01 fixture bytes changed: ' + name)
        self.catalog = path / 'catalog/source-inputs.json'
        self.catalog.parent.mkdir()
        self.catalog.write_bytes((SAVED / 'inputs/source-inputs.json').read_bytes())
        shutil.copytree(SAVED / 'inputs/notices', self.catalog.parent / 'notices')
        self.cache = path / 'private-cache'
        shutil.copytree(SAVED / 'accepted-cache', self.cache)
        self.cache.chmod(0o700)
        (self.cache / '.partial').mkdir(mode=0o700)
        # Git stores ordinary fixture files as 0644; the runtime cache is private.
        for entry in self.cache.rglob('*'):
            entry.chmod(0o700 if entry.is_dir() else 0o600)
        self.input, self.config, self.sources = (path / p for p in ('input.json', 'config.json', 'sources.json'))
        self.planner = ROOT / 'scripts/maintenance/rebuild_plan.py'
        self.row = json.loads(self.catalog.read_bytes())['sources'][0]
        self.input_value = dict(schema_version=1, metadata_role='pre-change-release', release_id='HOST_C01_OFFLINE_PROTOCOL_ONLY',
            snapshot_id='SYNTHETIC_REVIEWED_IMAGE_INVENTORY', packages=[], sources=[], build_dependencies=[],
            changed=dict(sources=list(NAMES), toolchains=[], advisories=[]),
            capacity=dict(native_aarch64_slots=2, owner='host-fixture-owner', reference='SYNTHETIC; no capacity measured'))
        self.config_value = dict(schema_version=1, owner='host-fixture-owner', review='HOST protocol control; no real image approval',
            max_parallel=2, cpu_budget=8, memory_gib_budget=8, max_wall_seconds=10, max_attempts=3, tasks=[])
        self.sources_value = dict(schema_version=1, builder_interface=INTERFACE, tasks={})
        external = ('binutils', 'gcc', 'glibc', 'make')
        for name in external:
            self.input_value['packages'].append(dict(name=name, version='1-1', arch='aarch64', depend=[], provides=[]))
            self.input_value['sources'].append(dict(id=name, recipe_sha256=self.m.B.sha(name.encode()),
                sources=[dict(url='https://example.invalid/' + name + '.tar.gz', sha256='1' * 64)]))
            self.input_value['build_dependencies'].append(dict(package=name, source_id=name, makedepend=[], checkdepend=[],
                toolchain=[], disposition='external', owner='fixture-upstream-owner', hold_reason=None))
        self.lock = path / 'image-packages.lock'
        self.lock.write_text(''.join(name + ' 1-1\n' for name in external))
        self.reports = {}
        for name in NAMES:
            # A private copy permits drift controls without touching canonical recipes.
            recipe = path / 'recipes' / name
            shutil.copytree(ROOT / 'packages/experiments' / name, recipe)
            build = self.m.B.module('fixture_v2_static_builder_' + name.replace('-', '_'), ROOT / 'scripts/build/build_v2.py')
            report = build.recipe(recipe / 'PKGBUILD')
            if report['errors']:
                raise AssertionError(report['errors'])
            self.reports[name] = report
            reviewed = path / (name + '.reviewed.json')
            reviewed.write_bytes(self.m.B.encoded(report['input_sha256']))
            metadata = build.normalize_metadata(report['metadata'])
            self.input_value['packages'].append(dict(name=name, version='1.3.2-1', arch='aarch64', depend=metadata['depends'], provides=metadata['provides']))
            self.input_value['sources'].append(dict(id=name, recipe_sha256=report['input_sha256']['PKGBUILD'], sources=[
                dict(url=url, sha256=h) for url,h in zip(metadata['source'],metadata['sha256sums'])]))
            self.input_value['build_dependencies'].append(dict(package=name, source_id=name, makedepend=metadata['makedepends'],
                checkdepend=metadata['checkdepends'], toolchain=[], disposition='build', owner='host-fixture-owner', hold_reason=None))
            self.config_value['tasks'].append(dict(package=name, owner='host-fixture-owner', recipe=str(recipe), reviewed_inputs=str(reviewed),
                reviewed_inputs_sha256=self.m.B.digest(reviewed), expected_packages=str(self.lock), expected_packages_sha256=self.m.B.digest(self.lock),
                image='sha256:' + 'a' * 64, mode='emulated', source_date_epoch=1791748800, timeout=3, prerequisite_artifacts={},
                image_dependency_review='SYNTHETIC image; exact recipe source fixture only'))
            plan = path / (name + '.source-plan.json')
            variant = name.removeprefix('cachy-asahi-zlib-')
            retained_plan = json.loads((SAVED / (variant + '-source-plan.json')).read_bytes())
            retained_review = json.loads((SAVED / (variant + '-reviewed-inputs.json')).read_bytes())
            if retained_plan['recipe_inputs'] != report['input_sha256'] or retained_review != report['input_sha256']:
                raise AssertionError('real C01 recipe differs from retained source review')
            if retained_plan['catalog_sha256'] != self.m.B.digest(self.catalog):
                raise AssertionError('retained C01 source catalog changed')
            plan.write_bytes(self.m.B.encoded(retained_plan))
            self.sources_value['tasks'][name] = dict(source_plan=str(plan), source_plan_sha256=self.m.B.digest(plan),
                source_catalog=str(self.catalog), source_cache=str(self.cache))

    def write(self):
        for path,value in ((self.input,self.input_value),(self.config,self.config_value),(self.sources,self.sources_value)):
            path.write_bytes(self.m.B.encoded(value))

    def arguments(self):
        self.write()
        return (self.input, self.m.B.digest(self.input), self.config, self.m.B.digest(self.config),
                self.planner, self.m.B.digest(self.planner), self.sources, self.m.B.digest(self.sources))

    def admit(self, interface=INTERFACE):
        return self.m.admission(*self.arguments(), builder_interface=interface)

    def cache_pin(self):
        return {str(p.relative_to(self.cache)):self.m.B.digest(p) for p in self.cache.rglob('*') if p.is_file()}

    def remove_external(self, name):
        self.input_value['packages'] = [p for p in self.input_value['packages'] if p['name'] != name]
        self.input_value['sources'] = [p for p in self.input_value['sources'] if p['id'] != name]
        self.input_value['build_dependencies'] = [p for p in self.input_value['build_dependencies'] if p['package'] != name]

    def add_competing_gcc(self):
        self.input_value['packages'].append(dict(name='another-compiler', version='1-1', arch='aarch64', depend=[], provides=['gcc']))
        self.input_value['sources'].append(dict(id='another-compiler', recipe_sha256='2'*64,
            sources=[dict(url='https://example.invalid/another-compiler.tar.gz', sha256='3'*64)]))
        self.input_value['build_dependencies'].append(dict(package='another-compiler', source_id='another-compiler', makedepend=[], checkdepend=[],
            toolchain=[], disposition='external', owner='fixture-upstream-owner', hold_reason=None))

    def add_reviewed_baseline_prerequisite(self, artifact_sha=None):
        """A derived temporary LTO graph, not an assertion about original C01."""
        baseline, lto = NAMES
        task = next(p for p in self.config_value['tasks'] if p['package'] == lto)
        pkgbuild = Path(task['recipe']) / 'PKGBUILD'
        text = pkgbuild.read_text()
        if "depends=('glibc')" not in text:
            raise AssertionError('unexpected original C01 dependency declaration')
        pkgbuild.write_text(text.replace("depends=('glibc')", "depends=('glibc' '" + baseline + "')"))
        build = self.m.B.module('fixture_v2_derived_static_builder', ROOT / 'scripts/build/build_v2.py')
        report = build.recipe(pkgbuild)
        if report['errors']:
            raise AssertionError(report['errors'])
        self.reports[lto] = report
        reviewed = Path(task['reviewed_inputs'])
        reviewed.write_bytes(self.m.encoded(report['input_sha256']))
        task['reviewed_inputs_sha256'] = self.m.B.digest(reviewed)
        source = next(p for p in self.input_value['sources'] if p['id'] == lto)
        source['recipe_sha256'] = report['input_sha256']['PKGBUILD']
        package = next(p for p in self.input_value['packages'] if p['name'] == lto)
        package['depend'] = ['glibc', baseline]
        rows = self.lock.read_text().splitlines() + [baseline + ' 1.3.2-1']
        self.lock.write_text(''.join(p + '\n' for p in sorted(rows)))
        for row in self.config_value['tasks']:
            row['expected_packages_sha256'] = self.m.B.digest(self.lock)
        task['prerequisite_artifacts'] = {baseline:artifact_sha or self.m.B.sha(('HOST FAKE ' + baseline + '\n').encode())}
        binding = self.sources_value['tasks'][lto]
        plan_path = Path(binding['source_plan'])
        plan = json.loads(plan_path.read_bytes()); plan['recipe_inputs'] = report['input_sha256']
        plan_path.write_bytes(self.m.encoded(plan))
        binding['source_plan_sha256'] = self.m.B.digest(plan_path)


FAKE = r'''
import hashlib,json,pathlib,sys,time
def deny_socket(event, args):
    if event.startswith('socket.'):
        raise RuntimeError('network forbidden in host fake source control')
sys.addaudithook(deny_socket)
sys.path.insert(0,sys.argv[1])
import source_materials as sm
import build_v2 as build
task=json.loads(sys.argv[2]);output=pathlib.Path(sys.argv[3]);fail=sys.argv[4]=='1'
output.mkdir(mode=0o700)
binding=task['offline_sources']
prepared=sm.prepare(build.recipe(pathlib.Path(task['recipe'])/'PKGBUILD'),binding['source_plan'],binding['source_plan_sha256'],binding['source_catalog'],binding['source_cache'])
selection=sm.stage(prepared,output/'source-material')
(output/'artifact.fake').write_bytes(('HOST FAKE '+task['package']+'\n').encode())
pins={'source-material/'+str(p.relative_to(output/'source-material')):build.digest(p) for p in (output/'source-material').rglob('*') if p.is_file()}
(output/'provenance.json').write_text(json.dumps(dict(status='HOST_FAKE_FAIL' if fail else 'HOST_FAKE_PASS',source_material=selection,files=pins)))
time.sleep(0.05)
sys.exit(7 if fail else 0)
'''


class FakeBuilder:
    kind = 'HOST_FAKE_V2_OFFLINE_SOURCE_PROTOCOL_ONLY'

    def __init__(self, module, fail=()):
        self.m, self.fail = module, set(fail)
        self.started, self.cleaned = [], []
        self.events = []

    def start(self, task, output, log, lock_fd):
        self.started.append(task['package'])
        self.events.append(('start', task['package']))
        return subprocess.Popen([sys.executable, '-I', '-B', '-c', FAKE, str(ROOT / 'scripts/build'),
            json.dumps(task), str(output), '1' if task['package'] in self.fail else '0'],
            stdout=log,stderr=subprocess.STDOUT,start_new_session=True,pass_fds=(lock_fd,))

    def verify(self, task, output):
        self.m.verify_material(task, output)
        record=json.loads((output/'provenance.json').read_text())
        if record['status'] != 'HOST_FAKE_PASS':
            raise ValueError('synthetic builder failed')
        self.events.append(('verified', task['package']))
        return self.m.B.digest(output/'artifact.fake')

    def cleanup(self, task, output):
        self.cleaned.append((task['package'],str(output)))
