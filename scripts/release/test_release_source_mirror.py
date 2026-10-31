#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Local exact-source mirrors; package archives are synthetic, never executed."""
import copy
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).absolute().parent
ROOT = next(parent for parent in HERE.parents if (parent / 'scripts/release/source_delivery.py').is_file())
spec = importlib.util.spec_from_file_location('mirror_under_test', HERE / 'release_source_mirror.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
DEPS = m.dependencies(ROOT / 'scripts/release')
sbom, (s, recipe, stream) = DEPS
REVISION = 'd02ff33655daab3edd4bac9f797e0eee25e0e928'
NAMES = ('cachy-asahi-maintenance', 'cachy-asahi-session-diagnostics')


def archive_bytes(rows):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for key, (body, mode) in sorted(rows.items()):
            node = tarfile.TarInfo(key); node.size = len(body); node.mode = mode
            archive.addfile(node, io.BytesIO(body))
    return gzip.compress(output.getvalue(), mtime=0)


def metadata(value):
    return ''.join(key + ' = ' + item + '\n' for key, items in value.items() for item in items).encode()


class ReleaseFixture:
    """Reusable complete release fixture from exact reviewed checkout source bytes."""
    def __init__(self, root, names=NAMES):
        self.root = Path(root); self.root.mkdir()
        self.manifest = dict(schema_version=1, release_id='source-mirror-fixture',
            created_utc='2026-10-27T00:00:00Z', packages=[], files={}, symlinks={})
        self.spec = dict(schema_version=1, release_id=self.manifest['release_id'], source_commit=REVISION,
            synthetic=True, policy=dict(selected_packages=list(names)), packages=[], evidence=[])
        self.index = dict(schema_version=1, purpose='release-source-delivery', synthetic=True, packages=[])
        self.bodies = {}; self.provenance = {}; self.archive_rows = {}
        for name in names:
            bodies, info = recipe.source_set(name, lambda key: s.local_read(ROOT / 'packages/tools' / name, key, recipe.MAX_FILE))
            profile = recipe.profile(name); self.bodies[name] = bodies
            pkginfo = metadata(dict(pkgname=[name], pkgbase=[name], pkgver=[profile['version']], arch=['any'], license=['MIT']))
            buildinfo = metadata(dict(format=['2'], pkgname=[name], pkgver=[profile['version']], pkgarch=['any'],
                pkgbuild_sha256sum=[profile['recipe']], installed=['python-3.14-1-aarch64']))
            rows = {key: (bodies[src], mode) for key, (src, mode) in recipe.payload(name).items()}
            rows.update({'.PKGINFO': (pkginfo, 0o644), '.BUILDINFO': (buildinfo, 0o644), '.MTREE': (b'inert synthetic package archive\n', 0o644)})
            self.archive_rows[name] = rows
            package = dict(name=name, version=profile['version'], arch='any', filename=name + '-' + profile['version'] + '-any.pkg.tar.gz',
                sha256='', provenance='provenance/' + name + '.json', license=['MIT'])
            self.manifest['packages'].append(package)
            source_key = 'packages/tools/' + name
            self.provenance[name] = dict(schema_version=1, package={key:package[key] for key in ('name','version','arch')},
                artifact_sha256='', source_commit=REVISION, recipe_sha256=profile['recipe'], licenses=['MIT'],
                sources=[dict(url='context-source:' + REVISION + '/' + source_key, sha256=profile['recipe'], commit=REVISION)],
                build=dict(execution='synthetic', architecture='aarch64', environment='inert-fixture', snapshot_id='fixture'))
            self.refresh_archive(name)
            self.refresh_source(name)
        self.refresh()

    def put(self, key, body):
        path = self.root / key; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(body)
        self.manifest['files'][key] = s.digest(body)

    def package(self, name):
        return next(row for row in self.manifest['packages'] if row['name'] == name)

    def material(self, name, key, body):
        eid = name + '-' + key; self.put('evidence/' + eid, body)
        return dict(id=eid, path='retained/' + eid, sha256=s.digest(body), bytes=len(body))

    def refresh_archive(self, name):
        package = self.package(name); raw = archive_bytes(self.archive_rows[name])
        package['sha256'] = self.provenance[name]['artifact_sha256'] = s.digest(raw)
        self.put('repo/' + package['filename'], raw)
        for record in self.index['packages']:
            if record['package']['name'] == name:
                record['package']['sha256'] = package['sha256']

    def refresh_source(self, name):
        bodies = self.bodies[name]; info = recipe.metadata(bodies['.SRCINFO'])
        saved = recipe.manifest(name, bodies, info, REVISION, None)
        record = dict(package={key:self.package(name)[key] for key in ('name','version','arch','sha256')},
            bundle=self.material(name, 'source.tar', recipe.tar_bytes(dict(bodies, **{'bundle.json':recipe.encoded(saved)}))),
            recipe=self.material(name, 'recipe', bodies['PKGBUILD']), recipe_key='PKGBUILD',
            source_map=self.material(name, 'map', recipe.encoded({key:s.digest(body) for key,body in bodies.items()})),
            notices=[self.material(name, key, bodies[key]) for key in ('NOTICE','LICENSE')],
            authorization=self.material(name, 'review', b'Retained synthetic review only; no legal/native/hardware acceptance.\n'),
            review_status='Synthetic host fixture; no source execution or native build')
        self.index['packages'] = [row for row in self.index['packages'] if row['package']['name'] != name] + [record]

    def refresh(self):
        self.spec['packages'] = []
        for package in self.manifest['packages']:
            name = package['name']; self.put(package['provenance'], m.encoded(self.provenance[name]))
            self.spec['packages'].append(dict(artifact=dict(path=package['filename'], sha256=package['sha256']),
                provenance=dict(path='retained/' + name + '.json', sha256=self.manifest['files'][package['provenance']])))
        raw = m.encoded(self.index); self.put('evidence/source-index', raw)
        self.spec['source_delivery'] = dict(schema_version=1,index=dict(id='source-index',path='retained/source-index',sha256=s.digest(raw)))
        self.spec['evidence'] = [self.spec['source_delivery']['index']] + [
            {key:row[key] for key in ('id','path','sha256')} for record in self.index['packages'] for row in s.materials(record)]
        self.put('spec.json', m.encoded(self.spec))
        raw = m.encoded(self.manifest); (self.root / 'release.json').write_bytes(raw); self.pin=s.digest(raw)

    def build(self, **options):
        return m.build(self.root, self.pin, DEPS, directory=ROOT / 'scripts/release', **options)


class MirrorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mirror-tests-'); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.fixture = ReleaseFixture(self.root / 'release')

    def refused(self, pattern='.'):
        with self.assertRaisesRegex((ValueError, OSError, KeyError), pattern):
            self.fixture.build()

    def test_complete_two_package_deterministic_dedup_and_relocation(self):
        first, manifest, verifier = self.fixture.build()
        self.assertEqual(first, self.fixture.build()[0])
        licenses = [self.fixture.bodies[name]['LICENSE'] for name in NAMES]
        self.assertEqual(licenses[0], licenses[1])
        checksum=s.digest(licenses[0]); self.assertIn(checksum,manifest['objects'])
        self.assertEqual(sum(key == checksum for key in manifest['objects']), 1)
        self.assertEqual([row['package']['name'] for row in manifest['packages']], list(NAMES))
        self.assertFalse(manifest['legal_acceptance']); self.assertEqual(manifest['hardware_validation'],'NOT_RUN')
        moved=self.root/'moved'; shutil.copytree(self.fixture.root,moved)
        self.assertEqual(first,m.build(moved,self.fixture.pin,DEPS,directory=ROOT/'scripts/release')[0])
        outcome=m.verify(first,s.digest(first),self.fixture.pin)
        self.assertEqual(outcome['packages'],2)
        self.assertEqual(verifier,(HERE/'release_source_mirror.py').read_bytes())

    def test_no_network_subprocess_or_source_execution(self):
        with patch.object(socket,'socket',side_effect=AssertionError('network forbidden')), \
             patch.object(socket,'getaddrinfo',side_effect=AssertionError('DNS forbidden')), \
             patch.object(subprocess,'Popen',side_effect=AssertionError('subprocess forbidden')):
            raw, _, _ = self.fixture.build()
            m.verify(raw,s.digest(raw),self.fixture.pin)

    def test_standalone_relocated_cli_verify_and_wrong_pin(self):
        raw, _, verifier=self.fixture.build()
        dest=self.root/'standalone'; dest.mkdir(); (dest/'mirror.tar').write_bytes(raw); (dest/'verify.py').write_bytes(verifier)
        argv=[sys.executable,'-I','-B',str(dest/'verify.py'),'verify','--bundle',str(dest/'mirror.tar'),
            '--sha256',s.digest(raw),'--release-sha256',self.fixture.pin]
        run=subprocess.run(argv,cwd=dest,env={'PATH':'/usr/bin:/bin','PYTHONPATH':'/nonexistent'},capture_output=True,timeout=15)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        self.assertEqual(json.loads(run.stdout)['packages'],2)
        argv[-1]='0'*64; run=subprocess.run(argv,cwd=dest,capture_output=True,timeout=15)
        self.assertEqual(run.returncode,1); self.assertEqual(json.loads(run.stdout)['status'],'REFUSED')

    def test_missing_source_refused(self):
        self.fixture.index['packages'].pop(); self.fixture.refresh(); self.refused('coverage')

    def test_tampered_source_and_archive_refused(self):
        for key in ('evidence/'+NAMES[0]+'-source.tar','repo/'+self.fixture.package(NAMES[0])['filename']):
            path=self.fixture.root/key; old=path.read_bytes(); path.write_bytes(old+b'tamper')
            self.refused('checksum'); path.write_bytes(old)

    def test_wrong_recipe_provenance_refused(self):
        self.fixture.provenance[NAMES[0]]['recipe_sha256']='a'*64; self.fixture.refresh(); self.refused('recipe')

    def test_unretained_remote_source_refused(self):
        self.fixture.provenance[NAMES[0]]['sources'].append(dict(url='https://example.invalid/required.tar',sha256='a'*64))
        self.fixture.refresh(); self.refused('remote source')

    def test_missing_buildinfo_or_license_refused(self):
        name=NAMES[0]
        for key in ('.BUILDINFO','usr/share/licenses/'+name+'/LICENSE'):
            old=self.fixture.archive_rows[name].pop(key); self.fixture.refresh_archive(name); self.fixture.refresh()
            self.refused('payload|source/BUILDINFO|license|unresolved')
            self.fixture.archive_rows[name][key]=old
        self.fixture.refresh_archive(name); self.fixture.refresh()

    def test_duplicate_package_refused(self):
        self.fixture.manifest['packages'].append(copy.deepcopy(self.fixture.package(NAMES[0])))
        self.fixture.refresh(); self.refused('duplicate')

    def test_source_map_tamper_refused(self):
        record=self.fixture.index['packages'][0]; name=record['package']['name']
        source_map={key:s.digest(value) for key,value in self.fixture.bodies[name].items()}; source_map['LICENSE']='a'*64
        record['source_map']=self.fixture.material(name,'map',m.encoded(source_map)); self.fixture.refresh(); self.refused('map')

    def test_source_bundle_links_refused_without_follow(self):
        record=self.fixture.index['packages'][0]; original=self.fixture.root/'evidence'/record['bundle']['id']
        with tarfile.open(fileobj=io.BytesIO(original.read_bytes()),mode='r:') as source:
            rows={node.name:source.extractfile(node).read() for node in source}
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w',format=tarfile.USTAR_FORMAT) as target:
            for key,body in rows.items():
                node=tarfile.TarInfo(key); node.size=len(body); target.addfile(node,io.BytesIO(body))
            node=tarfile.TarInfo('escape'); node.type=tarfile.SYMTYPE; node.linkname='/nonexistent/retained-source'; target.addfile(node)
        name=record['package']['name']; record['bundle']=self.fixture.material(name,'source.tar',output.getvalue())
        self.fixture.refresh(); self.refused('unsafe|source|bundle')

    def test_unsafe_release_input_types_and_ancestor(self):
        path=self.fixture.root/'evidence'/self.fixture.index['packages'][0]['recipe']['id']; raw=path.read_bytes()
        external=self.root/'outside'; external.write_bytes(raw)
        for kind in ('symlink','hardlink','fifo'):
            path.unlink()
            if kind=='symlink': path.symlink_to(external)
            elif kind=='hardlink': os.link(external,path)
            else: os.mkfifo(path)
            self.refused('source input|symbolic|levels'); path.unlink(); path.write_bytes(raw)
        old=self.fixture.root/'evidence'; moved=self.fixture.root/'moved'; old.rename(moved); old.symlink_to(moved)
        self.refused('directory|symbolic|levels')

    def test_mirror_tamper_extra_member_and_unsafe_members_refused(self):
        raw, _, _ = self.fixture.build()
        with self.assertRaisesRegex(ValueError,'checksum'):
            m.verify(raw+b'x',s.digest(raw),self.fixture.pin)
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as source:
            files={node.name:source.extractfile(node).read() for node in source}
        for key in ('../escape','unexpected'):
            changed=dict(files); changed[key]=b'foreign'
            if key.startswith('..'):
                with self.assertRaises(ValueError): m.tar_bytes(changed)
            else:
                changed=m.tar_bytes(changed)
                with self.assertRaisesRegex(ValueError,'object set'): m.verify(changed,s.digest(changed),self.fixture.pin)

    def test_frozen_helper_inputs_unchanged(self):
        paths=[ROOT/'scripts/release'/name for name in ('recipe_source_delivery.py','source_delivery.py','release_sbom.py')]
        before={path:path.read_bytes() for path in paths}; profiles=copy.deepcopy(recipe.PROFILES); legacy=copy.deepcopy(recipe.LEGACY_PROFILES)
        self.fixture.build()
        self.assertEqual(before,{path:path.read_bytes() for path in paths})
        self.assertEqual(recipe.PROFILES,profiles); self.assertEqual(recipe.LEGACY_PROFILES,legacy)

    def test_rehashed_mirror_inconsistent_joins_refused(self):
        raw, manifest, _ = self.fixture.build()
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as source:
            files = {node.name: source.extractfile(node).read() for node in source}
        for change in ('archive', 'source', 'coverage'):
            changed = copy.deepcopy(manifest)
            if change == 'archive':
                changed['packages'][0]['archive'] = changed['packages'][1]['archive']
            elif change == 'source':
                row = changed['packages'][0]
                row['source_files']['PKGBUILD'] = row['source_files']['LICENSE']
            else:
                changed['files'].pop(changed['packages'][0]['provenance']['path'])
            rebuilt = m.tar_bytes(dict(files, **{'mirror.json': m.encoded(changed)}))
            with self.assertRaisesRegex(ValueError, 'binding|mismatch|coverage'):
                m.verify(rebuilt, s.digest(rebuilt), self.fixture.pin)


class HTTPSFixture(ReleaseFixture):
    """One inert archive source with real source_materials/cache verification."""
    def __init__(self, root):
        super().__init__(root, names=())
        name = 'mirror-https-fixture'; self.name = name
        self.source = b'Original inert source archive bytes; retained as data only.\n'
        self.license = b'Original inert MIT license evidence; no legal acceptance.\n'
        self.retained = self.root.parent / (self.root.name + '-retained'); self.retained.mkdir(mode=0o700)
        self.url = 'https://example.invalid/fixture-1.0.tar.gz'
        pkg = dict(name=name, version='1.0-1', arch='any', filename=name+'-1.0-1-any.pkg.tar.gz',
            sha256='',provenance='provenance/'+name+'.json',license=['MIT'])
        self.manifest['packages'] = [pkg]; self.spec['policy']['selected_packages'] = [name]
        source_hash=s.digest(self.source)
        self.bodies[name] = {'PKGBUILD': b'# Inert fixture; deliberately never sourced\n',
            '.SRCINFO': metadata(dict(pkgname=[name],pkgver=['1.0'],pkgrel=['1'],arch=['any'],license=['MIT'],
                source=[self.url,'LICENSE'],sha256sums=[source_hash,s.digest(self.license)])),
            'LICENSE':self.license,'NOTICE':b'Original inert fixture notice\n'}
        self.provenance[name] = dict(schema_version=1,package={key:pkg[key] for key in ('name','version','arch')},
            artifact_sha256='',source_commit=REVISION,recipe_sha256=s.digest(self.bodies[name]['PKGBUILD']),licenses=['MIT'],
            sources=[dict(url=self.url,sha256=source_hash)],build=dict(execution='synthetic',architecture='aarch64',
                environment='fixture',snapshot_id='fixture'))
        self.archive_rows[name] = {'.PKGINFO':(metadata(dict(pkgname=[name],pkgver=['1.0-1'],arch=['any'],license=['MIT'])),0o644),
            '.BUILDINFO':(metadata(dict(format=['2'],pkgname=[name],pkgver=['1.0-1'],pkgarch=['any'],
                pkgbuild_sha256sum=[self.provenance[name]['recipe_sha256']],installed=['compiler-1-1-aarch64'])),0o644),
            'usr/share/licenses/'+name+'/LICENSE':(self.license,0o644),'usr/bin/fixture':(b'inert payload\n',0o755)}
        self.refresh_archive(name)
        record = dict(package={key:pkg[key] for key in ('name','version','arch','sha256')},recipe_key='PKGBUILD',
            bundle=self.material(name,'source.tar',recipe.tar_bytes(self.bodies[name])),
            recipe=self.material(name,'recipe',self.bodies[name]['PKGBUILD']),
            source_map=self.material(name,'map',m.encoded({key:s.digest(body) for key,body in self.bodies[name].items()})),
            notices=[self.material(name,'license',self.license)],authorization=self.material(name,'review',b'Existing fixture review\n'),
            review_status='Source transport fixture only')
        self.index['packages']=[record]; self.refresh()
        self.sm=m.module('mirror_fixture_materials',ROOT/'scripts/build/source_materials.py')
        self.cache=self.retained/'cache'; self.sm.cache.initialize(self.cache)
        notice=dict(id='license',path='LICENSE',sha256=s.digest(self.license),bytes=len(self.license))
        self.catalog=dict(schema_version=1,purpose='source-cache-inputs',sources=[dict(
            material=dict(id='archive',path='fixture-1.0.tar.gz',sha256=source_hash,bytes=len(self.source)),
            url=self.url,revision='fixture-1.0',license='MIT',license_evidence=[notice])])
        self.plan=dict(schema_version=1,purpose='offline-build-sources',
            recipe_inputs={key:s.digest(body) for key,body in self.bodies[name].items()},catalog_sha256='',
            sources=[dict(source=self.url,id='archive',revision='fixture-1.0')])
        (self.retained/'LICENSE').write_bytes(self.license)
        obj=self.cache/'objects'/source_hash; obj.write_bytes(self.source); obj.chmod(0o600)
        self.refresh_inputs()

    def refresh_inputs(self):
        catalog_raw=self.sm.cache.encoded(self.catalog); (self.retained/'catalog.json').write_bytes(catalog_raw)
        self.plan['catalog_sha256']=s.digest(catalog_raw)
        plan_raw=self.sm.cache.encoded(self.plan); (self.retained/'plan.json').write_bytes(plan_raw)
        row=self.catalog['sources'][0]
        receipt=self.sm.cache.encoded(dict(schema_version=1,purpose='source-cache-receipt',inputs_sha256=s.digest(catalog_raw),
            source=row,object_path='objects/'+row['material']['sha256'],legal_acceptance=False,source_completeness_accepted=False))
        receipt_path=self.cache/'receipts'/(s.digest(catalog_raw)+'-'+row['material']['id']+'.json')
        receipt_path.write_bytes(receipt); receipt_path.chmod(0o600)
        def desc(key,raw):
            return dict(id=key,path=key+'.json',sha256=s.digest(raw),bytes=len(raw))
        self.inputs=dict(schema_version=1,purpose='release-source-mirror-inputs',packages=[dict(
            package={key:self.package(self.name)[key] for key in ('name','version','arch','sha256')},
            plan=desc('plan',plan_raw),catalog=desc('catalog',catalog_raw),cache='cache')])
        self.inputs_raw=m.encoded(self.inputs); self.inputs_path=self.retained/'inputs.json'; self.inputs_path.write_bytes(self.inputs_raw)

    def build(self, **options):
        options.update(inputs=self.inputs_path,inputs_sha256=s.digest(self.inputs_raw),retained_root=self.retained)
        return super().build(**options)


class HTTPSMirrorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='https-mirror-tests-'); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.fixture=HTTPSFixture(self.root/'release')

    def refused(self, pattern='.'):
        with self.assertRaisesRegex((ValueError,OSError,KeyError),pattern): self.fixture.build()

    def test_complete_remote_archive_receipt_and_license_export_without_network(self):
        with patch.object(socket,'socket',side_effect=AssertionError('network forbidden')), \
             patch.object(socket,'getaddrinfo',side_effect=AssertionError('DNS forbidden')), \
             patch.object(subprocess,'Popen',side_effect=AssertionError('subprocess forbidden')):
            raw,manifest,_=self.fixture.build()
            outcome=m.verify(raw,s.digest(raw),self.fixture.pin)
            self.assertEqual(outcome['packages'],1)
            self.assertEqual(outcome['mirror_sha256'],s.digest(raw))
        row=manifest['packages'][0]
        self.assertEqual(row['remote_sources'][0]['object']['sha256'],s.digest(self.fixture.source))
        self.assertEqual(row['remote_notices'][s.digest(self.fixture.license)]['sha256'],s.digest(self.fixture.license))
        self.assertIsNotNone(row['plan']); self.assertIsNotNone(row['catalog'])

    def test_missing_source_cache_object_and_receipt_refused(self):
        for path in [self.fixture.cache/'objects'/s.digest(self.fixture.source),next((self.fixture.cache/'receipts').iterdir())]:
            old=path.read_bytes(); path.unlink(); self.refused('offline'); path.write_bytes(old); path.chmod(0o600)

    def test_tampered_source_cache_and_catalog_refused(self):
        path=self.fixture.cache/'objects'/s.digest(self.fixture.source); old=path.read_bytes(); path.write_bytes(old+b'changed')
        self.refused('mismatch|bound'); path.write_bytes(old)
        path=self.fixture.retained/'catalog.json'; path.write_bytes(path.read_bytes()+b'changed'); self.refused('catalog')

    def test_recipe_input_plan_binding_refused(self):
        self.fixture.plan['recipe_inputs']['PKGBUILD']='a'*64; self.fixture.refresh_inputs(); self.refused('recipe inputs')

    def test_ambiguous_duplicate_source_binding_refused(self):
        self.fixture.plan['sources']*=2; self.fixture.refresh_inputs(); self.refused('unique')

    def test_remote_checksum_url_and_license_binding_refused(self):
        row=self.fixture.catalog['sources'][0]; row['url']='https://example.invalid/foreign.tar'; self.fixture.refresh_inputs()
        self.refused('URL|checksum')

    def test_foreign_duplicate_and_unpinned_supplements_refused(self):
        old=copy.deepcopy(self.fixture.inputs)
        self.fixture.inputs['packages']*=2; self.fixture.inputs_raw=m.encoded(self.fixture.inputs)
        self.fixture.inputs_path.write_bytes(self.fixture.inputs_raw); self.refused('duplicate')
        self.fixture.inputs=old; self.fixture.inputs['packages'][0]['package']['sha256']='a'*64
        self.fixture.inputs_raw=m.encoded(self.fixture.inputs); self.fixture.inputs_path.write_bytes(self.fixture.inputs_raw)
        self.refused('identity')

    def test_ambiguous_srcinfo_groups_and_identity_refused(self):
        f = self.fixture; name = f.name
        original = f.bodies[name]['.SRCINFO']
        for changed in (original.replace(b'sha256sums = ', b'sha256sums_aarch64 = ', 1),
                        original.replace(b'pkgrel = 1', b'pkgver = 1')):
            f.bodies[name]['.SRCINFO'] = changed
            record = f.index['packages'][0]
            record['bundle'] = f.material(name, 'source.tar', recipe.tar_bytes(f.bodies[name]))
            record['source_map'] = f.material(name, 'map', m.encoded({key:s.digest(raw) for key,raw in f.bodies[name].items()}))
            f.refresh()
            f.plan['recipe_inputs'] = {key:s.digest(raw) for key,raw in f.bodies[name].items()}
            f.refresh_inputs()
            self.refused('SRCINFO')

    def test_rehashed_remote_receipt_mismatch_refused(self):
        raw, manifest, _ = self.fixture.build()
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as source:
            files = {node.name: source.extractfile(node).read() for node in source}
        manifest['packages'][0]['remote_sources'][0]['receipt'] = manifest['packages'][0]['catalog']
        rebuilt = m.tar_bytes(dict(files, **{'mirror.json': m.encoded(manifest)}))
        with self.assertRaisesRegex(ValueError, 'receipt binding'):
            m.verify(rebuilt, s.digest(rebuilt), self.fixture.pin)


if __name__ == '__main__':
    unittest.main()
