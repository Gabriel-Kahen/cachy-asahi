# SPDX-License-Identifier: MIT
"""Explicitly modeled build receipts; real archive parsing and authenticated CLI."""
import copy
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

import common
import provenance


def check_retained_archives(native_root, module=provenance):
    """Explicit actual-data regression; absent or changed retained bytes fail."""
    native_root = Path(native_root)
    accepted = {}
    dependencies = {'cachy-asahi-fish-config': ['fish', 'coreutils'], 'cachy-asahi-zsh-config': ['zsh'],
                    'cachy-asahi-hyprland-settings': ['hyprland>=0.56.2', 'hyprland<0.57.0', 'alacritty', 'wofi',
                                                    'swaylock', 'wireplumber', 'brightnessctl'],
                    'cachy-asahi-setup': ['python>=3.11']}
    for name, version, size, pin in (
        ('cachy-asahi-fish-config', '0.1.0-1', 5400, '22e6e3ca4f23b73434c4aed284016914652900c33e845516621c0eb8b176d64e'),
        ('cachy-asahi-zsh-config', '0.1.0-1', 6240, '1bcb8e7fde6da28bc817f252bee5c7084cd22ec4153512eaf5bb47bd83e90faa'),
        ('cachy-asahi-hyprland-settings', '0.1.0-1', 8780, '5d33320b55c2b3c778b94c128980c2d07d3fbcf466b3ab91ad8a706ff538ee81'),
        ('cachy-asahi-setup', '0.1.0-2', 14128, '40e392b4af6485d8518993073c1fe643eda60053312aeb618dfa9a6c9bee3489'),
    ):
        filename = name + '-' + version + '-any.pkg.tar.xz'
        raw = common.read(native_root / (name + '-1') / 'artifacts' / filename)
        common.need(len(raw) == size and common.digest(raw) == pin, 'retained archive external pin differs')
        package, members = module.package_bytes(raw)
        common.need((package['name'], package['version'], package['arch'], package['license']) ==
                    (name, version, 'any', ['MIT']), 'retained package identity/license differs')
        common.need(package['depend'] == dependencies[name] and
                    all(package[key] == [] for key in ('provides', 'conflict', 'replaces')),
                    'retained package relations differ')
        common.need(common.digest(members['usr/share/licenses/' + name + '/LICENSE']) ==
                    '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 'retained license differs')
        if name in ('cachy-asahi-fish-config', 'cachy-asahi-zsh-config'):
            common.need(members['.PKGINFO'].split(b'\n').count(b'url = ') == 1, 'retained empty URL relation differs')
        accepted[name] = {'sha256': pin, 'bytes': size, 'depend': package['depend']}
    return {'archives': accepted, 'scope': 'retained package parsing only', 'native_execution': 'NOT RUN'}


class Fixture:
    """Fabricated observations are never eligible native evidence."""
    def __init__(self, root, role='baseline'):
        self.root, self.role, self.files = root, role, {}
        self.base = {'schema_version': 1, 'kind': 'complete-target-transaction', 'target_arch': 'aarch64',
                     'snapshot_id': 'MODELED-generic', 'packages': [
                         {'name': f'base{n:03}', 'version': '1-1', 'arch': 'aarch64', 'depend': [],
                          'provides': [], 'conflict': [], 'files': [f'usr/base{n:03}']} for n in range(341)]}
        self.lock = ''.join(f"{p['name']} {p['version']}\n" for p in self.base['packages']).encode()
        self.image = 'sha256:' + '1' * 64
        self.fixture = {'schema_version': 1, 'source_commit': '2' * 40, 'development_only': True,
                        'selected_for_release': False, 'source_date_epoch': 123,
                        'generator_sha256': common.digest(b'# MODELED generator\n'), 'packages': {}}
        self.rows = []
        self.put('packages.lock', self.lock)
        self.put('source/entry.sh', b'# MODELED build entry\n')
        self.put('source/generator.py', b'# MODELED generator\n')
        for number, name in enumerate(sorted(provenance.ORIGINALS)):
            recipes = {'PKGBUILD': b'# MODEL recipe\n', '.SRCINFO': f'pkgname = {name}\npkgver = 1\npkgrel = 1\narch = any\nlicense = MIT\n'.encode(),
                       'LICENSE': b'MODELED MIT notice\n'}
            recipe_pins = {key: common.digest(raw) for key, raw in recipes.items()}
            filename = name + '-1-1-any.pkg.tar.xz'
            pkg = {'name': name, 'version': '1-1', 'arch': 'any'}
            payload = {'.PKGINFO': f'pkgname = {name}\npkgver = 1-1\narch = any\nlicense = MIT\n'.encode(),
                       '.BUILDINFO': f'format = 2\npkgname = {name}\npkgver = 1-1\npkgarch = any\npkgbuild_sha256sum = {recipe_pins["PKGBUILD"]}\n'.encode(),
                       '.MTREE': b'MODELED mtree', 'usr/share/licenses/' + name + '/LICENSE': recipes['LICENSE'],
                       'usr/share/' + name + '/fixture': b'MODELED package'}
            archive = self.archive(payload)
            self.put('selected/' + filename, archive)
            first, second = f'builds/{number}-1', f'builds/{number}-2'
            for attempt, prefix in enumerate((first, second), 1):
                evidence = {'build.log': b'MODELED compilation\n', 'validation.json': common.encoded({'errors': [], 'artifacts': [{'sha256': common.digest(archive)}]}),
                            'expected-packages.lock': self.lock, 'artifacts/packages.lock': self.lock,
                            'artifacts/generated.SRCINFO': recipes['.SRCINFO'], 'artifacts/environment.txt': b'MODELED ARM\n',
                            'artifacts/config.sha256': b'MODELED\n', 'artifacts/makepkg.conf': b'MODELED\n',
                            'artifacts/pacman.conf': b'MODELED\n', 'artifacts/' + filename: archive}
                for key, raw in evidence.items(): self.put(prefix + '/' + key, raw)
                for key, raw in recipes.items(): self.put(prefix + '/inputs/' + key, raw)
                receipt = {'schema_version': 1, 'status': 'built-package-static-pass', 'mode': 'native', 'network': 'none',
                           'image': self.image, 'image_id': self.image, 'builder_host_arch': 'aarch64', 'exit_code': 0,
                           'hardware_status': 'NOT RUN', 'recipe_inputs': recipe_pins, 'recipe_metadata': {'MODELED': True},
                           'artifacts': {filename: common.digest(archive)}, 'files': {key: common.digest(raw) for key, raw in evidence.items()},
                           'expected_packages_sha256': common.digest(self.lock), 'source_date_epoch': 123,
                           'entry_script_sha256': common.digest(self.files['source/entry.sh']), 'clean_environment_id': 'cachy-asahi-' + f'{number * 2 + attempt:016x}',
                           'command': ['docker', 'run', '--rm', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                                       '--network', 'none', self.image, '/builder-entry.sh']}
                self.put(prefix + '/provenance.json', common.encoded(receipt))
            compare = f'comparisons/{number}.json'
            self.put(compare, common.encoded({'status': 'contents-reproduced', 'errors': [], 'packages': {
                filename: {'installed_contents_equal': True, 'pkginfo_equal': True, 'bytes_equal': True}}}))
            diff = f'diffs/{number}.diff'; self.put(diff, b'MODELED changed recipe\n')
            self.fixture['packages'][name] = {'recipe': 'packages/MODELED/' + name,
                'base_inputs_sha256': recipe_pins, 'fixture_inputs_sha256': recipe_pins,
                'base_recipe_sha256': recipe_pins['PKGBUILD'], 'fixture_recipe_sha256': recipe_pins['PKGBUILD'],
                'base_version': '1-1', 'upgrade_version': '1-1', 'diff_sha256': common.digest(self.files[diff])}
            self.rows.append({'name': name, 'archive': 'selected/' + filename, 'first': first, 'second': second, 'compare': compare, 'diff': diff})
        self.put('fixture.json', common.encoded(self.fixture))
        self.request = {'schema_version': 1, 'purpose': 'native-artifact-provenance-inputs', 'source_commit': '5' * 40,
                        'recipe_source_commit': '2' * 40, 'repository_url': 'https://github.com/MODELED/project', 'image_id': self.image,
                        'archive_role': role, 'snapshot_id': 'MODELED-generic', 'packages_lock': 'packages.lock',
                        'files': {}, 'packages': self.rows, 'fixture_manifest': 'fixture.json',
                        'entry_script': 'source/entry.sh', 'generator_source': 'source/generator.py'}

    @staticmethod
    def archive(payload):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:xz') as archive:
            for name, raw in payload.items():
                member = tarfile.TarInfo(name); member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
        return buffer.getvalue()

    def put(self, name, raw):
        self.files[name] = raw
        path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)

    def run(self):
        self.request['files'] = {name: {'sha256': common.digest(raw), 'bytes': len(raw)} for name, raw in self.files.items()}
        raw, base = common.encoded(self.request), common.encoded(self.base)
        return provenance.consume(self.root, raw, common.digest(raw), base, common.digest(base))


class PackageURL(unittest.TestCase):
    INFO = ('pkgname = cachy-asahi-fish-config\npkgver = 1-1\narch = any\nlicense = MIT\n'
            'depend = fish\ndepend = coreutils\nprovides = helper\nconflict = other-helper\nreplaces = old-helper\n')

    def package(self, fields='', *, info=None):
        return provenance.package_bytes(Fixture.archive({'.PKGINFO': ((self.INFO if info is None else info) + fields).encode(),
                                                        'usr/share/fixture': b'UNCHANGED TEST payload'}))

    def test_single_empty_url_and_omission_have_same_metadata(self):
        absent, _ = self.package()
        empty, members = self.package('url = \n')
        self.assertEqual(empty, absent)
        self.assertTrue(members['.PKGINFO'].endswith(b'url = \n'))

    def test_nonempty_url_preserves_identity_relations_and_members(self):
        absent, _ = self.package()
        url = 'https://Example.test/A%2fb?x=Q#fragment'
        actual, members = self.package('url = ' + url + '\n')
        self.assertEqual(actual, absent)
        self.assertTrue(members['.PKGINFO'].endswith(('url = ' + url + '\n').encode()))
        self.assertEqual(actual['depend'], ['fish', 'coreutils'])
        self.assertEqual(actual['provides'], ['helper'])
        self.assertEqual(actual['conflict'], ['other-helper'])
        self.assertEqual(actual['replaces'], ['old-helper'])
        self.assertEqual(actual['license'], ['MIT'])

    def test_duplicate_urls_refused_even_when_equal_or_empty(self):
        for fields in ('url = \nurl = \n', 'url = https://x\nurl = https://x\n',
                       'url = \nurl = https://x\n', 'url = https://x\nurl = https://y\n'):
            with self.subTest(fields=fields), self.assertRaises(common.Refused): self.package(fields)

    def test_other_empty_fields_stay_refused(self):
        for key in ('pkgname', 'pkgver', 'arch', 'license', 'depend', 'provides', 'conflict', 'replaces', 'pkgdesc', 'builddate'):
            with self.subTest(key=key), self.assertRaisesRegex(common.Refused, 'invalid package field'):
                self.package(key + ' = \n')

    def test_malformed_url_keys_and_separators_refused(self):
        for fields in (' url = https://x\n', 'url  = https://x\n', 'url\t = https://x\n',
                       'url=https://x\n', 'url =https://x\n', 'url= https://x\n'):
            with self.subTest(fields=fields), self.assertRaises(common.Refused): self.package(fields)

    def test_whitespace_padding_and_unicode_controls_refused(self):
        for char in (' ', '\t', '\v', '\f', '\x00', '\x1b', '\x7f', '\x85', '\xa0', '\u200b', '\u202e', '\u2066'):
            for value in (char, 'https://x' + char, 'https://' + char + 'x'):
                with self.subTest(value=value), self.assertRaises(common.Refused): self.package('url = ' + value + '\n')

    def test_raw_cr_and_unicode_line_separator_erasure_refused(self):
        for fields in ('url = \r\n', 'url = https://x\r\n', 'url = https://x\r',
                       'url = https://x\u2028', 'url = https://x\u2029', 'url = https://x\x1c'):
            with self.subTest(fields=fields), self.assertRaises(common.Refused): self.package(fields)

    def test_url_cannot_weaken_identity_license_or_hook_checks(self):
        for info in (self.INFO.replace('arch = any', 'arch = x86_64'), self.INFO.replace('license = MIT', 'license = GPL'),
                     self.INFO + 'pkgname = cachy-asahi-fish-config\n'):
            with self.subTest(info=info), self.assertRaises(common.Refused): self.package('url = \n', info=info)
        raw = Fixture.archive({'.PKGINFO': (self.INFO + 'url = \n').encode(), '.INSTALL': b'TEST hook'})
        with self.assertRaises(common.Refused): provenance.package_bytes(raw)

    def test_url_like_description_remains_opaque(self):
        absent, members = self.package('pkgdesc = url = \n')
        self.assertEqual(absent['name'], 'cachy-asahi-fish-config')
        self.assertTrue(members['.PKGINFO'].endswith(b'pkgdesc = url = \n'))


class Consume(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rcn-provenance-tests-')
        self.root = Path(self.temp.name)
        self.fixture = Fixture(self.root)

    def tearDown(self): self.temp.cleanup()

    def test_modeled_complete_baseline_consumption(self):
        result = self.fixture.run()
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(set(result['provenance']), provenance.ORIGINALS)
        self.assertTrue(all(p['build']['execution'] == 'native' for p in result['provenance'].values()))

    def test_modeled_updated_preserves_synthetic_native_compilation(self):
        self.fixture.request['archive_role'] = 'updated'
        result = self.fixture.run()
        for p in result['provenance'].values():
            self.assertEqual(p['build']['execution'], 'synthetic')
            self.assertEqual(p['build']['actual_compilation'], 'native')
            generated = [src for src in p['sources'] if src.get('generated')]
            self.assertTrue(all('commit' not in src and src['url'].startswith('evidence:sha256:') for src in generated))
            generator = [src for src in p['sources'] if src.get('role') == 'generator']
            self.assertEqual(generator[0]['sha256'], self.fixture.fixture['generator_sha256'])

    def change_receipt(self, field, value):
        name = self.fixture.rows[0]['first'] + '/provenance.json'
        record = common.decode(self.fixture.files[name]); record[field] = value
        self.fixture.put(name, common.encoded(record))

    def test_coherently_rebound_wrong_architecture_refused(self):
        self.change_receipt('builder_host_arch', 'x86_64')
        with self.assertRaises(common.Refused): self.fixture.run()

    def test_coherently_rebound_inventory_refused(self):
        self.fixture.base['packages'][0]['version'] = '9-9'
        with self.assertRaises(common.Refused): self.fixture.run()

    def test_one_failed_build_not_skipped(self):
        self.change_receipt('status', 'failed')
        with self.assertRaises(common.Refused): self.fixture.run()

    def test_coherently_rebound_generator_source_not_promoted(self):
        self.fixture.put('source/generator.py', b'changed generator')
        with self.assertRaisesRegex(common.Refused, 'generator'): self.fixture.run()

    def test_coherently_rebound_build_entry_not_promoted(self):
        self.fixture.put('source/entry.sh', b'changed build entry')
        with self.assertRaisesRegex(common.Refused, 'entry source'): self.fixture.run()

    def test_same_container_pair_refused(self):
        row = self.fixture.rows[0]
        second = common.decode(self.fixture.files[row['second'] + '/provenance.json'])
        self.change_receipt('clean_environment_id', second['clean_environment_id'])
        with self.assertRaises(common.Refused): self.fixture.run()

    def test_nonzero_bool_not_zero_exit(self):
        self.change_receipt('exit_code', False)
        with self.assertRaises(common.Refused): self.fixture.run()

    def test_rebound_comparison_lie_refused(self):
        row = self.fixture.rows[0]; name = row['compare']
        value = common.decode(self.fixture.files[name]); next(iter(value['packages'].values()))['bytes_equal'] = False
        self.fixture.put(name, common.encoded(value))
        with self.assertRaises(common.Refused): self.fixture.run()

    def test_extra_input_tree_refused(self):
        (self.root / 'not-mapped').write_bytes(b'poison')
        with self.assertRaises(common.Refused): self.fixture.run()

    def test_drift_not_rebound_refused(self):
        (self.root / self.fixture.rows[0]['archive']).write_bytes(b'poison')
        with self.assertRaises(common.Refused): self.fixture.run()

    def test_archives_do_not_extract_links_or_duplicates(self):
        for kind in ('link', 'duplicate'):
            with self.subTest(kind=kind):
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
                    member = tarfile.TarInfo('x')
                    if kind == 'link': member.type = tarfile.SYMTYPE; member.linkname = '/etc/passwd'
                    archive.addfile(member)
                    if kind == 'duplicate': archive.addfile(member)
                with self.assertRaises(common.Refused): provenance.package_bytes(buffer.getvalue())

    def test_pax_body_refused_before_tarfile_consumption(self):
        header = tarfile.TarInfo('extended'); header.type = tarfile.XHDTYPE; header.size = 16 * 1024**2
        with self.assertRaisesRegex(common.Refused, 'PAX'):
            provenance.package_bytes(header.tobuf() + b'\0' * 1024)

    def test_bind_metadata_requires_exact_artifacts_and_no_models(self):
        components = self.fixture.run(); raw = common.encoded(components)
        authority = {'status': 'PASS', 'recipe_source_commit': components['source_commit'],
                     'source_commit': components['execution_source_commit'], 'image_id': components['image_id'],
                     'archive_role': 'baseline', 'archives': [{key: p[key] for key in ('name', 'version', 'sha256')} for p in components['packages']]}
        policy = {'purpose': 'reviewed-generic-restage-policy', 'platform_scope': 'generic-builder-only',
                  'supported_models': [], 'selected_packages': sorted(provenance.ORIGINALS),
                  'protected_packages': ['base000'], 'coordinated_sets': [{'name': 'MODELED generic', 'versions': {'base001': '1-1'}}]}
        def bind():
            a, p, license_raw = common.encoded(authority), common.encoded(policy), b'MODELED MIT notice\n'
            return provenance.bind_metadata(raw, common.digest(raw), a, common.digest(a), p, common.digest(p), license_raw, common.digest(license_raw))
        result = common.decode(bind())
        self.assertEqual(result['platform_scope'], 'generic-builder-only')
        policy['supported_models'] = ['Mac14,2']
        with self.assertRaises(common.Refused): bind()
        policy['supported_models'] = []
        authority['archives'][0]['sha256'] = '0' * 64
        with self.assertRaises(common.Refused): bind()


if __name__ == '__main__': unittest.main()
