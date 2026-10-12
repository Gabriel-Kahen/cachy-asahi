"""CI trust-boundary regressions; no Docker, network or package installation."""
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


native = module('native_arm')
freezer = module('freeze')
evidence = module('log_evidence')
SIGNER = '68B3537F39A313B3E574D06777193F152BDBE6A6'
STATUS = f'[GNUPG:] VALIDSIG {SIGNER} 2026-08-05 1785933702 0 4 0 1 10 00 {SIGNER}\n'


def pin(name, data=b'payload'):
    return {'filename': name, 'url': 'https://example.invalid/' + name,
            'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}


class TempCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)


class SignatureTests(unittest.TestCase):
    def test_expected_primary_signer(self):
        native.valid_signature(STATUS, SIGNER)

    def test_other_primary_rejected(self):
        with self.assertRaises(ValueError):
            native.valid_signature(STATUS.replace(SIGNER, 'A' * 40), SIGNER)

    def test_expired_revoked_bad_or_missing_signatures_rejected(self):
        for marker in ('EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG', 'NO_PUBKEY'):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                native.valid_signature(STATUS + f'[GNUPG:] {marker} ignored\n', SIGNER)

    def test_no_or_duplicate_valid_signature_rejected(self):
        for status in ('', STATUS + STATUS):
            with self.subTest(status=status), self.assertRaises(ValueError):
                native.valid_signature(status, SIGNER)

    def test_truncated_validsig_is_not_authentication(self):
        with self.assertRaises(ValueError):
            native.valid_signature(f'[GNUPG:] VALIDSIG {SIGNER}\n', SIGNER)


class FetchTests(TempCase):
    def response(self, data, url='https://example.invalid/payload'):
        result = io.BytesIO(data)
        result.url = url
        return result

    def test_fresh_download_and_cached_bytes_match_pin(self):
        item = pin('payload')
        with patch.object(native.urllib.request, 'urlopen', return_value=self.response(b'payload')) as opener:
            path = native.fetch(item, self.base)
            self.assertEqual(path.read_bytes(), b'payload')
            self.assertEqual(native.fetch(item, self.base), path)
            self.assertEqual(opener.call_count, 1)

    def test_bad_digest_or_oversized_download_leaves_no_result(self):
        for data in (b'changed', b'too many bytes'):
            with self.subTest(data=data), patch.object(native.urllib.request, 'urlopen', return_value=self.response(data)):
                with self.assertRaises(ValueError):
                    native.fetch(pin('payload'), self.base)
                self.assertEqual(list(self.base.iterdir()), [])

    def test_cached_replacement_and_symlink_rejected(self):
        target = self.base / 'payload'
        target.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            native.fetch(pin('payload'), self.base)
        target.unlink()
        source = self.base / 'other'
        source.write_bytes(b'payload')
        target.symlink_to(source)
        with self.assertRaises(ValueError):
            native.fetch(pin('payload'), self.base)

    def test_http_input_or_redirect_rejected(self):
        item = pin('payload')
        item['url'] = 'http://example.invalid/payload'
        with self.assertRaises(ValueError):
            native.fetch(item, self.base)
        with patch.object(native.urllib.request, 'urlopen', return_value=self.response(b'payload', 'http://example.invalid/payload')):
            with self.assertRaises(ValueError):
                native.fetch(pin('payload'), self.base)

    def test_traversal_rejected(self):
        with self.assertRaises(ValueError):
            native.fetch(pin('../outside'), self.base)

    def test_preexisting_partial_is_not_deleted(self):
        partial = self.base / 'payload.partial'
        partial.write_bytes(b'another download')
        with patch.object(native.urllib.request, 'urlopen', return_value=self.response(b'payload')):
            self.assertEqual(native.fetch(pin('payload'), self.base).read_bytes(), b'payload')
        self.assertEqual(partial.read_bytes(), b'another download')


class MetadataTests(TempCase):
    expected = {'name': 'sample', 'version': '1-1', 'arch': 'aarch64',
                'license': ['MIT'], 'depends': ['glibc'], 'provides': [],
                'conflicts': [], 'replaces': []}
    pkginfo = b'pkgname = sample\npkgver = 1-1\narch = aarch64\nlicense = MIT\ndepend = glibc\n'

    def archive(self, members):
        path = self.base / 'sample.pkg.tar.xz'
        with tarfile.open(path, 'w:xz') as archive:
            for name, data in members:
                member = tarfile.TarInfo(name)
                if data is None:
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/outside/hook'
                    archive.addfile(member)
                else:
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
        return path

    def test_signed_metadata_and_hooks_recorded(self):
        report = native.inspect_package(self.archive([('.PKGINFO', self.pkginfo), ('.INSTALL', b'post_install() { :; }')]), self.expected)
        self.assertIn('.INSTALL', report['hooks'])

    def test_signed_version_dependency_or_license_mismatch_rejected(self):
        for field, value in [('version', '2-1'), ('depends', []), ('license', ['GPL'])]:
            expected = dict(self.expected, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                native.inspect_package(self.archive([('.PKGINFO', self.pkginfo)]), expected)

    def test_traversal_member_rejected(self):
        with self.assertRaises(ValueError):
            native.inspect_package(self.archive([('.PKGINFO', self.pkginfo), ('../outside', b'x')]), self.expected)

    def test_duplicate_metadata_cannot_hide_earlier_member(self):
        with self.assertRaises(ValueError):
            native.inspect_package(self.archive([('.PKGINFO', self.pkginfo.replace(b'1-1', b'9-1')), ('.PKGINFO', self.pkginfo)]), self.expected)

    def test_symlinked_installation_hook_cannot_escape_review(self):
        with self.assertRaises(ValueError):
            native.inspect_package(self.archive([('.PKGINFO', self.pkginfo), ('usr/share/libalpm/hooks/custom.hook', None)]), self.expected)


class EvidenceTests(TempCase):
    def test_small_evidence_included_private_bootstrap_excluded(self):
        (self.base / 'result.json').write_text('{"native_build":"NOT RUN"}')
        for name in ('context', 'gpg'):
            path = self.base / name
            path.mkdir()
            (path / 'private').write_text('do not retain')
        with tarfile.open(fileobj=io.BytesIO(evidence.bundle(self.base)), mode='r:gz') as archive:
            self.assertEqual(archive.getnames(), [self.base.name + '/result.json'])

    def test_symlink_evidence_rejected(self):
        (self.base / 'link').symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            evidence.bundle(self.base)

    def test_missing_evidence_directory_rejected(self):
        with self.assertRaises((ValueError, OSError)):
            evidence.bundle(self.base / 'missing')

    def test_expanded_evidence_budget_enforced(self):
        with (self.base / 'large').open('wb') as stream:
            stream.truncate(16 * 1024**2 + 1)
        with self.assertRaises(ValueError):
            evidence.bundle(self.base)


class NativeBoundaryTests(TempCase):
    def arm_probe(self, endpoint):
        def capture(command, **kwargs):
            if command[:3] == ['docker', 'context', 'inspect']:
                return json.dumps([{'Endpoints': {'docker': {'Host': endpoint}}}])
            return 'arm64'

        with patch.object(native.platform, 'system', return_value='Linux'), patch.object(native.platform, 'machine', return_value='aarch64'), patch.object(native.os, 'getuid', return_value=1001), patch.object(native, 'run', side_effect=capture):
            return native.probe(self.base)

    def test_local_arm_probe_records_endpoint_without_claiming_build(self):
        with patch.dict(native.os.environ, {}, clear=True):
            record = self.arm_probe('unix:///var/run/docker.sock')
        self.assertEqual(record['docker_endpoint'], 'unix:///var/run/docker.sock')
        self.assertEqual(record['native_build'], 'NOT RUN')
        self.assertEqual(record['hardware_validation'], 'NOT RUN')

    def test_remote_arm_docker_context_rejected(self):
        with patch.dict(native.os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                self.arm_probe('ssh://remote.invalid')

    def test_remote_docker_host_override_rejected(self):
        with patch.dict(native.os.environ, {'DOCKER_HOST': 'tcp://remote.invalid:2376'}, clear=True):
            with self.assertRaises(ValueError):
                self.arm_probe('unix:///var/run/docker.sock')

    def test_pinned_json_checked_before_parsing(self):
        path = self.base / 'inputs.json'
        path.write_text('{"snapshot":"reviewed"}')
        digest = native.sha(path)
        self.assertEqual(native.load_pinned(path, digest), {'snapshot': 'reviewed'})
        path.write_text('{"snapshot":"changed"}')
        with self.assertRaises(ValueError):
            native.load_pinned(path, digest)

    def test_pinned_json_cannot_change_between_hash_and_parse(self):
        path = self.base / 'inputs.json'
        original = b'{"snapshot":"reviewed"}'
        path.write_bytes(original)
        digest = hashlib.sha256(original).hexdigest()

        def replace_after_hash(_):
            path.write_text('{"snapshot":"changed"}')
            return digest

        with patch.object(native, 'sha', side_effect=replace_after_hash):
            self.assertEqual(native.load_pinned(path, digest), {'snapshot': 'reviewed'})

    def test_x86_host_never_produces_native_pass(self):
        with patch.object(native.platform, 'machine', return_value='x86_64'), patch.object(native, 'run', return_value='arm64'):
            with self.assertRaises(ValueError):
                native.probe(self.base)
        self.assertEqual(json.loads((self.base / 'runner.json').read_text())['native_build'], 'NOT RUN')

    def test_nonarm_daemon_never_produces_native_pass(self):
        with patch.object(native.platform, 'system', return_value='Linux'), patch.object(native.platform, 'machine', return_value='aarch64'), patch.object(native, 'run', return_value='x86_64'):
            with self.assertRaises(ValueError):
                native.probe(self.base)

    def test_root_coordinator_rejected(self):
        with patch.object(native.platform, 'system', return_value='Linux'), patch.object(native.platform, 'machine', return_value='aarch64'), patch.object(native, 'run', return_value='arm64'), patch.object(native.os, 'getuid', return_value=0):
            with self.assertRaises(ValueError):
                native.probe(self.base)

    def test_frozen_rootfs_inventory_must_match_authenticated_image(self):
        inputs = {'rootfs': dict(pin('rootfs.tar.gz'), signature_sha256='a' * 64, signature_size=566),
                  'packages': [], 'keyring_files': [], 'signer_fingerprint': SIGNER,
                  'rootfs_packages': [{'name': ['fabricated']}]}
        status = type('Result', (), {'returncode': 0, 'stdout': STATUS, 'stderr': ''})()
        with patch.object(native, 'fetch'), patch.object(native, 'run'), patch.object(native.subprocess, 'run', return_value=status), patch.object(native, 'rootfs_inventory', return_value=[{'name': ['actual']}]), patch.object(native, 'inspect_package') as inspector:
            with self.assertRaises(ValueError):
                native.audit(inputs, self.base / 'cache', self.base)
            inspector.assert_not_called()

    def test_cache_replacement_rejected_before_docker(self):
        cache, out = self.base / 'cache', self.base / 'out'
        cache.mkdir()
        out.mkdir()
        rootfs = pin('rootfs.tar.gz', b'authenticated bytes')
        (cache / rootfs['filename']).write_bytes(b'replaced after audit')
        inputs = {'rootfs': rootfs, 'packages': [], 'keyring_files': []}
        (out / 'inputs.lock.json').write_text(json.dumps(inputs))
        with patch.object(native, 'run', side_effect=RuntimeError('would execute Docker')) as runner:
            with self.assertRaises(ValueError):
                native.build(inputs, cache, out, {})
            runner.assert_not_called()

    def test_build_masks_old_and_incoming_hooks_with_supported_transaction(self):
        cache, out = self.base / 'cache', self.base / 'out'
        cache.mkdir()
        out.mkdir()
        rootfs = pin('rootfs.tar.gz', b'authenticated bytes')
        (cache / rootfs['filename']).write_bytes(b'authenticated bytes')
        inputs = {'rootfs': rootfs, 'packages': [], 'keyring_files': []}
        (out / 'inputs.lock.json').write_text(json.dumps(inputs))
        (out / 'rootfs-hooks.json').write_text('["existing.hook"]')
        (out / 'package-audit.json').write_text(json.dumps({'incoming': {'installed_paths': [
            'usr/share/libalpm/hooks/new.hook', 'etc/pacman.d/hooks/existing.hook']}}))
        with patch.object(native, 'run', side_effect=ValueError('stop before Docker execution')):
            with self.assertRaisesRegex(ValueError, 'stop before Docker'):
                native.build(inputs, cache, out, {})
        context = out / 'context'
        self.assertEqual((context / 'disabled-hooks.txt').read_text(), 'existing.hook\nnew.hook\n')
        self.assertIn('HookDir = /builder-disabled-hooks', (context / 'pacman.conf').read_text())
        dockerfile = (context / 'Dockerfile').read_text()
        self.assertIn('ln -s /dev/null', dockerfile)
        self.assertIn('pacman -U --noconfirm --noscriptlet', dockerfile)
        self.assertNotIn('--nohooks', dockerfile)


class FreezeTests(TempCase):
    def inputs(self):
        description = ('%NAME%\nsample\n\n%VERSION%\n1-1\n\n%FILENAME%\nsample.pkg.tar.xz\n\n'
                       '%ARCH%\naarch64\n\n%PGPSIG%\nc2ln\n\n%SHA256SUM%\n' + 'a' * 64 + '\n\n'
                       '%CSIZE%\n7\n\n%LICENSE%\nMIT\n\n')
        depends = '%DEPENDS%\nglibc\n\n%PROVIDES%\nvirtual=1\n\n'
        for repo in ('core', 'extra', 'alarm', 'aur'):
            with tarfile.open(self.base / (repo + '.db'), 'w:gz') as archive:
                if repo == 'core':
                    for name, text in [('desc', description), ('depends', depends)]:
                        member = tarfile.TarInfo('sample-1-1/' + name)
                        data = text.encode()
                        member.size = len(data)
                        archive.addfile(member, io.BytesIO(data))
        for name in ('archlinuxarm.gpg', 'archlinuxarm-trusted', 'archlinuxarm-revoked',
                     'ArchLinuxARM-2026.08-aarch64-rootfs.tar.gz', 'ArchLinuxARM-2026.08-aarch64-rootfs.tar.gz.sig'):
            (self.base / name).write_bytes(b'fixture')
        (self.base / 'rootfs-inventory.json').write_text('[]')
        (self.base / 'transaction.txt').write_text('core sample 1-1 sample.pkg.tar.xz https://example.invalid/sample.pkg.tar.xz\n')

    def test_dependency_members_included_without_claiming_signed_database(self):
        self.inputs()
        result = freezer.freeze(self.base)
        self.assertEqual(result['packages'][0]['depends'], ['glibc'])
        self.assertEqual(result['packages'][0]['provides'], ['virtual=1'])
        self.assertTrue(all(row['signed'] is False for row in result['repository_databases']))
        self.assertEqual(result['native_build'], 'NOT RUN')

    def test_database_transaction_mismatch_rejected_explicitly(self):
        self.inputs()
        path = self.base / 'transaction.txt'
        path.write_text(path.read_text().replace('sample 1-1', 'sample 9-1'))
        with self.assertRaises(ValueError):
            freezer.freeze(self.base)


class RecipeFreezeTests(TempCase):
    def recipes(self):
        paths = []
        for name in native.RECIPES:
            path = self.base / 'packages' / 'settings' / name / 'PKGBUILD'
            path.parent.mkdir(parents=True)
            path.write_text('recipe is data in this test')
            paths.append(path)
        return paths

    def report(self, path):
        return {'recipe': str(path), 'errors': [], 'metadata': {'pkgname': [path.parent.name]},
                'input_sha256': {'PKGBUILD': hashlib.sha256(path.read_bytes()).hexdigest()}}

    def test_complete_four_recipe_hashes_frozen_without_shell_execution(self):
        self.recipes()
        output = self.base / 'review.json'
        with patch.object(native, 'ROOT', self.base), patch.object(native, 'recipe', side_effect=self.report), patch.object(native, 'setup_sync'), patch.object(native.subprocess, 'run') as runner:
            native.freeze_recipes(output)
            runner.assert_not_called()
        self.assertEqual(sorted(Path(p).name for p in json.loads(output.read_text())), sorted(native.RECIPES))

    def test_missing_recipe_cannot_freeze_complete_set(self):
        self.recipes()[0].unlink()
        output = self.base / 'review.json'
        with patch.object(native, 'ROOT', self.base), patch.object(native, 'recipe', side_effect=self.report), patch.object(native, 'setup_sync'):
            with self.assertRaises(ValueError):
                native.freeze_recipes(output)
        self.assertFalse(output.exists())


class HookMaskTests(unittest.TestCase):
    def test_masks_are_exact_unique_sorted_names(self):
        names = ['36-systemd-modules-load.hook', '25-systemd-binfmt.hook', '25-systemd-binfmt.hook']
        self.assertEqual(native.hook_masks(names), '25-systemd-binfmt.hook\n36-systemd-modules-load.hook\n')
        self.assertEqual(native.hook_masks([]), '')

    def test_unsafe_hook_names_rejected(self):
        for name in ('../escape.hook', '/absolute.hook', 'space name.hook', 'newline\n.hook',
                     '`id`.hook', '$(id).hook', 'name;id.hook', 'missing-suffix', '..'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                native.hook_masks([name])


class SetupSyncTests(TempCase):
    def setUp(self):
        super().setUp()
        self.package = self.base / 'packages/settings/cachy-asahi-setup'
        self.package.mkdir(parents=True)
        self.canonical = self.base / 'scripts/setup/setup.py'
        self.canonical.parent.mkdir(parents=True)
        source, license_text = b'raise RuntimeError("must never execute helper")\n', b'MIT fixture license\n'
        self.canonical.write_bytes(source)
        (self.package / 'cachy-asahi-setup').write_bytes(source)
        (self.base / 'LICENSE').write_bytes(license_text)
        (self.package / 'LICENSE').write_bytes(license_text)
        self.provenance = {'canonical_path': 'scripts/setup/setup.py', 'packaged_source': 'cachy-asahi-setup',
                           'sha256': hashlib.sha256(source).hexdigest(),
                           'license_sha256': hashlib.sha256(license_text).hexdigest()}
        self.write_provenance()

    def write_provenance(self):
        (self.package / 'source-provenance.json').write_text(json.dumps(self.provenance))

    def sync(self):
        with patch.object(native, 'ROOT', self.base):
            return native.setup_sync()

    def test_matching_source_and_license_are_only_read(self):
        before = {str(path): path.read_bytes() for path in self.base.rglob('*') if path.is_file()}
        with patch.object(native.subprocess, 'run') as runner:
            self.sync()
            runner.assert_not_called()
        self.assertEqual(before, {str(path): path.read_bytes() for path in self.base.rglob('*') if path.is_file()})

    def test_canonical_source_drift_rejected(self):
        self.canonical.write_text('changed canonical helper')
        with self.assertRaises(ValueError):
            self.sync()

    def test_packaged_source_drift_rejected(self):
        (self.package / 'cachy-asahi-setup').write_text('changed packaged helper')
        with self.assertRaises(ValueError):
            self.sync()

    def test_each_license_drift_rejected(self):
        for path in (self.base / 'LICENSE', self.package / 'LICENSE'):
            original = path.read_bytes()
            path.write_text('changed license')
            with self.subTest(path=str(path)), self.assertRaises(ValueError):
                self.sync()
            path.write_bytes(original)

    def test_unexpected_or_escaping_provenance_paths_rejected(self):
        for field, path in [('canonical_path', '../setup.py'), ('canonical_path', '/tmp/setup.py'),
                            ('canonical_path', 'scripts/setup/other.py'), ('packaged_source', '../setup.py'),
                            ('packaged_source', 'renamed-helper')]:
            original = self.provenance[field]
            self.provenance[field] = path
            self.write_provenance()
            with self.subTest(field=field, path=path), self.assertRaises(ValueError):
                self.sync()
            self.provenance[field] = original
        self.write_provenance()

    def test_each_bound_file_symlink_rejected_even_with_matched_bytes(self):
        for index, path in enumerate((self.canonical, self.package / 'cachy-asahi-setup',
                                      self.base / 'LICENSE', self.package / 'LICENSE')):
            content = path.read_bytes()
            target = self.base / ('target-' + str(index))
            target.write_bytes(content)
            path.unlink()
            path.symlink_to(target)
            with self.subTest(path=str(path)), self.assertRaises(ValueError):
                self.sync()
            path.unlink()
            path.write_bytes(content)

    def test_parent_symlink_escape_rejected_with_matched_bytes(self):
        with tempfile.TemporaryDirectory() as other:
            target = Path(other)
            (target / 'setup.py').write_bytes(self.canonical.read_bytes())
            self.canonical.unlink()
            self.canonical.parent.rmdir()
            self.canonical.parent.symlink_to(target, target_is_directory=True)
            with self.assertRaises(ValueError):
                self.sync()

    def test_incomplete_hash_pin_rejected(self):
        self.provenance['sha256'] = self.provenance['sha256'][:12]
        self.write_provenance()
        with self.assertRaises(ValueError):
            self.sync()


if __name__ == '__main__':
    unittest.main()
