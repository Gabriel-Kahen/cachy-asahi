#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Signed private fixture checks; no package installation or host trust changes.

Pass --workspace inside the private namespace's owned /tmp bind mount.
make_bundle(root, signer, sign) is reusable by the coordinator's transaction tests.
"""
import argparse
import base64
from contextlib import contextmanager, ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@contextmanager
def signing(root):
    """Create and retire only one private TEST key/agent under root."""
    root = Path(root)
    root.mkdir(mode=0o700)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'GNUPGHOME': str(root), 'LC_ALL': 'C'}

    def gpg(options):
        result = subprocess.run(['gpg', '--batch', '--no-options', '--homedir', str(root), *options],
                                env=env, capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors='replace'))
        return result.stdout

    try:
        gpg(['--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
             'TEST ONLY snapshot <snapshot@test.invalid>', 'ed25519', 'sign', '1d'])
        key = next(row.split(':')[9] for row in gpg(['--with-colons', '--list-keys']).decode().splitlines()
                   if row.startswith('fpr:'))
        public = gpg(['--export', key])

        def sign(path):
            signature = Path(str(path) + '.sig')
            signature.unlink(missing_ok=True)
            gpg(['--pinentry-mode', 'loopback', '--passphrase', '', '--local-user', key,
                 '--digest-algo', 'SHA256', '--detach-sign', '--output', str(signature), str(path)])

        yield key, public, sign
    finally:
        subprocess.run(['gpgconf', '--homedir', str(root), '--kill', 'all'],
                       env=env, capture_output=True, timeout=30)


def make_bundle(root, signer, sign, *, base_packages=None, payload=None, name='fixture', version='1-1', compression='gz'):
    """One signed synthetic archive/database plus full existing release semantics."""
    bundle = Path(root) / 'bundle'
    (bundle / 'repo').mkdir(parents=True)
    (bundle / 'provenance').mkdir()
    assert compression in ('gz','xz','zst')
    archive = bundle / f'repo/{name}-{version}-any.pkg.tar.{compression}'
    payload = {'.PKGINFO': f'pkgname = {name}\npkgver = {version}\narch = any\nlicense = MIT\n'.encode(),
               **(payload if payload is not None else {f'usr/share/{name}/config': b'TEST ONLY\n'})}
    with tarfile.open(archive, 'w:' + compression) as stream:
        for member_name, data in payload.items():
            item = tarfile.TarInfo(member_name)
            item.size = len(data)
            stream.addfile(item, io.BytesIO(data))
    sign(archive)
    base = {'schema_version': 1, 'snapshot_id': 'synthetic', 'target_arch': 'aarch64',
            'kind': 'complete-target-transaction', 'packages': base_packages if base_packages is not None else [
                {'name': 'platform-fixture', 'version': '1', 'arch': 'aarch64', 'depend': [],
                 'provides': [], 'conflict': [], 'files': ['boot/fixture']}]}
    (bundle / 'base.json').write_bytes(encoded(base))
    provenance = {'schema_version': 1, 'artifact_sha256': digest(archive),
        'package': {'name': name, 'version': version, 'arch': 'any'},
        'source_commit': 'a' * 40, 'recipe_sha256': 'b' * 64, 'licenses': ['MIT'],
        'sources': [{'url': 'https://invalid.example/fixture', 'sha256': 'c' * 64}],
        'build': {'execution': 'synthetic', 'architecture': 'aarch64', 'environment': 'TEST', 'snapshot_id': 'synthetic'}}
    provenance_path = bundle / f'provenance/{name}.json'
    provenance_path.write_bytes(encoded(provenance))
    effective = {row['name']: row['version'] for row in base['packages']}
    effective[name] = version
    spec = {'schema_version': 1, 'release_id': 'fixture-1', 'repo_name': 'fixture',
        'target_arch': 'aarch64', 'synthetic': True, 'source_commit': 'a' * 40,
        'base': {'path': 'base.json', 'sha256': digest(bundle / 'base.json'), 'snapshot_id': 'synthetic'},
        'packages': [{'artifact': {'path': archive.name, 'sha256': digest(archive)},
                      'provenance': {'path': name + '.json', 'sha256': digest(provenance_path)}}],
        'policy': {'supported_models': ['synthetic'], 'selected_packages': [name],
                   'protected_packages': [row['name'] for row in base['packages'] if row['name'] != name],
                   'coordinated_sets': [{'name': 'synthetic', 'versions': effective}]}}
    (bundle / 'spec.json').write_bytes(encoded(spec))
    pkginfo = {}
    for line in payload['.PKGINFO'].decode().splitlines():
        if line and not line.startswith('#'):
            key, value = line.split(' = ', 1)
            pkginfo.setdefault(key, []).append(value)
    assert pkginfo['pkgname'] == [name] and pkginfo['pkgver'] == [version] and pkginfo['arch'] == ['any']
    fields = {'NAME': [name], 'VERSION': [version], 'ARCH': ['any'], 'FILENAME': [archive.name],
              'SHA256SUM': [digest(archive)],
              'PGPSIG': [base64.b64encode(Path(str(archive) + '.sig').read_bytes()).decode()]}
    for field, key in (('DEPENDS', 'depend'), ('PROVIDES', 'provides'), ('CONFLICTS', 'conflict'), ('REPLACES', 'replaces')):
        if pkginfo.get(key):
            fields[field] = pkginfo[key]
    desc = ''.join('%' + key + '%\n' + '\n'.join(values) + '\n\n' for key, values in fields.items()).encode()
    for suffix in ('db', 'files'):
        path = bundle / f'repo/fixture.{suffix}.tar.gz'
        with tarfile.open(path, 'w:gz') as stream:
            item = tarfile.TarInfo(f'{name}-{version}/desc')
            item.size = len(desc)
            stream.addfile(item, io.BytesIO(desc))
        sign(path)
        (bundle / f'repo/fixture.{suffix}').symlink_to(path.name)
    package = dict(name=name, version=version, arch='any', license=pkginfo['license'],
                   depend=pkginfo.get('depend', []), provides=pkginfo.get('provides', []),
                   conflict=pkginfo.get('conflict', []), replaces=pkginfo.get('replaces', []),
                   files=sorted(path for path in payload if not path.startswith('.')),
                   filename=archive.name, sha256=digest(archive), provenance='provenance/' + name + '.json')
    release = dict(schema_version=1, release_id='fixture-1', signer=signer,
                   created_utc=datetime.now(timezone.utc).isoformat(), packages=[package],
                   files={p.relative_to(bundle).as_posix(): digest(p) for p in bundle.rglob('*')
                          if p.is_file() and not p.is_symlink()},
                   symlinks={p.relative_to(bundle).as_posix(): os.readlink(p)
                             for p in bundle.rglob('*') if p.is_symlink()})
    (bundle / 'release.json').write_bytes(encoded(release))
    sign(bundle / 'release.json')
    return bundle


def make_envelope(root, bundle, signer, public, sign, *, namespace='dev.fixture', sequence=1):
    """Return existing-client args and the snapshot's exact selection settings."""
    c = module('snapshot_fixture_client', ROOT / 'scripts/client/client.py')
    root, bundle = Path(root), Path(bundle)
    state = root / 'state'
    state.mkdir(mode=0o700, exist_ok=True)
    keyring = root / 'public.gpg'
    keyring.write_bytes(public)
    metadata = root / 'metadata.json'
    now = datetime.now(timezone.utc)
    c.build(argparse.Namespace(bundle=str(bundle), output=str(metadata), namespace=namespace,
        signer=signer, sequence=sequence, issued_utc=c.utc(now - timedelta(seconds=30)),
        expires_utc=c.utc(now + timedelta(hours=1))))
    sign(metadata)
    args = argparse.Namespace(bundle=str(bundle), metadata=str(metadata), signature=str(metadata) + '.sig',
        public_keyring=str(keyring), state_dir=str(state), namespace=namespace, signer=signer,
        minimum_sequence=sequence, apply=False)
    spec = json.loads((bundle / 'spec.json').read_text())
    settings = dict(namespace=namespace, signer=signer, minimum_sequence=sequence,
        release_id=spec['release_id'], repo_name=spec['repo_name'], metadata_sha256=digest(metadata),
        release_sha256=digest(bundle / 'release.json'), public_keyring_sha256=digest(keyring))
    return args, settings


class SnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stack = ExitStack()
        cls.addClassCleanup(cls.stack.close)
        cls.base = Path(cls.stack.enter_context(tempfile.TemporaryDirectory(prefix='snapshot-keys-')))
        cls.signer, cls.public, sign = cls.stack.enter_context(signing(cls.base / 'keys'))
        cls.sign = staticmethod(sign)
        cls.other, cls.other_public, _ = cls.stack.enter_context(signing(cls.base / 'other'))
        cls.fixture = make_bundle(cls.base / 'fixture', cls.signer, cls.sign)
        cls.c = module('snapshot_test_client', ROOT / 'scripts/client/client.py')
        cls.snapshot = module('snapshot_under_test', Path(__file__).with_name('snapshot.py'))
        cls.snapshot.ROOT = ROOT

    def setUp(self):
        self.case = tempfile.TemporaryDirectory(prefix='snapshot-case-')
        self.addCleanup(self.case.cleanup)
        self.root = Path(self.case.name)
        self.bundle = self.root / 'bundle'
        shutil.copytree(self.fixture, self.bundle, symlinks=True)
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.workspace = self.root / 'workspace'
        self.workspace.mkdir(mode=0o700)
        self.keyring = self.root / 'public.gpg'
        self.keyring.write_bytes(self.public)
        self.metadata = self.root / 'metadata.json'
        self.select()

    def select(self):
        self.metadata.unlink(missing_ok=True)
        self.args, self.settings = make_envelope(self.root, self.bundle, self.signer, self.public, self.sign)

    def resign(self):
        path = self.bundle / 'release.json'
        release = json.loads(path.read_text())
        for name in release['files']:
            release['files'][name] = digest(self.bundle / name)
        path.write_bytes(encoded(release))
        self.sign(path)
        self.select()

    def authenticated(self):
        return self.snapshot.authenticated(self.args, self.workspace, self.settings)

    def test_real_signed_bundle_semantics_private_copy_cleanup_and_no_checkpoint(self):
        before = self.keyring.read_bytes(), self.keyring.stat().st_mtime_ns
        with self.authenticated() as value:
            self.assertTrue(value['recheck']())
            self.assertNotEqual(value['bundle'], self.bundle)
            self.assertEqual(value['release']['packages'][0]['name'], 'fixture')
            self.assertEqual(os.readlink(value['bundle'] / 'repo/fixture.db'), 'fixture.db.tar.gz')
            self.assertTrue(value['spec']['synthetic'])
            self.assertEqual(list(self.state.iterdir()), [])
        self.assertEqual(list(self.workspace.iterdir()), [])
        self.assertEqual((self.keyring.read_bytes(), self.keyring.stat().st_mtime_ns), before)

    def test_bad_metadata_signature_is_rejected(self):
        Path(self.args.signature).write_bytes(b'invalid signature')
        with self.assertRaisesRegex(Exception, 'GPG rejected detached signature'), self.authenticated():
            pass

    def test_bad_package_signature_with_resigned_release_and_envelope_is_rejected(self):
        (self.bundle / 'repo/fixture-1-1-any.pkg.tar.gz.sig').write_bytes(b'invalid signature')
        self.resign()
        with self.assertRaisesRegex(Exception, 'GPG rejected detached signature'), self.authenticated():
            pass

    def test_signed_semantically_wrong_database_is_rejected(self):
        path = self.bundle / 'repo/fixture.db.tar.gz'
        with tarfile.open(path, 'w:gz') as stream:
            item = tarfile.TarInfo('wrong/desc')
            data = b'%NAME%\nwrong\n\n'
            item.size = len(data)
            stream.addfile(item, io.BytesIO(data))
        self.sign(path)
        self.resign()
        with self.assertRaisesRegex(Exception, 'repository database package identity mismatch'), self.authenticated():
            pass

    def test_extra_public_primary_even_with_new_keyring_pin_is_rejected(self):
        self.keyring.write_bytes(self.public + self.other_public)
        self.settings['public_keyring_sha256'] = digest(self.keyring)
        with self.assertRaisesRegex(Exception, 'one exact public primary certificate'), self.authenticated():
            pass

    def test_undeclared_source_file_is_rejected(self):
        (self.bundle / 'unexpected').write_text('extra')
        with self.assertRaisesRegex(Exception, 'missing or undeclared members'), self.authenticated():
            pass

    def test_custom_payload_and_baseline_replacement_use_existing_release_semantics(self):
        base = json.loads((self.bundle / 'base.json').read_text())['packages']
        base.append(dict(name='demo', version='0-1', arch='any', depend=[], provides=[], conflict=[],
                         files=['usr/share/demo/config']))
        root = self.root / 'custom'
        bundle = make_bundle(root, self.signer, self.sign, base_packages=base,
                             payload={'usr/share/demo/config': b'new\n'}, name='demo', version='2-1')
        args, settings = make_envelope(root, bundle, self.signer, self.public, self.sign)
        workspace = root / 'workspace'
        workspace.mkdir(mode=0o700)
        with self.snapshot.authenticated(args, workspace, settings) as value:
            self.assertTrue(value['recheck']())
            self.assertEqual(value['release']['packages'][0]['version'], '2-1')
            self.assertEqual(value['spec']['policy']['protected_packages'], ['platform-fixture'])

    def test_original_input_identity_drift_is_rejected(self):
        with self.authenticated() as value:
            data = self.metadata.read_bytes()
            self.metadata.unlink()
            self.metadata.write_bytes(data)
            with self.assertRaisesRegex(Exception, 'identity drifted'):
                value['recheck']()

    def test_original_bundle_drift_is_rejected(self):
        with self.authenticated() as value:
            (self.bundle / 'repo/fixture-1-1-any.pkg.tar.gz').write_bytes(b'changed')
            with self.assertRaisesRegex(Exception, 'original bundle drifted'):
                value['recheck']()

    def test_snapshot_file_and_result_drift_are_rejected(self):
        with self.authenticated() as value:
            value['metadata']['sequence'] = 2
            with self.assertRaisesRegex(Exception, 'result changed'):
                value['recheck']()
            value['metadata']['sequence'] = 1
            path = value['bundle'] / 'spec.json'
            path.chmod(0o600)
            path.write_bytes(b'changed')
            with self.assertRaisesRegex(Exception, 'snapshot drifted'):
                value['recheck']()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository-root', type=Path, required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    args, remaining = parser.parse_known_args()
    ROOT = args.repository_root.resolve(strict=True)
    args.workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    original_temporary = tempfile.TemporaryDirectory

    def owned_temporary(*positional, **keywords):
        keywords['dir'] = str(args.workspace)
        return original_temporary(*positional, **keywords)

    with mock.patch.object(tempfile, 'TemporaryDirectory', owned_temporary):
        unittest.main(argv=[__file__, *remaining])
