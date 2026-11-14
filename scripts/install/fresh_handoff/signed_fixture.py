# SPDX-License-Identifier: MIT
"""TEST-only real signed handoff assets. Never imported by product/runtime code.

Only the fixed ALARM public anchor is substituted by the test caller. No
signature, release, package, recovery or inspection verifier is mocked.
"""
import argparse
from datetime import datetime, timedelta, timezone
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


T = load('fresh_signed_release_fixtures', ROOT / 'scripts/release/test_release.py')


class SignedFixture:
    def __init__(self, owner, H):
        self.H, self.C, self.P = H, H.C, H.R.P
        self.temp = tempfile.TemporaryDirectory(prefix='fresh-TEST-signed-handoff-')
        owner.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.key = T.ReleaseTests.key
        self.home = T.ReleaseTests.home
        self.env = T.r.gpg_env(self.home, self.root)
        self.public = self.inputs / 'TEST-public.gpg'
        self.public.write_bytes(T.r.run(['gpg', '--batch', '--export', self.key], env=self.env))
        self.anchor = (self.key, self.ref(self.public)['sha256'])
        self.rows, image, availability, base = [], [], [], []
        for number in range(self.P.OLD_COUNT):
            name = f'test-old-{number:02d}'
            metadata = dict(NAME=[name], VERSION=['1-1'], ARCH=['aarch64'], LICENSE=['MIT'])
            archive = self.inputs / f'{name}-1-1-aarch64.pkg.tar.xz'
            text = f'pkgname = {name}\npkgver = 1-1\narch = aarch64\nlicense = MIT\n'
            with tarfile.open(archive, 'w:xz') as tar:
                for path, raw in {'.PKGINFO': text.encode(), f'usr/share/{name}/TEST-data': b'TEST recovery payload\n'}.items():
                    entry = tarfile.TarInfo(path)
                    entry.size = len(raw)
                    tar.addfile(entry, io.BytesIO(raw))
            T.r.sign(archive, self.key, self.env)
            signature = Path(str(archive) + '.sig')
            verification, observation = self.P.auth.verify(self.root, self.public, archive, signature, self.key)
            inspection = self.inputs / (name + '.inspection.json')
            inspection.write_bytes(self.C.encoded(self.P.auth.coverage.authenticate.observe(archive, self.P.expected(metadata))))
            index = self.inputs / (name + '.index.html')
            index.write_text(f'<a href="{archive.name}">TEST archive</a><a href="{signature.name}">TEST signature</a>')
            url = f'https://{self.P.HOST}/aarch64/packages/{name[0]}/{name}/'
            row = dict(name=name, version='1-1', arch='aarch64', status='PASS-signed-old-archive-data-matches-image-metadata',
                       observed_image_metadata=metadata, index_url=url,
                       actual_index_links=dict(archive=url+archive.name, signature=url+signature.name),
                       signature_verification=verification, signature_observation=observation)
            for field, path in (('archive', archive), ('signature', signature), ('operator_index', index), ('inspection', inspection)):
                row[field] = self.ref(path)
            row['archive']['url'], row['signature']['url'] = url+archive.name, url+signature.name
            self.rows.append(row)
            image.append(dict(metadata=metadata))
            availability.append(dict(name=name, protected_version='1-1', arch='aarch64', current_catalog_exact_version=False))
            base.append(dict(name=name, version='1-1', arch='aarch64', depend=[], provides=[], conflict=[], files=[]))
        self.base = base
        image_path = self.inputs / 'TEST-image.json'
        image_path.write_bytes(self.C.encoded(dict(kind='observed-image-local-package-metadata', packages=image,
                                                  hardware_accepted=False, dependency_transaction_accepted=False)))
        availability_path = self.inputs / 'TEST-availability.json'
        availability_path.write_bytes(self.C.encoded(dict(kind='protected-exact-version-current-catalog-availability',
            inputs=dict(image_inventory=self.ref(image_path)), old_archive_url_or_hash_guessed=False,
            installation_accepted=False, hardware_accepted=False, packages=availability)))
        prior = dict(schema_version=1, kind='exact-superseded-recovery-archive-data',
            inputs=dict(schema_version=1, certificate=self.ref(self.public), image_inventory=self.ref(image_path),
                        old_availability=self.ref(availability_path)),
            status='PASS-all-exact-old-recovery-archive-data', failures=[],
            planned_count=self.P.OLD_COUNT, verified_count=self.P.OLD_COUNT, packages=self.rows,
            **{key: False for key in ('system_mutation', 'installation_accepted', 'hardware_accepted',
                                     'image_payload_correspondence_accepted', 'independent_owner_trust_accepted')})
        self.prior_path = self.inputs / 'TEST-recovery-observations.json'
        self.prior_path.write_bytes(self.C.encoded(prior))
        self.predecessor, predecessor = self.kit(owner, 'predecessor', self.key)
        self.candidate, candidate = self.kit(owner, 'candidate', self.key)
        release = self.C.decode((self.predecessor/'release/release.json').read_bytes())
        spec = self.C.decode((self.predecessor/'release/spec.json').read_bytes())
        keys = ('name', 'version', 'arch', 'filename', 'sha256')
        recovery_selection = dict(schema_version=1, purpose='offline-recovery-selection', release_id=release['release_id'],
            kit_sha256=predecessor['kit_sha256'], release_sha256=predecessor['release_sha256'],
            base_sha256=spec['base']['sha256'], policy_sha256=self.C.digest(self.C.encoded(spec['policy'])),
            packages=sorted(({key: row[key] for key in keys} for row in release['packages']), key=lambda row: row['name']),
            protected_versions={self.base[0]['name']: dict(version='1-1', arch='aarch64')},
            recovery_receipt=self.ref(self.prior_path))
        selected = self.inputs / 'TEST-recovery-selection.json'
        selected.write_bytes(self.C.encoded(recovery_selection))
        self.recovery_args = argparse.Namespace(selection=str(selected), selection_sha256=self.ref(selected)['sha256'],
            kit=str(self.predecessor), output=str(self.root/'recovery'), signer=self.key,
            namespace='dev.test-predecessor', minimum_sequence=1, state_dir=str(self.state))
        # Caller installs the explicit TEST anchor before materialize/reverify.
        self.chosen = dict(schema_version=1, purpose='development-fresh-install-handoff',
            source_commit=subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
            candidate=dict(kit_sha256=candidate['kit_sha256'], release_sha256=candidate['release_sha256'],
                           signer=self.key, namespace='dev.test-candidate', minimum_sequence=1),
            recovery=dict(selection_sha256=self.recovery_args.selection_sha256,
                          release_sha256=predecessor['release_sha256'], signer=self.key,
                          namespace='dev.test-predecessor', minimum_sequence=1))

    def ref(self, path):
        raw = path.read_bytes()
        return dict(path=str(path), size=len(raw), sha256=self.C.digest(raw))

    def kit(self, owner, role, signer):
        case = T.ReleaseTests(methodName='runTest')
        case.setUp()
        owner.addCleanup(case.doCleanups)
        base = T.r.load(case.inputs / 'base.json')
        base['packages'] = [*self.base, *[row for row in base['packages'] if row['name'] == 'runtime']]
        case.put('base.json', base)
        case.release_spec['base'].update(case.ref('base.json'))
        case.release_spec['release_id'] = 'TEST-' + role
        case.release_spec['policy']['protected_packages'] = [self.base[0]['name']]
        case.put('integration.lock.json', dict(schema_version=1, fixture='genuine-signature TEST input; not hardware evidence'))
        case.release_spec['evidence'] = [dict(case.ref('integration.lock.json'), id='integration.lock.json')]
        case.save_spec()
        bundle = Path(T.r.stage(argparse.Namespace(spec=str(case.spec_path)), case.root, signer, case.env)['path'])
        metadata = case.base / 'development.json'
        now = datetime.now(timezone.utc)
        self.C.build(argparse.Namespace(bundle=str(bundle), output=str(metadata), namespace='dev.test-'+role,
            sequence=1, issued_utc=self.C.utc(now-timedelta(minutes=1)), expires_utc=self.C.utc(now+timedelta(hours=1)), signer=signer))
        T.r.sign(metadata, signer, case.env)
        public = case.base / 'public.gpg'
        public.write_bytes(T.r.run(['gpg', '--batch', '--export', signer], env=case.env))
        output = self.root / (role + '-kit')
        result = self.H.K.assemble(argparse.Namespace(bundle=str(bundle), metadata=str(metadata),
            signature=str(metadata)+'.sig', public_keyring=str(public), signer=signer,
            namespace='dev.test-'+role, minimum_sequence=1, state_dir=str(self.state),
            lock_evidence='integration.lock.json', output=str(output)))
        return output, result

    def materialize(self):
        result = self.H.R.materialize(self.recovery_args)
        self.recovery = Path(self.recovery_args.output)
        self.chosen['recovery']['receipt_sha256'] = result['receipt_sha256']
        return result
