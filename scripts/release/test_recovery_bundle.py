#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Original tiny custody fixtures; authentication seams are explicitly mocked.

No signing identity is generated or used. These tests establish filesystem,
inventory and CLI behavior, not positive cryptographic integration.
"""
import argparse
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('recovery_bundle', Path(__file__).with_name('recovery_bundle.py'))
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)
C, P, K = B.C, B.P, B.K


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='recovery-bundle-original-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.kit = self.root / 'kit'
        self.output = self.root / 'out'
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.signer = 'A' * 40
        self.rows, image, available, base = [], [], [], []
        for number in range(P.OLD_COUNT):
            name = f'original-{number:02d}'
            metadata = dict(NAME=[name], VERSION=['1-1'], ARCH=['aarch64'], LICENSE=['MIT'])
            archive = self.inputs / f'{name}-1-1-aarch64.pkg.tar.xz'
            text = f'pkgname = {name}\npkgver = 1-1\narch = aarch64\nlicense = MIT\n'
            with tarfile.open(archive, 'w:xz') as tar:
                for path, raw in {'.PKGINFO': text.encode(), f'usr/share/{name}/data': b'original fixture\n'}.items():
                    member = tarfile.TarInfo(path)
                    member.size = len(raw)
                    tar.addfile(member, io.BytesIO(raw))
            signature = self.inputs / (archive.name + '.sig')
            signature.write_bytes(b'ORIGINAL UNSIGNED SYNTHETIC SIGNATURE PLACEHOLDER\n')
            index_url = f'https://{P.HOST}/aarch64/packages/o/{name}/'
            index = self.inputs / (name + '.html')
            index.write_text(f'<a href="{archive.name}">archive</a><a href="{signature.name}">sig</a>')
            inspection = self.inputs / (name + '.json')
            inspection.write_bytes(C.encoded(P.auth.coverage.authenticate.observe(archive, P.expected(metadata))))
            row = dict(name=name, version='1-1', arch='aarch64',
                status='PASS-signed-old-archive-data-matches-image-metadata',
                observed_image_metadata=metadata, index_url=index_url,
                actual_index_links=dict(archive=index_url+archive.name, signature=index_url+signature.name),
                signature_verification=dict(status='cryptographic-signature-valid',
                    primary_fingerprint=P.auth.KEYS['alarm'][0], independent_owner_trust_accepted=False),
                signature_observation=dict(exit=0, reason='exit', gpg_status=(
                    '[GNUPG:] VALIDSIG ' + P.auth.KEYS['alarm'][0] + ' 2026-10-27 1 0 4 0 1 8 00 '
                    + P.auth.KEYS['alarm'][0] + '\n')))
            for field, path in (('archive', archive), ('signature', signature),
                                ('operator_index', index), ('inspection', inspection)):
                row[field] = self.ref(path)
            row['archive']['url'] = row['actual_index_links']['archive']
            row['signature']['url'] = row['actual_index_links']['signature']
            self.rows.append(row)
            image.append(dict(metadata=metadata))
            available.append(dict(name=name, protected_version='1-1', arch='aarch64', current_catalog_exact_version=False))
            base.append(dict(name=name, version='1-1', arch='aarch64'))
        self.certificate = self.inputs / 'public.gpg'
        self.certificate.write_bytes(b'\xc6\x01x')  # tiny binary PUBLIC packet, not a usable key
        keys = {**P.auth.KEYS, 'alarm': (P.auth.KEYS['alarm'][0], self.ref(self.certificate)['sha256'])}
        patch = mock.patch.object(P.auth, 'KEYS', keys)
        patch.start(); self.addCleanup(patch.stop)
        image_path = self.inputs / 'image.json'
        image_path.write_bytes(C.encoded(dict(kind='observed-image-local-package-metadata', packages=image,
                                             hardware_accepted=False, dependency_transaction_accepted=False)))
        availability_path = self.inputs / 'available.json'
        availability_path.write_bytes(C.encoded(dict(kind='protected-exact-version-current-catalog-availability',
            inputs=dict(image_inventory=self.ref(image_path)), old_archive_url_or_hash_guessed=False,
            installation_accepted=False, hardware_accepted=False, packages=available)))
        contract = dict(schema_version=1, certificate=self.ref(self.certificate),
                        image_inventory=self.ref(image_path), old_availability=self.ref(availability_path))
        self.prior = dict(schema_version=1, kind='exact-superseded-recovery-archive-data',
            inputs=contract, status='PASS-all-exact-old-recovery-archive-data', failures=[],
            planned_count=P.OLD_COUNT, verified_count=P.OLD_COUNT, packages=self.rows,
            **{key: False for key in ('system_mutation', 'installation_accepted', 'hardware_accepted',
                                     'image_payload_correspondence_accepted', 'independent_owner_trust_accepted')})
        self.prior_path = self.inputs / 'receipt.json'
        self.save_prior()
        policy = dict(selected_packages=['fixture'], protected_packages=['original-00'],
                      supported_models=['m2-air-13'], coordinated_sets=[])
        base_raw = C.encoded(dict(target_arch='aarch64', kind='complete-target-transaction', packages=base))
        (self.kit / 'release').mkdir(parents=True)
        (self.kit / 'release/base.json').write_bytes(base_raw)
        self.package = dict(name='fixture', version='1-1', arch='any', filename='fixture-1-1-any.pkg.tar.gz', sha256='1'*64)
        self.release = dict(release_id='original-predecessor', files={'base.json': C.digest(base_raw)}, packages=[self.package])
        (self.kit / 'release/release.json').write_bytes(C.encoded(self.release))
        (self.kit / 'release/spec.json').write_bytes(C.encoded(dict(release_id='original-predecessor',
            policy=policy, base=dict(sha256=C.digest(base_raw)))))
        (self.kit / 'kit.json').write_bytes(C.encoded(dict(original=True)))
        (self.kit / 'release/alias').symlink_to('base.json')
        self.chosen = dict(schema_version=1, purpose='offline-recovery-selection', release_id='original-predecessor',
            kit_sha256=self.ref(self.kit/'kit.json')['sha256'],
            release_sha256=self.ref(self.kit/'release/release.json')['sha256'], base_sha256=C.digest(base_raw),
            policy_sha256=C.digest(C.encoded(policy)), packages=[self.package],
            protected_versions={'original-00': dict(version='1-1', arch='aarch64')}, recovery_receipt=self.ref(self.prior_path))
        self.selection_path = self.root / 'selection.json'
        self.save_selection()
        self.args = argparse.Namespace(selection=str(self.selection_path), selection_sha256=self.selection_pin,
            kit=str(self.kit), output=str(self.output), signer=self.signer, namespace='dev.original',
            minimum_sequence=1, state_dir=str(self.state))
        self.inspections = []
        patch = mock.patch.object(K, 'inspect', side_effect=self.authenticated_seam)
        patch.start(); self.addCleanup(patch.stop)

    def ref(self, path):
        raw = path.read_bytes()
        return dict(path=str(path), size=len(raw), sha256=hashlib.sha256(raw).hexdigest())

    def save_prior(self):
        self.prior_path.write_bytes(C.encoded(self.prior))

    def save_selection(self):
        self.selection_path.write_bytes(C.encoded(self.chosen))
        self.selection_pin = self.ref(self.selection_path)['sha256']
        if hasattr(self, 'args'):
            self.args.selection_sha256 = self.selection_pin

    def authenticated_seam(self, args):
        # Deliberate seam: all byte copying, parsing, metadata and receipt checks
        # outside offline-kit signature authentication are the real code.
        C.need((args.signer, args.namespace, args.minimum_sequence)
               == (self.signer, 'dev.original', 1), 'TEST external trust mismatch')
        self.inspections.append(str(args.kit))
        return dict(release_sha256=self.chosen['release_sha256'])

    def build(self):
        self.result = B.materialize(self.args)
        self.verify_args = argparse.Namespace(**{**vars(self.args), 'workspace': str(self.output),
                                                'receipt_sha256': self.result['receipt_sha256']})
        return self.result

    def refuse(self, action):
        before = K.inventory(self.state)
        with self.assertRaises((C.Error, OSError, ValueError, KeyError, TypeError)):
            action()
        self.assertEqual(K.inventory(self.state), before)

    def test_real_copy_metadata_and_relocation_after_sources_removed(self):
        result = self.build()
        self.assertEqual(len(result['recovery_packages']), P.OLD_COUNT)
        self.assertEqual((self.output/'recovery/metadata/original-00.PKGINFO').read_text(),
                         'pkgname = original-00\npkgver = 1-1\narch = aarch64\nlicense = MIT\n')
        self.assertTrue((self.output/'predecessor/release/alias').is_symlink())
        relocated = self.root/'relocated'
        self.output.rename(relocated)
        shutil.rmtree(self.inputs); shutil.rmtree(self.kit); self.selection_path.unlink()
        self.verify_args.workspace = str(relocated)
        checked = B.verify(self.verify_args)
        self.assertEqual(checked['status'], 'verified-offline-recovery-data')
        for key in B.LIMITS:
            self.assertIs(checked[key], False)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_cli_parsing_materialization_and_verification(self):
        common = ['--selection-sha256', self.selection_pin, '--signer', self.signer,
                  '--namespace', 'dev.original', '--minimum-sequence', '1', '--state-dir', str(self.state)]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(B.main(['materialize', *common, '--kit', str(self.kit),
                                    '--selection', str(self.selection_path), '--output', str(self.output)]), 0)
        result = json.loads(stdout.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(B.main(['verify', *common, '--workspace', str(self.output),
                                    '--receipt-sha256', result['receipt_sha256']]), 0)

    def test_missing_or_mismatched_external_trust_refuses_before_output(self):
        for field, value in (('signer', 'B'*40), ('namespace', 'elsewhere'), ('minimum_sequence', 2),
                             ('selection_sha256', '0'*64)):
            args = argparse.Namespace(**{**vars(self.args), field:value})
            self.refuse(lambda: B.materialize(args))
            self.assertFalse(self.output.exists())

    def test_selected_release_packages_policy_and_base_are_exact(self):
        for key, value in (('release_sha256', '0'*64), ('release_id', 'other'), ('base_sha256', '0'*64),
                           ('policy_sha256', '0'*64), ('packages', []), ('protected_versions', {})):
            saved = copy.deepcopy(self.chosen)
            self.chosen[key] = value; self.save_selection()
            # Keep mocked authentication result independent of manipulated selection.
            with mock.patch.object(K, 'inspect', return_value={'release_sha256': saved['release_sha256']}):
                self.refuse(lambda: B.materialize(self.args))
            self.assertFalse(self.output.exists())
            self.chosen = saved; self.save_selection()

    def test_incomplete_inventory_and_retained_signature_status_refuse(self):
        for mutate in (lambda: self.prior.update(status='FAIL-incomplete-recovery-archive-data'),
                       lambda: self.prior.update(verified_count=15),
                       lambda: self.prior['packages'][0]['signature_observation'].update(gpg_status='[GNUPG:] BADSIG X\n')):
            saved = copy.deepcopy(self.prior)
            mutate(); self.save_prior(); self.chosen['recovery_receipt']=self.ref(self.prior_path); self.save_selection()
            self.refuse(lambda: B.materialize(self.args))
            self.assertFalse(self.output.exists())
            self.prior = saved; self.save_prior()

    def test_wrong_recovery_baseline_refuses(self):
        base_path = self.kit/'release/base.json'
        base = C.decode(base_path.read_bytes()); base['packages'][1]['version']='2-1'
        base_path.write_bytes(C.encoded(base))
        pin = self.ref(base_path)['sha256']
        release_path = self.kit/'release/release.json'
        release = C.decode(release_path.read_bytes()); release['files']['base.json']=pin
        release_path.write_bytes(C.encoded(release))
        spec_path = self.kit/'release/spec.json'
        spec = C.decode(spec_path.read_bytes()); spec['base']['sha256']=pin; spec_path.write_bytes(C.encoded(spec))
        self.chosen.update(base_sha256=pin, release_sha256=self.ref(release_path)['sha256']); self.save_selection()
        self.refuse(lambda: B.materialize(self.args)); self.assertFalse(self.output.exists())

    def test_archive_or_extracted_metadata_tamper_and_extra_file_refuse(self):
        self.build()
        for name in ('recovery/packages/original-00/archive', 'recovery/metadata/original-00.PKGINFO', 'commands.json'):
            path=self.output/name; original=path.read_bytes(); path.chmod(0o600); path.write_bytes(b'changed')
            self.refuse(lambda:B.verify(self.verify_args)); path.write_bytes(original)
        extra=self.output/'foreign'; extra.write_bytes(b'foreign')
        self.refuse(lambda:B.verify(self.verify_args))

    def test_recomputed_transport_cannot_change_bound_archive_or_metadata(self):
        self.build()
        for name in ('recovery/packages/original-00/archive', 'recovery/metadata/original-00.PKGINFO'):
            path=self.output/name; original=path.read_bytes(); path.chmod(0o600); path.write_bytes(b'changed')
            receipt_path=self.output/B.RECEIPT; receipt=C.decode(receipt_path.read_bytes())
            original_receipt=receipt_path.read_bytes()
            receipt['files'][name]=C.digest(b'changed'); receipt_path.chmod(0o600); receipt_path.write_bytes(C.encoded(receipt))
            self.verify_args.receipt_sha256=C.digest(receipt_path.read_bytes())
            self.refuse(lambda:B.verify(self.verify_args))
            path.write_bytes(original); receipt_path.write_bytes(original_receipt)
            self.verify_args.receipt_sha256=C.digest(original_receipt)

    def test_foreign_symlink_hardlink_fifo_and_private_mode_refuse(self):
        self.build()
        archive=self.output/'recovery/packages/original-00/archive'
        alias=self.root/'hardlink'; os.link(archive,alias)
        self.refuse(lambda:B.verify(self.verify_args));alias.unlink()
        foreign=self.output/'foreign';os.mkfifo(foreign)
        self.refuse(lambda:B.verify(self.verify_args));foreign.unlink()
        foreign.symlink_to(self.inputs/'image.json');self.refuse(lambda:B.verify(self.verify_args));foreign.unlink()
        self.output.chmod(0o755);self.refuse(lambda:B.verify(self.verify_args));self.output.chmod(0o700)

    def test_existing_output_and_symlink_substitution_preserve_victim(self):
        self.output.mkdir(); (self.output/'keep').write_bytes(b'keep')
        self.refuse(lambda:B.materialize(self.args))
        self.assertEqual((self.output/'keep').read_bytes(), b'keep')
        shutil.rmtree(self.output)
        victim=self.root/'victim';victim.mkdir();(victim/'keep').write_bytes(b'keep')
        original=K.publish
        def race(staging,parent,output,inode):
            output.symlink_to(victim, target_is_directory=True)
            return original(staging,parent,output,inode)
        with mock.patch.object(K,'publish',side_effect=race):self.refuse(lambda:B.materialize(self.args))
        self.assertEqual((victim/'keep').read_bytes(),b'keep')

    def test_copy_failure_cleans_private_work_and_never_publishes(self):
        with mock.patch.object(B,'write',side_effect=OSError('original I/O refusal')):
            self.refuse(lambda:B.materialize(self.args))
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob('.recovery-bundle-*')))

    def test_output_never_enters_external_receiver_state(self):
        for output in (self.state/'checkpoint.json', self.state/'other-child'):
            args=argparse.Namespace(**{**vars(self.args),'output':str(output)})
            self.refuse(lambda:B.materialize(args))
            self.assertFalse(output.exists());self.assertEqual(list(self.state.iterdir()),[])

    def test_missing_signature_certificate_tamper_and_reference_size_refuse(self):
        path = Path(self.rows[0]['signature']['path'])
        original = path.read_bytes(); path.unlink()
        self.refuse(lambda:B.materialize(self.args));path.write_bytes(original)
        original = self.certificate.read_bytes();self.certificate.write_bytes(b'changed')
        self.refuse(lambda:B.materialize(self.args));self.certificate.write_bytes(original)
        self.chosen['recovery_receipt']['size'] += 1;self.save_selection()
        self.refuse(lambda:B.materialize(self.args));self.assertFalse(self.output.exists())

    def test_aggregate_quota_and_path_escape_refuse_without_publication(self):
        for key, value in (('name','../escape'), ('archive', {**self.prior['packages'][0]['archive'],
                                                          'size': P.CACHE_LIMIT+1})):
            saved=copy.deepcopy(self.prior)
            self.prior['packages'][0][key]=value;self.save_prior()
            self.chosen['recovery_receipt']=self.ref(self.prior_path);self.save_selection()
            self.refuse(lambda:B.materialize(self.args));self.assertFalse(self.output.exists())
            self.prior=saved;self.save_prior()

    def test_cli_reports_refusal_and_command_template_has_no_apply(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(B.main(['materialize','--kit',str(self.kit),'--selection',str(self.selection_path),
                '--output',str(self.output),'--selection-sha256','0'*64,'--signer',self.signer,
                '--namespace','dev.original','--minimum-sequence','1','--state-dir',str(self.state)]),1)
        command=B.commands(self.chosen)
        self.assertIn('plan',command['argv']);self.assertNotIn('--apply',command['argv'])
        self.assertFalse(command['executed']);self.assertFalse(command['development_kit_is_stable_source'])

    def test_fractional_retained_http_observation_survives_materialize_and_relocation(self):
        self.prior['packages'][0]['http_attempts']=[{'pace_wait_seconds':0.125}]
        self.save_prior();self.chosen['recovery_receipt']=self.ref(self.prior_path);self.save_selection()
        self.build()
        relocated=self.root/'fractional-relocated';self.output.rename(relocated)
        self.verify_args.workspace=str(relocated)
        result=B.verify(self.verify_args)
        self.assertEqual(result['status'],'verified-offline-recovery-data')
        retained=B.recovery_json((relocated/'recovery/receipt.json').read_bytes())
        self.assertEqual(retained['packages'][0]['http_attempts'][0]['pace_wait_seconds'],0.125)

    def test_recovery_parser_rejects_duplicates_nonfinite_and_nonobjects(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}',b'{"x":1e999}',b'[]'):
            self.refuse(lambda:B.recovery_json(raw))

    def test_selection_and_client_authority_json_remain_integer_only(self):
        self.chosen['schema_version']=1.0;self.save_selection()
        self.refuse(lambda:B.selection(self.selection_path.read_bytes()))
        self.refuse(lambda:C.decode(b'{"sequence":1.5}'))

    def test_fractional_recovery_schema_counts_and_sizes_still_refuse(self):
        for change in (lambda:self.prior.update(schema_version=1.0),
                       lambda:self.prior.update(verified_count=float(P.OLD_COUNT)),
                       lambda:self.prior['packages'][0]['archive'].update(
                           size=float(self.prior['packages'][0]['archive']['size']))):
            original=copy.deepcopy(self.prior)
            change();self.save_prior();self.chosen['recovery_receipt']=self.ref(self.prior_path);self.save_selection()
            self.refuse(lambda:B.materialize(self.args));self.assertFalse(self.output.exists())
            self.prior=original;self.save_prior()

    def test_exact_pinned_armored_recovery_certificate_is_not_a_binary_kit_keyring(self):
        self.certificate.write_bytes(b'-----BEGIN PGP PUBLIC KEY BLOCK-----\noriginal TEST observation\n')
        certificate=self.ref(self.certificate)
        self.prior['inputs']['certificate']=certificate
        keys={**P.auth.KEYS,'alarm':(P.auth.KEYS['alarm'][0],certificate['sha256'])}
        self.save_prior();self.chosen['recovery_receipt']=self.ref(self.prior_path);self.save_selection()
        with mock.patch.object(P.auth,'KEYS',keys):
            self.build();self.assertEqual(B.verify(self.verify_args)['status'],'verified-offline-recovery-data')

    def test_recovery_timing_refuses_bool_strings_negative_and_malformed_rows(self):
        for value in (True,False,'0.125',-0.1,None):
            raw=C.encoded(dict(kind='exact-superseded-recovery-archive-data',
                packages=[dict(http_attempts=[dict(pace_wait_seconds=value)])]))
            self.refuse(lambda:B.recovery_json(raw))
        for attempts in ({},[True]):
            raw=C.encoded(dict(kind='exact-superseded-recovery-archive-data',packages=[dict(http_attempts=attempts)]))
            self.refuse(lambda:B.recovery_json(raw))

    def test_bool_recovery_authority_fields_and_wrong_fingerprint_refuse(self):
        for mutate in (lambda:self.prior.update(schema_version=True),
                       lambda:self.prior.update(verified_count=True),
                       lambda:self.prior['packages'][0]['archive'].update(size=True),
                       lambda:self.prior['packages'][0]['signature_verification'].update(primary_fingerprint='F'*40)):
            saved=copy.deepcopy(self.prior)
            mutate();self.save_prior();self.chosen['recovery_receipt']=self.ref(self.prior_path);self.save_selection()
            self.refuse(lambda:B.materialize(self.args));self.assertFalse(self.output.exists())
            self.prior=saved;self.save_prior()

    def test_retained_signature_exit_does_not_accept_bool_or_fractional_zero(self):
        for value in (False,True,0.0):
            original=copy.deepcopy(self.prior)
            self.prior['packages'][0]['signature_observation']['exit']=value
            self.save_prior();self.chosen['recovery_receipt']=self.ref(self.prior_path);self.save_selection()
            self.refuse(lambda:B.materialize(self.args));self.assertFalse(self.output.exists())
            self.prior=original;self.save_prior()


if __name__ == '__main__':
    unittest.main(verbosity=2)
