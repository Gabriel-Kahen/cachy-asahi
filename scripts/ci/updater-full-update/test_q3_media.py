# SPDX-License-Identifier: MIT
"""Offline source controls for the Q3 signed-media sealer."""

import base64
import gzip
import io
import json
from pathlib import Path
import runpy
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
M = SimpleNamespace(**runpy.run_path(str(HERE / 'q3-media.py')))
MODULES = M.dependencies()
SIGNER = 'A' * 40
NOW = 1800000000
UUID = '12345678-1234-1234-1234-123456789abc'


def actor_fence(event, _args):
    if event.startswith(('subprocess.', 'socket.', 'os.exec', 'os.spawn', 'os.posix_spawn', 'os.fork')):
        raise AssertionError('actor forbidden in media source controls: ' + event)


def compressed(name, body, extra=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for leaf, data in [(name, body), *([extra] if extra else [])]:
            item = tarfile.TarInfo(leaf)
            item.mode, item.mtime, item.size = 0o644, 1, len(data)
            archive.addfile(item, io.BytesIO(data))
    return gzip.compress(stream.getvalue(), mtime=0)


def lock(rows):
    return ''.join(f'{name} {version}\n' for name, version in sorted(rows.items())).encode()


def repo_database(guest, data, **drift):
    new = guest['REPO'][2]
    fields = dict(NAME=guest['NAME'], VERSION=guest['NEW'], ARCH='any', FILENAME=new,
                  SHA256SUM=M.sha(data['repo/' + new]),
                  PGPSIG=base64.b64encode(data['repo/' + new + '.sig']).decode())
    fields.update(drift)
    body = ''.join(f'%{name}%\n{value}\n\n' for name, value in fields.items()).encode()
    return compressed(f"{guest['NAME']}-{guest['NEW']}/desc", body)


class MediaTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='updater-q3-media-controls-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.packet, self.signed = self.work / 'packet', self.work / 'signed'
        for path in (self.packet / 'unsigned-media/vendor', self.packet / 'unsigned-media/repo',
                     self.signed / 'repo'):
            path.mkdir(parents=True)
        self.modules = {name: value.copy() if isinstance(value, dict) else value for name, value in MODULES.items()}
        self.guest = self.modules['guest']
        updater = b'modeled exact updater archive'
        hooks = b'20-systemd-sysusers.hook\n'
        q3 = {f'baseline-{i}': '1-1' for i in range(354)} | {'sudo': '1.9.17.p2-6', 'xdg-utils': '1.2.1-2'}
        before = q3 | self.guest['SUPPLEMENTS']
        q3_lock, before_lock = lock(q3), lock(before)
        self.unsigned = {'q3.lock': q3_lock, 'before.lock': before_lock, 'hooks.list': hooks}
        self.guest.update(UPDATER=M.sha(updater), Q3_LOCK=M.sha(q3_lock))
        self.modules['setup']['BEFORE_SHA'] = M.sha(before_lock)
        self.modules['prep']['HOOKS'] = (len(hooks), M.sha(hooks))
        vendor = {'vendor/runtime.pkg.tar.xz': b'vendor archive',
                  'vendor/runtime.pkg.tar.xz.sig': b'vendor detached signature',
                  'vendor/archlinuxarm.gpg': b'vendor public key'}
        self.modules['runtime']['runtime_files'] = lambda: (
            (name.removeprefix('vendor/'), 'inert', (len(data), M.sha(data))) for name, data in vendor.items()
            if not name.endswith('.gpg'))
        key = vendor['vendor/archlinuxarm.gpg']
        self.modules['runtime']['KEYRING_PIN'] = (len(key), M.sha(key))
        self.unsigned.update(vendor)
        existing = runpy.run_path(str(M.REPO / 'scripts/ci/updater-optional-check/historical/real-check/real-check.py'))
        old, new = self.guest['OLD_ARCHIVE'], self.guest['REPO'][2]
        for name, version in ((old, self.guest['OLD']), ('repo/' + new, self.guest['NEW'])):
            path = self.packet / 'unsigned-media' / name
            existing['write_package'](path, version)
            self.unsigned[name] = path.read_bytes()
        fixture = runpy.run_path(str(M.REPO / 'packages/tools/cachy-asahi-update/test-asahi-policy.py'))['fixture']
        policy, post = fixture()
        protected, pre = fixture('platform', phase='pre-transaction')
        self.payload = {'TEST-public.gpg': b'TEST key bytes', 'updater.pkg': updater, 'updater.pkg.sig': b'updater signature',
                        old + '.sig': b'old signature', 'repo/fixture.db.sig': b'database signature',
                        'policy.json': M.json_bytes(policy), 'pre.json': M.json_bytes(dict(post, phase='pre-transaction')),
                        'post.json': M.json_bytes(post), 'protected-policy.json': M.json_bytes(protected),
                        'protected-pre.json': M.json_bytes(pre)}

    def selection(self, case='update', *, request_case=None, drift=None):
        for name, body in self.unsigned.items():
            (self.packet / 'unsigned-media' / name).write_bytes(body)
        new_sig = 'repo/' + self.guest['REPO'][2] + '.sig'
        self.payload[new_sig] = self.payload[self.guest['OLD_ARCHIVE'] + '.sig'] if case == 'signature-refusal' else b'new signature'
        self.payload['repo/fixture.db'] = repo_database(self.guest, self.unsigned | self.payload, **(drift or {}))
        for name, body in self.payload.items():
            (self.signed / name).write_bytes(body)
        prep = M.json_bytes(dict(kind=M.PREPARATION, authority=None, nonce='a' * 32, case=case,
                                 base_inventory=356, target_inventory=362,
                                 input_ext4=dict(bytes=M.DISK_BYTES, label=M.DISK_LABEL, uuid=UUID),
                                 unsigned_media={name: M.pin(data) for name, data in self.unsigned.items()}))
        (self.packet / 'PLAN.UNISSUED.json').write_bytes(prep)
        request = M.json_bytes(dict(kind=M.REQUEST, case=request_case or case, preparation_sha256=M.sha(prep),
                                    valid_from=NOW - 5, expires=NOW + 55, signer=SIGNER,
                                    files={name: M.pin(data) for name, data in self.payload.items()}))
        (self.signed / 'request.json').write_bytes(request)
        return SimpleNamespace(packet=self.packet, signed=self.signed, output=self.work / 'output',
                               preparation_sha256=M.sha(prep), signed_sha256=M.sha(request))

    def test_select_both_cases(self):
        for case in ('update', 'signature-refusal'):
            with self.subTest(case=case):
                args = self.selection(case)
                data, request, uuid = M.select(args, self.modules, NOW)
                plan = json.loads(data['plan.json'])
                self.assertEqual(plan['case'], request['case'])
                self.assertEqual(plan['kind'], M.GUEST)
                self.assertEqual(uuid, UUID)
                self.assertEqual(plan['files'].keys(), self.guest['FILES'])
                self.assertEqual(plan['files']['updater.pkg'], self.guest['UPDATER'])
                self.assertFalse(args.output.exists())

    def test_bad_bindings_and_unrelated_material_refuse(self):
        args = self.selection(request_case='signature-refusal')
        with self.assertRaisesRegex(ValueError, 'signed-media request'):
            M.select(args, self.modules, NOW)
        args = self.selection()
        with self.assertRaisesRegex(ValueError, 'signed-media request'):
            M.select(args, self.modules, NOW + 55)
        with self.assertRaisesRegex(ValueError, 'external document pin differs'):
            M.select(SimpleNamespace(**(vars(args) | {'signed_sha256': 'b' * 64})), self.modules, NOW)
        self.signed.joinpath('private.key').write_bytes(b'irrelevant')
        with self.assertRaisesRegex(ValueError, 'unrelated material'):
            M.select(args, self.modules, NOW)

    def test_pinned_member_and_repository_signature_drift_refuse(self):
        args = self.selection(drift={'PGPSIG': 'incorrect'})
        with self.assertRaisesRegex(ValueError, 'sole inert signed candidate'):
            M.select(args, self.modules, NOW)
        args = self.selection(drift={'DEPENDS': 'unselected'})
        with self.assertRaisesRegex(ValueError, 'sole inert signed candidate'):
            M.select(args, self.modules, NOW)
        args = self.selection()
        (self.signed / 'updater.pkg').write_bytes(b'changed archive')
        with self.assertRaisesRegex(ValueError, 'media member differs'):
            M.select(args, self.modules, NOW)

    def test_extra_repo_member_and_trailing_data_refuse(self):
        member = f"{self.guest['NAME']}-{self.guest['NEW']}/desc"
        body = b'%NAME%\nentry\n\n'
        with self.assertRaisesRegex(ValueError, 'unexpected repository database member'):
            M.descriptor(compressed(member, body, ('unexpected/desc', body)), member)
        original = gzip.decompress(compressed(member, body))
        with self.assertRaisesRegex(ValueError, 'trailing repository data'):
            M.descriptor(gzip.compress(original + b'X'), member)

    def test_intentional_badsig_is_distinct_from_wrong_or_missing_key(self):
        status = (f'[GNUPG:] NEWSIG\n[GNUPG:] BADSIG {SIGNER[-16:]} TEST fixture\n').encode()
        self.assertTrue(M.expected_bad_signature(SimpleNamespace(returncode=1, stdout=status), SIGNER))
        self.assertFalse(M.expected_bad_signature(SimpleNamespace(returncode=0, stdout=status), SIGNER))
        self.assertFalse(M.expected_bad_signature(SimpleNamespace(returncode=1, stdout=status), 'B' * 40))
        for event in (b'NO_PUBKEY', b'GOODSIG', b'VALIDSIG', b'EXPKEYSIG'):
            self.assertFalse(M.expected_bad_signature(
                SimpleNamespace(returncode=1, stdout=status + b'[GNUPG:] ' + event + b' placeholder\n'), SIGNER))

    def test_detached_verification_requires_the_expected_outcome_for_each_leaf(self):
        keys = (f'pub:u:255:22:{SIGNER[-16:]}:{NOW - 10}:{NOW + 60}::::scSC:\n'
                f'fpr:::::::::{SIGNER}:\nuid:u::::::::TEST fixture:\n').encode()
        good = (f'[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG {SIGNER[-16:]} TEST fixture\n'
                f'[GNUPG:] VALIDSIG {SIGNER} 2027-01-15 {NOW - 1} 0 4 0 22 8 00 {SIGNER}\n').encode()
        bad = (f'[GNUPG:] NEWSIG\n[GNUPG:] BADSIG {SIGNER[-16:]} TEST fixture\n').encode()

        def result(status=0, data=b''):
            return SimpleNamespace(returncode=status, stdout=data)

        for case in ('update', 'signature-refusal'):
            with self.subTest(case=case):
                request = dict(case=case, signer=SIGNER, valid_from=NOW - 5, expires=NOW + 55)
                final = result(1, bad) if case == 'signature-refusal' else result(data=good)
                response = [result(data=keys), result(), *[result(data=good)] * 3, final]
                with patch.dict(M.verify_signatures.__globals__, command=Mock(side_effect=response)):
                    M.verify_signatures(self.modules['client'], self.modules['setup'], self.guest,
                                        self.signed, self.work, request, NOW)
                if case == 'signature-refusal':
                    response[-1] = result(data=good)
                    with patch.dict(M.verify_signatures.__globals__, command=Mock(side_effect=response)), \
                            self.assertRaisesRegex(ValueError, 'intentional NEW signature mismatch'):
                        M.verify_signatures(self.modules['client'], self.modules['setup'], self.guest,
                                            self.signed, self.work, request, NOW)

    def test_sealed_output_receipt_and_refuses_existing_destination(self):
        args = self.selection('signature-refusal')

        def fake_pack(_params, _reader, _tools, _work, _tree, image, _uuid, expected):
            self.assertIn('plan.json', expected)
            image.write_bytes(b'inert ext4 representation')
            return M.pin(image.read_bytes())

        modules = self.modules | {'tools': lambda: None}
        with patch.dict(M.seal.__globals__, verify_signatures=lambda *_: None, pack=fake_pack), \
                patch.object(M.time, 'time', return_value=NOW):
            receipt = M.seal(args, modules)
            self.assertEqual(receipt['case'], 'signature-refusal')
            self.assertEqual(receipt['kind'], M.MEDIA)
            self.assertEqual(receipt['preparation_sha256'], args.preparation_sha256)
            self.assertEqual(receipt, json.loads((args.output / 'media.json').read_bytes()))
            self.assertEqual(M.pin((args.output / 'plan.json').read_bytes()), receipt['plan'])
            self.assertEqual((args.output / 'media.raw').read_bytes(), b'inert ext4 representation')
            with self.assertRaisesRegex(ValueError, 'fresh output'):
                M.seal(args, modules)


if __name__ == '__main__':
    sys.addaudithook(actor_fence)
    unittest.main()
