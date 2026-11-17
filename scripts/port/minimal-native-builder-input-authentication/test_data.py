# SPDX-License-Identifier: MIT
"""Source/public-fixture and explicit MODEL refusal controls; never launch GPG."""
import base64
import collections
import copy
import datetime
import importlib.util
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('minimal206_public_verifier', HERE / 'verify.py')
A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
D = json.loads((A.SOURCE / 'builder.lock.json').read_bytes())
FIXTURES = A.ROOT / 'scripts/ci/core-native-lifecycle-source/payload/keyring'
# The maintained parser is loaded from whole-pinned bytes, never invoked as an actor.
sys.addaudithook(A.ActorFence())
sys.modules['package_checks'] = A.module(A.ROOT / 'scripts/checks/package_checks.py', A.ENGINES['scripts/checks/package_checks.py'], 'package_checks')
N = A.module(A.ROOT / 'scripts/ci/native_arm.py', A.ENGINES['scripts/ci/native_arm.py'], 'MODEL_maintained_signature_parser')
NOW = 1794950000


def model_key():
    return '\n'.join([
        'pub:-:4096:1:' + A.SIGNER[-16:] + ':1390085363:::q:::scESC:',
        'fpr:::::::::' + A.SIGNER + ':',
        'uid:-::::1390085363::MODEL::' + A.UID + ':',
        'sub:-:4096:1:' + A.SUBKEY[-16:] + ':1390085363::::::e:',
        'fpr:::::::::' + A.SUBKEY + ':',
    ]) + '\n'


def model_status(algorithm='10'):
    timestamp = NOW - 10
    date = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime('%Y-%m-%d')
    return '\n'.join([
        '[GNUPG:] NEWSIG',
        '[GNUPG:] KEY_CONSIDERED ' + A.SIGNER + ' 0',
        '[GNUPG:] SIG_ID ' + 'A' * 27 + '= ' + date + ' ' + str(timestamp),
        '[GNUPG:] GOODSIG ' + A.SIGNER[-16:] + ' ' + A.UID,
        '[GNUPG:] VALIDSIG ' + A.SIGNER + ' ' + date + ' ' + str(timestamp) + ' 0 4 0 1 ' + algorithm + ' 00 ' + A.SIGNER,
    ]) + '\n'


def model_retirement():
    return dict(passed=True, reaped=True, ownership='REAPED', exit=0, timeout=False,
                signals=[], error=None, output_complete=True, group_census='EMPTY_TWICE', seconds=.1)


class Controls(unittest.TestCase):
    def test_unissued_default_does_not_read_select_or_launch(self):
        with patch.object(A, 'read_pinned', side_effect=AssertionError('no input reads')), \
             patch.object(A, 'validate_selection', side_effect=AssertionError('no selection')), \
             patch.object(A.subprocess, 'Popen', side_effect=AssertionError('no actor')):
            report, code = A.verify(None, None)
        self.assertEqual(code, 2)
        self.assertEqual(report['actors'], [])
        self.assertEqual(report['status'], 'HOLD_ROOT_VERIFICATION_SELECTION_UNISSUED')

    def test_unissued_template_refuses_even_with_execution_flag(self):
        path = HERE / 'SELECTION.TEMPLATE.json'
        with patch.object(A.subprocess, 'Popen', side_effect=AssertionError('no actor')):
            self.assertRaisesRegex(ValueError, 'UNISSUED', A.verify, path, A.pin(path.read_bytes()), execute=True)

    def test_external_selection_requires_whole_pin_and_strict_json(self):
        with tempfile.TemporaryDirectory(prefix='MODEL-selection-') as name:
            path = Path(name) / 'MODEL.json'; path.write_bytes(b'{"issuer":"MODEL"}')
            self.assertRaises(ValueError, A.verify, path, dict(bytes=path.stat().st_size, sha256='0' * 64), execute=True)
        for raw in (b'{"accepted":true,"accepted":false}', b'{"time":NaN}', b'{"time":Infinity}'):
            self.assertRaises(ValueError, A.decode, raw)

    def test_MODEL_selection_fresh_review_exact_bindings_and_output_refusals(self):
        # In-memory schema MODEL only: never serialized as a selection, never
        # passed to verify(execute=True), never opens tools or package operands.
        with tempfile.TemporaryDirectory(prefix='MODEL-selection-shape-') as name:
            root = Path(name); cache = root / 'empty-MODEL-cache'; cache.mkdir(mode=0o700)
            evidence = root / 'MODEL-public-evidence'; evidence.write_bytes(b'MODEL only; no actual Root trust review')
            entry = HERE / 'verify.py'
            model = dict(schema=1, issuer='Root', status='ROOT_SELECTED_MINIMAL206_PUBLIC_INPUT_VERIFICATION_ONLY', accepted=True,
                         entry=dict(path=str(entry), **A.pin(entry.read_bytes())),
                         builder_lock=dict(path=str(A.SOURCE / 'builder.lock.json'), **A.BUILDER),
                         cache=str(cache), output=str(root / 'absent-output'),
                         tools={n: dict(path='/MODEL/' + n, bytes=1, sha256='0' * 64) for n in ('gpg', 'gpgv')},
                         trust_review=dict(current_official_trust_reviewed=True, reviewed_at_unix=NOW - 1, valid_until_unix=NOW + 60,
                                           evidence=dict(path=str(evidence), **A.pin(evidence.read_bytes()))))
            self.assertEqual(A.validate_selection(model, NOW), (cache, root / 'absent-output'))
            for key, value in (('issuer', 'MODEL'), ('accepted', False), ('schema', True), ('status', 'UNISSUED'),
                               ('output', str(cache / 'nested')), ('output', str(root)), ('MODEL-extra', 1)):
                bad = copy.deepcopy(model); bad[key] = value
                self.assertRaises(ValueError, A.validate_selection, bad, NOW)
            for key, value in (('current_official_trust_reviewed', False), ('reviewed_at_unix', NOW + 1),
                               ('valid_until_unix', NOW), ('valid_until_unix', NOW + 86401), ('reviewed_at_unix', float(NOW))):
                bad = copy.deepcopy(model); bad['trust_review'][key] = value
                self.assertRaises(ValueError, A.validate_selection, bad, NOW)
            bad = copy.deepcopy(model); bad['entry']['sha256'] = '0' * 64
            self.assertRaises(ValueError, A.validate_selection, bad, NOW)
            bad = copy.deepcopy(model); bad['trust_review']['evidence']['sha256'] = '0' * 64
            self.assertRaises(ValueError, A.validate_selection, bad, NOW)
            bad = copy.deepcopy(model); bad['builder_lock']['bytes'] += 1
            self.assertRaises(ValueError, A.validate_selection, bad, NOW)
            cache.chmod(0o755)
            self.assertRaises(ValueError, A.validate_selection, model, NOW)
            self.assertFalse((root / 'absent-output').exists())

    def test_fixed_source_and_complete422_contract(self):
        self.assertEqual(A.pin((A.SOURCE / 'builder.lock.json').read_bytes()), A.BUILDER)
        self.assertEqual(A.pin((A.SOURCE / 'source.lock.json').read_bytes()), A.SOURCE_LOCK)
        for path, row in A.ENGINES.items():
            self.assertEqual(A.pin((A.ROOT / path).read_bytes()), row)
        rows, signed = A.inputs(D)
        self.assertEqual((len(rows), len(signed), sum(r['bytes'] for r in rows.values())), (422, 207, A.TOTAL_BYTES))
        self.assertEqual(set(signed), {r['archive']['filename'] for r in D['packages']} | {D['rootfs']['filename']})
        self.assertIsNone(D['signature_authentication'])
        self.assertIsNone(D['native'])

    def test_incomplete_duplicate_graph_or_signature_contract_refuses(self):
        for field, value in (('metadata_graph_status', 'FAIL'), ('graph_blockers', ['MODEL']),
                             ('rootfs_reconciliation', dict(missing=['MODEL'])), ('packages', D['packages'][:-1])):
            bad = copy.deepcopy(D); bad[field] = value
            self.assertRaises(ValueError, A.inputs, bad)
        bad = copy.deepcopy(D); bad['packages'][1]['archive'] = bad['packages'][0]['archive']
        self.assertRaises(ValueError, A.inputs, bad)
        bad = copy.deepcopy(D); bad['packages'][0]['archive']['signature_b64'] = base64.b64encode(b'MODEL').decode()
        self.assertRaises(ValueError, A.inputs, bad)

    def test_original206_signature_algorithm_census(self):
        counts = collections.Counter()
        for row in D['packages']:
            raw = base64.b64decode(row['archive']['signature_b64'], validate=True)
            self.assertEqual(A.pin(raw), dict(bytes=row['archive']['signature_bytes'], sha256=row['archive']['signature_sha256']))
            counts[A.signature_algorithms(raw)] += 1
        self.assertEqual(counts, {('1', '8'): 40, ('1', '10'): 166})

    def test_signature_packet_unknown_weak_partial_extra_or_wrong_type_refuses(self):
        body = bytes([4, 0, 1, 10, 0, 0, 0, 0])
        old = bytes([0x88, len(body)]) + body
        new = bytes([0xC2, len(body)]) + body
        self.assertEqual(A.signature_algorithms(old), ('1', '10'))
        self.assertEqual(A.signature_algorithms(new), ('1', '10'))
        for bad in (b'', old[:-1], old + old, bytes([0xC2, 224]) + body,
                    old.replace(bytes([4, 0, 1, 10]), bytes([4, 0, 1, 2])),
                    old.replace(bytes([4, 0, 1, 10]), bytes([4, 1, 1, 10])),
                    old.replace(bytes([4, 0, 1, 10]), bytes([4, 0, 22, 10]))):
            self.assertRaises(ValueError, A.signature_algorithms, bad)

    def test_exact_official_public_armor_decode_no_gpg(self):
        files = {p.name: p.read_bytes() for p in FIXTURES.iterdir()}
        expected = {r['filename']: dict(bytes=r['size'], sha256=r['sha256']) for r in D['keyring_files']}
        self.assertEqual({n: A.pin(raw) for n, raw in files.items()}, expected)
        binary = A.public_key(files['archlinuxarm.gpg'], files['archlinuxarm-trusted'], files['archlinuxarm-revoked'])
        self.assertEqual(A.pin(binary), A.BINARY_KEY)

    def test_armor_crc_body_trust_and_revocation_substitution_refuses(self):
        armor = (FIXTURES / 'archlinuxarm.gpg').read_bytes(); trusted = (A.SIGNER + ':4:\n').encode()
        for raw, trust, revoked in ((armor.replace(b'=AIgD', b'=AAAA'), trusted, b''),
                                    (armor.replace(b'PUBLIC KEY', b'SECRET KEY'), trusted, b''),
                                    (armor, b'0' * 40 + b':4:\n', b''), (armor, trusted, b'MODEL\n'),
                                    (armor[:-1], trusted, b'')):
            self.assertRaises(ValueError, A.public_key, raw, trust, revoked)

    def test_held_input_pin_stable_identity_and_exact_mode(self):
        with tempfile.TemporaryDirectory(prefix='MODEL-held-') as name:
            path = Path(name) / 'operand'; path.write_bytes(b'MODEL'); path.chmod(0o600)
            expected = dict(A.pin(b'MODEL'), mode=0o600)
            leaf = A.Held(path, expected)
            try:
                self.assertEqual(leaf.raw(), b'MODEL')
                leaf.digest()
                path.write_bytes(b'OTHER')
                self.assertRaises(ValueError, leaf.stable)
            finally:
                leaf.close()
            self.assertRaises(ValueError, A.Held, path, dict(A.pin(b'OTHER'), mode=0o644))
            self.assertRaises(ValueError, A.Held, path, A.pin(b'MODEL'))

    def test_symlink_hardlink_and_replaced_leaf_refuse(self):
        with tempfile.TemporaryDirectory(prefix='MODEL-alias-') as name:
            root = Path(name); path = root / 'operand'; path.write_bytes(b'MODEL')
            alias = root / 'alias'; alias.symlink_to(path)
            self.assertRaises(ValueError, A.Held, alias, A.pin(b'MODEL'))
            alias.unlink(); os.link(path, alias)
            self.assertRaises(ValueError, A.Held, path, A.pin(b'MODEL'))
            alias.unlink(); leaf = A.Held(path, A.pin(b'MODEL'))
            try:
                path.rename(alias); path.write_bytes(b'MODEL')
                self.assertRaises(ValueError, leaf.stable)
            finally:
                leaf.close()

    def test_namespace_missing_extra_partial_and_entry_cap_refuse(self):
        with tempfile.TemporaryDirectory(prefix='MODEL-namespace-') as name:
            root = Path(name); path = root / 'MODEL'; path.write_bytes(b'')
            A.namespace(root, {'MODEL': {}})
            self.assertRaises(ValueError, A.namespace, root, {'MISSING': {}})
            (root / 'MODEL.partial').write_bytes(b'')
            self.assertRaises(ValueError, A.namespace, root, {'MODEL': {}})
            (root / 'MODEL.partial').unlink()
            for index in range(422):
                (root / str(index)).write_bytes(b'')
            self.assertRaises(ValueError, A.namespace, root, {p.name: {} for p in root.iterdir()})

    def test_MODEL_public_key_status_and_unusable_identity_refusals(self):
        good = model_key(); A.key_status(good, NOW)
        for bad in (good.replace('pub:-:', 'pub:r:'), good.replace('sub:-:', 'sub:e:'),
                    good.replace('uid:-:', 'uid:i:'), good.replace('pub:-:', 'sec:-:'),
                    good.replace(A.SIGNER, '0' * 40), good.replace(A.SUBKEY, '0' * 40),
                    good.replace(':4096:', ':2048:', 1), good.replace(':1390085363:', ':' + str(NOW + 1) + ':'),
                    good.replace(':1390085363::', ':1390085363:' + str(NOW - 1) + ':'),
                    good.replace(':scESC:', ':scESCD:'), good + good):
            self.assertRaises(ValueError, A.key_status, bad, NOW)

    def test_MODEL_signature_status_binds_both_original_algorithms(self):
        for algorithm in ('8', '10'):
            A.signature_status(model_status(algorithm), NOW, N, ('1', algorithm))

    def test_MODEL_bad_unknown_expired_missing_multiple_or_incoherent_status_refuses(self):
        good = model_status()
        for bad in (good + '[GNUPG:] ' + label + ' MODEL\n' for label in
                    ('BADSIG', 'ERRSIG', 'NO_PUBKEY', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'KEYEXPIRED', 'KEYREVOKED', 'SIGEXPIRED', 'FAILURE', 'ERROR', 'NODATA', 'BADARMOR', 'MODEL_UNKNOWN')):
            self.assertRaises(ValueError, A.signature_status, bad, NOW, N, ('1', '10'))
        for bad in (good + good, good.replace(A.SIGNER, '0' * 40), good.replace(' 0 4 0 1 10 00', ' ' + str(NOW - 1) + ' 4 0 1 10 00'),
                    good.replace(' 0 4 0 1 10 00', ' 0 4 0 1 8 00'), good.replace('[GNUPG:] NEWSIG\n', ''),
                    good + 'unframed diagnostic\n', good.replace('[GNUPG:] NEWSIG', '[GNUPG:] NEWSIG MODEL'),
                    good.replace(' 0\n', ' 2\n'), good.replace('SIG_ID ' + 'A' * 27 + '=', 'SIG_ID ?')):
            self.assertRaises(ValueError, A.signature_status, bad, NOW, N, ('1', '10'))

    def test_MODEL_every_retirement_field_is_required(self):
        row = model_retirement(); A.natural(row)
        for key, value in (('passed', False), ('reaped', False), ('ownership', 'UNKNOWN'), ('exit', True), ('exit', 1),
                           ('timeout', True), ('signals', ['SIGTERM']), ('error', 'MODEL'), ('output_complete', False),
                           ('group_census', 'EMPTY_ONCE'), ('group_census', 'UNKNOWN'), ('seconds', float('nan')),
                           ('seconds', A.ACTOR_CAP)):
            bad = dict(row); bad[key] = value
            self.assertRaises(ValueError, A.natural, bad)

    def test_fence_denies_unknown_actors_network_ffi_and_reuse(self):
        fence = A.ActorFence()
        for event in ('subprocess.Popen', 'socket.__new__', 'socket.connect', 'ctypes.dlopen', 'os.system', 'os.exec', 'os.posix_spawn'):
            self.assertRaises(ValueError, fence, event, ('MODEL',))
        command = ('/MODEL/selected', ['/MODEL/selected'], '/MODEL/public', {'HOME': '/MODEL/public'})
        fence.command = command; fence('subprocess.Popen', command)
        self.assertIsNone(fence.command)
        self.assertRaises(ValueError, fence, 'subprocess.Popen', command)

    def test_original_adoption_contract_is_build_input_only_and_unissued(self):
        template = json.loads((A.SOURCE / 'Root-authentication.TEMPLATE.json').read_bytes())
        self.assertEqual(set(template), {'issuer', 'status', 'accepted', 'builder_lock', 'signer_fingerprint', 'signatures',
                                         'all_verifiers_naturally_retired', 'Root_native_authority', 'current_official_trust_reviewed'})
        self.assertEqual(template['builder_lock'], A.BUILDER)
        self.assertEqual(template['signer_fingerprint'], A.SIGNER)
        for name in ('issuer', 'accepted', 'signatures', 'all_verifiers_naturally_retired', 'Root_native_authority', 'current_official_trust_reviewed'):
            self.assertIsNone(template[name])
        self.assertEqual(template['status'], 'UNISSUED')


if __name__ == '__main__':
    # A missing default/refusal boundary cannot accidentally launch a test actor.
    with patch.object(A.subprocess, 'Popen', side_effect=AssertionError('source/MODEL suite must never launch a process')):
        unittest.main(verbosity=2)
