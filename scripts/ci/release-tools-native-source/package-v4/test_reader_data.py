#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic extracted Reader DATA controls; no Reader/capsule/Source/native actor."""
import ast
import base64
import builtins
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tarfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
READER = HERE / 'payload/native/release_reader_v1.py'
RAW = READER.read_bytes()
TREE = ast.parse(RAW)
FUNCTIONS = {n.name: n for n in TREE.body if isinstance(n, ast.FunctionDef)}
PARENT = json.loads((HERE / 'parent-function-pins.json').read_bytes())['native/release_reader_v1.py']
CONTRACT = (HERE / 'payload/native/release-contract-v1.json').read_bytes()
PRODUCERS = ast.literal_eval(next(n.value for n in TREE.body if isinstance(n, ast.Assign)
    and any(isinstance(t, ast.Name) and t.id == 'PRODUCERS' for t in n.targets)))
SIGNER = 'A' * 40
FIXED = Path('/opt/native-release-tools-alpm-v1')
TRUST = '/tmp/release-tools-test-SYNTHETIC/trust'
VERIFIER = ['/usr/bin/gpg', '--batch', '--no-options', '--homedir', TRUST, '--no-auto-key-retrieve']
GPG = ['/usr/bin/gpg', '--batch', '--no-options', '--homedir', str(Path(TRUST).with_name('signing')),
       '--no-auto-key-retrieve', '--pinentry-mode', 'loopback', '--passphrase', '']
PREFIX = 'journey/release-alpm-v1/'


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def need(value, message):
    if not value:
        raise ValueError(message)


def stable_dump(node):
    """Python3.14 empty-field AST form, also on the metadata CI's Python3.12."""
    if isinstance(node, ast.AST):
        fields = []
        for name in node._fields:
            if not hasattr(node, name):
                continue
            value = getattr(node, name)
            if value == [] or value is None and not (isinstance(node, (ast.Constant, ast.MatchSingleton)) and name == 'value'):
                continue
            fields.append(name + '=' + stable_dump(value))
        return type(node).__name__ + '(' + ', '.join(fields) + ')'
    if isinstance(node, list):
        return '[' + ', '.join(stable_dump(item) for item in node) + ']'
    return repr(node)


def ast_pin(node):
    return pin(stable_dump(node).encode())['sha256']


def canonical_tar(bodies):
    # Independent stdlib writer/parser oracle; trim only its extra record blocks.
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(bodies.items()):
            member = tarfile.TarInfo(name); member.size = len(raw); member.mode = 0o644
            archive.addfile(member, io.BytesIO(raw))
    raw = stream.getvalue()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        last = archive.getmembers()[-1]
    end = (last.offset_data + last.size + 511) // 512 * 512
    return raw[:end] + b'\0' * 1024


class DataView:
    def __init__(self, logs):
        self.logs = logs
        self.reads = []

    def read(self, name):
        need(name in self.logs, 'only explicit in-memory DATA may be read')
        self.reads.append(name)
        return self.logs[name]


class ReaderDataTests(unittest.TestCase):
    def setUp(self):
        self.actor_attempts = []
        def denied(*args, **kw):
            self.actor_attempts.append(True)
            raise AssertionError('actor or filesystem access denied in extracted DATA control')
        for owner, name in ((subprocess, 'run'), (subprocess, 'Popen'), (socket, 'socket'),
                            (Path, 'open'), (builtins, 'open'), (os, 'open'), (os, 'system'),
                            (os, 'execv'), (os, 'execve')):
            self.enterContext(mock.patch.object(owner, name, side_effect=denied))
        self.contract_raw = CONTRACT
        self.ns = dict(__file__=str(READER), Path=Path, re=re, json=json, tarfile=tarfile, base64=base64,
                       need=need, pin=pin, PRODUCERS=copy.deepcopy(PRODUCERS), OPERATION='release-alpm-upgrade-v1',
                       read=lambda path: self.contract_raw)
        self.ns['__builtins__'] = dict(vars(builtins), __import__=denied, open=denied, exec=denied, eval=denied, compile=denied)
        selected = ['release_contract', 'strict_test_signature', 'retained_business_features']
        exec(compile(ast.Module(body=[FUNCTIONS[n] for n in selected], type_ignores=[]),
                     '<extracted-passive-DATA-functions>', 'exec'), self.ns)
        self.logs, self.files, self.commands = {}, {}, []
        self.public = b'SYNTHETIC public certificate DATA; not crypto evidence\n'
        self.public_pin = pin(self.public)
        self.add('export-only-test-binary-public', GPG + ['--export', SIGNER], self.public)
        self.business = {label: self.fixture(label) for label in ('system', 'moved')}
        self.view = DataView(self.logs)

    def tearDown(self):
        self.assertEqual(self.actor_attempts, [])

    def add(self, step, argv, raw=b'', expected=0):
        leaf = '%03d-%s.log' % (len(self.commands), step)
        row = dict(step=step, argv=list(map(str, argv)), expected=expected, log=leaf, log_pin=pin(raw))
        self.commands.append(row); self.logs[PREFIX + leaf] = raw
        self.files[PREFIX + leaf] = dict(kind='file', mode=0o600, **pin(raw))
        return row

    def fixture(self, label):
        home = FIXED / 'user-data' / ('system' if label == 'system' else 'relocated')
        cli = '/usr/bin/cachy-asahi-release-tools' if label == 'system' else str(FIXED / 'user-data/moved-prefix/usr/bin/cachy-asahi-release-tools')
        actor = ['/usr/bin/runuser', '-u', 'alarm', '--', '/usr/bin/env', 'HOME=' + str(home), cli]
        self.add(label + '-version', actor + ['--version'], b'cachy-asahi-release-tools 0.4.0\n')
        for step, name in [('recipe-pack', 'recipe-pack'), ('recipe-unpack', 'recipe-unpack'), ('sbom-before', 'sbom'),
                           ('sbom-after', 'sbom'), ('source-export', 'source-export'), ('sbom-compare', 'sbom-compare'),
                           ('sbom-compare-human', 'sbom-compare')]:
            self.add(label + '-' + step, actor + [name, '--synthetic-DATA-only'])
        directory = home / 'endpoint'
        reason = 'SYNTHETIC native v4 withdrawal fixture; not a production release.'
        record = dict(schema_version=1, release_id='native-fixture-1', signer=SIGNER,
            withdrawn_utc='2026-10-28T00:00:00+00:00', reason=reason,
            reason_sha256=pin(reason.encode())['sha256'], packages_retained=True)
        signature = b'SYNTHETIC detached signature DATA; NOT a valid signature'
        signature_pin = dict(pin(signature), base64=base64.b64encode(signature).decode())
        status = ('[GNUPG:] VALIDSIG ' + SIGNER + ' 2026-11-08 0 0 4 0 22 8 00 ' + SIGNER
                  + '\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n')
        original = directory / 'generation/withdrawals/native-fixture-1.json'
        self.add(label + '-endpoint-sign-withdrawal', GPG + ['--local-user', SIGNER, '--digest-algo', 'SHA256',
            '--output', str(original) + '.sig', '--detach-sign', str(original)])
        self.add(label + '-endpoint-verify-withdrawal', VERIFIER + ['--status-fd=1', '--verify', str(original) + '.sig', str(original)], status.encode())
        plan = dict(schema_version=1, purpose='local-repository-endpoint', selected_release=None, signer=SIGNER,
            files={'withdrawals/native-fixture-1.json': pin(encoded(record))['sha256'],
                   'withdrawals/native-fixture-1.json.sig': pin(signature)['sha256']}, symlinks={})
        identity = pin(encoded(plan))['sha256']
        bodies = {'export.json': encoded(plan), 'withdrawals/native-fixture-1.json': encoded(record),
                  'withdrawals/native-fixture-1.json.sig': signature}
        archive = pin(canonical_tar(bodies)); total = sum(map(len, bodies.values()))
        stable = dict(generation_sha256=pin(b'SYNTHETIC distinct stable inventory')['sha256'],
            archive=pin(b'SYNTHETIC distinct stable archive DATA'), refusals={}, outputs_absent=True, input_unchanged=True)
        for role, leaf in [('package', 'release/repo/endpoint-fixture-1.0-1-any.pkg.tar.gz'),
            ('database', 'release/repo/synthetic.db.tar.gz'), ('files', 'release/repo/synthetic.files.tar.gz'),
            ('release', 'release/release.json'), ('promotion', 'promotion.json')]:
            path = directory / 'stable-generation' / leaf
            self.add(label + '-endpoint-sign-stable-' + role, GPG + ['--local-user', SIGNER, '--digest-algo', 'SHA256',
                '--output', str(path) + '.sig', '--detach-sign', str(path)])
        common = ['--expected-generation', identity, '--public-keyring', str(directory / 'public.gpg'), '--signer', SIGNER, '--output']
        verify = dict(generation=identity, signer=SIGNER, selected_release=None, withdrawn_releases=['native-fixture-1'],
            repository_relative_path=None, stable_contract_checked=False, freshness_established=False,
            installation_authorized=False, production_accepted=False, network_used=False, trust_changed=False, state_changed=False)
        outputs = {}
        for key, step, tail, result, out, created in [
            ('preview', 'endpoint-preview', ['endpoint-copy', '--generation', str(directory / 'generation'), *common, str(directory / 'copied')], 'planned-local-endpoint-copy', 'copied', False),
            ('copy', 'endpoint-copy', ['endpoint-copy', '--generation', str(directory / 'generation'), *common, str(directory / 'copied'), '--apply'], 'copied-local-endpoint', 'copied', True),
            ('pack', 'endpoint-pack', ['endpoint-pack', '--generation', str(directory / 'copied'), *common, str(directory / 'endpoint.tar')], 'packed-endpoint-archive', 'endpoint.tar', True),
            ('unpack', 'endpoint-unpack', ['endpoint-unpack', '--archive', str(directory / 'endpoint.tar'), '--archive-sha256', archive['sha256'], *common, str(directory / 'unpacked')], 'unpacked-endpoint-archive', 'unpacked', True)]:
            value = dict(verify, status=result, output=str(directory / out), files=3, bytes=total, output_created=created)
            value.update(dict(aliases=0, archive_sha256=archive['sha256'], archive_bytes=archive['bytes']) if key in ('pack', 'unpack') else dict(symlinks=0))
            outputs[key] = value
            self.add(label + '-' + step, actor + tail, (json.dumps(value, sort_keys=True) + '\n').encode())
        for name, output in [('copy', 'refused-copy'), ('pack', 'refused.tar'), ('unpack', 'refused-unpack')]:
            tail = (['--archive', str(directory / 'stable.tar'), '--archive-sha256', stable['archive']['sha256']]
                    if name == 'unpack' else ['--generation', str(directory / 'stable-generation')])
            tail += ['--expected-generation', stable['generation_sha256'], '--public-keyring', str(directory / 'public.gpg'),
                     '--signer', SIGNER, '--output', str(directory / output)]
            if name == 'copy': tail += ['--apply']
            refusal = dict(status='endpoint-copy-refused' if name == 'copy' else 'endpoint-transport-refused',
                           errors=['synthetic fixtures cannot enter stable'])
            stable['refusals']['endpoint-' + name] = refusal
            self.add(label + '-stable-' + name, actor + ['endpoint-' + name, *tail],
                     (json.dumps(refusal, sort_keys=name == 'copy') + '\n').encode(), 1)
        endpoint = dict(signer=SIGNER, keyring=self.public_pin, generation_sha256=identity, generation_manifest=plan,
            withdrawal=dict(record=record, pin=pin(encoded(record)), signature=signature_pin, status=status),
            **outputs, archive=archive, roundtrip_identical=True, source_unchanged=True, stable=stable)
        return dict(status='PASS_ALL_EIGHT_ACTUAL_COMMANDS', cli=cli, synthetic=True,
            commands=['sbom', 'source-export', 'recipe-pack', 'recipe-unpack', 'sbom-compare', 'endpoint-copy', 'endpoint-pack', 'endpoint-unpack'],
            roundtrip_files=7, held_unknowns=1, build_context=None, license_conclusion='NOASSERTION',
            exports=dict(files=3, sha256='b' * 64), endpoint=endpoint, release='NOT_ADMITTED')

    def row(self, step):
        return next(row for row in self.commands if row['step'] == step)

    def selected(self, step):
        rows = [(i, row) for i, row in enumerate(self.commands) if row['step'] == step]
        need(len(rows) == 1, 'sole exact lifecycle command reference required')
        return rows[0]

    def check(self):
        return self.ns['retained_business_features'](self.view, self.files, self.business, FIXED, self.selected,
            SIGNER, self.public_pin, VERIFIER, GPG)

    def refuses(self):
        with self.assertRaises((ValueError, KeyError)):
            self.check()

    def repin(self, step, raw):
        row = self.row(step); row['log_pin'] = pin(raw)
        self.logs[PREFIX + row['log']] = raw
        self.files[PREFIX + row['log']] = dict(kind='file', mode=0o600, **pin(raw))

    def change_contract(self, value):
        self.contract_raw = encoded(value)
        self.ns['PRODUCERS']['native/release-contract-v1.json'] = pin(self.contract_raw)['sha256']

    def test_only_two_existing_function_deltas_and_one_pure_helper(self):
        self.assertEqual(set(FUNCTIONS) - set(PARENT), {'retained_business_features'})
        self.assertEqual(set(PARENT) - set(FUNCTIONS), set())
        changed = {name for name, digest in PARENT.items() if ast_pin(FUNCTIONS[name]) != digest}
        self.assertEqual(changed, {'release_contract', 'retained_release_alpm'})
        for node in TREE.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self.assertFalse(any(alias.name in ('subprocess', 'socket') for alias in node.names))

    def test_old_ALPM_inventory_signature_retirement_and_binding_blocks_held(self):
        body = FUNCTIONS['retained_release_alpm'].body
        self.assertEqual(ast_pin(ast.Module(body=body[:60], type_ignores=[])),
                         '63b3fc4dfb48650ed6acf6cdaef36f26f81a2afc1e468aab186385cfadc17ef0')
        self.assertEqual(ast_pin(ast.Module(body=body[-5:], type_ignores=[])),
                         '674d35b63abbaebbb1965af00570220f7033258684992535ec555e22a6771533')
        self.assertEqual(ast_pin(FUNCTIONS['validate']), PARENT['validate'])
        self.assertEqual(ast_pin(FUNCTIONS['strict_test_signature']), PARENT['strict_test_signature'])

    def test_exact_reviewed_v1_v4_contract_DATA(self):
        value = self.ns['release_contract']()
        self.assertEqual(set(value['recipes']), {'0.1.0-1', '0.4.0-1'})
        self.assertEqual(value['bundle']['bytes'], 942080)
        self.assertTrue(all(item is None for item in value['actual'].values()))

    def test_contract_counts_target_and_positive_checks_cannot_change(self):
        original = json.loads(CONTRACT)
        for version, key in [('0.1.0-1', 'source_files'), ('0.4.0-1', 'source_files'),
                             ('0.1.0-1', 'payload_files'), ('0.4.0-1', 'payload_files')]:
            value = copy.deepcopy(original); value['recipes'][version][key].pop(next(iter(value['recipes'][version][key])))
            self.change_contract(value)
            with self.assertRaises(ValueError): self.ns['release_contract']()
        for version in original['recipes']:
            value = copy.deepcopy(original); value['recipes'][version]['expected_test_count'] = True
            self.change_contract(value)
            with self.assertRaises(ValueError): self.ns['release_contract']()
        for key in ('source_commit', 'product_merge', 'product_merge_tree'):
            value = copy.deepcopy(original); value['recipes']['0.4.0-1'][key] = 'f' * 40
            self.change_contract(value)
            with self.assertRaises(ValueError): self.ns['release_contract']()
        value = copy.deepcopy(original); value['recipes']['0.2.0-1'] = value['recipes'].pop('0.4.0-1')
        self.change_contract(value)
        with self.assertRaises(ValueError): self.ns['release_contract']()

    def test_source_bundle_stays51_and_within_original_oneMiB_cap(self):
        original = json.loads(CONTRACT)
        for key, item in [('members', 52), ('members', True), ('bytes', 1024**2 + 1),
                          ('max_bytes', 2*1024**2), ('max_bytes', True)]:
            value = copy.deepcopy(original); value['bundle'][key] = item; self.change_contract(value)
            with self.assertRaises(ValueError): self.ns['release_contract']()

    def test_contract_pin_and_NULL_actual_selectors_remain_strict(self):
        self.contract_raw = CONTRACT + b' '
        with self.assertRaises(ValueError): self.ns['release_contract']()
        value = json.loads(CONTRACT); value['actual']['source'] = 'a' * 40; self.change_contract(value)
        with self.assertRaises(ValueError): self.ns['release_contract']()

    def test_positive_both_eight_command_DATA_routes_without_mutation_or_actors(self):
        before = copy.deepcopy((self.business, self.commands, self.logs, self.files))
        result = self.check()
        self.assertEqual(set(result), {'system', 'moved'})
        self.assertLess(max(result['system']), min(result['moved']))
        self.assertEqual((self.business, self.commands, self.logs, self.files), before)
        self.assertGreater(len(self.view.reads), 20)

    def test_old_five_only_or_acceptance_summary_cannot_qualify(self):
        baseline = copy.deepcopy(self.business)
        for key, value in [('status', 'PASS_ALL_FIVE_ACTUAL_COMMANDS'), ('commands', baseline['system']['commands'][:5]),
                           ('held_unknowns', 0), ('build_context', {}), ('license_conclusion', 'MIT'), ('release', 'ADMITTED')]:
            self.business = copy.deepcopy(baseline); self.business['system'][key] = value; self.refuses()

    def test_external_signer_certificate_inventory_pins_and_aliases_join(self):
        baseline = copy.deepcopy(self.business)
        for key, value in [('signer', 'B' * 40), ('keyring', pin(b'foreign')), ('generation_sha256', 'f' * 64),
                           ('roundtrip_identical', False), ('source_unchanged', False)]:
            self.business = copy.deepcopy(baseline); self.business['system']['endpoint'][key] = value; self.refuses()
        self.business = copy.deepcopy(baseline)
        self.business['system']['endpoint']['generation_manifest']['symlinks']['unlisted'] = 'target'; self.refuses()

    def test_withdrawal_record_signature_bytes_and_TEST_status_are_bound(self):
        baseline = copy.deepcopy(self.business)
        for path, value in [(('record', 'packages_retained'), False), (('record', 'signer'), 'B' * 40),
                            (('signature', 'sha256'), 'f' * 64), (('signature', 'base64'), 'YQ=='),
                            (('pin', 'bytes'), True)]:
            self.business = copy.deepcopy(baseline)
            self.business['system']['endpoint']['withdrawal'][path[0]][path[1]] = value; self.refuses()
        for token in ('NO_PUBKEY', 'BADSIG', 'EXPKEYSIG', 'REVKEYSIG', 'TRUST_UNDEFINED'):
            self.business = copy.deepcopy(baseline)
            self.business['system']['endpoint']['withdrawal']['status'] += '[GNUPG:] ' + token + '\n'; self.refuses()

    def test_archive_and_full_CLI_counts_cannot_be_self_asserted(self):
        baseline = copy.deepcopy(self.business)
        for key, field, value in [('archive', 'sha256', 'f' * 64), ('pack', 'archive_bytes', 1),
                                   ('unpack', 'files', True), ('copy', 'bytes', 1), ('preview', 'output_created', True)]:
            self.business = copy.deepcopy(baseline); self.business['system']['endpoint'][key][field] = value; self.refuses()

    def test_actual_argv_HOME_paths_generation_and_bypass_flags_are_closed(self):
        row = self.row('system-endpoint-pack'); original = list(row['argv'])
        for index, value in [(0, '/usr/bin/true'), (5, 'HOME=/tmp/foreign'),
                             (9, '/tmp/foreign-generation'), (11, 'f' * 64)]:
            row['argv'] = list(original); row['argv'][index] = value; self.refuses()
        row['argv'] = original + ['--model-gates']; self.refuses()

    def test_actual_raw_log_manifest_and_command_pins_must_all_join(self):
        step = 'system-endpoint-copy'; row = self.row(step); name = PREFIX + row['log']; raw = self.logs[name]
        self.logs[name] = raw + b'changed'; self.refuses()
        self.logs[name] = raw; row['log_pin'] = pin(raw + b'foreign'); self.refuses()
        row['log_pin'] = pin(raw); self.files[name]['sha256'] = 'f' * 64; self.refuses()

    def test_stable_refusal_requires_real_exit1_exact_gate_and_no_outputs(self):
        baseline = copy.deepcopy(self.business)
        for key in ('outputs_absent', 'input_unchanged'):
            self.business = copy.deepcopy(baseline); self.business['system']['endpoint']['stable'][key] = False; self.refuses()
        self.business = copy.deepcopy(baseline)
        self.business['system']['endpoint']['stable']['refusals']['endpoint-pack']['errors'] = ['missing key']; self.refuses()
        self.business = copy.deepcopy(baseline); row = self.row('system-stable-pack'); row['expected'] = 0; self.refuses()
        row['expected'] = True; self.refuses()

    def test_stable_signing_uses_exact_private_TEST_provider_and_SHA256(self):
        row = self.row('system-endpoint-sign-stable-promotion'); original = list(row['argv'])
        for value in ('SHA1', '--skip-signature'):
            row['argv'] = list(original); row['argv'][row['argv'].index('SHA256')] = value; self.refuses()
        row['argv'] = list(original); row['argv'][4] = '/tmp/foreign-signing'; self.refuses()

    def test_no_acceptance_flags_survive_even_rehashed_raw_JSON(self):
        endpoint = self.business['system']['endpoint']; baseline = copy.deepcopy(endpoint)
        for flag in ('stable_contract_checked', 'installation_authorized', 'production_accepted', 'network_used', 'trust_changed', 'state_changed'):
            self.business['system']['endpoint'] = copy.deepcopy(baseline)
            value = self.business['system']['endpoint']['pack']; value[flag] = True
            self.repin('system-endpoint-pack', (json.dumps(value, sort_keys=True) + '\n').encode()); self.refuses()

    def test_duplicate_or_reordered_actual_command_roles_are_refused(self):
        baseline = copy.deepcopy(self.commands)
        self.commands.append(copy.deepcopy(self.row('system-endpoint-pack'))); self.refuses()
        self.commands = copy.deepcopy(baseline)
        a = next(i for i, row in enumerate(self.commands) if row['step'] == 'system-endpoint-pack')
        b = next(i for i, row in enumerate(self.commands) if row['step'] == 'system-endpoint-copy')
        self.commands[a], self.commands[b] = self.commands[b], self.commands[a]; self.refuses()

    def test_binary_public_key_and_strict_primary_status_need_original_logs(self):
        row = self.row('export-only-test-binary-public'); row['argv'][-1] = 'B' * 40; self.refuses()
        row['argv'][-1] = SIGNER
        raw = self.logs[PREFIX + row['log']]; self.logs[PREFIX + row['log']] = raw + b'foreign'; self.refuses()


if __name__ == '__main__':
    unittest.main()
