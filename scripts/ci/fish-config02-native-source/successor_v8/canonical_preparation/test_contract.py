#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fenced preparation/caller DATA controls; no Root issuance or native actors.

Accepted documents exist only as explicit MODEL bytes in test memory. The actual
Source admission function runs with modeled source/read seams, never its prior
Source validator or inverses. No earlier source test suite is invoked.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
PREFIX = 'scripts/ci/fish-config02-native-source/successor_v2/'
TEMP_ROOT = Path(os.environ.get('TMPDIR', '/dev/shm'))
if TEMP_ROOT not in (Path('/dev/shm'), Path('/tmp')):
    raise SystemExit('DATA TMPDIR must be /dev/shm or /tmp')
TEMP_PREFIX = str(TEMP_ROOT / 'FISH-V8-CANONICAL-DATA.')
ACTORS = []
NOW = 2_000_000_000
MODEL_SOURCE = 'a' * 40
MODEL_REF = 'refs/heads/codex/fish02-no-host-apt-v4-source-MODEL_ONLY'


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'fcntl.')) or event in {
        'resource.setrlimit', 'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn',
        'os.kill', 'os.killpg', 'os.pidfd_open',
    }:
        ACTORS.append(event)
        raise AssertionError('FENCED no process/resource/network/custody actor: ' + event)
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        if (args[2] or 0) & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            if not str(Path(os.fsdecode(args[0])).absolute()).startswith(TEMP_PREFIX):
                raise AssertionError('FENCED writes only to disposable preparation DATA fixture')


sys.addaudithook(fence)


def module(path):
    value = ModuleType('fenced_canonical_' + path.stem)
    value.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), value.__dict__)
    return value


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def pin(body):
    return dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='FISH-V8-CANONICAL-DATA.', dir=TEMP_ROOT)
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.assertEqual, ACTORS, [], 'actual actors must remain zero')
        self.pidfd = patch.object(os, 'pidfd_open', create=True,
                                  side_effect=AssertionError('NO actual PIDFD open'))
        self.pidfd.start()
        self.addCleanup(self.pidfd.stop)
        self.output = self.root / 'packet'
        P.construct(SOURCE, self.output)
        self.plan = json.loads((self.output / 'PLAN.UNISSUED.json').read_bytes())

    def model(self):
        """No actual grant is created or retained; these are MODEL values only."""
        expected = K.expected()
        publication = dict(kind='FISH62_PUBLICATION_DATA_BINDING_V1', source=MODEL_SOURCE, ref=MODEL_REF,
                           tree=expected['source']['tree'], source_map=expected['source']['source_map'],
                           owner_program=expected['source']['owner_program'], policy=expected['source']['policy'],
                           workflow=dict(expected['workflow'], id=12345))
        admission = json.loads((self.output / 'admission.INTENT.UNISSUED.json').read_bytes())
        runtime = json.loads((self.output / 'runtime.INTENT.UNISSUED.json').read_bytes())
        for value in (admission, runtime):
            value.update(source=MODEL_SOURCE, ref=MODEL_REF, nonce='b' * 32, issued_by='Root', accepted=True,
                         created_utc=NOW - 10, expires_utc=NOW + 600)
        env = dict(expected['fixed_context'], GITHUB_SHA=MODEL_SOURCE, GITHUB_REF=MODEL_REF,
                   GITHUB_RUN_ID='44000000000', ImageOS='ubuntu24', ImageVersion='20261117.1.0')
        return publication, admission, runtime, env

    def caller(self, publication, admission, runtime, env, now=NOW):
        return K.validate_caller_data(self.plan, publication, encode(admission), encode(runtime), env, now)

    def frozen_admission(self, admission, runtime, env, now=NOW):
        """Actual D.admission; source/read observations are modeled DATA seams."""
        def read(path, *args, **kwargs):
            return BODIES[Path(path).relative_to(SOURCE).as_posix()]
        a_raw, r_raw = encode(admission), encode(runtime)
        with patch.object(D, 'source', return_value=None) as source, patch.object(D, 'read', side_effect=read):
            result = D.admission(SOURCE, K.expected()['source']['source_map']['sha256'], a_raw, r_raw,
                                 pin(a_raw)['sha256'], pin(r_raw)['sha256'], env, now)
            source.assert_called_once_with(SOURCE, K.expected()['source']['source_map']['sha256'])
        return result

    def context(self, env):
        return H.context(env, 'aarch64', b'ID=ubuntu\nVERSION_ID="24.04"\n', 0)

    def test_sealed_packet_retains_unissued_publication_and_root_gates(self):
        result = P.verify(SOURCE, self.output)
        self.assertIn('DATA_READY_ROOT_BINDINGS_UNISSUED', str(result))
        portable = module(self.output / 'prepare.py')
        self.assertIn('DATA_READY_ROOT_BINDINGS_UNISSUED', str(portable.verify(SOURCE, self.output)))
        K.validate_plan(self.plan)
        expected = K.expected()
        for key in ('source', 'workflow', 'normal_pair', 'ref_pattern'):
            self.assertEqual(self.plan[key], expected[key])
        self.assertEqual(set(self.plan['publication']), set(expected['publication_fields']))
        self.assertTrue(all(value is None for value in self.plan['publication'].values()))
        self.assertEqual(set(self.plan['root_bindings']), set(expected['root_binding_fields']))
        self.assertTrue(all(value is None for value in self.plan['root_bindings'].values()))
        self.assertIsNone(self.plan['Root_authority'])
        self.assertIsNone(self.plan['Root_acceptance'])
        for name in ('admission.INTENT.UNISSUED.json', 'runtime.INTENT.UNISSUED.json'):
            intent = json.loads((self.output / name).read_bytes())
            self.assertIs(intent['accepted'], False)
            for key in ('issued_by', 'source', 'ref', 'nonce', 'created_utc', 'expires_utc'):
                self.assertIsNone(intent[key])
        # Constructor packages this exact Source; it creates no successor Source.
        content = json.loads((self.output / 'SOURCE-CONTENT.PINS.json').read_bytes())
        self.assertIn(expected['source']['source_map']['sha256'], json.dumps(content))
        self.assertEqual(expected['source']['files'], 62)

    def test_model_documents_join_actual_admission_and_context_without_authority(self):
        publication, admission, runtime, env = self.model()
        result = self.caller(publication, admission, runtime, env)
        self.assertEqual(result['status'], 'CALLER_DATA_COMPATIBLE_ONLY')
        self.assertIsNone(result['Root_acceptance'])
        self.assertIs(result['actors_permitted'], False)
        self.assertEqual(result['pending_root_gates'], list(self.plan['root_bindings']))
        self.assertEqual(result['admission'], pin(encode(admission)))
        self.assertEqual(result['runtime'], pin(encode(runtime)))
        self.assertEqual(self.frozen_admission(admission, runtime, env), (admission, runtime))
        self.assertFalse(self.context(env)['reason_codes'])

    def test_new_plan_keeps_normal_pair_required_signatures_checks_and_inverse_pins(self):
        pair = self.plan['normal_pair']
        self.assertEqual(pair['mode'], 'NORMAL_NATIVE_OFFLINE_TWO_CLEAN_BUILDS')
        self.assertEqual(pair['builds'], 2)
        self.assertIs(pair['distinct_clean_environments'], True)
        self.assertIs(pair['makepkg_checks_required'], True)
        self.assertIs(pair['comparison_require_bytes'], True)
        self.assertEqual(pair['signature_policies'], dict(SigLevel='Required', LocalFileSigLevel='Required'))
        self.assertEqual(pair['complete_predecessor_chain'], [62, 60, 57, 53, 50, 48])
        profile = json.loads(BODIES['held-source32/scripts/ci/fish-config02-native-source/profile.json'])
        self.assertEqual(pair['package'], profile['package'])
        self.assertIs(pair['package']['check_required'], True)
        for name, wanted in dict(pair['protected_file_pins'], **pair['preserved_inverse_pins']).items():
            with self.subTest(name=name): self.assertEqual(pin(BODIES[name]), wanted)
        changed = copy.deepcopy(self.plan)
        changed['normal_pair']['signature_policies']['SigLevel'] = 'Optional'
        with self.assertRaises(ValueError): K.validate_plan(changed)

    def test_preserved_ref_namespace_catches_prior_v8_proposal(self):
        publication, admission, runtime, env = self.model()
        invalid_ref = 'refs/heads/codex/fish02-exact-source-readonly-v8-source-MODEL_ONLY'
        publication['ref'] = env['GITHUB_REF'] = invalid_ref
        admission['ref'] = runtime['ref'] = invalid_ref
        # The original outer admission accepts codex/*; preserved platform context
        # rejects this narrower mismatch. The new caller bridge must catch it.
        self.assertEqual(self.frozen_admission(admission, runtime, env), (admission, runtime))
        recorded = []
        with self.assertRaises(ValueError):
            H.context(env, 'aarch64', b'ID=ubuntu\nVERSION_ID=24.04\n', 0, record=recorded.append)
        self.assertIn('CI_SOURCE_REF', recorded[0]['reason_codes'])
        with self.assertRaises(ValueError): self.caller(publication, admission, runtime, env)

    def test_unissued_intents_and_publication_cannot_be_caller_admission(self):
        publication, admission, runtime, env = self.model()
        original_admission = json.loads((self.output / 'admission.INTENT.UNISSUED.json').read_bytes())
        original_runtime = json.loads((self.output / 'runtime.INTENT.UNISSUED.json').read_bytes())
        for a, r in ((original_admission, runtime), (admission, original_runtime),
                     (original_admission, original_runtime)):
            with self.subTest(admission=a['accepted'], runtime=r['accepted']), self.assertRaises(ValueError):
                self.caller(publication, a, r, env)
        for value in (None, self.plan['publication'], {}):
            with self.subTest(publication=value), self.assertRaises((ValueError, TypeError)):
                self.caller(value, admission, runtime, env)

    def test_publication_and_registration_pin_mismatches_refuse(self):
        publication, admission, runtime, env = self.model()
        mutations = [('source', 'c' * 40), ('ref', 'refs/heads/main'), ('tree', 'd' * 40),
                     ('source_map', dict(bytes=13251, sha256='0' * 64)),
                     ('owner_program', dict(bytes=3162, sha256='c100984bd7673b890ee32415302d0f254115ba398e66eabd89d308467880e7f6')),
                     ('policy', dict(bytes=1336, sha256='35aaed7f75b559b8a62ca3cbb33719e5201f17c48e9169ab37ae7b0a6dd449ed'))]
        for key, value in mutations:
            changed = copy.deepcopy(publication); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.caller(changed, admission, runtime, env)
        for key, value in (('id', None), ('id', True), ('id', 0), ('path', '.github/workflows/foreign.yml'),
                           ('pin', dict(bytes=5894, sha256='0' * 64))):
            changed = copy.deepcopy(publication); changed['workflow'][key] = value
            with self.subTest(workflow_key=key, value=value), self.assertRaises(ValueError):
                self.caller(changed, admission, runtime, env)
        changed = dict(publication, extra='unsupported publication selector')
        with self.assertRaises(ValueError): self.caller(changed, admission, runtime, env)

    def test_document_freshness_source_resource_and_legacy_apt_refusals(self):
        cases = ('admission-kind', 'runtime-kind', 'unaccepted', 'issuer', 'source', 'ref', 'map', 'resources',
                 'nonce-mismatch', 'nonce-shape', 'expired', 'future', 'overlong', 'noninteger-time',
                 'old-program', 'old-policy', 'host-tools', 'legacy-apt')
        for case in cases:
            publication, admission, runtime, env = self.model()
            if case == 'admission-kind': admission['kind'] = 'ROOT_FISH02_ADMISSION_V2'
            elif case == 'runtime-kind': runtime['kind'] = 'ROOT_FISH02_RUNTIME_V2'
            elif case == 'unaccepted': admission['accepted'] = False
            elif case == 'issuer': runtime['issued_by'] = 'MODEL foreign issuer'
            elif case == 'source': runtime['source'] = 'c' * 40
            elif case == 'ref': admission['ref'] += '-foreign'
            elif case == 'map': admission['source_map_sha256'] = '0' * 64
            elif case == 'resources': runtime['resources']['builder_cpus'] += 1
            elif case == 'nonce-mismatch': runtime['nonce'] = 'c' * 32
            elif case == 'nonce-shape': admission['nonce'] = runtime['nonce'] = 'not-a-nonce'
            elif case == 'expired': admission['expires_utc'] = NOW
            elif case == 'future': runtime['created_utc'] = NOW + 1
            elif case == 'overlong': runtime.update(created_utc=NOW - 1, expires_utc=NOW + 3600)
            elif case == 'noninteger-time': runtime['created_utc'] = str(NOW - 1)
            elif case == 'old-program': runtime['external_supervision'] = dict(bytes=3162, sha256='0' * 64)
            elif case == 'old-policy': runtime['bootstrap_resource_domain'] = dict(bytes=1336, sha256='0' * 64)
            elif case == 'host-tools': runtime['host_tools']['package_manager_invocations'] = 1
            elif case == 'legacy-apt': runtime['host_prerequisites'] = {'MODEL': True}
            with self.subTest(case=case), self.assertRaises(ValueError): self.caller(publication, admission, runtime, env)
            with self.subTest(actual_admission=case), self.assertRaises(ValueError):
                self.frozen_admission(admission, runtime, env)

    def test_hosted_context_changes_refuse_new_caller_bridge(self):
        for key, value in (('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_JOB', 'foreign'), ('GITHUB_ACTIONS', 'false'),
                           ('RUNNER_OS', 'Windows'), ('RUNNER_ARCH', 'X64'), ('GITHUB_REPOSITORY', 'foreign/repo'),
                           ('GITHUB_EVENT_NAME', 'push'), ('GITHUB_RUN_ID', '0'), ('GITHUB_SHA', 'c' * 40)):
            publication, admission, runtime, env = self.model(); env[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.caller(publication, admission, runtime, env)

    def test_plan_gate_and_member_seal_changes_refuse(self):
        for key in ('publication', 'root_bindings'):
            plan = copy.deepcopy(self.plan)
            first = next(iter(plan[key])); plan[key][first] = 'MODEL not an unissued field'
            with self.subTest(key=key), self.assertRaises(ValueError): K.validate_plan(plan)
        for key in ('source', 'workflow', 'normal_pair', 'ref_pattern'):
            plan = copy.deepcopy(self.plan); plan[key] = None
            with self.subTest(key=key), self.assertRaises(ValueError): K.validate_plan(plan)
        targets = ['PLAN.UNISSUED.json', 'admission.INTENT.UNISSUED.json', 'runtime.INTENT.UNISSUED.json', 'contract.py']
        for name in targets:
            target = self.output / name
            if not target.is_file(): target = next(self.output.rglob(name))
            raw = target.read_bytes()
            try:
                target.write_bytes(raw + b'\nMODEL seal drift\n')
                with self.subTest(member=name), self.assertRaises((ValueError, json.JSONDecodeError)):
                    P.verify(SOURCE, self.output)
            finally: target.write_bytes(raw)
        self.assertIn('DATA_READY_ROOT_BINDINGS_UNISSUED', str(P.verify(SOURCE, self.output)))


if __name__ == '__main__':
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not __debug__:
        raise SystemExit('run unoptimized DATA controls with Python -I -B')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True, help='explicit exact frozen Source62 files')
    options, rest = parser.parse_known_args(); SOURCE = options.source
    P = module(HERE / 'prepare.py'); K = module(HERE / 'contract.py')
    expected = K.expected()
    manifest_raw = (SOURCE / 'source-map.json').read_bytes()
    if pin(manifest_raw) != expected['source']['source_map']:
        raise SystemExit('exact frozen Source62 map required')
    manifest = json.loads(manifest_raw)
    BODIES = {name: (SOURCE / name).read_bytes() for name in manifest['files']}
    for name in (PREFIX + 'data.py', PREFIX + 'host_context.py'):
        if dict(pin(BODIES[name]), mode=0o644) != manifest['files'][name]:
            raise SystemExit('pinned pure source contract body required')
    D = module(SOURCE / PREFIX / 'data.py'); H = module(SOURCE / PREFIX / 'host_context.py')
    unittest.main(argv=[sys.argv[0], *rest], verbosity=2)
