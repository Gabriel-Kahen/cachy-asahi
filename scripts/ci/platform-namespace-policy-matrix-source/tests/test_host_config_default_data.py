#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite synthetic DATA controls; never open an actual native capsule."""
import sys


def deny(event, args):
    if event.startswith(('socket.', 'subprocess.', 'ctypes.', 'pty.')) or event in (
            'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn'):
        raise RuntimeError('actor forbidden: ' + event)


sys.addaudithook(deny)

import argparse
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_owner_data as controls


class HostConfigDefaultData(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='namespace-oom-new-DATA-')
        self.addCleanup(self.work.cleanup)
        self.fixture = controls.ports.Fixture(Path(self.work.name) / 'owner')

    def test_versioned_default_and_all_other_fields_type_exact(self):
        f = self.fixture
        with f.ports():
            m = f.module
            before = dict(OomKillDisable=False, Memory=536870912, SecurityOpt=[],
                          Nested=dict(enabled=False, values=[1, 'x']))
            after = dict(copy.deepcopy(before), OomKillDisable=None)
            self.assertEqual(m.host_config_default_v1(before, after, dict(version='28.0.4')),
                             'DOCKER_28_0_4_FALSE_TO_NULL_DEFAULT')
            self.assertEqual(m.host_config_default_v1(before, before, dict(version='DATA_ONLY_1')), 'EXACT_FALSE')
            bad = []
            for value in (True, 0, 1, 'false', [], {}):
                bad.append((before, dict(after, OomKillDisable=value), '28.0.4'))
            for version in ('28.0.3', '28.0.4+vendor', '28.0.5', None):
                bad.append((before, after, version))
            bad += [(after, before, '28.0.4'),
                    (dict(before, OomKillDisable=True), after, '28.0.4'),
                    (dict(before, OomKillDisable=True), dict(after, OomKillDisable=True), '28.0.4'),
                    (dict(before, OomKillDisable=0), after, '28.0.4'),
                    (after, after, '28.0.4'),
                    ({k: v for k, v in before.items() if k != 'OomKillDisable'}, after, '28.0.4'),
                    (before, {k: v for k, v in after.items() if k != 'OomKillDisable'}, '28.0.4'),
                    (before, dict(after, Memory=536870912.0), '28.0.4'),
                    (before, dict(after, Memory=268435456), '28.0.4'),
                    (before, dict(after, SecurityOpt=['seccomp=unconfined']), '28.0.4'),
                    (before, dict(after, NewField=None), '28.0.4'),
                    (before, dict(after, Nested=dict(enabled=0, values=[1, 'x'])), '28.0.4')]
            for left, right, version in bad:
                with self.subTest(left=left, right=right, version=version):
                    with self.assertRaises(m.MatrixGuard):
                        m.host_config_default_v1(left, right, dict(version=version))

    def test_owner_and_matching_synthetic_reader_preserve_raw_transition(self):
        f = self.fixture
        original = f.respond

        def response(argv):
            body, rc = original(argv)
            if argv[2:3] == ['info']:
                value = json.loads(body); value['version'] = '28.0.4'
                return controls.ports.encoded(value), rc
            if argv[2:4] == ['start', '-a']:
                f.containers[argv[-1]]['HostConfig']['OomKillDisable'] = None
            return body, rc

        with f.ports(), patch.object(f, 'respond', response):
            f.run()
            self.assertEqual(f.diagnostic['status'], controls.COMPLETE)
            self.assertEqual(f.diagnostic['host_config_comparison']['default_transitions'], list(f.module.CASES))
            original_raw = controls.ports.encoded(f.result)
            qualified = f.module.validate_result(f.result, json.loads(f.bodies[f.module.CONTRACT]), controls.expected(f))
            self.assertEqual(controls.ports.encoded(f.result), original_raw)
            self.assertEqual(qualified['host_config_comparison'], f.diagnostic['host_config_comparison'])
            for row in f.result['cases']:
                self.assertIs(row['inspect_before']['HostConfig']['OomKillDisable'], False)
                self.assertIsNone(row['inspect_after']['HostConfig']['OomKillDisable'])
            _, payloads = controls.project(f)
            retained = dict(payloads)
            # Newly invented RAM transport only; no old Source/capsule reader replay.
            read = controls.read(f, payloads)
            self.assertEqual(read['projection_status'], controls.COMPLETE)
            self.assertEqual(read['raw_result'], f.result)
            self.assertEqual(read['qualification']['host_config_comparison'],
                             read['runtime_qualification']['host_config_comparison'])
            self.assertEqual(payloads, retained)

    def test_marker_cannot_replace_independent_raw_role_comparison(self):
        f = self.fixture
        with f.ports():
            f.run()
            owner = copy.deepcopy(f.owner)
            owner['host_config_comparison']['default_transitions'] = list(f.module.CASES)
            owner['host_config_comparison']['status'] = 'PASS_SINGLE_FIELD_DEFAULT_TRANSITIONS'
            with self.assertRaisesRegex(f.module.MatrixGuard, 'independently recomputed'):
                f.module.validate_runtime_evidence(owner, f.result, controls.raw_payloads(f),
                    controls.expected(f), controls.source_proof(f))
            owner = copy.deepcopy(f.owner)
            result = copy.deepcopy(f.result)
            result['cases'][0]['inspect_after']['HostConfig']['Memory'] = 268435456
            with self.assertRaisesRegex(f.module.MatrixGuard, 'raw before/after inspect inverse'):
                f.module.validate_runtime_evidence(owner, result, controls.raw_payloads(f),
                    controls.expected(f), controls.source_proof(f))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--basis', required=True, type=Path)
    args, rest = parser.parse_known_args()
    controls.ports.configure_basis(args.basis.resolve(strict=True))
    unittest.main(argv=[sys.argv[0], *rest])
