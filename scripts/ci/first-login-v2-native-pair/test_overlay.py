#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile the real projected execution path without calling any actor."""

import argparse
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('overlay', Path(__file__).with_name('overlay.py'))
O = importlib.util.module_from_spec(spec)
spec.loader.exec_module(O)


class OverlayTests(unittest.TestCase):
    def test_original_roles_project_and_compile_complete_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            thin = root / 'thin'
            identity = O.thin(worktree, thin)
            _, extra = O.verify(thin, identity['map_sha256'], 'FIRST_LOGIN_V2_THIN_PUBLIC_SOURCE_V1')
            base = O.verified_parent(parent)
            setup = {O.THIN+'dependency/'+path.name: path.read_bytes()
                     for path in (staged/'dependency').iterdir()}
            setup[O.THIN+'dependency/public.gpg'] = b'INERT TEST FIXTURE, not a public certificate'
            runtime = O.runtime_material(base, extra, setup)
            for name, body in runtime.items():
                if name.endswith('.py'):
                    compile(body, name, 'exec')
            output = root/'runtime'
            active = O.write(output, 'FIRST_LOGIN_V2_PROJECTED_RUNTIME_V1', {
                'fish_r12': O.R12, 'first_login_map_sha256': identity['map_sha256']}, runtime)
            self.assertLess(active['bytes'], O.MAX)
            self.assertEqual({k: v for k, v in runtime.items() if k.startswith(O.HELD)},
                             {k: v for k, v in base.items() if k.startswith(O.HELD)})
            D = O.module(output/O.FULL/'data.py', 'test_runtime_data')
            N = O.module(output/O.FULL/'native349_carrier_case.py', 'test_wire_carrier')
            Q = O.module(output/O.FULL/'fish_rootfs_binding.py', 'test_rootfs')
            I = O.module(output/O.FULL/'fish_inventory.py', 'test_inventory')
            inherited = D.projected_entry((output/O.HELD/'entry.py').read_bytes()).encode()
            code = O.project_entry(I.project_entry(Q.project_entry(N.project_entry(inherited))))
            compile(code, '<exact-runner-entry>', 'exec')
            self.assertIn(b'FIRST_LOGIN_PAIR.bind_bootstrap', code)
            D.source(output, active['map_sha256'])
            with self.assertRaisesRegex(ValueError, 'map and exact r12'):
                D.source(output, identity['map_sha256'])
            E = O.module(output/O.FULL/'public_evidence.py', 'test_projected_export')
            self.assertEqual(E.DECLARATION, json.loads(runtime[O.FULL+'policy.json'])['inner_public_retention'])
            self.assertIn('build-2/artifacts/'+O.P.CHECK_LOG, E.SUCCESS_REQUIRED)
            C = O.module(output/O.HELD/'contract.py', 'test_held_contract')
            Lane = D.module_first_login(output)
            plans, compare = Lane.plans(C, output/O.HELD, root/'result',
                                        'sha256:'+'1'*64, output/O.THIN/'expected342.lock')
            self.assertEqual(len(plans), 2)
            self.assertTrue(all(Path(argv[4]) == output/O.RECIPE for argv in plans))
            self.assertTrue(all(argv[argv.index('--network')+1] == 'none' for argv in plans))
            self.assertIn('--require-bytes', compare)
            profile = json.loads(runtime[O.HELD+'profile.json'])
            context = {'GITHUB_SHA': '1'*40, 'GITHUB_REF': O.NEW_REF,
                       'GITHUB_REPOSITORY': 'Gabriel-Kahen/cachy-asahi', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                       'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_ID': '42'}
            common = dict(issued_by='Root', accepted=True, source=context['GITHUB_SHA'], ref=O.NEW_REF,
                          source_map_sha256=active['map_sha256'], resources=profile['resources'],
                          created_utc=10, expires_utc=20, nonce='1'*32, operation='FIRST_LOGIN_V2_PACKAGE_PAIR')
            a = O.encode(dict(common, kind='ROOT_FISH02_NO_HOST_APT_ADMISSION_V4'))
            r = O.encode(dict(common, kind='ROOT_FISH02_NO_HOST_APT_RUNTIME_V4',
                thin_map_sha256=identity['map_sha256'], host_tools=json.loads(runtime[O.FULL+'policy.json'])['host_tools'],
                external_supervision=D.pin(runtime[O.FULL+'owner-program.json']),
                bootstrap_resource_domain=D.pin(runtime[O.FULL+'policy.json'])))
            D.admission(output, active['map_sha256'], a, r, O.P.digest(a), O.P.digest(r), context, 15)
            stale = O.encode(dict(json.loads(a), operation='FISH02'))
            with self.assertRaisesRegex(ValueError, 'fixed First Login operation'):
                D.admission(output, active['map_sha256'], stale, r, O.P.digest(stale), O.P.digest(r), context, 15)

    def test_public_setup_wire_rejects_malformed_or_mismatched_whole(self):
        for wire in ('', '*' * 45708, 'A' * 45708):
            with self.assertRaises(ValueError):
                O.selected_setup(wire)

    def test_read_only_pin_plan_matches_actual_composition_with_inert_certificate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            thin = O.thin(worktree, root/'thin')
            inert = b'A' * 261
            raw = ((staged/'dependency'/O.P.SETUP).read_bytes()
                   + (staged/'dependency'/(O.P.SETUP+'.sig')).read_bytes() + inert)
            setup = {**O.P.PINS['setup8'], 'certificate': {'bytes': len(inert), 'sha256': O.P.digest(inert)}}
            with patch.dict(O.P.PINS, setup8=setup):
                pins = O.plan(parent, root/'thin', thin['map_sha256'])
                actual = O.compose(parent, root/'thin', thin['map_sha256'], root/'runtime', base64.b64encode(raw).decode())
            self.assertEqual(pins['map_sha256'], actual['map_sha256'])
            self.assertEqual(pins['bytes'], actual['bytes'])
            self.assertEqual(pins['files'], actual['files'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('worktree', 'parent', 'staged'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    worktree, parent, staged = args.worktree, args.parent, args.staged
    unittest.main(argv=[__file__, '-v'])
