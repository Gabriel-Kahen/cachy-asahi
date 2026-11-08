# SPDX-License-Identifier: MIT
"""NEW12 component source/payload DATA controls; no emitter/native/package actors."""
import argparse
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import adapter as A
import prepare as P
import rules

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--root', type=Path, default=HERE.parents[2])
parser.add_argument('--closed-source', action='store_true')
args, rest = parser.parse_known_args()
ROOT = args.root.resolve()
ACTIVE = False
ATTEMPTS = []
def fence(event, args):
    if ACTIVE and (event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.spawn', 'os.fork', 'os.posix_spawn')) or event in ('os.system', 'pty.spawn', 'os.kill', 'os.killpg')):
        ATTEMPTS.append(event)
        raise RuntimeError('component DATA actor denied: ' + event)
sys.addaudithook(fence)

def workflow_controls(here, root, closed_source):
    """Explicit caller mode; deployed Sources are checked against their real bound inputs."""
    policy=json.loads((here/'input-policy.json').read_bytes())
    if any(k not in policy or policy[k] is not None for k in ('native_source','actual_run','native_authority','resource_authority')):
        raise ValueError('actual native selectors must remain NULL')
    if closed_source:
        manifest_raw=(here/'source-manifest.json').read_bytes()
        manifest=json.loads(manifest_raw)
        if (policy.get('status')!='ROOT_BOUND_FINAL_PRODUCT_SOURCES' or manifest.get('status')!='FROZEN_ROOT_FINAL_SOURCES'
                or policy.get('candidate_source')!='438acd83fa3bcb79abe29a007ae9e8d0f784d03f'
                or policy.get('retained_input_carrier')!='3856733787d10820ab73f842e9f2bbf4fdb84181'):
            raise ValueError('explicit closed component Source required')
        raw=(root/'.github/workflows/native-arm-build.yml').read_text()
        markers=(policy['retained_input_carrier'],hashlib.sha256((here/'job.py').read_bytes()).hexdigest(),
                 hashlib.sha256(manifest_raw).hexdigest())
        if any(x in raw for x in ('@RETAINED_INPUT_SOURCE@','@JOB_SHA256@','@MANIFEST_SHA256@')):
            raise ValueError('deployed workflow placeholders refused')
        return raw,markers
    if policy.get('status')!='UNBOUND_CLIENT_V3_COMPONENT' or policy.get('candidate_source') is not None or policy.get('retained_input_carrier') is not None:
        raise ValueError('explicit maintained UNBOUND component required')
    return (here/'workflow.yml.in').read_text(),('@RETAINED_INPUT_SOURCE@','@JOB_SHA256@','@MANIFEST_SHA256@')

class Controls(unittest.TestCase):
    def setUp(self):
        global ACTIVE
        ACTIVE = True
        self.addCleanup(self.end_fence)
        self.policy = P.plan(ROOT, '438acd83fa3bcb79abe29a007ae9e8d0f784d03f')
        self.policy['retained_input_carrier'] = '3856733787d10820ab73f842e9f2bbf4fdb84181'
        self.C = A.module(ROOT, 'contract.py')

    def end_fence(self):
        global ACTIVE
        ACTIVE = False

    def tearDown(self):
        self.assertEqual(ATTEMPTS, [])

    def policy_read(self, path, *args):
        if Path(path).name == 'input-policy.json':
            return copy.deepcopy(self.policy)
        return self.original_read(path, *args)

    def bound(self):
        self.original_read = self.C.read
        return patch.object(self.C, 'read', self.policy_read)

    def test_default_actual_selectors_null_and_policy_refuses_before_actors(self):
        value = P.plan(ROOT)
        self.assertEqual(value['status'], 'UNBOUND_CLIENT_V3_COMPONENT')
        self.assertTrue(all(value[k] is None for k in ('candidate_source', 'native_source', 'actual_run', 'native_authority', 'resource_authority')))
        self.assertTrue(all(r['source_sha'] is None for r in value['products'].values()))
        original = self.C.read
        with patch.object(self.C, 'read', lambda path,*a: value if Path(path).name=='input-policy.json' else original(path,*a)):
            with self.assertRaisesRegex(ValueError, 'remain UNBOUND'):
                self.C.policy()
        if args.closed_source:
            self.assertEqual(self.C.policy()['status'], 'ROOT_BOUND_FINAL_PRODUCT_SOURCES')
        else:
            with self.assertRaisesRegex(ValueError, 'remain UNBOUND'):
                self.C.policy()

    def test_exact_current_two_recipe_source_and_runtime_dependency_closure(self):
        with self.bound():
            self.C.verify_source(ROOT)
            for name in self.C.NAMES:
                self.assertFalse(self.C.recipe(ROOT, name)['errors'])
        self.assertEqual(set(self.policy['products']), {'runtime', 'client'})
        self.assertEqual({r['version'] for r in self.policy['products'].values()}, {'0.1.0-1'})

    def test_frozen_infrastructure_and_old_factory_bytes_unchanged(self):
        for name, row in json.loads((HERE / 'infrastructure-pins.json').read_bytes()).items():
            self.assertEqual(P.PIN(ROOT / name), row)
        self.assertEqual(A.read(ROOT, A.OLD + 'run.py'), (ROOT / A.OLD / 'run.py').read_text())

    def test_exact_fifteen_disjoint_owned_payload_files_and_launcher_mode(self):
        rows = [r['payload'] for r in self.policy['products'].values()]
        self.assertEqual([len(r) for r in rows], [8, 7])
        self.assertFalse(set(rows[0]) & set(rows[1]))
        self.assertEqual(rows[1]['usr/bin/cachy-asahi-repository-client'][1], 0o755)

    def test_actual_payload_contract_rejects_extra_member_uid_and_wrong_mode(self):
        with self.bound():
            for name in self.C.NAMES:
                source = ROOT / 'packages/tools' / name
                members = {n: dict(type='0', mode=mode, uid=0, gid=0, sha256=self.C.digest(source / original)) for n, (original, mode) in self.C.files(name).items()}
                good = dict(errors=[], elf=None, members=members)
                self.C.payload(good, ROOT, name)
                for field, bad in [('uid', 1), ('mode', 0o777), ('type', '1')]:
                    changed = copy.deepcopy(good)
                    next(iter(changed['members'].values()))[field] = bad
                    with self.assertRaises(ValueError):
                        self.C.payload(changed, ROOT, name)
                changed = copy.deepcopy(good)
                changed['members']['usr/bin/unbound-extra'] = next(iter(members.values()))
                with self.assertRaises(ValueError):
                    self.C.payload(changed, ROOT, name)

    def test_two_clean_pair_routes_runtime575_and_counted_retirement(self):
        run = A.text(ROOT, 'run.py')
        job = A.text(ROOT, 'job.py')
        self.assertIn("products={C.ROLES['runtime']:build_pair", run)
        self.assertIn("products[C.ROLES['client']]=build_pair(C.ROLES['client'],runtime_image,runtime_base,runtime_lock,apps_actors)", run)
        self.assertNotIn("C.ROLES['apps']", run)
        self.assertNotIn("C.ROLES['cache']", run)
        self.assertNotIn('catalog-fixture', run)
        self.assertIn("[('base-consumers',5),('apps-consumers',2)]", job)
        self.assertIn('PASS_ORDERED_CONSUMERS_DEPENDENCY_IMAGES_PRODUCER_AND_AUTHORITY', job)

    def test_original_all_function_deadline_and_export_caps_held(self):
        run = A.text(ROOT, 'run.py')
        for marker in ('signal.setitimer(signal.ITIMER_REAL,2350)', 'len(self)<8', "out/(role+'-install.log'),600", 'limit=16*1024**2'):
            self.assertIn(marker, run)
        self.assertIn("execute(argv,directory/'build.log',240)", (ROOT / 'scripts/ci/welcome-native/run.py').read_text())
        self.assertIn("result['bytes']+info.st_size<=old.MAX_TOTAL", A.text(ROOT, 'job.py'))
        self.assertIn('MAX_TOTAL=192*1024**2', (ROOT / 'scripts/ci/tools-native/job.py').read_text())

    def test_real_verifier_wrapper_and_no_crypto_success_mock(self):
        raw = (HERE / 'rename_after_real_verification.py').read_text()
        self.assertIn('result = super().verify(data_path, signature)', raw)
        self.assertIn('result = super().bundle(root, ref, signature_sha256)', raw)
        self.assertNotIn('mock', raw.replace('crypto_success_mocks', ''))
        code = (HERE / 'installed_v3.py').read_text()
        self.assertIn("'GETINFO pid'", code)
        self.assertIn('os.pidfd_open(pid)', code)
        self.assertIn("'[GNUPG:] VALIDSIG '", code)

    def test_workflow_serialization_caps_and_explicit_qualified_carrier(self):
        raw, markers = workflow_controls(HERE, ROOT, args.closed_source)
        for marker in ('group: native-arm-apps7-client', 'cancel-in-progress: false', 'runs-on: ubuntu-24.04-arm',
                       'timeout-minutes: 100', *markers):
            self.assertIn(marker, raw)
        self.assertNotIn('04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd', raw)
        carrier = json.loads((HERE / 'retained-input-carrier.json').read_bytes())
        self.assertEqual(carrier['actual_commit'], '3856733787d10820ab73f842e9f2bbf4fdb84181')
        self.assertEqual(carrier['Root_proof']['sha256'], '11869b08c5d88a7788466cfb2df7e51f0fac1f2d72e9cf1430573187f8ae24e5')
        self.assertFalse(carrier['selected_by_default'])
        emitter = next(n for n in ast.parse((HERE / 'prepare.py').read_bytes()).body if isinstance(n, ast.FunctionDef) and n.name == 'emit')
        emitter_body = ast.unparse(emitter)
        self.assertNotIn('ORIGINAL_CARRIER', emitter_body)
        self.assertIn("carrier['tree']", emitter_body)
        self.assertEqual(carrier['historical_declared_commit'], '04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd')

    def test_all_new_derivatives_and_actor_sources_compile_without_execution(self):
        for name in ('contract.py', 'run.py', 'job.py'):
            compile(A.text(ROOT, name), name, 'exec')
        for source in HERE.glob('*.py'):
            ast.parse(source.read_bytes(), str(source))
        life = (HERE / 'lifecycle.py').read_text()
        self.assertIn("removal = [C.ROLES['client'], C.ROLES['runtime']]", life)
        self.assertIn("I.guard(L, 'lifecycle')", life)
        self.assertIn("L.inventory() == base | selected", life)
        self.assertIn("version_upgrade='NOT_RUN'", life)

    def modeled_lifecycle(self):
        """Schema test DATA only: these values never represent an observed native run."""
        stream = b'[GNUPG:] VALIDSIG MODELED_SCHEMA_DATA_ONLY\n'
        row = dict(bytes=len(stream), sha256=hashlib.sha256(stream).hexdigest(), base64=base64.b64encode(stream).decode())
        empty = dict(bytes=0, sha256=hashlib.sha256(b'').hexdigest(), base64='')
        witness = dict(completed_bundle_targets=3, state_renamed_after_all_real_signatures=True, crypto_success_mocks=0,
                       actual_verified_signatures=[{} for _ in range(5)], actual_GPG_commands=[dict(exit=0, stdout=row, stderr=empty) for _ in range(5)])
        transcript = [dict(real_rebind_verifier=witness)]
        raw = (json.dumps(transcript, sort_keys=True, separators=(',', ':')) + '\n').encode()
        control = dict(status='PASS_INSTALLED_V3_REAL_SIGNED_APPLY_AND_REBIND', actual_cli_readonly=True, actual_cli_apply=True,
            idempotent_readonly=True, rename_after_real_verification=True, refused_before_checkpoint_write=True, checkpoint_preserved=True,
            private_agent_retired=True, real_signature_checks_before_rebind=5, crypto_success_mocks=0, collected_code_imports=0,
            installed_source=True, transcript_bytes=len(raw), transcript_sha256=hashlib.sha256(raw).hexdigest(), transcript=transcript)
        events = []
        for phase, count in [('install', 576), ('same-version-reinstall', 576), ('remove', 574), ('reinstall-after-removal', 576), ('final-remove', 574)]:
            event = dict(phase=phase, count=count, base574_preserved=True, user_preserved=True)
            if count == 574:
                event['payloads_absent'] = True
            else:
                event['observations'] = [dict(home='client-v3-home-' + name, client_v3=copy.deepcopy(control)) for name in ('fresh', 'existing')]
            events.append(event)
        return dict(status='PASS_RUNTIME_CLIENT_V3_FRESH_LIFECYCLE', base_count=574, installed_count=576, architecture='aarch64',
            page_size=4096, base574_preserved=True, user_preserved=True, hardware='NOT_RUN', release='NOT_ADMITTED', version_upgrade='NOT_RUN',
            removal_order=[self.C.ROLES['client'], self.C.ROLES['runtime']], events=events)

    def test_finite_lifecycle_schema_and_whole_real_stream_transport_data(self):
        value = self.modeled_lifecycle()
        rules.validate(self.C, value)
        bad = copy.deepcopy(value)
        bad['events'][0]['observations'][0]['client_v3']['transcript'][0]['real_rebind_verifier']['actual_GPG_commands'][0]['stdout']['base64'] = ''
        with self.assertRaises(ValueError):
            rules.validate(self.C, bad)

    def test_lifecycle_refuses_missing_phase_upgrade_claim_and_incomplete_signature(self):
        value = self.modeled_lifecycle()
        for field, bad_value in [('installed_count', 577), ('page_size', 16384), ('version_upgrade', 'PASS')]:
            bad = copy.deepcopy(value)
            bad[field] = bad_value
            with self.assertRaises(ValueError):
                rules.validate(self.C, bad)
        bad = copy.deepcopy(value)
        bad['events'].pop()
        with self.assertRaises(ValueError):
            rules.validate(self.C, bad)
        bad = copy.deepcopy(value)
        bad['events'][0]['observations'][0]['client_v3']['real_signature_checks_before_rebind'] = 4
        with self.assertRaises(ValueError):
            rules.validate(self.C, bad)

if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *rest])
