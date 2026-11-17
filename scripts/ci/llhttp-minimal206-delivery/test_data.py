# SPDX-License-Identifier: MIT
"""Exercise the actual 96-file Source and local Git readback. Admission records are MODEL data."""

import argparse
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('minimal206_delivery', HERE / 'delivery.py')
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)
S = D.S

parser = argparse.ArgumentParser()
for name in ('parent', 'adoption', 'transcript'):
    parser.add_argument('--' + name, type=Path, required=True)
args, rest = parser.parse_known_args()
OPERANDS = args.parent, args.adoption, args.transcript
NOW = 1794931200


class DeliveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(prefix='minimal206-delivery-data-')
        cls.addClassCleanup(temp.cleanup)
        cls.root = Path(temp.name)
        cls.parent_bodies = S.parent_bodies(args.parent)
        cls.auth = S.adoption(args.adoption, args.transcript)
        cls.local = cls.root / 'local'
        cls.assurance = cls.root / 'assurance'
        cls.prepared = D.prepare(*OPERANDS, cls.local, cls.assurance)
        cls.checkout = cls.root / 'readback'
        D.git(cls.root, 'clone', '--quiet', '--no-local', '--branch', S.BRANCH, '--', str(cls.local), str(cls.checkout))
        cls.bodies = S.physical(cls.checkout, checkout=True)
        cls.identity = D.check_checkout(cls.checkout, cls.bodies)
        cls.actor = S.module(cls.checkout / S.NO / 'data.py', 'MODEL_actor')
        cls.contract = S.module(cls.checkout / S.NB / 'contract.py', 'MODEL_contract')
        cls.profile = S.decode(cls.bodies[S.NB + 'profile.json'])
        cls.env = dict(GITHUB_REPOSITORY=S.REPOSITORY, GITHUB_SHA=cls.identity['source'], GITHUB_REF=S.REF,
                       GITHUB_WORKFLOW_REF=f'{S.REPOSITORY}/{S.WORKFLOW}@{S.REF}',
                       GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_JOB='pair', GITHUB_RUN_ATTEMPT='1',
                       GITHUB_RUN_ID='123456')

    def setUp(self):
        self.pub = dict(self.identity, kind=D.PUBLICATION_KIND, issuer='Root', public_clone_complete=True,
                        public_blob_tree_join=True, Root_native_authority=None)
        self.reg = dict(kind=D.REGISTRATION_KIND, issuer='Root', repository=S.REPOSITORY, state='active',
                        workflow_id=123456, workflow_path=S.WORKFLOW, workflow=self.identity['workflow'],
                        registered_on_default_branch=True, registration_commit='a' * 40, observed_utc=NOW,
                        public_ref=S.REF, public_source=self.identity['source'], Root_native_authority=None)
        common = dict(accepted=True, issued_by='Root', created_utc=NOW - 1, expires_utc=NOW + 1200,
                      nonce='b' * 32, source=self.identity['source'], ref=S.REF,
                      source_map_sha256=self.identity['source_map']['sha256'],
                      resources=self.profile['resources'], builder_input_authentication=copy.deepcopy(self.auth))
        self.admit = dict(common, kind='ROOT_LLHTTP_MINIMAL206_BUILD_ONLY_HOSTED_ADMISSION_V1')
        self.runtime = dict(common, kind='ROOT_LLHTTP_MINIMAL206_BUILD_ONLY_HOSTED_RUNTIME_V1',
                            external_supervision=self.identity['program'],
                            bootstrap_resource_domain=self.identity['policy'],
                            host_tools=S.decode(self.bodies[S.NO + 'policy.json'])['host_tools'])

    def canonical(self):
        return D.canonical(*OPERANDS, self.checkout, *map(S.encode, (self.pub, self.reg, self.admit, self.runtime)), NOW)

    def actor_preflight(self, env):
        a, r = S.encode(self.admit), S.encode(self.runtime)
        return self.actor.admission(self.checkout, self.identity['source_map']['sha256'], a, r,
                                    S.pin(a)['sha256'], S.pin(r)['sha256'], env, NOW)

    def test_real_source_whole_git_readback_and_preserved_caps(self):
        changed = {name for name, raw in self.parent_bodies.items() if raw != self.bodies[name]}
        self.assertEqual(changed, {S.WORKFLOW, S.NB + 'contract.py', S.NO + 'data.py', S.NB + 'source-map.json',
                                   S.NO + 'base-binding.json', S.NO + 'owner-program.json', 'source-map.json',
                                   S.P.MARKER, S.NB + 'reviewed-inputs.json',
                                   S.NB + 'recipe/evidence/host-result.json'}
                         | {S.NO + n for n in S.E.EVIDENCE_OWNER}
                         | {S.NB + 'recipe/evidence/' + n for n in S.E.EVIDENCE_RECIPE})
        self.assertEqual(self.prepared['source'], self.identity['source'])
        self.assertEqual(self.prepared['files'], 96)
        self.assertIsNone(self.prepared['publication'])
        self.assertIsNone(self.prepared['Root_native_authority'])
        self.assertEqual(self.prepared['policy'], S.pin(self.parent_bodies[S.NO + 'policy.json']))
        self.assertEqual(self.bodies[S.WORKFLOW], (HERE.parents[2] / S.WORKFLOW).read_bytes())
        self.actor.source(self.checkout, self.identity['source_map']['sha256'])

    def test_private_preimages_only_in_restricted_assurance(self):
        before = S.authenticated_source(self.parent_bodies, public=False)
        rows = self.assurance / 'original-source'
        self.assertEqual(self.assurance.stat().st_mode & 0o777, 0o700)
        self.assertTrue(S.E.private_findings(before))
        self.assertFalse(S.E.private_findings(self.bodies))
        self.assertEqual(S.P.tree(before), S.PRIVATE_TREE)
        for name, raw in before.items():
            self.assertEqual((rows / name).read_bytes(), raw)
            self.assertEqual((rows / name).stat().st_mode & 0o777, 0o600)
        projected = S.decode(self.bodies[S.P.MARKER])['public_evidence_projection']
        private = projected['private_inverse_rows']
        self.assertEqual(len(private), 2)
        self.assertTrue(all(set(row) == {'pin', 'mode'} for row in private.values()))
        original = S.decode(before[S.P.MARKER])['changed']
        self.assertTrue(all(row['pin'] == original[key]['pin'] for key, row in private.items()))

    def test_real_recipe_review_and_host_outcomes(self):
        base = self.checkout / S.NB
        checker = S.module(base / 'runtime/scripts/checks/package_checks.py', 'public_recipe_data')
        report = checker.recipe(base / 'recipe/PKGBUILD')
        self.assertEqual(report['errors'], [])
        self.assertEqual(report['input_sha256'], S.decode(self.bodies[S.NB + 'reviewed-inputs.json']))
        rel = S.NB + 'recipe/evidence/host-result.json'
        before = S.decode(self.parent_bodies[rel])
        after = S.decode(self.bodies[rel])
        self.assertEqual(after.pop('original_log_pins'), before['logs'])
        for name, pin in after.pop('logs').items():
            self.assertEqual(pin, S.pin(self.bodies[S.NB + 'recipe/evidence/' + name]))
        before.pop('logs')
        self.assertEqual(before, after)

    def test_wrong_real_adoption_or_transcript_refused_before_output(self):
        bad = self.root / 'altered'
        for adoption_idx, path in enumerate(OPERANDS[1:], 1):
            altered = bytearray(path.read_bytes())
            altered[-1] ^= 1
            bad.write_bytes(altered)
            trio = list(OPERANDS)
            trio[adoption_idx] = bad
            output = self.root / 'never-created'
            with self.assertRaisesRegex(ValueError, 'whole exact Root r2'):
                D.prepare(*trio, output, self.root / 'never-assured')
            self.assertFalse(output.exists())

    def test_local_git_failure_does_not_leave_partial_source(self):
        output = self.root / 'partial'
        with patch.object(D, 'git', side_effect=OSError('MODEL git failure')):
            with self.assertRaises(OSError):
                D.prepare(*OPERANDS, output, self.root / 'never-assured')
        self.assertFalse(output.exists())

    def test_schema_shaped_forged_adoption_refused_by_actor_and_inner_gate(self):
        self.assertEqual(self.actor_preflight(self.env), (self.admit, self.runtime))
        self.admit['builder_input_authentication']['signatures']['sha256'] = '1' * 64
        with self.assertRaisesRegex(ValueError, 'exact Root-adopted minimal206'):
            self.actor_preflight(self.env)
        with self.assertRaisesRegex(ValueError, 'exact Root-adopted minimal206'):
            self.contract.minimal_inputs(self.admit, self.runtime, self.profile)

    def test_hosted_context_refuses_wrong_workflow_job_or_ref(self):
        for key, value in dict(GITHUB_WORKFLOW_REF='wrong', GITHUB_JOB='other', GITHUB_RUN_ATTEMPT='2',
                               GITHUB_REF='refs/heads/main', GITHUB_RUN_ID='').items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.actor_preflight(dict(self.env, **{key: value}))

    def test_canonical_returns_only_exact_five_inputs(self):
        result = self.canonical()
        self.assertEqual(result['workflow_id'], self.reg['workflow_id'])
        self.assertEqual(result['workflow_path'], S.WORKFLOW)
        self.assertEqual(result['body'], dict(ref=S.BRANCH, inputs={
            'source_map_sha256': self.identity['source_map']['sha256'],
            'admission_sha256': S.pin(S.encode(self.admit))['sha256'], 'admission_json': S.encode(self.admit).decode(),
            'runtime_sha256': S.pin(S.encode(self.runtime))['sha256'], 'runtime_json': S.encode(self.runtime).decode(),
        }))

    def test_canonical_publication_and_fresh_registration_binding(self):
        controls = ((self.pub, 'public_blob_tree_join', False), (self.pub, 'source', '1' * 40),
                    (self.reg, 'public_source', '1' * 40), (self.reg, 'workflow_id', False),
                    (self.reg, 'workflow', None), (self.reg, 'observed_utc', NOW - 600))
        for value, key, wrong in controls:
            saved = value[key]
            try:
                value[key] = wrong
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'Root.*readback required'):
                    self.canonical()
            finally:
                value[key] = saved

    def test_complete_checkout_mode_and_namespace_required(self):
        leaf = self.checkout / 'LICENSE'
        extra = self.checkout / 'unregistered'
        try:
            leaf.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'mode0644'):
                self.canonical()
            leaf.chmod(0o644)
            extra.mkdir()
            with self.assertRaisesRegex(ValueError, 'complete 96-file Source'):
                self.canonical()
        finally:
            leaf.chmod(0o644)
            if extra.exists():
                extra.rmdir()

    def test_document_hash_before_use(self):
        path = self.root / 'document'
        raw = S.encode(self.pub)
        path.write_bytes(raw)
        self.assertEqual(D.read_document(path, S.pin(raw)['sha256']), raw)
        with self.assertRaisesRegex(ValueError, 'externally pinned'):
            D.read_document(path, '1' * 64)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *rest], verbosity=2)
