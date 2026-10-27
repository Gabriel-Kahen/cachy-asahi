# SPDX-License-Identifier: MIT
"""Registered-alias construction and pre-secret closure; no actor/API execution."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import contract as C
import job as J
import prepare as P

ROOT=Path(os.environ.get('MIRRORS_NATIVE_SOURCE',Path(__file__).resolve().parents[3]))
ALIAS='.github/workflows/native-arm-build.yml'
DEDICATED='.github/workflows/native-arm-mirrors-candidate.yml'


class Registered(unittest.TestCase):
    def context(self,tmp):
        target=Path(tmp)/'context';P.prepare(ROOT,target,ROOT/'packages/tools/cachy-asahi-mirrors')
        return target,target/P.LANE

    def test_exact_alias_and_presecret_null_policy_with_subprocess_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,lane=self.context(tmp);manifest=J.read(lane/'source-manifest.json')
            with patch.object(C,'HERE',lane),patch.object(J.subprocess,'Popen',side_effect=AssertionError('actor before proof')) as blocked:
                J.manifest_files(source,manifest);C.verify_source(source)
                binding=J.workflow_binding(source,manifest)
                self.assertEqual((source/ALIAS).read_bytes(),(source/DEDICATED).read_bytes())
                self.assertEqual(binding['sha256'],C.digest(source/ALIAS));self.assertEqual(binding['paths'],[DEDICATED,ALIAS])
                with self.assertRaisesRegex(ValueError,'Root-bound published'):J.prove(source,manifest,{})
                blocked.assert_not_called()
            authorization=J.read(source.parent/(source.name+'-authorization.json'))['files']
            self.assertEqual(authorization[ALIAS],authorization[DEDICATED])
            for field in ('candidate_source','actual_source','actual_ref','actual_run'):
                self.assertIsNone(J.read(lane/'input-policy.json')[field])

    def test_alias_drift_or_absence_refuses_before_null_policy_or_actors(self):
        for mutation in ('drift','missing'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as tmp:
                source,lane=self.context(tmp);manifest=J.read(lane/'source-manifest.json')
                if mutation=='drift':(source/ALIAS).write_bytes((source/ALIAS).read_bytes()+b'\n')
                else:(source/ALIAS).unlink()
                with patch.object(C,'HERE',lane),patch.object(J.subprocess,'Popen',side_effect=AssertionError('actor before proof')) as blocked:
                    with self.assertRaises((ValueError,FileNotFoundError)):J.prove(source,manifest,{})
                    blocked.assert_not_called()

    def test_both_workflows_identically_tampered_still_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,lane=self.context(tmp);manifest=J.read(lane/'source-manifest.json')
            for name in (ALIAS,DEDICATED):(source/name).write_bytes((source/name).read_bytes().replace(b'timeout-minutes: 100',b'timeout-minutes: 101'))
            with patch.object(C,'HERE',lane),patch.object(J.subprocess,'Popen',side_effect=AssertionError('actor before proof')):
                with self.assertRaisesRegex(ValueError,'workflow bytes differ'):J.prove(source,manifest,{})

    def test_stale_embedded_manifest_hash_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,lane=self.context(tmp);manifest=J.read(lane/'source-manifest.json');manifest['extra']='drift'
            J.save(lane/'source-manifest.json',manifest)
            with patch.object(C,'HERE',lane),patch.object(J.subprocess,'Popen',side_effect=AssertionError('actor before proof')):
                with self.assertRaisesRegex(ValueError,'workflow bytes differ'):J.prove(source,manifest,{})

    def test_manifest_binding_drift_or_alternate_manifest_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,lane=self.context(tmp);manifest=J.read(lane/'source-manifest.json')
            for mutation in ('binding','manifest'):
                bad=json.loads(json.dumps(manifest))
                if mutation=='binding':bad['workflow_binding']['paths']=[DEDICATED]
                else:bad['extra']='alternate'
                with self.subTest(mutation=mutation),patch.object(C,'HERE',lane),self.assertRaises(ValueError):J.workflow_binding(source,bad)


if __name__=='__main__':unittest.main()
