# SPDX-License-Identifier: MIT
"""Real source closure plus pre-actor drift/null-policy refusal controls."""
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import contract as C
import prepare as P
import job as J

ROOT=Path(os.environ.get('MIRRORS_NATIVE_SOURCE',Path(__file__).resolve().parents[3]))


class Prepare(unittest.TestCase):
    def test_real_closed_context_validates_and_null_policy_refuses_before_source_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'context'
            result=P.prepare(ROOT,target,ROOT/'packages/tools/cachy-asahi-mirrors')
            self.assertIsNone(result['candidate_source']);self.assertIsNone(result['actual_source'])
            lane=target/P.LANE;manifest=J.read(lane/'source-manifest.json')
            with patch.object(C,'HERE',lane):
                C.verify_source(target);J.manifest_files(target,manifest)
                with patch.object(C,'load',side_effect=AssertionError('unbound policy reached source proof')):
                    with self.assertRaisesRegex(ValueError,'Root-bound published'):J.prove(target,manifest,{})
            workflow=(target/'.github/workflows/native-arm-mirrors-candidate.yml').read_text()
            self.assertNotIn('@JOB_SHA256@',workflow);self.assertNotIn('@MANIFEST_SHA256@',workflow)
            self.assertIn('group: native-arm-mirrors-candidates',workflow)
            self.assertNotIn('push:',workflow);self.assertNotIn('pull_request:',workflow)
            changed=target/'packages/tools/cachy-asahi-mirrors/LICENSE';changed.write_bytes(b'drift')
            with patch.object(C,'HERE',lane),self.assertRaisesRegex(ValueError,'source dependency differs'):C.verify_source(target)

    def test_original_infrastructure_drift_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);source=base/'source';source.mkdir();(source/'scripts/build').mkdir(parents=True)
            (source/'scripts/build/build.py').write_bytes(b'drift')
            with self.assertRaises(ValueError):P.prepare(source,base/'context',ROOT/'packages/tools/cachy-asahi-mirrors')
            self.assertFalse((base/'context').exists())

    def test_symlink_and_reused_output_refuse_before_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);alias=base/'alias';alias.symlink_to(ROOT,target_is_directory=True)
            with self.assertRaises(ValueError):P.prepare(alias,base/'context',ROOT/'packages/tools/cachy-asahi-mirrors')
            reused=base/'reused';reused.mkdir();(reused/'sentinel').write_bytes(b'preserve')
            with self.assertRaises(ValueError):P.prepare(ROOT,reused,ROOT/'packages/tools/cachy-asahi-mirrors')
            self.assertEqual((reused/'sentinel').read_bytes(),b'preserve')

    def test_invalid_candidate_selector_refuses_before_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'context'
            with self.assertRaises(ValueError):P.prepare(ROOT,output,ROOT/'packages/tools/cachy-asahi-mirrors','main')
            self.assertFalse(output.exists())


if __name__=='__main__':unittest.main()
