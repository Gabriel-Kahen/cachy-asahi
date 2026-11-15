# SPDX-License-Identifier: MIT
"""Check proposed phase maxima against real workflow timeout envelopes."""
import json
from pathlib import Path
import re
import unittest

HERE=Path(__file__).resolve().parent
P=json.loads((HERE/'payload/resource-policy.json').read_bytes());W=(HERE/'workflow.yml.in').read_text()

class ResourceControls(unittest.TestCase):
    def test_phase_ledgers_include_both_cleanup_layers(self):
        b=P['bootstrap'];self.assertEqual(b['native_seconds'],sum(b[k]for k in ('provider_seconds','delivery_seconds','retained_seconds','signed349_seconds','normal_image_seconds','qualification_seconds','qualification_cleanup_seconds','image_save_seconds')))
        b=P['build'];self.assertEqual(b['native_seconds'],sum(b[k]for k in ('provider_seconds','transfer_seconds','prepare_seconds','main_seconds','producer_cleanup_seconds','export_seconds')))
        self.assertLessEqual(b['image_import_seconds'],b['transfer_seconds']);self.assertEqual(b['main_seconds'],16200)
    def test_workflow_steps_and_outer_timeouts_fit(self):
        blocks=dict(re.findall(r'^  (bootstrap|build):\n(.*?)(?=^  [a-z]+:|\Z)',W,re.M|re.S))
        for phase,block in blocks.items():
            budget=P[phase];job=int(re.search(r'^    timeout-minutes: (\d+)',block,re.M)[1])
            steps=[int(n)for n in re.findall(r'^        timeout-minutes: (\d+)',block,re.M)]
            self.assertEqual(job,budget['job_minutes']);self.assertLessEqual(sum(steps),job)
            native=re.search(r'timeout-minutes: (\d+)\n        env:\n          GH_TOKEN:.*?timeout --signal=TERM --kill-after=(\d+)s (\d+)s python3',block,re.S)
            self.assertIsNotNone(native);minutes,kill,outer=map(int,native.groups())
            self.assertGreaterEqual(outer,budget['native_seconds']+budget['cleanup_seconds']);self.assertLess(outer+kill,60*minutes)
        self.assertEqual(sum(P[k]['job_minutes']for k in ('bootstrap','build')),P['workflow_job_minutes_max'])
    def test_shared_queue_and_distinct_bounded_transfer(self):
        self.assertIn('group: native-arm-build',W);self.assertIn('queue: max',W);self.assertIn('cancel-in-progress: false',W)
        self.assertIn('needs: bootstrap',W);self.assertEqual(P['phase_transfer']['requests'],7)
        self.assertEqual(P['phase_transfer']['image_bytes'],12*1024**3);self.assertEqual(P['phase_transfer']['artifact_bytes'],16*1024**3)
        self.assertEqual(P['actor']['capabilities'],[]);self.assertEqual(P['actor']['swap_bytes'],0)

if __name__=='__main__':unittest.main()
