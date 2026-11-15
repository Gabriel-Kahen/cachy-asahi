# SPDX-License-Identifier: MIT
"""Passive transport workflow controls; no credential, Git or native actor."""
import importlib.util
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_owned_transport_workflow_contract',HERE/'workflow_contract.py')
W=importlib.util.module_from_spec(spec);spec.loader.exec_module(W)


class OwnedWorkflowTransportControls(unittest.TestCase):
    def test_finite_transport_before_producer_preserves_native_phase_budgets(self):
        text=(HERE/'workflow.yml.in').read_text();report=W.validate(text)
        self.assertEqual((report['steps'],report['sum_step_minutes'],report['job_minutes']),(12,134,135))
        self.assertLess(480+2,500);self.assertLess(500+30,9*60)
        rows=dict(W.steps(text)[1])
        self.assertIn('--kill-after=30s 2300s',rows['Build fresh signed original341 producer with genuine image and package lock'])
        self.assertIn('--kill-after=30s 3850s',rows['Build two independent PGO candidates from fresh producer receipts'])
        self.assertIn('--kill-after=30s 320s',rows['Retire only owned build containers before original341 producer'])
        self.assertIn('--kill-after=30s 200s',rows['Retain bounded complete public PGO evidence including nested profiles'])
        self.assertNotIn('Checkout complete original retained package inputs',rows)
        self.assertNotIn('Move the exact retained checkout to its separate runtime input path',rows)

    def test_inside_source_carrier_path_refuses(self):
        text=(HERE/'workflow.yml.in').read_text()
        changed=text.replace('--carrier "$RUNNER_TEMP/pgo-hosted-retained" --execute',
            '--carrier "$GITHUB_WORKSPACE/source-retained" --execute',1)
        with self.assertRaises(ValueError):W.validate(changed)

    def test_transport_nonzero_cannot_be_promoted_or_outer_bound_removed(self):
        text=(HERE/'workflow.yml.in').read_text()
        for before,after in(('exit "$transport_exit"','exit 0'),('--kill-after=30s 500s','500s'),
            ('timeout-minutes: 9','timeout-minutes: 500')):
            with self.subTest(before=before),self.assertRaises(ValueError):W.validate(text.replace(before,after,1))

    def test_credential_step_and_exact_precredential_command_remain_held(self):
        text=(HERE/'workflow.yml.in').read_text();reference=W.REFERENCE.read_text()
        rows=dict(W.steps(text)[1]);old=dict(W.steps(reference)[1])
        name='Seed the six exact retained inputs using existing secrets only'
        self.assertEqual(rows[name],old[name]);self.assertEqual(W.validate(text)['existing_private_secret_references'],22)
        controls=rows['Run new hosted PGO source owner and retention controls before secrets']
        self.assertEqual(controls.split('        run: |\n',1)[1],
            '          set -euo pipefail\n          python3 -B -m unittest discover -s "$SLICE" -p \'test_owned*.py\'\n')
        transport=rows[W.TRANSPORT_STEP]
        self.assertIn('set -o noclobber',transport)
        self.assertTrue(all('${transport_stream}.'+name in transport for name in('stdout','stderr','exit-code')))
        self.assertEqual(W.PHASE_ROLES['input-transport'],'RETAINED_INPUT_TRANSPORT_DATA')


if __name__=='__main__':unittest.main()
