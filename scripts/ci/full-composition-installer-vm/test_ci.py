#!/usr/bin/env python3
"""Inert ordered-retirement policy controls, without launching a native actor."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('installer_candidate_ci',HERE/'ci.py')
ci=importlib.util.module_from_spec(spec); spec.loader.exec_module(ci)


class RetirementControls(unittest.TestCase):
    def test_absent_vm_and_pre_actor_failure_allow_producer_retirement(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)/'vm'; self.assertTrue(ci.vm_retired(output))
            output.mkdir(); (output/'actor-state.json').write_text(json.dumps(dict(state='PRE_ACTORS',purpose='full-composition-installer-vm')))
            self.assertTrue(ci.vm_retired(output))
    def test_started_missing_or_malformed_vm_result_retains_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)
            self.assertFalse(ci.vm_retired(output))
            (output/'actor-state.json').write_text(json.dumps(dict(state='STARTED',purpose='full-composition-installer-vm')))
            self.assertFalse(ci.vm_retired(output))
            (output/'result.json').write_bytes(b'not JSON'); self.assertFalse(ci.vm_retired(output))
    def test_uncertain_container_or_image_retirement_retains_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)
            for field in ('container_cleanup','image_cleanup'):
                for state in ('UNKNOWN','FAIL','NOT RUN'):
                    row=dict(container_cleanup='PASS',image_cleanup='PASS'); row[field]=state
                    (output/'result.json').write_text(json.dumps(row)); self.assertFalse(ci.vm_retired(output))
    def test_failed_transaction_with_confirmed_retirement_can_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)
            for image in ('PASS','NOT CREATED'):
                (output/'result.json').write_text(json.dumps(dict(status='FAIL',container_cleanup='PASS',image_cleanup=image)))
                self.assertTrue(ci.vm_retired(output))


if __name__=='__main__': unittest.main()
