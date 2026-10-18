# SPDX-License-Identifier: MIT
"""The fixed Git carriers have two nested packets and four flat roots."""
from pathlib import Path
import re
import unittest

HERE=Path(__file__).resolve().parent


class CarrierPaths(unittest.TestCase):
    def test_gate_runtime_and_positive_controls_use_exact_packet_roots(self):
        workflow=(HERE.parents[2]/'.github/workflows/native-arm-expanded604.yml').read_text()
        for role in ('legacy','eight','seven','management','setup','welcome'):
            suffix='/payload' if role in ('management','welcome') else ''
            with self.subTest(role=role):
                operands=re.findall(r'--'+role+r'-source "([^"\n]+)"',workflow)
                self.assertEqual(operands,['$GITHUB_WORKSPACE/expanded604-'+role+suffix]*2)
                values=re.findall(r'^          EXPANDED604_'+role.upper()+r'_ROOT: (.+)$',workflow,re.M)
                self.assertEqual(values,['${{ github.workspace }}/expanded604-'+role+suffix])


if __name__=='__main__':unittest.main()
