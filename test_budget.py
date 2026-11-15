# SPDX-License-Identifier: MIT
"""Physical allocation DATA controls; no retained images/archives or actors."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parent

def load(name):
    spec=importlib.util.spec_from_file_location('budget_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

R,K=load('runtime'),load('contracts')


class BudgetControls(unittest.TestCase):
    def test_sparse_logical_length_is_not_charged_as_allocated_bytes(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);p=root/'sparse-DATA'
            with p.open('wb') as stream:stream.truncate(1024**2)
            actual=p.stat().st_blocks*512
            self.assertLess(actual,p.stat().st_size)
            R.component_limits(root,((p,max(1,actual)),))
            with p.open('r+b') as stream:stream.write(b'FENCED'*1024);stream.flush()
            with self.assertRaisesRegex(ValueError,'allocated-byte'):R.component_limits(root,((p,1),))

    def test_component_observations_refuse_links_or_outside_paths(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);(root/'file').write_text('FENCED');(root/'link').symlink_to(root/'file')
            for p in (root/'link',root.parent/'outside'):
                with self.assertRaises(ValueError):R.component_limits(root,((p,4096),))

    def test_independent_physical_envelopes_and_historical_budget_retained(self):
        b=json.loads((HERE/'data/allocated-budget-v2.json').read_text());limits=b['limits'];model=b['model']
        self.assertEqual(model['prepare_peak_envelope_bytes'],limits['extended_raw_allocated']+limits['prefix_allocated']+limits['output_metadata_allocated'])
        self.assertEqual(model['boot_peak_envelope_bytes'],limits['overlay']+limits['extended_raw_allocated']+limits['output_metadata_allocated'])
        self.assertLess(model['prepare_peak_envelope_bytes'],K.RESOURCES['prepare_allocated_cap'])
        self.assertLess(model['boot_peak_envelope_bytes'],K.RESOURCES['boot_allocated_cap'])
        self.assertEqual((model['archive_copies'],model['baseline_exports'],model['readback_exports']),(0,0,0))
        old=json.loads((HERE/'data/budget-history-d8c10ee2.json').read_text())
        self.assertEqual(old['initial_quota_headroom'],dict(prepare=8*K.GIB,boot=6*K.GIB))
        self.assertEqual(K.RESOURCES['prepare_allocated_cap']+K.RESOURCES['reserve_bytes'],4*K.GIB)
        self.assertEqual(K.RESOURCES['boot_allocated_cap']+K.RESOURCES['reserve_bytes'],4608*1024**2)


if __name__=='__main__':unittest.main()
