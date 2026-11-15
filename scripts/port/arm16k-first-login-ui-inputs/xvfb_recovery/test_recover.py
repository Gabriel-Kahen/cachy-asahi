# SPDX-License-Identifier: MIT
import importlib.util,json,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('test_Xvfb_recover',HERE/'recover.py');R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
class Controls(unittest.TestCase):
    def test_only_exact_original_xvfb_identity(self):
        d=json.loads((HERE.parent/'six_pair_intake/inputs.json').read_text());p=next(v for v in d['pairs']if v['name']=='xorg-server-xvfb')['archive']
        self.assertEqual((R.NAME,R.SHA,R.SIG),(p['filename'],p['sha256'],p['signature_sha256']));self.assertEqual((p['bytes'],p['signature_bytes']),(705376,566))
    def test_archive_metadata_cannot_supply_foreign_or_traversing_path(self):
        html='<a href="https://foreign.invalid/archive">bad</a><a href="repos/../../bad">bad</a><a href="packages/">good</a>'
        self.assertEqual(R.archive_paths(html,'https://tardis.tiny-vps.com/aarm/'),['https://tardis.tiny-vps.com/aarm/packages/'])
    def test_tls_and_global_request_boundary_is_existing_strict_adapter(self):
        self.assertTrue(R.I.official('https://fl.us.mirror.archlinuxarm.org/aarch64/extra/'+R.NAME))
        with self.assertRaises(ValueError):R.I.official('http://fl.us.mirror.archlinuxarm.org/aarch64/extra/'+R.NAME)
        budget=R.I.Budget();budget.started-=181
        with self.assertRaises(TimeoutError):budget.remaining()
    def test_actual_terminal_holds_preserve_inputs(self):
        d=json.loads((HERE/'actual-result.json').read_text());self.assertEqual(d['status'],'HOLD_EXACT_XVFB_UNAVAILABLE');self.assertEqual(d['initial_requests'],11);self.assertLessEqual(d['seconds'],180);self.assertEqual(d['response_body_bytes'],15703);self.assertTrue(d['five_pairs_and_original_receipt_unchanged']);self.assertFalse(d['archive_pair_recovered'])
if __name__=='__main__':unittest.main()
