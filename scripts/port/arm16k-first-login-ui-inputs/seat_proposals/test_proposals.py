# SPDX-License-Identifier: MIT
import importlib.util,json,subprocess,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('test_seat_proposals',HERE/'propose.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
class Controls(unittest.TestCase):
    def test_bare_provider_ambiguity_remains_a_failure(self):
        d=json.loads((HERE/'actual-results.json').read_text())['bare_four_roots'];self.assertTrue(d['metadata_status'].startswith('HOLD'));self.assertTrue(any(v.get('requires')=='libxtables.so=12-64'for v in d['prepare_errors']))
    def test_minimal_and_UI_are_distinct_explicit_proposals(self):
        data=json.loads((HERE/'actual-results.json').read_text());m=data['minimal_explicit_iptables'];ui=data['UI_plus_NM_explicit_iptables'];self.assertEqual((m['preserved_baseline'],m['additions'],m['total']),(111,44,155));self.assertEqual(ui['additions'],172);self.assertEqual(len(ui['incremental_to_old145']),27);self.assertEqual(m['metadata_status'],'PASS_EXPLICIT_FINITE_METADATA_PREPARE');self.assertNotIn('gtk4',{r['name']for r in m['packages']});self.assertIn('iptables',{r['name']for r in m['roots']})
    def test_real_ARM_policy_matches_actual_source_pin_without_guest_claim(self):
        p=json.loads((HERE/'actual-results.json').read_text())['real_ARM_NM_policy']['result'];self.assertTrue(p['policy']['exact_x86_source_bytes_match']);self.assertEqual(p['policy']['sha256'],P.POLICY_SHA);self.assertEqual(p['policy']['defaults']['allow_active'],'yes');self.assertEqual(p['actual_guest_policy_install_session_authentication'],'NOT RUN')
    def test_optimization_refuses_before_input(self):
        r=subprocess.run([sys.executable,'-I','-O','-B',str(HERE/'propose.py'),'--proposal','minimal-seat','--output','/nonexistent/unused'],capture_output=True,text=True,timeout=5);self.assertEqual(r.returncode,2);self.assertIn('assertions must remain enabled',r.stderr)
if __name__=='__main__':unittest.main()
