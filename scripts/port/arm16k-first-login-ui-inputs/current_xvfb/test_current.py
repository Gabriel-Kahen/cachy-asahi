# SPDX-License-Identifier: MIT
import importlib.util,json,subprocess,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('test_current_static',HERE/'static_audit.py');S=importlib.util.module_from_spec(s);s.loader.exec_module(S)
class Controls(unittest.TestCase):
    def test_legacy_symbol_is_not_an_unversioned_default(self):
        _,exports=S.symbols('1: 0000 1 FUNC GLOBAL DEFAULT 1 old@GLIBC_2.17\n2: 0000 1 FUNC GLOBAL DEFAULT 1 current@@GLIBC_2.17\n3: 0000 1 FUNC GLOBAL DEFAULT 1 plain')
        self.assertFalse(exports['old@GLIBC_2.17']['default_export']);self.assertTrue(exports['current@GLIBC_2.17']['default_export']);self.assertTrue(exports['plain']['default_export'])
    def test_version_requirements_keep_exact_needed_namespace(self):
        self.assertEqual(S.version_needs("Version needs section '.gnu.version_r' contains 2 entries:\n  0: Version: 1 File: libc.so.6 Cnt: 1\n  1: Name: GLIBC_2.38 Flags: none Version: 2\n  2: Version: 1 File: libm.so.6 Cnt: 1\n  3: Name: GLIBC_2.17 Flags: none Version: 3"),{'libc.so.6':['GLIBC_2.38'],'libm.so.6':['GLIBC_2.17']})
    def test_actual_candidate_is_separate_and_statically_held(self):
        d=json.loads((HERE/'actual-result.json').read_text());self.assertEqual(d['version'],'21.1.26-1');self.assertEqual(d['metadata']['baseline_preserved'],111);self.assertEqual(d['metadata']['total'],256);self.assertEqual(d['static']['direct_needed_providers'],12);self.assertTrue(d['static']['all_direct_symbols_found']);self.assertFalse(d['static']['missing_needed_version_namespaces']);self.assertTrue(d['status'].startswith('HOLD_'))
    def test_optimization_refuses_before_input_or_network(self):
        for name,args in [('acquire.py',['--discovered-root','/nonexistent']),('static_audit.py',['--root','/nonexistent','--proposal','/nonexistent'])]:
            r=subprocess.run([sys.executable,'-I','-O','-B',str(HERE/name),*args],capture_output=True,text=True,timeout=5);self.assertEqual(r.returncode,2);self.assertIn('assertions must remain enabled',r.stderr)
if __name__=='__main__':unittest.main()
