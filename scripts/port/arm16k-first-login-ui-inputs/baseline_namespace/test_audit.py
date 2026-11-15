# SPDX-License-Identifier: MIT
import copy,importlib.util,json,subprocess,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('test_ARM111_namespace',HERE/'audit.py');A=importlib.util.module_from_spec(s);s.loader.exec_module(A)
class Controls(unittest.TestCase):
    def fixture(self):
        # Inert join fixture based on real111 identity metadata, no image reads.
        base=json.loads((HERE.parent/'baseline111.json').read_text());packages=[{'name':r['name'],'version':r['version'],'directory':r['name']+'-'+r['version'],'desc':r['desc']}for r in base['packages']];selection={'packages':packages,'paths':['usr/lib/fixture']};index={'packages':{r['directory']:{'desc':copy.deepcopy(r['desc']),'files':{}}for r in packages}};index['packages'][next(r['directory']for r in packages if r['name']=='glib2')]['files']={'FILES':['usr/lib/fixture']};prepared={'base_packages':[{k:r[k]for k in ['name','version','directory']}for r in packages]};return selection,index,prepared
    def test_exact_prepared_identity_and_directory_required(self):
        selected,index,prepared=self.fixture();self.assertEqual(len(A.join_rows(selected,index,prepared)),111);prepared['base_packages'][0]['directory']='foreign'
        with self.assertRaises(AssertionError):A.join_rows(selected,index,prepared)
    def test_package_provides_and_owned_paths_cannot_be_inferred(self):
        selected,index,prepared=self.fixture();rows=A.join_rows(selected,index,prepared);self.assertEqual(rows['glib2']['files'],['usr/lib/fixture']);self.assertIn('libgio-2.0.so=0-64',rows['glib2']['provides']);index['packages'][selected['packages'][0]['directory']]['files']={'FILES':['not-selected']}
        with self.assertRaises(AssertionError):A.join_rows(selected,index,prepared)
    def test_literal_linux_filename_preserved_and_traversal_refused(self):
        name=r'usr/lib/systemd/system/system-systemd\x2dcryptsetup.slice';self.assertEqual(A.canonical(name),name)
        for path in ['/absolute','a/../b','a//b','a\nb']:
            with self.assertRaises(AssertionError):A.canonical(path)
    def test_raw_stat_metadata_is_observed_not_assumed(self):
        result=subprocess.CompletedProcess([],0,'Inode: 3 Type: regular Mode:  0640\nUser: 12 Group: 34 Project: 0 Size: 42\n','')
        with patch.object(A.subprocess,'run',return_value=result):self.assertEqual(A.actual_stat(Path('/inert/raw'),'etc/pam.d/login'),{'type':'0','mode':0o640,'uid':12,'gid':34,'bytes':42,'link':''})
    def test_actual_output_pins_and_scope(self):
        d=json.loads((HERE/'actual-result.json').read_text());self.assertEqual(d['counts']['packages'],111);self.assertEqual(d['counts']['actual_raw_metadata_files'],222);self.assertEqual(d['counts']['fixed_namespace_leaves'],7);self.assertTrue(d['raw_SHA256_verified_before_and_after']);self.assertEqual(d['required_namespace']['usr/lib/girepository-1.0/Gio-2.0.typelib']['owner'],'glib2');self.assertTrue(d['no_archive44_authentication_guest_policy_install_execution'])
if __name__=='__main__':unittest.main()
