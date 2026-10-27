# SPDX-License-Identifier: MIT
"""Synthetic receipt controls only; no executable, installed or native evidence."""
import copy
import unittest
import contract as V

PAYLOAD_SHA='ddd8c3cedc5ba1291dcdd2d1d7a188e5b4d4a4ac7323ffe6f7ee554f6687d41e'


def receipt_fixture():
    """TEST-ONLY receipt primitive; it never substitutes for a native command."""
    rows=[dict(case=name,mode=mode,returncode=code,stdout_sha256=V.COMPARISON_HASHES[name],
        **({'forbidden_calls':0}if mode==V.GUARDED_MODE else {})) for name,mode,code in V.COMPARISON_CASES]
    return dict(phase='install',home='product-home-fresh',status='PASS_INSTALLED_COMPARISON_SYNTHETIC_REPORT_INPUTS',
        fixture_scope='SYNTHETIC_SUPPLIED_REPORTS_NOT_COLLECTED_OBSERVATIONS',
        installed_path='/usr/bin/cachy-asahi-doctor',installed_sha256=PAYLOAD_SHA,cases=rows,
        direct_executable_cases=9,guarded_installed_code_cases=3,input_existing_file_preservation=True,
        private_output_mode='0600',private_output_preserved=True,
        no_collection_process_network='PASS_GUARDED_INSTALLED_CODE_CASES',
        comparison_oracle=dict(unchanged_count=43,changed_checks=['audio/default-output','package/linux-asahi'],change_count=2),GUI='NOT_RUN',hardware='NOT_RUN',real_audio='NOT_RUN')


class ReceiptControls(unittest.TestCase):
    def verify(self,value):return V.validate_installed_comparison(value,PAYLOAD_SHA,'install','product-home-fresh')
    def test_complete_finite_synthetic_receipt_only(self):
        result=self.verify(receipt_fixture())
        self.assertEqual(result['status'],'PASS_FINITE_INSTALLED_COMPARISON_SYNTHETIC_INPUTS_ONLY')
        self.assertEqual(result['hardware'],'NOT_RUN')
    def test_phase_and_home_context_prevent_receipt_transplant(self):
        for key,value in (('phase','same-version-reinstall'),('home','product-home-existing')):
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'context differs'):self.verify(receipt_fixture()|{key:value})

    def test_missing_extra_or_wrong_typed_top_fields_refuse(self):
        good=receipt_fixture()
        for key in good:
            bad=copy.deepcopy(good);bad.pop(key)
            with self.subTest(key=key),self.assertRaises(ValueError):self.verify(bad)
        for change in ({'extra':'invented'},{'direct_executable_cases':True},{'guarded_installed_code_cases':'3'},
            {'input_existing_file_preservation':1},{'private_output_preserved':'PASS'},{'private_output_mode':'0644'}):
            with self.subTest(change=change),self.assertRaises(ValueError):self.verify(good|change)
    def test_wrong_installed_path_or_payload_sha_refuse(self):
        for change in ({'installed_path':'/source/cachy-asahi-doctor'},{'installed_sha256':'0'*64}):
            with self.assertRaises(ValueError):self.verify(receipt_fixture()|change)
        with self.assertRaises(ValueError):V.validate_installed_comparison(receipt_fixture(),'malformed','install','product-home-fresh')
    def test_missing_duplicate_or_unordered_cases_refuse(self):
        for change in ('missing','extra','duplicate','reversed'):
            bad=receipt_fixture()
            if change=='missing':bad['cases'].pop()
            elif change=='extra':bad['cases'].append(copy.deepcopy(bad['cases'][0]))
            elif change=='duplicate':bad['cases'][1]=copy.deepcopy(bad['cases'][0])
            else:bad['cases'].reverse()
            with self.subTest(change=change),self.assertRaises(ValueError):self.verify(bad)
    def test_each_case_result_mode_exit_and_hash_are_mandatory(self):
        good=receipt_fixture()
        for index in range(12):
            for key,value in (('case','substitute'),('mode','FIXTURE_PASS'),('returncode',True),('returncode',3),
                ('stdout_sha256','0'*64),('extra',1)):
                bad=copy.deepcopy(good);bad['cases'][index][key]=value
                with self.subTest(index=index,key=key),self.assertRaises(ValueError):self.verify(bad)
    def test_guarded_collection_process_network_attempts_refuse(self):
        for index in range(9,12):
            for change in ('missing',1,False,'0'):
                bad=receipt_fixture()
                if change=='missing':bad['cases'][index].pop('forbidden_calls')
                else:bad['cases'][index]['forbidden_calls']=change
                with self.subTest(index=index,change=change),self.assertRaises(ValueError):self.verify(bad)
    def test_finite_oracle_must_keep_exact_two_supplied_changes(self):
        for change in ({'unchanged_count':True},{'change_count':3},{'changed_checks':['package/m1n1']},{'extra':'invented'}):
            bad=receipt_fixture();bad['comparison_oracle'].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):self.verify(bad)
    def test_fixture_scope_and_unrun_hardware_boundaries_cannot_be_promoted(self):
        good=receipt_fixture()
        for key in ('fixture_scope','status','no_collection_process_network','GUI','hardware','real_audio'):
            with self.subTest(key=key),self.assertRaises(ValueError):self.verify(good|{key:'PASS_NATIVE_HARDWARE'})


if __name__=='__main__':unittest.main(verbosity=2)
