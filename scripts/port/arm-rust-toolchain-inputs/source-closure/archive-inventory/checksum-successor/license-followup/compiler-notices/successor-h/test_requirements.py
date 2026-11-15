"""Routing coverage/current-proof fences; no acquisition or case acceptance."""
import copy
import importlib.util
import json
from pathlib import Path
import resource
import signal
import unittest

HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location('notice_h',HERE/'requirements.py')
review=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(review)
DATA=json.loads((HERE/'requirements.json').read_text())
ROWS={r['component']:r for r in DATA['components']}
PACKET=Path('/tmp/cachy-checksum-successor-20261115-03/private-license-candidates.json')


class Controls(unittest.TestCase):
    def test_all90_exactly_once_zero_credit_selected12_exclude_G12(self):
        baseline=json.loads((HERE/'../successor-g/report.json').read_text())
        self.assertEqual(set(ROWS),set(baseline['remaining_components']))
        self.assertEqual(len(DATA['components']),90)
        self.assertEqual(len(DATA['selected_components']),12)
        self.assertFalse(set(DATA['selected_components'])&set(baseline['screened_components']))
        self.assertTrue(all(r['closure_credit']==0 for r in ROWS.values()))
        for key,group in DATA['routing_groups'].items():
            self.assertEqual(group,[r['component'] for r in DATA['components'] if r['requirements'][key]['status']=='UNRESOLVED'])
        for row in ROWS.values():
            unresolved=[key for key in review.PRIORITY if row['requirements'][key]['status']=='UNRESOLVED']
            self.assertEqual(row['next_route'],unresolved[0])
            self.assertEqual(row['requirements']['package_notice']['status'],'UNRESOLVED')

    def test_satisfied_wasm_versions_not_reopened_and_file_notice_not_package(self):
        for name in ['wasm-encoder-0.219.2','wasmparser-0.219.2','wasmparser-0.243.0']:
            row=ROWS[name]
            self.assertEqual(row['requirements']['workspace']['status'],'SATISFIED')
            self.assertTrue(row['requirements']['workspace']['detail']['version_proof_ref'])
            self.assertIsNone(row['ready_manifest_request'])
            self.assertEqual(row['requirements']['package_notice']['status'],'UNRESOLVED')
        self.assertIn('UPSTREAM_FILE_ONLY',ROWS['wasmparser-0.219.2']['current_file_notice']['status'])
        self.assertEqual(ROWS['wasmparser-0.243.0']['current_file_notice']['status'],'EXACT_VENDOR_AND_UPSTREAM_FILE_ONLY')

    def test_dirty_generated_and_missing_lineage_remain_distinct(self):
        self.assertEqual(set(DATA['routing_groups']['dirty_source']),{'spanned-0.4.1','vex-sdk-0.27.1'})
        for name in DATA['routing_groups']['dirty_source']:
            self.assertTrue(ROWS[name]['original_metadata']['dirty_flag'])
            self.assertEqual(ROWS[name]['next_route'],'dirty_source')
            request=ROWS[name]['ready_manifest_request']
            self.assertTrue(request is None or not request['automatic_fetch_recommended'])
        self.assertEqual(len(DATA['routing_groups']['publisher_transform']),11)
        for name in DATA['routing_groups']['publisher_transform']:
            row=ROWS[name]
            self.assertIsNone(row['original_metadata']['declared_revision'])
            self.assertEqual(row['next_route'],'publisher_transform')
            self.assertEqual(row['requirements']['publisher_transform']['detail']['declared_Rust_source_commit'],'ce89c898570852a1bb441d77570596e50bf362c2')
            self.assertFalse(row['publisher_metadata_lookup']['automatic_fetch_recommended'])

    def test_truncated_manifest_requests_have_full_hash_and_do_not_clear_SDK(self):
        self.assertEqual(len(DATA['routing_groups']['original_manifest']),5)
        for name,size in [('objc2-cloud-kit-0.3.2',9909),('objc2-core-data-0.3.2',11766),('objc2-ui-kit-0.3.2',63556)]:
            row=ROWS[name];request=row['ready_manifest_request']
            self.assertEqual(row['next_route'],'original_manifest')
            self.assertEqual(row['original_metadata']['captured_prefix_bytes'],8192)
            self.assertEqual(request['expected_original_body_pin']['bytes'],size)
            self.assertIn('ref=7b1abfd750a2cacaea71d6a56ecfb83cb7de560b',request['candidate_url'])
            self.assertTrue(request['automatic_fetch_recommended'])
            self.assertEqual(row['requirements']['sdk_scope']['status'],'UNRESOLVED')
        for name in ['mac-0.1.1','quine-mc_cluskey-0.2.4']:
            self.assertIsNone(ROWS[name]['original_metadata']['manifest_pin'])
            self.assertEqual(ROWS[name]['requirements']['workspace']['status'],'DEFERRED')

    def test_retained_tree_candidates_are_offline_and_not_promoted(self):
        for name in ['anes-0.1.6','ui_test-0.30.7','block2-0.6.2','objc2-0.6.3']:
            row=ROWS[name]
            self.assertTrue(row['offline_manifest_candidates'])
            self.assertIsNone(row['ready_manifest_request'])
            self.assertEqual(row['requirements']['manifest_git']['status'],'UNRESOLVED')
            self.assertIn('CANDIDATE_ONLY',row['offline_manifest_candidates'][0]['status'])
        self.assertEqual(ROWS['perf-event-open-sys-3.0.0']['requirements']['source_lineage']['status'],'SATISFIED')
        self.assertEqual(ROWS['perf-event-open-sys-4.0.0']['requirements']['source_lineage']['status'],'UNRESOLVED')

    def test_hifijson_correction_and_nonownership_nondeployment_boundaries(self):
        row=ROWS['hifijson-0.5.0']
        self.assertTrue(row['original_metadata']['declared_revision_is_40_hex'])
        self.assertEqual(len(row['original_metadata']['declared_revision']),40)
        self.assertEqual(row['requirements']['source_lineage']['detail']['observed_failed_primary']['HTTP'],422)
        self.assertEqual(row['next_route'],'source_lineage')
        self.assertEqual(len(DATA['routing_groups']['sdk_scope']),13)
        for name in ['block2-0.6.2','objc2-0.6.3','objc2-encode-4.1.0']:
            self.assertNotIn(name,DATA['routing_groups']['sdk_scope'])
        self.assertTrue(all(r['source_cleanliness_actual_target_activation_all_file_legal_native_M2_release_acceptance']=='HELD' for r in ROWS.values()))
        hold=DATA['retained_cross_cutting_holds']['object_manifest_correspondence']
        self.assertNotEqual(hold['authenticated_vendor_pin'],hold['published_source_pin'])

    def test_metadata_capture_and_candidate_URL_are_not_acceptance(self):
        self.assertEqual(review.package_metadata(None),({},'ABSENT'))
        prefix=b'[package]\nname="one"\nversion.workspace=true\n\n[features]\nvalue=["cut'
        record={'text':prefix.decode(),'complete_text':False,'captured_bytes':len(prefix),'captured_prefix_sha256':review.pin(prefix)['sha256']}
        package,state=review.package_metadata(record)
        self.assertEqual(state,'CAPTURED_PACKAGE_TABLE_ONLY')
        self.assertEqual(package['version'],{'workspace':True})
        with self.assertRaisesRegex(ValueError,'prefix pin'):
            review.package_metadata({**record,'captured_prefix_sha256':'0'*64})
        self.assertEqual(review.candidate_repository({'repository':{'workspace':True}},None,'unknown-1'),(None,'UNESTABLISHED'))
        self.assertIsNone(review.metadata_request('owner/repo',None,'Cargo.toml',None,False))

    def test_network_caps_errors_and_closed_acquisition(self):
        ledger=json.loads((HERE/'requests.json').read_text())
        result=review.network_summary(ledger)
        self.assertEqual((result['new_actual_HTTP_requests'],result['new_response_body_bytes'],result['error_requests']),(5,24084,[2,3]))
        for patch in [{'stopped_epoch':ledger['started_epoch']+901},{'body_bytes':0},{'acquisition_closed':False},
                      {'requests':[{'ordinal':i,'bytes':0} for i in range(1,52)],'body_bytes':0},
                      {'requests':[{'ordinal':1,'bytes':128*1024+1}],'body_bytes':128*1024+1},
                      {'requests':[{'ordinal':i,'bytes':128*1024} for i in range(1,18)],'body_bytes':17*128*1024}]:
            with self.subTest(patch=patch),self.assertRaises(ValueError): review.network_summary({**ledger,**patch})
        spec=importlib.util.spec_from_file_location('finite_h_fetch',HERE/'fetch.py');fetch=importlib.util.module_from_spec(spec);spec.loader.exec_module(fetch)
        with self.assertRaisesRegex(ValueError,'acquisition closed'):fetch.acquire('https://api.github.com/repos/unused/unused','unused.json')

    @unittest.skipUnless(PACKET.exists(),'private source packet deliberately not distributed')
    def test_complete_offline_routing_regeneration(self):
        self.assertEqual(review.build(PACKET),DATA)


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2));signal.alarm(30);unittest.main()
