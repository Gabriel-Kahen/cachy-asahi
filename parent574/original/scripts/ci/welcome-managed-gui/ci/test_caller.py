"""Closed export controls using synthetic pixels and mocked native actor events."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import caller
import contract
import test_phase as fixtures


class Caller(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.Phase.setUpClass();phase=fixtures.Phase('test_exact_real_interface_sequence_seven_frames_preservation_and_retirement')
        phase.setUp()
        try:phase.run_phase();cls.events=fixtures.managed_events(phase.events);cls.lock=copy.deepcopy(phase.lock)
        finally:phase.doCleanups()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)

    def fixture(self):
        base=self.root/'base';runtime=self.root/'runtime';base.mkdir();runtime.mkdir();(runtime/'frames').mkdir()
        proof=self.root/'proof.json';proof.write_text(json.dumps(dict(status='SOURCE_PROOF_PASS',generated_runner='PASS',job_token='a'*16)))
        image='sha256:'+'b'*64
        original=dict(status='PASS_NATIVE_OFFLINE_574_TRANSACTION',image=image,ownership=dict(token='a'*16),
            owned_cleanup=dict(status='PASS',image=dict(id=image,absence_verified=True),probe=dict(absence_verified=True)))
        (base/'report.json').write_text(json.dumps(original));(base/'installed-packages.lock').write_text('fixture 1\n')
        report=dict(status='PASS_INSTALLED_WELCOME_DOCTOR_MANAGED_GUI_METADATA',configuration='desktop-container-verifier-pass',
            workflow_scope='installed-welcome-doctor-managed-gui',physical_input='NOT_RUN',candidate_input=copy.deepcopy(self.lock),
            events=copy.deepcopy(self.events),gui_contract=contract.verify_result(self.events,self.lock),base_image=image,
            runtime_package_count=593,base_reference_cleanup=dict(ok=True),cleanup=[dict(exit=0) for _ in range(13)]+[dict(guest_disk_removed=True)],frames={})
        for name in caller.FRAMES:
            path=runtime/'frames'/(name+'.ppm');path.write_bytes(b'P6\n1024 768\n255\n'+b'\1\0\0'+b'\0'*(1024*768*3-3))
            report['frames'][name]=dict(sha256=caller.digest(path))
        for name in ('guest.log','events.log'):(runtime/name).write_text('mocked actor diagnostics\n')
        (runtime/'runtime.json').write_text(json.dumps(report));(runtime/'private.raw').write_bytes(b'excluded')
        return base,runtime,proof,report,original

    def test_source_identity_native_runner_and_pins_are_required(self):
        path=self.root/'source';path.write_text('fixed')
        manifest=dict(files={'source':dict(bytes=5,sha256=caller.digest(path))})
        env=dict(SOURCE_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,RUNNER_ARCH='ARM64',RUNNER_OS='Linux',GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1')
        self.assertEqual(caller.prove(self.root,manifest,env)['status'],'SOURCE_PROOF_PASS')
        for change in (dict(GITHUB_WORKFLOW_SHA='b'*40),dict(RUNNER_ARCH='X64'),dict(SOURCE_SHA='main')):
            with self.assertRaises(ValueError):caller.prove(self.root,manifest,env|change)
        path.write_text('drift')
        with self.assertRaises(ValueError):caller.prove(self.root,manifest,env)

    def test_fourteen_exact_pixels_remain_pending_visual_and_no_private_disk_is_exported(self):
        base,runtime,proof,_,_=self.fixture();out=self.root/'public';result=caller.retain(base,runtime,proof,out)
        self.assertEqual(result['status'],'PASS_INSTALLED_GUI_METADATA_PIXELS_PENDING_VISUAL_REVIEW')
        self.assertEqual(len(result['frames']),14);self.assertEqual(result['visual_review'],'NOT_RUN')
        self.assertEqual(result['producer_input_lifecycle'],'FAIL_USER_PRESERVATION_CHECK')
        self.assertFalse((out/'runtime/private.raw').exists())
        self.assertTrue(all(r['sha256']==caller.digest(out/'frames'/(name+'.ppm')) for name,r in result['frames'].items()))

    def test_missing_guide_frame_retains_other_diagnostics_without_acceptance(self):
        base,runtime,proof,_,_=self.fixture();(runtime/'frames/overlay-recovery.ppm').unlink()
        result=caller.retain(base,runtime,proof,self.root/'public')
        self.assertEqual(result['status'],'NOT_ACCEPTED');self.assertTrue((self.root/'public/runtime/guest.log').exists())

    def test_guide_semantic_tamper_is_replayed_not_accepted_from_status(self):
        base,runtime,proof,report,_=self.fixture()
        frame=next(e for e in report['events'] if e.get('event')=='frame_ready' and e.get('view')=='first-steps')
        frame['semantic']['summary']['showing_text_sha256']=[];(runtime/'runtime.json').write_text(json.dumps(report))
        self.assertEqual(caller.retain(base,runtime,proof,self.root/'public')['status'],'NOT_ACCEPTED')

    def test_historical_input_lifecycle_fact_is_not_rewritten_to_success(self):
        base,runtime,proof,report,_=self.fixture();report['candidate_input']['producer_lifecycle']='PASS'
        (runtime/'runtime.json').write_text(json.dumps(report))
        self.assertEqual(caller.retain(base,runtime,proof,self.root/'public')['status'],'NOT_ACCEPTED')

    def test_managed_unit_and_original_base_cleanup_are_required(self):
        base,runtime,proof,report,original=self.fixture();original['owned_cleanup']['image']['absence_verified']=False
        (base/'report.json').write_text(json.dumps(original))
        self.assertEqual(caller.retain(base,runtime,proof,self.root/'public')['status'],'NOT_ACCEPTED')

    def test_caps_and_aliases_refuse_without_unbounded_output(self):
        base,runtime,proof,_,_=self.fixture()
        with patch.object(caller,'MAX_TOTAL',100):result=caller.retain(base,runtime,proof,self.root/'public')
        self.assertEqual(result['status'],'NOT_ACCEPTED');self.assertLessEqual(result['total_bytes'],100)
        alias=self.root/'alias';alias.symlink_to(proof)
        with self.assertRaises(ValueError):caller.regular(alias,1024)


if __name__=='__main__':unittest.main()
