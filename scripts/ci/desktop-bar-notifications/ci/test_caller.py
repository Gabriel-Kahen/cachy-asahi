"""Inert source-proof/public-retention controls; no native or CI actors."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import caller


class CallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def environment(self):
        return dict(SOURCE_SHA='a'*40, GITHUB_SHA='a'*40, GITHUB_WORKFLOW_SHA='a'*40,
                    RUNNER_ARCH='ARM64', RUNNER_OS='Linux', GITHUB_RUN_ID='12', GITHUB_RUN_ATTEMPT='1')

    def test_explicit_source_workflow_and_native_identity_required(self):
        file = self.root/'owned';file.write_text('source')
        manifest = dict(files={'owned':dict(bytes=file.stat().st_size,sha256=caller.digest(file))})
        good = caller.prove(self.root,manifest,self.environment())
        self.assertEqual(good['status'],'SOURCE_PROOF_PASS')
        self.assertEqual(len(good['job_token']),16)
        for change in (dict(GITHUB_WORKFLOW_SHA='b'*40),dict(SOURCE_SHA='main'),dict(RUNNER_ARCH='X64'),
                       dict(GITHUB_RUN_ID='0')):
            with self.assertRaises(ValueError):caller.prove(self.root,manifest,self.environment()|change)

    def test_source_drift_wrong_size_symlink_and_traversal_refused(self):
        file=self.root/'owned';file.write_text('source')
        record=dict(bytes=file.stat().st_size,sha256=caller.digest(file))
        for path,row in (('owned',record|dict(bytes=0)),('owned',record|dict(sha256='0'*64)),('../owned',record)):
            with self.assertRaises(ValueError):caller.prove(self.root,dict(files={path:row}),self.environment())
        (self.root/'alias').symlink_to(file)
        with self.assertRaises(ValueError):caller.prove(self.root,dict(files={'alias':record}),self.environment())

    def make_result(self):
        base=self.root/'base';runtime=self.root/'runtime';base.mkdir();runtime.mkdir()
        proof=self.root/'proof.json';proof.write_text(json.dumps(dict(status='SOURCE_PROOF_PASS',
            generated_runner='PASS',job_token='b'*16)))
        image='sha256:'+'c'*64
        original=dict(status='PASS_NATIVE_OFFLINE_574_TRANSACTION',image=image,ownership=dict(token='b'*16),
            owned_cleanup=dict(status='PASS',image=dict(id=image,absence_verified=True),probe=dict(absence_verified=True)))
        (base/'report.json').write_text(json.dumps(original));(base/'installed-packages.lock').write_text('waybar 0.15.0-3\n')
        report=dict(status='PASS_BAR_NOTIFICATION_GENERIC_ARM_SMOKE',configuration='desktop-container-verifier-pass',
            base_image=image,runtime_package_count=591,base_reference_cleanup=dict(ok=True,base_image_present=True),
            cleanup=[dict(exit=0) for _ in range(13)]+[dict(guest_disk_removed=True)],frames={},events=[])
        (runtime/'frames').mkdir()
        for stage in ('minimal','overlay'):
            file=runtime/'frames'/(stage+'.ppm')
            file.write_bytes(b'P6\n1024 768\n255\n'+b'\0'*(1024*768*3))
            observer=dict(event='frame_captured',stage=stage,sha256=caller.digest(file),first_capture=True,visual_review='NOT_RUN')
            report['frames'][stage]=dict(sha256=caller.digest(file),width=1024,height=768,observer=observer)
            report['events'].append(observer)
        (runtime/'runtime.json').write_text(json.dumps(report))
        for name in ('guest.log','events.log'):(runtime/name).write_text('bounded diagnostic\n')
        # These are deliberately excluded even though they exist next to allowlisted files.
        (runtime/'fixture').mkdir();(runtime/'fixture/guest.raw').write_bytes(b'private disk')
        (base/'context').mkdir();(base/'context/secret-input').write_bytes(b'input cache')
        return base,runtime,proof,original,report

    def test_both_actual_ppm_bytes_and_pending_visual_metadata_are_retained(self):
        base,runtime,proof,_,_=self.make_result();output=self.root/'public'
        result=caller.retain(base,runtime,proof,output)
        self.assertEqual(result['status'],'PASS_NATIVE_METADATA_PIXELS_PENDING_VISUAL_REVIEW')
        for stage in ('minimal','overlay'):
            self.assertEqual((output/'frames'/(stage+'.ppm')).read_bytes(),(runtime/'frames'/(stage+'.ppm')).read_bytes())
            self.assertEqual(result['frames'][stage]['visual_review'],'NOT_RUN')
        self.assertFalse((output/'runtime/fixture').exists());self.assertFalse((output/'base/context').exists())
        self.assertTrue((output/'retention.json').is_file())

    def test_partial_frame_failure_keeps_available_diagnostics_without_acceptance(self):
        base,runtime,proof,_,_=self.make_result();(runtime/'frames/overlay.ppm').unlink()
        result=caller.retain(base,runtime,proof,self.root/'public')
        self.assertEqual(result['status'],'NOT_ACCEPTED')
        self.assertTrue((self.root/'public/frames/minimal.ppm').exists())
        self.assertTrue((self.root/'public/runtime/guest.log').exists())

    def test_hash_mismatch_and_old_runtime_result_fail_closed(self):
        for mutation in ('hash','old','observer','event'):
            with tempfile.TemporaryDirectory() as directory:
                previous=self.root;self.root=Path(directory)
                try:
                    base,runtime,proof,_,report=self.make_result()
                    if mutation=='hash':report['frames']['minimal']['sha256']='0'*64
                    elif mutation=='old':report['status']='PASS_NATIVE_CONFIGURATION_AND_GENERIC_SOFTWARE_SESSION'
                    elif mutation=='observer':report['frames']['minimal'].pop('observer')
                    else:report['events'].clear()
                    (runtime/'runtime.json').write_text(json.dumps(report))
                    self.assertEqual(caller.retain(base,runtime,proof,self.root/'public')['status'],'NOT_ACCEPTED')
                finally:self.root=previous

    def test_owned_cleanup_absence_and_identity_are_required(self):
        base,runtime,proof,original,_=self.make_result()
        original['owned_cleanup']['image']['absence_verified']=False
        (base/'report.json').write_text(json.dumps(original))
        self.assertEqual(caller.retain(base,runtime,proof,self.root/'public')['status'],'NOT_ACCEPTED')

    def test_runtime_cleanup_failure_does_not_accept_even_with_frames(self):
        base,runtime,proof,_,report=self.make_result();report['cleanup'][0]['exit']=1
        (runtime/'runtime.json').write_text(json.dumps(report))
        self.assertEqual(caller.retain(base,runtime,proof,self.root/'public')['status'],'NOT_ACCEPTED')

    def test_missing_report_is_retained_as_explicit_failure(self):
        base,runtime,proof,_,_=self.make_result();(runtime/'runtime.json').unlink()
        result=caller.retain(base,runtime,proof,self.root/'public')
        self.assertEqual(result['status'],'NOT_ACCEPTED');self.assertTrue(result['errors'])

    def test_ppm_shape_size_and_symlink_are_refused(self):
        file=self.root/'frame.ppm';file.write_bytes(b'P6\n1 1\n255\nabc')
        with self.assertRaises(ValueError):caller.frame(file)
        alias=self.root/'alias.ppm';alias.symlink_to(file)
        with self.assertRaises(ValueError):caller.frame(alias)

    def test_retention_is_fresh_and_total_bytes_are_bounded(self):
        base,runtime,proof,_,_=self.make_result();output=self.root/'public';output.mkdir()
        with self.assertRaises(ValueError):caller.retain(base,runtime,proof,output)
        from unittest.mock import patch
        with patch.object(caller,'MAX_TOTAL',100):
            result=caller.retain(base,runtime,proof,self.root/'small-public')
        self.assertEqual(result['status'],'NOT_ACCEPTED')
        self.assertLessEqual(result['total_bytes'],100)


if __name__=='__main__':unittest.main()
