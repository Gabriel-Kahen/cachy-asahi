# SPDX-License-Identifier: MIT
"""Closed public export: mocked native metadata and synthetic pixels only."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import caller
import contract
import test_keyboard as fixtures


class Caller(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
    def fixture(self):
        base=self.root/'base';runtime=self.root/'runtime';base.mkdir();runtime.mkdir();(runtime/'frames').mkdir()
        proof=self.root/'proof.json';proof.write_text(json.dumps(dict(status='SOURCE_PROOF_PASS',generated_runner='PASS',job_token='a'*16)))
        image='sha256:'+'b'*64
        original=dict(status='PASS_NATIVE_OFFLINE_574_TRANSACTION',packages=574,image=image,ownership=dict(token='a'*16),
            owned_cleanup=dict(status='PASS',image=dict(id=image,absence_verified=True),probe=dict(absence_verified=True)))
        (base/'report.json').write_text(json.dumps(original))
        source=Path(__file__).resolve().parents[5]
        # Artifact tests use current held source; canonical test runs use repository ancestry.
        if not (source/'scripts/ci/maintained-desktop574-inputs.json').exists():
            source=next(p for p in Path(__file__).resolve().parents if (p/'scripts/ci/maintained-desktop574-inputs.json').exists())
        lock=json.loads((source/'scripts/ci/maintained-desktop574-inputs.json').read_text())
        (base/'installed-packages.lock').write_text(''.join(r['name']+' '+r['version']+'\n' for r in sorted(lock['packages'],key=lambda r:r['name'])))
        events=fixtures.events()
        report=dict(status='PASS_MANAGED_VIRTUAL_KEYBOARD_METADATA',configuration='desktop-container-verifier-pass',
            workflow_scope='managed-virtual-keyboard',physical_input='NOT_RUN',events=events,keyboard_contract=contract.verify_result(events),
            base_image=image,runtime_package_count=591,base_reference_cleanup=dict(ok=True),cleanup=[dict(exit=0) for _ in range(13)]+[dict(guest_disk_removed=True)],frames={})
        for name in caller.FRAMES:
            path=runtime/'frames'/(name+'.ppm');path.write_bytes(b'P6\n1024 768\n255\n'+b'\1\0\0'+b'\0'*(1024*768*3-3))
            report['frames'][name]=dict(sha256=caller.digest(path))
        for name in ('guest.log','events.log'):(runtime/name).write_text('mocked actor diagnostics\n')
        (runtime/'runtime.json').write_text(json.dumps(report));(runtime/'private.raw').write_bytes(b'excluded')
        return base,runtime,proof,report,original
    def test_source_workflow_arm_and_exact_bytes_required(self):
        path=self.root/'source';path.write_text('fixed');manifest=dict(files={'source':dict(bytes=5,sha256=caller.digest(path))})
        env=dict(SOURCE_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,RUNNER_ARCH='ARM64',RUNNER_OS='Linux',GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1')
        self.assertEqual(caller.prove(self.root,manifest,env)['status'],'SOURCE_PROOF_PASS')
        for change in (dict(GITHUB_WORKFLOW_SHA='b'*40),dict(RUNNER_ARCH='X64'),dict(SOURCE_SHA='main')):
            with self.assertRaises(ValueError):caller.prove(self.root,manifest,env|change)
        path.write_text('drift')
        with self.assertRaises(ValueError):caller.prove(self.root,manifest,env)
    def test_six_pixels_and_honest_visual_pending_no_disk(self):
        base,runtime,proof,_,_=self.fixture();out=self.root/'public';result=caller.retain(base,runtime,proof,out)
        self.assertEqual(result['status'],'PASS_KEYBOARD_METADATA_PIXELS_PENDING_VISUAL_REVIEW')
        self.assertEqual(len(result['frames']),6);self.assertEqual(result['visual_review'],'NOT_RUN')
        self.assertFalse((out/'runtime/private.raw').exists())
    def test_missing_capture_retains_failure_diagnostics(self):
        base,runtime,proof,_,_=self.fixture();(runtime/'frames/overlay-editor.ppm').unlink()
        result=caller.retain(base,runtime,proof,self.root/'public')
        self.assertEqual(result['status'],'NOT_ACCEPTED');self.assertTrue((self.root/'public/runtime/guest.log').exists())
    def test_typed_result_replayed_not_status_accepted(self):
        base,runtime,proof,report,_=self.fixture()
        next(e for e in report['events'] if e['event']=='frame_ready')['proof']['file']['sha256']='0'*64
        (runtime/'runtime.json').write_text(json.dumps(report))
        self.assertEqual(caller.retain(base,runtime,proof,self.root/'public')['status'],'NOT_ACCEPTED')
    def test_original_owned_base_absence_required(self):
        base,runtime,proof,_,original=self.fixture();original['owned_cleanup']['image']['absence_verified']=False
        (base/'report.json').write_text(json.dumps(original))
        self.assertEqual(caller.retain(base,runtime,proof,self.root/'public')['status'],'NOT_ACCEPTED')
    def test_caps_and_symlinks_refuse(self):
        base,runtime,proof,_,_=self.fixture()
        with patch.object(caller,'MAX_TOTAL',100):result=caller.retain(base,runtime,proof,self.root/'public')
        self.assertEqual(result['status'],'NOT_ACCEPTED');self.assertLessEqual(result['total_bytes'],100)
        alias=self.root/'alias';alias.symlink_to(proof)
        with self.assertRaises(ValueError):caller.regular(alias,1024)



    def test_optional_failure_frame_is_retained_separately_and_cannot_accept(self):
        base,runtime,proof,report,_=self.fixture()
        image=(runtime/'frames/minimal-shell.ppm').read_bytes()
        (runtime/'frames/minimal-failure.ppm').write_bytes(image)
        (runtime/'frames/private-failure.ppm').write_bytes(image)
        report['events'].append(dict(event='keyboard_failure_diagnostic',stage='minimal',diagnostic_only=True,success_evidence=False))
        (runtime/'runtime.json').write_text(json.dumps(report))
        out=self.root/'public';result=caller.retain(base,runtime,proof,out)
        self.assertEqual(result['status'],'NOT_ACCEPTED');self.assertEqual(len(result['frames']),6)
        self.assertEqual(set(result['failure_frames']),{'minimal'})
        self.assertTrue(result['failure_frames']['minimal']['diagnostic_only'])
        self.assertFalse(result['failure_frames']['minimal']['success_evidence'])
        self.assertEqual((out/'frames/minimal-failure.ppm').read_bytes(),image)
        self.assertFalse((out/'frames/private-failure.ppm').exists())


if __name__=='__main__':unittest.main()
