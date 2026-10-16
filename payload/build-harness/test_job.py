#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert proof/ordered-cleanup/export controls. No Docker or source execution."""
import fcntl,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('release_job',HERE/'job.py');J=importlib.util.module_from_spec(spec);spec.loader.exec_module(J)

class JobControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        target=self.root/'scripts/ci/glibc-gnu-provider';target.mkdir(parents=True)
        J.save(target/'bindings.json',dict(gnu_inputs=dict(ref='e'*40)))
        self.admission=patch.object(J,'admission',return_value=dict(status='INERT_TEST_FIXTURE'));self.admission.start()
        self.addCleanup(self.admission.stop)
        self.normal=patch.object(J,'normal_binding',return_value=dict(status='INERT_TEST_FIXTURE'));self.normal.start()
        self.addCleanup(self.normal.stop)
    def tearDown(self):self.tmp.cleanup()
    def proof_args(self):
        file=self.root/'source.py';file.write_text('inert')
        manifest=dict(schema_version=1,files={'source.py':dict(bytes=5,sha256=J.sha(file))})
        env=dict(SOURCE_SHA='a'*40,WORKFLOW_SHA='a'*40,GITHUB_SHA='a'*40,RUNNER_ARCH='ARM64',RUNNER_OS='Linux',GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1')
        return manifest,env
    def test_source_workflow_guard_before_source_or_secrets(self):
        manifest,env=self.proof_args();env['WORKFLOW_SHA']='b'*40
        with patch.object(J,'manifest_files') as read,self.assertRaisesRegex(ValueError,'before secrets'):J.prove(self.root,manifest,env)
        read.assert_not_called()
    def test_deterministic_distinct_owner_tokens(self):
        manifest,env=self.proof_args();value=J.prove(self.root,manifest,env)
        self.assertEqual(value,J.prove(self.root,manifest,env));self.assertEqual(len(value['job_token']),16);self.assertEqual(len(value['consumer_token']),32)
        env['GITHUB_RUN_ATTEMPT']='2';self.assertNotEqual(value['consumer_token'],J.prove(self.root,manifest,env)['consumer_token'])
    def test_source_drift_before_actors(self):
        manifest,env=self.proof_args();(self.root/'source.py').write_text('changed')
        with self.assertRaisesRegex(ValueError,'source changed'):J.prove(self.root,manifest,env)
    def fixture(self):
        base=self.root/'base';base.mkdir();runtime=self.root/'runtime';runtime.mkdir();token='c'*32;image='sha256:'+'b'*64
        J.save(base/'report.json',dict(image=image));(runtime/'consumer.lock').touch(mode=0o600)
        J.save(runtime/'owner.json',dict(schema_version=1,token=token,image=image,label=J.LABEL))
        return base,runtime,dict(consumer_token=token),image
    def test_live_consumer_lease_blocks_retirement(self):
        base,runtime,proof,_=self.fixture();fd=os.open(runtime/'consumer.lock',os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:
            with self.assertRaises(BlockingIOError):J.retire_consumers(runtime,base,proof,command=lambda *_:self.fail('actor called while owner live'))
        finally:os.close(fd)
    def command(self,image,token,foreign=False):
        calls=[];alive={'caa-glibc-provider-'+token+'-a'}
        def invoke(argv):
            calls.append(argv)
            if argv[1:3]==['rm','-f']:alive.clear();return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
            name=argv[-1]
            if name not in alive:return SimpleNamespace(returncode=1,stdout=b'',stderr=('No such container: '+name).encode())
            value=dict(Id='d'*64,Image=image,Config=dict(Labels={J.LABEL:'foreign' if foreign else token}))
            return SimpleNamespace(returncode=0,stdout=json.dumps([value]).encode(),stderr=b'')
        return invoke,calls,alive
    def test_completed_lease_all_five_names_observed(self):
        base,runtime,proof,image=self.fixture();invoke,calls,alive=self.command(image,proof['consumer_token'])
        result=J.retire_consumers(runtime,base,proof,invoke);self.assertEqual(result['status'],'PASS_CONSUMERS_RETIRED');self.assertEqual(len(result['containers']),5)
        self.assertFalse(alive);self.assertEqual(sum(argv[1:3]==['rm','-f'] for argv in calls),1)
    def test_foreign_consumer_never_removed(self):
        base,runtime,proof,image=self.fixture();invoke,calls,alive=self.command(image,proof['consumer_token'],True)
        with self.assertRaisesRegex(ValueError,'producer must remain'):J.retire_consumers(runtime,base,proof,invoke)
        self.assertTrue(alive);self.assertFalse(any(argv[1:3]==['rm','-f'] for argv in calls))
    def test_unknown_daemon_not_absence(self):
        base,runtime,proof,_=self.fixture()
        def failed(_):return SimpleNamespace(returncode=1,stdout=b'',stderr=b'Cannot connect to the Docker daemon')
        with self.assertRaisesRegex(ValueError,'producer must remain'):J.retire_consumers(runtime,base,proof,failed)
    def test_cleanup_never_calls_producer_after_consumer_failure(self):
        base,runtime,proof,_=self.fixture();manifest,_=self.proof_args()
        with patch.object(J,'retire_consumers',side_effect=ValueError('unknown consumer')),patch.object(J.subprocess,'run') as actor:
            result=J.cleanup(self.root,manifest,proof,base,runtime,self.root/'cleanup.json')
        actor.assert_not_called();self.assertEqual(result['status'],'FAIL');self.assertEqual(result['producer'],'NOT_RETIRED')
    def test_missing_actor_lease_means_no_actor_protocol(self):
        base=self.root/'base';base.mkdir();runtime=self.root/'absent'
        self.assertEqual(J.retire_consumers(runtime,base,dict(consumer_token='a'*32))['status'],'PASS_NO_CONSUMER_ACTORS')
    def test_evidence_file_symlink_refused(self):
        target=self.root/'private-secret';target.write_text('never copy');link=self.root/'alias';link.symlink_to(target)
        with self.assertRaisesRegex(ValueError,'ordinary'):J.regular(link,1024)
    def test_evidence_size_cap_refused(self):
        target=self.root/'too-large';target.write_bytes(b'123')
        with self.assertRaisesRegex(ValueError,'bounded'):J.regular(target,2)
    def test_manual_workflow_order_and_existing_route(self):
        text=(HERE.parents[2]/'.github/workflows/native-arm-glibc-gnu-provider.yml').read_text()
        self.assertIn('workflow_dispatch:',text);self.assertNotIn('\n  push:',text);self.assertNotIn('\n  schedule:',text)
        self.assertLess(text.index('before secrets'),text.index('secrets.CACHY_'))
        self.assertIn('04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd',text)
        self.assertLess(text.index('Native conventional provider pair'),text.index('Retire consumers before the producer'))
        self.assertIn('timeout-minutes: 360',text);self.assertIn(' --job-token ',text)
        self.assertNotIn('upload-artifact',text[:text.index('Retire consumers before the producer')])

if __name__=='__main__':unittest.main()
