#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source/mocked actor controls only; no acquisition, Docker, build or native credit."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch
import contract as C
import planner_transport as T
import trial as R


class TrialTests(unittest.TestCase):
    def setUp(self):
        packet = next((p for p in Path(__file__).parents if (p/'evidence/input-pins.json').is_file()),None)
        self.temp = tempfile.TemporaryDirectory(prefix='source-test-',dir=packet/'evidence' if packet else None)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_real_two_recipe_metadata_and_inputs_are_explicit(self):
        rows = C.recipes(C.ROOT)
        self.assertEqual(set(rows),set(C.NAMES))
        self.assertEqual(rows[C.NAMES[0]]['metadata']['depends'],['coreutils','fish'])
        self.assertEqual(rows[C.NAMES[1]]['metadata']['depends'],['zsh'])
        for row in rows.values():
            self.assertFalse(row['report']['errors'])
            self.assertEqual(set(row['report']['input_sha256']),set(row['metadata']['source'])|{'.SRCINFO','PKGBUILD'})

    def test_raw_baseline_topology_and_unknown_recipe_pins_are_preserved(self):
        value = C.topology(C.ROOT)
        original = C.baseline(C.ROOT)
        self.assertEqual(len(value['packages']),576)
        self.assertEqual(len(value['sources']),2)
        self.assertEqual(value['changed']['sources'],list(C.NAMES))
        self.assertTrue(all(p['source_id'] is None for p in value['build_dependencies'] if p['disposition']=='external'))
        for package in original['packages']:
            row = next(p for p in value['packages'] if p['name']==package['name'])
            self.assertEqual(row['depend'],package['depends'])
            self.assertEqual(row['provides'],package['provides'])

    def test_actual_baseline_recipe_pins_are_mandatory_for_filled_plan(self):
        with self.assertRaisesRegex(ValueError,'actual baseline BUILDINFO'):
            C.topology(C.ROOT,{})

    def test_source_proof_refuses_unbound_revision_before_writing(self):
        with patch.object(C,'verify_source'):
            with self.assertRaisesRegex(ValueError,'hosted source/workflow'):
                R.proof(C.ROOT,self.root/'proof.json',dict(SOURCE_SHA='a'*40,GITHUB_SHA='b'*40,GITHUB_WORKFLOW_SHA='a'*40))
        self.assertFalse((self.root/'proof.json').exists())

    def test_source_proof_records_only_source_status(self):
        manifest = self.root/'scripts/ci/build-batch-native/source-manifest.json'
        manifest.parent.mkdir(parents=True);manifest.write_text('{}\n')
        env=dict(SOURCE_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40)
        with patch.object(C,'verify_source'):
            result=R.proof(self.root,self.root/'proof.json',env)
        self.assertEqual(result['native'],'NOT_RUN')
        self.assertEqual(result['source'],'a'*40)
        self.assertEqual(len(result['job_token']),16)

    def test_non_native_guard_rejects_before_any_docker(self):
        with patch.object(R.platform,'machine',return_value='x86_64'),patch.object(T,'capture') as capture:
            with self.assertRaisesRegex(ValueError,'ordinary native ARM'):
                R.native_guard(self.root,{})
        capture.assert_not_called()

    def test_native_planner_command_has_no_socket_network_or_floating_image(self):
        image='sha256:'+'c'*64;name='cachy-asahi-batch-plan-'+'d'*32
        command=T.command(C.ROOT,self.root,image,name,'d'*32,self.root/'input.json','e'*64)
        self.assertEqual(command[command.index('--network=none')],'--network=none')
        self.assertIn(image,command)
        self.assertIn('--pull=never',command)
        self.assertNotIn('/var/run/docker.sock',' '.join(command))
        self.assertIn(str(C.ROOT/'scripts/maintenance/rebuild_plan.py'),command)

    def test_planner_daemon_failure_is_not_absence(self):
        owner=dict(name='cachy-asahi-batch-plan-'+'a'*32,token='a'*32,image='sha256:'+'b'*64,source=str(C.ROOT),runtime=str(self.root))
        with patch.object(T,'capture',return_value=subprocess.CompletedProcess([],1,b'',b'daemon unavailable')):
            with self.assertRaisesRegex(ValueError,'absence not established'):
                T.retire(owner)

    def test_planner_foreign_mount_is_never_removed(self):
        owner=dict(name='cachy-asahi-batch-plan-'+'a'*32,token='a'*32,image='sha256:'+'b'*64,source=str(C.ROOT),runtime=str(self.root))
        row=dict(Name='/'+owner['name'],Image=owner['image'],Config=dict(Image=owner['image'],Labels={T.LABEL:owner['token']}),Mounts=[])
        with patch.object(T,'capture',return_value=subprocess.CompletedProcess([],0,json.dumps([row]).encode(),b'')) as capture:
            with self.assertRaisesRegex(ValueError,'planner ownership differs'):
                T.retire(owner)
        self.assertEqual(capture.call_count,1)

    def archive(self,missing=False):
        path=self.root/'baseline.pkg.tar.xz'
        entries={'.PKGINFO':b'pkgname = example\npkgver = 1-1\narch = any\ndepend = bash\n',
                 '.BUILDINFO':b'pkgbuild_sha256sum = '+b'a'*64+b'\n'}
        if missing:del entries['.BUILDINFO']
        with tarfile.open(path,'w:xz') as archive:
            for name,data in entries.items():
                item=tarfile.TarInfo(name);item.size=len(data);archive.addfile(item,io.BytesIO(data))
        row=dict(name='example',version='1-1',arch='any',depends=['bash'],provides=[],size=path.stat().st_size,sha256=C.digest(path))
        return path,row

    def test_recipe_pin_comes_from_exact_archive_buildinfo(self):
        path,row=self.archive()
        self.assertEqual(C.archive_recipe_pin(path,row),'a'*64)

    def test_missing_baseline_buildinfo_is_an_input_hold(self):
        path,row=self.archive(missing=True)
        with self.assertRaisesRegex(ValueError,'BUILDINFO unavailable'):
            C.archive_recipe_pin(path,row)

    def test_baseline_archive_metadata_drift_is_an_input_hold(self):
        path,row=self.archive();row['version']='99-1'
        with self.assertRaisesRegex(ValueError,'metadata differs'):
            C.archive_recipe_pin(path,row)

    def test_changed_baseline_archive_is_not_a_source_pin(self):
        path,row=self.archive();path.write_text('tampered')
        with self.assertRaisesRegex(ValueError,'archive changed'):
            C.archive_recipe_pin(path,row)

    def test_symlink_source_or_evidence_refused(self):
        original=self.root/'original';original.write_text('data');link=self.root/'link';link.symlink_to(original)
        with self.assertRaisesRegex(ValueError,'ordinary absolute'):
            C.raw(link)

    def test_no_consumer_cleanup_has_no_actor(self):
        with patch.object(C,'verify_source'),patch.object(T,'capture') as capture:
            result=R.cleanup(C.ROOT,self.root,self.root/'absent')
        self.assertEqual(result['status'],'PASS_NO_CONSUMERS_STARTED')
        capture.assert_not_called()

    def test_fault_observer_missed_fault_never_claims_build(self):
        stop=threading.Event();stop.set()
        R.inject_failure(C.ROOT,self.root,'sha256:'+'a'*64,stop)
        self.assertEqual(C.read(self.root/'fault-missed.json')['status'],'NO_ACTUAL_RUNNING_CONTAINER_FAULT_OBSERVED')

    def test_retention_is_explicitly_bytes_only(self):
        base=self.root/'base';base.mkdir();(base/'report.json').write_text('{}\n');(base/'installed-packages.lock').write_text('example 1-1\n')
        proof=self.root/'proof.json';proof.write_text('{}\n');cleanup=self.root/'cleanup.json';cleanup.write_text('{}\n')
        with patch.object(C,'verify_source'):
            result=R.retain(C.ROOT,base,self.root/'absent',proof,cleanup,self.root/'public')
        self.assertEqual(result['status'],'RETAINED_BYTES_ONLY_NOT_ACCEPTANCE')
        self.assertEqual(len(result['files']),4)


class FaultEstablishmentTests(unittest.TestCase):
    """Mocked observer controls, never native fault or build acceptance."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='observer-source-control-')
        self.addCleanup(self.temp.cleanup);self.output=Path(self.temp.name)
        self.path=self.output/'batch'/C.NAMES[0]/'attempt-001/build/provenance.json'
        self.image='sha256:'+'a'*64;self.name='cachy-asahi-'+'b'*16
        self.record=dict(status='building',image=self.image,clean_environment_id=self.name)

    def publish(self,body=None):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self.path.write_bytes(C.encoded(self.record)if body is None else body)

    def observed(self):
        base=self.path.parent
        return dict(Name='/'+self.name,Image=self.image,Config=dict(Image=self.image),State=dict(Running=True),
            Mounts=[dict(Type='bind',Source=str(s),Destination=d,RW=rw)for s,d,rw in (
                (base/'inputs','/inputs',False),(base/'artifacts','/out',True),
                (C.ROOT/'scripts/build/container-entry.sh','/builder-entry.sh',False),
                (base/'expected-packages.lock','/expected-packages.lock',False))])

    def run_observer(self,on_wait=None,inspect_row=None,kill_code=0):
        callback=on_wait or(lambda tick:None)
        class Stop:
            tick=0
            def is_set(stop):return stop.tick>=4
            def wait(stop,seconds):
                stop.tick+=1;callback(stop.tick)
        stop=Stop();commands=[]
        def capture(argv,timeout):
            commands.append(argv)
            if argv[:3]==['docker','container','inspect']:
                row=inspect_row()if callable(inspect_row)else inspect_row or self.observed()
                return subprocess.CompletedProcess(argv,0,json.dumps([row]).encode(),b'')
            self.assertEqual(argv,['docker','kill','--signal=KILL',self.name])
            return subprocess.CompletedProcess(argv,kill_code,(self.name+'\n').encode(),b'')
        with patch.object(T,'capture',side_effect=capture):
            R.inject_failure(C.ROOT,self.output,self.image,stop)
        return stop,commands

    def test_underlying_missing_read_is_actual_failure_class(self):
        with self.assertRaisesRegex(ValueError,'bounded ordinary input required'):
            C.read(self.path)

    def test_missing_provenance_retries_until_builder_creates_it(self):
        stop,commands=self.run_observer(on_wait=lambda tick:self.publish())
        self.assertEqual(stop.tick,1)
        self.assertEqual(len(commands),2)
        self.assertEqual(C.read(self.output/'fault.json')['status'],'ACTUAL_RUNNING_OWNED_OCI_CONTAINER_KILLED')
        self.assertFalse((self.output/'fault-error.json').exists())
        self.assertEqual(C.read(self.output/'fault-target-provenance.json'),self.record)

    def test_absence_without_running_builder_never_claims_fault(self):
        stop,commands=self.run_observer()
        self.assertEqual(stop.tick,4);self.assertEqual(commands,[])
        self.assertFalse((self.output/'fault.json').exists())
        self.assertFalse((self.output/'fault-error.json').exists())
        self.assertEqual(C.read(self.output/'fault-missed.json')['status'],'NO_ACTUAL_RUNNING_CONTAINER_FAULT_OBSERVED')

    def test_partial_json_is_retried_without_fault_claim(self):
        self.publish(b'{')
        stop,commands=self.run_observer(on_wait=lambda tick:self.publish())
        self.assertEqual(stop.tick,1);self.assertEqual(len(commands),2)
        self.assertTrue((self.output/'fault.json').exists())

    def test_existing_directory_and_oversized_file_are_fatal(self):
        self.path.mkdir(parents=True)
        _,commands=self.run_observer();self.assertEqual(commands,[])
        self.assertTrue((self.output/'fault-error.json').exists());self.assertFalse((self.output/'fault.json').exists())
        self.path.rmdir();(self.output/'fault-error.json').unlink()
        self.publish(b'x'*(4*1024**2+1))
        _,commands=self.run_observer();self.assertEqual(commands,[])
        self.assertTrue((self.output/'fault-error.json').exists());self.assertFalse((self.output/'fault.json').exists())

    def test_symlink_provenance_is_fatal_without_inspection(self):
        original=self.output/'other.json';original.write_bytes(C.encoded(self.record))
        self.path.parent.mkdir(parents=True);self.path.symlink_to(original)
        _,commands=self.run_observer();self.assertEqual(commands,[])
        self.assertIn('ordinary absolute',C.read(self.output/'fault-error.json')['error'])

    def test_not_running_container_is_never_killed(self):
        self.publish();row=self.observed();row['State']['Running']=False
        _,commands=self.run_observer(inspect_row=row)
        self.assertTrue(commands);self.assertTrue(all(c[1]=='container'for c in commands))
        self.assertFalse((self.output/'fault.json').exists())

    def test_foreign_mount_is_not_killed(self):
        self.publish();row=self.observed();row['Mounts'][0]['RW']=True
        _,commands=self.run_observer(inspect_row=row)
        self.assertEqual(len(commands),1);self.assertFalse((self.output/'fault.json').exists())
        self.assertIn('mount ownership differs',C.read(self.output/'fault-error.json')['error'])

    def test_failed_kill_never_becomes_fault_success(self):
        self.publish();_,commands=self.run_observer(kill_code=1)
        self.assertEqual(len(commands),2);self.assertFalse((self.output/'fault.json').exists())
        self.assertIn('fault injection failed',C.read(self.output/'fault-error.json')['error'])


if __name__=='__main__':
    unittest.main()
