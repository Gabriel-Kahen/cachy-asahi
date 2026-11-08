#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New synthetic phase/policy controls; no actual capsule or native actor."""
import sys

def deny(event,args):
    if event.startswith(('socket.','subprocess.','ctypes.','pty.')) or event in (
            'os.system','os.fork','os.forkpty','os.exec','os.posix_spawn'):
        raise RuntimeError('actor forbidden: '+event)

sys.addaudithook(deny)
import argparse
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_owner_data as controls


class AppArmorPhaseData(unittest.TestCase):
    def setUp(self):
        self.work=tempfile.TemporaryDirectory(prefix='namespace-apparmor-phase-new-DATA-')
        self.addCleanup(self.work.cleanup)
        self.fixture=controls.ports.Fixture(Path(self.work.name)/'owner')

    def test_phase_version_policy_and_negative_controls(self):
        with self.fixture.ports():
            m=self.fixture.module
            for case,policy in zip(m.CASES,m.POLICY):
                expected='unconfined'if case in('apparmor_only','both')else'docker-default'
                before=dict(AppArmorProfile=expected,State=dict(Status='created',Running=False),
                            HostConfig=dict(Privileged=False,SecurityOpt=policy))
                after=copy.deepcopy(before);after['State']['Status']='exited'
                self.assertEqual(m.apparmor_prestart_default_v1(before,after,dict(version='DATA_ONLY_1'),case),'EXACT_POLICY_PROFILE')
                empty=copy.deepcopy(before);empty['AppArmorProfile']=''
                if expected=='docker-default':
                    self.assertEqual(m.apparmor_prestart_default_v1(empty,after,dict(version='28.0.4'),case),
                                     'DOCKER_28_0_4_CREATED_EMPTY_TO_DOCKER_DEFAULT')
                bad=[(empty,after,'28.0.3'),(empty,after,'28.0.4+vendor'),(after,empty,'28.0.4')]
                for field,value in [('AppArmorProfile',None),('AppArmorProfile','unconfined'if expected=='docker-default'else'docker-default')]:
                    wrong=copy.deepcopy(after);wrong[field]=value;bad.append((before,wrong,'28.0.4'))
                wrong=copy.deepcopy(before);wrong['State']['Status']='exited';bad.append((wrong,after,'28.0.4'))
                wrong=copy.deepcopy(after);wrong['State']['Running']=True;bad.append((before,wrong,'28.0.4'))
                wrong=copy.deepcopy(after);wrong['HostConfig']['Privileged']=True;bad.append((before,wrong,'28.0.4'))
                wrong=copy.deepcopy(after);wrong['HostConfig']['SecurityOpt']=['apparmor=other'];bad.append((before,wrong,'28.0.4'))
                if expected=='unconfined':bad.append((empty,after,'28.0.4'))
                for left,right,version in bad:
                    with self.subTest(case=case,version=version,left=left,right=right),self.assertRaises(m.MatrixGuard):
                        m.apparmor_prestart_default_v1(left,right,dict(version=version),case)

    def test_complete_owner_and_matching_synthetic_reader_keep_raw_profiles(self):
        f=self.fixture;original=f.respond
        def respond(argv):
            body,rc=original(argv)
            if argv[2:3]==['info']:
                value=json.loads(body);value['version']='28.0.4';return controls.ports.encoded(value),rc
            if argv[2:3]==['create']:
                cid=body.decode().strip();container=f.containers[cid]
                if container['AppArmorProfile']=='docker-default':container['AppArmorProfile']=''
            if argv[2:4]==['start','-a']:
                container=f.containers[argv[-1]]
                if container['AppArmorProfile']=='':container['AppArmorProfile']='docker-default'
                container['HostConfig']['OomKillDisable']=None
            return body,rc
        with f.ports(),patch.object(f,'respond',respond):
            f.run();self.assertEqual(f.diagnostic['status'],controls.COMPLETE)
            marker=f.diagnostic['apparmor_profile_comparison']
            self.assertEqual(marker['default_transitions'],['baseline','seccomp_only'])
            raw=controls.ports.encoded(f.result);_,payloads=controls.project(f);retained=dict(payloads)
            read=controls.read(f,payloads)
            self.assertEqual(read['projection_status'],controls.COMPLETE)
            self.assertEqual(read['raw_result'],f.result)
            self.assertEqual(controls.ports.encoded(f.result),raw);self.assertEqual(payloads,retained)
            self.assertEqual(read['qualification']['apparmor_profile_comparison'],marker)
            self.assertEqual(read['runtime_qualification']['apparmor_profile_comparison'],marker)
            for row in f.result['cases']:
                if row['id']in('baseline','seccomp_only'):
                    self.assertEqual(row['inspect_before']['AppArmorProfile'],'')
                    self.assertEqual(row['inspect_after']['AppArmorProfile'],'docker-default')

    def test_marker_or_other_raw_delta_cannot_replace_reader_joins(self):
        f=self.fixture
        with f.ports():
            f.run();owner=copy.deepcopy(f.owner)
            owner['apparmor_profile_comparison']['default_transitions']=['baseline','seccomp_only']
            with self.assertRaisesRegex(f.module.MatrixGuard,'independently recomputed raw AppArmor'):
                f.module.validate_runtime_evidence(owner,f.result,controls.raw_payloads(f),controls.expected(f),controls.source_proof(f))
            for field,value in [('AppArmorProfile','unconfined'),('HostConfig',dict(f.result['cases'][0]['inspect_after']['HostConfig'],Memory=1))]:
                result=copy.deepcopy(f.result);result['cases'][0]['inspect_after'][field]=value
                with self.assertRaisesRegex(f.module.MatrixGuard,'raw before/after inspect inverse'):
                    f.module.validate_runtime_evidence(f.owner,result,controls.raw_payloads(f),controls.expected(f),controls.source_proof(f))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--basis',required=True,type=Path)
    args,rest=parser.parse_known_args();controls.ports.configure_basis(args.basis.resolve(strict=True))
    unittest.main(argv=[sys.argv[0],*rest])
