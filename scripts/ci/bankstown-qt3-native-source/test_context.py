#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Pure DATA/model controls. No Root authority or hosted/native operation."""
import ast
import copy
import importlib.util
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('bankstown_context_test',HERE/'context.py')
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
NOW=1000

class Fixture:
    def __init__(self,root):
        self.root=root
        self.limits=dict(metadata_query_seconds=30,metadata_max_bytes=1024**2,max_context_age_seconds=300,max_delegation_seconds=3600)
        self.ceiling=dict(max_command_seconds=1800,total_seconds=3600,builder_cpus=4,builder_memory_bytes=4*1024**3,builder_pids=512,command_rows=512)
        self.policy=dict(context=self.limits,stage_capabilities={'qt3':self.ceiling})
        self.bodies={'scripts/ci/bankstown-qt3-native-source/context.py':(HERE/'context.py').read_bytes(),
                     'programs/owner.py':b'# MODEL ONLY\n','programs/image.py':b'# MODEL IMAGE\n',
                     'programs/executor.py':b'# MODEL EXECUTOR\n','programs/owned.py':b'# MODEL SUPERVISOR\n',
                     'inputs/policy.json':C.encoded(self.policy),'inputs/audio.json':b'MODEL_AUDIO_INPUT'}
        for name,body in self.bodies.items():
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(body);p.chmod(0o644)
        raw=C.encoded(dict(schema=1,kind=C.SOURCE_KIND,operation=C.OPERATION,
                         actual=dict(source=None,ref=None,run=None,job=None),
                         files={n:dict(C.pin(b),mode=0o644) for n,b in self.bodies.items()}))
        for name in ('source-map.json','source.lock.json'):
            p=root/name;p.write_bytes(raw);p.chmod(0o644)
        def desc(name):return dict(member=name,**C.pin(self.bodies[name]))
        self.d=dict(schema=1,kind=C.DELEGATION,issuer='Root',approved=True,scope='CURRENT_PRIVATE_STAGE_ONLY',
                    stage='qt3',nonce='c'*64,binding=dict(source='b'*40,ref='refs/heads/codex/MODEL-audio',run=None,job=None,attempt=1,source_lock=C.pin(raw)),
                    issued_epoch=NOW-10,expires_epoch=NOW+1800,image_ids={'qt3':None},
                    programs=dict(context=desc('scripts/ci/bankstown-qt3-native-source/context.py'),owner=desc('programs/owner.py'),image=desc('programs/image.py'),image_executor=desc('programs/executor.py'),owned_process=desc('programs/owned.py')),
                    policy=desc('inputs/policy.json'),materials={'audio':desc('inputs/audio.json')},
                    capability=dict(operation=C.OPERATION,stage='qt3',allow_provisional_context=True,allow_provisional_image_checks=True,allow_pair_adoption=False,**self.ceiling),
                    context_limits=self.limits,hosted=dict(repository='MODEL/MODEL',workflow_ref='MODEL/MODEL/.github/workflows/model.yml@refs/heads/codex/MODEL-audio',workflow_sha='b'*40,job_key='audio',job_name='MODEL audio',runner_environment='github-hosted',runner_os='Linux',runner_arch='ARM64'),
                    audio=C.AUDIO,inputs_pin=C.pin(b'MODEL_INPUT_REQUEST'),root_selection=dict(directory='/var/lib/MODEL-root-inbox',wait_seconds=300),**C.FINAL)
        h=self.d['hosted']
        self.env=dict(GITHUB_ACTIONS='true',GITHUB_REPOSITORY=h['repository'],GITHUB_SHA='b'*40,GITHUB_REF=self.d['binding']['ref'],GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1',GITHUB_JOB='audio',GITHUB_WORKFLOW_REF=h['workflow_ref'],GITHUB_WORKFLOW_SHA='b'*40,GITHUB_WORKSPACE=str(root),RUNNER_ENVIRONMENT='github-hosted',RUNNER_OS='Linux',RUNNER_ARCH='ARM64',RUNNER_NAME='MODEL-runner')
        run_url='https://api.github.com/repos/MODEL/MODEL/actions/runs/123'
        job=dict(id=456,run_id=123,run_attempt=1,head_sha='b'*40,status='in_progress',conclusion=None,name='MODEL audio',runner_name='MODEL-runner',run_url=run_url,url='https://api.github.com/repos/MODEL/MODEL/actions/jobs/456',html_url='https://github.com/MODEL/MODEL/actions/runs/123/job/456')
        self.response=dict(url=run_url+'/jobs?filter=latest&per_page=100',status=200,body=C.encoded(dict(total_count=1,jobs=[job])),received_epoch=NOW,elapsed_ms=1)
    def capture(self,d=None):
        raw=C.encoded(self.d if d is None else d)
        return C.capture_context(raw,C.pin(raw)['sha256'],self.root,environ=self.env,jobs_response=self.response,now=NOW)

class ContextTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='bankstown-context-MODEL-');self.addCleanup(self.temp.cleanup)
        self.f=Fixture(Path(self.temp.name))
        for obj,name in ((socket,'socket'),(subprocess,'Popen')):
            p=mock.patch.object(obj,name,side_effect=AssertionError('NO_NETWORK_OR_ACTORS'));p.start();self.addCleanup(p.stop)
    def test_capture_replay_has_actual_model_tuple_and_no_acceptance(self):
        c=self.f.capture();self.assertEqual(c['binding'],dict(self.f.d['binding'],run='123',job='456'))
        self.assertEqual(C.validate_context(self.f.d,c,now=NOW+1),c)
        self.assertEqual(c['schema'],1);self.assertEqual(c['issuer'],C.ISSUER)
        self.assertEqual({k:c[k] for k in C.FINAL},C.FINAL)
    def test_held_projection_whole_inverse_and_untouched_primitives(self):
        raw=(C.SOURCE/C.HELD_MEMBER).read_bytes();projected=C.projected(raw)
        inverse=projected
        for old,new,count in reversed(C.PROJECTION):inverse=inverse.replace(new,old)
        self.assertEqual(inverse.encode(),raw)
        oldtree=ast.parse(raw);newtree=ast.parse(projected)
        for name in ('read','whole','descriptor','relative','_binding'):
            a=next(n for n in oldtree.body if isinstance(n,ast.FunctionDef) and n.name==name)
            b=next(n for n in newtree.body if isinstance(n,ast.FunctionDef) and n.name==name)
            self.assertEqual(ast.dump(a),ast.dump(b))
        with self.assertRaises(ValueError):C.projected(raw+b'\n')
    def test_root_null_wrong_pin_operation_old_schema_and_acceptance_refuse(self):
        for mutate in (lambda d:d.update(approved=None),lambda d:d.update(schema=3),lambda d:d.update(kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3'),lambda d:d['capability'].update(operation='other'),lambda d:d.update(Root_final_acceptance=True)):
            d=copy.deepcopy(self.f.d);mutate(d)
            with self.assertRaises(ValueError):self.f.capture(d)
        with self.assertRaises(ValueError):C.validate_delegation(C.encoded(self.f.d),'0'*64,now=NOW)
    def test_fixed_audio_compiler_qt_pair_and_resources(self):
        for mutate in (lambda d:d['audio'].update(rust_compiler='1.96.1'),lambda d:d['audio'].update(qt_candidate='6.12.0-2'),lambda d:d['capability'].update(allow_pair_adoption=True),lambda d:d['capability'].update(total_seconds=3601),lambda d:d.update(stage='backend')):
            d=copy.deepcopy(self.f.d);mutate(d)
            with self.assertRaises((ValueError,KeyError)):self.f.capture(d)
    def test_input_root_relay_and_future_ids_required(self):
        for mutate in (lambda d:d.update(inputs_pin=None),lambda d:d.update(root_selection=None),lambda d:d['root_selection'].update(wait_seconds=301),lambda d:d['root_selection'].update(directory='/a/../b'),lambda d:d['binding'].update(run='999')):
            d=copy.deepcopy(self.f.d);mutate(d)
            with self.assertRaises((ValueError,TypeError)):self.f.capture(d)
    def test_source_mode_tamper_extra_and_symlink_refuse(self):
        p=self.f.root/'inputs/audio.json';saved=p.read_bytes();p.write_bytes(b'changed')
        with self.assertRaises(ValueError):self.f.capture()
        p.write_bytes(saved);extra=self.f.root/'extra';extra.write_bytes(b'x')
        with self.assertRaises(ValueError):self.f.capture()
        extra.unlink();p.chmod(0o600)
        with self.assertRaises(ValueError):self.f.capture()
    def test_job_tuple_and_context_tamper_are_not_relabelled(self):
        c=self.f.capture();changed=copy.deepcopy(c);changed['binding']['job']='999'
        with self.assertRaises(ValueError):C.validate_context(self.f.d,changed,now=NOW)
        self.f.env['GITHUB_SHA']='a'*40
        with self.assertRaises(ValueError):self.f.capture()

if __name__=='__main__':unittest.main()
