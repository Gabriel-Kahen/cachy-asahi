#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Actor-fenced hosted Source, domain and phase-custody controls; modeled DATA."""
import copy
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


p=module('hosted_source_constructor_controls',HERE/'prepare.py')
c=module('hosted_source_domain_controls',HERE/'payload/hosted/common.py')
e=module('hosted_source_entry_controls',HERE/'payload/hosted/entry.py')


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.exec','os.fork','os.posix_spawn'):
        raise AssertionError('actor forbidden in Source controls: '+event)
sys.addaudithook(fence)


def daemon_fixture():
    rows=[dict(path='/MODELED/temp'+suffix,canonical=True,accessible=True,device=7,available_bytes=20*1024**3,total_inodes=1000000,available_inodes=200000) for suffix in ('','/perl-hosted','/alarm-cache','/pgo-hosted-retained')]
    return [dict(ID='MODELED',OSType='linux',Architecture='aarch64',SecurityOptions=['name=seccomp'],CgroupVersion='2',CpuCfsQuota=True,MemoryLimit=True,SwapLimit=True,PidsLimit=True,DockerRootDir='/MODELED/docker'),
        dict(Server=dict(Os='linux',Arch='arm64')),dict(system='Linux',machine='aarch64',uid=1001,gid=1001,MemAvailable_bytes=16*1024**3),
        dict(path='/var/run/docker.sock',uid=0,socket=True,stable=True),dict(path='/MODELED/docker',canonical=True,accessible=True,total_inodes=1000000,available_inodes=200000,available_bytes=20*1024**3,work_filesystems=rows)]


class SourceControls(unittest.TestCase):
    def test_rootful_profile_does_not_require_daemon_directory_runner_ownership(self):
        values=daemon_fixture();values[-1]['uid']=0
        result=c.daemon_data(*values);self.assertFalse(result['native_acceptance'])
        self.assertEqual(result['status'],'OBSERVED_ROOTFUL_NATIVE_LOCAL_DAEMON_PRECONDITIONS')

    def test_no_rootless_or_policy_fallback(self):
        for index,key,value in [(0,'SecurityOptions',['name=rootless']),(0,'SecurityOptions',['name=userns']),(0,'CgroupVersion','1'),(0,'SwapLimit',False),(3,'uid',1001),(3,'stable',False),(4,'canonical',False),(4,'accessible',False),(4,'total_inodes',0),(4,'available_inodes',0),(2,'MemAvailable_bytes',0)]:
            values=copy.deepcopy(daemon_fixture());values[index][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):c.daemon_data(*values)
        values=daemon_fixture();values[-1]['work_filesystems'][1]['available_bytes']=1
        with self.assertRaises(ValueError):c.daemon_data(*values)

    def test_exact_emitted_inverse_restores_all_held_data(self):
        before={'original/DATA':(b'MODELED original',0o644),'perl/DATA':(b'MODELED component',0o644)}
        files=p.compose(before,{'hosted/entry.py':(b'# MODELED inert code\n',0o644)})
        inverse=json.loads(files['inverse.json'][0]);undo={name:row for name,row in files.items() if name not in inverse['additions']}
        self.assertEqual(undo,before);self.assertEqual(p.atomic.tree(undo),inverse['before_tree']);self.assertTrue(all(v is None for v in json.loads(files['source-map.json'][0])['actual'].values()))
        with self.assertRaises(ValueError):p.compose(before,{'original/DATA':(b'overwrite',0o644)})

    def test_source_count_and_byte_limits_remain_finite(self):
        with self.assertRaises(ValueError):p.compose({}, {str(i):(b'MODELED',0o644) for i in range(321)})
        with self.assertRaises(ValueError):p.compose({}, {'DATA':(b'x'*(p.MAX_BYTES+1),0o644)})

    def test_output_cannot_touch_any_frozen_source(self):
        with self.assertRaisesRegex(ValueError,'disjoint'):p.construct(Path('/MODEL/original'),Path('/MODEL/packet'),'0'*64,HERE/'MUST_NOT_CREATE')
        self.assertFalse((HERE/'MUST_NOT_CREATE').exists())

    def test_scoped_filesystem_readback_limit_restores_on_refusal(self):
        original=p.atomic.MAX_FILES
        with tempfile.TemporaryDirectory() as tmp,patch.object(p,'render',return_value={}),patch.object(p.atomic,'publish',side_effect=ValueError('MODELED refusal')):
            with self.assertRaisesRegex(ValueError,'MODELED refusal'):p.construct(Path('/MODEL/original'),Path('/MODEL/packet'),'0'*64,Path(tmp)/'fresh')
        self.assertEqual(p.atomic.MAX_FILES,original)

    def test_declared_job_and_pair_time_budgets_fit(self):
        contract=json.loads((HERE/'payload/hosted/contract.json').read_bytes());steps=contract['step_timeouts_minutes'];b=contract['native_budget_seconds']
        self.assertLess(sum(steps.values()),contract['job_timeout_minutes'])
        self.assertEqual(b['pair'],6000);self.assertEqual(b['pair_full_build_each'],2400);self.assertEqual(b['pair_cleanup_included'],180)
        self.assertLessEqual(b['signed349_preparation_and_build']+b['pair']+b['bootstrap_image_retirement'],steps['native']*60)
        self.assertEqual(contract['concurrency'],dict(group='native-arm-build',cancel_in_progress=False,queue='max'))
        self.assertFalse(contract['acquisition']['new_secrets']);self.assertTrue(all(value is None for value in contract['actual'].values()))

    def test_source_proof_and_native_stream_names_never_collide(self):
        class ModeledOwned:
            def run(self,argv,**kwargs):
                kwargs['stdout'].write(b'MODELED stdout\n');kwargs['stderr'].write(b'MODELED stderr\n')
                kwargs['lifecycle'].update(pid=77,exit=0,natural_exit=True,forced_cleanup=False,retirement='REAPED',group_absent=True,leader_held_until_group_inspection=True,ownership_lost=False,exit_observed_via_waitpid=True,elapsed_seconds=.1)
                return subprocess.CompletedProcess(argv,0)
        with tempfile.TemporaryDirectory() as tmp,patch.object(e.c,'load',return_value=ModeledOwned()),patch.dict(os.environ,{'RUNNER_TEMP':tmp}):
            work=Path(tmp);(work/'home').mkdir()
            proof=e.Commands(work,1e30,scope='proof');native=e.Commands(work,1e30)
            self.assertEqual(proof(['MODELED'],timeout=1).stdout,b'MODELED stdout\n');self.assertEqual(native(['MODELED'],timeout=1).stdout,b'MODELED stdout\n')
            self.assertNotEqual(proof.rows[0]['stdout'],native.rows[0]['stdout'])
            native.cancelled[0]=True
            with self.assertRaises(ValueError):native(['MODELED'],timeout=1)
            native.cleaning=True;native(['MODELED'],timeout=1)


if __name__=='__main__':unittest.main(verbosity=2)
