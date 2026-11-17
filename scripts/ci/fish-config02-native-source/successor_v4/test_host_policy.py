# SPDX-License-Identifier: MIT
"""FENCED controller handoff/context checks; no host preflight or storage actor."""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
FROZEN=Path(os.environ.get('FISH48_SOURCE_ROOT','/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-fish48-source-r1/closed-source-tree'))
OLD=FROZEN/'scripts/ci/fish-config02-native-source/successor_v2'


def module(name):
    s=importlib.util.spec_from_file_location('fenced_v4_'+name,HERE/(name+'.py'))
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


O=module('hosted_owner');X=module('host_context');D=module('data');H=module('host_tools')
POLICY=json.loads((HERE/'policy.json').read_bytes())
ENV=dict(GITHUB_ACTIONS='true',RUNNER_OS='Linux',RUNNER_ARCH='ARM64',ImageOS='ubuntu24-arm64',
         GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_EVENT_NAME='workflow_dispatch',
         GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID='12345678',GITHUB_SHA='a'*40,GITHUB_JOB='pair',
         GITHUB_REF='refs/heads/codex/fish02-no-host-apt-v4-source-FENCED')


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.','fcntl.')) or event in (
            'os.system','os.fork','os.exec','os.posix_spawn','resource.setrlimit'):
        raise AssertionError('FENCED no host/native actor: '+event)


sys.addaudithook(fence)


class BeforeStorage(BaseException):pass


class Controls(unittest.TestCase):
    def test_existing_catalogue_has_no_host_package_manager_or_bsdtar(self):
        self.assertEqual(H.NAMES,D.HOST_NAMES)
        self.assertFalse(hasattr(H,'CI_CANDIDATES'))
        self.assertNotIn('bsdtar',H.NAMES)
        self.assertNotIn('host_prerequisites',POLICY)
        self.assertFalse(hasattr(O.Controller,'run_prerequisite'))
        for candidate in ('/usr/bin/apt-get','/usr/bin/apt-cache','/usr/bin/dpkg','/usr/bin/bsdtar'):
            with self.assertRaises(ValueError):H.inspect(candidate)

    def test_all_fifteen_context_checks_and_unknown_fields_remain_finite(self):
        facts=X.context(dict(ENV,PRIVATE_SENTINEL='PRIVATE_SENTINEL'),'aarch64',b'ID=ubuntu\nVERSION_ID=24.04\n',0)
        self.assertEqual(set(facts['checks']),D.CONTEXT_CHECKS)
        self.assertEqual(len(facts['checks']),15)
        self.assertTrue(all(v is True for v in facts['checks'].values()))
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(facts))
        records=[]
        with self.assertRaises(ValueError):
            X.context(dict(ENV,GITHUB_REF='refs/heads/codex/fish02-owned-v2-host-prerequisites-source-OLD'),
                      'aarch64',b'ID=ubuntu\nVERSION_ID=24.04\n',0,record=records.append)
        self.assertIn('CI_SOURCE_REF',records[0]['reason_codes'])

    def test_setup_context_then_existing_tools_then_policy_before_storage(self):
        owner=O.Controller.__new__(O.Controller);owner.policy=copy.deepcopy(POLICY)
        owner.out=Path('/FENCED/NO_ROOT_OUTPUT');owner.end=time.monotonic()+1650
        owner.cleanup_end=owner.end+90;owner.tools={};owner.host_policy={}
        events=[];records=[]
        owner.capacity=lambda:POLICY['minimum_available_bytes']
        owner.record_host_policy=lambda v:(events.append('record'),records.append(copy.deepcopy(v)))
        def preflight():
            events.append('preflight')
            self.assertTrue(records[-1]['context']['checks']['CI_SOURCE_REF'])
            owner.tools={name:dict(path='/usr/bin/'+name) for name in H.NAMES}
        owner.preflight=preflight
        def no_storage(*args,**kwargs):
            events.append('storage-boundary')
            raise BeforeStorage('MODEL stopped before storage open')
        with patch.dict(O.os.environ,ENV,clear=True),patch.object(O.os,'getuid',return_value=0), \
             patch.object(O.platform,'machine',return_value='aarch64'), \
             patch.object(O.X,'public_file',return_value=b'ID=ubuntu\nVERSION_ID=24.04\n'), \
             patch.object(O.shutil,'disk_usage',return_value=type('Space',(),dict(free=POLICY['minimum_disk_bytes']))()), \
             patch.object(O.os,'open',side_effect=no_storage):
            with self.assertRaises(BeforeStorage):owner.setup()
        self.assertEqual(events,['record','preflight','record','storage-boundary'])
        D.existing_host(records[-1],POLICY)
        self.assertEqual(records[-1]['commands'],[])
        self.assertEqual(records[-1]['package_manager_invocations'],0)
        self.assertEqual(records[-1]['host_package_mutations'],0)

    def test_context_refusal_durable_before_any_preflight_or_storage(self):
        owner=O.Controller.__new__(O.Controller);owner.policy=copy.deepcopy(POLICY);owner.host_policy={}
        owner.capacity=lambda:POLICY['minimum_available_bytes'];records=[]
        owner.record_host_policy=lambda v:records.append(copy.deepcopy(v))
        owner.preflight=lambda:self.fail('context refusal reached host preflight')
        with patch.dict(O.os.environ,ENV,clear=True),patch.object(O.os,'getuid',return_value=0), \
             patch.object(O.platform,'machine',return_value='x86_64'), \
             patch.object(O.X,'public_file',return_value=b'ID=ubuntu\nVERSION_ID=24.04\n'):
            with self.assertRaisesRegex(ValueError,'MACHINE_ARM64'):owner.setup()
        self.assertEqual(len(records),1)
        self.assertIn('MACHINE_ARM64',records[0]['context']['reason_codes'])
        self.assertEqual(records[0]['commands'],[])

    def test_actor_custody_capacity_and_preflight_bodies_unchanged(self):
        def functions(path):
            text=path.read_text();lines=text.splitlines(keepends=True)
            return {n.name:''.join(lines[n.lineno-1:n.end_lineno])for n in ast.walk(ast.parse(text))if isinstance(n,ast.FunctionDef)}
        before,after=functions(OLD/'hosted_owner.py'),functions(HERE/'hosted_owner.py')
        for name in ('run','capacity','tool','preflight','show','start','docker','loop_identity'):
            self.assertEqual(before[name],after[name],name)
        self.assertEqual(json.loads((OLD/'policy.json').read_bytes())['controller'],POLICY['controller'])
        self.assertEqual(json.loads((OLD/'policy.json').read_bytes())['owner'],POLICY['owner'])
        self.assertEqual(json.loads((OLD/'policy.json').read_bytes())['daemon'],POLICY['daemon'])
        for name in ('controller_scope_seconds','controller_work_seconds','pair_seconds','cleanup_seconds','storage_bytes',
                     'minimum_available_bytes','minimum_disk_bytes','host_reserve_bytes'):
            self.assertEqual(json.loads((OLD/'policy.json').read_bytes())[name],POLICY[name],name)


if __name__=='__main__':unittest.main(verbosity=2)
