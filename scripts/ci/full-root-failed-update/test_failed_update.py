#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert controlled-failure/ownership tests; no child or package actors run."""
from contextlib import nullcontext
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
spec=importlib.util.spec_from_file_location('failed_update_case',HERE/'run.py')
lane=importlib.util.module_from_spec(spec);spec.loader.exec_module(lane)
BASE=dict(line.split() for line in (ROOT/'scripts/ci/full-development-composition/expected-updater-v2.lock').read_text().splitlines())


def observation():return dict(complete=True,nodes={'home/inert':dict(type='file',sha256='held')},hardlink_groups={})

def selection():return dict(nonce='a'*32,root_identity=[1,2],spec_sha256='b'*64,worker_sha256='c'*64)

def marker(spec):return dict(event='prepared-precommit-exit',case=lane.CASE,nonce=spec['nonce'],exit_code=86,pid=123,
    root_identity=spec['root_identity'],spec_sha256=spec['spec_sha256'],worker_sha256=spec['worker_sha256'],
    prepared_add={'cachy-asahi-setup':'0.1.0-4'},prepared_remove={},lock=copy.deepcopy(lane.LOCK_NODE))

def worker():return dict(returncode=86,termination=None,direct_child_reaped=True,group_retired=True)


class BoundaryControls(unittest.TestCase):
    def fixture(self,root):
        alpm=SimpleNamespace(started=True,handle='handle',inventory=lambda:BASE,
            alpm_trans_get_add=lambda _: 'add',alpm_trans_get_remove=lambda _: 'remove',
            packages=lambda value:{'cachy-asahi-setup':'0.1.0-4'} if value=='add' else {})
        runtime=SimpleNamespace(commit_ready=True,alpm=alpm,root=root,config={'before_lock_sha256':lane.BEFORE},
                                observation={'nodes':{lane.LOCK:lane.LOCK_NODE}})
        selected=selection();selected['root_identity']=lane.identity(root)
        return runtime,selected
    def test_all_original_precommit_checks_must_return_before_injection(self):
        callback=Mock()
        class Strict:
            def precommit(self):raise ValueError('held guard refusal')
        with self.assertRaisesRegex(ValueError,'held guard'):lane.fault_class(Strict,callback)().precommit()
        callback.assert_not_called()
    def test_exact_boundary_writes_witness_before_exit86(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);runtime,spec=self.fixture(root);path=root/'marker.json'
            class Exit(Exception):pass
            def stop(code):
                self.assertEqual(code,86);self.assertTrue(path.is_file());raise Exit()
            with self.assertRaises(Exit):lane.arm(runtime,spec,path,exit_process=stop)
            actual=json.loads(path.read_bytes());self.assertEqual(actual['prepared_add'],{'cachy-asahi-setup':'0.1.0-4'})
            self.assertEqual(actual['lock'],lane.LOCK_NODE);self.assertEqual(actual['root_identity'],spec['root_identity'])
    def test_prepared_mismatch_inventory_drift_and_missing_lock_never_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for change in ('prepared','inventory','lock','not-ready'):
                runtime,spec=self.fixture(root);exit_process=Mock()
                if change=='prepared':runtime.alpm.packages=lambda _:{}
                elif change=='inventory':runtime.alpm.inventory=lambda:{}
                elif change=='lock':runtime.observation={'nodes':{}}
                else:runtime.commit_ready=False
                with self.subTest(change=change),self.assertRaises(ValueError):lane.arm(runtime,spec,root/'unused',exit_process=exit_process)
                exit_process.assert_not_called();self.assertFalse((root/'unused').exists())
    def test_existing_or_replaced_witness_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);runtime,spec=self.fixture(root);path=root/'marker';path.write_bytes(b'KEEP')
            with self.assertRaises(FileExistsError):lane.arm(runtime,spec,path,exit_process=Mock())
            self.assertEqual(path.read_bytes(),b'KEEP')
    def test_returning_injection_cannot_continue_to_commit(self):
        callback=Mock()
        class Strict:
            def precommit(self):self.checked=True
        instance=lane.fault_class(Strict,callback)()
        with self.assertRaisesRegex(ValueError,'commit remains prohibited'):instance.precommit()
        self.assertTrue(instance.checked);callback.assert_called_once_with(instance)


class ClassificationControls(unittest.TestCase):
    def values(self):
        before=observation();after=copy.deepcopy(before);after['nodes'][lane.LOCK]=copy.deepcopy(lane.LOCK_NODE)
        selected=selection();return worker(),marker(selected),selected,before,after,None,None
    def test_verified_precommit_stop_is_failed_update_with_known_no_commit(self):
        result=lane.assess(*self.values());self.assertEqual(result['status'],'FAIL')
        self.assertTrue(result['controlled_failure_verified']);self.assertTrue(result['stale_lock_retained'])
        for key in ('commit_started','packages_committed','checkpoint_changed'):self.assertIs(result[key],False)
    def test_other_exit_timeout_or_unreaped_child_cannot_pass(self):
        for change in (dict(returncode=0),dict(returncode=1),dict(returncode=-9),dict(termination='timeout'),
                       dict(direct_child_reaped=False),dict(group_retired=False),dict(group_retired=1)):
            values=list(self.values());values[0].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):lane.assess(*values)
    def test_stale_or_malformed_boundary_marker_cannot_pass(self):
        for change in (dict(nonce='other'),dict(root_identity=[4,5]),dict(spec_sha256='other'),dict(worker_sha256='other'),
                       dict(prepared_add={}),dict(prepared_remove={'other':'1'}),dict(exit_code=0),dict(pid=0),dict(extra=True)):
            values=list(self.values());values[1].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):lane.assess(*values)
    def test_missing_changed_or_preexisting_lock_cannot_pass(self):
        for stage in ('missing','changed','preexisting'):
            values=list(self.values())
            if stage=='missing':values[4]['nodes'].pop(lane.LOCK)
            elif stage=='changed':values[4]['nodes'][lane.LOCK]['mode']=0o600
            else:values[3]['nodes'][lane.LOCK]=lane.LOCK_NODE
            with self.subTest(stage=stage),self.assertRaises(ValueError):lane.assess(*values)
    def test_user_database_trust_or_group_drift_cannot_pass(self):
        for name in ('home/inert','var/lib/pacman/local/base-3-3/desc','etc/pacman.conf'):
            values=list(self.values());values[4]['nodes'][name]={'type':'file','sha256':'changed'}
            with self.subTest(name=name),self.assertRaises(ValueError):lane.assess(*values)
        values=list(self.values());values[4]['hardlink_groups']={'changed':{}}
        with self.assertRaises(ValueError):lane.assess(*values)
    def test_checkpoint_change_and_incomplete_observation_cannot_pass(self):
        for index,value in ((5,{'old':1}),(6,{'new':1})):
            values=list(self.values());values[index]=value
            with self.assertRaises(ValueError):lane.assess(*values)
        values=list(self.values());values[4]['complete']=False
        with self.assertRaises(ValueError):lane.assess(*values)


class DisposalControls(unittest.TestCase):
    def run_case(self,kind='expected'):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);source=home/'source';source.mkdir();data=home/'data';data.mkdir()
            args=SimpleNamespace(source=source,data=data,workspace=home/'copy',source_root=ROOT,scale='unused',scale_sha256='unused')
            config={'limits':{}}
            checkpoint=SimpleNamespace(state_directory=lambda *a:nullcontext(None),checkpoint=lambda _:None)
            scale=SimpleNamespace(configuration=lambda *a:config,bound=SimpleNamespace(client=checkpoint))
            def execute(argv,**kwargs):
                path=Path(argv[argv.index('--worker-spec')+1]);raw=path.read_bytes();selected=json.loads(raw)
                selected['spec_sha256']=lane.sha(path)
                if kind!='no-witness':lane.write_new(Path(selected['marker']),marker(selected))
                if kind=='state-drift':(Path(selected['args']['state_dir'])/'stray').write_bytes(b'changed')
                return SimpleNamespace(returncode=0 if kind=='wrong-exit' else 86,stdout=b'')
            process=SimpleNamespace(cancellation_handlers=nullcontext,
                Runner=lambda *a:SimpleNamespace(run=execute))
            def driver(driver_args,**kwargs):
                args.workspace.mkdir();(args.workspace/'root').mkdir();args.root=args.workspace/'root'
                args.state_dir=data/'state';args.state_dir.mkdir()
                update=kwargs['runtime_module'].apply(args)
                if kind!='cleanup-failure':shutil.rmtree(args.workspace)
                return dict(status='FAIL',copy_cleanup='FAIL-owned-workspace-retained-or-partial' if kind=='cleanup-failure' else 'PASS-owned-workspace-removed',**{k:update[k] for k in ('commit_started','packages_committed','checkpoint_changed')})
            api=SimpleNamespace(normal=SimpleNamespace(scale=scale,Runtime=object),driver=SimpleNamespace(run=driver),process=process,
                                copy=object(),constructor=object(),initialize=object())
            before=observation();after=copy.deepcopy(before);after['nodes'][lane.LOCK]=copy.deepcopy(lane.LOCK_NODE)
            original_after=copy.deepcopy(before)
            if kind=='source-drift':original_after['nodes']['home/inert']['sha256']='changed'
            if kind=='no-witness':observations=[before,before,original_after]
            else:observations=[before,before,after,original_after]
            with patch.object(lane,'observe',side_effect=observations):return lane.execute_case(args,api)
    def test_only_expected_failure_plus_disposal_and_source_preservation_passes(self):
        result=self.run_case();self.assertEqual(result['status'],'PASS',result);self.assertEqual(result['failure_cases'],1)
        self.assertEqual(result['committed_transactions'],0);self.assertTrue(result['original_source_preserved'])
        self.assertEqual(result['driver']['status'],'FAIL')
    def test_failure_to_reach_boundary_is_unknown_and_not_expected_success(self):
        result=self.run_case('no-witness');self.assertEqual(result['status'],'FAIL')
        self.assertEqual(result['commit_started'],'UNKNOWN');self.assertEqual(result['failure_cases'],0)
    def test_wrong_child_exit_cannot_be_expected_success(self):
        result=self.run_case('wrong-exit');self.assertEqual(result['status'],'FAIL')
    def test_failed_copy_disposal_cannot_pass_even_with_valid_boundary(self):
        result=self.run_case('cleanup-failure');self.assertEqual(result['status'],'FAIL')
        self.assertIs(result['commit_started'],False);self.assertEqual(result['failure_cases'],0)
    def test_unexpected_checkpoint_state_file_cannot_pass(self):
        result=self.run_case('state-drift');self.assertEqual(result['status'],'FAIL')
        self.assertEqual(result['checkpoint_changed'],'UNKNOWN')
    def test_changed_original_source_revokes_expected_case_pass(self):
        result=self.run_case('source-drift');self.assertEqual(result['status'],'FAIL')
        self.assertFalse(result['original_source_preserved'])


if __name__=='__main__':unittest.main()
