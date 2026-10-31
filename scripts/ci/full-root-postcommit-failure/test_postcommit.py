#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert postcommit boundary/state/disposal controls; no ALPM or child actors."""
from contextlib import nullcontext
import ast
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value
lane=load('postcommit_fixture_lane',HERE/'run.py')
driver=load('postcommit_fixture_database',ROOT/'scripts/ci/full-root-upgrade/root_upgrade.py')
BASE=dict(line.split() for line in (ROOT/'scripts/ci/full-development-composition/expected-updater-v2.lock').read_text().splitlines())
AFTER=dict(BASE,**{'cachy-asahi-setup':'0.1.0-4'})


def spec():return dict(nonce='a'*32,root_identity=[1,2],spec_sha256='b'*64,worker_sha256='c'*64)
def marker(selected):return dict(event='successful-postcommit-exit',case=lane.CASE,nonce=selected['nonce'],exit_code=87,pid=123,
    root_identity=selected['root_identity'],spec_sha256=selected['spec_sha256'],worker_sha256=selected['worker_sha256'],
    prepared_add={'cachy-asahi-setup':'0.1.0-4'},prepared_remove={},commit_calls=1,commit_return=0,
    after_lock_sha256=lane.AFTER,checkpoint_attempted=False)
def observation(locked=False):
    nodes={'home/inert':dict(type='file',sha256='held')}
    if locked:nodes[lane.LOCK]=copy.deepcopy(lane.LOCK_NODE)
    return dict(complete=True,nodes=nodes,hardlink_groups={})
def receipt():return dict(returncode=87,termination=None,direct_child_reaped=True,group_retired=True)


class DescriptorControls(unittest.TestCase):
    def fixture(self,hard=8192):
        actual=NS(RLIMIT_NOFILE=7,RLIM_INFINITY=-1,getrlimit=Mock(return_value=(1024,hard)),setrlimit=Mock())
        return NS(resource=actual),actual
    def test_private_exact_rebind_and_other_limits(self):
        module,actual=self.fixture();lane.process_binding(module)
        self.assertIsNot(module.resource,actual);module.resource.setrlimit(7,(128,128));actual.setrlimit.assert_called_once_with(7,(8192,8192))
        module.resource.setrlimit(3,(100,100));self.assertEqual(actual.setrlimit.call_args.args,(3,(100,100)))
    def test_small_hard_or_changed_request_refuses(self):
        module,actual=self.fixture(4096)
        with self.assertRaises(ValueError):lane.process_binding(module)
        self.assertIs(module.resource,actual)
        module,actual=self.fixture();lane.process_binding(module)
        with self.assertRaises(ValueError):module.resource.setrlimit(7,(256,256))
        actual.setrlimit.assert_not_called()


class BoundaryControls(unittest.TestCase):
    def runtime(self,root):
        class Base:
            def precommit(value):value.commit_ready=True
            def observed_after(value,after):
                lane.need(after==AFTER,'inherited after selection failed');value.inherited_after=True
        callback=Mock();runtime=lane.fault_class(Base,callback)();runtime.callback=callback
        runtime.alpm=NS(started=True,handle=object(),inventory=Mock(return_value=BASE),
            alpm_trans_get_add=lambda _: 'add',alpm_trans_get_remove=lambda _: 'remove',
            packages=lambda value:{'cachy-asahi-setup':'0.1.0-4'} if value=='add' else {},alpm_trans_commit=Mock(return_value=0))
        runtime.config=dict(before_lock_sha256=lane.BEFORE,after_lock_sha256=lane.AFTER)
        runtime.root=root;runtime.args=NS(state_dir=root/'state');runtime.args.state_dir.mkdir()
        return runtime
    def test_exact_hook_lies_between_actual_successful_commit_and_checkpoint(self):
        source=ast.parse((ROOT/'scripts/update/bound_update.py').read_text())
        calls=[(node.lineno,ast.unparse(node.func)) for node in ast.walk(source) if isinstance(node,ast.Call)]
        commit=next(n for n,f in calls if f=='alpm.alpm_trans_commit')
        observed=next(n for n,f in calls if f=='adapter.observed_after')
        checkpoint=next(n for n,f in calls if f=='client.commit')
        self.assertLess(commit,observed);self.assertLess(observed,checkpoint)
    def test_inherited_precommit_refusal_never_calls_original_commit_or_exit(self):
        callback=Mock()
        class Refuse:
            def precommit(self):raise ValueError('original refused')
        value=lane.fault_class(Refuse,callback)()
        with self.assertRaisesRegex(ValueError,'original refused'):value.precommit()
        callback.assert_not_called()
    def test_no_injection_before_original_success_and_arguments_are_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            runtime=self.runtime(Path(temp));original=runtime.alpm.alpm_trans_commit
            runtime.precommit()
            with self.assertRaisesRegex(ValueError,'successful original'):runtime.observed_after(AFTER)
            original.assert_not_called();runtime.callback.assert_not_called()
            handle=runtime.alpm.handle;details=object()
            self.assertEqual(runtime.alpm.alpm_trans_commit(handle,details),0)
            self.assertEqual(runtime.commit_calls,1);self.assertEqual(runtime.commit_return,0)
            original.assert_called_once_with(handle,details)
            with self.assertRaisesRegex(ValueError,'checkpoint remains prohibited'):runtime.observed_after(AFTER)
            self.assertTrue(runtime.inherited_after);runtime.callback.assert_called_once_with(runtime,AFTER)
            with self.assertRaisesRegex(ValueError,'one original'):runtime.alpm.alpm_trans_commit(handle,details)
    def test_original_commit_failure_cannot_arm_postcommit_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            runtime=self.runtime(Path(temp));runtime.alpm.alpm_trans_commit=Mock(return_value=9)
            runtime.precommit();self.assertEqual(runtime.alpm.alpm_trans_commit(runtime.alpm.handle,None),9)
            with self.assertRaisesRegex(ValueError,'successful original'):runtime.observed_after(AFTER)
    def test_known_commit_witness_is_fsynced_before_exit87(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);runtime=self.runtime(root);runtime.precommit();runtime.alpm.alpm_trans_commit(runtime.alpm.handle,None)
            runtime.alpm.inventory.return_value=AFTER;selected=spec();selected['root_identity']=lane.identity(root);path=root/'witness'
            class Stop(Exception):pass
            def exit_process(code):
                self.assertEqual(code,87);self.assertTrue(path.is_file());raise Stop()
            with self.assertRaises(Stop):lane.arm(runtime,AFTER,selected,path,exit_process=exit_process)
            self.assertEqual(lane.boundary(json.loads(path.read_bytes()),selected),dict(commit_started=True,packages_committed=True))
    def test_wrong_after_inventory_checkpoint_or_original_return_never_exits(self):
        for change in ('inventory','state','return'):
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp);runtime=self.runtime(root);runtime.precommit();runtime.alpm.alpm_trans_commit(runtime.alpm.handle,None)
                runtime.alpm.inventory.return_value=AFTER;selected=spec();selected['root_identity']=lane.identity(root)
                if change=='inventory':runtime.alpm.inventory.return_value=BASE
                elif change=='state':(runtime.args.state_dir/'checkpoint.json').write_bytes(b'changed')
                else:runtime.commit_return=False
                exit_process=Mock()
                with self.assertRaises(ValueError):lane.arm(runtime,AFTER,selected,root/'unused',exit_process=exit_process)
                exit_process.assert_not_called();self.assertFalse((root/'unused').exists())


class TruthControls(unittest.TestCase):
    def values(self):
        selected=spec();return [receipt(),marker(selected),selected,observation(),observation(True),None,None]
    def test_expected_interruption_means_commit_true_checkpoint_false_and_failure_status(self):
        result=lane.assess(*self.values());self.assertEqual(result['status'],'FAIL')
        self.assertIs(result['commit_started'],True);self.assertIs(result['packages_committed'],True)
        self.assertIs(result['checkpoint_changed'],False);self.assertTrue(result['controlled_failure_verified'])
    def test_wrong_exit_retirement_marker_or_checkpoint_cannot_pass(self):
        for index,change in ((0,dict(returncode=86)),(0,dict(group_retired=False)),(0,dict(termination='timeout')),
            (1,dict(nonce='old')),(1,dict(commit_return=False)),(1,dict(commit_return=1)),(1,dict(commit_calls=True)),
            (1,dict(after_lock_sha256=lane.BEFORE)),(1,dict(checkpoint_attempted=True)),(1,dict(extra=True))):
            values=self.values();values[index].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):lane.assess(*values)
        values=self.values();values[-1]={'state':'changed'}
        with self.assertRaises(ValueError):lane.assess(*values)
    def test_missing_or_changed_stale_lock_and_incomplete_scan_refuse(self):
        for change in ('mode','uid','missing','incomplete'):
            values=self.values()
            if change=='mode':values[4]['nodes'][lane.LOCK]['mode']=0o600
            elif change=='uid':values[4]['nodes'][lane.LOCK]['uid']=1
            elif change=='missing':values[4]['nodes'].pop(lane.LOCK)
            else:values[4]['complete']=False
            with self.assertRaises(ValueError):lane.assess(*values)


class DisposalControls(unittest.TestCase):
    def run_case(self,kind='expected'):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);source=home/'source';source.mkdir();data=home/'data';data.mkdir()
            args=NS(source=source,data=data,workspace=home/'copy',source_root=ROOT,scale='unused',scale_sha256='unused')
            checkpoint=NS(state_directory=lambda *a:nullcontext(None),checkpoint=lambda _:None)
            scale=NS(configuration=lambda *a:{'limits':{}},bound=NS(client=checkpoint))
            def execute(argv,**kwargs):
                path=Path(argv[argv.index('--worker-spec')+1]);selected=json.loads(path.read_bytes());selected['spec_sha256']=lane.sha(path)
                if kind not in ('no-witness','unexpected-checkpoint'):lane.write_new(Path(selected['marker']),marker(selected))
                if kind=='state-drift':(Path(selected['args']['state_dir'])/'stray').write_bytes(b'changed')
                return NS(returncode=86 if kind=='wrong-exit' else 1 if kind=='unexpected-checkpoint' else 87,
                    stdout=json.dumps(dict(status='PASS',commit_started=True,packages_committed=True,checkpoint_changed=True)).encode() if kind=='unexpected-checkpoint' else b'')
            process=NS(cancellation_handlers=nullcontext,Runner=lambda *a:NS(run=execute))
            def driver_run(driver_args,**kwargs):
                args.workspace.mkdir();(args.workspace/'root').mkdir();args.root=args.workspace/'root'
                args.state_dir=data/'state';args.state_dir.mkdir();update=kwargs['runtime_module'].apply(args)
                if kind!='cleanup-failure':shutil.rmtree(args.workspace)
                return dict(status='FAIL',copy_cleanup='FAIL-owned-workspace-retained-or-partial' if kind=='cleanup-failure' else 'PASS-owned-workspace-removed',
                            **{k:update[k] for k in ('commit_started','packages_committed','checkpoint_changed')})
            api=NS(normal=NS(scale=scale,Runtime=object),driver=NS(run=driver_run),process=process,copy=object(),constructor=object(),initialize=object())
            final=observation()
            if kind=='source-drift':final['nodes']['home/inert']['sha256']='changed'
            proofs=dict(after587_database_verified=True,postcommit_payload_verified=True,postcommit_preservation_verified=True)
            post=Mock(return_value=(observation(True),proofs))
            if kind=='payload-failure':post.side_effect=ValueError('payload differs')
            with patch.object(lane,'observe',side_effect=[observation(),observation(),final]),\
                 patch.object(lane,'prepare_verifier',return_value=(object(),[],{})),patch.object(lane,'verify_after',post):
                return lane.execute_case(args,api)
    def test_only_verified_interruption_and_disposal_is_case_pass(self):
        result=self.run_case();self.assertEqual(result['status'],'PASS',result);self.assertEqual(result['committed_transactions'],1)
        self.assertEqual(result['failure_cases'],1);self.assertEqual(result['driver']['status'],'FAIL')
        self.assertIs(result['checkpoint_changed'],False);self.assertTrue(result['original_source_preserved'])
    def test_missing_witness_keeps_uncertainty_and_has_no_case_credit(self):
        result=self.run_case('no-witness');self.assertEqual(result['status'],'FAIL');self.assertEqual(result['packages_committed'],'UNKNOWN')
        self.assertEqual(result['failure_cases'],0);self.assertEqual(result['copy_cleanup'],'PASS-owned-workspace-removed')
    def test_payload_failure_keeps_known_commit_and_checkpoint_truth(self):
        result=self.run_case('payload-failure');self.assertEqual(result['status'],'FAIL');self.assertIs(result['packages_committed'],True)
        self.assertIs(result['checkpoint_changed'],False);self.assertEqual(result['committed_transactions'],1)
    def test_checkpoint_drift_is_unknown_but_successful_commit_stays_known(self):
        result=self.run_case('state-drift');self.assertEqual(result['status'],'FAIL');self.assertIs(result['packages_committed'],True)
        self.assertEqual(result['checkpoint_changed'],'UNKNOWN')
    def test_wrong_exit_copy_failure_or_original_source_drift_never_pass(self):
        for kind in ('wrong-exit','cleanup-failure','source-drift'):
            with self.subTest(kind=kind):self.assertEqual(self.run_case(kind)['status'],'FAIL')
    def test_unexpected_normal_return_retains_commit_and_checkpoint_truth_without_case_credit(self):
        result=self.run_case('unexpected-checkpoint');self.assertEqual(result['status'],'FAIL')
        self.assertIs(result['packages_committed'],True);self.assertIs(result['checkpoint_changed'],True)
        self.assertEqual(result['committed_transactions'],1);self.assertEqual(result['failure_cases'],0)
    def test_supervision_uncertainty_uses_nonreturning_outer_disposal_handoff(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'retirement.json';exit_process=Mock(side_effect=SystemExit(88))
            with patch.object(sys,'stdout',io.StringIO()),self.assertRaises(SystemExit):lane.unsafe_retirement(path,RuntimeError('not retired'),exit_process=exit_process)
            exit_process.assert_called_once_with(88);value=json.loads(path.read_bytes())
            self.assertEqual(value['packages_committed'],'UNKNOWN');self.assertEqual(value['copy_cleanup'],'NOT ATTEMPTED-live-state-unknown')


class IndependentProjectionControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.root_limits=__import__('dataclasses').make_dataclass('Limits',[('deadline',float)])(0)
        self.before=observation();self.after=observation(True)
        self.verifier=NS(root_limits=self.root_limits,tree=Mock(return_value=self.after['nodes']),observation=self.after,
                         baseline=self.before,auxiliary_checks=[dict(checkpoint='observe-after')])
        self.old=[dict(name=n,version=v,files=[]) for n,v in BASE.items()]
        self.new=[dict(name=n,version=v,files=[] if n!='cachy-asahi-setup' else ['six'],owned_paths=[] if n!='cachy-asahi-setup' else ['six']) for n,v in AFTER.items()]
        self.driver=NS(ownership=Mock(return_value=({'held'},['kernel'])),preserved=Mock())
        self.api=NS(driver=self.driver);self.args=NS(root=self.root)
    def run_verify(self):
        with patch.object(lane,'database_after',return_value=self.new):
            return lane.verify_after(self.api,self.args,{},self.verifier,self.old,{'six':dict(type='file')})
    def test_reuses_held_projected_tree_database_and_original_preservation_checks(self):
        observed,proof=self.run_verify();self.assertIs(observed,self.after)
        self.assertTrue(proof['after587_database_verified']);self.assertTrue(proof['postcommit_payload_verified'])
        self.verifier.tree.assert_called_once_with(self.root);self.driver.preserved.assert_called_once_with(self.before['nodes'],self.after['nodes'],{'held'})
        self.assertGreater(self.verifier.root_limits.deadline,0)
    def test_incomplete_projected_tree_never_reaches_database_or_preservation(self):
        self.verifier.tree.side_effect=ValueError('held projection refused')
        with patch.object(lane,'database_after') as database,self.assertRaisesRegex(ValueError,'projection refused'):
            lane.verify_after(self.api,self.args,{},self.verifier,self.old,{'six':dict(type='file')})
        database.assert_not_called();self.driver.preserved.assert_not_called()
    def test_wrong_after_inventory_or_nonselected_metadata_or_selected_ownership_refuses(self):
        for change in ('version','metadata','ownership','directory-ownership'):
            changed=copy.deepcopy(self.new)
            if change=='version':changed[0]['version']='wrong'
            elif change=='metadata':next(row for row in changed if row['name']!='cachy-asahi-setup')['files']=['changed']
            elif change=='ownership':next(row for row in changed if row['name']=='cachy-asahi-setup')['files']=[]
            else:next(row for row in changed if row['name']=='cachy-asahi-setup')['owned_paths'].append('unexpected-directory')
            with patch.object(lane,'database_after',return_value=changed),self.assertRaises(ValueError):
                lane.verify_after(self.api,self.args,{},self.verifier,self.old,{'six':dict(type='file')})
    def test_verifier_baseline_precedes_archive_and_pin_mismatch_refuses_projection(self):
        source_before=observation();prefix='var/lib/pacman/local/cachy-asahi-setup-0.1.0-3'
        source_before['nodes'][prefix+'/files']={'node':'held'}
        verifier=NS(tree=Mock(return_value=source_before['nodes']),projected_paths=Mock(),archive_payload=Mock(),
                    aux_before=object(),projected={})
        reader=NS(database=Mock(return_value=self.old),directory=lambda *a:nullcontext(9),read_record=Mock(return_value=b'files'),
                  fields=lambda raw:{'FILES':['usr/','usr/bin/old']})
        api=NS(linked=NS(Runtime=Mock(return_value=verifier)),driver=reader)
        args=NS(root=self.root,comparator='/inert/comparator',package='/inert/setup4')
        with patch.object(lane,'sha',return_value='0'*64),self.assertRaisesRegex(ValueError,'setup4 archive differs'):
            lane.prepare_verifier(api,args,{},source_before)
        verifier.archive_payload.assert_not_called();verifier.projected_paths.assert_not_called()


class LockedDatabaseControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.nodes={};local=self.root/'var/lib/pacman/local';local.mkdir(parents=True)
        self.node('var/lib/pacman/db.lck',b'',0)
        self.lock=dict(lane.LOCK_NODE,uid=os.getuid(),gid=os.getgid());self.patched=patch.object(lane,'LOCK_NODE',self.lock)
        self.patched.start();self.addCleanup(self.patched.stop)
        self.node('var/lib/pacman/local/ALPM_DB_VERSION',b'9\n')
        for name,version in AFTER.items():
            prefix='var/lib/pacman/local/'+name+'-'+version
            self.node(prefix+'/desc',('%NAME%\n'+name+'\n\n%VERSION%\n'+version+'\n\n%ARCH%\nany\n').encode())
            self.node(prefix+'/files',b'') # ALPM metapackage empty records remain valid.
    def node(self,name,data,mode=0o644):
        path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(mode)
        info=path.stat();self.nodes[name]=dict(type='file',mode=mode,uid=info.st_uid,gid=info.st_gid,bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
    def read(self):
        # A mode0000 file cannot be read by this unprivileged unit process. The
        # existing bounded reader's lock read is modeled; desc/files reads are real.
        original=driver.read_record
        def reader(fd,name,**kw):
            if name=='db.lck':
                self.assertEqual(kw,dict(maximum=0,expected=self.lock));return b''
            return original(fd,name,**kw)
        with patch.object(driver,'read_record',side_effect=reader):return lane.database_after(driver,self.root,dict(complete=True,nodes=self.nodes))
    def test_all587_records_and_empty_metapackage_records_read_without_alpm(self):
        records=self.read();self.assertEqual({r['name']:r['version'] for r in records},AFTER)
        self.assertTrue(all(r['files']==[] for r in records))
        with self.assertRaisesRegex(ValueError,'existing package-manager lock'):driver.database(self.root)
    def test_database_content_changed_after_observation_refuses(self):
        path=self.root/'var/lib/pacman/local/cachy-asahi-setup-0.1.0-4/desc';path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaisesRegex(ValueError,'observation'):self.read()
    def test_changed_lock_metadata_or_missing_record_refuses(self):
        self.nodes[lane.LOCK]['mode']=0o600
        with self.assertRaisesRegex(ValueError,'stale lock'):self.read()
        self.nodes[lane.LOCK]['mode']=0
        (self.root/'var/lib/pacman/local/cachy-asahi-setup-0.1.0-4/files').unlink()
        with self.assertRaises(FileNotFoundError):self.read()


if __name__=='__main__':unittest.main()
