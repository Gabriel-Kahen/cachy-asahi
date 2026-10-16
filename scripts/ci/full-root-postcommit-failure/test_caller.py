#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert separate-lane caller checks; no native owner, child or signer executes."""
import hashlib
import importlib.util
import json
import io
import shutil
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())


def load(name):
    spec=importlib.util.spec_from_file_location('failure_'+name,HERE/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


h=load('caller');launch=load('launch');lane=load('run')


class HookControls(unittest.TestCase):
    def execute(self,change=None,source_change=False,worker_change=None):
        with tempfile.TemporaryDirectory() as temp:
            volume=Path(temp);signing=volume/'signing';signing.mkdir()
            expected=dict(line.split() for line in (ROOT/'scripts/ci/full-development-composition/expected-updater-v2.lock').read_text().splitlines())
            config=dict(stage_seconds=900,verify_seconds=600,driver_seconds=2400,
                scale={'limits':dict(root_nodes=200000,root_bytes=6*1024**3,file_bytes=1024**3,package_files=500000)})
            driver=dict(status='PASS',case=h.CASE,failure_cases=1,committed_transactions=1,
                commit_started=True,packages_committed=True,checkpoint_changed=False,
                after587_database_verified=True,postcommit_payload_verified=True,postcommit_preservation_verified=True,
                original_source_preserved=True,copy_cleanup='PASS-owned-workspace-removed')
            if change:driver.update(change)
            row=dict(returncode=0,termination=None,direct_child_reaped=True,group_kill_sent=True,stdout=json.dumps(driver).encode())
            if worker_change:row.update(worker_change)
            supervisor=SimpleNamespace(run=Mock(return_value=row))
            scope=SimpleNamespace(materialize=Mock(return_value=dict(status='PASS',source_manifest_sha256='a'*64)),
                verify=Mock(return_value=dict(status='PASS',source_manifest_sha256=('b' if source_change else 'a')*64)))
            modules={'caller_stage_roots':SimpleNamespace(Limits=lambda **kw:SimpleNamespace(**kw)),
                'caller_upgrade_supervision':supervisor,'caller_persistent_scope':scope,
                'caller_scale_validation':SimpleNamespace(configuration=Mock())}
            composition=SimpleNamespace(guard=Mock(),inventory=Mock(return_value=expected))
            with patch.object(h,'VOLUME',volume),patch.object(h,'SIGNING',signing),patch.object(h,'configuration',return_value=config),\
                 patch.object(h,'selected_links'),patch.object(h,'load',side_effect=lambda name,path:modules[name]),\
                 patch.object(h,'quiesce',return_value={'status':'PASS'}),patch.object(h,'driver_command',return_value=['INERT DRIVER']),\
                 patch.dict(os.environ,CACHY_ASAHI_BOUND_UPDATE='a'*32):
                result=h.run([],{'full_root_upgrade':True,'test_signer_fingerprint':'A'*40},expected,Path('/inputs'),Path('/unused'),composition)
            self.assertEqual(supervisor.run.call_count,1)
            return result
    def test_exact_interruption_has_one_commit_and_separate_scope(self):
        value=self.execute();self.assertEqual(value['status'],'PASS',value)
        self.assertEqual(value['failure_cases'],1);self.assertEqual(value['committed_transactions'],1)
        self.assertEqual(value['transaction_acceptance'],'NOT ESTABLISHED');self.assertTrue(value['persistent_source_preserved'])
    def test_normal_upgrade_success_is_not_a_failed_update_case(self):
        value=self.execute(dict(committed_transactions=1,commit_started=True,packages_committed=True,checkpoint_changed=True))
        self.assertEqual(value['status'],'FAIL');self.assertTrue(value['packages_committed'])
    def test_missing_boundary_recovery_or_source_proof_cannot_pass(self):
        for change in (dict(failure_cases=0),dict(failure_cases=True),dict(committed_transactions=False),dict(case='other'),
                       dict(original_source_preserved=False),dict(after587_database_verified=False),dict(postcommit_payload_verified=1),
                       dict(postcommit_preservation_verified=None),dict(committed_transactions=0),dict(copy_cleanup='FAIL-owned-workspace-retained-or-partial')):
            with self.subTest(change=change):self.assertEqual(self.execute(change)['status'],'FAIL')
    def test_timeout_remains_unknown_and_is_not_retried(self):
        value=self.execute(worker_change=dict(termination='timeout',returncode=-9,stdout=b''))
        self.assertEqual(value['status'],'FAIL');self.assertEqual(value['commit_started'],'UNKNOWN')
    def test_outer_persistent_source_drift_revokes_recovery_pass(self):
        value=self.execute(source_change=True);self.assertEqual(value['status'],'FAIL')
        self.assertNotIn('persistent_source_preserved',value)
    def test_driver_command_binds_only_declared_failure_and_existing_inputs(self):
        config=dict(copy_seconds=600,driver_seconds=2400,code_pins={'scripts/update/linked_runtime.py':'a'*64,
            'scripts/update/aux_initialize.py':'b'*64},release=dict(supported_models=['m2-air-13','m2-air-15'],sequence=1))
        with patch.object(h,'digest',return_value='c'*64),patch.object(h.sys,'executable','/usr/bin/python3'):
            argv=h.driver_command(config,Path('/control'),Path('/stage'),'A'*40)
        self.assertEqual(argv[argv.index('--failure-case')+1],h.CASE)
        self.assertEqual(argv[argv.index('--lane-config')+1],'/upgrade-config.json')
        self.assertIn('/upgrade-code/scripts/ci/full-root-postcommit-failure/run.py',argv)
        self.assertEqual(argv[argv.index('--runtime')+1],'/upgrade-code/scripts/update/linked_runtime.py')
        self.assertIn('--auxiliary-runtime',argv)


class FrozenConfigurationControl(unittest.TestCase):
    def test_frozen_lane_loads_existing_apis_and_rejects_config_drift_without_actor(self):
        config=HERE/'lane-config.json';value=json.loads(config.read_bytes())
        args=SimpleNamespace(source_root=ROOT,lane_config=config,lane_config_sha256=lane.sha(config),
            failure_case=lane.CASE,auxiliary_runtime=True,runtime=ROOT/'scripts/update/linked_runtime.py',
            runtime_sha256=value['code_pins']['scripts/update/linked_runtime.py'],
            initializer=ROOT/'scripts/update/aux_initialize.py',initializer_sha256=value['code_pins']['scripts/update/aux_initialize.py'],
            comparator=ROOT/'scripts/ci/full-development-composition/audio_aux.py')
        read=lane.read
        def projected(path,maximum=1024**2):
            path=Path(path)
            if path.parent==ROOT/'scripts/ci/full-root-postcommit-failure':path=HERE/path.name
            return read(path,maximum)
        with patch.object(lane,'read',side_effect=projected):
            selected=lane.selected_api(args)
            self.assertEqual(Path(selected.driver.__file__),ROOT/lane.NORMAL)
            self.assertEqual(selected.config['failure']['case'],lane.CASE)
            args.lane_config_sha256='0'*64
            with self.assertRaisesRegex(ValueError,'configuration pin'):lane.selected_api(args)

    def test_decoder_budgets_remain_exact16mib(self):
        original=json.loads((HERE/'lane-config.json').read_bytes())
        self.assertEqual(original['scale']['limits']['window_bytes'],16*1024**2)
        self.assertEqual(original['scale']['limits']['decoded_bytes'],16*1024**2)
        with tempfile.TemporaryDirectory() as temp:
            config=Path(temp)/'config.json'
            def digest(path):
                path=Path(path)
                try:return original['code_pins'][path.relative_to(ROOT).as_posix()]
                except ValueError:return original['external_pins'][str(path)]
            for field in ('window_bytes','decoded_bytes'):
                value=json.loads(json.dumps(original));value['scale']['limits'][field]=1024**2
                config.write_text(json.dumps(value))
                with patch.object(h,'ordinary',side_effect=lambda path,*a:Path(path)),patch.object(h,'digest',side_effect=digest):
                    with self.assertRaisesRegex(ValueError,'16MiB'):h.configuration(config,ROOT)


class LauncherControls(unittest.TestCase):
    def invoke(self,tamper=False,purpose='actual587-postcommit-failure-disposal-test',uncertain=False):
        with tempfile.TemporaryDirectory() as temp:
            code=Path(temp);names=['scripts/ci/full-root-upgrade-caller/'+n for n in ('run.py','container.py','persistent_scope.py')]
            names += [launch.PREFIX+n for n in ('caller.py','launch.py','run.py')]
            pins={}
            for name in names:
                path=code/name;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes((HERE/'launch.py').read_bytes() if name.endswith('/launch.py') else ('INERT '+name).encode())
                pins[name]=hashlib.sha256(path.read_bytes()).hexdigest()
            config=dict(purpose=purpose,failure=dict(case='postcommit-exit87',exit_code=87,worker_seconds=1200,verify_seconds=600),code_pins=pins)
            cfg=code/'lane.json';cfg.write_text(json.dumps(config))
            if tamper:(code/names[1]).write_bytes(b'changed')
            owner=SimpleNamespace();seen={}
            def main():
                seen['path']=owner.CALLER
                seen['files']={p.name:p.read_bytes() for p in owner.CALLER.iterdir()}
                public=code/'output/public';public.mkdir(parents=True)
                (public/'coordinator.json').write_text(json.dumps(dict(cleanup={'status':'FAIL' if uncertain else 'PASS'},upgrade_volume_cleanup='PASS-absence-verified')))
                return 0
            owner.main=Mock(side_effect=main)
            spec=SimpleNamespace(name='inert_owner',loader=SimpleNamespace(exec_module=Mock()))
            with patch.object(sys,'stderr',io.StringIO()),patch.object(sys,'argv',['launch.py','--upgrade-code',str(code),'--upgrade-config',str(cfg),'--output',str(code/'output')]),\
                 patch.object(launch.importlib.util,'spec_from_file_location',return_value=spec) as imported,\
                 patch.object(launch.importlib.util,'module_from_spec',return_value=owner):
                if tamper or purpose!='actual587-postcommit-failure-disposal-test':
                    with self.assertRaises(ValueError):launch.main()
                    imported.assert_not_called();owner.main.assert_not_called()
                else:
                    self.assertEqual(launch.main(),0);owner.main.assert_called_once()
                    self.assertEqual(set(seen['files']),{'container.py','persistent_scope.py','upgrade_hook.py'})
                    self.assertEqual(seen['files']['upgrade_hook.py'],(code/(launch.PREFIX+'caller.py')).read_bytes())
                    self.assertEqual(seen['path'].exists(),uncertain)
                    if uncertain:shutil.rmtree(seen['path']) # This test's retained inert source fixture only.
    def test_private_caller_binding_reuses_held_owner_and_retires_temporary_source(self):self.invoke()
    def test_uncertain_owner_cleanup_retains_backing_sources(self):self.invoke(uncertain=True)
    def test_source_tamper_refuses_before_import_or_actor(self):self.invoke(tamper=True)
    def test_normal_lane_config_cannot_accidentally_select_failure(self):self.invoke(purpose='actual587-persistent-root-setup4-test')


if __name__=='__main__':unittest.main()
