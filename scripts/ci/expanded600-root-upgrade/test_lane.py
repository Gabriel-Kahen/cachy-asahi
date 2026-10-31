#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source/data-only controls; no Docker, ALPM, compiler, VM, key or network actors."""
import ast
import copy
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock,patch
import contract as C
import adapter
import gate
owner=C.load('_expanded600_root_owner_tests',C.HERE/'run.py')

ROOT=next(p for p in C.HERE.parents if (p/'manifests/packages.toml').is_file())
PAIR=ROOT/'artifacts/development/setup5-accepted-pair-inputs-20261016/payload'


class SourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='root600-source-controls-');cls.base=Path(cls.temp.name)
        cls.held=C.read(C.HERE/'held-pins.json');cls.codes={};cls.sources={}
        for case,row in cls.held.items():
            source=cls.base/('source-'+case);source.mkdir();cls.sources[case]=source
            for name,pin in row['pins'].items():
                path=source/name;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(subprocess.check_output(['git','-C',str(ROOT),'show',row['source']+':'+name],timeout=15))
            code=cls.base/('private-'+case);adapter.prepare(source,code,case,git=False);cls.codes[case]=code
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def test_exact600_only_setup3_to_genuine5(self):
        before,after=C.locks();self.assertEqual(len(before),600);self.assertEqual(len(after),600)
        self.assertEqual([n for n in before if before[n]!=after[n]],['cachy-asahi-setup'])
        self.assertEqual(after['cachy-asahi-setup'],'0.1.0-5')
    def test_unbound_policy_stops_owner_before_any_actor(self):
        with patch.object(C,'read',return_value={'schema_version':1,'status':'UNBOUND'}),patch.object(C,'load') as load:
            # Arg parsing is not the acceptance gate. The policy itself must refuse without imports/actors.
            with self.assertRaisesRegex(ValueError,'unbound'):C.policy()
            load.assert_not_called()
    def test_all_private_pin_closures_bind_derived_bytes(self):
        for code in self.codes.values():
            config=C.read(code/'upgrade-config.json')
            for name,digest in config['code_pins'].items():self.assertEqual(C.sha(code/name),digest,name)
            self.assertEqual(config['scale']['before_lock_sha256'],C.BEFORE)
            self.assertEqual(config['scale']['after_lock_sha256'],C.AFTER)
            self.assertEqual(config['scale']['limits']['window_bytes'],16*1024**2)
            self.assertEqual(config['scale']['limits']['decoded_bytes'],16*1024**2)
    def test_changed_frozen_input_refuses_before_output(self):
        source=self.sources['normal'];path=source/'scripts/client/client.py';raw=path.read_bytes();path.write_bytes(raw+b'\n')
        try:
            target=self.base/'must-not-exist'
            with self.assertRaisesRegex(ValueError,'identity differs'):adapter.prepare(source,target,'normal',git=False)
            self.assertFalse(target.exists())
        finally:path.write_bytes(raw)
    def test_fresh_output_and_closed_case_required(self):
        with self.assertRaisesRegex(ValueError,'fresh'):adapter.prepare(self.sources['normal'],self.codes['normal'],'normal',git=False)
        with self.assertRaisesRegex(ValueError,'closed'):adapter.prepare(self.sources['normal'],self.base/'never','other',git=False)
    def test_original_resources_cleanup_reaping_and_apis_unchanged(self):
        untouched=['scripts/client/client.py','scripts/release/release.py','scripts/update/bound_update.py',
            'scripts/update/archive_stream.py','scripts/update/aux_checkpoint.py',
            'scripts/update/aux_initialize.py','scripts/update/aux_copy.py','scripts/update/supervision.py',
            'scripts/ci/full-root-upgrade-caller/persistent_scope.py','scripts/ci/full-root-upgrade-caller/run.py',
            'scripts/port/kernel-native-job/runtime.py']
        for case,code in self.codes.items():
            for name in untouched:self.assertEqual((code/name).read_bytes(),(self.sources[case]/name).read_bytes(),name)
    def test_complete_protected_policy_uses_the_selected600_inventory(self):
        before,after=C.locks();protected=sorted(set(before)-{'cachy-asahi-setup'})
        for case,code in self.codes.items():
            module=C.load('selected600_policy_'+case,code/'scripts/update/generic_policy.py')
            original=C.load('original587_policy_'+case,self.sources[case]/'scripts/update/generic_policy.py')
            kernel=next(n for n in protected if n.startswith('linux-'))
            policy=dict(schema_version=1,purpose='cachy-asahi-generic-development-update-policy',
                release_id='selected600-test',protected_packages=protected,
                protected_versions={n:before[n] for n in protected},platform_roles={'kernel':[kernel]},
                protected_units={k:sorted(v) for k,v in module.asahi.REQUIRED_UNITS.items()},
                before_lock_sha256=C.BEFORE,after_lock_sha256=C.AFTER)
            with self.assertRaisesRegex(ValueError,'invalid identifier list'):original.protected_names(policy)
            self.assertEqual(len(module.protected_names(policy)),599)
            settings=dict(purpose='disposable-generic-bound-update',model='generic-development-only',release_id=policy['release_id'])
            snapshot=dict(release={'release_id':policy['release_id']},spec={'policy':{'protected_packages':protected}})
            files={kernel:['/usr/lib/modules/6.1/kernel/inert.ko']}
            self.assertEqual(module.authorize(policy,settings,snapshot,before,after,files,files)['decision'],
                'generic-development-transaction-allowed')
            for names in (protected+[protected[0]],list(before)+['extra-invalid-bound']):
                with self.assertRaises(ValueError):module.protected_names(policy|{'protected_packages':names})
            bad=dict(before);bad[kernel]='changed'
            with self.assertRaises(ValueError):module.authorize(policy,settings,snapshot,bad,after,files,files)

    def test_only_declared_private_files_change(self):
        allowed=adapter.STRINGS|{'scripts/ci/full-development-composition/expected-updater-v2.lock',
            'scripts/ci/full-development-composition/expected-setup4-v2.lock'}
        for case,code in self.codes.items():
            changes=C.read(code/'adapter.json')['changes'];self.assertLessEqual(set(changes),allowed)
            for name in changes:self.assertEqual(changes[name]['before_sha256'],self.held[case]['pins'][name]['sha256'])
    def test_runtime_control_flow_is_inherited(self):
        class Neutral(ast.NodeTransformer):
            def visit_Constant(self,node):
                return ast.copy_location(ast.Constant(value=type(node.value).__name__),node)
            def visit_keyword(self,node):
                node=self.generic_visit(node)
                if node.arg=='after600_database_verified':node.arg='after587_database_verified'
                return node
        for case,code in self.codes.items():
            for name in adapter.STRINGS:
                if name not in self.held[case]['pins']:continue
                original=name
                if name=='scripts/ci/full-root-upgrade-caller/upgrade_hook.py' and case!='normal':
                    original='scripts/ci/'+('full-root-failed-update' if case.startswith('pre') else 'full-root-postcommit-failure')+'/caller.py'
                old=ast.parse((self.sources[case]/original).read_text());new=ast.parse((code/name).read_text())
                for tree in (old,new):
                    tree.body=[n for n in tree.body if not (isinstance(n,ast.FunctionDef) and n.name=='inspect_package') and
                        not (name.endswith('/container.py') and isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('PROJECTS','EXTRAS'))]
                self.assertEqual(ast.dump(Neutral().visit(old)),ast.dump(Neutral().visit(new)),name)
    def test_private_bootstrap_has_only_the_explicit27_additions(self):
        module=C.load('root600_test_bootstrap',self.codes['normal']/'scripts/ci/full-root-upgrade-caller/container.py')
        self.assertEqual(len(module.PROJECTS),17);self.assertEqual(len(module.EXTRAS),10)
        self.assertLessEqual(adapter.SCRIPTS,module.PROJECTS)
        self.assertEqual(module.EXTRAS,adapter.AUDIO|{'htmlq','pacman-contrib','archlinux-contrib','pyalpm'})
        self.assertLessEqual(module.PROJECTS|module.EXTRAS,C.locks()[0].keys())
    def test_normal_constructor_selection_and_payload(self):
        code=self.codes['normal'];ctor=C.load('root600_test_ctor',code/'scripts/ci/full-root-upgrade/construct_repository.py')
        args=NS(source_root=code,setup4_pair=PAIR,package=PAIR/'packages/cachy-asahi-setup-a/cachy-asahi-setup-0.1.0-5-any.pkg.tar.xz',
                provenance=PAIR/'runtime/cachy-asahi-setup-a/provenance.json')
        held=ctor.inspect_package(args);self.assertEqual(len(held.payload),6);self.assertEqual(ctor.sha(held.package),adapter.PACKAGE)
        self.assertEqual(ctor.locks(code,ctor.apis(code).setup)[2:],C.locks())
        args.package=PAIR/'packages/cachy-asahi-setup-b/cachy-asahi-setup-0.1.0-5-any.pkg.tar.xz'
        with self.assertRaisesRegex(ValueError,'explicit first'):ctor.inspect_package(args)
    def test_accepted_pair_stage_retains_all147_raw_members(self):
        target=self.base/'pair-staged'
        with patch.object(C,'revision',return_value=C.PAIR):gate.stage_pair(PAIR,target)
        expected={p.relative_to(PAIR).as_posix():C.sha(p) for p in PAIR.rglob('*') if p.is_file()}
        actual={p.relative_to(target).as_posix():C.sha(p) for p in target.rglob('*') if p.is_file()}
        self.assertEqual(actual,expected);self.assertEqual(len(actual),149)
        self.assertEqual((target/'runtime/lifecycle.log').stat().st_size,0)
    def test_precommit_inherited_refusal_cannot_be_success(self):
        lane=C.load('root600_test_pre',self.codes['precommit-exit86']/'scripts/ci/full-root-failed-update/run.py');arm=Mock()
        class Refuse:
            def precommit(self):raise ValueError('original refusal')
        with self.assertRaisesRegex(ValueError,'original refusal'):lane.fault_class(Refuse,arm)().precommit()
        arm.assert_not_called()
    def test_precommit_arm_requires_original_checks(self):
        lane=C.load('root600_test_pre2',self.codes['precommit-exit86']/'scripts/ci/full-root-failed-update/run.py');events=[]
        class Original:
            def precommit(self):events.append('original')
        def arm(_):events.append('arm')
        with self.assertRaisesRegex(ValueError,'commit remains prohibited'):lane.fault_class(Original,arm)().precommit()
        self.assertEqual(events,['original','arm'])
    def test_postcommit_arm_cannot_run_before_original_commit_returns_zero(self):
        lane=C.load('root600_test_post',self.codes['postcommit-exit87']/'scripts/ci/full-root-postcommit-failure/run.py');arm=Mock()
        class Original:
            def observed_after(self,after):self.checked=after
        obj=lane.fault_class(Original,arm)();obj.commit_calls=1;obj.commit_return=1
        with self.assertRaisesRegex(ValueError,'successful original'):obj.observed_after(C.locks()[1])
        arm.assert_not_called();self.assertEqual(obj.checked,C.locks()[1])
        obj.commit_return=0
        with self.assertRaisesRegex(ValueError,'checkpoint remains prohibited'):obj.observed_after(C.locks()[1])
        arm.assert_called_once_with(obj,C.locks()[1])
    def test_fault_descriptor_and_decoder_budgets_not_raised(self):
        for case in ('precommit-exit86','postcommit-exit87'):
            folder='full-root-failed-update' if case.startswith('pre') else 'full-root-postcommit-failure'
            lane=C.load('root600_budget_'+folder,self.codes[case]/'scripts/ci'/folder/'run.py')
            self.assertEqual(lane.CHILD_NOFILE,8192)
            config=C.read(self.codes[case]/'upgrade-config.json');self.assertEqual(config['failure']['worker_seconds'],1200)
            self.assertEqual(config['failure']['verify_seconds'],600);self.assertEqual(config['driver_seconds'],2400)


def receipt(case):
    count,started,committed,checkpoint={'normal':(1,True,True,True),'precommit-exit86':(0,False,False,False),
                                      'postcommit-exit87':(1,True,True,False)}[case]
    driver=dict(status='PASS',committed_transactions=count,commit_started=started,packages_committed=committed,
        checkpoint_changed=checkpoint,copy_cleanup='PASS-owned-workspace-removed',update={'checkpoint_directory_synced':True},
        case=case,failure_cases=1,original_source_preserved=True,after600_database_verified=True,
        postcommit_payload_verified=True,postcommit_preservation_verified=True)
    return dict(status='PASS',package_count=600,final_package_count=600,installed_inventory_sha256=C.BEFORE,
        final_inventory_sha256=C.BEFORE,dependency_checks='PASS-no-waivers',payload_ownership='PASS',
        full_root_upgrade=dict(status='PASS',driver=driver,persistent_source_preserved=True,
            persistent_source={'source_manifest_sha256':'held'},persistent_source_after={'source_manifest_sha256':'held'}))


class ResultControls(unittest.TestCase):
    def test_three_distinct_truths(self):
        for case in C.SOURCES:owner.verify_result(receipt(case),case)
    def test_normal_requires_actual_directory_sync(self):
        row=receipt('normal');row['full_root_upgrade']['driver']['update']['checkpoint_directory_synced']=False
        with self.assertRaisesRegex(ValueError,'sync'):owner.verify_result(row,'normal')
    def test_unknown_or_wrong_type_commit_truth_refuses(self):
        for value in ('UNKNOWN',1,None):
            row=receipt('normal');row['full_root_upgrade']['driver']['commit_started']=value
            with self.assertRaisesRegex(ValueError,'truth'):owner.verify_result(row,'normal')
    def test_failed_case_is_never_normal_acceptance(self):
        for case in ('precommit-exit86','postcommit-exit87'):
            with self.assertRaisesRegex(ValueError,'truth'):owner.verify_result(receipt(case),'normal')
    def test_postcommit_requires_independent_database_payload_preservation(self):
        for key in ('after600_database_verified','postcommit_payload_verified','postcommit_preservation_verified'):
            row=receipt('postcommit-exit87');row['full_root_upgrade']['driver'][key]=False
            with self.assertRaisesRegex(ValueError,'independent'):owner.verify_result(row,'postcommit-exit87')
    def test_source_change_or_uncertain_disposal_refuses(self):
        for key in ('persistent_source','copy_cleanup'):
            row=receipt('normal')
            if key=='persistent_source':row['full_root_upgrade']['persistent_source_after']['source_manifest_sha256']='changed'
            else:row['full_root_upgrade']['driver'][key]='UNKNOWN'
            with self.assertRaisesRegex(ValueError,'source preservation'):owner.verify_result(row,'normal')
    def test_incomplete_outer600_or_dependency_waiver_refuses(self):
        for key,value in [('package_count',599),('final_inventory_sha256',C.AFTER),('dependency_checks','WAIVED')]:
            row=receipt('normal');row[key]=value
            with self.assertRaisesRegex(ValueError,'outer actual600'):owner.verify_result(row,'normal')
    def test_unrelated_cache_owner_refuses_before_removal(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);(out/'owner.json').write_bytes(C.encoded({'purpose':'other'}))
            with self.assertRaisesRegex(ValueError,'owned600'):owner.cleanup_ready(out/'ready600',out,dict(output=str(out)))


if __name__=='__main__':unittest.main(verbosity=2)
