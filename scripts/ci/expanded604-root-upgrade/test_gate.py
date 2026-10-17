# SPDX-License-Identifier: MIT
"""Finite authority/result controls; temporary data only, every actor blocked."""
import copy
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
import contract as C
import gate
import run as owner
import freeze


def receipt(case):
    truth={'normal':(1,True,True,True),'precommit-exit86':(0,False,False,False),'postcommit-exit87':(1,True,True,False)}[case]
    driver=dict(zip(('committed_transactions','commit_started','packages_committed','checkpoint_changed'),truth))
    driver.update(status='PASS',copy_cleanup='PASS-owned-workspace-removed',update=dict(checkpoint_directory_synced=True),
         case=case,failure_cases=1,original_source_preserved=True,after604_database_verified=True,
         postcommit_payload_verified=True,postcommit_preservation_verified=True)
    return dict(status='PASS',package_count=604,final_package_count=604,installed_inventory_sha256=C.BEFORE,
         final_inventory_sha256=C.BEFORE,dependency_checks='PASS-no-waivers',payload_ownership='PASS',
         full_root_upgrade=dict(status='PASS',driver=driver,persistent_source_preserved=True,
             persistent_source=dict(source_manifest_sha256='held'),persistent_source_after=dict(source_manifest_sha256='held')))


class Authority(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='root604-authority-data-');self.root=Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.block=patch.object(subprocess,'Popen',side_effect=AssertionError('all actors forbidden'));self.block.start();self.addCleanup(self.block.stop)
        self.policy=copy.deepcopy(C.policy(bound=False));self.policy.update(status='ROOT_BOUND_ACTUAL_PREREQUISITES',
            installer_source='a'*40,decision_source='b'*40,installer_inputs={k:'c'*40 for k in C.INPUTS})
        statuses=('ROOT_ACCEPTED_NATIVE_EXPANDED604_COMPOSITION','ROOT_ACCEPTED_SIGNED_EXPANDED604_FRESH_INSTALLER',
             'ROOT_ACCEPTED_EXPANDED600_COPIED_ROOT_NORMAL','ROOT_ACCEPTED_EXPANDED600_COPIED_ROOT_PRECOMMIT_EXIT86',
             'ROOT_ACCEPTED_EXPANDED600_COPIED_ROOT_POSTCOMMIT_EXIT87')
        self.records={}
        for i,(key,status) in enumerate(zip(C.PREREQUISITES,statuses),1):
            row=dict(status=status,cleanup='PASS',hardware='NOT_RUN',release='NOT_ADMITTED',run_id=str(i),source_sha='a'*40,
                 package_count=604 if i<=2 else 600)
            if i<=2:row['expected604_sha256']=C.AFTER
            if key=='native604':row.update(installed_lifecycle='PASS',installed_six_modules='PASS')
            if key=='fresh604':row.update(ordinary_parent_retired='PASS',independent_root_readback='PASS')
            if i>2:
                case=tuple(C.SOURCES)[i-3];driver=receipt(case)['full_root_upgrade']['driver']
                row.update(driver);row.update(status=status,case=case,before_sha256=C.OLD.BEFORE,after_sha256=C.OLD.AFTER,
                    package_sha256=C.PACKAGE,fault_exit=(0,86,87)[i-3],checkpoint_directory_synced=True,
                    before_inventory_preserved=True,after600_database_verified=True)
            self.records[key]=row
        self.flush()
    def flush(self):
        for key,row in self.records.items():
            path=self.root/(key+'.json');path.write_bytes(C.encoded(row))
            self.policy['prerequisites'][key]=dict(path=path.name,bytes=path.stat().st_size,sha256=C.sha(path))
    def accepted(self):
        self.flush()
        with patch.object(C,'revision',return_value='b'*40):return C.prerequisites(self.root,self.policy)
    def test_all_five_exact_actual_decisions_accept(self):self.assertEqual(self.accepted(),self.records)
    def test_each_failed_or_missing_actual_refuses(self):
        for key in C.PREREQUISITES:
            original=self.records[key]['status'];self.records[key]['status']='FAIL'
            with self.assertRaisesRegex(ValueError,'acceptance'):self.accepted()
            self.records[key]['status']=original
        (self.root/'native604.json').unlink()
        with patch.object(C,'revision',return_value='b'*40),self.assertRaises(FileNotFoundError):C.prerequisites(self.root,self.policy)
    def test_five_distinct_runs_and_exact_fresh_source_required(self):
        self.records['fresh604']['run_id']='1'
        with self.assertRaisesRegex(ValueError,'distinct'):self.accepted()
        self.records['fresh604']['run_id']='2';self.records['fresh604']['source_sha']='d'*40
        with self.assertRaisesRegex(ValueError,'fresh604'):self.accepted()
    def test_source_carrier_hash_and_positive_byte_reference_required(self):
        with patch.object(C,'revision',return_value='d'*40),self.assertRaisesRegex(ValueError,'carrier'):C.prerequisites(self.root,self.policy)
        (self.root/'normal600.json').write_bytes(b'{}')
        with patch.object(C,'revision',return_value='b'*40),self.assertRaisesRegex(ValueError,'identity'):C.prerequisites(self.root,self.policy)
    def test_wrong_typed_commit_and_fault_exit_refuse(self):
        self.records['normal600']['commit_started']=1
        with self.assertRaisesRegex(ValueError,'truth'):self.accepted()
        self.records['normal600']['commit_started']=True;self.records['precommit600']['fault_exit']='86'
        with self.assertRaisesRegex(ValueError,'truth'):self.accepted()
    def test_actual600_checkpoint_and_independent_postcommit_proofs_required(self):
        for key,field in (('normal600','checkpoint_directory_synced'),('precommit600','before_inventory_preserved'),
             ('postcommit600','after600_database_verified'),('postcommit600','postcommit_payload_verified'),
             ('postcommit600','postcommit_preservation_verified')):
            self.records[key][field]=False
            with self.assertRaises(ValueError):self.accepted()
            self.records[key][field]=True
    def test_exact_final604_native_and_fresh_inventory_and_cleanup_required(self):
        for key,field,value in (('native604','expected604_sha256',C.BEFORE),('fresh604','package_count',600),
             ('native604','installed_six_modules','UNKNOWN'),('fresh604','ordinary_parent_retired','UNKNOWN'),
             ('postcommit600','copy_cleanup','UNKNOWN')):
            old=self.records[key][field];self.records[key][field]=value
            with self.assertRaises(ValueError):self.accepted()
            self.records[key][field]=old
    def test_unbound_policy_refuses_gate_freeze_and_owner_before_outputs_or_actors(self):
        before=list(self.root.iterdir())
        unbound=copy.deepcopy(C.policy(bound=False))
        unbound.update(status='UNBOUND_ACTUAL_PREREQUISITES',installer_source=None,decision_source=None)
        with patch.object(C,'read',return_value=unbound):
            with self.assertRaisesRegex(ValueError,'UNBOUND'):C.policy()
            with self.assertRaisesRegex(ValueError,'UNBOUND'):gate.main(['--implementation',str(self.root),'--source','0'*40,
                 '--workflow-sha','0'*40,'--case','normal','--preflight'])
            with self.assertRaisesRegex(ValueError,'UNBOUND'):freeze.freeze(self.root)
            argv=[]
            for field in ('implementation','installer-source','decision-source','upgrader-source','preparation-source',
                 'product','updater','desktop','updater-v2-source','native','fdk','cache','setup4-pair',
                 *(n.replace('_','-') for n in C.INPUTS),'audio-inputs','output'):argv.extend(['--'+field,str(self.root/field)])
            with self.assertRaisesRegex(ValueError,'UNBOUND'):owner.main(argv+['--implementation-revision','0'*40,'--case','normal'])
        self.assertEqual(before,list(self.root.iterdir()))
    def test_root_policy_requires_all_positive_closed_refs(self):
        with patch.object(C,'read',return_value=self.policy):self.assertEqual(C.policy(),self.policy)
        self.policy['prerequisites']['normal600']['bytes']=0
        with patch.object(C,'read',return_value=self.policy),self.assertRaisesRegex(ValueError,'positive-byte'):C.policy()
    def test_real_plan_capture_helper_composed_without_fallback(self):
        prior=C.old600()[1];producer=NS();args=NS(output=self.root/'producer');plan=dict(hooks=['held'],setup4=dict(helpers={'held':True}))
        original=lambda raw,ready,held,*a,**kw:ready;producer.export_ready=original
        def prepare(a):
            raw=a.output/'private';return producer.export_ready(raw,raw/'ready',dict(inputs=raw/'inputs',plan=plan))
        producer.prepare=prepare
        with patch.object(C,'old600',return_value=(None,prior)):
            ready,captured=owner.prepare_with_plan(producer,args)
        self.assertEqual(ready,args.output/'private/ready');self.assertEqual(captured,plan);self.assertIsNot(captured,plan)
        self.assertIs(producer.export_ready,original);self.assertFalse(args.output.exists())
    def test_decisions_only_runs_actuals_before_installer_without_audio_or_outputs(self):
        events=[]
        with patch.object(C,'policy',return_value=self.policy),patch.object(gate,'own_source'),\
             patch.object(C,'prerequisites',side_effect=lambda *a:events.append('actuals')),\
             patch.object(gate,'installer',side_effect=lambda *a:events.append('installer')):
            self.assertEqual(gate.main(['--implementation',str(self.root),'--source','0'*40,'--workflow-sha','0'*40,
                 '--case','normal','--decisions-only','--decision-source',str(self.root),'--installer-source',str(self.root)]),0)
        self.assertEqual(events,['actuals','installer'])


class Results(unittest.TestCase):
    def test_three_exact_truths(self):
        for case in C.SOURCES:owner.verify_result(receipt(case),case)
    def test_checkpoint_sync_and_commit_types_remain_required(self):
        row=receipt('normal');row['full_root_upgrade']['driver']['update']['checkpoint_directory_synced']=False
        with self.assertRaisesRegex(ValueError,'sync'):owner.verify_result(row,'normal')
        row=receipt('normal');row['full_root_upgrade']['driver']['commit_started']=1
        with self.assertRaisesRegex(ValueError,'truth'):owner.verify_result(row,'normal')
    def test_failed_cases_cannot_be_successful_normal(self):
        for case in ('precommit-exit86','postcommit-exit87'):
            with self.assertRaisesRegex(ValueError,'truth'):owner.verify_result(receipt(case),'normal')
    def test_postcommit_independent604_checks_and_source_preservation_required(self):
        for key in ('after604_database_verified','postcommit_payload_verified','postcommit_preservation_verified'):
            row=receipt('postcommit-exit87');row['full_root_upgrade']['driver'][key]=False
            with self.assertRaisesRegex(ValueError,'independent'):owner.verify_result(row,'postcommit-exit87')
        row=receipt('normal');row['full_root_upgrade']['persistent_source_after']['source_manifest_sha256']='changed'
        with self.assertRaisesRegex(ValueError,'preservation'):owner.verify_result(row,'normal')
    def test_no_inventory_or_dependency_waivers(self):
        for key,value in [('package_count',603),('final_inventory_sha256',C.AFTER),('dependency_checks','WAIVED')]:
            row=receipt('normal');row[key]=value
            with self.assertRaisesRegex(ValueError,'outer actual604'):owner.verify_result(row,'normal')


class WorkflowLayout(unittest.TestCase):
    def test_all_carrier_roots_match_accepted_fresh604_argument_layouts(self):
        import re
        root=Path(__file__).resolve().parents[3]
        workflows=root/'.github/workflows'
        expected={'management':('payload',),'welcome':('payload',),'setup':()}
        def layout(path,setup_checkout):
            text=path.read_text();result={}
            for kind,suffix in expected.items():
                rows=re.findall(r'--'+kind+r'-source "\$GITHUB_WORKSPACE/([^"\n]+)"',text)
                self.assertEqual(len(rows),2,(path.name,kind))
                checkout='expanded604-'+kind+'-source' if kind!='setup' else setup_checkout
                parts=[Path(value).parts for value in rows]
                self.assertTrue(all(p[0]==checkout for p in parts),(path.name,kind))
                self.assertEqual([p[1:] for p in parts],[suffix,suffix],(path.name,kind))
                result[kind]=parts[0][1:]
            return result
        with patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden')):
            accepted=layout(workflows/'native-arm-expanded604-installer-vm.yml','expanded604-setup-source')
            self.assertEqual(layout(workflows/'native-arm-expanded604-root-upgrade.yml','expanded604-setup5'),accepted)


if __name__=='__main__':unittest.main(verbosity=2)
