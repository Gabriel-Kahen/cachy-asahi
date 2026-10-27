#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real private ALPM queries/prepare/release; only fixture-file commit simulation.

No test invokes alpm_trans_commit, sudo, host package changes, hooks or helpers.
"""
import importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('live_candidate',HERE/'live.py');L=importlib.util.module_from_spec(spec);spec.loader.exec_module(L);R=L.R;O=L.O

class FixtureTransaction(L.LiveTransaction):
    instances=[];before_begin=None;after_prepare=None;expanded=False;failure=None
    def __init__(self,root,db):
        super().__init__(root,db);self.root=Path(root);self.selected={};self.calls=[];type(self).instances.append(self)
    def begin(self):
        if type(self).before_begin:type(self).before_begin(self)
        super().begin();self.calls.append('begin')
    def remove(self,name,version):
        super().remove(name,version);self.selected[name]=version;self.calls.append(('remove',name,version))
    def prepare(self):
        value=super().prepare();self.calls.append('prepare')
        if type(self).after_prepare:type(self).after_prepare(self)
        if self.expanded:return {},dict(value[1],**{'test-expanded':'1-1'})
        return value
    def commit(self):
        # Deliberate file model: never delegate this method to libalpm.
        self.calls.append('SIMULATED_FIXTURE_COMMIT')
        if self.failure=='interrupt':raise InterruptedError('private fixture interrupted commit')
        if self.failure=='error':raise O.Refused('private fixture commit failure')
        for name,version in self.selected.items():
            for raw in self.files(name,version):
                path=self.root/raw
                if path.is_file():path.unlink()
            shutil.rmtree(self.db/'local'/(name+'-'+version))
    def cleanup(self,result):self.calls.append('cleanup');super().cleanup(result)

class Live(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='orphans-live-control-');self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name)
        self.root=self.base/'root';self.root.mkdir(mode=0o700);self.db=self.root/'var/lib/pacman';(self.db/'local').mkdir(parents=True);(self.db/'local/ALPM_DB_VERSION').write_text('9\n')
        self.out=self.base/'out';self.out.mkdir(mode=0o700);self.sequence=0
        self.package('test-base',0);self.package('test-platform')
        self.policy=self.out/'policy.json';self.policy_value=dict(schema_version=1,profile='private-fixture',root=str(self.root),dbpath=str(self.db),supported_base={'test-base':'1-1'},platform={'test-platform':'1-1'},transaction_flags=R.FLAGS,hooks='refuse-matching',scriptlets='refuse',configuration='refuse-selected',ldconfig={'mode':'forbid'})
        self.write_policy()
        FixtureTransaction.instances=[];FixtureTransaction.before_begin=None;FixtureTransaction.after_prepare=None;FixtureTransaction.expanded=False;FixtureTransaction.failure=None
        # A regression choosing the production factory still cannot commit ALPM.
        self.guard=patch.object(L.LiveTransaction,'commit',side_effect=AssertionError('real ALPM commit forbidden in component controls'));self.guard.start();self.addCleanup(self.guard.stop)
    def write_policy(self):
        self.policy.write_bytes(O.encoded(self.policy_value));self.policy.chmod(0o600);self.policy_pin=O.digest(self.policy.read_bytes())
    def package(self,name,reason=1,version='1-1',depends=(),optional=(),provides=(),path=None,backup=False,scriptlet=False):
        d=self.db/'local'/(name+'-'+version);d.mkdir();fields={'NAME':[name],'VERSION':[version],'REASON':[str(reason)],'ARCH':['any'],'DEPENDS':list(depends),'OPTDEPENDS':list(optional),'PROVIDES':list(provides)}
        (d/'desc').write_text(''.join('%'+k+'%\n'+'\n'.join(v)+'\n\n' for k,v in fields.items() if v))
        path=path or 'usr/share/orphans-live-fixture/'+name;ancestors=[str(p)+'/' for p in reversed(Path(path).parents) if str(p)!='.']
        (d/'files').write_text('%FILES%\n'+'\n'.join(ancestors+[path])+'\n\n'+('%BACKUP%\n'+path+'\td41d8cd98f00b204e9800998ecf8427e\n\n' if backup else ''))
        (self.root/path).parent.mkdir(parents=True,exist_ok=True);(self.root/path).write_text('private payload '+name)
        if scriptlet:(d/'install').write_text('post_remove() { :; }\n')
        return d
    def assessment(self):return L.assess(self.root,self.db,self.policy,self.policy_pin)
    def planned(self,names=('test-leaf',)):
        self.sequence+=1;a=self.out/('assessment'+str(self.sequence));O.publish(a,self.assessment(),self.db)
        p=self.out/('plan'+str(self.sequence));L.plan(a,list(names),self.root,self.db,self.policy,self.policy_pin,p)
        return SimpleNamespace(target_root=self.root,target_dbpath=self.db,policy=self.policy,policy_sha256=self.policy_pin,plan=p,plan_sha256=O.digest(p.read_bytes()),select=list(names),result=self.out/('result'+str(self.sequence)),timeout_seconds=2,authorize_live_removal=True)
    def execute(self,args):
        receipts=[];result=L.execute(args,lambda row:receipts.append(json.loads(json.dumps(row))),factory=FixtureTransaction);self.assertEqual(receipts[-1],result);return result
    def assert_no_commit(self,result):
        self.assertIn(result['status'],('REFUSED','FAILED'),result);self.assertFalse(result['commit_started'],result)
        for api in FixtureTransaction.instances:self.assertNotIn('SIMULATED_FIXTURE_COMMIT',api.calls)
    def test_actual_alpm_reason_versioned_provider_and_optional_state(self):
        self.package('test-leaf');self.package('test-provider',provides=('test-virtual=3',));self.package('test-consumer',0,depends=('test-virtual>=2',));self.package('test-opt-provider',provides=('test-extra=4',));self.package('test-opt-consumer',0,optional=('test-extra>=3: optional private feature',))
        report=self.assessment();rows=report['installed']['packages']
        self.assertEqual(rows['test-provider']['required_by'],['test-consumer']);self.assertEqual(rows['test-consumer']['satisfiers']['depends']['test-virtual>=2'],'test-provider');self.assertEqual(rows['test-opt-provider']['optional_required_by'],['test-opt-consumer']);self.assertEqual(rows['test-opt-consumer']['satisfiers']['optdepends']['test-extra>=3: optional private feature'],'test-opt-provider');self.assertEqual(rows['test-leaf']['reason'],'dependency');self.assertEqual(report['eligible_candidates'],['test-leaf']);self.assertFalse((self.db/'db.lck').exists())
    def test_explicit_supported_base_and_platform_are_protected(self):
        self.package('test-leaf');report=self.assessment();self.assertEqual(report['eligible_candidates'],['test-leaf'])
        for name in ('test-base','test-platform'):
            self.assertTrue(report['installed']['packages'][name]['protected'])
            with self.assertRaises(O.Refused):self.planned((name,))
    def test_production_platform_name_is_protected_without_policy_listing(self):
        self.package('linux-asahi-test');self.assertNotIn('linux-asahi-test',self.assessment()['eligible_candidates'])
    def test_missing_or_wrong_supported_base_version_refuses(self):
        self.policy_value['supported_base']['test-missing']='1-1';self.write_policy()
        with self.assertRaises(O.Refused):self.assessment()
        self.policy_value['supported_base']={'test-base':'2-1'};self.write_policy()
        with self.assertRaises(O.Refused):self.assessment()
    def test_cli_has_no_default_target_for_any_live_operation(self):
        for command in ('assess','plan','remove'):
            r=subprocess.run([sys.executable,'-I','-B',str(HERE/'orphans3'),'live',command],capture_output=True,text=True,timeout=5);self.assertEqual(r.returncode,2,(command,r.stdout,r.stderr));self.assertIn('--target-root',r.stderr)
    def test_target_mismatch_and_root_fallback_refuse_before_transaction(self):
        self.package('test-leaf');args=self.planned()
        for root,db in ((Path('/'),Path('/var/lib/pacman')),(self.root,self.base/'foreign-db')):
            args.target_root=root;args.target_dbpath=db;self.assert_no_commit(self.execute(args));self.assertEqual(FixtureTransaction.instances,[])
    def test_root_target_requires_already_privileged_operator_without_auto_sudo(self):
        args=SimpleNamespace(target_root=Path('/'),target_dbpath=Path('/var/lib/pacman'),policy=self.policy,policy_sha256=self.policy_pin,plan=self.out/'must-not-read',plan_sha256='a'*64,select=['test-leaf'],authorize_live_removal=True)
        # Isolate pre-input refusal without spoofing ownership of a real plan.
        for uid in (1000,1001,65534):
            with self.subTest(uid=uid),patch.object(L.os,'geteuid',return_value=uid),patch.object(O,'json_file',side_effect=AssertionError('no input read before privilege refusal')) as inputs,patch.object(L,'plan',side_effect=AssertionError('no plan/ALPM query')) as reviewed:
                result=self.execute(args)
            self.assert_no_commit(result);self.assertIn('no auto-sudo',result['reason']);self.assertEqual(FixtureTransaction.instances,[]);inputs.assert_not_called();reviewed.assert_not_called()
    def test_authorization_flag_is_required_even_for_exact_reviewed_plan(self):
        self.package('test-leaf');args=self.planned();args.authorize_live_removal=False;self.assert_no_commit(self.execute(args));self.assertEqual(FixtureTransaction.instances,[])
    def test_policy_and_plan_hash_mismatch_refuse_before_transaction(self):
        self.package('test-leaf');args=self.planned();args.policy_sha256='0'*64;self.assert_no_commit(self.execute(args));args.policy_sha256=self.policy_pin;args.plan_sha256='0'*64;self.assert_no_commit(self.execute(args));self.assertEqual(FixtureTransaction.instances,[])
    def test_actual_prepare_simulated_commit_preserves_unselected_configuration(self):
        self.package('test-leaf');config=self.root/'etc/test-live-base.conf';config.parent.mkdir();config.write_text('user-owned setting\n');config.chmod(0o640);before=(config.read_bytes(),O.identity(config.stat()));args=self.planned();result=self.execute(args)
        self.assertEqual(result['status'],'APPLIED',result);self.assertEqual(result['prepared_add'],{});self.assertEqual(result['prepared_remove'],{'test-leaf':'1-1'});self.assertTrue(result['transaction_released']);self.assertTrue(result['handle_released']);self.assertEqual(result['lock_state'],'ABSENT');self.assertEqual(FixtureTransaction.instances[-1].calls,['begin',('remove','test-leaf','1-1'),'prepare','SIMULATED_FIXTURE_COMMIT','cleanup']);self.assertEqual((config.read_bytes(),O.identity(config.stat())),before);self.assertFalse((self.db/'local/test-leaf-1-1').exists());self.assertTrue((self.db/'local/test-platform-1-1').exists())
    def test_reason_drift_after_preflight_before_lock_refuses(self):
        d=self.package('test-leaf');args=self.planned()
        def drift(api):(d/'desc').write_text((d/'desc').read_text().replace('%REASON%\n1','%REASON%\n0'))
        FixtureTransaction.before_begin=drift;self.assert_no_commit(self.execute(args));self.assertIn('begin',FixtureTransaction.instances[-1].calls);self.assertNotIn('prepare',FixtureTransaction.instances[-1].calls);self.assertFalse((self.db/'db.lck').exists())
    def test_dependency_drift_after_prepare_refuses(self):
        self.package('test-leaf');d=self.package('test-consumer',0);args=self.planned()
        def drift(api):(d/'desc').write_text((d/'desc').read_text()+'%DEPENDS%\ntest-leaf\n\n')
        FixtureTransaction.after_prepare=drift;self.assert_no_commit(self.execute(args));self.assertIn('prepare',FixtureTransaction.instances[-1].calls)
    def test_prepared_solver_expansion_refuses_and_releases_real_lock(self):
        self.package('test-leaf');args=self.planned();FixtureTransaction.expanded=True;result=self.execute(args);self.assert_no_commit(result);self.assertEqual(result['prepared_remove'],{'test-leaf':'1-1','test-expanded':'1-1'});self.assertIn('prepare',FixtureTransaction.instances[-1].calls);self.assertFalse((self.db/'db.lck').exists())
    def test_same_bytes_plan_or_policy_replacement_after_prepare_refuses(self):
        self.package('test-leaf')
        for which in ('plan','policy','assessment'):
            args=self.planned()
            def replace(api):
                p=args.plan if which=='plan' else self.policy if which=='policy' else Path(O.json_file(args.plan)[0]['assessment']);q=self.out/'replacement';q.write_bytes(p.read_bytes());q.chmod(0o600);q.replace(p)
            FixtureTransaction.after_prepare=replace;self.assert_no_commit(self.execute(args));self.assertIn('prepare',FixtureTransaction.instances[-1].calls);FixtureTransaction.after_prepare=None
    def test_payload_replacement_after_prepare_refuses(self):
        self.package('test-leaf');args=self.planned();path=self.root/'usr/share/orphans-live-fixture/test-leaf'
        def replace(api):q=self.out/'replacement-payload';q.write_bytes(path.read_bytes());q.replace(path)
        FixtureTransaction.after_prepare=replace;self.assert_no_commit(self.execute(args));self.assertIn('prepare',FixtureTransaction.instances[-1].calls)
    def test_selected_configuration_backup_and_scriptlet_are_not_eligible(self):
        self.package('test-config',path='etc/test-config.conf');self.package('test-backup',backup=True);self.package('test-scriptlet',scriptlet=True);report=self.assessment()
        for name in ('test-config','test-backup','test-scriptlet'):
            self.assertNotIn(name,report['eligible_candidates'])
            with self.assertRaises(O.Refused):self.planned((name,))
    def test_broken_baseline_cannot_plan(self):
        self.package('test-leaf');self.package('test-broken',0,depends=('test-absent>=2',))
        with self.assertRaises(O.Refused):self.planned()
    def test_foreign_lock_is_preserved_without_transaction(self):
        self.package('test-leaf');args=self.planned();p=self.db/'db.lck';p.write_text('foreign');before=(p.read_bytes(),O.identity(p.stat()));self.assert_no_commit(self.execute(args));self.assertEqual((p.read_bytes(),O.identity(p.stat())),before);self.assertEqual(FixtureTransaction.instances,[])
    def test_commit_interruption_reports_uncertain_receipt_and_never_retries(self):
        self.package('test-leaf');args=self.planned();FixtureTransaction.failure='interrupt';result=self.execute(args)
        self.assertEqual(result['status'],'FAILED',result);self.assertTrue(result['commit_started']);self.assertEqual(result['packages_committed'],'UNKNOWN');self.assertEqual(FixtureTransaction.instances[-1].calls.count('SIMULATED_FIXTURE_COMMIT'),1);self.assertIn('DO_NOT_RETRY',result['recovery']);self.assertEqual(result['lock_state'],'ABSENT')
    def hook(self):
        path=self.root/'usr/share/libalpm/hooks/99-test-live.hook';path.parent.mkdir(parents=True,exist_ok=True);path.write_text('[Trigger]\nOperation = Remove\nType = Package\nTarget = test-leaf\n\n[Action]\nWhen = PostTransaction\nExec = /usr/bin/false\n');return path
    def test_matching_remove_hook_excludes_preview_without_running_it(self):
        self.package('test-leaf');self.hook();report=self.assessment();self.assertNotIn('test-leaf',report['eligible_candidates']);self.assertTrue(any('hook' in reason for reason in report['eligibility']['test-leaf']['reasons']))
        with self.assertRaises(O.Refused):self.planned()
    def test_new_remove_hook_after_prepare_refuses_before_simulated_commit(self):
        self.package('test-leaf');args=self.planned();FixtureTransaction.after_prepare=lambda api:self.hook();self.assert_no_commit(self.execute(args));self.assertIn('prepare',FixtureTransaction.instances[-1].calls)
    def test_ldconfig_requires_separate_policy_and_is_never_executed(self):
        self.package('test-leaf');helper=self.root/'usr/bin/ldconfig';helper.parent.mkdir();helper.write_text('private nonexecutable-text helper sentinel');helper.chmod(0o755);before=helper.read_bytes();report=self.assessment();self.assertNotIn('test-leaf',report['eligible_candidates']);self.assertTrue(any('ldconfig' in reason for reason in report['eligibility']['test-leaf']['reasons']));self.assertEqual(helper.read_bytes(),before)
    def test_supported_base_provider_closure_is_protected(self):
        d=self.db/'local/test-base-1-1';(d/'desc').write_text((d/'desc').read_text()+'%DEPENDS%\ntest-virtual>=2\n\n');self.package('test-provider',provides=('test-virtual=3',));report=self.assessment();self.assertTrue(report['installed']['packages']['test-provider']['protected']);self.assertIn('test-provider',report['installed']['protected_closure'])
    def test_replaced_lock_is_retained_without_uncertain_handle_release(self):
        self.package('test-leaf');args=self.planned();lock=self.db/'db.lck'
        def replace(api):
            foreign=self.out/'foreign';foreign.write_text('foreign lock\n');foreign.replace(lock)
        FixtureTransaction.after_prepare=replace;result=self.execute(args)
        try:
            self.assertEqual(result['status'],'FAILED',result);self.assertFalse(result['commit_started']);self.assertEqual(lock.read_text(),'foreign lock\n');self.assertTrue(result['handle_abandoned']);self.assertFalse(result['transaction_released']);self.assertFalse(result['handle_released']);self.assertNotIn('SIMULATED_FIXTURE_COMMIT',FixtureTransaction.instances[-1].calls)
        finally:
            # Dispose only this test's uncommitted private handle after retaining the foreign lock.
            api=FixtureTransaction.instances[-1];lock.rename(self.out/'retained-foreign');api.lib.alpm_trans_release(api.handle);api.started=False;api.lib.alpm_release(api.handle);api.handle=None
    def test_changed_target_directory_identity_cannot_reuse_reviewed_plan(self):
        self.package('test-leaf');args=self.planned();old=self.base/'old-root';self.root.rename(old);shutil.copytree(old,self.root);self.assert_no_commit(self.execute(args));self.assertEqual(FixtureTransaction.instances,[])

if __name__=='__main__':unittest.main()
