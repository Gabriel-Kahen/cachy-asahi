#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Focused inert controls. No native/Docker/signing/compiler/ALPM/CI/network actors."""
import ast
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock,patch
import contract as C
import job
import run
import installed as I

ROOT=next(p for p in C.HERE.parents if (p/'manifests/packages.toml').is_file())


def lifecycle(optional=False):
    count=577;events=[]
    for phase,n in (('install',count),('same-version-reinstall',count),('remove',574),('reinstall-after-removal',count),('final-remove',574)):
        event=dict(phase=phase,count=n,base574_preserved=True,user_preserved=True)
        if n==574:event['payloads_absent']=True
        else:
            event.update(installed_default_helpers='PASS',signed_catalog='PASS_NOT_APPLIED',cache_plan_verify='PASS_NOT_APPLIED',cache_apply='PASS_REAL_ALPM16_EMPTY_TRANSACTION',inventory_collector='PASS_READONLY_OBSERVED_ALPM9',observations=[
                dict(home='apps-cache-home-'+kind,apps_commands=['list','search','show','plan-install','plan-remove'],default_helpers='PASS_INSTALLED_EXACT_THREE',
                    signed_catalog='PASS_NOT_APPLIED',cache_plan_verify='PASS_NOT_APPLIED',cache_cleanup='APPLIED_DISPOSABLE_FIXTURES_ONLY',cache_apply='PASS_REAL_ALPM16_EMPTY_TRANSACTION',inventory_collector='PASS_READONLY_OBSERVED_ALPM9',plan_inventory_source='OBSERVED_SYNTHETIC_ALPM9_FIXTURE',real_database_inventory='PASS_EXACT577_OBSERVED_METADATA_RAW_HASHES_PRESERVED',
                    cache_apply_result=dict(status='APPLIED',lock='OWN_LOCK_RELEASED',removed_objects=['selected-1-1-any.pkg.tar.xz','selected-1-1-any.pkg.tar.xz.sig'],reclaimed_bytes=None,disk_space='NOT_MEASURED'),
                    cache_journal=dict(phase='APPLIED',lock_release='OWN_LOCK_RELEASED',alpm={'version':'16.0.1'})) for kind in ('fresh','existing')])
        events.append(event)
    return dict(status='PASS_APPS_CACHE_INSTALLED_LIFECYCLE',base_count=574,installed_count=count,base574_preserved=True,user_preserved=True,
        plans_applied='NOT_APPLIED',cache_cleanup='APPLIED_DISPOSABLE_FIXTURES_ONLY',cache_apply='PASS_REAL_ALPM16_EMPTY_TRANSACTION',hardware='NOT_RUN',architecture='aarch64',page_size=4096,events=events)


class SourceControls(unittest.TestCase):
    def test_unbound_stops_before_output_imports_or_actors(self):
        with tempfile.TemporaryDirectory() as d,patch.object(C,'policy',side_effect=ValueError('test UNBOUND')),patch.object(C,'load') as load:
            target=Path(d)/'must-not-exist'
            with self.assertRaisesRegex(ValueError,'UNBOUND'):run.execute(Path(d),Path(d),target,'a'*32)
            load.assert_not_called();self.assertFalse(target.exists())
    def test_proof_and_freeze_refuse_pending_cache(self):
        freezer=C.load('apps_cache_control_freeze',C.HERE/'freeze.py')
        with patch.object(C,'policy',side_effect=ValueError('test UNBOUND')):
            with self.assertRaisesRegex(ValueError,'UNBOUND'):job.prove(ROOT,{})
            with self.assertRaisesRegex(ValueError,'UNBOUND'):freezer.freeze(ROOT)
    def test_unfinished_cache_policy_cannot_authorize_freezing(self):
        policy=copy.deepcopy(C.read(C.HERE/'input-policy.json'))
        policy.update(status='ROOT_BOUND_FINAL_PRODUCT_SOURCES',candidate_source='a'*40)
        policy['products']['cache']=dict(name=C.ROLES['cache'],version=None,recipe_sha256=None,source_files={},payload={},check_markers=[])
        with patch.object(C,'read',return_value=policy),self.assertRaises(ValueError):C.policy()
    def test_adopted_runtime_pins_match_checked_out_tree_and_published_source(self):
        policy=C.read(C.HERE/'input-policy.json');ref='0bdf02dae0f6dfff284c723c3a0b8bf30594c646'
        self.assertEqual(policy['products']['runtime']['source_sha'],ref)
        for role,version,count in (('runtime','0.1.0-1',8),):
            row=policy['products'][role];self.assertEqual(row['source_sha'],ref);self.assertEqual(row['version'],version);self.assertEqual(len(row['payload']),count)
            for name,pin in row['source_files'].items():
                path='packages/tools/'+row['name']+'/'+name;raw=subprocess.check_output(['git','-C',str(ROOT),'show','HEAD:'+path],timeout=15)
                self.assertEqual(raw,(ROOT/path).read_bytes());self.assertEqual(len(raw),pin['bytes']);self.assertEqual(C.digest(ROOT/path),pin['sha256'])
    def test_all_final_recipe_source_joins_pass_with_only_an_in_memory_bound_status(self):
        original=C.read;policy=copy.deepcopy(original(C.HERE/'input-policy.json'));original_status=policy['status'];policy['status']='ROOT_BOUND_FINAL_PRODUCT_SOURCES'
        def fixture(path,*args,**kwargs):return policy if Path(path)==C.HERE/'input-policy.json' else original(path,*args,**kwargs)
        with patch.object(C,'read',side_effect=fixture):
            C.verify_source(ROOT)
            for name in C.NAMES:self.assertFalse(C.recipe(ROOT,name)['errors'])
        self.assertEqual(original(C.HERE/'input-policy.json')['status'],original_status)
    def test_only_three_unchanged_runtime_helpers(self):
        pins=C.read(C.HERE/'input-policy.json')['helper_pins'];self.assertEqual({n:r['sha256'] for n,r in pins.items()},C.HELPERS)
        self.assertEqual(sum(r['bytes'] for r in pins.values()),86445)
        for name,row in pins.items():C.checked(ROOT,name,row)
    def test_original_infrastructure_is_byte_pinned(self):
        pins=C.read(C.HERE/'infrastructure-pins.json')
        for name,row in pins.items():C.checked(ROOT,name,row)
        self.assertIn('scripts/ci/tools-native/job.py',pins);self.assertIn('scripts/ci/maintained_desktop574.py',pins)
    def test_adopted_recipes_can_be_inspected_without_actor_or_draft_freeze(self):
        partial=C.read(C.HERE/'input-policy.json')
        with patch.object(C,'policy',return_value=partial):
            for role in ('runtime','apps','cache'):
                result=C.recipe(ROOT,C.ROLES[role]);self.assertFalse(result['errors'])
                self.assertEqual(result['metadata']['arch'],['any'])
    def test_adopted_apps_v4_has_exact_collector_and_38_check_marker(self):
        policy=C.read(C.HERE/'input-policy.json');row=policy['products']['apps']
        self.assertEqual(row['version'],'0.1.0-5');self.assertEqual(len(row['source_files']),15);self.assertEqual(len(row['payload']),8)
        self.assertEqual(row['source_files']['inventory.py']['sha256'],'986c8baea2921cf3f58f98c2e76a1adad9013fbe4b1f47743d12397e9e6c2516')
        self.assertIn('Ran 39 tests',row['check_markers'])
        for name,pin in row['source_files'].items():C.checked(ROOT/'packages/tools/cachy-asahi-apps',name,pin)
    def test_adopted_cache_v2_exact_source_and_no_pyalpm_dependency(self):
        policy=C.read(C.HERE/'input-policy.json');row=policy['products']['cache']
        self.assertEqual(row['source_sha'],'6b226041c0cd26ac2f7ff9a5d1e0e824ae67a198');self.assertEqual(row['version'],'0.2.0-1')
        self.assertEqual(len(row['source_files']),7);self.assertEqual(len(row['payload']),4)
        for name,pin in row['source_files'].items():C.checked(ROOT/'packages/tools/cachy-asahi-cache',name,pin)
        with patch.object(C,'policy',return_value=policy):
            self.assertEqual(C.recipe(ROOT,C.ROLES['cache'])['metadata']['depends'],['python>=3.11','pacman'])
        self.assertIsNone(policy['dependency'])
    def test_native_checks_require_check_exit_markers_and_no_skips(self):
        with tempfile.TemporaryDirectory() as d,patch.object(C,'row',return_value={'check_markers':['REAL_CHECK_MARKER']}):
            path=Path(d)/'build.log'
            for raw in ('REAL_CHECK_MARKER','Starting check()\n','Starting check()\nREAL_CHECK_MARKER\nOK (skipped=1)'):
                path.write_text(raw)
                with self.assertRaises(ValueError):C.check_log(path,C.NAMES[0])
            path.write_text('Starting check()\nREAL_CHECK_MARKER\nOK\n');self.assertEqual(C.check_log(path,C.NAMES[0])['status'],'PASS_CHECK_EXIT_NO_SKIPS')
    def test_inherited_builder_preserves_resources_checks_and_dependency_enforcement(self):
        shared=C.load('apps_cache_controls_shared',ROOT/'scripts/ci/welcome-native/run.py')
        argv=shared.docker('sha256:'+'a'*64,'inert',Path('/tmp/inert'))
        for item in ('--network=none','--read-only','--memory=3g','--cpus=4','--pids-limit=256','--cap-drop=ALL','--security-opt=no-new-privileges'):self.assertIn(item,argv)
        entry=(ROOT/'scripts/build/container-entry.sh').read_text()
        self.assertIn('makepkg --verifysource --noconfirm',entry);self.assertIn('makepkg --cleanbuild --clean --force --log --noconfirm',entry)
        self.assertNotRegex(entry,r'makepkg[^\n]*(?:--nodeps|--nocheck)')
    def test_pair_gate_requires_buildinfo_and_archive_equality(self):
        old=C.load('apps_cache_controls_pair',ROOT/'scripts/ci/tools-native/run.py')
        result=dict(status='contents-reproduced',errors=[],packages={'inert':dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)})
        old.pair_gate(result)
        for key in result['packages']['inert']:
            changed=copy.deepcopy(result);changed['packages']['inert'][key]=False
            with self.assertRaises(ValueError):old.pair_gate(changed)
    def test_builder_has_no_repository_checkout_or_signing_authority_mount(self):
        tree=ast.parse((ROOT/'scripts/ci/welcome-native/run.py').read_text());build=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='build')
        text=ast.get_source_segment((ROOT/'scripts/ci/welcome-native/run.py').read_text(),build)
        self.assertNotIn('test-signing',text);self.assertNotIn('/authority',text);self.assertNotIn('dst=/source',text)
    def test_installed_paths_are_default_and_plans_never_applied(self):
        text=(C.HERE/'lifecycle.py').read_text();self.assertNotIn('--repository-source',text)
        self.assertIn("['list'],['search','sYnThEtIc'],['show','fixture']",text)
        self.assertIn("result['applied']=='NOT_APPLIED'",text)
        self.assertIn("'/usr/bin/cachy-asahi-cache','apply'",text)
        self.assertIn("'--confirm','REMOVE_SELECTED_CACHE_ARCHIVES'",text)
        self.assertIn("'--plan-sha256',planned['plan_sha256']",text)
        self.assertIn("'/usr/bin/cachy-asahi-apps','inventory'",text)
    def test_only_fixture_actor_receives_the_authority_home(self):
        text=(C.HERE/'run.py').read_text()
        self.assertEqual(text.count('dst=/authority'),1)
        self.assertNotIn('docker(image,actor,out',text)
        self.assertIn('docker(image,actor,phase_output,root=True)',text)
        self.assertIn('docker(image,actor,lifecycle_output,root=True)',text)
    def test_signature_and_dependency_policy_cannot_be_optional(self):
        text=(C.HERE/'installed.py').read_text();self.assertIn('LocalFileSigLevel = Required',text)
        all_source='\n'.join(p.read_text() for p in C.HERE.glob('*.py') if p.name!='test_lane.py')
        self.assertNotIn('--nodeps',all_source);self.assertNotIn('--nocheck',all_source)
        self.assertIn("'-T',*control['apps_dependencies']",(C.HERE/'runtime_image.py').read_text())
    def test_workflow_gates_before_secrets_and_preserves_native_source_identity(self):
        workflow=C.HERE.parents[2]/'.github/workflows/native-arm-apps-cache-candidates.yml'
        text=workflow.read_text();self.assertLess(text.index('id: proof'),text.index('${{ secrets.'))
        self.assertRegex(text,r'(?:@JOB_SHA256@|[0-9a-f]{64})[^\n]+\$SLICE/job.py')
        self.assertRegex(text,r'(?:@MANIFEST_SHA256@|[0-9a-f]{64})[^\n]+\$SLICE/source-manifest.json')
        self.assertIn('ubuntu-24.04-arm',text);self.assertIn('cancel-in-progress: false',text)

    def test_actual_pacman_subcommand_vectors_keep_transaction_flags_off_queries(self):
        prefix=['/usr/bin/pacman','--config','/tmp/apps-cache-pacman.conf','--noconfirm','--noscriptlet']
        helper=ast.parse((C.HERE/'installed.py').read_text())
        factory=next(node for node in helper.body if isinstance(node,ast.FunctionDef) and node.name=='pacman')
        returned=next(node for node in reversed(factory.body) if isinstance(node,ast.Return))
        self.assertEqual(eval(compile(ast.Expression(returned.value),'installed.py','eval'),{'config':'/tmp/apps-cache-pacman.conf'}),prefix)
        seen=[]
        def command(argv,**kwargs):
            operation=next(arg for arg in argv if arg in ('-Dk','-T','-U','-R'))
            self.assertEqual(argv[:3],prefix[:3])
            if operation in ('-Dk','-T'):
                self.assertNotIn('--noscriptlet',argv);self.assertNotIn('--noconfirm',argv)
            else:self.assertEqual(argv[:5],prefix)
            seen.append(operation)
        # Evaluate only the actual prefix assignment and pacman command expressions;
        # no container main(), package manager, filesystem mutation or subprocess runs.
        for name in ('runtime_image.py','lifecycle.py'):
            tree=ast.parse((C.HERE/name).read_text())
            main=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
            scope=dict(pacman=list(prefix),L=NS(command=command),archive='/inputs/runtime.pkg.tar.xz',
                archives=['/inputs/product.pkg.tar.xz'],selected=['inert-product'],control={'apps_dependencies':['python>=3.11']})
            assignment=next(node for node in main.body if isinstance(node,ast.Assign) and
                isinstance(node.targets[0],ast.Name) and node.targets[0].id=='query')
            exec(compile(ast.Module(body=[assignment],type_ignores=[]),name,'exec'),scope)
            for node in ast.walk(main):
                if not isinstance(node,ast.Call) or not isinstance(node.func,ast.Attribute) or node.func.attr!='command' or not node.args:continue
                first=node.args[0]
                if isinstance(first,ast.BinOp) and isinstance(first.left,ast.Name) and first.left.id in ('pacman','query'):
                    eval(compile(ast.Expression(node),name,'eval'),scope)
        self.assertEqual(seen.count('-Dk'),2);self.assertEqual(seen.count('-T'),1)
        self.assertEqual(seen.count('-U'),4);self.assertEqual(seen.count('-R'),2)


class LifecycleControls(unittest.TestCase):
    def test_exact_three_products_without_unneeded_dependency(self):
        with patch.object(C,'policy',return_value={'dependency':None}):C.validate_lifecycle(lifecycle())
    def test_preservation_or_readonly_claim_drift_refuses(self):
        for key,value in [('base574_preserved',False),('user_preserved',False),('plans_applied','APPLIED'),('cache_cleanup','UNPROVEN')]:
            row=lifecycle();row[key]=value
            with patch.object(C,'policy',return_value={'dependency':None}),self.assertRaises(ValueError):C.validate_lifecycle(row)
    def test_missing_real_fresh_existing_cli_observations_refuses(self):
        for change in ('missing','commands','authority'):
            row=lifecycle();records=row['events'][0]['observations']
            if change=='missing':records.pop()
            elif change=='commands':records[0]['apps_commands'].pop()
            else:records[0]['cache_cleanup']='UNPROVEN'
            with patch.object(C,'policy',return_value={'dependency':None}),self.assertRaises(ValueError):C.validate_lifecycle(row)
    def test_cache_apply_requires_real_lock_release_and_journal_without_space_claim(self):
        for key,value in [('lock','UNKNOWN'),('reclaimed_bytes',1),('disk_space','MEASURED'),('status','NOT_APPLIED')]:
            row=lifecycle();row['events'][0]['observations'][0]['cache_apply_result'][key]=value
            with patch.object(C,'policy',return_value={'dependency':None}),self.assertRaises(ValueError):C.validate_lifecycle(row)
        row=lifecycle();row['events'][0]['observations'][0]['cache_journal']['phase']='MOVING'
        with patch.object(C,'policy',return_value={'dependency':None}),self.assertRaises(ValueError):C.validate_lifecycle(row)
    def test_removal_requires_all_owned_payloads_absent(self):
        row=lifecycle();row['events'][2]['payloads_absent']=False
        with patch.object(C,'policy',return_value={'dependency':None}),self.assertRaises(ValueError):C.validate_lifecycle(row)
    def test_base_file_metadata_or_bytes_change_refuses(self):
        L=C.load('apps_cache_controls_preservation',ROOT/'scripts/ci/welcome-native/lifecycle.py')
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'held';path.write_bytes(b'held');held={'packages':[],'nodes':{str(path):I.entry(L,path)}}
            digest=I.preserve_base(L,held);self.assertEqual(len(digest),64)
            path.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'original574'):I.preserve_base(L,held)


class CleanupControls(unittest.TestCase):
    def test_original_eight_actor_lease_and_foreign_labels_remain_guarded(self):
        old=job.inherited(ROOT)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);runtime=root/'runtime';runtime.mkdir();base=root/'base';base.mkdir()
            image='sha256:'+'a'*64;token='b'*32;name='cachy-asahi-product-'+'c'*32
            (base/'report.json').write_bytes(C.encoded({'image':image}));(runtime/'consumer.lock').write_bytes(b'')
            (runtime/'owner.json').write_bytes(C.encoded(dict(schema_version=1,token=token,image=image,label=C.LABEL,containers=[name])))
            command=Mock(return_value=NS(returncode=0,stdout=json.dumps([dict(Image=image,Config={'Labels':{C.LABEL:'FOREIGN'}},Id='d'*64,Name='/'+name)]).encode(),stderr=b''))
            with self.assertRaisesRegex(ValueError,'foreign'):old.retire_consumers(runtime,base,{'consumer_token':token},command)
            self.assertFalse(any('rm' in call.args[0] for call in command.call_args_list))
            fd=os.open(runtime/'consumer.lock',os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            try:
                with self.assertRaises(BlockingIOError):old.retire_consumers(runtime,base,{'consumer_token':token},command)
            finally:os.close(fd)
    def test_unknown_consumer_retains_both_producer_and_authority(self):
        old=NS(manifest_files=Mock(),retire_consumers=Mock(side_effect=ValueError('unknown consumer')),cleanup=Mock())
        producer=NS(retire_owned=Mock())
        with tempfile.TemporaryDirectory() as d,patch.object(job,'inherited',return_value=old),patch.object(C,'load',return_value=producer):
            root=Path(d);runtime=root/'runtime';runtime.mkdir();authority=runtime/'test-signing';authority.mkdir();sentinel=authority/'private-held';sentinel.write_bytes(b'held')
            value=job.cleanup(ROOT,{},root/'base',runtime,root/'cleanup.json',command=Mock())
            self.assertEqual(value['status'],'FAIL');self.assertEqual(value['authority'],'RETAINED');self.assertEqual(sentinel.read_bytes(),b'held')
            old.cleanup.assert_not_called();producer.retire_owned.assert_not_called()
    def test_dependency_images_use_exact_existing_owner_and_no_prune(self):
        source=(ROOT/'scripts/ci/maintained_desktop574.py').read_text();self.assertIn("'--no-prune'",source)
        text=(C.HERE/'run.py').read_text();self.assertIn('producer.owner_begin(directory,dep_token)',text)
        self.assertIn('producer.inspect_image(dep_image,dep_token)',text)
        cleanup=(C.HERE/'job.py').read_text();self.assertLess(cleanup.index('old.retire_consumers'),cleanup.index('producer.retire_owned'))
        self.assertLess(cleanup.index('producer.retire_owned'),cleanup.index('ordered=old.cleanup'))
        self.assertLess(cleanup.index('ordered=old.cleanup'),cleanup.index('shutil.rmtree(authority)'))


if __name__=='__main__':unittest.main(verbosity=2)
