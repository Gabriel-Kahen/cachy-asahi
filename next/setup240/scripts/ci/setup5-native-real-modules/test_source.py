# SPDX-License-Identifier: MIT
"""Inert controls and actual retained archive inspection; no process/native actors."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import adapter
import contract as C
import installed
import job
import lifecycle
import prepare

SOURCE=Path(os.environ.get('SETUP5_REAL_SOURCE',Path(__file__).resolve().parents[3])).absolute()
SETUP=Path(os.environ.get('SETUP5_REAL_SETUP_INPUTS',SOURCE/'setup5-accepted-inputs')).absolute()
MODULES=Path(os.environ.get('SETUP5_REAL_MODULE_INPUTS',SOURCE/'setup5-six-module-inputs')).absolute()
OLD=Path(os.environ.get('SETUP5_REAL_OLD_INPUTS',Path(os.environ.get('RUNNER_TEMP','/tmp'))/'setup5-retained4')).absolute()


def real_receipt():
    cases={n:dict(status='PASS',caller_continued=True,shell_exit=0) for n in C.CASES}
    homes={str(i):dict(activation=dict(selected=list(C.MODULES),repeat_unchanged=True,preview_readonly=True),removal=dict(status='PASS',user_bytes_modes_preserved=True,unrelated_user_files_preserved=True)) for i in range(6)}
    return dict(status='PASS_NATIVE_INSTALLED_SETUP5_REAL_MODULE_GENERATED_RCS',scope='ACTUAL_INSTALLED_SETUP5_AND_SIX_MODULE_GENERATED_RCS',machine='aarch64',uid=1000,page_size=4096,installed_helper_sha256='ea505b6437a416c49e494e9ee0a16a9b160e95fed232ef920ad29aa510e28afd',installed_runtime_join=dict(status='PASS_SOURCE_IDENTICAL_RUNTIME',modules=list(C.MODULES)),zsh_mode='DEFAULT_ASYNC_PRESENCE_ASSERTED',notification_delivery='NOT_RUN',notification_scope='PRIVATE_NOTIFY_SEND_RECORDER_ONLY',hardware='NOT_RUN',defaults_enabled=False,release='NOT_ADMITTED',cases=cases,lifecycle=homes,conflicts=dict(status='PASS',activate_remove_exit=2,retained_edited_components=['fish-done','zsh-history-substring-search'],other_components_removed=4))


class Controls(unittest.TestCase):
    def setUp(self):
        self.actor=patch.object(subprocess,'Popen',side_effect=AssertionError('actual process/native actors forbidden'));self.actor.start();self.addCleanup(self.actor.stop)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        C.SOURCE=SOURCE;C.ROOTS=dict(setup5=SETUP,modules=MODULES,setup4=OLD)
        sys.path[:0]=[str(SOURCE/'scripts/build'),str(SOURCE/'scripts/checks')]
        self.checks=C.load('real_module_checks',SOURCE/'scripts/checks/package_checks.py');self.bind=C.load('real_module_binding',SOURCE/'scripts/build/build.py')

    def test_expected581_lock_is_exact574_plus_seven_candidates(self):
        baseline={r['name']:r['version'] for r in C.read(SOURCE/'scripts/ci/maintained-desktop574-inputs.json')['packages']}
        self.assertEqual(len(baseline),574);self.assertFalse(set(baseline)&set(C.NAMES));self.assertEqual(C.expected(),baseline|C.VERSIONS)

    def test_root_frozen_module_index_and_all_six_actual_pairs(self):
        rows=C.module_rows(MODULES,SOURCE,self.checks,self.bind)
        self.assertEqual(set(rows),set(C.NAMES)-{'cachy-asahi-setup'})
        self.assertIn('OVERALL_EXPANDED600_FAIL',rows['cachy-asahi-fish-bang-bang']['qualification'])

    def test_full_seven_package_stage_and_borrowed_inputs_are_unchanged(self):
        before=C.borrowed_snapshot();context,products=C.stage_inputs(SOURCE,self.root,{'inert-baseline':'data-only'},self.checks,self.bind)
        self.assertEqual(set(products),set(C.NAMES));self.assertEqual(C.borrowed_snapshot(),before)
        self.assertEqual(len(list((context/'pairs').rglob('*.pkg.tar.xz'))),14)
        self.assertEqual(set(C.read(context/'products.json')),{'cachy-asahi-setup'})
        self.assertEqual(set(C.read(context/'modules.json')),set(C.NAMES))
        self.assertEqual({v['version'] for n,v in products.items() if n=='cachy-asahi-setup'},{'0.1.0-5'})

    def test_input_index_mutation_refused_before_package_inspection(self):
        p=self.root/'index.json';p.write_text('{}')
        with patch.object(self.checks,'package',side_effect=AssertionError('must not inspect')):
            with self.assertRaisesRegex(ValueError,'identity'):C.module_rows(self.root,SOURCE,self.checks,self.bind)

    def test_exact_empty_log_reference_is_preserved_and_hash_checked(self):
        p=self.root/'empty.log';p.write_bytes(b'');ref=dict(path=p.name,bytes=0,sha256=C.hash_bytes(b''))
        self.assertEqual(C.checked(self.root,ref),p)
        p.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'identity'):C.checked(self.root,ref)

    def test_source_alias_and_parent_traversal_refused(self):
        (self.root/'dir').mkdir();(self.root/'alias').symlink_to(self.root/'dir',target_is_directory=True)
        for path in (self.root/'alias'/'index.json',self.root/'dir'/'..'/'index.json'):
            with self.assertRaisesRegex(ValueError,'ordinary'):C.safe(path)

    def test_borrowed_snapshot_detects_regular_bytes_and_mode_changes(self):
        p=self.root/'packet';p.mkdir();f=p/'file';f.write_bytes(b'x')
        with patch.object(C,'ROOTS',dict(one=p)):
            before=C.borrowed_snapshot();f.write_bytes(b'y');self.assertNotEqual(C.borrowed_snapshot(),before)
            before=C.borrowed_snapshot();f.chmod(0o600);self.assertNotEqual(C.borrowed_snapshot(),before)

    def test_manual_workflow_checks_packets_before_producer_and_preserves_cleanup(self):
        text=(Path(__file__).resolve().parents[3]/'.github/workflows/native-arm-setup5-real-modules.yml').read_text()
        self.assertIn('workflow_dispatch:',text);self.assertNotIn('schedule:',text);self.assertIn('cancel-in-progress: false',text)
        self.assertLess(text.index('Prove the explicit source'),text.index('Seed the six exact retained'))
        self.assertLess(text.index('Stage only exact indexed public packet files'),text.index('Focused source and hosted entry controls'))
        self.assertLess(text.index('Focused source and hosted entry controls'),text.index('Reconstruct pinned inputs'))
        self.assertIn('ref: de35c384a2e5b14b664d4156897f271b81e467ba',text)
        self.assertIn('--setup5-inputs "$RUNNER_TEMP/setup5-real-inputs/setup5"',text)
        self.assertIn('--modules-inputs "$RUNNER_TEMP/setup5-real-inputs/modules"',text)
        self.assertIn("if: always() && steps.proof.outcome == 'success'",text)
        self.assertIn('--kill-after=30s 1500s',text);self.assertIn('--kill-after=10s 330s',text)

    def test_run_reuses_owned_native_machinery_without_build_calls(self):
        raw=adapter.source(SOURCE);compile(raw,'<adapted-run>','exec')
        self.assertNotIn('shared.build(',raw);self.assertNotIn('comparison.compare(',raw)
        self.assertIn('len(self)<4',raw);self.assertIn('signal.ITIMER_REAL,1500',raw)
        self.assertIn("out/'lifecycle.log',600",raw);self.assertIn('C.stage_inputs(source,out,base,checks,bind)',raw)
        self.assertIn('C.borrowed_snapshot()==C.BORROWED',raw)
        self.assertIn('dst=/code,readonly',raw);self.assertIn('dst=/legacy,readonly',raw)

    def test_changed_adapter_anchor_refuses(self):
        with patch.object(Path,'read_text',return_value='changed'):
            with self.assertRaisesRegex(ValueError,'stage block'):adapter.source(SOURCE)

    def test_legacy_lifecycle_adapter_changes_only_two_mount_paths(self):
        path=SOURCE/'scripts/ci/setup5-native/lifecycle.py';expected=path.read_text().replace("Path('/runner/contract.py')","Path('/legacy/contract.py')").replace("'/runner/exercise.py'","'/legacy/exercise.py'")
        self.assertEqual(lifecycle.legacy_source(path),expected)
        legacy=C.load('legacy_exact_contract',SOURCE/'scripts/ci/setup5-native/contract.py')
        self.assertEqual(len(legacy.PHASES),8);self.assertEqual([n for _,n in legacy.PHASES],[575,575,575,575,575,574,575,574])

    def test_actual_accepted_24_observations_still_satisfy_original_gate(self):
        accepted=C.read(SETUP/'runtime/lifecycle.json');legacy=C.load('legacy_actual_gate',SOURCE/'scripts/ci/setup5-native/contract.py');legacy.validate_lifecycle(accepted)
        self.assertEqual(len(accepted['actual_observations']),24)
        changed=copy.deepcopy(accepted);changed['actual_observations'].pop()
        with self.assertRaisesRegex(ValueError,'per-phase'):legacy.validate_lifecycle(changed)

    def test_native_host_guard_refuses_before_user_output(self):
        with patch.object(installed.platform,'machine',return_value='x86_64'):
            with self.assertRaisesRegex(ValueError,'native ARM'):installed.exercise(SOURCE,self.root/'never-created')
        self.assertFalse((self.root/'never-created').exists())

    def test_real_receipt_requires_complete_cases_and_ordinary_native_exit(self):
        good=real_receipt();C.validate_real(good)
        for mutation in ('case','exit','caller','uid','arch','mode','helper','source'):
            bad=copy.deepcopy(good)
            if mutation=='case':bad['cases'].pop(next(iter(bad['cases'])))
            elif mutation=='exit':bad['cases']['zsh-request-forward']['shell_exit']=1
            elif mutation=='caller':bad['cases']['fish-request-forward']['caller_continued']=False
            elif mutation=='uid':bad['uid']=0
            elif mutation=='arch':bad['machine']='x86_64'
            elif mutation=='mode':bad['zsh_mode']='SYNC'
            elif mutation=='helper':bad['installed_helper_sha256']='0'*64
            else:bad['installed_runtime_join']['status']='UNVERIFIED'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):C.validate_real(bad)

    def test_real_receipt_requires_all_preservation_and_edited_conflict_gates(self):
        good=real_receipt()
        for mutation in ('home','repeat','preview','user','unrelated','conflict','retained'):
            bad=copy.deepcopy(good)
            if mutation=='home':bad['lifecycle'].pop('0')
            elif mutation in ('repeat','preview'):bad['lifecycle']['0']['activation'][{'repeat':'repeat_unchanged','preview':'preview_readonly'}[mutation]]=False
            elif mutation in ('user','unrelated'):bad['lifecycle']['0']['removal'][{'user':'user_bytes_modes_preserved','unrelated':'unrelated_user_files_preserved'}[mutation]]=False
            elif mutation=='conflict':bad['conflicts']['activate_remove_exit']=0
            else:bad['conflicts']['retained_edited_components']=[]
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):C.validate_real(bad)

    def test_retirement_reuses_labelled_lease_cap_four(self):
        namespace=job.namespace(SOURCE)
        self.assertTrue(callable(namespace['retire_consumers']));self.assertTrue(callable(namespace['cleanup']))
        self.assertIn('len(names)<=4',__import__('inspect').getsource(job.namespace))

    def test_combined_lifecycle_requires_unchanged_legacy_and_exact581_restore(self):
        good=dict(status='PASS_NATIVE_SETUP5_LEGACY_AND_REAL_MODULES',base_count=574,restored_count=574,products=C.VERSIONS,legacy=C.read(SETUP/'runtime/lifecycle.json'),events=[dict(phase=p,inventory_count=n,status='PASS',legacy_homes_preserved=True,system_preserved=True,database_check=True) for p,n in [('install-real-seven',581),('remove-real-seven',574)]],real_modules=real_receipt(),installed_payloads_preserved=True,new_user_state_preserved_on_remove=True,ordinary_user_processes_absent=True)
        C.validate_lifecycle(good)
        for mutation in ('count','legacy','payload','edits','process'):
            bad=copy.deepcopy(good)
            if mutation=='count':bad['events'][0]['inventory_count']=600
            elif mutation=='legacy':bad['legacy']['events'].pop()
            elif mutation=='payload':bad['installed_payloads_preserved']=False
            elif mutation=='edits':bad['new_user_state_preserved_on_remove']=False
            else:bad['ordinary_user_processes_absent']=False
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):C.validate_lifecycle(bad)

    def cleanup_fixture(self):
        base=self.root/'base';runtime=self.root/'runtime';base.mkdir();runtime.mkdir();image='sha256:'+'1'*64;token='2'*32
        names=['cachy-asahi-product-probe-'+'3'*32,'cachy-asahi-product-lifecycle-'+'4'*32]
        (base/'report.json').write_text(json.dumps(dict(image=image)))
        (runtime/'consumer.lock').write_bytes(b'');(runtime/'owner.json').write_text(json.dumps(dict(schema_version=1,token=token,image=image,label=C.LABEL,containers=names)))
        return base,runtime,image,token,names

    def test_two_owned_consumers_are_retired_in_reverse_order(self):
        base,runtime,image,token,names=self.cleanup_fixture();active=set(names);removed=[]
        def observe(argv):
            name=argv[-1]
            if 'inspect' in argv:
                if name not in active:return SimpleNamespace(returncode=1,stdout=b'',stderr=('No such container: '+name).encode())
                value=dict(Image=image,Config=dict(Labels={C.LABEL:token}),Id=('5' if name==names[0] else '6')*64,Name='/'+name)
                return SimpleNamespace(returncode=0,stdout=json.dumps([value]).encode(),stderr=b'')
            name=names[0] if argv[-1]=='5'*64 else names[1];active.remove(name);removed.append(name)
            return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
        value=job.namespace(SOURCE)['retire_consumers'](runtime,base,dict(consumer_token=token),observe)
        self.assertEqual(removed,names[::-1]);self.assertFalse(active);self.assertEqual(len(value['containers']),2)
        self.assertTrue(all(r['absence_verified'] for r in value['containers']))

    def test_foreign_consumer_is_not_signalled_or_removed(self):
        base,runtime,image,token,names=self.cleanup_fixture();calls=[]
        def observe(argv):
            calls.append(argv);value=dict(Image=image,Config=dict(Labels={C.LABEL:'foreign'}),Id='5'*64,Name='/'+names[-1])
            return SimpleNamespace(returncode=0,stdout=json.dumps([value]).encode(),stderr=b'')
        with self.assertRaisesRegex(ValueError,'foreign'):job.namespace(SOURCE)['retire_consumers'](runtime,base,dict(consumer_token=token),observe)
        self.assertEqual(len(calls),1);self.assertNotIn('rm',calls[0])

    def test_closed_export_joins_two_actual_consumers_and_all_standalone_observations(self):
        # Synthetic new-native fields only; reused historical legacy data remain exact.
        base,runtime,image,token,names=self.cleanup_fixture();context,products=C.stage_inputs(SOURCE,runtime,{'synthetic-control':'only'},self.checks,self.bind)
        legacy=C.read(SETUP/'runtime/lifecycle.json');real=real_receipt();life=dict(status='PASS_NATIVE_SETUP5_LEGACY_AND_REAL_MODULES',base_count=574,restored_count=574,products=C.VERSIONS,legacy=legacy,events=[dict(phase=p,inventory_count=n,status='PASS',legacy_homes_preserved=True,system_preserved=True,database_check=True) for p,n in [('install-real-seven',581),('remove-real-seven',574)]],real_modules=real,installed_payloads_preserved=True,new_user_state_preserved_on_remove=True,ordinary_user_processes_absent=True)
        cleanup=dict(status='PASS',image=dict(id=image,absence_verified=True),probe=dict(absence_verified=True));jobtoken='7'*16
        original=dict(status='PASS_NATIVE_OFFLINE_574_TRANSACTION',ownership=dict(token=jobtoken),image=image,owned_cleanup=cleanup)
        (base/'report.json').write_text(json.dumps(original));(base/'installed-packages.lock').write_text('synthetic-control only\n')
        report=dict(status='PASS_NATIVE_SETUP5_LEGACY_AND_REAL_MODULES',lifecycle=life,borrowed_inputs_preserved=True,base_count=574,base_image=image,base_lock_sha256=C.digest(base/'installed-packages.lock'),ownership_token=token,products={n:dict(sha256=p['sha256'],accepted_pair=p['accepted_pair']) for n,p in products.items()})
        for name,value in (('report.json',report),('lifecycle.json',life),('legacy-lifecycle.json',legacy),('real-modules.json',real)):(runtime/name).write_text(json.dumps(value))
        for name in ('base-inventory.log','lifecycle.log'):(runtime/name).write_text('synthetic inert control only\n')
        (runtime/'observations').mkdir()
        for row in legacy['actual_observations']:(runtime/'observations'/(row['profile']+'-'+row['phase']+'.json')).write_text(json.dumps(row['proof']))
        proof=self.root/'proof.json';proof.write_text(json.dumps(dict(status='SOURCE_PROOF_PASS',job_token=jobtoken,consumer_token=token)))
        ordered=self.root/'ordered.json';value=dict(status='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP',consumer=dict(status='PASS_CONSUMERS_RETIRED',containers=[dict(container=n,status='PASS',absence_verified=True) for n in names]),producer=cleanup);ordered.write_text(json.dumps(value))
        harness=self.root/'synthetic-harness';harness.mkdir();(harness/'source-manifest.json').write_text(json.dumps(dict(files={})))
        with patch.object(C,'HERE',harness),patch.object(C,'verify_source',return_value=None):
            J=job.namespace(SOURCE);result=job.retain(J,SOURCE,base,runtime,proof,ordered,self.root/'export-pass')
            self.assertEqual(result['status'],'PASS_NATIVE_SETUP5_LEGACY_AND_REAL_MODULES_RETIRED',result['errors'])
            value['consumer']['containers'].pop();ordered.write_text(json.dumps(value))
            result=job.retain(J,SOURCE,base,runtime,proof,ordered,self.root/'export-missing-consumer')
            self.assertEqual(result['status'],'FAIL_OR_INCOMPLETE')
            value['consumer']['containers'].append(dict(container=names[-1],status='PASS',absence_verified=True));ordered.write_text(json.dumps(value))
            (runtime/'observations/state-legacy.json').unlink()
            result=job.retain(J,SOURCE,base,runtime,proof,ordered,self.root/'export-missing-observation')
            self.assertEqual(result['status'],'FAIL_OR_INCOMPLETE')

    def test_indexed_packet_staging_excludes_checkout_git_metadata(self):
        code=self.root/'code'
        for name in ('scripts/ci/setup5-real-modules/run.py','scripts/checks/package_checks.py','scripts/build/build.py'):
            p=code/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(SOURCE/name,p)
        setup=self.root/'setup-checkout';modules=self.root/'module-checkout';shutil.copytree(SETUP,setup);shutil.copytree(MODULES,modules)
        for p in (setup,modules):(p/'.git').mkdir();(p/'.git/HEAD').write_text('private checkout metadata')
        with patch.object(C,'verify_source',return_value=None):value=prepare.stage(code,setup,modules,self.root/'staged')
        self.assertEqual(value['status'],'PASS_PASSIVE_ROOT_BOUND_PACKET_STAGING');self.assertEqual(value['setup5_files'],149);self.assertEqual(value['six_module_files'],154)
        self.assertFalse((self.root/'staged/setup5/.git').exists());self.assertFalse((self.root/'staged/modules/.git').exists())
        self.assertEqual((setup/'.git/HEAD').read_text(),'private checkout metadata')

    def test_actual_retained_scripts_join_current_sources_with_real_package_layouts(self):
        rows=C.module_rows(MODULES,SOURCE,self.checks,self.bind);stage=self.root/'private-payload-layout';stage.mkdir()
        for row in rows.values():
            with tarfile.open(C.checked(MODULES,row['files']['a']),'r:*') as archive:
                for member in archive:
                    name=member.name.removeprefix('./')
                    if name in row['payload']:
                        self.assertTrue(member.isfile());target=stage/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(archive.extractfile(member).read())
        B=C.load('existing_module_paths',SOURCE/'scripts/ci/shell-modules-coexistence/run.py');join=C.load('exact_installed_join',SOURCE/'scripts/ci/expanded-development-composition/installed_shells.py')
        join.RUNTIME={k:str(stage/p.removeprefix('/')) for k,p in join.RUNTIME.items()};join.installed_join(SOURCE,B)
        bad=stage/'usr/share/cachy-asahi/fish-done/done.fish';bad.write_bytes(bad.read_bytes()+b'# drift\n')
        with self.assertRaisesRegex(ValueError,'installed shell input differs'):join.installed_join(SOURCE,B)


# Entry counts observed in the retained complete host generated-RC workspace.
# CI builds the same seven-home shape with synthetic private bytes, never a
# fabricated native execution receipt or a dependency on an untracked host tree.
REAL_HOME_COUNTS={'edited-conflict-user':7,'fish-bang-autopair-done':66,'fish-done-autopair-bang':66,'fish-noninteractive':20,'zsh-autosuggest-highlight-substring':32,'zsh-highlight-substring-autosuggest':32,'zsh-noninteractive':11}


class WorkspacePreservation(unittest.TestCase):
    def setUp(self):
        self.actor=patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden'));self.actor.start();self.addCleanup(self.actor.stop)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.parent=Path(self.temp.name)/'user';work=self.parent/'work';work.mkdir(parents=True)
        self.L=C.load('unchanged_128_entry_snapshot',SOURCE/'scripts/ci/welcome-native/lifecycle.py');self.H=C.load('accepted_bounded_home_snapshot',SOURCE/'scripts/ci/setup5-real-modules/run.py')
        for name,count in REAL_HOME_COUNTS.items():
            home=work/name;(home/'config/fish').mkdir(parents=True);(home/'setup-state').mkdir()
            for relative in ('config/fish/config.fish','.zshrc','setup-state/state.json'):(home/relative).write_bytes(b'private user config/journal/edit bytes\n')
            (home/'fixture-link').symlink_to('.zshrc')
            for n in range(count-7):(home/('user-data-'+str(n))).write_bytes(b'preserve user data\n')
            self.assertEqual(sum(1 for _ in home.rglob('*')),count)
        self.real=dict(lifecycle={n:{} for n in REAL_HOME_COUNTS if n!='edited-conflict-user'});(work/'receipt.json').write_text(json.dumps(dict(scope='SYNTHETIC_WORKSPACE_SHAPE_ONLY'))+'\n')

    def snapshot(self):return lifecycle.workspace_snapshot(self.parent,self.real,self.L,self.H)

    def test_actual_seven_home_shape_exceeds_old128_but_every_node_is_preserved(self):
        with self.assertRaisesRegex(ValueError,'config entry cap'):self.L.snapshot(self.parent)
        before=self.snapshot();expected={'.':self.L.entry(self.parent),**{str(p.relative_to(self.parent)):self.L.entry(p) for p in self.parent.rglob('*')}}
        self.assertEqual(len(before),244);self.assertEqual(before,expected);self.assertEqual(self.snapshot(),before)

    def test_user_config_journal_data_link_and_directory_metadata_changes_are_detected(self):
        home=self.parent/'work/edited-conflict-user'
        for relative in ('config/fish/config.fish','setup-state/state.json'):
            before=self.snapshot();path=home/relative;path.write_bytes(path.read_bytes()+b'deliberate retained edit\n');self.assertNotEqual(self.snapshot(),before)
        before=self.snapshot();(home/'.zshrc').chmod(0o600);self.assertNotEqual(self.snapshot(),before)
        before=self.snapshot();(home/'fixture-link').unlink();(home/'fixture-link').symlink_to('config/fish/config.fish');self.assertNotEqual(self.snapshot(),before)
        before=self.snapshot();path=home/'config';info=path.stat();os.utime(path,ns=(info.st_atime_ns,info.st_mtime_ns+1000000));self.assertNotEqual(self.snapshot(),before)
        before=self.snapshot();path=self.parent/'work/receipt.json';path.write_text(path.read_text()+' ');self.assertNotEqual(self.snapshot(),before)

    def test_unregistered_outer_user_state_or_missing_home_is_refused(self):
        path=self.parent/'outside-user-state';path.write_text('must not silently exclude')
        with self.assertRaisesRegex(ValueError,'workspace root'):self.snapshot()
        path.unlink();path=self.parent/'work/extra-user-state';path.write_text('must not silently exclude')
        with self.assertRaisesRegex(ValueError,'registry'):self.snapshot()
        path.unlink();shutil.rmtree(self.parent/'work/edited-conflict-user')
        with self.assertRaisesRegex(ValueError,'registry'):self.snapshot()

    def test_existing_individual256_node_cap_is_still_required(self):
        home=self.parent/'work/edited-conflict-user'
        for n in range(250):(home/('extra-'+str(n))).write_bytes(b'')
        with self.assertRaisesRegex(ValueError,'bounded private home'):self.snapshot()

    def test_existing_individual_file_cap_is_still_required(self):
        (self.parent/'work/edited-conflict-user/oversize').write_bytes(b'x'*(1024**2+1))
        with self.assertRaisesRegex(ValueError,'bounded private fixture bytes'):self.snapshot()

    def test_existing_individual_home_byte_cap_is_still_required(self):
        home=self.parent/'work/edited-conflict-user'
        for n in range(5):(home/('large-'+str(n))).write_bytes(b'x'*1024**2)
        with self.assertRaisesRegex(ValueError,'bounded private fixture bytes'):self.snapshot()

    def test_aliased_home_and_special_file_are_refused(self):
        path=self.parent/'work/edited-conflict-user';shutil.rmtree(path);path.symlink_to('fish-bang-autopair-done',target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'ordinary absolute'):self.snapshot()
        path.unlink();path.mkdir();os.mkfifo(path/'special')
        with self.assertRaisesRegex(ValueError,'ordinary fixture node'):self.snapshot()

    def test_completed_raw_receipt_survives_a_later_preservation_failure(self):
        value=real_receipt();raw=json.dumps(value,separators=(',',':'))+'\n';target=Path(self.temp.name)/'published.json'
        result=lifecycle.retain_real(raw,target);self.assertEqual(result,value);self.assertEqual(target.read_bytes(),raw.encode());self.snapshot()
        (self.parent/'unexpected').write_text('later failure')
        with self.assertRaisesRegex(ValueError,'workspace root'):self.snapshot()
        self.assertEqual(target.read_bytes(),raw.encode())
        # Publishing data does not validate it or grant a final lifecycle PASS.
        raw='{"status":"FAIL"}\n';target=Path(self.temp.name)/'failed.json'
        with self.assertRaises(ValueError):lifecycle.retain_real(raw,target)
        self.assertEqual(target.read_text(),raw)

    def test_raw_receipt_byte_cap_refuses_without_publication(self):
        target=Path(self.temp.name)/'oversize.json'
        with self.assertRaisesRegex(ValueError,'bounded actual real-flow stdout'):lifecycle.retain_real('x'*(128*1024+1),target)
        self.assertFalse(target.exists())

    def test_main_retains_raw_before_cleanup_payload_snapshot_or_normal_remove(self):
        import ast
        raw=Path(lifecycle.__file__).read_text();tree=ast.parse(raw);main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        saved=next(i for i,n in enumerate(main.body) if isinstance(n,ast.Assign) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='retain_real')
        snapshot=next(i for i,n in enumerate(main.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='user_before' for t in n.targets))
        self.assertLess(saved,snapshot);self.assertNotIn('L.snapshot(parent)',raw)
        line=ast.unparse(main.body[saved]);self.assertIn("'/out/real-modules.json'",line)
        self.assertEqual(raw.count("Path('/out/real-modules.json')"),1)


if __name__=='__main__':unittest.main()
