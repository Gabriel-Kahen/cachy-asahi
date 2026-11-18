"""Hosted-safe contract and ownership tests: no Docker, builds, keys or dispatch."""
import copy
import fcntl
import json
import os
import sys
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import native_contract as C
import installed as I
import job as J
import run as R

HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('WELCOME_MANAGEMENT_SOURCE',HERE.parents[2]))


def complete_policy():
    value=C.read(HERE/'input-policy.json');value.update(status='ROOT_BOUND_FINAL_PRODUCT_SOURCE',candidate_source='1'*40)
    value['ui']=dict(labels=dict(management='Management',doctor='Run Doctor',orphans='Assess orphan packages'),
        strings=dict(running='Running',complete='Complete',failure='Failed',unavailable='Unavailable'),raw_preview_suffix='Raw output',max_output_bytes=65536,orphan_preview_bytes=8192,orphan_preview_suffix='\n[Raw preview truncated at 8 KiB.]')
    for name,row in value['products'].items():
        row.update(source_files={'PKGBUILD':dict(bytes=1,sha256='0'*64)},payload={'usr/bin/'+name:[name,0o755]},
            dependencies={k:[] for k in ('depends','makedepends','checkdepends','optdepends')},check_markers=['^OK$'],recipe_sha256='0'*64)
    value['products'][C.DOCTOR]['accepted_archive']=dict(name=C.DOCTOR+'-0.1.0-1-any.pkg.tar.xz',bytes=1,sha256='0'*64,source_commit='2'*40,producer_run='123')
    return value


ROOT_TAP='# random seed: R02Sfixture\n1..1\n# Start of management tests\nok 1 /management/root-guard\n# End of management tests\n'


def root_receipt():
    cflags=['-I/usr/include/glib-2.0'];libs=['-lgio-2.0','-lglib-2.0']
    return dict(status='PASS_NATIVE_REAL_ROOT_GUARD',uid=0,euid=0,architecture='aarch64',page_size=4096,
        scope='SEPARATE_SOURCE_BOUND_TEST_CONTROL_NOT_INSTALLED_PRODUCT_BEHAVIOR',hardware='NOT_RUN',
        source_files={n:C.product(C.NAME)['source_files'][n] for n in C.ROOT_GUARD_SOURCES},binary_sha256='0'*64,
        compile_command=C.root_guard_compile(cflags,libs),pkg_config_cflags=cflags,pkg_config_libs=libs,
        test_command=[C.ROOT_GUARD_BINARY,'-p','/management/root-guard'],**C.root_guard_tap(ROOT_TAP))


def receipt():
    observation=dict(reports={n:'0'*64 for n in C.REPORTS},actual_default_count=577,db_preserved=True,base_protected=True,
        readonly_enforced='UNPRIVILEGED_NO_DB_WRITE_ACCESS',plan_verify='PASS_NOT_APPLIED',foreign_lock='PASS_REFUSAL_PRESERVED',
        apply_supported=False,welcome_status='PASS_ACTUAL_PLATFORM',doctor='PASS_ACTUAL_READONLY_JSON')
    return dict(status='PASS_MANAGEMENT_INSTALLED_READONLY_LIFECYCLE',root_guard=root_receipt(),base_count=574,installed_count=577,base574_preserved=True,
        user_preserved=True,reports_preserved=True,hardware='NOT_RUN',removal='NOT_IMPLEMENTED',architecture='aarch64',page_size=4096,
        events=[dict(phase=phase,count=count,base574_preserved=True,user_preserved=True,**(dict(observations=[dict(observation,home='management-home-'+k)
            for k in ('fresh','existing')]) if count==577 else dict(payloads_absent=True))) for phase,count in C.PHASES])


class SourceControls(unittest.TestCase):
    def test_accepted_builder_imports_selected_contract_without_ambient_module(self):
        for ambient in (None,SimpleNamespace(marker='foreign contract')):
            with self.subTest(ambient=ambient),patch.dict(sys.modules):
                sys.modules.pop('contract',None)
                if ambient is not None:sys.modules['contract']=ambient
                before=list(sys.path)
                builder=R.load_builder(ROOT)
                self.assertIs(builder.C,C)
                self.assertEqual(Path(builder.__file__),ROOT/'scripts/ci/welcome-native/run.py')
                self.assertEqual(builder.inventory('fixture-package 1-1\n'),{'fixture-package':'1-1'})
                self.assertEqual(sys.path,before)
                if ambient is None:self.assertNotIn('contract',sys.modules)
                else:self.assertIs(sys.modules['contract'],ambient)

    def test_accepted_builder_import_failure_restores_generic_module(self):
        for ambient in (None,SimpleNamespace(marker='foreign contract')):
            with self.subTest(ambient=ambient),patch.dict(sys.modules),patch.object(C,'load',side_effect=RuntimeError('fixture import failure')):
                sys.modules.pop('contract',None)
                if ambient is not None:sys.modules['contract']=ambient
                with self.assertRaisesRegex(RuntimeError,'fixture import failure'):R.load_builder(ROOT)
                if ambient is None:self.assertNotIn('contract',sys.modules)
                else:self.assertIs(sys.modules['contract'],ambient)

    def test_unbound_refuses_before_any_native_observer_or_output(self):
        unbound=C.policy(False);unbound.update(status='UNBOUND_FIXTURE',candidate_source=None)
        with patch.object(C,'read',return_value=unbound),patch.object(R.platform,'system',side_effect=AssertionError('actor reached')):
            with self.assertRaisesRegex(ValueError,'UNBOUND'):R.execute(ROOT,Path('/unused/base'),Path('/unused/out'),'1'*32)
            with self.assertRaisesRegex(ValueError,'UNBOUND'):C.verify_source(ROOT)

    def test_unbound_source_manifest_cannot_prove(self):
        unbound=copy.deepcopy(C.read(HERE/'source-manifest.json'));unbound['status']='UNBOUND_FIXTURE'
        with self.assertRaises(ValueError):J.manifest_files(ROOT,unbound)

    def test_all_final_product_source_and_existing_doctor_archive_bound(self):
        value=C.policy();C.verify_source(ROOT)
        self.assertEqual(value['status'],'ROOT_BOUND_FINAL_PRODUCT_SOURCE')
        self.assertEqual(value['candidate_source'],'0b74d8ecea4f152bda4adfbd9bee488890db4363')
        self.assertEqual(set(value['products']),set(C.NAMES));self.assertEqual(value['ui']['strings']['complete'],'Elapsed:')
        self.assertEqual(value['ui']['strings']['running'],'Running check…');self.assertEqual(value['ui']['max_output_bytes'],1048576)
        for name,source_count,payload_count,recipe_sha in ((C.NAME,25,9,'06f3d380b27cdc0e4299d098d32706fbb89afcd2f9296bb7bdace2474e10e48e'),
                (C.DOCTOR,7,4,'119e2b839195e0c18b885b0208928e234af63e2a5f958dbf4fc9edad5a2c04b1'),
                (C.ORPHANS,8,5,'b59a1b67a8fd6290549e861bd40f5e94447d5376c86eca6baa94d2cdddb6b91a')):
            row=value['products'][name]
            self.assertEqual(len(row['source_files']),source_count);self.assertEqual(len(row['payload']),payload_count)
            self.assertEqual(row['recipe_sha256'],recipe_sha);C.recipe(ROOT,name)
        self.assertEqual(value['products'][C.ORPHANS]['version'],'0.1.0-2')
        stale=copy.deepcopy(value);stale['products'][C.ORPHANS]['version']='0.1.0-1'
        with patch.object(C,'read',return_value=stale),self.assertRaisesRegex(ValueError,'version'):C.policy()
        self.assertEqual(value['products'][C.ORPHANS]['check_markers'],['^Ran 20 tests in [0-9.]+s$','^OK$'])
        self.assertEqual(value['products'][C.DOCTOR]['accepted_archive'],dict(name='cachy-asahi-doctor-0.1.0-1-any.pkg.tar.xz',bytes=13708,
            sha256='06898669fdd6c9e5bdcc9909e6b0e75e958bdbd57520a7082c0e9f5f7fac7482',source_commit='09717a45388e5b90ca80fd3fef327444101c108f',producer_run='38886781500'))

    def test_complete_final_policy_shape_and_missing_ui_refusal(self):
        good=complete_policy()
        with patch.object(C,'read',return_value=good):self.assertEqual(C.policy(),good)
        for key in ('labels','strings','max_output_bytes','raw_preview_suffix','orphan_preview_bytes','orphan_preview_suffix'):
            bad=copy.deepcopy(good);bad['ui'].pop(key)
            with patch.object(C,'read',return_value=bad),self.subTest(key=key),self.assertRaises(ValueError):C.policy()

    def test_each_product_source_payload_checks_dependencies_required(self):
        for name in C.NAMES:
            for field in ('source_files','payload','check_markers','dependencies'):
                bad=complete_policy();bad['products'][name][field]=[] if field=='check_markers' else {}
                with patch.object(C,'read',return_value=bad),self.subTest(name=name,field=field),self.assertRaises(ValueError):C.policy()

    def test_doctor_accepted_archive_mandatory_exact_provenance(self):
        for field,value in (('name','foreign.pkg.tar.xz'),('bytes',0),('sha256','x'),('source_commit','branch'),('producer_run','0')):
            bad=complete_policy();bad['products'][C.DOCTOR]['accepted_archive'][field]=value
            with patch.object(C,'read',return_value=bad),self.subTest(field=field),self.assertRaises(ValueError):C.policy()

    def test_pinned_infrastructure_current_exact_bytes(self):
        pins=C.read(HERE/'infrastructure-pins.json')
        self.assertGreater(len(pins),20)
        for name,row in pins.items():C.checked(ROOT,name,row)
        self.assertFalse(any(n.startswith(('packages/tools/cachy-asahi-welcome/','packages/tools/cachy-asahi-doctor/')) for n in pins))
        self.assertNotIn('scripts/ci/welcome-managed-gui/transport.json',pins)

    def test_pin_reader_refuses_drift_traversal_link_duplicate_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);file=root/'input';file.write_text('known');pin=dict(bytes=5,sha256=C.digest(file));C.checked(root,'input',pin)
            file.write_text('drift')
            with self.assertRaises(ValueError):C.checked(root,'input',pin)
            with self.assertRaises(ValueError):C.checked(root,'../input',pin)
            (root/'alias').symlink_to(file)
            with self.assertRaises(ValueError):C.read(root/'alias')
            file.write_text('{"a":1,"a":2}')
            with self.assertRaises(ValueError):C.read(file)

    def test_native_checks_require_full_markers_and_no_skips(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(C,'product',return_value=dict(check_markers=C.product(C.ORPHANS)['check_markers'])):
            log=Path(tmp)/'build.log';good='Starting check()\nRan 20 tests in 1.0s\nOK\n';log.write_text(good)
            self.assertTrue(C.check_log(log,C.ORPHANS)['check_enabled'])
            for value in (good.replace('20','18'),good.replace('Starting check()',''),good+'OK (skipped=1)\n',good+'ERROR\n',good+'not ok 1\n'):
                log.write_text(value)
                with self.subTest(value=value),self.assertRaises(ValueError):C.check_log(log,C.ORPHANS)

    def test_exact_archive_bytes_and_buildinfo_pair_gate(self):
        good=dict(status='contents-reproduced',errors=[],packages={'pkg':dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)})
        R.pair_gate(good)
        for field in good['packages']['pkg']:
            bad=copy.deepcopy(good);bad['packages']['pkg'][field]=False
            with self.subTest(field=field),self.assertRaises(ValueError):R.pair_gate(bad)

    def test_database_query_excludes_transaction_only_flags(self):
        calls=[];api=SimpleNamespace(need=C.need,command=lambda argv:calls.append(argv))
        argv=['/usr/bin/pacman','--config','/tmp/management-pacman.conf','--noconfirm','--noscriptlet'];before=list(argv)
        I.database_check(api,argv)
        self.assertEqual(calls,[argv[:3]+['-Dk']]);self.assertEqual(argv,before)
        self.assertNotIn('--noscriptlet',calls[0]);self.assertIn('--noscriptlet',argv)

    def test_manual_workflow_proof_before_secrets_cleanup_before_retention(self):
        path=HERE.parents[2]/'.github/workflows/native-arm-welcome-management.yml';text=path.read_text()
        self.assertIn('workflow_dispatch:',text);self.assertNotIn('push:',text);self.assertNotIn('pull_request:',text)
        self.assertIn('cancel-in-progress: false',text)
        for token,name in (('@JOB_SHA256@','job.py'),('@MANIFEST_SHA256@','source-manifest.json')):
            expected=token if token in text else C.digest(HERE/name)
            self.assertEqual(text.count("'"+expected+"'"),1)
        self.assertLess(text.index('Prove the explicit'),text.index('secrets.'));self.assertLess(text.index('Retire owned'),text.index('Retain the closed'))
        source=(HERE/'run.py').read_text();self.assertNotIn('--nodeps',source);self.assertNotIn('--nocheck',source)
        self.assertNotIn('src={out}/test-signing',source);self.assertIn('signer_api.sign(context,out',source)
        self.assertIn("('a','b')",source);self.assertIn("all(row['archive'].name==accepted['name']",source)

    def test_full_lifecycle_acceptance_and_mutations(self):
        C.validate_lifecycle(receipt())
        for key,value in (('base_count',573),('installed_count',576),('hardware','PASS'),('user_preserved',False),('removal','APPLIED'),('reports_preserved',False)):
            row=receipt();row[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):C.validate_lifecycle(row)
        for i in range(5):
            row=receipt();row['events'].pop(i)
            with self.assertRaises(ValueError):C.validate_lifecycle(row)

    def test_actual_cli_and_all_reports_required(self):
        for key in ('actual_default_count','db_preserved','base_protected','readonly_enforced','plan_verify','foreign_lock','apply_supported','welcome_status','doctor'):
            row=receipt();row['events'][0]['observations'][0][key]=None
            with self.subTest(key=key),self.assertRaises(ValueError):C.validate_lifecycle(row)
        row=receipt();row['events'][0]['observations'][0]['reports']={}
        with self.assertRaises(ValueError):C.validate_lifecycle(row)


class RootGuardControls(unittest.TestCase):
    def welcome_log(self):
        # Format actually emitted by the three GLib binaries and the five-case CLI suite.
        groups=(('test_status.c',7),('test_management.c',13),('test_management_report.c',8),('test_report_work.c',3))
        text='Starting check()\n'
        import re
        for filename,count in groups:
            paths=re.findall(r'g_test_add_func\("([^"]+)"',(ROOT/'packages/tools'/C.NAME/filename).read_text())
            self.assertEqual(len(paths),count);text+='1..'+str(count)+'\n'
            for i,path in enumerate(paths,1):
                text+=(C.ROOT_GUARD_SKIP if path=='/management/root-guard' else 'ok '+str(i)+' '+path)+'\n'
        return text+'Ran 5 tests in 0.100s\nOK\nPASS_SOURCE_PAYLOAD_CONTRACT\n'

    def test_ordinary_check_is35_pass_plus_exact_scoped_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            log=Path(tmp)/'build.log';good=self.welcome_log();log.write_text(good)
            row=C.check_log(log,C.NAME);self.assertEqual((row['passed'],row['registered'],row['skipped']),(35,36,1))
            self.assertNotIn('NO_SKIPS',row['status']);self.assertEqual(row['root_guard'],'REQUIRES_SEPARATE_REAL_UID0_CASE')
            for bad in (good.replace(' # SKIP Root guard requires an actual root test process',''),
                good.replace('requires an actual root test process','waived'),good+'ok 14 /management/extra # SKIP unexpected\n',
                good.replace('ok 1 /status/installed','ok 1 /status/installed # SKIP regression'),good+'# TODO later\n'):
                log.write_text(bad)
                with self.subTest(bad=bad),self.assertRaises(ValueError):C.check_log(log,C.NAME)

    def test_nonwelcome_tap_skip_never_allowed(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(C,'product',return_value=dict(check_markers=['^OK$'])):
            path=Path(tmp)/'build.log';path.write_text('Starting check()\nOK\nok 1 /other # SKIP unexpected\n')
            with self.assertRaises(ValueError):C.check_log(path,C.ORPHANS)

    def test_actual_root_tap_demands_one_pass_no_skip(self):
        self.assertEqual(C.root_guard_tap(ROOT_TAP)['passed'],1)
        for tap in (ROOT_TAP.replace('1..1','1..2'),ROOT_TAP.replace('root-guard','other'),ROOT_TAP+'ok 2 /extra\n',
            ROOT_TAP.replace('ok 1','not ok 1'),ROOT_TAP.replace('root-guard\n','root-guard # SKIP not root\n'),ROOT_TAP+'# TODO later\n'):
            with self.subTest(tap=tap),self.assertRaises(ValueError):C.root_guard_tap(tap)

    def test_root_receipt_requires_actual_uid0_source_command_and_raw_tap(self):
        good=root_receipt();C.validate_root_guard(good,ROOT_TAP)
        for key,value in (('uid',1000),('euid',1000),('architecture','x86_64'),('page_size',0),('skipped',1),
            ('passed',0),('source_files',{}),('compile_command',['/bin/true']),('test_command',['/bin/true']),('tap_sha256','f'*64)):
            row=copy.deepcopy(good);row[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):C.validate_root_guard(row,ROOT_TAP)
        with self.assertRaises(ValueError):C.validate_root_guard(good,ROOT_TAP+'# changed\n')

    def test_lifecycle_cannot_substitute_ordinary_skip_for_root_execution(self):
        row=receipt();row.pop('root_guard')
        with self.assertRaises(ValueError):C.validate_lifecycle(row)
        row=receipt();row['root_guard']['status']='SKIPPED_NONROOT'
        with self.assertRaises(ValueError):C.validate_lifecycle(row)

    def test_root_control_separate_source_mount_and_installed_executables_unchanged(self):
        runner=(HERE/'run.py').read_text();life=(HERE/'lifecycle.py').read_text()
        self.assertIn('dst=/guard-source,readonly',runner);self.assertNotIn('src={out}/test-signing',runner)
        self.assertIn("len(self)<8",runner)
        self.assertIn("['/usr/bin/cachy-asahi-welcome','--status','--json']",life)
        self.assertIn("['/usr/bin/cachy-asahi-doctor','--json','--output'",life)
        self.assertIn("root_guard(L,C)",life);self.assertIn("source_files={name:pins[name]",life)
        job=(HERE/'job.py').read_text();self.assertIn("C.validate_root_guard(guard,(runtime/'root-guard.tap').read_text())",job)


class Cleanup(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.base=self.root/'base';self.runtime=self.root/'runtime';self.base.mkdir();self.runtime.mkdir()
        self.token='1'*32;self.image='sha256:'+'2'*64;self.name='cachy-asahi-product-'+'3'*32;self.calls=[]
        self.proof=dict(consumer_token=self.token,job_token='4'*16)
        J.save(self.base/'report.json',dict(image=self.image,owned_cleanup=dict(status='PASS')))
        (self.runtime/'consumer.lock').touch()
        self.owner=dict(schema_version=1,token=self.token,image=self.image,label=C.LABEL,containers=[self.name])
        J.save(self.runtime/'owner.json',self.owner);self.present=True

    def daemon(self,argv):
        self.calls.append(argv)
        if argv[:4]==['/usr/bin/docker','container','inspect',self.name]:
            if not self.present:return SimpleNamespace(returncode=1,stdout=b'',stderr=('No such container: '+self.name).encode())
            value=dict(Id='5'*64,Image=self.image,Name='/'+self.name,Config=dict(Labels={C.LABEL:self.token}))
            return SimpleNamespace(returncode=0,stdout=json.dumps([value]).encode(),stderr=b'')
        if argv[:3]==['/usr/bin/docker','rm','-f']:self.present=False
        return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')

    def test_owned_consumer_removed_by_confirmed_id_and_absence_verified(self):
        result=J.retire_consumers(self.runtime,self.base,self.proof,self.daemon)
        self.assertTrue(result['containers'][0]['absence_verified']);self.assertFalse(self.present)
        self.assertIn(['/usr/bin/docker','rm','-f','5'*64],self.calls)

    def test_foreign_label_is_preserved_and_producer_not_called(self):
        def foreign(argv):
            row=self.daemon(argv)
            if row.returncode==0 and 'inspect' in argv:
                data=json.loads(row.stdout);data[0]['Config']['Labels'][C.LABEL]='6'*32;row.stdout=json.dumps(data).encode()
            return row
        with patch.object(J,'manifest_files'):
            result=J.cleanup(ROOT,{},self.proof,self.base,self.runtime,self.root/'cleanup.json',foreign)
        self.assertEqual(result['status'],'FAIL');self.assertTrue(self.present)
        self.assertFalse(any('maintained_desktop574.py' in str(argv) for argv in self.calls))

    def test_active_consumer_lease_blocks_cleanup(self):
        with (self.runtime/'consumer.lock').open('r+') as lease:
            fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):J.retire_consumers(self.runtime,self.base,self.proof,self.daemon)
        self.assertFalse(self.calls)

    def test_unknown_daemon_state_cannot_be_absence(self):
        with self.assertRaisesRegex(ValueError,'unknown consumer daemon state'):
            J.retire_consumers(self.runtime,self.base,self.proof,lambda argv:SimpleNamespace(returncode=1,stdout=b'',stderr=b'connection refused'))

    def test_consumer_absence_precedes_producer_cleanup(self):
        with patch.object(J,'manifest_files'):
            result=J.cleanup(ROOT,{},self.proof,self.base,self.runtime,self.root/'cleanup.json',self.daemon)
        self.assertEqual(result['status'],'PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP')
        self.assertIn('maintained_desktop574.py',str(self.calls[-1]));self.assertFalse(self.present)

    def test_no_consumer_is_distinct_from_unknown_owner(self):
        (self.runtime/'consumer.lock').unlink()
        with self.assertRaisesRegex(ValueError,'owner without lease'):J.retire_consumers(self.runtime,self.base,self.proof,self.daemon)
        (self.runtime/'owner.json').unlink()
        self.assertEqual(J.retire_consumers(self.runtime,self.base,self.proof,self.daemon)['status'],'PASS_NO_CONSUMER_ACTORS')

    def test_unknown_or_duplicate_owner_names_fail_before_any_daemon_call(self):
        for names in ([self.name,self.name],['foreign-container'],[self.name]*9):
            bad=copy.deepcopy(self.owner);bad['containers']=names;J.save(self.runtime/'owner.json',bad)
            with self.subTest(names=names),self.assertRaises(ValueError):J.retire_consumers(self.runtime,self.base,self.proof,self.daemon)
        self.assertFalse(self.calls)

    def test_foreign_image_is_never_removed(self):
        def foreign(argv):
            row=self.daemon(argv)
            if row.returncode==0 and 'inspect' in argv:
                data=json.loads(row.stdout);data[0]['Image']='sha256:'+'a'*64;row.stdout=json.dumps(data).encode()
            return row
        with self.assertRaisesRegex(ValueError,'foreign consumer preserved'):J.retire_consumers(self.runtime,self.base,self.proof,foreign)
        self.assertFalse(any('rm' in argv for argv in self.calls))


class SourceProof(unittest.TestCase):
    def test_source_workflow_identity_precedes_secret_route(self):
        proof=C.load('orphans_test_source_proof',ROOT/'scripts/ci/welcome-native/ci/caller.py')
        environment=dict(SOURCE_SHA='1'*40,GITHUB_SHA='1'*40,GITHUB_WORKFLOW_SHA='1'*40,
                         RUNNER_ARCH='ARM64',RUNNER_OS='Linux',GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1')
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp);path=source/'sentinel';path.write_text('known')
            manifest=dict(files={'sentinel':dict(bytes=5,sha256=C.digest(path))})
            value=proof.prove(source,manifest,environment);self.assertEqual(value['status'],'SOURCE_PROOF_PASS')
            for field,bad_value in (('SOURCE_SHA','branch'),('GITHUB_SHA','2'*40),('GITHUB_WORKFLOW_SHA','2'*40),('RUNNER_ARCH','X64')):
                bad=environment|{field:bad_value}
                with self.subTest(field=field),self.assertRaises(ValueError):proof.prove(source,manifest,bad)
            path.write_text('drift')
            with self.assertRaisesRegex(ValueError,'source pin differs'):proof.prove(source,manifest,environment)

    def test_retention_rejects_symlink_and_oversized_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'data').write_bytes(b'xx');(root/'alias').symlink_to('data')
            with self.assertRaises(ValueError):J.regular(root/'alias',3)
            with self.assertRaises(ValueError):J.regular(root/'data',1)


if __name__=='__main__':unittest.main()
