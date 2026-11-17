# SPDX-License-Identifier: MIT
"""Producer MODEL and refusal controls; never native/GPG/Root acceptance."""
import copy
import importlib.util
import io
import json
import lzma
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('qt612_producer_controls',HERE/'producer.py')
P = importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
M = P.M;G = P.module('actor_gate');Q = P.module('finish_pair')
sys.addaudithook(M.fence)
CONTRACT = M.decode((HERE/'fixtures/F-serial-contract.DATA.json').read_bytes())
NOTICES = M.decode((HERE/'fixtures/F-notices.DATA.json').read_bytes())
POLICY = M.load(HERE/'resource-EXPERIMENTAL.json',P.EXPERIMENTAL,{})
DEPS = M.load(HERE/'dependency-candidates.lock.json',P.DEPENDENCIES,{})


class Controls(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='qt612-producer-MODEL-')
        self.addCleanup(tmp.cleanup);self.root = Path(tmp.name)

    def model(self):
        inventory = dict(line.split(' ',1) for line in (HERE.parents[2]/'scripts/ci/hyprland03-native-source-v1/fixtures/expected349.lock').read_text().splitlines())
        recipe = dict(provenance=dict(recipe_commit=P.F_COMMIT),active_files=CONTRACT['native_recipe_files'],source_ref13=[{}]*13)
        base = dict(kind='QT612_COMPLETE517_INPUT_DATA_ONLY',files=517,inventory=inventory,Root_acceptance=None)
        packages = {n:dict(name=n,version=r['version'],arch=r['arch'],filename=r['filename']) for n,r in DEPS['additional'].items()}
        packages['md4c'] = dict(name='md4c',version='0.5.3-1',arch='aarch64',filename='md4c-0.5.3-1-aarch64.pkg.tar.xz')
        deps = dict(kind='QT612_INCREMENTAL_SIGNED_INPUT_DATA_ONLY',packages=packages,complete=True,missing_roles=[],Root_acceptance=None,GPG='NOT_RUN')
        return recipe,base,deps

    def pair(self):
        reviewed = {n:r['sha256'] for n,r in CONTRACT['native_recipe_files'].items()}
        reviewed['qtbase-everywhere-src-6.12.0.tar.xz'] = CONTRACT['upstream']['archive']['sha256']
        expected = dict(image='sha256:'+'a'*64,inventory_sha256='b'*64,recipe_inputs=reviewed,nonce='c'*32,contract=CONTRACT,notice_policy=NOTICES)
        records = []
        for i in (1,2):
            records.append(dict(status='built-package-static-pass',exit_code=0,mode='native',image_id=expected['image'],image=expected['image'],
                expected_packages_sha256=expected['inventory_sha256'],recipe_inputs=reviewed,builder_host_arch='aarch64',
                clean_environment_id='cachy-qt612-reference-'+expected['nonce']+'-'+str(i),artifacts={P.PACKAGE:'d'*64},
                source_date_epoch=1792021458,recipe_metadata={},entry_script_sha256='e'*64))
        compare = dict(status='contents-reproduced',errors=[],packages={P.PACKAGE:dict.fromkeys(('installed_contents_equal','pkginfo_equal','buildinfo_equal','bytes_equal'),True)})
        return records,compare,expected

    def documents(self):
        common = dict(issued_by='Root',accepted=True,source='a'*40,ref='refs/heads/codex/MODEL',source_map_sha256='b'*64,
            policy_pin=P.EXPERIMENTAL,recipe_commit=P.F_COMMIT,nonce='c'*32,created_utc=100,expires_utc=15100,run='123',attempt='1',input_plan_sha256='d'*64)
        cap = dict(common,kind='ROOT_QT612_EXPERIMENTAL_CAPACITY_V1')
        runtime = dict(common,kind='ROOT_QT612_PRODUCER_RUNTIME_V1',readonly_filesystem_verified=True,owned_controller_kernel_verified=True,
            empty_owned_daemon_verified=True,signed_dependency_inventory_verified=True,provider_gpg_verified=True)
        context = dict(GITHUB_SHA=common['source'],GITHUB_REF=common['ref'],GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1',
            GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_EVENT_NAME='workflow_dispatch')
        return cap,runtime,context

    def test_complete_positive_model_admits_preparation_with_actor_disabled(self):
        recipe,base,deps = self.model();result = P.admit_complete_preparation(recipe,base,deps,POLICY)
        self.assertEqual(result['status'],'COMPLETE_QT612_PRODUCER_INPUTS_DATA_ONLY')
        self.assertEqual(len(result['inventory']),356);self.assertFalse(result['actor_enabled'])
        self.assertIsNone(result['Root_capacity']);self.assertIsNone(result['Root_acceptance'])

    def test_actual_available_md4c06_cannot_satisfy_f_recipe(self):
        recipe,base,deps = self.model();deps['packages']['md4c']['version'] = DEPS['rejected_md4c']['version']
        self.assertEqual(deps['packages']['md4c']['version'],'0.6.0-2')
        with self.assertRaisesRegex(ValueError,'NORMAL_QT612_DEPENDENCIES'):P.admit_complete_preparation(recipe,base,deps,POLICY)

    def test_md4c_constraint_boundaries(self):
        for version,allowed in [('0.5.2-1',False),('0.5.3-1',True),('0.5.10-2',True),('0.6.0-1',False),('1:0.5.3-1',False)]:
            with self.subTest(version=version):self.assertEqual(P.md4c_version(version),allowed)

    def test_missing_or_foreign_dependency_cannot_be_skipped(self):
        recipe,base,deps = self.model();del deps['packages']['md4c']
        with self.assertRaisesRegex(ValueError,'NORMAL_QT612_DEPENDENCIES'):P.admit_complete_preparation(recipe,base,deps,POLICY)

    def test_baseline_replacement_and_foreign_qt_provider_refuse(self):
        recipe,base,deps = self.model();base['inventory']['qt6-base'] = base['inventory'].pop(next(iter(base['inventory'])))
        with self.assertRaisesRegex(ValueError,'NO_FOREIGN_QT_BINARY'):P.admit_complete_preparation(recipe,base,deps,POLICY)

    def test_old_large_resource_proposal_cannot_become_experimental(self):
        recipe,base,deps = self.model();old = M.load(HERE/'resource-PROPOSAL.json',M.POLICY_PIN,{})
        with self.assertRaisesRegex(ValueError,'EXPERIMENTAL_POLICY'):P.admit_complete_preparation(recipe,base,deps,old)

    def test_experimental_profile_keeps_small_domains_and_serial_policy(self):
        self.assertEqual(POLICY['controller']['memory_bytes'],536870912);self.assertEqual(POLICY['owner']['AS_bytes'],2147483648)
        self.assertEqual(POLICY['daemon']['memory_bytes'],6442450944);self.assertEqual(POLICY['builder']['cpus'],1)
        self.assertEqual(POLICY['builder']['memory_bytes'],POLICY['builder']['memory_swap_bytes'])
        self.assertEqual(POLICY['storage_bytes'],12*1024**3);self.assertEqual(POLICY['cleanup_seconds'],90)
        self.assertEqual(POLICY['concurrent_builds'],1);self.assertFalse(POLICY['accepted'])

    def test_projected_build_inverse_and_normal_container_guards(self):
        raw = (HERE.parents[2]/'scripts/build/build_v2.py').read_bytes();projected = P.project_builder(raw)
        compile(projected,'MODEL-projected-build','exec')
        for token in (b"'--read-only'",b"'--memory', '4g', '--memory-swap', '4g', '--cpus', '1'",b'require_actual_capacity()',b'qt612-stage-contract.json'):
            self.assertIn(token,projected)
        self.assertIn(b'if completed.returncode:',projected)
        with self.assertRaisesRegex(ValueError,'PROJECTION_SEAM'):P.project_builder(raw.replace(b"'--cpus', '4'",b"'--cpus', '9'"))

    def test_entry_preserves_normal_deps_checks_and_smoke_evidence(self):
        raw = (HERE.parents[2]/'scripts/build/container-entry-v2.sh').read_bytes()
        result = P.project_entry(raw,CONTRACT['dependencies']['runtime']+CONTRACT['dependencies']['build'])
        for token in (b'pacman -T',b'makepkg --verifysource --noconfirm',b'makepkg --cleanbuild --force --log --noconfirm',
                      b'CMAKE_BUILD_PARALLEL_LEVEL=1 MAKEFLAGS=-j1',b'qt612-stage-contract.json'):
            self.assertIn(token,result)
        self.assertNotIn(b'--nodeps',result);self.assertNotIn(b'--nocheck',result)

    def test_dependency_image_uses_required_trusted_only_without_host_sync(self):
        _,base,deps = self.model();plan = P.dependency_image_plan('sha256:'+'a'*64,base,deps,builder_uid=1000,builder_gid=1000)
        self.assertIn('LocalFileSigLevel = Required TrustedOnly',plan['pacman_config'])
        self.assertIn('-U --noconfirm --noscriptlet',plan['dockerfile']);self.assertNotIn(' -S',plan['dockerfile'])
        self.assertNotIn('--nodeps',plan['dockerfile']);self.assertFalse(plan['actor_enabled'])

    def test_pair_commands_are_distinct_serial_and_strict(self):
        plan = P.pair_commands(self.root/'source',self.root/'output','sha256:'+'a'*64,dict(bytes=1,sha256='b'*64),nonce='c'*32)
        self.assertEqual([x['attempt'] for x in plan['builds']],['1','2']);self.assertTrue(plan['serial'])
        self.assertTrue(plan['require_first_natural_absence_before_second']);self.assertIn('--require-bytes',plan['compare'])
        self.assertEqual(plan['builds'][0]['argv'][-1],str(self.root/'output/build-1'));self.assertFalse(plan['actor_enabled'])

    def test_frozen_real_contract_model_pair_receipts_match(self):
        records,comparison,expected = self.pair()
        self.assertEqual(Q.validate_pair_records(*records,comparison,expected=expected),P.PACKAGE)

    def test_native_receipts_do_not_accept_failed_or_same_clean_identity(self):
        original,comparison,expected = self.pair()
        for kind in ('failed','identity','image','inventory'):
            records = copy.deepcopy(original)
            if kind == 'failed':records[0]['exit_code'] = 1
            elif kind == 'identity':records[1]['clean_environment_id'] = records[0]['clean_environment_id']
            elif kind == 'image':records[1]['image_id'] = 'sha256:'+'d'*64
            else:records[0]['expected_packages_sha256'] = 'd'*64
            with self.subTest(kind=kind),self.assertRaises(ValueError):Q.validate_pair_records(*records,comparison,expected=expected)

    def test_strict_archive_equality_and_archive_input_pin_cannot_be_dropped(self):
        records,comparison,expected = self.pair();comparison['packages'][P.PACKAGE]['bytes_equal'] = False
        with self.assertRaises(ValueError):Q.validate_pair_records(*records,comparison,expected=expected)
        records,comparison,expected = self.pair();del expected['recipe_inputs']['qtbase-everywhere-src-6.12.0.tar.xz']
        with self.assertRaisesRegex(ValueError,'BUILDVIEW15'):Q.validate_pair_records(*records,comparison,expected=expected)

    def test_unissued_capacity_and_runtime_refuse(self):
        cap,runtime,context = self.documents();cap['accepted'] = False
        with self.assertRaisesRegex(ValueError,'CAPACITY_UNISSUED'):G.validate_documents(cap,runtime,source_map='b'*64,policy_pin=P.EXPERIMENTAL,context=context,now=200)

    def test_model_root_document_join_is_not_actor_execution(self):
        cap,runtime,context = self.documents();result = G.validate_documents(cap,runtime,source_map='b'*64,policy_pin=P.EXPERIMENTAL,context=context,now=200)
        self.assertEqual(result['nonce'],'c'*32);self.assertIn('NOT_AUTHENTICATED',result['actor_truth'])

    def test_expired_capacity_wrong_attempt_and_filesystem_truth_refuse(self):
        original,runtime,context = self.documents()
        for kind in ('expiry','attempt','readonly'):
            cap = copy.deepcopy(original);run = copy.deepcopy(runtime);ctx = dict(context)
            if kind == 'expiry':cap['expires_utc'] = run['expires_utc'] = 150
            elif kind == 'attempt':ctx['GITHUB_RUN_ATTEMPT'] = '2'
            else:run['readonly_filesystem_verified'] = False
            with self.subTest(kind=kind),self.assertRaises(ValueError):G.validate_documents(cap,run,source_map='b'*64,policy_pin=P.EXPERIMENTAL,context=ctx,now=200)

    def test_xz_decoder_rejects_trailing_or_extra_streams(self):
        data = lzma.compress(b'MODEL')
        self.assertEqual(Q.XZReader(io.BytesIO(data)).read(5),b'MODEL')
        for tail in (b'foreign',lzma.compress(b'extra')):
            with self.assertRaisesRegex(ValueError,'TRAILING_BYTES'):Q.XZReader(io.BytesIO(data+tail)).read(8)

    def test_archive_paths_and_kernel_actor_calls_refuse(self):
        for name in ('/etc/passwd','../foreign','a/../../foreign'):
            with self.assertRaises(ValueError):Q.safe_name(name)
        for event in ('subprocess.Popen','os.pidfd_open','resource.setrlimit','socket.connect'):
            with self.assertRaisesRegex(ValueError,'NO_ACTORS'):M.fence(event,())

    def model_executor(self,fail=False,retention_fails=False):
        class Executor:
            API = 'ROOT_QT612_OWNED_EXECUTOR_V1'
            def __init__(self):self.events = [];self.runs = 0
            def require_domain_and_readonly_filesystem(self):self.events.append('domain-ro')
            def require_no_containers(self):self.events.append('empty')
            def require_absent_twice(self,name):self.events.append('absent:'+name[-1])
            def run(self,argv,timeout,env):
                self.runs += 1;self.events.append('run:'+str(self.runs))
                return dict(exit=2 if fail and self.runs == 1 else 0,reaped=True,natural=True,output_complete=True)
            def retain_public_failure_evidence(self,**record):
                self.events.append('retain-HOLD');self.failure_record = record
                if retention_fails:raise OSError('MODEL_RETENTION_UNAVAILABLE')
                return dict(complete=True,status='MODEL_PUBLIC_FAILURE_BYTES_RETAINED',Root_acceptance=None)
        return Executor()

    def test_positive_model_serial_pair_observes_scratch_absence_before_second(self):
        executor = self.model_executor();plan = P.pair_commands(self.root/'source',self.root/'output','sha256:'+'a'*64,dict(bytes=1,sha256='b'*64),nonce='c'*32)
        result = P.serial_pair(plan,executor,nonce='c'*32,finish=lambda r,c:dict(status='MODEL_ONLY',Root_acceptance=None))
        self.assertEqual(result['status'],'MODEL_ONLY')
        self.assertLess(executor.events.index('absent:1'),executor.events.index('run:2'))
        self.assertLess(executor.events.index('absent:2'),executor.events.index('run:3'))
        self.assertNotIn('retain-HOLD',executor.events)

    def test_failure_evidence_is_attempted_before_caller_cleanup_and_stays_hold(self):
        executor = self.model_executor(fail=True);plan = P.pair_commands(self.root/'source',self.root/'output','sha256:'+'a'*64,dict(bytes=1,sha256='b'*64),nonce='c'*32)
        with self.assertRaises(P.ProducerHold) as held:P.serial_pair(plan,executor,nonce='c'*32,finish=lambda *_:None)
        executor.events.append('caller-cleanup')
        self.assertEqual(held.exception.phase,'BUILD_1');self.assertTrue(held.exception.retention['complete'])
        self.assertLess(executor.events.index('retain-HOLD'),executor.events.index('caller-cleanup'))
        self.assertEqual(executor.runs,1);self.assertNotIn('message',held.exception.primary)

    def test_retention_failure_preserves_original_failure_without_success(self):
        executor = self.model_executor(fail=True,retention_fails=True);plan = P.pair_commands(self.root/'source',self.root/'output','sha256:'+'a'*64,dict(bytes=1,sha256='b'*64),nonce='c'*32)
        with self.assertRaises(P.ProducerHold) as held:P.serial_pair(plan,executor,nonce='c'*32,finish=lambda *_:None)
        self.assertEqual(held.exception.primary['exception'],'ValueError');self.assertFalse(held.exception.retention['complete'])
        self.assertEqual(held.exception.retention['retention_error']['exception'],'OSError')

    def test_new_serial_f_metadata_frozen_without_rewriting_legacy(self):
        self.assertEqual(M.pin(M.encoded(CONTRACT)),Q.SERIAL_CONTRACT_PIN)
        self.assertEqual(CONTRACT['package']['version'],'6.12.0-2')
        self.assertEqual(len(CONTRACT['configuration']['settings']),91)
        self.assertEqual(CONTRACT['parallelism']['CMAKE_AUTOGEN_PARALLEL'],1)
        legacy = M.decode((HERE/'fixtures/F-contract.DATA.json').read_bytes())
        self.assertEqual(M.pin(M.encoded(legacy)),Q.CONTRACT_PIN)

    def test_qualification_hold_retains_receipts_before_cleanup(self):
        executor = self.model_executor();plan = P.pair_commands(self.root/'source',self.root/'output','sha256:'+'a'*64,dict(bytes=1,sha256='b'*64),nonce='c'*32)
        def refuse(*_):raise ValueError('MODEL_QUALIFICATION_HOLD')
        with self.assertRaises(P.ProducerHold) as held:P.serial_pair(plan,executor,nonce='c'*32,finish=refuse)
        self.assertEqual(held.exception.phase,'QUALIFY');self.assertEqual(executor.runs,3)
        self.assertEqual(executor.events[-1],'retain-HOLD');self.assertTrue(held.exception.retention['complete'])

    def test_missing_public_failure_retention_prevents_first_build(self):
        executor = self.model_executor();executor.retain_public_failure_evidence = None
        plan = P.pair_commands(self.root/'source',self.root/'output','sha256:'+'a'*64,dict(bytes=1,sha256='b'*64),nonce='c'*32)
        with self.assertRaisesRegex(ValueError,'PUBLIC_FAILURE_RETENTION_REQUIRED'):P.serial_pair(plan,executor,nonce='c'*32,finish=lambda *_:None)
        self.assertEqual(executor.runs,0)


if __name__ == '__main__':unittest.main()
