# SPDX-License-Identifier: MIT
"""Source controls. Synthetic receipts never grant installed/native acceptance."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import contract as C
import prepare
import baseline_lifecycle
import run as R

ROOT=Path(__file__).resolve().parents[3]


def baseline_receipt():
    tree=ast.parse((ROOT/'scripts/ci/setup7-native/test_native.py').read_text())
    tree.body=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in ('legacy_receipt','receipt')]
    scope=dict(C=C.baseline(ROOT),ROOT=ROOT,json=json,OLD='3e652bff75f6202cd3c13c327e50a298f7b25149b3c5cb55cdf4912d35af5919')
    exec(compile(tree,'held-setup7-receipt-fixture','exec'),scope)
    return scope['receipt']()


def receipt():
    pins=json.loads((C.HERE/'source-pins.json').read_text());manifest=json.loads((C.HERE/'source-manifest.json').read_text())
    row=dict(scope='EXPLICIT_INERT_PRIVATE_FIXTURES_ONLY',uid=1000,architecture='aarch64',actual_page_size=4096,
             profiles=['fresh','existing','conflict','interrupted'],manifest_sha256='1'*64,hardware='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED',private_fixtures_retired=False,fixture_work='/tmp/setup8-delivery-controls')
    for field,leaf in (('setup_sha256','cachy-asahi-setup'),('engine_sha256','config_migrate.py'),('launcher_sha256','cachy-asahi-config-migrate')):
        row[field]=pins[C.RECIPES[C.CANDIDATE]+'/'+leaf]
    delivery=dict(row,status='PASS_SETUP8_DELIVERED_CLI_PRIVATE_FIXTURES',actual_sigkill_returncode=-9,
                  cases={n:'PASS' for n in manifest['delivery_case_names']})
    reinstall=dict(row,status='PASS_SETUP8_DELIVERED_CLI_REINSTALL_FIXTURES',actual_sigkill_returncode=None,
                   cases={'post-package-reinstall-user-version-preserved':'PASS'})
    upgrade=dict(status='PASS',uid=1000,**{n:True for n in ('old7_owned_before_upgrade','preview_readonly','applied','repeat_readonly',
        'outside_user_bytes_preserved','ledger_preserved_on_package_reinstall','new_cli_removal_preserved_user_bytes')})
    phases=(('install-setup7-for-migration',575),('upgrade-setup8',575),('repeat-setup8',575),('remove-setup8',574),('reinstall-setup8',575),('final-remove-setup8',574))
    return dict(status='PASS_SETUP8_INSTALLED_MIGRATION_AND_HELD_SETUP7_BASELINE',baseline7=baseline_receipt(),
        events=[dict(phase=n,inventory_count=count,status='PASS',homes_preserved=True,database_check=True) for n,count in phases],
        system_config_preserved=True,user_state_preserved_on_alpm=True,full574_restored=True,native_architecture='aarch64',actual_page_size=4096,
        hardware='NOT_RUN',upgrade_home=upgrade,migration_delivery=delivery,migration_reinstall=reinstall,
        private_fixtures_retired=True,baseline_fixture_retirement='DISPOSABLE_CONTAINER_CLEANUP_REQUIRED',private_fixtures_scope='EXPLICIT_DISPOSABLE_USER_HOMES_AND_PINNED_INERT_MANIFEST')


class Controls(unittest.TestCase):
    def setUp(self):
        guard=patch.object(subprocess,'Popen',side_effect=AssertionError('No native/container actor in source controls'))
        guard.start();self.addCleanup(guard.stop)

    def test_exact_additive_source_closure_and_two_profiles(self):
        C.verify_source(ROOT)
        self.assertEqual(C.version(ROOT,C.BASELINE),'0.1.0-7');self.assertEqual(C.version(ROOT,C.CANDIDATE),'0.3.0-1')
        self.assertEqual(len(C.files(C.BASELINE)),6);self.assertEqual(len(C.files(C.CANDIDATE)),10)
        self.assertEqual(C.recipe(ROOT,C.BASELINE),C.baseline(ROOT).recipe(ROOT))

    def test_complete_recipe_staging_is_separate_by_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            for name in C.NAMES:
                target=Path(temp)/name;C.stage_recipe(ROOT,target,name)
                self.assertEqual({p.name:C.digest(p) for p in target.iterdir()},C.recipe(ROOT,name)['input_sha256'])

    def test_retained_staging_preserves_original_installed_status_comparison_path(self):
        with tempfile.TemporaryDirectory() as temp:
            context=Path(temp);original=context/'sources'/C.BASELINE;original.mkdir(parents=True)
            (original/'cachy-asahi-setup').write_bytes(b'held original setup bytes')
            products={C.BASELINE:{'version':'0.1.0-7'},C.CANDIDATE:{'version':'0.3.0-1'}}
            (context/'products.json').write_text(json.dumps(products))
            held=SimpleNamespace(stage_retained=lambda *_:None)
            with patch.object(C,'baseline',return_value=held),patch.object(C,'OLD_PAIR',context),patch.object(C,'OLD5_PAIR',context):
                C.stage_retained(context,None,None)
            target=context/'sources'/C.PACKAGE/'cachy-asahi-setup'
            self.assertEqual(target.read_bytes(),(original/'cachy-asahi-setup').read_bytes())
            self.assertNotEqual(target.stat().st_ino,(original/'cachy-asahi-setup').stat().st_ino)
            self.assertEqual(json.loads((context/'baseline7-products.json').read_text()),{C.PACKAGE:products[C.BASELINE]})
            driver=context/'setup8-delivery.py'
            self.assertEqual(C.digest(driver),C.digest(ROOT/C.recipe_path(C.CANDIDATE)/'test_delivery.py'))
            self.assertEqual(driver.stat().st_mode & 0o777,0o644)

    def test_exact_adapter_anchors_compile_six_consumers_and_actual_archive_identity(self):
        for kind in ('run','job'):compile(prepare.source(kind,ROOT),'adapted-'+kind,'exec')
        code=prepare.source('run',ROOT);job=prepare.source('job',ROOT)
        self.assertIn('len(self)<6',code);self.assertIn('len(names)<=6',job)
        self.assertIn('len(owner[\'containers\'])==6',job);self.assertIn('len(ordered[\'consumer\'][\'containers\'])==6',job)
        self.assertIn("name=C.PACKAGE+'-'+version+'-any.pkg.tar.'+suffix",job)
        self.assertIn("basename.startswith(C.PACKAGE+'-')",job)
        self.assertIn('baseline7-lifecycle.json',job);self.assertIn('source-context/',job)
        self.assertTrue(callable(C.load('setup8-build',ROOT/'scripts/ci/welcome-native/run.py').build))

    def test_changed_adapter_anchor_fails_closed(self):
        with patch.object(C,'pinned',return_value='different source'):
            for kind in ('run','job'):
                with self.assertRaisesRegex(ValueError,'anchor'):prepare.source(kind,ROOT)

    def test_exact_source_proof_precedes_actors_and_requires_workflow_revision(self):
        job=prepare.adapter('job',ROOT);manifest=json.loads((C.HERE/'source-manifest.json').read_text())
        env=dict(SOURCE_SHA='1'*40,GITHUB_SHA='1'*40,GITHUB_WORKFLOW_SHA='1'*40,RUNNER_OS='Linux',RUNNER_ARCH='ARM64',GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1')
        value=job['prove'](ROOT,manifest,env)
        self.assertEqual(value['setup8_adapter_sha256']['welcome_build'],hashlib.sha256(C.build_source(ROOT).encode()).hexdigest())
        env['GITHUB_WORKFLOW_SHA']='2'*40
        with self.assertRaisesRegex(ValueError,'source/workflow'):job['prove'](ROOT,manifest,env)

    def test_both_complete_archive_pair_comparisons_required(self):
        value=dict(status='contents-reproduced',errors=[],packages={'package':{n:True for n in ('installed_contents_equal','pkginfo_equal','bytes_equal','buildinfo_equal')}})
        R.pair_gate(value)
        for name in value['packages']['package']:
            bad=copy.deepcopy(value);bad['packages']['package'][name]=False
            with self.assertRaises(ValueError):R.pair_gate(bad)

    def test_exact_ten_payload_hashes_modes_ownership_and_no_hooks(self):
        rows={n:dict(type='0',mode=m,uid=0,gid=0,sha256=C.digest(ROOT/C.recipe_path(C.CANDIDATE)/leaf)) for n,(leaf,m) in C.files().items()}
        report=dict(errors=[],elf={},members=rows);C.payload(report,ROOT,C.CANDIDATE)
        for field,value in (('type','2'),('uid',1000),('mode',0o777),('sha256','0'*64)):
            bad=copy.deepcopy(report);bad['members']['usr/bin/cachy-asahi-config-migrate'][field]=value
            with self.assertRaises(ValueError):C.payload(bad,ROOT,C.CANDIDATE)
        bad=copy.deepcopy(report);bad['members']['usr/share/libalpm/hooks/auto.hook']=rows['usr/bin/cachy-asahi-config-migrate']
        with self.assertRaises(ValueError):C.payload(bad,ROOT,C.CANDIDATE)

    def test_package_check_log_requires_original29_and_delivery4(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'build.log';path.write_text('Starting check()\nRan 29 tests\nOK\nPASS: Setup8\n')
            with self.assertRaises(ValueError):C.check_log(path,C.CANDIDATE)
            path.write_text(path.read_text()+'Ran 4 tests\nOK\n')
            self.assertEqual(C.check_log(path,C.CANDIDATE)['migration_source_tests'],29)

    def test_held_setup7_lifecycle_only_four_fixed_path_projections(self):
        held=C.pinned(ROOT,'scripts/ci/setup7-native/lifecycle.py');projected=baseline_lifecycle.source(ROOT)
        self.assertEqual(len(ast.parse(held).body),len(ast.parse(projected).body))
        self.assertIn("Path('/inputs/baseline7-products.json')",projected)
        self.assertIn("Path('/baseline7/contract.py')",projected)
        self.assertIn("'/baseline7/recovery_preview.py'",projected)
        compile(projected,'held-setup7-lifecycle','exec')

    def test_complete_synthetic_gate_only(self):
        C.validate_lifecycle(receipt());C.validate_lifecycle(json.loads(json.dumps(receipt(),sort_keys=True)))

    def test_each_new_transition_and_all_migration_proof_fields_are_required(self):
        value=receipt()
        for mutation in ('event','baseline','uid','case','reinstall-case','sigkill','engine','manifest','page','outside','ledger','restored','retirement','driver-work'):
            bad=copy.deepcopy(value)
            if mutation=='event':bad['events'].pop()
            elif mutation=='baseline':bad['baseline7']['direct_setup5'].pop()
            elif mutation=='uid':bad['migration_delivery']['uid']=0
            elif mutation=='case':bad['migration_delivery']['cases'].pop(next(iter(bad['migration_delivery']['cases'])))
            elif mutation=='reinstall-case':bad['migration_reinstall']['cases']={}
            elif mutation=='sigkill':bad['migration_delivery']['actual_sigkill_returncode']=0
            elif mutation=='engine':bad['migration_delivery']['engine_sha256']='0'*64
            elif mutation=='manifest':bad['migration_reinstall']['manifest_sha256']='0'*64
            elif mutation=='page':bad['migration_delivery']['actual_page_size']=16384
            elif mutation=='outside':bad['upgrade_home']['outside_user_bytes_preserved']=False
            elif mutation=='ledger':bad['upgrade_home']['ledger_preserved_on_package_reinstall']=False
            elif mutation=='retirement':bad['private_fixtures_retired']=False
            elif mutation=='driver-work':bad['migration_reinstall']['fixture_work']='/tmp/other'
            else:bad['full574_restored']=False
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):C.validate_lifecycle(bad)

    def test_native_host_entry_refuses_ordinary_source_check(self):
        runner=prepare.adapter('run',ROOT)
        with patch.dict(runner['execute'].__globals__,platform=SimpleNamespace(system=lambda:'Linux',machine=lambda:'x86_64')):
            with self.assertRaisesRegex(ValueError,'ordinary native ARM'):runner['execute'](ROOT,ROOT,ROOT,'1'*32)

    def test_cleanup_refuses_foreign_or_unleased_owner_without_actors(self):
        job=prepare.adapter('job',ROOT)
        with tempfile.TemporaryDirectory() as temp:
            runtime=Path(temp);(runtime/'owner.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'owner without lease'):job['retire_consumers'](runtime,runtime,{'consumer_token':'1'*32})


if __name__=='__main__':unittest.main()
