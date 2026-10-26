# SPDX-License-Identifier: MIT
"""Inert controls only; prohibit actors, never label synthetic proofs native actuals."""
import ast
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import contract as C
import exercise
import prepare
import retained
import run as R

ROOT=Path(os.environ.get('SETUP5_NATIVE_SOURCE',Path(__file__).resolve().parents[3]))
OLD='3e652bff75f6202cd3c13c327e50a298f7b25149b3c5cb55cdf4912d35af5919'


def receipt():
    helper=C.digest(ROOT/C.RECIPE/'cachy-asahi-setup');profiles=(*C.LEGACY,'new-grouped-journal');observations=[];proofs=[]
    per_phase={'legacy':('legacy-state-journal',),'upgrade':tuple(c for c in C.CASES if c not in ('rollback-refusal','new-interruption-recovery')),'rollback':('rollback-refusal',),'forward':('new-interruption-recovery',)}
    for profile in profiles:
        cases={}
        for phase,names in per_phase.items():
            wanted=OLD if phase in ('legacy','rollback') else helper;value=dict(status='PASS',phase=phase,profile=profile,cases={n:'PASS' for n in names},uid=1000,installed_helper_sha256=wanted,fixture_scope='INERT_NAMESPACED_MODULE_FIXTURES_ONLY')
            observations.append(dict(phase=phase,profile=profile,sha256=wanted,proof=value));cases.update(value['cases'])
        proofs.append(dict(profile=profile,cases=cases,uid=1000,installed_helper_sha256=helper))
    return dict(status='PASS_SETUP5_INSTALLED_LEGACY_LIFECYCLE',base_count=574,native_architecture='aarch64',actual_page_size=4096,fixture_scope='INERT_NAMESPACED_MODULE_FIXTURES_ONLY',real_module_acceptance='NOT_RUN',system_config_preserved=True,user_state_preserved_on_alpm=True,full574_restored=True,events=[dict(phase=p,inventory_count=n,status='PASS',homes_preserved=True,database_check=True) for p,n in C.PHASES],proofs=proofs,actual_observations=observations)


class ActorGuard(unittest.TestCase):
    def setUp(self):
        self.actor=patch.object(subprocess,'Popen',side_effect=AssertionError('No actual subprocess/container/native actor in inert controls'));self.actor.start();self.addCleanup(self.actor.stop)

class Inert(ActorGuard):
    def test_all_frozen_source_pins_and_setup5_mirror(self):
        C.verify_source(ROOT);self.assertEqual(len(C.recipe(ROOT)['input_sha256']),12);self.assertEqual(len(C.files()),6)

    def test_old_version_and_changed_recipe_checksums_refuse(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);target=root/C.RECIPE;target.parent.mkdir(parents=True);shutil.copytree(ROOT/C.RECIPE,target)
            (root/'scripts/checks').mkdir(parents=True);shutil.copyfile(ROOT/'scripts/checks/package_checks.py',root/'scripts/checks/package_checks.py')
            p=target/'.SRCINFO';p.write_text(p.read_text().replace('pkgrel = 5','pkgrel = 4'))
            with self.assertRaises(ValueError):C.recipe(root)

    def test_exact_adapters_compile_and_bound_four_consumers(self):
        for name in ('run','job'):compile(prepare.source(name,ROOT),'adapted-'+name,'exec')
        self.assertIn('len(self)<4',prepare.source('run',ROOT));self.assertIn('len(names)<=4',prepare.source('job',ROOT))
        self.assertIn('C.stage_retained(context,checks,bind)',prepare.source('run',ROOT));self.assertIn('C.stage_recipe',prepare.source('run',ROOT))
        shared=C.load('pure_accepted_setup5_build',ROOT/'scripts/ci/welcome-native/run.py');self.assertIn('C.stage_recipe',ast.unparse(ast.parse(C.pinned(ROOT,'scripts/ci/welcome-native/run.py').replace("shutil.copytree(source/'packages/tools'/name,inputs)",'C.stage_recipe(source,inputs)'))))
        self.assertTrue(callable(shared.build))

    def test_missing_or_changed_adapter_anchor_is_fatal(self):
        with patch.object(C,'pinned',return_value='changed helper'):
            with self.assertRaisesRegex(ValueError,'adapter anchor'):prepare.source('run',ROOT)

    def test_source_proof_binds_exact_source_workflow_and_adapter_hashes(self):
        J=prepare.adapter('job',ROOT);manifest=json.loads((ROOT/'scripts/ci/setup5-native/source-manifest.json').read_text());env=dict(SOURCE_SHA='1'*40,GITHUB_SHA='1'*40,GITHUB_WORKFLOW_SHA='1'*40,RUNNER_OS='Linux',RUNNER_ARCH='ARM64',GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1')
        value=J['prove'](ROOT,manifest,env);self.assertEqual(value['setup5_adapter_sha256'],dict({n:hashlib.sha256(prepare.source(n,ROOT).encode()).hexdigest() for n in ('run','job')},welcome_build=hashlib.sha256(C.build_source(ROOT).encode()).hexdigest()))
        env['GITHUB_WORKFLOW_SHA']='2'*40
        with self.assertRaisesRegex(ValueError,'source/workflow'):J['prove'](ROOT,manifest,env)

    def test_pair_requires_complete_archives_and_buildinfo(self):
        good=dict(status='contents-reproduced',errors=[],packages={'pkg':dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)});R.pair_gate(good)
        for field in good['packages']['pkg']:
            bad=copy.deepcopy(good);bad['packages']['pkg'][field]=False
            with self.subTest(field=field),self.assertRaises(ValueError):R.pair_gate(bad)

    def test_exact_six_payload_source_license_modes_ownership_no_elf(self):
        rows={n:dict(type='0',mode=m,uid=0,gid=0,sha256=C.digest(ROOT/C.RECIPE/o)) for n,(o,m) in C.files().items()};report=dict(errors=[],elf={},members=rows);C.payload(report,ROOT)
        for mutation in ('hash','mode','uid','link','missing','extra','elf'):
            bad=copy.deepcopy(report);key='usr/share/licenses/'+C.PACKAGE+'/LICENSE'
            if mutation=='hash':bad['members'][key]['sha256']='0'*64
            elif mutation=='mode':bad['members'][key]['mode']=0o755
            elif mutation=='uid':bad['members'][key]['uid']=1000
            elif mutation=='link':bad['members'][key]['type']='2'
            elif mutation=='missing':bad['members'].pop(key)
            elif mutation=='extra':bad['members']['etc/automatic']=rows[key]
            else:bad['elf']={'unexpected':{}}
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):C.payload(bad,ROOT)

    def test_actual_recipe_check_log_cannot_be_replaced_by_status_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'log';p.write_text('PASS')
            with self.assertRaises(ValueError):C.check_log(p)
            p.write_text('Starting check()\nRan 10 tests\nOK\n'+'PASS: canonical and packaged helper/license bytes match pinned provenance\n'*3);C.check_log(p)

    def test_complete_synthetic_receipt_gate_and_sorted_parent_equality(self):
        value=receipt();C.validate_lifecycle(value);C.validate_lifecycle(json.loads(json.dumps(value,sort_keys=True)))

    def test_every_package_transition_named_profile_and_case_required(self):
        value=receipt()
        for mutation in ('event','inventory','db','preservation','profile','case','ordinary','helper','real-modules','full574','observation','observed-join','old-helper'):
            bad=copy.deepcopy(value)
            if mutation=='event':bad['events'].pop()
            elif mutation=='inventory':bad['events'][0]['inventory_count']=574
            elif mutation=='db':bad['events'][0]['database_check']=False
            elif mutation=='preservation':bad['events'][3]['homes_preserved']=False
            elif mutation=='profile':bad['proofs'].pop()
            elif mutation=='case':bad['proofs'][0]['cases'].pop('rollback-refusal')
            elif mutation=='ordinary':bad['proofs'][0]['uid']=0
            elif mutation=='helper':bad['proofs'][0]['installed_helper_sha256']='0'*64
            elif mutation=='real-modules':bad['real_module_acceptance']='PASS'
            elif mutation=='full574':bad['full574_restored']=False
            elif mutation=='observation':bad['actual_observations'].pop()
            elif mutation=='observed-join':bad['actual_observations'][0]['proof']['cases']={}
            else:bad['actual_observations'][0]['proof']['installed_helper_sha256']='f'*64
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):C.validate_lifecycle(bad)

    def test_native_entry_and_installed_cli_guards_precede_system_mutation(self):
        text=(ROOT/'scripts/ci/setup5-native/lifecycle.py').read_text();self.assertLess(text.index('os.getpid()==1'),text.index("hooks=Path('/tmp"));self.assertNotIn('-Rdd',text);self.assertNotIn('--nodeps',text);self.assertNotIn('--overwrite',text)
        text=(ROOT/'scripts/ci/setup5-native/exercise.py').read_text();self.assertIn('ordinary native container user required',text);self.assertIn("CLI='/usr/bin/cachy-asahi-setup'",text);compile(exercise.CRASH,'actual-installed-interruption','exec')

    def test_user_lifecycle_never_executes_shell_or_module_fixture(self):
        text=(ROOT/'scripts/ci/setup5-native/exercise.py').read_text();tree=ast.parse(text)
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='subprocess' and n.func.attr=='run']
        self.assertEqual(len(calls),2)
        self.assertTrue(all(isinstance(n.args[0],ast.Name) and n.args[0].id=='argv' or isinstance(n.args[0],ast.List) and isinstance(n.args[0].elts[0],ast.Constant) and n.args[0].elts[0].value=='/usr/bin/python3' for n in calls))
        self.assertIn('argv = [CLI',ast.unparse(tree));self.assertIn("snapshot(home)==before",text);self.assertIn("expected=1,target=nested",text)

    def test_workflow_manual_unique_group_exact_existing_seed_and_retained_refs(self):
        text=(ROOT/'.github/workflows/native-arm-setup5-candidate.yml').read_text()
        self.assertIn('group: native-arm-setup5-candidate\n  cancel-in-progress: false',text);self.assertIn('04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd',text);self.assertIn(retained.SOURCE,text);self.assertIn('include-hidden-files: true',text)
        self.assertNotIn('push:',text);self.assertNotIn('pull_request:',text);self.assertIn('--setup4-pair',text)

    def test_closed_export_enumerates_hidden_inputs_and_public_observations_only(self):
        text=prepare.source('job',ROOT);self.assertIn("for basename in sorted(C.recipe",text);self.assertIn("source-manifest.json')['files']",text);self.assertIn('standalone user observation differs',text);self.assertNotIn("source/'packages/tools'",text)
        self.assertIn('MAX_TOTAL=96*1024**2',text);self.assertIn("'retained-setup4/'+name",text)

    def test_staging_uses_exact_pinned_recipe_without_historical_or_hidden_extras(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'snapshot';C.stage_recipe(ROOT,target);self.assertEqual({p.name for p in target.iterdir()},set(C.INPUTS));self.assertEqual(len(list(target.iterdir())),12)

    def test_partial_export_remains_failed_keeps_srcinfo_excludes_unknown_hidden(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'source';source.mkdir()
            manifest=json.loads((ROOT/'scripts/ci/setup5-native/source-manifest.json').read_text())
            for name in (*manifest['files'],'scripts/ci/setup5-native/source-manifest.json'):
                target=source/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
            (source/'scripts/ci/setup5-native/.unexpected').write_text('private unlisted input')
            base=root/'base';runtime=root/'runtime';base.mkdir();runtime.mkdir()
            for name in ('proof.json','cleanup.json'):(root/name).write_text('{}')
            J=prepare.adapter('job',ROOT);result=J['retain'](source,base,runtime,root/'proof.json',root/'cleanup.json',root/'public')
            self.assertEqual(result['status'],'FAIL_OR_INCOMPLETE');self.assertTrue(result['errors'])
            self.assertIn('source/'+C.PACKAGE+'/.SRCINFO',result['files']);self.assertNotIn('harness/.unexpected',result['files'])

    def test_exact_lifecycle_staging_branch_reproduces_old_missing_parent_and_now_succeeds(self):
        # Execute only the real adapted loop that failed before native lifecycle.
        tree=ast.parse(prepare.source('run',ROOT))
        loops=[n for n in ast.walk(tree) if isinstance(n,ast.For) and any(
            isinstance(call,ast.Call) and isinstance(call.func,ast.Attribute) and
            isinstance(call.func.value,ast.Name) and call.func.value.id=='C' and call.func.attr=='stage_recipe'
            for call in ast.walk(n))]
        self.assertEqual(len(loops),1)
        branch=compile(ast.fix_missing_locations(ast.Module(body=[loops[0]],type_ignores=[])),'exact-adapter-context-branch','exec')
        function=next(n for n in ast.parse((ROOT/'scripts/ci/setup5-native/contract.py').read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='stage_recipe')
        old=copy.deepcopy(function);mkdir=old.body[0].value
        self.assertEqual(mkdir.func.attr,'mkdir');self.assertEqual([k.arg for k in mkdir.keywords],['parents'])
        mkdir.keywords=[]  # The sole historical difference, matching actual38930145094.
        namespace=dict(recipe=C.recipe,RECIPE=C.RECIPE,shutil=shutil)
        exec(compile(ast.fix_missing_locations(ast.Module(body=[old],type_ignores=[])),'actual-old-staging-function','exec'),namespace)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            def fixture(name):
                out=root/name;out.mkdir();context=out/'lifecycle-inputs';context.mkdir()
                archive='cachy-asahi-setup-0.1.0-5-any.pkg.tar.xz'
                source=out/(C.PACKAGE+'-a')/'artifacts';source.mkdir(parents=True)
                (source/archive).write_bytes(b'bounded archive-copy fixture; never installed')
                return dict(C=C,shutil=shutil,source=ROOT,out=out,context=context,
                            products={C.PACKAGE:dict(archive=archive)}),source/archive
            failed,archive=fixture('old')
            with patch.object(C,'stage_recipe',namespace['stage_recipe']):
                with self.assertRaises(FileNotFoundError) as error:exec(branch,failed)
            self.assertEqual(error.exception.filename,str(failed['context']/'sources'/C.PACKAGE))
            fixed,archive=fixture('fixed');self.assertFalse((fixed['context']/'sources').exists())
            exec(branch,fixed)
            target=fixed['context']/'sources'/C.PACKAGE
            self.assertEqual((fixed['context']/archive.name).read_bytes(),archive.read_bytes())
            self.assertEqual({p.name:C.digest(p) for p in target.iterdir()},C.recipe(ROOT)['input_sha256'])
            self.assertIn('.SRCINFO',{p.name for p in target.iterdir()})

    def test_database_queries_omit_transaction_only_option(self):
        tree=ast.parse((ROOT/'scripts/ci/setup5-native/lifecycle.py').read_text())
        main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        base=next(n for n in main.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='pacman' for t in n.targets))
        installed=next(n for n in main.body if isinstance(n,ast.FunctionDef) and n.name=='installed')
        captured=[]
        def command(argv):captured.append(argv);return ''
        def need(ok,reason):self.assertTrue(ok,reason)
        scope=dict(config=Path('/inert/config'),original={},rows={'fixture':dict(payload={})},
                   C=SimpleNamespace(PACKAGE='candidate',files=lambda:{}),
                   L=SimpleNamespace(inventory=lambda:{'candidate':'fixture'},command=command,need=need))
        exec(compile(ast.Module(body=[base,installed],type_ignores=[]),'<exact-queries>','exec'),scope)
        scope['installed']('fixture')
        self.assertEqual(len(captured),4)
        self.assertTrue(all('--noscriptlet' not in argv for argv in captured))
        transition=next(n for n in main.body if isinstance(n,ast.FunctionDef) and n.name=='transition')
        statement=next(n for n in transition.body if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and n.value.func.attr=='command')
        self.assertIsInstance(statement,ast.Expr)
        for version in ('fixture',None):
            scope.update(version=version,archives={'fixture':Path('/inert/archive')})
            exec(compile(ast.Module(body=[statement],type_ignores=[]),'<exact-transaction>','exec'),scope)
            self.assertEqual(captured[-1].count('--noscriptlet'),1)
            self.assertIn('-U' if version else '-R',captured[-1])

    def test_recipe_staging_still_refuses_existing_destination_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'nested'/'package';target.mkdir(parents=True);(target/'sentinel').write_bytes(b'preserve')
            before={p.name:p.read_bytes() for p in target.iterdir()}
            with self.assertRaises(FileExistsError):C.stage_recipe(ROOT,target)
            self.assertEqual({p.name:p.read_bytes() for p in target.iterdir()},before)

    def test_retained_bundle_size_hash_failure_creates_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'bad';source.write_bytes(b'bad')
            with self.assertRaises(ValueError):retained.unpack(source,root/'out')
            self.assertFalse((root/'out').exists())


class Cleanup(ActorGuard):
    def setUp(self):
        super().setUp();self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.base=self.root/'base';self.runtime=self.root/'runtime';self.base.mkdir();self.runtime.mkdir();self.token='1'*32;self.image='sha256:'+'2'*64;self.name='cachy-asahi-product-'+'3'*32;self.calls=[];self.present=True;self.proof=dict(consumer_token=self.token,job_token='4'*16);self.J=prepare.adapter('job',ROOT)
        self.J['save'](self.base/'report.json',dict(image=self.image,owned_cleanup=dict(status='PASS')));(self.runtime/'consumer.lock').touch();self.owner=dict(schema_version=1,token=self.token,image=self.image,label=C.LABEL,containers=[self.name]);self.J['save'](self.runtime/'owner.json',self.owner)

    def daemon(self,argv):
        self.calls.append(argv)
        if argv[:4]==['/usr/bin/docker','container','inspect',self.name]:
            if not self.present:return SimpleNamespace(returncode=1,stdout=b'',stderr=('No such container: '+self.name).encode())
            return SimpleNamespace(returncode=0,stdout=json.dumps([dict(Id='5'*64,Image=self.image,Name='/'+self.name,Config=dict(Labels={C.LABEL:self.token}))]).encode(),stderr=b'')
        if argv[:3]==['/usr/bin/docker','rm','-f']:self.present=False
        return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')

    def test_confirmed_consumer_id_absence_precedes_producer_retirement(self):
        with patch.dict(self.J,manifest_files=lambda *args:None):value=self.J['cleanup'](ROOT,{},self.proof,self.base,self.runtime,self.root/'cleanup.json',self.daemon)
        self.assertEqual(value['status'],'PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP');self.assertIn(['/usr/bin/docker','rm','-f','5'*64],self.calls);self.assertIn('maintained_desktop574.py',str(self.calls[-1]))

    def test_foreign_consumer_blocks_all_removal_including_producer(self):
        def foreign(argv):
            value=self.daemon(argv)
            if not value.returncode and 'inspect' in argv:
                rows=json.loads(value.stdout);rows[0]['Config']['Labels'][C.LABEL]='6'*32;value.stdout=json.dumps(rows).encode()
            return value
        with patch.dict(self.J,manifest_files=lambda *args:None):value=self.J['cleanup'](ROOT,{},self.proof,self.base,self.runtime,self.root/'cleanup.json',foreign)
        self.assertEqual(value['status'],'FAIL');self.assertFalse(any('rm' in a or 'maintained_desktop574.py' in str(a) for a in self.calls))

    def test_active_consumer_lease_and_unknown_daemon_refuse(self):
        with (self.runtime/'consumer.lock').open('r+') as lease:
            fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.J['retire_consumers'](self.runtime,self.base,self.proof,self.daemon)
        self.assertFalse(self.calls)
        with self.assertRaises(ValueError):self.J['retire_consumers'](self.runtime,self.base,self.proof,lambda argv:SimpleNamespace(returncode=1,stdout=b'',stderr=b'connection refused'))


if __name__=='__main__':unittest.main()
