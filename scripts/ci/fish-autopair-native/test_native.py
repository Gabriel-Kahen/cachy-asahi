"""Source and inert receipt/daemon controls. No Fish, package or container runs."""
import copy
import contextlib
import io
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import contract as C
import prepare
import run as R

ROOT=Path(os.environ.get('FISH_AUTOPAIR_NATIVE_SOURCE',Path(__file__).resolve().parents[3]))


def proof():
    return dict(status='PASS',platform='aarch64',fish='fish, version 4.9.3',
        wrapper_sha256=C.digest(ROOT/'packages/tools'/C.PACKAGE/'opt-in.fish'),cases={
            name:dict(exit=0,**({} if name=='noninteractive' else dict(
                activation='enabled' if name in ('default','vi','hybrid') else 'yielded',
                snapshots=[dict(case=label,buffer='',cursor=0) for label in C.EDIT_CASES] if name in ('default','vi','hybrid') else [])))
            for name in C.CASES})


def receipt():
    value=proof();sha=hashlib.sha256((json.dumps(value,indent=2)+'\n').encode()).hexdigest()
    observations=[dict(home='fish-home-'+kind,proof=copy.deepcopy(value),receipt_sha256=sha,fish_sha256='1'*64) for kind in ('fresh','existing')]
    return dict(status='PASS_FISH_AUTOPAIR_INSTALLED_LIFECYCLE',base_count=574,installed_count=575,
        user_config_preserved=True,system_config_preserved=True,user_outputs_preserved=True,hardware='NOT_RUN',
        native_architecture='aarch64',actual_page_size=4096,wrapper_sha256=value['wrapper_sha256'],
        events=[dict(phase=phase,status='PASS',inventory_count=count,config_preserved=True,
            **(dict(observations=copy.deepcopy(observations)) if count==575 else dict(guarded_opt_in_absent=True))) for phase,count in
            (('install',575),('same-version-reinstall',575),('remove',574),('reinstall-after-removal',575),('final-remove',574))])


class RetainedReceiptOrder(unittest.TestCase):
    def test_sorted_report_joins_original_receipt_without_changing_its_digest(self):
        actual=receipt()
        report=json.loads(json.dumps(dict(lifecycle=actual),sort_keys=True))
        with self.assertRaisesRegex(ValueError,'receipt bytes/digest join differs'):
            C.validate_lifecycle(report['lifecycle'])
        C.validate_retained_lifecycle(report,actual)
        self.assertIn("C.validate_retained_lifecycle(report,read(runtime/'lifecycle.json',4*1024**2))",prepare.source('job',ROOT))

    def test_changed_proof_or_original_receipt_digest_is_refused(self):
        actual=receipt();report=json.loads(json.dumps(dict(lifecycle=actual),sort_keys=True))
        report['lifecycle']['events'][0]['observations'][0]['proof']['cases']['default']['exit']=1
        with self.assertRaisesRegex(ValueError,'parent/standalone lifecycle mismatch'):
            C.validate_retained_lifecycle(report,actual)
        actual['events'][0]['observations'][0]['receipt_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'receipt bytes/digest join differs'):
            C.validate_retained_lifecycle(dict(lifecycle=actual),actual)


class Source(unittest.TestCase):
    def test_exact_final15_source_and11_payload_bindings(self):
        result=C.recipe(ROOT);self.assertEqual(len(result['input_sha256']),15);self.assertEqual(len(C.files()),11)
        self.assertEqual(result['metadata']['depends'],['fish>=4.9.3']);self.assertEqual(result['metadata']['arch'],['any'])

    def test_base_supplies_exact_fish_and_python_without_new_inputs(self):
        data=json.loads((ROOT/'scripts/ci/maintained-desktop574-inputs.json').read_text());rows={r['name']:r for r in data['packages']}
        self.assertEqual(len(rows),574);self.assertEqual(rows['fish']['version'],'4.9.3-1');self.assertIn('python',rows)

    def test_exact_pinned_helper_adapters_compile_without_execution(self):
        for kind in ('run','job'):
            text=prepare.source(kind,ROOT);compile(text,'fish-'+kind,'exec')
            self.assertNotIn('/highlighting-fixture',text)
            self.assertNotIn('THREE_UNSELECTED_TOOLS_CANDIDATES',text)
        text=prepare.source('run',ROOT)
        self.assertIn('len(self)<4',text);self.assertIn('ONE_UNSELECTED_FISH_AUTOPAIR_CANDIDATE',text)
        self.assertIn('--env=CACHY_ASAHI_FISH_AUTOPAIR_LIFECYCLE=1',text)
        self.assertIn('len(names)<=4',prepare.source('job',ROOT));self.assertIn('MAX_TOTAL=96*1024**2',prepare.source('job',ROOT))

    def test_missing_anchor_is_a_hard_source_gate(self):
        with patch.object(C,'pinned',return_value='changed upstream helper'):
            with self.assertRaisesRegex(ValueError,'adapter anchor differs'):prepare.source('run',ROOT)

    def test_source_proof_binds_both_generated_adapters(self):
        adapter=prepare.adapter('job',ROOT);relative='packages/tools/'+C.PACKAGE+'/LICENSE.upstream';path=ROOT/relative
        manifest=dict(files={relative:dict(bytes=path.stat().st_size,sha256=C.digest(path))})
        environment=dict(SOURCE_SHA='1'*40,GITHUB_SHA='1'*40,GITHUB_WORKFLOW_SHA='1'*40,RUNNER_OS='Linux',
                         RUNNER_ARCH='ARM64',GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1')
        with patch.dict(adapter,manifest_files=lambda *args:None),patch.object(C,'verify_source'):
            result=adapter['prove'](ROOT,manifest,environment)
        self.assertEqual(result['fish_adapter_sha256'],{name:hashlib.sha256(prepare.source(name,ROOT).encode()).hexdigest() for name in ('run','job')})
        self.assertEqual(len(result['consumer_token']),32)

    def test_shared_helper_byte_drift_is_rejected_before_adaptation(self):
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp);path=source/'scripts/ci/tools-native/run.py';path.parent.mkdir(parents=True);path.write_text('changed')
            with self.assertRaisesRegex(ValueError,'pinned source differs'):prepare.source('run',source)

    def test_payload_source_license_mode_and_elf_mutations_refuse(self):
        members={n:dict(type='0',mode=mode,uid=0,gid=0,sha256=C.digest(ROOT/'packages/tools'/C.PACKAGE/original)) for n,(original,mode) in C.files().items()}
        report=dict(errors=[],elf={},members=members);self.assertEqual(len(C.payload(report,ROOT)),11)
        key='usr/share/licenses/'+C.PACKAGE+'/LICENSE.upstream'
        for mutation in ('hash','mode','owner','link','missing','extra','elf'):
            bad=copy.deepcopy(report)
            if mutation=='hash':bad['members'][key]['sha256']='0'*64
            elif mutation=='mode':bad['members'][key]['mode']=0o755
            elif mutation=='owner':bad['members'][key]['uid']=1000
            elif mutation=='link':bad['members'][key]['type']='2'
            elif mutation=='missing':bad['members'].pop(key)
            elif mutation=='extra':bad['members']['etc/fish/conf.d/automatic.fish']=members[key]
            else:bad['elf']={'usr/bin/unexpected':{}}
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):C.payload(bad,ROOT)

    def test_check_log_requires_actual_fourteen_case_summary_and_enabled_check(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'build.log'
            for text in ('','Starting check()\n{"status":"FAIL","cases":14}',
                         'Starting check()\n{"status":"PASS","cases":13}'):
                path.write_text(text)
                with self.assertRaises(ValueError):C.check_log(path)
            path.write_text('Starting check()\n{"status":"PASS","cases":14}\n');self.assertEqual(C.check_log(path)['cases'],14)

    def test_manual_workflow_uses_own_group_and_existing_seed_route(self):
        path=Path(__file__).resolve().parents[3]/'.github/workflows/native-arm-fish-autopair-candidate.yml'
        text=path.read_text();self.assertIn('group: native-arm-fish-autopair-candidate\n  cancel-in-progress: false',text)
        self.assertIn('04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd',text)
        self.assertIn('include-hidden-files: true',text)
        self.assertNotIn('push:',text);self.assertNotIn('pull_request:',text)

    def test_partial_closed_export_keeps_srcinfo_and_ignores_extra_hidden_harness_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'source';source.mkdir()
            pins=json.loads((C.HERE/'source-pins.json').read_text())
            for relative in pins:
                target=source/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/relative,target)
            relative='scripts/ci/fish-autopair-native/source-manifest.json'
            shutil.copyfile(ROOT/relative,source/relative)
            (source/'scripts/ci/fish-autopair-native/.unexpected').write_text('must not export')
            base=root/'base';runtime=root/'runtime';base.mkdir();runtime.mkdir()
            for name in ('proof.json','cleanup.json'):(root/name).write_text('{}')
            adapter=prepare.adapter('job',ROOT)
            result=adapter['retain'](source,base,runtime,root/'proof.json',root/'cleanup.json',root/'public')
            self.assertEqual(result['status'],'FAIL_OR_INCOMPLETE')
            self.assertIn('source/'+C.PACKAGE+'/.SRCINFO',result['files'])
            self.assertNotIn('harness/.unexpected',result['files'])


class Receipt(unittest.TestCase):
    def test_complete14_case57_snapshot_receipt_and_five_transitions(self):
        C.validate_lifecycle(receipt());C.validate_pty(proof(),proof()['wrapper_sha256'])

    def test_any_missing_case_bad_exit_namespace_or_snapshot_refuses(self):
        for change in ('missing-case','bad-exit','not-native','wrapper','snapshot','case-order','cursor','yielded','version'):
            bad=proof()
            if change=='missing-case':bad['cases'].pop('existing-wrapper')
            elif change=='bad-exit':bad['cases']['custom-key']['exit']=1
            elif change=='not-native':bad['platform']='x86_64'
            elif change=='wrapper':bad['wrapper_sha256']='0'*64
            elif change=='snapshot':bad['cases']['vi']['snapshots'].pop()
            elif change=='case-order':bad['cases']['default']['snapshots'].reverse()
            elif change=='cursor':bad['cases']['default']['snapshots'][0]['cursor']=-1
            elif change=='yielded':bad['cases']['custom-prefix']['activation']='enabled'
            else:bad['fish']='fish, version 4.0'
            with self.subTest(change=change),self.assertRaises(ValueError):C.validate_pty(bad,proof()['wrapper_sha256'])

    def test_each_lifecycle_scope_and_preservation_gate(self):
        for key,value in (('status','NOT_RUN'),('base_count',573),('installed_count',576),('user_config_preserved',False),
                          ('system_config_preserved',False),('user_outputs_preserved',False),('hardware','PASS'),('actual_page_size',0)):
            bad=receipt();bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):C.validate_lifecycle(bad)
        for index in range(5):
            bad=receipt();bad['events'].pop(index)
            with self.subTest(index=index),self.assertRaises(ValueError):C.validate_lifecycle(bad)

    def test_both_homes_receipt_hash_and_removed_guard_required(self):
        for change in ('one-home','receipt-hash','fish-hash','guard','wrong-wrapper'):
            bad=receipt()
            if change=='one-home':bad['events'][0]['observations'].pop()
            elif change=='receipt-hash':bad['events'][0]['observations'][0]['receipt_sha256']='0'*64
            elif change=='fish-hash':bad['events'][0]['observations'][0]['fish_sha256']=''
            elif change=='guard':bad['events'][2]['guarded_opt_in_absent']=False
            else:bad['wrapper_sha256']='0'*64
            with self.subTest(change=change),self.assertRaises(ValueError):C.validate_lifecycle(bad)

    def test_whole_archive_byte_and_buildinfo_identity_are_required(self):
        good=dict(status='contents-reproduced',errors=[],packages={'pkg':dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)})
        R.pair_gate(good)
        for field in good['packages']['pkg']:
            bad=copy.deepcopy(good);bad['packages']['pkg'][field]=False
            with self.subTest(field=field),self.assertRaises(ValueError):R.pair_gate(bad)


class Cleanup(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.base=self.root/'base';self.runtime=self.root/'runtime';self.base.mkdir();self.runtime.mkdir()
        self.token='1'*32;self.image='sha256:'+'2'*64;self.name='cachy-asahi-product-'+'3'*32;self.calls=[];self.present=True
        self.proof=dict(consumer_token=self.token,job_token='4'*16);self.J=prepare.adapter('job',ROOT)
        self.J['save'](self.base/'report.json',dict(image=self.image,owned_cleanup=dict(status='PASS')))
        (self.runtime/'consumer.lock').touch();self.owner=dict(schema_version=1,token=self.token,image=self.image,label=C.LABEL,containers=[self.name])
        self.J['save'](self.runtime/'owner.json',self.owner)

    def daemon(self,argv):
        self.calls.append(argv)
        if argv[:4]==['/usr/bin/docker','container','inspect',self.name]:
            if not self.present:return SimpleNamespace(returncode=1,stdout=b'',stderr=('No such container: '+self.name).encode())
            return SimpleNamespace(returncode=0,stdout=json.dumps([dict(Id='5'*64,Image=self.image,Name='/'+self.name,Config=dict(Labels={C.LABEL:self.token}))]).encode(),stderr=b'')
        if argv[:3]==['/usr/bin/docker','rm','-f']:self.present=False
        return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')

    def test_confirmed_id_removal_and_absence_before_producer(self):
        with patch.dict(self.J,manifest_files=lambda *args:None):
            result=self.J['cleanup'](ROOT,{},self.proof,self.base,self.runtime,self.root/'cleanup.json',self.daemon)
        self.assertEqual(result['status'],'PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP');self.assertFalse(self.present)
        self.assertIn(['/usr/bin/docker','rm','-f','5'*64],self.calls);self.assertIn('maintained_desktop574.py',str(self.calls[-1]))

    def test_foreign_label_blocks_consumer_removal_and_producer_retirement(self):
        def foreign(argv):
            row=self.daemon(argv)
            if row.returncode==0 and 'inspect' in argv:
                data=json.loads(row.stdout);data[0]['Config']['Labels'][C.LABEL]='6'*32;row.stdout=json.dumps(data).encode()
            return row
        with patch.dict(self.J,manifest_files=lambda *args:None):
            result=self.J['cleanup'](ROOT,{},self.proof,self.base,self.runtime,self.root/'cleanup.json',foreign)
        self.assertEqual(result['status'],'FAIL');self.assertFalse(any('rm' in a or 'maintained_desktop574.py' in str(a) for a in self.calls))

    def test_active_lease_prevents_cleanup(self):
        with (self.runtime/'consumer.lock').open('r+') as lease:
            fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.J['retire_consumers'](self.runtime,self.base,self.proof,self.daemon)
        self.assertFalse(self.calls)

    def test_unknown_daemon_and_more_than_four_actors_refuse(self):
        with self.assertRaisesRegex(ValueError,'unknown consumer daemon state'):
            self.J['retire_consumers'](self.runtime,self.base,self.proof,lambda argv:SimpleNamespace(returncode=1,stdout=b'',stderr=b'connection refused'))
        self.owner['containers']=['cachy-asahi-product-'+str(i)*32 for i in range(5)]
        self.J['save'](self.runtime/'owner.json',self.owner)
        with self.assertRaises(ValueError):self.J['retire_consumers'](self.runtime,self.base,self.proof,self.daemon)


class AbsenceProbe(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.home=self.root/'home';self.home.mkdir();self.output=self.root/'output';self.output.mkdir()
        self.L=C.load('absent_preservation_fixture',ROOT/'scripts/ci/welcome-native/lifecycle.py')
        self.M=C.load('absent_fish_fixture',ROOT/'scripts/ci/fish-autopair-native/lifecycle.py')
        self.session=self.L.session_paths(self.home,self.output)
        (self.session/'fish-config').mkdir(mode=0o700)
        (self.output/'outside').write_text('keep outside')

    def test_only_probe_config_endpoint_changes_not_home_or_other_xdg_state(self):
        original=self.L.user_environment(self.home,self.session)
        selected=self.M.absent_environment(self.L,self.home,self.session)
        self.assertEqual({k for k in original if original[k]!=selected[k]},{'XDG_CONFIG_HOME'})
        self.assertEqual(selected['HOME'],str(self.home))
        path=Path(selected['XDG_CONFIG_HOME']);self.assertTrue(path.is_relative_to(self.output))
        self.assertFalse(path.is_relative_to(self.home));self.assertEqual(path.stat().st_mode&0o777,0o700)

    def test_observed_fish_initialization_reproduces_strict_home_failure(self):
        before=self.L.snapshot(self.home);outside=self.L.entry(self.output/'outside')
        config=Path(self.L.user_environment(self.home,self.session)['XDG_CONFIG_HOME'])/'fish'
        config.mkdir()
        for name in ('completions','conf.d','functions'):(config/name).mkdir()
        (config/'config.fish').write_text('# generated by Fish startup')
        with contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(ValueError,'user config/outside changed'):
            self.L.preservation_check(self.home,before,self.output,outside)

    def test_isolated_fish_initialization_preserves_fresh_and_existing_home(self):
        for existing in (False,True):
            if existing:
                config=self.home/'.config/fish';config.mkdir();(config/'config.fish').write_text('keep custom')
                (config/'config-alias').symlink_to('config.fish')
            before=self.L.snapshot(self.home);outside=self.L.entry(self.output/'outside')
            selected=self.M.absent_environment(self.L,self.home,self.session)
            config=Path(selected['XDG_CONFIG_HOME'])/'fish';config.mkdir(exist_ok=True)
            for name in ('completions','conf.d','functions'):(config/name).mkdir(exist_ok=True)
            (config/'config.fish').write_text('# generated private probe config')
            self.L.preservation_check(self.home,before,self.output,outside)

    def test_protected_home_mutation_still_fails_after_probe_isolation(self):
        before=self.L.snapshot(self.home);outside=self.L.entry(self.output/'outside')
        self.M.absent_environment(self.L,self.home,self.session)
        (self.home/'.config/unexpected').write_text('must fail')
        with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(ValueError):
            self.L.preservation_check(self.home,before,self.output,outside)


if __name__=='__main__':unittest.main()
