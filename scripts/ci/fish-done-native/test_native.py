"""Source and inert receipt/daemon controls; no Fish or package/container actors."""
import ast
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

ROOT=Path(os.environ.get('FISH_DONE_NATIVE_SOURCE',Path(__file__).resolve().parents[3]))


def notification(failed=False,watched=False,status=7,detail=None):
    return dict(argv=['--hint=int:transient:1','--urgency='+('critical' if failed else 'normal'),
        '--icon=utilities-terminal','--app-name=fish','--expire-time=3000','--',
        'Failed ('+str(status)+') after 0.1s' if failed else 'Done in 0.1s',
        detail if detail is not None else ('Watched job' if watched else 'Foreground command')+' completed.'])


def proof():
    base=ROOT/'packages/tools'/C.PACKAGE
    cases={name:dict(exit=0,notifications=0,**({} if name=='noninteractive' else dict(
        activation='yielded' if name in C.YIELDED else 'enabled',**({} if name in C.YIELDED else dict(proofs=[]))))) for name in C.CASES}
    cases['foreground']['proofs']=[notification(),notification(True)]
    cases['background']['proofs']=[notification(watched=True),notification(True,True),notification(True,True,143)]
    cases['command-data']['proofs']=[notification(detail='&lt;tag&gt; $HOME $(touch PWNED) --leading')]
    for name in ('transport-failure','transport-timeout'):
        cases[name]['proofs']=[dict(elapsed_seconds=3.1 if name=='transport-timeout' else 0.2,invocation=notification())]
    for case in cases.values():case['notifications']=len(case.get('proofs',[]))
    return dict(status='PASS',machine='aarch64',fish='fish, version 4.9.3',scope=C.SCOPE,
        wrapper_sha256=C.digest(base/'opt-in.fish'),runtime_sha256=C.digest(base/'done.fish'),cases=cases)


def recorders(value):
    result={}
    for name,case in value['cases'].items():
        rows=[dict(argv=row.get('invocation',row)['argv'],pid=123+index) for index,row in enumerate(case.get('proofs',[]))]
        item=dict(transport='ABSENT_CONTROL' if name=='notify-send' else 'PRIVATE_NOTIFY_SEND_RECORDER',rows=rows)
        if name!='notify-send':item['shim_sha256']=C.RECORDER_SHA
        if rows:item['transcript_sha256']=hashlib.sha256(''.join(json.dumps(row)+'\n' for row in rows).encode()).hexdigest()
        if name=='transport-timeout':item['recorded_pids_absent']=True
        if name=='repeat-preserve':item.update(hooks_preserved=True,caller_continued=True,custom_binding_preserved=True)
        result[name]=item
    return result


def receipt():
    value=proof();sha=hashlib.sha256((json.dumps(value,indent=2)+'\n').encode()).hexdigest()
    observations=[dict(home='fish-home-'+kind,proof=copy.deepcopy(value),receipt_sha256=sha,fish_sha256='1'*64,
                       recorders=recorders(value)) for kind in ('fresh','existing')]
    return dict(status='PASS_FISH_DONE_INSTALLED_LIFECYCLE',base_count=574,installed_count=575,
        user_config_preserved=True,system_config_preserved=True,user_outputs_preserved=True,hardware='NOT_RUN',
        native_architecture='aarch64',actual_page_size=4096,notification_scope='LOCAL_RECORDER_ONLY',
        wrapper_sha256=value['wrapper_sha256'],runtime_sha256=value['runtime_sha256'],
        events=[dict(phase=phase,status='PASS',inventory_count=count,config_preserved=True,
            **(dict(observations=copy.deepcopy(observations)) if count==575 else dict(guarded_opt_in_absent=True))) for phase,count in
            (('install',575),('same-version-reinstall',575),('remove',574),('reinstall-after-removal',575),('final-remove',574))])


class Source(unittest.TestCase):
    def test_fixture_uses_exact_private_recorder_and_disconnected_bus(self):
        text=(ROOT/'packages/tools'/C.PACKAGE/'check-module.py').read_text()
        shims=[n.value for n in ast.walk(ast.parse(text)) if isinstance(n,ast.Constant) and isinstance(n.value,str) and
               n.value.startswith('#!/usr/bin/python3\n') and 'notifications.jsonl' in n.value]
        self.assertEqual(len(shims),1);self.assertEqual(hashlib.sha256(shims[0].encode()).hexdigest(),C.RECORDER_SHA)
        self.assertIn("PATH=str(home/'bin')",text);self.assertIn("home/'not-a-real-bus'",text)
        self.assertIn("missing = kind if kind in ('notify-send', 'timeout') else None",text)

    def test_foreground_monitor_keeps_named_bound_and_strict_pid_absence(self):
        product=ROOT/'packages/tools'/C.PACKAGE
        self.assertIn('command timeout --foreground --signal=TERM --kill-after=1s 2s notify-send',(product/'done.fish').read_text())
        self.assertIn("need(not Path(f'/proc/{pid}').exists(), 'timed-out notification process survived')",(product/'check-module.py').read_text())
        self.assertEqual(C.version(ROOT),'0.1.0-2')

    def test_previous_pkgrel_cannot_claim_new_frozen_identity(self):
        with tempfile.TemporaryDirectory() as root:
            target=Path(root);product=target/'packages/tools'/C.PACKAGE
            shutil.copytree(ROOT/'packages/tools'/C.PACKAGE,product)
            recipe=product/'PKGBUILD';recipe.write_text(recipe.read_text().replace('pkgrel=2','pkgrel=1'))
            with self.assertRaises(ValueError):C.recipe(target)

    def test_exact_final12_source_and8_payload_bindings(self):
        result=C.recipe(ROOT);self.assertEqual(len(result['input_sha256']),12);self.assertEqual(len(C.files()),8)
        self.assertEqual(result['metadata']['depends'],['fish>=4.9.3','libnotify','coreutils']);self.assertEqual(result['metadata']['arch'],['any'])

    def test_base_supplies_exact_fish_and_python_without_new_inputs(self):
        data=json.loads((ROOT/'scripts/ci/maintained-desktop574-inputs.json').read_text());rows={r['name']:r for r in data['packages']}
        self.assertEqual(len(rows),574);self.assertEqual(rows['fish']['version'],'4.9.3-1');self.assertIn('python',rows)
        self.assertEqual(rows['libnotify']['version'],'0.8.8-1');self.assertEqual(rows['coreutils']['version'],'9.12-2')

    def test_exact_pinned_helper_adapters_compile_without_execution(self):
        for kind in ('run','job'):
            text=prepare.source(kind,ROOT);compile(text,'fish-'+kind,'exec')
            self.assertNotIn('/highlighting-fixture',text)
            self.assertNotIn('THREE_UNSELECTED_TOOLS_CANDIDATES',text)
        text=prepare.source('run',ROOT)
        self.assertIn('len(self)<4',text);self.assertIn('ONE_UNSELECTED_FISH_DONE_CANDIDATE',text)
        self.assertIn('--env=CACHY_ASAHI_FISH_DONE_LIFECYCLE=1',text)
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
        self.assertEqual(result['done_adapter_sha256'],{name:hashlib.sha256(prepare.source(name,ROOT).encode()).hexdigest() for name in ('run','job')})
        self.assertEqual(len(result['consumer_token']),32)

    def test_shared_helper_byte_drift_is_rejected_before_adaptation(self):
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp);path=source/'scripts/ci/tools-native/run.py';path.parent.mkdir(parents=True);path.write_text('changed')
            with self.assertRaisesRegex(ValueError,'pinned source differs'):prepare.source('run',source)

    def test_payload_source_license_mode_and_elf_mutations_refuse(self):
        members={n:dict(type='0',mode=mode,uid=0,gid=0,sha256=C.digest(ROOT/'packages/tools'/C.PACKAGE/original)) for n,(original,mode) in C.files().items()}
        report=dict(errors=[],elf={},members=members);self.assertEqual(len(C.payload(report,ROOT)),8)
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

    def test_check_log_requires_actual_eighteen_case_summary_and_enabled_check(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'build.log'
            for text in ('','Starting check()\n{"status":"FAIL","cases":18}',
                         'Starting check()\n{"status":"PASS","cases":17}'):
                path.write_text(text)
                with self.assertRaises(ValueError):C.check_log(path)
            path.write_text('Starting check()\n{"status":"PASS","cases":18}\n');self.assertEqual(C.check_log(path)['cases'],18)

    def test_manual_workflow_uses_own_group_and_existing_seed_route(self):
        path=Path(__file__).resolve().parents[3]/'.github/workflows/native-arm-fish-done-candidate.yml'
        text=path.read_text();self.assertIn('group: native-arm-fish-done-candidate\n  cancel-in-progress: false',text)
        self.assertIn('04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd',text)
        self.assertIn('include-hidden-files: true',text)
        self.assertNotIn('push:',text);self.assertNotIn('pull_request:',text)

    def test_partial_closed_export_keeps_srcinfo_and_ignores_extra_hidden_harness_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'source';source.mkdir()
            pins=json.loads((C.HERE/'source-pins.json').read_text())
            for relative in pins:
                target=source/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/relative,target)
            relative='scripts/ci/fish-done-native/source-manifest.json'
            shutil.copyfile(ROOT/relative,source/relative)
            (source/'scripts/ci/fish-done-native/.unexpected').write_text('must not export')
            base=root/'base';runtime=root/'runtime';base.mkdir();runtime.mkdir()
            for name in ('proof.json','cleanup.json'):(root/name).write_text('{}')
            adapter=prepare.adapter('job',ROOT)
            result=adapter['retain'](source,base,runtime,root/'proof.json',root/'cleanup.json',root/'public')
            self.assertEqual(result['status'],'FAIL_OR_INCOMPLETE')
            self.assertIn('source/'+C.PACKAGE+'/.SRCINFO',result['files'])
            self.assertNotIn('harness/.unexpected',result['files'])


class Receipt(unittest.TestCase):
    def export_lifecycle(self,actual,reported):
        # Execute the exact adapted export gate statements, without other actors.
        tree=ast.parse(prepare.source('job',ROOT))
        block=next(node for node in ast.walk(tree) if isinstance(node,ast.Try) and any(
            isinstance(row,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='actual_lifecycle' for target in row.targets)
            for row in node.body))
        start=next(i for i,row in enumerate(block.body) if isinstance(row,ast.Assign) and any(
            isinstance(target,ast.Name) and target.id=='actual_lifecycle' for target in row.targets))
        gate=ast.fix_missing_locations(ast.Module(body=block.body[start:start+3],type_ignores=[]))
        with tempfile.TemporaryDirectory() as root:
            path=Path(root);(path/'lifecycle.json').write_text(json.dumps(actual,indent=2)+'\n')
            namespace=dict(C=C,runtime=path,report=dict(lifecycle=reported),read=prepare.adapter('job',ROOT)['read'])
            exec(compile(gate,'exact-export-lifecycle-gate','exec'),namespace)

    def test_sorted_parent_report_joins_original_unsorted_receipt_without_rewriting_digest(self):
        value=receipt();sorted_report=json.loads(json.dumps(value,sort_keys=True))
        self.assertEqual(value,sorted_report)
        C.validate_lifecycle(value)
        with self.assertRaisesRegex(ValueError,'receipt byte/digest join differs'):C.validate_lifecycle(sorted_report)
        self.export_lifecycle(value,sorted_report)

    def test_export_semantic_tamper_and_receipt_digest_tamper_remain_fatal(self):
        value=receipt();changed=copy.deepcopy(value);changed['user_outputs_preserved']=False
        with self.assertRaisesRegex(ValueError,'report lifecycle differs'):self.export_lifecycle(value,changed)
        value['events'][0]['observations'][0]['receipt_sha256']='f'*64
        with self.assertRaisesRegex(ValueError,'receipt byte/digest join differs'):
            self.export_lifecycle(value,json.loads(json.dumps(value,sort_keys=True)))

    def test_complete_eighteen_case_local_recorder_lifecycle(self):
        value=proof();C.validate_pty(value,value['wrapper_sha256'],value['runtime_sha256'])
        C.validate_recorders(recorders(value),value);C.validate_lifecycle(receipt())

    def test_missing_case_normal_exit_native_identity_runtime_or_scope_refuses(self):
        original=proof()
        for change in ('missing','exit','machine','runtime','wrapper','scope','yield','fish'):
            bad=copy.deepcopy(original)
            if change=='missing':bad['cases'].pop('disown')
            elif change=='exit':bad['cases']['existing-public']['exit']=1
            elif change=='machine':bad['machine']='x86_64'
            elif change=='runtime':bad['runtime_sha256']='0'*64
            elif change=='wrapper':bad['wrapper_sha256']='0'*64
            elif change=='scope':bad['scope']='real desktop notification delivered'
            elif change=='yield':bad['cases']['no-bus']['notifications']=1
            else:bad['fish']='fish, version 4.0'
            with self.subTest(change=change),self.assertRaises(ValueError):
                C.validate_pty(bad,original['wrapper_sha256'],original['runtime_sha256'])

    def test_foreground_and_process_exit_statuses_privacy_escaping_and_three_second_kill(self):
        for change in ('foreground7','background7','background143','private','literal','timeout-long','timeout-short'):
            bad=proof()
            if change=='foreground7':bad['cases']['foreground']['proofs'][1]['argv'][6]='Failed (9)'
            elif change=='background7':bad['cases']['background']['proofs'][1]['argv'][6]='Failed (9)'
            elif change=='background143':bad['cases']['background']['proofs'][2]['argv'][6]='Failed (9)'
            elif change=='private':bad['cases']['foreground']['proofs'][0]['argv'][7]='secret command/path'
            elif change=='literal':bad['cases']['command-data']['proofs'][0]['argv'][7]='<tag> evaluated'
            else:bad['cases']['transport-timeout']['proofs'][0]['elapsed_seconds']=5.0 if change=='timeout-long' else 1.0
            with self.subTest(change=change),self.assertRaises(ValueError):C.validate_pty(bad,proof()['wrapper_sha256'],proof()['runtime_sha256'])

    def test_raw_local_recorder_digest_and_proof_joins(self):
        value=proof()
        for change in ('missing','real-transport','shim','hash','proof-row','pid-survived','hooks','caller','binding'):
            bad=recorders(value)
            if change=='missing':bad.pop('timeout')
            elif change=='real-transport':bad['foreground']['transport']='SYSTEM_NOTIFY_SEND'
            elif change=='shim':bad['foreground']['shim_sha256']='0'*64
            elif change=='hash':bad['foreground']['transcript_sha256']='0'*64
            elif change=='proof-row':bad['foreground']['rows']=[]
            elif change=='pid-survived':bad['transport-timeout']['recorded_pids_absent']=False
            else:bad['repeat-preserve'][{'hooks':'hooks_preserved','caller':'caller_continued','binding':'custom_binding_preserved'}[change]]=False
            with self.subTest(change=change),self.assertRaises(ValueError):C.validate_recorders(bad,value)

    def test_pipeline_foreign_and_disowned_controls_cannot_record_watched_job(self):
        value=proof()
        for name in ('watch-rejection','disown'):
            bad=recorders(value);events=[dict(pid=123,argv=notification(watched=True)['argv'])];bad[name]['rows']=events
            bad[name]['transcript_sha256']=hashlib.sha256(''.join(json.dumps(r)+'\n' for r in events).encode()).hexdigest()
            with self.subTest(name=name),self.assertRaises(ValueError):C.validate_recorders(bad,value)

    def test_five_transitions_both_homes_and_preservation_required(self):
        for key,value in (('base_count',573),('installed_count',576),('user_config_preserved',False),('system_config_preserved',False),
                          ('user_outputs_preserved',False),('hardware','PASS'),('notification_scope','REAL_DESKTOP'),('actual_page_size',0)):
            bad=receipt();bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):C.validate_lifecycle(bad)
        for index in range(5):
            bad=receipt();bad['events'].pop(index)
            with self.subTest(index=index),self.assertRaises(ValueError):C.validate_lifecycle(bad)
        bad=receipt();bad['events'][0]['observations'].pop()
        with self.assertRaises(ValueError):C.validate_lifecycle(bad)

    def test_frozen_wrapper_runtime_receipt_binary_hash_and_removed_guard(self):
        for change in ('wrapper','runtime','receipt','fish','guard'):
            bad=receipt()
            if change=='wrapper':bad['wrapper_sha256']='0'*64
            elif change=='runtime':bad['runtime_sha256']='0'*64
            elif change=='receipt':bad['events'][0]['observations'][0]['receipt_sha256']='0'*64
            elif change=='fish':bad['events'][0]['observations'][0]['fish_sha256']=''
            else:bad['events'][2]['guarded_opt_in_absent']=False
            with self.subTest(change=change),self.assertRaises(ValueError):C.validate_lifecycle(bad)

    def test_complete_archive_bytes_and_buildinfo_are_required(self):
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
        self.M=C.load('absent_fish_fixture',ROOT/'scripts/ci/fish-done-native/lifecycle.py')
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
