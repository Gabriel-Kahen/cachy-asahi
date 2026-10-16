"""Inert preparation, running-state observer, cancellation and export controls."""
import copy
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import support as s
def load(name):
    spec=importlib.util.spec_from_file_location('trial_test_'+name,HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
o,p=load('observe'),load('prepare')
TOKEN='a'*16; OLD,IMAGE,FINAL=['sha256:'+c*64 for c in '012']; CID='b'*64; PROBE='c'*64
LABEL='org.cachy-asahi.bootstrap574.active-job'
NAME='cachy-asahi-574-active-'+TOKEN+'-build'; TAG='cachy-asahi-574-active:'+TOKEN+'-root'
TRANSACTION='exact held transaction'


def receipt(normal=False):
    containers=[{'cid':CID,'name':NAME,'image':IMAGE}]
    images=[{'id':IMAGE,'tag':TAG}]
    if normal:
        containers.append({'cid':PROBE,'name':NAME.removesuffix('build')+'probe','image':FINAL})
        images.append({'id':FINAL,'tag':TAG.removesuffix('root')+'result'})
    controls=[{'path':path,'uid':0,'gid':0,'type':'regular','mode':0o644 if index<2 else 0o600,
               'bytes':116,'sha256':'a'*64} for index,path in enumerate(o.COPY_CONTROLS)]
    controls[-1]['sha256']='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
    copy={'status':'PASS_ROOT_OWNED_COPY','container':dict(containers[0]),'archive':{'bytes':10240,'sha256':'b'*64},
          'files_verified':1155,'directories_verified':1,'uid':0,'gid':0,'members_sha256':'c'*64,'controls':controls}
    return {'status':'PASS' if normal else 'FAIL','phase':'completed' if normal else 'active-build','copy_metadata':copy,
        'cancelled':not normal,'token':TOKEN,'initial_image_ids':[OLD],
        'helper_sha256':s.PINS['maintained_desktop574.py'],'inputs_sha256':s.PINS['maintained-desktop574-inputs.json'],
        **({'packages':574,'inventory_sha256':'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'} if normal else {}),
        'cleanup':{'status':'PASS','client_fenced':True,'initial_image_ids':[OLD],'after_image_ids':[OLD],
                   'initial_image_ids_preserved':True,'captured_containers':containers,'captured_images':images,
                   'containers':[dict(r,absence_verified=True) for r in reversed(containers)],
                   'images':[dict(r,absence_verified=True) for r in reversed(images)]}}


class Query:
    def __init__(self):
        self.calls=[]; self.running=[True,True]; self.tools='PID COMMAND\n123 sh\n124 pacman\n'
        self.row={'Id':CID,'Name':'/'+NAME,'Image':IMAGE,'Config':{'Labels':{LABEL:TOKEN},'Entrypoint':['/bin/sh'],'Cmd':['-ec',TRANSACTION]},
                  'HostConfig':{'NetworkMode':'none','Privileged':False,'CapAdd':None,'Binds':None,'Devices':[]}}
        self.present=None; self.lost=False
    def run(self,*args,**kwargs):
        self.calls.append(args)
        if args[:2]==('container','inspect'):
            row=copy.deepcopy(self.row); row['State']={'Running':self.running.pop(0) if len(self.running)>1 else self.running[0],'Pid':123}
            return json.dumps([row])
        if args[:2]==('container','top'): return self.tools
        if args[:2]==('image','ls') and '--filter' not in args: return '' if self.lost else OLD
        if self.present and self.present in str(args): return self.present
        return ''


class Controls(unittest.TestCase):
    def setUp(self):
        for name in ('Popen','run','check_output'):
            guard=patch.object(subprocess,name,side_effect=AssertionError('external actor forbidden'))
            guard.start(); self.addCleanup(guard.stop)
        self.temp=tempfile.TemporaryDirectory(dir=HERE); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.query=Query()
        self.active={'phase':'active-build','token':TOKEN,'active_executor':{'cid':CID,'name':NAME,'image':IMAGE}}

    def test_running_exact_transaction_and_real_transaction_tool_required(self):
        row=o.active(self.query,self.active,TRANSACTION,LABEL)
        self.assertTrue(row['running']); self.assertEqual(row['running_inspections'],2)
        self.assertEqual(row['observed_transaction_tools'],['pacman'])
        self.assertEqual(row['transaction_sha256'],s.sha(TRANSACTION.encode()))

    def test_created_container_does_not_establish_cancellation(self):
        self.query.running=[False]
        self.assertIsNone(o.active(self.query,self.active,TRANSACTION,LABEL))
        self.assertFalse(any(a[:2]==('container','top') for a in self.query.calls))

    def test_running_shell_only_does_not_establish_transaction_progress(self):
        self.query.tools='PID COMMAND\n123 sh\n'
        self.assertIsNone(o.active(self.query,self.active,TRANSACTION,LABEL))

    def test_transaction_ending_between_reads_does_not_establish_cancellation(self):
        self.query.running=[True,False]
        self.assertIsNone(o.active(self.query,self.active,TRANSACTION,LABEL))

    def test_wrong_CID_name_image_label_and_command_refused(self):
        changes=[('Id','d'*64),('Name','/foreign'),('Image',OLD)]
        for key,value in changes:
            query=Query(); query.row[key]=value
            with self.subTest(key=key), self.assertRaises(s.Refused): o.active(query,self.active,TRANSACTION,LABEL)
        for key,value in (('Labels',{LABEL:'f'*16}),('Cmd',['-ec','sleep 1000']),('Entrypoint',['/bin/false'])):
            query=Query(); query.row['Config'][key]=value
            with self.subTest(key=key), self.assertRaises(s.Refused): o.active(query,self.active,TRANSACTION,LABEL)

    def test_privileged_network_caps_and_mount_policy_refused(self):
        for key,value in (('Privileged',True),('NetworkMode','host'),('CapAdd',['SYS_ADMIN']),('Binds',['/var/run/docker.sock:/socket']),('Devices',[{}])):
            query=Query(); query.row['HostConfig'][key]=value
            with self.subTest(key=key), self.assertRaises(s.Refused): o.active(query,self.active,TRANSACTION,LABEL)

    def test_no_active_probe_substitution(self):
        self.active['phase']='active-probe'
        self.assertIsNone(o.active(self.query,self.active,TRANSACTION,LABEL)); self.assertEqual(self.query.calls,[])

    def test_independent_absence_checks_all_handles_and_baseline(self):
        row=o.project_owner(receipt()); observed=dict(self.active['active_executor'],token=TOKEN)
        result=o.absent(self.query,row,[OLD],observed)
        self.assertEqual(result['status'],'PASS'); self.assertEqual(result['containers_absent'],1)
        self.assertTrue(all(a[:2] in (('container','ls'),('image','ls')) for a in self.query.calls))

    def test_claimed_cleanup_cannot_pass_when_actual_CID_remains(self):
        self.query.present=CID
        with self.assertRaises(s.Refused): o.absent(self.query,o.project_owner(receipt()),[OLD])

    def test_actual_initial_image_loss_and_owner_baseline_mismatch_refused(self):
        self.query.lost=True
        with self.assertRaises(s.Refused): o.absent(self.query,o.project_owner(receipt()),[OLD])
        with self.assertRaises(s.Refused): o.absent(Query(),o.project_owner(receipt()),[])

    def test_cleanup_must_cover_exact_captured_resources(self):
        row=receipt(); row['cleanup']['containers']=[]
        with self.assertRaises(s.Refused): o.absent(self.query,o.project_owner(row),[OLD])
        row=receipt(); row['cleanup']['client_fenced']=False
        with self.assertRaises(s.Refused): o.absent(self.query,o.project_owner(row),[OLD])

    def test_public_projection_discards_arbitrary_fields_and_URLs(self):
        row=receipt(); row['secret']='PRIVATE'; row['cleanup']['stderr']='https://private.invalid/TOKEN'
        projected=o.project_owner(row)
        self.assertNotIn('PRIVATE',json.dumps(projected)); self.assertNotIn('private.invalid',json.dumps(projected))
        self.assertEqual(s.error(ValueError('PRIVATE URL')),{'kind':'ValueError'})

    def test_duplicate_nonfinite_and_oversize_public_metadata_refused(self):
        path=self.root/'bad.json'
        for raw in (b'{"status":1,"status":2}',b'{"x":NaN}',b' '*131073):
            path.write_bytes(raw)
            with self.assertRaises(s.Refused): s.read(path)

    def run_case(self, mode, missed=False, bad_cleanup=False):
        out=self.root/mode
        query=Query(); proc=Mock(); proc.returncode=None; proc.pid=12345
        proc.poll.side_effect=lambda:proc.returncode
        cancelled=[]
        def spawn(*argv,**kwargs):
            self.assertTrue(kwargs['start_new_session']); self.assertNotIn('CACHY_',str(kwargs['env']))
            return proc
        def send(sig):
            self.assertEqual(sig,signal.SIGTERM); cancelled.append(True)
        def wait(timeout):
            owner=out/'owner'; owner.mkdir(exist_ok=True)
            row=receipt(normal=not cancelled)
            if bad_cleanup: row['cleanup']['status']='FAIL'
            (owner/'result.json').write_text(json.dumps(row))
            proc.returncode=130 if cancelled else 0; return proc.returncode
        proc.wait.side_effect=wait; proc.send_signal.side_effect=send
        observation=None if missed else dict(self.active['active_executor'],token=TOKEN,running=True)
        module=SimpleNamespace(Docker=lambda _:query,LABEL=LABEL)
        with patch.object(o.subprocess,'Popen',side_effect=spawn), patch.object(o,'wait_active',return_value=observation), \
             patch.object(o.os,'killpg',side_effect=ProcessLookupError):
            row=o.case(mode,module,self.root,self.root/'context',out,TRANSACTION)
        return row,cancelled,proc

    def test_case_running_cancel_requires_nonzero_cancelled_owner_and_cleanup(self):
        row,cancelled,proc=self.run_case('cancel')
        self.assertEqual(row['status'],'PASS_ACTIVE_TRANSACTION_CANCELLATION'); self.assertEqual(cancelled,[True])
        self.assertTrue(row['owner_process']['reaped']); self.assertTrue(row['owner_process']['owner_session_absent'])
        self.assertEqual(row['independent_absence']['status'],'PASS')

    def test_case_finished_before_observation_is_NOT_ESTABLISHED_without_TERM(self):
        row,cancelled,proc=self.run_case('cancel',missed=True)
        self.assertEqual(row['status'],'NOT_ESTABLISHED'); self.assertEqual(cancelled,[])

    def test_normal_optional_execution_requires_real574_receipt_and_exit0(self):
        row,cancelled,proc=self.run_case('normal')
        self.assertEqual(row['status'],'PASS_NORMAL_OPTIONAL_574'); self.assertEqual(cancelled,[])
        self.assertEqual(row['owner']['packages'],574); self.assertEqual(row['independent_absence']['images_absent'],2)

    def test_case_cleanup_FAIL_never_becomes_trial_PASS(self):
        row,_,_=self.run_case('cancel',bad_cleanup=True)
        self.assertEqual(row['status'],'FAIL')

    def test_owner_finished_race_does_not_become_running_evidence(self):
        path=self.root/'result.json'; path.write_text(json.dumps({'phase':'completed'}))
        proc=Mock(); proc.poll.side_effect=[None,0]
        with patch.object(o,'active',side_effect=ValueError('container already removed')):
            self.assertIsNone(o.wait_active(proc,self.query,path,TRANSACTION,LABEL,1e99))

    def test_observation_deadline_refuses_without_sending_TERM_to_other_processes(self):
        proc=Mock(); proc.poll.return_value=None
        with patch.object(o.time,'monotonic',return_value=10), self.assertRaises(s.Refused):
            o.wait_active(proc,self.query,self.root/'absent.json',TRANSACTION,LABEL,5)
        proc.send_signal.assert_not_called()

    def test_stop_reaps_only_own_child_and_marks_forced_kill_unacceptable(self):
        proc=Mock(pid=12345); proc.returncode=None; proc.poll.return_value=None
        def wait(timeout):
            if timeout==600: raise subprocess.TimeoutExpired('inert',600)
            proc.returncode=-9; return -9
        proc.wait.side_effect=wait
        with patch.object(o.os,'killpg',side_effect=[None,ProcessLookupError]) as kill:
            row=o.stop(proc)
        proc.send_signal.assert_called_once_with(signal.SIGTERM)
        self.assertEqual(kill.call_args_list[0].args,(12345,signal.SIGKILL))
        self.assertTrue(row['forced_kill']); self.assertTrue(row['reaped'])

    def test_lingering_owner_session_is_reported_not_ignored(self):
        proc=Mock(pid=12345); proc.returncode=0; proc.poll.return_value=0
        with patch.object(o.os,'killpg'):
            row=o.stop(proc)
        self.assertFalse(row['owner_session_absent']); proc.send_signal.assert_not_called()

    def test_acquisition_uses_held_plan_fetch_configure_and_final_context_gate(self):
        rows=[{'filename':'fixed-'+str(i),'target':self.root/str(i)} for i in range(3)]
        calls=[]
        held=SimpleNamespace(plan=lambda *a:rows,fetch=lambda row:calls.append(row['filename']),configure=Mock())
        owner=SimpleNamespace(private=lambda _:None,context=Mock(return_value=(TRANSACTION,'one 1\n')))
        def module(ci,name): return held if name=='maintained_desktop574.py' else owner
        with patch.object(p.s,'load',side_effect=module), patch.object(p.s,'pinned'), patch.object(p.s,'read',return_value=({},{})):
            row=p.acquire(self.root,self.root)
        self.assertEqual(row['status'],'PREPARED_EXACT_574_CONTEXT'); self.assertEqual(row['acquired'],3)
        self.assertCountEqual(calls,['fixed-0','fixed-1','fixed-2']); held.configure.assert_called_once(); owner.context.assert_called_once()

    def test_acquisition_failures_are_counted_sanitized_and_never_silently_skipped(self):
        rows=[{'filename':'fixed-'+str(i),'target':self.root/str(i)} for i in range(40)]
        def fetch(_): raise OSError('PRIVATE URL TOKEN')
        held=SimpleNamespace(plan=lambda *a:rows,fetch=fetch,configure=Mock())
        owner=SimpleNamespace(private=lambda _:None,context=Mock())
        with patch.object(p.s,'load',side_effect=lambda ci,name:held if name=='maintained_desktop574.py' else owner), \
             patch.object(p.s,'pinned'), patch.object(p.s,'read',return_value=({},{})):
            row=p.acquire(self.root,self.root)
        self.assertEqual(row['status'],'FAIL'); self.assertEqual(row['failure_count'],40)
        self.assertEqual(len(row['failures']),32); self.assertTrue(row['failures_truncated'])
        self.assertNotIn('PRIVATE',json.dumps(row)); held.configure.assert_not_called(); owner.context.assert_not_called()

    def test_public14_seed_pins_both_sources_and_targets_existing_six_cache(self):
        owner=SimpleNamespace(private=lambda _:None)
        def command(argv,log,env,seconds):
            self.assertEqual(argv[-2:],['--cache',str(self.root/'context/deps')])
            self.assertEqual(seconds,120); self.assertFalse(any(k.startswith('CACHY_') for k in env))
            log.write_text(json.dumps({'status':'SEEDED_EXACT_PUBLIC_INPUTS','files':14,'copied':14,'existing':0}))
        owner.command=command
        with patch.object(p.s,'load',return_value=owner), patch.object(p.s,'read',return_value=({'status':'SIX_EXACT_EXISTING_SEED_FILES_READY','seeded_files':6},{})), patch.object(p.s,'pinned') as pins:
            row=p.public_seed(self.root,self.root,self.root/'public-assets')
        self.assertEqual(row['files'],14); self.assertEqual(pins.call_count,2)
        self.assertEqual(row['source_commit'],s.PUBLIC_COMMIT)

    def test_source_contract_has_only_manual_workflow_and_exact_existing_secret_set(self):
        proposed=HERE.parents[2]
        workflow=(proposed/'.github/workflows/native-arm-maintained574-active-cancellation.yml').read_text()
        import re
        secrets=set(re.findall(r'secrets\.([A-Z0-9_]+)',workflow))
        expected={'CACHY_OLD_FOUR_'+name for name in ('JBIGKIT_01','JBIGKIT_02','JBIGKIT_SIG_01','LIBTIFF_SIG_01')}
        expected|={'CACHY_OLD_FOUR_LIBTIFF_%02d'%i for i in range(1,16)}
        expected|={'CACHY_RETAINED_BUBBLEWRAP_V1_'+name for name in ('PACKAGE_01','PACKAGE_02','SIGNATURE_01')}
        self.assertEqual(secrets,expected); self.assertEqual(len(secrets),22)
        self.assertIn('workflow_dispatch:',workflow); self.assertNotIn('schedule:',workflow)
        sequence=(HERE/'ci_sequence.sh').read_text()
        self.assertNotIn('maintained_desktop574.py" build',sequence)
        self.assertIn('unset "$task_key"',sequence); self.assertIn('env -i',sequence)

    def test_dirty_preparation_environment_refused_before_loading_helpers(self):
        argv=['prepare.py','acquire','--source-ci',str(self.root),'--base',str(self.root),'--public-output',str(self.root/'public.json')]
        with patch.object(sys,'argv',argv), patch.dict(p.os.environ,{'CACHY_OLD_FOUR_LIBTIFF_01':'PRIVATE'}), \
             patch.object(p.s,'load') as loader, self.assertRaises(s.Refused):
            p.main()
        loader.assert_not_called()

    def test_original_owner_pair_and_held_sources_remain_exact(self):
        root=next(v for v in HERE.parents if (v/'scripts/ci/maintained_desktop574.py').is_file())
        for name,pin in s.PINS.items():
            path=HERE.parent/name
            if not path.exists():path=root/'scripts/ci'/name
            if not path.exists():
                path=root/'artifacts/development/maintained574-active-cancellation-20261016/proposed/scripts/ci'/name
            s.pinned(path,pin)


class DiagnosticControls(unittest.TestCase):
    def diagnostic(self):
        import base64
        raw=b'bounded transaction failure\n'
        return dict(returncode=7,log_bytes=len(raw),tail_bytes=len(raw),tail_sha256=s.sha(raw),
                    tail_base64=base64.b64encode(raw).decode())

    def test_exact_build_tail_is_projected(self):
        value=receipt();value['build_failure']=self.diagnostic()
        self.assertEqual(o.project_owner(value)['build_failure'],value['build_failure'])

    def test_drift_oversize_wrong_phase_or_extra_fields_refuse(self):
        for field,changed in (('tail_sha256','0'*64),('tail_bytes',4097),('tail_base64','x'*5465),('returncode',0)):
            value=receipt();value['build_failure']=self.diagnostic();value['build_failure'][field]=changed
            with self.subTest(field=field),self.assertRaises((s.Refused,ValueError)):o.project_owner(value)
        value=receipt(normal=True);value['build_failure']=self.diagnostic()
        with self.assertRaises(s.Refused):o.project_owner(value)
        value=receipt();value['build_failure']=dict(self.diagnostic(),private='excluded')
        with self.assertRaises(s.Refused):o.project_owner(value)


class TrustMetadataControls(unittest.TestCase):
    def value(self):
        import base64
        value=receipt();raw=b'ValueError: ordinary bounded producer trust/config required\n'
        value['build_failure']={'returncode':1,'log_bytes':len(raw),'tail_bytes':len(raw),'tail_sha256':s.sha(raw),
                                'tail_base64':base64.b64encode(raw).decode()}
        rows=[{'path':path,'status':'HTTP_ERROR','http_status':404} for path in o.TRUST_PATHS]
        rows[-1]={'path':'/etc/pacman.conf','status':'PRESENT','archive_type':'regular','uid':1001,'gid':1001,
                  'mode':0o644,'bytes':100,'fails_regular_uid_size_predicate':True}
        value['trust_metadata']={'status':'OBSERVED','method':'fixed-path-docker-archive-headers','rows':rows,
                                 'container':dict(value['cleanup']['captured_containers'][0])}
        return value

    def test_fixed_metadata_is_projected_without_accepting_failed_transaction(self):
        value=self.value();projected=o.project_owner(value)
        self.assertEqual(projected['trust_metadata'],value['trust_metadata'])
        self.assertEqual(projected['status'],'FAIL');self.assertEqual(projected['cleanup']['status'],'PASS')

    def test_wrong_path_contents_numeric_claims_container_or_scope_refuse(self):
        for field,changed in (('path','/root/.ssh/id_ed25519'),('uid',-1),('bytes',2**64),
                              ('fails_regular_uid_size_predicate',False),('contents','PRIVATE')):
            value=self.value();value['trust_metadata']['rows'][-1][field]=changed
            with self.subTest(field=field),self.assertRaises(s.Refused):o.project_owner(value)
        value=self.value();value['trust_metadata']['container']['cid']='f'*64
        with self.assertRaises(s.Refused):o.project_owner(value)
        value=self.value();del value['build_failure']
        with self.assertRaises(s.Refused):o.project_owner(value)

    def test_unavailable_diagnostic_does_not_waive_failure_or_cleanup_guard(self):
        value=self.value();value['trust_metadata']={'status':'UNAVAILABLE','method':'fixed-path-docker-archive-headers',
                                                   'rows':[],'error_kind':'TimeoutError'}
        projected=o.project_owner(value)
        self.assertEqual(projected['status'],'FAIL');self.assertEqual(projected['trust_metadata']['rows'],[])
        value['trust_metadata']['private']='PRIVATE'
        with self.assertRaises(s.Refused):o.project_owner(value)


class CopyMetadataControls(unittest.TestCase):
    def test_execution_requires_full_root_owned_copy_and_critical_control_modes(self):
        value=receipt(normal=True)
        self.assertEqual(o.project_owner(value)['copy_metadata'],value['copy_metadata'])
        del value['copy_metadata']
        with self.assertRaises(s.Refused):o.project_owner(value)

    def test_wrong_owner_count_mode_hash_or_container_refuses(self):
        for field,changed in (('uid',1001),('files_verified',1154),('archive',{'bytes':2**32,'sha256':'a'*64})):
            value=receipt();value['copy_metadata'][field]=changed
            with self.subTest(field=field),self.assertRaises(s.Refused):o.project_owner(value)
        value=receipt();value['copy_metadata']['controls'][0]['mode']=0o600
        with self.assertRaises(s.Refused):o.project_owner(value)
        value=receipt();value['copy_metadata']['controls'][-1]['sha256']='0'*64
        with self.assertRaises(s.Refused):o.project_owner(value)
        value=receipt();value['copy_metadata']['container']['cid']='f'*64
        with self.assertRaises(s.Refused):o.project_owner(value)


if __name__=='__main__': unittest.main()
