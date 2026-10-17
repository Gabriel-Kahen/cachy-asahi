"""Inert management/profile adapter controls; no GUI, package, service, VM or network actor."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import native_contract as N
import candidates as A
import prepare as P
import management_contract as C
import management_root as R
import management_phase as G
from test_doctor_lifetime import Lifetime

ROOT=Path(os.environ.get('WELCOME_MANAGEMENT_SOURCE',Path(__file__).resolve().parents[3]))
HERE=Path(__file__).resolve().parent
UI=dict(labels=dict(management='Management',doctor='Run Doctor',orphans='Assess orphan packages'),
    strings=dict(running='Running check…',complete='Elapsed:',failure='Check failed.',unavailable='The optional tool is not installed or executable. This check is unavailable.'),
    raw_preview_suffix='\n[Raw preview truncated at 64 KiB.]',max_output_bytes=1024**2,
    orphan_preview_bytes=8192,orphan_preview_suffix='\n[Raw preview truncated at 8 KiB.]')


def node(text,*,name='',enabled=True,showing=True):
    raw=text.encode();return dict(name_base64=base64.b64encode(name.encode()).decode(),role=43,showing=showing,selected=False,checked=False,enabled=enabled,sensitive=enabled,
        body_base64=base64.b64encode(raw).decode(),text_sha256=C.sha(raw),text_bytes=len(raw))


def child(tool='orphans',pid=100,parent=90,welcome=80,stopped=False):
    argv=['/usr/bin/cachy-asahi-'+tool,'--json' if tool=='doctor' else 'assess']
    return dict(pid=pid,starttime=1000+pid,supervisor_pid=parent,welcome_pid=welcome,uid=[23001]*4,pgid=pid,stopped=stopped,
        argv=argv,raw_argv=['/usr/bin/python3',*argv],exe='/usr/bin/python3.14',original_executable=argv[0])


def scroll_proof(label,pid=80):
    chain=[dict(pid=pid,role=role,visible=True,showing=True,rect=rect) for role,rect in
        ((43,[44,401,202,34]),(68,[5,97,990,448]),(49,[5,97,990,448]),(23,[0,0,1000,550]))]
    proof=dict(status='PASS',pid=pid,actions=0,interface='Component',action_name='ensure-visible',scroll_called=True,
        scroll_returned=False,focus_called=False,focused=False,unclipped_after_scroll=True,method='ALREADY_UNCLIPPED',
        coordinate_space='ATSPI_SCREEN',name_base64=base64.b64encode(label.encode()).decode(),chain=chain)
    window=dict(pid=pid,mapped=True,visible=True,floating=True,hidden=False,xwayland=False,at=[12,12],size=[1000,550],
        title='cachy-asahi Welcome',**{'class':'cachy-asahi-welcome'},address='0x123')
    return proof,window



def retirement(closing,inventory):
    fast=dict(nonce='a'*32,sequence=86,operation='retired',status='PASS',process=closing,
        helper_absent=True,supervisor_absent=True,group_absent=True,group_members=[],group_members_clipped=False)
    proof=dict(fast,sequence=87,operation='retired-proof',inventory=inventory,nonselected_database='PRESERVED')
    return fast,proof


def events():
    inventory={'fixture-'+str(i):'1' for i in range(594)}
    doctor=dict(tool='cachy-asahi-doctor',scope='local observations only',checks=[dict(state='checked')],coverage=dict(checked=1,unknown=0,unavailable=0))
    orphan=dict(scope=C.SCOPE,apply_supported=False,root='/',dbpath='/var/lib/pacman',candidates=[],broken_dependencies=[],packages={n:dict(version=v,candidate=False) for n,v in inventory.items()})
    refusal=dict(verification='REFUSED',apply_supported=False,reason='existing ALPM lock: active or uncertain; readonly assessment refused')
    rows=[]
    for stage in ('minimal','overlay'):
        reports={};actions=[]
        for label,scope,scroll in C.action_plan(UI):
            proof,window=scroll_proof(label) if scroll else (dict(status='PASS',pid=80,actions=1,action_name='click'),None)
            actions.append(dict(event='management_action',stage=stage,sequence=len(actions)+1,pid=80,label=label,scope=scope,scroll=scroll,proof=proof,window=window,physical_input='NOT_RUN'))
        rows.extend(actions[:2])
        for view in C.MANAGEMENT_VIEWS:
            kind=view.removeprefix('management-')
            if kind=='absent':expected=dict(text=[UI['strings']['unavailable']],buttons={UI['labels']['doctor']:False,UI['labels']['orphans']:False})
            elif kind=='closing':
                rows.extend(actions[-2:]);expected=dict(text=[UI['strings']['running']],buttons={UI['labels']['orphans']:False})
            else:
                start=3+4*('doctor','orphans','failure').index(kind)
                if kind=='doctor':rows.append(actions[2])
                rows.extend(actions[start:start+3]);tool='doctor' if kind=='doctor' else 'orphans'
                raw=C.encoded(dict(doctor=doctor,orphans=orphan,failure=refusal)[kind]);_,summary=C.report(raw,kind,inventory)
                expected=dict(text=[UI['strings']['failure' if kind=='failure' else 'complete'],summary,C.preview(raw,UI,kind)],buttons={UI['labels'][tool]:True})
                reports[kind]=dict(base64=base64.b64encode(raw).decode(),sha256=C.sha(raw),bytes=len(raw),gui_process=child(tool))
                if kind=='doctor':reports[kind]['gui_report']=dict(base64=base64.b64encode(raw).decode(),sha256=C.sha(raw),bytes=len(raw))
            nodes=[node(text) for text in expected['text']]+[node('',name=label,enabled=enabled) for label,enabled in expected['buttons'].items()]
            snap=dict(status='PASS',pid=80,nodes=nodes)
            semantic=dict(snapshot=snap,snapshot_sha256=C.sha(C.encoded(snap)),expected=expected,summary=C.snapshot(snap,80,view,expected))
            rows.append(dict(event='frame_ready',stage=stage,view=view,welcome_pid=80,semantic=semantic,capture_after_ms=5000,hardware='NOT_RUN',physical_input='NOT_RUN'))
            if kind in ('doctor','orphans','failure'):rows.append(actions[start+3])
        fast,proof=retirement(child(stopped=True),inventory)
        rows.append(dict(event='management_result',stage=stage,reports=reports,closing_process=child(stopped=True),welcome_exit=0,
            retirement_observation=fast,retirement_proof=proof,
            owned_group_absent=True,owned_helper_absent=True,owned_supervisor_absent=True,metadata_readonly=True,nonselected_database='PRESERVED',inventory=inventory,
            present_count=594,absent_count=592,scope='GENERIC4K_UNPRIVILEGED_ACTUAL_DEFAULT_TOOLS',hardware='NOT_RUN'))
    return rows,dict(status='VERIFIED_NATIVE_CANDIDATES',products={n:{} for n in N.NAMES},policy=dict(ui=UI))


def result(rows):return next(e for e in rows if e['event']=='management_result')


class Semantics(unittest.TestCase):
    def test_disabled_button_visibility_requires_owned_enabled_same_panel_peer(self):
        label=UI['labels']['orphans'];proof,window=scroll_proof(label)
        proof.update(method='PEER_FOCUS_SCROLL',unclipped_after_scroll=False,peer_focus_reply='REPLIED',peer_focus_error=None,peer_focus=dict(pid=80,role=62,name_base64='VmlldyByZXBvcnQ=',scope='Orphan assessment',
            enabled=True,sensitive=True,focused=True,same_panel=True,target_enabled=False,target_sensitive=False))
        C.visible_control(proof,80,label,window)
        for field,value in (('pid',81),('pid',80.0),('role',43),('scope','Doctor'),('name_base64',base64.b64encode(b'Other').decode()),
                            ('enabled',False),('focused',False),('focused',1),('sensitive',False),('same_panel',False),('target_enabled',True),('target_sensitive',True)):
            bad=copy.deepcopy(proof);bad['peer_focus'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):C.visible_control(bad,80,label,window)
        bad=copy.deepcopy(proof);bad['chain'][1]['rect'][3]=50
        with self.assertRaises(ValueError):C.visible_control(bad,80,label,window)
        with self.assertRaises(ValueError):C.visible_control(proof,80,'Open Files',window)
    def test_peer_focus_cannot_replace_original_target_or_claim_target_focus(self):
        label=UI['labels']['orphans'];proof,window=scroll_proof(label)
        proof['peer_focus']={}
        with self.assertRaises(ValueError):C.visible_control(proof,80,label,window)
        driver=(HERE/'a11y_driver.c').read_text()
        for text in ('a == b','actual peer focused state','disabled target state preserved','check(settled_geometry(pid, &value)',
                     'peer_matches == 1','role == ATSPI_ROLE_TOGGLE_BUTTON'):
            self.assertIn(text,driver)
        self.assertNotIn('gtk_widget_set_sensitive',driver)
    def test_visibility_requires_genuine_component_or_unclipped_or_focused_geometry(self):
        label=UI['labels']['orphans'];proof,window=scroll_proof(label)
        C.visible_control(proof,80,label,window)
        proof.update(method='COMPONENT_SCROLL',scroll_returned=True);C.visible_control(proof,80,label,window)
        proof.update(method='FOCUS_SCROLL',scroll_returned=False,focus_called=True,focused=True,unclipped_after_scroll=False)
        C.visible_control(proof,80,label,window)
        for field,value in (('focused',False),('focus_called',False),('unclipped_after_scroll',True)):
            bad=copy.deepcopy(proof);bad[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):C.visible_control(bad,80,label,window)
    def test_false_scroll_cannot_hide_clipping_sentinel_missing_owner_or_window(self):
        label=UI['labels']['orphans'];proof,window=scroll_proof(label)
        for edit in ('clipped','sentinel','hidden','foreign','missing-viewport','name','old-proof','window'):
            bad=copy.deepcopy(proof);native=copy.deepcopy(window)
            if edit=='clipped':bad['chain'][1]['rect']=[5,97,990,300]
            elif edit=='sentinel':bad['chain'][1]['rect'][0]=-2147483648
            elif edit=='hidden':bad['chain'][1]['showing']=False
            elif edit=='foreign':bad['chain'][1]['pid']=81
            elif edit=='missing-viewport':bad['chain'].pop(1)
            elif edit=='name':bad['name_base64']=base64.b64encode(b'Run Doctor').decode()
            elif edit=='old-proof':bad=dict(status='PASS',pid=80,actions=0,interface='Component',action_name='scroll-anywhere')
            else:native['mapped']=False
            with self.subTest(edit=edit),self.assertRaises(ValueError):C.visible_control(bad,80,label,native)
    def test_final_ui_binding_required(self):
        C.interface(dict(ui=UI))
        for key in UI:
            bad=copy.deepcopy(UI);bad.pop(key)
            with self.subTest(key=key),self.assertRaises(ValueError):C.interface(dict(ui=bad))
    def test_actual_text_hash_and_optional_disabled_state(self):
        value=dict(status='PASS',pid=80,nodes=[node('unavailable',name=UI['labels']['orphans'],enabled=False)])
        C.snapshot(value,80,'management-absent',dict(text=['unavailable'],buttons={UI['labels']['orphans']:False}))
        for field in ('enabled','sensitive','body_base64','text_sha256'):
            bad=copy.deepcopy(value);bad['nodes'][0][field]=True if field in ('enabled','sensitive') else '0'*64
            with self.subTest(field=field),self.assertRaises(Exception):C.snapshot(bad,80,'management-absent',dict(text=['unavailable'],buttons={UI['labels']['orphans']:False}))
    def test_root_profile_owner_is_once_ordered_and_requires_previous_retirement(self):
        profiles={};retired=set()
        with patch.object(R.DL,'parent',side_effect=lambda stage,nonce:dict(stage=stage,profile_nonce=nonce)) as issue:
            with self.assertRaises(ValueError):R.issue_profile(profiles,retired,'overlay','b'*32)
            R.issue_profile(profiles,retired,'minimal','a'*32)
            with self.assertRaises(ValueError):R.issue_profile(profiles,retired,'minimal','a'*32)
            with self.assertRaises(ValueError):R.issue_profile(profiles,retired,'overlay','b'*32)
            retired.add('minimal')
            with self.assertRaises(ValueError):R.issue_profile(profiles,retired,'overlay','a'*32)
            R.issue_profile(profiles,retired,'overlay','b'*32)
            with self.assertRaises(ValueError):R.issue_profile(profiles,retired,'overlay','b'*32)
            self.assertEqual(issue.call_count,2)
    def test_full_finite_management_receipt_replays(self):
        rows,lock=events();self.assertEqual(C.verify_result(rows,lock)['status'],'PASS_MANAGEMENT_NATIVE_METADATA_PIXELS_PENDING_REVIEW')
    def test_missing_firstframe_or_duplicate_view_refuses(self):
        rows,lock=events()
        for i in [j for j,e in enumerate(rows) if e['event']=='frame_ready']:
            bad=copy.deepcopy(rows);bad.pop(i)
            with self.subTest(i=i),self.assertRaises(ValueError):C.verify_result(bad,lock)
        bad=copy.deepcopy(rows);bad.insert(0,copy.deepcopy(next(e for e in bad if e['event']=='frame_ready')))
        with self.assertRaises(ValueError):C.verify_result(bad,lock)
    def test_wrong_fixed_helper_wrong_user_or_nonretirement_refuses(self):
        rows,lock=events()
        for field,value in (('uid',[0]*4),('argv',['/tmp/fake','assess']),('stopped',False),('pgid',80)):
            bad=copy.deepcopy(rows);result(bad)['closing_process'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):C.verify_result(bad,lock)
        for field in ('owned_group_absent','owned_helper_absent','owned_supervisor_absent','metadata_readonly'):
            bad=copy.deepcopy(rows);result(bad)[field]=False
            with self.subTest(field=field),self.assertRaises(ValueError):C.verify_result(bad,lock)
    def test_raw_report_drift_scope_or_count_drift_refuses(self):
        rows,lock=events()
        bad=copy.deepcopy(rows);result(bad)['reports']['orphans']['sha256']='0'*64
        with self.assertRaises(ValueError):C.verify_result(bad,lock)
        for field,value in (('present_count',593),('absent_count',591),('scope','M2_PASS'),('hardware','PASS')):
            bad=copy.deepcopy(rows);result(bad)[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):C.verify_result(bad,lock)
    def test_action_and_exact_gui_state_replay_rejects_missing_or_forged_operations(self):
        rows,lock=events()
        for edit in ('missing','pid','scope','proof','state'):
            bad=copy.deepcopy(rows)
            if edit=='missing':bad.pop(0)
            elif edit=='state':
                frame=next(e for e in bad if e['event']=='frame_ready');frame['semantic']['expected']['buttons']={}
                frame['semantic']['summary']=C.snapshot(frame['semantic']['snapshot'],80,frame['view'],frame['semantic']['expected'])
            else:
                row=next(e for e in bad if e['event']=='management_action')
                if edit=='proof':row['proof']['actions']=0
                else:row[edit]=81 if edit=='pid' else 'arbitrary'
            with self.subTest(edit=edit),self.assertRaises(ValueError):C.verify_result(bad,lock)
    def test_doctor_uses_its_actual_gui_timestamp_and_report(self):
        rows,lock=events();row=result(rows)['reports']['doctor'];value=json.loads(base64.b64decode(row['base64']));value['collected_utc']='independent timestamp'
        raw=C.encoded(value);row.update(base64=base64.b64encode(raw).decode(),sha256=C.sha(raw),bytes=len(raw))
        C.verify_result(rows,lock)
        row['gui_report']['sha256']='0'*64
        with self.assertRaises(ValueError):C.verify_result(rows,lock)
    def test_root_counterpart_is_fixed_package_only_and_guarded(self):
        self.assertEqual(R.TOOLS,('cachy-asahi-doctor','cachy-asahi-orphans'))
        text=(HERE/'management_root.py').read_text();self.assertIn('base.guard(True)',text);self.assertNotIn('os.unlink',text)
        self.assertIn('alpm_trans_release',text);self.assertIn('signal.pidfd_send_signal',text)
        self.assertNotIn('shell=True',text);self.assertNotIn('nodeps',text)



class ClosingRetirement(unittest.TestCase):
    def test_metadata_runs_after_fast10s_with_both_raw_replies_retained(self):
        closing=child(stopped=True);inventory={'fixed':'1'};pending={};fast,proof=retirement(closing,inventory)
        clock=[0];phase=['fast'];calls=[]
        def request(operation):
            calls.append(operation)
            if operation=='retired':return fast
            self.assertEqual(phase[0],'preservation');clock[0]+=20;return proof
        def wait(probe,healthy,seconds,label):
            self.assertEqual((seconds,label),(10,'owned management group retirement'))
            healthy();until=clock[0]+seconds;self.assertLess(clock[0],until);value=probe()
            self.assertLess(clock[0],until);phase[0]='preservation';return value
        with patch.object(G,'request',side_effect=request):self.assertEqual(G.closing_retirement(wait,pending,closing,inventory),(fast,proof))
        self.assertEqual(clock[0],20);self.assertEqual(calls,['retired','retired-proof'])
        self.assertIs(pending['retirement_observation'],fast);self.assertIs(pending['retirement_proof'],proof)
        # Root's actual fast branch must not invoke either full metadata reader.
        with patch.object(R.select,'select',return_value=([10],[],[])),patch.object(R.Path,'glob',return_value=[]):
            read=unittest.mock.Mock(side_effect=AssertionError('metadata on fast path'))
            state=R.retirement_reply('retired',closing,10,20,None,read,read,{})
            self.assertTrue(state['group_absent']);read.assert_not_called()
            full=R.retirement_reply('retired-proof',closing,10,20,None,lambda:inventory,lambda:{}, {})
            self.assertEqual(full['inventory'],inventory);self.assertEqual(full['nonselected_database'],'PRESERVED')
    def test_real_fast_absence_failure_remains10s_failure_without_proof(self):
        closing=child(stopped=True);fast,_=retirement(closing,{})
        fast.update(helper_absent=False);pending={}
        def wait(probe,healthy,seconds,label):
            self.assertEqual(seconds,10)
            for _ in range(10):self.assertIsNone(probe())
            raise ValueError(label+' deadline')
        with patch.object(G,'request',return_value=fast) as request,self.assertRaisesRegex(ValueError,'retirement deadline'):
            G.closing_retirement(wait,pending,closing,{})
        self.assertEqual(request.call_count,10);self.assertTrue(all(c==unittest.mock.call('retired') for c in request.call_args_list))
        self.assertIs(pending['retirement_observation'],fast);self.assertNotIn('retirement_proof',pending)
        with patch.object(R.select,'select',return_value=([],[],[])),patch.object(R.Path,'glob',return_value=[]):
            read=unittest.mock.Mock(side_effect=AssertionError('proof before retirement'))
            with self.assertRaisesRegex(ValueError,'actual owned retirement'):R.retirement_reply('retired-proof',closing,10,20,None,read,read,{})
            read.assert_not_called()
    def test_full_proof_requires_current_identity_nonce_sequence_and_all_metadata(self):
        closing=child(stopped=True);inventory={'fixed':'1'};fast,proof=retirement(closing,inventory)
        C.retirement_proof(fast,proof,closing,inventory)
        for field,value in (('nonce','b'*32),('sequence',89),('operation','retired'),('process',dict(closing,starttime=2)),
                            ('inventory',{}),('nonselected_database','CHANGED'),('helper_absent',False),('supervisor_absent',1),
                            ('group_absent',False),('group_members',[222]),('group_members_clipped',True)):
            bad=copy.deepcopy(proof);bad[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):C.retirement_proof(fast,bad,closing,inventory)
        for field in ('inventory','nonselected_database','process','sequence'):
            bad=copy.deepcopy(proof);bad.pop(field)
            with self.subTest(missing=field),self.assertRaises(ValueError):C.retirement_proof(fast,bad,closing,inventory)
        rows,lock=events()
        for field in ('retirement_observation','retirement_proof'):
            bad=copy.deepcopy(rows);result(bad).pop(field)
            with self.subTest(receipt=field),self.assertRaises(ValueError):C.verify_result(bad,lock)
    def test_preservation_failure_keeps_both_raw_replies_and_original_bounds(self):
        closing=child(stopped=True);fast,proof=retirement(closing,{});proof['nonselected_database']='CHANGED';pending={}
        with patch.object(G,'request',side_effect=[fast,proof]),self.assertRaisesRegex(ValueError,'nonselected metadata'):
            G.closing_retirement(lambda probe,healthy,seconds,label:probe(),pending,closing,{})
        self.assertIs(pending['retirement_observation'],fast);self.assertIs(pending['retirement_proof'],proof)
        self.assertEqual(len(C.action_plan(UI)),17);self.assertEqual(len(C.VIEWS),12)
        self.assertIn('time.monotonic()+90',(HERE/'management_phase.py').read_text())
        self.assertIn("management_root.serve(managed_base, session, env, logs, DL.service_lease()['deadline_ns'])",(HERE/'prepare.py').read_text())
        source=(HERE/'management_phase.py').read_text()
        self.assertIn("stable()==closing_before and not Path('/var/lib/pacman/db.lck').exists()",source)
        self.assertIn('until=time.monotonic()+45',source)


class ReportReadiness(unittest.TestCase):
    def test_live_helper_or_supervisor_does_not_launch_snapshot(self):
        for helper,supervisor in ((False,False),(False,True),(True,False)):
            with self.subTest(helper=helper,supervisor=supervisor),patch.object(G,'request',return_value=dict(helper_absent=helper,supervisor_absent=supervisor)) as request:
                snapshot=unittest.mock.Mock(side_effect=AssertionError('report snapshot must wait'))
                self.assertIsNone(G.completed_report_snapshot(snapshot));request.assert_called_once_with('observed')
                snapshot.assert_not_called()
    def test_exited_pidfds_only_allow_actual_snapshot_not_synthetic_success(self):
        raw=dict(status='PASS',pid=80,nodes=[])
        with patch.object(G,'request',return_value=dict(helper_absent=True,supervisor_absent=True)):
            snapshot=unittest.mock.Mock(return_value=raw)
            self.assertIs(G.completed_report_snapshot(snapshot),raw);snapshot.assert_called_once_with('snapshot')
            with self.assertRaises(ValueError):C.snapshot(raw,80,'management-orphans',dict(text=['Elapsed:']))
    def test_completion_state_is_typed_and_fail_closed(self):
        for state in ({},dict(helper_absent=1,supervisor_absent=True),dict(helper_absent=True,supervisor_absent='yes')):
            with self.subTest(state=state),patch.object(G,'request',return_value=state),self.assertRaises(ValueError):
                G.completed_report_snapshot(unittest.mock.Mock())
    def test_pidfd_readiness_is_nonblocking_and_does_not_signal_or_close(self):
        with patch.object(R.select,'select',side_effect=[([10],[],[]),([],[],[])]) as ready,patch.object(R.os,'close') as close,patch.object(R.signal,'pidfd_send_signal') as signal:
            self.assertEqual(R.completion(10,20),dict(helper_absent=True,supervisor_absent=False))
            self.assertEqual(ready.call_args_list,[unittest.mock.call([10],[],[],0),unittest.mock.call([20],[],[],0)])
            close.assert_not_called();signal.assert_not_called()
        with patch.object(R.select,'select') as ready:
            self.assertEqual(R.completion(None,None),dict(helper_absent=False,supervisor_absent=False));ready.assert_not_called()
    def test_actual_owned_pidfds_observe_both_process_exits(self):
        actors=[];fds=[]
        try:
            for _ in range(2):
                actor=subprocess.Popen([sys.executable,'-I','-B','-c',
                    "import sys;print('READY',flush=True);sys.stdin.buffer.read(1)"],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                actors.append(actor);self.assertEqual(actor.stdout.readline(),b'READY\n');fds.append(os.pidfd_open(actor.pid))
            self.assertEqual(R.completion(*fds),dict(helper_absent=False,supervisor_absent=False))
            actors[0].stdin.write(b'x');actors[0].stdin.flush();actors[0].wait(timeout=3)
            self.assertEqual(R.completion(*fds),dict(helper_absent=True,supervisor_absent=False))
            actors[1].stdin.write(b'x');actors[1].stdin.flush();actors[1].wait(timeout=3)
            self.assertEqual(R.completion(*fds),dict(helper_absent=True,supervisor_absent=True))
        finally:
            for actor in actors:
                if actor.poll() is None:actor.kill();actor.wait(timeout=3)
                for stream in (actor.stdin,actor.stdout,actor.stderr):stream.close()
            for fd in fds:os.close(fd)
    def test_same_deadline_all_operations_and_closing_view_are_preserved(self):
        text=(HERE/'management_phase.py').read_text()
        self.assertIn("hooks['wait'](probe,healthy,45 if deadline is None else remaining(deadline),'actual '+view)",text)
        self.assertIn("hooks['wait'](actual_doctor,healthy,remaining(report_until),'actual GTK Doctor report')",text)
        self.assertIn("report_until=open_completed_report(hooks['wait'],healthy,action,",text)
        self.assertIn("capture('management-'+kind,expected,report_until)",text)
        self.assertIn("if view in ('management-doctor','management-orphans','management-failure') else a11y('snapshot')",text)
        self.assertEqual(len(C.action_plan(UI)),17)
        self.assertEqual(len(C.VIEWS)*2,24)
        self.assertIn("observed('orphans',True)",text)


class FailureCleanup(unittest.TestCase):
    def fixture(self,directory,mode='missing'):
        from types import SimpleNamespace
        inputs=Path(directory);products={};baseline={'base':'1',**{n:'1' for n in R.TOOLS}}
        missing={n:v for n,v in baseline.items() if n not in R.TOOLS};state={'inventory':baseline if mode=='baseline' else missing,'commands':[]}
        for name in R.TOOLS:
            raw=(name+' original archive').encode();path=inputs/(name+'.pkg.tar.xz');path.write_bytes(raw)
            products[name]=dict(archive=path.name,sha256=C.sha(raw))
        def command(argv,timeout):
            self.assertEqual(argv,['pacman','--signed-fixture','-U',*[str(inputs/products[n]['archive']) for n in R.TOOLS]])
            self.assertEqual(timeout,60);state['commands'].append(argv);state['inventory']=baseline
        return SimpleNamespace(inventory=lambda:state['inventory'],command=command),products,baseline,state
    def test_removed_tools_restore_from_exact_signed_archives_after_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            L,products,baseline,state=self.fixture(directory)
            with patch.object(R,'INPUTS',Path(directory)),patch.object(R,'metadata',return_value={'kept':'exact'}):R.restore_profile(L,['pacman','--signed-fixture'],products,baseline,{'kept':'exact'})
            self.assertEqual(state['inventory'],baseline);self.assertEqual(len(state['commands']),1)
    def test_complete_profile_cleanup_does_not_reinstall(self):
        with tempfile.TemporaryDirectory() as directory:
            L,products,baseline,state=self.fixture(directory,'baseline')
            with patch.object(R,'INPUTS',Path(directory)),patch.object(R,'metadata',return_value={}):R.restore_profile(L,['pacman','--signed-fixture'],products,baseline,{})
            self.assertEqual(state['commands'],[])
    def test_archive_metadata_or_unknown_inventory_drift_refuses_cleanup_mutation(self):
        for case in ('archive','metadata','inventory'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as directory:
                L,products,baseline,state=self.fixture(directory);actual={}
                if case=='archive':(Path(directory)/products[R.TOOLS[0]]['archive']).write_bytes(b'changed')
                elif case=='metadata':actual={'changed':True}
                else:state['inventory']={**state['inventory'],'foreign':'1'}
                with patch.object(R,'INPUTS',Path(directory)),patch.object(R,'metadata',return_value=actual),self.assertRaises(ValueError):R.restore_profile(L,['pacman','--signed-fixture'],products,baseline,{})
                self.assertEqual(state['commands'],[])
    def test_main_failure_finally_uses_same_restoration_and_always_retires_key_agent(self):
        text=(HERE/'management_root.py').read_text()
        self.assertEqual(text.count('restore_profile(L,pacman,products,baseline,preserved)'),3)
        self.assertIn("finally:L.command(['/usr/bin/gpgconf'",text)


class Adapter(unittest.TestCase):
    def test_policy_is_unbound_before_staging(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'runner'
            unbound=N.policy(False);unbound.update(status='UNBOUND_FIXTURE',candidate_source=None)
            with patch.object(N,'read',return_value=unbound),self.assertRaisesRegex(ValueError,'UNBOUND'):P.prepare(ROOT,out,Path('/unused'))
            self.assertFalse(out.exists())
    def test_accepted_adapter_derives24_exact_frames_and_preserves_gates(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out=root/'runner'
            def stage(source,assets,output):
                output.mkdir();lock=dict(status='SYNTHETIC_TEMPLATE_CONTROL_ONLY',eligibility='PRIVATE_GUI_TRIAL_ONLY',products={},policy=dict(ui=UI))
                (output/'candidate-lock.json').write_bytes(N.encoded(lock));return lock
            with patch.object(N,'verify_source'),patch.object(A,'verify_source'),patch.object(N,'policy',return_value=dict(ui=UI)),patch.object(A,'stage',side_effect=stage):P.prepare(ROOT,out,root/'assets')
            for path in out.glob('*.py'):compile(path.read_text(),str(path),'exec')
            runtime=(out/'desktop574_runtime.py').read_text();guest=(out/'base_guest.py').read_text();session=(out/'session.py').read_text()
            self.assertIn("version={'cachy-asahi-doctor':'0.1.0-1','cachy-asahi-orphans':'0.1.0-2','cachy-asahi-welcome':'0.1.0-4'}[name]",(out/'gui_contract.py').read_text())
            for stage_name in ('minimal','overlay'):
                for view in C.VIEWS:self.assertIn(stage_name+'-'+view,runtime)
            self.assertIn('management_root.serve',guest);self.assertIn('managed_session.SETPRIV',guest);self.assertNotIn('dbus-run-session',guest)
            self.assertIn("guard(True)  # Never power off a host that failed the guest guard.\n    DL.service()",guest)
            self.assertLess(guest.index('    DL.service()'),guest.index('        EVENTS = wait_event_port()'))
            self.assertNotIn('DL.parent()',guest)
            self.assertIn("MG.request('profile',stage=stage,profile_nonce=nonce)",session)
            self.assertIn("MG.request('profile-retired',stage=stage,profile_nonce=nonce",session)
            self.assertIn('DL.start(workspace,stage,nonce,doctor.process.pid)',session)
            self.assertIn('DL.validate_profiles(profile_retirements)',(out/'contract.py').read_text())
            self.assertIn('MG.exercise',session);self.assertIn('welcome=actor',session)
            self.assertIn('LocalFileSigLevel = Required',runtime);self.assertIn('/tmp/products/TEST-public.asc',runtime)
            self.assertNotIn('test-signing',runtime);self.assertIn('time.monotonic() + 1300',runtime)
            self.assertIn('TimeoutStartSec=1200',(out/'desktop574_fixture.sh').read_text())
            subprocess.run(['/usr/bin/bash','-n',str(out/'desktop574_fixture.sh')],check=True,capture_output=True)
            import ast
            tree=ast.parse(runtime);writes=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='write_text' and n.args and isinstance(n.args[0],ast.JoinedStr)]
            docker=next(n.args[0] for n in writes if any(isinstance(v,ast.Constant) and isinstance(v.value,str) and v.value.startswith('FROM ') for v in n.args[0].values))
            rendered=''.join(v.value if isinstance(v,ast.Constant) else 'owned-base' for v in docker.values)
            run=next(line[4:] for line in rendered.splitlines() if line.startswith('RUN '))
            subprocess.run(['/usr/bin/bash','-n'],input=run,text=True,check=True,capture_output=True)
            self.assertIn("python3 -c 'import json;",run)
            proof=json.loads((out/'runner-proof.json').read_bytes());self.assertGreater(len(proof['files']),20)
            # Load the actual generated graph in separate isolated interpreters,
            # including the Doctor process which does not inherit guest modules.
            shadow=root/'shadow';shadow.mkdir()
            for name in ('management_contract','management_root','management_phase'):
                (shadow/(name+'.py')).write_text("raise RuntimeError('ambient module imported')\n")
            probe='''import importlib.util,json,runpy,sys
from pathlib import Path
root=Path(sys.argv[1]);entry=sys.argv[2];before=list(sys.path)
ns=runpy.run_path(str(root/entry),run_name='isolated_import_control')
load=ns['load'];base=load('isolated_base','base_guest.py')
assert base.management_root.C is sys.modules['management_contract']
assert Path(base.management_root.__file__)==root/'management_root.py'
if entry=='desktop574_guest.py':
    api=load('isolated_api','managed_session.py');session=load('isolated_session','session.py')
    assert session.MG.C is sys.modules['management_contract']
    assert session.C.MG is sys.modules['management_contract']
    assert Path(session.MG.__file__)==root/'management_phase.py'
else:
    assert ns['C'].MG is sys.modules['management_contract']
assert sys.path==before
assert all(Path(sys.modules[n].__file__)==root/(n+'.py') for n in
           ('management_contract','management_root'))
print(json.dumps(dict(status='PASS_ISOLATED_GENERATED_IMPORTS',entry=entry,actors='NOT_RUN',sys_path='UNCHANGED')))
'''
            for entry in ('desktop574_guest.py','doctor_worker.py'):
                with self.subTest(isolated_entry=entry):
                    result=subprocess.run([sys.executable,'-I','-B','-c',probe,str(out),entry],cwd=shadow,
                        env=dict(os.environ,PYTHONPATH=str(shadow)),text=True,capture_output=True,timeout=20,check=True)
                    self.assertEqual(json.loads(result.stdout)['status'],'PASS_ISOLATED_GENERATED_IMPORTS')

    def test_outer_deadlines_allow_the_original_gui_cleanup_budget(self):
        run=(HERE/'run.py').read_text();workflow=(HERE.parents[2]/'.github/workflows/native-arm-welcome-management.yml').read_text()
        self.assertIn("timeout=450 if log.name=='gui-runtime.log'",run)
        self.assertIn('setitimer(signal.ITIMER_REAL,3900)',run)
        self.assertIn('--kill-after=480s 4500s',workflow);self.assertIn('timeout-minutes: 85',workflow)
        self.assertGreater(4500,3900+450);self.assertGreater(85*60,4500+480)
    def test_source_observation_never_substitutes_helpers_or_gui_text(self):
        text=(HERE/'management_phase.py').read_text();self.assertIn("['/usr/bin/cachy-asahi-welcome']",text)
        self.assertIn('report_command(base,kind',text);self.assertNotIn('management_test_configure',text)
        self.assertNotIn('gtk_label_set_text',text);self.assertIn("request('lock')",text)
        self.assertIn("observed('orphans',True)",text);self.assertIn("close(current,False)",text)


if __name__=='__main__':unittest.main()
