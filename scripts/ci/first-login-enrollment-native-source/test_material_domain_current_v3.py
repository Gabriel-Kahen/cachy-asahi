# SPDX-License-Identifier: MIT
"""Fenced material physical-caller controls. No real actors, secrets or privilege."""
import contextlib
import copy
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

# The actual context fixture applies its finite test AS bound before the actor
# fence; it never performs an operational role or metadata query.
F=module('material_domain_context_fixture',HERE/'test_delegated_context_v4.py')
unittest.addModuleCleanup(F.BASE.cleanup)
M=module('material_domain_controls',HERE/'payload/native/material_domain_current_v3.py')
E=module('material_domain_held_executor_controls',HERE/'payload/native/owned_executor_current_v3.py')
S=module('material_domain_real_stager_controls',HERE/'payload/native/stage_materials_current_v3_python_v1.py')


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn'))or event in (
        'os.system','resource.setrlimit','fcntl.flock','os.setuid','os.setgid','os.setgroups','os.chown','os.kill','os.killpg'):
        raise AssertionError('FENCED material DATA only: '+event)

sys.addaudithook(fence)
NONCE='a'*64
MODEL_SCOPE_TOOLS={name:dict(path='/usr/bin/'+name,MODEL_ONLY=True)for name in ('python3','systemd-run','sudo')}


def natural(exit=0):return dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,exit=exit)


def physical_receipt(closing=False):
    return dict(kind='CLOSE'if closing else'STAGE',natural=True,supervision=natural(),scope_absence=dict(scope=M.scope_name(NONCE,closing),absent_twice=True),**M.FINAL)


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='FENCED-material-domain-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.control=self.root/'control';self.control.mkdir(mode=0o700)
        self.r=dict(control_root=str(self.control),shared_timing=dict(deadline_monotonic=time.monotonic()+4000,expires_epoch=time.time()+4000),context=dict(binding={'MODEL':'not-authority'}))
        self.d=dict(nonce=NONCE,issued_epoch=int(time.time())-10,expires_epoch=int(time.time())+7540,programs=dict(base_inputs={'MODEL':'only'}))
        self.g=dict(storage_parent=str(self.root/'input-domain'),expires_epoch=time.time()+4000)
    def session(self):
        value=M.MaterialSession(self.r,(self.root,self.d,{},self.g,E,S,SimpleNamespace()));return value
    def values(self):return {name:'INERT_MODEL_VALUE'for name in S.secret_names()}

    def test_actual_committed_dependency_bodies_and_separate_unissued_caps(self):
        self.assertEqual(M.pin(Path(E.__file__).read_bytes()),M.EXECUTOR_PIN)
        self.assertEqual(M.pin(Path(S.__file__).read_bytes()),M.STAGER_PIN)
        self.assertEqual(M.CLOSE_SECONDS,90);self.assertEqual(M.PROPOSAL['cleanup_seconds'],90)
        self.assertEqual(M.PROPOSAL['scope_limits'],S.SCOPE);self.assertEqual(M.PROPOSAL['controller_AS_bytes'],2*1024**3)
        self.assertIsNone(M.PROPOSAL['Root_issuance']);self.assertEqual(S.PROPOSAL['controller_AS_bytes'],2*1024**3)
        self.assertEqual(M.PROPOSAL['storage_bytes'],8*1024**3);self.assertLessEqual(M.PROPOSAL['filesystem_inodes'],20000)
        self.assertEqual(M.INPUT_METADATA['staging_base_lock']['member'],'bootstrap/scripts/ci/inputs.lock.json')

    def test_scope_vector_is_finite_and_close_never_extends_its_reservation(self):
        for closing,seconds in ((False,3600),(True,90),(True,12)):
            argv=M.scope_argv(Path('/MODEL/current.py'),Path('/MODEL/request'), 'b'*64,NONCE,seconds,closing)
            self.assertIn('--scope',argv);self.assertIn('--property=MemoryMax=536870912',argv)
            self.assertIn('--property=RuntimeMaxSec='+str(seconds)+'s',argv)
            self.assertIn('--property=TasksMax=64',argv);self.assertNotIn('docker',str(argv))
        for closing,seconds in ((False,3601),(True,91),(True,1)):
            with self.assertRaises(ValueError):M.scope_argv(Path('/MODEL/current.py'),Path('/MODEL/request'),'b'*64,NONCE,seconds,closing)

    def test_data_atime_changes_are_ignored_but_mutation_still_refuses(self):
        path=self.root/'relatime-DATA';path.write_bytes(b'MODEL')
        before=SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o600,st_uid=1001,st_gid=1001,st_nlink=1,st_size=5,st_mtime_ns=10,st_ctime_ns=20,st_atime_ns=30)
        after=copy.copy(before);after.st_atime_ns=999
        original=Path.lstat
        def status(p,*a,**kw):return after if p==path else original(p,*a,**kw)
        with patch.object(M.os,'fstat',side_effect=[before,after]),patch.object(Path,'lstat',status):self.assertEqual(M.read(path),b'MODEL')
        after.st_mtime_ns=999
        with patch.object(M.os,'fstat',side_effect=[before,after]),patch.object(Path,'lstat',status),self.assertRaises(ValueError):M.read(path)

    def test_substituted_stager_or_executor_refuses_before_import(self):
        for expected in (M.STAGER_PIN,M.EXECUTOR_PIN):
            row=dict(member='MODEL-unreviewed.py',bytes=expected['bytes'],sha256='0'*64)
            with patch.object(M.importlib.util,'spec_from_file_location',side_effect=AssertionError('no unreviewed program'))as imported:
                with self.assertRaises(ValueError):M.load(self.root,row,'MODEL',expected)
                imported.assert_not_called()

    def test_actual_scope_observer_refuses_foreign_group_or_changed_limits(self):
        good=dict(pid=123,starttime=456,cgroup='/system.slice/'+M.scope_name(NONCE),limits=M.SCOPE)
        with patch.object(E,'kernel_domain',return_value=good):self.assertEqual(M.actual_scope(E,NONCE,{}),good)
        for changed in (dict(good,cgroup='/FOREIGN'),dict(good,limits=dict(M.SCOPE,**{'memory.max':'max'})),dict(good,starttime=0)):
            with patch.object(E,'kernel_domain',return_value=changed),self.assertRaises(ValueError):M.actual_scope(E,NONCE,{})

    def test_scope_tool_selection_preserves_canonical_python_and_launcher_sudo_guard(self):
        def inspect(candidate):
            E.need(candidate in {p for rows in E.CANDIDATES.values()for p in rows},'finite existing executor candidates')
            return dict(path='/usr/bin/python3.14'if candidate=='/usr/bin/python3'else candidate)
        launcher=SimpleNamespace(fixed_tool=unittest.mock.Mock(return_value=dict(path='/usr/bin/sudo')))
        with patch.object(E,'inspect_tool',side_effect=inspect),patch.object(E,'checked_tool',side_effect=lambda row:row['path']),patch.object(M,'load',return_value=launcher):
            tools=M.scope_tools(self.root,dict(programs=dict(hosted_launcher={'MODEL':'pinned'})),E)
        launcher.fixed_tool.assert_called_once_with('/usr/bin/sudo')
        argv=M.scope_argv(Path('/MODEL/current.py'),Path('/MODEL/request'),'b'*64,NONCE,100,python_path=tools['python3']['path'])
        self.assertIn('/usr/bin/python3.14',argv)
        with patch.object(E,'inspect_tool',side_effect=[FileNotFoundError('MODEL absent'),dict(path='/usr/sbin/mkfs.ext4')]):
            self.assertEqual(M.observed_tool(E,'mkfs.ext4')['path'],'/usr/sbin/mkfs.ext4')
        with patch.object(E,'inspect_tool',side_effect=ValueError('MODEL present invalid'))as inspect:
            with self.assertRaises(ValueError):M.observed_tool(E,'mkfs.ext4')
            self.assertEqual(inspect.call_count,1)

    def test_root_stage_and_close_admin_receipts_use_disjoint_owned_namespaces(self):
        storage=M.RootStorage(self.r,E,None,self.g,self.d);storage.admin=self.root/'MODEL-admin'
        with patch.object(M,'observed_tool',side_effect=lambda executor,name:dict(path='/usr/bin/'+name)):
            storage.attach_engine();stage=storage.engine.work;storage.closing=True;storage.attach_engine();close=storage.engine.work
        self.assertNotEqual(stage,close);self.assertEqual(storage.engine.maximum,16)
        self.assertEqual(stage.parent,close.parent)

    def test_external_root_hash_refuses_before_selected_import(self):
        r=dict(delegation_raw='{}',delegation_sha256='0'*64,grant_raw='{}',grant_sha256='0'*64)
        with patch.object(M,'load',side_effect=AssertionError('no code before external authentication'))as load:
            with self.assertRaises(ValueError):M.authorize(r)
            load.assert_not_called()

    def test_actual_stager_grant_preserves_exact_scope_context_and_whole_lifetime(self):
        now=int(time.time());d=dict(nonce=NONCE,issued_epoch=now-10,expires_epoch=now+7500,capability=dict(allow_material_staging=True),
            policy=dict(member='policy',bytes=1,sha256='b'*64),context_limits=dict(max_context_age_seconds=7560,max_delegation_seconds=7560))
        c=dict(binding=dict(source='c'*40,ref='refs/heads/codex/MODEL',source_lock=dict(bytes=1,sha256='d'*64)))
        g=dict(schema=3,kind='ROOT_CURRENT_COMPLETE517_STAGING_V3',issuer='Root',approved=True,**c['binding'],nonce=NONCE,
            policy=M.descriptor(d['policy']),issued_epoch=now-5,expires_epoch=now+7400,redirect_urls={},secret_provider='CALLER_ONE_SHOT_EXACT22',scope='COMPLETE517_PUBLIC_DATA_ONLY',storage_parent='/var/lib/cachy-current-material-domain-'+NONCE)
        raw=M.encoded(g);self.assertEqual(S.validate_grant(raw,M.pin(raw)['sha256'],d,c,dict(material_staging_current_v3=S.PROPOSAL)),g)
        d['context_limits']['max_context_age_seconds']=300
        with self.assertRaises(ValueError):S.validate_grant(raw,M.pin(raw)['sha256'],d,c,dict(material_staging_current_v3=S.PROPOSAL))

    def test_real_scope_property_parser_rejects_extended_or_mismatched_domain(self):
        now=time.monotonic();t=dict(deadline_monotonic=now+100,expires_epoch=time.time()+100);scope=dict(cgroup='/MODEL/cgroup')
        props=dict(ControlGroup=scope['cgroup'],RuntimeMaxUSec='30s',ActiveEnterTimestampMonotonic=str(int(now*1000000)))
        raw=''.join(k+'='+v+'\n'for k,v in props.items()).encode();self.assertEqual(M.decoded_scope_properties(raw),props)
        self.assertLess(M.check_scope_properties(E,props,scope,t,90),t['deadline_monotonic'])
        for change in (dict(RuntimeMaxUSec='91s'),dict(ControlGroup='/FOREIGN'),dict(ActiveEnterTimestampMonotonic='0')):
            with self.assertRaises(ValueError):M.check_scope_properties(E,dict(props,**change),scope,t,90)
        t['deadline_monotonic']=now+31
        with self.assertRaises(ValueError):M.check_scope_properties(E,props,scope,t,90)
        with self.assertRaises(ValueError):M.decoded_scope_properties(raw+b'ControlGroup=duplicate\n')

    def test_scope_absence_requires_two_actual_absences_and_finite_cutoff(self):
        path=SimpleNamespace(name='MODEL.scope',exists=unittest.mock.Mock(side_effect=[True,False,False]))
        with patch.object(M,'scope_path',return_value=path),patch.object(M.time,'sleep'):
            self.assertTrue(M.absent(NONCE,time.monotonic()+1)['absent_twice']);self.assertEqual(path.exists.call_count,3)
        with patch.object(M,'scope_path',return_value=SimpleNamespace(exists=lambda:True)),patch.object(M.time,'monotonic',side_effect=[0,0,11]):
            with self.assertRaises(ValueError):M.absent(NONCE,100)

    def test_close_before_stage_submits_no_actor_or_storage_claim_for_foreign_domain(self):
        session=self.session()
        with patch.object(M,'absent',side_effect=lambda nonce,deadline,closing=False:dict(scope=M.scope_name(nonce,closing),absent_twice=True)),patch.object(session,'execute',side_effect=AssertionError('no role before staging')):
            receipt=session.close();self.assertFalse(receipt['submitted']);self.assertTrue(receipt['owned_storage_absent'])
        self.assertEqual(session.close(),receipt)

    def test_failed_or_incomplete_stage_never_returns_refs_and_clears_exact_values(self):
        session=self.session();values=self.values();environment={name:'INERT_PARENT'for name in S.secret_names()};environment['KEEP']='PUBLIC'
        with patch.dict(M.os.environ,environment,clear=True),patch.object(session,'execute',side_effect=ValueError('MODEL forced exit')):
            with self.assertRaises(ValueError):session.stage(secrets=values)
            self.assertEqual(dict(M.os.environ),{'KEEP':'PUBLIC'})
        self.assertEqual(values,{});self.assertEqual(session.state,'HOLD_CLOSEONLY')

    def test_public_retirement_projection_refuses_missing_false_or_wrong_scope_proofs(self):
        good=physical_receipt();result=M.scope_retirement(E,good,NONCE)
        self.assertEqual((result['natural'],result['scope_absent'],result['scope']),(True,True,M.scope_name(NONCE)))
        self.assertNotIn('argv',result);self.assertEqual(result['supervision_pin'],M.pin(M.encoded(good['supervision'])))
        for mutation in ('missing','natural','supervision','exit','signals','absence','false_absence','wrong_scope'):
            row=copy.deepcopy(good)
            if mutation=='missing':row={}
            elif mutation=='natural':row['natural']=False
            elif mutation=='supervision':row.pop('supervision')
            elif mutation=='exit':row['supervision']['exit']=2
            elif mutation=='signals':row['supervision']['signals']=[15]
            elif mutation=='absence':row.pop('scope_absence')
            elif mutation=='false_absence':row['scope_absence']['absent_twice']=False
            else:row['scope_absence']['scope']='FOREIGN.scope'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):M.scope_retirement(E,row,NONCE)

    def test_stage_missing_retirement_cannot_return_or_read_provider_refs(self):
        session=self.session();values=self.values()
        with patch.object(session,'execute',return_value=None),patch.object(M,'read',side_effect=AssertionError('no refs without recorded physical proof')):
            with self.assertRaises(ValueError):session.stage(secrets=values)
        self.assertEqual(values,{});self.assertEqual(session.state,'HOLD_CLOSEONLY')

    def test_public_close_refuses_missing_or_false_root_storage_observations(self):
        for mutation in ('missing_retirement','forced_close','storage','missing_stage_absence','false_stage_absence','wrong_stage_scope'):
            session=self.session();session.stage_submitted=True
            proof=physical_receipt(True)
            receipt=dict(owned_storage_absent=True,scope_absence=dict(scope=M.scope_name(NONCE),absent_twice=True),
                binding=self.r['context']['binding'],nonce=NONCE,request_pin=M.pin(M.encoded(self.r)),**M.FINAL)
            if mutation=='forced_close':proof['supervision']['exit']=2
            elif mutation=='storage':receipt['owned_storage_absent']=False
            elif mutation=='missing_stage_absence':receipt.pop('scope_absence')
            elif mutation=='false_stage_absence':receipt['scope_absence']['absent_twice']=False
            elif mutation=='wrong_stage_scope':receipt['scope_absence']['scope']='FOREIGN.scope'
            path=self.control/'material-domain-close.json';M.write(path,receipt)
            def execute(**kwargs):
                if mutation!='missing_retirement':session.receipts.append(proof)
            with self.subTest(mutation=mutation),patch.object(session,'execute',side_effect=execute),self.assertRaises(ValueError):session.close()
            self.assertEqual(session.state,'HOLD_CLOSEONLY');session.request.unlink();path.unlink()

    def test_scope_held_result_requires_natural_retirement_before_any_absence_claim(self):
        for mutation in ('signal','exit','timeout','incomplete'):
            session=self.session();values=self.values();outcome=dict(natural(),output=b'')
            if mutation=='signal':outcome['signals']=[15]
            elif mutation=='exit':outcome['exit']=2
            elif mutation=='timeout':outcome['timeout']=True
            else:outcome['output_complete']=False
            session.O=SimpleNamespace(prepare=lambda:None,supervise=lambda *a,**k:dict(outcome))
            @contextlib.contextmanager
            def stream():yield io.BytesIO()
            def private_input(v,names):
                try:yield io.BytesIO(b'MODEL ONLY')
                finally:v.clear()
            with patch.object(M,'scope_tools',return_value=MODEL_SCOPE_TOOLS),patch.object(E,'require_runtime_capabilities'),patch.object(E,'inspect_tool',return_value={'MODEL':True}),patch.object(E,'checked_tool',side_effect=['/usr/bin/python3','/usr/bin/systemd-run','/usr/bin/sudo']),patch.object(E,'stderr_buffer',stream),patch.object(M,'stderr_identity',return_value=('MODEL',)),patch.object(M,'retired_stderr',return_value=b''),patch.object(M,'sealed_secret_input',side_effect=private_input),patch.object(M.subprocess,'Popen',return_value=object()),patch.object(M,'absent',side_effect=AssertionError('no normal absence projection after forced result'))as absence:
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):session.execute(secrets=values)
                absence.assert_not_called()
            self.assertFalse(session.receipts[-1]['natural']);self.assertEqual(values,{})
            session.request.unlink()

    def test_expired_cleanup_refuses_before_privilege_and_clipped_cleanup_is_recorded(self):
        session=self.session();session.stage_submitted=True;session.r['shared_timing']['expires_epoch']=time.time()-1
        with patch.object(M,'scope_tools',return_value=MODEL_SCOPE_TOOLS),patch.object(E,'require_runtime_capabilities'),patch.object(E,'inspect_tool',return_value={}),patch.object(E,'checked_tool',side_effect=['/usr/bin/python3','/usr/bin/systemd-run','/usr/bin/sudo']),patch.object(M.subprocess,'Popen',side_effect=AssertionError('no expired privilege'))as spawn:
            with self.assertRaises(ValueError):session.execute(closing=True)
            spawn.assert_not_called()
        self.assertEqual(session.state,'OPEN')

    def test_clipped_cleanup_uses_remaining_budget_and_actual_absence_receipt(self):
        session=self.session();session.stage_submitted=True
        session.r['shared_timing']=dict(deadline_monotonic=1040,expires_epoch=2040);session.g['expires_epoch']=2040
        session.request.unlink();M.write(session.request,session.r)
        calls=[];session.O=SimpleNamespace(prepare=lambda:calls.append('prepare'),supervise=lambda *a,**kw:dict(natural(),output=b''))
        @contextlib.contextmanager
        def errors():yield io.BytesIO()
        with patch.object(M,'scope_tools',return_value=MODEL_SCOPE_TOOLS),patch.object(M.time,'monotonic',return_value=1000),patch.object(M.time,'time',return_value=2000),patch.object(E,'require_runtime_capabilities'),patch.object(E,'inspect_tool',return_value={}),patch.object(E,'checked_tool',side_effect=['/usr/bin/python3','/usr/bin/systemd-run','/usr/bin/sudo']),patch.object(E,'stderr_buffer',errors),patch.object(M,'stderr_identity',return_value=('MODEL',)),patch.object(M,'retired_stderr',return_value=b''),patch.object(M.subprocess,'Popen',side_effect=lambda argv,**kw:calls.append(argv)or object()),patch.object(M,'absent',return_value=dict(absent_twice=True,scope='MODEL')):
            receipt=session.execute(closing=True)
        self.assertTrue(receipt['natural']);self.assertTrue(receipt['scope_absence']['absent_twice'])
        self.assertIn('--property=RuntimeMaxSec=25s',calls[1]);self.assertEqual(calls[0],'prepare')
        self.assertIsNone(receipt['Root_final_acceptance'])

    def test_successful_stage_preserves_refs_until_explicit_close_handoff(self):
        session=self.session();out=Path(self.g['storage_parent'])/('cachy-current-materials-'+NONCE);out.mkdir(parents=True)
        receipt=dict(status='COMPLETE517_HOSTED_CACHE_DATA_ONLY',binding=self.r['context']['binding'],verified_files=517,
            Root_expires_epoch=min(self.d['expires_epoch'],self.g['expires_epoch'],self.d['issued_epoch']+7560),whole_deadline_monotonic=self.r['shared_timing']['deadline_monotonic'],**M.FINAL)
        refs=dict(complete=True,verified_files=517);fields=dict(MODEL='assembler inputs')
        for name,value in (('staging-receipt.json',receipt),('complete517.json',refs),('assembler-fields.json',fields)):M.write(out/name,value)
        private_values=self.values();order=[]
        def executed(**kwargs):
            session.stage_submitted=True;session.receipts.append(physical_receipt());order.append('stage-natural-and-absent')
        with patch.object(session,'execute',side_effect=executed),patch.object(M,'retained_storage',return_value=dict(MODEL=True)),patch.object(M,'load',return_value=SimpleNamespace(assembler_fields=lambda value:fields)),patch.object(session,'close',side_effect=AssertionError('no eager cleanup')):
            result=session.stage(secrets=private_values)
        self.assertEqual(set(result),{'receipt','references','assembler_fields','staging_scope_retirement'});self.assertEqual(result['staging_scope_retirement']['scope'],M.scope_name(NONCE));self.assertTrue(result['staging_scope_retirement']['natural']);self.assertEqual(private_values,{})
        self.assertEqual(session.state,'RETAINED_FOR_CONSUMERS');self.assertTrue(out.exists())
        order.extend(('assembler-read','image-read'));self.assertTrue((out/'complete517.json').exists())
        close=dict(owned_storage_absent=True,scope_absence=dict(scope=M.scope_name(NONCE),absent_twice=True),binding=self.r['context']['binding'],nonce=NONCE,request_pin=M.pin(M.encoded(self.r)),**M.FINAL)
        M.write(self.control/'material-domain-close.json',close)
        with patch.object(session,'execute',side_effect=lambda **kw:(session.receipts.append(physical_receipt(True)),order.append('close-after-final-use'))):
            closed=session.close();self.assertTrue(closed['closed']);self.assertTrue(closed['scope_absent']);self.assertTrue(closed['input_storage_absent'])
            self.assertEqual(closed['request_pin'],close['request_pin'])
        self.assertEqual(order,['stage-natural-and-absent','assembler-read','image-read','close-after-final-use'])
        self.assertEqual(session.state,'CLOSED')

    def test_retained_storage_rejects_unmounted_unbounded_or_foreign_owner(self):
        parent=self.root/'retained';parent.mkdir();grant=dict(storage_parent=str(parent));r=dict(runner_uid=1001)
        scope=dict(cgroup='/system.slice/'+M.scope_name(NONCE),limits=M.SCOPE,pid=123,starttime=456)
        storage=dict(path=str(parent),device=123,total_bytes=8*1024**3,total_nodes=18432)
        receipt=dict(domain=scope,storage_domain=storage)
        capacity=SimpleNamespace(f_blocks=8*1024**3//4096,f_frsize=4096,f_files=18432)
        info=SimpleNamespace(st_uid=1001,st_mode=stat.S_IFDIR|0o700,st_dev=123)
        original=Path.stat
        def observed(path,*a,**kw):return info if path==parent else original(path,*a,**kw)
        with patch.object(Path,'is_mount',return_value=True),patch.object(Path,'stat',observed),patch.object(M.os,'statvfs',return_value=capacity):
            self.assertTrue(M.retained_storage(receipt,r,self.d,grant,self.root,{'absent_twice':True})['retained_for_consumers'])
            info.st_uid=0
            with self.assertRaises(ValueError):M.retained_storage(receipt,r,self.d,grant,self.root,{'absent_twice':True})
            info.st_uid=1001;capacity.f_files=20001;storage['total_nodes']=20001
            with self.assertRaises(ValueError):M.retained_storage(receipt,r,self.d,grant,self.root,{'absent_twice':True})
        with self.assertRaises(ValueError):M.retained_storage(receipt,r,self.d,grant,self.root,{'absent_twice':True})

    def test_storage_begin_never_adopts_existing_mount_or_foreign_admin(self):
        r=copy.deepcopy(self.r);storage=M.RootStorage(r,E,None,self.g,self.d);storage.mount=self.root/'foreign';storage.mount.mkdir()
        storage.admin=self.root/'absent-admin';storage.policy=dict(executor_current_v3=dict(minimum_disk_bytes=1))
        with patch.object(M.os,'getuid',return_value=0),patch.object(M.os,'geteuid',return_value=0),patch.object(storage,'run',side_effect=AssertionError('no command on foreign storage')):
            with self.assertRaises(ValueError):storage.begin()
        self.assertTrue(storage.mount.is_dir());self.assertFalse(storage.admin.exists())

    def test_root_entry_drops_to_runner_before_actual_stager_wrapper_and_clears_input(self):
        request=dict(self.r,runner_uid=1001,runner_gid=1001,delegation_raw='MODEL',delegation_sha256='b'*64,grant_raw='MODEL',grant_sha256='c'*64);path=self.control/'root-model-request';M.write(path,request)
        identities=dict(uid=0,gid=0);events=[];values=self.values();parent=str(self.root/'retained')
        grant=dict(storage_parent=parent);props=dict(ControlGroup='/system.slice/'+M.scope_name(NONCE),RuntimeMaxUSec='3000s',ActiveEnterTimestampMonotonic=str(int(time.monotonic()*1000000)))
        class ModelStorage:
            def __init__(self,*a):pass
            def begin(self):events.append('begin')
            def run(self,*a):return ''.join(k+'='+v+'\n'for k,v in props.items()).encode()
            def allocate(self):events.append('allocate');assert identities['uid']==0
        def invoke(**kwargs):
            self.assertEqual((identities['uid'],identities['gid']),(1001,1001));events.append('actual-stager-wrapper')
            self.assertIsInstance(kwargs['secret_provider'],S.OneShotSecrets)
            self.assertEqual(set(kwargs['secret_provider'](tuple(S.secret_names()))),set(S.secret_names()))
            self.assertEqual(kwargs['base_lock'],{'MODEL':'closed lock'});return dict(MODEL=True)
        dependency=(self.root,self.d,{},grant,E,S,None)
        with patch.object(M,'authorize',return_value=dependency),patch.object(E,'require_runtime_capabilities'),patch.object(E,'kernel_domain',return_value=dict(cgroup=props['ControlGroup'],limits=M.SCOPE,starttime=1)),patch.object(M.os,'getuid',side_effect=lambda:identities['uid']),patch.object(M.os,'geteuid',side_effect=lambda:identities['uid']),patch.object(M.os,'getgid',side_effect=lambda:identities['gid']),patch.object(M.os,'uname',return_value=SimpleNamespace(sysname='Linux',machine='aarch64')),patch.object(M.resource,'setrlimit',side_effect=lambda kind,value:events.append(('rlimit',kind,value))),patch.object(M,'RootStorage',ModelStorage),patch.object(M.os,'setgroups'),patch.object(M.os,'setgid',side_effect=lambda gid:identities.update(gid=gid)),patch.object(M.os,'setuid',side_effect=lambda uid:identities.update(uid=uid)),patch.dict(M.os.environ,{},clear=True),patch.object(M,'secret_input',return_value=values),patch.object(M,'staging_inputs',return_value=dict(base_lock={'MODEL':'closed lock'},bootstrap_profile={'MODEL':'closed profile'})),patch.object(S,'_stage_materials',side_effect=invoke):
            M.root_entry(path,M.pin(path.read_bytes())['sha256'])
        self.assertEqual(values,{});self.assertLess(events.index('allocate'),events.index('actual-stager-wrapper'))
        self.assertIn(('rlimit',M.resource.RLIMIT_AS,(2*1024**3,2*1024**3)),events)

    def test_storage_cleanup_refuses_foreign_backing_or_live_scope(self):
        storage=M.RootStorage(self.r,E,None,dict(storage_parent=str(self.root/'mount')),self.d)
        storage.admin=self.root/'admin';storage.admin.mkdir();storage.backing=storage.admin/'storage.img';storage.backing.write_bytes(b'MODEL')
        wanted=M.identity(storage.backing);storage.owned=dict(closed=False,backing=dict(wanted,inode=wanted['inode']+1),loop=None,mountpoint=None,mount_device=None)
        with patch.object(M,'absent',return_value={'scope':M.scope_name(NONCE),'absent_twice':True}),patch.object(storage,'loop_rows',side_effect=AssertionError('no loop mutation on foreign identity')):
            with self.assertRaises(ValueError):storage.close()
        self.assertEqual(storage.backing.read_bytes(),b'MODEL')
        storage.owned['backing']=wanted
        with patch.object(M,'absent',side_effect=ValueError('MODEL live staging cgroup')),patch.object(storage,'loop_rows',side_effect=AssertionError('no storage touch before absence')):
            with self.assertRaises(ValueError):storage.close()

    def test_storage_cleanup_removes_only_registered_empty_mount_and_loop(self):
        storage=M.RootStorage(self.r,E,None,dict(storage_parent=str(self.root/'mount')),self.d)
        storage.admin=self.root/'admin';storage.admin.mkdir();storage.backing=storage.admin/'storage.img';storage.backing.write_bytes(b'')
        storage.mount=self.root/'mount';storage.mount.mkdir()
        storage.owned=dict(closed=False,backing=M.identity(storage.backing),loop='/dev/loop999',mountpoint=M.identity(storage.mount),mount_device=123)
        calls=[];rows=[[dict(name='/dev/loop999',**{'back-file':str(storage.backing)})],[],[]]
        with patch.object(M,'absent',return_value={'scope':M.scope_name(NONCE),'absent_twice':True}),patch.object(storage,'loop_rows',side_effect=lambda *a:rows.pop(0)),patch.object(storage,'same_loop',side_effect=lambda device:calls.append(('identity',device))),patch.object(storage,'run',side_effect=lambda name,args:calls.append((name,args))),patch.object(storage,'save'):
            receipt=storage.close()
        self.assertEqual(calls,[('identity','/dev/loop999'),('losetup',['--detach','/dev/loop999'])])
        self.assertTrue(receipt['owned_storage_absent']);self.assertFalse(storage.backing.exists());self.assertFalse(storage.mount.exists())
        self.assertIsNone(receipt['Root_final_acceptance'])


class GenuineAuthorization(unittest.TestCase):
    def test_real_committed_context_stager_and_executor_authorize_model_closed_sources(self):
        for version in (3,4):
            fixture=F.V3.ContextTests('test_capture_and_replay_keep_authority_unset')if version==3 else F.SelectedComponentTests('test_selected_completed_producer_v3_and_v4_are_distinct_historical_runs')
            fixture.setUp()
            try:
                fixture.limits.update(max_context_age_seconds=7560,max_delegation_seconds=7560)
                policy=M.decoded((HERE/'owned-executor-current-v3.policy.PROPOSAL.json').read_bytes())
                policy.update(context=fixture.limits,stage_capabilities=policy['stage_capability_proposals'],material_staging_current_v3=S.PROPOSAL,material_domain_executor_current_v3=M.PROPOSAL)
                fixture.files.update({'programs/executor.py':Path(E.__file__).read_bytes(),'programs/domain.py':Path(M.__file__).read_bytes(),
                    'programs/stager.py':Path(S.__file__).read_bytes(),'programs/owned.py':(HERE.parents[2]/'scripts/virtual/owned_process.py').read_bytes(),
                    'programs/assembler.py':b'# MODEL caller role, not invoked\n','inputs/policy.json':M.encoded(policy),
                    'bootstrap/scripts/ci/inputs.lock.json':(HERE.parents[2]/'scripts/ci/inputs.lock.json').read_bytes(),
                    'native/input-profile.json':(HERE.parents[2]/'scripts/ci/desktop-current011-native-source/fixtures/native/input-profile.json').read_bytes()})
                fixture.reseal();d=copy.deepcopy(fixture.d);d['binding']['source_lock']=M.pin(fixture.map_raw);d['context_limits']=fixture.limits
                roles={'image_executor':'programs/executor.py','material_domain_executor':'programs/domain.py','materials_stager':'programs/stager.py','owned_process':'programs/owned.py','inputs_assembler':'programs/assembler.py'}
                for role,member in roles.items():d['programs'][role]=dict(member=member,**M.pin(fixture.files[member]))
                d['materials'].update(M.INPUT_METADATA);d['policy'].update(M.pin(fixture.files['inputs/policy.json']));d['capability'].update(policy['stage_capabilities']['backend'],allow_material_staging=True)
                raw=M.encoded(d);C=M.load(fixture.root,d['programs']['context'],'genuine_material_context_'+str(version))
                c=C.capture_context(raw,M.pin(raw)['sha256'],fixture.root,environ=fixture.env,jobs_response=fixture.response(),now=F.NOW)
                control=fixture.root.parent/'caller-control';control.mkdir(mode=0o700)
                grant=dict(schema=3,kind='ROOT_CURRENT_COMPLETE517_STAGING_V3',issuer='Root',approved=True,**{k:c['binding'][k]for k in ('source','ref','source_lock')},
                    nonce=d['nonce'],policy=M.descriptor(d['policy']),issued_epoch=F.NOW-5,expires_epoch=F.NOW+3500,redirect_urls={},secret_provider='CALLER_ONE_SHOT_EXACT22',scope='COMPLETE517_PUBLIC_DATA_ONLY',storage_parent='/var/lib/cachy-current-material-domain-'+d['nonce'])
                grant_raw=M.encoded(grant);start=time.monotonic()-1
                timing=dict(schema=3,kind='CURRENT_HOSTED_SHARED_7560_PREREQUISITE_TIMING_V3',request_pin=M.pin(b'MODEL caller request'),delegation_pin=c['delegation_pin'],binding=c['binding'],policy_pin=M.descriptor(d['policy']),boot_pin=M.boot_pin(),started_monotonic=start,deadline_monotonic=start+3000,expires_epoch=min(d['expires_epoch'],grant['expires_epoch']),whole_budget_seconds=7560,**M.FINAL)
                r=dict(source_root=str(fixture.root),delegation_raw=raw.decode(),delegation_sha256=M.pin(raw)['sha256'],context=c,grant_raw=grant_raw.decode(),grant_sha256=M.pin(grant_raw)['sha256'],shared_timing=timing,control_root=str(control),runner_uid=os.getuid(),runner_gid=os.getgid())
                with patch.object(M.time,'time',return_value=F.NOW):
                    dependencies=M.authorize(r)
                    self.assertEqual(dependencies[1],d);self.assertEqual(dependencies[5].API,S.API)
                    fields=M.staging_inputs(fixture.root,d);self.assertEqual(set(fields),{'base_lock','bootstrap_profile'})
                    self.assertEqual(fields['base_lock']['sha256'],M.INPUT_METADATA['staging_base_lock']['sha256'])
                    equal=copy.deepcopy(r);equal_grant=dict(grant,expires_epoch=d['expires_epoch']);equal_raw=M.encoded(equal_grant)
                    equal.update(grant_raw=equal_raw.decode(),grant_sha256=M.pin(equal_raw)['sha256']);equal['shared_timing']['expires_epoch']=d['expires_epoch']
                    self.assertEqual(M.authorize(equal)[3]['expires_epoch'],d['expires_epoch'])
                    tampered=copy.deepcopy(r);tampered['shared_timing']['expires_epoch']=d['expires_epoch']
                    with self.assertRaises(ValueError):M.authorize(tampered)
                    extended=copy.deepcopy(r);extended['shared_timing']['deadline_monotonic']=time.monotonic()+3550
                    with self.assertRaises(ValueError):M.authorize(extended)
                    expired=copy.deepcopy(r);expired_grant=dict(grant,expires_epoch=F.NOW-1);expired_raw=M.encoded(expired_grant)
                    expired.update(grant_raw=expired_raw.decode(),grant_sha256=M.pin(expired_raw)['sha256'])
                    with self.assertRaises(ValueError):M.authorize(expired)
                    changed=copy.deepcopy(r);changed['shared_timing']['deadline_monotonic']=start+8000
                    with self.assertRaises(ValueError):M.authorize(changed)
                    changed=copy.deepcopy(d);del changed['materials']['staging_bootstrap_profile']
                    with self.assertRaises(ValueError):M.staging_inputs(fixture.root,changed)
                self.assertEqual(M.pin(fixture.files['programs/executor.py']),M.EXECUTOR_PIN)
            finally:fixture.doCleanups()


if __name__=='__main__':unittest.main()
