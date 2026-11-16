#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Fenced owner dispatch MODEL controls, never Root or native qualification."""
import contextlib
import copy
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in {'os.system','os.exec','os.posix_spawn','os.fork','fcntl.flock'}:
        raise AssertionError('MODEL operational event forbidden: '+event)

sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

O=load('bankstown_owner_controls',HERE/'owner.py')
E=load('bankstown_owner_actual_executor',HERE/'controller.py').E
H=O.H

MODEL_BUILDER=b'''class ModelDocker:
    def __init__(self, endpoint): self.endpoint = endpoint
    def docker(self, args):
        argv = ['/usr/bin/docker', '--host', self.endpoint] + args
        return argv
'''

class StatView:
    """Only MODEL ownership/mode facts; all bytes and identities stay actual."""
    def __init__(self,row,uid=0,unsafe=False):self.row,self.uid,self.unsafe=row,uid,unsafe
    def __getattr__(self,key):
        if key=='st_uid':return self.uid
        if key=='st_mode':return (self.row.st_mode & ~0o022) | (0o022 if self.unsafe else 0)
        return getattr(self.row,key)

@contextlib.contextmanager
def root_custody(*,uid=0,unsafe=False,directory=None):
    path_type=type(Path())
    class ModelRootPath(path_type):
        def lstat(self,*args,**kwargs):return StatView(super().lstat(*args,**kwargs),uid,unsafe)
    ordinary=H.ordinary
    model_os=types.SimpleNamespace(**{name:getattr(os,name) for name in dir(os)})
    model_os.fstat=lambda fd:StatView(os.fstat(fd),uid,unsafe)
    def selected_path(value):
        path=ordinary(value)
        if directory is not None and not (path==directory or path.is_relative_to(directory) or directory.is_relative_to(path)):
            return path
        return ModelRootPath(path)
    with patch.object(H,'ordinary',side_effect=selected_path),patch.object(O,'os',model_os):yield

class Executor:
    def __init__(self):self.deadline=time.monotonic()+1200;self.calls=0
    def live(self):self.calls+=1

class OwnerControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='qt3-owner-MODEL-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
    def test_literal_projection_uses_only_declared_model_source_seam(self):
        # Main lacks the separately authored8 files. Only whole-source delivery is
        # modeled here; actual builder integration is a separate Root check.
        with patch.object(H,'verify_reference',return_value=MODEL_BUILDER) as held:
            module,proof=O.projected_builder(self.root)
        self.assertEqual(module.ModelDocker('unix:///MODEL').docker(['info']),['/usr/bin/docker','--host=unix:///MODEL','info'])
        self.assertEqual(proof['original'],H.pin(MODEL_BUILDER))
        self.assertEqual(MODEL_BUILDER.replace(O.DOCKER_BEFORE,O.DOCKER_AFTER).replace(O.DOCKER_AFTER,O.DOCKER_BEFORE),MODEL_BUILDER)
        self.assertEqual(held.call_args.args[0]['sha256'],O.BUILDER_PIN['sha256'])
        for raw in (MODEL_BUILDER+O.DOCKER_BEFORE,MODEL_BUILDER.replace(O.DOCKER_BEFORE,O.DOCKER_AFTER)):
            with patch.object(H,'verify_reference',return_value=raw),self.assertRaises(ValueError):O.projected_builder(self.root)
    def test_actual_source_pin_gate_refuses_model_before_execution(self):
        p=self.root/O.BUILDER_MEMBER;p.parent.mkdir(parents=True);p.write_bytes(MODEL_BUILDER);p.chmod(0o644)
        with self.assertRaises(ValueError):O.projected_builder(self.root)
    def test_actual_maintained_executor_requires_single_host_argument(self):
        e=object.__new__(E.Executor);e.endpoint='unix:///MODEL/owned.sock';e.maximum_command_seconds=300
        e.live=lambda:None;e.resolve=lambda argv:(argv,{'docker':{'MODEL':'tool'}})
        good=['/usr/bin/docker','--host='+e.endpoint,'info']
        with patch.object(E.CommandEngine,'run',return_value={'MODEL':'receipt'}) as base:
            self.assertEqual(e.run('MODEL-info',good,30),{'MODEL':'receipt'})
            self.assertEqual(base.call_args.args,('MODEL-info',good,30,0))
            base.reset_mock()
            with self.assertRaisesRegex(ValueError,'private explicit Docker endpoint'):
                e.run('MODEL-info',['/usr/bin/docker','--host',e.endpoint,'info'],30)
            base.assert_not_called()
    def selection_fixture(self):
        directory=self.root/'root-inbox';directory.mkdir();source=self.root/'source';source.mkdir();work=self.root/'work';work.mkdir()
        image_raw=H.encoded({'nonce':'a'*64,'MODEL':'image receipt'})
        d={'root_selection':{'directory':str(directory),'wait_seconds':10},'expires_epoch':int(time.time())+300}
        now=int(time.time());admission=directory/'admission.json';admission.write_bytes(b'MODEL_EXTERNAL_ROOT_TRIAL')
        envelope=dict(schema=1,kind='ROOT_DELIVERED_BANKSTOWN_QT3_ADMISSION_SELECTION_V1',issuer='Root',approved=True,nonce='a'*64,image_receipt_pin=H.pin(image_raw),issued_at=now-1,expires_at=now+100,admission=dict(path=str(admission),**H.pin(admission.read_bytes())))
        p=directory/('a'*64+'.admission.json');p.write_bytes(H.encoded(envelope))
        args=dict(phase='admission',delegation=d,image_raw=image_raw,executor=Executor(),source_root=source,work=work)
        return args,p,envelope
    def test_actual_root_inbox_reader_with_modeled_root_custody(self):
        args,p,envelope=self.selection_fixture()
        with root_custody():self.assertEqual(O.await_selection(**args),envelope)
        self.assertGreater(args['executor'].calls,0)
        for kwargs in ({'uid':1000},{'unsafe':True}):
            with root_custody(**kwargs),self.assertRaises(ValueError):O.await_selection(**args)
    def test_root_selection_rejects_nonce_image_pin_expiry_and_unapproved(self):
        args,p,envelope=self.selection_fixture()
        for mutate in (lambda v:v.update(nonce='b'*64),lambda v:v.update(image_receipt_pin=H.pin(b'other')),lambda v:v.update(approved=False),lambda v:v.update(expires_at=0),lambda v:v.update(schema=True)):
            v=copy.deepcopy(envelope);mutate(v);p.write_bytes(H.encoded(v))
            with root_custody(),self.assertRaises(ValueError):O.await_selection(**args)
    def test_missing_selection_is_finite_and_never_autoapproved(self):
        args,p,envelope=self.selection_fixture();p.unlink();args['executor'].deadline=time.monotonic()+80
        with root_custody(),patch.object(O.time,'sleep',side_effect=AssertionError('NO_WAIT_EXPECTED')),self.assertRaisesRegex(ValueError,'NOT_DELIVERED'):
            O.await_selection(**args)
        self.assertFalse(p.exists())
    def test_root_trial_hash_and_directory_custody_refuse(self):
        args,p,envelope=self.selection_fixture()
        Path(envelope['admission']['path']).write_bytes(b'changed')
        with root_custody(),self.assertRaisesRegex(ValueError,'PIN_DIFFERS'):O.await_selection(**args)
        args['delegation']['root_selection']['directory']=str(args['work'])
        with root_custody(),self.assertRaisesRegex(ValueError,'DISJOINT'):O.await_selection(**args)
    def test_profile_selection_requires_separate_exact_root_reference_pins(self):
        args,p,envelope=self.selection_fixture()
        directory=p.parent
        expected={}
        for name in ('profile','profile_receipt'):
            path=args['work']/name;path.write_bytes(('MODEL_'+name).encode())
            expected[name]=dict(path=str(path),**H.pin(path.read_bytes()))
        envelope.pop('admission');envelope.update(kind='ROOT_DELIVERED_BANKSTOWN_QT3_PROFILE_SELECTION_V1',**expected)
        target=directory/('a'*64+'.profile.json');target.write_bytes(H.encoded(envelope))
        args.update(phase='profile',expected=expected)
        with root_custody(directory=directory):self.assertEqual(O.await_selection(**args),envelope)
        changed=copy.deepcopy(envelope);changed['profile']['sha256']='0'*64;target.write_bytes(H.encoded(changed))
        with root_custody(directory=directory),self.assertRaisesRegex(ValueError,'PROFILE_SELECTION_DIFFERS'):O.await_selection(**args)
    def test_original_failure_preserved_when_retention_also_fails(self):
        data=self.root/'failure.json';data.write_bytes(b'MODEL_FAILURE');original=RuntimeError('original stage failure')
        def fail():raise original
        with patch.object(O,'retain',side_effect=ValueError('retention failed')):
            with self.assertRaises(RuntimeError) as caught:O.retained_call(fail,[(data,self.root/'public')])
        self.assertIs(caught.exception,original);self.assertIn('retention',original.__notes__[0].lower())

    def pipeline(self,*,stop_phase=None,build_failure=None):
        source=self.root/'source';source.mkdir();out=self.root/'owner-stage';out.mkdir();public=self.root/'public'
        catalog=source/'catalog';catalog.write_bytes(b'MODEL_CATALOG');inputs={'catalog':dict(path=str(catalog),**H.pin(catalog.read_bytes()))}
        e=Executor();events=[];d={'inputs_pin':H.pin(H.encoded(inputs)),'policy':{'member':'policy.json'}}
        c={'binding':{'source':'b'*40,'ref':'refs/heads/codex/MODEL','run':'123','job':'456','attempt':1},'nonce':'a'*64}
        policy={'MODEL':'reviewed policy'}
        C=types.SimpleNamespace(validate_delegation=lambda *a:d,validate_context=lambda *a:c,source=lambda *a:source,decode=H.decoded,read=lambda *a:(H.encoded(policy),0o644))
        def image(**kw):
            self.assertIs(kw['executor'],e);events.append('image');p=kw['output'];p.mkdir();(p/'image-provisional.json').write_bytes(b'MODEL_IMAGE_REPORT');return {'MODEL':'image'}
        admission=self.root/'external-root-admission';admission.write_bytes(b'MODEL_EXTERNALLY_SELECTED_TRIAL')
        def materialize(**kw):
            self.assertIs(kw['executor'],e);events.append('materialize');p=kw['output'];p.mkdir()
            receipt={'nonce':c['nonce'],'MODEL':'image receipt'};path=p/'image-receipt.json';path.write_bytes(H.encoded(receipt));(p/'view-DATA.json').write_bytes(b'MODEL_VIEW');return receipt,path
        def reference(path,*,cap,deadline):
            self.assertEqual(deadline,e.deadline);return dict(path=str(path),**H.pin(path.read_bytes()))
        def selected(**kw):
            self.assertIs(kw['executor'],e);phase=kw['phase'];events.append('Root-'+phase)
            if phase==stop_phase:raise ValueError('MODEL Root selection absent: '+phase)
            if phase=='admission':return {'admission':dict(path=str(admission),**H.pin(admission.read_bytes()))}
            return kw['expected']
        # These signatures match the actual separately authored passive D API.
        def export(*,profile_path,output_receipt_path,image_receipt_path,image_receipt_sha256,admission_path,admission_sha256,catalog_path,source_root,executor):
            self.assertIs(executor,e);events.append('export');self.assertEqual(admission_path,admission)
            profile_path.write_bytes(b'MODEL_NATIVE_PROFILE')
            result={'profile':dict(path=str(profile_path),**H.pin(profile_path.read_bytes()))}
            output_receipt_path.write_bytes(H.encoded(result));return result
        def verify(*,profile_path,profile_sha256,output_receipt_path,output_receipt_sha256,image_receipt_path,image_receipt_sha256,admission_path,admission_sha256,catalog_path,source_root,executor):
            self.assertIs(executor,e);events.append('verify')
            self.assertEqual(H.pin(profile_path.read_bytes())['sha256'],profile_sha256)
            self.assertEqual(H.pin(output_receipt_path.read_bytes())['sha256'],output_receipt_sha256)
        def build_private_test(*,admission_raw,admission_sha256,profile_path,profile_sha256,executor,source_root,output):
            self.assertIs(executor,e);events.append('build');output.mkdir();(output/'artifacts').mkdir();(output/'commands').mkdir()
            (output/'commands/commands.json').write_bytes(b'MODEL_COMMANDS')
            (output/'result.json').write_bytes(b'MODEL_FAILURE' if build_failure else b'MODEL_PASS')
            if build_failure:raise build_failure
            (output/'artifacts/bankstown-MODEL.pkg.tar.xz').write_bytes(b'MODEL_NOT_PACKAGE')
            return {'status':'PASS_PRIVATE_TEST_BUILD_DATA_ONLY'}
        builder=types.SimpleNamespace(load=lambda path,name:types.SimpleNamespace(validate_trial=lambda raw,sha,now:{'resources':{'wall_seconds':100}}),build_private_test=build_private_test)
        phases={'context':C,'image':types.SimpleNamespace(build_qt3_image=image),'materialize':types.SimpleNamespace(materialize_image=materialize,file_reference=reference)}
        with patch.object(O,'local',side_effect=lambda name:phases[name]),patch.object(O,'load_profile',return_value=types.SimpleNamespace(export=export,verify=verify)),patch.object(O,'await_selection',side_effect=selected),patch.object(O,'root_file',side_effect=lambda path:Path(path).read_bytes()),patch.object(O,'projected_builder',return_value=(builder,{'MODEL':'projection'})):
            try:return O.run_owned_current_v3(delegation_raw=b'MODEL',delegation_sha256='0'*64,context=c,source_root=source,inputs=inputs,executor=e,output=out,public_output=public),events,e,public
            except BaseException as error:
                error.model_events=events;error.model_public=public;raise
    def test_pipeline_same_executor_and_two_external_selections(self):
        report,events,e,public=self.pipeline()
        self.assertEqual(events,['image','materialize','Root-admission','export','Root-profile','verify','build'])
        self.assertTrue(report['completed']);self.assertIsNone(report['Root_final_acceptance'])
        self.assertFalse(report['independent_component_acceptance']);self.assertGreaterEqual(e.calls,4)
        self.assertTrue((public/'pipeline-DATA.json').is_file())
    def test_pipeline_missing_second_root_selection_never_builds(self):
        with self.assertRaises(ValueError) as caught:self.pipeline(stop_phase='profile')
        self.assertNotIn('verify',caught.exception.model_events);self.assertNotIn('build',caught.exception.model_events)
        self.assertFalse((caught.exception.model_public/'pipeline-DATA.json').exists())
    def test_pipeline_builder_failure_keeps_original_and_data(self):
        original=RuntimeError('MODEL original build failure')
        with self.assertRaises(RuntimeError) as caught:self.pipeline(build_failure=original)
        self.assertIs(caught.exception,original)
        self.assertEqual((original.model_public/'build/result.json').read_bytes(),b'MODEL_FAILURE')
        self.assertFalse((original.model_public/'pipeline-DATA.json').exists())

if __name__=='__main__':unittest.main()
