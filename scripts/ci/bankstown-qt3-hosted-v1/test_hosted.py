# SPDX-License-Identifier: MIT
"""Fenced MODEL controls; no hosted metadata, mounts, privilege or native actors."""
import ast
import copy
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
            'os.system', 'os.exec', 'os.fork', 'os.posix_spawn', 'fcntl.flock'):
        raise AssertionError('MODEL_NO_OPERATIONAL_ROLE: '+event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('bankstown_hosted_controls', HERE/'hosted.py')
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)
sys.addaudithook(L.H.validation_fence)

CONTEXT = b'''import json,hashlib
from pathlib import Path
def validate_delegation(raw,sha,now=None):
 assert hashlib.sha256(raw).hexdigest()==sha
 return json.loads(raw)
def source(d,root):
 m=json.loads((root/'source-map.json').read_bytes())
 assert hashlib.sha256((root/'source-map.json').read_bytes()).hexdigest()==d['binding']['source_lock']['sha256']
 assert {str(p.relative_to(root))for p in root.rglob('*')if p.is_file()}==set(m['files'])|{'source-map.json'}
 for n,row in m['files'].items():
  raw=(root/n).read_bytes();assert row==dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),mode=420)
 return root,m['files']
'''
EXECUTOR = b"API='CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3'\ndef validate_policy(p,d):return p['executor_current_v3']\ndef probe_tools():return dict(missing_or_invalid=[])\n"
OWNER = b'def run_owned_current_v3(*,delegation_raw,delegation_sha256,context,source_root,inputs,executor,output,public_output):raise AssertionError("MODEL_ONLY")\n'
ASSEMBLER = b'def validate_hosted_inputs_v3(*,inputs,delegation,source_root):return dict(valid=True,required_refs=inputs["staged_refs"])\n'
KEYS = {'base_lock','bootstrap_profile','baseline_inventory','base_materials',
        'supplemental_materials','keyring_materials','candidate_materials','catalog','official_trust'}


class HostedControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='bankstown-hosted-MODEL-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def model(self):
        self.root, self.main, self.staged = [self.base/x for x in ('source','main','staged')]
        for path in (self.root,self.main,self.staged):
            path.mkdir(mode=0o700)
        self.payload = self.staged/'MODEL-DATA'
        self.payload.write_bytes(b'MODEL_ONLY_NOT_A_PACKAGE')
        self.ref = dict(path=str(self.payload), **L.pin(self.payload.read_bytes()))
        self.inputs = {key:{} for key in KEYS}
        self.wrapper = self.staged/'inputs.json'
        self.wrapper.write_bytes(L.H.encoded(dict(schema=1,kind='ROOT_STAGED_BANKSTOWN_QT3_INPUTS_V1',
                                                 owner_inputs=self.inputs,staged_refs=[self.ref])))
        self.files = {L.PREFIX+'hosted.py':(HERE/'hosted.py').read_bytes(),
                      'context.py':CONTEXT,'executor.py':EXECUTOR,'owner.py':OWNER,
                      'assembler.py':ASSEMBLER,'owned.py':(ROOT/'scripts/virtual/owned_process.py').read_bytes(),
                      'policy.json':L.H.encoded(dict(executor_current_v3=dict(controller=L.SCOPE,
                          controller_AS_bytes=512*1024**2,controller_seconds=3960)))}
        for name,raw in self.files.items():
            path = self.root/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o644)
        path = self.main/(L.PREFIX+'hosted.py')
        path.parent.mkdir(parents=True)
        path.write_bytes((HERE/'hosted.py').read_bytes())
        self.row = lambda n:dict(member=n,**L.pin(self.files[n]))
        raw = L.H.encoded(dict(files={n:dict(L.pin(b),mode=420) for n,b in self.files.items()}))
        (self.root/'source-map.json').write_bytes(raw)
        self.d = dict(approved=True,nonce='a'*64,capability={},expires_epoch=5320,
                      binding=dict(source='b'*40,ref='refs/heads/codex/MODEL-audio',source_lock=L.pin(raw)),
                      policy=self.row('policy.json'), materials={},
                      programs=dict(context=self.row('context.py'),owner=self.row('owner.py'),image_executor=self.row('executor.py'),
                          hosted_launcher=self.row(L.PREFIX+'hosted.py'),owned_process=self.row('owned.py'),inputs_assembler=self.row('assembler.py')),
                      hosted=dict(repository='MODEL/MODEL',job_key='audio',workflow_ref='MODEL/MODEL/.github/workflows/audio.yml@refs/heads/codex/MODEL-audio',workflow_sha='b'*40))
        self.r = dict(launcher=self.row(L.PREFIX+'hosted.py'),delegation_json=L.H.encoded(self.d).decode(),
                      delegation_pin=L.pin(L.H.encoded(self.d)),staged_root=str(self.staged),
                      staged_inputs=dict(path=str(self.wrapper),**L.pin(self.wrapper.read_bytes())),
                      control_name='cachy-current-hosted-'+self.d['nonce'])
        self.env = dict(GITHUB_WORKSPACE=str(self.root),RUNNER_TEMP=str(self.base),GITHUB_SHA='b'*40,
                        GITHUB_REF=self.d['binding']['ref'],GITHUB_RUN_ATTEMPT='1',GITHUB_REPOSITORY='MODEL/MODEL',
                        GITHUB_JOB='audio',GITHUB_WORKFLOW_REF=self.d['hosted']['workflow_ref'],GITHUB_WORKFLOW_SHA='b'*40,
                        RUNNER_ARCH='ARM64',RUNNER_OS='Linux',RUNNER_ENVIRONMENT='github-hosted',GITHUB_ACTIONS='true')

    def held_preflight(self):
        with patch.object(L.H,'AUDIO_OWNER_PIN',L.pin(OWNER)),patch.object(L.H.os,'uname',return_value=SimpleNamespace(sysname='Linux',machine='aarch64')),patch.object(L.H,'fixed_tool',return_value={'MODEL':'NOT_OBSERVED'}):
            return L._preflight(self.r,self.root,self.main,self.base/self.r['control_name'],self.env,1000)

    def root_request(self):
        d = dict(stage='qt3',capability={},programs=dict(owner=dict(member=L.AUDIO+'owner.py',**L.OWNER),
                 image_executor=dict(member=L.AUDIO+'controller.py',**L.CONTROLLER),inputs_assembler=dict(member=L.PREFIX+'inputs.py',bytes=1,sha256='a'*64)),
                 policy=dict(member=L.PREFIX+'policy.PROPOSAL.json',**L.POLICY))
        return dict(schema=1,kind='ROOT_AUTHORIZED_BANKSTOWN_QT3_HOSTED_LAUNCH_V1',issuer='Root',approved=True,
                    trusted_main_commit='a'*40,launcher=dict(member=L.PREFIX+'hosted.py',**L.pin((HERE/'hosted.py').read_bytes())),
                    delegation_json=L.H.encoded(d).decode(),delegation_pin=L.pin(L.H.encoded(d)),
                    staged_inputs=dict(path=str(self.base/'MODEL-inputs.json'),bytes=1,sha256='b'*64),
                    staged_root=str(self.base),control_name='MODEL_UNISSUED',
                    authorization=dict(jobs_metadata=True,privileged_controller=True,launcher_limits=L.LIMITS))

    def check_request(self,r):
        path = self.base/'MODEL-request.json'
        path.write_bytes(L.H.encoded(r))
        return L.request(path,L.pin(path.read_bytes())['sha256'])

    def test_complete_projection_inverse_and_basis_pin(self):
        raw = (HERE/'basis/hosted_current_v3.py').read_bytes()
        text = L.projected(raw)
        for before,after,_ in reversed(L.PROJECTION):
            text = text.replace(after,before)
        self.assertEqual(text.encode(),raw)
        for bad in (raw+b'\n', raw[:-1]):
            with self.assertRaises(ValueError):L.projected(bad)

    def test_unchanged_metadata_supervision_scope_and_controller_functions(self):
        raw = (HERE/'basis/hosted_current_v3.py').read_bytes()
        a,b = ast.parse(raw),ast.parse(L.projected(raw))
        for name in ('read','whole','descriptor','program','validation_fence','scope_argv','run','fetch_jobs','fixed_tool','scope_absent','controller_observation','execute'):
            find = lambda t:next(n for n in t.body if isinstance(n,ast.FunctionDef) and n.name==name)
            self.assertEqual(ast.dump(find(a)),ast.dump(find(b)),name)

    def test_actual_audio_controller_isolated_maintained_dispatch(self):
        value = L.program(ROOT,dict(member=L.AUDIO+'controller.py',**L.CONTROLLER),'audio_controller_control')
        self.assertEqual(value.API,'CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3')
        self.assertEqual(Path(value.__file__),ROOT/(L.AUDIO+'controller.py'))
        self.assertEqual(value.context_contract.__module__,'_bankstown_qt3_controller_context')
        self.assertEqual(value.controller_main.__name__,'controller_main')
        self.assertTrue(callable(value.Controller.cleanup))
        with self.assertRaises(ValueError):L.program(ROOT,dict(member=L.AUDIO+'controller.py',**dict(L.CONTROLLER,sha256='0'*64)),'bad')

    def test_root_request_exact_audio_selection_and_external_hash(self):
        r = self.root_request()
        self.assertEqual(self.check_request(r),r)
        with self.assertRaises(ValueError):L.request(self.base/'MODEL-request.json','0'*64)
        for key,value in [('schema',3),('kind','ROOT_AUTHORIZED_CURRENT_HOSTED_LAUNCH_V3'),('approved',None),('unknown',True)]:
            changed=copy.deepcopy(r);changed[key]=value
            with self.assertRaises(ValueError):self.check_request(changed)

    def test_no_implicit_material_or_host_prerequisite_paths(self):
        for which in ('allow_host_prerequisites','allow_material_staging'):
            r=self.root_request();d=L.H.decode(r['delegation_json']);d['capability'][which]=True
            r['delegation_json']=L.H.encoded(d).decode();r['delegation_pin']=L.pin(L.H.encoded(d))
            with self.assertRaises(ValueError):self.check_request(r)
        r=self.root_request();r['material_staging']={}
        with self.assertRaises(ValueError):self.check_request(r)

    def test_old_owner_or_controller_cannot_cross_request_dispatch(self):
        for key in ('owner','image_executor'):
            r=self.root_request();d=L.H.decode(r['delegation_json']);d['programs'][key]['sha256']='0'*64
            r['delegation_json']=L.H.encoded(d).decode();r['delegation_pin']=L.pin(L.H.encoded(d))
            with self.assertRaises(ValueError):self.check_request(r)

    def test_actual_audio_policy_unchanged_domains_and_explicit_lifetime(self):
        p=L.H.decode((HERE/'policy.PROPOSAL.json').read_bytes())
        old=L.H.decode((ROOT/(L.AUDIO+'policy.PROPOSAL.json')).read_bytes())
        for key in ('executor_current_v3','image_domains','image_steps','frozen_stage_limits','stage_capabilities'):
            self.assertEqual(p[key],old[key])
        self.assertEqual(p['context']['max_delegation_seconds'],4320)
        self.assertEqual(p['executor_current_v3']['controller_seconds'],3960)
        self.assertEqual(p['executor_current_v3']['cleanup_seconds'],180)
        self.assertEqual(p['hosted_transport_v1']['whole_launcher_seconds'],180+3960+30)
        self.assertEqual(L.pin((HERE/'policy.PROPOSAL.json').read_bytes()),L.POLICY)
        e=L.program(ROOT,dict(member=L.AUDIO+'controller.py',**L.CONTROLLER),'policy_controller')
        self.assertEqual(e.validate_policy(p,dict(capability=dict(stage='qt3',**p['stage_capabilities']['qt3']))),p['executor_current_v3'])

    def test_whole_intake_and_finite_direct_scope(self):
        self.model();plan=self.held_preflight()
        self.assertEqual(plan.inputs,self.inputs);self.assertEqual(plan.intake['files'],1)
        argv=L.H.scope_argv(plan,self.base/'request','a'*64,self.base/'context','b'*64,self.wrapper,'c'*64)
        for value in ('RuntimeMaxSec=3960s','MemoryMax=536870912','MemorySwapMax=0','CPUQuota=100%','TasksMax=64','TimeoutStopSec=10s'):
            self.assertIn('--property='+value,argv)
        self.assertNotIn('/bin/sh',argv)
        self.assertEqual(L.H.controller_seconds(plan),3960)

    def test_old_3960_lifetime_refuses_new_4320_lifetime_fits(self):
        self.model();d=L.H.decode(self.r['delegation_json']);d['expires_epoch']=4960
        self.r['delegation_json']=L.H.encoded(d).decode()
        with self.assertRaises(ValueError):self.held_preflight()
        d['expires_epoch']=5320;self.r['delegation_json']=L.H.encoded(d).decode()
        self.held_preflight()

    def test_changed_missing_duplicate_private_and_outside_bodies_refuse(self):
        self.model()
        for mode in ('changed','missing','duplicate','private','outside'):
            ref=dict(self.ref);refs=[ref]
            if mode=='changed':ref['sha256']='0'*64
            elif mode=='missing':ref['path']=str(self.staged/'ABSENT')
            elif mode=='duplicate':refs.append(dict(ref))
            else:
                path=(self.staged/'.ssh'/'MODEL')if mode=='private'else(self.base/'OUTSIDE')
                path.parent.mkdir(exist_ok=True);path.write_bytes(self.payload.read_bytes());ref['path']=str(path)
            self.wrapper.write_bytes(L.H.encoded(dict(schema=1,kind='ROOT_STAGED_BANKSTOWN_QT3_INPUTS_V1',owner_inputs=self.inputs,staged_refs=refs)))
            self.r['staged_inputs'].update(L.pin(self.wrapper.read_bytes()))
            with self.subTest(mode=mode),self.assertRaises((ValueError,FileNotFoundError)):self.held_preflight()

    def test_actual_hosted_selectors_refuse_before_operational_entry(self):
        self.model()
        for key in ('GITHUB_SHA','GITHUB_REF','GITHUB_WORKFLOW_SHA','GITHUB_WORKSPACE','RUNNER_ARCH','GITHUB_RUN_ATTEMPT'):
            old=self.env[key];self.env[key]='WRONG'
            with self.subTest(key=key),self.assertRaises(ValueError):self.held_preflight()
            self.env[key]=old

    def mount(self,options='ro',entries=1,size=8*1024**3,nodes=18432):
        staged=self.base/'mount';staged.mkdir(mode=0o700,exist_ok=True)
        raw=(f'123 45 7:9 / {staged} {options} - ext4 /dev/loop-MODEL rw\n'*entries).encode()
        return staged,raw,SimpleNamespace(f_blocks=size//4096,f_frsize=4096,f_files=nodes)

    def test_readonly_mount_observation_and_directory_promise_refusal(self):
        staged,raw,space=self.mount()
        with patch('builtins.open',return_value=io.BytesIO(raw)),patch.object(L.os,'statvfs',return_value=space):
            row=L.mount_custody(staged)
        self.assertEqual(row['mount_id'],'123');self.assertFalse(row['retirement_observed_here'])
        self.assertIsNone(row['Root_acceptance'])
        for options,entries,size,nodes in [('rw',1,8*1024**3,18432),('ro',0,8*1024**3,18432),('ro',2,8*1024**3,18432),('ro',1,33*1024**3,18432),('ro',1,8*1024**3,20001)]:
            staged,raw,space=self.mount(options,entries,size,nodes)
            with patch('builtins.open',return_value=io.BytesIO(raw)),patch.object(L.os,'statvfs',return_value=space),self.assertRaises(ValueError):L.mount_custody(staged)

    def test_descendant_mounts_refuse_even_under_readonly_root(self):
        staged,raw,space=self.mount()
        for options in ('ro','rw'):
            child=f'124 123 7:10 / {staged}/child {options} - ext4 /dev/loop-OTHER rw\n'.encode()
            with patch('builtins.open',return_value=io.BytesIO(raw+child)),patch.object(L.os,'statvfs',return_value=space),self.assertRaisesRegex(ValueError,'DESCENDANT'):
                L.mount_custody(staged)

    def test_retained_mount_identity_rejoined(self):
        plan=SimpleNamespace(request={'staged_root':'/MODEL'},input_mount={'mount_id':'123'})
        with patch.object(L,'mount_custody',return_value={'mount_id':'123'}):self.assertEqual(L.retained_input_mount(plan),plan.input_mount)
        with patch.object(L,'mount_custody',return_value={'mount_id':'124'}),self.assertRaises(ValueError):L.retained_input_mount(plan)

    def test_source72_original_members_preserved_and_tamper_refuses(self):
        raw=(HERE/'source72-map.DATA.json').read_bytes();old=L.H.decode(raw)
        root=self.base/'source';prefix=root/L.PREFIX;prefix.mkdir(parents=True)
        (prefix/'source72-map.DATA.json').write_bytes(raw)
        (root/'source-map.json').write_bytes(L.H.encoded(dict(files=old['files'])))
        self.assertEqual(L.source72_parent(root),L.SOURCE72)
        changed=copy.deepcopy(old['files']);changed[next(iter(changed))]['mode']=0o755
        (root/'source-map.json').write_bytes(L.H.encoded(dict(files=changed)))
        with self.assertRaises(ValueError):L.source72_parent(root)

    def workflow_blocks(self):
        path=ROOT/'.github/workflows/native-arm-bankstown-qt3-hosted-v1.yml'
        blocks=[];active=None
        for line in path.read_text().splitlines():
            if line.strip()=="python3 -I -B - <<'PY'":active=[]
            elif active is not None:
                if line.strip()=='PY':blocks.append('\n'.join(active));active=None
                else:active.append(line[10:])
        self.assertEqual(len(blocks),2)
        for block in blocks:ast.parse(block)
        return blocks

    def test_real_workflow_bootstrap_binds_request_before_checkout(self):
        block=self.workflow_blocks()[0]
        r=self.root_request();d=L.H.decode(r['delegation_json'])
        d.update(binding=dict(source='b'*40,ref='refs/heads/codex/MODEL-audio'),nonce='c'*64)
        r.update(delegation_json=L.H.encoded(d).decode(),delegation_pin=L.pin(L.H.encoded(d)),control_name='cachy-current-hosted-'+d['nonce'])
        raw=L.H.encoded(r)
        output=self.base/'MODEL-GITHUB-OUTPUT';output.write_text('')
        env=dict(ROOT_REQUEST_JSON=raw.decode(),ROOT_REQUEST_SHA256=L.pin(raw)['sha256'],
                 GITHUB_SHA='b'*40,GITHUB_REF=d['binding']['ref'],GITHUB_RUN_ATTEMPT='1',
                 RUNNER_TEMP=str(self.base),GITHUB_OUTPUT=str(output))
        with patch.dict(os.environ,env,clear=True):exec(compile(block,'workflow-MODEL','exec'),{})
        emitted=dict(line.split('=',1)for line in output.read_text().splitlines())
        self.assertEqual(emitted['source'],'b'*40)
        self.assertEqual(emitted['main'],'a'*40)
        self.assertEqual(Path(emitted['request']).read_bytes(),raw)
        self.assertEqual(Path(emitted['request']).stat().st_mode&0o777,0o600)

    def test_workflow_wrong_actual_ref_refuses_before_request_write(self):
        block=self.workflow_blocks()[0]
        r=self.root_request();d=L.H.decode(r['delegation_json'])
        d.update(binding=dict(source='b'*40,ref='refs/heads/codex/MODEL-audio'),nonce='c'*64)
        r.update(delegation_json=L.H.encoded(d).decode(),delegation_pin=L.pin(L.H.encoded(d)),control_name='cachy-current-hosted-'+d['nonce'])
        raw=L.H.encoded(r)
        env=dict(ROOT_REQUEST_JSON=raw.decode(),ROOT_REQUEST_SHA256=L.pin(raw)['sha256'],
                 GITHUB_SHA='b'*40,GITHUB_REF='refs/heads/codex/WRONG',GITHUB_RUN_ATTEMPT='1',
                 RUNNER_TEMP=str(self.base),GITHUB_OUTPUT=str(self.base/'NEVER'))
        with patch.dict(os.environ,env,clear=True),self.assertRaises(AssertionError):exec(compile(block,'workflow-MODEL','exec'),{})
        self.assertFalse((self.base/'NEVER').exists())
        self.assertFalse(list(self.base.glob('current-root-request-*')))

    def test_required_python314_cannot_be_inferred(self):
        with patch.object(L.sys,'version_info',(3,12)),self.assertRaisesRegex(ValueError,'PYTHON314'):
            L.preflight({},self.base,self.base,self.base,{},1000)


if __name__ == '__main__':
    unittest.main()
