# SPDX-License-Identifier: MIT
"""Actor-fenced MODEL Root assertions; no actual authority, lease or dispatch."""
import argparse
from contextlib import ExitStack
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
ACTORS=[]

def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.posix_spawn','os.fork')) or event in ('os.system','fcntl.flock','resource.setrlimit'):
        ACTORS.append(event);raise AssertionError('MODEL contract controls forbid actor: '+event)

sys.addaudithook(fence)

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

C=load('MODEL_source205_main_route_contract',HERE/'contract.py')
G=load('MODEL_main_route_profile_fixture',HERE.parent/'request_generation/test_prepare.py')
CORE_RAW=(HERE.parent/'payload/hosted.py').read_bytes()
NOW=1000


def model_case(profile):
    """All Root-approved fields below are synthetic test assertions, not grants."""
    case=C.templates()['Root-case.TEMPLATE.json']
    case.update(issuer='Root',approved=True,case_id='c'*64,stage='backend',nonce='f'*64,issued_epoch=990,expires_epoch=1990,workflow_id=707)
    case['source'].update(cid='a'*40,ref='refs/heads/codex/MODEL-Source205')
    case['main'].update(cid='b'*40,tree='d'*40,reader=dict(member=C.READER,bytes=1,sha256='e'*64))
    d=dict(schema=4,kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4',issuer='Root',approved=True,
        scope='CURRENT_PRIVATE_STAGE_ONLY',binding=dict(source=case['source']['cid'],ref=case['source']['ref'],run=None,job=None,attempt=1,source_lock=C.SOURCE205['source_map']),
        stage=case['stage'],nonce=case['nonce'],issued_epoch=case['issued_epoch'],expires_epoch=case['expires_epoch'],
        programs=profile['delegation_programs'],materials=dict(profile['materials'],**profile['staging_materials']),policy=C.POLICY,
        capability=dict(operation=C.OPERATION,stage=case['stage'],allow_provisional_context=True,allow_provisional_image_checks=True,
            allow_pair_adoption=False,allow_host_prerequisites=True,allow_material_staging=True,**C.CAPS),
        context_limits=C.CONTEXT,hosted=dict(repository=C.REPOSITORY,workflow_ref=C.REPOSITORY+'/'+C.WORKFLOW+'@'+case['source']['ref'],workflow_sha=case['source']['cid'],
            job_key='current',job_name='current-onboarding-delegated-v3',runner_environment='github-hosted',runner_os='Linux',runner_arch='ARM64'),
        image_ids=dict(backend=None,ui=None,lifecycle=None),**C.FINAL)
    grant=dict(schema=3,kind='ROOT_CURRENT_COMPLETE517_STAGING_V3',issuer='Root',approved=True,source=case['source']['cid'],ref=case['source']['ref'],source_lock=C.SOURCE205['source_map'],
        nonce=case['nonce'],policy={k:C.POLICY[k]for k in ('bytes','sha256')},issued_epoch=case['issued_epoch'],expires_epoch=case['expires_epoch'],
        redirect_urls={('MODEL-%02d.pkg'%i):[]for i in range(21)},secret_provider='CALLER_ONE_SHOT_EXACT22',scope='COMPLETE517_PUBLIC_DATA_ONLY',storage_parent='/var/lib/cachy-current-material-domain-'+case['nonce'])
    trust=dict(public_key=dict(member='MODEL/public-key',bytes=1,sha256='d'*64),fingerprint='A'*40,Root_admission=dict(kind='MODEL_ONLY'))
    assembler=dict(schema=3,kind='CURRENT_ONBOARDING_INPUT_REQUEST_V3',stage=case['stage'],source_date_epoch=1,base_lock=None,bootstrap_profile=None,base_materials=None,supplemental_materials=None,keyring_materials=None,
        official_trust=trust,test_trust=trust,products={},retention=None)
    raw_d=C.encoded(d);raw_g=C.encoded(grant);raw_a=C.encoded(assembler)
    request=dict(schema=3,kind='ROOT_AUTHORIZED_CURRENT_HOSTED_LAUNCH_V3',issuer='Root',approved=True,trusted_main_commit=case['main']['cid'],launcher=case['main']['launcher'],
        delegation_json=raw_d.decode(),delegation_pin=C.pin(raw_d),staged_inputs=None,staged_root=None,control_name='cachy-current-hosted-'+case['nonce'],
        authorization=dict(jobs_metadata=True,privileged_controller=True,launcher_limits=C.LIMITS,host_prerequisites=True,whole_timing=C.TIMING,material_staging=True),
        material_staging=dict(grant_json=raw_g.decode(),grant_pin=C.pin(raw_g),assembler_request=dict(json=raw_a.decode(),pin=C.pin(raw_a))))
    b=C.binding(case)
    admission=dict(schema=1,kind='ROOT_SOURCE205_ONCE_ADMISSION_V1',issuer='Root',approved=True,binding=b,issued_epoch=991,expires_epoch=1990,resources=C.RESOURCES,
        reservation=dict(held_by='Root',active=0,pending=0,group=C.GROUP,operation=C.OPERATION,no_exemptions=True))
    lease=dict(path=C.LEASE_PATH,dev=54,inode=59258250,uid=1000,gid=1000,mode=0o644,nlink=1,bytes=0,mtime_ns=1792920106392345934,ctime_ns=1792920106392345934)
    case['canonical_lease']=copy.deepcopy(lease)
    custody=dict(held_fd=3,held_fd_identity=lease,path_identity=lease,owner_pid=123,owner_starttime=456,owner_pidfd=4,
        owner_alive=True,owner_starttime_verified=True,pidfd_identity_verified=True,independent_nonblocking_rejected=True,lock_held=True,release='CLOSE_ONLY')
    sweeps=[dict(sequence=i,observation_id=str(i)*64,observed_epoch=994+i,statuses=list(C.STATUSES),pages_complete=True,all_jobs_complete=True,runs=[])for i in (1,2)]
    runtime=dict(schema=1,kind='ROOT_SOURCE205_ONCE_RUNTIME_V1',issuer='Root',approved=True,binding=b,issued_epoch=992,expires_epoch=1990,lease_identity=lease,custody=custody,sweeps=sweeps)
    registration=dict(schema=1,kind='ROOT_SOURCE205_WORKFLOW_REGISTRATION_V1',issuer='Root',approved=True,binding=b,observed_epoch=998,repository=C.REPOSITORY,workflow_id=707,path=C.WORKFLOW,state='active',body_pin=C.WORKFLOW_PIN)
    readback=dict(schema=1,kind='ROOT_SOURCE205_READBACK_V1',issuer='Root',approved=True,binding=b,observed_epoch=998,source=case['source'],main=case['main'],profile_pin=C.PROFILE,publication_complete=True,main_adoption_complete=True)
    once=dict(schema=1,kind='ROOT_SOURCE205_ONCE_GUARD_V1',issuer='Root',approved=True,binding=b,observed_epoch=998,once=True,retry=False,prior_run_ids=[],prior_intents=[],uncertain=False,post_count=0,
        phase='BEFORE_POST',output_fresh=True,exclusive_intent=True,runtime_pin=None,request_pin=None)
    return copy.deepcopy(dict(case=case,admission=admission,runtime=runtime,registration=registration,readback=readback,once=once,request=request))


def pack(values):
    values=copy.deepcopy(values);values['once']['runtime_pin']=C.pin(C.encoded(values['runtime']));values['once']['request_pin']=C.pin(C.encoded(values['request']))
    values['case']['pins']={name:C.pin(C.encoded(values[name]))for name in C.OPERANDS[1:]}
    raw={name:C.encoded(value)for name,value in values.items()};return raw,{name:C.pin(value)for name,value in raw.items()}


def change_request(values,which,mutate):
    request=values['request']
    if which=='delegation':
        value=C.decode(request['delegation_json'].encode());mutate(value);raw=C.encoded(value)
        request.update(delegation_json=raw.decode(),delegation_pin=C.pin(raw))
    elif which=='grant':
        value=C.decode(request['material_staging']['grant_json'].encode());mutate(value);raw=C.encoded(value)
        request['material_staging'].update(grant_json=raw.decode(),grant_pin=C.pin(raw))
    else:
        row=request['material_staging']['assembler_request'];value=C.decode(row['json'].encode());mutate(value);raw=C.encoded(value)
        row.update(json=raw.decode(),pin=C.pin(raw))


class Controls(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        profile=G.model_inputs()[3];profile['materials']={key.lower():row for key,row in profile['materials'].items()};self.profile_raw=C.encoded(profile)
        self.real_profile=C.PROFILE;self.stack.enter_context(patch.object(C,'PROFILE',C.pin(self.profile_raw)))
        self.values=model_case(profile)
    def tearDown(self):self.assertEqual(ACTORS,[])
    def call(self,values=None,**changes):
        raw,pins=pack(self.values if values is None else values)
        kwargs=dict(now=NOW,core_raw=CORE_RAW,profile_raw=self.profile_raw);kwargs.update(changes)
        return C.qualify(raw,pins,**kwargs)
    def test_complete_model_bindings_qualify_only_as_data_and_copy_root_request(self):
        raw,pins=pack(self.values);result=C.qualify(raw,pins,now=NOW,core_raw=CORE_RAW,profile_raw=self.profile_raw)
        self.assertTrue(result['ready_for_external_root_operator']);self.assertFalse(result['Root_authentication']);self.assertIsNone(result['Root_acceptance'])
        self.assertFalse(result['lease_observed_here']);self.assertFalse(result['native_entered']);self.assertEqual(result['POSTs'],0)
        self.assertEqual(result['request_raw'],raw['request']);self.assertEqual(result['dispatch_inputs'],dict(root_request_json=raw['request'].decode(),root_request_sha256=pins['request']['sha256']))
        self.assertEqual(result['operator_argv'],['gh','api','--method','POST','repos/'+C.REPOSITORY+'/actions/workflows/707/dispatches','--input','-'])
        self.assertEqual(C.decode(result['dispatch_body'])['ref'],'codex/MODEL-Source205');self.assertFalse(result['retry'])
    def test_null_templates_are_unissued_and_have_no_source_main_or_workflow_default(self):
        with patch.object(C,'PROFILE',self.real_profile):templates=C.templates()
        for name,value in templates.items():
            self.assertEqual(C.decode((HERE/name).read_bytes()),value);self.assertIsNone(value['issuer']);self.assertIsNone(value['approved'])
            self.assertIsNone(value['issued_epoch']);self.assertIsNone(value['expires_epoch'])
        case=C.templates()['Root-case.TEMPLATE.json'];self.assertIsNone(case['source']['cid']);self.assertIsNone(case['main']['cid']);self.assertIsNone(case['workflow_id'])
        with self.assertRaises(ValueError):C.validate_case(case,NOW)
    def test_case_cid_schema_profile_old_v6_main_and_workflow_refuse(self):
        mutations=(lambda v:v['case']['source'].update(cid=C.SOURCE196),lambda v:v['case']['source'].update(source_map=G.P.BASES['source196_basis']['source_map']),
            lambda v:v['case'].update(schema=True),lambda v:v['case'].update(workflow_id=None),lambda v:v['case']['main']['launcher'].update(sha256='f8387c748f31698b45656998248f099a8207bb58f7f9d7e70ef53a73be286d97'),
            lambda v:v['case']['main']['reader'].update(bytes=True),lambda v:v['case']['main']['workflow'].update(member='.github/workflows/native-arm-build.yml'),lambda v:v['case']['source'].update(cid=C.CONSTRUCTOR))
        for index,mutate in enumerate(mutations):
            value=copy.deepcopy(self.values);mutate(value)
            with self.subTest(index=index),self.assertRaises(ValueError):self.call(value)
    def test_each_unissued_approval_expiry_and_binding_refuse(self):
        for name in C.OPERANDS[:-1]:
            for field,changed in (('approved',None),('issuer','MODEL_NOT_ROOT')):
                value=copy.deepcopy(self.values);value[name][field]=changed
                with self.subTest(name=name,field=field),self.assertRaises(ValueError):self.call(value)
        for now in (True,0,1990,999999):
            with self.subTest(now=now),self.assertRaises(ValueError):self.call(now=now)
        for name in ('admission','runtime','registration','readback','once'):
            value=copy.deepcopy(self.values);value[name]['binding']['source']=C.SOURCE196
            with self.subTest(name=name),self.assertRaises(ValueError):self.call(value)
    def test_exact_profile_core_pin_and_external_operand_pin_refuse_rehash(self):
        self.assertEqual(self.real_profile,dict(bytes=21451,sha256='99198c00308780aaf95e803c43d01ab185b55a049731287b7644c2425dd90a12'))
        for changes in (dict(core_raw=CORE_RAW+b' '),dict(profile_raw=self.profile_raw+b' ')):
            with self.subTest(changes=list(changes)),self.assertRaises(ValueError):self.call(**changes)
        raw,pins=pack(self.values)
        for name in C.OPERANDS:
            altered=dict(raw);altered[name]+=b' '
            with self.subTest(name=name),self.assertRaises(ValueError):C.qualify(altered,pins,now=NOW,core_raw=CORE_RAW,profile_raw=self.profile_raw)
    def test_resource_exemptions_or_nonzero_reservation_refuse(self):
        for mode in ('case-limit','admission-limit','exemption','active','pending','reservation'):
            value=copy.deepcopy(self.values)
            if mode=='case-limit':value['case']['resources']['launcher_limits']['launcher_seconds']+=1
            elif mode=='admission-limit':value['admission']['resources']['stage_limits']['builder_cpus']=8
            elif mode=='exemption':value['case']['resources']['exemptions']=['MODEL_EXEMPTION']
            elif mode in ('active','pending'):value['admission']['reservation'][mode]=1
            else:value['admission']['reservation']['no_exemptions']=False
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.call(value)
    def test_fresh_complete_double_all_status_all_job_census_is_required(self):
        for mode in ('one','same-id','stale','missing-status','pagination','jobs-complete','heavy','unknown','job-unknown','job-arm64','empty-jobs','appeared','moved'):
            value=copy.deepcopy(self.values);runtime=value['runtime'];sweep=runtime['sweeps'][0]
            if mode=='one':runtime['sweeps'].pop()
            elif mode=='same-id':runtime['sweeps'][1]['observation_id']=sweep['observation_id']
            elif mode=='stale':sweep['observed_epoch']=0
            elif mode=='missing-status':sweep['statuses'].pop()
            elif mode=='pagination':sweep['pages_complete']=False
            elif mode=='jobs-complete':sweep['all_jobs_complete']=False
            else:
                run=dict(run=8,attempt=1,status='in_progress',workflow_id=9,source='7'*40,group='other',operation='other',classification='LIGHT_OTHER',body_pin=C.pin(b'MODEL_BODY'),
                    jobs=[dict(job=11,status='in_progress',classification='LIGHT_OTHER',runner_arch='X64',body_pin=C.pin(b'MODEL_JOB'))]);sweep['runs']=[run]
                if mode=='heavy':run['classification']='HEAVY'
                elif mode=='unknown':run['classification']='UNKNOWN'
                elif mode=='job-unknown':run['jobs'][0]['runner_arch']='UNKNOWN'
                elif mode=='job-arm64':run['jobs'][0]['runner_arch']='ARM64'
                elif mode=='empty-jobs':run['jobs']=[]
                elif mode=='moved':runtime['sweeps'][1]['runs']=[copy.deepcopy(run)];runtime['sweeps'][1]['runs'][0]['status']='pending'
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.call(value)
    def test_converged_qualified_automatic_x86_light_rows_are_data_only(self):
        value=copy.deepcopy(self.values)
        run=dict(run=8,attempt=1,status='in_progress',workflow_id=9,source='7'*40,group='other',operation='other',classification='LIGHT_OTHER',body_pin=C.pin(b'MODEL_BODY'),
            jobs=[dict(job=11,status='in_progress',classification='LIGHT_OTHER',runner_arch='X64',body_pin=C.pin(b'MODEL_JOB'))])
        for sweep in value['runtime']['sweeps']:sweep['runs']=[copy.deepcopy(run)]
        self.assertTrue(self.call(value)['ready_for_external_root_operator'])
        for field,changed in (('workflow_id',707),('source','a'*40),('group',C.GROUP),('operation',C.OPERATION)):
            altered=copy.deepcopy(value)
            for sweep in altered['runtime']['sweeps']:sweep['runs'][0][field]=changed
            with self.subTest(field=field),self.assertRaises(ValueError):self.call(altered)
    def test_custody_fd_pidfd_starttime_identity_and_closeonly_are_mandatory(self):
        for field,changed in (('held_fd',True),('owner_pidfd',3),('owner_pid',0),('owner_starttime',0),('owner_alive',False),('owner_starttime_verified',False),('pidfd_identity_verified',False),('independent_nonblocking_rejected',False),('lock_held',False),('release','UNLOCK')):
            value=copy.deepcopy(self.values);value['runtime']['custody'][field]=changed
            with self.subTest(field=field),self.assertRaises(ValueError):self.call(value)
        value=copy.deepcopy(self.values);value['runtime']['custody']['path_identity']['inode']+=1
        with self.assertRaises(ValueError):self.call(value)
    def test_registration_readback_prior_uncertainty_and_replay_refuse(self):
        for mode in ('workflow-id','workflow-state','main-readback','source-readback','readback-partial','prior-run','prior-intent','uncertain','posted','wrong-phase','reused-output','not-exclusive'):
            value=copy.deepcopy(self.values)
            if mode=='workflow-id':value['registration']['workflow_id']+=1
            elif mode=='workflow-state':value['registration']['state']='disabled_manually'
            elif mode=='main-readback':value['readback']['main']['cid']='8'*40
            elif mode=='source-readback':value['readback']['source']['cid']=C.SOURCE196
            elif mode=='readback-partial':value['readback']['publication_complete']=False
            elif mode=='prior-run':value['once']['prior_run_ids']=[1]
            elif mode=='prior-intent':value['once']['prior_intents']=['MODEL_uncertain']
            elif mode=='uncertain':value['once']['uncertain']=True
            elif mode=='posted':value['once']['post_count']=1
            elif mode=='wrong-phase':value['once']['phase']='AFTER_POST'
            elif mode=='reused-output':value['once']['output_fresh']=False
            else:value['once']['exclusive_intent']=False
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.call(value)
    def test_final_once_guard_cannot_predate_qualified_inputs(self):
        for name in ('admission','runtime','registration','readback','sweeps'):
            value=copy.deepcopy(self.values)
            if name=='sweeps':
                for sweep in value['runtime']['sweeps']:sweep['observed_epoch']=999
            elif name in ('admission','runtime'):value[name]['issued_epoch']=999
            else:value[name]['observed_epoch']=999
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'ONCE_CAUSAL_ORDER'):self.call(value)
    def test_root_request_delegation_grant_and_assembler_semantics_refuse_drift(self):
        for mode in ('schema3','retarget','nonce','source196','capability','grant','grant-clock','assembler','trust','url'):
            value=copy.deepcopy(self.values)
            if mode=='schema3':change_request(value,'delegation',lambda d:d.update(schema=3))
            elif mode=='retarget':change_request(value,'delegation',lambda d:d['programs']['materials_stager'].update(sha256='0'*64))
            elif mode=='nonce':change_request(value,'delegation',lambda d:d.update(nonce='0'*64))
            elif mode=='source196':change_request(value,'delegation',lambda d:d['binding'].update(source=C.SOURCE196))
            elif mode=='capability':change_request(value,'delegation',lambda d:d['capability'].update(allow_pair_adoption=True))
            elif mode=='grant':change_request(value,'grant',lambda g:g.update(approved=None))
            elif mode=='grant-clock':change_request(value,'grant',lambda g:g.update(expires_epoch=999999))
            elif mode=='assembler':change_request(value,'assembler',lambda a:a.update(extra='MODEL_UNKNOWN'))
            elif mode=='trust':change_request(value,'assembler',lambda a:a.update(official_trust=None))
            else:change_request(value,'grant',lambda g:g['redirect_urls'].update({'MODEL-00.pkg':['http://private.invalid/secret']}))
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.call(value)
    def test_unknown_duplicate_boolean_and_cap_inputs_refuse(self):
        value=copy.deepcopy(self.values);value['case']['extra']='MODEL_UNKNOWN'
        with self.assertRaises(ValueError):self.call(value)
        raw,pins=pack(self.values)
        for bad in (b'{"schema":1,"schema":1}\n',b'x'*(C.MAX_BYTES+1)):
            altered=dict(raw);altered['runtime']=bad;selected=dict(pins);selected['runtime']=C.pin(bad)
            with self.assertRaises(ValueError):C.qualify(altered,selected,now=NOW,core_raw=CORE_RAW,profile_raw=self.profile_raw)
        value=copy.deepcopy(self.values);value['once']['post_count']=False
        with self.assertRaises(ValueError):self.call(value)


def genuine_controls(path):
    class GenuineSource205Profile(unittest.TestCase):
        def test_real_unissued_profile_and_model_root_assertions_are_data_only(self):
            raw=Path(path).read_bytes();self.assertEqual(C.pin(raw),C.PROFILE)
            values=model_case(C.decode(raw));operands,pins=pack(values)
            result=C.qualify(operands,pins,now=NOW,core_raw=CORE_RAW,profile_raw=raw)
            self.assertTrue(result['ready_for_external_root_operator']);self.assertFalse(result['Root_authentication']);self.assertEqual(result['POSTs'],0)
            self.assertEqual(ACTORS,[])
    return GenuineSource205Profile


if __name__=='__main__':
    parser=argparse.ArgumentParser(add_help=False);parser.add_argument('--genuine-profile',type=Path)
    chosen,remaining=parser.parse_known_args()
    if chosen.genuine_profile is not None:globals()['GenuineSource205Profile']=genuine_controls(chosen.genuine_profile)
    unittest.main(argv=[sys.argv[0],*remaining])
