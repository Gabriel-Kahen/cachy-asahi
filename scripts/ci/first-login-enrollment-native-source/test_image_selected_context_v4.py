#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert image/context-v4 API integration; no actors, trust issuance or network."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

# Reuse the committed context author's ordinary DATA carrier, including its
# exact predecessor fixture and actor-denial audit fence. Do not copy a relaxed
# context implementation or forge a replacement public API.
F=module('image_actual_context_v4_fixture',HERE/'test_delegated_context_v4.py')
unittest.addModuleCleanup(F.BASE.cleanup)
P=module('image_selected_actual_context_v4',HERE/'payload/native/image_current_v3.py')
E=module('executor_selected_actual_context_v4',HERE/'payload/native/owned_executor_current_v3.py')


def put(path,body):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body);path.chmod(0o600)
    return dict(path=str(path),**P.pin(body))


class ImageContextIntegration(unittest.TestCase):
    def setUp(self):
        self.fixture=F.SelectedComponentTests('test_selected_completed_producer_v3_and_v4_are_distinct_historical_runs')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        clock=mock.patch.object(P.time,'time',return_value=F.NOW+8000);clock.start();self.addCleanup(clock.stop)

    def operands(self,version=4,different_workspace=False,**selection):
        d,c,args=self.fixture.fixture(version,different_workspace,**selection)
        root=self.fixture.root.parent/'image-public-operands';root.mkdir(exist_ok=True)
        mapping={'producer_delegation':'producer_delegation_raw','producer_context':None,'completion':'completion_raw',
                 'pair':'pair_raw','root_component':'root_component_raw','root_test':'root_test_raw'}
        refs={name:put(root/(name+'.json'),F.M.encoded(args['producer_context'])if field is None else args[field])for name,field in mapping.items()}
        pair=dict(kind=P.SELECTED_PRODUCT_KIND,selection_role=None,
                  archives=[put(root/('archive-%d.pkg'%i),raw)for i,raw in enumerate(args['archive_bodies'])],
                  signatures=[put(root/('signature-%d.sig'%i),raw)for i,raw in enumerate(args['signature_bodies'])],**refs)
        component=d['pair_selection']['component']
        row=dict(name=component['name'],version=component['version'],arch=component['architecture'],archive=pair['archives'][0],signature=pair['signatures'][0],
                 Root_decision=pair['root_component'],Root_verification=pair['root_test'],pair_adoption=pair)
        key=dict(public_key=put(root/'test.public',args['public_test_key_raw']),fingerprint='E'*40)
        return d,c,row,key

    def adopt(self,d,c,row,key):return P.adopt_selected_product(row,key,F.M,d,c)

    def test_exact_program_registry_and_source_map_identity(self):
        self.assertEqual(P.CONTEXT_PROGRAM_PINS[4],P.pin(F.PROGRAM.read_bytes()))
        self.assertEqual(P.CONTEXT_PROGRAM_PINS[3],P.pin(F.M._PREDECESSOR))
        self.assertEqual(F.M.decode(self.fixture.map_raw)['kind'],'CURRENT_ONBOARDING_CLOSED_SOURCE_V3')

    def test_exact_reviewed_component_to_producer_mapping(self):
        self.assertEqual(F.M.COMPONENT_PRODUCER_STAGES,{
            ('cachy-asahi-repository-enrollment','0.4.0-1','any'):'backend',
            ('cachy-asahi-first-login','0.1.0-3','any'):'backend',
            ('cachy-asahi-first-login-ui','0.2.0-2','any'):'ui'})
        for (name,version,arch),stage in F.M.COMPONENT_PRODUCER_STAGES.items():
            for producer_version in (3,4):
                with self.subTest(component=name,producer_version=producer_version):
                    d,c,row,key=self.operands(producer_version,producer_stage=stage,consumer_stage='lifecycle',
                        component=dict(name=name,version=version,architecture=arch))
                    receipt=self.adopt(d,c,row,key)
                    self.assertEqual(receipt['component'],dict(name=name,version=version,architecture=arch))
                    self.assertEqual(c['stage'],'lifecycle');self.assertTrue(receipt['current_stage_gpg_required'])

    def test_selected_ui_component_cannot_use_ui_consumer_or_backend_producer(self):
        ui=dict(name='cachy-asahi-first-login-ui',version='0.2.0-2',architecture='any')
        with self.assertRaises(ValueError):self.operands(producer_stage='ui',consumer_stage='ui',component=ui)
        d,c,row,key=self.operands(producer_stage='backend',consumer_stage='lifecycle',component=ui)
        with self.assertRaises(ValueError):self.adopt(d,c,row,key)

    def test_actual_executor_and_image_admission_rejoin_genuine_v3_and_current_v4_source(self):
        # No patched registry, context validation, policy validation or loader.
        # These authentic program bytes and ordinary MODEL Source grants prove
        # parser composition only, never operational Root authority or a role.
        for version in (3,4):
            with self.subTest(version=version):
                fixture=F.V3.ContextTests('test_capture_and_replay_keep_authority_unset')if version==3 else F.SelectedComponentTests('test_selected_completed_producer_v3_and_v4_are_distinct_historical_runs')
                fixture.setUp()
                try:
                    policy=P.decoded((HERE/'owned-executor-current-v3.policy.PROPOSAL.json').read_bytes())
                    policy['context']=fixture.limits
                    policy['stage_capabilities']=copy.deepcopy(policy['stage_capability_proposals'])
                    policy['image_alpm_capabilities']=P.CAPS
                    fixture.files['inputs/policy.json']=P.encoded(policy)
                    fixture.files['programs/executor.py']=(HERE/'payload/native/owned_executor_current_v3.py').read_bytes()
                    fixture.files['programs/image.py']=(HERE/'payload/native/image_current_v3.py').read_bytes()
                    fixture.files['programs/owned_process.py']=(HERE.parents[2]/'scripts/virtual/owned_process.py').read_bytes()
                    self.assertEqual(P.pin(fixture.files['programs/owned_process.py'])['sha256'],E.OWNED_SHA)
                    fixture.reseal()
                    d=copy.deepcopy(fixture.d)
                    d['binding']['source_lock']=P.pin(fixture.map_raw)
                    for role in ('context','image','image_executor'):
                        member=d['programs'][role]['member'];d['programs'][role].update(P.pin(fixture.files[member]))
                    d['programs']['owned_process']=dict(member='programs/owned_process.py',**P.pin(fixture.files['programs/owned_process.py']))
                    d['policy'].update(P.pin(fixture.files[d['policy']['member']]))
                    d['capability'].update(policy['stage_capabilities']['backend'])
                    H=E.load_pinned(fixture.root,d['programs']['context'],'actual_context_source_'+str(version))
                    raw=P.encoded(d)
                    context=H.capture_context(raw,P.pin(raw)['sha256'],fixture.root,environ=fixture.env,jobs_response=fixture.response(),now=F.NOW)
                    with mock.patch.object(P.time,'time',return_value=F.NOW):
                        admitted,actual,observed_policy,owned=E.admitted_inputs(fixture.root,raw,P.pin(raw)['sha256'],context)
                    self.assertEqual(admitted,d);self.assertEqual(observed_policy,policy)
                    self.assertEqual(E.context_contract(admitted,context,actual,fixture.root),version)
                    self.assertEqual(P.context_contract(admitted,context,actual,fixture.root),version)
                    self.assertEqual(context['issuer'],'DELEGATED_CONTEXT_PROGRAM_V'+str(version))
                    self.assertTrue(callable(owned.supervise));self.assertIsNone(context['Root_final_acceptance'])
                    # Only the hardware observations are MODEL values here.
                    # Image admission imports and validates the same real Source
                    # context bytes and policy as the unmocked executor parser.
                    domain=lambda role:dict(pid=11 if role=='owner'else 12,starttime=123,cgroup='/MODEL/'+d['nonce']+'/'+role,limits=policy['image_domains'][role])
                    facts=dict(api=P.API,binding=context['binding'],nonce=d['nonce'],stage=d['stage'],
                        code_pin=H.descriptor(d['programs']['image_executor']),domain_policy_pin=P.pin(fixture.files[d['policy']['member']]),
                        native_architecture='aarch64',uid=1001,gid=1001,owner_domain=domain('owner'),daemon_domain=domain('daemon'),
                        daemon_pidfd_held=True,whole_owner_deadline_enforced=True,daemon_deadline_enforced=True,exclusive_daemon=True,
                        docker_endpoint=policy['image_endpoint_template'].format(nonce=d['nonce']),
                        storage=dict(quota_bytes=policy['image_storage_bytes'],kernel_enforced=True,scope='ALL_IMAGE_OWNER_CONTEXT_DAEMON_WRITES'))
                    class ModelExecutor:
                        pass
                    executor=ModelExecutor();executor.facts=facts
                    def observed(pid):return dict(facts['owner_domain'if pid==11 else'daemon_domain'],executable='python3'if pid==11 else'dockerd')
                    with mock.patch.object(P.time,'time',return_value=F.NOW),mock.patch.object(P,'native_identity',return_value=dict(system='Linux',machine='aarch64',uid=1001,gid=1001,pid=11)),mock.patch.object(P,'actual_domain',side_effect=observed):
                        image_d,image_c,image_policy,image_H=P.admit(raw,P.pin(raw)['sha256'],context,fixture.root,executor)
                    self.assertEqual((image_d,image_c,image_policy),(d,context,policy))
                    self.assertEqual(P.context_contract(image_d,image_c,image_H,fixture.root),version)
                finally:fixture.doCleanups()

    def test_superseded_v4_body_and_v4_mislabeled_as_v3_refuse_before_import(self):
        d,c,_,_=self.operands()
        for wrong in ('superseded_v4','v4_as_v3'):
            changed=copy.deepcopy(d)
            if wrong=='superseded_v4':changed['programs']['context'].update(bytes=42498,sha256='7dc4af2ea5db1f36db62e9df0c00cd728edfa16114b7218a9ee494965f638566')
            else:changed.update(schema=3,kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3')
            raw=P.encoded(changed)
            with self.subTest(wrong=wrong),mock.patch.object(E,'load_pinned',side_effect=AssertionError('no import of unsupported basis'))as load:
                with self.assertRaises(ValueError):E.admitted_inputs(self.fixture.root,raw,P.pin(raw)['sha256'],c)
                load.assert_not_called()
            with mock.patch.object(P,'load_program',side_effect=AssertionError('no import of unsupported basis'))as load:
                with self.assertRaises(ValueError):P.admit(raw,P.pin(raw)['sha256'],c,self.fixture.root,None)
                load.assert_not_called()

    def test_original_v3_and_v4_completed_producers_use_genuine_v4_consumer(self):
        for version in (3,4):
            with self.subTest(producer_schema=version):
                d,c,row,key=self.operands(version)
                result=self.adopt(d,c,row,key)
                self.assertEqual(result['binding']['run'],'23456');self.assertEqual(result['producer_binding']['run'],'12345')
                self.assertEqual(result['schema'],4);self.assertEqual(result['issuer'],'DELEGATED_CONTEXT_PROGRAM_V4')
                self.assertTrue(result['current_stage_gpg_required']);self.assertIsNone(result['Root_final_acceptance'])
                self.assertFalse(result['independent_component_acceptance']);self.assertFalse(result['hardware_acceptance']);self.assertFalse(result['release_acceptance'])
                self.assertNotEqual(result['signatures'][0],result['signatures'][1])
                for name,field in (('root_component','root_component_decision_pin'),('root_test','root_test_decision_pin')):
                    self.assertEqual(result[field],P.pin(P.reference(row['pair_adoption'][name])))

    def test_historical_workspace_can_disappear_without_renewal(self):
        d,c,row,key=self.operands(3,True)
        result=self.adopt(d,c,row,key)
        producer=P.decoded(P.reference(row['pair_adoption']['producer_delegation']))
        self.assertLess(producer['expires_epoch'],F.NOW+8000)
        self.assertEqual(result['producer_binding']['run'],'12345')

    def test_explicit_role_map_is_passed_unchanged(self):
        d,c,row,key=self.operands();d['pair_selections']={'backend':d.pop('pair_selection')}
        c=self.fixture.reobserve(d,c);row['pair_adoption']['selection_role']='backend'
        self.assertEqual(self.adopt(d,c,row,key)['schema'],4)
        row['pair_adoption']['selection_role']='other'
        with self.assertRaises(ValueError):self.adopt(d,c,row,key)

    def test_every_second_body_and_historical_operand_is_bound(self):
        d,c,row,key=self.operands()
        fields=('producer_delegation','producer_context','completion','pair','root_component','root_test')
        for field in fields:
            with self.subTest(field=field):
                changed=copy.deepcopy(row);ref=put(self.fixture.root.parent/('wrong-'+field+'.json'),P.encoded(dict(MODEL_ONLY='substituted')))
                changed['pair_adoption'][field]=ref
                if field in ('root_component','root_test'):
                    changed['Root_decision'if field=='root_component'else'Root_verification']=ref
                with self.assertRaises((ValueError,KeyError)):self.adopt(d,c,changed,key)
        for group in ('archives','signatures'):
            changed=copy.deepcopy(row);changed['pair_adoption'][group][1]=put(self.fixture.root.parent/('wrong-'+group),b'MODEL SUBSTITUTED SECOND BODY')
            with self.subTest(group=group),self.assertRaises(ValueError):self.adopt(d,c,changed,key)

    def test_component_key_and_selected_capability_cannot_be_substituted(self):
        d,c,row,key=self.operands()
        changed=dict(row,version='0.0-wrong')
        with self.assertRaises(ValueError):self.adopt(d,c,changed,key)
        with self.assertRaises(ValueError):self.adopt(d,c,row,dict(key,fingerprint='F'*40))
        changed_key=dict(key,public_key=put(self.fixture.root.parent/'wrong.public',b'MODEL WRONG PUBLIC KEY'))
        with self.assertRaises(ValueError):self.adopt(d,c,row,changed_key)
        d['capability']['allow_selected_pair_adoption']=False
        with self.assertRaises(ValueError):self.adopt(d,c,row,key)

    def test_current_root_decision_expiry_is_strict(self):
        d,c,row,key=self.operands();decision=P.decoded(P.reference(row['Root_decision']))
        for now in (decision['expires_epoch'],decision['expires_epoch']+1):
            with self.subTest(now=now),mock.patch.object(P.time,'time',return_value=now),self.assertRaises(ValueError):self.adopt(d,c,row,key)


if __name__=='__main__':unittest.main()
