# SPDX-License-Identifier: MIT
"""Pure hosted domain/admission DATA controls; no command or role executes."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('baseline_hosted_definition_test',HERE/'payload/hosted/entry.py')
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
BINDING=dict(source='1'*40,ref='refs/heads/codex/baseline-observation-fixture',run='1234',job='5678')
IMAGE='sha256:'+'2'*64
ROOT=Path('/passive/source-fixture')
LABELS={'cachy-asahi.hosted-perl-baseline':'opaque-owned-fixture','cachy-asahi.hosted-perl-baseline.source':BINDING['source']}


def actual():
    own=e.owner(BINDING)
    return dict(Name='/'+own['name'],Image=IMAGE,
        Config=dict(User='0:0',Labels=dict(LABELS,**{own['label']:own['token'],own['label']+'.source':BINDING['source']})),
        HostConfig=dict(ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=None,
            Memory=536870912,MemorySwap=536870912,NanoCpus=2000000000,PidsLimit=64,
            SecurityOpt=['no-new-privileges'],Privileged=False,Devices=[],DeviceRequests=[],
            VolumesFrom=None,Tmpfs=None),
        Mounts=[dict(Type='bind',Source=str(ROOT),Destination='/inputs',RW=False)])


def admission_fixture():
    policy=json.loads((HERE/'policy.json').read_bytes())
    observer_policy=(HERE/'observer-policy.json').read_bytes()
    policy_sha=hashlib.sha256(observer_policy).hexdigest()
    admission=dict(schema=1,status='ROOT_ADMITTED_SINGLE_PERL_BASELINE_OBSERVATION_ATTEMPT',
        authority='Root',operation=e.c.OPERATION,source=BINDING['source'],ref=BINDING['ref'],
        source_map_sha256='3'*64,observer_policy_sha256=policy_sha,resources=policy,
        fixed_path_capture_policy_reviewed=True,readonly_cap0_observer_domain_reviewed=True,
        holds_preserved=True)
    return admission,policy,observer_policy,dict(observer_policy_sha256=policy_sha)


def binding_check(admission,policy,observer_policy,contract):
    raw=e.c.encode(admission)
    args=SimpleNamespace(source_sha=BINDING['source'],map_sha256='3'*64,
        approval_sha256=e.c.pin(raw)['sha256'])
    documents={'perl-baseline-root-admission.json':raw,'contract.json':e.c.encode(contract),
        'policy.json':e.c.encode(policy),'observer-policy.json':observer_policy}
    def read(path,*args):return documents[Path(path).name]
    with patch.dict(e.os.environ,{'RUNNER_TEMP':'/passive/runner-temp-fixture'}),patch.object(e.c,'verify_source') as verified,patch.object(e.c,'context',return_value=copy.deepcopy(BINDING)),patch.object(e.c,'read',side_effect=read),patch.object(e,'Commands',side_effect=AssertionError('actors prohibited')):
        result=e.base_binding(args)
        verified.assert_called_once_with(e.ROOT,args.map_sha256)
        return result


class HostedDataTests(unittest.TestCase):
    def test_operation_and_admission_are_separate_from_mutating_lifecycle(self):
        self.assertEqual(e.c.OPERATION,'perl5423-baseline-observation-native-v1')
        template=json.loads((HERE/'root-admission.TEMPLATE.json').read_bytes())
        self.assertEqual(template['status'],'UNADMITTED')
        self.assertIsNone(template['authority'])
        self.assertFalse(template['readonly_cap0_observer_domain_reviewed'])
        self.assertFalse(template['fixed_path_capture_policy_reviewed'])

    def test_ownership_names_change_with_source_ref_run(self):
        before=e.owner(BINDING)
        for key,value in [('source','a'*40),('ref','refs/heads/codex/other'),('run','4321')]:
            with self.subTest(key=key):
                changed=e.owner(dict(BINDING,**{key:value}))
                self.assertNotEqual(changed['token'],before['token'])
                self.assertNotEqual(changed['name'],before['name'])
                self.assertNotEqual(changed['tag'],before['tag'])

    def test_observer_receives_only_public_image_source_policy_binding(self):
        argv,binding=e.observer_argv(ROOT,IMAGE,BINDING,'4'*64)
        self.assertEqual(set(binding),{'source','ref','run','job','image','token','policy_sha256'})
        self.assertEqual(json.loads(argv[-1]),binding)
        self.assertEqual(binding['image'],IMAGE)
        self.assertEqual(argv[-5:-1],['-I','-B','/inputs/hosted/observer.py','--binding-json'])
        self.assertIn('--network=none',argv)
        self.assertIn('--read-only',argv)
        self.assertIn('--cap-drop=ALL',argv)
        self.assertFalse(any('cap-add' in item or 'SYS_ADMIN' in item or 'CHOWN' in item for item in argv))
        self.assertEqual(argv[argv.index('--mount')+1],'type=bind,src=/passive/source-fixture,dst=/inputs,readonly')
        self.assertNotIn('ROOT_ADMITTED',argv[-1])
        self.assertNotIn('pacman',argv)
        self.assertNotIn('perl',argv)

    def test_exact_readonly_domain_passes_without_observation_or_command(self):
        self.assertEqual(e.inspect_observer(actual(),ROOT,IMAGE,BINDING,LABELS),e.owner(BINDING))

    def test_root_uid_capabilities_and_privilege_drift_refuse(self):
        changes=[('User','1001:1001'),('CapDrop',[]),('CapAdd',['CHOWN']),
            ('CapAdd',['SYS_ADMIN']),('Privileged',True),('SecurityOpt',[])]
        for key,value in changes:
            with self.subTest(key=key,value=value):
                row=actual();row['Config' if key=='User' else 'HostConfig'][key]=value
                with self.assertRaises(ValueError):e.inspect_observer(row,ROOT,IMAGE,BINDING,LABELS)

    def test_each_resource_limit_and_network_readonly_requirement_refuses_drift(self):
        for key,value in [('ReadonlyRootfs',False),('NetworkMode','host'),('Memory',1073741824),
            ('MemorySwap',1073741824),('NanoCpus',1000000000),('PidsLimit',128)]:
            with self.subTest(key=key):
                row=actual();row['HostConfig'][key]=value
                with self.assertRaises(ValueError):e.inspect_observer(row,ROOT,IMAGE,BINDING,LABELS)

    def test_devices_volumes_and_tmpfs_refuse(self):
        for key,value in [('Devices',[{'PathOnHost':'/dev/null'}]),('DeviceRequests',[{'Count':1}]),
            ('VolumesFrom',['other']),('Tmpfs',{'/tmp':'rw'})]:
            with self.subTest(key=key):
                row=actual();row['HostConfig'][key]=value
                with self.assertRaises(ValueError):e.inspect_observer(row,ROOT,IMAGE,BINDING,LABELS)

    def test_mounts_must_be_one_source_readonly_bind(self):
        for key,value in [('Type','volume'),('Source','/other'),('Destination','/work'),('RW',True)]:
            with self.subTest(key=key):
                row=actual();row['Mounts'][0][key]=value
                with self.assertRaises(ValueError):e.inspect_observer(row,ROOT,IMAGE,BINDING,LABELS)
        row=actual();row['Mounts'].append(dict(Type='bind',Source='/writable',Destination='/work',RW=True))
        with self.assertRaises(ValueError):e.inspect_observer(row,ROOT,IMAGE,BINDING,LABELS)

    def test_image_and_labels_are_exactly_bound(self):
        for change in ['image','name','inherited-label','observer-token','extra-label']:
            with self.subTest(change=change):
                row=actual()
                if change=='image':row['Image']='sha256:'+'9'*64
                elif change=='name':row['Name']='/different'
                elif change=='inherited-label':row['Config']['Labels'].pop(next(iter(LABELS)))
                elif change=='observer-token':row['Config']['Labels'][e.owner(BINDING)['label']]='wrong'
                else:row['Config']['Labels']['unexpected']='label'
                with self.assertRaises(ValueError):e.inspect_observer(row,ROOT,IMAGE,BINDING,LABELS)

    def test_fixed_policy_review_needs_no_unknown_future_config_map(self):
        admission,policy,observer_policy,contract=admission_fixture()
        self.assertNotIn('image_expectations',admission)
        self.assertNotIn('image_expectations',contract)
        self.assertEqual(binding_check(admission,policy,observer_policy,contract),BINDING)

    def test_each_root_review_flag_and_status_remain_mandatory(self):
        for field,value in [('fixed_path_capture_policy_reviewed',False),
            ('readonly_cap0_observer_domain_reviewed',False),('holds_preserved',False),
            ('authority',None),('status','UNADMITTED'),('operation','perl5423-installed-lifecycle-native-v1')]:
            with self.subTest(field=field):
                admission,policy,observer_policy,contract=admission_fixture();admission[field]=value
                with self.assertRaises(ValueError):binding_check(admission,policy,observer_policy,contract)

    def test_observer_policy_and_resource_review_are_exact(self):
        for change in ['policy-sha','policy-bytes','resource-policy','source','ref','map']:
            with self.subTest(change=change):
                admission,policy,observer_policy,contract=admission_fixture()
                if change=='policy-sha':admission['observer_policy_sha256']='0'*64
                elif change=='policy-bytes':observer_policy+=b' '
                elif change=='resource-policy':admission['resources']=dict(policy,observer_memory_bytes=2**30)
                elif change=='source':admission['source']='0'*40
                elif change=='ref':admission['ref']='refs/heads/codex/other'
                else:admission['source_map_sha256']='0'*64
                with self.assertRaises(ValueError):binding_check(admission,policy,observer_policy,contract)


if __name__=='__main__':unittest.main()
