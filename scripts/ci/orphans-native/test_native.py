"""Host source, real temporary metadata, and inert ownership/acceptance controls."""
import copy
import ctypes
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import contract as C
import fixture as F
import job as J
import installed as I
import run as R

ROOT=Path(os.environ.get('ORPHANS_NATIVE_SOURCE',Path(__file__).resolve().parents[3]))
HERE=Path(__file__).resolve().parent
TOOL=ROOT/'packages/tools/cachy-asahi-orphans/cachy-asahi-orphans'


def receipt():
    observation=dict(default_database='PASS_EXACT575_METADATA_ONLY',base_protected=True,default_root='/',default_dbpath='/var/lib/pacman',
        readonly_enforced='UNPRIVILEGED_NO_DB_WRITE_ACCESS',fixture='PASS_VERSIONED_PROVIDED_OPTIONAL_CYCLE_PROTECTED',plan_verify='PASS_NOT_APPLIED',
        db_preserved=True,foreign_lock='PASS_REFUSAL_PRESERVED',apply_supported=False,reports={name:'0'*64 for name in C.REPORTS})
    return dict(status='PASS_ORPHANS_INSTALLED_READONLY_LIFECYCLE',base_count=574,installed_count=575,base574_preserved=True,user_preserved=True,
        reports_preserved=True,hardware='NOT_RUN',removal='NOT_IMPLEMENTED',architecture='aarch64',page_size=4096,
        events=[dict(phase=phase,count=count,base574_preserved=True,user_preserved=True,**(dict(observations=[dict(observation,home='orphans-home-'+k)
            for k in ('fresh','existing')]) if count==575 else dict(payloads_absent=True))) for phase,count in C.PHASES])


class Sources(unittest.TestCase):
    def test_final_eight_adopted_product_bytes_and_recipe(self):
        row=C.recipe(ROOT,C.PRODUCT);self.assertEqual(len(row['input_sha256']),8);self.assertEqual(len(C.files(C.PRODUCT)),5)
        self.assertEqual(row['input_sha256']['PKGBUILD'],'b7c6055622f57dd3a30101ee418301a2cb3e910f03ccbb99a25ebbbed4cb9391')
        self.assertEqual(row['metadata']['depends'],['python>=3.11','pacman'])
        for name,pin in C.policy(False)['source_files'].items():C.checked(TOOL.parent,name,pin)

    def test_default_unbound_policy_stops_before_native_checks_or_output(self):
        value=C.policy(False)|dict(status='UNBOUND_REQUIRES_ROOT',candidate_source=None);read=C.read
        with patch.object(C,'read',side_effect=lambda p,*a: value if Path(p).name=='input-policy.json' else read(p,*a)):
            with patch.object(R.platform,'system',side_effect=AssertionError('native boundary reached')),self.assertRaisesRegex(ValueError,'UNBOUND'):
                R.execute(ROOT,Path('/unused/base'),Path('/unused/output'),'1'*32)
            with self.assertRaisesRegex(ValueError,'UNBOUND'):C.verify_source(ROOT)

    def test_final_binding_and_infrastructure_identity(self):
        value=C.policy(False)|dict(status='ROOT_BOUND_FINAL_PRODUCT_SOURCE',candidate_source='1'*40)
        read=C.read
        with patch.object(C,'read',side_effect=lambda p,*a: value if Path(p).name=='input-policy.json' else read(p,*a)):C.verify_source(ROOT)
        for name,pin in C.read(HERE/'infrastructure-pins.json').items():C.checked(ROOT,name,pin)

    def test_product_and_dependency_byte_drift_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'sentinel';source.write_text('known');pin=dict(bytes=5,sha256=C.digest(source));C.checked(root,'sentinel',pin)
            source.write_text('drift')
            with self.assertRaises(ValueError):C.checked(root,'sentinel',pin)
            with self.assertRaises(ValueError):C.checked(root,'../sentinel',pin)

    def test_five_payload_identity_and_mutations(self):
        members={n:dict(type='0',mode=mode,uid=0,gid=0,sha256=C.digest(TOOL.parent/original)) for n,(original,mode) in C.files(C.PRODUCT).items()}
        good=dict(errors=[],elf={},members=members);self.assertEqual(len(C.payload(good,ROOT,C.PRODUCT)),5)
        for field,value in (('sha256','0'*64),('mode',0o777),('uid',1000),('type','2')):
            bad=copy.deepcopy(good);bad['members']['usr/bin/cachy-asahi-orphans'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):C.payload(bad,ROOT,C.PRODUCT)
        for key in ('missing','extra','elf'):
            bad=copy.deepcopy(good)
            if key=='missing':bad['members'].pop('usr/bin/cachy-asahi-orphans')
            elif key=='extra':bad['members']['etc/pacman.conf']=copy.deepcopy(next(iter(members.values())))
            else:bad['elf']={'unexpected':{}}
            with self.subTest(key=key),self.assertRaises(ValueError):C.payload(bad,ROOT,C.PRODUCT)

    def test_mandatory_actual_eighteen_checks_no_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'log';valid='Starting check()\n..................\nRan 18 tests in 3.000s\n\nOK\n';p.write_text(valid)
            self.assertEqual(C.check_log(p,C.PRODUCT)['count'],18)
            for content in (valid.replace('18','17'),valid.replace('Starting check()',''),valid.replace('OK','OK (skipped=1)'),valid+'ERROR\n',valid.replace('OK','FAILED')):
                p.write_text(content)
                with self.subTest(content=content),self.assertRaises(ValueError):C.check_log(p,C.PRODUCT)

    def test_database_query_excludes_transaction_only_flags(self):
        calls=[];L=SimpleNamespace(need=C.need,command=lambda argv:calls.append(argv))
        transaction=['/usr/bin/pacman','--config','/tmp/orphans-pacman.conf','--noconfirm','--noscriptlet'];held=list(transaction)
        I.database_check(L,transaction)
        self.assertEqual(calls,[['/usr/bin/pacman','--config','/tmp/orphans-pacman.conf','-Dk']])
        self.assertEqual(transaction,held);self.assertNotIn('--noscriptlet',calls[0])
        self.assertIn('--noscriptlet',transaction)

    def test_exact_archive_buildinfo_and_payload_pair_gate(self):
        good=dict(status='contents-reproduced',errors=[],packages={'pkg':dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)})
        R.pair_gate(good)
        for field in good['packages']['pkg']:
            bad=copy.deepcopy(good);bad['packages']['pkg'][field]=False
            with self.subTest(field=field),self.assertRaises(ValueError):R.pair_gate(bad)

    def test_manual_workflow_and_signing_mount_boundary(self):
        workflow=HERE.parents[2]/'.github/workflows/native-arm-orphans-candidate.yml'
        text=workflow.read_text();self.assertIn('group: native-arm-orphans-candidate\n  cancel-in-progress: false',text)
        self.assertNotIn('push:',text);self.assertNotIn('pull_request:',text);self.assertTrue('@MANIFEST_SHA256@' in text or C.digest(HERE/'source-manifest.json') in text)
        self.assertLess(text.index('Prove the explicit'),text.index('secrets.'));self.assertLess(text.index('Retire owned'),text.index('Retain the closed'))
        tree=(HERE/'run.py').read_text();self.assertIn('docker(image,container,lifecycle_output,root=True)',tree)
        self.assertNotIn('src={out}/test-signing',tree);self.assertNotIn('--nodeps',tree)
        self.assertIn("signer_api.sign(context,out",tree);self.assertIn("('a','b')",tree)


class Acceptance(unittest.TestCase):
    def test_complete_lifecycle_shape(self):C.validate_lifecycle(receipt())

    def test_each_phase_and_protection_or_scope_drift_refuses(self):
        for i in range(5):
            bad=receipt();bad['events'].pop(i)
            with self.subTest(i=i),self.assertRaises(ValueError):C.validate_lifecycle(bad)
        for field,value in (('base574_preserved',False),('user_preserved',False),('reports_preserved',False),('hardware','PASS'),('removal','APPLIED'),('page_size',0),('installed_count',576)):
            bad=receipt();bad[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):C.validate_lifecycle(bad)

    def test_both_actual_users_and_readonly_fixture_facts_required(self):
        for field in ('default_database','base_protected','default_root','default_dbpath','readonly_enforced','fixture','plan_verify','db_preserved','foreign_lock','apply_supported'):
            bad=receipt();bad['events'][0]['observations'][0][field]=None
            with self.subTest(field=field),self.assertRaises(ValueError):C.validate_lifecycle(bad)
        bad=receipt();bad['events'][0]['observations'].pop()
        with self.assertRaises(ValueError):C.validate_lifecycle(bad)
        bad=receipt();bad['events'][2]['payloads_absent']=False
        with self.assertRaises(ValueError):C.validate_lifecycle(bad)




class Cleanup(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.base=self.root/'base';self.runtime=self.root/'runtime';self.base.mkdir();self.runtime.mkdir()
        self.token='1'*32;self.image='sha256:'+'2'*64;self.name='cachy-asahi-product-'+'3'*32;self.calls=[]
        self.proof=dict(consumer_token=self.token,job_token='4'*16)
        J.save(self.base/'report.json',dict(image=self.image,owned_cleanup=dict(status='PASS')))
        (self.runtime/'consumer.lock').touch()
        self.owner=dict(schema_version=1,token=self.token,image=self.image,label=C.LABEL,containers=[self.name])
        J.save(self.runtime/'owner.json',self.owner);self.present=True

    def daemon(self,argv):
        self.calls.append(argv)
        if argv[:4]==['/usr/bin/docker','container','inspect',self.name]:
            if not self.present:return SimpleNamespace(returncode=1,stdout=b'',stderr=('No such container: '+self.name).encode())
            value=dict(Id='5'*64,Image=self.image,Name='/'+self.name,Config=dict(Labels={C.LABEL:self.token}))
            return SimpleNamespace(returncode=0,stdout=json.dumps([value]).encode(),stderr=b'')
        if argv[:3]==['/usr/bin/docker','rm','-f']:self.present=False
        return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')

    def test_owned_consumer_removed_by_confirmed_id_and_absence_verified(self):
        result=J.retire_consumers(self.runtime,self.base,self.proof,self.daemon)
        self.assertTrue(result['containers'][0]['absence_verified']);self.assertFalse(self.present)
        self.assertIn(['/usr/bin/docker','rm','-f','5'*64],self.calls)

    def test_foreign_label_is_preserved_and_producer_not_called(self):
        def foreign(argv):
            row=self.daemon(argv)
            if row.returncode==0 and 'inspect' in argv:
                data=json.loads(row.stdout);data[0]['Config']['Labels'][C.LABEL]='6'*32;row.stdout=json.dumps(data).encode()
            return row
        with patch.object(J,'manifest_files'):
            result=J.cleanup(ROOT,{},self.proof,self.base,self.runtime,self.root/'cleanup.json',foreign)
        self.assertEqual(result['status'],'FAIL');self.assertTrue(self.present)
        self.assertFalse(any('maintained_desktop574.py' in str(argv) for argv in self.calls))

    def test_active_consumer_lease_blocks_cleanup(self):
        with (self.runtime/'consumer.lock').open('r+') as lease:
            fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):J.retire_consumers(self.runtime,self.base,self.proof,self.daemon)
        self.assertFalse(self.calls)

    def test_unknown_daemon_state_cannot_be_absence(self):
        with self.assertRaisesRegex(ValueError,'unknown consumer daemon state'):
            J.retire_consumers(self.runtime,self.base,self.proof,lambda argv:SimpleNamespace(returncode=1,stdout=b'',stderr=b'connection refused'))

    def test_consumer_absence_precedes_producer_cleanup(self):
        with patch.object(J,'manifest_files'):
            result=J.cleanup(ROOT,{},self.proof,self.base,self.runtime,self.root/'cleanup.json',self.daemon)
        self.assertEqual(result['status'],'PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP')
        self.assertIn('maintained_desktop574.py',str(self.calls[-1]));self.assertFalse(self.present)

    def test_no_consumer_is_distinct_from_unknown_owner(self):
        (self.runtime/'consumer.lock').unlink()
        with self.assertRaisesRegex(ValueError,'owner without lease'):J.retire_consumers(self.runtime,self.base,self.proof,self.daemon)
        (self.runtime/'owner.json').unlink()
        self.assertEqual(J.retire_consumers(self.runtime,self.base,self.proof,self.daemon)['status'],'PASS_NO_CONSUMER_ACTORS')

    def test_unknown_or_duplicate_owner_names_fail_before_any_daemon_call(self):
        for names in ([self.name,self.name],['foreign-container'],[self.name]*5):
            bad=copy.deepcopy(self.owner);bad['containers']=names;J.save(self.runtime/'owner.json',bad)
            with self.subTest(names=names),self.assertRaises(ValueError):J.retire_consumers(self.runtime,self.base,self.proof,self.daemon)
        self.assertFalse(self.calls)

    def test_foreign_image_is_never_removed(self):
        def foreign(argv):
            row=self.daemon(argv)
            if row.returncode==0 and 'inspect' in argv:
                data=json.loads(row.stdout);data[0]['Image']='sha256:'+'a'*64;row.stdout=json.dumps(data).encode()
            return row
        with self.assertRaisesRegex(ValueError,'foreign consumer preserved'):J.retire_consumers(self.runtime,self.base,self.proof,foreign)
        self.assertFalse(any('rm' in argv for argv in self.calls))


class SourceProof(unittest.TestCase):
    def test_source_workflow_identity_precedes_secret_route(self):
        proof=C.load('orphans_test_source_proof',ROOT/'scripts/ci/welcome-native/ci/caller.py')
        environment=dict(SOURCE_SHA='1'*40,GITHUB_SHA='1'*40,GITHUB_WORKFLOW_SHA='1'*40,
                         RUNNER_ARCH='ARM64',RUNNER_OS='Linux',GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1')
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp);path=source/'sentinel';path.write_text('known')
            manifest=dict(files={'sentinel':dict(bytes=5,sha256=C.digest(path))})
            value=proof.prove(source,manifest,environment);self.assertEqual(value['status'],'SOURCE_PROOF_PASS')
            for field,bad_value in (('SOURCE_SHA','branch'),('GITHUB_SHA','2'*40),('GITHUB_WORKFLOW_SHA','2'*40),('RUNNER_ARCH','X64')):
                bad=environment|{field:bad_value}
                with self.subTest(field=field),self.assertRaises(ValueError):proof.prove(source,manifest,bad)
            path.write_text('drift')
            with self.assertRaisesRegex(ValueError,'source pin differs'):proof.prove(source,manifest,environment)

    def test_retention_rejects_symlink_and_oversized_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'data').write_bytes(b'xx');(root/'alias').symlink_to('data')
            with self.assertRaises(ValueError):J.regular(root/'alias',3)
            with self.assertRaises(ValueError):J.regular(root/'data',1)


if __name__=='__main__':unittest.main()
