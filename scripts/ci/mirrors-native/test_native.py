"""Source and inert filesystem/daemon controls; never launch native actors."""
import copy
import fcntl
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import contract as C
import job as J
import run as R

ROOT=Path(os.environ.get('MIRRORS_NATIVE_SOURCE',Path(__file__).resolve().parents[3]))


def receipt():
    proof=dict(status='PASS_LOCAL_MIRROR_LIFECYCLE',real_cli=True,interrupted_recovery=True,original_bytes_preserved=True,
        private_TLS_key_removed=True,architecture='aarch64',page_size=4096,fixture='EXPLICIT_LOCAL_CONTROLLED_SNAPSHOT_ONLY',
        commands=[dict(exit=-9 if i<9 else 0) for i in range(42)],events=[
            dict(phase=phase,recovery=action,signal='SIGKILL',original_bytes_restored=True,metadata_restored=True)
            for phase,action in (('prepared','activate'),('prepared','restore'),('activated','activate'),('activated','restore'),('restoring','restore'),('restored','restore'))]+[
            dict(case=case,refusal_preserves_edit=True) for case in ('active-user-edit','prepared-user-edit','activated-user-edit','restoring-user-edit')]+[
            dict(case='loopback-TLS',exact_and_mismatched_snapshot=True,existing_candidate_preserved=True,all_failed_no_output=True),dict(case='roundtrip'),dict(case='absent')])
    observations=[dict(home='mirrors-home-'+kind,mirrors=copy.deepcopy(proof)) for kind in ('fresh','existing')]
    return dict(trust='EPHEMERAL_TEST_SIGNED_LOCAL_CANDIDATE_ONLY',signature_verification=__import__('test_signed_lifecycle').fixture(),status='PASS_MIRRORS_INSTALLED_LIFECYCLE',staged_observations=copy.deepcopy(observations),base_count=574,installed_count=575,user_config_preserved=True,
        system_config_preserved=True,user_outputs_preserved=True,hardware='NOT_RUN',native_architecture='aarch64',actual_page_size=4096,
        events=[dict(phase=phase,status='PASS',inventory_count=count,config_preserved=True,
                     **(dict(observations=copy.deepcopy(observations)) if count==575 else dict(removed_payload_absent=True)))
                for phase,count in (('install',575),('same-version-reinstall',575),('remove',574),('reinstall-after-removal',575),('final-remove',574))])


class Sources(unittest.TestCase):
    def test_final_binding_requires_fixed_activate_and_restore_vectors(self):
        good=copy.deepcopy(C.spec());good['status']='FINAL_SOURCE_REVIEWED'
        with patch.object(C,'spec',return_value=good):C.final_spec()
        for change in ('missing','wrong-verb','unbounded-args','missing-state'):
            bad=copy.deepcopy(good);activation=bad['products'][C.NAMES[0]]['activation_cli']
            if change=='missing':bad['products'][C.NAMES[0]]['activation_cli']=None
            elif change=='wrong-verb':activation['activate'][0]='arbitrary'
            elif change=='unbounded-args':activation['activate']*=3
            else:activation['restore'].remove('{journal}')
            with self.subTest(change=change),patch.object(C,'spec',return_value=bad),self.assertRaises(ValueError):C.final_spec()

    def test_unfinished_mirror_spec_cannot_be_frozen(self):
        with patch.object(C,'spec',return_value=dict(status='MISSING_FINAL_BINDING')):
            with self.assertRaisesRegex(ValueError,'final tool source/payload binding'):C.final_spec()

    def test_mirror_and_shell_dependency_versions_are_already_in_exact574(self):
        data=json.loads((ROOT/'scripts/ci/maintained-desktop574-inputs.json').read_text());rows={r['name']:r for r in data['packages']}
        self.assertEqual(len(rows),574)
        for name in ('python','ca-certificates','openssl','pacman','fakeroot'):self.assertIn(name,rows)
        self.assertEqual(rows['zsh']['version'],'5.9.2-1');self.assertEqual(rows['python']['version'],'3.14.8-1')

    def test_missing_final_source_freeze_is_a_hard_gate(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(C,'HERE',Path(temp)):
            (Path(temp)/'source-pins.json').write_text('{}')
            (Path(temp)/'product-spec.json').write_text(json.dumps(dict(status='MISSING',products={name:{} for name in C.NAMES})))
            with self.assertRaisesRegex(ValueError,'final tool source/payload binding'):C.verify_source(ROOT)

    def test_source_checksum_drift_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp);dest=source/'packages/tools'/C.NAMES[0];shutil.copytree(ROOT/'packages/tools'/C.NAMES[0],dest)
            checks=source/'scripts/checks';checks.mkdir(parents=True);shutil.copyfile(ROOT/'scripts/checks/package_checks.py',checks/'package_checks.py')
            (dest/'LICENSE').write_text('changed')
            with self.assertRaisesRegex(ValueError,'checksum differs'):C.recipe(source,C.NAMES[0])

    def test_exact_mirror_source_license_payload_join_and_mutations(self):
        name=C.NAMES[0];members={n:dict(type='0',mode=mode,uid=0,gid=0,sha256=C.digest(ROOT/'packages/tools'/name/original)) for n,(original,mode) in C.files(name).items()}
        report=dict(errors=[],elf={},members=members);self.assertEqual(len(C.payload(report,ROOT,name)),len(C.files(name)))
        for mutation in ('elf','extra','missing','license','mode','uid','type'):
            bad=copy.deepcopy(report);key='usr/share/licenses/'+name+'/LICENSE'
            if mutation=='elf':bad['elf']={'usr/bin/unexpected':{}}
            elif mutation=='extra':bad['members']['etc/pacman.conf']=copy.deepcopy(members[key])
            elif mutation=='missing':bad['members'].pop(key)
            elif mutation=='license':bad['members'][key]['sha256']='0'*64
            elif mutation=='mode':bad['members'][key]['mode']=0o777
            elif mutation=='uid':bad['members'][key]['uid']=1000
            else:bad['members'][key]['type']='2'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):C.payload(bad,ROOT,name)

    def test_build_log_requires_enabled_check_and_actual_mirror_fixture_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'build.log'
            for content in ('','Starting check()','Starting check()\nFAILED'):
                path.write_text(content)
                with self.assertRaises(ValueError):C.check_log(path,C.NAMES[0])
            path.write_text('Starting check()\n'+'\n'.join(C.spec()['products'][C.NAMES[0]]['check_markers'])+'\n');self.assertEqual(C.check_log(path,C.NAMES[0])['status'],'PASS_CHECK_EXIT')


class Acceptance(unittest.TestCase):
    def test_complete_lifecycle_shape(self):C.validate_lifecycle(receipt())

    def test_each_missing_phase_and_each_scope_drift_refuses_acceptance(self):
        for index in range(5):
            bad=receipt();bad['events'].pop(index)
            with self.subTest(index=index),self.assertRaises(ValueError):C.validate_lifecycle(bad)
        for field,value in (('hardware','PASS'),('user_config_preserved',False),('system_config_preserved',False),
                            ('user_outputs_preserved',False),('installed_count',576),('actual_page_size',0),('staged_observations',[])):
            bad=receipt();bad[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):C.validate_lifecycle(bad)

    def test_real_behavior_and_both_user_homes_required(self):
        for tool in ('mirrors',):
            bad=receipt();bad['events'][0]['observations'][0][tool]['status']='NOT_RUN'
            with self.subTest(tool=tool),self.assertRaises(ValueError):C.validate_lifecycle(bad)
        bad=receipt();bad['events'][0]['observations'].pop()
        with self.assertRaises(ValueError):C.validate_lifecycle(bad)
        bad=receipt();bad['events'][2]['removed_payload_absent']=False
        with self.assertRaises(ValueError):C.validate_lifecycle(bad)
        for field in ('real_cli','interrupted_recovery','original_bytes_preserved'):
            bad=receipt();bad['events'][0]['observations'][0]['mirrors'][field]=False
            with self.subTest(field=field),self.assertRaises(ValueError):C.validate_lifecycle(bad)

    def test_incomplete_interruption_or_wrong_machine_receipt_refuses(self):
        for field,replacement in (('events',[]),('commands',[]),('architecture','x86_64'),('page_size',16384),('private_TLS_key_removed',False)):
            bad=receipt();bad['events'][0]['observations'][0]['mirrors'][field]=replacement
            with self.subTest(field=field),self.assertRaises(ValueError):C.validate_lifecycle(bad)

    def test_byte_comparison_is_required_beyond_installed_contents(self):
        good=dict(status='contents-reproduced',errors=[],packages={'pkg':dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)})
        R.pair_gate(good)
        for field in good['packages']['pkg']:
            bad=copy.deepcopy(good);bad['packages']['pkg'][field]=False
            with self.subTest(field=field),self.assertRaises(ValueError):R.pair_gate(bad)
        bad=copy.deepcopy(good);bad['packages']['pkg']['bytes_equal']='true'
        with self.assertRaises(ValueError):R.pair_gate(bad)


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
        for names in ([self.name,self.name],['foreign-container'],[self.name]*9):
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
        proof=C.load('tools_test_source_proof',ROOT/'scripts/ci/welcome-native/ci/caller.py')
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
