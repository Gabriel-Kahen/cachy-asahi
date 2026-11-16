# SPDX-License-Identifier: MIT
"""Fenced fictitious owner callbacks; no native/ALPM/GPG/Reader role runs."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('owned_current_route',HERE/'owned_route.py')
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
N=R.native();PROFILE=json.loads((HERE/'profile.json').read_bytes())
INPUTS=json.loads((HERE/'inputs.TEMPLATE.json').read_bytes())


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('fcntl.flock','os.exec','os.fork','os.system','os.posix_spawn'):
        raise RuntimeError('current owned DATA controls forbid '+event)


sys.addaudithook(fence)


def life():
    return dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,
                timeout=False,signals=[],error=None,exit=0)


def check_log(kind):
    head=b'==> Starting check()...\n'
    if kind=='enrollment':return head+json.dumps(PROFILE['enrollment_check_report']).encode()+b'\n'
    return head+b''.join(('Ran %d tests in 0.123s\n\nOK\n'%n).encode() for n in PROFILE['packages'][kind]['check_counts'])


class FakeCommands:
    def __init__(self,output,fail_compare=False):
        self.output=output;output.mkdir();self.records=[];self.timeout=180;self.max_output=1024**2
        self.deadline=time.monotonic()+600;self.fail_compare=fail_compare
    def run(self,step,argv,cwd,expected):
        kind=next(k for k in N.KINDS if step.startswith('current-'+k+'-'))
        if step.endswith('-compare'):
            raw=R.encoded(dict(status='fail' if self.fail_compare else 'contents-reproduced',errors=[] if not self.fail_compare else ['FICTION refusal'],packages={PROFILE['packages'][kind]['archive']:dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)}))
        else:
            out=Path(argv[argv.index('--output')+1]);(out/'artifacts').mkdir(parents=True)
            (out/'build.log').write_bytes(check_log(kind));(out/'artifacts'/PROFILE['packages'][kind]['archive']).write_bytes(b'FICTION NOT A PACKAGE')
            raw=b'FICTION bounded command DATA'
        name='%03d.log'%len(self.records);(self.output/name).write_bytes(raw)
        self.records.append(dict(step=step,argv=argv,cwd=str(cwd),expected=expected,success=True,log=name,log_pin=R.pin(raw),supervision=life()))
        return raw


class FakeTools:
    @staticmethod
    def ordinary(path,maximum=16*1024**2):return Path(path).read_bytes()
    @staticmethod
    def pin(path):return R.pin(Path(path).read_bytes())


class Session:
    def __init__(self,stage,grant,output,fail_compare=False,fail_cleanup=False):
        self.facts=dict(operation=R.OPERATION,stage=stage,binding=grant['binding'],image='sha256:'+'a'*64,architecture='aarch64',page_size=4096)
        self.commands=FakeCommands(output/'commands',fail_compare);self.tools=FakeTools;self.fail_cleanup=fail_cleanup;self.stage=stage;self.grant=grant;self.cleanup=None
    def __enter__(self):return self
    def verify_signatures(self,inputs):
        verified={}
        for key in (('setup8','first_login_backend') if self.stage=='ui' else ('setup8',)):
            v=inputs[key];selected=R.signature(v['current_TEST_signature_verification'],v['archive'],v['signature'],time.time(),N)
            signer=selected['fingerprint'];status='[GNUPG:] VALIDSIG '+signer+' 2026-11-16 100 0 4 0 22 8 00 '+signer+'\n[GNUPG:] TRUST_ULTIMATE\n'
            command=dict(step='owner-current-signature-'+key,argv=['/usr/bin/gpg','--homedir','/tmp/build-tools-test-FICTION/trust','--batch','--no-auto-key-retrieve','--auto-key-locate','clear','--status-fd=1','--verify',selected['signature']['path'],selected['archive']['path']],expected=0,success=True,log_pin=R.pin(status.encode()),supervision=life())
            verified[key]=dict(archive={k:selected['archive'][k] for k in ('bytes','sha256')},signature={k:selected['signature'][k] for k in ('bytes','sha256')},public_test_key={k:selected['public_key'][k] for k in ('bytes','sha256')},fingerprint=signer,status_text=status,command=command)
        return dict(status='PASS_OWNED_CURRENT_STAGE_TEST_VERIFICATION',operation=R.OPERATION,stage=self.stage,binding=self.grant['binding'],scope='DELEGATED_CURRENT_OWNER_GPG_NOT_ROOT_OBSERVATION',verified=verified)
    def __exit__(self,*errors):
        self.cleanup=dict(status='PASS_OWNED_CURRENT_STAGE_RETIREMENT',operation=R.OPERATION,stage=self.stage,binding=self.grant['binding'],natural_retirement=True,owned_container_absence_verified=not self.fail_cleanup,protected_state_unchanged=True)


def signature_fixture(root,name='setup8'):
    def put(name,raw):
        p=root/name;p.write_bytes(raw);return dict(path=str(p),**R.pin(raw))
    archive=put(name+'.archive',b'FICTION PACKAGE');signature=put(name+'.signature',b'FICTION SIGNATURE');public=put(name+'.public',b'FICTION PUBLIC KEY')
    key={k:public[k] for k in ('bytes','sha256')}|dict(fingerprint='A'*40,trust_scope='TEST_ONLY')
    proof=dict(schema=1,Root_issuer='Root',status='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE',verified=True,trust_scope='TEST_ONLY',actual_verified_utc='2026-01-01T00:00:00+00:00',archive={k:archive[k] for k in ('bytes','sha256')},signature={k:signature[k] for k in ('bytes','sha256')},public_test_key=key,status_stream=R.pin(b'FICTION HISTORICAL STATUS'))
    proof_ref=put(name+'.verification',R.encoded(proof));package='cachy-asahi-setup' if name=='setup8' else 'cachy-asahi-first-login'
    decision=dict(schema=1,issuer='Root',accepted=True,holds_preserved=True,trust_scope='TEST_ONLY',issued_at='2026-01-01T00:01:00+00:00',status='ACCEPTED_PRIVATE_SETUP8_PACKAGE_TEST_ONLY' if name=='setup8' else 'ACCEPTED_PRIVATE_CURRENT_ONBOARDING_PACKAGE_TEST_ONLY',archive={k:archive[k] for k in ('bytes','sha256')}|dict(package=package,version=R.PROJECT[package],arch='any'),signature=proof['signature'],signature_file=signature['path'],verification_proof_sha256=proof_ref['sha256'],public_test_key=key,public_test_key_file=public['path'])
    decision_ref=put(name+'.decision',R.encoded(decision))
    return dict(archive=archive,signature=signature,current_TEST_signature_verification=dict(Root_decision=decision_ref,Root_verification=proof_ref)),decision,proof


class Controls(unittest.TestCase):
    def test_registration_is_new_and_never_overwrites_old_operation(self):
        old=lambda:None;registry={'first-login-enrollment-alpm-v1':old};R.register(registry)
        self.assertIs(registry['first-login-enrollment-alpm-v1'],old);self.assertIs(registry[R.OPERATION],R.run_registered)
        with self.assertRaises(ValueError):R.register(registry)
    def test_unissued_inputs_refuse_before_owner_or_output(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'out';opened=[]
            with self.assertRaises(ValueError):R.run_registered(stage='backend',source=Path(d)/'source',profile=PROFILE,inputs=INPUTS,
                grant=dict(schema=1,operation=R.OPERATION,stage='backend',issuer=None,approved=None),output=out,
                open_session=lambda *a:opened.append(a))
            self.assertFalse(opened);self.assertFalse(out.exists())
    def test_typed_images_and_project_free_lifecycle(self):
        for stage,count in R.COUNTS.items():
            packages={'base-'+str(i):'1-1' for i in range(count)}
            for i,name in enumerate((['cachy-asahi-setup'] if stage=='backend' else ['cachy-asahi-setup','cachy-asahi-first-login'] if stage=='ui' else [])):
                del packages['base-'+str(i)];packages[name]=R.PROJECT[name]
            R.image_packages(stage,packages)
            wrong=dict(packages);wrong.pop(next(iter(wrong)))
            with self.assertRaises(ValueError):R.image_packages(stage,wrong)
            wrong=dict(packages);wrong.pop(next(n for n in wrong if n.startswith('base-')));wrong['cachy-asahi-first-login-ui']='0.2.0-1'
            with self.assertRaises(ValueError):R.image_packages(stage,wrong)
        ui={'base-'+str(i):'1-1' for i in range(370)}|{'cachy-asahi-setup':'0.3.0-1','cachy-asahi-first-login':'0.1.0-3'}
        with self.assertRaises(ValueError):R.image_packages('lifecycle',ui)
    def model(self,stage='backend',fail_compare=False,fail_cleanup=False):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name);out=root/'out'
        values=copy.deepcopy(INPUTS);values.update(source={'FICTION':True},source_date_epoch=100,
            Root_admission={'FICTION':True},image_namespace_qualification={'FICTION':True},Root_capacity=dict(build_seconds=180,total_seconds=600,command_rows=512,builder_cpus=4,builder_memory_bytes=4*1024**3,builder_pids=512))
        packages={n:'FICTION' for n in ('python','gnupg','pacman','coreutils','libarchive','bubblewrap','util-linux','fish','zsh','gtk4','python-gobject')};packages|={'cachy-asahi-setup':'0.3.0-1','cachy-asahi-first-login':'0.1.0-3'}
        for prefix in ('','ui_'):
            values[prefix+'builder_image']='sha256:'+'a'*64;values[prefix+'builder_inventory']=dict(path='/FICTION/lock',bytes=10,sha256='b'*64,packages=packages)
        for key in ('setup8','first_login_backend'):
            for field in values[key]:
                if values[key][field] is None:values[key][field]={'FICTION':True}
            values[key].update(signature_fixture(root,key)[0])
        for field in ('exact_closure','archive_signature_inputs','verification'):values['official_ui_dependencies'][field]={'FICTION':True}
        grant=dict(binding={'FICTION':True,'source_lock':{'FICTION':True}},profile_pin={'FICTION':True},inputs_pin={'FICTION':True},source_root=str(root/'source'),output=str(out))
        selected=R.signature(values['setup8']['current_TEST_signature_verification'],values['setup8']['archive'],values['setup8']['signature'],time.time(),N)
        grant['owner']=dict(test_fingerprint=selected['fingerprint'],test_public_key=selected['public_key'])
        if stage=='ui':
            # Both fixture decisions select the same actual public key file.
            reference=values['first_login_backend']['current_TEST_signature_verification'];decision=json.loads(R.reference(reference['Root_decision']))
            decision['public_test_key_file']=selected['public_key']['path'];path=Path(reference['Root_decision']['path']);path.write_bytes(R.encoded(decision));reference['Root_decision']=dict(path=str(path),**R.pin(path.read_bytes()))
        opened=[]
        def owner(*args):
            s=Session(stage,grant,out,fail_compare,fail_cleanup);opened.append(s);return s
        return root,out,values,grant,owner,opened
    def test_executable_pair_dispatch_uses_existing_vectors_and_complete_receipts(self):
        for stage,count in [('backend',6),('ui',3)]:
            root,out,values,grant,owner,opened=self.model(stage)
            with patch.object(R,'admission',return_value=(N,dict(id='sha256:'+'a'*64))):
                report=R.run_registered(stage=stage,source=root/'source',profile=PROFILE,inputs=values,grant=grant,output=out,open_session=owner)
            self.assertEqual(len(report['commands']),count);self.assertEqual(report['status'],R.PASS)
            self.assertIsNone(report['Root_acceptance']);self.assertTrue(opened[0].cleanup['owned_container_absence_verified'])
            self.assertEqual(report['artifacts'].keys(),{'ui'} if stage=='ui' else {'enrollment','first-login'})
    def test_comparison_failure_and_cleanup_unknown_never_pass(self):
        for compare,cleanup in [(True,False),(False,True)]:
            root,out,values,grant,owner,opened=self.model(fail_compare=compare,fail_cleanup=cleanup)
            with patch.object(R,'admission',return_value=(N,dict(id='sha256:'+'a'*64))):
                with self.assertRaises(ValueError):R.run_registered(stage='backend',source=root/'source',profile=PROFILE,inputs=values,grant=grant,output=out,open_session=owner)
            report=json.loads((out/'route.json').read_bytes());self.assertEqual(report['status'],'HOLD');self.assertIn('failure',report)
            self.assertIsNotNone(opened[0].cleanup)
    def test_mismatched_root_output_refuses_before_callback(self):
        root,out,values,grant,owner,opened=self.model();grant['output']=str(root/'other-output')
        with patch.object(R,'admission',return_value=(N,dict(id='sha256:'+'a'*64))):
            with self.assertRaises(ValueError):R.run_registered(stage='backend',source=root/'source',profile=PROFILE,inputs=values,grant=grant,output=out,open_session=owner)
        self.assertFalse(opened);self.assertFalse(out.exists())
    def test_host_or_remote_lifecycle_is_not_a_signed_image_session(self):
        with self.assertRaises(ValueError):R.signed_domain(SimpleNamespace(facts={'execution_domain':'REMOTE'}))
    def test_lifecycle_retains_public_data_before_owner_private_cleanup(self):
        root,out,values,grant,_,_=self.model('lifecycle');private=root/'FICTION-private';private.mkdir()
        signed={}
        for key in ('setup8',*N.KINDS):
            archive=private/(key+'.archive');archive.write_bytes(b'FICTION package DATA')
            sig=private/(key+'.signature');sig.write_bytes(b'FICTION signature DATA')
            signed[key]=dict(archive=str(archive),signature=str(sig),archive_pin=R.pin(archive.read_bytes()),signature_pin=R.pin(sig.read_bytes()))
        grant['signed']=signed;config=private/'pacman.conf';config.write_bytes(b'FICTION owner config DATA')
        class LocalModel(Session):
            def __enter__(self):
                self.protected_before={'FICTION':'before'};self.protected_after=lambda:{'FICTION':'before'}
                self.pacman=['--config',str(config)];self.verifier=['FICTION'];self.fingerprint='F'*40
                self.verify_state=lambda:None;return self
            def __exit__(self,*errors):
                super().__exit__(*errors)
                self.cleanup.update(status='PENDING_OUTER_CONTAINER_RETIREMENT',owned_container_absence_verified=False)
                for path in private.iterdir():path.unlink()
                private.rmdir()
        with patch.object(R,'admission',return_value=(N,dict(id='sha256:'+'a'*64))), \
             patch.object(R,'signed_domain'),patch.object(N,'lifecycle',return_value={'status':'FICTION adapter result'}):
            result=R.run_registered(stage='lifecycle',source=root/'source',profile=PROFILE,inputs=values,grant=grant,
                output=out,open_session=lambda *a:LocalModel('lifecycle',grant,out))
        self.assertFalse(private.exists());self.assertEqual(result['status'],'PENDING_OUTER_CURRENT_STAGE_RETIREMENT')
        self.assertFalse(result['owner_cleanup']['owned_container_absence_verified'])
        for key in signed:
            self.assertEqual(R.pin((out/'signed'/(key+'.archive')).read_bytes()),signed[key]['archive_pin'])
            self.assertEqual(R.pin((out/'signed'/(key+'.signature')).read_bytes()),signed[key]['signature_pin'])
        self.assertEqual(R.pin((out/'signature-config.txt').read_bytes()),result['signature_config_pin'])
    def test_natural_supervision_refuses_every_uncertain_outcome(self):
        R.natural(life())
        for key,value in [('reaped',False),('ownership','UNKNOWN'),('group_census','UNKNOWN'),('output_complete',False),('timeout',True),('signals',['TERM']),('error','cancel'),('exit',1),('exit',False)]:
            with self.subTest(key=key),self.assertRaises(ValueError):R.natural(dict(life(),**{key:value}))
    def test_observations_retain_stat_and_hash_after_held_local_check(self):
        row=dict(mode=0o755,bytes=5,sha256='c'*64);recipe=dict(payload_files={'usr/bin/example':row});seen=[]
        held=SimpleNamespace(check_payload=lambda *args:dict(verified=True,files=recipe['payload_files']))
        def run(step,argv):
            seen.append((step,argv));return b'0:0:755:5:1:regular file\n' if '-stat-' in step else ('c'*64+'  /usr/bin/example\n').encode()
        R.ObservedTools(held).check_payload(recipe,run,[],'test')
        self.assertEqual([x[0] for x in seen],['test-stat-0','test-sha256-0'])
        with self.assertRaises(ValueError):R.ObservedTools(held).check_payload(recipe,lambda *a:b'wrong',[],'test')
    def test_root_decision_joins_public_actual_schema_without_claiming_fresh_observation(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            value,decision,proof=signature_fixture(root);refs=value['current_TEST_signature_verification']
            selected=R.signature(refs,value['archive'],value['signature'],time.time(),N)
            self.assertEqual(selected['kind'],'ROOT_RETAINED_TEST_SIGNATURE_DECISION');self.assertEqual(selected['fingerprint'],'A'*40)
            self.assertNotIn('observed_at_unix',selected)
            for field,change in [('accepted',False),('trust_scope','PRODUCTION'),('verification_proof_sha256','0'*64),('signature_file','/OTHER/SIGNATURE'),('status','ROOT_VERIFIED_CURRENT_TEST_SIGNATURE_V2')]:
                bad=dict(decision,**{field:change});path=root/'changed';path.write_bytes(R.encoded(bad));other=dict(refs,Root_decision=dict(path=str(path),**R.pin(path.read_bytes())))
                with self.subTest(field=field),self.assertRaises(ValueError):R.signature(other,value['archive'],value['signature'],time.time(),N)
            with self.assertRaises(ValueError):R.signature(refs,value['archive'],value['signature'],0,N)
            with self.assertRaises(ValueError):R.signature(refs['Root_verification'],value['archive'],value['signature'],time.time(),N)
            public=root/'setup8.public';public.write_bytes(b'CHANGED KEY')
            with self.assertRaises(ValueError):R.signature(refs,value['archive'],value['signature'],time.time(),N)
    def test_current_owner_verification_is_mandatory_strict_and_precedes_builds(self):
        root,out,values,grant,_,_=self.model();out.mkdir();session=Session('backend',grant,out)
        good=session.verify_signatures(values);self.assertEqual(R.stage_signatures(session,values,grant,'backend',N),good)
        for change in ('expired','wrong-fingerprint','forced','wrong-scope','missing'):
            bad=copy.deepcopy(good);row=bad['verified']['setup8']
            if change=='expired':
                row['status_text']+='[GNUPG:] EXPKEYSIG '+row['fingerprint']+'\n';row['command']['log_pin']=R.pin(row['status_text'].encode())
            elif change=='wrong-fingerprint':row['fingerprint']='B'*40
            elif change=='forced':row['command']['supervision']['signals']=['TERM']
            elif change=='wrong-scope':bad['scope']='ROOT_OBSERVED_NOW'
            else:bad['verified']={}
            with patch.object(session,'verify_signatures',return_value=bad),self.subTest(change=change),self.assertRaises(ValueError):R.stage_signatures(session,values,grant,'backend',N)
        root,out,values,grant,owner,opened=self.model()
        with patch.object(R,'admission',return_value=(N,dict(id='sha256:'+'a'*64))),patch.object(Session,'verify_signatures',side_effect=ValueError('FICTION current key expired')):
            with self.assertRaises(ValueError):R.run_registered(stage='backend',source=root/'source',profile=PROFILE,inputs=values,grant=grant,output=out,open_session=owner)
        self.assertFalse(opened[0].commands.records);self.assertEqual(json.loads((out/'route.json').read_bytes())['status'],'HOLD')
    def test_root_verification_body_and_independently_selected_owner_key_must_join(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);value,decision,proof=signature_fixture(root);refs=value['current_TEST_signature_verification']
            for field,change in [('verified',False),('Root_issuer','Worker'),('archive',R.pin(b'OTHER')),('public_test_key',dict(proof['public_test_key'],fingerprint='B'*40))]:
                changed=dict(proof,**{field:change});p=root/'changed-verification';p.write_bytes(R.encoded(changed));verification=dict(path=str(p),**R.pin(p.read_bytes()))
                changed_decision=dict(decision,verification_proof_sha256=verification['sha256']);q=root/'changed-decision';q.write_bytes(R.encoded(changed_decision));decision_ref=dict(path=str(q),**R.pin(q.read_bytes()))
                with self.subTest(field=field),self.assertRaises(ValueError):R.signature(dict(Root_decision=decision_ref,Root_verification=verification),value['archive'],value['signature'],time.time(),N)
        root,out,values,grant,_,_=self.model();out.mkdir();session=Session('backend',grant,out)
        grant['owner']['test_fingerprint']='B'*40
        with self.assertRaisesRegex(ValueError,'key policy'):R.stage_signatures(session,values,grant,'backend',N)


if __name__=='__main__':unittest.main(verbosity=2)
