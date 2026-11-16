# SPDX-License-Identifier: MIT
"""Fenced fictional callbacks; no actor, build, signing, Source or Reader role."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
        raise RuntimeError('delegated route DATA controls forbid '+event)


sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
R=load('fenced_delegated_route',HERE/'route.py')
# Unmodified maintained pure predicates only, never native build/ALPM executors.
N=load('fenced_unmodified_native_predicates',HERE.parent/'successor_v2/native.py')
V=load('fenced_private_static_validator',HERE/'validate_build.py')
PROFILE=json.loads((HERE.parent/'successor_v2/profile.json').read_bytes())


def supervision():
    return dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,
                timeout=False,signals=[],error=None,exit=0,seconds=.01)


class Tools:
    @staticmethod
    def ordinary(path,cap=16*1024**2):
        raw=Path(path).read_bytes();R.need(len(raw)<=cap,'fenced bytes cap');return raw
    @staticmethod
    def pin(path):return R.pin(Tools.ordinary(path))


class Session:
    def __init__(self,case,kw):
        self.case=case;self.kw=kw;self.output=kw['output'];self.stage=case.stage;self.records=[];self.tools=Tools
        self.native=N;self.native_pin=dict(R.NATIVE_PIN);self.profile=PROFILE;self.image=dict(id=case.image['image_id'],packages=case.image['packages'],inventory_pin=case.image['inventory_pin']);self.build_inputs=case.plan
        self.facts=dict(operation=R.OP,stage=self.stage,binding=case.context['binding'],nonce=case.d['nonce'],
            delegation_pin=R.pin(case.raw),image=self.image['id'],architecture='aarch64',page_size=4096,
            context_pin=R.pin(R.encoded(case.context)),context_program_pin={k:case.d['programs']['context'][k] for k in ('bytes','sha256')},
            context_issuer=case.context['issuer'],context_kind=case.context['kind'])
    def __enter__(self):
        (self.output/'commands').mkdir();return self
    def __exit__(self,*errors):
        self.cleanup=dict(status='PENDING_OUTER_CONTAINER_RETIREMENT' if self.stage=='lifecycle' else 'PASS_DELEGATED_CURRENT_STAGE_RETIREMENT',
            operation=R.OP,stage=self.stage,binding=self.case.context['binding'],nonce=self.case.d['nonce'],natural_retirement=True,
            owned_container_absence_verified=self.stage!='lifecycle',protected_state_unchanged=True,**R.FINAL)
        if self.case.bad_cleanup:self.cleanup['owned_container_absence_verified']=not self.cleanup['owned_container_absence_verified']
    def run(self,step,argv):
        kind=next(k for k in R.KINDS if step.startswith('current-'+k+'-'))
        if step.endswith('-compare'):
            flags=dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)
            if self.case.bad_pair:flags['bytes_equal']=False
            raw=R.encoded(dict(status='contents-reproduced',errors=[],packages={PROFILE['packages'][kind]['archive']:flags}))
        else:
            root=Path(argv[argv.index('--output')+1]);(root/'artifacts').mkdir(parents=True)
            log=b'Starting check()\n'
            if kind=='enrollment':log+=json.dumps(PROFILE['enrollment_check_report']).encode()+b'\n'
            else:log+=b''.join(('Ran %d tests in 0.01s\nOK\n'%n).encode() for n in PROFILE['packages'][kind]['check_counts'])
            if self.case.bad_check:log+=b'FAILED (skipped=1)\n'
            (root/'build.log').write_bytes(log);(root/'artifacts'/PROFILE['packages'][kind]['archive']).write_bytes(b'FICTION PACKAGE '+kind.encode())
            raw=b'FICTION COMMAND OUTPUT'
        row=dict(step=step,argv=argv,expected=0,success=True,log_pin=R.pin(raw),supervision=supervision())
        if self.case.forced:row['supervision']['signals']=[15]
        self.records.append(row);return raw
    def build(self,kind,label):
        # Fictional observed Docker receipt, explicitly not a generic CLI row.
        output=self.output/'builds'/(kind+'-'+label)
        argv=['/usr/bin/python3','-I','-B','/FICTION/producer','--output',str(output)]
        self.run('current-'+kind+'-'+label,argv)
        self.records[-1]['argv']=['/usr/bin/docker','create','--name','FICTION-'+kind+'-'+label]
        return dict(status='built-package-static-pass')
    def compare(self,kind):
        argv=['/usr/bin/python3','-I','-B',str(self.case.source/'scripts/build/compare.py'),
              str(self.output/'builds'/(kind+'-a')),str(self.output/'builds'/(kind+'-b')),'--require-bytes']
        return self.run('current-'+kind+'-compare',argv)


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fenced-private-route-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/'source';self.source.mkdir();self.stage='backend'
        self.bad_pair=self.bad_check=self.bad_cleanup=self.forced=False
    def fixture(self,stage='backend'):
        self.stage=stage;self.output=self.root/('output-'+stage)
        capacity=dict(max_command_seconds=180,total_seconds=600,builder_cpus=4,builder_memory_bytes=4*1024**3,builder_pids=512,command_rows=512)
        binding=dict(source='a'*40,ref='refs/heads/codex/FICTION',run=None,job=None,attempt=1,source_lock=R.pin(b'FICTION SOURCE'))
        self.d=dict(schema=3,kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3',issuer='Root',approved=True,scope='CURRENT_PRIVATE_STAGE_ONLY',
            stage=stage,nonce='b'*64,binding=binding,capability=dict(operation=R.OP,stage=stage,**capacity),
            programs={'context':dict(member='FICTION/context.py',**R.pin(b'FICTION CONTEXT PROGRAM'))},**R.FINAL)
        self.raw=R.encoded(self.d);actual=dict(binding,run='123',job='456')
        self.context=dict(schema=3,kind='DELEGATED_CURRENT_ONBOARDING_CONTEXT_V3',issuer='DELEGATED_CONTEXT_PROGRAM_V3',operation=R.OP,
            stage=stage,source_root=str(self.source),delegation_pin=R.pin(self.raw),nonce=self.d['nonce'],binding=actual,**R.FINAL)
        packages={n:'1-1' for n in ('python','gnupg','pacman','coreutils','libarchive','bubblewrap','util-linux','fish','zsh','gtk4','python-gobject')}
        if stage!='lifecycle':packages['cachy-asahi-setup']='0.3.0-1'
        if stage=='ui':packages['cachy-asahi-first-login']='0.1.0-3'
        for i in range(dict(backend=350,ui=374,lifecycle=372)[stage]-len(packages)):packages['base-'+str(i)]='1-1'
        lock=self.source/(stage+'.lock');body=''.join(n+' '+v+'\n' for n,v in sorted(packages.items())).encode();lock.write_bytes(body)
        self.image=dict(status='PROVISIONAL_CURRENT_IMAGE_CONSTRUCTED_DATA_ONLY',operation=R.OP,stage=stage,binding=actual,
            delegation_pin=R.pin(self.raw),owner_executor_facts={'nonce':self.d['nonce']},image_id='sha256:'+'c'*64,
            packages=packages,inventory_pin=R.pin(body),Root_final_acceptance=None,independent_image_qualification=None)
        self.plan=dict(source_date_epoch=1,capacity=dict(build_seconds=180,builder_cpus=4,builder_memory_bytes=4*1024**3,builder_pids=512),
            builder_inventory=dict(path=str(lock),**R.pin(body),packages=packages))
        self.opened=[]
        def opener(**kw):
            s=Session(self,kw);self.opened.append(s);return s
        return dict(stage=stage,source=self.source,profile=PROFILE,inputs={'materials':{'FICTION':{'member':'public'}}},
            delegation_raw=self.raw,delegation_sha256=R.pin(self.raw)['sha256'],context=self.context,image=self.image,
            executor=object(),output=self.output,open_session=opener)
    def test_build_stages_never_call_old_root_gates_and_keep_acceptance_false(self):
        for stage,count in (('backend',6),('ui',3)):
            args=self.fixture(stage)
            with patch.object(N,'build_vectors',side_effect=AssertionError('old Root gate')),patch.object(N,'build_pairs',side_effect=AssertionError('old Root gate')):
                report=R.run_registered(**args)
            self.assertEqual(report['status'],'PROVISIONAL_CURRENT_'+stage.upper()+'_DATA_ONLY');self.assertEqual(len(report['commands']),count)
            self.assertEqual(report['issuer'],'DELEGATED_CURRENT_OWNER_V3');R.final(report)
            self.assertEqual(set(self.opened[0].kw),{'delegation_raw','delegation_sha256','context','image_report','executor','source_root','output','inputs'})
    def test_successful_report_includes_actual_session_exit_cleanup_receipts(self):
        args=self.fixture()
        cleanup=dict(step='private-retire-0',argv=['/usr/bin/gpgconf','--homedir','/FICTION/trust','--kill','all'],
                     expected=0,success=True,log_pin=R.pin(b''),supervision=supervision())
        class RetiringSession(Session):
            def __exit__(self,*errors):
                super().__exit__(*errors);self.records.append(cleanup)
        args['open_session']=lambda **kw:RetiringSession(self,kw)
        report=R.run_registered(**args)
        self.assertEqual(report['status'],'PROVISIONAL_CURRENT_BACKEND_DATA_ONLY')
        self.assertEqual(report['commands'][-1],cleanup);self.assertEqual(len(report['commands']),7)
        persisted=json.loads((args['output']/'route.json').read_bytes())
        self.assertEqual(persisted['commands'],report['commands'])
    def test_bad_authority_context_or_image_refuses_before_callback_or_output(self):
        for mutation in ('delegation-pin','context-issuer','context-final','image-binding','image-inventory','profile'):
            args=self.fixture();self.output=self.root/('invalid-'+mutation);args['output']=self.output
            if mutation=='delegation-pin':args['delegation_sha256']='0'*64
            elif mutation=='context-issuer':args['context']['issuer']='Root'
            elif mutation=='context-final':args['context']['hardware_acceptance']=True
            elif mutation=='image-binding':args['image']['binding']={'FAKE':True}
            elif mutation=='image-inventory':args['image']['packages'].pop('python')
            else:args['profile']={}
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):R.run_registered(**args)
            self.assertFalse(self.opened);self.assertFalse(self.output.exists())
    def test_private_plan_refuses_old_root_keys_wrong_inventory_and_resources(self):
        self.fixture();image=dict(id=self.image['image_id'],packages=self.image['packages']);R.private_build_plan(self.source,PROFILE,self.plan,image,'backend',self.output)
        for change in ('old','resources','inventory','epoch'):
            plan=copy.deepcopy(self.plan)
            if change=='old':plan['Root_capacity']=plan.pop('capacity')
            elif change=='resources':plan['capacity']['builder_cpus']=8
            elif change=='inventory':plan['builder_inventory']['packages']['python']='OTHER'
            else:plan['source_date_epoch']=False
            with self.subTest(change=change),self.assertRaises(ValueError):R.private_build_plan(self.source,PROFILE,plan,image,'backend',self.output)
    def test_failed_checks_comparison_forced_or_cleanup_never_become_provisional(self):
        for failure in ('bad_check','bad_pair','forced','bad_cleanup'):
            args=self.fixture();args['output']=self.root/failure;setattr(self,failure,True)
            with self.subTest(failure=failure),self.assertRaises(ValueError):R.run_registered(**args)
            report=json.loads((args['output']/'route.json').read_bytes());self.assertEqual(report['status'],'HOLD_DELEGATED_CURRENT_STAGE');self.assertIn('failure',report)
            setattr(self,failure,False)
    def test_native_pin_and_same_session_facts_are_required(self):
        for change in ('pin','facts'):
            args=self.fixture();args['output']=self.root/change
            def opener(**kw):
                session=Session(self,kw)
                if change=='pin':session.native_pin=R.pin(b'NOT THE HELD NATIVE')
                else:session.facts['nonce']='d'*64
                return session
            args['open_session']=opener
            with self.subTest(change=change),self.assertRaises(ValueError):R.run_registered(**args)
    def test_selected_context_v4_requires_exact_validated_session_observation(self):
        def version4(args):
            self.d.update(schema=4,kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4');self.raw=R.encoded(self.d)
            args.update(delegation_raw=self.raw,delegation_sha256=R.pin(self.raw)['sha256'])
            self.context.update(schema=4,kind='DELEGATED_CURRENT_ONBOARDING_CONTEXT_V4',issuer='DELEGATED_CONTEXT_PROGRAM_V4',delegation_pin=R.pin(self.raw))
            self.image['delegation_pin']=R.pin(self.raw)
        args=self.fixture();version4(args)
        report=R.run_registered(**args);self.assertEqual(report['owner_facts']['context_kind'],self.context['kind'])
        for field,bad in (('context_pin',R.pin(b'OTHER CONTEXT')),('context_program_pin',R.pin(b'OTHER PROGRAM')),
                          ('context_issuer','Root'),('context_kind','DELEGATED_CURRENT_ONBOARDING_CONTEXT_V3')):
            args=self.fixture();args['output']=self.root/field;version4(args)
            def opener(**kw):
                session=Session(self,kw);session.facts[field]=bad;return session
            args['open_session']=opener
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'selected context provider'):R.run_registered(**args)
            self.assertFalse((args['output']/'builds').exists())
    def test_context_version_issuer_and_kind_cannot_be_mixed_or_root_relabelled(self):
        for schema,kind,issuer in ((4,'DELEGATED_CURRENT_ONBOARDING_CONTEXT_V3','DELEGATED_CONTEXT_PROGRAM_V3'),
                                   (3,'DELEGATED_CURRENT_ONBOARDING_CONTEXT_V4','DELEGATED_CONTEXT_PROGRAM_V4'),
                                   (4,'DELEGATED_CURRENT_ONBOARDING_CONTEXT_V4','Root')):
            args=self.fixture();self.context.update(schema=schema,kind=kind,issuer=issuer)
            with self.subTest(schema=schema,kind=kind,issuer=issuer),self.assertRaises(ValueError):R.run_registered(**args)
            self.assertFalse(self.opened);self.assertFalse(self.output.exists())
    def test_lifecycle_retains_public_bytes_and_defers_its_own_absence(self):
        args=self.fixture('lifecycle');private=self.root/'private';private.mkdir();signed={}
        for key in ('setup8',*R.KINDS):
            archive=private/(key+'.archive');archive.write_bytes(b'FICTION ARCHIVE');sig=private/(key+'.signature');sig.write_bytes(b'FICTION SIGNATURE')
            signed[key]=dict(archive=str(archive),signature=str(sig),archive_pin=Tools.pin(archive),signature_pin=Tools.pin(sig))
        config=private/'pacman.conf';config.write_bytes(b'FICTION REQUIRED SIGNATURE CONFIG')
        def opener(**kw):
            session=Session(self,kw);session.signed=signed;session.pacman=['--config',str(config)];session.verifier=['FICTION'];session.fingerprint='A'*40
            session.protected_before={'FICTION':'BASELINE'};session.protected_after=lambda:{'FICTION':'BASELINE'};session.verify_state=lambda:None
            return session
        args['open_session']=opener
        with patch.object(R,'signed_domain'),patch.object(N,'lifecycle',return_value={'status':'FICTION HELD LIFECYCLE'}):report=R.run_registered(**args)
        self.assertEqual(report['status'],'PENDING_OUTER_CURRENT_STAGE_RETIREMENT');self.assertFalse(report['owner_cleanup']['owned_container_absence_verified']);R.final(report)
        for key in signed:
            for field in ('archive','signature'):self.assertEqual(Tools.pin(self.output/'signed'/(key+'.'+field)),signed[key][field+'_pin'])
    def test_real_local_namespace_guard_refuses_host_shortcut(self):
        with patch.object(R.os,'getuid',return_value=1000),self.assertRaises(ValueError):R.signed_domain()
    def test_natural_and_operational_fences_reject_uncertainty(self):
        R.natural(supervision())
        for change in ({'exit':False},{'signals':[15]},{'timeout':True},{'ownership':'UNKNOWN'}):
            with self.assertRaises(ValueError):R.natural(dict(supervision(),**change))
        for event in ('subprocess.Popen','socket.__new__','ctypes.dlopen','fcntl.flock','os.exec'):
            with self.assertRaises(RuntimeError):fence(event,())
    def test_static_validator_exact_import_seam_uses_only_pinned_predicates(self):
        repo=HERE.parents[3];raw=(repo/'scripts/build/build.py').read_bytes()
        projected=V.project_build(raw);self.assertEqual(projected.replace(V.REPLACEMENT,V.SEAM),raw)
        self.assertNotIn(V.SEAM,projected)
        for invalid in (b'NO SEAM',raw+V.SEAM):
            with self.assertRaises(ValueError):V.project_build(invalid)
        before=list(sys.path);P,B,entry=V.helpers(repo,PROFILE)
        self.assertEqual(sys.path,before);self.assertIs(B.recipe,P.recipe);self.assertIs(B.metadata,P.metadata)
        self.assertEqual(entry,PROFILE['helpers']['scripts/build/container-entry.sh']['sha256'])
    def validator_fixture(self):
        repo=HERE.parents[3];recipe=PROFILE['packages']['first-login']
        for name in ('scripts/checks/package_checks.py','scripts/build/build.py','scripts/build/container-entry.sh'):
            destination=self.source/name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(repo/name,destination);destination.chmod(0o644)
        profile=self.source/(V.FAMILY+'/successor_v2/profile.json');profile.parent.mkdir(parents=True);profile.write_bytes(R.encoded(PROFILE))
        original=self.source/recipe['path'];original.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(repo/recipe['path'],original)
        slot=self.root/'validator-slot';shutil.copytree(original,slot/'inputs');artifacts=slot/'artifacts';artifacts.mkdir()
        lock=self.source/'expected.lock';lock.write_bytes(b'FICTION 1-1\n')
        (slot/'expected-packages.lock').write_bytes(lock.read_bytes());(slot/'build.log').write_bytes(b'FICTION BUILD LOG')
        for name in ('environment.txt','config.sha256','makepkg.conf','pacman.conf'):(artifacts/name).write_bytes(b'FICTION DATA')
        (artifacts/'packages.lock').write_bytes(lock.read_bytes());(artifacts/'generated.SRCINFO').write_bytes((original/'.SRCINFO').read_bytes())
        (artifacts/recipe['archive']).write_bytes(b'FICTION COMPRESSED BODY - NEVER DECODE')
        P,B,_=V.helpers(self.source,PROFILE);reviewed=P.recipe(slot/'inputs/PKGBUILD');self.assertFalse(reviewed['errors'])
        path=self.source/'reviewed/first-login.json';path.parent.mkdir();path.write_bytes(R.encoded(reviewed['input_sha256']))
        md=B.normalize_metadata(reviewed['metadata']);pkg=dict(pkgname=md['pkgname'],pkgbase=md['pkgbase'],pkgver=['0.1.0-3'],arch=md['arch'],license=md['license'],builddate=['1'])
        for source,target in {'depends':'depend','makedepends':'makedepend','checkdepends':'checkdepend','optdepends':'optdepend','provides':'provides','conflicts':'conflict','replaces':'replaces','backup':'backup'}.items():pkg[target]=md[source]
        parsed=dict(artifact=recipe['archive'],members={},errors=[],metadata={'.PKGINFO':pkg,'.BUILDINFO':dict(pkgbuild_sha256sum=[reviewed['input_sha256']['PKGBUILD']],builddate=['1'])})
        return dict(source_root=self.source,kind='first-login',build_directory=slot,expected_inventory=lock,source_date_epoch=1),P,B,parsed
    def test_validator_checks_real_snapshot_inventory_and_metadata_without_decoder(self):
        args,P,B,parsed=self.validator_fixture()
        with patch.object(V,'helpers',return_value=(P,B,'a'*64)),patch.object(P,'package',return_value=parsed) as decoder:
            result=V.validate(**args)
        self.assertEqual(result['status'],'PASS_DELEGATED_BUILD_STATIC_VALIDATION');self.assertEqual(decoder.call_count,1)
        report=json.loads((args['build_directory']/'validation.json').read_bytes());self.assertEqual(report['errors'],[])
        (args['build_directory']/'validation.json').unlink();(args['build_directory']/'inputs/PKGBUILD').write_bytes(b'CHANGED')
        with patch.object(P,'package',side_effect=AssertionError('snapshot fails before decoder')),self.assertRaises(ValueError):V.validate(**args)
    def test_validator_refuses_helper_pin_drift_and_generated_metadata_drift(self):
        args,P,B,parsed=self.validator_fixture()
        generated=args['build_directory']/'artifacts/generated.SRCINFO';generated.write_bytes(generated.read_bytes().replace(b'pkgver = 0.1.0',b'pkgver = 9.9.9'))
        with patch.object(V,'helpers',return_value=(P,B,'a'*64)),patch.object(P,'package',side_effect=AssertionError('metadata fails before decoder')),self.assertRaises(ValueError):V.validate(**args)
        helper=self.source/'scripts/build/build.py';helper.write_bytes(helper.read_bytes()+b'\n')
        with self.assertRaisesRegex(ValueError,'pinned'):V.helpers(self.source,PROFILE)


if __name__=='__main__':unittest.main(verbosity=2)
