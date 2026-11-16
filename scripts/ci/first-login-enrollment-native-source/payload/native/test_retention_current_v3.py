# SPDX-License-Identifier: MIT
"""FENCED public-receipt DATA models; no actors, GPG, network or real packages."""
import base64,copy,hashlib,importlib.util,io,json,os,sys,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch


def deny_operational_roles(event,args):
    if event.startswith(('socket.','subprocess.')) or event in (
            'os.system','os.exec','os.posix_spawn','os.spawn','os.fork','os.forkpty'):
        raise AssertionError('FENCED: actor/network/GPG execution forbidden')


sys.addaudithook(deny_operational_roles)

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('FENCED_retention_current_v3',HERE/'retention_current_v3.py');R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)


def encoded(value):return(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def natural():return dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,timeout=False,signals=[],error=None,exit=0)


class Encoder:
    def __init__(self,mutation=None,result=b'FENCED-INERT-CAPSULE'):self.calls=[];self.mutation=mutation;self.result=result
    def __call__(self,root):
        self.calls.append({p.relative_to(root).as_posix():p.read_bytes()for p in root.rglob('*')if p.is_file()})
        if self.mutation:self.mutation(root)
        return self.result


class Fixture:
    def __init__(self,root,stage):
        self.stage=stage;self.root=root;self.output=root/'FENCED-output';self.output.mkdir();self.destination=root/'FENCED-retained'
        self.binding=dict(source='a'*40,ref='refs/heads/codex/FENCED',run='101',job='102',attempt=1,source_lock=dict(bytes=1,sha256='b'*64))
        self.profile=dict(setup8=self.recipe('setup8'),packages={kind:self.recipe(kind)for kind in ('enrollment','first-login','ui')});self.inputs={};self.public={};self.streams={};self.stage_rows=[]
        self.image='sha256:'+'c'*64
        for role in R.PUBLIC:
            if role in ('context','domain'):
                facts=dict(architecture='aarch64',page_size=4096,image=self.image)if role=='context'else dict(execution_domain='FENCED_PUBLIC_EXECUTION',observations=[dict(kind='container',body=dict(image=self.image,cid='d'*64,name='FENCED-container',state=dict(Status='exited',Running=False,ExitCode=0)),source_pin=pin(b'FENCED inert inspection')),dict(kind='retirement',body=dict(cid='d'*64,status='REMOVED_AND_ABSENT',absence_verified=True),source_pin=pin(b'FENCED inert retirement'))])
                body=encoded(dict(schema=1,kind='CURRENT_ONBOARDING_PUBLIC_'+role.upper()+'_V3',operation=R.OP,stage=stage,binding=self.binding,facts=facts))
            elif role=='inventory':body=''.join('fiction%03d 0-1\n'%n for n in range(R.COUNTS[stage])).encode()
            elif role=='public_test_key':body=b'-----BEGIN PGP PUBLIC KEY BLOCK-----\nFENCED NOT A KEY\n-----END PGP PUBLIC KEY BLOCK-----\n'
            else:body=encoded({'FENCED':role,'Root_acceptance':None})
            self.public[role]=self.keep(root/'public-inputs'/(role+'.data'),body)
        verification={};keys=('setup8','first_login_backend')if stage=='ui'else('setup8',)
        admin_rel='owner-admin/commands'if stage=='lifecycle'else'owner-state/admission'
        admin_rows=[]
        for step in (()if stage=='lifecycle'else('fresh-owner-label','native-daemon'))+('import-root-test-public','current-primary','trust-current-test-primary')+(("baseline-inventory",'before-e','before-d')if stage=='lifecycle'else()):self.row(admin_rel,admin_rows,step,self.inventory(372)if step=='baseline-inventory'else b'FENCED PUBLIC ADMIN\n')
        for key in keys:
            archive=self.keep(root/'public-inputs'/(key+'.archive'),b'FENCED INERT '+key.encode());signature=self.keep(root/'public-inputs'/(key+'.signature'),b'FENCED INERT SIGNATURE')
            self.inputs[key]=dict(archive=archive,signature=signature,current_TEST_signature_verification={field:self.keep(root/'public-inputs'/(key+'.'+field+'.json'),encoded({'FENCED':field,'Root_acceptance':None}))for field in ('Root_decision','Root_verification')})
            status=b'[GNUPG:] FENCED PUBLIC STATUS ONLY\n';row=self.row(admin_rel,admin_rows,'owner-current-signature-'+key,status)
            verification[key]=dict(archive={k:archive[k]for k in ('bytes','sha256')},signature={k:signature[k]for k in ('bytes','sha256')},public_test_key={k:self.public['public_test_key'][k]for k in ('bytes','sha256')},fingerprint='F'*40,status_text=status.decode(),command=row)
        admin_ref=self.keep(self.output/admin_rel/'commands.json',encoded(admin_rows))
        self.route=dict(schema=1,operation=R.OP,stage=stage,binding=self.binding,status='PASS_CURRENT_ONBOARDING_OWNED_STAGE_DATA_ONLY',Root_acceptance=None,owner_facts=dict(image=self.image,architecture='aarch64',page_size=4096,execution_domain='FENCED_PUBLIC_EXECUTION'),owner_cleanup=dict(stage=stage,binding=self.binding,natural_retirement=True,owned_container_absence_verified=True,protected_state_unchanged=True),commands=self.stage_rows,stage_signature_verification=dict(status='PASS_OWNED_CURRENT_STAGE_TEST_VERIFICATION',operation=R.OP,stage=stage,binding=self.binding,scope='DELEGATED_CURRENT_OWNER_GPG_NOT_ROOT_OBSERVATION',verified=verification))
        if stage in ('backend','ui'):
            self.route.update(artifacts={},builds=dict(pairs={}))
            for number,kind in enumerate(R.KINDS[stage]):
                recipe_raw=('FENCED RECIPE '+kind).encode();self.profile['packages'][kind]=dict(**self.recipe(kind),archive=kind+'.pkg.tar.zst',files={'PKGBUILD':dict(mode=0o644,**pin(recipe_raw))})
                archive_raw=('FENCED INERT PACKAGE '+kind).encode();self.route['artifacts'][kind]={label:pin(archive_raw)for label in ('a','b')}
                for counter,label in enumerate(('a','b')):
                    self.row('commands',self.stage_rows,'current-'+kind+'-'+label,b'FENCED GENERIC BUILD OUTPUT\n');slot=self.output/'builds'/(kind+'-'+label);self.keep(slot/'inputs/PKGBUILD',recipe_raw)
                    names={name:(b'Starting check()\nFENCED PASS\n'if name=='build.log'else encoded({'FENCED':name}))for name in R.BUILD_FILES};names['artifacts/'+kind+'.pkg.tar.zst']=archive_raw
                    for name,body in names.items():self.keep(slot/name,body)
                    clean='cachy-asahi-%016x'%(number*2+counter+1)
                    self.keep(slot/'provenance.json',encoded(dict(FENCED='NOT_ACTUAL_BUILD',command=['FENCED_PRIVATE_PROVENANCE_COMMAND'],recipe_inputs={'PKGBUILD':pin(recipe_raw)['sha256']},files={n:pin(b)['sha256']for n,b in names.items()},clean_environment_id=clean)))
                    self.keep(self.output/'owner-state/intents'/(clean+'.json'),encoded(dict(name=clean,image='sha256:'+'c'*64,readonly=True,create_argv=['FENCED_PRIVATE_CREATE_ARGS'])))
                    self.keep(self.output/'owner-state/intents'/(clean+'.result'),encoded(dict(status='PASS_OWNED_GENERIC_BUILD_PROXY',name=clean,retirement=dict(status='REMOVED_AND_ABSENT',cid='d'*64,name=clean,inspection={'Config':'FENCED_PRIVATE_INSPECTION'}))))
                comparison=dict(status='contents-reproduced',errors=[],packages={kind+'.pkg.tar.zst':dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)})
                self.route['builds']['pairs'][kind]=comparison;self.row('commands',self.stage_rows,'current-'+kind+'-compare',encoded(comparison))
            retired=[dict(status='ABSENT',name='cachy-asahi-%016x'%(n+1))for n in range(2*len(R.KINDS[stage]))];retirement=self.multi_stream('owner-state/retirement',['retire-%d-query'%n for n in range(len(retired))]+['final-owner-label'])
            shapes=[['image-inspect'],['native-architecture'],['fresh-name','create','inspect-created','start-attached','inspect-terminal','proxy-final-query','proxy-final-inspect','proxy-final-remove','proxy-final-after']]
            self.streams=dict(admission=admin_ref,retirement=retirement,proxies=[self.multi_stream('owner-state/proxy-%02d/commands'%n,shapes[n%3])for n in range(6*len(R.KINDS[stage]))])
            self.keep(self.output/'owner-state/cleanup.json',encoded(dict(stage=stage,binding=self.binding,failures=[],retired=retired)))
        else:
            self.lifecycle()
            self.route['signed']={}
            for key in ('setup8','enrollment','first-login','ui'):
                a=b'FENCED SIGNED DATA '+key.encode();s=b'FENCED SIGNATURE '+key.encode();self.keep(self.output/'signed'/(key+'.archive'),a);self.keep(self.output/'signed'/(key+'.signature'),s)
                recipe=self.profile['setup8']if key=='setup8'else self.profile['packages'][key];self.route['signed'][key]=dict(name=recipe['name'],version=recipe['version'],payload_files=recipe['payload_files'],archive_pin=pin(a),signature_pin=pin(s))
            protected={name:dict(files=0,bytes=0,sha256=pin(b'')['sha256'])for name in ('alpm_db','alarm_home','root_home','global_trust','global_config','package_cache')};self.route.update(protected_before=protected,protected_after=copy.deepcopy(protected),lifecycle=self.lifecycle_report)
            self.keep(self.output/'owner-local.json',encoded(dict(status='PASS_LOCAL_STAGE_PENDING_OUTER_RETIREMENT',operation=R.OP,stage=stage,binding=self.binding,body_success=True,protected_state_unchanged=True,private_retirement=dict(homes_retired=True,no_sockets=True,private_directory_absent=True),failures=[])))
            self.keep(self.output/'outer-owner/receipt.final.json',encoded(dict(status='PASS_OWNED_CURRENT_LIFECYCLE_RETIREMENT',operation=R.OP,stage=stage,binding=self.binding,intent={'Config':'FENCED_PRIVATE_LAUNCH'})))
            self.route['signature_config_pin']=pin(b'FENCED private config pin only; body is never opened')
            domain=json.loads(Path(self.public['domain']['path']).read_bytes())
            domain['facts']['signature_policy']=dict(architecture='aarch64',SigLevel='Required',LocalFileSigLevel='Required',offline_verifier=True,public_TEST_only=True,private_home_retired=True,signature_config_pin=self.route['signature_config_pin'])
            self.public['domain']=self.keep(Path(self.public['domain']['path']),encoded(domain))
            self.route['outer_retirement']=json.loads((self.output/'outer-owner/receipt.final.json').read_bytes())
            self.streams=dict(administrative=admin_ref,outer=self.multi_stream('outer-owner/commands',['fresh-owner-label','native-daemon','fresh-name','create','inspect-created','start-attached','inspect-terminal','retire-query','retire-inspect','retire-remove','retire-after']))
            for role in ('prior_backend','prior_ui'):self.public[role]=self.keep(root/'public-inputs'/(role+'.capsule'),b'FENCED PRIOR PUBLIC CAPSULE '+role.encode())
        for step in (('restored-inventory','after-e','after-d')if stage=='lifecycle'else())+('retire-private-0','no-agent-private-0','retire-private-1','no-agent-private-1'):self.row(admin_rel,admin_rows,step,self.inventory(372)if step=='restored-inventory'else b'gpg-connect-agent: no gpg-agent running in this session\n'if step.startswith('no-agent-private-')else b'FENCED PUBLIC ADMIN\n')
        self.streams['administrative'if stage=='lifecycle'else'admission']=self.keep(self.output/admin_rel/'commands.json',encoded(admin_rows))
        self.flush()
        for name in ('inside.json','proxy.json','signature-config.txt','owner-state/proxy.json'):
            self.keep(self.output/name,b'FENCED_PRIVATE_FILE_MUST_NEVER_BE_READ')
    @staticmethod
    def inventory(count):return ''.join('fiction%03d 0-1\n'%n for n in range(count)).encode()
    @staticmethod
    def recipe(kind):
        names={'setup8':('cachy-asahi-setup','0.3.0-1'),'enrollment':('cachy-asahi-repository-enrollment','0.4.0-1'),'first-login':('cachy-asahi-first-login','0.1.0-3'),'ui':('cachy-asahi-first-login-ui','0.2.0-2')};name,version=names[kind]
        return dict(name=name,version=version,payload_files={'usr/share/FENCED/'+kind+'.txt':dict(mode=0o644,**pin(('FENCED PAYLOAD '+kind).encode()))})
    def multi_stream(self,directory,steps):
        rows=[]
        for step in steps:self.row(directory,rows,step,b'')
        return self.keep(self.output/directory/'commands.json',encoded(rows))
    def lifecycle(self):
        self.lifecycle_report=dict(status='PASS_CURRENT_THREE_SIGNED_ALPM_DATA_ONLY',Root_acceptance=None,native16K='NOT_RUN',GUI='NOT_RUN',M2='NOT_RUN',inventories={},payloads={})
        def row(step,raw=b'FENCED PUBLIC LIFECYCLE\n'):self.row('commands',self.stage_rows,step,raw)
        def inventory(step,count):
            raw=self.inventory(count);row(step,raw)
            if step!='current-baseline':self.lifecycle_report['inventories'][step]=pin(raw)
        def payload(kind,label):
            recipe=self.profile['setup8']if kind=='setup8'else self.profile['packages'][kind]
            row(label+'-file-list',''.join('/'+name+'\n'for name in sorted(recipe['payload_files'])).encode())
            for i,(name,body)in enumerate(sorted(recipe['payload_files'].items())):
                row(label+'-owner-'+str(i),(recipe['name']+'\n').encode());row(label+'-stat-'+str(i),('0:0:%o:%d:1:regular file\n'%(body['mode'],body['bytes'])).encode());row(label+'-sha256-'+str(i),(body['sha256']+'  /'+name+'\n').encode())
            return dict(verified=True,files=recipe['payload_files'])
        def absence(label,kinds):
            names=sorted(name for kind in kinds for name in (self.profile['setup8']if kind=='setup8'else self.profile['packages'][kind])['payload_files'])
            for i in range(len(names)):
                for flag in ('-e','-L'):row(label+'-'+str(i)+flag,b'')
        inventory('current-baseline',372)
        for kind in ('setup8','enrollment','first-login','ui'):row('current-signature-'+kind,b'[GNUPG:] FENCED PUBLIC SIGNATURE\n');row('current-pkginfo-'+kind,('pkgname = '+self.recipe(kind)['name']+'\npkgver = '+self.recipe(kind)['version']+'\narch = any\n').encode())
        row('current-install-setup8');inventory('current-dependency-inventory',373);self.lifecycle_report['payloads']['setup8']=payload('setup8','current-setup8')
        for cycle in ('install','reinstall'):
            row('current-'+cycle);inventory('current-'+cycle+'-inventory',376)
            self.lifecycle_report['payloads'][cycle]={kind:payload(kind,'current-'+cycle+'-'+kind)for kind in ('enrollment','first-login','ui')}
            for kind in ('enrollment','first-login','ui'):row('current-'+cycle+'-help-'+kind)
            row('current-remove-'+cycle);inventory('current-after-remove-'+cycle,373);absence('current-absent-'+cycle,('enrollment','first-login','ui'))
        row('current-remove-setup8');inventory('current-final-inventory',372);absence('current-absent-setup8',('setup8',))
    def keep(self,path,raw):
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);return dict(path=str(path),**pin(raw))
    def row(self,directory,rows,step,raw):
        name='%03d-%s.log'%(len(rows),step);self.keep(self.output/directory/name,raw)
        value=dict(step=step,argv=['/FENCED/not-executed','FENCED_PRIVATE_ARG'],cwd='/FENCED/private-cwd',expected=0,success=True,log=name,log_pin=pin(raw),supervision=natural(),channels='stdout+stderr combined in pipe order');rows.append(value);return value
    def stream(self,directory,step,raw):
        rows=[];self.row(directory,rows,step,raw);return self.keep(self.output/directory/'commands.json',encoded(rows))
    def flush(self):
        self.keep(self.output/'commands/commands.json',encoded(self.stage_rows));self.keep(self.output/'route.json',encoded(self.route))
    def retain(self,encoder):
        return R.retain_stage(self.stage,self.output,self.destination,binding=self.binding,profile=self.profile,inputs=self.inputs,public=self.public,streams=self.streams,public_roots=[self.root/'public-inputs'],encoder=encoder)


class Controls(unittest.TestCase):
    def test_standalone_audit_fence_denies_actor_and_network_events(self):
        for event in ('subprocess.Popen','socket.connect','os.system','os.exec','os.posix_spawn','os.fork'):
            with self.subTest(event=event),self.assertRaises(AssertionError):
                sys.audit(event)

    def test_credential_json_never_reaches_actual_retention_export(self):
        marker='FENCED_INERT_NOT_A_CREDENTIAL'
        cases=[dict(Root_acceptance=None,GITHUB_TOKEN=marker,Authorization=marker,nested=dict(api_token=marker)),
               {'nested':[{'Authorization':marker}]},{'Api_Key':marker},{'private_Key':marker},
               {'nested':{'credentialStore':marker}},{'GitHub_Token':None}]
        for role in ('runtime','context','domain','admission','image_qualification'):
            for body in cases:
                with self.subTest(role=role,body=list(body)),tempfile.TemporaryDirectory(prefix='FENCED-credential-refusal-') as temporary:
                    f=self.fixture(temporary);encoder=Encoder();stream=io.StringIO()
                    value=json.loads(Path(f.public[role]['path']).read_bytes())
                    value.update(body)
                    f.public[role]=f.keep(Path(f.public[role]['path']),encoded(value))
                    with self.assertRaisesRegex(ValueError,'credential-shaped'):
                        result=f.retain(encoder)
                        R.emit(result,stream)
                    self.assertFalse(encoder.calls)
                    self.assertEqual(stream.getvalue(),'')
                    self.assertFalse(f.destination.exists())

    def fixture(self,root,stage='backend'):return Fixture(Path(root),stage)
    def test_three_stage_capsules_preserve_bodies_empty_logs_and_public_projection(self):
        for stage in R.SCHEMAS:
            with self.subTest(stage=stage),tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
                f=self.fixture(temporary,stage);encoder=Encoder();original=R.read_file
                def public_only(path,*args):
                    self.assertNotIn(Path(path).name,('inside.json','proxy.json','signature-config.txt'));return original(path,*args)
                with patch.object(R,'read_file',side_effect=public_only):result=f.retain(encoder)
                self.assertEqual(result['evidence_state'],'COMPLETE');self.assertIsNone(result['Root_acceptance']);self.assertEqual(result['capsule_pin'],pin(encoder.result));self.assertEqual(len(encoder.calls),1)
                files=encoder.calls[0];self.assertIn('retention-manifest.json',files);self.assertTrue(any(raw==b''for name,raw in files.items()if name.endswith('.log')))
                joined=b'\n'.join(files.values());self.assertNotIn(b'FENCED_PRIVATE_FILE_MUST_NEVER_BE_READ',joined);self.assertNotIn(b'FENCED_PRIVATE_CREATE_ARGS',joined);self.assertNotIn(b'FENCED_PRIVATE_INSPECTION',joined);self.assertNotIn(b'FENCED_PRIVATE_LAUNCH',joined);self.assertNotIn(b'FENCED_PRIVATE_ARG',joined);self.assertNotIn(b'FENCED_PRIVATE_PROVENANCE_COMMAND',joined)
                manifest=result['manifest'];self.assertEqual(manifest['kind'],R.SCHEMAS[stage]);self.assertFalse(manifest['legacy_private_launch_replay']);self.assertTrue(manifest['public_domain_context_required'])
                for key in ('Root_acceptance','component_acceptance','hardware_acceptance','release_acceptance'):self.assertIsNone(manifest[key])
                for name,row in manifest['files'].items():self.assertEqual(row,pin(files[name]))
    def test_cleanup_uncertainty_retains_hold_without_acceptance(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
            f=self.fixture(temporary);f.route['owner_cleanup']['owned_container_absence_verified']=False;f.flush();encoder=Encoder();result=f.retain(encoder)
            self.assertEqual(result['evidence_state'],'HOLD');self.assertIn('UNCERTAIN_OR_PENDING_OWNED_RETIREMENT',result['manifest']['holds']);self.assertIsNone(result['Root_acceptance']);self.assertEqual(len(encoder.calls),1)
    def test_unknown_or_missing_roles_private_context_and_reference_drift_refuse_before_encoder(self):
        for mode in ('missing','unknown','private_context','context_binding','ref_drift','proxy_count'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
                f=self.fixture(temporary);encoder=Encoder()
                if mode=='missing':f.public.pop('domain')
                elif mode=='unknown':f.public['private_key']=f.public['public_test_key']
                elif mode=='proxy_count':f.streams['proxies'].pop()
                elif mode=='ref_drift':Path(f.public['inventory']['path']).write_bytes(b'FENCED CHANGED')
                else:
                    value=json.loads(Path(f.public['context']['path']).read_bytes())
                    if mode=='private_context':value['facts']['Config']={'FENCED':'private'}
                    else:value['binding']={'FENCED':'OTHER'}
                    f.public['context']=f.keep(Path(f.public['context']['path']),encoded(value))
                with self.assertRaises((OSError,ValueError)):f.retain(encoder)
                self.assertFalse(encoder.calls)
    def test_missing_pair_body_provenance_comparison_and_preservation_refuse_before_encoder(self):
        for mode in ('missing_archive','missing_provenance_file','comparison','counterpart'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
                f=self.fixture(temporary,'ui');encoder=Encoder()
                if mode=='missing_archive':(f.output/'builds/ui-a/artifacts/ui.pkg.tar.zst').unlink()
                elif mode=='missing_provenance_file':(f.output/'builds/ui-a/validation.json').unlink()
                elif mode=='comparison':row=next(r for r in f.stage_rows if r['step']=='current-ui-compare');row['log_pin']=pin(b'{}');f.keep(f.output/'commands'/row['log'],b'{}');f.flush()
                elif mode=='counterpart':(f.output/'builds/ui-b/artifacts/ui.pkg.tar.zst').write_bytes(b'FENCED WRONG PAIR')
                else:f.route['protected_after']['root_home']['files']=1;f.flush()
                with self.assertRaises((OSError,ValueError)):f.retain(encoder)
                self.assertFalse(encoder.calls)
    def test_alias_and_private_path_refuse_before_encoder(self):
        for mode in ('symlink','hardlink','private','traversal'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
                f=self.fixture(temporary);encoder=Encoder();path=Path(f.public['runtime']['path'])
                if mode=='symlink':path.unlink();path.symlink_to(Path(f.public['admission']['path']))
                elif mode=='hardlink':(f.root/'FENCED-link').hardlink_to(path)
                elif mode=='private':f.public['runtime']=dict(path=str(f.output/'inside.json'),**pin(b'FENCED_PRIVATE_FILE_MUST_NEVER_BE_READ'))
                else:f.streams['admission']['path']=str(f.output/'owner-state/../inside.json')
                with self.assertRaises((OSError,ValueError)):f.retain(encoder)
                self.assertFalse(encoder.calls)
    def test_missing_inventory_or_payload_bodies_cannot_be_replaced_by_producer_pass(self):
        for mode in ('missing_inventory_body','missing_inventory_receipt','inventory_count','missing_payload_body','payload_receipt','unknown_stage_step'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
                f=self.fixture(temporary,'lifecycle');encoder=Encoder();inventory=next(r for r in f.stage_rows if r['step']=='current-install-inventory');payload=next(r for r in f.stage_rows if r['step']=='current-install-ui-owner-0')
                if mode=='missing_inventory_body':(f.output/'commands'/inventory['log']).unlink()
                elif mode=='missing_inventory_receipt':f.route['lifecycle']['inventories'].pop('current-install-inventory');f.flush()
                elif mode=='inventory_count':
                    raw=f.inventory(375);inventory['log_pin']=pin(raw);f.keep(f.output/'commands'/inventory['log'],raw);f.route['lifecycle']['inventories']['current-install-inventory']=pin(raw);f.flush()
                elif mode=='missing_payload_body':(f.output/'commands'/payload['log']).unlink()
                elif mode=='payload_receipt':f.route['lifecycle']['payloads']['install']['ui']['files']={};f.flush()
                else:f.row('commands',f.stage_rows,'current-FENCED-unexplained',b'FENCED PRODUCER PASS');f.flush()
                with self.assertRaises((OSError,ValueError)):f.retain(encoder)
                self.assertFalse(encoder.calls)
    def test_public_roots_and_observed_context_domain_are_mandatory(self):
        for mode in ('outside_root','context_image','context_architecture','context_page_size','domain_empty','domain_private','domain_status_only'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
                f=self.fixture(temporary,'ui');encoder=Encoder()
                if mode=='outside_root':
                    f.public['runtime']=f.keep(f.root/'unapproved-public.json',encoded({'FENCED':'outside'}))
                else:
                    role='context'if mode.startswith('context_')else'domain';path=Path(f.public[role]['path']);value=json.loads(path.read_bytes())
                    if mode=='context_image':value['facts']['image']='sha256:'+'e'*64
                    elif mode=='context_architecture':value['facts']['architecture']='x86_64'
                    elif mode=='context_page_size':value['facts']['page_size']=True
                    elif mode=='domain_empty':value['facts']['observations']=[]
                    elif mode=='domain_private':value['facts']['observations'][0]['body']['Config']={'Env':['FENCED_PRIVATE']}
                    else:value['facts']['observations'][0]['body']={'status':'PASS'}
                    f.public[role]=f.keep(path,encoded(value))
                original=R.read_file
                def guarded(path,*args):
                    self.assertNotEqual(Path(path),f.root/'unapproved-public.json');return original(path,*args)
                with patch.object(R,'read_file',side_effect=guarded),self.assertRaises(ValueError):f.retain(encoder)
                self.assertFalse(encoder.calls)
    def test_private_launch_logs_are_not_opened_and_command_projection_stays_single(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
            f=self.fixture(temporary,'ui');proxy=Path(f.streams['proxies'][2]['path']);rows=json.loads(proxy.read_bytes());private_logs=set()
            for row in rows:
                if any(word in row['step']for word in ('inspect','create','start-attached','native-daemon')):
                    raw=b'FENCED_PRIVATE_DOCKER_CONFIGURATION';f.keep(proxy.parent/row['log'],raw);row['log_pin']=pin(raw);private_logs.add(proxy.parent/row['log'])
            f.streams['proxies'][2]=f.keep(proxy,encoded(rows));original=R.read_file;encoder=Encoder()
            def guarded(path,*args):
                self.assertNotIn(Path(path),private_logs);return original(path,*args)
            with patch.object(R,'read_file',side_effect=guarded):f.retain(encoder)
            selected=json.loads(encoder.calls[0]['streams/proxy-2/commands.public.json'])
            self.assertEqual(len(selected),len(rows));self.assertEqual([r['step']for r in selected],[r['step']for r in rows]);self.assertEqual(sum(bool(r.get('private_launch_body_excluded'))for r in selected),len(private_logs))
            self.assertNotIn(b'FENCED_PRIVATE_DOCKER_CONFIGURATION',b'\n'.join(encoder.calls[0].values()))
    def test_lifecycle_preservation_retirement_and_incomplete_command_retain_hold(self):
        for mode in ('preservation','private_retirement','outer_retirement','command'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
                f=self.fixture(temporary,'lifecycle');encoder=Encoder()
                if mode=='preservation':f.route['protected_after']['root_home']['files']=1;f.flush()
                elif mode=='command':f.stage_rows[0]['supervision']['output_complete']=False;f.flush()
                else:
                    path=f.output/('owner-local.json'if mode=='private_retirement'else'outer-owner/receipt.final.json');value=json.loads(path.read_bytes())
                    if mode=='private_retirement':value['private_retirement']['no_sockets']=False
                    else:value['status']='HOLD'
                    f.keep(path,encoded(value))
                result=f.retain(encoder);self.assertEqual(result['evidence_state'],'HOLD');self.assertTrue(result['manifest']['holds']);self.assertIsNone(result['Root_acceptance']);self.assertEqual(len(encoder.calls),1)
    def test_caps_and_bad_encoder_or_encoder_staging_tamper_refuse(self):
        for field,value in (('MAX_FILE',8),('MAX_TOTAL',64),('MAX_MEMBERS',3)):
            with self.subTest(cap=field),tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
                f=self.fixture(temporary);encoder=Encoder()
                with patch.object(R,field,value),self.assertRaises(ValueError):f.retain(encoder)
                self.assertFalse(encoder.calls)
        for mode in ('empty','wrong_type','oversize','staging_tamper'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
                f=self.fixture(temporary);encoder=Encoder(result=b''if mode=='empty'else'FENCED'if mode=='wrong_type'else b'X'*17 if mode=='oversize'else b'FENCED')
                if mode=='staging_tamper':encoder.mutation=lambda root:(root/'FENCED-extra').write_bytes(b'FENCED')
                with patch.object(R,'MAX_COMPRESSED',16),self.assertRaises(ValueError):f.retain(encoder)
    def test_existing_log_encoder_retains_exact_public_namespace_and_frames_capsule(self):
        spec=importlib.util.spec_from_file_location('FENCED_existing_log_evidence',HERE.parents[2]/'log_evidence.py');log_evidence=importlib.util.module_from_spec(spec);spec.loader.exec_module(log_evidence)
        with tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
            f=self.fixture(temporary,'ui');root=f.destination/'current-ui-public-v3';original_read=R.read_file;original_walk=Path.rglob;walks=[]
            private={f.output/name for name in ('inside.json','proxy.json','signature-config.txt','owner-state/proxy.json')};before={p:p.stat() for p in private}
            def only_public(path,*args):
                self.assertNotIn(Path(path),private);return original_read(path,*args)
            def only_staging(path,pattern):
                self.assertEqual(path,root);walks.append(path);return original_walk(path,pattern)
            with patch.object(R,'read_file',side_effect=only_public),patch.object(Path,'rglob',only_staging):result=f.retain(log_evidence.bundle)
            self.assertEqual(walks,[root]);self.assertEqual({p:p.stat() for p in private},before)
            expected=dict(result['manifest']['files']);expected['retention-manifest.json']=pin(R.encode(result['manifest']))
            with tarfile.open(fileobj=io.BytesIO(result['capsule']),mode='r:gz')as archive:
                members=archive.getmembers();self.assertTrue(all(m.isfile()for m in members));self.assertEqual(len(members),len(expected))
                self.assertEqual({m.name for m in members},{root.name+'/'+name for name in expected})
                for member in members:
                    with archive.extractfile(member)as stream:raw=stream.read()
                    self.assertEqual(pin(raw),expected[member.name.removeprefix(root.name+'/')]);self.assertNotIn(b'FENCED_PRIVATE',raw)
            stream=io.StringIO();R.emit(result,stream);lines=stream.getvalue().splitlines()
            self.assertEqual(lines[0],'CACHY_ASAHI_EVIDENCE_BEGIN %s sha256=%s bytes=%d'%(root.name,pin(result['capsule'])['sha256'],len(result['capsule'])))
            self.assertEqual(lines[-1],'CACHY_ASAHI_EVIDENCE_END '+root.name);self.assertEqual(base64.b64decode(''.join(lines[1:-1]),validate=True),result['capsule'])
    def test_mixed_case_private_fields_and_wrong_domain_identity_refuse(self):
        for role in ('context','domain'):
            for key in ('env','GITHUB_TOKEN','private_Key','launch_Manifest'):
                with self.subTest(role=role,key=key),tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
                    f=self.fixture(temporary,'ui');encoder=Encoder();path=Path(f.public[role]['path']);value=json.loads(path.read_bytes())
                    target=value['facts']if role=='context'else value['facts']['observations'][0]['body'];target[key]={'FENCED':'PRIVATE'};f.public[role]=f.keep(path,encoded(value))
                    with self.assertRaises(ValueError):f.retain(encoder)
                    self.assertFalse(encoder.calls)
        for mode in ('wrong_image','empty_state','unmatched_retirement'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
                f=self.fixture(temporary,'ui');encoder=Encoder();path=Path(f.public['domain']['path']);value=json.loads(path.read_bytes());observations=value['facts']['observations']
                if mode=='wrong_image':observations[0]['body']['image']='sha256:'+'e'*64
                elif mode=='empty_state':observations[0]['body']['state']={}
                else:observations[1]['body']['cid']='e'*64
                f.public['domain']=f.keep(path,encoded(value))
                if mode=='unmatched_retirement':
                    result=f.retain(encoder);self.assertEqual(result['evidence_state'],'HOLD');self.assertIn('UNMATCHED_PUBLIC_RETIREMENT_IDENTITIES',result['manifest']['holds']);self.assertIsNone(result['Root_acceptance'])
                else:
                    with self.assertRaises(ValueError):f.retain(encoder)
                    self.assertFalse(encoder.calls)
    def test_known_launch_failure_retains_redacted_hold_without_command_arguments(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
            f=self.fixture(temporary,'lifecycle');row=f.stage_rows[0];row.update(success=False,supervision=None,launch_error='FENCED_PRIVATE_LAUNCH_ERROR');f.flush();encoder=Encoder();result=f.retain(encoder)
            self.assertEqual(result['evidence_state'],'HOLD');self.assertIsNone(result['Root_acceptance']);self.assertIn('NON_NATURAL_OR_UNCERTAIN_COMMAND',result['manifest']['holds'])
            projected=json.loads(encoder.calls[0]['streams/stage/commands.public.json']);self.assertEqual(len(projected),len(f.stage_rows));self.assertEqual(projected[0]['launch_error'],'PRESENT_REDACTED');self.assertEqual(projected[0]['supervision']['ownership'],'UNKNOWN')
            joined=b'\n'.join(encoder.calls[0].values());self.assertNotIn(b'FENCED_PRIVATE_LAUNCH_ERROR',joined);self.assertNotIn(b'FENCED_PRIVATE_ARG',joined);self.assertNotIn(b'/FENCED/private-cwd',joined)
    def test_read_drift_private_markers_and_emit_envelope(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
            path=Path(temporary)/'FENCED.data';path.write_bytes(b'FENCED original');original=R.os.read;mutated=[]
            def drift(fd,size):
                raw=original(fd,size)
                if raw and not mutated:path.write_bytes(b'FENCED modified');mutated.append(True)
                return raw
            with patch.object(R.os,'read',side_effect=drift),self.assertRaises(ValueError):R.read_file(path)
            path.write_bytes(b'-----BEGIN PGP PRIVATE KEY BLOCK-----\nFENCED\n')
            with self.assertRaises(ValueError):R.read_file(path)
        with tempfile.TemporaryDirectory(prefix='FENCED-retention-')as temporary:
            result=self.fixture(temporary,'ui').retain(Encoder());out=io.StringIO();R.emit(result,out);lines=out.getvalue().splitlines()
            self.assertTrue(lines[0].startswith('CACHY_ASAHI_EVIDENCE_BEGIN current-ui-public-v3 '));self.assertEqual(lines[-1],'CACHY_ASAHI_EVIDENCE_END current-ui-public-v3');self.assertEqual(base64.b64decode(''.join(lines[1:-1])),result['capsule'])
            bad=copy.deepcopy(result);bad['capsule']+=b'FENCED';out=io.StringIO()
            with self.assertRaises(ValueError):R.emit(bad,out)
            self.assertEqual(out.getvalue(),'')


if __name__=='__main__':unittest.main()
