#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert image executor models only; no process, Docker, GPG, network or lease."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.'))or event in ('os.system','os.exec','os.fork','os.posix_spawn','resource.setrlimit','fcntl.flock'):
        raise RuntimeError('modeled image DATA only: '+event)


sys.addaudithook(fence)
s=importlib.util.spec_from_file_location('current_image_model_controls',HERE/'image_current_v3.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)


def put(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o600)
    return dict(path=str(path),**P.pin(raw))


def package(path,name,version,arch='aarch64'):
    raw=io.BytesIO()
    with tarfile.open(fileobj=raw,mode='w:xz')as archive:
        body=('pkgname = '+name+'\npkgver = '+version+'\narch = '+arch+'\n').encode()
        info=tarfile.TarInfo('.PKGINFO');info.size=len(body);archive.addfile(info,io.BytesIO(body))
    return put(path,raw.getvalue())


def supervision(code=0):
    return dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,exit=code)


class HeldModel:
    def snapshot_receipt(self,path):return dict(MODEL_ONLY=True,path=str(path),unchanged=True)
    def retire_private(self,run,work,homes):
        self.retired=list(homes);shutil.rmtree(work)
        return dict(homes_retired=True,no_sockets=True,private_directory_absent=True,failures=[])
    def _metadata(self,raw):
        value={}
        for line in raw.decode().splitlines():
            if ' = 'in line:k,v=line.split(' = ',1);value.setdefault(k,[]).append(v)
        return value


class ContextModel:
    OPERATION=P.OP
    DELEGATION='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3'
    CONTEXT='DELEGATED_CURRENT_ONBOARDING_CONTEXT_V3'
    ISSUER='DELEGATED_CONTEXT_PROGRAM_V3'
    def __init__(self,d,c,archive):
        self.d,self.c,self.archive=d,c,archive
        self.__file__=str(Path(c['source_root'])/d['programs']['context']['member'])
    def validate_delegation(self,raw,sha):
        assert P.pin(raw)['sha256']==sha and P.decoded(raw)==self.d
        return self.d
    def validate_context(self,d,c):assert d==self.d and c==self.c;return c
    def adopt_pair(self,d,c,**kwargs):
        assert set(kwargs)=={'producer_delegation_raw','producer_context','pair_raw','test_raw'}
        return dict(kind='DELEGATED_CURRENT_ONBOARDING_PAIR_ADOPTION_V'+str(d['schema']),binding=c['binding'],archives=[self.archive]*2,
                    Root_final_acceptance=None,independent_component_acceptance=False,MODEL_ONLY=True)


class ExecutorModel:
    """No command is executed: generated receipts and IDs are explicitly MODEL."""
    def __init__(self,facts,base,expected,payload,fingerprint):
        self.facts,self.base,self.expected,self.payload,self.fingerprint=facts,base,expected,payload,fingerprint
        self.images={};self.containers={};self.calls=[];self.fail_step=None;self.bad_inspect=None;self.bad_signature=False;self.fail_retirement_step=None;self.live_failed_start=False;self.hook_failure=False
    def id(self,n):return '%064x'%n
    def inspect(self,row):
        value=copy.deepcopy(row)
        if self.bad_inspect is not None:self.bad_inspect(value)
        return value
    def run(self,step,argv,seconds,expected=0):
        self.calls.append((step,argv,seconds,expected));raw=b'';code=expected
        if step==self.fail_step:code=7
        elif argv[0]=='/usr/bin/gpg':
            if '--verify'in argv:
                trust='test'if '/test'in argv[argv.index('--homedir')+1]else'official'
                f=self.fingerprint[trust];raw=('[GNUPG:] GOODSIG MODEL_ONLY\n[GNUPG:] VALIDSIG '+f+' 0 0 0 0 0 '+f+'\n').encode()
                if self.bad_signature or step==getattr(self,'bad_signature_step',None):raw+=b'[GNUPG:] EXPKEYSIG MODEL_ONLY\n'
        elif step=='seed-build':
            iid='sha256:'+self.id(1);Path(argv[argv.index('--iidfile')+1]).write_text(iid+'\n')
            labels=dict(item.split('=',1)for i,item in enumerate(argv)if i and argv[i-1]=='--label')
            self.images[iid]=dict(Id=iid,Os='linux',Architecture='arm64',Config=dict(Labels=labels),RepoTags=[argv[argv.index('--tag')+1]],RepoDigests=[])
        elif argv[0]=='/usr/bin/docker':
            args=argv[2:]
            if args[:1]==['info']:
                raw=P.encoded(dict(OSType='linux',Architecture='aarch64',CgroupVersion='2',ID=self.facts['engine_id'],MemoryLimit=True,SwapLimit=True,CpuCfsQuota=True,PidsLimit=True,SecurityOptions=['name=seccomp,profile=builtin']))
            elif args[:2]==['image','ls']:
                raw=''.join(image+'\n'for image in self.images).encode()
            elif args[:2]==['image','inspect']:raw=json.dumps([self.images[args[2]]]).encode()
            elif args[:2]==['image','rm']:del self.images[args[2]]
            elif args[:1]==['ps']:
                target=args[args.index('--filter')+1][len('name=^/'):].removesuffix('$')
                raw=''.join(cid+'\n'for cid,row in self.containers.items()if row['Name']=='/'+target).encode()
            elif args[:2]==['container','create']:
                cid=self.id(len(self.calls)+10);name=args[args.index('--name')+1]
                entry=args.index('--entrypoint=/bin/bash');image=args[entry+1];cmd=args[entry+2:]
                labels=dict(item.split('=',1)for i,item in enumerate(args)if i and args[i-1]=='--label')
                caps=[item.split('=',1)[1]for item in args if item.startswith('--cap-add=')]
                self.containers[cid]=dict(Id=cid,Name='/'+name,Image=image,Config=dict(Labels=labels,Entrypoint=['/bin/bash'],Cmd=cmd,User=args[args.index('--user')+1]),
                    HostConfig=dict(NetworkMode='none',Privileged=False,Devices=[],DeviceRequests=[],CapDrop=['ALL'],CapAdd=caps,Memory=4*1024**3,MemorySwap=4*1024**3,NanoCpus=4*10**9,PidsLimit=512,ReadonlyRootfs='--read-only'in args,SecurityOpt=['no-new-privileges']),
                    Mounts=[],State=dict(Running=False,ExitCode=0,OOMKilled=False));raw=(cid+'\n').encode()
            elif args[:2]==['container','inspect']:raw=json.dumps([self.inspect(self.containers[args[2]])]).encode()
            elif args[:2]==['container','start']:
                cid=args[-1];phase=self.containers[cid]['Name'].rsplit('-',1)[1]
                if phase=='probe':raw=P.lock(self.expected)
                elif self.hook_failure:raw=b'error: command failed to execute correctly (MODEL hook failure)\n'
            elif args[:2]==['container','stop']:self.containers[args[-1]]['State']['Running']=False
            elif args[:2]==['container','rm']:del self.containers[args[2]]
            elif args[:2]==['container','commit']:
                cid=args[-2];iid='sha256:'+self.id(len(self.calls)+100)
                self.images[iid]=dict(Id=iid,Os='linux',Architecture='arm64',Config=dict(Labels=self.containers[cid]['Config']['Labels']),RepoTags=[args[-1]],RepoDigests=[]);raw=(iid+'\n').encode()
            elif args[:1]==['cp']and':/image-facts/.'in args[1]:
                cid=args[1].split(':')[0];dest=Path(args[2]);phase=self.containers[cid]['Name'].rsplit('-',1)[1]
                (dest/'inventory.lock').write_bytes(P.lock(self.base if phase=='base'else self.expected))
                (dest/'package-file-check.log').write_bytes(b'MODEL ONLY pacman Qkk receipt\n')
                payload={}if phase=='base'else self.payload
                lines=[]
                for path,row in sorted(payload.items()):lines.extend([row['owner']+'\t'+path+'\t0:0:%o:%d:1:regular file'%(row['mode'],row['bytes']),row['sha256']+'  /'+path])
                (dest/'payload.tsv').write_text('\n'.join(lines)+('\n'if lines else''))
                (dest/'package-files.txt').write_text(''.join('PACKAGE '+owner+'\n'+''.join('/'+n+'\n'for n,r in sorted(payload.items())if r['owner']==owner)for owner in sorted({r['owner']for r in payload.values()})))
                (dest/'alarm.passwd').write_text('alarm:x:%d:%d:MODEL:/home/alarm:/bin/bash\n'%(self.facts['uid'],self.facts['gid']))
                (dest/'alarm.group').write_text('alarm:x:%d:\n'%self.facts['gid'])
        retirement=supervision(code)
        if step==self.fail_retirement_step:
            retirement['group_census']='UNKNOWN'
            if self.live_failed_start and step.startswith('start-'):self.containers[argv[-1]]['State']['Running']=True
        return dict(stdout=raw,stderr=b'',receipt=dict(step=step,argv=argv,expected=expected,exit=code,output_pin=P.pin(raw),stderr_pin=P.pin(b''),supervision=retirement,MODEL_ONLY=True))


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='current-image-v3-MODEL-');cls.addClassCleanup(cls.temp.cleanup);cls.root=Path(cls.temp.name)
        cls.material=cls.root/'public-MODEL';cls.material.mkdir();cls.base_rows=[];cls.base_versions={}
        root_records=[];raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w:gz')as archive:
            for i in range(165):
                name='model-base-%03d'%i;version='0.0-model-1';cls.base_versions[name]=version
                md=dict(name=[name],version=[version],arch=['aarch64'],license=['MODEL'],depends=[],provides=[]);root_records.append(md)
                body=('%%NAME%%\n%s\n\n%%VERSION%%\n%s\n\n%%ARCH%%\naarch64\n\n%%LICENSE%%\nMODEL\n'%(name,version)).encode()
                info=tarfile.TarInfo('var/lib/pacman/local/'+name+'-'+version+'/desc');info.size=len(body);archive.addfile(info,io.BytesIO(body))
        rootfs=put(cls.material/'rootfs.tar.gz',raw.getvalue());root_sig=put(cls.material/'rootfs.tar.gz.sig',b'MODEL ROOTFS SIGNATURE')
        cls.materials={'rootfs.tar.gz':rootfs,'rootfs.tar.gz.sig':root_sig}
        for i in range(93,341):
            name='model-base-%03d'%i;version='0.0-model-2';cls.base_versions[name]=version;filename=name+'.pkg.tar.xz'
            ar=package(cls.material/filename,name,version);sig=put(cls.material/(filename+'.sig'),b'MODEL ONLY SIGNATURE')
            cls.base_rows.append(dict(name=name,version=version,arch='aarch64',filename=filename,size=ar['bytes'],sha256=ar['sha256'],signature_size=sig['bytes'],signature_sha256=sig['sha256']))
            cls.materials[filename]=ar;cls.materials[filename+'.sig']=sig
        cls.base_doc=dict(rootfs=dict(filename='rootfs.tar.gz',size=rootfs['bytes'],sha256=rootfs['sha256'],signature_size=root_sig['bytes'],signature_sha256=root_sig['sha256']),
                          rootfs_packages=root_records,packages=cls.base_rows,signer_fingerprint='A'*40,MODEL_ONLY=True)
        cls.base_ref=put(cls.material/'base-lock.json',P.encoded(cls.base_doc))
        cls.supplements=[];cls.supplement_materials={};original=dict(cls.base_versions)
        for name in sorted(P.SUPPLEMENTAL):
            version='0.0-model-1';arch='any'if name in ('meson','python-tqdm')else'aarch64';filename=name+'.pkg.tar.xz'
            ar=package(cls.material/filename,name,version,arch);sig=put(cls.material/(filename+'.sig'),b'MODEL ONLY SUPPLEMENTAL SIGNATURE')
            cls.supplements.append(dict(name=name,version=version,arch=arch,filename=filename,size=ar['bytes'],sha256=ar['sha256'],signature_size=sig['bytes'],signature_sha256=sig['sha256']))
            cls.supplement_materials[filename]=ar;cls.supplement_materials[filename+'.sig']=sig;cls.base_versions[name]=version
        cls.bootstrap_ref=put(cls.material/'bootstrap-profile.json',P.encoded(dict(original341=dict(package_count=341,packages=original),
            additions=dict(count=8,expected_augmented_package_count=349,unresolved=[],rows=cls.supplements),MODEL_ONLY=True)))
        cls.inventory_ref=put(cls.material/'baseline349.lock',P.lock(cls.base_versions))
        cls.factory_raw=P.encoded(dict(parent_files={member:dict({k:ref[k]for k in ('bytes','sha256')},mode=0o644)for member,ref in
            (('bootstrap/scripts/ci/inputs.lock.json',cls.base_ref),('native/input-profile.json',cls.bootstrap_ref),('native/expected349.lock',cls.inventory_ref))},MODEL_ONLY=True))
        cls.catalog={};cls.official={}
        for name in sorted(P.OFFICIAL):
            version='1:0.0-model-1'if name=='gtk4'else'0.0-model-1';filename=name+'.pkg.tar.xz'
            ar=package(cls.material/filename,name,version);sig=put(cls.material/(filename+'.sig'),b'MODEL ONLY OFFICIAL SIGNATURE')
            cls.official[name]=dict(name=name,version=version,arch='aarch64',filename=filename,archive=ar,signature=sig)
            cls.catalog[name]=dict(name=name,version=version,arch='aarch64',archive={k:ar[k]for k in ('bytes','sha256')},signature={k:sig[k]for k in ('bytes','sha256')})
        cls.catalog_ref=put(cls.material/'official-catalog.json',P.encoded(dict(selected=cls.catalog,unresolved=[],ambiguous=[],conflicts=[],ordering_comparisons_pending=[],conflict_ordering_pending=[],MODEL_ONLY=True)))
        cls.official_ref=put(cls.material/'official-materials.json',P.encoded(dict(packages=cls.official,MODEL_ONLY=True)))

    def setUp(self):
        self.home=self.root/uuid.uuid4().hex;self.home.mkdir();self.source=self.home/'source';self.source.mkdir();self.out=self.home/'result'
        self.nonce=uuid.uuid4().hex;self.stage='backend';self.fprs=dict(official='A'*40,test='B'*40)
        self.policy=dict(image_domains={role:{'memory.max':str(2*1024**3),'memory.swap.max':'0','pids.max':'1024','cpu.max':'400000 100000'}for role in ('owner','daemon')},
            image_endpoint_template='unix:///tmp/MODEL-{nonce}.sock',image_storage_bytes=32*1024**3,image_steps=dict(verification_seconds=60,bootstrap_seconds=1800,stage_seconds=180,inspect_seconds=15,cleanup_seconds=90),image_alpm_capabilities=P.CAPS)
        policy_ref=put(self.source/'policy.json',P.encoded(self.policy))
        program=lambda member,body:dict(member=member,**P.pin(body))
        put(self.source/'context.DATA',b'MODEL CONTEXT PROGRAM');put(self.source/'executor.DATA',b'MODEL EXECUTOR PROGRAM')
        own=P.data(Path(P.__file__),128*1024)
        self.d=dict(schema=3,kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3',issuer='Root',operation=P.OP,stage='backend',nonce=self.nonce,expires_epoch=int(time.time())+1800,programs=dict(context=program('context.DATA',b'MODEL CONTEXT PROGRAM'),image=program('image.py',own),image_executor=program('executor.DATA',b'MODEL EXECUTOR PROGRAM')),
            policy=program('policy.json',P.encoded(self.policy)),capability=dict(allow_provisional_image_checks=True,builder_cpus=4,builder_memory_bytes=4*1024**3,builder_pids=512,command_rows=512,max_command_seconds=1800,total_seconds=1800),MODEL_ONLY=True)
        self.c=dict(schema=3,kind='DELEGATED_CURRENT_ONBOARDING_CONTEXT_V3',issuer='DELEGATED_CONTEXT_PROGRAM_V3',operation=P.OP,program_pin=P.pin(b'MODEL CONTEXT PROGRAM'),source_root=str(self.source),stage='backend',nonce=self.nonce,binding=dict(source='c'*40,ref='refs/heads/codex/MODEL',run='42',job='43',attempt=1,source_lock=dict(bytes=1,sha256='d'*64)))
        self.c['delegation_pin']=P.pin(P.encoded(self.d))
        domain=lambda role:dict(pid=11 if role=='owner'else 12,starttime=123,cgroup='/MODEL/'+self.nonce+'/'+role,limits=self.policy['image_domains'][role])
        self.facts=dict(api=P.API,binding=self.c['binding'],nonce=self.nonce,stage='backend',code_pin={k:self.d['programs']['image_executor'][k]for k in ('bytes','sha256')},domain_policy_pin={k:policy_ref[k]for k in ('bytes','sha256')},native_architecture='aarch64',owner_domain=domain('owner'),daemon_domain=domain('daemon'),daemon_pidfd_held=True,
            whole_owner_deadline_enforced=True,daemon_deadline_enforced=True,exclusive_daemon=True,docker_endpoint=self.policy['image_endpoint_template'].format(nonce=self.nonce),storage=dict(quota_bytes=self.policy['image_storage_bytes'],kernel_enforced=True,scope='ALL_IMAGE_OWNER_CONTEXT_DAEMON_WRITES'),uid=os.getuid(),gid=os.getgid(),engine_id='MODEL_ENGINE')
        put(self.source/'scripts/ci/first-login-enrollment-native-source/profile.json',self.factory_raw)
        self.inputs=dict(base_lock=self.base_ref,baseline_inventory=self.inventory_ref,base_materials=self.materials,bootstrap_profile=self.bootstrap_ref,supplemental_materials=self.supplement_materials,official_catalog=self.catalog_ref,official_materials=self.official_ref)
        for key in ('official','test'):
            public=put(self.home/(key+'.public'),b'MODEL PUBLIC KEY ONLY')
            admission=put(self.home/(key+'-trust.json'),P.encoded(dict(issuer='Root',approved=True,public_key=public,fingerprint=self.fprs[key],scope='CURRENT_ONBOARDING_IMAGE_INPUT_TRUST_ONLY',issued_epoch=int(time.time())-1,expires_epoch=int(time.time())+1800,MODEL_ONLY=True)))
            self.inputs[key+'_trust']=dict(public_key=public,fingerprint=self.fprs[key],Root_admission=admission)
        self.inputs['setup8']=self.project('cachy-asahi-setup','0.3.0-1','setup8')
        self.inputs['cli03']=self.project('cachy-asahi-first-login','0.1.0-3','cli03')
        pair={name:put(self.home/(name+'.json'),P.encoded(dict(MODEL_ONLY=True)))for name in ('producer_delegation','producer_context','pair','test')}
        self.inputs['cli03']['pair_adoption']=pair
        profile=dict(setup8=dict(archive_pin={k:self.inputs['setup8']['archive'][k]for k in ('bytes','sha256')},payload_files=self.inputs['setup8']['payload_files']),packages={'first-login':dict(payload_files=self.inputs['cli03']['payload_files'])},MODEL_ONLY=True)
        profile_ref=put(self.source/'scripts/ci/first-login-enrollment-native-source/successor_v2/profile.json',P.encoded(profile))
        self.H=ContextModel(self.d,self.c,{k:self.inputs['cli03']['archive'][k]for k in ('bytes','sha256')})
        self.T=HeldModel()
        self.patches=[mock.patch.object(P,'FACTORY_PROFILE_PIN',P.pin(self.factory_raw)),mock.patch.object(P,'BOOTSTRAP_PROFILE_PIN',{k:self.bootstrap_ref[k]for k in ('bytes','sha256')}),mock.patch.object(P,'CONTEXT_PROGRAM_PINS',{**P.CONTEXT_PROGRAM_PINS,3:P.pin(b'MODEL CONTEXT PROGRAM')}),mock.patch.object(P,'PROFILE_SHA',profile_ref['sha256']),mock.patch.object(P,'BASE_LOCK_SHA',self.base_ref['sha256']),mock.patch.object(P,'BASE_INVENTORY_SHA',self.inventory_ref['sha256']),mock.patch.object(P,'tools',return_value=self.T),mock.patch.object(P,'protected_state',side_effect=lambda T:{p:T.snapshot_receipt(Path(p))for p in P.PROTECTED}),
            mock.patch.object(P,'native_identity',return_value=dict(system='Linux',machine='aarch64',uid=os.getuid(),gid=os.getgid(),pid=11)),
            mock.patch.object(P,'actual_domain',side_effect=lambda pid:dict((self.facts['owner_domain']if pid==11 else self.facts['daemon_domain']),executable='python3'if pid==11 else'dockerd'))]
        for patch in self.patches:patch.start();self.addCleanup(patch.stop)
        self.addCleanup(lambda:shutil.rmtree(Path('/tmp')/('build-tools-test-current-image-'+self.nonce),ignore_errors=True))

    def project(self,name,version,slot):
        ar=package(self.home/(slot+'.pkg.tar.xz'),name,version,'any');sig=put(self.home/(slot+'.sig'),b'MODEL PROJECT SIGNATURE')
        payload={('usr/share/MODEL/'+slot+'/leaf-%02d'%i):dict(bytes=1,sha256=P.pin(b'M')['sha256'],mode=0o644)for i in range(10 if slot=='setup8'else 6)}
        pub=dict(bytes=self.inputs['test_trust']['public_key']['bytes'],sha256=self.inputs['test_trust']['public_key']['sha256'],fingerprint=self.fprs['test'],trust_scope='TEST_ONLY')
        proof=put(self.home/(slot+'-proof.json'),P.encoded(dict(schema=1,Root_issuer='Root',status='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE',trust_scope='TEST_ONLY',verified=True,archive={k:ar[k]for k in ('bytes','sha256')},signature={k:sig[k]for k in ('bytes','sha256')},public_test_key=pub,MODEL_ONLY=True)))
        decision=put(self.home/(slot+'-decision.json'),P.encoded(dict(schema=1,issuer='Root',accepted=True,holds_preserved=True,status=('ACCEPTED_PRIVATE_SETUP8_PACKAGE_TEST_ONLY'if slot=='setup8'else'ACCEPTED_PRIVATE_CURRENT_ONBOARDING_PACKAGE_TEST_ONLY'),trust_scope='TEST_ONLY',public_test_key=pub,verification_proof_sha256=proof['sha256'],archive=dict({k:ar[k]for k in ('bytes','sha256')},package=name,version=version,arch='any'),signature={k:sig[k]for k in ('bytes','sha256')},MODEL_ONLY=True)))
        return dict(name=name,version=version,arch='any',filename=slot+'.pkg.tar.xz',archive=ar,signature=sig,payload_files=payload,Root_decision=decision,Root_verification=proof)

    def executor(self,stage='backend'):
        self.stage=stage;self.d['stage']=self.c['stage']=self.facts['stage']=stage;self.c['delegation_pin']=P.pin(P.encoded(self.d))
        expected=dict(self.base_versions)
        if stage in ('lifecycle','ui'):expected.update({n:r['version']for n,r in self.official.items()})
        payload={}
        if stage in ('backend','ui'):
            expected['cachy-asahi-setup']='0.3.0-1'
            payload.update({n:dict(r,owner='cachy-asahi-setup')for n,r in self.inputs['setup8']['payload_files'].items()})
        if stage=='ui':
            expected['cachy-asahi-first-login']='0.1.0-3'
            payload.update({n:dict(r,owner='cachy-asahi-first-login')for n,r in self.inputs['cli03']['payload_files'].items()})
        return ExecutorModel(self.facts,self.base_versions,expected,payload,self.fprs)

    def build(self,e):return P.build_stage(delegation_raw=P.encoded(self.d),delegation_sha256=P.pin(P.encoded(self.d))['sha256'],context=self.c,source_root=self.source,inputs=self.inputs,executor=e,output=self.out,context_program=self.H)

    def test_modeled350_normal_alpm_build_and_fresh_probe(self):
        e=self.executor();result=self.build(e)
        self.assertEqual(result['status'],'PROVISIONAL_CURRENT_IMAGE_CONSTRUCTED_DATA_ONLY');self.assertEqual(len(result['packages']),350)
        self.assertIsNone(result['independent_image_qualification']);self.assertIsNone(result['Root_final_acceptance'])
        self.assertFalse(e.containers);self.assertEqual(set(e.images),{result['image_id']})
        self.assertTrue(self.T.retired);self.assertEqual(result['protected_before'],result['protected_after'])
        self.assertLess(len(result['commands']),512)

    def test_base341_and_all8_supplements_use_normal_signed349_transaction(self):
        e=self.executor();result=self.build(e);provenance=result['base_input_provenance']
        self.assertEqual((provenance['original_package_count'],provenance['supplemental_package_count'],provenance['final_package_count']),(341,8,349))
        rows=provenance['materials'];self.assertEqual(len(rows),257)
        supplemental=[r for r in rows if r['source_group']=='supplemental_materials']
        self.assertEqual({r['name']for r in supplemental},P.SUPPLEMENTAL)
        calls={step:argv for step,argv,_,_ in e.calls}
        self.assertTrue(all('verify-%03d'%i in calls for i in range(249,257)))
        staged=P.data(self.out/'base-materials/packages.list').decode().splitlines()
        self.assertEqual(len(staged),256);self.assertTrue(P.SUPPLEMENTAL<=set(staged))
        self.assertEqual(len(P.data(self.out/'base-materials/archives.list').splitlines()),256)
        self.assertIn('pacman --config',P.DRIVER);self.assertNotIn('--nodeps',P.DRIVER);self.assertNotIn('--noscriptlet',P.DRIVER)

    def test_missing_extra_or_substituted_supplement_refuses_before_output(self):
        for mutation in ('missing','extra','pin','duplicate_path'):
            inputs=copy.deepcopy(self.inputs);rows=inputs['supplemental_materials'];name=next(iter(rows))
            if mutation=='missing':rows.pop(name)
            elif mutation=='extra':rows['unexpected.pkg.tar.xz']=rows[name]
            elif mutation=='pin':rows[name]['sha256']='0'*64
            else:rows[name]['path']=self.inputs['base_materials']['rootfs.tar.gz']['path']
            e=self.executor()
            with self.subTest(mutation=mutation),mock.patch.object(self,'inputs',inputs),self.assertRaises(ValueError):self.build(e)
            self.assertFalse(e.calls);self.assertFalse(self.out.exists())

    def test_supplement_signature_failure_holds_before_seed(self):
        e=self.executor();e.bad_signature_step='verify-249'
        with self.assertRaises(ValueError):self.build(e)
        self.assertFalse(any(step=='seed-build'for step,_,_,_ in e.calls));self.assertFalse(e.images)
        report=P.decoded(P.data(self.out/'image-provisional.json'));self.assertEqual(report['status'],'HOLD')

    def test_final_base_inventory_cannot_omit_supplements(self):
        e=self.executor();e.base={name:version for name,version in e.base.items()if name not in P.SUPPLEMENTAL}
        with self.assertRaises(ValueError):self.build(e)
        report=P.decoded(P.data(self.out/'image-provisional.json'))
        self.assertEqual(report['status'],'HOLD');self.assertFalse(e.images)
        self.assertIn('inventory',report['failure']['message'])

    def test_supplement_profile_and_factory_provenance_are_mandatory(self):
        for mutation in ('profile','factory'):
            e=self.executor()
            with self.subTest(mutation=mutation):
                if mutation=='profile':
                    wrong=dict(self.inputs,bootstrap_profile=put(self.home/'wrong-profile.json',P.encoded(dict(MODEL_ONLY='wrong'))))
                    with mock.patch.object(self,'inputs',wrong),self.assertRaises(ValueError):self.build(e)
                else:
                    path=self.source/'scripts/ci/first-login-enrollment-native-source/profile.json';path.write_bytes(b'{}')
                    try:
                        with self.assertRaises(ValueError):self.build(e)
                    finally:path.write_bytes(self.factory_raw)
                self.assertFalse(e.calls);self.assertFalse(self.out.exists())

    def test_modeled372_needs_no_project_or_test_trust(self):
        e=self.executor('lifecycle');self.inputs['test_trust']=None;self.inputs['setup8']=None;self.inputs['cli03']=None
        result=self.build(e);self.assertEqual(len(result['packages']),372)
        self.assertFalse(any(name.startswith('cachy-asahi-')for name in result['packages']))

    def test_modeled374_requires_actual_cli_pair_adoption(self):
        result=self.build(self.executor('ui'));self.assertEqual(len(result['packages']),374)
        self.assertEqual(result['packages']['cachy-asahi-first-login'],'0.1.0-3')

    def v4(self,selected=False):
        body=b'MODEL CONTEXT V4 PROGRAM'
        put(self.source/'context.DATA',body);P.CONTEXT_PROGRAM_PINS[4]=P.pin(body)
        self.d.update(schema=4,kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4')
        self.d['programs']['context']=dict(member='context.DATA',**P.pin(body))
        self.c.update(schema=4,kind='DELEGATED_CURRENT_ONBOARDING_CONTEXT_V4',issuer='DELEGATED_CONTEXT_PROGRAM_V4',program_pin=P.pin(body))
        self.H.DELEGATION=self.d['kind'];self.H.CONTEXT=self.c['kind'];self.H.ISSUER=self.c['issuer']
        if not selected:return
        self.d['capability'].update(allow_pair_adoption=False,allow_selected_pair_adoption=True)
        cli=self.inputs['cli03'];now=int(time.time())
        fields={name:put(self.home/('selected-'+name+'.json'),P.encoded(dict(MODEL_ONLY=True,issued_epoch=now-1,expires_epoch=now+1000)))
                for name in ('producer_delegation','producer_context','completion','pair','root_component','root_test')}
        cli.update(Root_decision=fields['root_component'],Root_verification=fields['root_test'])
        pair=dict(kind=P.SELECTED_PRODUCT_KIND,selection_role='backend',archives=[cli['archive'],put(self.home/'selected-archive-B.pkg.tar.xz',P.reference(cli['archive']))],
                  signatures=[cli['signature'],put(self.home/'selected-signature-B.sig',b'MODEL DISTINCT SECOND SIGNATURE')],**fields)
        cli['pair_adoption']=pair
        def adopt(d,c,**args):
            self.assertEqual(args['selection_role'],'backend')
            self.assertEqual(args['archive_bodies'],[P.reference(r)for r in pair['archives']])
            self.assertEqual(args['signature_bodies'],[P.reference(r)for r in pair['signatures']])
            self.assertEqual(args['public_test_key_raw'],P.reference(self.inputs['test_trust']['public_key']))
            for field in ('producer_delegation','completion','pair','root_component','root_test'):
                self.assertEqual(args[field+'_raw'],P.reference(pair[field]))
            self.assertEqual(args['producer_context'],P.decoded(P.reference(pair['producer_context'])))
            names={'producer_delegation':'producer_delegation_pin','producer_context':'producer_context_pin','completion':'completion_pin',
                'pair':'pair_pin','root_component':'root_component_decision_pin','root_test':'root_test_decision_pin'}
            return dict(schema=4,kind='DELEGATED_CURRENT_ONBOARDING_SELECTED_PAIR_ADOPTION_V4',issuer=self.H.ISSUER,
                binding=c['binding'],producer_binding=dict(c['binding'],run='historical-MODEL'),component=dict(name=cli['name'],version=cli['version'],architecture=cli['arch']),
                nonce=d['nonce'],delegation_pin=c['delegation_pin'],selection_pin=P.pin(b'MODEL SELECTION'),
                archives=list(map(P.pin,args['archive_bodies'])),signatures=list(map(P.pin,args['signature_bodies'])),public_test_key_pin=P.pin(args['public_test_key_raw']),
                test_fingerprint=self.fprs['test'],trust_scope='TEST_ONLY',current_stage_gpg_required=True,Root_final_acceptance=None,
                independent_component_acceptance=False,hardware_acceptance=False,release_acceptance=False,
                **{target:P.pin(P.reference(pair[field]))for field,target in names.items()})
        self.H.adopt_selected_pair=mock.Mock(side_effect=adopt)
        self.H.adopt_pair=mock.Mock(side_effect=AssertionError('selected route must never call legacy adoption'))

    def test_v4_backend_and_same_run_ui_keep_separate_identity(self):
        self.v4();e=self.executor('ui');result=self.build(e)
        self.assertEqual(len(result['packages']),374);self.assertEqual(result['selected_pair_adoptions_v4'],[])

    def test_v4_selected_ui_replays_all_operands_and_verifies_both_signatures(self):
        self.v4(True);e=self.executor('ui');result=self.build(e)
        self.assertEqual(self.H.adopt_selected_pair.call_count,2);self.H.adopt_pair.assert_not_called()
        self.assertEqual(len(result['packages']),374)
        receipt=result['selected_pair_adoptions_v4'][0]
        self.assertTrue(receipt['adoption']['current_stage_gpg_required'])
        calls={step:argv for step,argv,_,_ in e.calls}
        self.assertEqual(len(receipt['current_stage_gpg_steps']),2)
        self.assertEqual([calls[step][-2:]for step in receipt['current_stage_gpg_steps']],
                         [[sig['path'],ar['path']]for sig,ar in zip(self.inputs['cli03']['pair_adoption']['signatures'],self.inputs['cli03']['pair_adoption']['archives'])])
        self.assertEqual(P.decoded(P.reference(self.inputs['cli03']['Root_decision']))['MODEL_ONLY'],True)

    def test_v4_selected_second_signature_expiry_holds_before_seed(self):
        self.v4(True);e=self.executor('ui');e.bad_signature_step='verify-selected-281-1'
        # 257 base + 23 official + Setup8 => selected backend is row281.
        with self.assertRaises(ValueError):self.build(e)
        self.assertTrue(any(step==e.bad_signature_step for step,_,_,_ in e.calls))
        self.assertFalse(any(step=='seed-build'for step,_,_,_ in e.calls));self.assertFalse(e.images)
        self.assertEqual(self.H.adopt_selected_pair.call_count,1)

    def test_v4_selected_root_expiry_after_current_gpg_holds_before_seed(self):
        self.v4(True);e=self.executor('ui');clock=[time.time()];original=e.run
        def run(step,argv,seconds,expected=0):
            result=original(step,argv,seconds,expected)
            if step.startswith('verify-selected-'):clock[0]+=1001
            return result
        e.run=run
        with mock.patch.object(P.time,'time',side_effect=lambda:clock[0]),self.assertRaises(ValueError):self.build(e)
        self.assertFalse(any(step=='seed-build'for step,_,_,_ in e.calls))
        self.assertEqual(self.H.adopt_selected_pair.call_count,1)
        report=P.decoded(P.data(self.out/'image-provisional.json'))
        self.assertIn('Root decision expiry',report['failure']['message'])

    def test_v4_selected_requires_capability_without_legacy_fallback(self):
        self.v4(True);self.d['capability']['allow_selected_pair_adoption']=False;e=self.executor('ui')
        with self.assertRaises(ValueError):self.build(e)
        self.assertFalse(e.calls);self.assertFalse(self.out.exists());self.H.adopt_pair.assert_not_called()

    def test_v4_selected_cannot_take_legacy_operand(self):
        self.v4(True);self.inputs['cli03']['pair_adoption'].pop('kind');e=self.executor('ui')
        with self.assertRaises(ValueError):self.build(e)
        self.assertFalse(e.calls);self.H.adopt_pair.assert_not_called()

    def test_v4_selected_expired_root_decision_refuses_before_any_command(self):
        self.v4(True);row=self.inputs['cli03'];ref=put(self.home/'expired-selected-component.json',P.encoded(dict(issued_epoch=1,expires_epoch=2)))
        row['Root_decision']=row['pair_adoption']['root_component']=ref;e=self.executor('ui')
        with self.assertRaises(ValueError):self.build(e)
        self.assertFalse(e.calls);self.assertFalse(self.out.exists())

    def test_v4_identity_cannot_be_mixed_with_v3_program(self):
        self.v4();self.c['issuer']='DELEGATED_CONTEXT_PROGRAM_V3';e=self.executor()
        with self.assertRaises(ValueError):self.build(e)
        self.assertFalse(e.calls);self.assertFalse(self.out.exists())

    def test_ui_old_cli02_refuses_before_output(self):
        e=self.executor('ui');self.inputs['cli03']['version']='0.1.0-2'
        with self.assertRaises(ValueError):self.build(e)
        self.assertFalse(self.out.exists());self.assertFalse(e.calls)

    def test_program_policy_context_and_actual_domain_mismatch_refuse(self):
        e=self.executor();e.facts['owner_domain']['limits']=dict(e.facts['owner_domain']['limits'],**{'memory.max':'max'})
        with self.assertRaises(ValueError):self.build(e)
        self.assertFalse(e.calls)

    def test_shared_global_endpoint_or_unbounded_storage_refuse(self):
        e=self.executor();e.facts['docker_endpoint']='unix:///var/run/docker.sock'
        with self.assertRaises(ValueError):self.build(e)
        e.facts['docker_endpoint']=self.policy['image_endpoint_template'].format(nonce=self.nonce);e.facts['storage']['kernel_enforced']=False
        with self.assertRaises(ValueError):self.build(e)

    def test_expired_or_bad_signature_is_not_positive(self):
        e=self.executor();e.bad_signature=True
        with self.assertRaises(ValueError):self.build(e)
        report=P.decoded(P.data(self.out/'image-provisional.json'));self.assertEqual(report['status'],'HOLD')
        self.assertIn('expired',report['failure']['message']);self.assertFalse(e.images)

    def test_first_executor_failure_preserved_after_cleanup(self):
        e=self.executor();e.fail_step='seed-build'
        with self.assertRaises(ValueError):self.build(e)
        report=P.decoded(P.data(self.out/'image-provisional.json'));self.assertEqual(report['status'],'HOLD')
        failed=[r for r in report['commands']if r['step']=='seed-build'];self.assertEqual(failed[0]['exit'],7)
        self.assertIn('natural',report['failure']['message'])

    def test_actor_security_mutation_refuses_and_cleanup_cannot_pass(self):
        e=self.executor();e.bad_inspect=lambda r:r['HostConfig'].update(Privileged=True)
        with self.assertRaises(ValueError):self.build(e)
        report=P.decoded(P.data(self.out/'image-provisional.json'));self.assertEqual(report['status'],'HOLD');self.assertTrue(report['cleanup']['errors'])

    def test_existing_private_namespace_not_deleted(self):
        e=self.executor();private=Path('/tmp')/('build-tools-test-current-image-'+self.nonce);private.mkdir(mode=0o700);marker=private/'FOREIGN';marker.write_bytes(b'do not remove')
        with self.assertRaises(ValueError):self.build(e)
        self.assertEqual(marker.read_bytes(),b'do not remove');self.assertFalse(e.calls)

    def test_uncertain_create_is_discovered_and_retired_without_replay(self):
        e=self.executor();e.fail_retirement_step='create-base'
        with self.assertRaises(ValueError):self.build(e)
        report=P.decoded(P.data(self.out/'image-provisional.json'))
        self.assertEqual(report['status'],'HOLD');self.assertFalse(e.containers);self.assertFalse(e.images)
        self.assertTrue(report['cleanup']['retired_containers'])
        self.assertEqual(sum(step=='create-base'for step,argv,seconds,expected in e.calls),1)

    def test_failed_live_actor_is_stopped_but_never_passes(self):
        e=self.executor();e.fail_retirement_step='start-base';e.live_failed_start=True
        with self.assertRaises(ValueError):self.build(e)
        report=P.decoded(P.data(self.out/'image-provisional.json'))
        self.assertEqual(report['status'],'HOLD');self.assertFalse(e.containers)
        self.assertTrue(any(row['kind']=='forced-stop'for row in report['cleanup']['errors']))

    def test_existing_image_namespace_is_never_collision_cleaned(self):
        e=self.executor();image='sha256:'+e.id(999)
        e.images[image]=dict(Id=image,Config={'Labels':{}},RepoTags=['FOREIGN'],RepoDigests=[])
        with self.assertRaises(ValueError):self.build(e)
        self.assertIn(image,e.images)
        self.assertFalse(any('remove-image'in step for step,argv,seconds,expected in e.calls))

    def test_current_setup8_identity_and_payload_cannot_be_substituted(self):
        e=self.executor();self.inputs['setup8']['name']='other-package'
        with self.assertRaises(ValueError):self.build(e)
        self.assertFalse(e.calls);self.assertFalse(self.out.exists())

    def test_changed_protected_observation_cannot_return_an_image_pass(self):
        e=self.executor();calls=[0]
        def observation(T):
            calls[0]+=1;return {'MODEL_state':calls[0]}
        with mock.patch.object(P,'protected_state',side_effect=observation):
            with self.assertRaises(ValueError):self.build(e)
        report=P.decoded(P.data(self.out/'image-provisional.json'))
        self.assertEqual(report['status'],'HOLD');self.assertTrue(report['cleanup_or_protected_failure'])

    def test_hook_failure_log_with_zero_exit_is_not_silently_accepted(self):
        e=self.executor();e.hook_failure=True
        with self.assertRaises(ValueError):self.build(e)
        report=P.decoded(P.data(self.out/'image-provisional.json'))
        self.assertEqual(report['status'],'HOLD');self.assertIn('hook/scriptlet',report['failure']['message'])

    def test_hook_failure_only_on_stderr_with_zero_exit_stays_hold(self):
        e=self.executor();original=e.run
        def separated(step,argv,seconds,expected=0):
            result=original(step,argv,seconds,expected)
            if step=='start-base':
                result['stderr']=b'error: command failed to execute correctly (MODEL stderr hook)\n'
                result['receipt']['stderr_pin']=P.pin(result['stderr'])
            return result
        e.run=separated
        with self.assertRaises(ValueError):self.build(e)
        report=P.decoded(P.data(self.out/'image-provisional.json'))
        self.assertEqual(report['status'],'HOLD');self.assertIn('hook/scriptlet',report['failure']['message'])
        row=next(row for row in report['commands'] if row['step']=='start-base')
        self.assertNotEqual(row['stderr_pin'],P.pin(b''))

    def test_driver_no_dependency_hook_scriptlet_or_network_bypass(self):
        for text in ('--nodeps','--nocheck','--noscriptlet','HookDir','pacman -S','curl','wget'):self.assertNotIn(text,P.DRIVER)
        self.assertIn('LocalFileSigLevel = Required',P.DRIVER);self.assertIn('pacman -Qkk',P.DRIVER)

    def test_whole_body_tamper_and_alias_refuse(self):
        row=dict(self.inputs['setup8']['archive']);row['sha256']='0'*64
        with self.assertRaises(ValueError):P.whole(row)
        path=self.home/'alias';path.symlink_to(self.inputs['setup8']['archive']['path'])
        with self.assertRaises(ValueError):P.whole(dict(row,path=str(path)))

    def test_nonfinite_or_duplicate_policy_json_refuses(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1e9999}'):
            with self.assertRaises(ValueError):P.decoded(raw)

    def test_strict_signature_forbidden_status_and_wrong_primary(self):
        raw=('[GNUPG:] GOODSIG MODEL\n[GNUPG:] VALIDSIG '+self.fprs['test']+' 0 '+self.fprs['test']+'\n').encode()
        P.signature(raw,self.fprs['test'])
        for bad in (raw+b'[GNUPG:] REVKEYSIG MODEL\n',raw.replace(self.fprs['test'].encode(),b'C'*40)):
            with self.assertRaises(ValueError):P.signature(bad,self.fprs['test'])


class SeparatedRetirementControls(unittest.TestCase):
    """Execute only the held cleanup DATA logic with an inert command model."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='build-tools-test-MODEL-adapter-')
        self.addCleanup(self.temp.cleanup);self.private=Path(self.temp.name)
        self.logs=tempfile.TemporaryDirectory(prefix='image-adapter-MODEL-logs-')
        self.addCleanup(self.logs.cleanup)
        self.homes=[str(self.private/name)for name in ('official','test')]
        for home in self.homes:Path(home).mkdir(mode=0o700)
        self.held=P.tools(HERE.parents[4]);self.mode=None;self.calls=[]
        parent=self
        class InertExecutor:
            def run(self,step,argv,seconds,expected=0):
                parent.calls.append((step,list(argv),seconds,expected))
                no_agent=argv[0]=='/usr/bin/gpg-connect-agent'
                stdout=b'';stderr=P.NO_AGENT_STDERR_V3 if no_agent else b'';code=2 if no_agent else 0
                if no_agent:
                    if parent.mode=='wrong_exit':code=7
                    elif parent.mode=='agent_present':code=0;stdout=b'OK MODEL agent is running\n';stderr=b''
                    elif parent.mode=='unknown_stderr':stderr=b'MODEL unknown error\n'
                    elif parent.mode=='stdout_substitution':stdout=stderr;stderr=b''
                row=dict(step=step,argv=list(argv),expected=expected,exit=code,output_pin=P.pin(stdout),stderr_pin=P.pin(stderr),supervision=supervision(code),MODEL_ONLY=True)
                result=dict(stdout=stdout,stderr=stderr,receipt=row)
                if no_agent:
                    if parent.mode=='missing_pin':row.pop('stderr_pin')
                    elif parent.mode=='missing_stderr':result.pop('stderr')
                    elif parent.mode=='wrong_pin':row['stderr_pin']=dict(bytes=len(stderr),sha256='0'*64)
                    elif parent.mode=='stderr_substitution':result['stderr']=b'MODEL substituted bytes\n'
                    elif parent.mode=='wrong_supervision_exit':row['supervision']['exit']=0
                return result
        d=dict(capability=dict(command_rows=32,max_command_seconds=60,total_seconds=180),expires_epoch=int(time.time())+180,MODEL_ONLY=True)
        self.build=P.Build(InertExecutor(),d,{}, {},Path(self.logs.name))
    def retire(self):return P.retire_private_separated_v3(self.held,self.build,self.private,self.homes)
    def test_expected_nonzero_stderr_projects_only_the_exact_held_callback_token(self):
        result=self.retire()
        self.assertFalse(result['failures']);self.assertTrue(result['no_sockets']);self.assertTrue(result['private_directory_absent'])
        rows=[row for row in self.build.rows if row['argv'][0]=='/usr/bin/gpg-connect-agent']
        self.assertEqual(len(rows),2)
        for row in rows:
            self.assertEqual(row['expected'],2);self.assertEqual(row['exit'],2)
            self.assertEqual(row['supervision']['exit'],2)
            self.assertEqual(row['output_pin'],P.pin(b''));self.assertEqual(row['stderr_pin'],P.pin(P.NO_AGENT_STDERR_V3))
            self.assertEqual((Path(self.logs.name)/(row['step']+'.log')).read_bytes(),b'')
            self.assertEqual((Path(self.logs.name)/(row['step']+'.stderr.log')).read_bytes(),P.NO_AGENT_STDERR_V3)
            adapter=row['held_tools_adapter_v3'];self.assertEqual(adapter['source_stream'],'stderr');self.assertFalse(adapter['stdout_relabelled'])
            self.assertEqual(adapter['held_callback_token_pin'],row['stderr_pin'])
    def test_unknown_stderr_wrong_exit_missing_pin_and_stream_substitution_refuse(self):
        for mode in ('wrong_exit','missing_pin','missing_stderr','wrong_pin','stderr_substitution','unknown_stderr','stdout_substitution','wrong_supervision_exit'):
            with self.subTest(mode=mode):
                self.mode=mode
                # Recreate only inert private homes after the held cleanup removes them.
                self.private.mkdir(mode=0o700,exist_ok=True)
                for home in self.homes:Path(home).mkdir(mode=0o700,exist_ok=True)
                self.build.rows.clear();self.build.stderr.clear()
                result=self.retire()
                self.assertTrue(result['failures']);self.assertFalse(result['no_sockets'])
                self.assertFalse(any('held_tools_adapter_v3'in row for row in self.build.rows))
    def test_agent_present_success_exit_is_never_no_agent_evidence(self):
        self.mode='agent_present';result=self.retire()
        self.assertTrue(result['failures']);self.assertFalse(result['no_sockets'])
        rows=[row for row in self.build.rows if row['argv'][0]=='/usr/bin/gpg-connect-agent']
        self.assertEqual(len(rows),2);self.assertTrue(all(row['exit']==0 and row['expected']==2 for row in rows))
    def test_normal_stdout_parsing_does_not_receive_stderr(self):
        self.build.e.run=lambda step,argv,seconds,expected=0:dict(stdout=b'{"MODEL":true}\n',stderr=b'MODEL diagnostic only\n',receipt=dict(step=step,argv=argv,expected=expected,exit=0,output_pin=P.pin(b'{"MODEL":true}\n'),stderr_pin=P.pin(b'MODEL diagnostic only\n'),supervision=supervision(),MODEL_ONLY=True))
        raw=self.build.run('stdout-json',['/usr/bin/docker','--host=unix:///MODEL/private.sock','info'],15)
        self.assertEqual(P.decoded(raw),{'MODEL':True});self.assertEqual(self.build.stderr['stdout-json'],b'MODEL diagnostic only\n')


if __name__=='__main__':unittest.main()
