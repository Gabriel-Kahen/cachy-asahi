# SPDX-License-Identifier: MIT
"""MODEL integration, never native qualification or privacy acceptance.

Real owner/route/Runner/build/compare/GPG-receipt/exit and real retention selector,
publisher and encoder run. Source/context authentication, Setup8 authenticity,
image construction and every executable result are explicit fictional boundaries.
No executable, package, key, daemon or lease is invoked. Retention's historical
81d66 request basis is deliberately outside this model.
"""
import argparse
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
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
        raise RuntimeError('MODEL forbids operational boundary '+event)
sys.addaudithook(fence)
parser=argparse.ArgumentParser()
parser.add_argument('--retention-source-root',type=Path,required=True)
parser.add_argument('--owner-sha256',required=True)
ARGS,REST=parser.parse_known_args()
HERE=Path(__file__).resolve().parent;AUTHOR=HERE.parents[4]
FAMILY='scripts/ci/first-login-enrollment-native-source'
PURE=ARGS.retention_source_root.resolve()
PINS={
 FAMILY+'/payload/native/test_retention_delegated_v4.py':'cf89400b59145a109ae541eddccfb5cb0d94788677e95fe52034e96344f2a05b',
 FAMILY+'/payload/native/retention_delegated_v4.py':'677bd9c6c34e63352da017f4191e64d60a3e53f7cec25de3d6d861388265ba3a',
 FAMILY+'/payload/native/retention_current_v3.py':'738360745901f1938be1e6a893ce45131c3f1f825421991522cfee3c66ed8c6a',
 'scripts/ci/log_evidence.py':'a25f0089759c12afae3eea23bab8b22fa05cf5bbaa9eddc1611ce78b0405f8f5'}
def digest(body):return hashlib.sha256(body).hexdigest()
for member,sha in PINS.items():
    if digest((PURE/member).read_bytes())!=sha:raise ValueError('reviewed immutable pure body changed: '+member)
def module(path,name,sha):
    body=path.read_bytes()
    if digest(body)!=sha:raise ValueError('whole reviewed integration program changed: '+name)
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;exec(compile(body,str(path),'exec'),value.__dict__);return value
O=module(HERE/'owner_delegated_v3.py','model_actual_owner',ARGS.owner_sha256)
Q=module(AUTHOR/FAMILY/'successor_v4/route.py','model_actual_route','78be10c869556ecc0cd07e7ddc0b94016c3fae0cc02b1470420861808289cdee')
F=module(PURE/FAMILY/'payload/native/test_retention_delegated_v4.py','model_retention_fixture',PINS[FAMILY+'/payload/native/test_retention_delegated_v4.py'])
V,R,E=F.V,F.R,F.E
N,T,A,PROFILE=O.modules(AUTHOR)


class Model:
    def __init__(self,root,*,makepkg_log=False,fail_attach=False,mutate=None):
        class DataOnly(F.Fixture):
            def builds(self):pass
        self.f=DataOnly(root,'backend');f=self.f
        # Discard all handwritten stage skeletons. Actual route must create it.
        shutil.rmtree(f.output)
        self.mutate=mutate
        self.makepkg_log,self.fail_attach=makepkg_log,fail_attach
        self.sessions=[];self.by_cid={};self.present=set();self.calls=[]
        f.profile=copy.deepcopy(PROFILE)
        for kind in ('enrollment','first-login'):
            recipe=f.profile['packages'][kind]
            for name,row in recipe['files'].items():
                body=(AUTHOR/recipe['path']/name).read_bytes()
                if O.pin(body)!={k:row[k]for k in ('bytes','sha256')}:raise ValueError('frozen recipe drift')
                f.write(f.source/recipe['path']/name,body)
        entry=(AUTHOR/'scripts/build/container-entry.sh').read_bytes();f.write(f.source/'scripts/build/container-entry.sh',entry)
        f.write(f.source/(FAMILY+'/successor_v2/profile.json'),O.encoded(PROFILE))
        required=['python','gnupg','pacman','coreutils','libarchive','bubblewrap','util-linux','fish','zsh']
        packages={'fiction%03d'%i:'1-1'for i in range(340)}|{k:'1-1'for k in required}|{'cachy-asahi-setup':'0.3.0-1'}
        self.inventory=''.join(k+' '+v+'\n'for k,v in sorted(packages.items())).encode()
        f.image.update(operation=O.OP,packages=packages,inventory_pin=f.write(f.image_root/'facts-backend/inventory.lock',self.inventory))
        f.image['cleanup']['retained_target_image_unqualified']=f.image['image_id']
        f.facts.update(docker_endpoint='unix:///tmp/MODEL-private-daemon.sock',uid=os.getuid(),gid=os.getgid())
        self.facts=f.facts;self.deadline=time.monotonic()+600
        f.d.update(schema=4,kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4',issuer='Root',approved=True,
            scope='CURRENT_PRIVATE_STAGE_ONLY',binding=dict(f.binding,run=None,job=None),expires_epoch=4102444800,image_ids=dict(backend=None,ui=None,lifecycle=None),
            capability=dict(operation=O.OP,stage='backend',total_seconds=600,max_command_seconds=180,command_rows=512,builder_cpus=4,builder_memory_bytes=4*1024**3,builder_pids=512),**O.FINAL)
        f.d['programs']={k:dict(member='MODEL/'+k+'.py',**O.pin(k.encode()))for k in ('context','owner','image','route','retention','inputs_assembler','build_validator')}
        f.c.update(kind='DELEGATED_CURRENT_ONBOARDING_CONTEXT_V4',operation=O.OP,source_root=str(f.source),
                   policy_pin=f.d['policy']|{},**O.FINAL)
        f.c['policy_pin']={k:f.d['policy'][k]for k in ('bytes','sha256')}
        f.c['delegation_pin']=O.pin(O.encoded(f.d));f.image['delegation_pin']=f.c['delegation_pin']
        f.write(f.image_root/'image-provisional.json',O.encoded(f.image))
        self.H=SimpleNamespace(descriptor=lambda row:{k:row[k]for k in ('bytes','sha256')})
        policy=O.decode((f.source/'policy.json').read_bytes())
        protected=f.source/'MODEL-protected';protected.mkdir()
        self.plan=dict(d=f.d,c=f.c,policy=policy,H=self.H,image=dict(id=f.image['image_id'],packages=packages,inventory_pin=f.image['inventory_pin']),
            native=N,tools=T,alpm=A,profile=f.profile,inventory=self.inventory,source=f.source,
            protected_fn=lambda tools:{str(protected):tools.snapshot_receipt(protected)})
        self.inputs=dict(image_inputs={},stage_inputs=dict(f.inputs['stage_inputs'],source_date_epoch=17,schema=3,kind='DELEGATED_CURRENT_PRIVATE_INPUTS_V3'))
        self.prepared_image=root/'prepared-image';shutil.move(f.image_root,self.prepared_image)
        f.output.parent.chmod(0o700)

    def state(self,intent,cid):
        return dict(Id=cid,Name='/'+intent['name'],Image=intent['image'],Config=dict(User=intent['user'],Entrypoint=intent['entrypoint'],Cmd=intent['cmd'],Labels=intent['labels']),
            HostConfig=dict(NetworkMode='none',Privileged=False,ReadonlyRootfs=intent['readonly'],CapDrop=['ALL'],CapAdd=intent['capadd'],
                SecurityOpt=['no-new-privileges'],Devices=[],DeviceRequests=None,VolumesFrom=None,Tmpfs=intent['tmpfs'],Memory=4*1024**3,
                MemorySwap=4*1024**3,NanoCpus=4*10**9,PidsLimit=512,Init=False,AutoRemove=False,PidMode='',UTSMode='',IpcMode='private'),
            Mounts=[dict(Type='bind',Destination=d,Source=s,RW=rw)for d,s,rw in intent['mounts']],State=dict(Running=False,ExitCode=0,OOMKilled=False))

    def artifacts(self,kind,label):
        f=self.f;slot=f.output/'builds'/(kind+'-'+label);artifacts=slot/'artifacts';recipe=f.profile['packages'][kind]
        for name in ('generated.SRCINFO','environment.txt','config.sha256','makepkg.conf','pacman.conf'):
            f.write(artifacts/name,b'MODEL inert static environment\n')
        f.write(artifacts/'packages.lock',self.inventory)
        f.write(artifacts/recipe['archive'],('MODEL inert archive '+kind).encode())
        if self.makepkg_log:f.write(artifacts/(recipe['name']+'-makepkg.log'),b'MODEL actual-shaped makepkg log\n')

    def run(self,step,argv,seconds,*,expected=0):
        self.calls.append((step,argv));f=self.f;err=b''
        if step=='private-test-primary':out=('fpr:::::::::'+f.fingerprint+':\n').encode()
        elif step.startswith('private-signature-'):out=f.status()
        elif step.startswith('no-agent-private-'):
            if expected!=2:raise ValueError('MODEL actual no-agent exit is2')
            out=b'';err=b'gpg-connect-agent: no gpg-agent running in this session\n'
        elif step in ('private-test-import','private-test-ownertrust')or step.startswith('private-retire-'):out=b''
        elif step=='private-daemon':out=O.encoded(dict(ID=f.facts['engine_id'],OSType='linux',Architecture='aarch64',CgroupVersion='2'))
        elif step=='private-image':out=O.encoded([dict(Id=f.image['image_id'],Architecture='arm64',Os='linux',Config=dict(Labels={'org.cachy-asahi.current-image.nonce':f.nonce}))])
        elif step.endswith('-fresh')or step.endswith('-query')or '-after-'in step:
            name=next(a[len('name=^/'):-1]for a in argv if a.startswith('name=^/'))
            cid=next((cid for cid,row in self.by_cid.items()if row['name']==name and cid in self.present),None)
            out=((cid+' '+name+'\n').encode()if cid else b'')
        elif step.endswith('-create'):
            row=self.sessions[-1].actors[-1]['intent'];cid='%064x'%(len(self.by_cid)+1);self.by_cid[cid]=copy.deepcopy(row);self.present.add(cid);out=(cid+'\n').encode()
        elif step.endswith(('-created','-terminal','-inspect')):out=O.encoded([self.state(self.by_cid[argv[-1]],argv[-1])])
        elif step.endswith('-remove'):self.present.discard(argv[-1]);out=(argv[-1]+'\n').encode()
        elif step=='private-probe-attach':out=self.inventory
        elif step.startswith('build-')and step.endswith('-attach'):
            if self.fail_attach:raise ValueError('MODEL forced build failure')
            label=step[-8];kind=step[len('build-'):-len('-a-attach')];self.artifacts(kind,label)
            out=b'==> Starting check()...\n'
            if kind=='enrollment':out+=json.dumps(f.profile['enrollment_check_report'],sort_keys=True).encode()+b'\n'
            else:out+=b''.join(('Ran %d tests in 0.1s\nOK\n'%n).encode()for n in f.profile['packages'][kind]['check_counts'])
            err=b'MODEL complete separate build stderr\n'
        elif step.startswith('validate-'):
            label=step[-1];kind=step[len('validate-'):-2];recipe=f.profile['packages'][kind];slot=f.output/'builds'/(kind+'-'+label)
            archive=(slot/'artifacts'/recipe['archive']).read_bytes()
            validation=dict(errors=[],artifacts=[dict(artifact=recipe['archive'],sha256=O.pin(archive)['sha256'],errors=[])])
            f.write(slot/'validation.json',O.encoded(validation))
            out=O.encoded(dict(status='PASS_DELEGATED_BUILD_STATIC_VALIDATION',validation_pin=O.pin(O.encoded(validation)),
                recipe_inputs={k:v['sha256']for k,v in recipe['files'].items()},recipe_metadata={'MODEL':'static-validation-executor'},
                entry_script_sha256=O.pin((f.source/'scripts/build/container-entry.sh').read_bytes())['sha256'],artifacts={recipe['archive']:O.pin(archive)['sha256']}))
        elif step.startswith('current-')and step.endswith('-compare'):
            kind=step[len('current-'):-len('-compare')]
            out=O.encoded(dict(status='contents-reproduced',errors=[],packages={f.profile['packages'][kind]['archive']:dict(
                installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)}))
        else:raise AssertionError('unexpected MODEL executable result '+step)
        # These are the modeled call's actual operands/outcome, never native facts.
        receipt=dict(step=step,argv=argv,expected=expected,exit=expected,timeout_seconds=seconds,supervision_cap_seconds=seconds,
            output_pin=O.pin(out),stderr_pin=O.pin(err),supervision=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',
            output_complete=True,timeout=False,signals=[],error=None,exit=expected,seconds=.01,passed=expected==0))
        return dict(stdout=out,stderr=err,receipt=receipt)

    def execute(self):
        f=self.f;wrapper=f.output.parent
        class Validator:
            def validate_owner_inputs_v3(inner,**kwargs):
                if kwargs['inputs']is not self.inputs or set(kwargs['inputs'])!={'image_inputs','stage_inputs'}:raise AssertionError('exact canonical inner object')
                if set(kwargs['inputs']['stage_inputs'])!={'schema','kind','source_date_epoch','setup8','products'}:raise AssertionError('closed inner stage schema')
                return dict(valid=True,required_refs=f.refs)
            def stage_inputs(inner,value):return value['stage_inputs']
        class Image:
            def build_stage(inner,**kwargs):
                if kwargs['inputs']is not self.inputs['image_inputs']or kwargs['context']is not f.c:raise AssertionError('unchanged image/context identity')
                shutil.copytree(self.prepared_image,kwargs['output']);return f.image
        def route(**kwargs):
            result=Q.run_registered(**kwargs)
            if self.mutate=='stdout':(f.output/'commands/build-enrollment-a-attach.stdout').write_bytes(b'MODEL CHANGED STDOUT')
            if self.mutate=='stderr':(f.output/'commands/build-enrollment-a-attach.stderr').write_bytes(b'MODEL CHANGED STDERR')
            if self.mutate=='index':
                path=f.output/'commands/commands.json';path.write_bytes(O.encoded(O.decode(path.read_bytes())[:-1]))
            return result
        modules={'inputs_assembler':Validator(),'image':Image(),'route':SimpleNamespace(run_registered=route),'retention':V,'build_validator':SimpleNamespace()}
        def loader(source,row,name):return modules[next(k for k in modules if row==f.d['programs'][k])]
        def opened(**kwargs):
            session=O.Session(self.plan,f.source,f.output,self.inputs['stage_inputs'],f.image,self);self.sessions.append(session);return session
        def setup(session):
            session.verify('setup8',f.source/'archive.data',f.source/'signature.data')
        with patch.object(O,'source_request',return_value=(f.d,f.c,self.plan['policy'],self.H)),patch.object(O,'load',side_effect=loader), \
             patch.object(O,'open_delegated_session',side_effect=opened),patch.object(O.Session,'setup',new=setup), \
             patch.object(O.os,'uname',return_value=SimpleNamespace(machine='aarch64')), \
             patch.object(V,'request',return_value=(R,E.bundle,f.refs)):
            return O.run_owned_current_v3(delegation_raw=O.encoded(f.d),delegation_sha256=O.pin(O.encoded(f.d))['sha256'],context=f.c,
                source_root=f.source,inputs=self.inputs,executor=self,output=wrapper,public_output=f.destination)


class Controls(unittest.TestCase):
    def model(self,**options):
        temp=tempfile.TemporaryDirectory(prefix='MODEL_PRIVATE_integration-');self.addCleanup(temp.cleanup)
        return Model(Path(temp.name),**options)
    def test_real_callbacks_generate_evidence_consumed_by_real_retainer(self):
        model=self.model();result=model.execute();f=model.f
        self.assertTrue(result['completed']);self.assertIsNone(result['Root_final_acceptance'])
        report=O.decode((f.output/'route.json').read_bytes());session=model.sessions[0]
        self.assertEqual(report['commands'],session.records)
        self.assertEqual(O.decode((f.output/'commands/commands.json').read_bytes()),session.records)
        self.assertEqual(len(session.actors),5);self.assertFalse(model.present)
        self.assertEqual(session.cleanup['status'],'PASS_DELEGATED_CURRENT_STAGE_RETIREMENT')
        noagent=next(row for row in report['commands']if row['step']=='no-agent-private-0')
        diagnostic=b'gpg-connect-agent: no gpg-agent running in this session\n'
        self.assertEqual(noagent['expected'],2);self.assertEqual(noagent['executor_receipt']['exit'],2)
        self.assertIs(noagent['supervision']['passed'],False);self.assertIs(noagent['executor_receipt']['supervision']['passed'],False)
        self.assertEqual(noagent['timeout_seconds'],noagent['executor_receipt']['timeout_seconds'])
        self.assertEqual(noagent['supervision_cap_seconds'],noagent['executor_receipt']['supervision_cap_seconds'])
        self.assertEqual(noagent['stderr_pin'],O.pin(diagnostic));self.assertEqual(session.runner.stderr_outputs[noagent['step']],diagnostic)
        public=f.destination/'delegated-backend-public-v4'
        self.assertTrue((public/'retention-manifest.json').is_file())
        self.assertEqual((public/'streams/stage/build-enrollment-a-attach.stderr').read_bytes(),b'MODEL complete separate build stderr\n')
        capsule=f.destination/'delegated-backend-public-v4.tar.gz';self.assertEqual(O.pin(capsule.read_bytes()),result['retention']['capsule_pin'])
        with tarfile.open(capsule,'r:gz')as archive:
            name=next(m.name for m in archive.getmembers()if m.name.endswith('streams/stage/no-agent-private-0.stderr'))
            self.assertEqual(archive.extractfile(name).read(),diagnostic)
        # Known 4da93bf3 privacy defect, characterized rather than called private:
        # the original image inventory path survives the public projection.
        projected=(public/'route.public.json').read_bytes()
        self.assertEqual(R.decode(projected)['image']['inventory_pin']['path'],f.image['inventory_pin']['path'])
        self.assertIn(str(f.image_root).encode(),projected)
    def test_realistic_makepkg_log_is_current_retainer_hold(self):
        model=self.model(makepkg_log=True)
        with self.assertRaisesRegex(ValueError,'complete exact build output'):model.execute()
        self.assertFalse((model.f.output.parent/'completion.json').exists())
        self.assertFalse(O.decode((model.f.output.parent/'failure.json').read_bytes())['completed'])
    def test_executable_failure_is_retired_and_never_published_complete(self):
        model=self.model(fail_attach=True)
        with self.assertRaises(ValueError):model.execute()
        self.assertFalse(model.present);self.assertFalse((model.f.output.parent/'completion.json').exists())
        self.assertFalse((model.f.destination/'delegated-backend-public-v4/retention-manifest.json').exists())
    def test_actual_route_stream_and_aggregate_index_drift_hold_before_retention(self):
        for mutation in ('stdout','stderr','index'):
            with self.subTest(mutation=mutation):
                model=self.model(mutate=mutation)
                with self.assertRaises(ValueError):model.execute()
                self.assertFalse((model.f.output.parent/'completion.json').exists())
                self.assertFalse((model.f.destination/'delegated-backend-public-v4/retention-manifest.json').exists())


if __name__=='__main__':unittest.main(argv=[sys.argv[0],*REST])
