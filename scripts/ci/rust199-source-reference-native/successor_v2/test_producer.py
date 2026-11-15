# SPDX-License-Identifier: MIT
"""FENCED modeled controller execution; no real Root qualification or actors."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('rust_volume_producer_DATA',HERE/'payload/hosted/producer.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
V=P.V
IMAGE='sha256:'+'d'*64  # FENCED token, not an image qualification.


def receipt(owner):
    return dict(schema=1,status='INITIALIZED_EMPTY_WORK_VOLUME',binding=owner,
                before=dict(device=13,inode=17,uid=0,gid=0,mode=0o755),
                after=dict(device=13,inode=17,uid=1001,gid=1001,mode=0o700),limits=V.LIMITS,
                capabilities='CHOWN_ONLY_CHMOD_BEFORE_CHOWN',recursive=False)


def natural():
    return dict(natural_exit=True,forced_cleanup=False,group_absent=True,retirement='REAPED',ownership_lost=False,
                leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,exit=0)


class Model:
    """Only dictionary transitions and DATA files; never invokes any command."""
    def __init__(self,root,work,mutation=None):
        self.root=root;self.work=work;self.mutation=mutation;self.events=[];self.containers={};self.volumes={}
        self.deadline=time.monotonic()+19800;self.on_tick=None;self.cleaning=False;self.cancelled=[False];self.owned=self
        self.initialized=False;self.prepared=False
    def run(self,argv,**kwargs):
        assert argv[:len(P.DOCKER)]==P.DOCKER and argv[len(P.DOCKER)]=='cp'
        self.events.append(argv[len(P.DOCKER):])
        kwargs['stdout'].write(b'FENCED EXPORT DATA ONLY');kwargs['lifecycle'].update(natural())
        if self.mutation=='forced-export':kwargs['lifecycle']['forced_cleanup']=True
        return subprocess.CompletedProcess(argv,0)
    def actor(self,argv):
        def option(prefix):return next(x[len(prefix):] for x in argv if x.startswith(prefix))
        name=argv[argv.index('--name')+1];labels={argv[n+1].split('=',1)[0]:argv[n+1].split('=',1)[1] for n,x in enumerate(argv) if x=='--label'}
        init=name.endswith('-init');mounts=[];real=[]
        for n,item in enumerate(argv):
            if item!='--mount':continue
            parts={x.split('=',1)[0]:(x.split('=',1)[1] if '=' in x else True) for x in argv[n+1].split(',')}
            row=dict(Type=parts['type'],Source=parts['src'],Target=parts['dst'],ReadOnly=parts.get('readonly',False))
            if row['Type']=='volume':
                row['VolumeOptions']={'NoCopy':parts.get('volume-nocopy',False)}
                if 'volume-subpath' in parts:row['VolumeOptions']['Subpath']=parts['volume-subpath']
                actual=dict(Type='volume',Name=row['Source'],Driver='local',Source=str(self.work/'FENCED-volume'/parts.get('volume-subpath','')))
            else:actual=dict(Type='bind',Source=row['Source'])
            actual.update(Destination=row['Target'],RW=not row['ReadOnly'],Propagation='');mounts.append(row);real.append(actual)
        host=dict(ReadonlyRootfs='--read-only' in argv,NetworkMode=option('--network='),CapDrop=['ALL'],CapAdd=['CHOWN'] if '--cap-add=CHOWN' in argv else [],SecurityOpt=['no-new-privileges'],Privileged=False,
                  UsernsMode='',PidMode='',IpcMode='private',CgroupnsMode='private',Memory=128*1024**2 if init else 8*1024**3,MemorySwap=128*1024**2 if init else 8*1024**3,
                  NanoCpus=2000000000,PidsLimit=32 if init else 512,Init=True,Mounts=mounts,RestartPolicy={'Name':'no'},LogConfig={'Type':'none','Config':{}},
                  Ulimits=[dict(Name='nofile',Soft=1024,Hard=1024),dict(Name='core',Soft=0,Hard=0)])
        host['Tmpfs']={x[len('--tmpfs='):].split(':',1)[0]:x.split(':',1)[1] for x in argv if x.startswith('--tmpfs=')}
        entry=argv.index('--entrypoint=/usr/bin/python');config=dict(User=option('--user='),Labels=labels,Hostname='rust199-native',WorkingDir=option('--workdir='),Entrypoint=['/usr/bin/python'],Cmd=argv[entry+2:],Env=[argv[n+1] for n,x in enumerate(argv) if x=='--env'])
        state=dict(Status='created',Running=False,ExitCode=0,OOMKilled=False,Restarting=False,Error='',Pid=0)
        row=dict(Name='/'+name,Id=hashlib.sha256(name.encode()).hexdigest(),Image=IMAGE,Config=config,HostConfig=host,Mounts=real,State=state)
        if self.mutation=='foreign' and name.endswith('-prepare'):row['Config']['Labels']['cachy-asahi.token']='FOREIGN'
        if self.mutation=='mount' and name.endswith('-prepare'):row['HostConfig']['Mounts'][0]['VolumeOptions']={}
        if self.mutation=='cap' and init:row['HostConfig']['CapAdd'].append('FOWNER')
        if self.mutation=='main-root' and name.endswith('-makepkg'):row['HostConfig']['Mounts'][0]['VolumeOptions'].pop('NoCopy')
        if self.mutation=='main-alias' and name.endswith('-makepkg'):row['HostConfig']['Mounts'][-1]['VolumeOptions'].pop('NoCopy')
        return name,row
    def __call__(self,argv,timeout=60,check=True):
        assert argv[:len(P.DOCKER)]==P.DOCKER
        a=argv[len(P.DOCKER):];self.events.append(a);body=b''
        if a[:2]==['container','ls']:body='\n'.join(self.containers).encode()
        elif a[:2]==['volume','ls']:body='\n'.join(self.volumes).encode()
        elif a[:2]==['image','inspect']:body=P.encode([dict(Id=IMAGE,Os='linux',Architecture='arm64',Config={})])
        elif a[:2]==['volume','create']:
            name=a[-1];labels={a[n+1].split('=',1)[0]:a[n+1].split('=',1)[1] for n,x in enumerate(a) if x=='--label'}
            self.volumes[name]=dict(Name=name,Driver='local',Options={},Labels=labels,Mountpoint=str(self.work/'FENCED-volume'))
        elif a[:2]==['volume','inspect']:body=P.encode([self.volumes[a[-1]]])
        elif a[0]=='create':
            name,row=self.actor(a);self.containers[name]=row
            if name.endswith('-prepare') and self.initialized:raise AssertionError('prepare created after final initialization')
            if name.endswith('-makepkg') and not self.prepared:raise AssertionError('main before prepared stage0')
        elif a[:2]==['container','inspect']:body=P.encode([self.containers[a[-1]]])
        elif a[:2]==['start','--attach']:
            name=a[-1];row=self.containers[name]
            if name.endswith('-init'):
                assert any(n.endswith('-prepare') for n in self.containers)
                owner=json.loads(row['Config']['Cmd'][-1]);value=receipt(owner)
                if self.mutation=='owner':value['after']['uid']=0
                if self.mutation=='inode':value['after']['inode']+=1
                body=P.encode(value);self.initialized=True
                if self.mutation=='container-id':row['Id']='e'*64
            elif name.endswith('-prepare'):
                assert self.initialized
                assert (self.work/'rust-build/inputs/volume-initialization.json').is_file()
                self.prepared=True
            else:assert self.initialized and self.prepared
            row['State']['Status']='exited'
            if self.mutation in ('live-failure','replacement-failure','replacement-after-stop') and name.endswith('-prepare'):
                if self.mutation=='replacement-failure':row['Id']='f'*64
                row['State'].update(Status='running',Running=True,Pid=1234)
                raise ValueError('FENCED actor failure requiring force')
        elif a[0]=='stop':
            self.containers[a[-1]]['State'].update(Status='exited',Running=False,Pid=0)
            if self.mutation=='replacement-after-stop':self.containers[a[-1]]['Id']='f'*64
        elif a[:2]==['container','rm']:del self.containers[a[-1]]
        elif a[:2]==['volume','rm']:del self.volumes[a[-1]]
        else:raise AssertionError('Unexpected modeled DATA transition '+str(a))
        return subprocess.CompletedProcess(argv,0,body,b'')


class Controls(unittest.TestCase):
    def modeled(self,mutation=None):
        with tempfile.TemporaryDirectory(prefix='FENCED-RustVolume-DATA-') as temporary:
            base=Path(temporary);root=base/'source';root.mkdir();work=base/'work';work.mkdir()
            body=b'FENCED NOT A SOURCE MAP';(root/'source-map.json').write_bytes(body)
            (work/'daemon.json').write_bytes(P.encode(dict(info={'DockerRootDir':str(work)})))
            materials=[]
            for n in range(5):
                path=base/f'FENCED-{n}.tar.xz';path.write_bytes(b'FENCED NO ARCHIVE')
                materials.append(dict(name=path.name,local_path=str(path),transport='LOCAL_READONLY',**P.pin(path,100)))
            a=dict(status='FENCED_MODEL_NOT_ROOT_ADMITTED',source=dict(sha='FENCED-source',ref='FENCED-ref',run='FENCED-run',job='FENCED-job',map_sha256=hashlib.sha256(body).hexdigest(),approval='FENCED-approval'),image={'id':IMAGE},materials=materials)
            model=Model(root,work,mutation)
            def snapshot(*args):return {key:'a'*64 for key in ('ROOT_ADMISSION_SHA256','SOURCE_MAP_SHA256','CONTRACT_SHA256')}
            with patch.object(P,'snapshot',snapshot),patch.object(P.Path,'read_text',return_value='MemAvailable: 99999999 kB\n'),patch.object(P.os,'statvfs',return_value=SimpleNamespace(f_bavail=128*1024**3//4096,f_frsize=4096,f_favail=2000000)),patch.object(P.resource,'getrlimit',return_value=(-1,-1)),patch.object(P.resource,'setrlimit',lambda *a:None):
                report=P.run(root,work,a,model)
            return report,model.events
    def test_modeled_whole_route_order_and_natural_cleanup(self):
        report,events=self.modeled();self.assertEqual(report['status'],'COMPLETED_EXPORTED_RETIRED');self.assertTrue(report['owned_resources_absent'])
        creates=[i for i,a in enumerate(events) if a[0]=='create'];starts=[i for i,a in enumerate(events) if a[:2]==['start','--attach']]
        self.assertEqual(len(creates),3);self.assertEqual(len(starts),3);self.assertLess(creates[1],starts[0]);self.assertLess(starts[1],creates[2])
        self.assertIn('-prepare',events[creates[0]][events[creates[0]].index('--name')+1]);self.assertTrue(events[starts[0]][-1].endswith('-init'))
        for event in events:
            if event[0]=='create':
                for n,arg in enumerate(event):
                    if arg=='--mount' and 'type=volume,' in event[n+1]:self.assertIn('volume-nocopy',event[n+1])
        self.assertEqual(report['volume_initialization']['after']['mode'],0o700)
    def test_foreign_actor_is_never_deleted(self):
        report,events=self.modeled('foreign');self.assertEqual(report['status'],'FAIL');self.assertTrue(report.get('cleanup_errors'))
        self.assertFalse(any(a[:2]==['container','rm'] and a[-1].endswith('-prepare') for a in events))
    def test_missing_nocopy_and_extra_capability_refuse_before_start(self):
        for mutation in ('mount','cap'):
            report,events=self.modeled(mutation);self.assertEqual(report['status'],'FAIL')
            self.assertFalse(any(a[:2]==['start','--attach'] for a in events))
    def test_main_copyup_and_replaced_initializer_identity_refused(self):
        for mutation in ('main-root','main-alias','container-id'):
            report,events=self.modeled(mutation);self.assertEqual(report['status'],'FAIL')
            self.assertFalse(any(a[:2]==['start','--attach'] and a[-1].endswith('-makepkg') for a in events))
            if mutation=='container-id':
                self.assertTrue(report.get('cleanup_errors'))
                self.assertFalse(any(a[:2]==['container','rm'] and a[-1].endswith('-init') for a in events))
    def test_receipt_wrong_owner_or_inode_prevents_prepare(self):
        for mutation in ('owner','inode'):
            report,events=self.modeled(mutation);self.assertEqual(report['status'],'FAIL');self.assertTrue(report['owned_resources_absent'])
            self.assertFalse(any(a[:2]==['start','--attach'] and a[-1].endswith('-prepare') for a in events))
    def test_forced_cleanup_and_forced_export_preserve_failure(self):
        for mutation in ('live-failure','forced-export'):
            report,events=self.modeled(mutation);self.assertEqual(report['status'],'FAIL');self.assertTrue(report['owned_resources_absent'])
    def test_model_refuses_initialization_before_prepare_creation(self):
        model=Model(Path('/FENCED-SOURCE'),Path('/FENCED-WORK'))
        b=V.binding(dict(sha='FENCED-source',run='FENCED-run',job='FENCED-job'),IMAGE,'a'*64);labels=P.labels(b['source'],b['token'],'init')
        argv=P.init_options(b['init'],b['volume'],IMAGE,labels,b);model(argv)
        with self.assertRaises(AssertionError):model(P.DOCKER+['start','--attach',b['init']])
    def test_replaced_failed_actor_never_stopped_exported_or_removed(self):
        report,events=self.modeled('replacement-failure');self.assertEqual(report['status'],'FAIL');self.assertTrue(report.get('cleanup_errors'))
        self.assertFalse(any(a[0] in ('stop','cp') for a in events))
        self.assertFalse(any(a[:2]==['container','rm'] and a[-1].endswith('-prepare') for a in events))
        report,events=self.modeled('replacement-after-stop');self.assertEqual(report['status'],'FAIL');self.assertTrue(report.get('cleanup_errors'))
        self.assertTrue(any(a[0]=='stop' for a in events));self.assertFalse(any(a[0]=='cp' for a in events))
        self.assertFalse(any(a[:2]==['container','rm'] and a[-1].endswith('-prepare') for a in events))
    def test_initialization_literal_chmod_precedes_chown_and_no_recursion(self):
        self.assertLess(V.INIT_CODE.index('os.fchmod(fd,0o700)'),V.INIT_CODE.index('os.fchown(fd,1001,1001)'))
        self.assertNotIn('walk(',V.INIT_CODE);self.assertNotIn('rglob',V.INIT_CODE)
        self.assertLess(V.INIT_CODE.index('INITIALIZER_WORK_ROOT_OBSERVED'),V.INIT_CODE.index('fd=os.open'))
        self.assertIn('file=sys.stderr,flush=True',V.INIT_CODE)
    def test_source_image_root_admission_and_preentry_refusals(self):
        b=V.binding({'FENCED':'DATA'},IMAGE,'a'*64);value=V.admission(b);initialized=receipt(b)
        for phase,empty in (('prepare',True),('makepkg',False)):V.verify_work(value,initialized,initialized['after'],1001,1001,True,empty,phase)
        for key,changed in (('source',{'FOREIGN':'DATA'}),('image','sha256:'+'e'*64),('root_admission_sha256','b'*64)):
            bad=copy.deepcopy(initialized);bad['binding'][key]=changed
            with self.assertRaises(ValueError):V.verify_receipt(bad,b)
        for actual,uid,gid,writable,empty,phase in (({**initialized['after'],'inode':18},1001,1001,True,True,'prepare'),(initialized['after'],0,1001,True,True,'prepare'),(initialized['after'],1001,1001,False,True,'prepare'),(initialized['after'],1001,1001,True,False,'prepare'),(initialized['after'],1001,1001,True,True,'makepkg')):
            with self.assertRaises(ValueError):V.verify_work(value,initialized,actual,uid,gid,writable,empty,phase)


if __name__=='__main__':unittest.main()
