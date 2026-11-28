# SPDX-License-Identifier: MIT
"""Modeled DATA only; audit fence forbids all actual process/namespace/daemon calls."""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('nested_preflight_controls',HERE/'probe.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)

def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.exec','os.fork','os.system','fcntl.flock'):
        raise RuntimeError('probe controls forbid actual actors: '+event)
sys.addaudithook(fence)


def context(uid=1001,offset=0):return dict(uid=uid,gid=uid,ns={n:n+':['+str(v+offset)+']'for n,v in zip(M.NS,(1,2,3,4))})
def fixture(stage):
    outer=context();parent=context(offset=10);parent['ns']['pid']=outer['ns']['pid'];value=copy.deepcopy(parent)
    value.update(kind='NESTED_NAMESPACE_PROBE_DATA_V1',stage=stage,net_interfaces=['lo'],uid_map='1001 0 1\n',gid_map='1001 0 1\n',bwrap_parent=None)
    if stage=='mapped-root':value.update(uid=0,gid=0,ns=dict(parent['ns'],user='user:[30]'),uid_map='0 1001 1\n',gid_map='0 1001 1\n',bwrap_parent=parent)
    return outer,value

def retirement(exit=0):return dict(passed=exit==0,exit=exit,reaped=True,ownership='REAPED',timeout=False,signals=[],group_census='EMPTY_TWICE',output_complete=True,error=None,seconds=.1,cap_seconds=20)


def binaries():
    return {n:dict(path='/usr/bin/'+n,resolved='/usr/bin/'+n,bytes=32,sha256='a'*64)
            for n in ('python3','bwrap','unshare')}


def diagnostic():
    return dict(kind='NESTED_NAMESPACE_PREFLIGHT_DATA_V1',outer=context(),binaries=binaries(),
                binary_qualification=None,context_qualification=None,observations=[dict(stage=n)
                for n in ('bwrap','mapped-root')],children_absent_twice=True)


def inspected():
    image='sha256:'+'1'*64;name='cachy-nested-preflight-MODELED';labels={'owner':'MODELED'};runtime=Path('/MODELED/runtime')
    row=dict(Id='2'*64,Name='/'+name,Image=image,Config=dict(Labels=labels,User='1001:1001',Entrypoint=['/usr/bin/python3'],Cmd=['-I','-B','/probe/probe.py','--inside-probe']),
        HostConfig=dict(ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=None,Privileged=False,Devices=[],DeviceRequests=None,Init=False,PidMode='',IpcMode='private',UTSMode='',Binds=None,PortBindings={},PublishAllPorts=False,Memory=512*1024**2,MemorySwap=512*1024**2,NanoCpus=1000000000,PidsLimit=64,Tmpfs={'/tmp':'rw,nosuid,nodev,exec,size=64m'},SecurityOpt=['no-new-privileges','seccomp='+(HERE/'nested-seccomp.json').read_text()]),
        Mounts=[dict(Type='bind',Source=str(HERE),Destination='/probe',RW=False),dict(Type='bind',Source=str(runtime/'owned_process.py'),Destination='/runtime/owned_process.py',RW=False)])
    return row,(name,image,labels,runtime,1001,1001)


class Controls(unittest.TestCase):
    def test_two_modeled_effect_predicates_are_not_support_observations(self):
        for stage in ('bwrap','mapped-root'):
            outer,value=fixture(stage);self.assertTrue(M.effects(outer,value,stage))
            self.assertEqual(M.ACTUAL,dict(image_id=None,binary_qualification=None,context_qualification=None,namespace_qualification=None))

    def test_mapped_root_must_change_only_user_relative_to_bwrap(self):
        for kind in ('same-user','changed-mount','host-net','wrong-map','wrong-uid','bool-uid','wrong-parent','host-pid'):
            outer,value=fixture('mapped-root')
            if kind=='same-user':value['ns']['user']=value['bwrap_parent']['ns']['user']
            if kind=='changed-mount':value['ns']['mnt']='mnt:[99]'
            if kind=='host-net':value['ns']['net']=outer['ns']['net']
            if kind=='wrong-map':value['uid_map']='0 0 4294967295\n'
            if kind=='wrong-uid':value['uid']=1001
            if kind=='bool-uid':value['uid']=False
            if kind=='wrong-parent':value['bwrap_parent']['uid']=0
            if kind=='host-pid':value['ns']['pid']='pid:[99]'
            with self.subTest(kind=kind),self.assertRaises((ValueError,KeyError)):M.effects(outer,value,'mapped-root')

    def test_bwrap_needs_actual_distinct_user_mount_net_and_ordinary_identity(self):
        for name in ('user','mnt','net'):
            outer,value=fixture('bwrap');value['ns'][name]=outer['ns'][name]
            with self.subTest(name=name),self.assertRaises(ValueError):M.effects(outer,value,'bwrap')
        outer,value=fixture('bwrap');value['uid']=0
        with self.assertRaises(ValueError):M.effects(outer,value,'bwrap')

    def test_denied_unknown_exit_timeout_output_and_cause_remain_distinct(self):
        outer,_=fixture('bwrap')
        row=M.assess(outer,'bwrap',retirement(1),b'',b'Operation not permitted\n');self.assertEqual(row['outcome'],'DENIED');self.assertEqual(row['cause'],'NOT_INFERRED')
        for r,stdout,stderr in ((retirement(1),b'',b'unknown failure'),(retirement(),b'not JSON',b''),(dict(retirement(1),timeout=True),b'',b'Permission denied'),(dict(retirement(1),group_census='UNKNOWN'),b'',b'Permission denied'),(dict(retirement(1),output_complete=False),b'',b'Permission denied'),(dict(retirement(),passed=False),b'{}',b''),(dict(retirement(1),seconds=21),b'',b'Permission denied')):
            self.assertEqual(M.assess(outer,'bwrap',r,stdout,stderr)['outcome'],'UNKNOWN')
        self.assertEqual(M.ACTUAL['namespace_qualification'],None)

    def test_signalled_nonordinary_or_inconsistent_exit_is_unknown_not_denied(self):
        for code in (-9,-1,256):
            row=retirement(code)
            self.assertEqual(M.assess({},'bwrap',row,b'',b'Permission denied')['outcome'],'UNKNOWN')
        row=dict(retirement(1),passed=True)
        self.assertEqual(M.assess({},'bwrap',row,b'',b'Operation not permitted')['outcome'],'UNKNOWN')

    def test_complete_finite_binary_observations_required_without_qualification(self):
        value=diagnostic();self.assertIs(M.diagnostic(value),value)
        for bad in ('missing','one-missing','extra','zero-size','huge-size','bool-size','hash','path','relative','parent','newline','qualified','context-qualified','missing-qualification','extra-field','duplicate-stage'):
            value=diagnostic()
            if bad=='missing':value.pop('binaries')
            if bad=='one-missing':value['binaries'].pop('unshare')
            if bad=='extra':value['binaries']['other']=value['binaries']['bwrap']
            if bad in ('zero-size','huge-size','bool-size'):value['binaries']['bwrap']['bytes']={'zero-size':0,'huge-size':64*1024**2+1,'bool-size':True}[bad]
            if bad=='hash':value['binaries']['bwrap']['sha256']='not a digest'
            if bad=='path':value['binaries']['bwrap']['path']='/usr/bin/other'
            if bad=='relative':value['binaries']['bwrap']['resolved']='usr/bin/bwrap'
            if bad=='parent':value['binaries']['bwrap']['resolved']='/usr/bin/../bin/bwrap'
            if bad=='newline':value['binaries']['bwrap']['resolved']='/usr/bin/bwrap'+chr(10)
            if bad=='qualified':value['binary_qualification']='PASS'
            if bad=='context-qualified':value['context_qualification']='PASS'
            if bad=='missing-qualification':value.pop('binary_qualification')
            if bad=='extra-field':value['unexpected']='not accepted'
            if bad=='duplicate-stage':value['observations'][1]['stage']='bwrap'
            with self.subTest(bad=bad),self.assertRaises(ValueError):M.diagnostic(value)

    def test_complete_raw_diagnostic_bytes_are_retained(self):
        import base64
        out=M.assess(context(),'bwrap',retirement(1),b'\x00partial\xff',b'Permission denied\n')
        self.assertEqual(base64.b64decode(out['stdout_b64']),b'\x00partial\xff');self.assertEqual(base64.b64decode(out['stderr_b64']),b'Permission denied\n')

    def test_selected_bwrap_argv_and_exec_only_unshare_flags(self):
        for stage in ('bwrap','mapped-root'):
            argv=M.nested_argv('/tmp/MODELED',stage)
            self.assertEqual(argv[:11],['/usr/bin/bwrap','--unshare-net','--ro-bind','/','/','--proc','/proc','--dev','/dev','--tmpfs','/tmp'])
            self.assertNotIn('--unshare-pid',argv);self.assertNotIn('--unshare-all',argv)
        tree=ast.parse(M.MAPPED);call=next(n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='execv')
        self.assertEqual(ast.literal_eval(call.args[0]),'/usr/bin/unshare')
        self.assertEqual([ast.literal_eval(n)for n in call.args[1].elts[:4]],['/usr/bin/unshare','--user','--map-root-user','--'])
        ast.parse(M.INNER)
        self.assertIn('assert e.errno==30',M.INNER)

    def test_exact_constrained_container_argv(self):
        row,args=inspected();name,image,labels,runtime,uid,gid=args
        argv=M.create_argv(image,name,labels,Path('/private/probe.cid'),Path('/private/nested-seccomp.json'),runtime,uid,gid)
        for item in ('--pull=never','--platform=linux/arm64','--user=1001:1001','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=1','--memory=512m','--memory-swap=512m','--pids-limit=64','--ipc=private'):self.assertIn(item,argv)
        self.assertEqual(argv[-5:],[image,'-I','-B','/probe/probe.py','--inside-probe'])
        self.assertFalse(any('privileged'in s or 'unconfined'in s or 'cap-add'in s or 'docker.sock'in s for s in argv))
        self.assertEqual(sum(s.startswith('type=bind,')and s.endswith(',readonly')for s in argv),2)
        M.confinement(row,*args)

    def test_inspected_serialized_seccomp_joins_full_json(self):
        row,args=inspected();profile=json.loads((HERE/'nested-seccomp.json').read_bytes())
        row['HostConfig']['SecurityOpt']=['seccomp='+json.dumps(profile,separators=(',',':')),'no-new-privileges=true'];M.confinement(row,*args)
        for opts in (['no-new-privileges','seccomp=unconfined'],['no-new-privileges','seccomp=/private/profile.json'],['no-new-privileges','seccomp='+json.dumps(dict(profile,defaultAction='SCMP_ACT_ALLOW'))]):
            row['HostConfig']['SecurityOpt']=opts
            with self.assertRaises((ValueError,json.JSONDecodeError)):M.confinement(row,*args)

    def test_wrong_identity_caps_mounts_resources_or_namespace_modes_refuse(self):
        for kind in ('name','image','label','user','entry','caps','privileged','rw','extra-mount','RAM','swap','CPU','PID','host-pid','host-ipc'):
            row,args=inspected()
            if kind=='name':row['Name']='/foreign'
            if kind=='image':row['Image']='sha256:'+'3'*64
            if kind=='label':row['Config']['Labels']={'owner':'foreign'}
            if kind=='user':row['Config']['User']='0:0'
            if kind=='entry':row['Config']['Cmd']=['/foreign']
            if kind=='caps':row['HostConfig']['CapAdd']=['SYS_ADMIN']
            if kind=='privileged':row['HostConfig']['Privileged']=True
            if kind=='rw':row['Mounts'][0]['RW']=True
            if kind=='extra-mount':row['Mounts'].append(dict(Type='bind',Source='/home',Destination='/host',RW=True))
            if kind in ('RAM','swap','CPU','PID'):row['HostConfig'][{'RAM':'Memory','swap':'MemorySwap','CPU':'NanoCpus','PID':'PidsLimit'}[kind]]*=2
            if kind=='host-pid':row['HostConfig']['PidMode']='host'
            if kind=='host-ipc':row['HostConfig']['IpcMode']='host'
            with self.subTest(kind=kind),self.assertRaises(ValueError):M.confinement(row,*args)

    def test_exact_existing_helper_pins_and_no_import_actors(self):
        root=HERE.parents[2]/'scripts/integration/arm16k_systemd_tcg_guest/frozen'
        for name,pin in M.HELPERS.items():self.assertEqual(M.P.pin((root/name).read_bytes())['sha256'],pin)
        O,B=M.helpers(root);self.assertTrue(callable(O.supervise));self.assertTrue(callable(B.OwnedContainer.recover))

    def test_supervisor_contract_and_prelaunch_validation(self):
        events=[];child=SimpleNamespace(returncode=None,_child_created=True)
        def popen(argv,**kwargs):
            events.append('launch');kwargs['stdout'].write(b'bounded stdout');kwargs['stderr'].write(b'bounded stderr');return child
        def supervise(value,**kwargs):
            events.append('supervise');self.assertIs(value,child);self.assertEqual(kwargs['streams'],());self.assertEqual(kwargs['max_output'],0);self.assertIsNone(kwargs['log_fd']);child.returncode=0;return dict(retirement(),output=b'')
        O=SimpleNamespace(prepare=lambda:events.append('prepare'),supervise=supervise)
        with tempfile.TemporaryDirectory()as tmp,patch.object(M.subprocess,'Popen',side_effect=popen):
            r,stdout,stderr=M.supervised(O,['MODELED'],Path(tmp),'one',8,1024)
            self.assertEqual((stdout,stderr),(b'bounded stdout',b'bounded stderr'));M.natural(r)
            self.assertEqual(events,['prepare','launch','supervise'])
            self.assertEqual((Path(tmp)/'one.stdout').stat().st_mode&0o777,0o600)
        with patch.object(M.subprocess,'Popen')as launch,self.assertRaises(ValueError):M.supervised(O,['MODELED'],Path('/unused'),'two',.1,1024)
        launch.assert_not_called()

    def test_unexpected_supervisor_refusal_still_transfers_owned_child(self):
        child=SimpleNamespace(returncode=None,_child_created=True);calls=[]
        def supervise(value,**kwargs):
            calls.append(kwargs)
            if len(calls)==1:raise ValueError('MODELED helper refusal')
            child.returncode=0;return dict(retirement(),output=b'')
        O=SimpleNamespace(prepare=lambda:None,supervise=supervise)
        with tempfile.TemporaryDirectory()as tmp,patch.object(M.subprocess,'Popen',return_value=child),self.assertRaisesRegex(ValueError,'helper refusal'):
            M.supervised(O,['MODELED'],Path(tmp),'one',8,1024)
        self.assertEqual(len(calls),2);self.assertEqual(calls[1]['cap'],1.5);self.assertEqual(child.returncode,0)

    def test_execution_is_unselected_without_explicit_admission(self):
        with patch.object(M.P,'request')as request,self.assertRaises(ValueError):M.run(None,None,None,None,None)
        request.assert_not_called()

    def test_owned_cleanup_refuses_foreign_name_or_labels_before_removal(self):
        root=HERE.parents[2]/'scripts/integration/arm16k_systemd_tcg_guest/frozen';_,B=M.helpers(root)
        for kind in ('foreign-name','foreign-label'):
            with tempfile.TemporaryDirectory()as tmp:
                row,args=inspected();name,image,labels,runtime,uid,gid=args;row['State']=dict(Running=False,ExitCode=0,OOMKilled=False);commands=[]
                if kind=='foreign-label':row['Config']['Labels']={'owner':'foreign'}
                class Scope(B.OwnedContainer):
                    def validate(self,value):M.confinement(value,*args)
                    def call(self,argv,deadline):
                        commands.append(argv)
                        if argv[1:3]==['container','ls']:
                            actual='foreign'if kind=='foreign-name'else name
                            return SimpleNamespace(returncode=0,stdout=(row['Id']+' '+actual+'\n').encode())
                        return SimpleNamespace(returncode=0,stdout=json.dumps([row]).encode())
                scope=Scope(name,Path(tmp)/'cid',image,labels,HERE,tmp);scope.submitted=True;report={};scope.cleanup(report)
                self.assertTrue(report['cleanup_errors']);self.assertFalse(any('rm'in c for c in commands));self.assertFalse(report.get('owned_container_absence_verified',False))

    def test_owned_stopped_cleanup_and_final_absence_model(self):
        root=HERE.parents[2]/'scripts/integration/arm16k_systemd_tcg_guest/frozen';_,B=M.helpers(root)
        with tempfile.TemporaryDirectory()as tmp:
            row,args=inspected();name,image,labels,runtime,uid,gid=args;removed=[];commands=[]
            class Scope(B.OwnedContainer):
                def validate(self,value):M.confinement(value,*args)
                def call(self,argv,deadline):
                    commands.append(argv)
                    if argv[1:3]==['container','ls']:return SimpleNamespace(returncode=0,stdout=b''if removed else(row['Id']+' '+name+'\n').encode())
                    if argv[1:3]==['container','inspect']:return SimpleNamespace(returncode=0,stdout=json.dumps([row]).encode())
                    if argv[1:3]==['container','rm']:removed.append(True)
                    return SimpleNamespace(returncode=0,stdout=b'0\n')
            scope=Scope(name,Path(tmp)/'cid',image,labels,HERE,tmp);scope.submitted=True;report={};scope.cleanup(report)
            self.assertTrue(report['owned_container_absence_verified']);self.assertFalse(report['cleanup_errors'])
            self.assertEqual(next(c for c in commands if c[1:3]==['container','rm']),['docker','container','rm','--force',row['Id']])
    def test_complete_controller_model_retains_data_without_namespace_qualification(self):
        root=HERE.parents[2]/'scripts/integration/arm16k_systemd_tcg_guest/frozen';O,B=M.helpers(root)
        class Cancellation:
            pending=[];cleaning=False
            def __enter__(self):return self
            def __exit__(self,*args):pass
        for case in ('pass','denied','missing-binaries','changed-policy'):
            denied=case=='denied'
            with self.subTest(case=case),tempfile.TemporaryDirectory()as tmp:
                out=Path(tmp)/'fresh';state={'created':False,'removed':False};calls=[]
                def execute(owned,argv,output,label,seconds,per_stream):
                    original=['docker',*argv[2:]];calls.append(original);stdout=b'';stderr=b''
                    if original[1]=='version':stdout=json.dumps(M.P.SERVER).encode()
                    elif original[1:3]==['image','inspect']:stdout=json.dumps([dict(Id='sha256:'+'1'*64,Architecture='arm64',Os='linux',Config=dict(Labels={},Volumes=None))]).encode()
                    elif original[1]=='create':
                        state['created']=True;state['name']=original[original.index('--name')+1];state['labels']={original[i+1].split('=',1)[0]:original[i+1].split('=',1)[1]for i,v in enumerate(original)if v=='--label'}
                        (output/'container.cid').write_text('2'*64+'\n')
                    elif original[1:3]==['container','ls']:
                        if state['created']and not state['removed']:stdout=('2'*64+' '+state['name']+'\n').encode()
                    elif original[1:3]==['container','inspect']:
                        row,_=inspected();row.update(Name='/'+state['name']);row['Config'].update(Labels=state['labels'],User=str(os.getuid())+':'+str(os.getgid()));row['Mounts'][1]['Source']=str(root/'owned_process.py');row['State']=dict(Running=False,ExitCode=0,OOMKilled=False);stdout=json.dumps([row]).encode()
                    elif original[1]=='logs':
                        outer=context(os.getuid());outer['gid']=os.getgid();observations=[]
                        for stage in ('bwrap','mapped-root'):
                            _,value=fixture(stage);value['uid']=os.getuid()if stage=='bwrap'else 0;value['gid']=os.getgid()if stage=='bwrap'else 0
                            if stage=='mapped-root':value['bwrap_parent'].update(uid=os.getuid(),gid=os.getgid());value.update(uid_map=f'0 {os.getuid()} 1\n',gid_map=f'0 {os.getgid()} 1\n')
                            observations.append(M.assess(outer,stage,retirement(1)if denied else retirement(),b''if denied else json.dumps(value).encode(),b'Operation not permitted\n'if denied else b''))
                        stdout=json.dumps(dict(kind='NESTED_NAMESPACE_PREFLIGHT_DATA_V1',outer=outer,binaries={}if case=='missing-binaries'else binaries(),binary_qualification=None,context_qualification=None,observations=observations,children_absent_twice=True)).encode()
                        if case=='changed-policy':
                            retained=output/'nested-seccomp.json'
                            retained.chmod(0o600)
                            retained.write_bytes(b'{}')
                    elif original[1:3]==['container','rm']:state['removed']=True
                    elif original[1]=='wait':stdout=b'0\n'
                    self.assertLessEqual(len(stdout),per_stream)
                    (output/(label+'.stdout')).write_bytes(stdout);(output/(label+'.stderr')).write_bytes(stderr)
                    return dict(retirement(),cap_seconds=seconds),stdout,stderr
                with patch.object(B,'Cancellation',Cancellation),patch.object(M,'helpers',return_value=(O,B)),patch.object(M,'supervised',side_effect=execute):
                    report=M.run('sha256:'+'1'*64,HERE/'nested-seccomp.json',M.P.PROFILE['sha256'],out,root,True)
                self.assertTrue(report['cleanup']['owned_container_absence_verified']);self.assertIsNone(report['namespace_qualification'])
                if case=='missing-binaries':
                    self.assertEqual(report['status'],'HOLD');self.assertIn('binary observations',report['failure']['message']);self.assertNotIn('observations',report)
                elif case=='changed-policy':
                    args=['probe.py','--image','sha256:'+'1'*64,'--profile',str(HERE/'nested-seccomp.json'),
                          '--profile-sha256',M.P.PROFILE['sha256'],'--output',str(out),'--runtime-root',str(root),'--allow-preflight']
                    with patch.object(M.sys,'argv',args),patch.object(M,'run',return_value=report):
                        self.assertEqual(M.main(),2)
                    self.assertEqual(report['status'],'HOLD')
                    self.assertIn('exact nested policy SHA-256',report['failure']['message'])
                    self.assertEqual([r['outcome']for r in report['observations']['observations']],['OBSERVED_REQUIRED_EFFECTS']*2)
                    self.assertEqual(json.loads((out/'preflight.json').read_bytes()),report)
                else:
                    self.assertEqual(report['status'],'OBSERVATIONS_RETAINED_NOT_QUALIFICATION')
                    self.assertEqual([r['outcome']for r in report['observations']['observations']],['DENIED'if denied else'OBSERVED_REQUIRED_EFFECTS']*2)
                self.assertEqual(sum(c[1]=='create'for c in calls),1);self.assertEqual(sum(c[1]=='start'for c in calls),1)
                self.assertLessEqual(sum(p.stat().st_size for p in out.iterdir()if p.is_file()),M.RESOURCES['controller_bytes'])


if __name__=='__main__':unittest.main()
