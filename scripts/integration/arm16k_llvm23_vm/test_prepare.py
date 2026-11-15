# SPDX-License-Identifier: MIT
"""Fenced synthetic image/command controls; no actual image, archive, or actor."""
import copy,ctypes,hashlib,importlib.util,json,os,shutil,sys,tempfile,time,unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
def load(name):
    spec=importlib.util.spec_from_file_location('llvm_prepare_control_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
K,P,H,D,O=(load(n)for n in('contracts','prepare_image','prepare','image','ownership'))
BOOT=load('boot')
def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.posix_spawn','os.fork','fcntl.flock'):
        raise RuntimeError('synthetic preparation controls forbid operation: '+event)
sys.addaudithook(fence)
def node(body=b'MODEL',mode=0o644):return dict(kind='file',mode=mode,bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
def rawpin(p):return K.pin(p,64*1024**2)


class Model:
    def __init__(self,root):
        self.root=root;self.base=root/'base';self.packet=root/'packet';self.materials=root/'materials';self.kernel=root/'kernel';self.work=root/'work'
        for p in(self.base,self.packet,self.materials,self.kernel,self.work):p.mkdir(mode=0o700)
        self.nodes={};self.records={};self.inv={f'model{i}':'1'for i in range(111)}
        def directory(path):
            for parent in reversed(Path(path).parents):
                if parent.as_posix()!='.':self.nodes[parent.as_posix()]=dict(kind='dir',mode=0o755)
            self.nodes[path]=dict(kind='dir',mode=0o755)
        def file(path,body=b'MODEL',mode=0o644):
            directory(str(Path(path).parent));self.nodes[path]=node(body,mode)
        for p in O.PROTECTED:file(p)
        for p in('var/lib','etc/systemd/system','usr/bin'):directory(p)
        file('usr/bin/model-tool',b'MODEL_TOOL',0o755)
        directory('var/lib/pacman/local')
        for name in self.inv:
            path='var/lib/pacman/local/'+name+'-1';directory(path)
            desc='%NAME%\n'+name+'\n\n%VERSION%\n1\n';files='%FILES%\n'+('usr/bin/model-tool\n'if name=='model0'else'')
            self.records[name+'-1']=dict(desc=desc,files=files)
            file(path+'/desc',desc.encode());file(path+'/files',files.encode())
        (self.base/'guest.raw').write_bytes(b'x'*4096)
        (self.base/'prepared.json').write_bytes(K.canonical(dict(nonce='b'*32,files={'guest.raw':rawpin(self.base/'guest.raw')})))
        (self.base/'credentials.json').write_bytes(b'MODELED_PRIVATE_TEST_CREDENTIAL_NOT_REAL\n');(self.base/'credentials.json').chmod(0o600)
        for name in('Image','config'):(self.kernel/name).write_bytes(b'MODEL_'+name.encode())
        package=dict(K.PACKAGE)
        for key,name in P.MATERIALS.items():
            path=self.materials/name;path.write_bytes(('MODEL_DATA_NOT_AN_ARCHIVE_'+key).encode());package[key]=rawpin(path)
        self.ctx=dict(case={'package':package},certs={'baseline_certificate':dict(raw=rawpin(self.base/'guest.raw'),inventory=self.inv),
            'runtime_certificate':dict(files={'/usr/bin/model-tool':dict(bytes=10,sha256=hashlib.sha256(b'MODEL_TOOL').hexdigest(),mode=0o755,owner='model0',version='1',resolved='/usr/bin/model-tool'),
              K.PREFIX+'/bin/clang':dict(owner=K.PACKAGE['name'])},candidate_namespace={K.PREFIX+'/bin/clang':dict(kind='f',bytes=32)})},
            limits=dict(prepared_raw_bytes=4096,image_scan_passes=2,guest_output_cap_bytes=32,prepare_seconds=60,cleanup_seconds=10,
                clone_allocated_cap_bytes=1024**2,logs_cap_bytes=1024**2,reserve_bytes=1,owner_memory_bytes=1024**2,cpus=2,pids=64),
            source_lock={'bytes':32,'sha256':'a'*64},nonce='c'*32,base=json.loads((self.base/'prepared.json').read_bytes()),baseline={'guest_required_pins':{}},
            kernel={'files':{n:rawpin(self.kernel/n)for n in('Image','config')}},tool={'image_id':'sha256:'+'d'*64},
            authority={'credentials':rawpin(self.base/'credentials.json')},deadline=int(time.monotonic())+50,final_deadline=int(time.monotonic())+60,
            paths=dict(base=str(self.base),materials=str(self.materials),kernel_bundle=str(self.kernel),packet=str(self.packet)))
        files={}
        for name in('root.sh','case.env','probe.sh','smoke.c','unwind.cpp','case.sh','arm16k-llvm23-vm.service'):
            body=('nonce='+self.ctx['nonce']+'\n').encode()if name=='case.env'else b'MODELED_DATA_NOT_EXECUTED\n'
            (self.packet/name).write_bytes(body);files[name]=dict(**rawpin(self.packet/name),mode=0o644)
        (self.packet/'case-packet.json').write_bytes(K.canonical(dict(operation=K.OP,nonce=self.ctx['nonce'],Source_lock=self.ctx['source_lock'],files=files)))
        self.paths=dict(base=self.base,materials=self.materials,kernel_bundle=self.kernel,packet=self.packet,work=self.work)
        self.events=[];self.guards=0;self.tamper=None
    def guard(self):self.guards+=1
    def scan(self,path,deadline,guard,**limits):
        guard();nodes=copy.deepcopy(self.nodes)
        if path!=self.base/'guest.raw':
            planned,_=P.plan(self.ctx,self.packet,self.materials,self.nodes,K);nodes.update(planned)
            if self.tamper=='old':nodes['etc/shadow']['sha256']='0'*64
            if self.tamper=='extra':nodes['usr/bin/unreviewed']=node()
            if self.tamper=='mode':nodes[P.UNIT]['mode']=0o600
            self.explicit_limits=limits
        return dict(nodes=nodes,records=copy.deepcopy(self.records),profile=dict(image_bytes=path.stat().st_size))
    def command(self,label,argv,**kw):
        self.events.append((label,argv,kw))
        if label=='sparse-clone':shutil.copyfile(argv[-2],argv[-1])
        if label=='grow-raw':
            with Path(argv[-2]).open('r+b')as stream:stream.truncate(int(argv[-1]))
        return SimpleNamespace(returncode=0)
    def build(self):return P.build(self.ctx,self.paths,self.command,self.guard,(K,None,None,O,SimpleNamespace(scan=self.scan)))


class PreparationControls(unittest.TestCase):
    def test_complete_synthetic111_prepare_stages_DATA_only_and_preserves_nonce(self):
        with tempfile.TemporaryDirectory(prefix='llvm-prepare-MODEL-')as tmp:
            m=Model(Path(tmp));before=(m.base/'guest.raw').read_bytes();result=m.build()
            self.assertEqual(result['status'],'PREPARED_LLVM23_IMAGE_NOT_BOOTED');self.assertEqual(result['nonce'],'c'*32);self.assertEqual(result['baseline_nonce'],'b'*32)
            self.assertEqual((m.base/'guest.raw').read_bytes(),before);self.assertGreater(m.guards,5)
            self.assertEqual(m.explicit_limits['max_read_bytes'],8192)
            commands=[a[1]for _,a,_ in m.events];self.assertNotIn('pacman',commands);self.assertNotIn('tar',commands)
            owned=K.load(m.work/'assembly/ownership.json',64*1024**2);self.assertEqual(len(owned['packages']),111)
            self.assertEqual(owned['staged_namespace'][P.WANTS]['target'],'../arm16k-llvm23-vm.service')
    def test_baseline_ALPM_runtime_and_protected_refusals_precede_clone(self):
        for kind in('ALPM','runtime','protected'):
            with tempfile.TemporaryDirectory(prefix='llvm-prepare-MODEL-')as tmp:
                m=Model(Path(tmp))
                if kind=='ALPM':m.records['model0-1']['desc']+='corrupt\n'
                elif kind=='runtime':m.ctx['certs']['runtime_certificate']['files']['/usr/bin/model-tool']['sha256']='0'*64
                else:del m.nodes['etc/shadow']
                with self.subTest(kind=kind),self.assertRaises(ValueError):m.build()
                self.assertFalse(m.events);self.assertFalse((m.work/'assembly').exists())
    def test_actual_retained_baseline_required_pin_schema_is_sha256_strings(self):
        actual=K.load(HERE/'data/baseline111.json')['guest_required_pins']
        self.assertTrue(actual);self.assertTrue(all(type(value)is str and len(value)==64 for value in actual.values()))
        with tempfile.TemporaryDirectory(prefix='llvm-prepare-MODEL-')as tmp:
            m=Model(Path(tmp));path,digest=next(iter(actual.items()));m.nodes[path]=node();m.ctx['baseline']['guest_required_pins']={path:digest}
            scan=dict(nodes=m.nodes,records=m.records)
            with self.assertRaisesRegex(ValueError,'Root original protected path'):P.qualify_baseline(m.ctx,scan,O,K)
            m.nodes[path]['sha256']=digest
            owned,protected=P.qualify_baseline(m.ctx,scan,O,K);self.assertEqual(protected[path]['sha256'],digest)
    def test_packet_nonce_and_material_hash_refuse_before_clone(self):
        for kind in('nonce','material','extra'):
            with tempfile.TemporaryDirectory(prefix='llvm-prepare-MODEL-')as tmp:
                m=Model(Path(tmp))
                if kind=='nonce':m.ctx['nonce']='e'*32
                elif kind=='material':next(m.materials.iterdir()).write_bytes(b'changed')
                else:(m.packet/'unrecorded').write_bytes(b'MODEL')
                with self.subTest(kind=kind),self.assertRaises(ValueError):m.build()
                self.assertFalse(m.events)
    def test_complete_readback_refuses_old_delta_and_metadata_changes(self):
        for kind in('old','extra','mode'):
            with tempfile.TemporaryDirectory(prefix='llvm-prepare-MODEL-')as tmp:
                m=Model(Path(tmp));m.tamper=kind
                with self.subTest(kind=kind),self.assertRaises(ValueError):m.build()
                self.assertFalse((m.work/'assembly/prepared.json').exists())
    def test_owned_geometry_growth_and_shrink_cap_refusals(self):
        with tempfile.TemporaryDirectory(prefix='llvm-prepare-MODEL-')as tmp:
            m=Model(Path(tmp));m.ctx['limits']['prepared_raw_bytes']=8192;m.build()
            self.assertEqual([n for n,_,_ in m.events if n.startswith('grow-')],['grow-raw','grow-owned-ext4-check','grow-owned-ext4'])
            self.assertEqual((m.work/'assembly/guest.raw').stat().st_size,8192);self.assertEqual((m.base/'guest.raw').stat().st_size,4096)
        for target in(4095,4096*1024**2+4096):
            with tempfile.TemporaryDirectory(prefix='llvm-prepare-MODEL-')as tmp:
                m=Model(Path(tmp));m.ctx['limits']['prepared_raw_bytes']=target
                with self.assertRaises(ValueError):m.build()
                self.assertFalse(m.events)
    def test_debugfs_script_has_only_fixed_new_service_DATA_paths(self):
        with tempfile.TemporaryDirectory(prefix='llvm-prepare-MODEL-')as tmp:
            m=Model(Path(tmp));rows,files=P.plan(m.ctx,m.packet,m.materials,m.nodes,K);script=P.edits(rows,files).decode()
            self.assertIn('symlink /'+P.WANTS+' ../arm16k-llvm23-vm.service',script)
            self.assertNotIn('/etc/shadow',script);self.assertNotIn(K.PREFIX,script);self.assertNotIn('credentials',script)
            files[next(iter(files))]=Path('/MODEL;unreviewed')
            with self.assertRaises(ValueError):P.edits(rows,files)
    def test_preflight_refusal_has_no_output_or_runtime_calls(self):
        with tempfile.TemporaryDirectory(prefix='llvm-prepare-MODEL-')as tmp:
            out=Path(tmp)/'not-created';called=[]
            def refuse(*a):raise ValueError('Root actual facts NULL')
            T=SimpleNamespace(preflight=refuse,modules=lambda:called.append('runtime'))
            with self.assertRaises(ValueError):H.execute(SimpleNamespace(output=out),T)
            self.assertFalse(out.exists());self.assertFalse(called)


class HostModel:
    def __init__(self,m,output):
        self.m=m;self.out=output;self.row=None;self.cleaned=False;self.guard_calls=0;self.fail=False;self.scope=None
        owner=self
        class Cancel:
            cleaning=False;pending=[]
            def __enter__(self):return self
            def __exit__(self,*a):pass
        class Owned:
            def __init__(self,name,cidfile,image,labels,base,out):self.name=name;self.cidfile=cidfile;self.cid='e'*64;self.out=out;self.submitted=False;owner.scope=self
            def listing(self,*a):return None
            def recover(self,*a):self.validate(owner.row);return owner.row
            def cleanup(self,report):owner.cleaned=True;self.validate(owner.row);report['owned_container_absence_verified']=True
        self.B=SimpleNamespace(Cancellation=Cancel,OwnedContainer=Owned)
        self.R=SimpleNamespace(transport=lambda a:nullcontext(),command=self.command,docker_call=self.docker,LIVE_GUARD=None)
        self.T=SimpleNamespace(preflight=lambda a,phase:m.ctx,modules=lambda:(K,self.R,self.B,O,D),guard=lambda c,o:self.guard,
                               load=lambda name:P if name=='prepare_image'else BOOT,recheck=lambda c:True)
    def guard(self):self.guard_calls+=1
    def docker(self,argv,*args,**kw):
        if self.R.LIVE_GUARD:self.R.LIVE_GUARD()
        if argv[1:4]==['container','rm','--force']:self.cleaned=True
        return SimpleNamespace(returncode=0)
    def command(self,argv,out,label,*args,**kw):
        if self.R.LIVE_GUARD:self.R.LIVE_GUARD()
        if label=='rootless':return b'["name=rootless"]'
        if label=='image':return json.dumps([dict(Id=self.m.ctx['tool']['image_id'],Config={'Labels':{}})]).encode()
        if label=='create':
            mounts=[];labels={}
            for i,v in enumerate(argv):
                if v=='--mount':
                    parts=argv[i+1].split(',');d=dict(x.split('=',1)for x in parts if '='in x);mounts.append(dict(Type=d['type'],Source=d['source'],Destination=d['target'],RW='readonly'not in parts))
                if v=='--label':k,value=argv[i+1].split('=',1);labels[k]=value
            limits=self.m.ctx['limits'];self.row=dict(Name='/'+self.scope.name,Image=self.m.ctx['tool']['image_id'],
                Config=dict(Labels=labels,User='0:0',Entrypoint=['/usr/bin/python3'],Cmd=['-I','-B','/code/prepare_image.py']),Mounts=mounts,
                HostConfig=dict(ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=[],Privileged=False,Devices=[],Init=True,SecurityOpt=['no-new-privileges'],Memory=limits['owner_memory_bytes'],MemorySwap=limits['owner_memory_bytes'],NanoCpus=limits['cpus']*10**9,PidsLimit=limits['pids']),
                State=dict(ExitCode=0,OOMKilled=False,Running=False));return b''
        if label=='offline-prepare':
            if self.fail:raise ValueError('MODELED actor refusal')
            a=self.out/'actor-work/assembly';a.mkdir();
            for n in('guest.raw','Image','kernel.config'):(a/n).write_bytes(b'MODEL')
            (a/'ownership.json').write_bytes(K.canonical({'MODELED':True}))
            p=dict(status='PREPARED_LLVM23_IMAGE_NOT_BOOTED',source_lock=self.m.ctx['source_lock'],nonce=self.m.ctx['nonce'],baseline_nonce=self.m.ctx['base']['nonce'],files={n:rawpin(a/n)for n in('guest.raw','Image','kernel.config')},ownership=rawpin(a/'ownership.json'))
            (a/'prepared.json').write_bytes(K.canonical(p));return b''
        return b''


class HostControls(unittest.TestCase):
    def test_fixed_file_mounts_never_expose_credentials_and_host_copy_is_private(self):
        with tempfile.TemporaryDirectory(prefix='llvm-prepare-MODEL-')as tmp:
            m=Model(Path(tmp));h=HostModel(m,Path(tmp)/'host');result=H.execute(SimpleNamespace(output=h.out),h.T)
            self.assertEqual(result['status'],'PREPARED_LLVM23_IMAGE_NOT_BOOTED');self.assertTrue(h.cleaned);self.assertIsNone(h.R.LIVE_GUARD)
            mounts=h.row['Mounts'];self.assertEqual(len(mounts),11)
            self.assertNotIn('/base',[r['Destination']for r in mounts]);self.assertNotIn('/materials',[r['Destination']for r in mounts])
            self.assertFalse(any('credentials'in r['Source']for r in mounts));self.assertTrue(all(not r['RW']for r in mounts if r['Destination']!='/work'))
            credentials=h.out/'actor-work/assembly/credentials.json';self.assertEqual(credentials.read_bytes(),(m.base/'credentials.json').read_bytes());self.assertEqual(credentials.stat().st_mode&0o777,0o600)
            for field,value in [('NetworkMode','host'),('CapAdd',['CHOWN']),('MemorySwap',999)]:
                bad=copy.deepcopy(h.row);bad['HostConfig'][field]=value
                with self.subTest(field=field),self.assertRaises(ValueError):h.scope.validate(bad)
    def test_actor_failure_still_cleans_exact_owned_scope_and_restores_callback(self):
        with tempfile.TemporaryDirectory(prefix='llvm-prepare-MODEL-')as tmp:
            m=Model(Path(tmp));h=HostModel(m,Path(tmp)/'host');h.fail=True;result=H.execute(SimpleNamespace(output=h.out),h.T)
            self.assertNotEqual(result['status'],'PREPARED_LLVM23_IMAGE_NOT_BOOTED');self.assertTrue(h.cleaned);self.assertIsNone(h.R.LIVE_GUARD)
            self.assertFalse((h.out/'actor-work/assembly/credentials.json').exists())
    def test_cleanup_quota_fault_marks_HOLD_but_does_not_prevent_owned_retirement(self):
        with tempfile.TemporaryDirectory(prefix='llvm-prepare-MODEL-')as tmp:
            m=Model(Path(tmp));h=HostModel(m,Path(tmp)/'host');original=h.guard
            def guard():
                if m.ctx.get('active_deadline')==m.ctx['final_deadline']:raise ValueError('MODELED cleanup reserve exhausted')
                original()
            h.T.guard=lambda c,o:guard
            result=H.execute(SimpleNamespace(output=h.out),h.T)
            self.assertEqual(result['status'],'HOLD_CLEANUP_OR_CANCELLED');self.assertTrue(h.cleaned)
            self.assertTrue(result['owned_container_absence_verified']);self.assertIn('cleanup_guard_failure',result);self.assertIsNone(h.R.LIVE_GUARD)


class ScannerControls(unittest.TestCase):
    def fake(self,raw,size=1,change=None):
        text='%NAME%\nMODEL\n\n%VERSION%\n1\n';files='%FILES%\nlarge\n';bodies={'var/lib/pacman/local/MODEL-1/desc':text.encode(),'var/lib/pacman/local/MODEL-1/files':files.encode()}
        rows={'.':dict(type='directory',mode=0o755,inode=2)}
        for p in('var','var/lib','var/lib/pacman','var/lib/pacman/local','var/lib/pacman/local/MODEL-1'):rows[p]=dict(type='directory',mode=0o755,inode=len(rows)+2)
        for p,body in bodies.items():rows[p]=dict(type='file',mode=0o644,inode=len(rows)+2,size=len(body),sha256=hashlib.sha256(body).hexdigest())
        rows['large']=dict(type='file',mode=0o644,inode=99,size=size,sha256='a'*64)
        class Reader:
            blocksize,incompat,rocompat,inode_size=D.PROFILE
            def __init__(self,p,max_nodes,max_file_bytes):self.fd=os.open(p,os.O_RDONLY);self.size=p.stat().st_size;self.cap=max_file_bytes;self.read_budget=2*1024**3
            def __enter__(self):return self
            def __exit__(self,*a):os.close(self.fd)
            def read(self,offset,length):return b'x'*length
            def inventory(self):
                self.read(0,16)
                if change:change(rows)
                if size>self.cap:raise ValueError('parser file cap')
                return dict(nodes=rows,reader='SYNTHETIC_ONLY')
            def inode(self,number):
                row=next(r for r in rows.values()if r['inode']==number);return{k:v for k,v in row.items()if k!='sha256'},number
            def chunks(self,fields,number):yield bodies[next(n for n,r in rows.items()if r['inode']==number)]
        return SimpleNamespace(Ext4Reader=Reader)
    def test_explicit_Root_large_file_bound_and_read_budget(self):
        with tempfile.TemporaryDirectory(prefix='llvm-scan-MODEL-')as tmp:
            raw=Path(tmp)/'raw';raw.write_bytes(b'x'*4096);frozen=self.fake(raw,300*1024**2)
            def modules(name):return K if name=='contracts'else O if name=='ownership'else SimpleNamespace(load=lambda n:frozen)
            with patch.object(D,'module',side_effect=modules):
                with self.assertRaisesRegex(ValueError,'parser file cap'):D.scan(raw,time.monotonic()+10)
                observed=D.scan(raw,time.monotonic()+10,max_file_bytes=300*1024**2,max_read_bytes=1024**3)
                self.assertEqual(observed['nodes']['large']['bytes'],300*1024**2)
                with self.assertRaisesRegex(ValueError,'read budget'):D.scan(raw,time.monotonic()+10,max_file_bytes=300*1024**2,max_read_bytes=8)
    def test_scan_closes_on_guard_or_ALPM_record_drift(self):
        with tempfile.TemporaryDirectory(prefix='llvm-scan-MODEL-')as tmp:
            raw=Path(tmp)/'raw';raw.write_bytes(b'x'*4096);frozen=self.fake(raw,change=lambda rows:rows['var/lib/pacman/local/MODEL-1/desc'].update(sha256='0'*64))
            with patch.object(D,'module',side_effect=lambda n:K if n=='contracts'else O if n=='ownership'else SimpleNamespace(load=lambda x:frozen)):
                with self.assertRaisesRegex(ValueError,'inventory'):D.scan(raw,time.monotonic()+10)
                def guard():raise ValueError('MODELED quota exhausted')
                with self.assertRaisesRegex(ValueError,'quota'):D.scan(raw,time.monotonic()+10,guard)


if __name__=='__main__':unittest.main(verbosity=2)
