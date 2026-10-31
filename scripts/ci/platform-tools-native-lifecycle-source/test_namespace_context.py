"""New targeted namespace-context DATA controls; no native actor or kernel probe."""
import argparse,ast,copy,hashlib,importlib.util,io,json,os,re,stat,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
def deny(event,args):
    if event.startswith(('subprocess.','socket.'))or event in('os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','os.kill','os.killpg'):raise AssertionError('namespace DATA control actor denied')
sys.addaudithook(deny)
def need(value,why):
    if not value:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def selected(path,scope):
    tree=ast.parse(path.read_bytes());nodes=[]
    for n in tree.body:
        if isinstance(n,ast.FunctionDef)and(n.name.startswith('namespace_')or n.name in('retained_namespace_observation','observe_makepkg')):nodes.append(n)
        elif isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id.startswith('NAMESPACE_')for t in n.targets):nodes.append(n)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<trusted LOCAL namespace DATA functions>','exec'),scope);return scope
FIXED=Path('/opt/native-platform-tools-alpm-v1/source');SLOT=FIXED.parent/'build-current';MAP='a'*64
def observer():
    status=b'Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\n'+b''.join(n.encode()+b':\t0000000000000000\n'for n in('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))+b'NoNewPrivs:\t0\nSeccomp:\t2\nSeccomp_filters:\t1\n'
    inputs={'/proc/self/status':status,'/proc/self/uid_map':b'0 0 4294967295\n','/proc/self/gid_map':b'0 0 4294967295\n','/proc/self/attr/current':b'docker-default (enforce)\n',
        '/proc/sys/kernel/unprivileged_userns_clone':b'1\n','/proc/sys/user/max_user_namespaces':b'10000\n','/proc/sys/kernel/apparmor_restrict_unprivileged_userns':b'1\n',
        '/proc/self/mountinfo':b'1 2 0:3 /PRIVATE_SOURCE / rw,nosuid - overlay PRIVATE_SOURCE rw,lowerdir=PRIVATE_SOURCE\n2 1 0:4 / /proc rw,nosuid,nodev,noexec - proc proc rw\n'}
    reads=[]
    def read(path,cap):
        reads.append((path,cap));raw=inputs.get(path)
        return(None,'READ_ERRNO_2')if raw is None else(None,'BOUND')if len(raw)>cap else(raw,None)
    fakeos=types.SimpleNamespace(getuid=lambda:1000,geteuid=lambda:1000,getgid=lambda:1000,getegid=lambda:1000,getgroups=lambda:[1000],getcwd=lambda:str(SLOT),readlink=lambda p:Path(p).name+':[123]')
    binary=types.SimpleNamespace(lstat=lambda:types.SimpleNamespace(st_mode=stat.S_IFREG|0o755,st_uid=0,st_gid=0))
    scope=dict(Path=lambda p:binary if str(p)=='/usr/bin/bwrap'else Path(p),os=fakeos,stat=stat,re=re,json=json,need=need,ordinary=lambda *_:b'PUBLIC SYNTHETIC BWRAP BINARY',data_pin=pin)
    selected(HERE/'payload/native/platform_tools_v1.py',scope);scope['namespace_read']=read
    return scope,inputs,reads
def reader():
    scope=dict(Path=Path,re=re,json=json,need=need,pin=pin,platform_contract=lambda:dict(invocation=dict(source=str(FIXED))));selected(HERE/'producer-overlay/native/platform_reader_v1.py',scope);return scope
def case(raw_context=None):
    obs,_,_=observer();context=obs['namespace_context'](MAP)if raw_context is None else raw_context
    r=reader();raw=r['NAMESPACE_PREFIX']+json.dumps(context,sort_keys=True,separators=(',',':')).encode()+b'\nmakepkg DATA\nbwrap: No permissions to create a new namespace\n';name='003-build-a.log'
    argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(SLOT),'PKGDEST='+str(SLOT),'SRCDEST='+str(SLOT),'BUILDDIR='+str(SLOT),'SOURCE_DATE_EPOCH=1793145600','PACKAGER=cachy-asahi native TEST builder',
        '/usr/bin/python3','-I','-B',str(FIXED/'native/platform_alpm_v1.py'),'--observe-makepkg','--map-sha256',MAP,'--','/usr/bin/makepkg','--cleanbuild','--nodeps','--nosign','--noconfirm','--config',str(FIXED/'native/platform-makepkg-v1.conf')]
    command=dict(step='build-a',argv=argv,cwd=str(SLOT),expected=0,log=name,log_pin=pin(raw),supervision=dict(output_complete=True,group_census='EMPTY_TWICE',exit=4))
    files={'journey/platform-alpm-v1/result.json':dict(kind='file'),'journey/platform-alpm-v1/'+name:dict(kind='file',**pin(raw))}
    view=types.SimpleNamespace(load=lambda _:dict(commands=[command]),read=lambda _:raw)
    return r,context,raw,command,files,view
class Controls(unittest.TestCase):
    def test_observer_cli_keeps_exact_makepkg_remainder(self):
        tree=ast.parse((HERE/'producer-overlay/native/platform_alpm_v1.py').read_bytes())
        block=next(n for n in tree.body if isinstance(n,ast.If)and isinstance(n.test,ast.Compare)and isinstance(n.test.left,ast.Name)and n.test.left.id=='__name__')
        nodes=[]
        for n in block.body:
            if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='args'for t in n.targets):break
            nodes.append(n)
        scope=dict(argparse=argparse,__doc__='DATA parser only');exec(compile(ast.Module(body=nodes,type_ignores=[]),'<LOCAL argparse configuration>','exec'),scope)
        args=scope['parser'].parse_args(['--observe-makepkg','--map-sha256',MAP,'--','/usr/bin/makepkg','--cleanbuild'])
        self.assertEqual(args.makepkg_args,['--','/usr/bin/makepkg','--cleanbuild']);self.assertTrue(args.observe_makepkg)
        args=scope['parser'].parse_args(['--inside-image','--retain-failure-image','--map-sha256',MAP]);self.assertEqual(args.makepkg_args,[])
    def test_namespace_read_hard_bound_closes_and_discards_partial(self):
        scope,_,_=observer();source=ast.parse((HERE/'payload/native/platform_tools_v1.py').read_bytes());node=next(n for n in source.body if isinstance(n,ast.FunctionDef)and n.name=='namespace_read')
        stream=io.BytesIO(b'x'*65);closed=[];fake=types.SimpleNamespace(O_RDONLY=0,O_CLOEXEC=0,O_NOFOLLOW=0,O_NONBLOCK=0,open=lambda *_:9,fstat=lambda _:types.SimpleNamespace(st_mode=stat.S_IFREG),read=lambda _,n:stream.read(n),close=closed.append)
        values=dict(os=fake,stat=stat,need=need);exec(compile(ast.Module(body=[node],type_ignores=[]),'<LOCAL bounded read model>','exec'),values)
        self.assertEqual(values['namespace_read']('/proc/self/status',64),(None,'BOUND'));self.assertEqual(closed,[9])
    def test_observer_typed_context_and_reader(self):
        scope,_,reads=observer();value=scope['namespace_context'](MAP);self.assertEqual(reader()['namespace_context_document'](value,MAP,SLOT),value);self.assertEqual(len(reads),7+1)
    def test_unknown_policy_is_unknown_not_disabled(self):
        scope,inputs,_=observer();inputs.clear();value=scope['namespace_context'](MAP);reader()['namespace_context_document'](value,MAP,SLOT)
        self.assertTrue(all(v['status']=='UNKNOWN'for v in value['sysctls'].values()))
    def test_other_lsm_label_hash_only(self):
        scope,inputs,_=observer();inputs['/proc/self/attr/current']=b'PRIVATE_LABEL_EXAMPLE';value=scope['namespace_context'](MAP)
        self.assertEqual(value['lsm']['status'],'HASH_ONLY');self.assertNotIn('PRIVATE_LABEL_EXAMPLE',json.dumps(value));reader()['namespace_context_document'](value,MAP,SLOT)
    def test_mount_source_paths_never_exported(self):
        scope,_,_=observer();value=scope['namespace_context'](MAP);self.assertNotIn('PRIVATE_SOURCE',json.dumps(value));self.assertEqual(value['mounts']['/']['options'],['nosuid','rw'])
    def test_metadata_bound_does_not_export_partial(self):
        scope,inputs,_=observer();inputs['/proc/self/attr/current']=b'x'*257;value=scope['namespace_context'](MAP);self.assertEqual(value['lsm'],dict(status='UNKNOWN',reason='BOUND'))
    def test_groups_explicitly_truncated(self):
        scope,_,_=observer();scope['os'].getgroups=lambda:list(range(40));value=scope['namespace_context'](MAP);self.assertTrue(value['process']['groups_truncated']);self.assertEqual(len(value['process']['groups']),32);reader()['namespace_context_document'](value,MAP,SLOT)
    def test_changed_map_cwd_root_or_unknown_schema_refused(self):
        _,value,*_=case();r=reader()
        mutations=[lambda v:v.update(source_map_sha256='b'*64),lambda v:v.update(cwd='/wrong'),lambda v:v['process'].update(uid=0,euid=0),lambda v:v.update(extra='unbound')]
        for mutate in mutations:
            v=copy.deepcopy(value);mutate(v)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):r['namespace_context_document'](v,MAP,SLOT)
    def test_wrong_typed_fields_refused(self):
        _,value,*_=case();r=reader()
        for mutate in[lambda v:v['process'].update(uid=True),lambda v:v['status']['Seccomp'].update(value=False),lambda v:v['namespaces']['user'].update(value='other:[1]'),lambda v:v['lsm'].update(label='PRIVATE_LABEL'),lambda v:v['sysctls']['max_user_namespaces'].update(value=-1)]:
            v=copy.deepcopy(value);mutate(v)
            with self.assertRaises(ValueError):r['namespace_context_document'](v,MAP,SLOT)
    def test_source_bound_failure_context_and_errno_mapping(self):
        r,_,_,command,files,view=case();value=r['retained_namespace_observation'](view,files,MAP)
        self.assertTrue(value['builds'][0]['source_mapped_clone_EPERM_message']);self.assertEqual(value['builds'][0]['raw_syscall_trace'],'NOT_COLLECTED');self.assertEqual(value['builds'][0]['policy_cause'],'UNKNOWN');self.assertEqual(value['native'],'NOT_ADMITTED');self.assertEqual(command['supervision']['exit'],4)
    def test_missing_prefix_duplicate_or_suffix_only_refused(self):
        for mode in('missing','suffix','duplicate'):
            r,_,raw,command,files,view=case();raw=b'plain makepkg\n'if mode=='missing'else b'prefix\n'+raw if mode=='suffix'else raw+raw.splitlines(keepends=True)[0]
            command['log_pin']=pin(raw);files['journey/platform-alpm-v1/'+command['log']].update(pin(raw));view.read=lambda _,raw=raw:raw
            with self.subTest(mode=mode),self.assertRaises(ValueError):r['retained_namespace_observation'](view,files,MAP)
    def test_changed_or_incomplete_log_refused(self):
        for mode in('hash','incomplete'):
            r,_,_,command,files,view=case()
            if mode=='hash':command['log_pin']['sha256']='0'*64
            else:command['supervision']['output_complete']=False
            with self.subTest(mode=mode),self.assertRaises(ValueError):r['retained_namespace_observation'](view,files,MAP)
    def test_wrong_argv_or_expected_refused(self):
        for mode in('argv','expected'):
            r,_,_,command,files,view=case()
            if mode=='argv':command['argv'].append('--nocheck')
            else:command['expected']='nonzero'
            with self.subTest(mode=mode),self.assertRaises(ValueError):r['retained_namespace_observation'](view,files,MAP)
    def test_duplicate_or_noncanonical_context_refused(self):
        for mode in ('duplicate','spaces'):
            r,context,raw,command,files,view=case()
            encoded=json.dumps(context,sort_keys=True,separators=(',',':')).encode()
            if mode=='duplicate':encoded=b'{"schema":999,'+encoded[1:]
            else:encoded=json.dumps(context,sort_keys=True).encode()
            raw=r['NAMESPACE_PREFIX']+encoded+b'\nmakepkg DATA\n';command['log_pin']=pin(raw);files['journey/platform-alpm-v1/'+command['log']].update(pin(raw));view.read=lambda _,raw=raw:raw
            with self.subTest(mode=mode),self.assertRaises(ValueError):r['retained_namespace_observation'](view,files,MAP)
    def test_namespace_not_reached_is_explicit(self):
        self.assertEqual(reader()['retained_namespace_observation'](None,{},MAP)['status'],'NOT_REACHED_NAMESPACE_OBSERVATION')
    def test_wrapper_preserves_makepkg_argv_and_execs_same_pid_model(self):
        obs,_,_=observer();value=obs['namespace_context'](MAP);calls=[]
        class ExecModel(Exception):pass
        def execute(path,argv):calls.append((path,argv));raise ExecModel()
        env={key:str(SLOT)for key in('HOME','PKGDEST','SRCDEST','BUILDDIR')};env.update(SOURCE_DATE_EPOCH='1793145600',PACKAGER='cachy-asahi native TEST builder')
        binary=io.BytesIO();scope=dict(Path=Path,os=types.SimpleNamespace(getuid=lambda:1000,geteuid=lambda:1000,getgid=lambda:1000,getegid=lambda:1000,environ=env,execv=execute),pwd=types.SimpleNamespace(getpwnam=lambda _:types.SimpleNamespace(pw_uid=1000,pw_gid=1000)),PREFIX=FIXED.parent,SOURCE=FIXED,need=need,json=json,sys=types.SimpleNamespace(stdout=types.SimpleNamespace(buffer=binary)),T=types.SimpleNamespace(namespace_context=lambda _:value,NAMESPACE_PREFIX=obs['NAMESPACE_PREFIX']))
        selected(HERE/'producer-overlay/native/platform_alpm_v1.py',scope);argv=['/usr/bin/makepkg','--cleanbuild','--nodeps','--nosign','--noconfirm','--config',str(FIXED/'native/platform-makepkg-v1.conf')]
        with patch.dict(sys.modules,common=types.SimpleNamespace(verify_source=lambda *_:None)),patch.object(Path,'cwd',return_value=SLOT):
            with self.assertRaises(ExecModel):scope['observe_makepkg'](FIXED,MAP,argv)
            env['HOME']='/wrong'
            with self.assertRaises(ValueError):scope['observe_makepkg'](FIXED,MAP,argv)
        self.assertEqual(calls,[('/usr/bin/makepkg',argv)]);self.assertTrue(binary.getvalue().startswith(obs['NAMESPACE_PREFIX']))
    def test_new_factory_exact_source199_and_parent_inverse(self):
        spec=importlib.util.spec_from_file_location('_new_namespace_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
        basis=Path(os.environ['PLATFORM_NATIVE_BASIS']).absolute();profile,before,after=F.render(basis)
        self.assertEqual(len(after),199);self.assertEqual(len(json.loads(after['native/source-map.json'][0])['files']),198);self.assertEqual(F.git_tree(after),profile['source_tree'])
        inverse=dict(after)
        for n in set(after)|set(before):
            if n not in before:inverse.pop(n,None)
            elif after.get(n)!=before[n]:inverse[n]=before[n]
        self.assertEqual(inverse,before);self.assertEqual(F.git_tree(inverse),profile['parent_tree'])
if __name__=='__main__':unittest.main(verbosity=2)
