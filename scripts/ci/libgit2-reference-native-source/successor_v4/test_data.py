#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Eight actor-fenced Source-readonly controls; ordinary MODEL DATA only."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
OLD=HERE.parent/'owner'
NONCE='0123456789abcdef0123456789abcdef'
SHARED=dict(bytes=3052,sha256='55c58b6e15a73339f0c901a6d379f468e39e90e81a6602651942f35162a8e9d8')
ADAPTER=dict(bytes=1766,sha256='8078d7cdbae5d4a91470170f51160887d9810e84c5dad14dd5a4d6f9888beee7')
GUARD="    D.need(not os.access('/tmp',os.W_OK) and not os.access('/var/tmp',os.W_OK) and not os.access(root,os.W_OK),'actual owner writable filesystem restricted to quota work domain')"

def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn')) or event in ('os.system','os.pidfd_open','fcntl.flock','resource.setrlimit'):
        raise AssertionError('LIBGIT2_V4_DATA_NO_ACTOR: '+event)
sys.addaudithook(fence)

def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

P=module(HERE/'prepare.py','libgit2_v4_prepare_control')
P3=module(HERE.parent/'successor_v3/prepare.py','libgit2_v4_parent_control')
V=module(HERE.parent/'successor_v2/prepare.py','libgit2_v4_v2_control')
Q=module(HERE/'source_readonly.py','libgit2_v4_readonly_control')
D=module(OLD/'data.py','libgit2_v4_service_data_control')

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def bodies(root):return {str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}
def functions(tree):return {n.name:ast.dump(n,include_attributes=False) for n in ast.walk(tree) if isinstance(n,ast.FunctionDef)}

def projected():
    original={P.PREFIX+'hosted_owner.py':V.project((OLD/'hosted_owner.py').read_bytes()),P.PREFIX+'payload.py':(OLD/'payload.py').read_bytes()}
    old=dict(original);old.update(P3.projections(original)[0])
    code,seams=P.projections(old);return old,code,seams

class Controls(unittest.TestCase):
    def setUp(self):
        area=tempfile.TemporaryDirectory(prefix='libgit2-v4-namespace-MODEL-')
        self.addCleanup(area.cleanup);self.base=Path(area.name)
        self.root,self.out=self.base/'MODEL_SOURCE',self.base/'MODEL_OWNED'
        self.root.mkdir();self.out.mkdir()

    def argv(self,kind='owner'):
        limits=dict(memory_bytes=2147483648,AS_bytes=2147483648,cpus=1,pids=256)
        args=D.service_args(NONCE,kind,limits,['/usr/bin/python3',str(self.root/'MODEL_payload.py'),'--MODEL-DATA'],self.out/'volume'/(kind+'.log'),1000,1000)
        args.insert(3,'--description=cachy-libgit2-reference-owned-'+NONCE+'-'+kind)
        return args

    def model(self):
        cls=type(self)
        if hasattr(cls,'model_fixture'):return cls.model_fixture
        names=('LIBGIT2_CONSUMER_ROOT','LIBGIT2_DATA_RECIPE_ROOT','LIBGIT2_DATA_ARCHIVE','LLHTTP_DATA_ARCHIVE')
        values={n:os.environ.get(n) for n in names}
        if not all(values.values()):self.skipTest('explicit frozen consumer, genuine original recipe and source DATA required')
        area=tempfile.TemporaryDirectory(prefix='libgit2-v4-full-Source-MODEL-',dir='/home/gabe/.cache')
        cls.addClassCleanup(area.cleanup);root=Path(area.name)
        I=module(HERE.parent/'test_interop.py','libgit2_v4_interop_model_fixture')
        A=module(HERE.parent/'prepare.py','libgit2_v4_original_constructor')
        consumer=Path(values['LIBGIT2_CONSUMER_ROOT']);f=I.fixture(root/'MODEL-operands',consumer)
        base=root/'MODEL-original83-Source'
        r0=A.construct(ROOT,Path(values['LIBGIT2_DATA_RECIPE_ROOT']),Path(values['LIBGIT2_DATA_ARCHIVE']),base,dependency_paths=f.paths,dependency_expected=f.expected,consumer_root=consumer)
        v2=root/'MODEL-v2-Source';r2=V.construct(base,r0['source_map']['sha256'],v2)
        parent=root/'MODEL-v3-Source';r3=P3.construct(v2,r2['source_map']['sha256'],parent)
        output=root/'MODEL-v4-Source';r4=P.construct(parent,r3['source_map']['sha256'],output)
        for result in (r0,r2,r3,r4):
            self.assertTrue(all(v is None for v in result['actual'].values()))
            self.assertEqual(result.get('native_build',result.get('native_pair')),'NOT RUN')
        cls.model_fixture=dict(root=root,base=base,v2=v2,parent=parent,output=output,results=(r0,r2,r3,r4),old=bodies(parent),new=bodies(output))
        return cls.model_fixture

    def test_exact_shared_bytes_and_one_namespace_literal_whole_inverse(self):
        raw=(HERE/'source_readonly_shared.py').read_bytes()
        self.assertEqual(pin(raw),SHARED);self.assertEqual(pin((HERE/'source_readonly.py').read_bytes()),ADAPTER)
        self.assertEqual(Q.SHARED_PIN,SHARED);self.assertEqual(len(Q.EDITS),1)
        before=b'/sys/fs/cgroup/system.slice/cachy-llhttp-reference-'
        after=b'/sys/fs/cgroup/system.slice/cachy-libgit2-reference-'
        adapted=Q.project(raw)
        self.assertEqual(raw.count(before),1);self.assertEqual(adapted.count(after),1)
        self.assertEqual(adapted,raw.replace(before,after));self.assertEqual(adapted.replace(after,before),raw)
        self.assertEqual(Q.DECLARATION['kind'],'LLHTTP_EXACT_SOURCE_READONLY_NAMESPACE_V5')
        for wrong in (raw+b'\nCHANGED',raw.replace(before,after),raw[:-1]):
            with self.subTest(bytes=len(wrong)),self.assertRaises(ValueError):Q.project(wrong)

    def test_matching_omission_only_start_seam_and_unchanged_payload_guard(self):
        old,code,seams=projected();key=P.PREFIX+'hosted_owner.py'
        self.assertEqual(set(code),{key});self.assertNotIn('BindReadOnlyPaths',old[key].decode())
        self.assertNotIn('BindReadOnlyPaths',(OLD/'data.py').read_text())
        for kind in ('owner','daemon'):
            args=self.argv(kind)
            self.assertIn('--property=ProtectSystem=strict',args)
            self.assertIn('--property=ReadOnlyPaths=/tmp /var/tmp /sys/fs/cgroup',args)
            self.assertFalse(any(a.startswith('--property=BindReadOnlyPaths=') for a in args))
        restored=code[key].decode()
        for seam in reversed(seams[key]):
            self.assertEqual(restored.count(seam['after']),1);restored=restored.replace(seam['after'],seam['before'])
        self.assertEqual(restored.encode(),old[key])
        before,after=ast.parse(old[key]),ast.parse(code[key]);saved=copy.deepcopy(after)
        start=next(n for n in ast.walk(after) if isinstance(n,ast.FunctionDef) and n.name=='start')
        index,call=next((i,n) for i,n in enumerate(start.body) if isinstance(n,ast.Assign) and isinstance(n.value,ast.Call) and ast.unparse(n.value.func)=='Q.project_service')
        self.assertEqual(ast.unparse(call),'argv = Q.project_service(argv, self.root, self.out, self.nonce, kind)')
        self.assertIn('argv.insert',ast.unparse(start.body[index-1]))
        self.assertEqual(ast.unparse(start.body[index+1]),'self.units[kind] = dict(submitted=True, cgroup=None)')
        self.assertEqual(ast.unparse(start.body[index+2]),'self.run(argv)');start.body.pop(index)
        after.body=[n for n in after.body if not (
            isinstance(n,ast.Assign) and (any(isinstance(t,ast.Name) and t.id=='Q' for t in n.targets) or isinstance(n.value,ast.Call) and 'source_readonly' in ast.unparse(n.value)))
            and not (isinstance(n,ast.Expr) and 'exec_module(Q)' in ast.unparse(n))]
        self.assertEqual(ast.dump(after),ast.dump(before))
        protected=functions(before);changed=functions(saved)
        self.assertEqual({k:v for k,v in protected.items() if k!='start'},{k:v for k,v in changed.items() if k!='start'})
        self.assertEqual(old[P.PREFIX+'payload.py'].decode().count(GUARD),1)
        node=compile(ast.parse(GUARD.strip()),'<unchanged-libgit2-guard-MODEL>','exec')
        def need(ok,why):
            if not ok:raise ValueError(why)
        for writable in (None,'/tmp','/var/tmp',self.root):
            observed=[]
            def access(path,mode):observed.append((path,mode));return path==writable
            scope=dict(D=types.SimpleNamespace(need=need),root=self.root,os=types.SimpleNamespace(access=access,W_OK=os.W_OK))
            with self.subTest(writable=str(writable)):
                if writable is None:
                    exec(node,scope);self.assertEqual([p for p,_ in observed],['/tmp','/var/tmp',self.root])
                else:
                    with self.assertRaisesRegex(ValueError,'^actual owner writable filesystem restricted to quota work domain$'):exec(node,scope)
                self.assertTrue(all(mode==os.W_OK for _,mode in observed))

    def test_both_service_exact_source_bind_preserves_all_existing_argv(self):
        for kind in ('owner','daemon'):
            with self.subTest(kind=kind):
                before=self.argv(kind);saved=before[:];boundary=before.index('--')
                after=Q.project_service(before,self.root,self.out,NONCE,kind)
                self.assertIsNot(after,before);self.assertEqual(before,saved)
                self.assertEqual(after,before[:boundary]+['--property=BindReadOnlyPaths='+str(self.root)]+before[boundary:])
                for prefix in ('--property=ReadWritePaths=','--property=ReadOnlyPaths=','--property=ProtectSystem='):
                    self.assertEqual([a for a in after if a.startswith(prefix)],[a for a in before if a.startswith(prefix)])

    def test_alias_file_overlap_noncanonical_path_and_service_refusals(self):
        alias=self.base/'MODEL_ALIAS';alias.symlink_to(self.root,target_is_directory=True)
        file=self.base/'MODEL_FILE';file.write_bytes(b'ordinary DATA')
        cases=((alias,self.out),(self.root,alias),(self.root,self.root),(self.root,self.root/'nested'),(self.out/'nested',self.out),
               ('relative',self.out),(self.root,'relative'),('/',self.out),(str(self.root)+'/../MODEL_SOURCE',self.out),
               (str(self.root)+'//',self.out),(str(self.root)+'/.',self.out),(self.root,str(self.out)+'/'),
               (self.root,str(self.out)+'//nested'),(file,self.out),(self.root,file),(str(self.root)+' bad',self.out),
               (str(self.root)+':/override',self.out))
        for root,out in cases:
            with self.subTest(root=str(root),out=str(out)),self.assertRaises(ValueError):Q.project_service(self.argv(),root,out,NONCE,'owner')
        for kind,nonce in (('other',NONCE),('',NONCE),('OWNER',NONCE),('owner','invalid'),('daemon','A'*32)):
            with self.subTest(kind=kind,nonce=nonce),self.assertRaises(ValueError):Q.project_service(self.argv(),self.root,self.out,nonce,kind)

    def test_conflicting_duplicate_bind_root_and_tmp_override_refusals(self):
        forbidden=('BindPaths','BindReadOnlyPaths','ReadWriteDirectories','ReadOnlyDirectories','RootDirectory','RootImage','TemporaryFileSystem')
        for kind in ('owner','daemon'):
            args=self.argv(kind);boundary=args.index('--')
            props=[a for a in args if a.startswith(('--property=ProtectSystem=','--property=ReadOnlyPaths=','--property=ReadWritePaths='))]
            bad=[args+['--'],args[:boundary],tuple(args),args[:10],args[:boundary]+['']+args[boundary:]]
            for key,value in (('ReadWritePaths',str(self.root)),('ProtectSystem','false'),('ReadOnlyPaths','/tmp /var/tmp')):
                bad.append(['--property='+key+'='+value if a.startswith('--property='+key+'=') else a for a in args])
                bad.append([a for a in args if not a.startswith('--property='+key+'=')])
            for extra in props+['--property='+k+'='+str(self.root) for k in forbidden]:bad.append(args[:boundary]+[extra]+args[boundary:])
            for value in bad:
                with self.subTest(kind=kind,argv=value),self.assertRaises(ValueError):Q.project_service(value,self.root,self.out,NONCE,kind)

    def test_full_model_v3_v2_original83_inverse_program_policy_and_docs(self):
        f=self.model();old,new=f['old'],f['new'];r0,r2,r3,r4=f['results']
        self.assertEqual(P.parent_bodies(f['parent'],r3['source_map']['sha256'])[0],old)
        self.assertEqual(P.inverse(new,r3['source_map']['sha256']),old)
        prior=P3.inverse(old,r2['source_map']['sha256']);self.assertEqual(prior,bodies(f['v2']))
        original=V.inverse(prior,r0['source_map']['sha256']);self.assertEqual(original,bodies(f['base']))
        self.assertEqual(V.proof()['author'],'83d95b33210483887fc0f423ec12008208cbc0be')
        self.assertEqual(r4['tree'],V.tree(new));self.assertEqual(r4['parent_Source'],'UNBOUND')
        self.assertIsNone(r4['Root_acceptance']);marker=json.loads(new[P.MARKER])
        for name in ('actual','actual_dependency_tuple','Root_roles','Root_output','Root_acceptance'):self.assertIsNone(marker[name])
        self.assertEqual(marker['actual_namespace_effect'],'NOT RUN')
        for name,raw in old.items():
            if name not in set(P.CHANGED)|{'source-map.json'}:self.assertEqual(new[name],raw,name)
        policy=json.loads(new[P.PREFIX+'policy.json']);before=json.loads(old[P.PREFIX+'policy.json'])
        added=set(policy)-set(before);self.assertEqual(len(added),1)
        self.assertEqual(policy.pop(added.pop()),Q.DECLARATION);self.assertEqual(policy,before)
        for name in ('source-map.json',P.PREFIX+'owner-program.json'):
            row=json.loads(new[name]);self.assertEqual(new[name],V.encode(row))
            for leaf,wanted in row['files'].items():self.assertEqual(wanted,dict(pin(new[leaf]),mode=0o644))
        program=json.loads(new[P.PREFIX+'owner-program.json'])
        self.assertEqual(program['base_source_map_sha256'],json.loads(old[P.PREFIX+'owner-program.json'])['base_source_map_sha256'])
        for helper in ('source_readonly.py','source_readonly_shared.py'):
            leaf=P.PREFIX+helper;self.assertEqual(new[leaf],(HERE/helper).read_bytes());self.assertIn(leaf,program['files'])
        self.assertEqual(new[P.NEXT+'README.md'],(HERE/'README.md').read_bytes())
        self.assertEqual(new[P.NEXT+'predecessor-pin.json'],(HERE/'predecessor-pin.json').read_bytes())
        self.assertIn('UNBOUND',(HERE/'README.md').read_text());self.assertIn('new actual libgit2 attempt',(HERE/'README.md').read_text())

    def test_complete_inverse_rejects_actor_guard_helper_ancestry_and_metadata_tamper(self):
        f=self.model();new=f['new'];sha=f['results'][2]['source_map']['sha256']
        leaves=[P.PREFIX+n for n in ('hosted_owner.py','payload.py','data.py','policy.json','owner-program.json','source_readonly.py','source_readonly_shared.py','go_cli_va.py','failed_retirement.py')]
        leaves += [P.MARKER,'source-map.json',P.NEXT+'README.md',P.NEXT+'predecessor-pin.json']
        leaves += [n for n in new if n.startswith(('previous-v3/','previous-v2/','previous-v1/')) and n.endswith('source-map.json')]
        self.assertIn('previous-v3/source-map.json',leaves)
        for leaf in leaves:
            wrong=dict(new);wrong[leaf]+=b'\nCHANGED DATA\n'
            with self.subTest(leaf=leaf),self.assertRaises(ValueError):P.inverse(wrong,sha)
        for leaf,key,value in ((P.MARKER,'actual','UNAUTHORIZED_MODEL_ACTUAL'),(P.PREFIX+'policy.json','source_readonly_namespace',{})):
            wrong=dict(new);row=json.loads(wrong[leaf]);row[key]=value;wrong[leaf]=V.encode(row)
            with self.subTest(leaf=leaf,key=key),self.assertRaises(ValueError):P.inverse(wrong,sha)
        wrong=dict(new);wrong['undeclared-extra']=b'MODEL'
        with self.assertRaises(ValueError):P.inverse(wrong,sha)
        with self.assertRaises(ValueError):P.inverse(new,'0'*64)

    def test_external_parent_map_modes_physical_namespace_and_projection_drift_refuse(self):
        old,_,seams=projected()
        for name,edits in seams.items():
            for seam in edits:
                wrong=dict(old);wrong[name]=old[name].replace(seam['before'].encode(),b'CHANGED_ANCHOR',1)
                with self.subTest(seam=seam['before']),self.assertRaises(ValueError):P.projections(wrong)
        f=self.model();parent=f['parent'];sha=f['results'][2]['source_map']['sha256'];output=f['root']/'wrong-output'
        with self.assertRaises(ValueError):P.construct(parent,'0'*64,output)
        self.assertFalse(output.exists())
        for path in (parent/'source-map.json',parent/P.PREFIX/'hosted_owner.py'):
            try:
                path.chmod(0o600)
                with self.subTest(path=str(path)),self.assertRaises(ValueError):P.parent_bodies(parent,sha)
            finally:path.chmod(0o644)
        actor=parent/P.PREFIX/'hosted_owner.py';saved=actor.read_bytes()
        try:
            actor.write_bytes(saved+b'\n# altered actor\n')
            with self.assertRaises(ValueError):P.parent_bodies(parent,sha)
        finally:actor.write_bytes(saved)
        extra=parent/'undeclared-extra'
        try:
            extra.write_bytes(b'MODEL')
            with self.assertRaises(ValueError):P.parent_bodies(parent,sha)
        finally:extra.unlink()
        alias=f['root']/'MODEL_PARENT_ALIAS';alias.symlink_to(parent,target_is_directory=True)
        with self.assertRaises(ValueError):P.parent_bodies(alias,sha)
        with self.assertRaises(ValueError):P.construct(parent,sha,parent/'nested-output')
        self.assertFalse((parent/'nested-output').exists())

if __name__=='__main__':unittest.main(verbosity=2)
