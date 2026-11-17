#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Actor-fenced phase/retirement controls; MOCK PIDFD and MODEL Sources only."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
OLD=HERE.parent/'owner'
NONCE='a'*32
UNIT='cachy-libgit2-reference-'+NONCE+'-owner.service'
GROUP='/system.slice/'+UNIT
PINS={'payload_diagnostic.py':dict(bytes=1564,sha256='18592a89eb5c6cc7fd182167a37d566dbfa098647167e2a67180083927f1517a'),
      'failed_retirement.py':dict(bytes=4165,sha256='95fc52f8a6c610ae165eecfe959cc696c210fa0fd3238bd9b24c9d5ffbcf9df1')}

def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn')) or event in ('os.system','os.pidfd_open','fcntl.flock','resource.setrlimit'):
        raise AssertionError('LIBGIT2_V3_DATA_NO_ACTOR: '+event)
sys.addaudithook(fence)

def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

P=module(HERE/'prepare.py','libgit2_v3_prepare_control')
V=module(HERE.parent/'successor_v2/prepare.py','libgit2_v3_parent_control')
X=module(HERE/'payload_diagnostic.py','libgit2_v3_diagnostic_control')
F=module(HERE/'namespace_adapter.py','libgit2_v3_namespace_control')

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def fixture():
    owned=dict(submitted=True,pid=123,starttime=456,cgroup=GROUP,original_pidfd=7,original_pidfd_identity=dict(dev=1,inode=2))
    row=dict(Description='cachy-libgit2-reference-owned-'+NONCE+'-owner',LoadState='loaded',ActiveState='failed',SubState='failed',MainPID='0',ControlGroup='',Result='exit-code',ExecMainCode='1',ExecMainStatus='2')
    census=[dict(cgroup=GROUP,path_present=False,events_empty=True,procs_empty=True,pidfd_exited=True) for _ in range(2)]
    return owned,row,census

def projected():
    # Only frozen source bodies are projected here. No Source/actual admission is invented.
    old={P.PREFIX+'hosted_owner.py':V.project((OLD/'hosted_owner.py').read_bytes()),P.PREFIX+'payload.py':(OLD/'payload.py').read_bytes()}
    code,seams=P.projections(old);return old,code,seams

def function(tree,name):
    return next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name==name)

class Controls(unittest.TestCase):
    def test_exact_shared_helpers_and_bounded_private_phase_hashes(self):
        for name,wanted in PINS.items():self.assertEqual(pin((HERE/name).read_bytes()),wanted)
        raw=(HERE/'failed_retirement.py').read_bytes();adapted=F.project(raw)
        self.assertEqual(adapted.replace(b'cachy-libgit2-reference-',b'cachy-llhttp-reference-'),raw)
        self.assertEqual(adapted.count(b'cachy-libgit2-reference-'),2)
        with self.assertRaises(ValueError):F.project(raw+b'\nCHANGED')
        self.assertEqual(F.DECLARATION['kind'],'LLHTTP_OWNED_FAILED_OWNER_RETIREMENT_V3')
        self.assertEqual(X.DECLARATION['kind'],'LLHTTP_PAYLOAD_PHASE_HASH_ONLY_V3')
        private='PRIVATE_ENV_TOKEN_AND_PATH=/private/unpublished/value'
        for phase in X.PHASES:
            X.phase(phase);text=X.record(ValueError(private));row=json.loads(text.removeprefix('HOLD_PAYLOAD: '))
            self.assertLessEqual(len((text+'\n').encode()),512);self.assertNotIn(private,text)
            self.assertEqual(row['phase'],phase);self.assertEqual(row['message_bytes'],len(private.encode()))
            self.assertEqual(row['message_prefix_sha256'],hashlib.sha256(private.encode()).hexdigest())
            self.assertFalse(row['truncated'])
        X.phase('entry');text=X.record(ValueError(private*1000));row=json.loads(text.removeprefix('HOLD_PAYLOAD: '))
        self.assertTrue(row['truncated']);self.assertEqual(row['message_prefix_bytes'],8192)
        self.assertEqual(row['message_prefix_sha256'],hashlib.sha256((private*1000).encode()[:8192]).hexdigest());self.assertNotIn(private,text)
        error=type('PRIVATE_CUSTOM_EXCEPTION_NAME',(Exception,),{})(private)
        self.assertEqual(json.loads(X.record(error).removeprefix('HOLD_PAYLOAD: '))['exception'],'OTHER')
        with self.assertRaises(ValueError):X.phase(private)

    def test_mock_already_failed_owner_retires_without_payload_success(self):
        owned,row,census=fixture()
        for status in ('1','2','255'):
            current=dict(row,ExecMainStatus=status)
            with patch.object(F,'pidfd_exited',return_value=True) as poll:result=F.retire_failed('owner',NONCE,owned,current,current,7,census)
            poll.assert_called_once_with(7,owned['original_pidfd_identity'])
            self.assertEqual(result['unit'],UNIT);self.assertEqual(result['retirement'],'STOPPED_EMPTY_FAILED_OWNER')
            self.assertIs(result['payload_success'],False);self.assertEqual(result['payload_exit'],int(status));self.assertIs(result['unit_reset'],False)

    def test_strict_failed_owner_identity_state_and_census_refusals(self):
        modes=('active-before','active-after','description','unit-cgroup','missing-pid','missing-start','pidfd-ledger','pidfd-identity','missing-pidfd','zero-exit','large-exit','signal-exit','changed-exit','one-census','nonempty-events','nonempty-procs','foreign-census','live-census','unknown-unit','daemon','nonce')
        for mode in modes:
            owned,before,census=fixture();after=copy.deepcopy(before);fd=7;kind='owner';nonce=NONCE
            if mode=='active-before':before.update(ActiveState='active',SubState='running',MainPID='123',ControlGroup=GROUP)
            elif mode=='active-after':after['ActiveState']='active'
            elif mode=='description':after['Description']='foreign'
            elif mode=='unit-cgroup':owned['cgroup']='/foreign'
            elif mode=='missing-pid':owned.pop('pid')
            elif mode=='missing-start':owned.pop('starttime')
            elif mode=='pidfd-ledger':owned['original_pidfd']=8
            elif mode=='pidfd-identity':owned.pop('original_pidfd_identity')
            elif mode=='missing-pidfd':fd=None
            elif mode=='zero-exit':after['ExecMainStatus']='0'
            elif mode=='large-exit':after['ExecMainStatus']='256'
            elif mode=='signal-exit':after['ExecMainCode']='2'
            elif mode=='changed-exit':after['ExecMainStatus']='3'
            elif mode=='one-census':census.pop()
            elif mode=='nonempty-events':census[1]['events_empty']=False
            elif mode=='nonempty-procs':census[1]['procs_empty']=False
            elif mode=='foreign-census':census[1]['cgroup']='/foreign'
            elif mode=='live-census':census[1]['pidfd_exited']=False
            elif mode=='unknown-unit':after['LoadState']='not-found'
            elif mode=='daemon':kind='daemon'
            else:nonce='foreign'
            with self.subTest(mode=mode),patch.object(F,'pidfd_exited',return_value=True),self.assertRaises(ValueError):F.retire_failed(kind,nonce,owned,before,after,fd,census)
        owned,row,census=fixture()
        with patch.object(F,'pidfd_exited',return_value=False),self.assertRaises(ValueError):F.retire_failed('owner',NONCE,owned,row,row,7,census)

    def test_bounded_ordinary_file_cgroup_models_and_unknown_refusals(self):
        with tempfile.TemporaryDirectory(prefix='libgit2-v3-cgroup-MODEL-') as name:
            path=Path(name);events=path/'cgroup.events';procs=path/'cgroup.procs'
            events.write_bytes(b'populated 0\nfrozen 0\n');procs.write_bytes(b'')
            self.assertTrue(F.empty_snapshot(path)['events_empty'])
            procs.write_bytes(b'123\n')
            with self.assertRaises(ValueError):F.empty_snapshot(path)
            procs.write_bytes(b'')
            for raw in (b'populated 1\n',b'unknown 0\n',b'populated 1\npopulated 0\n',b'populated 0 extra\n',b'x'*65537):
                events.write_bytes(raw)
                with self.subTest(raw_bytes=len(raw)),self.assertRaises(ValueError):F.empty_snapshot(path)
            self.assertFalse(F.empty_snapshot(path/'missing')['path_present'])
            with patch.object(Path,'lstat',side_effect=PermissionError('unknown census access')),self.assertRaises(PermissionError):F.empty_snapshot(path)

    def test_complete_projection_inverse_and_protected_functions(self):
        old,code,seams=projected()
        for name,raw in code.items():
            text=raw.decode()
            for seam in reversed(seams[name]):self.assertEqual(text.count(seam['after']),1);text=text.replace(seam['after'],seam['before'])
            self.assertEqual(text.encode(),old[name])
        before=ast.parse(old[P.PREFIX+'hosted_owner.py']);after=ast.parse(code[P.PREFIX+'hosted_owner.py'])
        for name in ('cleanup','run','main','setup','preflight','capacity','docker','loop_identity','record_host_policy'):
            with self.subTest(function=name):self.assertEqual(ast.dump(function(before,name)),ast.dump(function(after,name)))
        text=code[P.PREFIX+'hosted_owner.py'].decode()
        self.assertNotIn('reset-failed',text);self.assertIn("'ordinary payload natural success required'",text)
        payload_before=function(ast.parse(old[P.PREFIX+'payload.py']),'main');payload_after=function(ast.parse(code[P.PREFIX+'payload.py']),'main')
        class StripPhases(ast.NodeTransformer):
            def visit_Expr(self,node):
                call=node.value
                if isinstance(call,ast.Call) and isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Name) and call.func.value.id=='X' and call.func.attr=='phase':return None
                return self.generic_visit(node)
        self.assertEqual(ast.dump(payload_before),ast.dump(StripPhases().visit(payload_after)))
        for name in old:
            for seam in seams[name]:
                wrong=dict(old);wrong[name]=old[name].replace(seam['before'].encode(),b'CHANGED_ANCHOR',1)
                with self.subTest(name=name),self.assertRaises(ValueError):P.projections(wrong)

    def test_actual_projected_stop_function_with_mock_pidfd_and_rows(self):
        _,code,_=projected();node=function(ast.parse(code[P.PREFIX+'hosted_owner.py']),'stop')
        D=module(OLD/'data.py','libgit2_v3_stop_model_data')
        scope=dict(D=D,F=F,Path=Path,time=type('Clock',(),{'sleep':staticmethod(lambda _:None)}))
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<projected-stop-MODEL>','exec'),scope)
        for mode in ('failed','active','active-to-failed','foreign','missing-custody','success','absent'):
            owned,before,_=fixture();after=copy.deepcopy(before);commands=[]
            if mode in ('active','active-to-failed'):before.update(ActiveState='active',SubState='running',MainPID='123',ControlGroup=GROUP)
            if mode=='active':after=copy.deepcopy(before)
            if mode=='foreign':before['Description']='foreign'
            if mode=='missing-custody':owned.pop('original_pidfd')
            if mode=='success':before.update(ActiveState='inactive',SubState='dead',Result='success',ExecMainStatus='0');after=copy.deepcopy(before)
            model=type('ControllerModel',(),{})();model.nonce=NONCE;model.units={} if mode=='absent' else {'owner':owned};model.pidfds={'owner':7}
            rows=iter((before,after,after));model.show=lambda _:copy.deepcopy(next(rows));model.tool=lambda _: '/usr/bin/systemctl';model.run=lambda argv,seconds:commands.append(argv)
            with self.subTest(mode=mode),patch.object(F,'empty_snapshot',return_value=dict(path_present=False,events_empty=True,procs_empty=True)),patch.object(F,'pidfd_exited',return_value=True):
                if mode=='failed':
                    result=scope['stop'](model,'owner');self.assertIs(result['payload_success'],False);self.assertEqual(commands,[['/usr/bin/systemctl','stop',UNIT]])
                elif mode=='success':self.assertEqual(scope['stop'](model,'owner')['result'],'success')
                elif mode=='absent':self.assertEqual(scope['stop'](model,'owner'),dict(submitted=False));self.assertEqual(commands,[])
                else:
                    with self.assertRaises(ValueError):scope['stop'](model,'owner')
                    if mode=='foreign':self.assertEqual(commands,[])

    def make_model_parent(self,root):
        names=('LIBGIT2_CONSUMER_ROOT','LIBGIT2_DATA_RECIPE_ROOT','LIBGIT2_DATA_ARCHIVE','LLHTTP_DATA_ARCHIVE');values={n:os.environ.get(n) for n in names}
        if not all(values.values()):self.skipTest('explicit frozen consumer, genuine original recipe and source DATA required')
        I=module(HERE.parent/'test_interop.py','libgit2_v3_parent_model_fixture');A=module(HERE.parent/'prepare.py','libgit2_v3_original_constructor')
        consumer=Path(values['LIBGIT2_CONSUMER_ROOT']);f=I.fixture(root/'MODEL-operands',consumer);base=root/'MODEL-original-Source'
        result=A.construct(ROOT,Path(values['LIBGIT2_DATA_RECIPE_ROOT']),Path(values['LIBGIT2_DATA_ARCHIVE']),base,dependency_paths=f.paths,dependency_expected=f.expected,consumer_root=consumer)
        self.assertEqual(result['native_build'],'NOT RUN');self.assertTrue(all(v is None for v in result['actual'].values()))
        parent=root/'MODEL-v2-Source';result=V.construct(base,result['source_map']['sha256'],parent)
        self.assertEqual(result['native_build'],'NOT RUN');self.assertTrue(all(v is None for v in result['actual'].values()))
        return parent,result

    def test_model_full_parent_inverse_program_policy_and_integrity_refusals(self):
        with tempfile.TemporaryDirectory(prefix='libgit2-v3-Source-MODEL-',dir='/home/gabe/.cache') as name:
            root=Path(name);parent,parent_result=self.make_model_parent(root);sha=parent_result['source_map']['sha256']
            original,_=P.parent_bodies(parent,sha);out=root/'MODEL-v3-Source';result=P.construct(parent,sha,out)
            bodies={str(p.relative_to(out)):p.read_bytes() for p in out.rglob('*') if p.is_file()}
            self.assertEqual(P.inverse(bodies),original);self.assertEqual(result['tree'],V.tree(bodies));self.assertTrue(all(v is None for v in result['actual'].values()))
            self.assertIsNone(json.loads(bodies[P.MARKER])['actual'])
            for name,raw in original.items():
                if name not in set(P.CHANGED)|{'source-map.json'}:self.assertEqual(bodies[name],raw)
            policy=json.loads(bodies[P.PREFIX+'policy.json'])
            self.assertEqual(policy.pop('payload_diagnostics'),X.DECLARATION);self.assertEqual(policy.pop('failed_owner_retirement'),F.DECLARATION)
            self.assertEqual(policy,json.loads(original[P.PREFIX+'policy.json']))
            program=json.loads(bodies[P.PREFIX+'owner-program.json'])
            self.assertEqual(program['base_source_map_sha256'],json.loads(original[P.PREFIX+'owner-program.json'])['base_source_map_sha256'])
            for helper in P.HELPERS:self.assertEqual(program['files'][P.PREFIX+helper],dict(pin(bodies[P.PREFIX+helper]),mode=0o644))
            leaves=[P.PREFIX+n for n in P.HELPERS]+[P.PREFIX+'hosted_owner.py',P.PREFIX+'payload.py',P.PREFIX+'policy.json',P.PREFIX+'owner-program.json',P.MARKER,'source-map.json','previous-v2/source-map.json']
            for leaf in leaves:
                wrong=dict(bodies);wrong[leaf]+=b'\nCHANGED'
                with self.subTest(leaf=leaf),self.assertRaises(ValueError):P.inverse(wrong)
            for leaf,key,value in ((P.MARKER,'actual','UNAUTHORIZED_MODEL_ACTUAL'),(P.PREFIX+'policy.json','failed_owner_retirement',{})):
                wrong=dict(bodies);row=json.loads(wrong[leaf]);row[key]=value;wrong[leaf]=json.dumps(row).encode()
                with self.assertRaises(ValueError):P.inverse(wrong)
            wrong=dict(bodies);row=json.loads(wrong[P.PREFIX+'policy.json']);row['controller']['memory_bytes']=2147483648;wrong[P.PREFIX+'policy.json']=json.dumps(row).encode()
            with self.assertRaises(ValueError):P.inverse(wrong)
            wrong=dict(bodies);wrong['undeclared-extra']=b'MODEL'
            with self.assertRaises(ValueError):P.inverse(wrong)
        self.assertFalse(out.exists());self.assertFalse(parent.exists())

    def test_parent_external_map_modes_and_static_actor_tampering_refuse(self):
        with tempfile.TemporaryDirectory(prefix='libgit2-v3-refusal-MODEL-',dir='/home/gabe/.cache') as name:
            root=Path(name);empty=root/'empty';empty.mkdir();(empty/'source-map.json').write_text('{}\n')
            with self.assertRaises(ValueError):P.parent_bodies(empty,'0'*64)
            parent,result=self.make_model_parent(root);sha=result['source_map']['sha256'];out=root/'wrong-Source'
            with self.assertRaises(ValueError):P.construct(parent,'0'*64,out)
            self.assertFalse(out.exists());source_map=parent/'source-map.json';source_map.chmod(0o600)
            with self.assertRaises(ValueError):P.parent_bodies(parent,sha)
            source_map.chmod(0o644);leaf=parent/P.PREFIX/'hosted_owner.py';raw=leaf.read_bytes();leaf.write_bytes(raw+b'\n# altered actor\n')
            with self.assertRaises(ValueError):P.parent_bodies(parent,sha)
            leaf.write_bytes(raw);leaf.chmod(0o666)
            with self.assertRaises(ValueError):P.parent_bodies(parent,sha)

if __name__=='__main__':unittest.main(verbosity=2)
