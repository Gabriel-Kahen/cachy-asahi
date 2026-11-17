#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Actor-fenced finite Docker-VA bindings; MODEL Source gives no authority."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
OLD=HERE.parent/'owner'
HELPER_PIN=dict(bytes=1996,sha256='3b2feba315f3a0e4cfed2498160e75591d64c7b8f0e8f5c11b46321b04b5eff3')
DECLARATION=dict(kind='OBSERVED_DOCKER_CLI_FINITE_VA_V1',normal_controller_AS_bytes=536870912,
    normal_child_AS_bytes=536870912,docker_cli_AS_bytes=2147483648,
    allowed_canonical_paths=['/usr/bin/docker','/usr/sbin/docker'],
    executable_observation_required=True,physical_cgroup_limits_unchanged=True)

def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn')) or event in ('os.system','os.pidfd_open','fcntl.flock','resource.setrlimit'):
        raise AssertionError('FINITE_VA_DATA_NO_ACTOR: '+event)
sys.addaudithook(fence)

def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

P=module(HERE/'prepare.py','libgit2_va_prepare_control')
V=module(HERE/'go_cli_va.py','libgit2_va_helper_control')

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def policy():
    value=json.loads((OLD/'policy.json').read_bytes());value['docker_cli_address_space']=copy.deepcopy(DECLARATION);return value

def function(tree,name):
    return ast.dump(next(n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name==name),include_attributes=False)

class Controls(unittest.TestCase):
    def test_exact_immutable_helper_and_literal_declaration(self):
        self.assertEqual(pin((HERE/'go_cli_va.py').read_bytes()),HELPER_PIN)
        self.assertEqual(V.DECLARATION,DECLARATION)
        self.assertEqual(V.controller_limit(policy()),(536870912,2147483648))

    def test_only_exact_fresh_observed_docker_gets_two_gib(self):
        tools={'docker':dict(path='/usr/bin/docker'),'python3':dict(path='/usr/bin/python3'),'systemctl':dict(path='/usr/bin/systemctl')}
        value=policy()
        self.assertEqual(V.child_plan(['/usr/bin/docker','info'],tools,value),dict(kind='GO_DOCKER_CLI',soft_bytes=2147483648,hard_bytes=2147483648))
        for name in ('python3','systemctl'):
            self.assertEqual(V.child_plan(['/usr/bin/'+name,'docker'],tools,value),dict(kind='NORMAL_HOST_CHILD',soft_bytes=536870912,hard_bytes=536870912))
        for argv in ([],['docker','info'],['/tmp/docker','info'],['/usr/bin/dockerd','info'],['/usr/bin/python3 -c docker']):
            with self.subTest(argv=argv),self.assertRaises(ValueError):V.child_plan(argv,tools,value)
        for selected in ('/tmp/docker','/usr/local/bin/docker'):
            wrong=copy.deepcopy(tools);wrong['docker']['path']=selected
            with self.assertRaises(ValueError):V.child_plan([selected,'info'],wrong,value)
        tools['docker']['path']='/usr/sbin/docker'
        self.assertEqual(V.child_plan(['/usr/sbin/docker','info'],tools,value)['soft_bytes'],2147483648)

    def test_finite_policy_refuses_any_waiver_or_unlimited_budget(self):
        for key in DECLARATION:
            value=policy();value['docker_cli_address_space'][key]=None
            with self.subTest(key=key),self.assertRaises(ValueError):V.controller_limit(value)
        for budget in (-1,0,4*1024**3,resource.RLIM_INFINITY):
            value=policy();value['docker_cli_address_space']['docker_cli_AS_bytes']=budget
            with self.assertRaises(ValueError):V.controller_limit(value)
        value=policy();value['controller']['AS_bytes']=2147483648
        with self.assertRaises(ValueError):V.controller_limit(value)
        with self.assertRaises(ValueError):V.controller_limit(json.loads((OLD/'policy.json').read_bytes()))
        for plan in ({},dict(kind='GO_DOCKER_CLI',soft_bytes=-1,hard_bytes=-1),dict(kind='NORMAL_HOST_CHILD',soft_bytes=536870912,hard_bytes=2147483648)):
            with self.assertRaises(ValueError):V.child_limits(plan)

    def test_preexec_exact_pair_and_readback_without_real_rlimit_mutation(self):
        for cap,kind in ((536870912,'NORMAL_HOST_CHILD'),(2147483648,'GO_DOCKER_CLI')):
            plan=dict(kind=kind,soft_bytes=cap,hard_bytes=cap)
            with patch.object(resource,'setrlimit') as setter,patch.object(resource,'getrlimit',return_value=(cap,cap)):
                V.child_limits(plan)();setter.assert_called_once_with(resource.RLIMIT_AS,(cap,cap))
            for observed in ((cap,-1),(0,cap),(cap,cap+1)):
                with patch.object(resource,'setrlimit'),patch.object(resource,'getrlimit',return_value=observed),self.assertRaises(ValueError):V.child_limits(plan)()

    def test_controller_projection_inverse_preserves_custody_and_retirement(self):
        raw=(OLD/'hosted_owner.py').read_bytes();projected=P.project(raw);text=projected.decode();inverse=text
        for before,after in reversed(P.EDITS):inverse=inverse.replace(after,before)
        self.assertEqual(inverse.encode(),raw)
        self.assertLess(text.index('H.checked(row)'),text.index('address_space=V.child_plan'))
        self.assertLess(text.index('resource.getrlimit(resource.RLIMIT_AS)==V.controller_limit'),text.index('child=subprocess.Popen'))
        self.assertIn('preexec_fn=V.child_limits(address_space)',text)
        self.assertIn('resource.setrlimit(resource.RLIMIT_AS,V.controller_limit(policy))',text)
        self.assertIn('address_space=address_space',text)
        old,new=ast.parse(raw),ast.parse(projected)
        for name in ('cleanup','preflight','start','loop_identity','show','docker','capacity','record_host_policy'):
            with self.subTest(function=name):self.assertEqual(function(old,name),function(new,name))
        for before,_ in P.EDITS:
            with self.assertRaises(ValueError):P.project(raw.replace(before.encode(),b'CHANGED_ANCHOR',1))

    def make_model_parent(self,root):
        names=('LIBGIT2_CONSUMER_ROOT','LIBGIT2_DATA_RECIPE_ROOT','LIBGIT2_DATA_ARCHIVE','LLHTTP_DATA_ARCHIVE')
        values={n:os.environ.get(n) for n in names}
        if not all(values.values()):self.skipTest('explicit frozen consumer, genuine original recipe and source DATA required')
        I=module(HERE.parent/'test_interop.py','libgit2_va_parent_model_fixture')
        A=module(HERE.parent/'prepare.py','libgit2_va_parent_constructor')
        f=I.fixture(root/'MODEL-operands',Path(values['LIBGIT2_CONSUMER_ROOT']))
        parent=root/'MODEL-parent-Source'
        result=A.construct(ROOT,Path(values['LIBGIT2_DATA_RECIPE_ROOT']),Path(values['LIBGIT2_DATA_ARCHIVE']),parent,
            dependency_paths=f.paths,dependency_expected=f.expected,consumer_root=Path(values['LIBGIT2_CONSUMER_ROOT']))
        self.assertEqual(result['native_build'],'NOT RUN');self.assertTrue(all(v is None for v in result['actual'].values()))
        return parent,result

    def test_model_source_full_inverse_program_policy_and_held_bytes(self):
        with tempfile.TemporaryDirectory(prefix='libgit2-finite-VA-MODEL-',dir='/home/gabe/.cache') as name:
            root=Path(name);parent,parent_result=self.make_model_parent(root);sha=parent_result['source_map']['sha256']
            original,_=P.parent_bodies(parent,sha);out=root/'MODEL-successor-Source';result=P.construct(parent,sha,out)
            bodies={str(p.relative_to(out)):p.read_bytes() for p in out.rglob('*') if p.is_file()}
            self.assertEqual(P.inverse(bodies),original)
            self.assertEqual(result['tree'],P.tree(bodies));self.assertTrue(all(v is None for v in result['actual'].values()))
            self.assertEqual(pin(bodies[P.PREFIX+'go_cli_va.py']),HELPER_PIN)
            marker=json.loads(bodies[P.MARKER]);self.assertIsNone(marker['actual'])
            changed=set(P.CHANGED)|{'source-map.json'}
            for leaf,body in original.items():
                if leaf not in changed:self.assertEqual(bodies[leaf],body)
            value=json.loads(bodies[P.PREFIX+'policy.json']);self.assertEqual(value.pop('docker_cli_address_space'),DECLARATION)
            self.assertEqual(value,json.loads(original[P.PREFIX+'policy.json']))
            program=json.loads(bodies[P.PREFIX+'owner-program.json'])
            self.assertEqual(program['files'][P.PREFIX+'go_cli_va.py'],dict(HELPER_PIN,mode=0o644))
            self.assertEqual(program['base_source_map_sha256'],json.loads(original[P.PREFIX+'owner-program.json'])['base_source_map_sha256'])
            for leaf in (P.PREFIX+'go_cli_va.py','previous-v1/'+P.PREFIX+'policy.json','previous-v1/source-map.json','source-map.json'):
                wrong=dict(bodies);wrong[leaf]+=b'\nCHANGED'
                with self.subTest(leaf=leaf),self.assertRaises(ValueError):P.inverse(wrong)
            wrong=dict(bodies);current=json.loads(wrong[P.PREFIX+'policy.json']);current['docker_cli_address_space']['docker_cli_AS_bytes']=-1
            wrong[P.PREFIX+'policy.json']=json.dumps(current).encode()
            with self.assertRaises(ValueError):P.inverse(wrong)
            wrong=dict(bodies);current=json.loads(wrong[P.MARKER]);current['required_future_integration']=[]
            wrong[P.MARKER]=json.dumps(current).encode()
            with self.assertRaises(ValueError):P.inverse(wrong)
            wrong=dict(bodies);wrong[P.PREFIX+'owner-program.json']+=b' '
            with self.assertRaises(ValueError):P.inverse(wrong)
            wrong=dict(bodies);current=json.loads(wrong[P.MARKER]);current['actual']='MODEL_UNAUTHORIZED_ACTUAL'
            wrong[P.MARKER]=json.dumps(current).encode()
            with self.assertRaises(ValueError):P.inverse(wrong)
            wrong=dict(bodies);current=json.loads(wrong[P.PREFIX+'policy.json']);current['controller']['memory_bytes']=2147483648
            wrong[P.PREFIX+'policy.json']=json.dumps(current).encode()
            with self.assertRaises(ValueError):P.inverse(wrong)
        self.assertFalse(out.exists());self.assertFalse(parent.exists())

    def test_parent_map_static_actor_tampering_and_unbound_inputs_refuse(self):
        with tempfile.TemporaryDirectory(prefix='libgit2-finite-VA-refusal-MODEL-',dir='/home/gabe/.cache') as name:
            root=Path(name);empty=root/'empty';empty.mkdir();(empty/'source-map.json').write_text('{}\n')
            with self.assertRaises(ValueError):P.parent_bodies(empty,'0'*64)
            parent,result=self.make_model_parent(root);sha=result['source_map']['sha256'];out=root/'wrong-Source'
            with self.assertRaises(ValueError):P.construct(parent,'0'*64,out)
            self.assertFalse(out.exists())
            source_map=parent/'source-map.json';source_map.chmod(0o600)
            with self.assertRaises(ValueError):P.parent_bodies(parent,sha)
            source_map.chmod(0o644)
            leaf=parent/P.PREFIX/'hosted_owner.py';raw=leaf.read_bytes();leaf.write_bytes(raw+b'\n# changed actor\n')
            with self.assertRaises(ValueError):P.parent_bodies(parent,sha)
            leaf.write_bytes(raw);leaf.chmod(0o666)
            with self.assertRaises(ValueError):P.parent_bodies(parent,sha)

if __name__=='__main__':unittest.main(verbosity=2)
