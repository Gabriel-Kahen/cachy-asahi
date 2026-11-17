#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Fenced successor/VA selection controls; no Docker, role, network or cgroup actor."""
import ast
import copy
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
PARENT=Path(os.environ.get('LLHTTP_VA_PARENT','/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-llhttp62-source-r1/closed-source-tree'))
OLD=ROOT/'scripts/ci/llhttp-reference-native-source/owner'
def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
P=module(HERE/'prepare.py','llhttp_va_prepare_test');V=module(HERE/'go_cli_va.py','llhttp_va_selection_test')
def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.'))or event in ('os.system','os.fork','os.forkpty','os.exec','os.posix_spawn','fcntl.flock','os.pidfd_open','resource.setrlimit'):
        raise RuntimeError('DATA actor forbidden: '+event)
sys.addaudithook(fence)

def policy():
    value=json.loads((OLD/'policy.json').read_bytes());value['docker_cli_address_space']=copy.deepcopy(V.DECLARATION);return value

class Controls(unittest.TestCase):
    def test_exact_selected_executable_only(self):
        tools={'docker':{'path':'/usr/bin/docker'},'systemctl':{'path':'/usr/bin/systemctl'},'python3':{'path':'/usr/bin/python3'}};value=policy()
        self.assertEqual(V.controller_limit(value),(512*1024**2,2*1024**3))
        self.assertEqual(V.child_plan(['/usr/bin/docker','info'],tools,value)['soft_bytes'],2*1024**3)
        for tool in ('systemctl','python3'):
            self.assertEqual(V.child_plan(['/usr/bin/'+tool,'docker'],tools,value),dict(kind='NORMAL_HOST_CHILD',soft_bytes=512*1024**2,hard_bytes=512*1024**2))
        for argv in (['docker','info'],['/tmp/docker','info'],['/usr/bin/dockerd','info'],[],['/usr/bin/python3 -c docker']):
            with self.subTest(argv=argv),self.assertRaises(ValueError):V.child_plan(argv,tools,value)
        tools['docker']['path']='/tmp/docker'
        with self.assertRaises(ValueError):V.child_plan(['/tmp/docker','info'],tools,value)

    def test_finite_policy_no_unlimited_fallback(self):
        for key in V.DECLARATION:
            value=policy();value['docker_cli_address_space'][key]=None
            with self.subTest(key=key),self.assertRaises(ValueError):V.controller_limit(value)
        for budget in (-1,0,4*1024**3,resource.RLIM_INFINITY):
            value=policy();value['docker_cli_address_space']['docker_cli_AS_bytes']=budget
            with self.assertRaises(ValueError):V.controller_limit(value)
        with self.assertRaises(ValueError):V.child_limits(dict(kind='GO_DOCKER_CLI',soft_bytes=-1,hard_bytes=-1))

    def test_child_preexec_uses_exact_soft_hard_and_readback(self):
        for cap,kind in ((V.NORMAL_AS,'NORMAL_HOST_CHILD'),(V.DOCKER_AS,'GO_DOCKER_CLI')):
            value=dict(kind=kind,soft_bytes=cap,hard_bytes=cap)
            with patch.object(resource,'setrlimit')as setter,patch.object(resource,'getrlimit',return_value=(cap,cap)):
                V.child_limits(value)();setter.assert_called_once_with(resource.RLIMIT_AS,(cap,cap))
            with patch.object(resource,'setrlimit'),patch.object(resource,'getrlimit',return_value=(cap,-1)),self.assertRaises(ValueError):V.child_limits(value)()

    def test_real_failure_callchain_and_exact_controller_inverse(self):
        raw=(OLD/'hosted_owner.py').read_bytes();text=P.project(raw).decode();inverse=text
        for before,after in reversed(P.EDITS):inverse=inverse.replace(after,before)
        self.assertEqual(inverse.encode(),raw)
        self.assertIn("self.docker('info','--format','{{json .}}')",raw.decode())
        self.assertIn("policy['controller']['AS_bytes'],policy['controller']['AS_bytes']",raw.decode())
        self.assertIn('preexec_fn=V.child_limits(address_space)',text)
        self.assertLess(text.index('H.checked(row)'),text.index('address_space=V.child_plan'))
        self.assertLess(text.index('resource.getrlimit(resource.RLIMIT_AS)==V.controller_limit'),text.index('child=subprocess.Popen'))
        tree=ast.parse(text);before=ast.parse(raw)
        for name in ('cleanup','preflight','start','loop_identity','show','docker'):
            get=lambda t:ast.dump(next(n for n in ast.walk(t)if isinstance(n,ast.FunctionDef)and n.name==name),include_attributes=False)
            self.assertEqual(get(tree),get(before))

    def test_full68_constructor_inverse_unchanged_resources_namespace(self):
        if not PARENT.exists():self.skipTest('genuine retained Source62 DATA required; no acquisition/fallback')
        original,_=P.parent_bodies(PARENT)
        with tempfile.TemporaryDirectory(prefix='llhttp-va-Source-DATA-',dir='/home/gabe')as name:
            out=Path(name)/'Source';result=P.construct(PARENT,out);self.assertEqual(result['files'],68);self.assertTrue(all(v is None for v in result['actual'].values()))
            bodies={str(n.relative_to(out)):n.read_bytes()for n in out.rglob('*')if n.is_file()};self.assertEqual(P.inverse(bodies),original)
            self.assertEqual(result['tree'],P.tree(bodies));value=json.loads(bodies[P.PREFIX+'policy.json']);value.pop('docker_cli_address_space');self.assertEqual(value,json.loads(original[P.PREFIX+'policy.json']))
            for leaf in ('held-source/scripts/ci/llhttp-reference-native-source/base/entry.py','.github/workflows/native-arm-llhttp-reference-source.yml'):
                self.assertEqual(bodies[leaf],original[leaf])
            wrong=dict(bodies);wrong['previous-v1/'+P.PREFIX+'policy.json']+=b' '
            with self.assertRaises(ValueError):P.inverse(wrong)

    def test_caller_constructor_seals_every_inherited_program_and_fixed68(self):
        parent=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-canonical-ONCE-DRAFT-20261117-r1')
        if not PARENT.exists()or not parent.exists():self.skipTest('genuine parent Source/caller DATA required')
        Q=module(HERE/'prepare_caller.py','llhttp_va_caller_constructor_test')
        with tempfile.TemporaryDirectory(prefix='llhttp-va-caller-constructor-DATA-',dir='/home/gabe')as name:
            root=Path(name);source=root/'Source';P.construct(PARENT,source);out=root/'caller';result=Q.construct(parent,source,out)
            self.assertIsNone(result['binding']['source_CID']);self.assertIsNone(result['binding']['source_ref']);self.assertEqual(result['binding']['source_files'],68)
            inverse=json.loads((out/'full-files-inverse.DATA.json').read_bytes());self.assertIn('issue_root_packet.DRAFT.py',inverse['files']);self.assertIn('packet/make_root_config.DRAFT.py',inverse['files']);self.assertIn('packet/operator-DRAFT/policy.json',inverse['files'])
            helper=source/P.PREFIX/'go_cli_va.py';helper.write_bytes(helper.read_bytes()+b'\n# unauthorized variant\n')
            with self.assertRaises(ValueError):Q.construct(parent,source,root/'wrong-caller')

    def test_parent_missing_tampered_or_wrong_source_refuses(self):
        with tempfile.TemporaryDirectory(prefix='llhttp-va-wrong-DATA-',dir='/home/gabe')as name:
            root=Path(name);(root/'source-map.json').write_text('{}\n')
            with self.assertRaises(ValueError):P.parent_bodies(root)
        bad=(OLD/'hosted_owner.py').read_bytes().replace(b'def run(',b'def removed_run(')
        # A non-anchor edit remains held by the exact Source62 parent pin.
        self.assertNotEqual(P.pin(bad),P.pin((OLD/'hosted_owner.py').read_bytes()))

    def test_primary_calculation_and_local_probe_limits(self):
        primary=json.loads((HERE/'primary-sources.DATA.json').read_bytes());rows=primary['derived']['reservations'];self.assertEqual(sum(rows),613548032);self.assertGreater(sum(rows),V.NORMAL_AS);self.assertLess(sum(rows),V.DOCKER_AS)
        local=json.loads((HERE/'local-startup.DATA.json').read_bytes());self.assertEqual(local['binary']['ELF_machine'],62);self.assertEqual([r['AS_bytes']for r in local['results']],[V.NORMAL_AS,V.DOCKER_AS]);self.assertEqual([r['exit']for r in local['results']],[2,0]);self.assertEqual(local['native_ARM'],'NOT RUN')
        self.assertIn('failed to reserve page summary memory',local['results'][0]['stderr'])

if __name__=='__main__':unittest.main(verbosity=2)
