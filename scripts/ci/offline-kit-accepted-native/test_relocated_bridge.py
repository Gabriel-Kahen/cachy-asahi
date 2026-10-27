#!/usr/bin/env python3
"""Faithful shallow relocation controls; all authentication APIs and FDs are fake."""
import ast,hashlib,importlib.util,json,re,socket,subprocess,types,unittest
from pathlib import Path
from unittest.mock import patch
BASE=Path(__file__).resolve().parent
BRIDGE=(BASE/'trial-code/plan_bridge.py') if (BASE/'trial-code/plan_bridge.py').is_file() else BASE/'source/scripts/ci/offline-kit-accepted-native/trial-code/plan_bridge.py'
BASELINE_ROOT = 'ROOT = Path(__file__).absolute().parents[2]'
PREDECESSOR_SHA256 = '17f25fe87729b2c4019befe17e4a7f000310c9061b9ed8523bbfbcd1e7a3aa75'
HELD_FUNCTION_SHA256 = {'need': '4b3a697e0d6c229d054eb933137631f3eec63797433cf8a40cb5f41231911d04', 'root_path': '4a05fb2d0e7b58a073be754ac9e5fdc55a9d31f51062cc50f11f77137cbabacf', 'inventory': 'ee55ddaa5c3c3a06994f5989c37bc5653f622eaf6c3ea51456c56d39151c4b54', 'derive': 'c8891e776845382cf7c06e37e871709fb4cf4715cda4229564835e0d36b873c7', 'plan': '0ccd34d5cef04abd8e0abaa10ba3aea9f052f5eaf49447ac3da4de2785084765', 'main': '36f514a294cf1ae12d70601c24c0a536aa067e92ffe808e7b79006f3481c2787'}

def loaded(path='/trusted/plan_bridge.py'):
    namespace={'__name__':'fixture_relocated_proposal','__file__':path}
    exec(compile(BRIDGE.read_bytes(),str(BRIDGE),'exec'),namespace)
    return types.SimpleNamespace(**namespace)


def fixture_api(changed=False,crossed=False):
    package=dict(name='cachy-asahi-maintenance',version='0.1.0-2',arch='any',sha256='a'*64)
    target=dict(package,path='repo/maintenance.pkg.tar.xz')
    raw=b'fixture release DATA';spec=b'{"synthetic": false}'
    digest=lambda body:hashlib.sha256(body).hexdigest()
    row=dict(package=dict(package),recipe=dict(sha256='b'*64),bundle=dict(sha256='c'*64),review_status='FIXTURE_UNADOPTED_SOURCE')
    if crossed:row['package']['sha256']='d'*64
    api=types.SimpleNamespace(calls=0)
    def inspect(args):
        api.calls+=1
        return dict(release_sha256=digest(raw),kit_sha256='e'*64,metadata_sha256=('0' if changed and api.calls>1 else 'f')*64)
    c=types.SimpleNamespace(absolute=Path,NAME=re.compile(r'[A-Za-z0-9._+-]+\Z'),
        directory=lambda path:987654,describe=lambda fd:(dict(targets=dict(packages=[target])),
        dict(files={'spec.json':digest(spec),target['path']+'.sig':'1'*64}),raw),digest=digest,
        read_member=lambda fd,name:spec,decode=json.loads,
        source_associations=lambda fd,value,release:dict(packages=[row]))
    api.inspect=inspect;api.c=c
    return api


class RelocatedBridgeControls(unittest.TestCase):
    def setUp(self):
        for obj,name in ((subprocess,'Popen'),(socket,'socket')):
            p=patch.object(obj,name,side_effect=AssertionError('NO_PROCESS_OR_NETWORK'));p.start();self.addCleanup(p.stop)
    def args(self,**changes):
        values=dict(kit='/media/good',state_dir='/result/state',kit_sha256='e'*64,namespace='dev.fixture',
                    signer='A'*40,minimum_sequence=1)
        values.update(changes);return types.SimpleNamespace(**values)
    def test_exact_old_assignment_reproduces_actual_shallow_failure(self):
        node=ast.parse(BASELINE_ROOT).body[0]
        self.assertEqual(ast.get_source_segment(BASELINE_ROOT,node),'ROOT = Path(__file__).absolute().parents[2]')
        with self.assertRaises(IndexError) as error:
            exec(compile(ast.Module(body=[node],type_ignores=[]),'trusted_predecessor_root_assignment','exec'),{'Path':Path,'__file__':'/trusted/plan_bridge.py'})
        self.assertEqual(error.exception.args,(2,))
    def test_shallow_import_does_not_load_api_or_require_repository_depth(self):
        with patch.object(importlib.util,'spec_from_file_location',side_effect=AssertionError('NO_API_IMPORT')):
            bridge=loaded()
        self.assertEqual(bridge.__file__,'/trusted/plan_bridge.py')
        self.assertFalse(hasattr(bridge,'ROOT'))
    def test_shallow_implicit_api_fails_clear_before_import(self):
        bridge=loaded()
        with patch.object(importlib.util,'spec_from_file_location',side_effect=AssertionError('NO_GUESSED_IMPORT')):
            with self.assertRaisesRegex(ValueError,'explicit authenticated kit API'):bridge.kit_api()
    def test_explicit_verified_api_reaches_same_blocked_plan_from_shallow_path(self):
        bridge=loaded();api=fixture_api();closed=[]
        with patch.object(bridge.os,'close',side_effect=closed.append):result=bridge.plan(self.args(),api=api)
        self.assertEqual(api.calls,2);self.assertEqual(closed,[987654])
        self.assertEqual(result['status'],'BLOCKED_ENGINE_COMPATIBILITY')
        self.assertFalse(result['transaction_authorized']);self.assertFalse(result['packages_installed'])
        self.assertEqual(result['candidate_contract']['after'],{'cachy-asahi-maintenance':'0.1.0-2'})
    def test_explicit_api_removal_stays_hypothetical(self):
        bridge=loaded();api=fixture_api()
        with patch.object(bridge.os,'close'):
            result=bridge.plan(self.args(operation='remove',before={'cachy-asahi-maintenance':'0.1.0-2'}),api=api)
        self.assertEqual(result['candidate_contract']['after'],{})
        self.assertFalse(result['packages_removed']);self.assertFalse(result['transaction_authorized'])
    def test_existing_reauthentication_and_source_join_gates_remain(self):
        bridge=loaded()
        for api,reason in ((fixture_api(changed=True),'kit changed during planning'),(fixture_api(crossed=True),'source-delivery association')):
            with self.subTest(reason=reason),patch.object(bridge.os,'close'),self.assertRaisesRegex(ValueError,reason):bridge.plan(self.args(),api=api)
    def test_repository_default_api_is_lazy_and_keeps_original_relative_target(self):
        bridge=loaded('/fixture/repo/scripts/install/offline_kit_plan.py');seen=[]
        loader=types.SimpleNamespace(exec_module=lambda value:setattr(value,'fixture',True))
        spec=types.SimpleNamespace(loader=loader)
        def selected(name,path):seen.append(str(path));return spec
        with patch.object(importlib.util,'spec_from_file_location',side_effect=selected),patch.object(importlib.util,'module_from_spec',return_value=types.SimpleNamespace()):
            result=bridge.kit_api()
        self.assertTrue(result.fixture);self.assertEqual(seen,['/fixture/repo/scripts/release/offline_kit.py'])
    def test_every_other_function_is_byte_held(self):
        new=BRIDGE.read_text()
        after={n.name:hashlib.sha256(ast.get_source_segment(new,n).encode()).hexdigest()for n in ast.parse(new).body if isinstance(n,ast.FunctionDef)and n.name!='kit_api'}
        self.assertEqual(after,HELD_FUNCTION_SHA256)

if __name__=='__main__':unittest.main(verbosity=2)
