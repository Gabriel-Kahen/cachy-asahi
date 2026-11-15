#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced source/DATA controls; no full Reader, Source or probe execution."""
import ast
from copy import deepcopy
import ctypes  # Initialize stdlib before the fence; every subsequent ctypes actor refuses.
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
SOURCE6B=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/native-build-namespace-preflight-source-r2')


def fence(event,args):
    if event.startswith(('subprocess.','os.exec','os.spawn','os.fork','socket.','ctypes.')) or event=='os.system':
        raise AssertionError('actor denied by observable DATA controls: '+event)
sys.addaudithook(fence)


def data_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


Q=data_module('_observable_DATA_constructor',HERE/'prepare.py')
P,MANIFEST=Q.factory();BEFORE=P.snapshot(SOURCE6B);AFTER=Q.transform(BEFORE,P,MANIFEST)
PROFILE=P.decode(Q.read(HERE/'profile.json'));CHECKSUM=Q.pin(Q.read(HERE/'profile.json'))['sha256']
OLD_TESTS=data_module('_held_namespace_image_DATA_models',P.HERE/'test_image_lifecycle_data.py')


def definitions(raw,names,namespace=None):
    nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name in names]
    Q.need({n.name for n in nodes}==set(names),'exact selected pure DATA definitions')
    scope=dict(need=Q.need,pin=Q.pin,Path=Path,re=re,json=json,hashlib=hashlib,OPERATION=Q.OPERATION)
    scope.update(namespace or {});exec(compile(ast.Module(body=nodes,type_ignores=[]),'<isolated-pure-DATA>','exec'),scope)
    return NS(**scope)


def image_guards():
    raw=AFTER['native/image_lifecycle.py'][0]
    names={'_need','_closed','_own','_aliases','_build','_ledger'};constants={'LABEL','ROLES','IMAGE','DOCKER','CLOSED','BUILD_KEYS'}
    nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name in names or
        isinstance(n,ast.ClassDef) and n.name=='ImageGuard' or isinstance(n,ast.Assign) and
        any(isinstance(t,ast.Name) and t.id in constants for t in n.targets)]
    scope=dict(Path=Path,re=re,json=json,hashlib=hashlib)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<isolated-image-guards>','exec'),scope)
    return NS(**scope)


class VisibilityModel:
    def __init__(self,code=1,raw=None):
        self.binding=deepcopy(OLD_TESTS.BINDING);self.map_hash='a'*64
        self.raw=raw if raw is not None else b'Step 11/11 : RUN diagnostic\nTraceback (most recent call last):\nValueError: MODELED namespace collector guard\n'
        self.name='actor-logs/0025.log';self.values={};self.files={}
        self.row=dict(argv=['/usr/bin/docker','--host=unix:///var/run/docker.sock','build','--network=none','--pull=false','--no-cache','--platform=linux/arm64',
            '--tag','native-developer-tools:'+self.binding['token'],'--label','org.cachy-asahi.native-developer='+self.binding['token'],
            '--label','org.cachy-asahi.native-developer.source='+self.binding['source'],'--iidfile','/MODELED/native-developer-work/overlay/image-id','/MODELED/native-developer-work/overlay/context'],
            log='/MODELED/actors/0009.log',public_log=self.name,log_pin=Q.pin(self.raw),exit=code,status='PASS' if code==0 else 'FAIL',
            natural_exit=True,group_absent=True,exit_observed_via_waitpid=True,leader_held_until_group_inspection=True,
            ownership_lost=False,forced_cleanup=False,retirement='REAPED')
        self.receipt=dict(binding=self.binding,source_map_sha256=self.map_hash,operation=Q.OPERATION,output_root='/MODELED/native-developer-work/public',actors=[self.row])
        self.cleanup=dict(build_operations=[dict(role='tools',terminal=True,actor=self.row)],actors=[])
        self.projection=dict(binding=self.binding,source_map_sha256=self.map_hash,selected={})
        self.join()

    def join(self):
        self.row['log_pin']=Q.pin(self.raw);self.values[self.name]=self.raw
        self.files[self.name]=dict(kind='file',mode=384,**Q.pin(self.raw))
        self.projection['selected'][self.name]=dict(kind='file',mode=384,source_mode=420,**Q.pin(self.raw))
        self.values['public-projection.json']=P.encoded(self.projection)

    def read(self,name):return self.values[name]
    def load(self,name):return json.loads(self.read(name))
    def validate(self):
        f=definitions(AFTER[Q.READER][0],{'retained_namespace_build_log'})
        return f.retained_namespace_build_log(self,self.files,self.receipt,self.cleanup,self.binding,self.map_hash)


class ObservableDataControls(unittest.TestCase):
    def test_complete_exact_source_family_external_profile_and_inverse(self):
        after,_=Q.compose(BEFORE,CHECKSUM);self.assertEqual(after,AFTER)
        self.assertEqual(Q.facts(BEFORE,after,P,MANIFEST),PROFILE)
        self.assertEqual({n for n in BEFORE if BEFORE[n]!=after[n]},Q.CHANGED)
        self.assertEqual(sum(BEFORE[n]==after[n]for n in BEFORE),196)
        inverse=dict(after)
        for name in Q.CHANGED:inverse[name]=BEFORE[name]
        self.assertEqual(inverse,BEFORE);self.assertEqual(P.tree(inverse),Q.PARENT_TREE)
        with self.assertRaises(ValueError):Q.compose(BEFORE,'0'*64)
        for name in ('.github/workflows/native-arm-build.yml','native/build_tools_tools_v2.py',Q.MAP):
            bad=dict(BEFORE);body,mode=bad[name];bad[name]=(body+b'\n',mode)
            with self.subTest(path=name),self.assertRaises(ValueError):Q.transform(bad,P,MANIFEST)
        bad=dict(BEFORE);body,mode=bad['native/owner.py'];bad['native/owner.py']=(body,493)
        with self.assertRaises(ValueError):Q.transform(bad,P,MANIFEST)

    def test_no_actual_selectors_or_changed_projection_workflow_probe_contract(self):
        self.assertEqual(PROFILE['actual'],dict(source=None,ref=None,run=None,job=None,artifact=None))
        self.assertFalse(PROFILE['acceptance']);self.assertEqual(PROFILE['native'],'NOT_RUN')
        for name in ('native/build_tools_projection_v2.py','native/build-tools-contract-v2.json','native/build_tools_alpm_v2.py',
                     'native/build_tools_tools_v2.py','native/invocation.json','.github/workflows/native-arm-build.yml'):
            self.assertEqual(BEFORE[name],AFTER[name],name)
        mapping=P.decode(AFTER[Q.MAP][0]);self.assertEqual(mapping['namespace_build_log_visibility'],Q.VISIBILITY)
        self.assertEqual(mapping['files'],{n:r for n,r in P.descriptors(AFTER).items()if n!=Q.MAP})

    def test_whole_factory_manifest_refuses_before_code_import(self):
        original=Q.read
        def tampered(path,cap=4*1024**2):
            raw=original(path,cap)
            return raw+b' ' if Path(path)==HERE/'factory-inputs.json' else raw
        with patch.object(Q,'read',tampered),patch.object(Q.importlib.util,'spec_from_file_location',side_effect=AssertionError('must not import')):
            with self.assertRaisesRegex(ValueError,'fixed whole held factory'):Q.factory()

    def test_every_modified_function_has_exact_byte_inverse(self):
        helper=Q.read(HERE/'reader_visibility.py.in')
        for name,replacements in Q.TRANSFORMS.items():
            raw=AFTER[name][0]
            if name==Q.READER:raw=Q.once(raw,helper,b'')
            for old,new in reversed(replacements):raw=Q.once(raw,new,old)
            self.assertEqual(raw,BEFORE[name][0],name)
        for name in Q.TRANSFORMS:ast.parse(AFTER[name][0])

    def test_image_id_still_comes_from_iidfile_not_verbose_stdout(self):
        source=AFTER['native/owner.py'][0].decode()
        self.assertIn("image = read(overlay / 'image-id').decode().strip()",source)
        self.assertIn("actor.run(command, timeout=600)",source)
        self.assertNotIn('image = actor.run(command',source)
        model=OLD_TESTS.Model();model.builds['tools']['argv'].remove('--quiet')
        row=model.builds['tools'];raw=b'Sending build context\nStep 11/11 : RUN diagnostic\nSuccessfully built MODELED\n'
        model.put(row['public_log'],raw);row['log_pin']=Q.pin(raw);model.refresh()
        self.assertEqual([len(model.builds[r]['argv'])for r in ('base','tools')],[16,16])
        image_guards()._ledger(model.ledger)
        reader=definitions(AFTER[Q.READER][0],{'retained_image_lifecycle'})
        reader.retained_image_lifecycle(model,model.files,model.receipt,model.cleanup,OLD_TESTS.BINDING,OLD_TESTS.MAP)

    def test_registration_and_independent_reader_refuse_quiet_or_policy_injection(self):
        for mutation in ('quiet','base_quiet','security','network','missing_iidfile','wrong_iidfile'):
            model=OLD_TESTS.Model();model.builds['tools']['argv'].remove('--quiet');argv=model.builds['tools']['argv']
            if mutation=='quiet':argv.insert(3,'--quiet')
            elif mutation=='base_quiet':model.builds['base']['argv'].insert(3,'--quiet')
            elif mutation=='security':argv[3]='--security-opt=seccomp=unconfined'
            elif mutation=='network':argv[3]='--network=host'
            elif mutation=='missing_iidfile':argv[-3]='--quiet'
            else:argv[-2]='/MODELED/foreign/image-id'
            model.refresh()
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):image_guards()._ledger(model.ledger)
            f=definitions(AFTER[Q.READER][0],{'retained_image_lifecycle'})
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):f.retained_image_lifecycle(model,model.files,model.receipt,model.cleanup,OLD_TESTS.BINDING,OLD_TESTS.MAP)

    def test_full_nonzero_failure_log_is_visible_without_namespace_inference(self):
        model=VisibilityModel();result=model.validate()
        self.assertEqual(result['status'],'VALIDATED_UNQUIET_TOOLS_BUILD_LOG_DATA_ONLY');self.assertEqual(result['exit'],1)
        self.assertEqual(result['log_pin'],Q.pin(model.raw));self.assertIn(b'Traceback',model.read(result['public_log']))
        self.assertEqual(result['namespace_policy_cause'],'UNKNOWN');self.assertEqual(result['native'],'NOT_ADMITTED')
        self.assertNotIn('outcomes',result)
        model=VisibilityModel(0);self.assertEqual(model.validate()['exit'],0)
        model=VisibilityModel(1,b'UNKNOWN output\x00binary DATA\n');self.assertEqual(model.validate()['native'],'NOT_ADMITTED')

    def test_failure_visibility_refuses_quiet_flags_wrong_paths_labels_and_operation(self):
        for field in ('quiet','network','security','extra','iid','context','label','token','operation','output'):
            model=VisibilityModel();argv=model.row['argv']
            if field=='quiet':argv.insert(3,'--quiet')
            elif field=='network':argv[3]='--network=host'
            elif field=='security':argv[3]='--security-opt=seccomp=unconfined'
            elif field=='extra':argv.insert(3,'--progress=plain')
            elif field=='iid':argv[-2]='/MODELED/elsewhere/image-id'
            elif field=='context':argv[-1]+='/extra'
            elif field=='label':argv[12]='org.cachy-asahi.native-developer.source='+'f'*40
            elif field=='token':argv[8]='native-developer-tools:'+'f'*24
            elif field=='operation':model.receipt['operation']='some-other-operation'
            else:model.receipt['output_root']='/MODELED/../public'
            with self.subTest(field=field),self.assertRaises(ValueError):model.validate()

    def test_natural_nonzero_only_refuses_ambiguous_or_incomplete_retirement(self):
        for key in ('natural_exit','group_absent','exit_observed_via_waitpid','leader_held_until_group_inspection',
                    'ownership_lost','forced_cleanup','retirement','status','exit','terminal'):
            model=VisibilityModel()
            if key=='terminal':model.cleanup['build_operations'][0]['terminal']=False
            elif key=='exit':model.row[key]=-9
            elif key=='status':model.row[key]='PASS'
            elif key=='retirement':model.row[key]='FORCED'
            else:model.row[key]=not model.row[key]
            with self.subTest(key=key),self.assertRaises(ValueError):model.validate()

    def test_raw_projection_manifest_pins_and_unique_actor_are_required(self):
        for case in ('raw','manifest','projection','missing','actor','operation','log','retirement_log','projection_binding'):
            model=VisibilityModel()
            if case=='raw':model.values[model.name]+=b' altered'
            elif case=='manifest':model.files[model.name]['sha256']='f'*64
            elif case=='projection':model.projection['selected'][model.name]['bytes']+=1;model.values['public-projection.json']=P.encoded(model.projection)
            elif case=='missing':del model.files[model.name]
            elif case=='actor':model.receipt['actors'].append(deepcopy(model.row))
            elif case=='operation':model.cleanup['build_operations'].append(deepcopy(model.cleanup['build_operations'][0]))
            elif case=='log':model.receipt['actors'].append(dict(public_log=model.name))
            elif case=='retirement_log':model.cleanup['actors'].append(dict(public_log=model.name))
            else:model.projection['source_map_sha256']='f'*64;model.values['public-projection.json']=P.encoded(model.projection)
            with self.subTest(case=case),self.assertRaises(ValueError):model.validate()

    def test_not_reached_is_explicit_and_cannot_hide_an_existing_tools_actor(self):
        model=VisibilityModel();model.cleanup['build_operations']=[]
        with self.assertRaises(ValueError):model.validate()
        model.receipt['actors']=[];result=model.validate()
        self.assertEqual(result['status'],'TOOLS_BUILD_NOT_REACHED_DATA_ONLY');self.assertEqual(result['native'],'NOT_ADMITTED')

    def test_second_distinct_tools_build_refuses_but_alias_inspection_is_allowed(self):
        model=VisibilityModel();extra=deepcopy(model.row);extra.update(log='/MODELED/actors/retry.log',public_log='actor-logs/0026.log')
        model.receipt['actors'].append(extra)
        with self.assertRaisesRegex(ValueError,'hidden retry'):model.validate()
        model=VisibilityModel();extra=deepcopy(model.row)
        extra.update(argv=['/usr/bin/docker','--host=unix:///var/run/docker.sock','image','inspect','native-developer-tools:'+model.binding['token']],
                     log='/MODELED/actors/inspect.log',public_log='actor-logs/0026.log')
        model.receipt['actors'].append(extra)
        self.assertEqual(model.validate()['status'],'VALIDATED_UNQUIET_TOOLS_BUILD_LOG_DATA_ONLY')

    def test_exact_unchanged_privacy_predicate_and_cap_no_binary_exception(self):
        source=ast.parse(BEFORE['native/build_tools_projection_v2.py'][0])
        old=next(n.value for n in source.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PRIVATE_MARKER'for t in n.targets))
        helper=ast.parse(Q.read(HERE/'reader_visibility.py.in')).body[0]
        new=next(n.value for n in helper.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='private_marker'for t in n.targets))
        self.assertEqual(ast.dump(old),ast.dump(new))
        for raw in (b'PRIVATE_KEY=fixture',b'authorization: bearer MODELED',b'\x00binary secret=fixture',b'ghp_MODELED_ONLY'):
            model=VisibilityModel(1,raw)
            with self.assertRaises(ValueError):model.validate()
        model=VisibilityModel();model.row['log_pin']['bytes']=16*1024**2+1
        with self.assertRaises(ValueError):model.validate()

    def test_failure_branch_calls_visibility_before_failed_return(self):
        node=next(n for n in ast.parse(AFTER[Q.READER][0]).body if isinstance(n,ast.FunctionDef) and n.name=='validate')
        calls=[n for n in ast.walk(node)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='retained_namespace_build_log']
        self.assertEqual(len(calls),1)
        failed=next(n for n in node.body if isinstance(n,ast.If) and any(isinstance(x,ast.Name) and x.id=='failed' for x in ast.walk(n.test)))
        self.assertLess(calls[0].lineno,failed.lineno)
        self.assertIn('build_log_visibility',ast.get_source_segment(AFTER[Q.READER][0].decode(),failed))

    def test_null_ingress_refuses_before_any_capsule_source_access(self):
        def forbidden(*args):raise AssertionError('forbidden source/capsule access')
        f=definitions(AFTER[Q.READER][0],{'validate'},dict(build_tools_local_binding=forbidden,open_capsule=forbidden))
        with self.assertRaises(ValueError):f.validate(Path('/ABSENT'),dict(source=None,ref=None,run=None,map_sha256=None))

    def test_original_quiet_failure_fixture_has_no_recoverable_cause(self):
        observed=json.loads(Q.read(HERE/'observed-failure.json'));raw=Q.read(HERE/'fixtures/quiet-original.log.data')
        self.assertEqual(Q.pin(raw),observed['log']['pin']);self.assertEqual(len(raw),1101)
        self.assertIn(b'Dockerfile:11',raw);self.assertNotIn(b'Traceback',raw)
        self.assertEqual(observed['mapped_files_verified'],87);self.assertEqual(observed['namespace_outcome'],'UNKNOWN')
        self.assertIn('--quiet',observed['tools_build']['actor']['argv']);self.assertFalse(observed['retry_authorized'])
        model=VisibilityModel(1,raw);model.row['argv'].insert(3,'--quiet')
        with self.assertRaises(ValueError):model.validate()

    def test_whole_merged_stream_capture_and_raw_copy_asts_are_preserved(self):
        runner=BEFORE['bootstrap/scripts/ci/zlib-pgo-native-hosted/owner.py'][0].decode()
        actor=next(n for n in ast.parse(runner).body if isinstance(n,ast.ClassDef) and n.name=='Actors')
        run=next(n for n in actor.body if isinstance(n,ast.FunctionDef) and n.name=='run')
        raw=ast.get_source_segment(runner,run)
        self.assertIn("with log.open('wb')as stream:",raw)
        self.assertIn('stdout=stream,stderr=subprocess.STDOUT',raw)
        self.assertIn("need(log.stat().st_size<=16*1024**2,'bounded actor log')",raw)
        owner=AFTER['native/owner.py'][0].decode()
        self.assertIn("data = read(path)\n                target = logs / ('%04d.log' % number); target.write_bytes(data)",owner)
        self.assertIn("row['public_log'] = str(target.relative_to(output)); row['log_pin'] = pin(data)",owner)
        self.assertEqual(BEFORE['bootstrap/scripts/ci/zlib-pgo-native-hosted/owner.py'],AFTER['bootstrap/scripts/ci/zlib-pgo-native-hosted/owner.py'])

    def test_constructor_alias_hardlink_refusals_without_source_publication(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d)/'ordinary';p.write_bytes(b'{}');a=Path(d)/'alias';a.symlink_to(p)
            with self.assertRaises(ValueError):Q.read(a)
            a.unlink();os.link(p,a)
            with self.assertRaises(ValueError):Q.read(p)


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(ObservableDataControls)
    for module in (OLD_TESTS,data_module('_held_namespace_probe_DATA_controls',P.HERE/'test_preflight_data.py')):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
    result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
