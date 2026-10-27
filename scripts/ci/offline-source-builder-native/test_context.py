#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only batch context controls. No Git, Docker, source fetch or native actors."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

LANE='scripts/ci/offline-source-builder-native'
HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('OFFLINE_CONTEXT_TEST_ROOT',str(HERE.parents[2]))).absolute()
CONTEXT=ROOT/LANE
FEATURES={'scripts/build/build_v2.py','scripts/build/compare_v2.py','scripts/build/container-entry-v2.sh',
    'scripts/build/source_materials.py','scripts/checks/package_checks.py','scripts/maintenance/source_cache.py',
    'scripts/release/source_delivery.py','scripts/maintenance/build_batch_v2.py','scripts/maintenance/build_outputs_v2.py',
    'scripts/maintenance/build_batch.py','scripts/maintenance/rebuild_plan.py','scripts/release/check_source_pins.py','scripts/release/release.py'}
HELD={'scripts/build/build.py','scripts/build/compare.py','scripts/build/container-entry.sh'}
AST_SCHEMA='ast-structural-v1'
# Derived from byte-pinned source38 owner, not an observed CI output.
ORIGINAL_AST={
    'bootstrap':'15bfa6b193f77b956c04306d9c6ae71a9c699538d9d38ce014683e791070733a',
    'Actors':'f134011093b23a1df7c54364c58111c009ffdae5210ba7851339a47525b26ad1',
    'admitted':'bbc54b45674acf393cdf387035fb5884a1ae723cb1d558592ef29338d72503d5'
}


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


O=module('_finite_batch_context_owner_controls',CONTEXT/'owner.py')
G=module('_finite_batch_graph_controls',CONTEXT/'batch_graph.py')


def encoded(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()


def portable_ast_value(value):
    if isinstance(value,ast.AST):
        fields=[]
        for name,child in sorted(ast.iter_fields(value)):
            if type(child)is list and not child:
                continue
            if child is None and not(isinstance(value,ast.Constant)and name=='value'):
                continue
            fields.append([name,portable_ast_value(child)])
        return ['ast',type(value).__name__,fields]
    if type(value)is list:return ['list',[portable_ast_value(child)for child in value]]
    if value is None:return ['none']
    if type(value)is bool:return ['bool',value]
    if type(value)is int:return ['int',str(value)]
    if type(value)is float:return ['float',value.hex()]
    if type(value)is complex:return ['complex',value.real.hex(),value.imag.hex()]
    if type(value)is str:return ['str',value]
    if type(value)is bytes:return ['bytes',value.hex()]
    if value is Ellipsis:return ['ellipsis']
    raise ValueError('unsupported parsed AST value: '+type(value).__name__)


def portable_ast_bytes(node):
    value=['ast-structural-v1',portable_ast_value(node)]
    return json.dumps(value,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode('ascii')



class ContextControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='SYNTHETIC-batch-context-');self.addCleanup(self.temp.cleanup)
        self.work=Path(self.temp.name)
        self.feature=Path(os.environ.get('OFFLINE_FEATURE_TEST_ROOT',str(Path(os.environ.get('RUNNER_TEMP','/not-selected'))/'offline-source-feature-code')))
        self.original={str(p):O.sha(O.read(p)) for p in (ROOT/O.MAP,ROOT/O.ALIASES[0],ROOT/O.ALIASES[1],CONTEXT/'baseline-source-provenance.json')}

    def tearDown(self):
        self.assertEqual(self.original,{name:O.sha(O.read(Path(name))) for name in self.original})

    def copy_feature(self):
        root=self.work/'feature'
        for name in FEATURES|HELD:
            source=self.feature/name;target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source,target);target.chmod(source.stat().st_mode&0o777)
        return root

    def test_exact_thirteen_real_feature_files_and_three_held_originals(self):
        with patch.object(O.subprocess,'Popen',side_effect=AssertionError('actor forbidden')):
            execution=O.feature_files(self.feature);original=O.held_helpers(self.feature)
        self.assertEqual(set(execution),FEATURES);self.assertEqual(set(original),HELD)
        for name,row in {**execution,**original}.items():
            raw=O.read(self.feature/name)
            self.assertEqual(row,dict(bytes=len(raw),sha256=O.sha(raw),mode=(self.feature/name).stat().st_mode&0o777))
        binding=O.load(CONTEXT/'feature-binding.json')
        self.assertEqual(binding['files'],execution);self.assertEqual(binding['held_original_helpers'],original)
        self.assertIsNone(binding['actual']);self.assertEqual(binding['proof_sha256'],O.sha(O.read(CONTEXT/'feature-git-proof.json')))

    def test_changed_batch_file_refuses_before_any_actor(self):
        root=self.copy_feature();path=root/'scripts/maintenance/build_batch_v2.py';path.write_bytes(path.read_bytes()+b'\n')
        with patch.object(O.subprocess,'Popen',side_effect=AssertionError('actor forbidden')):
            with self.assertRaisesRegex(ValueError,'selected batch feature changed'):O.feature_files(root)

    def test_held_original_bytes_and_mode_cannot_follow_feature_map_drift(self):
        root=self.copy_feature();path=root/'scripts/build/build.py';path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaisesRegex(ValueError,'original builder bytes changed'):O.feature_files(root)
        root=self.work/'mode-feature'
        for name in FEATURES|HELD:
            target=root/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(self.feature/name,target)
        (root/'scripts/build/container-entry.sh').chmod(0o755)
        with self.assertRaisesRegex(ValueError,'original builder bytes changed'):O.held_helpers(root)

    def test_both_c01_recipe_maps_and_source_plans_are_bound_to_real_files(self):
        catalog=O.sha(O.read(CONTEXT/'source-inputs.json'))
        pins={'baseline':'e512ef4b02cef42fd377b0501d44831ba6fb5174c02220cb3527d6f782b77a7d',
              'lto':'2c5c53ed0231fd9562c54b48d3773f33b6bdbecb92a8f30daca1fac101cf8786'}
        for variant in ('baseline','lto'):
            directory=ROOT/'packages/experiments'/('cachy-asahi-zlib-'+variant)
            actual={p.name:O.sha(O.read(p)) for p in directory.iterdir() if p.is_file()}
            reviewed=O.load(CONTEXT/(variant+'-reviewed-inputs.json'));plan=O.load(CONTEXT/(variant+'-source-plan.json'))
            self.assertEqual(set(actual),{'PKGBUILD','probe.c','strict-gzip.c','LICENSE.project'})
            self.assertEqual(actual,reviewed);self.assertEqual(plan['recipe_inputs'],actual)
            self.assertEqual(actual['PKGBUILD'],pins[variant]);self.assertEqual(plan['catalog_sha256'],catalog)
            self.assertEqual(plan['sources'],[dict(id='zlib-1.3.2',source='https://zlib.net/zlib-1.3.2.tar.gz',revision='zlib-1.3.2 release archive; exact archive SHA256 pinned')])
        self.assertNotEqual(O.load(CONTEXT/'baseline-source-plan.json')['recipe_inputs'],O.load(CONTEXT/'lto-source-plan.json')['recipe_inputs'])

    def test_retained_source_and_notice_are_exact_pinned_input_data(self):
        catalog=O.load(CONTEXT/'source-inputs.json');row=catalog['sources'][0]
        self.assertEqual(O.sha(O.read(CONTEXT/'zlib-1.3.2.tar.gz')),'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16')
        self.assertEqual(len(O.read(CONTEXT/'zlib-1.3.2.tar.gz')),1502830)
        notice=row['license_evidence'][0];body=O.read(CONTEXT/notice['path'])
        self.assertEqual((len(body),O.sha(body)),(notice['bytes'],notice['sha256']))

    def test_original341_bootstrap_native_admission_and_supervisor_ast_remain_frozen(self):
        tree=ast.parse(O.read(CONTEXT/'owner.py').decode())
        nodes={node.name:node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.ClassDef))}
        for name,pin in ORIGINAL_AST.items():
            body=portable_ast_bytes(nodes[name])
            self.assertEqual(hashlib.sha256(body).hexdigest(),pin,name)
        self.assertEqual(O.sha(O.read(ROOT/'scripts/ci/inputs.lock.json')),'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f')
        self.assertEqual(O.sha(O.read(CONTEXT/'expected-packages.lock')),'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25')
        self.assertEqual(len(O.read(CONTEXT/'expected-packages.lock').decode().splitlines()),341)

    def test_source_map_and_registered_dedicated_aliases_are_closed(self):
        with patch.object(O.subprocess,'Popen',side_effect=AssertionError('actor forbidden')):
            manifest=O.source(ROOT,O.sha(O.read(ROOT/O.MAP)))
        self.assertIsNone(manifest['actual'])
        self.assertEqual(O.ALIASES,('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-offline-build-batch-v2.yml'))
        self.assertEqual(O.read(ROOT/O.ALIASES[0]),O.read(ROOT/O.ALIASES[1]))
        binding=O.load(CONTEXT/'feature-binding.json');workflow=O.read(ROOT/O.ALIASES[0]).decode()
        self.assertEqual(workflow.count('test "$FEATURE_CODE_SHA" = "'+binding['selected_feature_code_sha']+'"'),2)
        self.assertNotIn('default:',workflow)
        self.assertIn(LANE+'/capture_command.py',manifest['files'])

    def test_unknown_leaf_or_alias_mutation_cannot_satisfy_source_map(self):
        root=self.work/'source';shutil.copytree(ROOT,root,ignore=shutil.ignore_patterns('.git'))
        (root/'unselected').write_text('SYNTHETIC unselected leaf\n')
        with self.assertRaises(ValueError):O.source(root,O.sha(O.read(root/O.MAP)))
        (root/'unselected').unlink();(root/O.ALIASES[1]).write_text('changed')
        with self.assertRaises(ValueError):O.source(root,O.sha(O.read(root/O.MAP)))

    def test_wrong_constructor_selected_feature_sha_refuses_without_git(self):
        binding=O.load(CONTEXT/'feature-binding.json');wrong='f'*40 if binding['selected_feature_code_sha']!='f'*40 else 'e'*40
        args=SimpleNamespace(feature_code_sha=wrong)
        with patch.object(O,'basis_binding',return_value=({},{})),patch.object(O.subprocess,'check_output',side_effect=AssertionError('Git forbidden')):
            with self.assertRaisesRegex(ValueError,'constructor-selected feature SHA'):O.binding(args,first=True)

    def test_missing_rootfs_pins_refuse_before_proof_writes_or_any_actor(self):
        # Re-freeze only a private synthetic copy; original source stays byte-identical.
        root=self.work/'unbound-source';shutil.copytree(ROOT,root,ignore=shutil.ignore_patterns('.git'))
        marker=root/LANE/'baseline-source-provenance.json';marker.write_bytes(encoded(dict(schema_version=1,actual=None,status='UNBOUND_INPUT_HOLD')));marker.chmod(0o644)
        manifest=O.load(root/O.MAP);raw=marker.read_bytes();manifest['files'][LANE+'/baseline-source-provenance.json']=dict(bytes=len(raw),sha256=O.sha(raw),mode=0o644)
        (root/O.MAP).write_bytes(encoded(manifest));map_sha=O.sha(O.read(root/O.MAP))
        template=O.read(root/LANE/'workflow.yml.in').decode()
        workflow=template.replace('@OWNER_SHA@',manifest['files'][LANE+'/owner.py']['sha256']).replace('@MAP_SHA@',map_sha)
        for alias in O.ALIASES:(root/alias).write_text(workflow)
        O.source(root,map_sha)
        with patch.object(O.subprocess,'Popen',side_effect=AssertionError('actor forbidden')),patch.object(socket,'socket',side_effect=AssertionError('network forbidden')):
            review=G.graph_review(root)
        self.assertEqual(review['native'],'NOT_RUN');self.assertEqual(review['builds'],'NOT_RUN')
        self.assertEqual(len(review['missing_rootfs_source_provenance']),76)
        args=SimpleNamespace(source_root=root,proof=self.work/'must-not-exist.json',work=self.work/'not-created')
        with patch.object(O,'HERE',root/LANE),patch.object(O,'ROOT',root),patch.object(O,'binding',return_value=(manifest,{})),\
             patch.object(O,'basis_proof',side_effect=AssertionError('proof writer forbidden')),patch.object(O,'Actors',side_effect=AssertionError('native actor forbidden')),\
             patch.object(O.subprocess,'check_output',side_effect=AssertionError('Git/API forbidden')):
            with self.assertRaisesRegex(ValueError,'ROOTFS_SOURCE_PROVENANCE_INPUT_HOLD'):O.proof(args)
        self.assertFalse(args.proof.exists());self.assertFalse(args.work.exists())


if __name__=='__main__':unittest.main(verbosity=2)
