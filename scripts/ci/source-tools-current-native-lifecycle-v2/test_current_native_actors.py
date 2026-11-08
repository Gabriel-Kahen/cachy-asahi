#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New v2 policy/response controls only; no native actor or process is run."""
import argparse
import ast
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
FIXTURE_TAR_SHA256 = '81d978c79f71edbd72190739b91bd1e2b1c43bec357a94d68a436ecc22e1b0b4'
FIXTURE_MANIFEST_SHA256 = '462fdce95d667cb27ce3c415adf719f2dd52a680186b4b92d57cce098bc41ccf'
FIXTURE_NAMES = frozenset(('native/expected349.lock', 'native/input-profile.json',
    'bootstrap/scripts/ci/inputs.lock.json', 'native/source-tools-contract-v1.json',
    'native/source_tools_tools_v1.py', 'native/source_tools_alpm_v1.py',
    'native/source_tools_probe_v1.py', 'native/source_tools_guest_v1.py'))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def fixture_files(path):
    """Decode eight authenticated policy/AST fixtures; never execute baseline code."""
    path=Path(path).absolute();manifest_path=path.with_suffix('.json')
    for operand in (path,manifest_path):
        if operand!=operand.resolve() or any(item.is_symlink()for item in(operand,*operand.parents)):
            raise ValueError('ordinary fixture paths required')
        if not operand.is_file() or operand.stat().st_nlink!=1 or operand.stat().st_size>2*1024**2:
            raise ValueError('bounded single-link fixture required')
    raw=path.read_bytes();manifest_raw=manifest_path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=FIXTURE_TAR_SHA256 or hashlib.sha256(manifest_raw).hexdigest()!=FIXTURE_MANIFEST_SHA256:
        raise ValueError('fixed policy fixture identity differs')
    manifest=json.loads(manifest_raw)
    if manifest['bundle']!=pin(raw) or set(manifest['files'])!=FIXTURE_NAMES or manifest['immutable_Source'] is not False:
        raise ValueError('finite fixture DATA subset required')
    files={};canonical=io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as archive:
        for node in archive:
            if node.name not in FIXTURE_NAMES or node.name in files or not node.isfile() or node.pax_headers:
                raise ValueError('exact regular fixture members required')
            expected=manifest['files'][node.name]
            if node.uid or node.gid or node.mtime or node.mode!=0o644 or not 0<node.size<=1024**2:
                raise ValueError('canonical bounded fixture metadata required')
            body=archive.extractfile(node).read()
            if {**pin(body),'mode':node.mode}!=expected:
                raise ValueError('fixture body pin differs')
            files[node.name]=body
    if set(files)!=FIXTURE_NAMES or sum(map(len,files.values()))>1024**2:
        raise ValueError('complete finite fixture subset required')
    with tarfile.open(fileobj=canonical,mode='w',format=tarfile.USTAR_FORMAT)as archive:
        for name,body in sorted(files.items()):
            node=tarfile.TarInfo(name);node.size=len(body);node.mode=0o644;node.uid=node.gid=node.mtime=0
            archive.addfile(node,io.BytesIO(body))
    if canonical.getvalue()!=raw:
        raise ValueError('canonical fixture tar required')
    return files


def unpack_fixture(path,root):
    files=fixture_files(path)
    for name,body in files.items():
        target=root/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        descriptor=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(descriptor,'wb')as stream:stream.write(body)
    return root


def fixture_catalog(fixture, info, mirror):
    packages = [dict(package=row['name'], **{key: row[key] for key in
        ('version', 'arch', 'package_sha256', 'recipe_sha256', 'srcinfo_sha256')},
        source_profile='REVIEWED_ORIGINAL_RECIPE_PROFILE') for row in fixture['packages']]
    return dict(schema_version=1, purpose='release-source-mirror-catalog',
        status='VERIFIED_OFFLINE_SOURCE_MIRROR_CATALOG', mirror_sha256=mirror,
        release_sha256=fixture['release_sha256'], release_id='source-tools-two-package-'+fixture['label'],
        head_release_sha256=info['fixtures'][-1]['release_sha256'], packages=packages,
        retained_releases=[dict(release_id='source-tools-two-package-'+row['label'],
            release_sha256=row['release_sha256']) for row in info['fixtures']], synthetic=True,
        legal_acceptance=False, corresponding_source_completeness='NOT_ASSERTED',
        native_build_validation='NOT_PERFORMED', hardware_validation='NOT_RUN', release_acceptance='NOT_ADMITTED')


class CurrentNativeActorControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.T = load('source_tools_tools_v2', ACTORS/'source_tools_tools_v2.py')
        cls.C = load('source_tools_current_check_v2', INPUTS/'check_current_makepkg.py')
        cls.A = load('current_native_adapter_v2', ACTORS/'source_tools_alpm_v2.py')
        cls.P = load('current_native_probe_v2', ACTORS/'source_tools_probe_v2.py')
        cls.selection = json.loads((INPUTS/'selection-v2.json').read_bytes())
        cls.bundle = (INPUTS/'recipe-inputs-v2.tar').read_bytes()
        with tarfile.open(fileobj=io.BytesIO(cls.bundle), mode='r:') as archive:
            files = {row.name: archive.extractfile(row).read() for row in archive}
        with tarfile.open(fileobj=io.BytesIO(files['recipe/fixtures.tar.gz']), mode='r:gz') as archive:
            cls.info = json.loads(archive.extractfile('fixtures/fixtures.json').read())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='current-native-data-controls-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)/'policy-data'
        (self.root/'native').mkdir(parents=True)
        (self.root/'bootstrap/scripts/ci').mkdir(parents=True)
        for relative in ('native/expected349.lock', 'native/input-profile.json', 'bootstrap/scripts/ci/inputs.lock.json'):
            shutil.copyfile(FROZEN/relative, self.root/relative)
        old = json.loads((FROZEN/'native/source-tools-contract-v1.json').read_bytes())
        self.policy = copy.deepcopy(old)
        self.current_selection=copy.deepcopy(self.selection)
        self.policy.update(operation='source-tools-alpm-v2', checks=self.current_selection['checks'],
            current_recipe_selection=self.current_selection)
        self.policy['recipe'] = dict(version='0.2.0-1', archive='cachy-asahi-source-tools-0.2.0-1-any.pkg.tar.zst',
            expected_test_count=28, source_files=self.current_selection['recipe']['files'],
            payload_files=self.current_selection['recipe']['payload_files'])
        self.policy['bundle'] = dict(path='native/source-tools-sources-v2.tar', members=16, max_bytes=1024**2, **pin(self.bundle))
        (self.root/self.policy['bundle']['path']).write_bytes(self.bundle)
        for key, source, target in (
            ('current_package_module', 'current_package_inputs.py', 'source_tools_current_package_v2.py'),
            ('current_check_module', 'check_current_makepkg.py', 'source_tools_current_check_v2.py'),
            ('makepkg_config', 'makepkg-v2.conf', 'source-tools-makepkg-v2.conf')):
            raw = (INPUTS/source).read_bytes(); destination='native/'+target
            (self.root/destination).write_bytes(raw)
            self.policy[key] = dict(path=destination, **pin(raw))
        self.write_policy()

    def write_policy(self):
        (self.root/'native/source-tools-contract-v2.json').write_text(json.dumps(self.policy))

    def test_current_policy_binds_actual_sixteen_and_eighteen_with_held_baseline(self):
        policy, base = self.T.source_policy(self.root)
        self.assertEqual(policy['recipe']['version'], '0.2.0-1')
        self.assertEqual(len(base.splitlines()),349)
        self.assertEqual(len(policy['recipe']['source_files']),16)
        self.assertEqual(len(policy['recipe']['payload_files']),18)
        self.assertTrue(all(value is None for value in policy['actual'].values()))
        self.assertEqual(len(self.T.recipe_members(self.root,policy)),16)

    def test_legacy_version_members_payload_and_business_counts_refuse(self):
        for field, value in (('version','0.1.0-1'),('expected_test_count',17),('expected_test_count',True)):
            with self.subTest(field=field,value=value):
                saved=copy.deepcopy(self.policy);self.policy['recipe'][field]=value;self.write_policy()
                with self.assertRaises(ValueError):self.T.source_policy(self.root)
                self.policy=saved
        self.policy['recipe']['payload_files'].pop(next(iter(self.policy['recipe']['payload_files'])))
        self.write_policy()
        with self.assertRaises(ValueError):self.T.source_policy(self.root)

    def test_current_module_source_and_recipe_tamper_refuse(self):
        path=self.root/'native/source_tools_current_check_v2.py';raw=path.read_bytes();path.write_bytes(raw+b'\n# altered\n')
        with self.assertRaises(ValueError):self.T.source_policy(self.root)
        path.write_bytes(raw)
        path=self.root/'native/source-tools-sources-v2.tar';path.write_bytes(self.bundle+b'x')
        with self.assertRaises(ValueError):self.T.recipe_members(self.root,self.policy)

    def test_updated_outer_bundle_pin_does_not_allow_a_missing_current_source(self):
        with tarfile.open(fileobj=io.BytesIO(self.bundle),mode='r:')as source:
            output=io.BytesIO()
            with tarfile.open(fileobj=output,mode='w',format=tarfile.USTAR_FORMAT)as archive:
                for row in source:
                    if row.name=='recipe/source_mirror_catalog.py':continue
                    archive.addfile(row,source.extractfile(row))
        raw=output.getvalue();(self.root/self.policy['bundle']['path']).write_bytes(raw)
        self.policy['bundle'].update(pin(raw))
        with self.assertRaises(ValueError):self.T.recipe_members(self.root,self.policy)

    def test_native_policy_rejects_waived_checks_new_actuals_and_skipped_catalog(self):
        self.policy['actual']['run']='unauthorized';self.write_policy()
        with self.assertRaises(ValueError):self.T.source_policy(self.root)
        self.policy['actual']['run']=None;self.policy['checks']['catalog_tests']=0;self.write_policy()
        with self.assertRaises(ValueError):self.T.source_policy(self.root)

    def test_catalog_binds_actual_fixture_pins_for_both_history_releases(self):
        mirror='a'*64
        for fixture in self.info['fixtures']:
            catalog=fixture_catalog(fixture,self.info,mirror)
            self.assertEqual(self.P.catalog_packages(catalog,fixture,self.info,mirror),catalog['packages'])
            package=catalog['packages'][0]
            arguments=self.P.catalog_context_arguments(package,'/held/mirror.tar',mirror,fixture['release_sha256'],'/held/new-context')
            self.assertEqual(arguments,['build-context','--bundle','/held/mirror.tar','--mirror-sha256',mirror,
                '--release-sha256',fixture['release_sha256'],'--package',package['package'],'--version',package['version'],
                '--arch',package['arch'],'--package-sha256',package['package_sha256'],'--recipe-sha256',package['recipe_sha256'],
                '--srcinfo-sha256',package['srcinfo_sha256'],'--output','/held/new-context'])

    def test_catalog_mixed_release_changed_pin_missing_package_and_false_credit_refuse(self):
        fixture=self.info['fixtures'][0];catalog=fixture_catalog(fixture,self.info,'a'*64)
        for field,value in (('release_sha256','0'*64),('head_release_sha256','0'*64),('packages',catalog['packages'][:1]),
                            ('retained_releases',catalog['retained_releases'][:1]),('native_build_validation','PASS'),
                            ('synthetic',False),('legal_acceptance',True),('schema_version',True)):
            with self.subTest(field=field):
                changed=copy.deepcopy(catalog);changed[field]=value
                with self.assertRaises(ValueError):self.P.catalog_packages(changed,fixture,self.info,'a'*64)
        changed=copy.deepcopy(catalog);changed['packages'][0]['recipe_sha256']='0'*64
        with self.assertRaises(ValueError):self.P.catalog_packages(changed,fixture,self.info,'a'*64)

    def test_all_twenty_eight_unique_steps_keep_original_seventeen_then_catalog_eleven(self):
        old=ast.parse((FROZEN/'native/source_tools_probe_v1.py').read_bytes())
        steps=next(ast.literal_eval(node.value)for node in old.body if isinstance(node,ast.Assign)
            and any(isinstance(target,ast.Name)and target.id=='STEPS'for target in node.targets))
        self.assertEqual(self.P.STEPS[:17],steps)
        self.assertEqual(len(self.P.STEPS),len(set(self.P.STEPS)))
        self.assertEqual(len(self.P.STEPS),28)
        self.assertEqual(self.P.STEPS[17], 'catalog-legacy-list')
        self.assertEqual(self.P.STEPS[-1], 'catalog-wrong-pin')

    def test_current_check_binding_uses_multiline_five_objects_and_never_grants_native_credit(self):
        files=self.policy['recipe']['source_files']
        cli=dict(status='PASS',tests=9,failures=0,errors=0,evidence='PURE_DATA_FOCUSED_CLI_CONTROLS',
            current_launcher_sha256=files['cachy-asahi-source-tools']['sha256'],
            packed_private_source_sha256=files['private-source.tar.gz']['sha256'],native_build='NOT_RUN',
            alpm_installation='NOT_RUN',namespace_probe='NOT_RUN',hardware='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED')
        catalog=dict(status='PASS',tests=9,failures=0,errors=0,skipped=0,helper_sha256=files['source_mirror_catalog.py']['sha256'],
            exact_materialized_contexts=4,fixtures='TWO_PACKAGES_LEGACY_CURRENT_SYNTHETIC_ARCHIVES_REAL_ORIGINAL_RECIPE_BYTES',
            native='NOT_RUN',installation='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
        packaged=dict(status='PASS',staged_payload_files=18,checkout_hidden=True,moved_prefix=True,
            network_namespace='loopback-only',removal='EXACT_FILE_INVERSE_USER_CONTENT_PRESERVED',alpm_installation='NOT_RUN',native_build='NOT_RUN',
            workflow=dict(status='PASS',controls=17,exact_contexts=4,packages_per_release=2,retained_releases=2,
                source_execution='NOT_RUN',commands=[dict(synthetic_not_native=index)for index in range(17)]))
        rows=[cli,catalog,dict(status='PASS',payload_files=None,private_source_files=11),
            dict(status='PASS',payload_files=18,private_source_files=11),packaged]
        raw=b'SYNTHETIC_NOT_NATIVE\nStarting check()\n'+b'\n'.join(json.dumps(row,indent=2 if index==0 else None).encode()for index,row in enumerate(rows))+b'\n'
        result=self.A.check_result(raw,self.policy)
        self.assertEqual(result['check_rows'],5)
        self.assertEqual(result['native_acceptance'],'NOT_GRANTED')
        with self.assertRaises(ValueError):self.A.check_result(raw.replace(files['source_mirror_catalog.py']['sha256'].encode(),b'0'*64),self.policy)
        with self.assertRaises(ValueError):self.A.check_result(b'Starting check()\n'+b'\n'.join(json.dumps(row).encode()for row in rows[2:])+b'\n',self.policy)

    def test_sensitive_original_functions_and_limits_are_preserved(self):
        policy=json.loads((HERE/'preserved-function-identities.json').read_bytes())
        for name,functions in policy['functions'].items():
            source=(ACTORS/name).read_text().replace('source-tools-alpm-v2','source-tools-alpm-v1').replace('source_tools_probe_v2','source_tools_probe_v1').replace('source-tools-contract-v2','source-tools-contract-v1').replace('source_tools_alpm_v2','source_tools_alpm_v1')
            actual={node.name:hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest()
                for node in ast.parse(source).body if isinstance(node,ast.FunctionDef)}
            for function,digest in functions.items():self.assertEqual(actual[function],digest,(name,function))
        source=(ACTORS/'source_tools_alpm_v2.py').read_text()
        self.assertIn('timeout=180,total=450,max_output=1024**2',source)
        self.assertIn('timeout=20,total=90,max_output=1024**2',source)
        self.assertNotIn('--nocheck',source)
        self.assertEqual(self.P.NS_MODES,dict(context=0,user=0x10000000,mount=0x00020000,
            user_mount=0x10020000,user_net=0x50000000,user_mount_net=0x50020000))

    def test_portable_fixture_is_only_eight_pinned_data_members_and_tamper_refuses(self):
        path=HERE/'baseline-policy-fixtures-v1.tar'
        files=fixture_files(path)
        self.assertEqual(set(files),FIXTURE_NAMES)
        self.assertNotIn('native/owner.py',files)
        self.assertNotIn('native/source-map.json',files)
        folder=self.root/'bad-fixture';folder.mkdir()
        bad=folder/path.name;bad.write_bytes(path.read_bytes()+b'altered')
        shutil.copyfile(path.with_suffix('.json'),bad.with_suffix('.json'))
        with self.assertRaises(ValueError):fixture_files(bad)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--actor-root',type=Path,default=HERE)
    parser.add_argument('--current-inputs',type=Path,required=True)
    frozen=parser.add_mutually_exclusive_group()
    frozen.add_argument('--frozen-source',type=Path)
    frozen.add_argument('--frozen-fixture-tar',type=Path,default=HERE/'baseline-policy-fixtures-v1.tar')
    args=parser.parse_args();ACTORS=args.actor_root.resolve();INPUTS=args.current_inputs.resolve()
    temporary=None
    try:
        if args.frozen_source is not None:FROZEN=args.frozen_source.resolve()
        else:
            temporary=tempfile.TemporaryDirectory(prefix='baseline-policy-data-only-')
            FROZEN=unpack_fixture(args.frozen_fixture_tar,Path(temporary.name))
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(CurrentNativeActorControls)
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        report=dict(status='PASS'if result.wasSuccessful()else'FAIL',tests=result.testsRun,failures=len(result.failures),
            errors=len(result.errors),skipped=len(result.skipped),evidence='CURRENT_NATIVE_ROUTE_DATA_CONTROLS_SYNTHETIC_NOT_NATIVE',
            baseline_fixture='PINNED_EIGHT_FILE_DATA_SUBSET'if temporary is not None else'CALLER_RETAINED_FROZEN_SOURCE',
            actual_actor_calls=0,actual_native_builds=0,actual_ALPM=0,actual_readers=0,Source_constructor=0)
        print(json.dumps(report,sort_keys=True));raise SystemExit(not result.wasSuccessful()or bool(result.skipped))
    finally:
        if temporary is not None:temporary.cleanup()
