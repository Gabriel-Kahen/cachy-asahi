#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert release-label regression; crypto actors are mocked, never credited."""
from contextlib import ExitStack, contextmanager
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'manifests/packages.toml').is_file())


def load(relative):
    # Compile proposed bytes with their eventual canonical dependency location.
    path = HERE / Path(relative).name if relative.startswith('scripts/update/') else HERE.parent / 'ci/full-root-upgrade/root_upgrade.py'
    name = 'snapshot_selection_' + Path(relative).stem
    value = SimpleNamespace(__name__=name, __file__=str(ROOT / relative))
    exec(compile(path.read_bytes(), str(path), 'exec'), value.__dict__)
    return value


snapshot = load('scripts/update/snapshot.py')
bound = load('scripts/update/bound_update.py')
driver = load('scripts/ci/full-root-upgrade/root_upgrade.py')


def encoded(value): return (json.dumps(value, sort_keys=True) + '\n').encode()
def sha(raw): return hashlib.sha256(raw).hexdigest()


class SelectionControls(unittest.TestCase):
    def settings(self):
        return dict(schema_version=1, purpose='disposable-generic-bound-update', namespace='actual.test', signer='A'*40,
            minimum_sequence=1, release_id='full-root-test', repo_name='test', metadata_sha256='1'*64,
            release_sha256='2'*64, public_keyring_sha256='3'*64, base_trust_sha256='4'*64,
            model='generic-development-only', running_kernel_release='NOT-HARDWARE-OBSERVED', operations=['repository-update'])
    def configured(self, settings):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'settings.json'; path.write_bytes(encoded(settings))
            return bound.configuration(path,sha(path.read_bytes()))
    def test_existing_config_without_new_field_stays_synthetic(self):
        value=self.configured(self.settings())
        self.assertNotIn('release_synthetic',value)
        self.assertIs(snapshot.selected_synthetic(bound.client,value),True)
    def test_explicit_actual_selection_is_pinned_boolean_and_generic_only(self):
        value=dict(self.settings(),release_synthetic=False)
        self.assertEqual(self.configured(value),value)
        self.assertIs(snapshot.selected_synthetic(bound.client,value),False)
    def test_nonboolean_values_refuse_in_both_entrypoints(self):
        for value in (0,1,None,'false',[],{}):
            settings=dict(self.settings(),release_synthetic=value)
            with self.subTest(value=value):
                with self.assertRaises(ValueError): self.configured(settings)
                with self.assertRaises(Exception): snapshot.selected_synthetic(bound.client,settings)
    def test_actual_label_cannot_be_used_as_hardware_selection(self):
        for change in (dict(model='m2-air-13'),dict(running_kernel_release='hardware'),
                       dict(operations=['install'])):
            settings=dict(self.settings(),release_synthetic=False,**change)
            with self.subTest(change=change):
                with self.assertRaises(ValueError): self.configured(settings)
                with self.assertRaises(Exception): snapshot.selected_synthetic(bound.client,settings)
    def test_unrecognized_settings_and_changed_pin_still_refuse(self):
        with self.assertRaises(ValueError): self.configured(dict(self.settings(),unknown=True))
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'settings.json'; path.write_bytes(encoded(dict(self.settings(),release_synthetic=False)))
            with self.assertRaisesRegex(ValueError,'configuration changed'): bound.configuration(path,'0'*64)


class AuthenticationControls(unittest.TestCase):
    settings = SelectionControls.settings
    def fixture(self, root, metadata_label=False, spec_label=False):
        bundle=root/'source'; bundle.mkdir()
        spec=dict(synthetic=spec_label,release_id='full-root-test',repo_name='test')
        (bundle/'spec.json').write_bytes(encoded(spec))
        release=dict(schema_version=1,release_id='full-root-test',signer='A'*40,created_utc='2026-10-16T00:00:00Z',
                     packages=[],files={'spec.json':sha((bundle/'spec.json').read_bytes())},symlinks={})
        raw=encoded(release); (bundle/'release.json').write_bytes(raw); (bundle/'release.json.sig').write_bytes(b'INERT SIGNATURE')
        meta=root/'metadata.json'; meta.write_bytes(encoded(dict(synthetic=metadata_label,release_id='full-root-test',repo_name='test')))
        signature=root/'metadata.json.sig'; signature.write_bytes(b'INERT SIGNATURE')
        key=root/'public.gpg'; key.write_bytes(b'INERT PUBLIC CERTIFICATE')
        workspace=root/'work'; workspace.mkdir(mode=0o700)
        settings=dict(self.settings(),metadata_sha256=sha(meta.read_bytes()),release_sha256=sha(raw),public_keyring_sha256=sha(key.read_bytes()))
        args=SimpleNamespace(bundle=str(bundle),metadata=str(meta),signature=str(signature),public_keyring=str(key),state_dir=str(root/'state'))
        client=snapshot.module('selection_fixture_client',ROOT/'scripts/client/client.py')
        verify=Mock(return_value=dict(metadata_sha256=settings['metadata_sha256'],release_sha256=settings['release_sha256']))
        semantic=Mock(return_value=(release,spec)); client.verify=verify
        release_api=SimpleNamespace(verify_release=semantic)
        return args,workspace,settings,client,release_api,verify,semantic
    def context(self, client, release_api):
        stack=ExitStack()
        stack.enter_context(patch.object(snapshot,'module',side_effect=lambda name,path:client if 'client' in name else release_api))
        stack.enter_context(patch.object(snapshot,'public_home',return_value={}))
        self.addCleanup(stack.close); return stack
    def test_actual_metadata_reproduces_old_default_refusal_before_crypto(self):
        with tempfile.TemporaryDirectory() as temp:
            args,work,settings,c,r,verify,semantic=self.fixture(Path(temp))
            self.context(c,r)
            with self.assertRaisesRegex(Exception,'synthetic label'), snapshot.authenticated(args,work,settings): pass
            verify.assert_not_called(); semantic.assert_not_called(); self.assertFalse((work/'authenticated').exists())
    def test_explicit_actual_pair_reaches_both_unchanged_verifiers_and_recheck(self):
        with tempfile.TemporaryDirectory() as temp:
            args,work,settings,c,r,verify,semantic=self.fixture(Path(temp)); settings['release_synthetic']=False
            self.context(c,r)
            with snapshot.authenticated(args,work,settings) as row:
                self.assertIs(row['metadata']['synthetic'],False); self.assertIs(row['spec']['synthetic'],False)
                self.assertTrue(row['recheck']()); verify.assert_called_once(); semantic.assert_called_once()
                self.assertIs(verify.call_args.args[0].apply,False)
            self.assertFalse((work/'authenticated').exists())
    def test_legacy_synthetic_pair_still_reaches_unchanged_verifiers(self):
        with tempfile.TemporaryDirectory() as temp:
            args,work,settings,c,r,verify,semantic=self.fixture(Path(temp),True,True); self.context(c,r)
            with snapshot.authenticated(args,work,settings) as row: self.assertIs(row['spec']['synthetic'],True)
            verify.assert_called_once(); semantic.assert_called_once()
    def test_actual_label_rejects_synthetic_metadata_before_crypto(self):
        for label in (True,0,None):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp:
                args,work,settings,c,r,verify,semantic=self.fixture(Path(temp),label,False)
                settings['release_synthetic']=False; self.context(c,r)
                with self.assertRaisesRegex(Exception,'synthetic label'), snapshot.authenticated(args,work,settings): pass
                verify.assert_not_called(); semantic.assert_not_called()
    def test_metadata_release_and_repository_identity_still_exact(self):
        for field in ('release_id','repo_name'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                args,work,settings,c,r,verify,semantic=self.fixture(Path(temp)); settings['release_synthetic']=False
                metadata=json.loads(Path(args.metadata).read_bytes()); metadata[field]='other'
                Path(args.metadata).write_bytes(encoded(metadata)); settings['metadata_sha256']=sha(Path(args.metadata).read_bytes())
                self.context(c,r)
                with self.assertRaisesRegex(Exception,'identity differs'), snapshot.authenticated(args,work,settings): pass
                verify.assert_not_called(); semantic.assert_not_called()
    def test_verified_spec_release_and_repository_identity_still_exact(self):
        for field in ('release_id','repo_name'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                args,work,settings,c,r,verify,semantic=self.fixture(Path(temp)); settings['release_synthetic']=False
                semantic.return_value[1][field]='other'; self.context(c,r)
                with self.assertRaisesRegex(Exception,'semantic release selection'), snapshot.authenticated(args,work,settings): pass
                verify.assert_called_once(); semantic.assert_called_once()
    def test_metadata_spec_mismatch_refuses_after_semantic_verifier(self):
        with tempfile.TemporaryDirectory() as temp:
            args,work,settings,c,r,verify,semantic=self.fixture(Path(temp),False,True); settings['release_synthetic']=False
            self.context(c,r)
            with self.assertRaisesRegex(Exception,'semantic release selection'), snapshot.authenticated(args,work,settings): pass
            verify.assert_called_once(); semantic.assert_called_once()
    def test_invalid_signature_or_semantics_never_yields_actual_snapshot(self):
        for stage in ('signature','semantics'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temp:
                args,work,settings,c,r,verify,semantic=self.fixture(Path(temp)); settings['release_synthetic']=False
                self.context(c,r)
                (verify if stage=='signature' else semantic).side_effect=c.Error('INERT verifier rejection')
                with self.assertRaisesRegex(Exception,'verifier rejection'), snapshot.authenticated(args,work,settings): pass
                verify.assert_called_once()
                if stage=='signature': semantic.assert_not_called()
    def test_actual_recheck_still_rejects_original_or_snapshot_drift(self):
        for location in ('source','snapshot'):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as temp:
                args,work,settings,c,r,verify,semantic=self.fixture(Path(temp)); settings['release_synthetic']=False
                self.context(c,r)
                with snapshot.authenticated(args,work,settings) as row:
                    target=Path(args.bundle)/'spec.json' if location=='source' else row['bundle']/'spec.json'
                    target.chmod(0o600); target.write_bytes(b'CHANGED')
                    with self.assertRaisesRegex(Exception,'drifted'): row['recheck']()


class FullRootCallerControl(unittest.TestCase):
    def test_actual_driver_writes_hash_bound_false_selection_before_update(self):
        before,_=driver.selection(ROOT)
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp); data=home/'data'; data.mkdir(mode=0o700)
            workspace,source=home/'copy',home/'source'; source.mkdir()
            copied=dict(copy=dict(copy_complete=True,excluded=[],copy_byte_identical_before_initialization=True),cleanup='NOT RUN')
            @contextmanager
            def copy_root(*args,**kwargs):
                try: yield workspace/'root',copied
                finally: copied['cleanup']='PASS-owned-workspace-removed'
            nodes={'home/inert':dict(type='file')}
            bound_api=SimpleNamespace(install=SimpleNamespace(private=lambda path,uid:path),guard=Mock(),trust_digest=lambda _: '4'*64)
            config=dict(platform_mode='generic-development',before_lock_sha256=driver.BEFORE,after_lock_sha256=driver.AFTER,
                        limits=dict(root_nodes=200000,root_bytes=6*1024**3,file_bytes=1024**3,package_files=500000))
            scale=SimpleNamespace(bound=bound_api,configuration=lambda *a:config,roots=SimpleNamespace(Limits=lambda **kw:kw))
            generic=SimpleNamespace(asahi=SimpleNamespace(REQUIRED_UNITS={'system':set()}),read_policy=Mock())
            runtime=SimpleNamespace(tree=Mock(return_value=nodes),policy_module=generic)
            captured={}
            def apply(args):
                selected=bound.configuration(args.settings,args.settings_sha256)
                captured.update(selected)
                return dict(status='FAIL',commit_started=False,packages_committed=False,checkpoint_changed=False)
            api=SimpleNamespace(scale=scale,Runtime=lambda *a:runtime,apply=apply)
            bundle=home/'bundle'; bundle.mkdir(); (bundle/'release.json').write_bytes(b'INERT RELEASE')
            metadata,keyring=home/'metadata.json',home/'public.gpg'
            metadata.write_bytes(b'INERT METADATA'); keyring.write_bytes(b'INERT CERTIFICATE')
            release=dict(status='SIGNED_DEVELOPMENT_CONSTRUCTION',bundle=bundle,metadata=metadata,
                         signature=home/'metadata.sig',public_keyring=keyring,release_id='full-root-test',repo_name='test',signer='A'*40)
            constructor=SimpleNamespace(construct=Mock(return_value=release))
            args=SimpleNamespace(source_root=ROOT,scale='unused',scale_sha256='unused',data=data,workspace=workspace,
                                 source=source,copy_seconds=1,namespace='actual.test',sequence=1,repo_name='test')
            packages=[dict(name=n,version=v) for n,v in before.items()]
            with patch.object(driver,'database',return_value=packages), patch.object(driver,'ownership',return_value=(set(),['linux-aarch64'])):
                result=driver.run(args,runtime_module=api,copy_module=SimpleNamespace(copied_root=copy_root),
                    constructor=constructor,prepare_copy=lambda *a:dict(status='PASS',root_initialized=True,source_preserved=True))
            self.assertIs(captured.get('release_synthetic'),False,result)
            self.assertEqual(captured['model'],'generic-development-only')
            self.assertEqual(result['copy_cleanup'],'PASS-owned-workspace-removed')
            self.assertIs(result['commit_started'],False); self.assertEqual(result['status'],'FAIL')


if __name__=='__main__': unittest.main()
