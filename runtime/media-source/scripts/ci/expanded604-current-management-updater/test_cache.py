# SPDX-License-Identifier: MIT
"""Finite real cache API controls over inert complete inventories; no actors."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
import before_cache as B
import contract as C

DEFAULT=next((p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file()),Path.cwd())
ROOT=Path(os.environ.get('EXPANDED604_SOURCE',DEFAULT))
SETUP='cachy-asahi-setup'
LSP_BYTES=5587560
PAIR=ROOT/'artifacts/development/setup5-accepted-pair-inputs-20261016/payload'


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module


class Cache(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='root604-cache-inert-');self.root=Path(self.temp.name)
        self.addCleanup(self.cleanup)
        self.block=patch.object(subprocess,'Popen',side_effect=AssertionError('all subprocess actors forbidden'))
        self.block.start();self.addCleanup(self.block.stop)
        self.real=load('_604_actual_cache_contract_'+str(id(self)),ROOT/'scripts/ci/expanded604-current-management/contract.py')
        self.output=self.root/'owned';self.output.mkdir();self.target=self.output/'ready604'
        self.ready=self.root/'original587';self.producer=self.root/'producer';self.producer.mkdir()
        self.owner=dict(purpose='expanded604-current-management-updater',output=str(self.output),producer=str(self.producer),token='a'*32,case='normal')
        (self.output/'owner.json').write_bytes(C.encoded(self.owner))
        self.roles=dict(ephemeral_TEST='A'*40,upstream_ALARM='B'*40)
        self.before,self.after=C.locks();self.after_manifest=self.cache(self.target,self.after,'READY_SIGNED_EXPANDED604',C.AFTER)
        raw=(ROOT/'scripts/ci/full-development-composition/expected-updater-v2.lock').read_bytes()
        original=dict(line.split() for line in raw.decode().splitlines())
        self.original_manifest=self.cache(self.ready,original,'READY_SIGNED_INITIAL587',hashlib.sha256(raw).hexdigest())
        self.raw=self.producer/'private';inputs=self.raw/'inputs';inputs.mkdir(parents=True)
        for name in ('expectedbase.lock','core-lifecycle.py','provider-helpers.py','TEST-public.asc','archlinuxarm.gpg'):
            (inputs/name).write_bytes(('inert-original-'+name).encode())
        self.plan=dict(hooks=[{'exact':'original-hook-record'}],signer_fingerprint=self.roles['upstream_ALARM'],
            test_signer_fingerprint=self.roles['ephemeral_TEST'],setup4={'helpers':{
                name:dict(size=(inputs/name).stat().st_size,sha256=C.sha(inputs/name)) for name in ('core-lifecycle.py','provider-helpers.py')},
                'discarded_package_metadata':'must not be selected'},discarded_other_metadata='must not become a new plan')
        self.check_calls=[];self.verifier_calls=[];self.verifier_closed=[];self.refuse_verifier=False;outer=self
        class Verifier:
            def __init__(self,home,keys):
                outer.assertEqual(home,outer.producer/'private/expanded604-before-verifier')
                outer.assertEqual(keys,[outer.target/k['path'] for k in outer.after_manifest['keyrings']])
            def __call__(self,archive,signature,signer):
                outer.verifier_calls.append((archive,signature,signer))
                if outer.refuse_verifier:raise ValueError('inert verifier refusal')
            def close(self):outer.verifier_closed.append(True)
        def checked(root,row,cap=16*1024**2):
            self.check_calls.append((root,copy.deepcopy(row),cap));return self.real.checked(root,row,cap)
        def helper(name,path):
            if name=='_root604_public_verifier':return NS(PublicVerifier=Verifier)
            return self.real.load(name,path)
        self.api=NS(BUILDER=self.real.BUILDER,checked=checked,target_manifest=self.real.target_manifest,
            load=helper,scoped_load=self.real.scoped_load)

    def cleanup(self):
        for path in self.root.rglob('*'):
            if path.is_dir():path.chmod(0o700)
        self.temp.cleanup()

    def cache(self,directory,inventory,status,digest):
        (directory/'packages').mkdir(parents=True);(directory/'keys').mkdir();rows=[];projects=[]
        for name,version in sorted(inventory.items()):
            archive='packages/'+name+'-'+version+'-any.pkg.tar.xz';path=directory/archive
            if name==SETUP and version=='0.1.0-5':
                shutil.copyfile(PAIR/'packages/cachy-asahi-setup-a/cachy-asahi-setup-0.1.0-5-any.pkg.tar.xz',path)
            else:path.write_bytes(b'\0'*LSP_BYTES if name=='lsp-plugins-lv2' else ('INERT ARCHIVE '+name+' '+version).encode())
            signature=archive+'.sig';(directory/signature).write_bytes(('INERT SIGNATURE '+name).encode())
            row=dict(name=name,version=version,archive=archive,size=path.stat().st_size,sha256=C.sha(path),signature=signature,
                signature_size=(directory/signature).stat().st_size,signature_sha256=C.sha(directory/signature),
                signer=self.roles['ephemeral_TEST' if name.startswith('cachy-asahi-') or name in self.real.AUDIO-{'lsp-plugins-lv2'} else 'upstream_ALARM'])
            rows.append(row)
            if name.startswith('cachy-asahi-'):
                projects.append(dict(name=name,version=version,archive=path.name,sha256=row['sha256'],
                    payload=[dict(path='/usr/share/'+name+'/inert',type='file',mode=0o644,sha256=row['sha256'])]))
        keys=[]
        for name in ('TEST-public.asc','archlinuxarm.gpg'):
            path=directory/'keys'/name;path.write_bytes(('INERT PUBLIC '+name).encode())
            keys.append(dict(path='keys/'+name,size=path.stat().st_size,sha256=C.sha(path)))
        builder=directory/'builder-packages.lock'
        shutil.copyfile(PAIR/'runtime/cachy-asahi-setup-a/expected-packages.lock',builder)
        (directory/'expected-installed.lock').write_text(''.join(n+' '+v+'\n' for n,v in sorted(inventory.items())))
        self.assertEqual(C.sha(directory/'expected-installed.lock'),digest)
        value=dict(schema_version=1,status=status,packages=rows,projects=projects,keyrings=keys,
            expected_lock=dict(path='expected-installed.lock',sha256=digest),
            builder_lock=dict(path='builder-packages.lock',size=builder.stat().st_size,sha256=C.sha(builder)),
            preparation=dict(signer_roles=self.roles,compressed_archive_bytes=sum(r['size'] for r in rows)))
        (directory/'manifest.json').write_bytes(C.encoded(value));return value

    def swap(self):return B.replace_setup3(self.ready,self.target,self.producer,ROOT,self.api,self.owner)
    def write_manifest(self,value):
        path=self.target/'manifest.json';path.chmod(0o600);path.write_bytes(C.encoded(value))
    def protected(self,rows):return {r['name']:r for r in rows if r['name']!=SETUP}

    def test_complete604_swap_retains603_packages20_projects_and_exact_predecessor(self):
        before_files={r['name']:{key:C.sha(self.target/r[key]) for key in ('archive','signature')} for r in self.after_manifest['packages'] if r['name']!=SETUP}
        selected=next(r for r in self.after_manifest['packages'] if r['name']==SETUP)
        predecessor=next(r for r in self.original_manifest['packages'] if r['name']==SETUP)
        self.assertEqual(selected['sha256'],C.PACKAGE);self.assertEqual(self.swap(),self.target)
        result=B.verify(self.target,self.api)
        self.assertEqual(len(result['packages']),604);self.assertEqual(len(self.protected(result['packages'])),603)
        self.assertEqual(self.protected(result['packages']),self.protected(self.after_manifest['packages']))
        self.assertEqual(len(self.protected(result['projects'])),20)
        self.assertEqual(self.protected(result['projects']),self.protected(self.after_manifest['projects']))
        self.assertEqual(next(r for r in result['packages'] if r['name']==SETUP),predecessor)
        for name,hashes in before_files.items():
            row=next(r for r in result['packages'] if r['name']==name)
            for key,digest in hashes.items():self.assertEqual(C.sha(self.target/row[key]),digest)
        self.assertFalse((self.target/selected['archive']).exists());self.assertFalse((self.target/selected['signature']).exists())
        self.assertEqual(self.verifier_calls,[(self.target/predecessor['archive'],self.target/predecessor['signature'],self.roles['ephemeral_TEST'])])
        self.assertEqual(self.verifier_closed,[True]);self.assertEqual((self.target/'packages').stat().st_mode&0o777,0o555)
        receipt=C.read(self.output/'before-cache.json');self.assertEqual(receipt['unselected_archive_records'],603)
        reference=result['copied_root604']['after604_manifest'];snapshot=C.checked(self.output,reference)
        self.assertEqual(C.read(snapshot),self.after_manifest);self.assertEqual(receipt['original_after_manifest'],reference)
        self.assertEqual(snapshot,self.output/'after604-materialized-manifest.json');self.assertEqual(snapshot.stat().st_mode&0o777,0o400)

    def test_owner_lease_refuses_before_any_target_inspection_or_verifier(self):
        for change in ({'purpose':'unrelated'},{'token':'b'*32},{'producer':str(self.root/'other-producer')}):
            with self.subTest(change=change),patch.object(self.api,'target_manifest') as inspect:
                with self.assertRaisesRegex(ValueError,'lease'):B.replace_setup3(self.ready,self.target,self.producer,ROOT,self.api,self.owner|change)
                inspect.assert_not_called()
        with patch.object(self.api,'target_manifest') as inspect,self.assertRaisesRegex(ValueError,'lease'):
            B.replace_setup3(self.ready,self.output/'foreign',self.producer,ROOT,self.api,self.owner)
        inspect.assert_not_called();self.assertEqual(self.verifier_calls,[])

    def test_actual_verify_rejects_archive_bytes_and_complete_inventory_drift(self):
        self.swap();value=C.read(self.target/'manifest.json')
        row=next(r for r in value['packages'] if r['name']=='cachy-asahi-apps');path=self.target/row['archive'];raw=path.read_bytes()
        path.chmod(0o600);path.write_bytes(raw+b'changed')
        with self.assertRaisesRegex(ValueError,'identity differs'):B.verify(self.target,self.api)
        path.write_bytes(raw)
        bad=copy.deepcopy(value);bad['packages'].pop();self.write_manifest(bad)
        with self.assertRaisesRegex(ValueError,'complete signed'):B.verify(self.target,self.api)
        bad=copy.deepcopy(value);bad['projects'][0]['version']='wrong';self.write_manifest(bad)
        with self.assertRaisesRegex(ValueError,'project payload'):B.verify(self.target,self.api)

    def test_original_same_authority_and_verifier_refusal_cannot_publish_before_cache(self):
        manifest=self.ready/'manifest.json';value=C.read(manifest)
        value['preparation']['signer_roles']={'ephemeral_TEST':'C'*40,'upstream_ALARM':'B'*40};manifest.write_bytes(C.encoded(value))
        with self.assertRaisesRegex(ValueError,'same-authority'):self.swap()
        self.assertFalse((self.output/'before-cache.json').exists());self.assertEqual(self.verifier_calls,[])
        manifest.write_bytes(C.encoded(self.original_manifest));self.refuse_verifier=True
        with self.assertRaisesRegex(ValueError,'inert verifier refusal'):self.swap()
        self.assertEqual(self.verifier_closed,[True]);self.assertFalse((self.output/'before-cache.json').exists())
        self.assertEqual(C.read(self.target/'manifest.json')['status'],'READY_SIGNED_EXPANDED604')

    def test_flat31_archives21_projects_preserves_original_hooks_signers_helpers(self):
        self.swap();expected=C.read(self.target/'manifest.json');target=self.output/'flat'
        self.assertEqual(B.flat_inputs(self.target,self.raw,target,self.plan,self.api),target)
        plan=C.read(target/'plan.json');self.assertEqual((len(plan['packages']),len(plan['projects'])),(31,21))
        for key in ('hooks','signer_fingerprint','test_signer_fingerprint'):self.assertEqual(plan[key],self.plan[key])
        self.assertEqual(plan['setup4'],dict(helpers=self.plan['setup4']['helpers']));self.assertTrue(plan['full_root_upgrade'])
        self.assertNotIn('discarded_other_metadata',plan);self.assertEqual(plan['projects'],expected['projects'])
        for name in ('expectedbase.lock','core-lifecycle.py','provider-helpers.py','TEST-public.asc','archlinuxarm.gpg'):
            self.assertEqual((target/name).read_bytes(),(self.raw/'inputs'/name).read_bytes())
        self.assertEqual(C.sha(target/'expected-installed.lock'),C.BEFORE)
        for row in plan['packages']:
            self.assertEqual(C.sha(target/row['filename']),row['sha256']);self.assertEqual(C.sha(target/(row['filename']+'.sig')),row['signature_sha256'])
        with self.assertRaisesRegex(ValueError,'fresh'):B.flat_inputs(self.target,self.raw,target,self.plan,self.api)

    def test_lsp5587560_real_bytes_use256mib_archive_bound_without_relaxing4mib_refs(self):
        self.swap();self.check_calls.clear();target=self.output/'flat-lsp';B.flat_inputs(self.target,self.raw,target,self.plan,self.api)
        row=next(r for r in C.read(self.target/'manifest.json')['packages'] if r['name']=='lsp-plugins-lv2')
        path=target/Path(row['archive']).name;self.assertEqual(path.stat().st_size,LSP_BYTES)
        self.assertEqual(C.sha(path),row['sha256'])
        calls=[cap for root,ref,cap in self.check_calls if ref['path']==row['archive']]
        self.assertEqual(calls,[256*1024**2,256*1024**2])
        ref=dict(path=row['archive'],bytes=row['size'],sha256=row['sha256'])
        with self.assertRaisesRegex(ValueError,'reference'):C.checked(self.target,ref)
        over=self.root/'overlarge.json';over.write_bytes(b' '* (4*1024**2)+b'0')
        with self.assertRaisesRegex(ValueError,'JSON'):C.read(over)

    def test_signature1mib_cap_refuses_before_flat_output(self):
        self.swap();value=C.read(self.target/'manifest.json');row=next(r for r in value['packages'] if r['name']=='lsp-plugins-lv2')
        path=self.target/row['signature'];path.chmod(0o600);path.write_bytes(b'X'*(1024**2+1))
        row.update(signature_size=path.stat().st_size,signature_sha256=C.sha(path));self.write_manifest(value)
        target=self.output/'never-flat'
        with self.assertRaisesRegex(ValueError,'reference'):B.flat_inputs(self.target,self.raw,target,self.plan,self.api)
        self.assertFalse(target.exists())


if __name__=='__main__':unittest.main(verbosity=2)
