#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Actor-fenced synthetic bootstrap controls; no future bootstrap role executes."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('hosted_bootstrap_data_tests',HERE/'payload/hosted/bootstrap.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)


def deny(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.exec','os.fork','os.posix_spawn'):
        raise AssertionError('actor forbidden in synthetic bootstrap controls: '+event)
sys.addaudithook(deny)


def fixture():
    packages=[dict(name='original-'+str(i).zfill(3),version='1',filename='original-'+str(i)+'.pkg.tar.xz') for i in range(248)]
    rootfs=[dict(name=['base-'+str(i)],version=['1']) for i in range(93)]
    # Original package upgrades override rootfs versions; this is not a collision.
    rootfs.append(dict(name=['original-000'],version=['OLD']))
    additions=[dict(name='extra-'+str(i),version='2',filename='extra-'+str(i)+'.pkg.tar.xz') for i in range(8)]
    original=dict(rootfs_packages=rootfs,packages=packages,rootfs={'MODELED':True},keyring_files=[{'MODELED':'key'}],signer_fingerprint='MODELED')
    profile=dict(additions=dict(rows=additions))
    versions={row['name'][0]:row['version'][0] for row in rootfs}
    versions.update({row['name']:row['version'] for row in packages+additions})
    expected=''.join(name+' '+version+'\n' for name,version in sorted(versions.items())).encode()
    return original,profile,expected


def owner():return b.image_owner(dict(source='1'*40,ref='refs/heads/codex/MODELED',run='123'))


class Controls(unittest.TestCase):
    def test_real_frozen_metadata_derives_exact349_without_actors(self):
        references=HERE.parents[2]/'scripts/ci/perl5423-repro-native-source/references'
        original=json.loads((references/'original-inputs.lock.json').read_bytes())
        profile=json.loads((references/'input-profile.json').read_bytes())
        expected=(references/'expected349.lock').read_bytes()
        combined=b.combined_inputs(original,profile,expected)
        self.assertEqual(len(combined['packages']),256)
        self.assertEqual(len(combined['rootfs_packages']),165)
        self.assertEqual(hashlib.sha256(expected).hexdigest(),b.EXPECTED349)
        large={row['filename']:row['size'] for row in original['packages'] if row['size']>64*1024**2}
        self.assertEqual(large,{'linux-firmware-nvidia-20260916-1-any.pkg.tar.xz':104330276,
                               'linux-aarch64-7.2.10-1-aarch64.pkg.tar.xz':68687880})
        # The original cache-only leaf streams these; the fixed8 copy helper's
        # 64MiB per-file budget must not be applied to original package inputs.
        calls=[]
        def checked(cache,row):calls.append((cache,row));return cache/row['filename']
        for row in original['packages']:
            if row['filename'] in large:
                cache=Path('/MODELED/cache')
                self.assertEqual(b.cache_only(row,cache,time.monotonic()+30,checked),cache/row['filename'])
        self.assertEqual({row['filename'] for cache,row in calls},set(large))

    def test_combined_inputs_preserve_rootfs_signer_keyring_and_all_versions(self):
        original,profile,expected=fixture();before=copy.deepcopy((original,profile))
        with patch.object(b,'EXPECTED349',hashlib.sha256(expected).hexdigest()):
            result=b.combined_inputs(original,profile,expected)
        self.assertEqual(len(result['packages']),256)
        for key in ('rootfs','rootfs_packages','keyring_files','signer_fingerprint'):self.assertEqual(result[key],original[key])
        self.assertEqual((original,profile),before)
        self.assertIn(b'original-000 1\n',expected)
        for change in ('duplicate','missing','inventory'):
            o,p,w=copy.deepcopy((original,profile,expected))
            if change=='duplicate':p['additions']['rows'][0]=o['packages'][0]
            if change=='missing':p['additions']['rows'].pop()
            if change=='inventory':w=w.replace(b'base-0 1',b'base-0 2')
            with patch.object(b,'EXPECTED349',hashlib.sha256(expected).hexdigest()),self.subTest(change=change),self.assertRaises(ValueError):b.combined_inputs(o,p,w)

    def test_fixed_single_build_and_inventory_metadata_argv(self):
        own=owner();argv=['docker','build','--network=none','--iidfile','/MODELED/image-id','/MODELED/context'];before=argv.copy()
        actual=b._docker_argv(argv,own)
        self.assertEqual(argv,before);self.assertEqual(actual[:3],b.DOCKER+['build'])
        for value in ('--no-cache',own['tag'],b.LABEL+'='+own['token'],b.LABEL+'.source='+own['source']):self.assertIn(value,actual)
        image='sha256:'+'2'*64
        probe=['docker','run','--rm','--pull=never','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--entrypoint=/bin/cat',image,'/builder-packages.lock']
        decorated=b._docker_argv(probe,own)
        for value in ('perl-bootstrap-inventory-'+own['token'],'--cpus=1','--memory=128m','--memory-swap=128m','--pids-limit=32'):self.assertIn(value,decorated)
        with self.assertRaises(ValueError):b._docker_argv(probe[:-1]+['/etc/shadow'],own)
        self.assertEqual(b._docker_argv(['gpg','--verify'],own),['gpg','--verify'])

    def test_scoped_callback_routes_gpg_and_native_capture_and_restores_on_failure(self):
        prior=subprocess.run;old=lambda *a,**k:'OLD';native=SimpleNamespace(run=old);calls=[]
        def callback(argv,log=None,timeout=60,**kwargs):
            calls.append((argv,log,timeout,kwargs));return subprocess.CompletedProcess(argv,0,'MODELED output\n','')
        with self.assertRaisesRegex(RuntimeError,'MODELED interruption'):
            with b.native_commands(native,callback,time.monotonic()+30,owner()) as (invoke,builds):
                self.assertEqual(native.run(['docker','info'],timeout=100),'MODELED output')
                self.assertIsNone(native.run(['gpg','--import'],log=Path('/MODELED/log')))
                result=subprocess.run(['gpg','--verify'],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.stdout,'MODELED output\n')
                invoke(['docker','build','--iidfile','/MODELED/image-id'],capture_output=True)
                with self.assertRaisesRegex(ValueError,'exactly one'):invoke(['docker','build','--iidfile','/MODELED/second'])
                raise RuntimeError('MODELED interruption')
        self.assertIs(subprocess.run,prior);self.assertIs(native.run,old);self.assertFalse(b._ACTIVE)
        self.assertEqual(len(calls),4);self.assertTrue(all(0<row[2]<=30 for row in calls))

    def test_expired_nonfinite_or_wrong_thread_command_scope_refuses_before_callback(self):
        native=SimpleNamespace(run=lambda:None);callback=lambda *a,**k:(_ for _ in ()).throw(AssertionError('must not launch'))
        for deadline in (time.monotonic()-1,float('inf'),float('nan')):
            with self.subTest(deadline=deadline),self.assertRaises(ValueError):
                with b.native_commands(native,callback,deadline,owner()):pass
        with patch.object(b.threading,'current_thread',return_value=object()),self.assertRaises(ValueError):
            with b.native_commands(native,callback,time.monotonic()+30,owner()):pass
        self.assertFalse(b._ACTIVE)

    def test_existing_operation_directory_is_preserved_and_other_output_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory);out=work/'bootstrap';ops=out/'operations';ops.mkdir(parents=True,mode=0o700)
            leaf=ops/'000.stdout';leaf.write_bytes(b'MODELED daemon DATA');leaf.chmod(0o600)
            index=out/'operations.json';index.write_bytes(b'[]\n');index.chmod(0o600)
            before=leaf.stat();self.assertEqual(b.bootstrap_directory(work),out);self.assertEqual(leaf.stat(),before)
            (out/'unrecorded').write_bytes(b'MODELED stale DATA')
            with self.assertRaisesRegex(ValueError,'fresh bootstrap'):b.bootstrap_directory(work)
            (out/'unrecorded').unlink();leaf.unlink();leaf.symlink_to('/MODELED/other')
            with self.assertRaises(ValueError):b.bootstrap_directory(work)

    def test_scoped_original_import_aliases_and_path_restore(self):
        root=Path('/MODELED/source');old_path=sys.path.copy();sentinel=object();old_common=sys.modules.get('common')
        loaded=[]
        def load(name,path):
            value=SimpleNamespace(__file__=str(path))
            if path.name=='common.py':value.verify_source=lambda original,pin:loaded.append((original,pin))
            sys.modules[name]=value
            if path.name=='native_arm.py':sys.modules['package_checks']=value;sys.path.insert(0,'/MODELED/held')
            return value
        sys.modules['common']=sentinel
        try:
            with self.assertRaises(RuntimeError):
                with b.held_modules(root,SimpleNamespace(load=load)):
                    self.assertIsNot(sys.modules['common'],sentinel);raise RuntimeError('MODELED failure')
            self.assertIs(sys.modules['common'],sentinel);self.assertEqual(sys.path,old_path)
            self.assertEqual(loaded,[(root/'original',b.ORIGINAL_MAP)])
        finally:
            if old_common is None:sys.modules.pop('common',None)
            else:sys.modules['common']=old_common

    def test_retained_blob_wrapper_keeps_its_contract_and_defers_cancel_to_owned_tick(self):
        state=SimpleNamespace(cancelled=[False]);witness=[]
        def primitive_run(argv,**kwargs):
            witness.append('MODELED_OWNED_WITNESS');state.cancelled[0]=True
            kwargs['on_tick']()
        primitive=SimpleNamespace(run=primitive_run)
        def held_wrapper(argv,**kwargs):
            self.assertNotIn('on_tick',kwargs)
            return primitive.run(argv,**kwargs)
        pgo=SimpleNamespace(owned_child=lambda:primitive,owned_subprocess_run=held_wrapper);old=subprocess.run
        with self.assertRaises(ValueError):
            with b.seed_commands(pgo,state):subprocess.run(['MODELED_GIT'],capture_output=True)
        self.assertEqual(witness,['MODELED_OWNED_WITNESS']);self.assertIs(primitive.run,primitive_run);self.assertIs(subprocess.run,old)

    def test_additions_publish_only_exact_sixteen_and_preserve_prior_cache(self):
        def encode(value):return(json.dumps(value,sort_keys=True)+'\n').encode()
        def checked(path,row,deadline,destination=None):
            raw=path.read_bytes();b.need(len(raw)==row['size'] and hashlib.sha256(raw).hexdigest()==row['sha256'],'fixture exact input')
            if destination:destination.write(raw)
            return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        def inventory(cache,deadline):
            return {p.name:(p.stat().st_ino,p.stat().st_size,p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in cache.iterdir()}
        provision=SimpleNamespace(checked_file=checked,cache_inventory=inventory);common=SimpleNamespace(encode=encode)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);carrier=root/'carrier';(carrier/'packages').mkdir(parents=True);cache=root/'cache';cache.mkdir();out=root/'out';out.mkdir();rows=[]
            prior=cache/'prior';prior.write_bytes(b'MODELED preexisting DATA');before=prior.stat()
            for i in range(8):
                name='extra-'+str(i)+'.pkg.tar.xz';body=('MODELED archive '+str(i)).encode();sig=('MODELED signature '+str(i)).encode()
                (carrier/'packages'/name).write_bytes(body);(carrier/'packages'/(name+'.sig')).write_bytes(sig)
                rows.append(dict(filename=name,size=len(body),sha256=hashlib.sha256(body).hexdigest(),signature_size=len(sig),signature_sha256=hashlib.sha256(sig).hexdigest()))
            profile=dict(additions=dict(rows=rows));result=b.seed_additions(profile,carrier,cache,out,time.monotonic()+30,provision,common)
            self.assertEqual(result['status'],'PASS_FIXED_EIGHT_CACHE_DATA_ONLY');self.assertEqual(len(list(cache.iterdir())),17);self.assertEqual(prior.stat(),before)
            existing=cache/rows[0]['filename'];existing_before=existing.stat()
            result=b.seed_additions(profile,carrier,cache,out,time.monotonic()+30,provision,common)
            self.assertEqual(result['files'][rows[0]['filename']]['status'],'EXACT_EXISTING_FILE_PRESERVED');self.assertEqual(existing.stat(),existing_before)
            existing.write_bytes(b'MODELED wrong cache bytes');bad=existing.read_bytes()
            with self.assertRaises(ValueError):b.seed_additions(profile,carrier,cache,out,time.monotonic()+30,provision,common)
            self.assertEqual(existing.read_bytes(),bad);self.assertFalse(any(p.name.endswith('.partial') for p in cache.iterdir()))


if __name__=='__main__':unittest.main(verbosity=2)
