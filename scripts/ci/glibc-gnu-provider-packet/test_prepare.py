#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert synthetic controls. No native build, acceptance or installation credit."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import prepare as p

ROOT = next(root for root in Path(__file__).resolve().parents if (root/'manifests/packages.toml').is_file())


def archive(rows, mode):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode=mode) as stream:
        for name,raw in rows.items():
            info = tarfile.TarInfo(name); info.size = len(raw); info.mode = 0o644
            stream.addfile(info, io.BytesIO(raw))
    return out.getvalue()


def elf(interp=None):
    raw = bytearray(512); raw[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<H', raw, 18, 183); struct.pack_into('<Q', raw, 32, 64)
    struct.pack_into('<HH', raw, 54, 56, 2 if interp else 1)
    struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0, 0, len(raw), len(raw), 16384)
    if interp:
        value = interp.encode()+b'\0'; raw[256:256+len(value)] = value
        struct.pack_into('<IIQQQQQQ', raw, 120, 3, 4, 256, 256, 256, len(value), len(value), 1)
    return bytes(raw)


class Fixture:
    def __init__(self, root):
        self.root = root; self.collection = root/'collection'; self.collection.mkdir()
        self.files = {}; f = self.files
        self.runtime = ROOT/'scripts/ci/glibc-owned-runtime'
        harness = ROOT/'scripts/ci/glibc-gnu-provider'
        manifest = json.loads((harness/'source-manifest.json').read_bytes())
        for name in manifest['files']: f['build-harness/'+name] = (harness/name).read_bytes()
        f['build-harness/source-manifest.json'] = (harness/'source-manifest.json').read_bytes()
        sources = json.loads((self.runtime/'source-manifest.json').read_bytes())['files']
        original = {n:sources[n] for n in ('abi_smoke.c','exec_child.c','probe.c','probe.h','plugin.c','runner.py')}
        patched = copy.deepcopy(original); patched['abi_smoke.c'] = dict(bytes=12437,sha256=p.NORMAL)
        license_names = ('COPYINGv2','COPYING.LESSERv2','LICENSES')
        license_rows = {n:('synthetic-license-'+n).encode() for n in license_names}
        gnu = archive({'glibc-2.43/'+n:raw for n,raw in license_rows.items()}, 'w:gz')
        src = {n.removeprefix('source/'):(ROOT/'packages/core/cachy-asahi-glibc-gnu-provider'/n.removeprefix('source/')).read_bytes()
               for n in p.FROZEN_RECIPE if n.startswith('source/')}
        src.update({'glibc-2.43.tar.gz':gnu, 'glibc-2.43.tar.gz.sig':b'synthetic-signature',
                    'gnu-keyring.gpg':b'synthetic-keyring', 'source-authentication.json':b'{"synthetic":true}\n'})
        self.gnu = {n:p.digest(src[n]) for n in p.GNU}
        for n,raw in src.items(): f['source/'+n] = raw
        f['source/bundle.json'] = p.encoded(dict(status='SOURCE_BUNDLE_READY_UNSELECTED_GNU_PROVIDER',files={n:p.digest(v) for n,v in src.items()}))
        recipe = p.digest(src['PKGBUILD'])['sha256']
        info = ('pkgname = cachy-asahi-glibc-gnu-provider\npkgver = 2.43.caa1-1\narch = aarch64\n'
                'provides = glibc=2.43\nconflict = glibc\nbackup = etc/gai.conf\ndepend = filesystem\n'
                'depend = tzdata\ndepend = linux-api-headers>=4.10\n').encode()
        build = ('format = 2\npkgname = cachy-asahi-glibc-gnu-provider\npkgver = 2.43.caa1-1\npkgarch = aarch64\n'
                 'pkgbuild_sha256sum = '+recipe+'\n').encode()
        package = {'.PKGINFO':info,'.BUILDINFO':build,'.MTREE':b'synthetic-mtree'}
        for n in ('etc/gai.conf','usr/lib/libc.so.6','usr/lib/libm.so.6','usr/lib/ld-linux-aarch64.so.1',
                  'usr/lib/gconv/ISO8859-1.so','usr/lib/locale/C.utf8/LC_CTYPE'): package[n] = b'synthetic-payload'
        package.update({'usr/share/licenses/cachy-asahi-glibc-gnu-provider/'+n:raw for n,raw in license_rows.items()})
        pkg = archive(package,'w:xz'); self.package_sha = p.digest(pkg)['sha256']
        lock = b''.join(('synthetic-package-%03d 1\n'%i).encode() for i in range(574))
        self.lock = p.digest(lock)['sha256']; f['base/installed-packages.lock'] = lock
        f['base/report.json'] = p.encoded(dict(status='PASS_NATIVE_OFFLINE_574_TRANSACTION'))
        self.private = (ROOT/'artifacts/development/glibc16k-run38941180852/root-verification.json').read_bytes()
        self.private_runtime = (ROOT/'artifacts/development/glibc16k-run38941180852/runtime.json').read_bytes()
        seed = str(p.RUN)+':1:'+p.SOURCE
        token = p.hashlib.sha256(('glibc-provider-consumer:'+seed).encode()).hexdigest()[:32]
        proof = dict(status='SOURCE_PROOF_PASS',source_sha=p.SOURCE,workflow_sha=p.SOURCE,run_id=str(p.RUN),run_attempt='1',
                     consumer_token=token,job_token=p.hashlib.sha256(('glibc-provider-producer:'+seed).encode()).hexdigest()[:16],
                     private16k=dict(**p.digest(self.private_runtime),root_verification=p.digest(self.private)))
        f['source-proof.json'] = p.encoded(proof)
        cleanup = [dict(container='caa-glibc-provider-'+token+'-'+s,status='PASS-absence-verified') for s in ('b-smoke','b','a-smoke','a','probe')]
        f['ordered-cleanup.json'] = p.encoded(dict(status='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP',
            consumer=dict(status='PASS_CONSUMERS_RETIRED',containers=cleanup),
            producer=dict(status='PASS',probe=dict(absence_verified=True),image=dict(absence_verified=True))))
        def command(directory, count):
            rows=[]
            for i in range(count):
                row=dict(exit_code=0,group_absence_verified=True,argv=['synthetic-inert-record'])
                for suffix in ('stdout','stderr'):
                    raw = b'synthetic output\n' if suffix == 'stdout' else b''
                    f[directory+'/command-%02d.'%i+suffix] = raw
                    row[suffix+'_bytes']=len(raw); row[suffix+'_sha256']=p.digest(raw)['sha256']
                rows.append(row)
            return rows
        builds=[]
        for side in ('a','b'):
            prefix='runtime/'+side+'/' ; evidence=prefix+'evidence/'
            f['packages/'+side+'/'+p.PACKAGE] = pkg
            for n in ('.PKGINFO','.BUILDINFO','.MTREE'): f[prefix+'package-metadata/'+n]=package[n]
            for n in ('check-exit','abi-exit','makepkg-exit'): f[evidence+n]=b'0\n'
            for n in ('packages-before.lock','packages-after.lock','packages-runtime.lock'): f[evidence+n]=lock
            f[evidence+'generated.SRCINFO']=f['build-harness/expected.SRCINFO']
            f[evidence+'upstream-tests.json']=p.encoded(dict(status='PASS_UPSTREAM_APPLICABLE_TESTS',check_exit=0,abi_exit=0,
                malformed=[],counts=dict(PASS=1,FAIL=0,XFAIL=0,XPASS=0,UNSUPPORTED=0,ERROR=0),
                results=[dict(path='test.test-result',status='PASS',name='synthetic',sha256='1'*64)]))
            f[evidence+'provider-stage.json']=p.encoded(dict(status='PASS_INERT_PROVIDER_STAGING',dirname_object_bytes=18))
            f[evidence+'provider-ownership.json']=p.encoded(dict(status='PASS_HELD574_PROVIDER_FILE_OWNERSHIP',checked_packages=574,inventory_sha256=self.lock,other_owner_collisions={}))
            f[evidence+'static-abi.json']=p.encoded(dict(status='PASS_STATIC_PUBLIC_ABI',libraries=[dict(library=n,missing=[],baseline_symbols=1) for n in sorted(p.ABI_LIBRARIES)]))
            f[prefix+'header-check/receipt.json']=p.encoded(dict(status='PASS_CANDIDATE_C_HEADERS_COMPILE_ONLY',bootstrap_libc_header_fallback=False,dependencies={'synthetic':p.digest(b'x')}))
            f[prefix+'runtime-inputs.json']=b'{"synthetic":true}\n'
            runtime=dict(status='PASS_OWNED_CANDIDATE_GLIBC_RUNTIME_SMOKE',mode='NATIVE_EXECUTE',host_architecture='aarch64',
                input_sha256=p.digest(f[prefix+'runtime-inputs.json'])['sha256'],runtime=dict(status='PASS',cases=8),cases=sorted(p.CASES),
                commands=command(prefix+'runtime-smoke',14),
                sources={n:dict(**v,device_major=8,device_minor=1,inode=100+i) for i,(n,v) in enumerate(original.items())})
            f[prefix+'runtime-smoke/receipt.json']=p.encoded(runtime)
            compiled={}
            for n in sorted(p.BINARIES):
                interp=None if n=='plugin.so' else '/lib/ld-linux-aarch64.so.1'
                raw=elf(interp); f[prefix+'normal-clients/bin/'+n]=raw
                compiled[n]=dict(**p.digest(raw),elf_machine=183,artifact='bin/'+n,interpreter=interp)
            patchrow=dict(exit_code=0,group_absence_verified=True)
            for suffix in ('stdout','stderr'):
                raw=b'synthetic patch\n' if suffix=='stdout' else b''
                f[prefix+'normal-clients/patch.'+suffix]=raw
                patchrow[suffix+'_bytes']=len(raw);patchrow[suffix+'_sha256']=p.digest(raw)['sha256']
            receipt=dict(status='PASS_COMPILED_NORMAL_INTERPRETER_CLIENTS_NOT_EXECUTED',
                policy_sha256=p.digest(f['build-harness/normal-client-policy.json'])['sha256'],runtime_manifest_sha256=p.SMOKE,
                sources=patched,original_sources=original,bootstrap_headers={'synthetic':p.digest(b'x')},compiled_files=compiled,
                commands=command(prefix+'normal-clients/build',13),source_patch_command=patchrow,
                toolchain={**{n:p.digest(b'synthetic-tool') for n in ('gcc','cc1','collect2','as','ld')},'version':'synthetic'},
                source_patch_tool=p.digest(b'synthetic-patch-tool'))
            f[prefix+'normal-clients/receipt.json']=p.encoded(receipt)
            builds.append(dict(side=side,container='caa-glibc-provider-'+token+'-'+side,sha256=self.package_sha,
                makepkg_exit=0,status='PASS_NATIVE_BUILD_TEST_ABI_RUNTIME',
                runtime_receipt_sha256=p.digest(f[prefix+'runtime-smoke/receipt.json'])['sha256'],
                normal_compile_receipt_sha256=p.digest(f[prefix+'normal-clients/receipt.json'])['sha256'],
                normal_clients={n:compiled[n]['sha256'] for n in compiled}))
        f['runtime/result.json']=p.encoded(dict(status='PASS_UNSELECTED_NATIVE_PAIR',archive_bytes_reproduced=True,
            normal_client_bytes_reproduced=True,source_bundle_preserved=True,frozen_sources_preserved=True,
            ownership_token=token,base_lock_sha256=self.lock,builds=builds,cleanup=cleanup,
            source_bundle_manifest_sha256=p.digest(f['source/bundle.json'])['sha256'],
            harness_manifest_sha256=p.digest(f['build-harness/source-manifest.json'])['sha256']))
        self.held=b'synthetic-held archive'; (root/p.HELD).write_bytes(self.held)
        self.args=SimpleNamespace(collection=self.collection,output=root/'packet',pair_decision=root/'pair.json',
            normal_decision=root/'normal.json',private16k=root/'private.json',private_runtime=root/'private-runtime.json',
            runtime_sources=self.runtime,held=root/p.HELD)
        self.args.private16k.write_bytes(self.private); self.args.private_runtime.write_bytes(self.private_runtime)
        self.publish()

    def publish(self):
        f = self.files
        rows={n:dict(**p.digest(raw),source_bytes=len(raw),truncated=False) for n,raw in f.items() if n!='retention.json'}
        f['retention.json']=p.encoded(dict(status='PASS_UNSELECTED_GNU_PROVIDER_NATIVE_PAIR_EVIDENCE',errors=[],files=rows,
                                         total_bytes=sum(r['bytes'] for r in rows.values())))
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
            for n,raw in f.items(): z.writestr(n,raw)
        raw=out.getvalue(); (self.collection/'artifact.zip').write_bytes(raw)
        (self.collection/'logs.zip').write_bytes(b'synthetic-original-logs')
        (self.collection/'collection.json').write_bytes(p.encoded({n:p.digest((self.collection/n).read_bytes()) for n in ('artifact.zip','logs.zip')}))
        (self.collection/'run.json').write_bytes(p.encoded(dict(id=p.RUN,head_sha=p.SOURCE,status='completed',conclusion='success',run_attempt=1)))
        (self.collection/'artifacts.json').write_bytes(p.encoded(dict(artifacts=[dict(workflow_run=dict(id=p.RUN,head_sha=p.SOURCE),
            digest='sha256:'+p.digest(raw)['sha256'],expired=False,size_in_bytes=len(raw),name='glibc-gnu-provider-'+str(p.RUN)+'-1')])) )
        join=dict(run_id=p.RUN,source_sha=p.SOURCE,artifact_sha256=p.digest(raw)['sha256'],retention_sha256=p.digest(f['retention.json'])['sha256'])
        self.args.pair_decision.write_bytes(p.encoded(dict(**join,status='ROOT_ACCEPTED_PROVIDER_NATIVE_PAIR',hardware='NOT_RUN',
            archive_sha256=self.package_sha,provider_pkgbuild_sha256=p.digest(f['source/PKGBUILD'])['sha256'])))
        self.args.normal_decision.write_bytes(p.encoded(dict(**join,status='ROOT_ACCEPTED_NORMAL_INTERPRETER_PROBES',normal_source_sha256=p.NORMAL,
            files={n:p.ref('runtime/a/normal-clients/bin/'+n,f['runtime/a/normal-clients/bin/'+n]) for n in sorted(p.BINARIES)},
            compile_receipts={s:p.ref('runtime/'+s+'/normal-clients/receipt.json',f['runtime/'+s+'/normal-clients/receipt.json']) for s in ('a','b')})))


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='SYNTHETIC-provider-packet-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.f=Fixture(self.root)
        for name,value in (('LOCK',self.f.lock),('HELD_SHA',p.digest(self.f.held)['sha256']),('GNU',self.f.gnu)):
            patcher=patch.object(p,name,value);patcher.start();self.addCleanup(patcher.stop)
        blocker=patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden in inert materializer'))
        blocker.start();self.addCleanup(blocker.stop)

    def refuse(self):
        with self.assertRaises((ValueError,KeyError,OSError)): p.prepare(self.f.args)
        self.assertFalse(self.f.args.output.exists())
        self.assertEqual(list(self.root.glob('.packet-*')),[])

    def change(self,name,fn):
        value=json.loads(self.f.files[name]);fn(value);self.f.files[name]=p.encoded(value);self.f.publish()

    def test_complete_packet_is_accepted_by_real_owner_data_gate(self):
        before={n:p.digest(raw) for n,raw in self.f.files.items()}
        result=p.prepare(self.f.args);self.assertEqual(result['installed'],'NOT_RUN')
        index=json.loads((self.f.args.output/'packet.json').read_bytes())
        self.assertTrue(all(r['bytes']>0 for r in index['files'].values()))
        self.assertNotIn('runtime/a/normal-clients/build/command-00.stderr',index['files'])
        source=json.loads((self.f.args.output/'source-map.json').read_bytes())
        self.assertEqual(source['files']['runtime/a/normal-clients/build/command-00.stderr']['bytes'],0)
        self.assertEqual(before,{n:p.digest(raw) for n,raw in self.f.files.items()})
        spec=importlib.util.spec_from_file_location('real_owner',ROOT/'scripts/ci/glibc-gnu-provider-lifecycle-owner/job.py')
        owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
        spec=importlib.util.spec_from_file_location('real_common',ROOT/'scripts/ci/glibc-gnu-provider-lifecycle/common.py')
        common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common);common.HELD_SHA=p.HELD_SHA
        binding=dict(packet=dict(directory='packet',index_sha256=p.digest((self.f.args.output/'packet.json').read_bytes())['sha256']))
        with patch.object(owner,'selection',return_value=binding),patch.object(owner,'load',return_value=common):
            directory,accepted=owner.packet(ROOT,self.root)
        self.assertEqual(directory,self.f.args.output);self.assertEqual(accepted,index)

    def test_actual_shape_has_no_source_srcinfo(self):
        self.assertNotIn('source/.SRCINFO', self.f.files)
        p.native(self.f.files, json.loads((self.f.collection/'run.json').read_bytes()))

    def test_each_generated_srcinfo_must_match(self):
        for side in ('a','b'):
            with self.subTest(side=side):
                name='runtime/'+side+'/evidence/generated.SRCINFO'
                original=self.f.files[name]
                self.f.files[name]=original+b'pkgrel = 99\n'
                with self.assertRaisesRegex(ValueError, 'actual SRCINFO expectation'):
                    p.native(self.f.files, json.loads((self.f.collection/'run.json').read_bytes()))
                self.f.files[name]=original

    def test_expected_srcinfo_cannot_be_replaced_alongside_both_generated(self):
        for name in ('build-harness/expected.SRCINFO','runtime/a/evidence/generated.SRCINFO','runtime/b/evidence/generated.SRCINFO'):
            self.f.files[name]+=b'pkgrel = 99\n'
        manifest=json.loads(self.f.files['build-harness/source-manifest.json'])
        manifest['files']['expected.SRCINFO']=p.digest(self.f.files['build-harness/expected.SRCINFO'])
        self.f.files['build-harness/source-manifest.json']=p.encoded(manifest)
        result=json.loads(self.f.files['runtime/result.json'])
        result['harness_manifest_sha256']=p.digest(self.f.files['build-harness/source-manifest.json'])['sha256']
        self.f.files['runtime/result.json']=p.encoded(result)
        self.f.publish();self.refuse()

    def test_frozen_recipe_bytes_refuse_even_with_refreshed_bundle(self):
        self.f.files['source/stage.py']+=b'# changed\n'
        bundle=json.loads(self.f.files['source/bundle.json'])
        bundle['files']['stage.py']=p.digest(self.f.files['source/stage.py'])
        self.f.files['source/bundle.json']=p.encoded(bundle)
        result=json.loads(self.f.files['runtime/result.json'])
        result['source_bundle_manifest_sha256']=p.digest(self.f.files['source/bundle.json'])['sha256']
        self.f.files['runtime/result.json']=p.encoded(result)
        self.f.publish();self.refuse()

    def test_invented_source_srcinfo_refuses(self):
        self.f.files['source/.SRCINFO']=self.f.files['build-harness/expected.SRCINFO']
        self.f.publish();self.refuse()

    def test_runtime_source_extra_inode_fields_preserve_exact_byte_join(self):
        runtime=json.loads(self.f.files['runtime/a/runtime-smoke/receipt.json'])
        normal=json.loads(self.f.files['runtime/a/normal-clients/receipt.json'])
        self.assertNotEqual(runtime['sources'], normal['original_sources'])
        p.native(self.f.files, json.loads((self.f.collection/'run.json').read_bytes()))

    def test_runtime_source_content_mismatch_refuses_with_fresh_export(self):
        self.change('runtime/a/runtime-smoke/receipt.json',lambda v:v['sources']['probe.c'].update(sha256='0'*64))
        result=json.loads(self.f.files['runtime/result.json'])
        result['builds'][0]['runtime_receipt_sha256']=p.digest(self.f.files['runtime/a/runtime-smoke/receipt.json'])['sha256']
        self.f.files['runtime/result.json']=p.encoded(result)
        self.f.publish();self.refuse()

    def test_running_run_refuses_before_output(self):
        file=self.f.collection/'run.json';value=json.loads(file.read_bytes());value['status']='in_progress';file.write_bytes(p.encoded(value));self.refuse()

    def test_collection_hash_mismatch_refuses(self):
        with (self.f.collection/'artifact.zip').open('ab') as out:out.write(b'changed')
        self.refuse()

    def test_root_decision_is_required_and_cannot_cross_join(self):
        value=json.loads(self.f.args.pair_decision.read_bytes());value['source_sha']='0'*40
        self.f.args.pair_decision.write_bytes(p.encoded(value));self.refuse()

    def test_normal_decision_must_bind_original_compile_receipts(self):
        value=json.loads(self.f.args.normal_decision.read_bytes());value['compile_receipts']['b']['sha256']='0'*64
        self.f.args.normal_decision.write_bytes(p.encoded(value));self.refuse()

    def test_unaccepted_status_refuses(self):
        value=json.loads(self.f.args.pair_decision.read_bytes());value['status']='NOT_RUN'
        self.f.args.pair_decision.write_bytes(p.encoded(value));self.refuse()

    def test_upstream_aggregate_cannot_hide_failed_record(self):
        self.change('runtime/a/evidence/upstream-tests.json',lambda v:v['results'][0].update(status='FAIL'));self.refuse()

    def test_compiler_output_loss_refuses_even_with_refreshed_export(self):
        self.f.files['runtime/a/normal-clients/build/command-12.stdout']=b'changed'
        self.f.publish();self.refuse()

    def test_same_container_cannot_pose_as_two_builds(self):
        self.change('runtime/result.json',lambda v:v['builds'][1].update(container=v['builds'][0]['container']));self.refuse()

    def test_cleanup_requires_each_native_consumer(self):
        self.change('ordered-cleanup.json',lambda v:v['consumer']['containers'].pop());self.refuse()

    def test_embedded_buildinfo_must_join_retained_bytes(self):
        self.f.files['runtime/b/package-metadata/.BUILDINFO']+=b'# substituted\n'
        self.f.publish();self.refuse()

    def test_wrong_elf_interpreter_refuses(self):
        with self.assertRaises(ValueError):p.interpreter(b'not ELF')
        self.assertEqual(p.interpreter(elf('/opt/caa/loader')),'/opt/caa/loader')
        native=json.loads(self.f.files['runtime/result.json'])
        for side in ('a','b'):
            prefix='runtime/'+side+'/normal-clients/'
            raw=elf('/opt/caa/loader');self.f.files[prefix+'bin/smoke-normal']=raw
            receipt=json.loads(self.f.files[prefix+'receipt.json'])
            receipt['compiled_files']['smoke-normal'].update(**p.digest(raw),interpreter='/opt/caa/loader')
            self.f.files[prefix+'receipt.json']=p.encoded(receipt)
            row=next(r for r in native['builds'] if r['side']==side)
            row['normal_clients']['smoke-normal']=p.digest(raw)['sha256']
            row['normal_compile_receipt_sha256']=p.digest(self.f.files[prefix+'receipt.json'])['sha256']
        self.f.files['runtime/result.json']=p.encoded(native)
        self.f.publish();self.refuse()

    def test_held_archive_digest_cannot_be_substituted(self):
        self.f.args.held.write_bytes(b'other synthetic held archive');self.refuse()

    def test_frozen_runtime_sources_must_match_compile_receipt(self):
        runtime=self.root/'runtime-source';runtime.mkdir()
        for n in ('source-manifest.json','LICENSE','abi_smoke.c','exec_child.c','probe.c','probe.h','plugin.c','runner.py'):
            (runtime/n).write_bytes((self.f.runtime/n).read_bytes())
        (runtime/'probe.c').write_bytes(b'changed source')
        self.f.args.runtime_sources=runtime;self.refuse()

    def test_truncated_complete_receipt_is_refused(self):
        report=json.loads(self.f.files['retention.json'])
        report['files']['runtime/a/normal-clients/receipt.json']['source_bytes']+=1
        report['files']['runtime/a/normal-clients/receipt.json']['truncated']=True
        raw=io.BytesIO()
        with zipfile.ZipFile(raw,'w') as z:
            for n,value in self.f.files.items():z.writestr(n,p.encoded(report) if n=='retention.json' else value)
        with self.assertRaises(ValueError):p.export(raw.getvalue())

    def test_alias_and_existing_output_refuse(self):
        self.f.args.output.mkdir();self.refuse_existing=True
        with self.assertRaises(ValueError):p.prepare(self.f.args)
        self.assertEqual(list(self.f.args.output.iterdir()),[])
        self.f.args.output.rmdir()
        alias=self.root/'alias';alias.symlink_to(self.f.args.pair_decision);self.f.args.pair_decision=alias;self.refuse()

    def test_duplicate_json_and_zip_paths_refuse(self):
        with self.assertRaises(ValueError):p.obj(b'{"x":1,"x":2}')
        raw=io.BytesIO()
        with zipfile.ZipFile(raw,'w') as z:z.writestr('../escape',b'x')
        with self.assertRaises(ValueError):p.export(raw.getvalue())

    def test_failed_write_removes_only_private_staging(self):
        old=Path.write_bytes
        def fail(file,raw):
            if '.packet-' in str(file):raise OSError('synthetic disk failure')
            return old(file,raw)
        with patch.object(Path,'write_bytes',fail):self.refuse()


if __name__=='__main__':unittest.main()
