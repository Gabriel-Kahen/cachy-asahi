#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Modeled metadata and isolation controls; no upstream/native fixture executes."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
r=load('cargo_replay_unit',HERE/'replay.py');child=load('cargo_replay_child_unit',HERE/'namespace_child.py')
a=r.module('cargo_replay_vendor_unit',r.ROOT/r.PINS['vendor'][0],r.PINS['vendor'][1])


def archive(files):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w')as out:
        for name,body in sorted(files.items()):
            info=tarfile.TarInfo(name);info.size=len(body);out.addfile(info,io.BytesIO(body))
    return stream.getvalue()


class Replay(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='cargo-replay-unit-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        lock=('version=3\n[[package]]\nname="root"\nversion="1.0.0"\ndependencies=["alpha"]\n'
            '[[package]]\nname="alpha"\nversion="1.2.3"\nsource="'+a.REGISTRY+'"\nchecksum="'+'a'*64+'"\n').encode()
        self.files={'root/Cargo.toml':b'[package]\nname="root"\nversion="1.0.0"\n[dependencies]\nalpha="1"\n','root/Cargo.lock':lock}
        self.bodies={a.PACKAGES['bankstown']:archive(self.files)}
        self.vendor={'crates':{'vendor/alpha-1.2.3':dict(name='alpha',version='1.2.3',package_checksum='a'*64)}}
        self.document=dict(version=1,packages=[dict(id='opaque-root',name='root',version='1.0.0',source=None,manifest_path='/sources/bankstown/Cargo.toml'),
            dict(id='opaque-alpha',name='alpha',version='1.2.3',source=a.REGISTRY,manifest_path='/vendor/alpha-1.2.3/Cargo.toml')],
            resolve=dict(root='opaque-root',nodes=[dict(id='opaque-root',dependencies=['opaque-alpha'],features=[],deps=[dict(name='alpha',pkg='opaque-alpha',dep_kinds=[dict(kind=None,target=None)])]),
                dict(id='opaque-alpha',dependencies=[],features=['default'],deps=[])]))

    def graph(self):return r.normalize_graph(a,self.document,'bankstown',self.bodies,self.vendor)

    def test_full_modeled_graph_lock_vendor_join_and_holds(self):
        graph=self.graph();self.assertEqual((graph['reachable_packages'],graph['reachable_edges']),(2,1))
        self.assertEqual(graph['root'],['root','1.0.0','']);self.assertFalse(graph['original_native_flags_or_features_proven'])
        self.assertFalse(graph['complete_corresponding_source_accepted']);self.assertFalse(graph['legal_acceptance'])

    def test_package_dependency_declarations_are_not_resolved_edges(self):
        self.document['packages'][0]['dependencies']=[dict(name='unactivated-unfiltered-declaration')]
        graph=self.graph();self.assertEqual(graph['reachable_packages'],2);self.assertEqual(graph['reachable_edges'],1)

    def test_unreachable_package_still_requires_delivered_source(self):
        self.document['packages'].append(dict(id='unknown',name='missing',version='1.0.0',source=a.REGISTRY,manifest_path='/vendor/missing/Cargo.toml'))
        with self.assertRaisesRegex(r.Requirement,'NOT_IN_ORIGINAL_LOCK'):self.graph()

    def test_changed_resolved_version_refused(self):
        self.document['packages'][1]['version']='9.0.0'
        with self.assertRaisesRegex(r.Requirement,'NOT_IN_ORIGINAL_LOCK'):self.graph()

    def test_missing_vendor_material_never_stubbed(self):
        self.vendor['crates'].clear()
        with self.assertRaisesRegex(r.Requirement,'UNDELIVERED_MATERIAL'):self.graph()

    def test_wrong_vendor_manifest_path_and_checksum_refused(self):
        self.document['packages'][1]['manifest_path']='/other/Cargo.toml'
        with self.assertRaisesRegex(r.Requirement,'VENDOR_PATH_DIFFERS'):self.graph()
        self.document['packages'][1]['manifest_path']='/vendor/alpha-1.2.3/Cargo.toml';self.vendor['crates']['vendor/alpha-1.2.3']['package_checksum']='b'*64
        with self.assertRaisesRegex(r.Requirement,'CHECKSUM_DIFFERS'):self.graph()

    def test_dangling_and_inconsistent_edge_forms_refused(self):
        self.document['resolve']['nodes'][0]['dependencies'].append('missing')
        with self.assertRaisesRegex(r.Requirement,'EDGE_FORMS_DIFFER'):self.graph()
        self.document['resolve']['nodes'][0]['deps'].append(dict(name='missing',pkg='missing',dep_kinds=[]))
        with self.assertRaisesRegex(r.Requirement,'GRAPH_TARGET_REQUIREMENT'):self.graph()

    def test_duplicate_opaque_ids_refused(self):
        self.document['packages'].append(copy.deepcopy(self.document['packages'][0]))
        with self.assertRaisesRegex(r.Requirement,'IDENTITY_REQUIREMENT'):self.graph()

    def test_malformed_features_or_dependency_kinds_refused(self):
        self.document['resolve']['nodes'][0]['features']=[True]
        with self.assertRaisesRegex(r.Requirement,'NODE_FORMAT'):self.graph()
        self.document['resolve']['nodes'][0]['features']=[];self.document['resolve']['nodes'][0]['deps'][0]['dep_kinds'][0]['kind']='unknown'
        with self.assertRaisesRegex(r.Requirement,'DEPENDENCY_KIND'):self.graph()

    def proof(self):return dict(metadata_isolation={key:True for key in r.PROOF_FIELDS})

    def test_requires_complete_exact_positive_isolation_proof(self):
        proof=self.proof();raw=json.dumps(proof).encode()+b'\ncargo 1.96.1\n'
        self.assertEqual(r.parse_output(raw,0)[1],proof['metadata_isolation'])
        for edit in (lambda p:p['metadata_isolation'].pop('seccomp'),lambda p:p['metadata_isolation'].update(seccomp=False),
                     lambda p:p['metadata_isolation'].update(unknown=True)):
            p=copy.deepcopy(proof);edit(p)
            with self.assertRaisesRegex(r.Requirement,'ISOLATION_NOT_ESTABLISHED'):r.parse_output(json.dumps(p).encode(),0)
        with self.assertRaisesRegex(r.Requirement,'RUNTIME_REQUIREMENT'):r.parse_output(raw,101)

    def test_warning_text_is_data_and_duplicate_proofs_refused(self):
        proof=json.dumps(self.proof()).encode();raw=b'warning: data only\n'+proof+b'\n'+json.dumps(self.document).encode()+b'\n'
        self.assertEqual(len(r.parse_output(raw,0)[0]),2)
        with self.assertRaisesRegex(r.Requirement,'ISOLATION_NOT_ESTABLISHED'):r.parse_output(proof+b'\n'+proof,0)

    def test_actionable_refusal_does_not_echo_arbitrary_error_text(self):
        text=b'error: no matching package named `missing-crate` found\n/private/operator/secrets\nerror while loading shared libraries: libexample.so.1\n'
        rows=r.failure_requirements(text)
        self.assertEqual(rows,[dict(code='VENDORED_PACKAGE_REQUIRED',material='missing-crate'),dict(code='PINNED_RUNTIME_SHARED_LIBRARY_REQUIRED',material='libexample.so.1')])
        self.assertNotIn(b'/private/',r.encoded(rows))

    def test_inherited_wrappers_credentials_toolchains_and_flags_excluded(self):
        with mock.patch.dict(os.environ,{'RUSTC_WRAPPER':'evil','CARGO_HOME':'evil','RUSTUP_TOOLCHAIN':'evil','RUSTFLAGS':'evil','LD_PRELOAD':'evil','CARGO_ALIAS_METADATA':'evil'}):env=r.environment()
        self.assertFalse(any('evil'in value for value in env.values()))
        self.assertEqual(env['RUSTC'],'/tool/bin/rustc');self.assertEqual(env['CARGO_NET_OFFLINE'],'true')
        self.assertNotIn('LD_PRELOAD',env);self.assertNotIn('RUSTUP_TOOLCHAIN',env)

    def test_only_fixed_locked_offline_filtered_default_metadata_operations(self):
        for name in a.PACKAGES:
            cmd=child.OPERATIONS[name]
            self.assertEqual(cmd[:2],['/tool/bin/cargo','metadata'])
            for flag in ('--locked','--offline','--filter-platform','aarch64-unknown-linux-gnu'):self.assertIn(flag,cmd)
            self.assertFalse({'--all-features','--features','--no-default-features','build','check','test'}&set(cmd))
        self.assertEqual(set(child.OPERATIONS),set(a.PACKAGES)|{'cargo-version','rustc-version'})

    def test_source_projection_refuses_configs_executables_links_and_changes(self):
        for name in ('sources','vendor'):(self.root/name).mkdir()
        r.put(self.root/'sources','root/Cargo.toml',b'data',0o400);baseline=r.projection_state(self.root)
        r.put(self.root/'sources','root/.cargo/config.toml',b'trusted config must not inherit',0o400)
        with self.assertRaisesRegex(r.Requirement,'SOURCE_CONTROL'):r.projection_state(self.root)
        (self.root/'sources/root/.cargo/config.toml').unlink();(self.root/'sources/root/.cargo').rmdir()
        self.assertEqual(r.projection_state(self.root),baseline)
        (self.root/'sources/root/Cargo.toml').chmod(0o500)
        with self.assertRaisesRegex(r.Requirement,'EXECUTABLE_PRESENT'):r.projection_state(self.root)
        (self.root/'sources/root/Cargo.toml').unlink();(self.root/'sources/root/Cargo.toml').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(r.Requirement,'LINK_REQUIRED_ABSENT'):r.projection_state(self.root)

    def test_exclusion_does_not_remove_checksum_manifests(self):
        self.assertFalse(r.excluded('alpha/.cargo-checksum.json'))
        for path in ('alpha/.cargo/config','alpha/.cargo/config.toml','alpha/rust-toolchain','alpha/rust-toolchain.toml'):self.assertTrue(r.excluded(path))

    def test_missing_runtime_file_refused_before_any_actor(self):
        profile={'files':{'/tool/bin/cargo':dict(origin='toolchain/bin/cargo',bytes=1,sha256='0'*64,ELF=True)}}
        with mock.patch('subprocess.Popen',side_effect=AssertionError('no actor')):
            with self.assertRaisesRegex(r.Requirement,'SUPPORT_FILE_MISSING:/tool/bin/cargo'):r.stage_runtime(profile,self.root,self.root)

    def test_wrong_catalog_pin_refused_without_actor(self):
        with mock.patch('subprocess.Popen',side_effect=AssertionError('no actor')):
            with self.assertRaisesRegex(r.Requirement,'PROFILE_PIN_DIFFERS'):r.load_profile('0'*64)

    def test_requirements_report_is_private_and_never_accepts(self):
        output=self.root/'report';value=r.prerequisite_report(output,'VENDORED_SOURCE_REQUIRED')
        self.assertFalse(value['complete_corresponding_source_accepted']);self.assertFalse(value['legal_acceptance'])
        self.assertEqual((output/'metadata-replay.json').stat().st_mode&0o777,0o600)
        self.assertEqual(output.stat().st_mode&0o777,0o700)
        with self.assertRaises(FileExistsError):r.prerequisite_report(output,'other')
        self.assertEqual(json.loads((output/'metadata-replay.json').read_bytes()),value)

    def test_elf_reader_refuses_non_elf_and_wrong_architecture(self):
        with self.assertRaisesRegex(r.Requirement,'ELF64'):r.elf_dependencies(b'not ELF')
        raw=bytearray(128);raw[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',raw,18,183)
        with self.assertRaisesRegex(r.Requirement,'X86_64'):r.elf_dependencies(raw)


def bpf_result(number,arg0=0,arch=0xc000003e):
    memory={0:number,4:arch,16:arg0};rows=child.instructions();pc=0;accumulator=0
    for _ in range(1024):
        code,jt,jf,k=rows[pc];pc+=1
        if code==0x20:accumulator=memory[k]
        elif code==0x15:pc+=jt if accumulator==k else jf
        elif code==0x45:pc+=jt if accumulator&k else jf
        elif code==0x06:return k
        else:raise AssertionError('unmodeled BPF instruction')
    raise AssertionError('BPF did not terminate')


class SyscallPolicy(unittest.TestCase):
    def test_all_denied_calls_and_namespace_clone_flags_are_blocked(self):
        for number in child.DENIED:self.assertEqual(bpf_result(number),0x00050001)
        for flag in (0x20000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000):
            self.assertEqual(bpf_result(56,flag),0x00050001)

    def test_regular_process_threads_and_runtime_calls_remain_allowed(self):
        self.assertEqual(bpf_result(56,0x100|0x800|0x10000),0x7fff0000)
        for number in (0,1,9,10,39,57,58,59):self.assertEqual(bpf_result(number),0x7fff0000)
        self.assertEqual(bpf_result(435),0x00050026)

    def test_foreign_architecture_and_x32_cannot_bypass_policy(self):
        self.assertEqual(bpf_result(41,arch=0xc00000b7),0x80000000)
        self.assertEqual(bpf_result(0x40000000|41),0x00050001)


if __name__=='__main__':unittest.main(verbosity=2)
