#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Passive MODEL bytes only; no retained archive or native executable is run."""
import copy
import importlib.util
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


P = module('bankstown_profile_tests', 'profile.py')
T = module('bankstown_admission_models', 'test_admission.py')
A = P.A


def elf(*, needed=None, soname=None, machine=183):
    raw = bytearray(512)
    struct.pack_into('<16sHHIQQQIHHHHHH', raw, 0, b'\x7fELF\x02\x01\x01'+b'\0'*9,
                     3, machine, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0, 0, len(raw), len(raw), 16384)
    strings = b'\0'; tags = [(5, 320)]
    for tag, word in ((1, needed), (14, soname)):
        if word:
            tags.append((tag, len(strings))); strings += word.encode() + b'\0'
    tags += [(10, len(strings)), (0, 0)]
    struct.pack_into('<IIQQQQQQ', raw, 120, 2, 4, 192, 192, 0, len(tags)*16, len(tags)*16, 8)
    for i, row in enumerate(tags): struct.pack_into('<qQ', raw, 192+i*16, *row)
    raw[320:320+len(strings)] = strings
    return bytes(raw)


class Profile(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='bankstown-profile-MODEL-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for obj, name in ((socket, 'socket'), (subprocess, 'Popen')):
            p = mock.patch.object(obj, name, side_effect=AssertionError('NO_ACTORS_OR_NETWORK'))
            p.start(); self.addCleanup(p.stop)

    def fixture(self):
        d, entries, joins = T.model(), {}, []
        bodies = {path: elf(needed='libMODEL.so') for path in d['tool_paths'].values()}
        bodies['/usr/lib/libMODEL.so'] = elf(soname='libMODEL.so')
        bodies['/usr/lib/Scrt1.o'] = b'MODEL_NOT_AN_ACTUAL_CRT_OBJECT'
        d['selected_files'] = {}
        for path, raw in bodies.items():
            target = self.root / path[1:]; target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_symlink(): target.unlink()
            target.write_bytes(raw); target.chmod(0o755 if raw.startswith(b'\x7fELF') else 0o644)
            row = dict(type='file', mode=target.stat().st_mode & 0o777, **A.pin(raw))
            inspected = P.elf(raw)
            if inspected: row['elf'] = inspected
            entries[path] = row; d['selected_files'][path] = A.pin(raw)
            if path in d['tool_paths'].values():
                joins.append(dict(consumer=path, needed='libMODEL.so', provider='/usr/lib/libMODEL.so'))
        return d, dict(elf_dependency_joins=joins), entries

    def project(self, d, c, entries):
        return P._project(d, c, entries, self.root, A.pin(b'UNISSUED_MODEL'), time.monotonic()+5)

    def test_model_bytes_profile_and_provider_joins(self):
        d, c, entries = self.fixture()
        p = self.project(d, c, entries)
        self.assertEqual(p['files'], d['selected_files'])
        self.assertEqual(p['purpose'], 'bankstown-1.1.0-5-native-toolchain')
        self.assertEqual(p['compiler_version'], '1.99.0')
        self.assertIsNone(p['Root_acceptance'])
        self.assertFalse(p['native_component_acceptance'])

    def test_missing_provider_and_soname_refuse(self):
        d, c, e = self.fixture()
        del d['selected_files']['/usr/lib/libMODEL.so']
        with self.assertRaisesRegex(ValueError, 'PROVIDER'): self.project(d, c, e)
        d, c, e = self.fixture()
        c['elf_dependency_joins'][0]['needed'] = 'different.so'
        with self.assertRaisesRegex(ValueError, 'JOIN'): self.project(d, c, e)

    def test_actual_hash_mode_and_elf_mismatch_refuse(self):
        d, c, e = self.fixture()
        target = self.root/'usr/bin/rustc'; target.write_bytes(b'CHANGED')
        with self.assertRaises(ValueError): self.project(d, c, e)
        d, c, e = self.fixture(); target.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'MODE'): self.project(d, c, e)
        d, c, e = self.fixture(); e['/usr/bin/rustc']['elf']['machine'] = 62
        with self.assertRaisesRegex(ValueError, 'ELF'): self.project(d, c, e)

    def test_absolute_logical_link_stays_inside_root(self):
        d, c, e = self.fixture()
        cc = self.root/'usr/bin/cc'; cc.rename(self.root/'usr/bin/gcc')
        cc.symlink_to('/usr/bin/gcc')
        e['/usr/bin/gcc'] = e.pop('/usr/bin/cc')
        e['/usr/bin/cc'] = dict(type='symlink', target='/usr/bin/gcc', resolved='/usr/bin/gcc')
        d['selected_files']['/usr/bin/gcc'] = d['selected_files'].pop('/usr/bin/cc')
        for j in c['elf_dependency_joins']:
            if j['consumer'] == '/usr/bin/cc': j['consumer'] = '/usr/bin/gcc'
        self.assertIn('/usr/bin/gcc', self.project(d, c, e)['files'])
        cc.unlink(); cc.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError, 'LINK_DIFFERS'): self.project(d, c, e)

    def test_link_escape_cycle_and_ancestor_alias_refused(self):
        for target in ('../../../../etc/passwd', '/usr/bin/cc'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                d, c, e = self.fixture(); p=self.root/'usr/bin/cc'; p.unlink(); p.symlink_to(target)
                e['/usr/bin/cc'] = dict(type='symlink', target=target,
                    resolved='/usr/bin/cc' if target.startswith('/') else '/etc/passwd')
                P.resolve('/usr/bin/cc', e, self.root)
        d, c, e = self.fixture()
        alias = self.root/'alias'; alias.symlink_to(self.root/'usr')
        with self.assertRaisesRegex(ValueError, 'LINK'): P.resolve('/alias/bin/cc', e, self.root)

    def test_native_elf_parser_refuses_foreign_and_truncated_tables(self):
        with self.assertRaisesRegex(ValueError, 'AARCH64'): P.elf(elf(machine=62))
        raw=bytearray(elf()); struct.pack_into('<Q', raw, 32, 1000)
        with self.assertRaisesRegex(ValueError, 'BOUND'): P.elf(bytes(raw))
        self.assertIsNone(P.elf(b'MODEL_CRT'))

    def test_catalog_hardlink_support_binds_actual_inode_and_data(self):
        d,c,e=self.fixture()
        alias=self.root/'usr/lib/libMODEL.a'; target=self.root/'usr/lib/Scrt1.o'
        os.link(target,alias)
        e['/usr/lib/libMODEL.a']={'type':'hardlink','target':'usr/lib/Scrt1.o',
                                'resolved':'/usr/lib/Scrt1.o','mode':0o644}
        d['selected_files']['/usr/lib/libMODEL.a']=A.pin(target.read_bytes())
        self.assertIn('/usr/lib/libMODEL.a',self.project(d,c,e)['files'])
        body=alias.read_bytes();alias.unlink();alias.write_bytes(body);alias.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'HARDLINK_DIFFERS'):self.project(d,c,e)

    def test_production_rust_and_lock_pins_are_actual_maintained_data(self):
        raw=P.held(P.SOURCE/P.RUST, P.RUST_PIN)
        self.assertEqual(raw, P.held(P.SOURCE/(P.BASE+'rust-137-files.json'), P.RUST_PIN))
        self.assertEqual(len(A.decoded(raw)['files']), 137)
        lock=A.decoded(P.held(P.SOURCE/(P.BASE+'qtbase-successor/candidate.lock.json'), P.LOCK_PIN))
        self.assertEqual(lock['new_packages']['qt6-base']['version'], '6.12.0-3')
        for name,pin in P.RECIPE_PINS.items():
            self.assertEqual(A.pin((P.SOURCE/A.RECIPE/name).read_bytes()),pin)

    def test_production_source_boundary_cannot_accept_model_materials(self):
        with self.assertRaises((ValueError, OSError)):
            P._source(T.model(), time.monotonic()+5)

    def catalog_fixture(self):
        # Metadata-only model uses real maintained selection and Rust137 descriptors.
        # No actual333 catalog or materialized Rust bytes are available/admitted.
        lock=A.decoded(P.held(P.SOURCE/(P.BASE+'qtbase-successor/candidate.lock.json'), P.LOCK_PIN))
        binding=A.decoded(P.held(P.SOURCE/(P.BASE+'qtbase-successor/parent-binding.json'), P.PARENT_PIN))
        baseline=A.decoded(P.held(P.SOURCE/(P.BASE+'inputs.lock.json'), binding['files']['inputs.lock.json']))
        rust=A.decoded(P.held(P.SOURCE/P.RUST, P.RUST_PIN))
        selected={n:r for n,r in baseline['packages'].items() if n!='qt6-base'} | lock['new_packages']
        d=T.model(); d['selected_files'].update(rust['files'])
        packages={}
        for name, expected in selected.items():
            info={'pkgname':[name], 'pkgver':[expected['version']], 'arch':[expected['arch']],
                  'depend':expected['depends'], 'provides':expected['provides']}
            packages[name]={'metadata':{'/.PKGINFO':info}, 'entries':{},
                 'signature':{'status':'VALID_SIGNATURE_MATHEMATICS','signer':lock['signer_primary'],
                              'key_freshness':'NOT_ESTABLISHED','source_acceptance':'NOT_ESTABLISHED'}}
        packages['rust']['entries']={p:dict(type='file',mode=0o644,**r) for p,r in rust['files'].items()}
        c=dict(purpose=lock['purpose'], candidate='EXPLICIT_OPTIONAL_QT_BASE_6.12.0-3',
               candidate_lock=P.LOCK_PIN,parent_binding=P.PARENT_PIN,complete=True,
               original_minus2_hold='UNCHANGED',protected_input_count=275,
               native_tools_profile='NOT_PRODUCED',source_legal_freshness_acceptance='HELD',
               payload_execution='NOT_RUN',packages=packages,missing_inputs=[],
               unresolved_package_dependencies=[],unresolved_elf_dependencies=[],unresolved_GNU_versions=[])
        for field,name in (('version_parser','elf_versions.py'),('source_facts','source-facts.json')):
            path=P.BASE+'qtbase-successor/'+name
            value=A.pin((P.SOURCE/path).read_bytes()); d['materials'][path]=value;c[field]=value
        inventory={n:r['version'] for n,r in selected.items()} | {'make':'MODEL','pacman':'MODEL','fakeroot':'MODEL'}
        inventory_raw=''.join(f'{n} {v}\n' for n,v in sorted(inventory.items())).encode()
        path=self.root/'model/inventory.lock';path.parent.mkdir();path.write_bytes(inventory_raw)
        d['materials']['model/inventory.lock']=d['image']['inventory']=A.pin(inventory_raw)
        return d,c,lock,baseline,rust

    def test_model_catalog_exact333_metadata_and_rust137_join(self):
        d,c,lock,baseline,rust=self.catalog_fixture()
        raw=A.encoded(c);d['catalog']=A.pin(raw)
        with mock.patch.object(P,'SOURCE',self.root):
            observed,entries=P._catalog(raw,d,lock,baseline,rust)
        self.assertEqual(len(observed['packages']),333)
        self.assertEqual(len(entries),137)

    def test_catalog_schema_closure_identity_and_rust_tamper_refuse(self):
        d,c,lock,baseline,rust=self.catalog_fixture()
        for mutate in (lambda v:v.update(schema=1), lambda v:v.update(complete=False),
                       lambda v:v.update(unresolved_GNU_versions=[{}]),
                       lambda v:v['packages']['rust']['metadata']['/.PKGINFO'].update(pkgver=['1.96.1']),
                       lambda v:v['packages']['rust']['entries']['/usr/bin/rustc'].update(sha256='0'*64)):
            changed=copy.deepcopy(c);mutate(changed);raw=A.encoded(changed);d['catalog']=A.pin(raw)
            with mock.patch.object(P,'SOURCE',self.root),self.assertRaises(ValueError):
                P._catalog(raw,d,lock,baseline,rust)

    def test_inventory_is_union_not333_and_missing_packaging_refuses(self):
        d,c,lock,baseline,rust=self.catalog_fixture();p=self.root/'model/inventory.lock'
        raw_inventory=p.read_bytes().replace(b'make MODEL\n',b'');p.write_bytes(raw_inventory)
        d['materials']['model/inventory.lock']=d['image']['inventory']=A.pin(raw_inventory)
        raw=A.encoded(c);d['catalog']=A.pin(raw)
        with mock.patch.object(P,'SOURCE',self.root),self.assertRaisesRegex(ValueError,'COMPLETE_NATIVE_BUILDER'):
            P._catalog(raw,d,lock,baseline,rust)

    def test_held_input_symlink_fifo_mutation_and_pin_refused(self):
        p=self.root/'file'; p.write_bytes(b'MODEL'); expected=A.pin(b'MODEL')
        self.assertEqual(P.held(p, expected), b'MODEL')
        alias=self.root/'alias'; alias.symlink_to(p)
        with self.assertRaises(ValueError): P.held(alias, expected)
        fifo=self.root/'fifo'; os.mkfifo(fifo)
        with self.assertRaises(ValueError): P.held(fifo, expected)
        with self.assertRaises(ValueError): P.held(p, A.pin(b'OTHER'))

    def test_export_fresh_private_exact_output_with_explicit_projection_model(self):
        # Only the write/readback seam is modeled; production _prepare is not admitted.
        d,c,e=self.fixture(); projected=self.project(d,c,e); target=self.root/'profile.json'
        with mock.patch.object(P, '_prepare', return_value=projected):
            actual=P.export_profile(admission_raw=b'UNISSUED_MODEL', admission_sha256='0'*64,
                                    catalog_path=self.root/'absent', root=self.root, output=target)
            self.assertEqual(actual, projected)
            self.assertEqual(target.read_bytes(), A.encoded(projected))
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(ValueError, 'FRESH'):
                P.export_profile(admission_raw=b'x', admission_sha256='0'*64,
                                 catalog_path=self.root/'absent', root=self.root, output=target)
        with self.assertRaisesRegex(ValueError, 'ACTUAL_ROOT'):
            P.verify_profile(admission_raw=b'x',admission_sha256='0'*64,catalog_path=target,
                             root=self.root,profile_path=target,profile_sha256='0'*64)


if __name__ == '__main__':
    unittest.main()
