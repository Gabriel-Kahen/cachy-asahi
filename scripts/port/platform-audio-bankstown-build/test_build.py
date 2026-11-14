#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Finite host builder controls; model data never executes as source artifacts."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('bankstown_build_tests',HERE/'build.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)


class Build(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='bankstown-builder-test-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def test_candidate_source_metadata_is_pinned_and_architecture_specific(self):
        value=b.recipe_sources();self.assertEqual(value['arch'],['aarch64']);self.assertEqual(len(value['source']),9)
        self.assertEqual(value['pkgrel'],['5'])

    def test_host_environment_excludes_inherited_rustup_wrappers_and_tuning(self):
        with mock.patch.dict(os.environ,{'RUSTFLAGS':'evil','CARGO_HOME':'evil','RUSTUP_TOOLCHAIN':'evil','LD_PRELOAD':'evil','RUSTC_WRAPPER':'evil'}):value=b.environment()
        self.assertNotIn('evil',value.values());self.assertEqual(value['RUSTC'],'/tool/bin/rustc')
        self.assertEqual(value['CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER'],'/build-tools/cc')
        self.assertEqual(value['CARGO_BUILD_JOBS'],'1');self.assertNotIn('LD_PRELOAD',value)

    def test_linker_bound_is_explicit_and_pinned(self):
        raw=(HERE/'link-host.sh').read_bytes();profile=json.loads((HERE/'host-tools.json').read_bytes())
        self.assertEqual(profile['host_linker'],b.desc(raw));self.assertIn(b'--threads=1',raw)
        self.assertTrue(profile['host_only']);self.assertFalse(profile['native_compiler_selected'])
        self.assertIn('/tool/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld',profile['files'])
        self.assertIn('/usr/lib/libmvec.so.1',profile['files'])

    def test_isolation_proof_exact_set_and_return_status_required(self):
        proof={name:True for name in b.PROOF_FIELDS};raw=json.dumps(dict(bankstown_build_isolation=proof)).encode()
        self.assertEqual(b.isolation(raw,0)[0],proof)
        for changed in (dict(proof,unknown=True),dict(proof,network_denied=False)):
            with self.assertRaisesRegex(ValueError,'ISOLATION'):b.isolation(json.dumps(dict(bankstown_build_isolation=changed)).encode(),0)
        with self.assertRaisesRegex(ValueError,'SOURCE_BUILD_OR_PACKAGE'):b.isolation(raw,1)

    def test_nonobject_upstream_stdout_is_data(self):
        raw=b'[]\n42\n'+json.dumps(dict(bankstown_build_isolation={key:True for key in b.PROOF_FIELDS})).encode()
        self.assertEqual(b.isolation(raw,0)[1],[])

    def test_prefix_rejects_dangling_links_and_special_files(self):
        prefix=self.root/'prefix';prefix.mkdir();(prefix/'dangling').symlink_to('/not-present')
        with self.assertRaisesRegex(ValueError,'LINK_REFUSED'):b.layout(prefix,None,None)
        (prefix/'dangling').unlink();os.mkfifo(prefix/'fifo')
        with self.assertRaisesRegex(ValueError,'SPECIAL_FILE_REFUSED'):b.layout(prefix,None,None)

    def test_missing_prefix_material_cannot_be_a_pass(self):
        prefix=self.root/'prefix';prefix.mkdir()
        with self.assertRaisesRegex(ValueError,'COVERAGE_DIFFERS'):b.layout(prefix,None,None)

    def test_held_metadata_and_runner_sources_are_unchanged(self):
        r=b.metadata()
        for _,(path,pin)in r.PINS.items():self.assertEqual(b.desc((b.ROOT/path).read_bytes())['sha256'],pin)


def namespace_policy():
    held=HERE.parent/'platform-audio-cargo-metadata/namespace_child.py'
    original=importlib.util.spec_from_file_location
    def redirect(name,path,*args,**kwargs):return original(name,held if str(path)=='/bootstrap.py'else path,*args,**kwargs)
    with mock.patch('importlib.util.spec_from_file_location',side_effect=redirect):
        spec=original('bankstown_build_policy_model',HERE/'build_namespace.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
    return p


def evaluate(rows,number,arg0=0):
    memory={0:number,4:0xc000003e,16:arg0};pc=0;value=0
    for _ in range(1024):
        code,jt,jf,k=rows[pc];pc+=1
        if code==0x20:value=memory[k]
        elif code==0x15:pc+=jt if value==k else jf
        elif code==0x45:pc+=jt if value&k else jf
        elif code==0x06:return k
        else:raise AssertionError('unmodeled BPF instruction')
    raise AssertionError('nonterminating BPF')


class Policy(unittest.TestCase):
    def test_only_unnamed_unix_pairs_and_local_messaging_are_permitted(self):
        rows=namespace_policy().build_instructions()
        self.assertEqual(evaluate(rows,53,1),0x7fff0000)
        for domain in (2,10,30):self.assertEqual(evaluate(rows,53,domain),0x50001)
        for call in (41,42,49,50,272,308):self.assertEqual(evaluate(rows,call),0x50001)
        for call in (44,45,46,47):self.assertEqual(evaluate(rows,call),0x7fff0000)

    def test_clone_namespace_escape_is_still_denied(self):
        rows=namespace_policy().build_instructions()
        self.assertEqual(evaluate(rows,56,0x10000000),0x50001);self.assertEqual(evaluate(rows,56,0x4111),0x7fff0000)


if __name__=='__main__':unittest.main(verbosity=2)
