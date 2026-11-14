#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Candidate source/receipt controls. ELF fixtures are synthetic nonexecuted data."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('bankstown_guard_tests',HERE/'build_guard.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)


def elf(machine=62,kind=2,alignment=16384):
    raw=bytearray(512);ident=b'\x7fELF\x02\x01'+b'\0'*10
    struct.pack_into('<16sHHIQQQIHHHHHH',raw,0,ident,3,machine,1,0,64,128,0,64,56,1,64,3,0)
    struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0,0,512,512,alignment)
    struct.pack_into('<IIQQQQIIQQ',raw,192,0,11,0,0,320,48,2,0,8,24)
    struct.pack_into('<IIQQQQIIQQ',raw,256,0,3,0,0,400,16,0,0,1,0)
    struct.pack_into('<IBBHQQ',raw,344,1,16|kind,0,1,4096,4)
    raw[400:416]=b'\0lv2_descriptor\0';return bytes(raw)


class Candidate(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='bankstown-candidate-test-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def test_exact_retained_sources_and_static_srcinfo(self):
        g.sources(HERE)
        result=subprocess.run(['/usr/bin/makepkg','--printsrcinfo'],cwd=HERE,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,(HERE/'.SRCINFO').read_bytes())
        info={}
        for line in result.stdout.decode().splitlines():
            if ' = 'in line:
                key,value=line.strip().split(' = ',1);info.setdefault(key,[]).append(value)
        self.assertEqual((info['pkgname'],info['pkgver'],info['pkgrel'],info['arch']),(['bankstown'],['1.1.0'],['5'],['aarch64']))
        for name,pin in zip(info['source'],info['sha256sums']):self.assertEqual(g.sha((HERE/name).read_bytes()),pin)

    def test_original_recipe_and_archives_unchanged(self):
        repo=HERE.parents[2];p=json.loads((repo/'scripts/release/platform_audio_source_profiles.json').read_bytes())['profiles']['bankstown']
        self.assertEqual(g.sha((repo/'packages/audio/bankstown/PKGBUILD').read_bytes()),p['inputs']['PKGBUILD']['sha256'])
        for name,pin in g.SOURCES.items():self.assertEqual(g.sha((repo/'packages/audio/bankstown'/name).read_bytes()),pin)

    def test_source_tamper_refused(self):
        with mock.patch.object(g,'read',return_value=b'changed'),self.assertRaisesRegex(ValueError,'DECLARED_SOURCE_DIFFERS'):g.sources(HERE)

    def test_intended_native_is_original_alarm_not_host_alternative(self):
        req=json.loads((HERE/'native-toolchain-requirements.json').read_bytes())
        self.assertEqual(req['selected_native_compiler'],'1.99.0');self.assertEqual(req['selected_native_rust']['sha256'],'337e715182a8f81bfd6df844793c5d1cb2697ff9e94ddb496dd850ba901c31d4')
        self.assertFalse(req['unselected_alternative']['selected_for_native']);self.assertEqual(req['unselected_alternative']['version'],'1.96.1')
        self.assertFalse(req['complete_corresponding_source_accepted']);self.assertFalse(req['legal_acceptance'])

    def test_native_payload_association_is_pinned_data(self):
        raw=(HERE/'native-rust-inputs.json').read_bytes();self.assertEqual(g.sha(raw),g.NATIVE_RUST_PIN)
        value=json.loads(raw);self.assertEqual(value['payload_regular_files'],137);self.assertEqual(value['payload_regular_bytes'],262066494)
        self.assertEqual(value['signature']['authentication'],'NOT_PERFORMED')
        self.assertEqual(value['pkgbuild_sha256'],'ef3fac9176e2a3698314d616e56d88b2df64d057ee7e9dfa13c98eb980a345fa')

    def test_requirements_document_is_not_an_accepted_native_catalog(self):
        path=HERE/'native-toolchain-requirements.json'
        with self.assertRaisesRegex(ValueError,'AUDITED_NATIVE_TOOL_CATALOG_REQUIRED'):g.native_tools(path,g.sha(path.read_bytes()))

    def test_missing_and_wrong_native_profile_refused(self):
        with self.assertRaisesRegex(ValueError,'INPUT_REQUIRED'):g.native_tools(self.root/'missing','0'*64)
        path=self.root/'profile';path.write_text('{}')
        with self.assertRaisesRegex(ValueError,'CATALOG_PIN_REQUIRED'):g.native_tools(path,'0'*64)

    def test_inherited_ancestor_cargo_config_refused(self):
        cwd=self.root/'work';cwd.mkdir();g.neutral_tree(cwd)
        (self.root/'.cargo').mkdir();(self.root/'.cargo/config').write_text('[alias]\nmetadata="unsafe"\n')
        with self.assertRaisesRegex(ValueError,'INHERITED_CARGO'):g.neutral_tree(cwd)

    def test_host_and_native_receipts_have_distinct_compiler_scope(self):
        host=g.receipt(elf(), 'x86_64-unknown-linux-gnu','a'*64,'HOST_DIAGNOSTIC_ONLY')
        native=g.receipt(elf(183),'aarch64-unknown-linux-gnu','b'*64,'NATIVE_SOURCE_BUILD')
        self.assertEqual(host['selected_compiler'],'1.96.1');self.assertEqual(native['selected_compiler'],'1.99.0')
        self.assertEqual(host['release_policy']['host_diagnostic_lld_threads'],1)
        for value in(host,native):
            self.assertFalse(value['complete_corresponding_source_accepted']);self.assertFalse(value['legal_acceptance']);self.assertEqual(value['native_component_qualification'],'NOT_ADMITTED')

    def test_host_artifact_cannot_be_relabelled_native(self):
        with self.assertRaisesRegex(ValueError,'TARGET_OR_TYPE'):g.artifact(elf(),'aarch64-unknown-linux-gnu')
        with self.assertRaisesRegex(ValueError,'MODE_DIFFERS'):g.receipt(elf(),'x86_64-unknown-linux-gnu','a'*64,'NATIVE_SOURCE_BUILD')

    def test_missing_tool_catalog_binding_refused(self):
        with self.assertRaisesRegex(ValueError,'CATALOG_ASSOCIATION_REQUIRED'):g.receipt(elf(),'x86_64-unknown-linux-gnu',None,'HOST_DIAGNOSTIC_ONLY')

    def test_artifact_export_must_be_a_function(self):
        with self.assertRaisesRegex(ValueError,'LV2_DESCRIPTOR'):g.artifact(elf(kind=1),'x86_64-unknown-linux-gnu')

    def test_structural_alignment_refused_without_hardware_claim(self):
        with self.assertRaisesRegex(ValueError,'16K_LOAD'):g.artifact(elf(alignment=4096),'x86_64-unknown-linux-gnu')
        self.assertEqual(g.artifact(elf(),'x86_64-unknown-linux-gnu')['hardware_validation'],'NOT_RUN')

    def test_artifact_and_acceptance_tamper_refused(self):
        raw=elf();receipt=g.receipt(raw,'x86_64-unknown-linux-gnu','a'*64,'HOST_DIAGNOSTIC_ONLY');g.check_receipt(raw,'x86_64-unknown-linux-gnu',receipt)
        for field in ('complete_corresponding_source_accepted','legal_acceptance'):
            changed=copy.deepcopy(receipt);changed[field]=True
            with self.assertRaisesRegex(ValueError,'RECEIPT_DIFFERS'):g.check_receipt(raw,'x86_64-unknown-linux-gnu',changed)
        with self.assertRaisesRegex(ValueError,'RECEIPT_DIFFERS'):g.check_receipt(raw+b'changed','x86_64-unknown-linux-gnu',receipt)

    def test_native_build_without_catalog_stops_before_tools(self):
        script='source "$1"; srcdir="$2"; build'
        result=subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c',script,'candidate-test',str(HERE/'PKGBUILD'),str(self.root)],
            env={'PATH':'/usr/bin','HOME':str(self.root)},capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0);self.assertIn('separately audited native',result.stderr)
        self.assertFalse((self.root/'target').exists())


if __name__=='__main__':unittest.main(verbosity=2)
