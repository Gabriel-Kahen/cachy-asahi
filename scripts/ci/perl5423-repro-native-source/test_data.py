#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Portable packet DATA controls; no operational Source/Native/Reader actors."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import shutil
from unittest.mock import patch
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('perl_native_packet',HERE/'prepare.py')
api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
PROFILE='624bcc976f1101cedb387c7fa5998cd9b4088f2ab7d4c38f972c1aed857a4941'


def no_actors(event,args):
    if event in ('subprocess.Popen','os.system','os.exec','os.posix_spawn','socket.connect','socket.bind'):
        raise AssertionError('operational actor forbidden in DATA controls: '+event)
sys.addaudithook(no_actors)


class PacketData(unittest.TestCase):
    def setUp(self):self.profile,self.files=api.operands(PROFILE);self.contract=api.atomic.decode(self.files['contract.json'][0])
    def test_exact_recipe_and_source_pins(self):
        self.assertEqual(len(self.profile['recipe_files']),18)
        self.assertEqual(self.profile['source']['bytes'],22610875)
        self.assertEqual(self.profile['source']['sha256'],'16b23f32e34df12709fc5fa0a7028d3df3c3cfceca21e38faada6a025edff725')
        self.assertEqual(self.profile['recipe_files']['PKGBUILD']['sha256'],'cf0df8990ac83f48a4c29978c932922108f0e01cb6d052209934da5b01af4068')
        self.assertEqual(api.metadata(self.files['recipe/.SRCINFO'][0])['arch'],['aarch64','x86_64'])
    def test_complete_dependency_inventory_and_provider_join(self):
        deps=api.atomic.decode(self.files['dependencies.json'][0])
        self.assertEqual(deps['baseline']['packages'],349);self.assertEqual(len(deps['joins']),13);self.assertEqual(len(deps['providers']),12)
        crypt=next(r for r in deps['joins'] if r['declaration']=='libcrypt.so')
        self.assertEqual(crypt['provider'],'libxcrypt');self.assertIn('libcrypt.so=2-64',crypt['provides'])
        self.assertEqual(deps['providers']['procps-ng']['effective_metadata']['version'],'4.0.7-1')
        self.assertFalse(deps['optional_perl_text_diff']['present'])
        for row in deps['providers'].values():
            self.assertTrue(row['individual_archive_metadata']['license']);self.assertTrue(row['individual_archive_metadata']['source_url'])
    def test_whole_profile_and_frozen_operand_tamper_refuse(self):
        with self.assertRaisesRegex(ValueError,'profile differs'):api.operands('0'*64)
        with self.assertRaises(ValueError):api.operands('not-a-hash')
        raw=self.files['references/namespace-contract.json'][0]
        self.assertEqual(api.pin(raw)['sha256'],'a553d3385a4d4d0005736e1a7e931eb13a6df41071c2e1337df635ea7e69f3f8')
        with tempfile.TemporaryDirectory() as tmp:
            factory=Path(tmp)/'factory';shutil.copytree(HERE,factory)
            operand=factory/'references/container-entry-v2.sh.txt';operand.write_bytes(operand.read_bytes()+b'tamper')
            with patch.object(api,'HERE',factory),self.assertRaisesRegex(ValueError,'operand changed'):api.operands(PROFILE)
    def test_namespace_is_actual_unrun_prerequisite(self):
        n=self.contract['namespace_prerequisite'];self.assertEqual(n['source'],api.NAMESPACE)
        self.assertEqual(n['uid'],1001);self.assertEqual(n['status'],'PUBLISHED_NOT_RUN');self.assertIsNone(n['actual_run'])
        for key,value in [('status','SUPPORTED'),('actual_run','123'),('uid',1000)]:
            c=copy.deepcopy(self.contract);c['namespace_prerequisite'][key]=value
            with self.assertRaises(ValueError):api.validate_contract(c)
    def test_no_native_authority_or_selectors_can_be_filled(self):
        for change in [{'native_acceptance':True},{'qualification':'PASS'},{'actual':{}},{'actual':dict(api.ACTUAL,run='123')}]:
            c=copy.deepcopy(self.contract);c.update(change)
            with self.assertRaises(ValueError):api.validate_contract(c)
    def test_full_tests_epoch_and_marker_remain_exact(self):
        for flag in ['--nodeps','--nocheck','--ignorearch']:
            c=copy.deepcopy(self.contract);c['makepkg_argv'].append(flag)
            with self.assertRaises(ValueError):api.validate_contract(c)
        c=copy.deepcopy(self.contract);c['required_environment']['SOURCE_DATE_EPOCH']='1791748800'
        with self.assertRaises(ValueError):api.validate_contract(c)
        c=copy.deepcopy(self.contract);c['required_environment']['CACHY_ASAHI_PERL_BUILD']='0'
        with self.assertRaises(ValueError):api.validate_contract(c)
    def test_fixed_resources_and_required_adapter_holds(self):
        for key,value in [('cpus',4),('pids',512),('memory_swap_total_bytes',8589934592),('uid',1000)]:
            c=copy.deepcopy(self.contract);c['resources']['actor'][key]=value
            with self.assertRaises(ValueError):api.validate_contract(c)
        c=copy.deepcopy(self.contract);c['resources']['full_build_seconds']=180
        with self.assertRaises(ValueError):api.validate_contract(c)
        c=copy.deepcopy(self.contract);c['required_Root_adapters'][0]='already-qualified'
        with self.assertRaises(ValueError):api.validate_contract(c)
    def test_inert_old_builder_is_reference_not_qualified_entry(self):
        entry=self.files['references/container-entry-v2.sh.txt'][0]
        self.assertNotIn(b'CACHY_ASAHI_PERL_BUILD',entry)
        self.assertIn('required_environment_into_actual_builder',self.contract['required_Root_adapters'])
        self.assertEqual(api.pin(self.files['references/build_v2.py.txt'][0])['sha256'],'37242a5680c0cb587087042455782478dac0f574f977a5f696c97d29eac39b43')
    def test_bad_archive_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'bad.tar.gz';p.write_bytes(b'not source');out=Path(tmp)/'packet'
            with self.assertRaisesRegex(ValueError,'upstream archive'):api.construct(p,PROFILE,out)
            self.assertFalse(out.exists())
    def test_output_inside_frozen_inputs_refuses_before_render(self):
        for directory in [api.ROOT/'packages/port/perl5423-repro-candidate',api.HERE,api.HELPER.parent,api.ROOT/'manifests']:
            out=directory/'must-not-create-packet'
            with self.subTest(directory=directory),patch.object(api,'render',side_effect=AssertionError('render called before disjoint guard')):
                with self.assertRaisesRegex(ValueError,'disjoint'):api.construct(Path('/nonexistent-source'),PROFILE,out)
                self.assertFalse(out.exists())

    def test_filesystem_helper_refuses_alias_and_atomic_output_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent=Path(tmp);source=parent/'file';source.write_bytes(b'DATA');link=parent/'link';link.symlink_to(source)
            with self.assertRaises(OSError):api.atomic.read(link)
            out=parent/'packet';files={'DATA.txt':(b'inert\n',0o644)}
            api.atomic.publish(files,out)
            with self.assertRaises(ValueError):api.atomic.publish(files,out)
            self.assertEqual((out/'DATA.txt').read_bytes(),b'inert\n')


if __name__=='__main__':unittest.main(verbosity=2)
