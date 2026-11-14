#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Explicit checks of an actual host build report/prefix; never load the plugin."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('bankstown_actual_prefix',HERE/'build.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)


class ActualPrefix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=Path(ARGS.report).absolute();cls.report=json.loads((cls.root/'host-build.json').read_bytes())
        cls.prefix=cls.root/'prefix';cls.guard=b.module('actual_prefix_guard',b.RECIPE/'build_guard.py')
        cls.receipt=json.loads((cls.prefix/'usr/share/doc/bankstown/BUILD-INPUTS.json').read_bytes())

    def test_real_build_metadata_package_and_isolation_completed(self):
        r=self.report;self.assertEqual(r['status'],'HOST_SOURCE_BUILD_AND_PACKAGE_FUNCTION_PREFIX_PASS');self.assertEqual(r['requirements'],[])
        self.assertEqual(set(r['operations']),{'metadata','build','package'})
        for row in r['operations'].values():self.assertEqual(row['returncode'],0);self.assertEqual(set(row['isolation']),b.PROOF_FIELDS);self.assertTrue(all(row['isolation'].values()))
        self.assertEqual((r['operations']['metadata']['graph']['reachable_packages'],r['operations']['metadata']['graph']['reachable_edges']),(18,37))
        self.assertEqual(r['native_aarch64_execution'],'NOT_RUN');self.assertFalse(r['audio_plugin_loaded']);self.assertFalse(r['package_archive_built'])
        self.assertFalse(r['complete_corresponding_source_accepted']);self.assertFalse(r['legal_acceptance'])

    def test_actual_exact_ten_file_layout_and_current_recipe_binding(self):
        self.assertEqual(b.layout(self.prefix,self.guard,self.receipt),self.report['layout']);self.assertEqual(len(self.report['layout']),10)
        self.assertEqual(self.report['recipe'],b.desc((b.RECIPE/'PKGBUILD').read_bytes()))
        self.assertTrue(self.report['source_lock_unchanged'])

    def test_actual_host_artifact_cannot_pass_native_architecture_guard(self):
        raw=(self.prefix/'usr/lib/lv2/bankstown.lv2/bankstown.so').read_bytes()
        self.assertEqual(self.guard.artifact(raw,b.TARGET),self.report['artifact'])
        self.assertEqual(self.report['artifact']['machine'],62);self.assertEqual(self.receipt['mode'],'HOST_DIAGNOSTIC_ONLY')
        self.assertEqual(self.receipt['selected_compiler'],'1.96.1')
        with self.assertRaisesRegex(ValueError,'TARGET_OR_TYPE'):self.guard.artifact(raw,'aarch64-unknown-linux-gnu')

    def test_actual_receipt_tamper_and_extra_link_are_refused(self):
        with tempfile.TemporaryDirectory(prefix='bankstown-prefix-tamper-')as directory:
            prefix=Path(directory)/'prefix';shutil.copytree(self.prefix,prefix)
            path=prefix/'usr/share/doc/bankstown/BUILD-INPUTS.json';value=json.loads(path.read_bytes());value['legal_acceptance']=True;path.write_bytes(b.encoded(value))
            with self.assertRaisesRegex(ValueError,'RECEIPT_DIFFERS'):b.layout(prefix,self.guard,self.receipt)
            path.write_bytes(b.encoded(self.receipt));(prefix/'extra').symlink_to('/not-present')
            with self.assertRaisesRegex(ValueError,'LINK_REFUSED'):b.layout(prefix,self.guard,self.receipt)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--report',required=True);ARGS,rest=parser.parse_known_args()
    unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
