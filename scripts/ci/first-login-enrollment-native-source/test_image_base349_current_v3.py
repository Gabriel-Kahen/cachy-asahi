#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Genuine metadata parser controls; MODEL unavailable archive refs, no actors."""
import argparse
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
args=argparse.ArgumentParser(add_help=False)
args.add_argument('--source-root',type=Path,default=REPO)
args.add_argument('--base-lock',type=Path,default=REPO/'scripts/ci/inputs.lock.json')
args.add_argument('--bootstrap-profile',type=Path,default=REPO/'scripts/ci/desktop-current011-native-source/fixtures/native/input-profile.json')
args.add_argument('--baseline-inventory',type=Path,default=HERE/'fixtures/expected349.lock')
OPERANDS,UNITTEST_ARGS=args.parse_known_args()


def fence(event,arguments):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn'))or event in ('os.system','resource.setrlimit','fcntl.flock'):
        raise AssertionError('genuine image metadata DATA only: '+event)


sys.addaudithook(fence)
spec=importlib.util.spec_from_file_location('image_base349_real_metadata',HERE/'payload/native/image_current_v3.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)


def ref(path):return dict(path=str(path),**P.pin(path.read_bytes()))


class GenuineBaseMetadata(unittest.TestCase):
    def setUp(self):
        self.base=P.decoded(OPERANDS.base_lock.read_bytes())
        self.profile=P.decoded(OPERANDS.bootstrap_profile.read_bytes())
        # These deliberately unavailable MODEL paths exercise metadata selection
        # only. They are never a provider handoff, available cache or GPG result.
        def materials(rows):
            result={}
            for row in rows:
                result[row['filename']]=dict(path='/MODEL_UNAVAILABLE/'+row['filename'],bytes=row['size'],sha256=row['sha256'])
                result[row['filename']+'.sig']=dict(path='/MODEL_UNAVAILABLE/'+row['filename']+'.sig',bytes=row['signature_size'],sha256=row['signature_sha256'])
            return result
        self.inputs=dict(base_lock=ref(OPERANDS.base_lock),bootstrap_profile=ref(OPERANDS.bootstrap_profile),baseline_inventory=ref(OPERANDS.baseline_inventory),
            base_materials=materials([self.base['rootfs'],*self.base['packages']]),supplemental_materials=materials(self.profile['additions']['rows']))

    def test_genuine_source_parent_profiles_and_final349_join_without_relaxed_pins(self):
        with mock.patch.object(P,'whole',side_effect=AssertionError('no archive readiness or execution claimed')):
            base,rows,baseline=P.base_inputs(self.inputs,OPERANDS.source_root)
        self.assertEqual(base,self.base);self.assertEqual(len(rows),257);self.assertEqual(len(baseline),349)
        self.assertEqual(len(self.profile['original341']['packages']),341)
        supplemental=[r for r in rows if r['source_group']=='supplemental_materials']
        self.assertEqual({r['name']for r in supplemental},P.SUPPLEMENTAL)
        self.assertEqual({r['name']:r['arch']for r in supplemental},{r['name']:r['arch']for r in self.profile['additions']['rows']})
        self.assertEqual(baseline,self.profile['original341']['packages']|{r['name']:r['version']for r in self.profile['additions']['rows']})
        self.assertEqual(P.pin(OPERANDS.base_lock.read_bytes())['sha256'],P.BASE_LOCK_SHA)
        self.assertEqual(P.pin(OPERANDS.bootstrap_profile.read_bytes()),P.BOOTSTRAP_PROFILE_PIN)

    def test_every_missing_supplement_and_unselected_extra_refuses(self):
        for name in self.inputs['supplemental_materials']:
            changed=copy.deepcopy(self.inputs);changed['supplemental_materials'].pop(name)
            with self.subTest(name=name),self.assertRaises(ValueError):P.base_inputs(changed,OPERANDS.source_root)
        changed=copy.deepcopy(self.inputs);changed['supplemental_materials']['unselected.pkg.tar.xz']=next(iter(changed['supplemental_materials'].values()))
        with self.assertRaises(ValueError):P.base_inputs(changed,OPERANDS.source_root)

    def test_changed_archive_signature_or_cross_group_alias_refuses(self):
        for group in ('base_materials','supplemental_materials'):
            names=list(self.inputs[group])[:2]if group=='base_materials'else self.inputs[group]
            for name in names:
                changed=copy.deepcopy(self.inputs);changed[group][name]['sha256']='0'*64
                with self.subTest(group=group,name=name),self.assertRaises(ValueError):P.base_inputs(changed,OPERANDS.source_root)
        changed=copy.deepcopy(self.inputs);name=next(iter(changed['supplemental_materials']))
        changed['supplemental_materials'][name]['path']=next(iter(changed['base_materials'].values()))['path']
        with self.assertRaises(ValueError):P.base_inputs(changed,OPERANDS.source_root)

    def test_source_factory_body_cannot_be_invented_by_caller(self):
        with tempfile.TemporaryDirectory(prefix='MODEL-wrong-factory-')as directory:
            root=Path(directory);path=root/'scripts/ci/first-login-enrollment-native-source/profile.json';path.parent.mkdir(parents=True);path.write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError,'Source factory provenance'):P.base_inputs(self.inputs,root)

    def test_original341_cannot_be_relabeled_final349(self):
        with tempfile.TemporaryDirectory(prefix='MODEL-wrong-baseline-')as directory:
            path=Path(directory)/'wrong.lock';path.write_bytes(P.lock(self.profile['original341']['packages']))
            changed=dict(self.inputs,baseline_inventory=ref(path))
            with self.assertRaisesRegex(ValueError,'held349 version vector'):P.base_inputs(changed,OPERANDS.source_root)


if __name__=='__main__':unittest.main(argv=[sys.argv[0],*UNITTEST_ARGS])
