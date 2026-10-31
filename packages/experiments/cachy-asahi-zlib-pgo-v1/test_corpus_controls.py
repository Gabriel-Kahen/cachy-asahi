# SPDX-License-Identifier: MIT
"""Passive fixed-corpus controls: no source/native programs or network execute."""
import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import corpus_controls as C

HERE=Path(__file__).resolve().parent


class CorpusControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='corpus-controls-',dir=HERE)
        self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        for name in ('training.bin','validation.bin','corpus-policy.json'):shutil.copyfile(HERE/name,self.root/name)

    def policy(self,value):
        (self.root/'corpus-policy.json').write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')

    def test_exact_frozen_files_and_meaningful_gates(self):
        p=C.validate(self.root);m=p['measurement']
        self.assertEqual(p['training']['bytes'],262144)
        self.assertEqual(p['validation']['bytes'],4194304)
        self.assertEqual(m['payload_bytes'],16777216)
        self.assertEqual(m['iterations'],4);self.assertEqual(m['compression_level'],6)
        self.assertEqual(m['correctness_slots'],2);self.assertEqual(m['excluded_warmup_slots'],4)
        self.assertEqual(m['measured_slots'],12);self.assertEqual(m['total_slots'],18)
        self.assertEqual(m['order'],C.ORDER);self.assertEqual(m['order'].count('baseline'),6)
        self.assertEqual(m['thresholds'],dict(minimum_elapsed_improvement_pct=5,maximum_elapsed_range_pct=25,maximum_regression={}))
        self.assertEqual(p['hardware'],'NOT RUN');self.assertEqual(p['performance_acceptance'],'NOT GRANTED')
        self.assertTrue(all(m[k]is None for k in ('current_source','current_run','current_image')))

    def test_training_generation_is_fixed_and_reads_no_heldout(self):
        with patch.object(Path,'read_bytes',side_effect=AssertionError('training must not read input files')):
            first=C.training_bytes();second=C.training_bytes()
        self.assertEqual(first,second);self.assertEqual(C.sha(first),'a6e84ea4cf12d2152fd408cea20bc2a395d4308f06683d13fc4909ae7ad46af6')
        self.assertLessEqual(len(first),1048576)
        self.assertNotEqual(C.sha(first),C.VALIDATION_SHA256)
        self.assertTrue(all(C.sha(first)!=row['sha256']for row in C.SECTIONS))

    def test_swapped_roles_leak_paths_and_modified_gates_refuse(self):
        base=C.expected_policy()
        mutations=[('training-role',lambda p:p['training'].update(role='independent-validation-and-measurement-only')),
            ('validation-role',lambda p:p['validation'].update(role='training-only')),
            ('leaked-input',lambda p:p['separation']['training_input_allowlist'].append('validation.bin')),
            ('useful-budget',lambda p:p['measurement']['thresholds'].update(minimum_elapsed_improvement_pct=0)),
            ('variability-budget',lambda p:p['measurement']['thresholds'].update(maximum_elapsed_range_pct=100)),
            ('trimmed-order',lambda p:p['measurement']['order'].pop()),
            ('profile-context',lambda p:p.update(source_zlib_sha256='0'*64)),
            ('unknown-field',lambda p:p.update(acceptance=True)),
            ('bool-schema',lambda p:p.update(schema=True))]
        for name,mutate in mutations:
            p=copy.deepcopy(base);mutate(p);self.policy(p)
            with self.subTest(name=name),self.assertRaises(ValueError):C.validate(self.root)

    def test_both_blob_mutations_and_repinning_refuse(self):
        for name in ('training.bin','validation.bin'):
            target=self.root/name;old=target.read_bytes();bad=bytes([old[0]^1])+old[1:];target.write_bytes(bad)
            with self.subTest(name=name),self.assertRaises(ValueError):C.validate(self.root)
            p=C.expected_policy();key='training'if name=='training.bin'else'validation';p[key]['sha256']=C.sha(bad);self.policy(p)
            with self.subTest(name=name+'-repinned'),self.assertRaises(ValueError):C.validate(self.root)
            target.write_bytes(old);self.policy(C.expected_policy())
        (self.root/'validation.bin').write_bytes((self.root/'training.bin').read_bytes())
        with self.assertRaises(ValueError):C.validate(self.root)

    def test_full_validation_sections_remain_exact(self):
        p=C.validate(self.root);v=(self.root/'validation.bin').read_bytes()
        self.assertEqual(len(p['validation']['sections']),4)
        for row in p['validation']['sections']:
            part=v[row['offset']:row['offset']+row['bytes']]
            self.assertEqual(len(part),1048576);self.assertEqual(C.sha(part),row['sha256'])
        p['validation']['sections'][0]['sha256']='0'*64;self.policy(p)
        with self.assertRaises(ValueError):C.validate(self.root)

    def test_alias_hardlink_missing_and_oversize_refuse(self):
        path=self.root/'training.bin';old=path.read_bytes();path.unlink();path.symlink_to(HERE/'training.bin')
        with self.assertRaises(ValueError):C.validate(self.root)
        path.unlink();os.link(HERE/'training.bin',path)
        try:
            with self.assertRaises(ValueError):C.validate(self.root)
        finally:path.unlink()
        with self.assertRaises(OSError):C.validate(self.root)
        path.write_bytes(b'x'*(1048576+1))
        with self.assertRaises(ValueError):C.validate(self.root)
        path.write_bytes(old)

    def test_duplicate_keys_and_nonfinite_policy_refuse(self):
        path=self.root/'corpus-policy.json'
        path.write_text('{"schema":1,"schema":1}')
        with self.assertRaises(ValueError):C.validate(self.root)
        path.write_text('{"schema":NaN}')
        with self.assertRaises(ValueError):C.validate(self.root)


if __name__=='__main__':unittest.main()
