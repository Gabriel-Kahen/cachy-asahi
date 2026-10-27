# SPDX-License-Identifier: MIT
"""Bounded source-only context/identity/corpus controls; no native packages are run."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'scripts/benchmarks'))
import benchmark as B
import installed_zlib as I
import paired_zlib as P

def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
O=module('_runtime_owner_controls',HERE/'owner.py')
G=module('_runtime_guest_controls',HERE/'guest.py')


class ContextControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='runtime-context-');self.addCleanup(self.tmp.cleanup);self.temp=Path(self.tmp.name)
        for name in ('Popen','run','check_output'):
            guard=patch.object(O.subprocess,name,side_effect=AssertionError('source controls forbid actors'));guard.start();self.addCleanup(guard.stop)

    def test_exact_accepted_packages_source_flags_and_corresponding_programs(self):
        accepted,members=I.archives();self.assertEqual(accepted['accepted_component']['source'],'d33e595a10acf2d148752ea382ae607283fc0b73')
        for logical,row in accepted['packages'].items():
            self.assertEqual(row['version'],'1.3.2-2');self.assertEqual(row['arch'],'aarch64')
            for name,program in row['programs'].items():
                path=program['path'].lstrip('/');self.assertEqual(I.sha(members[logical][path]),program['sha256'])
            self.assertIn('-fno-lto' if logical=='baseline' else '-flto=2',row['configured_flags']['CFLAGS'])

    def test_fixed_hash_corpus_and_declared_finite_profile(self):
        p=I.profile();m=I.pinned(I.LANE/'corpus/manifest.json',I.CORPUS_SHA);raw=I.read(I.LANE/'corpus/mixed.bin')
        self.assertEqual(I.sha(raw),m['sha256']);self.assertEqual(len(raw),4*1024**2)
        for row in m['sections']:
            self.assertEqual(I.sha(raw[row['offset']:row['offset']+row['bytes']]),row['sha256'])
        self.assertEqual(p['total_slots'],18);self.assertEqual(p['order'].count('baseline'),6);self.assertEqual(p['order'].count('candidate'),6)
        self.assertEqual([s['phase'] for s in P.schedule({'order':p['order']},1)],['correctness']*2+['warmup']*4+['measured']*12)
        I.bounds(16*1024**2,4)
        for size,iterations in ((1,4),(16*1024**2,3),(True,4),(16*1024**2,True)):
            with self.assertRaises(ValueError):I.bounds(size,iterations)

    def test_guest_config_has_honest_unavailable_conditions_and_exact_variant_delta(self):
        c=G.config('1234');B.validate_config(c)
        self.assertEqual(c['measurement_scope'],I.SCOPE);self.assertEqual(c['execution_context'],'virtual')
        for key in ('ambient_C','thermal_start_C','battery_soc_percent'):self.assertIsNone(c['controls'][key])
        self.assertEqual(c['allowed_state_changes'],[]);self.assertNotIn('hardware_gate_evidence',c)
        for v in ('baseline','candidate'):self.assertEqual(c['variant_env'][v],{'ZLIB_MINIGZIP':c['change'][v]})

    def test_owner_argv_has_only_exact_offline_resource_bounded_container(self):
        env=dict(GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID='1234',GITHUB_WORKFLOW_REF='Gabriel-Kahen/cachy-asahi/.github/workflows/native-arm-build.yml@refs/heads/fixture')
        own=O.identity('a'*40,env);argv=O.measurement_argv(own,'sha256:'+'b'*64,self.temp/'out','c'*64)
        for option in ('--network=none','--cpus=2','--memory=4g','--pids-limit=256','--security-opt=no-new-privileges','--cap-drop=ALL'):self.assertIn(option,argv)
        self.assertEqual(argv.count('--mount'),2);self.assertFalse(any(a.startswith(('--privileged','--device','--pid=host')) for a in argv))
        self.assertIn('/inputs/scripts/ci/c01-native-paired-runtime/guest.py',argv)
        self.assertEqual([a for a in argv if a.startswith('--cap-add=')],['--cap-add='+c for c in O.CAPS])

    def test_execute_and_native_guards_precede_any_mutation(self):
        with self.assertRaises(ValueError):O.admitted(SimpleNamespace(execute=False))
        with patch.object(G.platform,'machine',return_value='x86_64'),patch.object(G,'helper_module',side_effect=AssertionError('no installer')):
            with self.assertRaises(ValueError):G.run(SimpleNamespace())
        with patch.object(I.platform,'machine',return_value='x86_64'):
            with self.assertRaises(ValueError):I.validate_plan({'config':{}})

    def test_incomplete_or_tuning_acceptance_declarations_cannot_pass(self):
        (self.temp/'result.json').write_text('{"status":"FAIL"}')
        with self.assertRaises(ValueError):O.validate_measurement(self.temp,{'source_sha':'a'*40,'run_id':'1234'})

    def test_frozen_complete_source_registered_alias_and_mutation_refusals(self):
        raw=O.read(HERE/'source-map.json');pin=O.sha(raw);manifest=O.source(ROOT,pin)
        self.assertIn('.github/workflows/native-arm-build.yml',O.ALIASES)
        self.assertEqual(O.read(ROOT/O.ALIASES[0]),O.read(ROOT/O.ALIASES[1]))
        self.assertIn('scripts/ci/c01-native-paired-runtime/inputs/baseline-r2-1.pkg.tar.xz',manifest['files'])
        for kind in ('corpus','archive','alias','extra'):
            root=self.temp/kind;shutil.copytree(ROOT,root)
            if kind=='corpus':target=root/'scripts/ci/c01-native-paired-runtime/corpus/mixed.bin';target.write_bytes(target.read_bytes()+b'x')
            elif kind=='archive':target=root/'scripts/ci/c01-native-paired-runtime/inputs/baseline-r2-1.pkg.tar.xz';target.write_bytes(target.read_bytes()+b'x')
            elif kind=='alias':(root/O.ALIASES[0]).write_bytes(b'changed')
            else:(root/'extra').write_bytes(b'changed')
            with self.subTest(kind=kind),self.assertRaises(ValueError):O.source(root,pin)


if __name__=='__main__':unittest.main()
