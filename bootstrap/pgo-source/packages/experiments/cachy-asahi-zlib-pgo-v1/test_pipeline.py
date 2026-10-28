# SPDX-License-Identifier: MIT
"""Passive source/control fixtures; never compile, train or start a process."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_pipeline_controls',HERE/'pipeline.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)


class PipelineControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        P.load('corpus',HERE/'corpus.py');cls.core=P.load('_pipeline_core_fixture',HERE/'arm_c01.py');cls.core.select_experiment('ARM-C03')

    def setUp(self):
        packet=HERE.parents[3];tmp=packet/'evidence/tmp';tmp.mkdir(parents=True,exist_ok=True)
        self.temporary=tempfile.TemporaryDirectory(prefix='pipeline-controls-',dir=tmp);self.addCleanup(self.temporary.cleanup);self.root=Path(self.temporary.name)
        self.enterContext(patch.object(subprocess,'Popen',side_effect=AssertionError('process forbidden')))
        self.enterContext(patch.object(subprocess,'run',side_effect=AssertionError('process forbidden')))
        self.enterContext(patch.object(subprocess,'check_output',side_effect=AssertionError('process forbidden')))
        self.enterContext(patch.object(socket,'socket',side_effect=AssertionError('network forbidden')))

    def source_fixture(self):
        root=self.root/'inputs';root.mkdir()
        for name in P.LOCALS:shutil.copyfile(HERE/name,root/name)
        archive=HERE.parents[2]/'inputs/cache-seed/objects'/P.SOURCE_SHA
        shutil.copyfile(archive,root/'zlib-1.3.2.tar.gz')
        policy=dict(schema=1,source_sha256=P.SOURCE_SHA,local_files={n:P.pin(P.read(root/n))for n in P.LOCALS},training=dict(path='training.bin',**P.pin(P.read(root/'training.bin'))),validation=dict(path='validation.bin',**P.pin(P.read(root/'validation.bin'))),training_seconds=120,build_seconds=180,job_seconds=1200)
        (root/'recipe-policy.json').write_bytes(P.encoded(policy));return root,policy

    def test_frozen_training_plan_has_only_training_bytes_and_fixed_example(self):
        plan=P.training_plan('/retained/control')
        self.assertEqual(len(plan),4)
        self.assertEqual([r['input']for r in plan],['training.bin','train.gz',None,'train.gz'])
        self.assertEqual(plan[0]['argv'],['/tmp/build/minigzip','-6'])
        self.assertEqual(plan[3]['argv'],['/tmp/build/gun'])
        self.assertNotIn('validation',str(plan));self.assertNotIn('heldout',str(plan))

    def test_closed_flags_keep_generic_isa_profile_diagnostics_and_unprofiled_oracle(self):
        self.assertIn('-O2 -g -march=armv8-a -mtune=generic',P.BASE)
        self.assertIn('-fno-lto',P.BASE);self.assertNotIn('-march=native',P.BASE)
        self.assertEqual(P.USE,' -fprofile-use=/tmp/profile -Werror=missing-profile -Werror=coverage-mismatch')
        self.assertIn('max-page-size=65536,-z,common-page-size=16384',P.LINK)
        calls=[]
        class Stub:
            def run(self,*args,**kwargs):calls.append((args,kwargs));return b''
        P.auxiliary(Stub(),Path('/inputs'),'control')
        self.assertEqual(len(calls),4)
        self.assertTrue(all('-fprofile-'not in ' '.join(a[0][1])for a in calls))

    def test_configure_probes_baseline_then_exact_fatal_profile_use_assignments(self):
        raw=('CC=gcc\nAR=gcc-ar\nRANLIB=gcc-ranlib\nCFLAGS='+P.BASE+' -fPIC -DHAVE_HIDDEN\nLDFLAGS='+P.LINK+'\n').encode()
        make=self.root/'Makefile';log=self.root/'configure.log';make.write_bytes(raw);log.write_bytes(raw)
        result=P.apply_use_flags(make,log,self.core)
        self.assertIn(P.USE,result['CFLAGS']);self.assertEqual(result['LDFLAGS'],P.LINK+P.USE)
        self.assertEqual(log.read_bytes(),raw)
        for changed in (raw+b'CFLAGS=extra\n',raw.replace(b'-mtune=generic',b'-mtune=apple-m2')):
            make.write_bytes(changed);log.write_bytes(changed)
            with self.assertRaises(ValueError):P.apply_use_flags(make,log,self.core)

    def test_offline_source_policy_missing_tampered_or_extra_inputs_refuse(self):
        root,policy=self.source_fixture();self.assertEqual(P.inputs(root),policy)
        train=root/'training.bin';raw=train.read_bytes();train.write_bytes(raw+b'x')
        with self.assertRaises(ValueError):P.inputs(root)
        train.write_bytes(raw);bad=copy.deepcopy(policy);bad['local_files'].pop('profile_seal.py');(root/'recipe-policy.json').write_bytes(P.encoded(bad))
        with self.assertRaises(ValueError):P.inputs(root)
        bad=copy.deepcopy(policy);bad['job_seconds']=1201;(root/'recipe-policy.json').write_bytes(P.encoded(bad))
        with self.assertRaises(ValueError):P.inputs(root)

    def test_failed_source_or_non_native_guard_precedes_actor(self):
        root,policy=self.source_fixture();(root/'zlib-1.3.2.tar.gz').write_bytes(b'wrong source')
        with self.assertRaises(ValueError):P.construct(root,self.root/'result')
        self.assertFalse((self.root/'result').exists())
        with patch.object(P.platform,'machine',return_value='x86_64'),self.assertRaises(ValueError):P.guard()

    def test_static_order_seals_before_two_use_builds_and_checks_after(self):
        tree=ast.parse((HERE/'pipeline.py').read_text());node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='construct')
        text=ast.get_source_segment((HERE/'pipeline.py').read_text(),node)
        self.assertLess(text.index('shutil.rmtree(PROFILE);PROFILE.mkdir'),text.index('for row in plan:'))
        self.assertLess(text.index('seal.seal('),text.index('for attempt in (1,2):'))
        self.assertGreaterEqual(text.count('expected_sha256=original_seal'),3)
        self.assertIn("need(outputs[0]==outputs[1]",text)
        self.assertIn("correctness(runner,output,read(root/'validation.bin'))",text)

    def test_echoed_fatal_flags_are_not_diagnostics_and_real_profile_warning_refuses(self):
        P.profile_diagnostics(('gcc '+P.BASE+P.USE+' -c inflate.c\n').encode())
        for raw in (b'inflate.c:1: warning: profile count data file not found\n',b'inflate.c:1: error: number of counters in profile data does not match\n',b'libgcov profiling error: file mismatch\n'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):P.profile_diagnostics(raw)

    def test_passive_payload_verification_refuses_incomplete_or_changed_result(self):
        output=self.root/'result';output.mkdir()
        for attempt in (1,2):
            directory=output/('optimized-'+str(attempt));directory.mkdir()
            for name in P.PAYLOAD:(directory/name).write_bytes(b'synthetic payload '+name.encode())
        (output/'profile-seal.json').write_bytes(b'synthetic seal')
        payload={n:P.pin(P.read(output/'optimized-1'/n))for n in P.PAYLOAD}
        report=dict(status='PASS_FINITE_PGO_CONSTRUCTION_AND_NATIVE_CORRECTNESS_ONLY',optimized_clean_builds=2,outputs=[payload,payload],profile_seal_sha256=P.sha(b'synthetic seal'),binding=dict(source_files={'local/profile_seal.py':P.pin(P.read(HERE/'profile_seal.py'))}))
        (output/'result.json').write_bytes(P.encoded(report))
        (output/'receipt.json').write_bytes(P.encoded(dict(schema=1,status=report['status'],acceptance=False,performance='NOT MEASURED',hardware='NOT RUN',files={p.relative_to(output).as_posix():P.pin(p.read_bytes())for p in output.rglob('*')if p.is_file()})))
        # This fixture checks payload/retention joins; the independent seal suite
        # tests real passive GCDA/header/binding validation, never synthetic origin.
        with patch.object(P,'load',return_value=SimpleNamespace(verify=lambda *a,**k:None)):
            self.assertEqual(P.check(output),report)
            (output/'optimized-2/minigzip').write_bytes(b'wrong')
            with self.assertRaises(ValueError):P.check(output)

    def test_failed_incomplete_profile_data_survives_without_alias_following(self):
        profiles=self.root/'bad-profiles';profiles.mkdir();output=self.root/'failed';output.mkdir()
        (profiles/'partial.gcda').write_bytes(b'not valid profile data')
        (profiles/'alias.gcda').symlink_to(profiles/'partial.gcda')
        rows=P.retain_failed_profiles(profiles,output)
        self.assertEqual((output/'failed-profiles/partial.gcda').read_bytes(),b'not valid profile data')
        self.assertIs(rows['alias.gcda']['retained'],False)
        self.assertFalse((output/'failed-profiles/alias.gcda').exists())


if __name__=='__main__':unittest.main()
