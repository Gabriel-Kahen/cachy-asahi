#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Explicit host-tool metadata controls; actual source inputs cannot be skipped."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('audio_actual_metadata_tests',HERE/'replay.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
NATIVE='e2ab9b6cc2810bf5d5b6454abdb9bcdeea6567797247c745b0d04541cb99c6c8'


class ActualReplay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='audio-actual-metadata-test-');cls.addClassCleanup(cls.temp.cleanup)
        cls.private=Path(cls.temp.name);cls.handoff=Path(ARGS.handoff).absolute();cls.toolchain=Path(ARGS.toolchain).absolute()
        cls.tools=ARGS.tools_profile_sha256;cls.index=ARGS.index_sha256
        poison=cls.private/'poison';(poison/'cargo').mkdir(parents=True)
        (poison/'cargo/config.toml').write_text('[build]\nrustc="/must-never-run"\nrustc-wrapper="/must-never-run"\n[alias]\nmetadata="!must-never-run"\n')
        cls.output=cls.private/'positive-report'
        with mock.patch.dict(os.environ,{'HOME':str(poison),'CARGO_HOME':str(poison/'cargo'),'RUSTUP_TOOLCHAIN':'must-not-install',
            'RUSTC':'/must-never-run','RUSTC_WRAPPER':'/must-never-run','RUSTC_WORKSPACE_WRAPPER':'/must-never-run',
            'CARGO_ALIAS_METADATA':'!must-never-run','RUSTFLAGS':'must-never-pass','LD_PRELOAD':'/must-never-load'}):
            cls.report=r.run(cls.handoff,cls.index,NATIVE,cls.toolchain,cls.tools,cls.output)
        cls.a=r.module('actual_replay_vendor',r.ROOT/r.PINS['vendor'][0],r.PINS['vendor'][1]);cls.runtime_api=r.module('actual_replay_runner',r.ROOT/r.PINS['runner'][0],r.PINS['runner'][1])
        profile=r.load_profile(cls.tools);cls.runtime=r.stage_runtime(profile,cls.toolchain,cls.private)
        intake=cls.a.intake_module();value=intake.profile(intake.ordinary(cls.handoff/'native-inputs.json'),NATIVE);api=intake.load_api(value);cls.materials={}
        for name in cls.a.PACKAGES:
            raw=intake.ordinary(cls.handoff/'sources'/name/'source.tar');_,cls.materials[name]=api.verified(raw,r.digest(raw))
        r.stage_materials(cls.a,cls.materials,cls.private)
        for name in ('work','home','tmp'):(cls.private/name).mkdir(mode=0o700)
        r.put(cls.private/'work','exec-probe',r.read(cls.runtime/'tool/bin/cargo'),0o500)
        r.put(cls.private/'home','cargo/config.toml',b'[source.crates-io]\nreplace-with="vendored-sources"\n[source.vendored-sources]\ndirectory="/vendor"\n[net]\noffline=true\n',0o400)

    def operation(self,name):
        logdir=self.private/('logs-'+self._testMethodName)
        runner=self.runtime_api.Runner(45,{'LANG':'C','PATH':'/usr/bin'},logdir)
        with self.runtime_api.cancellation_handlers():return runner.run(r.command(self.runtime,self.private,name),timeout=30,limit=4*1024**2)

    def test_actual_graphs_join_original_inputs_with_all_denial_proofs(self):
        self.assertEqual(self.report['status'],'NEW_HOST_DEFAULT_FEATURE_TARGET_GRAPHS_RECORDED');self.assertEqual(self.report['requirements'],[])
        expected={'bankstown':(18,37),'speakersafetyd':(47,63),'triforce-lv2':(39,80)}
        for name,row in self.report['packages'].items():
            self.assertEqual((row['graph']['reachable_packages'],row['graph']['reachable_edges']),expected[name])
            self.assertEqual(set(row['isolation']),r.PROOF_FIELDS);self.assertTrue(all(row['isolation'].values()))
            self.assertFalse(row['graph']['original_native_flags_or_features_proven'])
        self.assertTrue(self.report['source_locks_unchanged']);self.assertTrue(self.report['compiled_artifact_outputs_absent'])
        self.assertFalse(self.report['complete_corresponding_source_accepted']);self.assertFalse(self.report['legal_acceptance'])

    def test_actual_inherited_operator_configuration_was_excluded(self):
        self.assertTrue(self.report['tool_probes']['cargo-version']['version_output'][0].startswith('cargo 1.96.1 '))
        self.assertTrue(self.report['tool_probes']['rustc-version']['version_output'][0].startswith('rustc 1.96.1 '))
        self.assertEqual(len(self.report['omitted_source_controls']),20)
        self.assertEqual(sum(x['reason']=='INERT_SOURCE_SYMLINK_NOT_MATERIALIZED'for x in self.report['omitted_source_controls']),11)
        self.assertNotIn(b'must-never',r.encoded(self.report))

    def test_actual_missing_vendor_cannot_fetch_or_invent_material(self):
        source=self.private/'vendor/wmidi-3.1.0';held=self.private/'held-wmidi';source.rename(held)
        try:result=self.operation('bankstown')
        finally:held.rename(source)
        self.assertNotEqual(result.returncode,0)
        observations=r.failure_requirements(result.stdout)
        self.assertIn(dict(code='VENDORED_PACKAGE_REQUIRED',material='wmidi'),observations)
        self.assertIn(b'"network_socket_denied": true',result.stdout)

    def test_actual_missing_target_source_is_refused_without_stub(self):
        source=self.private/'sources/bankstown/src/lib.rs';held=self.private/'held-source';source.rename(held)
        try:result=self.operation('bankstown')
        finally:held.rename(source)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(dict(code='MANIFEST_TARGET_SOURCE_REQUIRED'),r.failure_requirements(result.stdout))
        self.assertIn(b'"source_elf_exec_denied": true',result.stdout)

    def test_actual_metadata_tampered_version_cannot_claim_original_lock_join(self):
        lines=(self.output/'bankstown.log').read_bytes().splitlines();document=next(json.loads(x)for x in lines if x.startswith(b'{"packages"'))
        package=next(p for p in document['packages']if p['source']is not None);package['version']='999.0.0'
        vendor,_,_=self.a.vendor_data(self.materials['bankstown']['cargo-vendor-117.tar.xz'])
        with self.assertRaisesRegex(r.Requirement,'ORIGINAL_LOCK'):r.normalize_graph(self.a,document,'bankstown',self.materials['bankstown'],vendor)

    def test_cli_missing_tool_catalog_pin_writes_private_requirements(self):
        output=self.private/'refusal-report'
        cmd=[sys.executable,'-I','-B',str(HERE/'replay.py'),'--handoff',str(self.handoff),'--index-sha256',self.index,
            '--profile-sha256',NATIVE,'--toolchain',str(self.toolchain),'--tools-profile-sha256','0'*64,'--output',str(output)]
        result=subprocess.run(cmd,cwd='/',capture_output=True,text=True);self.assertEqual(result.returncode,2,result.stderr)
        report=json.loads((output/'metadata-replay.json').read_bytes())
        self.assertEqual(report['requirements'],[dict(code='TRUSTED_TOOLS_PROFILE_PIN_DIFFERS')]);self.assertFalse(report['complete_corresponding_source_accepted'])
        self.assertEqual((output/'metadata-replay.json').stat().st_mode&0o777,0o600)

    def test_actual_cli_report_reproduces_and_preserves_existing_output(self):
        output=self.private/'cli-report'
        cmd=[sys.executable,'-I','-B',str(HERE/'replay.py'),'--handoff',str(self.handoff),'--index-sha256',self.index,
            '--profile-sha256',NATIVE,'--toolchain',str(self.toolchain),'--tools-profile-sha256',self.tools,'--output',str(output)]
        result=subprocess.run(cmd,cwd='/',capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stderr+result.stdout)
        raw=(output/'metadata-replay.json').read_bytes();self.assertEqual(r.desc(raw),r.desc(r.encoded(self.report)))
        for path in (self.private,self.toolchain,self.handoff):self.assertTrue(str(path).encode()not in raw,'operator path leaked')
        sentinel=raw
        with self.assertRaises(FileExistsError):r.prerequisite_report(output,'OUTPUT_ALREADY_EXISTS')
        self.assertEqual((output/'metadata-replay.json').read_bytes(),sentinel)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('handoff','index-sha256','toolchain','tools-profile-sha256'):parser.add_argument('--'+name,required=True)
    ARGS,remaining=parser.parse_known_args();unittest.main(argv=[sys.argv[0],*remaining],verbosity=2)
