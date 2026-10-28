#!/usr/bin/env python3
"""Inert normal-build orchestration models; all external commands are blocked."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('trial574_subject',HERE/'maintained574_owned_trial.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
TOKEN='a'*16;OLD='sha256:'+'0'*64;IMAGE='sha256:'+'1'*64;CID='c'*64

class CommandExit(ValueError):
    def __init__(self,code):self.code=code

class Trial(unittest.TestCase):
    def setUp(self):
        for name in ('Popen','run','check_output'):
            guard=patch.object(subprocess,name,side_effect=AssertionError('external actor forbidden'));guard.start();self.addCleanup(guard.stop)
        self.temp=tempfile.TemporaryDirectory(dir=HERE);self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.base=self.root/'base';self.out=self.root/'out'
        for path in(self.base,self.out,self.base/'context',self.base/'home',self.out/'public'):path.mkdir(mode=0o700)
        inputs=HERE/'maintained-desktop574-inputs.json'
        if not inputs.exists():inputs=Path(__file__).resolve().parents[6]/'scripts/ci/maintained-desktop574-inputs.json'
        self.inputs_path=inputs;self.inputs=json.loads(inputs.read_bytes());self.calls=[];self.list_calls=0;self.fail_build=None;self.fail_cleanup=None;self.change=None;self.lose_baseline=False
        self.h=SimpleNamespace(__file__=str(HERE/'maintained_desktop574.py'),owner_names=lambda token:('cachy-asahi-574-owned:'+token,'cachy-asahi-574-probe-'+token),docker=self.query,inspect_image=self.inspect)
        self.process=SimpleNamespace(command=self.command,CommandExit=CommandExit)
    def query(self,*args):
        self.assertEqual(args,('image','ls','-a','--no-trunc','-q'));self.list_calls+=1
        return '' if self.lose_baseline and self.list_calls>1 else OLD
    def inspect(self,image,token):
        self.assertEqual((image,token),(IMAGE,TOKEN))
        return dict(Id=IMAGE,RepoTags=[self.h.owner_names(token)[0]],RepoDigests=[])
    def report(self):
        tag,name=self.h.owner_names(TOKEN)
        return dict(status='PASS_NATIVE_OFFLINE_574_TRANSACTION',native_build='PASS',packages=574,hardware='NOT_RUN',acquired=1153,failures=[],build_returncode=0,image=IMAGE,
            ownership=dict(token=TOKEN,image_tag=tag,probe_name=name,probe_cidfile='probe-cid',before_images=[OLD],build_started=True,build_complete=True,probe_started=True,probe_complete=True,image=IMAGE))
    def command(self,argv,log,env,seconds):
        self.assertNotIn('CACHY_',str(env));mode=argv[4];self.calls.append((mode,seconds));self.assertEqual(argv[-1],TOKEN)
        if mode=='build':
            report=self.report()
            expected=''.join(f"{r['name']} {r['version']}\n"for r in sorted(self.inputs['packages'],key=lambda r:r['name'])).encode()
            (self.base/'context/expected-packages.lock').write_bytes(expected);(self.base/'installed-packages.lock').write_bytes(expected)
            (self.base/'image-id').write_text(IMAGE);(self.base/'probe-cid').write_text(CID)
            if self.change:self.change(report)
            (self.base/'report.json').write_text(json.dumps(report))
            if self.fail_build:raise self.fail_build
        else:
            self.assertEqual(mode,'cleanup')
            if self.fail_cleanup:raise self.fail_cleanup
            report=json.loads((self.base/'report.json').read_bytes());report['owned_cleanup']=dict(status='PASS',build='COMPLETED',probe=dict(cid=CID,absence_verified=True),image=dict(id=IMAGE,absence_verified=True))
            (self.base/'report.json').write_text(json.dumps(report))
    def run_trial(self):
        with patch.object(t.uuid,'uuid4',return_value=SimpleNamespace(hex=TOKEN+'b'*16)):
            return t.trial(self.h,self.process,self.base,self.out,self.inputs)
    def test_normal_one_build_one_cleanup_inventory_and_baseline(self):
        row=self.run_trial();self.assertEqual(row['status'],'PASS');self.assertEqual(self.calls,[('build',2400),('cleanup',240)])
        self.assertTrue(row['before_image_ids_preserved']);self.assertEqual(row['verified_build']['packages'],574)
        self.assertEqual(row['daemon_wide_cleanup'],'NOT_CLAIMED')
    def test_wrong_build_report_cannot_pass_but_cleanup_still_runs(self):
        for field,value in (('packages',573),('acquired',1152),('build_returncode',False),('failures',[{}]),('native_build','NOT_RUN')):
            with self.subTest(field=field):
                self.calls=[];self.change=lambda r:r.update({field:value})
                row=self.run_trial();self.assertEqual(row['status'],'FAIL');self.assertEqual(row['first_failure']['phase'],'build');self.assertEqual(self.calls[-1][0],'cleanup')
    def test_wrong_token_or_incomplete_probe_refuses(self):
        for field,value in (('token','b'*16),('probe_complete',False),('before_images',[])):
            with self.subTest(field=field):
                self.change=lambda r:r['ownership'].update({field:value})
                self.assertEqual(self.run_trial()['status'],'FAIL')
    def test_inventory_bytes_are_required_not_only_report_count(self):
        original=self.command
        def change(*args):
            original(*args)
            if args[0][4]=='build':(self.base/'installed-packages.lock').write_bytes(b'not574\n')
        self.process.command=change
        row=self.run_trial();self.assertEqual(row['status'],'FAIL');self.assertEqual(row['cleanup'],'PASS')
    def test_nonzero_build_primary_preserved_with_cleanup_failure_and_baseline_attempt(self):
        self.fail_build=CommandExit(7);self.fail_cleanup=OSError(5,'PRIVATE')
        row=self.run_trial();self.assertEqual(row['first_failure'],dict(phase='build',kind='CommandExit',exit_code=7))
        self.assertIn('cleanup',row['secondary_failure_phases']);self.assertTrue(row['before_image_ids_preserved']);self.assertNotIn('PRIVATE',json.dumps(row))
    def test_timeout_does_not_claim_build_or_daemon_retirement(self):
        self.fail_build=subprocess.TimeoutExpired('inert',2400);self.fail_cleanup=CommandExit(1)
        row=self.run_trial();self.assertEqual(row['status'],'FAIL');self.assertEqual(row['cleanup'],'FAIL_OR_UNKNOWN');self.assertNotIn('verified_build',row)
        self.assertEqual(row['active_build_cancellation'],'NOT_TESTED')
    def test_cancellation_is_sticky_but_later_cleanup_and_baseline_are_attempted(self):
        primary=KeyboardInterrupt();self.fail_build=primary;self.fail_cleanup=SystemExit(9)
        with self.assertRaises(KeyboardInterrupt)as caught:self.run_trial()
        self.assertIs(caught.exception,primary);self.assertEqual(self.calls,[('build',2400),('cleanup',240)])
        row=json.loads((self.out/'public/trial.json').read_bytes());self.assertTrue(row['cancelled']);self.assertTrue(row['before_image_ids_preserved'])
    def test_lost_original_image_refuses_even_if_owned_cleanup_passed(self):
        self.lose_baseline=True;row=self.run_trial();self.assertEqual(row['status'],'FAIL');self.assertFalse(row['before_image_ids_preserved'])
        self.assertEqual(row['first_failure']['phase'],'baseline-preservation')
    def test_cleanup_wrong_image_is_refused(self):
        original=self.command
        def change(*args):
            original(*args)
            if args[0][4]=='cleanup':
                report=json.loads((self.base/'report.json').read_bytes());report['owned_cleanup']['image']['id']=OLD
                (self.base/'report.json').write_text(json.dumps(report))
        self.process.command=change
        self.assertEqual(self.run_trial()['cleanup'],'FAIL_OR_UNKNOWN')

    def test_final_receipt_fault_does_not_replace_original_cancel_or_command_error(self):
        original=t.save
        for primary in (KeyboardInterrupt(),CommandExit(7),None):
            self.fail_build=primary;self.fail_cleanup=None;self.calls=[];counter=[]
            def saving(path,row):
                counter.append(path)
                if len(counter)==2:raise OSError(5,'PRIVATE final write')
                return original(path,row)
            with patch.object(t,'save',side_effect=saving):
                if isinstance(primary,KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt)as caught:self.run_trial()
                    self.assertIs(caught.exception,primary)
                else:
                    row=self.run_trial();self.assertEqual(row['status'],'FAIL');self.assertTrue(row['retention_uncertain'])
                    self.assertEqual(row['first_failure']['kind'],'CommandExit'if primary else'OSError')
            self.assertEqual(self.calls,[('build',2400),('cleanup',240)])
    def test_missing_build_report_never_passes_or_skips_cleanup_baseline(self):
        original=self.command
        def missing(*args):
            original(*args)
            if args[0][4]=='build':(self.base/'report.json').unlink()
        self.process.command=missing
        row=self.run_trial();self.assertEqual(row['status'],'FAIL');self.assertEqual(self.calls[-1][0],'cleanup')
        self.assertTrue(row['before_image_ids_preserved']);self.assertNotIn('verified_build',row)
    def test_seed_requires_public_objects_in_context_deps_not_another_cache(self):
        asset=self.root/'asset';asset.mkdir();(self.base/'context/deps').mkdir(mode=0o700)
        (self.base/'seed-report.json').write_text(json.dumps(dict(status='SIX_EXACT_EXISTING_SEED_FILES_READY',seeded_files=6)))
        rows=[];planned=[]
        for i in range(12):
            name=f'fixed-{i}';data=name.encode();path=self.base/'context/deps'/name;path.write_bytes(data)
            row=dict(filename=name,size=len(data),sha256=t.sha(path));rows.append(row);planned.append(row)
        (asset/'index.json').write_text(json.dumps(dict(desktop574_lock_sha256=t.PINS['maintained-desktop574-inputs.json'],files=rows)))
        (asset/'seed.py').write_text('# inert Source body\n')
        pins={name:t.sha(asset/name)for name in('seed.py','index.json')}
        self.h.plan=lambda *args:planned
        with patch.object(t,'ASSET_PINS',pins):
            t.seeded(self.h,self.base,asset,self.inputs)
            path=self.base/'context/deps/fixed-0';path.rename(self.root/'elsewhere')
            with self.assertRaises(FileNotFoundError):t.seeded(self.h,self.base,asset,self.inputs)
            path.symlink_to(self.root/'elsewhere')
            with self.assertRaises(ValueError):t.seeded(self.h,self.base,asset,self.inputs)
    def test_pinned_inputs_and_expected_inventory_are_real_current_metadata(self):
        self.assertEqual(len(self.inputs['packages']),574)
        data=''.join(f"{r['name']} {r['version']}\n"for r in sorted(self.inputs['packages'],key=lambda r:r['name'])).encode()
        import hashlib
        self.assertEqual(hashlib.sha256(data).hexdigest(),t.INVENTORY_SHA)
        self.assertEqual(t.sha(self.inputs_path.with_name('maintained_desktop574.py')),t.PINS['maintained_desktop574.py'])

if __name__=='__main__':unittest.main()
