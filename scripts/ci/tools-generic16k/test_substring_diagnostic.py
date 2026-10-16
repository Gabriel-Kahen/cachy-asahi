# SPDX-License-Identifier: MIT
"""Temporary fixture files and mocked pipes only; no candidate, VM or native actor."""
import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import guest
import run as R


class SubstringDiagnostic(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.work=Path(self.tmp.name)
        self.nonce='a'*32;self.release='test-generic16k'
        self.manifest=dict(source_commit='e'*40,files={n:dict(bytes=3,mode=420,sha256=guest.sha(b'pin')) for n in guest.SUBSTRING_IDENTITIES})
        self.manifest_raw=(json.dumps(self.manifest,sort_keys=True,indent=2)+'\n').encode()
        self.argv=['/usr/bin/python3','-I','-B','/fixtures/substring_observer.py','--module-dir',
            '/usr/share/cachy-asahi/zsh-history-substring-search','--work','/tmp/tools16k/substring',
            '--highlight-wrapper','/usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh']
        self.receipt=dict(status='FAIL',host_architecture='aarch64',tests=[dict(name=n,status='FAIL' if n=='editing' else 'PASS',
            **(dict(reason='older substring match missing',error_type='ValueError') if n=='editing' else dict(exit=0))) for n in guest.SUBSTRING_CASES])
        (self.work/'receipt.json').write_text(json.dumps(self.receipt)+'\n')
        for name in guest.SUBSTRING_CASES:
            path=self.work/name;path.mkdir();(path/'terminal.log').write_bytes(b'terminal head\n'+b'x'*2000+b'\nterminal tail')
            (path/'ready').write_bytes(b'ready\n');(path/'prompt-sequence').write_bytes(b'2\n')
            (path/'history').write_bytes(b'DO NOT EXPORT HISTORY')
            (path/'setup.zsh').write_bytes(b'DO NOT EXPORT SETUP')
        (self.work/'editing/snapshot-1').write_bytes(b'printf multi-needle\nprintf second-line\0' + b'37')
        (self.work/'editing/snapshot-2').write_bytes(b'wrong-match\0' + b'11')
        self.stdout=b'{"status":"FAIL","cases":6,"host_architecture":"aarch64"}\n';self.stderr=b'original fixture stderr'
        row=dict(argv=self.argv,exit=1,expected_exit=0,natural_exit=True,group_absent=True,pid=23456,pgid=23456,
            seconds=1,stdout_bytes=len(self.stdout),stdout_sha256=guest.sha(self.stdout),stderr_bytes=len(self.stderr),stderr_sha256=guest.sha(self.stderr))
        self.error=guest.CommandFailure('guest command exit/group differs: 1',row,self.stdout,self.stderr)
        self.actor=patch.object(guest.subprocess,'Popen',side_effect=AssertionError('actor execution forbidden'));self.actor.start();self.addCleanup(self.actor.stop)

    def raw(self):
        # Temporary files stay owned by this user; exported identity models only the marked guest UID.
        read=guest.diagnostic_file
        def diagnostic_file(*args,**kwargs):
            result=read(*args,**kwargs)
            if result.get('status')=='FILE':result.update(uid=23001,gid=23001)
            return result
        with patch.object(guest,'diagnostic_file',side_effect=diagnostic_file),\
             patch.object(guest.os,'uname',return_value=SimpleNamespace(machine='aarch64')),\
             patch.object(guest.os,'sysconf',return_value=16384),\
             patch.object(guest.os,'getresuid',return_value=(23001,)*3),patch.object(guest.os,'getresgid',return_value=(23001,)*3),\
             patch.object(guest.os,'getgroups',return_value=[]):
            return guest.substring_diagnostic(self.error,self.work,self.nonce,self.release,self.manifest_raw,self.argv)

    def parse(self,raw):return R.failed_substring_diagnostic(b'TOOLS16K_DIAGNOSTIC '+raw.encode()+b'\r\n',self.nonce,self.release,self.manifest)

    def test_original_failure_receipt_case_reason_and_terminal_survive(self):
        raw=self.raw();value=self.parse(raw)
        self.assertFalse(value['acceptance_credit']);self.assertEqual(value['fixture_receipt'],self.receipt)
        case=value['value']['cases']['editing'];self.assertEqual(case['snapshot_numbers_present'],[1,2]);self.assertEqual(case['latest_snapshot'],2)
        self.assertEqual(base64.b64decode(case['files']['latest_snapshot']['sample_base64']),b'wrong-match\0' + b'11')
        self.assertTrue(base64.b64decode(case['files']['terminal.log']['sample_base64']).endswith(b'terminal tail'))
        self.assertNotIn('DO NOT EXPORT',raw);self.assertEqual(value['value']['command']['exit'],1)
        self.assertEqual(set(value['value']['cases']),set(guest.SUBSTRING_CASES));self.assertLessEqual(len(raw.encode()),65536)

    def test_nonzero_expected_is_not_mistaken_for_failure(self):
        read,write=os.pipe();os.close(write);out=os.fdopen(read,'rb');read,write=os.pipe();os.close(write);err=os.fdopen(read,'rb')
        events=[];process=SimpleNamespace(pid=23456,stdout=out,stderr=err,wait=lambda timeout:events.append('wait') or 1)
        def signal(pid,sig):
            events.append(sig)
            if sig==0:raise ProcessLookupError()
        with patch.object(guest.subprocess,'Popen',return_value=process),patch.object(guest.os,'waitid',return_value=object()),patch.object(guest.os,'killpg',side_effect=signal):
            row,_=guest.command(['inert'],{},expected=1)
        self.assertEqual(row['exit'],1);self.assertTrue(row['group_absent'])
        self.assertEqual(events,[guest.signal.SIGTERM,guest.signal.SIGKILL,'wait',0])

    def test_original_unexpected_exit_retains_raw_outputs_and_group_before_raise(self):
        pipes=[]
        for raw in (self.stdout,self.stderr):
            read,write=os.pipe();os.write(write,raw);os.close(write);pipes.append(os.fdopen(read,'rb'))
        events=[];process=SimpleNamespace(pid=23456,stdout=pipes[0],stderr=pipes[1],wait=lambda timeout:events.append('wait') or 1)
        def signal(pid,sig):
            events.append(sig)
            if sig==0:raise ProcessLookupError()
        with patch.object(guest.subprocess,'Popen',return_value=process),patch.object(guest.os,'waitid',return_value=object()),patch.object(guest.os,'killpg',side_effect=signal):
            with self.assertRaises(guest.CommandFailure) as caught:guest.command(self.argv,{})
        self.assertEqual(caught.exception.stdout,self.stdout);self.assertEqual(caught.exception.stderr,self.stderr)
        self.assertEqual(caught.exception.row['pid'],23456);self.assertTrue(caught.exception.row['natural_exit'])
        self.assertEqual(events,[guest.signal.SIGTERM,guest.signal.SIGKILL,'wait',0])

    def test_failure_emits_once_then_reraises_identical_error_without_rerun(self):
        output=io.StringIO();calls=[];raw=self.raw()
        def call(argv,**kwargs):calls.append((argv,kwargs));raise self.error
        with patch.object(guest,'substring_diagnostic',return_value=raw),contextlib.redirect_stdout(output):
            with self.assertRaises(guest.CommandFailure) as caught:guest.run_substring(call,Path('/tmp/tools16k/substring'),self.nonce,self.release,self.manifest_raw)
        self.assertIs(caught.exception,self.error);self.assertEqual(calls,[(self.argv,dict(seconds=180))])
        self.assertEqual(output.getvalue(),'TOOLS16K_DIAGNOSTIC '+raw+'\n')

    def test_capture_failure_cannot_hide_original_failure(self):
        output=io.StringIO()
        def call(*_,**__):raise self.error
        with patch.object(guest,'substring_diagnostic',side_effect=OSError('inert')),contextlib.redirect_stdout(output):
            with self.assertRaises(guest.CommandFailure) as caught:guest.run_substring(call,self.work,self.nonce,self.release,self.manifest_raw)
        self.assertIs(caught.exception,self.error);self.assertEqual(output.getvalue(),'TOOLS16K_DIAGNOSTIC_UNAVAILABLE OSError\n')

    def test_missing_oversize_alias_and_hardlink_are_explicit_without_reading(self):
        self.assertEqual(guest.diagnostic_file(self.work/'absent',64),dict(status='ABSENT'))
        path=self.work/'big';path.write_bytes(b'x'*65537)
        self.assertEqual(guest.diagnostic_file(path,64)['status'],'UNAVAILABLE')
        link=self.work/'link';link.symlink_to(self.work/'receipt.json')
        self.assertEqual(guest.diagnostic_file(link,64)['status'],'UNAVAILABLE')
        os.link(self.work/'receipt.json',self.work/'hardlink')
        self.assertEqual(guest.diagnostic_file(self.work/'receipt.json',64)['status'],'UNAVAILABLE')
        directory=self.work/'alias';directory.symlink_to(self.work/'editing',target_is_directory=True)
        self.assertEqual(guest.diagnostic_file(directory/'ready',64)['status'],'UNAVAILABLE')

    def test_identity_argv_case_sample_and_duplicate_forgery_are_rejected(self):
        original=json.loads(self.raw())
        for field,bad in [('nonce','b'*32),('source_commit','b'*40),('uid',[0]*3),('groups',[23001]),('acceptance_credit',True),('product_change','FIXED')]:
            value=copy.deepcopy(original);value[field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):self.parse(json.dumps(value))
        for kind in ('argv','case','sample','command','identity'):
            value=copy.deepcopy(original)
            if kind=='argv':value['argv'][-1]='/foreign'
            elif kind=='case':value['cases']['foreign']=value['cases'].pop('editing')
            elif kind=='sample':value['cases']['editing']['files']['terminal.log']['sample_base64']='eA=='
            elif kind=='command':value['command']['exit']=0
            else:value['identities']['fixtures/substring.py']['sha256']='0'*64
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.parse(json.dumps(value))
        wire=b'TOOLS16K_DIAGNOSTIC '+self.raw().encode()+b'\n'
        with self.assertRaises(ValueError):R.failed_substring_diagnostic(wire*2,self.nonce,self.release,self.manifest)
        with self.assertRaises(ValueError):self.parse('x'*65537)

    def test_diagnostic_cannot_count_as_guest_pass_and_absence_is_not_fabricated(self):
        raw=b'TOOLS16K_DIAGNOSTIC '+self.raw().encode()+b'\n'
        with self.assertRaisesRegex(ValueError,'natural bounded guest exit0 required'):R.guest_report(raw,0,self.nonce,self.release,self.manifest)
        self.assertIsNone(R.failed_substring_diagnostic(b'original failure without receipt\n',self.nonce,self.release,self.manifest))

    def test_total_cap_keeps_original_receipt_and_case_progress(self):
        self.receipt['padding']='x'*14000
        (self.work/'receipt.json').write_text(json.dumps(self.receipt))
        for name in guest.SUBSTRING_CASES:(self.work/name/'snapshot-10').write_bytes(b'x'*4096)
        raw=self.raw();value=self.parse(raw)
        self.assertLessEqual(len(raw.encode()),65536);self.assertEqual(value['fixture_receipt'],self.receipt)
        self.assertTrue(value['value']['snapshot_samples_omitted_for_total_cap'])
        self.assertTrue(all(case['latest_snapshot']==10 for case in value['value']['cases'].values()))

    def terminal_files(self,padded=False):
        for name in guest.SUBSTRING_CASES:
            value=dict(schema_version=1,status='NO_PTY_ORIGINAL_NONINTERACTIVE_CASE' if name=='noninteractive' else 'TERMINAL_OBSERVATION_ONLY',
                acceptance_credit=False,case=name,fixture_sha256=guest.sha(b'pin'),observer_sha256=guest.sha(b'pin'),
                observer_reaping='NONE',observer_signals='NONE')
            if name!='noninteractive':
                point=dict(elapsed_ns=1,status='OBSERVED_UNREAPED_CHILD',returncode=None,waitid=None,
                    uid=[23001]*4,gid=[23001]*4,cpu_limit=[10,10],proc=dict(pid=300,ppid=200,pgid=300,sid=300,state='R',utime=990,stime=9,start=7))
                value.update(pid=300,parent_pid=200,uid=23001,gid=23001,clock_ticks=100,initial=point,
                    events=[dict(point,stage='BEFORE_ORIGINAL_CLOSE',elapsed_ns=2),
                            dict(stage='AFTER_ORIGINAL_CLOSE',elapsed_ns=3,status='ORIGINAL_ALREADY_REAPED',returncode=-15)])
            if padded:value['padding']='x'*(3059-len(json.dumps(value,sort_keys=True,separators=(',',':')).encode()))
            raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode();self.assertLessEqual(len(raw),3072)
            (self.work/name/'terminal-exit.json').write_bytes(raw)

    def test_terminal_observations_join_all_six_fixed_files_without_acceptance_credit(self):
        self.terminal_files();value=self.parse(self.raw())
        self.assertEqual(set(value['terminal_exit']),set(guest.SUBSTRING_CASES))
        self.assertEqual(value['terminal_exit']['coexist']['initial']['cpu_limit'],[10,10])
        self.assertFalse(value['acceptance_credit']);self.assertEqual(value['fixture_receipt'],self.receipt)

    def test_terminal_observation_source_forgery_and_oversize_are_not_accepted(self):
        self.terminal_files();path=self.work/'coexist/terminal-exit.json';value=json.loads(path.read_bytes())
        value['observer_sha256']='0'*64;path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'source/case/scope'):self.parse(self.raw())
        path.write_bytes(b'x'*3073);value=self.parse(self.raw())
        self.assertEqual(value['value']['cases']['coexist']['files']['terminal-exit.json']['status'],'UNAVAILABLE')
        self.assertNotIn('coexist',value['terminal_exit'])

    def test_all_file_caps_keep_cpu_observations_and_original_receipt_under_uart_cap(self):
        self.terminal_files(padded=True);self.receipt['padding']='x'*14000
        (self.work/'receipt.json').write_text(json.dumps(self.receipt))
        for name in guest.SUBSTRING_CASES:(self.work/name/'snapshot-10').write_bytes(b'x'*4096)
        raw=self.raw();value=self.parse(raw)
        self.assertLessEqual(len(raw.encode()),65536);self.assertEqual(set(value['terminal_exit']),set(guest.SUBSTRING_CASES))
        self.assertEqual(value['fixture_receipt'],self.receipt)
        self.assertTrue(value['value']['snapshot_samples_omitted_for_total_cap'])

    def test_valid_original_success_is_unchanged_and_emits_no_diagnostic(self):
        value=dict(status='PASS_HOST_ZSH_PTY_CONTROLS',tests=[dict(status='PASS',exit=0) for _ in range(6)])
        (self.work/'receipt.json').write_text(json.dumps(value))
        output=io.StringIO();calls=[]
        with contextlib.redirect_stdout(output):
            result=guest.run_substring(lambda argv,**kwargs:calls.append((argv,kwargs)),self.work,self.nonce,self.release,self.manifest_raw)
        self.assertEqual(result,value);self.assertEqual(len(calls),1);self.assertEqual(output.getvalue(),'')


if __name__=='__main__':unittest.main(verbosity=2)
