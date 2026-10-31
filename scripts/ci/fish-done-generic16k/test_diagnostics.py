# SPDX-License-Identifier: MIT
"""Inert failed-driver evidence controls; no Fish/VM/notification/native actors."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import guest
import run


class Diagnostics(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        blocked=patch.object(subprocess,'Popen',side_effect=AssertionError('actual actor forbidden'));blocked.start();self.addCleanup(blocked.stop)

    def fixture(self):
        root=self.root/'driver';root.mkdir();home=root/'user';home.mkdir();(home/'sentinel').write_bytes(b'outer preserved')
        case=root/'cases/foreground';case.mkdir(parents=True)
        receipt=dict(status='FAIL',error='long success did not notify once',cases={'noninteractive':dict(exit=0,notifications=0)})
        (root/'cases/receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        (case/'notifications.jsonl').write_text('')
        (case/'terminal.log').write_bytes(b'private fixed fixture terminal\n')
        (case/'events').write_text('PRE sleep .12\nPOST sleep .12\n')
        (case/'load-status').write_text('0');(case/'setup-status').write_text('0');(case/'status-2').write_text('0')
        manifest=dict(files={});raw=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
        error=guest.CommandFailure('guest command exit/group differs',dict(exit=1,expected_exit=0,natural_exit=True,group_absent=True,proc_before_teardown={},proc_after_teardown={}),b'',b'original assertion traceback')
        return root,home,manifest,raw,error

    def diagnostic(self):
        root,home,manifest,raw,error=self.fixture()
        with patch.object(guest.os,'uname',return_value=SimpleNamespace(machine='aarch64')),patch.object(guest.os,'sysconf',return_value=16384),patch.object(guest.os,'getuid',return_value=23001):
            value=guest.failure_diagnostic(error,root,'a'*32,'test16k',raw,home,guest.snapshot(home))
        return value,manifest

    def test_original_failed_receipt_empty_recorder_status_and_terminal_preserved(self):
        raw,manifest=self.diagnostic();value=json.loads(raw)
        original=value['original_receipt'];self.assertTrue(original['sample_complete'])
        receipt=json.loads(base64.b64decode(original['sample_base64']));self.assertEqual(receipt['error'],'long success did not notify once')
        self.assertEqual(value['cases']['foreground']['notifications.jsonl']['bytes'],0);self.assertEqual(value['cases']['foreground']['notifications.jsonl']['record_count'],0)
        self.assertTrue(value['driver']['natural_exit']);self.assertEqual(value['driver']['exit'],1)
        self.assertFalse(value['acceptance_credit']);self.assertEqual(value['product_change'],'NONE')
        row=run.failed_driver_diagnostic(b'DONE16K_DIAGNOSTIC '+raw.encode()+b'\n','a'*32,'test16k',manifest)
        self.assertEqual(row['sha256'],hashlib.sha256(raw.encode()).hexdigest())

    def test_nonzero_and_surplus_recorder_rows_are_distinguishable_without_reclassification(self):
        root,home,manifest,raw,error=self.fixture();path=root/'cases/foreground/notifications.jsonl'
        path.write_text(''.join(json.dumps(dict(pid=99+i,argv=['literal fixture']))+'\n' for i in range(2)))
        with patch.object(guest.os,'uname',return_value=SimpleNamespace(machine='aarch64')),patch.object(guest.os,'sysconf',return_value=16384),patch.object(guest.os,'getuid',return_value=23001):value=json.loads(guest.failure_diagnostic(error,root,'a'*32,'test16k',raw,home,guest.snapshot(home)))
        rows=json.loads('['+','.join(base64.b64decode(value['cases']['foreground']['notifications.jsonl']['sample_base64']).decode().splitlines())+']')
        self.assertEqual(len(rows),2);self.assertEqual(value['cases']['foreground']['notifications.jsonl']['record_count'],2);self.assertEqual(value['status'],'FAILED_DRIVER_DIAGNOSTIC_ONLY')

    def test_nonce_scope_page_uid_hash_and_duplicate_marker_tampering_refuse(self):
        raw,manifest=self.diagnostic();value=json.loads(raw)
        for field,bad in [('nonce','b'*32),('page_size',4096),('uid',0),('kernel','other'),('acceptance_credit',True),('payload_manifest_sha256','f'*64)]:
            changed=copy.deepcopy(value);changed[field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):run.failed_driver_diagnostic(b'DONE16K_DIAGNOSTIC '+json.dumps(changed).encode(),'a'*32,'test16k',manifest)
        with self.assertRaises(ValueError):run.failed_driver_diagnostic((b'DONE16K_DIAGNOSTIC '+raw.encode()+b'\n')*2,'a'*32,'test16k',manifest)

    def test_complete_raw_receipt_hash_cannot_be_forged(self):
        raw,manifest=self.diagnostic();value=json.loads(raw);value['original_receipt']['sha256']='0'*64
        with self.assertRaises(ValueError):run.failed_driver_diagnostic(b'DONE16K_DIAGNOSTIC '+json.dumps(value).encode(),'a'*32,'test16k',manifest)

    def test_success_gate_rejects_any_diagnostic_marker_even_without_error_marker(self):
        with self.assertRaisesRegex(ValueError,'natural bounded guest exit0'):run.guest_report(b'DONE16K_DIAGNOSTIC {}\n',0,'a'*32,'test16k',{})

    def test_stdout_stderr_samples_remain_bounded_and_original_hashes_join(self):
        raw=b'a'*65536;value=guest.sample(raw,4096,True)
        self.assertEqual(value['sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(value['sample_offset'],61440)
        self.assertFalse(value['sample_complete']);self.assertEqual(len(base64.b64decode(value['sample_base64'])),4096)

    def test_alias_hardlink_oversize_and_script_bytes_are_not_exported(self):
        target=self.root/'private';target.write_bytes(b'private script');alias=self.root/'alias';alias.symlink_to(target)
        self.assertEqual(guest.diagnostic_file(alias,128)['status'],'UNAVAILABLE')
        hard=self.root/'hard';os.link(target,hard);self.assertEqual(guest.diagnostic_file(target,128)['status'],'UNAVAILABLE');hard.unlink()
        row=guest.diagnostic_file(target);self.assertEqual(row['sample_base64'],'');self.assertEqual(row['sha256'],hashlib.sha256(target.read_bytes()).hexdigest())
        target.write_bytes(b'x'*65537);self.assertEqual(guest.diagnostic_file(target,128)['status'],'UNAVAILABLE')

    def test_only_fixed_last_two_case_directories_export_data(self):
        root,home,manifest,raw,error=self.fixture();(root/'cases/foreign').mkdir();(root/'cases/foreign/secret').write_text('never')
        with patch.object(guest.os,'uname',return_value=SimpleNamespace(machine='aarch64')),patch.object(guest.os,'sysconf',return_value=16384),patch.object(guest.os,'getuid',return_value=23001):value=json.loads(guest.failure_diagnostic(error,root,'a'*32,'test16k',raw,home,guest.snapshot(home)))
        self.assertNotIn('foreign',value['cases']);self.assertNotIn('secret',json.dumps(value))

    def test_large_terminal_and_recorder_files_keep_total_under_uart_bound(self):
        root,home,manifest,raw,error=self.fixture()
        for leaf in ('terminal.log','notifications.jsonl','events'):(root/'cases/foreground'/leaf).write_bytes(b'x'*65536)
        with patch.object(guest.os,'uname',return_value=SimpleNamespace(machine='aarch64')),patch.object(guest.os,'sysconf',return_value=16384),patch.object(guest.os,'getuid',return_value=23001):value=guest.failure_diagnostic(error,root,'a'*32,'test16k',raw,home,guest.snapshot(home))
        self.assertLessEqual(len(value.encode()),65536)
        run.failed_driver_diagnostic(b'DONE16K_DIAGNOSTIC '+value.encode(),'a'*32,'test16k',manifest)

    def test_private_proc_fields_exclude_other_uid_and_contents(self):
        proc=self.root/'proc';proc.mkdir()
        for pid,uid in [(99,23001),(100,0)]:
            path=proc/str(pid);path.mkdir();(path/'status').write_text(f'Name:\tfixture\nState:\tZ (zombie)\nPid:\t{pid}\nPPid:\t1\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nSecret:\tnever\n')
        value=guest.proc_snapshot(99,proc);self.assertEqual([r['pid'] for r in value['processes']],[99]);self.assertNotIn('Secret',value['processes'][0]['fields']);self.assertTrue(value['leader_observed'])

    def test_failed_child_exit_group_absence_and_teardown_observations_retained(self):
        pipes=[]
        for raw in (b'',b'original child failure'):
            read,write=os.pipe();os.write(write,raw);os.close(write);pipes.append(os.fdopen(read,'rb'))
        events=[];process=SimpleNamespace(pid=23456,stdout=pipes[0],stderr=pipes[1],wait=lambda timeout:events.append('wait') or 1)
        def signal(pid,sig):
            events.append(sig)
            if sig==0:raise ProcessLookupError()
        with patch.object(guest.subprocess,'Popen',return_value=process),patch.object(guest.os,'waitid',return_value=object()),patch.object(guest.os,'killpg',side_effect=signal),patch.object(guest,'proc_snapshot',side_effect=[dict(phase='before'),dict(phase='after')]):
            with self.assertRaises(guest.CommandFailure) as caught:guest.command(['inert'],{})
        error=caught.exception;self.assertEqual(error.stderr,b'original child failure');self.assertEqual(error.row['exit'],1);self.assertTrue(error.row['natural_exit']);self.assertTrue(error.row['group_absent'])
        self.assertEqual(error.row['proc_before_teardown'],dict(phase='before'));self.assertEqual(events,[guest.signal.SIGTERM,guest.signal.SIGKILL,'wait',0])


if __name__=='__main__':unittest.main()
