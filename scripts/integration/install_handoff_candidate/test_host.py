#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic owned-container cleanup controls; no Docker execution credit."""
import copy
import errno
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('candidate_host',Path(__file__).with_name('host.py'))
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
CID = 'a'*64


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='handoff-cleanup-control-')
        self.addCleanup(self.temp.cleanup)
        self.identity = dict(name='cachy-asahi-handoff-test-'+'b'*32,nonce='b'*32,image='sha256:'+'c'*64,
            cidfile=Path(self.temp.name)/'container-id',argv=['TEST'],
            mounts={('/TEST/inputs','/inputs',False),('/TEST/runner','/runner',False),('/TEST/out','/out',True)})
        self.row = dict(Name='/'+self.identity['name'],Image=self.identity['image'],
            Config=dict(Labels={H.OWNER_LABEL:self.identity['nonce']},Cmd=['TEST'],Entrypoint=['/usr/bin/python3']),
            Mounts=[dict(Source=s,Destination=d,RW=w,Type='bind') for s,d,w in self.identity['mounts']])
        self.calls = []
        self.present = True

    def command(self,label,argv,**kwargs):
        self.calls.append((label,argv,kwargs))
        self.assertGreater(kwargs['deadline'],time.monotonic())
        self.assertLessEqual(kwargs['seconds'],10)
        if label == 'find-only-owned-name': return (CID+'\n').encode() if self.present else b''
        if label == 'recover-owned-container-identity': return json.dumps([self.row]).encode()
        if label == 'remove-only-owned-container': self.present=False; return (CID+'\n').encode()
        if label == 'verify-owned-container-absent': return b'' if not self.present else (CID+'\n').encode()
        self.fail('unexpected cleanup command')

    def test_expired_task_budget_does_not_prevent_independent_cleanup(self):
        expired = time.monotonic()-600
        result = H.cleanup_owned(self.command,self.identity,CID)
        self.assertTrue(result['container_removed'])
        self.assertEqual(result['cleanup_budget_seconds'],45)
        self.assertTrue(all(kwargs['deadline'] > expired for _,_,kwargs in self.calls))
        self.assertFalse(self.present)

    def test_create_client_failure_recovers_exact_labeled_mounted_container(self):
        self.identity['cidfile'].write_text(CID+'\n')
        result = H.cleanup_owned(self.command,self.identity,None)
        self.assertTrue(result['recovered_after_client_failure'])
        self.assertTrue(result['container_removed'])
        removed = next(argv for label,argv,_ in self.calls if label == 'remove-only-owned-container')
        self.assertEqual(removed,['docker','rm','-f',CID])

    def test_foreign_label_or_mount_is_never_removed(self):
        original = copy.deepcopy(self.row)
        for field in ('label','mount'):
            with self.subTest(field=field):
                self.row=copy.deepcopy(original);self.calls=[]
                if field == 'label': self.row['Config']['Labels'][H.OWNER_LABEL]='foreign'
                else: self.row['Mounts'][0]['Source']='/foreign-data'
                with self.assertRaises(AssertionError): H.cleanup_owned(self.command,self.identity,None)
                self.assertFalse(any(label == 'remove-only-owned-container' for label,_,_ in self.calls))
                self.assertTrue(self.present)

    def test_wrong_cidfile_is_never_used_for_removal(self):
        self.identity['cidfile'].write_text('d'*64+'\n')
        with self.assertRaises(AssertionError): H.cleanup_owned(self.command,self.identity,None)
        self.assertTrue(self.present)
        self.assertFalse(any(label == 'remove-only-owned-container' for label,_,_ in self.calls))

    def test_absent_owned_name_is_checked_without_removing_other_containers(self):
        self.present=False
        result=H.cleanup_owned(self.command,self.identity,None)
        self.assertTrue(result['container_removed'])
        self.assertEqual([label for label,_,_ in self.calls],['find-only-owned-name','verify-owned-container-absent'])

    def test_cleanup_receipt_disk_failure_does_not_block_removal(self):
        record = dict(commands=[])
        def unavailable(): raise OSError(errno.ENOSPC,'TEST full evidence filesystem')
        def callback(label,argv,**kwargs):
            result = self.command(label,argv,**kwargs)
            H.retain_command(record,dict(label=label),unavailable,cleanup=True)
            return result
        result = H.cleanup_owned(callback,self.identity,CID)
        self.assertTrue(result['container_removed'])
        self.assertFalse(self.present)
        self.assertEqual(len(record['cleanup_evidence_errors']),len(self.calls))
        self.assertTrue(all(row['errno'] == errno.ENOSPC for row in record['cleanup_evidence_errors']))

    def test_normal_receipt_write_failure_still_refuses_task_progress(self):
        def unavailable(): raise OSError(errno.ENOSPC,'TEST full evidence filesystem')
        with self.assertRaises(OSError): H.retain_command(dict(commands=[]),dict(label='TEST'),unavailable)


if __name__ == '__main__':
    unittest.main()
