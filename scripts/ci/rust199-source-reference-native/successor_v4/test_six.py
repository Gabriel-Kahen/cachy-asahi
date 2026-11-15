# SPDX-License-Identifier: MIT
"""Fenced six-input/once controls; no network, custody or operational role."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('FENCED_six',HERE/'operator/dispatch_six.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
SOURCE='a'*40;REF='codex/FENCED';MAP='b'*64;REVIEW='c'*64

def fixture():
    grant=dict(schema=4,status='ROOT_ADMITTED_RUST199_SOURCE_RESOURCE_ONCE',once=True,retry=False,holds_preserved=True,source=dict(sha=SOURCE,ref='refs/heads/'+REF,map_sha256=MAP,approval=REVIEW,run=None,job=None))
    raw=p.canonical(grant);digest=hashlib.sha256(raw).hexdigest()
    values=dict(source_sha=SOURCE,source_map_sha256=MAP,approval_sha256=REVIEW,root_admission_sha256=digest,root_admission_json=raw.decode(),operation='rust199-source-reference-native-v1')
    return grant,values,dict(source=SOURCE,ref=REF,map_sha256=MAP,review_sha256=REVIEW,admission_sha256=digest)

class Runtime:
    def __init__(self,mode='success'):self.calls=[];self.sweeps=0;self.mode=mode;self.discovery=0
    def validate_grant(self,*args):self.calls.append('grant')
    def held(self):return dict(same_FD=True,original_owner_pidfd_alive=True,real_independent_NB_conflict=True,release='CLOSE_ONLY')
    def source_readback(self,*args):self.calls.append('readback')
    def main_cas(self,before):self.calls.append('main');return 'FENCED-main'
    def empty_sweeps(self):
        self.sweeps+=1;return dict(passes=2,statuses=list(p.STATUS),complete_paginated=True,empty=True,metadata_GETs=10)
    def check_gate(self,proof):self.calls.append('fresh-gate')
    def sleep(self,n):self.calls.append(('sleep',n))
    def run(self,argv,**kw):
        self.calls.append(argv)
        if 'POST'in argv:
            if self.mode=='post-error':raise ValueError('FENCED uncertain POST')
            return b''
        self.discovery+=1
        rows=[]
        if self.discovery>1 and self.mode!='incomplete':
            row=dict(id=123,head_sha=SOURCE,head_branch=REF,event='workflow_dispatch',run_attempt=1,workflow_id=p.WORKFLOW,path=p.WORKFLOW_PATH)
            rows=[row,row]if self.mode=='ambiguous'else[row]
        return json.dumps(dict(workflow_runs=rows,total_count=len(rows))).encode()

class SixControls(unittest.TestCase):
    def test_exact_six_and_independent_hashes(self):
        g,v,pub=fixture();self.assertEqual(p.validate_inputs(v,SOURCE,REF,MAP,REVIEW,pub['admission_sha256']),g)
        for key in v:
            bad=copy.deepcopy(v);bad.pop(key)
            with self.assertRaises(ValueError):p.validate_inputs(bad,SOURCE,REF,MAP,REVIEW,pub['admission_sha256'])
        with self.assertRaises(ValueError):p.validate_inputs(v,SOURCE,REF,MAP,'d'*64,pub['admission_sha256'])
    def test_only_json_has_16k_allowance(self):
        _,v,pub=fixture()
        for key in set(v)-{'root_admission_json'}:
            bad=dict(v);bad[key]='x'*201
            with self.assertRaises(ValueError):p.validate_inputs(bad,SOURCE,REF,MAP,REVIEW,pub['admission_sha256'])
        for raw in ('x'*16385,'{"x":1,"x":2}', '{"x":1.0}'):
            bad=dict(v,root_admission_json=raw)
            with self.assertRaises(ValueError):p.validate_inputs(bad,SOURCE,REF,MAP,REVIEW,pub['admission_sha256'])
    def test_future_ids_null_and_raw_canonical(self):
        g,v,pub=fixture()
        for field in ('run','job'):
            bad=copy.deepcopy(g);bad['source'][field]='123';raw=p.canonical(bad);digest=hashlib.sha256(raw).hexdigest();inputs=dict(v,root_admission_json=raw.decode(),root_admission_sha256=digest)
            with self.assertRaises(ValueError):p.validate_inputs(inputs,SOURCE,REF,MAP,REVIEW,digest)
        bad=dict(v,root_admission_json=json.dumps(g));bad['root_admission_sha256']=hashlib.sha256(bad['root_admission_json'].encode()).hexdigest()
        with self.assertRaises(ValueError):p.validate_inputs(bad,SOURCE,REF,MAP,REVIEW,bad['root_admission_sha256'])
    def run_case(self,mode):
        _,v,pub=fixture();r=Runtime(mode)
        with tempfile.TemporaryDirectory(prefix='FENCED-six-')as directory:
            root=Path(directory);original=root/'original9d.data';original.write_bytes(b'FENCED original, never executable')
            old=p.ORIGINAL9D;p.ORIGINAL9D=hashlib.sha256(original.read_bytes()).hexdigest()
            try:
                if mode=='success':self.assertEqual(p.dispatch_once(pub,v,root/'out',r,original)['id'],123)
                else:
                    with self.assertRaises(ValueError):p.dispatch_once(pub,v,root/'out',r,original)
                    self.assertEqual(json.loads((root/'out/HOLD.json').read_bytes()),dict(status='HOLD',POSTs=1,retry=False))
            finally:p.ORIGINAL9D=old
        self.assertEqual(r.sweeps,1);self.assertEqual(sum(type(c)is list and 'POST'in c for c in r.calls),1)
        return r
    def test_once_post_and_exactly_one_two_sweep_gate(self):self.run_case('success')
    def test_ambiguity_incomplete_and_uncertain_post_hold(self):
        for mode in ('ambiguous','incomplete','post-error'):
            r=self.run_case(mode)
            self.assertLessEqual(r.discovery,13)
    def test_original9d_and_missing_custody_refuse(self):
        _,v,pub=fixture()
        with tempfile.TemporaryDirectory(prefix='FENCED-original-')as directory:
            root=Path(directory);old=root/'original';old.write_bytes(b'FENCED drift')
            with self.assertRaises(ValueError):p.dispatch_once(pub,v,root/'out',Runtime(),old)
            with self.assertRaises(ValueError):p.dispatch_once(pub,v,root/'out',None,old)
            self.assertFalse((root/'out').exists())
    def test_receipts_sync_before_post_and_sync_failure_never_posts(self):
        _,v,pub=fixture()
        with tempfile.TemporaryDirectory(prefix='FENCED-sync-')as directory:
            root=Path(directory);original=root/'original';original.write_bytes(b'FENCED original data');runtime=Runtime()
            old=p.ORIGINAL9D;p.ORIGINAL9D=hashlib.sha256(original.read_bytes()).hexdigest()
            try:
                with patch.object(p.os,'fsync',side_effect=OSError('FENCED sync failure')):
                    with self.assertRaises(OSError):p.dispatch_once(pub,v,root/'out',runtime,original)
                self.assertEqual(sum(type(c)is list and 'POST'in c for c in runtime.calls),0)
            finally:p.ORIGINAL9D=old

if __name__=='__main__':unittest.main()
