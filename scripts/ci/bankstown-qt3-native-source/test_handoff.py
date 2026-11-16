#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Passive synthetic receipt controls; no Root grant or runtime qualification."""
import copy
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in {'os.system','os.exec','os.posix_spawn','os.fork','fcntl.flock'}:
        raise AssertionError('MODEL operational event forbidden: '+event)

sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('bankstown_handoff_test',HERE/'handoff.py')
H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)


def receipt(root):
    nonce='a'*64
    ref=lambda name:dict(path=str(root/name),**H.pin(b'MODEL-'+name.encode()))
    return dict(schema=1,kind=H.KIND,status='PASS_PRIVATE_IMAGE_DATA_ONLY',
                source=dict(root=str(root/'source'),commit='b'*40,ref='refs/heads/codex/MODEL'),
                binding=dict(source='b'*40,ref='refs/heads/codex/MODEL',run='123',job='456',attempt=1,source_lock=H.pin(b'MODEL_SOURCE_MAP')),
                nonce=nonce,delegation_pin=H.pin(b'UNISSUED_MODEL'),catalog=ref('catalog'),
                image=dict(id='sha256:'+'c'*64,inventory=dict(path=str(root/'inventory'),**H.EXPECTED477),protected349=H.PROTECTED349),
                filesystem=dict(root=str(root/'image'),image_id='sha256:'+'c'*64,archive=ref('archive')),
                executor=dict(code_pin=H.pin(b'MODEL_EXECUTOR'),engine_id='MODEL_ENGINE',docker_endpoint='unix:///MODEL/'+nonce+'/docker.sock',owner_pid=123,daemon_pid=456),
                lifetime=dict(observed_monotonic=100.0,work_deadline_monotonic=200.0),legal='HELD',key_freshness='HELD',**H.FINAL)

class HandoffControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='qt3-handoff-MODEL-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.d=receipt(self.root)
    def check(self,value=None,now=150):
        raw=H.encoded(self.d if value is None else value)
        return H.validate_image_receipt(raw,H.pin(raw)['sha256'],now_monotonic=now,verify_files=False)
    def test_schema_only_model_never_asserts_actual_files_or_acceptance(self):
        self.assertEqual(self.check(),self.d)
        self.assertEqual({k:self.check()[k] for k in H.FINAL},H.FINAL)
        raw=H.encoded(self.d)
        with self.assertRaises(ValueError):H.validate_image_receipt(raw,H.pin(raw)['sha256'],now_monotonic=150)
    def test_external_pin_and_exact_keys_and_duplicate_json(self):
        raw=H.encoded(self.d)
        with self.assertRaisesRegex(ValueError,'EXTERNAL'):H.validate_image_receipt(raw,'0'*64,verify_files=False)
        for mutate in (lambda d:d.update(extra='unbound'),lambda d:d.update(schema=True),lambda d:d.update(status='PASS_NATIVE'),lambda d:d.update(kind='OTHER')):
            d=copy.deepcopy(self.d);mutate(d)
            with self.assertRaises(ValueError):self.check(d)
        raw=raw.replace(b'"schema": 1',b'"schema": 1, "schema": 1')
        with self.assertRaisesRegex(ValueError,'DUPLICATE'):H.validate_image_receipt(raw,H.pin(raw)['sha256'],verify_files=False)
    def test_source_binding_image_and_inventory_tamper(self):
        for mutate in (lambda d:d['binding'].update(source='d'*40),lambda d:d['binding'].update(ref='refs/heads/other'),lambda d:d['binding'].update(job=None),lambda d:d['binding'].update(attempt=True),lambda d:d['filesystem'].update(image_id='sha256:'+'d'*64),lambda d:d['image']['inventory'].update(sha256='0'*64),lambda d:d['image'].update(id='mutable:latest')):
            d=copy.deepcopy(self.d);mutate(d)
            with self.assertRaises(ValueError):self.check(d)
    def test_lifetime_bounds_and_nonfinite_refuse(self):
        for now in (99,200,True,float('inf')):
            with self.assertRaises(ValueError):self.check(now=now)
        for field in ('observed_monotonic','work_deadline_monotonic'):
            d=copy.deepcopy(self.d);d['lifetime'][field]=True
            with self.assertRaises(ValueError):self.check(d)
    def test_holds_pid_and_endpoint_do_not_become_authority(self):
        for mutate in (lambda d:d.update(legal='ACCEPTED'),lambda d:d.update(key_freshness='PASS'),lambda d:d.update(Root_final_acceptance={}),lambda d:d.update(independent_component_acceptance=0),lambda d:d.update(hardware_acceptance=True),lambda d:d['executor'].update(daemon_pid=123),lambda d:d['executor'].update(docker_endpoint='unix:///run/docker.sock')):
            d=copy.deepcopy(self.d);mutate(d)
            with self.assertRaises(ValueError):self.check(d)
    def test_aliased_or_overlapping_roots_refuse(self):
        target=self.root/'source';target.mkdir();link=self.root/'alias';link.symlink_to(target)
        d=copy.deepcopy(self.d);d['source']['root']=str(link)
        with self.assertRaises(ValueError):self.check(d)
        d=copy.deepcopy(self.d);d['filesystem']['root']=str(target/'inside')
        with self.assertRaises(ValueError):self.check(d)
    def test_actual_reference_pin_deadline_and_alias_refusal(self):
        p=self.root/'body';p.write_bytes(b'MODEL_DATA');r=dict(path=str(p),**H.pin(b'MODEL_DATA'))
        self.assertEqual(H.verify_reference(r,body=True),b'MODEL_DATA')
        with self.assertRaisesRegex(ValueError,'DEADLINE'):H.verify_reference(r,deadline=0)
        p.write_bytes(b'OTHER_DATA')
        with self.assertRaises(ValueError):H.verify_reference(r)
        p.write_bytes(b'MODEL_DATA');link=self.root/'link';link.symlink_to(p)
        with self.assertRaises(ValueError):H.verify_reference(dict(r,path=str(link)))
        hard=self.root/'hard';os.link(p,hard)
        with self.assertRaises(ValueError):H.verify_reference(r)
    def test_reference_byte_cap_and_special_file_refuse(self):
        p=self.root/'body';p.write_bytes(b'MODEL');r=dict(path=str(p),**H.pin(b'MODEL'))
        with self.assertRaises(ValueError):H.verify_reference(r,cap=4)
        fifo=self.root/'fifo';os.mkfifo(fifo)
        with self.assertRaises(ValueError):H.verify_reference(dict(r,path=str(fifo)))

if __name__=='__main__':unittest.main()
