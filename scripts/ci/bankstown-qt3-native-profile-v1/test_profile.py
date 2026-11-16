#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""MODEL orchestration only; maintained consumers are tested separately."""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.exec', 'os.fork', 'os.posix_spawn'):
        raise AssertionError('MODEL_CONTROLS_FORBID_ACTORS')


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('bankstown_profile_seam_models', HERE / 'profile.py')
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
P = B.P


class Seam(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='MODEL-bankstown-profile-seam-')
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.source = self.root/'MODEL-source'; self.source.mkdir()
        self.fs = self.root/'MODEL-filesystem'; self.fs.mkdir()
        self.catalog = self.source/'catalog.MODEL.json'
        self.inventory = self.source/'inventory.MODEL.lock'
        base = B.I.inventory(B.PROTECTED.read_bytes(), 349)
        added = {'model-added-%03d'%i:'0.0-MODEL' for i in range(126)} | {'qt6-base':'6.12.0-3', 'rust':'1:1.99.0-1'}
        selected = dict(list(sorted(base.items()))[:205], **added)
        self.catalog.write_bytes(P.encoded({'MODEL_ONLY': True, 'packages': {
            n: {'metadata': {'/.PKGINFO': {'pkgname':[n], 'pkgver':[v]}}} for n,v in selected.items()}}))
        self.inventory.write_bytes(''.join(n+' '+v+'\n' for n,v in sorted(dict(base,**added).items())).encode())
        self.archive = self.root/'archive.MODEL.bytes'; self.archive.write_bytes(b'MODEL_NOT_A_REAL_IMAGE_ARCHIVE')
        now = time.monotonic()
        source = dict(root=str(self.source), commit='1'*40, ref='refs/heads/MODEL-unissued')
        self.image = dict(schema=1, kind='BANKSTOWN_QT3_IMAGE_DATA_V1', status='PASS_PRIVATE_IMAGE_DATA_ONLY',
            source=source, binding=dict(source=source['commit'], ref=source['ref'], run='1', job='1', attempt=1, source_lock=P.pin(b'MODEL_SOURCE')),
            nonce='2'*64, delegation_pin=P.pin(b'UNISSUED_MODEL_DELEGATION'), catalog=P.ref(self.catalog),
            image=dict(id='sha256:'+'3'*64, inventory=P.ref(self.inventory), protected349=P.pin(B.PROTECTED.read_bytes())),
            filesystem=dict(root=str(self.fs), image_id='sha256:'+'3'*64, archive=P.ref(self.archive)),
            executor=dict(code_pin=P.pin(b'MODEL_EXECUTOR'), engine_id='MODEL_ENGINE', docker_endpoint='unix:///MODEL/'+ '2'*64 +'/not-a-socket', owner_pid=1, daemon_pid=2),
            lifetime=dict(observed_monotonic=now, work_deadline_monotonic=now+60), **B.FINAL)
        self.receipt = self.root/'receipt.MODEL.json'
        self.admission = self.root/'admission.MODEL.json'; self.admission.write_bytes(b'EXPLICITLY_UNISSUED_MODEL_ADMISSION')
        self.trial = dict(source={k:source[k] for k in ('commit','ref')}, image=dict(id=self.image['image']['id'],inventory=P.pin(self.inventory.read_bytes())),
            catalog=P.pin(self.catalog.read_bytes()), owned_executor={k:self.image['executor'][k] for k in ('code_pin','engine_id','docker_endpoint')},
            expires_at=time.time()+60, materials={'catalog.MODEL.json':P.pin(self.catalog.read_bytes()), 'inventory.MODEL.lock':P.pin(self.inventory.read_bytes())})
        self.projected = {'MODEL_ONLY': 'NOT_NATIVE_EVIDENCE', 'Root_acceptance': None}
        self.consumer = SimpleNamespace(A=SimpleNamespace(validate_trial=lambda *a, **k:self.trial, encoded=P.encoded),
            export_profile=lambda **kw: (P.write(kw['output'],P.encoded(self.projected)), self.projected)[1], _prepare=lambda *args:self.projected)
        self.executor = SimpleNamespace(live=lambda:None, deadline=self.image['lifetime']['work_deadline_monotonic'], facts=dict(
            api='CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3', binding=self.image['binding'], nonce=self.image['nonce'], stage='qt3',
            owner_domain={'pid':1},daemon_domain={'pid':2},daemon_pidfd_held=True,whole_owner_deadline_enforced=True,
            daemon_deadline_enforced=True,exclusive_daemon=True,**self.image['executor']))
        self.profile=self.root/'profile.MODEL.json'; self.result=self.root/'profile-receipt.MODEL.json'
        self.patch=patch.object(P,'consumers',return_value=self.consumer);self.patch.start();self.addCleanup(self.patch.stop)
        # C fixes the genuine477 whole pin. Only this orchestration MODEL changes it.
        model_pin=patch.object(B.R,'EXPECTED477',P.pin(self.inventory.read_bytes()))
        model_pin.start();self.addCleanup(model_pin.stop)
        self.write_receipt()

    def write_receipt(self):
        self.receipt.write_bytes(P.encoded(self.image))
        self.inputs=dict(image_receipt_path=self.receipt,image_receipt_sha256=P.pin(self.receipt.read_bytes())['sha256'],
            admission_path=self.admission,admission_sha256=P.pin(self.admission.read_bytes())['sha256'],
            catalog_path=self.catalog,source_root=self.source,executor=self.executor)

    def export(self):
        return B.export(profile_path=self.profile,output_receipt_path=self.result,**self.inputs)

    def verify(self, **changes):
        args=dict(profile_path=self.profile,profile_sha256=P.pin(self.profile.read_bytes())['sha256'],
            output_receipt_path=self.result,output_receipt_sha256=P.pin(self.result.read_bytes())['sha256'],**self.inputs)
        args.update(changes);return B.verify(**args)

    def test_model_seam_exports_fresh_private_profile_bound_to_receipt_and_live_executor(self):
        row=self.export()
        self.assertEqual(row,self.verify());self.assertEqual(row['image_receipt'],P.pin(self.receipt.read_bytes()))
        self.assertEqual(row['executor'],self.image['executor']);self.assertEqual(row['lifetime'],self.image['lifetime'])
        self.assertEqual(row['profile'],P.ref(self.profile));self.assertIsNone(row['Root_final_acceptance'])
        self.assertEqual(row['inventory_joins']['inventory_count'],477)
        self.assertFalse(row['hardware_acceptance']);self.assertEqual(self.result.stat().st_mode&0o777,0o600)
        with self.assertRaises(ValueError):self.export()

    def test_external_receipt_profile_and_result_whole_sha_are_required(self):
        self.inputs['image_receipt_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'RECEIPT_PIN'):self.export()
        self.write_receipt();self.export()
        for change in ({'profile_sha256':'0'*64},{'output_receipt_sha256':'0'*64}):
            with self.subTest(change=change),self.assertRaises(ValueError):self.verify(**change)

    def test_trial_source_image_catalog_and_executor_cannot_be_rebound(self):
        for field in ('source','image','catalog','owned_executor'):
            old=copy.deepcopy(self.trial[field]);self.trial[field]={}
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'JOIN'):B.prepare(**self.inputs)
            self.trial[field]=old

    def test_missing_or_changed_inventory_archive_and_admitted_material_refuse(self):
        self.archive.write_bytes(b'CHANGED')
        with self.assertRaises(ValueError):B.prepare(**self.inputs)
        self.archive.write_bytes(b'MODEL_NOT_A_REAL_IMAGE_ARCHIVE')
        self.inventory.write_bytes(self.inventory.read_bytes().replace(b'6.12.0-3',b'6.12.0-2'))
        with self.assertRaises(ValueError):B.prepare(**self.inputs)
        self.inventory.write_bytes(self.inventory.read_bytes().replace(b'6.12.0-2',b'6.12.0-3'))
        self.trial['materials']['also-inventory.MODEL.lock']=self.trial['image']['inventory']
        with self.assertRaisesRegex(ValueError,'ADMITTED'):B.prepare(**self.inputs)

    def test_executor_identity_nonce_deadline_and_dead_service_refuse(self):
        for field in ('engine_id','binding','nonce','daemon_pidfd_held','exclusive_daemon'):
            old=self.executor.facts[field];self.executor.facts[field]=None
            with self.subTest(field=field),self.assertRaises(ValueError):B.prepare(**self.inputs)
            self.executor.facts[field]=old
        old=self.executor.deadline;self.executor.deadline=old+1
        with self.assertRaises(ValueError):B.prepare(**self.inputs)
        self.executor.deadline=old
        self.executor.live=lambda: (_ for _ in ()).throw(ValueError('MODEL_DEAD_EXECUTOR'))
        with self.assertRaisesRegex(ValueError,'DEAD_EXECUTOR'):B.prepare(**self.inputs)

    def test_lifetime_cannot_be_replayed_or_nonfinite(self):
        for lifetime in (dict(observed_monotonic=1,work_deadline_monotonic=2),
                         dict(observed_monotonic=float('nan'),work_deadline_monotonic=2),
                         dict(observed_monotonic=1,work_deadline_monotonic=float('inf'))):
            image=copy.deepcopy(self.image);image['lifetime']=lifetime
            with self.subTest(lifetime=lifetime),self.assertRaises(ValueError):B.R.validate(image,P,now=time.monotonic())

    def test_null_actual_selectors_and_acceptance_escalation_refuse(self):
        for mutate in (lambda d:d['image'].update(id=None),lambda d:d['executor'].update(engine_id=None),
                       lambda d:d.update(Root_final_acceptance=True),lambda d:d.update(hardware_acceptance=True),
                       lambda d:d['filesystem'].update(image_id='sha256:'+'9'*64),lambda d:d.update(extra='MODEL')):
            image=copy.deepcopy(self.image);mutate(image)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):B.R.validate(image,P,now=time.monotonic())

    def test_profile_bytes_cannot_change_after_export(self):
        self.export();self.profile.write_bytes(P.encoded({'MODEL_TAMPER':True}))
        with self.assertRaisesRegex(ValueError,'PROJECTION'):self.verify()

    def test_profile_output_cannot_be_swapped_before_receipt_is_bound(self):
        self.consumer.export_profile=lambda **kw:(P.write(kw['output'],b'MODEL_SWAPPED_OUTPUT'),self.projected)[1]
        with self.assertRaises(ValueError):self.export()
        self.assertFalse(self.result.exists())

    def test_expiry_or_archive_change_after_projection_has_no_pass_receipt(self):
        state=B.prepare(**self.inputs);state['deadline']=1
        P.write(self.profile,P.encoded(self.projected))
        with self.assertRaisesRegex(ValueError,'DEADLINE'):B.finish(state,self.profile,P.encoded(self.projected))
        state=B.prepare(**self.inputs);self.archive.write_bytes(b'CHANGED_AFTER_INSPECTION')
        with self.assertRaisesRegex(ValueError,'ARCHIVE_CHANGED'):B.finish(state,self.profile,P.encoded(self.projected))
        self.assertFalse(self.result.exists())


if __name__=='__main__':unittest.main()
