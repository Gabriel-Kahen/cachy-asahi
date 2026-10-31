# SPDX-License-Identifier: MIT
"""No clients/VMs: exact first-frame and real-manager contract regressions."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import capture
import contract
import session
from test_slice import managed_events, row


def events():
    phases=[]
    for stage in ('minimal','overlay'):
        phases.extend([dict(event='frame_ready',stage=stage,bar=row(pid=1)|dict(monitor='Virtual-1',level='2'),
            mako=row('notifications',2)|dict(monitor='Virtual-1',level='3',x=684,y=40,w=330,h=100),
            notification=dict(id=7,app_name=session.APP,summary=session.SUMMARY,body=session.BODY),
            waybar_pid=1,mako_pid=2,capture_after_ms=5000),
            dict(event='phase_pass',stage=stage,waybar='PASS',mako='PASS',config_preserved=True)])
    phases.append(dict(event='session_pass',status='PASS',waybar='PASS',mako='PASS'))
    return managed_events(phases)


class Completion(unittest.TestCase):
    def test_full_managed_normal_contract_remains_visual_pending(self):
        self.assertEqual(contract.verify_result(events())['status'],'PASS')
        self.assertTrue(all(e['visual_review']=='NOT_RUN' for e in events() if e['event']=='frame_captured'))

    def test_no_private_bus_reload_or_metadata_only_acceptance(self):
        for mutation in ('private','reload','owner','missing','late','digest','visual','expiry','order','activation-environment'):
            data=events();request=next(e for e in data if e['event']=='frame_ready');observed=next(e for e in data if e['event']=='frame_captured')
            if mutation=='private':request['managed_identity']['address']='unix:path=/tmp/private'
            elif mutation=='reload':request['activation']='reload-assisted'
            elif mutation=='owner':request['compositor_pid']=request['mako_pid']
            elif mutation=='missing':data.remove(observed)
            elif mutation=='late':observed['capture_ms']=5001
            elif mutation=='digest':observed['request_sha256']='0'*64
            elif mutation=='visual':observed['visual_review']='PASS'
            elif mutation=='expiry':request['notification_timeout_ms']=5000
            elif mutation=='activation-environment':request['activation_environment']['systemd_verified']=False
            else:data.remove(observed);data.append(observed)
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):contract.verify_result(data)

    def test_first_exact_frame_is_retained_and_joined_once(self):
        with tempfile.TemporaryDirectory() as root:
            fixture=Path(root)/'fixture';frames=Path(root)/'frames';fixture.mkdir();frames.mkdir()
            event=next(e for e in events() if e['event']=='frame_ready');report=dict(frames={},events=[event]);calls=[]
            content=b'original unmodified QMP bytes'
            def execute(method,args):
                calls.append((method,args));(fixture/'minimal.ppm').write_bytes(content)
            qmp=SimpleNamespace(execute=execute);decode=lambda _:dict(width=1024,height=768,sha256=hashlib.sha256(content).hexdigest())
            with patch.object(capture.time,'monotonic',side_effect=[0,.1]):
                capture.capture_frame(event,qmp,fixture,frames,report,decode)
            self.assertEqual((frames/'minimal.ppm').read_bytes(),content)
            observer=report['frames']['minimal']['observer']
            self.assertEqual(observer,report['events'][-1]);self.assertEqual(observer['request_sha256'],capture.request_digest(event))
            self.assertEqual(observer['capture_ms'],100);self.assertEqual(len(calls),1)
            with self.assertRaises(ValueError):capture.capture_frame(event,qmp,fixture,frames,report,decode)
            self.assertEqual(len(calls),1)

    def test_late_capture_fails_and_does_not_replace_first_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            fixture=Path(root)/'fixture';frames=Path(root)/'frames';fixture.mkdir();frames.mkdir()
            event=next(e for e in events() if e['event']=='frame_ready');report=dict(frames={},events=[])
            def execute(*_):(fixture/'minimal.ppm').write_bytes(b'first')
            with patch.object(capture.time,'monotonic',side_effect=[0,5.001]),self.assertRaises(ValueError):
                capture.capture_frame(event,SimpleNamespace(execute=execute),fixture,frames,report,lambda _:dict(sha256='a'*64))
            self.assertEqual((frames/'minimal.ppm').read_bytes(),b'first');self.assertEqual(report['frames'],{})

    def test_stale_alias_or_preexisting_frame_is_refused_before_qmp(self):
        with tempfile.TemporaryDirectory() as root:
            fixture=Path(root)/'fixture';frames=Path(root)/'frames';fixture.mkdir();frames.mkdir()
            (fixture/'minimal.ppm').symlink_to(fixture/'missing')
            with self.assertRaises(ValueError):capture.capture_frame(next(e for e in events() if e['event']=='frame_ready'),
                SimpleNamespace(execute=lambda *_:self.fail('QMP called')),fixture,frames,dict(frames={}),None)

    def test_decoder_failure_retains_first_bytes_without_retry_or_success(self):
        with tempfile.TemporaryDirectory() as root:
            fixture=Path(root)/'fixture';frames=Path(root)/'frames';fixture.mkdir();frames.mkdir()
            def execute(*_):(fixture/'minimal.ppm').write_bytes(b'first invalid frame')
            def reject(_):raise ValueError('invalid original frame')
            report=dict(frames={},events=[])
            with self.assertRaisesRegex(ValueError,'invalid original'):
                capture.capture_frame(next(e for e in events() if e['event']=='frame_ready'),
                    SimpleNamespace(execute=execute),fixture,frames,report,reject)
            self.assertEqual((frames/'minimal.ppm').read_bytes(),b'first invalid frame')
            self.assertEqual(report,dict(frames={},events=[]))

    def test_no_product_or_budget_change_and_borrowed_managed_api_is_exact(self):
        here=Path(__file__).resolve().parent;source=here.parents[2]
        for name in ('managed_session.py','managed_contract.py'):
            self.assertEqual((here/name).read_bytes(),(source/'scripts/ci/desktop-user-session'/name).read_bytes())
        body=(here/'session.py').read_text();self.assertNotIn('--outer-margin',body);self.assertNotIn('reload',body.replace('normal-shipped-config-no-reload','normal'))
        self.assertIn('while time.monotonic() - start < 5:',body);self.assertIn('after = time.monotonic() + 8',body)
        self.assertIn("'0', '0', '0'",body)


if __name__=='__main__':unittest.main()
