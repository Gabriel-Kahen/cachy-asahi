# SPDX-License-Identifier: MIT
"""Finite clock/marker/process controls; no GUI, DB, service or native actor."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import patch
import doctor_lifetime as D


class Lifetime(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.nonce='a'*32
        now=time.monotonic_ns();self.service=dict(schema_version=1,purpose='EXISTING_FIXTURE_SERVICE_1200S',parent_pid=1,parent_nonce='c'*32,started_ns=now-2*10**9,deadline_ns=now+1198*10**9)
        self.binding=dict(schema_version=1,purpose='EXISTING_MANAGED_PROFILE_1080S',parent_pid=1,parent_nonce='b'*32,started_ns=now-10**9,deadline_ns=now+1079*10**9,stage='minimal',profile_nonce=self.nonce,service=self.service)
    def lease(self):
        p=self.root/'lease.json';D.publish(p,self.binding,0o444);return p
    def test_parent_deadline_cannot_renew_or_user_replace(self):
        path=self.lease();self.assertEqual(D.lease('minimal',self.nonce,path,os.getuid()),self.binding)
        with self.assertRaises(FileExistsError):D.publish(path,self.binding,0o444)
        with patch.object(D.time,'monotonic_ns',return_value=self.binding['deadline_ns']),self.assertRaisesRegex(ValueError,'expired'):D.lease('minimal',self.nonce,path,os.getuid())
        self.root.chmod(0o777)
        with self.assertRaisesRegex(ValueError,'nonreplaceable'):D.lease('minimal',self.nonce,path,os.getuid())
    def test_symlink_hardlink_and_parent_interval_refuse(self):
        path=self.lease();alias=self.root/'alias';alias.symlink_to(path)
        with self.assertRaises(OSError):D.lease('minimal',self.nonce,alias,os.getuid())
        alias.unlink();os.link(path,alias)
        with self.assertRaisesRegex(ValueError,'metadata'):D.lease('minimal',self.nonce,path,os.getuid())
        alias.unlink();path.chmod(0o600);value=dict(self.binding,deadline_ns=self.binding['deadline_ns']+1);path.write_bytes(D.encoded(value));path.chmod(0o444)
        with self.assertRaisesRegex(ValueError,'fixed parent'):D.lease('minimal',self.nonce,path,os.getuid())
    def test_fixed_release_marker_clock_and_nonce(self):
        path=self.root/'release.json'
        with patch.object(D.time,'monotonic_ns',return_value=self.binding['deadline_ns']),self.assertRaisesRegex(ValueError,'deadline'):D.wait_marker(path,self.nonce,self.binding['deadline_ns'])
        D.publish(path,dict(nonce='wrong'),0o600)
        with patch.object(D,'read',return_value=dict(nonce='wrong')),self.assertRaisesRegex(ValueError,'identity'):D.wait_marker(path,self.nonce,self.binding['deadline_ns'])
        with patch.object(D,'read',return_value=dict(nonce=self.nonce)):self.assertEqual(D.wait_marker(path,self.nonce,self.binding['deadline_ns']),dict(nonce=self.nonce))
    def worker(self,wait):
        start=dict(nonce=self.nonce,terminal_pid=99,parent=self.binding)
        D.publish(self.root/'start.json',start,0o600)
        def read(path,uid,mode):return json.loads(path.read_bytes())
        C=SimpleNamespace(publish=lambda p,v:D.publish(p,v,0o600))
        with patch.object(D,'lease',return_value=self.binding),patch.object(D,'read',side_effect=read),patch.object(D.os,'isatty',return_value=True),patch.object(D,'WRAPPER_PID',88),patch.object(D,'TERMINAL_PID',99),patch.object(D,'wait_marker',side_effect=wait):
            code=D.worker(C,None,self.root,'minimal',self.nonce,lambda *args:dict(status='COMMANDS_PASSED'))
        return code,json.loads((self.root/'lifetime.json').read_bytes())
    def test_timeout_after_initial_success_is_retained(self):
        code,row=self.worker(ValueError('Doctor parent lifetime deadline'));self.assertEqual(code,1);self.assertEqual(row['outcome'],'TIMEOUT');self.assertEqual(row['phase'],'WAIT_RELEASE');self.assertEqual(json.loads((self.root/'result.json').read_bytes())['status'],'COMMANDS_PASSED')
    def test_cancel_after_initial_success_is_retained(self):
        code,row=self.worker(D.Cancelled('owned cancellation'));self.assertEqual(code,1);self.assertEqual(row['outcome'],'CANCELLED')
    def test_actual_owned_child_wait_captures_nonzero_not_terminal_intent(self):
        for code in (0,7):
            work=self.root/str(code);work.mkdir()
            with patch.object(D,'lease',return_value=self.binding):result=D.supervise(lambda:code,work)
            row=json.loads((work/'worker-exit.json').read_bytes());self.assertEqual(row['child_returncode'],code);self.assertEqual(result,0 if code==0 else 1);self.assertEqual(row['reason'],'NATURAL_CHILD_EXIT');self.assertNotEqual(row['child_pid'],row['wrapper_pid'])
    def test_final_validation_requires_actual_child_wait_release_and_original_interval(self):
        row=dict(schema_version=1,stage='minimal',nonce=self.nonce,terminal_pid=99,worker_pid=77,wrapper_pid=88,parent=self.binding,started_ns=self.binding['started_ns']+1,finished_ns=self.binding['started_ns']+2,phase='WAIT_RELEASE',outcome='RELEASED',intended_exit=0,error_type=None,reason=None)
        actual=dict(schema_version=1,wrapper_pid=88,terminal_pid=99,child_pid=77,child_returncode=0,wait_status=0,reason='NATURAL_CHILD_EXIT',parent=self.binding,finished_ns=row['finished_ns']+1)
        value=dict(status='RECORDED',stage='minimal',nonce=self.nonce,terminal_pid=99,terminal_exit=0,receipt=row,receipt_bytes=len(D.encoded(row)),child_wait=actual)
        self.assertEqual(D.validate(value,'minimal',self.nonce,99,88)['status'],'PASS_RELEASED_NATURAL_DOCTOR_WORKER_AND_TERMINAL')
        import copy
        for field,bad in (('child_returncode',7),('wait_status',1792),('reason','PARENT_CANCELLED'),('child_pid',76)):
            changed=copy.deepcopy(value);changed['child_wait'][field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):D.validate(changed,'minimal',self.nonce,99,88)
        changed=copy.deepcopy(value);changed['receipt']['outcome']='TIMEOUT';changed['receipt_bytes']=len(D.encoded(changed['receipt']))
        with self.assertRaises(ValueError):D.validate(changed,'minimal',self.nonce,99,88)
    def test_pidfd_refusal_retires_and_reaps_exact_child(self):
        with patch.object(D,'lease',return_value=self.binding),patch.object(D.os,'pidfd_open',side_effect=OSError('fixture refusal')):
            self.assertEqual(D.supervise(lambda:time.sleep(5),self.root),1)
        row=json.loads((self.root/'worker-exit.json').read_bytes());self.assertEqual(row['reason'],'PIDFD_REFUSED');self.assertEqual(row['child_returncode'],-9)
        with self.assertRaises(ChildProcessError):os.waitpid(row['child_pid'],os.WNOHANG)
    def test_profile_owner_is_fresh_fixed_and_never_renews_original_global_service(self):
        service=self.root/'service.json';D.publish(service,self.service,0o444)
        with patch.object(D,'root_parent'),patch.object(D,'service_lease',return_value=self.service),patch.object(D.os,'getpid',return_value=1):
            path=self.root/'profile.json';owner=D.parent('minimal',self.nonce,path,service)
            self.assertEqual(owner['service'],self.service);self.assertEqual(owner['deadline_ns']-owner['started_ns'],1080*10**9)
            with self.assertRaises(FileExistsError):D.parent('minimal',self.nonce,path,service)
        for stage,nonce in (('overlay',self.nonce),('minimal','d'*32)):
            with self.subTest(stage=stage,nonce=nonce),self.assertRaises(ValueError):D.binding(self.binding,stage,nonce)
    def test_profile1080_never_extends_service1200_or_allows_setup_reset(self):
        owner=dict(self.binding,started_ns=self.service['deadline_ns']-10**9,deadline_ns=self.service['deadline_ns']+1079*10**9)
        D.binding(owner,'minimal',self.nonce);self.assertEqual(D.deadline(owner),self.service['deadline_ns'])
        path=self.root/'late.json';D.publish(path,owner,0o444)
        with patch.object(D.time,'monotonic_ns',return_value=self.service['deadline_ns']),self.assertRaisesRegex(ValueError,'expired'):
            D.lease('minimal',self.nonce,path,os.getuid())
        with patch.object(D,'root_parent'),patch.object(D.time,'monotonic_ns',return_value=self.service['started_ns']):
            service=self.root/'once.json';first=D.service(service)
            self.assertEqual(first['deadline_ns'],self.service['started_ns']+1200*10**9)
            with self.assertRaises(FileExistsError):D.service(service)
    def test_two_profiles_need_same_service_distinct_nonces_and_previous_actual_retirement(self):
        import copy
        first=dict(stage='minimal',parent=self.binding,finished_ns=self.binding['started_ns']+10)
        second_owner=dict(self.binding,stage='overlay',profile_nonce='d'*32,parent_nonce='e'*32,started_ns=first['finished_ns']+1,deadline_ns=first['finished_ns']+1+1080*10**9)
        second=dict(stage='overlay',parent=second_owner,finished_ns=second_owner['started_ns']+1)
        D.validate_profiles([first,second])
        for field,value in (('service',dict(self.service,parent_nonce='f'*32)),('parent_nonce',self.binding['parent_nonce']),('profile_nonce',self.nonce),('started_ns',first['finished_ns'])):
            bad=copy.deepcopy(second);bad['parent'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):D.validate_profiles([first,bad])
        with self.assertRaises(ValueError):D.validate_profiles([second,first])
    def test_missing_final_child_wait_is_unknown(self):
        with patch.object(D,'read',side_effect=FileNotFoundError):self.assertEqual(D.capture(self.root,'minimal',self.nonce,99,0)['status'],'UNKNOWN')

if __name__=='__main__':unittest.main(verbosity=2)
