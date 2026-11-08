#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New AVC DATA controls. Actor/network/syscall entrypoints denied before imports."""
import sys

def deny(event,args):
    if event.startswith(('socket.','subprocess.','ctypes.','pty.'))or event in('os.system','os.fork','os.forkpty','os.exec','os.posix_spawn'):
        raise RuntimeError('actor forbidden: '+event)
sys.addaudithook(deny)
import argparse
import ast
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_owner_data as controls

WINDOW=[1794130000000000,1794130001000000]


def event(window=WINDOW,**changes):
    value=dict(__REALTIME_TIMESTAMP=str((window[0]+window[1])//2),_BOOT_ID='a'*32,
               __CURSOR='private-cursor-not-published',__MONOTONIC_TIMESTAMP='1234',
               MESSAGE='audit: type=1400 audit(1794130000.500:42): apparmor="DENIED" operation="capable" profile="unprivileged_userns" pid=777 comm="bwrap" capability=12 capname="net_admin" private_note="NEW_PRIVATE_KERNEL_SENTINEL"')
    value.update(changes);return value


class KernelAuditV4Data(unittest.TestCase):
    def setUp(self):
        self.work=tempfile.TemporaryDirectory(prefix='kernel-avc-v4-new-DATA-');self.addCleanup(self.work.cleanup)
        self.f=controls.ports.Fixture(Path(self.work.name)/'owner')

    def run_owner(self,f,mode='match'):
        original=f.respond
        def respond(argv):
            if argv[0]!='/usr/bin/journalctl':return original(argv)
            def us(arg):
                v=next(s.split('=@',1)[1]for s in argv if s.startswith(arg+'=@'));a,b=v.split('.');return int(a)*1000000+int(b)
            window=[us('--since'),us('--until')]
            self.assertEqual(argv,f.module.kernel_audit_argv_v4(window))
            if mode=='permission':return b'No journal files were opened due to insufficient permissions.\n',1
            return controls.ports.encoded(event(window)),0
        with patch.object(f,'respond',respond):
            f.diagnostic=f.module.owner_matrix_kernel_audit_v4(f.actor,f.root,f.args,f.own,f.context,f.dockerfile,f.ledger,f.verify_base,f.source_proof)
        f.owner=controls.ports.load(f.work/'public/namespace-policy/owner.json')
        f.result=controls.ports.load(f.work/'public/namespace-policy/result.json')
        return controls.ports.load(f.work/'public/namespace-policy/kernel-audit-v4.json')

    def test_fixed_readonly_command_windows_and_actual_owner_route(self):
        with self.f.ports():
            m=self.f.module;argv=m.kernel_audit_argv_v4(WINDOW)
            self.assertEqual(argv[0],'/usr/bin/journalctl');self.assertIn('--dmesg',argv);self.assertIn('--lines=all',argv)
            self.assertNotIn('sudo',' '.join(argv));self.assertNotIn('--follow',argv)
            import time
            capture=m.capture_kernel_audit_v4(self.f.actor,self.f.root,self.f.args,self.f.own,'baseline','a'*64,WINDOW,time.monotonic()+10,0,1)
            self.assertEqual(capture['observation']['status'],'UNKNOWN_NOT_STARTED');self.assertEqual(self.f.calls,[])
            self.assertIsNone(capture['private_raw_pin'])
            for window in([True,WINDOW[1]],[WINDOW[1],WINDOW[0]],[WINDOW[0],WINDOW[0]+60000001],['x',WINDOW[1]],WINDOW+[1]):
                with self.assertRaises(m.MatrixGuard):m.kernel_audit_argv_v4(window)
            text=(controls.ports.FACTORY/'payload/native/owner.py').read_text();tree=ast.parse(text)
            self.assertEqual(sum(isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='owner_matrix_kernel_refusals_v5'for n in ast.walk(tree)),1)

    def test_implicit_journal_fields_closed_candidates_and_private_values(self):
        with self.f.ports():
            m=self.f.module;raw=controls.ports.encoded(event())
            value=m.kernel_audit_parse_v4(raw,WINDOW,0);self.assertEqual(len(value['records']),1)
            public=value['records'][0]['fields'];self.assertEqual(public['profile'],'unprivileged_userns');self.assertEqual(public['capability'],12)
            retained=controls.ports.encoded(value);self.assertNotIn(b'NEW_PRIVATE_KERNEL_SENTINEL',retained);self.assertNotIn(b'private-cursor',retained)
            self.assertEqual(value['owned_process_binding'],'UNKNOWN_NO_HOST_PID_STARTTIME_CHAIN');self.assertEqual(value['namespace_effect'],'UNKNOWN')
            for changes in(dict(MESSAGE=event()['MESSAGE'].replace('comm="bwrap"','comm="sshd"')),
                           dict(__REALTIME_TIMESTAMP=str(WINDOW[0]-1)),dict(MESSAGE=event()['MESSAGE'].replace('unprivileged_userns','foreign-secret-profile'))):
                self.assertEqual(m.kernel_audit_parse_v4(controls.ports.encoded(event(**changes)),WINDOW,0)['records'],[])

    def test_permission_missing_malformed_and_excess_output_remain_unknown(self):
        with self.f.ports():
            m=self.f.module
            for raw,rc in((b'permission denied',1),(b'',0),(b'not JSON',0),(b'{"MESSAGE":"x","MESSAGE":"y"}',0),
                           (b'\n'.join(controls.ports.encoded(event()).strip()for _ in range(9)),0),
                           (controls.ports.encoded(event(MESSAGE=event()['MESSAGE'].replace('capability=12','capability=21'))),0)):
                value=m.kernel_audit_parse_v4(raw,WINDOW,rc);self.assertTrue(value['status'].startswith('UNKNOWN'));self.assertEqual(value['records'],[])
            with self.assertRaises(m.MatrixGuard):m.kernel_audit_parse_v4(b'x'*(2*1024**2+1),WINDOW,0)

    def test_full_owner_private_raw_filtered_projection_and_matching_reader(self):
        f=self.f
        with f.ports():
            audit=self.run_owner(f);self.assertEqual(len(audit['captures']),4)
            journal=[c for c in f.calls if c['argv'][0]=='/usr/bin/journalctl'];self.assertEqual(len(journal),4)
            for c in journal:self.assertEqual(c['stdout_limit'],2*1024**2);self.assertLessEqual(c['timeout'],10)
            for row in audit['captures']:
                raw=(f.work/row['private_raw_role']).read_bytes();self.assertEqual(f.module.pin(raw),row['private_raw_pin'])
                self.assertIn(b'NEW_PRIVATE_KERNEL_SENTINEL',raw)
            self.assertEqual(audit['summary']['candidate_records'],4);self.assertEqual(audit['summary']['namespace_effect'],'UNKNOWN')
            _,payloads=controls.project(f);self.assertIn(f.module.KERNEL_AUDIT_V4_LEAF,payloads)
            self.assertFalse(any('kernel-audit-v4-private'in n for n in payloads))
            self.assertNotIn(b'NEW_PRIVATE_KERNEL_SENTINEL',b''.join(payloads.values()))
            returned=controls.read(f,payloads);qualified=returned['kernel_audit_v4']
            self.assertFalse(qualified['independent_owned_process_proof']);self.assertFalse(qualified['raw_original_body_inverse'])
            self.assertEqual(qualified['summary'],audit['summary']);self.assertFalse(returned['acceptance'])

    def test_permission_refusal_does_not_retry_or_widen_held_policies(self):
        f=self.f
        with f.ports():
            audit=self.run_owner(f,'permission');self.assertEqual(len(audit['captures']),4)
            self.assertTrue(all(r['observation']['status']=='UNKNOWN_COMMAND_OR_PERMISSION'for r in audit['captures']))
            self.assertEqual(len([c for c in f.calls if c['argv'][0]=='/usr/bin/journalctl']),4)
            for c in f.calls:
                self.assertNotIn('sudo',c['argv']);self.assertNotIn('--privileged',c['argv']);self.assertNotIn('--cap-add',c['argv'])
            creates=[c['argv']for c in f.calls if c['argv'][2:3]==['create']]
            self.assertEqual(len(creates),4)
            self.assertEqual([r['security_opt']for r in f.result['cases']],list(f.module.POLICY))
            _,payloads=controls.project(f);returned=controls.read(f,payloads)
            self.assertEqual(returned['kernel_audit_v4']['summary']['status'],'UNKNOWN_NO_INDEPENDENT_OWNED_PROCESS_BINDING')

    def test_forged_owned_pid_or_cause_marker_rejected_even_after_owner_repin(self):
        f=self.f
        with f.ports():
            audit=self.run_owner(f)
            for change in('binding','cause','summary','raw','call_budget','byte_budget'):
                value=copy.deepcopy(audit)
                if change=='binding':value['captures'][0]['observation']['owned_process_binding']='PROVED_OWNED_PID'
                elif change=='cause':value['captures'][0]['observation']['namespace_effect']='APPARMOR_CAUSE_PROVED'
                elif change=='summary':value['summary']['candidate_records']=0
                elif change=='raw':value['captures'][0]['actor']['MESSAGE']='unfiltered kernel bytes'
                owner=copy.deepcopy(f.owner);owner['kernel_audit_v4']=value
                if change=='call_budget':owner['calls']*=4
                if change=='byte_budget':owner['calls'][0]['log_pin']['bytes']=24*1024**2
                with self.subTest(change=change),self.assertRaises(f.module.MatrixGuard):f.module.validate_kernel_audit_v4(value,owner,controls.expected(f))

    def test_capability_profile_type_and_time_forgery_recomputed(self):
        f=self.f
        with f.ports():
            audit=self.run_owner(f)
            for key,bad in(('capability',21),('pid',True),('profile','foreign-secret'),('timestamp_us',str(10**15))):
                value=copy.deepcopy(audit);value['captures'][0]['observation']['records'][0]['fields'][key]=bad
                owner=copy.deepcopy(f.owner);owner['kernel_audit_v4']=value
                with self.subTest(key=key),self.assertRaises(f.module.MatrixGuard):f.module.validate_kernel_audit_v4(value,owner,controls.expected(f))

    def test_original_actor_ownership_guard_still_refuses_audit_uncertainty(self):
        f=self.f
        with f.ports():
            original=f.supervisor.run
            def run(argv,**kw):
                value=original(argv,**kw)
                if argv[0]=='/usr/bin/journalctl':kw['lifecycle']['ownership_lost']=True
                return value
            with patch.object(f.supervisor,'run',run):audit=self.run_owner(f)
            self.assertEqual(f.diagnostic['status'],controls.UNKNOWN)
            self.assertEqual(len([c for c in f.calls if c['argv'][0]=='/usr/bin/journalctl']),1)
            self.assertEqual(audit['summary']['status'],'UNKNOWN_NO_INDEPENDENT_OWNED_PROCESS_BINDING')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--basis',required=True,type=Path)
    args,rest=parser.parse_known_args();controls.ports.configure_basis(args.basis.resolve(strict=True))
    unittest.main(argv=[sys.argv[0],*rest])
