#!/usr/bin/env python3
"""Inert contracts only: never create Docker, QEMU, mounts, devices, or keys."""
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent


def module(name):
    spec=importlib.util.spec_from_file_location('full_vm_'+name,HERE/(name+'.py'))
    value=importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


prepare=module('prepare')
run=module('run')
NONCE='a'*32
KERNEL='7.2.10-1-aarch64-ARCH'


class VMControls(unittest.TestCase):
    def test_host_selection_ignores_existing_module_names(self):
        paths={'common':HERE.parents[2]/'scripts/virtual/common.py',
               'prepare':HERE/'prepare.py','profile':HERE/'profile.py'}
        sentinels={name:SimpleNamespace(unrelated=True) for name in paths}
        with patch.dict(sys.modules,sentinels):
            for name,path in paths.items():
                selected=run.selected_module(name,path)
                self.assertEqual(Path(selected.__file__).resolve(),path.resolve())
                self.assertIs(sys.modules[name],sentinels[name])
    def base(self): return {'p'+str(i):'1' for i in range(574)}
    def tooling(self): return [{'name':'t'+str(i),'version':'1'} for i in range(21)]
    def events(self):
        return [dict(event='boot',scope='generic-arm-full-installer-software',page_size=4096,kernel=KERNEL,uid=0),
                dict(event='result',status='PASS_FULL_COMPOSITION_INSTALLER',phase='complete',
                     package_count=587,expected_lock_sha256=run.EXPECTED_LOCK,hooks='DISABLED',scriptlets='DISABLED',
                     hardware='NOT RUN',native_container_P0='UNCHANGED-FAILED',**dict.fromkeys(run.PASS_FLAGS,True)),
                dict(event='exit',status='PASS_FULL_COMPOSITION_INSTALLER',cleanup='PASS')]
    def wire(self,events,nonce=NONCE):
        return b''.join(('FULL_INSTALLER '+nonce+' '+json.dumps(e)+'\n').encode() for e in events)
    def test_union_preserves_all_builder_packages(self):
        actual=prepare.union_inventory(self.base(),self.tooling())
        self.assertEqual(len(actual),595)
        self.assertEqual({k:actual[k] for k in self.base()},self.base())
    def test_overlap_same_version_does_not_duplicate(self):
        rows=self.tooling(); rows[0]={'name':'p0','version':'1'}
        self.assertEqual(len(prepare.union_inventory(self.base(),rows)),594)
    def test_version_replacement_is_refused(self):
        rows=self.tooling(); rows[0]={'name':'p0','version':'2'}
        with self.assertRaisesRegex(ValueError,'replacement'): prepare.union_inventory(self.base(),rows)
    def test_missing_builder_package_is_refused(self):
        base=self.base(); base.pop('p0')
        with self.assertRaises(ValueError): prepare.union_inventory(base,self.tooling())
    def test_duplicate_tooling_package_is_refused(self):
        rows=self.tooling(); rows[-1]=rows[0]
        with self.assertRaises(ValueError): prepare.union_inventory(self.base(),rows)
    def test_positive_protocol(self):
        events=run.parse_protocol(b'kernel boot log\n'+self.wire(self.events()),NONCE,True)
        self.assertEqual(run.validate_completion(events,NONCE,SimpleNamespace(KERNEL=KERNEL)),self.events()[1])
    def test_partial_live_line_waits(self):
        data=self.wire(self.events())[:-2]
        self.assertEqual(len(run.parse_protocol(data,NONCE)),2)
        with self.assertRaisesRegex(ValueError,'truncated'): run.parse_protocol(data,NONCE,True)
    def test_wrong_nonce_refused(self):
        with self.assertRaises(ValueError): run.parse_protocol(self.wire(self.events(),'b'*32),NONCE)
    def test_duplicate_result_refused(self):
        events=self.events(); events.insert(2,events[1])
        with self.assertRaises(ValueError): run.parse_protocol(self.wire(events),NONCE)
    def test_out_of_order_result_refused(self):
        with self.assertRaises(ValueError): run.parse_protocol(self.wire(self.events()[1:]),NONCE)
    def test_unknown_protocol_event_refused(self):
        with self.assertRaises(ValueError): run.parse_protocol(self.wire([{'event':'shell'}]),NONCE)
    def test_duplicate_json_key_refused(self):
        with self.assertRaises(ValueError): run.parse_protocol(
            ('FULL_INSTALLER '+NONCE+' {"event":"boot","event":"result"}\n').encode(),NONCE)
    def test_missing_exit_cannot_pass(self):
        with self.assertRaises(ValueError): run.validate_completion(self.events()[:2],NONCE,SimpleNamespace(KERNEL=KERNEL))
    def test_failed_guest_cannot_pass(self):
        events=self.events(); events[1]['status']='FAIL'
        with self.assertRaises(ValueError): run.validate_completion(events,NONCE,SimpleNamespace(KERNEL=KERNEL))
    def test_failed_guest_cleanup_cannot_pass(self):
        events=self.events(); events[2]['cleanup']='FAIL'
        with self.assertRaises(ValueError): run.validate_completion(events,NONCE,SimpleNamespace(KERNEL=KERNEL))
    def test_status_only_cannot_pass(self):
        events=self.events(); events[1]={'event':'result','status':'PASS_FULL_COMPOSITION_INSTALLER'}
        with self.assertRaises(ValueError): run.validate_completion(events,NONCE,SimpleNamespace(KERNEL=KERNEL))
    def test_each_missing_evidence_flag_refused(self):
        for key in run.PASS_FLAGS:
            with self.subTest(flag=key):
                events=self.events(); events[1].pop(key)
                with self.assertRaises(ValueError): run.validate_completion(events,NONCE,SimpleNamespace(KERNEL=KERNEL))
    def test_integer_cannot_substitute_boolean_evidence(self):
        events=self.events(); events[1]['committed']=1
        with self.assertRaises(ValueError): run.validate_completion(events,NONCE,SimpleNamespace(KERNEL=KERNEL))
    def test_result_profile_binding_refused(self):
        with self.assertRaises(ValueError): run.validate_completion(self.events(),NONCE,SimpleNamespace(KERNEL=KERNEL),'b'*64)
    def test_result_profile_binding_accepted(self):
        events=self.events(); events[1].update(profile_sha256='b'*64,nonce=NONCE)
        self.assertEqual(run.validate_completion(events,NONCE,SimpleNamespace(KERNEL=KERNEL),'b'*64),events[1])
    def test_16k_boot_cannot_claim_4k_route(self):
        events=self.events(); events[0]['page_size']=16384
        with self.assertRaises(ValueError): run.validate_completion(events,NONCE,SimpleNamespace(KERNEL=KERNEL))
    def test_kernel_mismatch_refused(self):
        events=self.events(); events[0]['kernel']='other'
        with self.assertRaises(ValueError): run.validate_completion(events,NONCE,SimpleNamespace(KERNEL=KERNEL))
    def test_event_bound_refused(self):
        with self.assertRaises(ValueError): run.parse_protocol(
            ('FULL_INSTALLER '+NONCE+' ').encode()+b'x'*(run.MAX_EVENT+1)+b'\n',NONCE)
    def test_qemu_runs_snapshot_tcg_without_host_devices(self):
        argv=run.qemu_argv(Path('/prepared/Image'),Path('/prepared/guest.raw'))
        self.assertIn('tcg,thread=multi',argv); self.assertIn('virt-11.1',argv)
        self.assertTrue(any('snapshot=on' in x for x in argv))
        self.assertFalse(any('/dev/' in x for i,x in enumerate(argv) if i==0 or argv[i-1]!='-append'))
        self.assertNotIn('kvm',argv)
    def test_preparation_capabilities_are_only_metadata(self):
        c={'nonce':NONCE}
        args=run.container_args(c,'disk','sha256:'+'0'*64,[],Path('/tmp/out'),'owned')
        self.assertEqual({x for x in args if x.startswith('--cap-add=')},
            {'--cap-add=CHOWN','--cap-add=DAC_OVERRIDE','--cap-add=FOWNER','--cap-add=FSETID'})
        self.assertIn('--read-only',args); self.assertIn('--network=none',args)
        self.assertFalse(any('SYS_ADMIN' in x or 'proc=' in x or 'unconfined' in x for x in args))
    def test_vm_container_has_zero_caps(self):
        args=run.container_args({'nonce':NONCE},'vm','sha256:'+'0'*64,[],Path('/tmp/out'),'owned')
        self.assertIn('--cap-drop=ALL',args); self.assertIn('--user=23001:23001',args)
        self.assertFalse(any(x.startswith('--cap-add=') for x in args))
    def test_guest_disk_is_finite_and_no_mount_builder(self):
        self.assertEqual(prepare.DISK_BYTES,20*1024**3)
        self.assertIn('systemd-udev-trigger.service',prepare.UNIT)
        self.assertIn('/usr/local/share/full-installer/guest.py boot',prepare.UNIT)


if __name__=='__main__': unittest.main()
