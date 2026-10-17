#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite inert controls: no Docker daemon, package transaction, VM or hardware."""
import ast
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import adapter
import run as R
import prepare
import export
import sandbox

class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work=tempfile.TemporaryDirectory();cls.source=Path(cls.work.name)/'source';cls.source.mkdir()
        cls.repo=next(p for p in C.HERE.parents if (p/'manifests/packages.toml').is_file())
        for name in C.decode(C.read(C.HERE/'dependencies.json'))['files']:
            p=cls.source/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(cls.repo/name,p)
        for name in C.decode(C.read(C.HERE/'source-manifest.json'))['files']:
            p=cls.source/name;p.parent.mkdir(parents=True,exist_ok=True)
            if name.startswith(C.LANE+'/'):shutil.copyfile(C.HERE/name.removeprefix(C.LANE+'/'),p)
            elif name.startswith('.github/'):shutil.copyfile(C.HERE.parents[2]/name,p)
            else:raise AssertionError(name)
    @classmethod
    def tearDownClass(cls):cls.work.cleanup()

    def selection(self):return dict(nonce='a'*32,kernel=dict(release='exact16k'),kernel_profile_sha256='b'*64,source_nodes_sha256='c'*64,capabilities_sha256='d'*64)
    def events(self):
        s=self.selection();files={'result.json':dict(bytes=0,sha256='e'*64)}
        for case in ('pristine','modified'):
            for stage in ('source-before','clone','before574','precommit-refused','provider574','reinstalled574','held574','source-after'):files[case+'-'+stage+'-root.json.gz']=dict(bytes=0,sha256='e'*64)
        isolation=dict(status='PASS_OBSERVED_NATIVE_CAPS_AND_MOUNT_FENCE',mask=sandbox.MASK,no_new_privs=1,seccomp=2,raw_block_devices=[],writable_source_alias=False,mount_flags=[15,4096])
        return [dict(event='boot',page_size=16384,kernel='exact16k',architecture='aarch64',kernel_profile_sha256='b'*64),dict(event='result',status=C.PASS,page_size=16384,normal_runtime_observations=8,hardware='NOT_RUN',release='NOT_ADMITTED',source_nodes_sha256='c'*64,capabilities=dict(status='EXACT_SOURCE_MAP_PRESERVED',cases=2,stages=8,source_capabilities_sha256='d'*64),isolation=isolation,files=files,bytes=0),dict(event='exit',status=C.PASS,cleanup='PASS_OWNED_CLONES_REMOVED')]
    def uart(self,events):return b'kernel boot log\n'+b'\n'.join(('GNU_INSTALLED16K '+self.selection()['nonce']+' '+json.dumps(r)).encode() for r in events)+b'\n'

    def test_source_closure(self):C.check_source(self.source)
    def test_unbound_refuses_nonexistent_acceptances(self):
        with self.assertRaisesRegex(ValueError,'UNBOUND'):C.gate(Path('/definitely-absent'))
    def test_actual_system16k_decision_bound(self):
        policy=C.decode(C.read(C.HERE/'input-policy.json'));ref=policy['binding']['system16k'];value=C.decode(C.read(C.ref(C.HERE/'prerequisites',ref)))
        self.assertEqual(value['status'],'ROOT_ACCEPTED_GNU_PROVIDER_SYSTEM_PATHS_GENERIC16K');self.assertEqual(value['ALPM_installation'],'NOT_RUN')
    def test_native_stays_unbound(self):
        policy=C.decode(C.read(C.HERE/'input-policy.json'));self.assertIsNone(policy['binding']['native_lifecycle']);self.assertEqual(policy['status'],'UNBOUND_DO_NOT_EXECUTE')
    def test_four_edits_nineteen_bodies(self):
        text,receipt=adapter.derive(self.source);self.assertEqual(receipt['counted_edits'],4);self.assertEqual(len(receipt['unchanged_bodies']),19);self.assertEqual(receipt['changed_bodies'],['guard','validate_runtime']);ast.parse(text)
    def test_original_transactions_payload_hardlinks_and_sequencing(self):
        text,_=adapter.derive(self.source);before=C.read(self.source/C.NATIVE/'container.py').decode()
        def bodies(raw):return {n.name:ast.get_source_segment(raw,n) for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        a,b=bodies(before),bodies(text)
        for name in ('transaction','run_case','payload','unchanged','Commands','copy_probes','runtime_mounts','snapshot','main'):self.assertEqual(a[name],b[name],name)
    def test_anchor_drift_fails(self):
        path=self.source/C.NATIVE/'container.py';before=path.read_text()
        try:
            path.write_text(before.replace("results[0]['page_size']==4096","results[0]['page_size']==8192"))
            with patch.object(C,'check_source',lambda source:None):
                with self.assertRaisesRegex(ValueError,'anchor'):adapter.derive(self.source)
        finally:path.write_text(before)
    def test_valid_protocol(self):self.assertEqual(R.protocol(self.uart(self.events()),self.selection())['status'],C.PASS)
    def test_duplicate_protocol(self):
        with self.assertRaises(ValueError):R.protocol(self.uart(self.events()*2),self.selection())
    def test_foreign_nonce(self):
        with self.assertRaises(ValueError):R.protocol(self.uart(self.events()).replace(b'a'*32,b'f'*32),self.selection())
    def test_unfinished_protocol(self):
        with self.assertRaises(ValueError):R.protocol(self.uart(self.events()[:2]),self.selection())
    def test_wrong_page_size(self):
        events=self.events();events[0]['page_size']=4096
        with self.assertRaises(ValueError):R.protocol(self.uart(events),self.selection())
    def test_uninstalled_result_rejected(self):
        events=self.events();events[1]['status']='PASS_GNU_SYSTEM_PATHS_GENERIC16K_AND_ORDERED_CLEANUP'
        with self.assertRaises(ValueError):R.protocol(self.uart(events),self.selection())
    def test_missing_snapshot(self):
        events=self.events();events[1]['files'].pop('modified-clone-root.json.gz')
        with self.assertRaises(ValueError):R.protocol(self.uart(events),self.selection())
    def test_capability_drift(self):
        events=self.events();events[1]['capabilities']['source_capabilities_sha256']='0'*64
        with self.assertRaises(ValueError):R.protocol(self.uart(events),self.selection())
    def test_public_payload_name_rejected(self):
        events=self.events();events[1]['files']['source.tar']=dict(bytes=0,sha256='e'*64)
        with self.assertRaises(ValueError):R.protocol(self.uart(events),self.selection())
    def test_evidence_cap(self):
        events=self.events();events[1]['files']['result.json']['bytes']=513*1024**2;events[1]['bytes']=513*1024**2
        with self.assertRaises(ValueError):R.protocol(self.uart(events),self.selection())
    def test_qemu_private_disks_offline_tcg(self):
        args=R.qemu(Path('/kernel'),Path('/boot'),Path('/volume'));self.assertIn('none',args);self.assertIn('tcg,thread=multi',args);self.assertIn('virtio-blk-pci,drive=volume',args);self.assertTrue(any('readonly=on,file=/boot' in p for p in args));self.assertFalse(any('/dev/' in p for p in args if p.startswith('if=')))
    def test_init_has_same_device_disjoint_binds(self):
        self.assertIn('mount --bind /volume/held /held',prepare.INIT);self.assertIn('mount --bind /volume/work /work',prepare.INIT);self.assertIn('mount -o remount,bind,ro /held',prepare.INIT)
        self.assertLess(prepare.INIT.index('umount /volume'),prepare.INIT.index('exec /usr/bin/python3'));self.assertIn('umount /dev',prepare.INIT)
    def test_init_shell_syntax(self):
        result=subprocess.run(['/usr/bin/bash','-n'],input=prepare.INIT.encode(),capture_output=True,timeout=10);self.assertEqual(result.returncode,0,result.stderr)
    def test_host_preparation_refused(self):
        with self.assertRaises(ValueError):prepare.prepare()
    def test_host_export_refused(self):
        with self.assertRaises(ValueError):export.main()
    def test_archive_copy_is_full_payload(self):
        text=C.read(C.HERE/'prepare.py').decode();self.assertIn("copy_tree(Path('/held'),boot)",text);self.assertIn("copy_tree(Path('/held'),volume/'held')",text);self.assertIn("'-d',directory,image",text)
    def test_workflow_gate_and_teardown_order(self):
        raw=C.read(self.source/'.github/workflows/native-arm-glibc-gnu-provider-installed16k.yml').decode()
        self.assertLess(raw.index('Installed16K Root decisions'),raw.index('using unchanged secrets'));self.assertLess(raw.index('id: installed16k'),raw.index('unknown16K consumer absence'));self.assertLess(raw.index('unknown16K consumer absence'),raw.index('"$SLICE/job.py" cleanup'))
    def test_no_interruption_acceptance_dependency(self):
        policy=C.decode(C.read(C.HERE/'input-policy.json'));self.assertEqual(set(policy['binding']),{'native_lifecycle','system16k'})
    def filtered(self,nr,flags=0,arch=0xc00000b7):
        rows=sandbox.filter_rows();memory={0:nr,4:arch,40:flags&0xffffffff,44:flags>>32};pc=0;acc=0
        for _ in range(256):
            code,jt,jf,value=rows[pc]
            if code==0x20:acc=memory[value];pc+=1
            elif code==0x15:pc+=1+(jt if acc==value else jf)
            elif code==0x06:return value
            else:raise AssertionError(code)
        raise AssertionError('unbounded filter')
    def test_mount_filter_actual_flag_program(self):
        self.assertEqual(self.filtered(40,15),0x7fff0000);self.assertEqual(self.filtered(40,4096),0x7fff0000)
        for flags in (0,1,32,4096|32,15|32,4096|1,1<<32):self.assertEqual(self.filtered(40,flags)&0xffff0000,0x50000,flags)
    def test_mount_api_and_namespace_fences(self):
        for nr in sandbox.ENOSYS_CALLS:self.assertEqual(self.filtered(nr),0x50000|38,nr)
        for nr in sandbox.EPERM_CALLS:self.assertEqual(self.filtered(nr),0x50000|1,nr)
        self.assertEqual(self.filtered(63),0x7fff0000);self.assertEqual(self.filtered(63,arch=0xc000003e),0x80000000)
    def test_parent_caps_are_not_given_to_worker(self):
        self.assertEqual(sandbox.MASK,2149843147);self.assertFalse(sandbox.MASK&(1<<27));self.assertFalse(sandbox.MASK&(1<<22));self.assertFalse(sandbox.MASK&(1<<19))
    def test_host_sandbox_refuses(self):
        with self.assertRaises(ValueError):sandbox.apply()
    def test_writable_source_alias_receipt_refused(self):
        events=self.events();events[1]['isolation']['writable_source_alias']=True
        with self.assertRaises(ValueError):R.protocol(self.uart(events),self.selection())
    def test_real_ext4_regular_hardlink_symlink_serialization(self):
        # This is a real private file-image round trip, not native/16K acceptance.
        import os
        mkfs=shutil.which('mkfs.ext4');debugfs=shutil.which('debugfs')
        self.assertIsNotNone(mkfs);self.assertIsNotNone(debugfs)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';source.mkdir();(source/'payload').write_bytes(b'bound payload\n');os.link(source/'payload',source/'alias');(source/'literal').symlink_to('payload');image=root/'fixture.raw'
            with image.open('xb') as stream:stream.truncate(16*1024**2)
            result=subprocess.run([mkfs,'-q','-F','-b','4096','-d',str(source),str(image)],capture_output=True,timeout=30);self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run([debugfs,'-R','dump /alias '+str(root/'readback'),str(image)],capture_output=True,timeout=10);self.assertEqual(result.returncode,0,result.stderr);self.assertEqual((root/'readback').read_bytes(),b'bound payload\n')
            inode=[]
            for name in ('payload','alias'):
                result=subprocess.run([debugfs,'-R','stat /'+name,str(image)],capture_output=True,text=True,timeout=10);self.assertEqual(result.returncode,0,result.stderr);inode.append(result.stdout.split()[1])
            self.assertEqual(*inode)

if __name__=='__main__':unittest.main()
