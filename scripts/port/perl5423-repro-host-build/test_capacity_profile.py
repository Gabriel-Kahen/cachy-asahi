#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Finite filesystem-capacity controls; no Docker or filesystem mutation."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('perl13_capacity_driver',HERE/'run.py')
api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
p=api.profile
USAGE='Global reserve: 536870912 (used: 0)\nMetadata,DUP: Size:20407386112, Used:16974151680 (83.18%)\n'
MEM='MemAvailable: 16777216 kB\n'


class CapacityControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name);self.device=self.path.stat().st_dev
        self.observation=dict(path=str(self.path),device=self.device,f_fsid=7,total_inodes=0,available_inodes=0)
        self.record=dict(mount={'uuid':'1383d536-02c6-42ac-a2f0-1de9b55f309c'},path=str(self.path),device=self.device,f_fsid=7,filesystem='btrfs',usage_query_path=str(self.path),metadata=p.metadata(USAGE))
    def space(self,path):return types.SimpleNamespace(f_bavail=20000,f_frsize=api.MIB,f_files=0,f_favail=0,f_fsid=7)
    def probe(self,path,device):return {**self.record,'path':str(Path(path).resolve()),'usage_query_path':str(Path(path).resolve()),'device':device}
    def test_dynamic_inode_zeros_use_measured_metadata_without_fake_counters(self):
        row=api.guard(self.path,self.path,'test',statvfs=self.space,meminfo=MEM,probe=self.probe)
        self.assertEqual(row['status'],'PASS')
        self.assertEqual(row['filesystems'][0]['inode_model'],'UNREPORTED_DYNAMIC')
        self.assertTrue(all(r['available_inodes']==r['total_inodes']==0 for r in row['requirements']))
        self.assertEqual(row['filesystems'][0]['node_budget'],102000)
        self.assertEqual(row['filesystems'][0]['metadata']['required_headroom_bytes'],1024*api.MIB)
    def test_bytes_and_memory_still_refuse_proven_dynamic_btrfs(self):
        def tight(path):return types.SimpleNamespace(f_bavail=5695,f_frsize=api.MIB,f_files=0,f_favail=0,f_fsid=7)
        row=api.guard(self.path,self.path,'test',statvfs=tight,meminfo=MEM,probe=self.probe)
        self.assertEqual(row['status'],'HOLD_CAPACITY');self.assertIn('bytes:',row['failure'])
        self.assertEqual(row['filesystems'][0]['status'],'PASS')
        row=api.guard(self.path,self.path,'test',statvfs=self.space,meminfo='MemAvailable: 1 kB\n',probe=self.probe)
        self.assertEqual(row['status'],'HOLD_CAPACITY');self.assertIn('memory',row['failure'])
    def test_fixed_zero_inode_pool_and_unknown_filesystems_refuse(self):
        for kind in ['tmpfs','ext2/ext3','xfs','unknown']:
            with self.subTest(kind=kind):
                row=api.guard(self.path,self.path,'test',statvfs=self.space,meminfo=MEM,probe=lambda path,device:{**self.probe(path,device),'filesystem':kind})
                self.assertEqual(row['status'],'HOLD_CAPACITY')
    def test_metadata_parser_refuses_missing_duplicate_malformed_mixed_and_used_reserve(self):
        for text in ['',USAGE+USAGE,USAGE.replace('20407386112','20G'),USAGE.replace('Metadata,DUP','Data+Metadata,single'),USAGE.replace('(used: 0)','(used: 1)'),USAGE.replace('16974151680','99999999999')]:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):p.metadata(text)
    def test_low_metadata_wrong_identity_and_excess_workload_refuse(self):
        for record,nodes in [({**self.record,'metadata':p.metadata(USAGE.replace('16974151680','19870515200'))},102000),({**self.record,'device':self.device+1},102000),({**self.record,'f_fsid':8},102000),({**self.record,'path':'/wrong'},102000),(self.record,102001)]:
            with self.subTest(record=record,nodes=nodes):
                with self.assertRaises(ValueError):p.inode_model(record,self.observation,nodes)
    def test_failed_query_refuses_without_silent_fallback(self):
        def fail(*args):raise ValueError('metadata query failed')
        row=api.guard(self.path,self.path,'test',statvfs=self.space,meminfo=MEM,probe=fail)
        self.assertEqual(row['status'],'HOLD_CAPACITY');self.assertIn('query failed',row['failure'])
    def test_inconsistent_inode_counters_refuse(self):
        for kind in ['tmpfs','btrfs']:
            for total,free in [(0,1),(1,2),(-1,0),(1,-1)]:
                with self.subTest(kind=kind,total=total,free=free),self.assertRaises(ValueError):
                    p.inode_model({**self.record,'filesystem':kind},{**self.observation,'total_inodes':total,'available_inodes':free},102000)
    def test_shared_device_alias_or_later_counter_changes_refuse(self):
        for bad_call in [2,4]:
            count=0
            def malformed(path):
                nonlocal count
                count+=1
                value=self.space(path)
                if count==bad_call:value.f_favail=1
                return value
            with self.subTest(bad_call=bad_call):
                row=api.guard(self.path,self.path,'test',statvfs=malformed,meminfo=MEM,probe=self.probe)
                self.assertEqual(row['status'],'HOLD_CAPACITY');self.assertIn('inode counters',row['failure'])

    def test_kernel_mount_join_refuses_cross_device_or_source(self):
        mount=dict(target='/home',source='/dev/example[/subvolume]',fstype='btrfs',**{'maj:min':'0:33'})
        raw='12 1 0:33 /subvolume /home rw - btrfs /dev/example rw\n'
        self.assertEqual(p.kernel_mount(mount,raw)['mount_device'],'0:33')
        for bad in [raw.replace('0:33','0:99'),raw.replace('/dev/example','/dev/other'),raw+raw]:
            with self.assertRaises(ValueError):p.kernel_mount(mount,bad)
    def test_shared_btrfs_pool_across_devices_refuses(self):
        # Model different subvolume st_dev values sharing one physical pool.
        other=self.path/'other';other.mkdir();real_stat=Path.stat
        def changed_stat(path,*args,**kwargs):
            value=real_stat(path,*args,**kwargs)
            if path==other:return types.SimpleNamespace(st_dev=self.device+1)
            return value
        with patch.object(Path,'stat',changed_stat):
            row=api.guard(self.path,other,'test',statvfs=self.space,meminfo=MEM,probe=self.probe)
        self.assertEqual(row['status'],'HOLD_CAPACITY');self.assertIn('shared Btrfs pool',row['failure'])

    def test_measure_binds_exact_path_mount_device_and_stable_identity(self):
        calls=[];fsid=os.statvfs(self.path).f_fsid
        mount=dict(target=str(self.path),source='/dev/test[/subvolume]',fstype='btrfs',uuid='1383d536-02c6-42ac-a2f0-1de9b55f309c',**{'maj:min':'0:33'})
        def command(argv):
            calls.append(argv)
            if argv[0]=='stat':body=b'btrfs 9123683e b173c8dfb7987037'
            elif argv[0]=='findmnt':body=json.dumps({'filesystems':[mount]}).encode()
            else:body=USAGE.encode()
            return subprocess.CompletedProcess(argv,0,body)
        with patch.object(p,'kernel_mount',return_value={}):record=p.measure(command,self.path,self.device)
        self.assertEqual(record['f_fsid'],fsid)
        self.assertEqual(calls[2],['btrfs','filesystem','usage','-b',str(self.path)])
        with self.assertRaisesRegex(ValueError,'crossed device'):p.measure(command,self.path,self.device+1)
        mount['target']='/proc'
        with self.assertRaisesRegex(ValueError,'mount/path'):p.measure(command,self.path,self.device)
    def test_measure_refuses_changed_filesystem_and_failed_command(self):
        calls=[]
        mount=dict(target=str(self.path),source='/dev/test',fstype='btrfs',uuid='1383d536-02c6-42ac-a2f0-1de9b55f309c',**{'maj:min':'0:33'})
        def command(argv):
            calls.append(argv)
            if argv[0]=='stat':body=('btrfs 9123683e '+('aa' if len(calls)==1 else 'bb')).encode()
            elif argv[0]=='findmnt':body=json.dumps({'filesystems':[mount]}).encode()
            else:body=USAGE.encode()
            return subprocess.CompletedProcess(argv,0,body)
        with patch.object(p,'kernel_mount',return_value={}),self.assertRaisesRegex(ValueError,'identity changed'):p.measure(command,self.path,self.device)
        def bad_exit(argv):return subprocess.CompletedProcess(argv,1,b'btrfs 9123683e aa')
        with self.assertRaisesRegex(ValueError,'query failed'):p.measure(bad_exit,self.path,self.device)
        def fail(argv):raise ValueError('command failed')
        with self.assertRaisesRegex(ValueError,'command failed'):p.measure(fail,self.path,self.device)


if __name__=='__main__':unittest.main(verbosity=2)
