# SPDX-License-Identifier: MIT
"""Synthetic passive consumer controls; no evidence Reader or native actor."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('passive_consumer',Path(__file__).with_name('consumer.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)


def need(value,why):
    if not value:raise ValueError(why)


def mountinfo():
    rows=[]
    for i,(path,flags,kind,options) in enumerate((('/', 'ro','overlay','rw'),('/inputs','ro','ext4','rw'),('/work','rw','ext4','rw'),
        ('/sys/fs/cgroup','ro','cgroup2','rw'),('/tmp','rw,noexec,nosuid,nodev','tmpfs','rw,size=64m,uid=1001,gid=1001'),
        ('/run','rw,noexec,nosuid,nodev','tmpfs','rw,size=8192k,uid=1001,gid=1001'),('/xs-work','rw,nosuid,nodev','tmpfs','rw,size=268435456,uid=1001,gid=1001')),1):
        rows.append(f'{i} 0 0:1 / {path} {flags} - {kind} none {options}')
    return '\n'.join(rows)+'\n'


def observation():
    namespaces={key:key+':[42]' for key in ('user','mnt','net','pid')}
    argv=['/usr/bin/python3','-I','-B','/inputs/consumer/native_adapter/native.py','actor','--admission-sha256','a'*64]
    row=dict(pid=2,ppid=1,starttime=20,uid=1001,euid=1001,gid=1001,egid=1001,architecture='aarch64',page_bytes=4096,
        limits=c.LIMITS,interfaces=['lo'],hostname='perl5423-native',status={**{k:'0' for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')},'NoNewPrivs':'1','Seccomp':'2'},
        namespaces=namespaces,uid_map=[[0,0,4294967295]],gid_map=[[0,0,4294967295]],cgroup='0::/\n',mountinfo=mountinfo(),groups=[1001],
        cmdline=argv,exe='/usr/bin/python3.14',cwd='/work')
    parent=copy.deepcopy(row);parent.update(pid=1,ppid=0,starttime=10,exe='/sbin/docker-init',cmdline=['/sbin/docker-init','--']+argv)
    sandbox=dict(schema=1,authorization='ROOT_ADMITTED_FOUR_COMMAND_XS_SMOKE',exclusive_scope=True,uid=1001,gid=1001,target_arch='aarch64',workspace='/xs-work',
        workspace_identity=dict(owner_uid=1001,device=5,inode=77),cgroup_membership='0::/\n',cgroup_directory='/sys/fs/cgroup',cgroup_identity=[5,88],namespaces=dict(namespaces,cgroup='cgroup:[42]'))
    return dict(schema=1,operation_sha256='a'*64,entry=row,parent=parent,sandbox=sandbox,native_acceptance=False,XS_acceptance=False),sandbox


class Controls(unittest.TestCase):
    def test_harness_summary_has_scoped_assertions(self):
        result=c.harness(b't/roundtrip.t .. ok\nAll tests successful.\nFiles=1, Tests=21, 0 wallclock secs\nResult: PASS\n',need)
        self.assertEqual(result['assertions'],21);self.assertFalse(result['raw_TAP_present'])

    def test_harness_wrong_count_refused(self):
        with self.assertRaises(ValueError):c.harness(b'All tests successful.\nFiles=1, Tests=20,\nResult: PASS\n',need)

    def test_harness_failure_refused(self):
        with self.assertRaises(ValueError):c.harness(b'not ok 1 - x\nAll tests successful.\nFiles=1, Tests=21,\nResult: PASS\n',need)

    def test_partial_tap_not_promoted(self):
        with self.assertRaises(ValueError):c.harness(b'ok 1 - loaded fixture version\nAll tests successful.\nFiles=1, Tests=21,\nResult: PASS\n',need)

    def test_exact_runtime_model(self):
        observed,sandbox=observation();c.runtime(observed,sandbox,'a'*64,need)

    def test_each_runtime_boundary_refuses(self):
        for key,value in [('uid',0),('interfaces',['lo','eth0']),('limits',dict(c.LIMITS,**{'memory.swap.max':'1'})),('uid_map',[[0,100000,65536]]),('cgroup','0::/other\n'),('ppid',3)]:
            with self.subTest(key=key):
                observed,sandbox=observation();observed['entry'][key]=value
                with self.assertRaises(ValueError):c.runtime(observed,sandbox,'a'*64,need)

    def test_parent_capabilities_refused(self):
        observed,sandbox=observation();observed['parent']['status']['CapEff']='1'
        with self.assertRaises(ValueError):c.runtime(observed,sandbox,'a'*64,need)

    def test_writable_input_mount_refused(self):
        with self.assertRaises(ValueError):c.mounts(mountinfo().replace('/inputs ro','/inputs rw'),need)

    def test_exec_tmp_refused(self):
        with self.assertRaises(ValueError):c.mounts(mountinfo().replace('/tmp rw,noexec','/tmp rw'),need)

    def test_oversized_exec_workspace_refused(self):
        with self.assertRaises(ValueError):c.mounts(mountinfo().replace('size=268435456','size=512m'),need)

    def test_selected_runtime_domain(self):
        self.assertTrue(c.selected(c.ARCH+'/Config.pm'));self.assertTrue(c.selected(c.PURE+'/ExtUtils/MakeMaker.pm'))
        self.assertFalse(c.selected('usr/bin/pacman'));self.assertFalse(c.selected(c.ARCH+'-other/Config.pm'))


if __name__=='__main__':unittest.main()
