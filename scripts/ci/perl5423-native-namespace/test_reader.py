#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Actor-fenced synthetic namespace DATA controls; no real diagnostic role."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest


def deny(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.exec','os.fork','os.posix_spawn'):
        raise AssertionError('operational actor forbidden: '+event)


sys.addaudithook(deny)
spec=importlib.util.spec_from_file_location('perl_namespace_passive_reader',Path(__file__).with_name('reader.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

MOUNTS='''1 0 0:1 / / ro,relatime - overlay overlay rw
2 1 0:2 /MODELED /inputs ro,relatime - ext4 /MODELED rw
3 1 0:2 /MODELED-volume /work rw,relatime - ext4 /MODELED rw
4 1 0:4 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=65536k,uid=1001,gid=1001
5 1 0:5 / /run rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=8192k,uid=1001,gid=1001
'''


def process(pid,ppid):
    return dict(pid=pid,ppid=ppid,pgrp=pid,session=pid,starttime=100+pid,uid=1001,euid=1001,gid=1001,egid=1001,groups=[1001],architecture='aarch64',page_bytes=4096,cwd='/work/recipe',exe='/usr/bin/python3.14',cmdline=['/usr/bin/python3','-I','-B','/inputs/entry.py'],namespaces={k:k+':['+str(n)+']' for n,k in enumerate(('user','mnt','net','pid'),10)},uid_map=[[0,0,4294967295]],gid_map=[[0,0,4294967295]],status={**{key:'0000000000000000' for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')},'NoNewPrivs':'1','Seccomp':'2','Seccomp_filters':'1'},limits=dict(r.LIMITS),cgroup='0::/MODELED\n',mountinfo=MOUNTS,interfaces=['lo'],hostname='perl5423-native')


def fixture():
    a=dict(schema=1,operation=r.OPERATION,source='1'*40,run='123',job='456',image='sha256:'+'2'*64,approval='3'*64,source_map_sha256='4'*64,domain_sha256=r.DOMAIN_SHA,token='5'*24,container='perl-namespace-123-'+'5'*12,volume='perl-namespace-123-'+'5'*12+'-work',inputs='/MODELED/inputs')
    sha=r.pin(r.encode(a))['sha256']
    host=dict(binding_sha256=sha,image_inspect=dict(Id=a['image'],Architecture='arm64',Os='linux',Config={'Volumes':None}),container_inspect={'Name':'/'+a['container'],'Image':a['image'],'Config':{'User':'1001:1001','Hostname':'perl5423-native','Entrypoint':['/usr/bin/bash'],'Cmd':['--noprofile','--norc','/inputs/entry.sh'],'Env':['ADAPTER_ADMISSION_SHA256='+sha]},'HostConfig':{'NanoCpus':2000000000,'Memory':4294967296,'MemorySwap':4294967296,'PidsLimit':256,'NetworkMode':'none','ReadonlyRootfs':True,'Init':True,'CapDrop':['ALL'],'CapAdd':None,'SecurityOpt':['no-new-privileges'],'Privileged':False,'Devices':[],'DeviceRequests':None,'Tmpfs':dict(r.TMPFS)},'Mounts':[{'Destination':'/inputs','Type':'bind','RW':False,'Source':a['inputs']},{'Destination':'/work','Type':'volume','RW':True,'Name':a['volume']}]},create_argv=r.create_argv(a))
    entry=process(7,1);parent=process(1,0);parent.update(exe='/sbin/docker-init',cmdline=['/sbin/docker-init','--','/usr/bin/bash','--noprofile','--norc','/inputs/entry.sh'],cwd='/')
    report=dict(schema=1,operation=r.OPERATION,status='OBSERVED_NAMESPACE_DATA',native_acceptance=False,admission_sha256=sha,source_map_sha256=a['source_map_sha256'],domain_sha256=r.DOMAIN_SHA,host_sha256=r.pin(r.encode(host))['sha256'],token=a['token'],entry=entry,parent=parent,commands=[],failure=None)
    logs={}
    for index,case in enumerate(r.CASES,20):
        before=process(index,7);before['cmdline']=r.probe_argv(case,a,sha,'--exec-probe');after=copy.deepcopy(before)
        inner=r.probe_argv(case,a,sha,'--inner');after['cmdline']=inner[inner.index('/usr/bin/python3'):]
        after['namespaces']['user']='user:['+str(index+100)+']'
        if case==r.CASES[0]:
            after.update(pid=index+1,ppid=index,starttime=300,cwd='/tmp',uid_map=[[1001,1001,1]],gid_map=[[1001,1001,1]])
            after['namespaces'].update(mnt='mnt:[200]',net='net:[201]')
        else:after.update(uid=0,euid=0,gid=0,egid=0,uid_map=[[0,1001,1]],gid_map=[[0,1001,1]])
        base=dict(schema=1,operation=r.OPERATION,case=case,admission_sha256=sha,source_map_sha256=a['source_map_sha256'],token=a['token'])
        frames=[dict(**base,phase='exec',context=before,argv=inner,executable={'bytes':100,'sha256':'6'*64,'mode':0o755,'uid':0,'gid':0}),dict(**base,phase='inner',context=after)]
        raw=b''.join(r.FRAME+r.encode(frame) for frame in frames);name=case+'.log';logs[name]=raw
        lifecycle=dict(pid=index,exit=0,natural_exit=True,forced_cleanup=False,retirement='REAPED',group_absent=True,leader_held_until_group_inspection=True,ownership_lost=False,exit_observed_via_waitpid=True,elapsed_seconds=1.0)
        report['commands'].append(dict(case=case,argv=before['cmdline'],log=name,log_pin=r.pin(raw),returncode=0,lifecycle=lifecycle))
    return report,logs,host,a


def frames(raw):return [r.decode(line[len(r.FRAME):]) for line in raw.splitlines(keepends=True)]


def replace_frames(report,logs,index,items,tail=b''):
    row=report['commands'][index];raw=b''.join(r.FRAME+r.encode(v) for v in items)+tail
    logs[row['log']]=raw;row['log_pin']=r.pin(raw)


class PassiveNamespaceData(unittest.TestCase):
    def test_positive_is_synthetic_data_without_authority(self):
        result=r.classify(*fixture());self.assertEqual(result['status'],'PASS_NAMESPACE_EFFECTS');self.assertFalse(result['native_acceptance'])
        self.assertEqual(set(result['cases']),set(r.CASES));self.assertEqual(result['policy_cause'],'UNKNOWN')
        self.assertEqual(result['reader_sha256'],r.pin(Path(r.__file__).read_bytes())['sha256'])

    def test_null_old_source_wrong_domain_refuse(self):
        for key,value in [('source',None),('source',r.OLD_SOURCE),('domain_sha256','0'*64),('run','0'),('approval',None)]:
            report,logs,host,a=fixture();a[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):r.classify(report,logs,host,a)

    def test_readonly_network_capability_and_swap_inspection_refuse(self):
        for key,value in [('ReadonlyRootfs',False),('NetworkMode','host'),('CapAdd',['SYS_ADMIN']),('MemorySwap',-1),('Init',False)]:
            report,logs,host,a=fixture();host['container_inspect']['HostConfig'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):r.classify(report,logs,host,a)

    def test_image_volumes_and_wrong_mount_refuse(self):
        report,logs,host,a=fixture();host['image_inspect']['Config']['Volumes']={'/implicit':{}}
        with self.assertRaises(ValueError):r.classify(report,logs,host,a)
        report,logs,host,a=fixture();host['container_inspect']['Mounts'][0]['RW']=True
        with self.assertRaises(ValueError):r.classify(report,logs,host,a)

    def test_create_argv_cannot_substitute_image_or_runtime(self):
        report,logs,host,a=fixture();host['create_argv'][-4]='sha256:'+'9'*64
        with self.assertRaises(ValueError):r.classify(report,logs,host,a)

    def test_parent_and_entry_cannot_change_namespace_or_identity(self):
        for who,key,value in [('entry','ppid',2),('parent','uid',0),('parent','exe','/usr/bin/bash'),('entry','cmdline',['/bin/sh'])]:
            report,logs,host,a=fixture();report[who][key]=value
            with self.subTest(who=who,key=key),self.assertRaises(ValueError):r.classify(report,logs,host,a)
        report,logs,host,a=fixture();report['parent']['namespaces']['user']='user:[999]'
        with self.assertRaises(ValueError):r.classify(report,logs,host,a)

    def test_actual_runtime_capability_limit_and_interface_refuse(self):
        for key,value in [('status',{**process(7,1)['status'],'CapBnd':'1'}),('limits',{**r.LIMITS,'memory.swap.max':'max'}),('interfaces',['lo','eth0']),('architecture','x86_64')]:
            report,logs,host,a=fixture();report['entry'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):r.classify(report,logs,host,a)

    def test_actual_mount_permissions_sizes_and_ownership_refuse(self):
        for old,new in [(' /inputs ro,',' /inputs rw,'),('rw,size=65536k','rw,size=65537k'),('uid=1001','uid=0'),('nodev,noexec','nodev,exec')]:
            report,logs,host,a=fixture();report['entry']['mountinfo']=MOUNTS.replace(old,new)
            with self.subTest(old=old),self.assertRaises(ValueError):r.classify(report,logs,host,a)

    def test_wrapper_lineage_and_boundary_pin_refuse(self):
        for key,value in [('pid',999),('ppid',999),('pgrp',999),('session',999)]:
            report,logs,host,a=fixture();items=frames(logs[report['commands'][0]['log']]);items[0]['context'][key]=value;replace_frames(report,logs,0,items)
            with self.subTest(key=key),self.assertRaises(ValueError):r.classify(report,logs,host,a)
        report,logs,host,a=fixture();items=frames(logs[report['commands'][0]['log']]);items[0]['argv'][0]='/bin/true';replace_frames(report,logs,0,items)
        with self.assertRaises(ValueError):r.classify(report,logs,host,a)

    def test_wrong_case_binding_and_duplicate_inner_frames_refuse(self):
        for key,value in [('case',r.CASES[1]),('token','0'*24),('source_map_sha256','0'*64)]:
            report,logs,host,a=fixture();items=frames(logs[report['commands'][0]['log']]);items[1][key]=value;replace_frames(report,logs,0,items)
            with self.subTest(key=key),self.assertRaises(ValueError):r.classify(report,logs,host,a)
        report,logs,host,a=fixture();items=frames(logs[report['commands'][0]['log']]);replace_frames(report,logs,0,items+[items[1]])
        with self.assertRaises(ValueError):r.classify(report,logs,host,a)

    def test_no_effect_and_wrong_outer_mapping_never_qualify(self):
        for key,value in [('namespaces',process(20,7)['namespaces']),('uid_map',[[1001,0,1]]),('cwd','/work/recipe')]:
            report,logs,host,a=fixture();items=frames(logs[report['commands'][0]['log']]);items[1]['context'][key]=value;replace_frames(report,logs,0,items)
            with self.subTest(key=key):self.assertEqual(r.classify(report,logs,host,a)['status'],'OBSERVED_NAMESPACE_NO_QUALIFICATION')

    def test_unshare_pid_starttime_and_mapping_effects(self):
        for key,value in [('pid',999),('starttime',999),('uid_map',[[0,0,1]])]:
            report,logs,host,a=fixture();items=frames(logs[report['commands'][1]['log']]);items[1]['context'][key]=value;replace_frames(report,logs,1,items)
            with self.subTest(key=key):self.assertEqual(r.classify(report,logs,host,a)['status'],'OBSERVED_NAMESPACE_NO_QUALIFICATION')

    def test_tool_denial_preserves_unknown_cause_and_errno(self):
        report,logs,host,a=fixture();items=frames(logs[report['commands'][0]['log']]);replace_frames(report,logs,0,items[:1],b'bwrap: Creating new namespace failed: Operation not permitted\n')
        row=report['commands'][0];row['returncode']=row['lifecycle']['exit']=1
        result=r.classify(report,logs,host,a);self.assertEqual(result['status'],'OBSERVED_NAMESPACE_NO_QUALIFICATION')
        result=result['cases'][r.CASES[0]];self.assertEqual(result['outcome'],'DENIED');self.assertEqual(result['namespace_errno'],'UNKNOWN');self.assertEqual(result['policy_cause'],'UNKNOWN')

    def test_signal_exit_does_not_establish_tool_denial(self):
        report,logs,host,a=fixture();items=frames(logs[report['commands'][0]['log']]);replace_frames(report,logs,0,items[:1],b'bwrap: Creating new namespace failed: Operation not permitted\n')
        row=report['commands'][0];row['returncode']=row['lifecycle']['exit']=-9
        self.assertEqual(r.classify(report,logs,host,a)['cases'][r.CASES[0]]['outcome'],'UNKNOWN')

    def test_inner_session_escape_and_reused_identity_cannot_qualify(self):
        for key in ('pgrp','session'):
            report,logs,host,a=fixture();items=frames(logs[report['commands'][0]['log']]);items[1]['context'][key]=999;replace_frames(report,logs,0,items)
            with self.subTest(key=key),self.assertRaises(ValueError):r.classify(report,logs,host,a)
        report,logs,host,a=fixture();items=frames(logs[report['commands'][0]['log']]);items[1]['context']['starttime']=1;replace_frames(report,logs,0,items)
        self.assertEqual(r.classify(report,logs,host,a)['status'],'OBSERVED_NAMESPACE_NO_QUALIFICATION')

    def test_exec_error_is_not_namespace_denial(self):
        report,logs,host,a=fixture();items=frames(logs[report['commands'][0]['log']]);second={k:v for k,v in items[0].items() if k not in ('context','argv','executable')};second.update(phase='exec-error',errno=1)
        replace_frames(report,logs,0,items[:1]+[second]);row=report['commands'][0];row['returncode']=row['lifecycle']['exit']=126
        result=r.classify(report,logs,host,a)['cases'][r.CASES[0]];self.assertEqual(result['outcome'],'UNKNOWN');self.assertEqual(result['namespace_errno'],'UNKNOWN')

    def test_incomplete_failed_and_mixed_raw_logs_cannot_qualify(self):
        report,logs,host,a=fixture();report['status']='FAIL_NAMESPACE_DATA';report['failure']='MODELED failure'
        self.assertEqual(r.classify(report,logs,host,a)['status'],'OBSERVED_NAMESPACE_NO_QUALIFICATION')
        report,logs,host,a=fixture();report['commands'].pop();logs.pop(r.CASES[1]+'.log')
        self.assertEqual(r.classify(report,logs,host,a)['status'],'OBSERVED_NAMESPACE_NO_QUALIFICATION')
        report,logs,host,a=fixture();logs[r.CASES[0]+'.log']+=b'extra bytes'
        with self.assertRaises(ValueError):r.classify(report,logs,host,a)

    def test_forced_uncertain_or_overdue_retirement_refuse(self):
        for key,value in [('forced_cleanup',True),('ownership_lost',True),('group_absent',False),('exit_observed_via_waitpid',False),('elapsed_seconds',29.0)]:
            report,logs,host,a=fixture();report['commands'][0]['lifecycle'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):r.classify(report,logs,host,a)

    def test_bad_maps_and_strict_json_boundaries(self):
        for rows in [[[0,0,2**32]],[[0,0,4],[3,4,2]],[[0,0,2],[2,1,2]],[[x,x,1] for x in range(9)]]:
            with self.subTest(rows=rows),self.assertRaises(ValueError):r.maps(rows)
        for raw in [b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1e999}',b'['*30+b'0'+b']'*30]:
            with self.assertRaises(ValueError):r.decode(raw)


if __name__=='__main__':unittest.main(verbosity=2)
