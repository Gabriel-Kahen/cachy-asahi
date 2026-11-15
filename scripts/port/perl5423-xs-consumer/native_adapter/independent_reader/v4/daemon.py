# SPDX-License-Identifier: MIT
"""Pinned local daemon DATA predicates; never load Source classifier code."""
from pathlib import Path
import re
MIB=1024**2
def need(value,message):
 if not value:raise ValueError(message)

def native_path(value):
    need(type(value) is str and 1<len(value)<=4096 and re.fullmatch('/[A-Za-z0-9._+/-]+',value) and
         all(part not in ('','.','..') for part in value.split('/')[1:]),'one canonical bounded absolute native path')
    return Path(value)

def filesystem_data(value):
    need(type(value) is dict and set(value)=={'path','canonical','accessible','device','available_bytes','total_inodes','available_inodes'} and
         value['canonical'] is value['accessible'] is True,'complete canonical accessible filesystem observation')
    native_path(value['path'])
    need(all(type(value[k]) is int and 0<=value[k]<2**64 for k in ('device','available_bytes','total_inodes','available_inodes')) and
         value['available_bytes']>=8*1024*MIB and 120000<=value['available_inodes']<=value['total_inodes'],
         'fixed observed filesystem bytes/inode reserve required')

def daemon_data(value):
    need(value['schema']==1 and value['status']=='OBSERVED_ROOTFUL_NATIVE_LOCAL_DAEMON_PRECONDITIONS' and value['native_acceptance'] is False,'actual local daemon observation')
    info,version,host,socket,storage=(value[k] for k in ('info','version','host','socket','storage'))
    need(host['system']=='Linux' and host['machine']=='aarch64' and host['uid']==host['gid']==1001 and
         version['Server']['Os']=='linux' and version['Server']['Arch'] in ('arm64','aarch64') and info['OSType']=='linux' and
         info['Architecture'] in ('arm64','aarch64'),'actual native coordinator and daemon')
    need(socket==dict(path='/var/run/docker.sock',uid=0,socket=True,stable=True) and
         type(info['SecurityOptions']) is list and all(type(v) is str and 'rootless' not in v and 'userns' not in v for v in info['SecurityOptions']) and
         info['CgroupVersion']=='2' and all(info[k] is True for k in ('CpuCfsQuota','MemoryLimit','SwapLimit','PidsLimit')),'actual rootful local cgroup/socket profile')
    need(type(info['ID']) is str and info['ID'] and storage['path']==info['DockerRootDir'] and storage['canonical'] is storage['accessible'] is True and
         all(type(storage[k]) is int for k in ('available_bytes','total_inodes','available_inodes')) and
         120000<=storage['available_inodes']<=storage['total_inodes'] and storage['available_bytes']>=8*1024*MIB and
         type(host['MemAvailable_bytes']) is int and host['MemAvailable_bytes']>=8*1024*MIB,'actual visible fixed-pool storage/RAM admission')
    work=storage['work_filesystems'];need(type(work) is list and len(work)==4,'four actual work/cache/carrier/temp filesystem observations')
    for row in work:filesystem_data(row)
    temp=native_path(work[0]['path'])
    need([row['path'] for row in work]==[str(temp),str(temp/'perl-hosted'),str(temp/'alarm-cache'),str(temp/'pgo-hosted-retained')],
         'exact actual temp/work/cache/carrier paths; per-device observations are not additive')
