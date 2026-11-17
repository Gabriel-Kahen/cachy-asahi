# SPDX-License-Identifier: MIT
"""Stopped/empty failed owner retirement, independently of payload success."""
import os
from pathlib import Path
import re
import select
import stat

DECLARATION=dict(kind='LLHTTP_OWNED_FAILED_OWNER_RETIREMENT_V3',owner_only=True,original_pidfd_identity=True,
                 original_pid_start_cgroup=True,censuses=2,empty_events_and_procs=True,
                 failed_before_stop=True,accepted_result='exit-code',accepted_exec_code='1',
                 failed_exit_min=1,failed_exit_max=255,payload_success=False,reset_unit=False)

def need(ok,why):
    if not ok:raise ValueError(why)

def pidfd_identity(fd):
    need(type(fd)is int and fd>=0 and os.readlink('/proc/self/fd/'+str(fd))=='anon_inode:[pidfd]','same original PIDFD type')
    info=os.fstat(fd);return dict(dev=info.st_dev,inode=info.st_ino)

def pidfd_exited(fd,identity):
    need(pidfd_identity(fd)==identity,'original PIDFD identity retained')
    poll=select.poll();poll.register(fd,select.POLLIN);rows=poll.poll(0)
    return bool(rows)and all(number==fd and mask&select.POLLIN and not mask&(select.POLLERR|select.POLLNVAL)for number,mask in rows)

def bounded(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb')as stream:raw=stream.read(65537)
    need(len(raw)<=65536,'bounded kernel cgroup census');return raw

def empty_snapshot(path):
    path=Path(path)
    try:before=path.lstat()
    except FileNotFoundError:return dict(path_present=False,events_empty=True,procs_empty=True)
    need(stat.S_ISDIR(before.st_mode),'ordinary original cgroup directory')
    events=bounded(path/'cgroup.events');procs=bounded(path/'cgroup.procs')
    after=path.lstat();need((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino),'same cgroup directory through census')
    pairs=[line.split()for line in events.splitlines()];need(all(len(row)==2 for row in pairs)and len({row[0]for row in pairs})==len(pairs),'complete unique kernel cgroup event fields')
    rows=dict(pairs);empty=rows.get(b'populated')==b'0'and not procs.strip()
    need(empty,'original cgroup events and process census empty')
    return dict(path_present=True,events_empty=True,procs_empty=True)

def failed_state(row,description):
    return row.get('LoadState')=='loaded'and row.get('Description')==description and row.get('ActiveState')=='failed'and row.get('SubState')=='failed'and row.get('MainPID')=='0'and row.get('ControlGroup')==''and row.get('Result')=='exit-code'and row.get('ExecMainCode')=='1'and re.fullmatch('[1-9][0-9]{0,2}',row.get('ExecMainStatus',''))is not None and 1<=int(row['ExecMainStatus'])<=255

def retire_failed(kind,nonce,owned,before,after,fd,censuses):
    need(kind=='owner'and re.fullmatch('[0-9a-f]{32}',nonce or ''),'failed-owner-only finite retirement')
    unit='cachy-llhttp-minimal-builder-'+nonce+'-owner.service';group='/system.slice/'+unit;description='cachy-llhttp-minimal-builder-owned-'+nonce+'-owner'
    need(owned.get('submitted')is True and type(owned.get('pid'))is int and owned['pid']>0 and type(owned.get('starttime'))is int and owned['starttime']>0 and owned.get('cgroup')==group,'actual original PID/start/cgroup custody required')
    need(type(fd)is int and owned.get('original_pidfd')==fd and type(owned.get('original_pidfd_identity'))is dict,'exact original PIDFD ledger required')
    need(failed_state(before,description)and failed_state(after,description)and before['ExecMainStatus']==after['ExecMainStatus'],'same already-failed owned unit before/after stop')
    need(pidfd_exited(fd,owned['original_pidfd_identity']),'original PIDFD naturally exited')
    need(type(censuses)is list and len(censuses)==2 and all(row.get('cgroup')==group and row.get('events_empty')is True and row.get('procs_empty')is True and row.get('pidfd_exited')is True for row in censuses),'two original empty cgroup and exited PIDFD censuses')
    return dict(unit=unit,empty_twice=True,pidfd_exited=True,original_identity_verified=True,state='failed',result='exit-code',
                retirement='STOPPED_EMPTY_FAILED_OWNER',payload_exit=int(after['ExecMainStatus']),payload_success=False,unit_reset=False)
