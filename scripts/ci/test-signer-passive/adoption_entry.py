# SPDX-License-Identifier: MIT
"""One public read-only observer; no compile/GPG/probe actor or private issuer."""
import base64
import hashlib
import json
import math
from pathlib import Path
import re

PURPOSE='SIGNER_NATIVE_PASSIVE_ADOPTION_V1'
MAX_RAW=4*1024**2
SOURCE_NAMES={'passive.py','observation_entry.py','provenance.py','retention.py','adoption_entry.py'}
ISSUER={
    'schema_version':1,'purpose':'SIGNER_NATIVE_PASSIVE_PUBLIC_ISSUER_V1',
    'repository':'Gabriel-Kahen/cachy-asahi',
    'branch':'codex/signer-native-passive-observation-20261014',
    'workflow':'.github/workflows/native-arm-runner-observation.yml',
    'job_name':'observe','runner_label':'ubuntu-24.04-arm',
    'argv':['/usr/bin/python3.12','-I','-B','-S','-'],
    'operation':'ONE_READ_ONLY_HOSTED_ARM_TOOLCHAIN_OBSERVATION',
    'gcc_directory':'CURRENT_DEFAULT_GCC','seconds':60,
    'compile_allowed':False,'GPG_allowed':False,'probe_allowed':False,
    'signing_allowed':False,'system_mutation_allowed':False}

class Refused(ValueError):pass
class Deadline(Refused):pass
class Cancelled(BaseException):pass

def need(value,code):
    if not value:raise Refused(code)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()

class DiagnosticIO:
    """Record attempted reads without changing the underlying observer or limits."""
    def __init__(self,io):
        self.io=io;self.operation=None;self.path=None
        self.completed_samples=0;self.completed_inventories=0
    @property
    def nodes(self):return self.io.nodes
    @nodes.setter
    def nodes(self,value):self.io.nodes=value
    @property
    def bytes_read(self):return self.io.bytes_read
    @bytes_read.setter
    def bytes_read(self,value):self.io.bytes_read=value
    def sample(self,path,end):
        self.operation='sample';self.path=str(path)
        result=self.io.sample(path,end);self.completed_samples+=1;return result
    def inventory(self,path,end):
        self.operation='inventory';self.path=str(path)
        result=self.io.inventory(path,end);self.completed_inventories+=1;return result
    def gcc_directories(self,end):
        self.operation='inventory';self.path='/usr/lib/gcc/aarch64-linux-gnu'
        result=self.io.gcc_directories(end);self.completed_inventories+=1;return result
    def gcc_helper_directories(self,end):
        self.operation='inventory';self.path='/usr/libexec/gcc/aarch64-linux-gnu'
        result=self.io.gcc_helper_directories(end);self.completed_inventories+=1;return result
    def charge(self,end):
        self.operation='charge';self.path=None;return self.io.charge(end)
    def snapshot(self):
        path=self.path
        if not (type(path) is str and path.startswith('/') and len(path)<=1024
                and str(Path(path))==path and '..' not in Path(path).parts
                and all(32<=ord(c)<127 for c in path)):path=None
        def bounded(value,maximum):return value if type(value) is int and 0<=value<=maximum else None
        return dict(operation=self.operation,path=path,
            completed_samples=self.completed_samples,completed_inventories=self.completed_inventories,
            nodes=bounded(self.nodes,65536),bytes_read=bounded(self.bytes_read,512*1024**2))

def reason(error):
    """Static refusal codes only; never stringify exception bodies or tracebacks."""
    code=error.args[0] if error.args else None
    if not (type(code) is str and re.fullmatch('[A-Za-z0-9_.:-]{1,160}',code)):code=None
    number=getattr(error,'errno',None)
    if not (type(number) is int and 1<=number<=4095):number=None
    return code,number

def run(passive,provenance,retention,*,entry,configuration,issuer,source_pins,
        source_packet_sha256,environment,emit,host=None,clock=None,signals=None,
        io_factory=None,retention_factory=None):
    """The rendered workflow authenticates five raw bodies before this call.

    This literal public issuer permits only observation, on the inherited trusted
    host/runtime. Actual observed versions/hashes are evidence for later Root
    selection, never permission to execute unknown toolchains. Root authenticates
    Source commit, dispatch and transport independently of these printed fields.
    """
    if host is None:
        import os
        host=os
    if clock is None:
        import time
        clock=time.monotonic
    if signals is None:
        import signal
        signals=signal
    if io_factory is None:io_factory=passive.PassiveIO
    if retention_factory is None:retention_factory=retention.Retention
    first=None;first_phase=None;cancelled=False;phase='issuer';context=None
    saved={};timer_touched=False;retained=None;store=None;io=None
    def remember(error):
        nonlocal first,first_phase,cancelled
        if first is None:first=error;first_phase=phase
        cancelled|=isinstance(error,(KeyboardInterrupt,Cancelled)) or getattr(store,'cancelled',False) is True
    def live():
        need(type(entry) in (int,float) and math.isfinite(entry) and entry>0,'original-entry')
        if clock()>=entry+60:raise Deadline('original-observation-end')
        need(not cancelled,'cancelled')
    def cancel(number,frame):
        nonlocal cancelled
        cancelled=True;raise Cancelled()
    def expired(number,frame):raise Deadline('original-observation-end')
    try:
        live();need(entry<=clock(),'original-entry')
        need(issuer==ISSUER,'literal-public-observation-issuer')
        need(configuration=={'schema_version':1,
            'purpose':'NATIVE_SIGNER_COMPILE_PASSIVE_OBSERVATION_V1',
            'gcc_directory':ISSUER['gcc_directory']},'literal-observation-configuration')
        need(type(source_pins) is dict and set(source_pins)==SOURCE_NAMES
             and digest(canonical(source_pins))==source_packet_sha256,'rendered-Source-packet')
        for row in source_pins.values():
            need(type(row) is dict and set(row)=={'bytes','mode','sha256'}
                 and type(row['bytes']) is int and 0<row['bytes']<=128*1024
                 and row['mode']==0o644 and type(row['sha256']) is str
                 and re.fullmatch('[0-9a-f]{64}',row['sha256']),'literal-Source-row')
        need(type(environment) is dict and environment.get('GITHUB_REPOSITORY')==ISSUER['repository']
             and environment.get('RUNNER_OS')=='Linux' and environment.get('RUNNER_ARCH')=='ARM64'
             and environment.get('GITHUB_EVENT_NAME')=='workflow_dispatch'
             and environment.get('GITHUB_REF')=='refs/heads/'+ISSUER['branch']
             and environment.get('GITHUB_JOB')==ISSUER['job_name']
             and environment.get('GITHUB_WORKFLOW_REF')==ISSUER['repository']+'/'+ISSUER['workflow']
                  +'@refs/heads/'+ISSUER['branch'],'literal-dispatch-scope')
        sha=environment.get('GITHUB_SHA')
        need(type(sha) is str and re.fullmatch('[0-9a-f]{40}',sha)
             and sha==environment.get('GITHUB_WORKFLOW_SHA')==environment.get('ROOT_EXPECTED_SOURCE_SHA'),
             'Root-dispatched-exact-Source-commit')
        run_id,attempt=environment.get('GITHUB_RUN_ID'),environment.get('GITHUB_RUN_ATTEMPT')
        need(type(run_id) is str and re.fullmatch('[1-9][0-9]{0,19}',run_id)
             and type(attempt) is str and re.fullmatch('[1-9][0-9]{0,9}',attempt),'run-identity')
        uid,gid=host.getuid(),host.getgid()
        need(type(uid) is int and type(gid) is int and uid==host.geteuid()>0
             and gid==host.getegid()>0 and host.uname().machine=='aarch64','inherited-native-ARM-host')
        context=dict(source_commit=sha,workflow_commit=sha,run_id=run_id,run_attempt=attempt,
                     machine='aarch64',uid=uid)
        temp=environment.get('RUNNER_TEMP')
        need(type(temp) is str and temp.startswith('/') and str(Path(temp))==temp
             and '..' not in Path(temp).parts and len(temp)<=1024,'inherited-private-runner-temp')
        directory=temp+'/signer-native-passive-'+run_id+'-'+attempt
        phase='controls';live()
        timer=signals.getitimer(signals.ITIMER_REAL)
        need(type(timer) is tuple and timer==(0.0,0.0),'existing-active-timer')
        for number,handler in ((signals.SIGINT,cancel),(signals.SIGTERM,cancel),(signals.SIGALRM,expired)):
            live();saved[number]=signals.getsignal(number);signals.signal(number,handler)
        live();timer_touched=True
        signals.setitimer(signals.ITIMER_REAL,max(.000001,entry+60-clock()),0)
        phase='retention-prepare';live()
        store=retention_factory(directory,endpoint=entry+60,owner_uid=uid,owner_gid=gid)
        phase='observation';live();io=DiagnosticIO(io_factory())
        observation=passive.observe_candidate(io,gcc_directory=configuration['gcc_directory'],
                                              context=context,endpoint=entry+60)
        live();phase='provenance'
        versions=provenance.capture(io,endpoint=entry+60,source_rows=source_pins,
            gcc_directory=observation['candidate']['gcc_directory'])
        live()
        payload=dict(schema_version=1,purpose=PURPOSE,source_pins=source_pins,
            configuration=configuration,context=context,observation=observation,provenance=versions,
            entry=entry,deadline_at=entry+60,selected=False,execution_grant_issued=False,compile_allowed=False)
        raw=canonical(payload);need(0<len(raw)<=MAX_RAW,'complete-envelope-budget')
        # The memory envelope is unaccepted until controls are restored, the
        # exact files close successfully, and the observer/job exit naturally0.
        phase='finalization'
    except BaseException as error:remember(error)
    finally:
        phase='finalization'
        if timer_touched:
            try:signals.setitimer(signals.ITIMER_REAL,0,0)
            except BaseException as error:remember(error)
        for number,handler in reversed(tuple(saved.items())):
            try:signals.signal(number,handler)
            except BaseException as error:remember(error)
        try:live()
        except BaseException as error:remember(error)
    if first is None:
        try:
            phase='retention';live()
            final=dict(schema_version=1,purpose=PURPOSE,status='OBSERVED_COMPLETE_NOT_SELECTED',
                candidate_sha256=digest(raw),context=context,entry=entry,deadline_at=entry+60,
                ended=clock(),selected=False,execution_grant_issued=False,compile_allowed=False)
            final_raw=canonical(final)
            completion=dict(schema_version=1,purpose=PURPOSE,status='RETAINED_COMPLETE_NOT_SELECTED',
                context=context,source_packet_sha256=source_packet_sha256,
                configuration_sha256=digest(canonical(configuration)),
                public_issuer_sha256=digest(canonical(issuer)),entry=entry,deadline_at=entry+60,
                observer_returncode=0,selected=False,execution_grant_issued=False,compile_allowed=False)
            retained=store.publish(raw,final_raw,completion,endpoint=entry+60)
            cancelled|=getattr(store,'cancelled',False) is True
            live()
            phase='terminal';emit('SIGNER_PASSIVE_ADOPTION_RETAINED='+canonical({
                'status':'RETAINED_COMPLETE_NOT_SELECTED','context':context,
                'files':retained,'candidate_sha256':digest(raw)}).decode(),deadline=entry+60)
            live()
        except BaseException as error:remember(error)
    if first is not None:
        first_reason,first_errno=reason(first)
        progress=dict(operation=None,path=None,completed_samples=0,completed_inventories=0,
                      nodes=None,bytes_read=None)
        if io is not None:
            try:progress=io.snapshot()
            except BaseException:pass
        def safe_digest(value):
            try:return digest(canonical(value))
            except (TypeError,ValueError,OverflowError):return None
        valid_entry=type(entry) in (int,float) and math.isfinite(entry) and entry>0
        failure=dict(schema_version=1,purpose='SIGNER_NATIVE_PASSIVE_FAILURE_V1',
            status='FAIL',candidate_valid=False,first_phase=first_phase,
            first_cause=type(first).__name__,first_reason=first_reason,first_errno=first_errno,
            cancelled=cancelled,context=context,source_packet_sha256=source_packet_sha256,
            configuration_sha256=safe_digest(configuration),
            public_issuer_sha256=safe_digest(issuer),entry=entry if valid_entry else None,
            deadline_at=entry+60 if valid_entry else None,
            progress=progress,observer_returncode=1,
            selected=False,execution_grant_issued=False,compile_allowed=False)
        # A fresh store has only its owned directory handles. A used/failed
        # store already closed once and retains its original partial files.
        if store is not None and store.used is False and store._first is None:
            try:store.publish_failure(canonical(failure),endpoint=entry+60)
            except BaseException as error:remember(error)
        cancelled|=getattr(store,'cancelled',False) is True
        failure['cancelled']=cancelled
        try:emit('SIGNER_PASSIVE_ADOPTION_FAIL='+canonical(failure).decode(),deadline=entry+60)
        except BaseException:pass
        return 1
    return 0
