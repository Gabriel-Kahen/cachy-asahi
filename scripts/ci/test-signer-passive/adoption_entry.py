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
    'workflow':'.github/workflows/test-signer-native-passive-observation.yml',
    'job_name':'observe','runner_label':'ubuntu-24.04-arm',
    'argv':['/usr/bin/python3.12','-I','-B','-S','-'],
    'operation':'ONE_READ_ONLY_HOSTED_ARM_TOOLCHAIN_OBSERVATION',
    'gcc_directory':'/usr/lib/gcc/aarch64-linux-gnu/13','seconds':60,
    'compile_allowed':False,'GPG_allowed':False,'probe_allowed':False,
    'signing_allowed':False,'system_mutation_allowed':False}

class Refused(ValueError):pass
class Deadline(Refused):pass
class Cancelled(BaseException):pass

def need(value,code):
    if not value:raise Refused(code)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()

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
    saved={};timer_touched=False;retained=None;store=None
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
        phase='observation';live();io=io_factory()
        observation=passive.observe_candidate(io,gcc_directory=configuration['gcc_directory'],
                                              context=context,endpoint=entry+60)
        live();phase='provenance'
        versions=provenance.capture(io,endpoint=entry+60,source_rows=source_pins)
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
            store=retention_factory(directory,endpoint=entry+60,owner_uid=uid,owner_gid=gid)
            retained=store.publish(raw,final_raw,completion,endpoint=entry+60)
            cancelled|=getattr(store,'cancelled',False) is True
            live()
            phase='terminal';emit('SIGNER_PASSIVE_ADOPTION_RETAINED='+canonical({
                'status':'RETAINED_COMPLETE_NOT_SELECTED','context':context,
                'files':retained,'candidate_sha256':digest(raw)}).decode(),deadline=entry+60)
            live()
        except BaseException as error:remember(error)
    if first is not None:
        phase_code=first_phase
        failure=dict(schema_version=1,status='FAIL',candidate_valid=False,
            first_phase=phase_code,first_cause=type(first).__name__,cancelled=cancelled,
            selected=False,execution_grant_issued=False,compile_allowed=False)
        try:emit('SIGNER_PASSIVE_ADOPTION_FAIL='+canonical(failure).decode(),deadline=entry+60)
        except BaseException:pass
        return 1
    return 0
