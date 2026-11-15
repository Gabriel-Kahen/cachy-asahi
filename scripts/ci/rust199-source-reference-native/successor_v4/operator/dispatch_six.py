# SPDX-License-Identifier: MIT
"""Distinct six-input once primitive; a future sealed Root custody operator supplies IO."""
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import urlencode

REPOSITORY='Gabriel-Kahen/cachy-asahi';WORKFLOW=381664314;WORKFLOW_PATH='.github/workflows/native-arm-build.yml'
STATUS=('in_progress','pending','queued','waiting','requested')
KEYS={'source_sha','source_map_sha256','approval_sha256','root_admission_sha256','root_admission_json','operation'}
ORIGINAL9D='9d014a2c5405f2ba5a478143545629cd5499eda2218a7306ca20cd4f24d5f94f'


def need(value,why):
    if not value:raise ValueError(why)


def canonical(value):return(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()

def decode(raw):
    need(type(raw)is bytes and len(raw)<=16384,'bounded JSON')
    def pairs(rows):
        out={}
        for key,value in rows:need(key not in out,'duplicate JSON key');out[key]=value
        return out
    def invalid(_):raise ValueError('noninteger/nonfinite JSON')
    return json.loads(raw,object_pairs_hook=pairs,parse_float=invalid,parse_constant=invalid)


def validate_inputs(values,source,ref,map_sha256,review_sha256,admission_sha256):
    need(type(values)is dict and set(values)==KEYS,'exact six-input protocol')
    need(all(type(value)is str and 0<len(value)<=200 for key,value in values.items()if key!='root_admission_json'),'five small string inputs at200')
    raw=values['root_admission_json'].encode();need(0<len(raw)<=16384,'only canonical Root JSON has16KiB allowance')
    grant=decode(raw);need(raw==canonical(grant) and hashlib.sha256(raw).hexdigest()==values['root_admission_sha256']==admission_sha256,'whole canonical admission digest')
    need(values['source_sha']==source and values['source_map_sha256']==map_sha256 and values['approval_sha256']==review_sha256 and values['operation']=='rust199-source-reference-native-v1','exact source/map/independent approval/operation')
    s=grant['source'];need(grant['schema']==4 and type(grant['schema'])is int and grant['status']=='ROOT_ADMITTED_RUST199_SOURCE_RESOURCE_ONCE' and grant['once']is True and grant['retry']is False and grant['holds_preserved']is True,'exact Root source/resource once envelope')
    need(s==dict(sha=source,ref='refs/heads/'+ref,map_sha256=map_sha256,approval=review_sha256,run=None,job=None),'future provider IDs must remain NULL at dispatch')
    need(all(re.fullmatch('[0-9a-f]{64}',v)for v in (map_sha256,review_sha256,admission_sha256)) and re.fullmatch('[0-9a-f]{40}',source) and re.fullmatch('codex/[A-Za-z0-9._/-]+',ref),'literal exact selectors')
    return grant


def custody(runtime):
    row=runtime.held()
    need(row['same_FD']is row['original_owner_pidfd_alive']is row['real_independent_NB_conflict']is True and row['release']=='CLOSE_ONLY','canonical same-FD/PIDFD/actual independent NB conflict required')
    return row


def empty_gate(runtime):
    value=runtime.empty_sweeps()
    need(value['passes']==2 and value['statuses']==list(STATUS) and value['complete_paginated']is True and value['empty']is True and value['metadata_GETs']==10,'two complete all-repository five-status EMPTY sweeps; no exemptions')
    return value


def sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)


def persist(output,name,raw):
    # Exclusive receipts and synced directory entries survive an uncertain POST.
    fd=os.open(output/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    sync_directory(output)


def dispatch_once(publication,values,output,runtime,original9d):
    """runtime owns canonical C/U/S/L/runtime54 custody, supervised commands and close-only retirement."""
    need(runtime is not None,'explicit sealed Root custody runtime required')
    need(hashlib.sha256(Path(original9d).read_bytes()).hexdigest()==ORIGINAL9D,'original9d bytes preserved')
    source,ref=publication['source'],publication['ref'];grant=validate_inputs(values,source,ref,publication['map_sha256'],publication['review_sha256'],publication['admission_sha256'])
    runtime.validate_grant(grant,publication)  # Full Source/resource/material Root reviews, not an input-only grant.
    output=Path(output);need(output.is_absolute() and '..'not in output.parts and output==output.resolve() and not output.exists() and output.parent.is_dir() and all(not p.is_symlink()for p in(output,*output.parents)),'fresh canonical ordinary Root output, no prior or uncertain attempt')
    custody(runtime);runtime.source_readback(publication);first_main=runtime.main_cas(None);gate_proof=empty_gate(runtime)
    endpoint='repos/'+REPOSITORY+'/actions/workflows/'+str(WORKFLOW)+'/runs?'+urlencode(dict(branch=ref,event='workflow_dispatch',per_page=100))
    def get():
        custody(runtime);raw=runtime.run(['gh','api',endpoint],timeout=45);data=json.loads(raw)
        need(type(data['workflow_runs'])is list and data['total_count']==len(data['workflow_runs'])<=100,'complete first-discovery page')
        return raw,data['workflow_runs']
    raw,prior=get();need(prior==[],'any prior Source/ref attempt holds; never redispatch')
    output.mkdir(mode=0o700);sync_directory(output.parent);persist(output,'before-dispatch-runs.json',raw)
    body=json.dumps(dict(ref=ref,inputs=values)).encode();intent=dict(source=source,ref=ref,workflow_id=WORKFLOW,once=True,retry=False,prior_run_ids=[],POSTs=0)
    persist(output,'intent.json',canonical(intent));custody(runtime);runtime.main_cas(first_main);runtime.check_gate(gate_proof);custody(runtime)
    # Durable intent precedes exactly one POST; every subsequent error is HOLD/no retry.
    intent['POSTs']=1;persist(output,'at-POST.json',canonical(intent))
    try:
        custody(runtime);runtime.check_gate(gate_proof)
        runtime.run(['gh','api','--method','POST','repos/'+REPOSITORY+'/actions/workflows/'+str(WORKFLOW)+'/dispatches','--input','-'],timeout=45,input=body)
        for index in range(12):
            raw,rows=get();persist(output,'discovery-%02d.json'%index,raw)
            selected=[r for r in rows if r['head_sha']==source and r['head_branch']==ref and r['event']=='workflow_dispatch']
            need(len(selected)<=1,'ambiguous first discovery; HOLD without retry')
            if selected:
                row=selected[0];need(row['run_attempt']==1 and row['workflow_id']==WORKFLOW and row['path']==WORKFLOW_PATH,'exact unique first Source/ref/workflow attempt1')
                persist(output,'actual-run.json',canonical(row));custody(runtime);return row
            runtime.sleep(5)
        raise ValueError('one POST sent, first discovery incomplete; HOLD/no retry')
    except BaseException:
        persist(output,'HOLD.json',canonical(dict(status='HOLD',POSTs=1,retry=False)));raise


if __name__=='__main__':raise SystemExit('Use the separately sealed Root once custody operator; this primitive grants no lease or authority')
