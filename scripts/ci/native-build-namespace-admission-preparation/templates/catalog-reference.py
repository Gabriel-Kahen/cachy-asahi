"""Read one separately Root-issued finite body catalog; grant no runner authority.

Caller retains all per-certificate Git/body/mode/run/runner/all-jobs predicates.
The original eight reference list and its independent binding remain unchanged.
"""
import hashlib
import json
from pathlib import Path
import re

KEYS={'schema','status','issuer','independently_classified','native_permission','CI_success_claim','historical_certificate_references','certificates','facts','issued_at','job_scope','review'}
CERT_KEYS={'schema','status','issuer','independently_classified','classification','approval_scope','closed_scope','runner_literals','job_labels','workflow','reviewed_git_source','workflow_id','native_permission','CI_success_claim'}

def need(value,reason):
    if not value: raise ValueError(reason)

def certificates(reference,historical):
    need(type(reference)is dict and set(reference)=={'path','sha256'} and type(reference['sha256'])is str and re.fullmatch('[0-9a-f]{64}',reference['sha256']),'exact separately pinned Root catalog reference')
    p=Path(reference['path']);need(p.is_absolute()and p==p.resolve()and not any(x.is_symlink()for x in(p,*p.parents))and p.is_file()and p.stat().st_nlink==1,'ordinary Root catalog')
    raw=p.read_bytes();need(0<len(raw)<=65536 and hashlib.sha256(raw).hexdigest()==reference['sha256'],'bounded exact Root catalog')
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate Root catalog key');result[key]=value
        return result
    def constant(value):raise ValueError('nonfinite Root catalog number')
    c=json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)
    need(type(c)is dict and set(c)==KEYS and type(c['schema'])is int and c['schema']==1 and c['issuer']=='Root'and c['status']=='ROOT_ISSUED_EXACT_SIX_HOSTED_X86_WORKFLOW_BODY_SUCCESSOR'and c['independently_classified']is True and c['native_permission']is False and c['CI_success_claim']is False,'independently Root-issued catalog only; no worker/native/CI grant')
    need(type(historical)is list and len(historical)==8 and c['historical_certificate_references']==historical,'exact original eight Root references held')
    need(type(c['facts'])is dict and set(c['facts'])=={'bytes','sha256'}and type(c['facts']['bytes'])is int and 0<c['facts']['bytes']<=65536 and re.fullmatch('[0-9a-f]{64}',c['facts']['sha256'])and all(type(c[k])is str and c[k]for k in('issued_at','job_scope','review')),'exact Root review/data provenance fields')
    rows=c['certificates'];need(type(rows)is list and len(rows)==6,'finite separately issued six-row catalog')
    seen=set()
    for row in rows:
        need(type(row)is dict and set(row)==CERT_KEYS and type(row['schema'])is int and row['schema']==1 and row['issuer']=='Root'and row['status']=='ROOT_CLASSIFIED_EXACT_HOSTED_X86_BODY'and row['independently_classified']is True and row['classification']=='AUTOMATIC_HOSTED_X86_CI_ONLY'and row['approval_scope']=='EXACT_BYTES_EACH_ACTUAL_SOURCE_AND_JOBS_REJOINED'and row['native_permission']is False and row['CI_success_claim']is False,'existing exact Root body-certificate type required')
        w=row['workflow'];need(type(w)is dict and set(w)=={'path','bytes','sha256','mode','oid'}and w['mode']=='100644'and type(w['bytes'])is int and 0<w['bytes']<=65536 and type(w['path'])is str and w['path'].startswith('.github/workflows/')and re.fullmatch('[0-9a-f]{64}',w['sha256'])and re.fullmatch('[0-9a-f]{40}',w['oid']),'bounded exact catalog workflow row')
        key=(w['path'],w['sha256']);need(key not in seen,'duplicate catalog body refused');seen.add(key)
        need(type(row['workflow_id'])is int and row['workflow_id']>0 and row['runner_literals']==row['job_labels']==['ubuntu-24.04']and type(row['closed_scope'])is str and row['closed_scope'],'closed literal hosted x86 DATA scope')
    return rows
