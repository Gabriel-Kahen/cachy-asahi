"""Reuse exact CI gate; additional x86 bodies require explicit Root certificates."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
BASE=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/release-native-resume-20261108/ci/ci_gate.py')
SHA='abe6eeb56b046b04ab8be89cef0ce8f7ab03ac2f0f9ec63e952b543db34a7733'


def need(value,reason):
    if not value:raise ValueError(reason)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def oid(kind,raw):return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
need(pin(BASE.read_bytes())['sha256']==SHA,'held complete CI gate')
spec=importlib.util.spec_from_file_location('_held_release_nov8_ci',BASE)
held=importlib.util.module_from_spec(spec);spec.loader.exec_module(held)
qualify=held.qualify


def reference(row):
    need(type(row)is dict and set(row)=={'path','sha256'},'exact externally pinned Root certificate reference')
    path=Path(row['path']);need(path.is_absolute() and path==path.resolve()
        and not any(p.is_symlink()for p in(path,*path.parents)) and path.is_file() and path.stat().st_nlink==1,'ordinary Root certificate')
    raw=path.read_bytes();need(len(raw)<=65536 and pin(raw)['sha256']==row['sha256'],'bounded exact Root certificate')
    return json.loads(raw)


def validate_current_certificate(c):
    expected=set(json.loads((HERE/'x86-body-certificate.template.json').read_bytes()))
    need(type(c)is dict and set(c)==expected and type(c['schema'])is int and c['schema']==1
         and c['issuer']=='Root'and c['status']=='ROOT_CLASSIFIED_EXACT_HOSTED_X86_WORKFLOW_BODY'
         and c['independently_classified']is True and c['classification']=='AUTOMATIC_HOSTED_X86_CI_ONLY'
         and c['approval_scope']=='EXACT_BYTES_EACH_ACTUAL_SOURCE_AND_JOBS_REJOINED'
         and c['native_permission']is False and c['CI_success_claim']is False,'exact existing Root current certificate schema/status/authority')
    need(c['runner_literals']==c['job_labels']==['ubuntu-24.04']and type(c['closed_scope'])is str and c['closed_scope'],'closed current hosted x86 scope')
    w=c['workflow'];need(type(w)is dict and set(w)=={'path','bytes','sha256','mode','oid'}
         and w['path']in('.github/workflows/static.yml','.github/workflows/client-v3-native-source.yml','.github/workflows/platform-namespace-vm-probe-v1-data.yml')and w['mode']=='100644'
         and type(w['bytes'])is int and 0<w['bytes']<=262144
         and type(w['sha256'])is str and re.fullmatch('[0-9a-f]{64}',w['sha256'])
         and type(w['oid'])is str and re.fullmatch('[0-9a-f]{40}',w['oid'])
         and type(c['workflow_id'])is int and c['workflow_id']==({'.github/workflows/static.yml':381664315,'.github/workflows/client-v3-native-source.yml':411193901,'.github/workflows/platform-namespace-vm-probe-v1-data.yml':411421315}[w['path']]),'exact current static body descriptor')
    witness=c['reviewed_git_source'];need(type(witness)is dict and set(witness)=={'source','raw_commit'}
         and type(witness['source'])is str and re.fullmatch('[0-9a-f]{40}',witness['source'])
         and type(witness['raw_commit'])is dict and set(witness['raw_commit'])=={'bytes','sha256'}
         and type(witness['raw_commit']['bytes'])is int and 0<witness['raw_commit']['bytes']<=65536
         and re.fullmatch('[0-9a-f]{64}',witness['raw_commit']['sha256']),'exact current raw Git witness descriptor')
    return c


def current_certificates(rows):
    expected=json.loads((HERE/'Root-current-x86-certificates.json').read_bytes())['certificates']
    need(type(rows)is list and 0<len(rows)<=14 and rows==expected,'exact separately pinned current Root certificate references')
    need(len({(r['path'],r['sha256'])for r in rows})==len(rows),'duplicate current Root references refused')
    return [validate_current_certificate(reference(row))for row in rows]


def certify_x86_run(get,git,run,path,raw,jobs,main,receipts):
    root,_=held.inputs()
    registry=held.obj(root/'x86-workflow-certificates.json')['certificates']
    digest=pin(raw)['sha256']
    if digest in registry:
        return held.certify_x86_run(get,git,run,path,raw,jobs,main,receipts)
    # Admission was already authenticated by the original gate. Rejoin its pin.
    bound=json.loads((Path(receipts)/'admission-bound.json').read_bytes())
    admission_path=Path(bound['path']);admission_raw=admission_path.read_bytes()
    need(pin(admission_raw)==bound['admission'],'same authenticated fresh Root admission')
    admission=json.loads(admission_raw)
    rows=admission['x86_body_certificates']
    need(type(rows)is list and len(rows)==8,'exact original eight Root-certified body references')
    expected_refs=json.loads((HERE/'Root-eight-x86-certificates.json').read_bytes())['certificates']
    need(rows==expected_refs,'original eight literal references unchanged')
    certs=[reference(row)for row in rows]
    reader=HERE/'catalog-reference.py'
    need(pin(reader.read_bytes())['sha256']=='278ddc0692681acbcd76af6d1cbe4f7cf947eb64cc852e838a233b1b06783ae4','pinned separately Root-issued catalog reader')
    spec=importlib.util.spec_from_file_location('_release_source686_catalog',reader)
    catalog=importlib.util.module_from_spec(spec);spec.loader.exec_module(catalog)
    catalog_rows=catalog.certificates(admission['x86_body_catalog'],rows)
    certs+=catalog_rows
    certs+=current_certificates(admission['current_x86_body_certificates'])
    certs+=namespace_certificates(admission['namespace_x86_body_certificates'])
    need(len({(c['workflow']['path'],c['workflow']['sha256'])for c in certs})==len(certs),'no duplicate historical/catalog/current authority rows')
    matches=[c for c in certs if c['workflow']['path']==path and c['workflow']['sha256']==digest]
    need(len(matches)==1,'HOLD unknown x86 workflow body without one independently Root-typed certificate')
    c=matches[0]
    expected=set(json.loads((HERE/'x86-body-certificate.template.json').read_bytes()))
    need(set(c)==expected and c['schema']==1 and c['issuer']=='Root'
        and c['status']==('ROOT_CLASSIFIED_EXACT_HOSTED_X86_BODY' if any(c is row for row in catalog_rows) else 'ROOT_CLASSIFIED_EXACT_HOSTED_X86_WORKFLOW_BODY')
        and c['independently_classified']is True and c['classification']=='AUTOMATIC_HOSTED_X86_CI_ONLY'
        and c['approval_scope']=='EXACT_BYTES_EACH_ACTUAL_SOURCE_AND_JOBS_REJOINED'
        and c['native_permission']is False and c['CI_success_claim']is False,
        'independent Root classification only; no worker classification or native/green grant')
    need(type(c['closed_scope'])is str and c['closed_scope']
         and c['runner_literals']in(['ubuntu-24.04'],['ubuntu-latest'])
         and c['job_labels']in(['ubuntu-24.04'],['ubuntu-latest']),
         'Root closed literal x86 scope required')
    w=c['workflow'];need(set(w)=={'path','bytes','sha256','mode','oid'} and w['mode']=='100644'
        and pin(raw)=={k:w[k]for k in('bytes','sha256')} and oid('blob',raw)==w['oid'], 'exact approved body/mode/blob')
    runners=re.findall(rb'^\s+runs-on:\s*([^\n]+)\s*$',raw,re.M)
    need(runners and all(label.strip().decode()==c['runner_literals'][0]for label in runners),'unknown/mixed/dynamic/native runner HOLD')
    witness=c['reviewed_git_source']
    need(set(witness)=={'source','raw_commit'} and re.fullmatch('[0-9a-f]{40}',witness['source']), 'literal reviewed Source witness')
    witness_raw=git('cat-file','commit',witness['source'])
    need(oid('commit',witness_raw)==witness['source']and pin(witness_raw)==witness['raw_commit'], 'Root reviewed raw Git witness')
    expected_row=w['mode'].encode()+b' blob '+w['oid'].encode()+b'\t'+path.encode()+b'\0'
    need(git('show',witness['source']+':'+path)==raw and git('ls-tree','-z',witness['source'],'--',path)==expected_row,
        'reviewed witness exact Git body/mode/blob')
    need(run['event']in('push','pull_request') and path==run['path']
        and run['workflow_id']==c['workflow_id'] and type(run['id'])is int and run['id']>0
        and type(run['run_attempt'])is int and run['run_attempt']>0
        and run['repository']['id']==run['head_repository']['id']==1414857795
        and run['repository']['full_name']==run['head_repository']['full_name']=='Gabriel-Kahen/cachy-asahi',
        'exact same-repository automatic workflow identity')
    source=run['head_sha'];need(re.fullmatch('[0-9a-f]{40}',source),'actual literal Source')
    actual_raw=git('cat-file','commit',source)
    need(oid('commit',actual_raw)==source and git('show',source+':'+path)==raw
        and git('ls-tree','-z',source,'--',path)==expected_row,'actual current Source raw/body/mode/blob rejoin')
    need(bool(jobs) and len(jobs)==len({j['id']for j in jobs}),'complete actual jobs required')
    for job in jobs:
        need(job['run_id']==run['id']and job['head_sha']==source and job['run_attempt']==run['run_attempt'],'actual run/source/attempt/job join')
        if job['status']in('queued','waiting','requested','pending'):
            need(job['labels']==c['job_labels']and job['runner_id']in(None,0),'queued exact hosted selection')
        elif job['conclusion']=='skipped':
            need(job['labels']in([],c['job_labels']),'skipped exact hosted selection')
        else:
            need(job['labels']==c['job_labels']and type(job['runner_id'])is int and job['runner_id']>0
                 and job['runner_group_id']==0 and job['runner_group_name']=='GitHub Actions'
                 and job['runner_name']=='GitHub Actions '+str(job['runner_id']),
                 'actual independent GitHub-hosted runner identity')
    result=dict(status='ROOT_TYPED_EXACT_BODY_AND_ACTUAL_GIT_JOBS_HOSTED_X86_ONLY',source=source,
        reviewed_source=witness['source'],run=run['id'],attempt=run['run_attempt'],workflow_id=run['workflow_id'],
        path=path,workflow=w,jobs=[j['id']for j in jobs],native_permission=False,CI_success_claim=False,extra_GETs=0)
    held.save(Path(receipts),'Root-typed-x86-'+str(run['id'])+'.json',result)
    return result


def namespace_certificates(rows):
    expected=json.loads((HERE/'Root-namespace-x86-certificates.json').read_bytes())['certificates']
    need(type(rows)is list and 0<len(rows)<=8 and rows==expected,'exact independently Root-issued namespace preparation extras')
    need(len({(r['path'],r['sha256'])for r in rows})==len(rows),'duplicate namespace certificate reference')
    return [validate_namespace_certificate(reference(row)) for row in rows]


def validate_namespace_certificate(c):
    expected=set(json.loads((HERE/'x86-body-certificate.template.json').read_bytes()))
    need(type(c)is dict and set(c)==expected and type(c['schema'])is int and c['schema']==1 and c['issuer']=='Root' and
         c['status']=='ROOT_CLASSIFIED_EXACT_HOSTED_X86_WORKFLOW_BODY' and c['independently_classified']is True and
         c['classification']=='AUTOMATIC_HOSTED_X86_CI_ONLY' and c['approval_scope']=='EXACT_BYTES_EACH_ACTUAL_SOURCE_AND_JOBS_REJOINED' and
         c['native_permission']is False and c['CI_success_claim']is False,'Root exact-byte extra never grants CI/native/resource permission')
    need(c['runner_literals']==c['job_labels']==['ubuntu-24.04'] and type(c['closed_scope'])is str and c['closed_scope'],'closed literal hosted x86 extra')
    w=c['workflow'];need(type(w)is dict and set(w)=={'path','bytes','sha256','mode','oid'} and
         re.fullmatch(r'\.github/workflows/[A-Za-z0-9_-]+\.yml',w['path']) and w['mode']=='100644' and
         type(w['bytes'])is int and 0<w['bytes']<=262144 and re.fullmatch('[0-9a-f]{64}',w['sha256']) and
         re.fullmatch('[0-9a-f]{40}',w['oid']) and type(c['workflow_id'])is int and c['workflow_id']>0,'exact Root extra workflow descriptor')
    witness=c['reviewed_git_source'];need(type(witness)is dict and set(witness)=={'source','raw_commit'} and re.fullmatch('[0-9a-f]{40}',witness['source']) and
         type(witness['raw_commit'])is dict and set(witness['raw_commit'])=={'bytes','sha256'} and type(witness['raw_commit']['bytes'])is int and
         0<witness['raw_commit']['bytes']<=65536 and re.fullmatch('[0-9a-f]{64}',witness['raw_commit']['sha256']),'exact Root raw Git witness')
    return c
