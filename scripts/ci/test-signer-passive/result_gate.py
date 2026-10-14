# SPDX-License-Identifier: MIT
"""Pure Root transport/result gate; accepted passive data grants no execution.

Root authenticates GitHub job and Source/issuer/config expectation externally.
Payload hashes cannot authenticate an arbitrary job, callback or runtime.
"""
import base64
import hashlib
import json
import math
from pathlib import Path
import re
import stat

MAX_RAW = 4 * 1024 * 1024
SEARCH = ('/usr/lib/aarch64-linux-gnu','/usr/lib','/lib/aarch64-linux-gnu','/lib')
REUSE_SHA = '98ee7bb0c1788e465a5d8e709aef766768466d968b7fe68b888bbb9a1b8181a2'
CANDIDATE = 'SIGNER_PASSIVE_ADOPTION_CANDIDATE='
FINAL = 'SIGNER_PASSIVE_ADOPTION_FINAL='
PURPOSE = 'SIGNER_NATIVE_PASSIVE_ADOPTION_V1'

class Refused(ValueError): pass

def need(value,reason):
    if not value: raise Refused(reason)

def sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None

def canonical(value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    need(len(raw)<=MAX_RAW,'JSON-budget');return raw

def digest(raw): return hashlib.sha256(raw).hexdigest()

def strict_json(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_RAW,'JSON-budget')
    def pairs(items):
        result={}
        for name,value in items:
            need(name not in result,'duplicate-JSON-key');result[name]=value
        return result
    def constant(value):raise Refused('nonfinite-JSON')
    try:return json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_constant=constant)
    except Refused:raise
    except (UnicodeError,ValueError,TypeError,RecursionError) as error:raise Refused('malformed-JSON') from error

def path(value):
    need(type(value) is str and 0<len(value)<=1024 and value.startswith('/')
         and str(Path(value))==value and '..' not in Path(value).parts and len(Path(value).parts)<=32
         and all(32<=ord(c)<127 for c in value),'snapshot-path')
    need(value=='/' or value=='/usr' or any(value==p or value.startswith(p+'/')
         for p in ('/usr/bin','/usr/lib','/usr/libexec','/usr/include','/lib')),'snapshot-path-scope')
    return value

def identity(value,kind=None):
    need(type(value) is list and len(value)==9 and all(type(v) is int and 0<=v<2**64 for v in value),
         'snapshot-identity')
    mode=value[2]
    need(value[3]==value[4]==0 and value[5]>=1,'snapshot-owner')
    if kind=='file':need(stat.S_ISREG(mode) and value[5]==1 and stat.S_IMODE(mode) in (0o644,0o755),'snapshot-file-identity')
    elif kind=='alias':need(stat.S_ISLNK(mode) and value[5]==1 and 0<value[6]<=256,'snapshot-alias-identity')
    elif kind=='directory':need(stat.S_ISDIR(mode) and not mode&0o022,'snapshot-directory-identity')
    else:need(stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode),'snapshot-entry-identity')
    return value[2:7]

def aliases(items):
    need(type(items) is list and len(items)<=16,'snapshot-alias-count')
    result=[]
    for item in items:
        need(type(item) is dict and set(item)=={'path','target','identity'},'snapshot-alias-shape')
        target=item['target']
        need(type(target) is str and 0<len(target)<=256 and '..' not in Path(target).parts
             and all(32<=ord(c)<127 for c in target),'snapshot-alias-target')
        result.append({'path':path(item['path']),'target':target,'identity':identity(item['identity'],'alias')})
    need(len({item['path'] for item in result})==len(result),'snapshot-alias-replay')
    return result

def ancestors(items):
    need(type(items) is list and 0<len(items)<=64,'snapshot-ancestor-count')
    result=[]
    for item in items:
        need(type(item) is dict and set(item)=={'path','identity'},'snapshot-ancestor-shape')
        result.append({'path':path(item['path']),'identity':identity(item['identity'],'directory')})
    need([item['path'] for item in result]==sorted({item['path'] for item in result})
         and result[0]['path']=='/','snapshot-ancestor-coverage')
    return result

def sample_shape(item,rows):
    need(type(item) is dict and set(item)=={'canonical','row','identity','aliases','ancestors'},'snapshot-sample-shape')
    name=path(item['canonical']);need(name in rows,'snapshot-unselected-file')
    need(item['row']=={k:rows[name][k] for k in ('bytes','mode','sha256')},'snapshot-row')
    meta=identity(item['identity'],'file')
    need(meta[0]==stat.S_IFREG|rows[name]['mode'] and meta[4]==rows[name]['bytes'],'snapshot-row-identity')
    return {'canonical':name,'row':item['row'],'identity':meta,
            'aliases':aliases(item['aliases']),'ancestors':ancestors(item['ancestors'])}

def inventory_shape(item):
    if item is None:return None
    need(type(item) is dict and set(item)=={'canonical','aliases','ancestors','directories','entries','leaves'},
         'snapshot-inventory-shape')
    root=path(item['canonical']);result={'canonical':root,'aliases':aliases(item['aliases']),
        'ancestors':ancestors(item['ancestors']),'directories':[],'entries':[],'leaves':item['leaves']}
    need(type(item['directories']) is list and 0<len(item['directories'])<=1024
         and type(item['entries']) is list and len(item['entries'])<=8192
         and type(item['leaves']) is list and len(item['leaves'])<=8192,'snapshot-inventory-bounds')
    dirs={};nodes={}
    for node in item['directories']:
        need(type(node) is dict and set(node)=={'path','identity','names'},'snapshot-directory-shape')
        name=path(node['path']);need(Path(name).is_relative_to(root) and name not in dirs,'snapshot-directory-scope')
        names=node['names']
        need(type(names) is list and len(names)<=8192 and all(type(n) is str and 0<len(n)<=255
             and n not in ('.','..') and '/' not in n and all(32<=ord(c)<127 for c in n) for n in names)
             and names==sorted(set(names)),'snapshot-directory-names')
        meta=identity(node['identity'],'directory');dirs[name]=names
        result['directories'].append({'path':name,'identity':meta,'names':names})
    need(root in dirs,'snapshot-root-directory')
    for node in item['entries']:
        need(type(node) is dict and set(node)=={'path','identity'},'snapshot-entry-shape')
        name=path(node['path']);need(name!=root and Path(name).is_relative_to(root) and name not in nodes,'snapshot-entry-scope')
        meta=identity(node['identity']);nodes[name]=node['identity']
        result['entries'].append({'path':name,'identity':meta})
        need(str(Path(name).parent) in dirs and Path(name).name in dirs[str(Path(name).parent)],'snapshot-entry-parent')
        if stat.S_ISDIR(meta[0]):need(name in dirs,'snapshot-missing-child-directory')
    need(set(nodes)=={str(Path(parent)/name) for parent,names in dirs.items() for name in names},'snapshot-listed-entry-coverage')
    need(item['leaves']==sorted(name for name,meta in nodes.items() if not stat.S_ISDIR(meta[2])),
         'snapshot-listed-leaf-coverage')
    # Parent/child directory rows are separate physical observations and must agree.
    for node in item['directories']:
        if node['path']!=root:need(nodes[node['path']]==node['identity'],'snapshot-child-directory-identity')
    return result


LIB_GCC='/usr/lib/gcc/aarch64-linux-gnu'
EXEC_GCC='/usr/libexec/gcc/aarch64-linux-gnu'
HELPER_ROLES=('cc1','cc1plus','collect2','lto-wrapper')
VERSION_DIRECTORY=r'[1-9][0-9]{0,2}(?:\.[0-9]{1,3}){0,2}'

def discovery_shape(item,root,required=True):
    if item is None:
        need(not required,'required-gcc-discovery');return {}
    need(type(item) is dict and set(item)=={'canonical','aliases','ancestors','identity','directories'}
         and item['canonical']==root,'complete-gcc-discovery')
    identity(item['identity'],'directory');aliases(item['aliases']);ancestors(item['ancestors'])
    need({str(p) for p in Path(root).parents}<={a['path'] for a in item['ancestors']},
         'gcc-discovery-ancestor-coverage')
    directories=item['directories']
    need(type(directories) is list and len(directories)<=32,'gcc-discovery-directory-bound')
    result={};names=[]
    for row in directories:
        need(type(row) is dict and set(row)=={'path','identity'},'gcc-discovery-directory-shape')
        name=path(row['path'])
        need(str(Path(name).parent)==root and re.fullmatch(VERSION_DIRECTORY,Path(name).name),
             'gcc-discovery-immediate-version-directory')
        identity(row['identity'],'directory');names.append(name);result[name]=row['identity']
    need(names==sorted(set(names)),'gcc-discovery-sorted-unique-directories')
    return result

def discovery_join(snapshot,directory,witness):
    need(type(witness) is dict and type(witness.get('ancestors')) is list,'gcc-discovery-witness')
    held={a['path']:a['identity'] for a in witness['ancestors']}
    chosen=next(row['identity'] for row in snapshot['directories'] if row['path']==directory)
    need(held.get(directory)==chosen and held.get(snapshot['canonical'])==snapshot['identity']
         and all(held.get(a['path'])==a['identity'] for a in snapshot['ancestors']),
         'gcc-discovery-held-directory-identity')

def validate_gcc_discovery(candidate,requests,observed):
    lib=candidate['gcc_discovery'];helper=candidate['helper_discovery']
    library=discovery_shape(lib,LIB_GCC);helpers=discovery_shape(helper,EXEC_GCC,False)
    need(len(library)+len(helpers)<=32,'aggregate-gcc-version-directory-bound')
    request=requests.get('/usr/bin/gcc');target=candidate['roles']['gcc']
    need(type(target) is str and request is not None and request['canonical']==target,'default-gcc-driver-binding')
    match=re.fullmatch(r'/usr/bin/(?:aarch64-linux-gnu-)?gcc-([1-9][0-9]{0,2})',target)
    need(match is not None,'default-gcc-driver-canonical-major')
    major=match.group(1)
    selected=[name for name in library if Path(name).name.split('.')[0]==major]
    need(len(selected)==1 and candidate['gcc_directory']==selected[0],'unique-default-gcc-directory')
    directory=selected[0]
    include=candidate['inventories'][directory+'/include']
    discovery_join(lib,directory,include)
    roots=sorted([directory]+[name for name in helpers if Path(name).name.split('.')[0]==major])
    expected={root+'/'+role for root in roots for role in HELPER_ROLES}
    pattern='(?:'+re.escape(LIB_GCC)+'|'+re.escape(EXEC_GCC)+')/'+VERSION_DIRECTORY+'/(?:'+'|'.join(HELPER_ROLES)+')'
    actual={name for name in requests if re.fullmatch(pattern,name)}
    need(actual==expected,'complete-helper-request-matrix')
    for role in HELPER_ROLES:
        positives=[requests[root+'/'+role] for root in roots if requests[root+'/'+role] is not None]
        canonical={item['canonical'] for item in positives}
        need(len(canonical)==1 if role in ('cc1','cc1plus') else len(canonical)<=1,
             'unique-required-or-optional-helper')
        target=next(iter(canonical)) if canonical else None
        need(candidate['roles'][role]==target,'helper-role-positive-negative-binding')
        for item in positives:
            name=item['canonical'];parent=str(Path(name).parent)
            need(name in {root+'/'+role for root in roots} and name in candidate['files']
                 and candidate['files'][name]['kind']=='ELF' and candidate['files'][name]['mode']==0o755,
                 'helper-canonical-root-role-mode')
            need(item['identity']==observed[name]['identity'] and item['row']==observed[name]['row'],
                 'helper-canonical-full-identity-digest')
            discovery_join(lib if parent==directory else helper,parent,item)


def validate_observation(observation):
    need(type(observation) is dict and set(observation) == {'candidate', 'evidence'}, 'complete-observation-shape')
    candidate = observation['candidate']
    evidence = observation['evidence']
    need(type(candidate) is dict and set(candidate) == {'schema_version', 'purpose', 'gcc_directory', 'gcc_discovery', 'helper_discovery', 'roles', 'files', 'headers', 'inventories', 'selected', 'execution_grant_issued'} and (type(candidate['schema_version']) is int) and (candidate['schema_version'] == 1) and (candidate['purpose'] == 'NATIVE_SIGNER_COMPILE_TOOLCHAIN_CANDIDATE_V1') and (candidate['selected'] is False) and (candidate['execution_grant_issued'] is False), 'unselected-observation')
    gcc_major(candidate['gcc_directory'])
    rows = candidate['files']
    need(type(rows) is dict and 0 < len(rows) <= 4096, 'snapshot-file-count')
    for name, row in rows.items():
        path(name)
        need(type(row) is dict and set(row) == {'bytes', 'mode', 'sha256', 'kind'} and (type(row['bytes']) is int) and (0 < row['bytes'] <= 64 * 1024 ** 2) and (type(row['mode']) is int) and (row['mode'] in (420, 493)) and sha(row['sha256']) and (row['kind'] in ('ELF', 'HEADER', 'DATA')), 'snapshot-file-row')
    need(sum((row['bytes'] for row in rows.values())) <= 256 * 1024 ** 2, 'snapshot-unique-body-budget')
    need(candidate['headers'] == sorted((name for name, row in rows.items() if row['kind'] == 'HEADER')) and 0 < len(candidate['headers']) <= 4096, 'snapshot-full-header-set')
    expected_evidence = {'schema_version', 'status', 'context', 'observations', 'requests', 'deadline_at', 'file_bytes', 'executed_tools', 'loaded_libraries', 'compile_allowed', 'driver_helper_specs_correspondence', 'complete_header_include_correspondence', 'loader_cache_preload_dlopen_correspondence', 'privileged_tool_filecap_cgroup_migration_exclusion', 'inherited_sample_close_cancel_priority', 'source_reuse_sha256'}
    need(type(evidence) is dict and set(evidence) == expected_evidence and (type(evidence['schema_version']) is int) and (evidence['schema_version'] == 1) and (evidence['status'] == 'OBSERVED_CANDIDATE_NOT_SELECTED') and all((evidence[key] is False for key in ('executed_tools', 'loaded_libraries', 'compile_allowed'))) and (evidence['source_reuse_sha256'] == REUSE_SHA), 'complete-passive-evidence')
    ctx = evidence['context']
    need(type(ctx) is dict and set(ctx) == {'source_commit', 'workflow_commit', 'run_id', 'run_attempt', 'machine', 'uid'} and (ctx['machine'] == 'aarch64') and (type(ctx['uid']) is int) and (ctx['uid'] > 0) and (type(ctx['source_commit']) is str) and re.fullmatch('[0-9a-f]{40}', ctx['source_commit']) and (ctx['source_commit'] == ctx['workflow_commit']) and (type(ctx['run_id']) is str) and re.fullmatch('[1-9][0-9]{0,19}', ctx['run_id']) and (type(ctx['run_attempt']) is str) and re.fullmatch('[1-9][0-9]{0,9}', ctx['run_attempt']), 'original-observation-context')
    need(type(evidence['deadline_at']) in (int, float) and math.isfinite(evidence['deadline_at']) and (evidence['deadline_at'] > 0) and (type(evidence['file_bytes']) is int) and (evidence['file_bytes'] == sum((row['bytes'] for row in rows.values()))), 'original-observation-frame-count')
    need(all((evidence[key] == 'UNKNOWN' for key in ('driver_helper_specs_correspondence', 'complete_header_include_correspondence', 'loader_cache_preload_dlopen_correspondence', 'privileged_tool_filecap_cgroup_migration_exclusion'))) and evidence['inherited_sample_close_cancel_priority'] == 'later cancellation can replace ordinary read fault', 'passive-evidence-scope')
    requests = evidence['requests']
    observed = evidence['observations']
    need(type(requests) is dict and 0 < len(requests) <= 16384 and (type(observed) is dict) and (set(observed) == set(rows)), 'complete-observation-coverage')
    positive = set()
    for name, item in requests.items():
        path(name)
        if item is not None:
            sample_shape(item, rows)
            positive.add(item['canonical'])
    need(positive == set(rows), 'request-file-coverage')
    for name, item in observed.items():
        base = {'canonical', 'row', 'identity', 'aliases', 'ancestors'}
        need(type(item) is dict and set(item) == (base | {'interpreter', 'needed', 'resolved'} if rows[name]['kind'] == 'ELF' else base), 'observation-file-shape')
        sample_shape({k: item[k] for k in base}, rows)
        need(item['canonical'] == name, 'observation-canonical-file')
        if rows[name]['kind'] == 'ELF':
            interp = item['interpreter']
            needed = item['needed']
            resolved = item['resolved']
            need(interp is None or type(interp) is str, 'observation-interpreter')
            need(type(needed) is list and len(needed) <= 32 and (len(needed) == len(set(needed))) and all((type(n) is str and re.fullmatch('[A-Za-z0-9_.+-]{1,128}', n) for n in needed)), 'observation-needed')
            need(type(resolved) is dict and set(resolved) == set(needed) | ({'PT_INTERP'} if interp else set()), 'observation-linkage-coverage')
            if interp:
                path(interp)
                need(interp in requests and requests[interp] is not None and (requests[interp]['canonical'] == resolved['PT_INTERP']), 'interpreter-request-binding')
            for soname in needed:
                probes = [directory + '/' + soname for directory in SEARCH]
                need(all((p in requests for p in probes)), 'all-library-search-witnesses')
                targets = {requests[p]['canonical'] for p in probes if requests[p] is not None}
                need(len(targets) == 1 and resolved[soname] in targets, 'unique-library-request-binding')
            need(all((target in rows and rows[target]['kind'] == 'ELF' for target in resolved.values())), 'selected-linkage-target')
    gcc = candidate['gcc_directory']
    role_paths = {'gcc': '/usr/bin/gcc', 'as': '/usr/bin/as', 'ld': '/usr/bin/ld', 'readelf': '/usr/bin/readelf', 'objdump': '/usr/bin/objdump', 'python_candidate': '/usr/bin/python3', 'specs': gcc + '/specs'}
    need(type(candidate['roles']) is dict and set(candidate['roles']) == set(role_paths)|set(HELPER_ROLES), 'complete-role-set')
    for role, name in role_paths.items():
        need(name in requests, 'role-request-coverage')
        request = requests[name]
        target = candidate['roles'][role]
        if target is None:
            need(role == 'specs' and request is None, 'negative-role-witness')
        else:
            need(request is not None and request['canonical'] == target and (target in rows) and (rows[target]['kind'] == ('DATA' if role == 'specs' else 'ELF')) and (role == 'specs' or rows[target]['mode'] == 493), 'role-request-binding')
    roots = {gcc + '/include', gcc + '/include-fixed', gcc + '/plugin', '/usr/include/aarch64-linux-gnu/asm', '/usr/include/linux', '/usr/include/asm-generic'}
    need(type(candidate['inventories']) is dict and set(candidate['inventories']) == roots, 'complete-inventory-roots')
    for root, item in candidate['inventories'].items():
        shape = inventory_shape(item)
        if shape is None:
            need(root in (gcc + '/include-fixed', gcc + '/plugin'), 'missing-required-header-root')
        else:
            for leaf in item['leaves']:
                need(leaf in requests and requests[leaf] is not None, 'inventory-header-request-coverage')
                row = rows[requests[leaf]['canonical']]
                need(row['kind'] in ('ELF', 'DATA') if root == gcc + '/plugin' else row['kind'] == 'HEADER', 'inventory-leaf-body-kind')
    validate_gcc_discovery(candidate,requests,observed)
    return (candidate, evidence)

ISSUER = {'schema_version':1,'purpose':'SIGNER_NATIVE_PASSIVE_PUBLIC_ISSUER_V1',
    'repository':'Gabriel-Kahen/cachy-asahi','branch':'codex/signer-native-passive-observation-20261014',
    'workflow':'.github/workflows/native-arm-runner-observation.yml','job_name':'observe',
    'runner_label':'ubuntu-24.04-arm','argv':['/usr/bin/python3.12','-I','-B','-S','-'],
    'gcc_directory':'CURRENT_DEFAULT_GCC','seconds':60,
    'operation':'ONE_READ_ONLY_HOSTED_ARM_TOOLCHAIN_OBSERVATION','compile_allowed':False,
    'GPG_allowed':False,'probe_allowed':False,'signing_allowed':False,'system_mutation_allowed':False}
ISSUER_SHA = 'b3b55b55ad887acd6fc9cea66bf006afd0e2b9c643b2b4ac9bf9fc56d7d89a16'
SOURCE_NAMES = {'passive.py','observation_entry.py','provenance.py','retention.py','adoption_entry.py'}
OBSERVER_STEP = 'Observe and retain Source-pinned read-only ARM toolchain'


def source_rows(rows):
    need(type(rows) is dict and set(rows)==SOURCE_NAMES,'closed-active-Source-rows')
    for name,row in rows.items():
        need(type(row) is dict and set(row)=={'bytes','mode','sha256'}
             and type(row['bytes']) is int and 0<row['bytes']<=1024**2
             and type(row['mode']) is int and row['mode']==0o644 and sha(row['sha256']),'Source-row')
    need(sum(r['bytes'] for r in rows.values())<=2*1024**2,'Source-total-budget')
    need(rows['passive.py']['sha256']=='b844e94ae9cf69882550526a93aed3606398e9252175472be0bf6f2888eba1c9'
         and rows['observation_entry.py']['sha256']=='540db1ab5a877fd2486673e86d2a1216c036dd9d8bec3953f44f467ee4966071',
         'literal-inherited-Source')


def flags(row):
    need(all(row[k] is False for k in ('selected','execution_grant_issued','compile_allowed')),
         'no-execution-admission')


def validate_root_result(records, expectation, job, *, artifact_files):
    """Root passes externally authenticated normalized metadata, never payload claims.

    The return is retained passive data only. It contains no opaque grants and
    cannot close compilation, loaded-code, kernel-handler, signer or M2 gates.
    """
    try:return _validate_root_result(records,expectation,job,artifact_files)
    except Refused:raise
    except (ValueError,TypeError,KeyError,IndexError,OverflowError,RecursionError) as error:
        raise Refused('malformed-contract') from error


def _validate_root_result(records, expectation, job, artifact_files):
    keys={'schema_version','purpose','repository','branch','workflow','job_name','runner_label',
          'source_commit','workflow_commit','run_id','run_attempt','job_id','source_pins',
          'source_packet_sha256','configuration','configuration_sha256','public_issuer','public_issuer_sha256'}
    need(type(expectation) is dict and set(expectation)==keys and type(expectation['schema_version']) is int
         and expectation['schema_version']==1 and expectation['purpose']=='ROOT_EXPECTED_SIGNER_PASSIVE_ADOPTION_V1',
         'external-expectation-shape')
    need(expectation['public_issuer']==ISSUER and expectation['public_issuer_sha256']==ISSUER_SHA
         and digest(canonical(expectation['public_issuer']))==ISSUER_SHA,'literal-public-issuer')
    need(all(expectation[k]==ISSUER[k] for k in ('repository','branch','workflow','job_name','runner_label')),
         'exact-public-job-scope')
    for k in ('source_commit','workflow_commit'):
        need(type(expectation[k]) is str and re.fullmatch('[0-9a-f]{40}',expectation[k]),'exact-commit')
    need(expectation['source_commit']==expectation['workflow_commit'],'same-Source-workflow-commit')
    for k in ('run_id','run_attempt','job_id'):
        need(type(expectation[k]) is str and re.fullmatch('[1-9][0-9]{0,19}',expectation[k]),'exact-job-identifier')
    source_rows(expectation['source_pins'])
    need(sha(expectation['source_packet_sha256']) and digest(canonical(expectation['source_pins']))==expectation['source_packet_sha256'],
         'externally-selected-Source-packet')
    configuration=expectation['configuration']
    need(configuration=={'schema_version':1,'purpose':'NATIVE_SIGNER_COMPILE_PASSIVE_OBSERVATION_V1',
                          'gcc_directory':ISSUER['gcc_directory']}
         and type(configuration['schema_version']) is int and sha(expectation['configuration_sha256'])
         and digest(canonical(configuration))==expectation['configuration_sha256'],'externally-selected-configuration')
    jkeys={'repository','branch','workflow','name','runner_label','source_commit','workflow_commit',
           'run_id','run_attempt','job_id','status','conclusion','observer_step','observer_conclusion'}
    need(type(job) is dict and set(job)==jkeys,'authenticated-job-shape')
    need(all(job[k]==expectation[k] for k in jkeys-{'name','status','conclusion','observer_step','observer_conclusion'})
         and job['name']==expectation['job_name'] and job['status']=='completed'
         and job['conclusion']==job['observer_conclusion']=='success' and job['observer_step']==OBSERVER_STEP,
         'authenticated-natural-job-success')
    need(type(records) is list and len(records)==2 and all(type(r) is str and r.isascii()
         and '\n' not in r and '\r' not in r and 0<len(r)<=6*1024**2 for r in records),'exact-two-records')
    need(records[0].startswith(CANDIDATE) and records[1].startswith(FINAL),'single-ordered-adoption-markers')
    encoded=records[0][len(CANDIDATE):]
    try:raw=base64.b64decode(encoded,validate=True)
    except (ValueError,TypeError) as error:raise Refused('candidate-base64') from error
    need(base64.b64encode(raw).decode('ascii')==encoded,'canonical-base64')
    candidate=strict_json(raw);final_raw=records[1][len(FINAL):].encode('ascii');final=strict_json(final_raw)
    need(canonical(candidate)==raw and canonical(final)==final_raw,'canonical-record-JSON')
    ckeys={'schema_version','purpose','source_pins','configuration','context','observation','provenance',
           'entry','deadline_at','selected','execution_grant_issued','compile_allowed'}
    fkeys={'schema_version','purpose','status','candidate_sha256','context','entry','deadline_at','ended',
           'selected','execution_grant_issued','compile_allowed'}
    need(type(candidate) is dict and set(candidate)==ckeys and type(final) is dict and set(final)==fkeys,
         'complete-envelope-shapes')
    need(all(type(r['schema_version']) is int and r['schema_version']==1 and r['purpose']==PURPOSE
         for r in (candidate,final)) and final['status']=='OBSERVED_COMPLETE_NOT_SELECTED','envelope-purpose-status')
    flags(candidate);flags(final)
    need(canonical(candidate['source_pins'])==canonical(expectation['source_pins']) and canonical(candidate['configuration'])==canonical(configuration),
         'envelope-Source-configuration')
    need(sha(final['candidate_sha256']) and final['candidate_sha256']==digest(raw),'complete-envelope-digest')
    entry,end,ended=candidate['entry'],candidate['deadline_at'],final['ended']
    need(all(type(n) in (int,float) and math.isfinite(n) for n in (entry,end,ended))
         and entry>0 and end==entry+60 and entry<=ended<end
         and final['entry']==entry and type(final['entry']) is type(entry)
         and final['deadline_at']==end and type(final['deadline_at']) is type(end),'same-original-sixty-second-frame')
    ctx=candidate['context']
    need(type(ctx) is dict and set(ctx)=={'source_commit','workflow_commit','run_id','run_attempt','machine','uid'}
         and all(ctx[k]==expectation[k] for k in ('source_commit','workflow_commit','run_id','run_attempt'))
         and ctx['machine']=='aarch64' and type(ctx['uid']) is int and ctx['uid']>0 and canonical(final['context'])==canonical(ctx),
         'authenticated-payload-context')
    validate_artifacts(artifact_files,records,raw,final_raw,candidate,final,expectation)
    c,e=validate_observation(candidate['observation'])
    need(configuration['gcc_directory']=='CURRENT_DEFAULT_GCC' and canonical(e['context'])==canonical(ctx)
         and type(e['deadline_at']) is type(end) and e['deadline_at']==end,'original-observation-binding')
    validate_provenance(candidate['provenance'],candidate['source_pins'],candidate['observation'])
    return {'status':'ROOT_VALIDATED_PASSIVE_DATA_ONLY','candidate_sha256':digest(raw),
            'final_sha256':digest(final_raw),'source_packet_sha256':expectation['source_packet_sha256'],
            'candidate':candidate,'final':final,'selected':False,'execution_grant_issued':False,
            'compile_allowed':False,'GPG_allowed':False,'probe_allowed':False,
            'kernel_handler_admitted':False,'loaded_runtime_admitted':False,'M2_hardware_admitted':False}


def validate_artifacts(files,records,raw,final_raw,candidate,final,expectation):
    need(type(files) is dict and set(files)=={'records.ndjson','candidate.json','final.json','completion.json'},
         'four-complete-artifacts')
    need(all(type(v) is bytes and 0<len(v)<=6*1024**2 for v in files.values()),'artifact-byte-budget')
    records_raw=('\n'.join(records)+'\n').encode('ascii')
    need(files['records.ndjson']==records_raw and files['candidate.json']==raw and files['final.json']==final_raw,
         'exact-retained-records-and-payloads')
    completion=strict_json(files['completion.json'])
    need(canonical(completion)==files['completion.json'],'canonical-completion')
    keys={'schema_version','purpose','status','context','source_packet_sha256','configuration_sha256',
          'public_issuer_sha256','entry','deadline_at','observer_returncode','selected','execution_grant_issued',
          'compile_allowed','records_sha256','candidate_sha256','final_sha256','ended'}
    need(type(completion) is dict and set(completion)==keys and type(completion['schema_version']) is int
         and completion['schema_version']==1 and completion['purpose']==PURPOSE
         and completion['status']=='RETAINED_COMPLETE_NOT_SELECTED','complete-retention-schema')
    flags(completion)
    need(type(completion['observer_returncode']) is int and completion['observer_returncode']==0
         and canonical(completion['context'])==canonical(candidate['context']),'retained-intended-zero-context')
    need(all(completion[k]==expectation[k] for k in ('source_packet_sha256','configuration_sha256','public_issuer_sha256'))
         and completion['records_sha256']==digest(records_raw) and completion['candidate_sha256']==digest(raw)
         and completion['final_sha256']==digest(final_raw),'complete-retention-digests')
    need(type(completion['entry']) is type(candidate['entry']) and completion['entry']==candidate['entry']
         and type(completion['deadline_at']) is type(candidate['deadline_at'])
         and completion['deadline_at']==candidate['deadline_at'] and type(completion['ended']) in (int,float)
         and math.isfinite(completion['ended']) and final['ended']<=completion['ended']<candidate['deadline_at'],
         'retention-original-frame')

BASE_PACKAGES={'gcc','binutils','python3.12','python3.12-minimal',
               'libpython3.12-stdlib','libc6','linux-libc-dev','libc6-dev'}
BASE_OPTIONAL={'binutils-aarch64-linux-gnu','libpython3.12-minimal'}
GCC_DIRECTORY=r'/usr/lib/gcc/aarch64-linux-gnu/([1-9][0-9]{0,2})(?:\.[0-9]{1,3}){0,2}'

def gcc_major(directory):
    need(type(directory) is str,'concrete-gcc-directory')
    match=re.fullmatch(GCC_DIRECTORY,directory)
    need(match is not None,'concrete-gcc-directory')
    return match.group(1)

def package_sets(major):
    need(type(major) is str and re.fullmatch('[1-9][0-9]{0,2}',major),'selected-gcc-major')
    required=BASE_PACKAGES|{'gcc-'+major}
    family={'gcc-'+major,'gcc-'+major+'-base','gcc-'+major+'-aarch64-linux-gnu',
            'cpp-'+major,'cpp-'+major+'-aarch64-linux-gnu',
            'libgcc-'+major+'-dev','libstdc++-'+major+'-dev'}
    return required,BASE_OPTIONAL|(family-required),family

def text(value,bound=4096):
    return type(value) is str and 0<len(value)<=bound and '\0' not in value and value!='UNKNOWN'

def file_row(row):
    need(type(row) is dict and set(row)=={'bytes','mode','sha256'} and type(row['bytes']) is int
         and 0<row['bytes']<=64*1024**2 and type(row['mode']) is int and row['mode'] in (0o644,0o755)
         and sha(row['sha256']),'provenance-file-row')


def validate_provenance(provenance,source_pins,observation):
    need(type(provenance) is dict and set(provenance)=={'kernel','python','stdlib','dpkg'},'complete-provenance')
    k=provenance['kernel']
    need(type(k) is dict and set(k)=={'uname','proc_version','proof_scope'} and k['proof_scope']=='HOST_METADATA_ONLY',
         'kernel-provenance-scope')
    uname=k['uname'];proc=k['proc_version']
    need(type(uname) is dict and set(uname)=={'sysname','nodename','release','version','machine'}
         and all(text(v) for v in uname.values()) and uname['sysname']=='Linux' and uname['machine']=='aarch64',
         'native-kernel-metadata')
    need(type(proc) is dict and set(proc)=={'bytes','sha256','text'} and type(proc['bytes']) is int
         and 0<proc['bytes']<=65536 and sha(proc['sha256']) and text(proc['text'],65536)
         and len(proc['text'].encode('utf-8'))==proc['bytes'] and digest(proc['text'].encode('utf-8'))==proc['sha256'],
         'exact-proc-version-bytes')
    need(proc['text'].startswith('Linux version '+uname['release']+' '),'kernel-release-correspondence')
    p=provenance['python']
    need(type(p) is dict and set(p)=={'version','version_info','executable','executable_file','implementation','flags',
         'observer_source_rows','bodies_embedded','execution_admission_issued'} and p['bodies_embedded'] is False
         and p['execution_admission_issued'] is False and canonical(p['observer_source_rows'])==canonical(source_pins),
         'python-Source-no-admission')
    info=p['version_info'];impl=p['implementation']
    need(type(info) is list and len(info)==5 and all(type(info[i]) is int and info[i]>=0 for i in (0,1,2,4))
         and info[:2]==[3,12] and info[3]=='final' and text(p['version'],1024) and p['version'].startswith('3.12.'),
         'selected-python-version')
    need(type(impl) is dict and set(impl)=={'name','cache_tag','version'} and impl['name']=='cpython'
         and impl['cache_tag']=='cpython-312' and canonical(impl['version'])==canonical(info),'selected-CPython-implementation')
    expected_flags={'isolated':1,'ignore_environment':1,'no_site':1,'no_user_site':1,'dont_write_bytecode':1,
                    'optimize':0,'safe_path':True}
    need(type(p['flags']) is dict and set(p['flags'])==set(expected_flags)
         and all(type(p['flags'][name]) is type(value) and p['flags'][name]==value
                 for name,value in expected_flags.items()),'isolated-read-only-python-flags')
    ex=p['executable_file'];need(type(ex) is dict and set(ex)=={'canonical','row'}
         and p['executable']=='/usr/bin/python3.12','selected-python-executable')
    path(ex['canonical']);file_row(ex['row']);rows=observation['candidate']['files']
    need(ex['canonical']==observation['candidate']['roles']['python_candidate'] and ex['canonical'] in rows
         and ex['row']=={key:rows[ex['canonical']][key] for key in ('bytes','mode','sha256')},
         'same-observed-python-file')
    std=provenance['stdlib']
    need(type(std) is dict and set(std)=={'modules','files','builtin_or_frozen','excluded_loaded','scope','bodies_embedded'}
         and std['scope']=='CURRENT_LOADED_ORIGINS_ONLY_NOT_EXECUTED_BYTE_OR_WHOLE_STDLIB_PROOF'
         and std['bodies_embedded'] is False,'stdlib-origin-scope')
    need(type(std['files']) is dict and 0<len(std['files'])<=4096 and type(std['modules']) is list
         and 0<len(std['modules'])<=2048,'stdlib-file-module-budget')
    prefix='/usr/lib/python3.12/'
    empty_files=set()
    for name,row in std['files'].items():
        path(name);need(name.startswith(prefix),'stdlib-canonical-scope')
        if type(row) is dict and type(row.get('bytes')) is int and row['bytes']==0:
            need(set(row)=={'bytes','mode','sha256'} and row['mode']==0o644 and
                 type(row['mode']) is int and row['sha256']==digest(b'') and name.endswith('.py'),
                 'empty-stdlib-source-row')
            empty_files.add(name)
        else:file_row(row)
    referenced=set();names=set()
    for module in std['modules']:
        need(type(module) is dict and set(module)=={'name','origin','file','cached','basis','canonical','canonical_cached'}
             and text(module['name'],256) and module['name'] not in names,'stdlib-module-shape')
        names.add(module['name'])
        need(text(module['origin'],1024) and module['origin'].startswith(prefix)
             and module['basis'] in ('text-origin','bytecode-origin','native-extension-origin')
             and module['canonical'] in std['files'],'stdlib-origin-file-binding')
        suffix={'text-origin':'.py','bytecode-origin':'.pyc','native-extension-origin':'.so'}[module['basis']]
        need(module['origin'].endswith(suffix),'stdlib-origin-basis')
        if module['canonical'] in empty_files:
            path(module['origin'])
            need(module['basis']=='text-origin' and module['origin'].endswith('.py')
                 and module['origin'].startswith(prefix),'empty-stdlib-source-reference')
        for field in ('file','cached'):
            need(module[field] is None or text(module[field],1024),'stdlib-optional-origin')
        referenced.add(module['canonical'])
        cache=module['canonical_cached']
        need(module['cached'] not in empty_files,'empty-stdlib-cache-reference')
        need(cache is None or (module['cached'] is not None and cache in std['files'] and cache.endswith('.pyc')),
             'stdlib-cache-binding')
        if cache is not None:referenced.add(cache)
        need(cache not in empty_files,'empty-stdlib-cache-reference')
    need(referenced==set(std['files']),'complete-stdlib-references')
    for key in ('builtin_or_frozen','excluded_loaded'):
        need(type(std[key]) is list and len(std[key])<=2048,'loaded-origin-budget')
        for row in std[key]:
            need(type(row) is dict and set(row)=={'name','origin'} and text(row['name'],256)
                 and row['name'] not in names,'loaded-origin-shape');names.add(row['name'])
            if key=='builtin_or_frozen':need(row['origin'] in ('built-in','frozen'),'builtin-frozen-origin')
            else:need(row['origin'] is None or (text(row['origin'],1024) and not row['origin'].startswith(prefix)),
                      'excluded-origin-scope')
    d=provenance['dpkg']
    need(type(d) is dict and set(d)=={'status_file','packages','scope'}
         and d['scope']=='INSTALLED_RECORDS_NOT_BINARY_OWNERSHIP_BUILD_PROOF','dpkg-installed-scope')
    status=d['status_file'];packages=d['packages']
    need(type(status) is dict and set(status)=={'bytes','sha256'} and type(status['bytes']) is int
         and 0<status['bytes']<=32*1024**2 and sha(status['sha256']),'dpkg-status-file')
    required,optional,family=package_sets(gcc_major(observation['candidate']['gcc_directory']))
    need(type(packages) is dict and required<=set(packages)<=required|optional,
         'complete-selected-package-records')
    for name,row in packages.items():
        need(type(row) is dict and set(row)=={'version','architecture','status','stanza_sha256','stanza_bytes'}
             and text(row['version'],256) and re.fullmatch('[A-Za-z0-9.+:~_-]+',row['version'])
             and (row['architecture']=='arm64' if name in required else row['architecture'] in ('arm64','all')),
             'package-version-architecture')
        need(row['status']=='install ok installed' and sha(row['stanza_sha256'])
             and type(row['stanza_bytes']) is int and 0<row['stanza_bytes']<=65536,'installed-package-stanza')
    need(sum(row['stanza_bytes'] for row in packages.values())<=status['bytes'],'dpkg-status-stanza-budget')
    major=gcc_major(observation['candidate']['gcc_directory'])
    need(all(re.match(r'^'+re.escape(major)+r'(?:\.|-)',packages[name]['version'].split(':')[-1])
             for name in family&set(packages)),'selected-gcc-installed-family')
    version='.'.join(str(v) for v in info[:3])
    need(all(packages[name]['version'].split(':')[-1].startswith(version+'-') for name in
         ('python3.12','python3.12-minimal','libpython3.12-stdlib')),'Python-installed-record-correspondence')


def main(argv=None):
    """Read-only local CLI. Root authenticates/extracts transport before invocation."""
    import argparse
    import os
    parser=argparse.ArgumentParser(description='Validate retained passive data; grant no execution')
    parser.add_argument('--expectation',required=True)
    parser.add_argument('--job',required=True)
    parser.add_argument('--artifacts',required=True)
    args=parser.parse_args(argv)
    def bounded(name,bound):
        with open(name,'rb') as handle:raw=handle.read(bound+1)
        need(len(raw)<=bound,'local-file-budget');return raw
    try:
        expected=strict_json(bounded(args.expectation,MAX_RAW))
        job=strict_json(bounded(args.job,MAX_RAW))
        names=[]
        with os.scandir(args.artifacts) as entries:
            for entry in entries:
                need(len(names)<4 and entry.is_file(follow_symlinks=False),'exact-regular-artifact-inventory')
                names.append(entry.name)
        need(set(names)=={'records.ndjson','candidate.json','final.json','completion.json'},'exact-artifact-inventory')
        files={name:bounded(Path(args.artifacts)/name,6*1024**2)
               for name in ('records.ndjson','candidate.json','final.json','completion.json')}
        body=files['records.ndjson']
        need(body.endswith(b'\n') and b'\r' not in body,'retained-newline-records')
        records=body[:-1].decode('ascii').split('\n')
        result=validate_root_result(records,expected,job,artifact_files=files)
        print(json.dumps({k:v for k,v in result.items() if k not in ('candidate','final')},sort_keys=True))
        return 0
    except (Refused,OSError,UnicodeError) as error:
        print(json.dumps({'status':'FAIL','reason':str(error),'compile_allowed':False},sort_keys=True))
        return 1



def normalize_job(run, job, *, workflow_commit):
    """Normalize Root-authenticated GitHub API objects; never authenticate transport.

    workflow_commit is independently verified by Root from the selected workflow
    revision. A run's head SHA alone cannot establish that workflow binding.
    Missing API fields refuse instead of falling back to result-payload claims.
    """
    try:
        need(type(run) is dict and type(job) is dict,'API-job-objects')
        need(run['repository']['full_name']==ISSUER['repository'] and run['head_branch']==ISSUER['branch']
             and run['path']==ISSUER['workflow'] and run['event']=='workflow_dispatch'
             and run['status']=='completed' and run['conclusion']=='success','API-exact-successful-run')
        need(type(workflow_commit) is str and re.fullmatch('[0-9a-f]{40}',workflow_commit)
             and run['head_sha']==workflow_commit==job['head_sha'],'API-independent-workflow-commit')
        need(all(type(v) is int and v>0 for v in (run['id'],run['run_attempt'],job['id'],job['run_id'],job['run_attempt']))
             and job['run_id']==run['id'] and job['run_attempt']==run['run_attempt'],'API-run-attempt-binding')
        need(job['name']==ISSUER['job_name'] and job['status']=='completed' and job['conclusion']=='success'
             and type(job['labels']) is list and ISSUER['runner_label'] in job['labels'],'API-exact-successful-job')
        steps=job['steps'];need(type(steps) is list and len(steps)<=64,'API-step-budget')
        observed=[step for step in steps if type(step) is dict and step.get('name')==OBSERVER_STEP]
        need(len(observed)==1 and observed[0]['status']=='completed' and observed[0]['conclusion']=='success',
             'API-exact-natural-observer-step')
        return {'repository':ISSUER['repository'],'branch':ISSUER['branch'],'workflow':ISSUER['workflow'],
                'name':ISSUER['job_name'],'runner_label':ISSUER['runner_label'],'source_commit':run['head_sha'],
                'workflow_commit':workflow_commit,'run_id':str(run['id']),'run_attempt':str(run['run_attempt']),
                'job_id':str(job['id']),'status':'completed','conclusion':'success','observer_step':OBSERVER_STEP,
                'observer_conclusion':'success'}
    except Refused:raise
    except (KeyError,TypeError,ValueError) as error:raise Refused('incomplete-API-job-binding') from error

if __name__=='__main__':raise SystemExit(main())
