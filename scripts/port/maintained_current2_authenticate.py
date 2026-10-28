#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact current2 metadata binding; authentication needs separate Root operation."""
import argparse
import ast
import base64
import concurrent.futures
import copy
import functools
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import types
import urllib.parse
import urllib.request

CURRENT = {'archive-lock.json': 'f8f4a3748a962e2f793702207cbaf32ed6106a635ad35f70a0f5551d7c6a2362', 'binding-sidecar.json': '90aa6719a47b3a62a025b846b17a472b44d24cb78439d4c157d438a03e4a042f', 'builder-input.json': 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f', 'core.db': '91b52f917c664d5c6c16686b4749b2c4bb3f2673b49097f736d145ba88016364', 'desktop-proposal.json': 'a7a83e750112446026a05fcd0a1a410a8c7aac218afeeed30e106a181ab9aca7', 'extra.db': 'f26b9c8dfd9211400ac605d7a2c0d08b7cfbd2de88b595b97b8e7d8af64dcffd', 'final.lock': 'adf91712422e86817d027c4c8089023df980c53dede701e8599402e743dd0641', 'parent-receipt.json': '7e097a62b708190384b6cc142f59a9c86d2fd579995bce072ee2b1a487d4c07e', 'projection-metadata.json': '2214b5170d8f2f0e0e86d7f1a88efc8a421c40d7186263d5c0c9913686d5a00a', 'repositories.json': 'f00e7e39141d125400c30108994a46cf52ff57e3b03a6d8cab72dfc1fcdee033', 'seed-metadata.json': 'a0e0dc168ceccddf80eff3de57f9515973f0c6810f021425813d46d9425a3e88', 'seed.lock': 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25', 'worker-receipt.json': 'd536a11eb27a3cade695351c3f6475d438de865b4240d9990207e42146abeca0'}
WORKER_KEYS = set(['archive_acquisition', 'baseline_retention', 'builder_input_sha256', 'changes', 'commands', 'conflicts', 'counts_are_observed', 'database_diagnostics', 'dependency_relationships', 'final_count', 'full_candidate_inventory', 'hardware', 'initial_count', 'installation', 'observed_added_count', 'observed_changed_count', 'observed_transaction_count', 'optional_roots_not_selected', 'phase', 'preview_effective_sha256', 'preview_held_sha256', 'print_diagnostic', 'print_exit', 'proposed_seed_changes', 'provider_constraints', 'removals', 'retained_seed_count', 'roots', 'runtime_sha256', 'schema', 'seed_held', 'seed_inventory_sha256', 'signature_authentication', 'snapshots', 'source_sha256', 'status', 'target_Asahi_transaction', 'unsatisfied', 'worker_runtime_effective_sha256'])
PARENT_KEYS = set(['archive_acquisition', 'cleanup_seconds', 'cleanup_verified', 'installation', 'native_Asahi_M2', 'natural_exit', 'observed_elapsed_seconds', 'source_sha256', 'status', 'work_seconds', 'worker_exit', 'worker_receipt_sha256'])
WORKER_KNOWN = {'runtime_sha256': '9a2f5047bffdb8ccbca6d83334d6457792e805e55488da3cccf6d944e51e685d', 'worker_runtime_effective_sha256': 'beacea5c3639ab48abfcdd9caf830a6497bf92282272725d75321c96d1e6b53f', 'preview_held_sha256': 'd737c51474e05cc2c4db2e87fc021f50328eea7744983dd4076d44751fce7383', 'preview_effective_sha256': '0cd2b5e7a852db063275724333718e2a0aa4f70acc48a9b9d982c122a2f5eeb9', 'baseline_retention': 'All exact retained seed identities remain constraints; proposed seed changes cause refusal', 'database_diagnostics': [{'entry': 'extra/findnewest-0.3-4', 'reason': 'missing/non-singleton NAME; unselectable'}]}
HELPERS = {'scripts/port/authenticate.py':'241cd67370eb593bdf948a25788f006ecf470c645ba5d198bc9c318119ebfe10',
    'scripts/port/preview.py':'d737c51474e05cc2c4db2e87fc021f50328eea7744983dd4076d44751fce7383',
    'scripts/ci/native_arm.py':'1a5369e007193fafce355ca6d20f4e771a0f342e0176bfd80f95a718328a0d10'}
ROWS_SHA = '555de8ac36cebde79960eb74e962afcbcc55dca2c8d9fdcc6d165fe3e9b1a896'
RESOLVER_SHA = 'f481a05c24a88176f7df92cbe71f4644ce0a566ee05ff49edfcbd0a31be1418d'
CONTEXT = '/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/reviews/maintained-desktop-current-resolution2-20261015/run-001/private-context'
SCOPE = 'maintained-current2-generic-archive-authentication-v1'
JSON_LIMIT = 4*1024**2
DB_LIMIT = 20_000_000
TOTAL_LIMIT = 64*1024**2
NAME = re.compile(r'[a-z0-9][a-z0-9+_.-]*\Z')
REL = re.compile(r'([a-zA-Z0-9][a-zA-Z0-9+_.-]*)(>=|<=|=|>|<)?([^\s]*)\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')
TRUST = 'unsigned metadata and inherited seed only; archive authentication still required; no whole574/Asahi/M2/source/legal/release admission'
sha = lambda raw:hashlib.sha256(raw).hexdigest()
encoded = lambda value:(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()


def need(ok,label):
    if not ok:raise ValueError(label)


def exact_keys(value,keys,label):
    need(type(value) is dict and set(value)==set(keys),label)


def integer(value,minimum=0,maximum=2**31):
    need(type(value) is int and minimum<=value<=maximum,'integer-bound')
    return value


def document(raw):
    def pairs(rows):
        result={}
        for key,value in rows:need(key not in result,'duplicate-json');result[key]=value
        return result
    def number(value):
        result=float(value);need(math.isfinite(result),'nonfinite-json');return result
    return json.loads(raw,object_pairs_hook=pairs,parse_float=number,
        parse_constant=lambda value:need(False,'nonfinite-json'))


def read(path,pin,limit=JSON_LIMIT):
    """Pin each no-follow directory FD; recheck name edges after bounded read.

    These are finite edge observations, not an atomic filesystem snapshot.
    A privileged writer or swaps undone between observations remain outside
    this guarantee; every opened object still must match its content pin.
    """
    need(type(pin) is str and HEX.fullmatch(pin),'input-pin')
    path=Path(path).absolute()
    need('..' not in path.parts and len(path.parts)>1,'input-ancestors')
    directory_flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    handles=[];edges=[]
    fields=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
    try:
        parent=os.open(path.anchor,directory_flags);handles.append(parent)
        for name in path.parts[1:-1]:
            child=os.open(name,directory_flags,dir_fd=parent);handles.append(child)
            identity=os.fstat(child)
            need(stat.S_ISDIR(identity.st_mode),'input-ancestors')
            edges.append((parent,name,child,identity.st_dev,identity.st_ino))
            parent=child
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        handles.append(fd)
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and not before.st_mode&0o022 and 0<before.st_size<=limit,'input-shape')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(limit+1)
        after=os.fstat(fd)
        need(all(getattr(before,k)==getattr(after,k) for k in fields) and len(raw)==before.st_size and sha(raw)==pin,'input-drift')
        for owner,name,child,device,inode in edges:
            held=os.fstat(child);named=os.stat(name,dir_fd=owner,follow_symlinks=False)
            need(stat.S_ISDIR(named.st_mode) and (held.st_dev,held.st_ino)==(named.st_dev,named.st_ino)==(device,inode),'input-ancestor-drift')
        named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        need(all(getattr(before,k)==getattr(named,k) for k in fields),'input-drift')
        return raw
    finally:
        for fd in reversed(handles):os.close(fd)


def inventory(raw):
    rows=[line.split() for line in raw.decode().splitlines()]
    need(rows and all(len(row)==2 and NAME.fullmatch(row[0]) and row[1] and not re.search(r'\s|/',row[1]) for row in rows),'inventory-row')
    need(len({row[0] for row in rows})==len(rows),'inventory-duplicate')
    need(raw==''.join(n+' '+v+'\n' for n,v in sorted(rows)).encode(),'canonical-inventory')
    return dict(rows)


def engine(source_root):
    """Exact held definitions only; no adjacent module, CLI, bytecode or actor."""
    raw={path:read(Path(source_root)/path,pin) for path,pin in HELPERS.items()}
    native=types.ModuleType('current2_native_helpers');native.__file__=str(Path(source_root)/'scripts/ci/native_arm.py')
    native.__dict__.update(hashlib=hashlib,json=json,re=re,urllib=urllib)
    preview=types.ModuleType('current2_preview_helpers');preview.__dict__.update(re=re)
    legacy=types.ModuleType('current2_archive_engine');legacy.__file__=str(Path(source_root)/'scripts/port/authenticate.py')
    legacy.__dict__.update({name:globals()[name] for name in ('concurrent','hashlib','json','os','Path','re','struct','subprocess','tarfile','tempfile','urllib')})
    legacy.__dict__.update(native=native,preview=preview)
    for path,module,functions,constants in [
        ('scripts/ci/native_arm.py',native,{'sha','save','check_pin','signature_item','valid_signature','pkginfo'},set()),
        ('scripts/port/preview.py',preview,{'need'},{'NAME'}),
        ('scripts/port/authenticate.py',legacy,{'validate','fetch','observe','status','authenticate'},{'SIGNER','CACHE','MAX_BYTES','KEY_FIELDS','ARCHIVE_FIELDS'})]:
        nodes=[node for node in ast.parse(raw[path]).body if isinstance(node,ast.FunctionDef) and node.name in functions or isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id in constants for t in node.targets)]
        need({node.name for node in nodes if isinstance(node,ast.FunctionDef)}==functions,'helper-functions')
        need(len(nodes)==len(functions)+len(constants),'helper-definition-count')
        exec(compile(ast.Module(nodes,type_ignores=[]),str(Path(source_root)/path),'exec',dont_inherit=True),module.__dict__)
    return legacy


def fields(text):
    result={};key=None
    for line in text.splitlines():
        if line.startswith('%') and line.endswith('%'):
            key=line[1:-1];need(key not in result,'database-duplicate-field');result[key]=[]
        elif line and key:result[key].append(line)
    return result


@functools.lru_cache(maxsize=2)
def database(raw,repo):
    entries={};scanned=0;expanded=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r|*') as archive:
        for member in archive:
            scanned+=1;expanded+=member.size
            need(scanned<=100000 and expanded<=256*1024**2,'database-expansion-bound')
            if not member.name.endswith(('/desc','/depends')):continue
            need(member.isfile() and 0<=member.size<=131072,'database-member')
            body=archive.extractfile(member).read(131073);need(len(body)==member.size,'database-member-size')
            row=fields(body.decode());group=entries.setdefault(member.name.rsplit('/',1)[0],{})
            need(not set(row)&set(group),'database-duplicate-metadata');group.update(row)
    packages={}
    for meta in entries.values():
        if len(meta.get('NAME',[]))!=1:continue  # Same held unselectable-NAME policy.
        need(meta['NAME'][0] not in packages,'database-duplicate-name')
        packages[meta['NAME'][0]]=dict(meta,repo=repo)
    return packages


def metadata(meta,name,version):
    need(type(meta) is dict and meta.get('NAME')==[name] and meta.get('VERSION')==[version] and meta.get('ARCH') in (['aarch64'],['any']),'metadata-identity')
    need('_invalid' not in meta and all(type(k) is str and (type(v) is str if k=='repo' else type(v) is list and all(type(x) is str for x in v)) for k,v in meta.items()),'metadata-types')
    for key in ('DEPENDS','PROVIDES','CONFLICTS','REPLACES'):
        for value in meta.get(key,[]):
            match=REL.fullmatch(value);need(match and bool(match[2])==bool(match[3]),'metadata-relation')


def archive_row(meta):
    mapping={'name':'NAME','version':'VERSION','arch':'ARCH','depends':'DEPENDS','provides':'PROVIDES','conflicts':'CONFLICTS','replaces':'REPLACES','license':'LICENSE'}
    row={key:copy.deepcopy(meta.get(field,[]) if key in ('depends','provides','conflicts','replaces','license') else meta[field][0]) for key,field in mapping.items()}
    signature=base64.b64decode(meta['PGPSIG'][0],validate=True)
    row.update(filename=meta['FILENAME'][0],sha256=meta['SHA256SUM'][0],size=int(meta['CSIZE'][0]),isize=int(meta['ISIZE'][0]),
        signature_sha256=sha(signature),signature_size=len(signature),repo=meta['repo'],source_url=copy.deepcopy(meta.get('URL',[])),
        url='https://ca.us.mirror.archlinuxarm.org/aarch64/'+meta['repo']+'/'+meta['FILENAME'][0])
    return row


def public_record(meta):
    mapping={'name':'NAME','version':'VERSION','arch':'ARCH','depends':'DEPENDS','provides':'PROVIDES','conflicts':'CONFLICTS','replaces':'REPLACES','license_metadata':'LICENSE','upstream_url':'URL','archive_filename':'FILENAME','archive_sha256':'SHA256SUM'}
    return {key:meta.get(field,[]) for key,field in mapping.items()}|dict(repository=meta.get('repo','retained-generic-builder'),
        maintenance_owner_class='maintained-upstream-ALARM; project compatibility owner unassigned',
        archive_authentication='NOT RUN by this preview; metadata hash is not archive authentication',
        source_recipe_and_license_text_audit='outstanding; license_metadata is repository/package declaration')


def validate_resolution(data,blobs):
    proposal,builder,lock,worker,parent,side,seed_meta,final_meta,repos=(data[n] for n in ('desktop-proposal.json','builder-input.json','archive-lock.json','worker-receipt.json','parent-receipt.json','binding-sidecar.json','seed-metadata.json','projection-metadata.json','repositories.json'))
    seed,final=inventory(blobs['seed.lock']),inventory(blobs['final.lock'])
    exact_keys(worker,WORKER_KEYS,'worker-schema');exact_keys(parent,PARENT_KEYS,'parent-schema')
    need(type(worker['schema']) is int and worker['schema']==1 and all(worker[key]==value for key,value in WORKER_KNOWN.items()),'known-resolver-api')
    need(type(lock['schema']) is int and lock['schema']==1 and lock['scope']=='GENERIC-desktop-data-authentication','archive-lock-schema')
    need(worker['status']=='PASS_FRESH_GENERIC_METADATA_RESOLUTION_RETAINED_SEED' and parent['status']=='PASS_FRESH_GENERIC_METADATA_RESOLUTION_PARENT' and worker['phase']=='complete','resolution-status')
    need(worker['source_sha256']==parent['source_sha256']==RESOLVER_SHA and parent['worker_receipt_sha256']==CURRENT['worker-receipt.json'],'resolution-source-proof')
    need(type(parent['worker_exit']) is int and parent['worker_exit']==0 and parent['natural_exit'] is parent['cleanup_verified'] is True,'parent-terminal')
    need(type(parent['work_seconds']) is type(parent['cleanup_seconds']) is int and parent['work_seconds']==300 and parent['cleanup_seconds']==4,'parent-budget')
    need(type(parent['observed_elapsed_seconds']) in (int,float) and math.isfinite(parent['observed_elapsed_seconds']) and 0<parent['observed_elapsed_seconds']<=304,'parent-elapsed')
    need(parent['archive_acquisition']==parent['installation']==parent['native_Asahi_M2']=='NOT RUN','parent-scope')
    need(worker['archive_acquisition']==worker['signature_authentication']==worker['installation']==worker['target_Asahi_transaction']==worker['hardware']=='NOT RUN','worker-scope')
    need(worker['counts_are_observed'] is worker['seed_held'] is True and worker['proposed_seed_changes']==[] and worker['removals']==[],'seed-conservation')
    need(proposal['builder_lock_sha256']==worker['builder_input_sha256']==lock['builder_lock_sha256']==CURRENT['builder-input.json'] and proposal['builder_inventory_sha256']==worker['seed_inventory_sha256']==CURRENT['seed.lock'],'builder-seed-binding')
    need(lock['proposal_sha256']==CURRENT['desktop-proposal.json'] and lock['preview_receipt_sha256']==CURRENT['worker-receipt.json'],'lock-proof-binding')
    need(proposal['roots']==worker['roots'] and proposal['provider_constraints']==worker['provider_constraints'] and proposal['optional_roots']==worker['optional_roots_not_selected'],'root-provider-binding')
    need(type(repos) is list and [r['name'] for r in repos]==['core','extra'] and repos==proposal['snapshots']==worker['snapshots']==lock['repository_databases'],'snapshot-binding')
    packages={}
    for row in repos:
        exact_keys(row,{'name','url','sha256','size','signed'},'snapshot-schema')
        integer(row['size'],1,DB_LIMIT);need(row['signed'] is False and row['url']=='https://ca.us.mirror.archlinuxarm.org/aarch64/'+row['name']+'/'+row['name']+'.db','snapshot-policy')
        raw=blobs[row['name']+'.db'];need(len(raw)==row['size'] and sha(raw)==row['sha256'],'snapshot-body')
        for name,meta in database(raw,row['name']).items():packages.setdefault(name,meta)
    exact_keys(seed_meta,seed,'seed-metadata-membership');exact_keys(final_meta,final,'projection-metadata-membership')
    for name,version in final.items():metadata(final_meta[name],name,version)
    need(all(name in final and final[name]==version and final_meta[name]==seed_meta[name] for name,version in seed.items()),'all-seed-metadata-held')
    rows=lock['packages'];need(type(rows) is list and rows==sorted(rows,key=lambda row:row['name']),'canonical-archive-order')
    additions={row['name']:row for row in rows};need(len(additions)==len(rows) and set(additions)==set(final)-set(seed),'complete-addition-membership')
    for name,row in additions.items():
        for key in ('size','isize','signature_size'):integer(row[key],0 if key=='isize' else 1,300_000_000 if key!='signature_size' else 65536)
        need(all(type(row[key]) is str and HEX.fullmatch(row[key]) for key in ('sha256','signature_sha256')),'archive-hash-types')
        need(name in packages and final[name]==row['version'] and final_meta[name]==packages[name] and row==archive_row(packages[name]),'complete-archive-database-metadata')
    need(worker['full_candidate_inventory']==[public_record(meta) for name,meta in sorted(final_meta.items())],'all-candidate-metadata')
    expected_changes=[dict(name=name,old_version=None,version=row['version'],kind='add',download_bytes=row['size']) for name,row in sorted(additions.items())]
    need(worker['changes']==expected_changes,'complete-transaction-changes')
    for row in proposal['roots']+proposal['provider_constraints']+proposal['baseline_editors']:
        need(final.get(row['name'])==row['version'],'selected-root-provider-editor')
    relations=worker['dependency_relationships'];need(type(relations) is list and 0<len(relations)<=4096,'relation-bound')
    for row in relations:exact_keys(row,{'package','relation','provider'},'relation-schema')
    need([(row['package'],row['relation']) for row in relations]==[(name,dep) for name,meta in sorted(final_meta.items()) for dep in meta.get('DEPENDS',[])] and all(row['provider'] in final for row in relations),'all-provider-relations')
    need(worker['unsatisfied']==[] and worker['conflicts']==[] and worker['print_exit']==0 and type(worker['print_exit']) is int and worker['print_diagnostic']=='','resolution-closure')
    deps=sorted({row['relation'] for row in relations});chunks=[deps[i:i+200] for i in range(0,len(deps),200)]
    commands=worker['commands'];need(type(commands) is list and len(commands)==1+len(chunks),'complete-command-count')
    prefix=['/usr/bin/pacman']
    for flag,name in (('--config','pacman.conf'),('--root','root'),('--dbpath','db'),('--cachedir','cache'),('--gpgdir','gpg'),('--hookdir','hooks'),('--logfile','pacman.log')):prefix += [flag,CONTEXT+'/'+name]
    prefix += ['--arch','aarch64','--color','never']
    targets=[r['name']+'='+r['version'] for r in proposal['roots']+proposal['provider_constraints']]
    for index,command in enumerate(commands):
        exact_keys(command,{'operation','slot','argv','state','exit','natural_exit','cleanup_verified','stdout_bytes','stderr_bytes'},'command-schema')
        need(command['state']=='RETURNED' and type(command['exit']) is int and command['exit']==0 and command['natural_exit'] is command['cleanup_verified'] is True,'command-terminal')
        integer(command['stdout_bytes'],0,1024**2);integer(command['stderr_bytes'],0,1024**2)
        print_bytes=sum(len(('\t'.join((row['name'],row['version'],row['repo'],row['arch'],str(row['size']),row['sha256']))+'\n').encode()) for row in rows)
        need((index>0 or command['stderr_bytes']==0) and command['stdout_bytes']==(print_bytes if index==0 else 0),'command-byte-counts')
        expected=prefix+(['--sync','--print','--needed','--noconfirm','--print-format','%n\t%v\t%r\t%a\t%s\t%h']+targets if index==0 else ['--deptest']+chunks[index-1])
        need(command['argv']==expected and command['operation']==('preview' if index==0 else 'deps') and command['slot']==('print' if index==0 else 'deptest-'+str(index-1)),'exact-private-command')
    counts=dict(seed=len(seed),transaction=len(rows),final=len(final),relations=len(relations),unique_relations=len(deps),commands=len(commands))
    for key,count in [('initial_count',len(seed)),('final_count',len(final)),('retained_seed_count',len(seed)),('observed_transaction_count',len(rows)),('observed_added_count',len(rows)),('observed_changed_count',0)]:
        need(type(worker[key]) is int and worker[key]==count,'observed-worker-count')
    exact_keys(side,{'schema_version','purpose','worker_receipt_sha256','parent_receipt_sha256','transaction_archive_rows_file_sha256','archive_package_rows_canonical_sha256','package_rows_count','canonical_encoding','archive_lock_sha256','actor_emitted_package_row_digest','outer_or_completion_proof','Root_admission'},'sidecar-schema')
    need(side['canonical_encoding']=='Name-sorted package-row array, json.dumps(sort_keys=True,separators=(comma,colon),allow_nan=False) plus newline','sidecar-canonical-domain')
    need(type(side['schema_version']) is int and side['schema_version']==1 and side['purpose']=='DERIVED_METADATA_SIDECAR_NOT_ACTOR_EMITTED_OR_ADMISSION' and side['actor_emitted_package_row_digest'] is False and side['outer_or_completion_proof'] is side['Root_admission'] is None,'derived-not-actor-proof')
    transaction_file=(json.dumps(dict(packages=rows),sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    need(side['worker_receipt_sha256']==CURRENT['worker-receipt.json'] and side['parent_receipt_sha256']==CURRENT['parent-receipt.json'] and side['transaction_archive_rows_file_sha256']==sha(transaction_file) and side['archive_lock_sha256']==CURRENT['archive-lock.json'],'sidecar-proof-joins')
    need(type(side['package_rows_count']) is int and side['package_rows_count']==len(rows) and side['archive_package_rows_canonical_sha256']==sha(encoded(rows))==ROWS_SHA,'canonical-full-package-rows')
    need(builder['keyring_files']==lock['keyring_files'] and builder['signer_fingerprint']==lock['signer_fingerprint']=='68B3537F39A313B3E574D06777193F152BDBE6A6','held-key-policy')
    return counts


def prepare(profile,blobs,legacy):
    required={'schema_version','scope','selected_for_release','adapter_sha256','files_sha256','helper_sha256','archive_package_rows_canonical_sha256','observed_counts','resolution_proof_scope','trust_scope','operational_selection'}
    exact_keys(profile,required,'profile-schema')
    need(type(profile['schema_version']) is int and profile['schema_version']==2 and profile['scope']==SCOPE and profile['selected_for_release'] is False and profile['operational_selection'] is None,'profile-scope')
    source=Path(__file__).read_bytes()
    need(profile['adapter_sha256']==sha(source) and profile['files_sha256']==CURRENT and profile['helper_sha256']==HELPERS and profile['archive_package_rows_canonical_sha256']==ROWS_SHA,'profile-source-inputs')
    need(profile['resolution_proof_scope']=='actual f481 worker and parent only; derived sidecar is not outer/completion telemetry' and profile['trust_scope']==TRUST,'profile-trust-scope')
    exact_keys(blobs,CURRENT,'input-membership')
    need(sum(len(raw) for raw in blobs.values() if type(raw) is bytes)<=TOTAL_LIMIT,'input-total-budget')
    for name,pin in CURRENT.items():
        raw=blobs[name];need(type(raw) is bytes and 0<len(raw)<=(DB_LIMIT if name.endswith('.db') else JSON_LIMIT) and sha(raw)==pin,'exact-input-bytes')
    data={name:document(raw) for name,raw in blobs.items() if name.endswith('.json')}
    counts=validate_resolution(data,blobs)
    exact_keys(profile['observed_counts'],counts,'profile-count-membership')
    need(all(type(profile['observed_counts'][key]) is int and profile['observed_counts'][key]==value for key,value in counts.items()),'profile-derived-counts')
    effective=copy.deepcopy(data['archive-lock.json'])
    legacy.validate(effective)  # Held fixed-count/size/key/URL API remains unchanged.
    return effective


def validate_authentication_result(result,effective,legacy):
    required={'archive_lock_sha256','bounded_bytes','builder_lock_sha256','download','failures','gpg_version','hardware','installation','key_import','keyring_files','native_helper_sha256','package_count','packages','preview_receipt_sha256','proposal_sha256','public_only_gpg_home_removed','repository_databases','schema','scope','signer_fingerprint','source_sha256','status','target_Asahi_transaction','verified_count'}
    exact_keys(result,required,'authentication-summary-schema');count=len(effective['packages'])
    need(type(result['schema']) is int and result['schema']==1 and result['scope']=='GENERIC-desktop-data-authentication','authentication-scope')
    for key in ('hardware','installation','target_Asahi_transaction'):need(result[key]=='NOT RUN','authentication-not-installation')
    need(result['source_sha256']==HELPERS['scripts/port/authenticate.py'] and result['native_helper_sha256']==HELPERS['scripts/ci/native_arm.py'],'authentication-helper-pins')
    for key in ('builder_lock_sha256','proposal_sha256','preview_receipt_sha256','repository_databases','keyring_files','signer_fingerprint'):
        need(result[key]==effective[key],'authentication-input-binding')
    need(result['archive_lock_sha256']==sha(encoded(effective)) and result['public_only_gpg_home_removed'] is True,'authentication-lock-cleanup')
    need(type(result['bounded_bytes']) is int and result['bounded_bytes']==sum(row['size']+row['signature_size'] for row in effective['packages']),'authentication-byte-total')
    need(result['download']=='read-only HTTPS archives/signatures into private cache' and type(result['gpg_version']) is str and result['gpg_version'].startswith('gpg (GnuPG) '),'authentication-tool-scope')
    exact_keys(result['key_import'],{'exit','secret_keys_generated','ownertrust_modified'},'key-import-schema')
    need(type(result['key_import']['exit']) is int and result['key_import']['exit']==0 and result['key_import']['secret_keys_generated'] is result['key_import']['ownertrust_modified'] is False,'public-key-import-only')
    need(type(result['verified_count']) is type(result['package_count']) is int and result['verified_count']==result['package_count']==count and result['status']=='PASS-'+str(count)+'-authenticated-generic-archives' and result['failures']==[],'authentication-terminal')
    rows=result['packages'];need(type(rows) is list and len(rows)==count and len({row['name'] for row in rows})==count,'authentication-membership')
    by_name={row['name']:row for row in rows}
    need(set(by_name)=={row['name'] for row in effective['packages']},'authentication-package-set')
    for expected in effective['packages']:
        row=by_name[expected['name']]
        exact_keys(row,{'name','version','archive_sha256','signature_sha256','status','gpg','archive_observations'},'authentication-row-schema')
        need(row['status']=='PASS-authenticated-data' and row['version']==expected['version'] and row['archive_sha256']==expected['sha256'] and row['signature_sha256']==expected['signature_sha256'],'authentication-row')
        exact_keys(row['gpg'],{'exit','status','diagnostic'},'gpg-protocol-schema')
        need(type(row['gpg']['exit']) is int and row['gpg']['exit']==0 and all(type(row['gpg'][key]) is str and len(row['gpg'][key])<=65536 for key in ('status','diagnostic')),'gpg-protocol-types')
        legacy.status(types.SimpleNamespace(returncode=row['gpg']['exit'],stdout=row['gpg']['status']))
        observed=row['archive_observations']
        exact_keys(observed,{'file','sha256','path_count','ELF_count','hook_scriptlet_count','package_execution'},'inspection-protocol-schema')
        need(observed['file']=='observations/'+expected['name']+'.json' and type(observed['sha256']) is str and HEX.fullmatch(observed['sha256']) and observed['package_execution']=='NOT RUN','inspection-binding')
        for key in ('path_count','ELF_count','hook_scriptlet_count'):integer(observed[key],0,400000)
        need(observed['ELF_count']<=observed['path_count'],'inspection-counts')


def execute(profile,blobs,legacy,public_keys,output):
    """Only a separately Root-selected whole-process plan may invoke this seam."""
    effective=prepare(profile,blobs,legacy);count=len(effective['packages'])
    need(os.getuid()==os.geteuid()!=0,'ordinary-executor')
    output=Path(output).absolute();public_keys=Path(public_keys).absolute()
    need(not output.exists() and not any(p.is_symlink() for p in (output,*output.parents)),'new-output')
    info=output.parent.stat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o022,'owned-output-parent')
    need(not any(p.is_symlink() for p in (public_keys,*public_keys.parents)) and all(not (public_keys/row['filename']).is_symlink() for row in effective['keyring_files']),'public-key-path')
    output.mkdir(mode=0o700)
    receipt=dict(schema_version=1,scope=SCOPE,status='RUNNING',profile_canonical_sha256=sha(encoded(profile)),inputs_sha256=CURRENT,
        archive_lock_raw_sha256=CURRENT['archive-lock.json'],effective_archive_lock_canonical_sha256=sha(encoded(effective)),
        archive_package_rows_canonical_sha256=ROWS_SHA,expected_count=count,authenticated_count=0,
        metadata_parent_proof_sha256=CURRENT['parent-receipt.json'],whole_invocation_proof='SEPARATE_ROOT_SELECTED_GUARDIAN_REQUIRED',
        whole574_trust='NOT_ESTABLISHED',Asahi_M2_source_legal_release='NOT_ESTABLISHED')
    try:
        result=legacy.authenticate(effective,legacy.CACHE,public_keys,output/'authentication',sha(encoded(effective)))
        need(type(result) is dict,'authentication-summary')
        reported=result.get('verified_count')
        if type(reported) is int and 0<=reported<=count:receipt['authenticated_count']=reported
        validate_authentication_result(result,effective,legacy)
        receipt.update(authenticated_count=count,status='PASS-current2-maintained-authenticated-archives')
    except BaseException as error:
        receipt.update(status='FAIL',error_kind=type(error).__name__ if type(error) in (ValueError,OSError,KeyError,TypeError,KeyboardInterrupt,SystemExit) else 'OTHER')
        try:legacy.native.save(output/'maintained-binding.json',receipt)
        except BaseException:pass  # Preserve the primary actor/control failure.
        raise
    legacy.native.save(output/'maintained-binding.json',receipt);return receipt


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',type=Path,required=True);parser.add_argument('--profile-sha256',required=True)
    parser.add_argument('--inputs',type=Path,required=True);parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--execute',action='store_true');parser.add_argument('--public-key-directory',type=Path);parser.add_argument('--output',type=Path)
    args=parser.parse_args(argv)
    try:
        profile=document(read(args.profile,args.profile_sha256));blobs={name:read(args.inputs/name,pin,DB_LIMIT if name.endswith('.db') else JSON_LIMIT) for name,pin in CURRENT.items()}
        legacy=engine(args.source_root);effective=prepare(profile,blobs,legacy)
        if args.execute:
            need(args.public_key_directory is not None and args.output is not None,'execution-paths')
            result=execute(profile,blobs,legacy,args.public_key_directory,args.output)
        else:
            need(args.public_key_directory is None and args.output is None,'preview-only-paths')
            result=dict(status='READY_SOURCE_PROPOSAL_REQUIRES_SEPARATE_ROOT_SELECTED_OPERATION',packages=len(effective['packages']),
                projection=len(inventory(blobs['final.lock'])),archive_lock_raw_sha256=CURRENT['archive-lock.json'],
                effective_archive_lock_canonical_sha256=sha(encoded(effective)),archive_package_rows_canonical_sha256=ROWS_SHA,actual_authentication='NOT RUN',Root_selection=None)
        print(json.dumps(result,sort_keys=True));return int(result.get('status')=='FAIL')
    except (ValueError,OSError,KeyError,TypeError,RecursionError,subprocess.SubprocessError):
        print('REFUSED current2 Source/profile/input/metadata boundary');return 2


if __name__=='__main__':raise SystemExit(main())
