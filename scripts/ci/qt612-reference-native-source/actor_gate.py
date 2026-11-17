# SPDX-License-Identifier: MIT
"""Explicit fresh Root capacity/runtime gate; defines no actor or issuer."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

POLICY_PIN = dict(bytes=1786,sha256='937d2c05b96df99dde7097d10647c5ea96aea38d3442ffcbca2f3647dd643ece')
F_COMMIT = '69a02851b87ca29daf2e197101b66bf75ff61889'


def need(value,why):
    if not value:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def validate_documents(capacity,runtime,*,source_map,policy_pin,context,now):
    keys = {'kind','issued_by','accepted','source','ref','source_map_sha256','policy_pin','recipe_commit',
            'nonce','created_utc','expires_utc','run','attempt','input_plan_sha256'}
    flags = {'readonly_filesystem_verified','owned_controller_kernel_verified','empty_owned_daemon_verified',
             'signed_dependency_inventory_verified','provider_gpg_verified'}
    for value,kind in ((capacity,'ROOT_QT612_EXPERIMENTAL_CAPACITY_V1'),(runtime,'ROOT_QT612_PRODUCER_RUNTIME_V1')):
        need(type(value) is dict and set(value) == keys|(flags if value is runtime else set()),'CLOSED_ROOT_QT612_DOCUMENT')
        need(value['kind'] == kind and value['issued_by'] == 'Root' and value['accepted'] is True,'ROOT_QT612_CAPACITY_UNISSUED')
        need(value['recipe_commit'] == F_COMMIT and value['source_map_sha256'] == source_map
             and value['policy_pin'] == policy_pin == POLICY_PIN,'EXACT_QT612_SOURCE_POLICY')
        need(type(value['created_utc']) is int and type(value['expires_utc']) is int
             and value['created_utc'] <= now < value['expires_utc']
             and 0 < value['expires_utc']-value['created_utc'] <= 15120,'FRESH_QT612_CAPACITY_WINDOW')
        need(type(value['source']) is str and re.fullmatch('[0-9a-f]{40}',value['source'])
             and value['source'] == context.get('GITHUB_SHA') and value['ref'] == context.get('GITHUB_REF')
             and value['ref'].startswith('refs/heads/') and re.fullmatch('[1-9][0-9]{1,19}',value['run'] or '')
             and value['run'] == context.get('GITHUB_RUN_ID')
             and value['attempt'] == context.get('GITHUB_RUN_ATTEMPT') == '1'
             and re.fullmatch('[0-9a-f]{32}',value['nonce'] or '')
             and re.fullmatch('[0-9a-f]{64}',value['input_plan_sha256'] or ''),'ACTUAL_QT612_SINGLE_RUN_BINDING')
    need(all(capacity[k] == runtime[k] for k in keys-{'kind'})
         and all(runtime[k] is True for k in flags),'SAME_ROOT_QT612_CAPACITY_AND_RUNTIME')
    need(context.get('GITHUB_REPOSITORY') == 'Gabriel-Kahen/cachy-asahi'
         and context.get('GITHUB_EVENT_NAME') == 'workflow_dispatch','ACTUAL_QT612_DISPATCH_CONTEXT')
    return dict(nonce=runtime['nonce'],actor_truth='EXTERNALLY_ROOT_ISSUED_NOT_AUTHENTICATED_BY_JSON')


def read_selected(path,sha,cap=65536):
    need(type(path) is str and type(sha) is str and re.fullmatch('[0-9a-f]{64}',sha),'EXTERNAL_QT612_DOCUMENT_PIN_REQUIRED')
    p = Path(path)
    need(p.is_absolute() and p == p.resolve() and not any(x.is_symlink() for x in (p,*p.parents)),'ORDINARY_QT612_ROOT_DOCUMENT')
    fd = os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap
             and not before.st_mode&0o022,'BOUNDED_QT612_ROOT_DOCUMENT')
        raw = os.read(fd,cap+1)
        attrs = lambda s:tuple(getattr(s,k) for k in ('st_dev','st_ino','st_size','st_mode','st_nlink','st_mtime_ns','st_ctime_ns'))
        need(len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == sha
             and attrs(before) == attrs(os.fstat(fd)) == attrs(p.lstat()),'WHOLE_QT612_ROOT_DOCUMENT')
    finally:os.close(fd)
    def pairs(rows):
        result = {}
        for k,v in rows:need(k not in result,'DUPLICATE_QT612_DOCUMENT_KEY');result[k] = v
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'NONFINITE_QT612_DOCUMENT'))


def require_actual_capacity(source_root=None):
    """Called only at projected actor entry, before its first Docker command."""
    need(os.getuid() == os.geteuid() > 0 and os.uname().machine in ('aarch64','arm64'), 'ACTUAL_ORDINARY_NATIVE_ARM_REQUIRED')
    root = Path(__file__).resolve().parents[3] if source_root is None else Path(source_root).resolve()
    expected = os.environ.get('QT612_SOURCE_MAP_SHA256')
    need(type(expected) is str and re.fullmatch('[0-9a-f]{64}',expected),'ROOT_QT612_SOURCE_MAP_UNBOUND')
    mapping = read_selected(str(root/'source-map.json'),expected,4*1024**2)
    need(mapping.get('kind') == 'QT612_REFERENCE_PRODUCER_SOURCE_DATA_V1'
         and mapping.get('input_plan_complete') is True and mapping.get('Root_acceptance') is None
         and mapping.get('actual') and all(v is None for v in mapping['actual'].values()),'COMPLETE_QT612_INPUT_SOURCE_REQUIRED')
    verify_source_files(root,mapping)
    capacity = read_selected(os.environ.get('QT612_CAPACITY_PATH'),os.environ.get('QT612_CAPACITY_SHA256'))
    runtime = read_selected(os.environ.get('QT612_RUNTIME_PATH'),os.environ.get('QT612_RUNTIME_SHA256'))
    state = validate_documents(capacity,runtime,source_map=expected,policy_pin=POLICY_PIN,context=os.environ,now=int(time.time()))
    need(capacity['input_plan_sha256'] == mapping['files']['input-plan.DATA.json']['sha256'], 'SAME_QT612_INPUT_PLAN_BODY')
    need(os.environ.get('CACHY_QT612_REFERENCE_NONCE') == state['nonce'],'SAME_QT612_BUILD_NONCE')
    return state


def verify_source_files(root,mapping):
    rows = mapping['files']
    need(type(rows) is dict and 32 <= len(rows) <= 128
         and sum(r['bytes'] for r in rows.values()) <= 256*1024**2,'BOUNDED_QT612_ACTOR_SOURCE')
    found,pending,nodes = set(),[root],0
    while pending:
        parent = pending.pop()
        for path in parent.iterdir():
            if parent == root and path.name == '.git':
                need(not path.is_symlink(),'ORDINARY_CHECKOUT_METADATA_ONLY');continue
            nodes += 1;need(nodes <= 512 and not path.is_symlink(),'BOUNDED_QT612_ACTOR_NAMESPACE')
            if path.is_dir():pending.append(path)
            else:need(path.is_file(),'ORDINARY_QT612_SOURCE_LEAF');found.add(path.relative_to(root).as_posix())
    need(found == set(rows)|{'source-map.json'},'COMPLETE_QT612_ACTOR_SOURCE')
    for name,row in rows.items():
        path = root/name
        need(type(name) is str and not Path(name).is_absolute() and '..' not in Path(name).parts
             and set(row) == {'bytes','sha256','mode'} and row['mode'] == 0o644
             and type(row['bytes']) is int and 0 <= row['bytes'] <= 512*1024**2
             and re.fullmatch('[0-9a-f]{64}',row['sha256']),'EXACT_QT612_ACTOR_SOURCE_REFERENCE')
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o644
                 and before.st_size == row['bytes'],'ORDINARY_QT612_ACTOR_SOURCE_FILE')
            h,size = hashlib.sha256(),0
            while block := os.read(fd,min(1024**2,row['bytes']+1-size)):
                size += len(block);need(size <= row['bytes'],'QT612_ACTOR_SOURCE_GREW');h.update(block)
            attrs = lambda s:tuple(getattr(s,k) for k in ('st_dev','st_ino','st_size','st_mode','st_nlink','st_mtime_ns','st_ctime_ns'))
            need(dict(bytes=size,sha256=h.hexdigest()) == {k:row[k] for k in ('bytes','sha256')}
                 and attrs(before) == attrs(os.fstat(fd)) == attrs(path.lstat()),'WHOLE_QT612_ACTOR_SOURCE_BODY')
        finally:os.close(fd)
