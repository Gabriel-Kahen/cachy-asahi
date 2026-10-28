#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Callable single-file batch with a separately selected Root authority.

Default plan mode never opens image/archive/tool contents. Execute mode requires
an externally pinned Root grant and future candidate-source admission.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import signal
import stat
import sys
import time
import types

MIB = 1024**2
FIELDS = ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
POLICY = dict(shared_work_bytes=8*1024**3, absolute_seconds=1200, command_seconds=20,
              cleanup_seconds=2, addressspace_bytes=2*1024**3, cpu_seconds=1195,
              report_bytes=256*MIB, metadata_bytes=8*MIB, stderr_bytes=65536,
              file_bytes=512*MIB, chunk_bytes=MIB, nodes=500000)
SCOPE='s01-filesystem-license-batch-v1'
PROPOSAL_SHA='b4a8d41d1f7e7cc00c44b6a706e9f4eb28586d15c5e3e123c5762eef0dc90222'
SELECTED_PATH='usr/share/licenses/filesystem/LICENSE'
PARTS=SELECTED_PATH.split('/')
PACKAGE=dict(name='filesystem',version='2025.10.12-1',arch='any')
BATCH=dict(maximum_calls=31,maximum_CAT_calls=1,archive_parse_count=1,directory_frames=5,selected_file_bytes=MIB,regular_nlink=1,child_stat_reuse=False)
TOOL_SHA='4f53cd7be7a9f23c526007bd846b4c09b040be364504959dbf4273b5591d3ef6'
IMAGE_SHA='76f95dae6180bc4a45ffdeaccec26681d75b2207b90062064fcd2a845adbf9db'
IMAGE_SIZE=3680501760
ARCHIVE_SHA='228b63ef4a88501a68856231a19325a1ad31d92016a692d0a8be181edc70703f'
OWNERSHIP_SHA='f12aba8413c5d8a5de9419f4321381cde0b1ca50a4d9e1c4f40421768952e994'
INVENTORY_SHA='5c1630b5cdf07898118979895682c3a3b705e416c9840ada4e1a5193dccd6941'
SOURCE4={'installed_payload_correspondence.py':'3a71ba896700f72130e35a56845516bd9c42de0b1b0fd782b79829b37ac262a7',
         'installed_payload_image_reader.py':'485913978598a444f86de17c7583e14b96fb7fdb9b25334f4f59d054af09c16a',
         'test_installed_payload_correspondence.py':'4b7652b408c28f1fd4d19591804b3c059e3929197c14d31f13f80e009cf480ae',
         'test_installed_payload_image_reader.py':'511718296b0344f76a0b47c2705df92438eeb5404ff1af5b0eb70ff0dd770219'}
MISSING=[dict(name='networkmanager',version='1.58.1-1',arch='aarch64',directory='networkmanager-1.58.1-1'),
         dict(name='perl',version='5.42.2-2',arch='aarch64',directory='perl-5.42.2-2')]
ACCEPTANCE = dict(installed_payload_verified=False, image_issuer_authentication_accepted=False,
                  independent_key_owner_trust_accepted=False, installation_accepted=False,
                  hardware_accepted=False, complete_correspondence_accepted=False)


def need(value, code):
    if not value:
        raise ValueError(code)


def check_deadline(deadline):
    if deadline is not None:
        need(type(deadline) in (int,float) and math.isfinite(deadline) and time.monotonic() < deadline, 'absolute-job-deadline')


def identity(path):
    info = Path(path).lstat()
    return [getattr(info, name) for name in FIELDS]


def regular_reference(ref, maximum):
    need(type(ref) is dict and set(ref) == {'path','size','sha256','identity'}, 'reference-shape')
    need(type(ref['path']) is str, 'reference-path')
    path = Path(ref['path'])
    need(path.is_absolute() and '..' not in path.parts and str(path) == ref['path'], 'reference-path')
    need(type(ref['size']) is int and 0 < ref['size'] <= maximum and
         type(ref['sha256']) is str and len(ref['sha256']) == 64 and
         all(c in '0123456789abcdef' for c in ref['sha256']), 'reference-value')
    ids = ref['identity']
    need(type(ids) is list and len(ids) == 9 and all(type(n) is int and n >= 0 for n in ids) and
         stat.S_ISREG(ids[2]) and ids[3] == 1 and ids[6] == ref['size'], 'reference-identity')
    return ref


def captured(ref, maximum, deadline=None):
    """Read only bounded source/JSON; never adopt an unknown initial FD identity."""
    check_deadline(deadline);regular_reference(ref,maximum);path=Path(ref['path'])
    need(all(stat.S_ISDIR(p.lstat().st_mode) for p in path.parents),'reference-ancestor')
    entry=dict(fd=None,inode=None)
    try:
        old=None
        if deadline is not None:
            old=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM,signal.SIGALRM})
        try:
            entry['fd']=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            info=os.fstat(entry['fd']);before=[getattr(info,name) for name in FIELDS]
            need(before==ref['identity'],'reference-drift')
            entry['inode']=report_inode(info)
        finally:
            if old is not None:restore_report_mask(old)
        data=bytearray()
        while len(data)<=ref['size']:
            check_deadline(deadline);report_fd(entry)
            block=os.read(entry['fd'],min(65536,ref['size']+1-len(data)))
            if not block:break
            data.extend(block)
        need(len(data)==ref['size'] and hashlib.sha256(data).hexdigest()==ref['sha256'],'reference-hash')
        need([getattr(os.fstat(entry['fd']),name) for name in FIELDS]==before==identity(path),'reference-drift')
        check_deadline(deadline);return bytes(data)
    finally:
        primary=sys.exc_info()[1];chosen=primary
        def fault(error):
            nonlocal chosen
            chosen=report_failure(chosen,error,'owned source/JSON descriptor disposal unproved')
        close_report_fd(entry,fault)
        if chosen is not None and chosen is not primary:raise chosen


def closed_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False,'nonfinite'))
    need(type(value) is dict, 'json-object')
    return value


def json_file(path, expected_sha, deadline=None):
    info = Path(path).lstat()
    ref = dict(path=str(Path(path).absolute()), size=info.st_size, sha256=expected_sha, identity=identity(path))
    result = closed_json(captured(ref, 8*MIB, deadline))
    check_deadline(deadline)
    return result


def validate_selection(value):
    fields={'schema_version','scope','proposal_sha256','reader','core','source4','tool_contract','image','ownership','inventory',
            'archive','selected_package','selected_path','batch','policy','required_tuples','missing_tuples',
            'baseline_available_archives','signer_joins_unresolved','full_walk_selected','full_correspondence_selected','full341_accepted','output_path'}
    need(type(value) is dict and set(value)==fields and type(value['schema_version']) is int and value['schema_version']==1 and
         value['scope']==SCOPE and value['proposal_sha256']==PROPOSAL_SHA,'selection-shape')
    need(type(value['policy']) is dict and value['policy']==POLICY and all(type(n) is int for n in value['policy'].values()),'policy-drift')
    need(type(value['batch']) is dict and set(value['batch'])==set(BATCH) and
         all(type(value['batch'][k]) is type(v) and value['batch'][k]==v for k,v in BATCH.items()),'batch-scope-drift')
    need(value['selected_path']==SELECTED_PATH and type(value['selected_package']) is dict and
         value['selected_package']==PACKAGE and all(type(v) is str for v in value['selected_package'].values()) and
         all(value[k] is False for k in ('full_walk_selected','full_correspondence_selected','full341_accepted')),'scope-drift')
    for key,maximum in (('reader',MIB),('core',MIB),('tool_contract',8*MIB),('image',4*1024**3),('ownership',8*MIB),('inventory',8*MIB)):
        regular_reference(value[key],maximum)
    need(value['reader']['sha256']==SOURCE4['installed_payload_image_reader.py'] and
         value['core']['sha256']==SOURCE4['installed_payload_correspondence.py'] and
         value['tool_contract']['sha256']==TOOL_SHA and value['image']['sha256']==IMAGE_SHA and value['image']['size']==IMAGE_SIZE and
         value['ownership']['sha256']==OWNERSHIP_SHA and value['inventory']['sha256']==INVENTORY_SHA,'fixed-pins')
    refs=value['source4']
    need(type(refs) is list and len(refs)==4,'source-four')
    names=set()
    for ref in refs:
        regular_reference(ref,MIB);name=Path(ref['path']).name
        need(name in SOURCE4 and name not in names and ref['sha256']==SOURCE4[name],'source-four-pins');names.add(name)
    need(next(ref for ref in refs if Path(ref['path']).name=='installed_payload_image_reader.py')==value['reader'] and
         next(ref for ref in refs if Path(ref['path']).name=='installed_payload_correspondence.py')==value['core'],'source-four-binding')
    row=value['archive'];need(type(row) is dict and set(row)=={'tuple','reference'} and type(row['tuple']) is dict and
                            row['tuple']==PACKAGE and all(type(v) is str for v in row['tuple'].values()),'archive-tuple')
    regular_reference(row['reference'],300_000_000)
    need(row['reference']['size']==14864 and row['reference']['sha256']==ARCHIVE_SHA,'archive-pin')
    need(type(value['required_tuples']) is list and len(value['required_tuples'])==261 and
         type(value['baseline_available_archives']) is int and value['baseline_available_archives']==259 and
         type(value['signer_joins_unresolved']) is int and value['signer_joins_unresolved']==26 and
         type(value['missing_tuples']) is list and value['missing_tuples']==MISSING,'incomplete-baseline-context')
    names=set()
    for row in value['required_tuples']:
        need(type(row) is dict and set(row)=={'name','version','arch','directory'} and all(type(v) is str for v in row.values()) and
             row['name'] not in names and row['directory']==row['name']+'-'+row['version'] and row['arch'] in ('aarch64','any'),'required-tuple')
        names.add(row['name'])
    need(any({k:row[k] for k in PACKAGE}==PACKAGE for row in value['required_tuples']) and
         all(row in value['required_tuples'] for row in MISSING),'baseline-tuple-membership')
    need(type(value['output_path']) is str,'output-path')
    output=Path(value['output_path'])
    need(output.is_absolute() and '..' not in output.parts and str(output)==value['output_path'],'output-path')
    return value


def metadata_guard(selection,deadline=None):
    """No payload reads; exact selected metadata and closed v3 tool/link references."""
    for ref in [selection['image'],selection['ownership'],selection['inventory'],selection['archive']['reference']]:
        check_deadline(deadline)
        need(identity(ref['path'])==ref['identity'] and
             all(stat.S_ISDIR(p.lstat().st_mode) for p in Path(ref['path']).parents),'input-metadata-drift')
    contract=closed_json(captured(selection['tool_contract'],8*MIB,deadline))
    need(contract.get('schema_version')==2 and type(contract.get('schema_version')) is int and
         contract.get('approved') is False and contract.get('actors')=='NOT RUN','tool-contract-scope')
    for row in contract['binary_and_recursive_DT_NEEDED'].values():
        check_deadline(deadline);ref=row['reference'];regular_reference(ref,512*MIB)
        need(identity(ref['path'])==ref['identity'],'tool-metadata-drift')
        for link in row['links']:
            need(identity(link['path'])==link['identity'] and os.readlink(link['path'])==link['target'],'tool-link-drift')
    for item in contract['interpreter_links']:
        for link in item['ancestor_links']:
            need(os.readlink(link['path'])==link['target'],'interpreter-link-drift')
    return contract


def grant_checked(grant,selection_sha,harness_sha,selection):
    fields={'schema_version','approved','scope','selection_sha256','harness_sha256','reader_sha256','core_sha256',
            'tool_contract_sha256','image_sha256','inventory_sha256','ownership_sha256','archive_sha256',
            'output_path','policy','batch','selected_package','selected_path','full_correspondence_selected'}
    need(type(grant) is dict and set(grant)==fields and type(grant['schema_version']) is int and grant['schema_version']==1 and
         grant['approved'] is True,'root-grant-not-selected')
    expected=dict(scope=SCOPE,selection_sha256=selection_sha,harness_sha256=harness_sha,
                  reader_sha256=selection['reader']['sha256'],core_sha256=selection['core']['sha256'],
                  tool_contract_sha256=selection['tool_contract']['sha256'],image_sha256=selection['image']['sha256'],
                  inventory_sha256=selection['inventory']['sha256'],ownership_sha256=selection['ownership']['sha256'],
                  archive_sha256=selection['archive']['reference']['sha256'],output_path=selection['output_path'],policy=POLICY,
                  batch=BATCH,selected_package=PACKAGE,selected_path=SELECTED_PATH,full_correspondence_selected=False)
    need(all(type(grant[k]) is type(v) and grant[k]==v for k,v in expected.items()) and
         all(type(v) is int for v in grant['policy'].values()) and
         all(type(grant['batch'][k]) is type(v) for k,v in BATCH.items()),'root-grant-binding')


def metadata_inputs(selection,reader,ledger,deadline):
    inventory=closed_json(captured(selection['inventory'],8*MIB,deadline))
    ownership=closed_json(captured(selection['ownership'],8*MIB,deadline))
    owners=ledger.core.image_ownership(ownership,inventory,selection['inventory']['sha256'],selection['image']['sha256'])
    actual=[owners[name]['identity'] for name in owners]
    expected=[{k:row[k] for k in PACKAGE} for row in selection['required_tuples']]
    need(sorted(actual,key=lambda row:row['name'])==sorted(expected,key=lambda row:row['name']),'inventory-baseline-tuples')
    need(owners.get('filesystem',{}).get('identity')==PACKAGE and SELECTED_PATH in owners['filesystem']['files'] and
         [name for name,row in owners.items() if SELECTED_PATH in row['files']]==['filesystem'],'selected-ownership')
    metadata=next(row['metadata'] for row in inventory['packages'] if row['metadata']['NAME']==['filesystem'])
    need(metadata.get('LICENSE')==['0BSD'] and metadata.get('DEPENDS')==['iana-etc'],'selected-declared-license-dependencies')
    ledger.check();check_deadline(deadline)
    return dict(owner=PACKAGE,owned_package_paths=len(owners['filesystem']['files']),declared_license=['0BSD'],dependencies=['iana-etc'])


def load_reader(selection, deadline):
    for ref in selection['source4']:
        captured(ref, MIB, deadline)
    raw = captured(selection['reader'], MIB, deadline)
    need(stat.S_IMODE(selection['reader']['identity'][2]) == 0o644, 'reader-mode')
    module = types.ModuleType('root_selected_s01_reader'); module.__file__ = selection['reader']['path']
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    need(module.CORE_SHA == selection['core']['sha256'] and
         module.TOOL_CONTRACT_SHA == selection['tool_contract']['sha256'] and
         module.IMAGE_SHA == selection['image']['sha256'] and module.IMAGE_SIZE == selection['image']['size'], 'reader-fixed-pins')
    return module


def charge_report(ledger, data):
    need(len(data) <= POLICY['report_bytes'], 'aggregate-report-bound')
    owner = object(); ledger.acquire(owner)
    try:
        for start in range(0, len(data), MIB):
            ledger.charge(min(MIB, len(data)-start), owner)
    finally:
        ledger.release(owner)


def report_inode(info):
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))


def report_fd(entry):
    need(entry.get('inode') is not None, 'report-descriptor-initial-identity-unknown')
    info = os.fstat(entry['fd'])
    need(report_inode(info) == entry['inode'], 'report-descriptor-custody')
    return info


def report_parent(custody):
    parent = custody['parent']
    need(stat.S_ISDIR(report_fd(parent).st_mode), 'report-parent-custody')
    return parent['fd']


def unlink_report(custody, name, inode, code):
    """Absence is lexical; deletion requires the recorded inode in the held parent."""
    fd = report_parent(custody) if 'parent' in custody else None
    path = name if fd is not None else str(name)
    try:
        info = os.stat(path, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    need(inode is not None and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
         (info.st_dev, info.st_ino) == tuple(inode[:2]), code)
    os.unlink(path, dir_fd=fd)


def revoke_owned(custody):
    path = custody.get('path')
    try:
        if path is not None:
            unlink_report(custody, 'preflight.json' if 'parent' in custody else path,
                          custody.get('inode'), 'final-report-revocation-custody')
    except BaseException:
        custody['revocation_failed'] = True
        raise
    need(not custody.get('revocation_failed'), 'final-report-revocation-previously-unproved')


def report_failure(primary, failure, label):
    if primary is None:
        return failure
    if isinstance(primary, Exception) and not isinstance(failure, Exception):
        failure.__cause__ = primary
        return failure
    primary.add_note(label+': '+type(failure).__name__)
    return primary


def restore_report_mask(old):
    primary = sys.exc_info()[1]
    try:
        signal.pthread_sigmask(signal.SIG_SETMASK,old)
    except BaseException as failure:
        chosen = report_failure(primary, failure, 'report signal restoration unproved')
        if chosen is not primary:
            raise chosen


def revoke_after_failure(custody):
    primary = sys.exc_info()[1]
    try:
        revoke_owned(custody)
    except BaseException as failure:
        chosen = report_failure(primary, failure, 'owned report revocation unproved')
        if chosen is not primary:
            raise chosen


def close_report_fd(entry, fault):
    """Three bounded attempts; never adopt identity after an initial query failure."""
    for _ in range(3):
        fd = entry.get('fd')
        if fd is None:
            return
        try:
            info = os.fstat(fd)
        except OSError as error:
            if error.errno == 9:  # EBADF proves this slot absent, without closing it.
                entry['fd'] = None
                return
            fault(error)
            continue
        except BaseException as error:
            fault(error)
            continue
        try:
            need(entry.get('inode') is not None and report_inode(info) == entry['inode'],
                 'report-descriptor-custody')
            os.close(fd)
            entry['fd'] = None
            return
        except BaseException as error:
            fault(error)
    fault(ValueError('report-descriptor-disposal-unproved'))


def finish_report(custody, close_parent=False):
    """Attempt remaining owned disposal while retaining the first failure/control."""
    primary = sys.exc_info()[1]
    chosen = primary
    def fault(error, label='owned partial cleanup unproved'):
        nonlocal chosen
        chosen = report_failure(chosen, error, label)
    def revoke():
        try:
            revoke_owned(custody)
        except BaseException as error:
            fault(error, 'owned report revocation unproved')
    partial = custody.get('partial')
    if partial is not None and not partial.get('published'):
        try:
            # A displaced still-linked owned inode is not a proved absent partial.
            fd = report_parent(custody)
            try:
                os.stat('preflight.json.partial', dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                need(report_fd(partial).st_nlink == 0, 'partial-report-displaced-custody')
            else:
                unlink_report(custody, 'preflight.json.partial', partial.get('inode'),
                              'partial-report-cleanup-custody')
        except BaseException as error:
            fault(error)
    if chosen is not None:
        revoke()
    if partial is not None:
        close_report_fd(partial, fault)
    if chosen is not None:
        revoke()
    parent = custody.get('parent')
    if parent is not None and (close_parent or chosen is not None):
        def parent_fault(error):
            fault(error, 'owned parent descriptor cleanup unproved')
            revoke()  # Retain directory custody for revocation before a retry closes it.
        close_report_fd(parent, parent_fault)
    if chosen is not None and chosen is not primary:
        raise chosen


def persist_report(ledger, output, result, custody):
    """One retained report/partial, charged once on the same work ledger."""
    ledger.check()
    result['ledger']['work_bytes_before_report'] = ledger.budget.tree_bytes
    result['report_bytes_charged'] = 0
    for _ in range(20):
        result['ledger']['work_bytes_after_report_charge'] = ledger.budget.tree_bytes + result['report_bytes_charged']
        data = json.dumps(result,sort_keys=True,separators=(',', ':'),allow_nan=False).encode()+b'\n'
        if len(data) == result['report_bytes_charged']:
            break
        result['report_bytes_charged'] = len(data)
    else:
        raise ValueError('report-accounting-convergence')
    charge_report(ledger,data); ledger.check()
    need(ledger.budget.tree_bytes == result['ledger']['work_bytes_after_report_charge'], 'report-accounting')
    output = Path(output)
    need(not output.exists() and not output.is_symlink() and
         all(stat.S_ISDIR(p.lstat().st_mode) for p in output.parents), 'fresh-output-required')
    try:
        old = signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM,signal.SIGALRM})
        try:
            output.mkdir(mode=0o700)
            stamp = output.lstat()
            need(stat.S_ISDIR(stamp.st_mode), 'report-parent-custody')
            parent = custody['parent'] = dict(fd=None, inode=None)
            parent['fd'] = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = os.fstat(parent['fd'])
            need(report_inode(info) == report_inode(stamp), 'report-parent-custody')
            parent['inode'] = report_inode(info)
            partial = custody['partial'] = dict(fd=None, inode=None, published=False)
            partial['fd'] = os.open('preflight.json.partial', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                    0o600, dir_fd=report_parent(custody))
            info = os.fstat(partial['fd'])
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'partial-report-custody')
            named = os.stat('preflight.json.partial',dir_fd=report_parent(custody),follow_symlinks=False)
            need(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and report_inode(named) == report_inode(info),
                 'partial-report-initial-binding')
            partial['inode'] = report_inode(info)
        finally:
            restore_report_mask(old)
        for start in range(0,len(data),MIB):
            ledger.check()
            remaining = memoryview(data)[start:start+MIB]
            while remaining:
                report_fd(partial)
                written = os.write(partial['fd'], remaining)
                need(written > 0, 'report-write-progress')
                remaining = remaining[written:]
        report_fd(partial); os.fsync(partial['fd'])
        ledger.check(); report_fd(partial); os.fchmod(partial['fd'],0o600)
        old = signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM,signal.SIGALRM})
        try:
            fd = report_parent(custody)
            need(report_inode(output.lstat()) == parent['inode'], 'report-parent-path-custody')
            named = os.stat('preflight.json.partial',dir_fd=fd,follow_symlinks=False)
            need(report_inode(named) == partial['inode'] and named.st_nlink == 1,
                 'partial-report-publication-custody')
            try:
                os.stat('preflight.json',dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('final-report-publication-custody')
            os.replace('preflight.json.partial','preflight.json',src_dir_fd=fd,dst_dir_fd=fd)
            custody.update(path=str(output/'preflight.json'),inode=partial['inode'])
            partial['published'] = True
        finally:
            restore_report_mask(old)
        ledger.check()
    finally:
        finish_report(custody)


def batch_walk(tool,expected,reader,ledger):
    """Only the fixed selected ancestry, independent child restats and one CAT."""
    ledger.core.node_shape(expected)
    need(expected['type']=='file' and expected['bytes']<=BATCH['selected_file_bytes'],'selected-archive-regular-cap')
    calls=cat_calls=nodes=0;visited=set();initial_calls=ledger.calls
    def call(kind,inode,size=0):
        nonlocal calls,cat_calls
        check_deadline(ledger.end);ledger.check(tool)
        need(calls<BATCH['maximum_calls'] and ledger.calls==initial_calls+calls,'batch-call-custody')
        reader.request(kind,inode);calls+=1
        if kind=='cat':cat_calls+=1;need(cat_calls<=1,'batch-CAT-bound')
        before=(ledger.budget.decoded,ledger.budget.tree_bytes,ledger.budget.nodes)
        result=tool.call(kind,inode,size)
        need(type(result) is dict and set(result)=={'data','bytes','sha256','returncode'} and
             type(result['bytes']) is int and result['bytes']>=0 and type(result['data']) is bytes and
             type(result['sha256']) is str and len(result['sha256'])==64 and all(c in '0123456789abcdef' for c in result['sha256']) and
             type(result['returncode']) is int and result['returncode']==0,'batch-response-shape')
        need((result['data']==b'' and result['bytes']==size) if kind=='cat' else
             (len(result['data'])==result['bytes']<=POLICY['metadata_bytes'] and hashlib.sha256(result['data']).hexdigest()==result['sha256']),
             'batch-response-bound')
        need(ledger.calls==initial_calls+calls and ledger.budget.decoded==before[0] and ledger.budget.nodes==before[2] and
             ledger.budget.tree_bytes==before[1]+result['bytes'],'batch-call-expansion-or-debt')
        ledger.check(tool);return result
    def read(inode):return reader.inode_stat(call('stat',inode)['data'],inode)
    def walk(inode,parent,depth,prior=None):
        nonlocal nodes
        ledger.check(tool);need(depth<len(PARTS) and inode not in visited,'batch-directory-cycle');visited.add(inode)
        before=read(inode)
        need(before['type']=='directory' and (prior is None or before==prior),'batch-directory-stat')
        raw=call('ls',inode)['data'];children=reader.listing(raw)
        need(all(children['.'][key]==before[key] for key in ('inode','type','mode','uid','gid')) and
             children['..']['inode']==parent and (children['.']['bytes'] is None or children['.']['bytes']==before['bytes']),'batch-directory-parent')
        name=PARTS[depth];need(name in children,'batch-selected-missing');entry=children[name]
        ledger.budget.node();nodes+=1
        pre=read(entry['inode'])
        need(all(pre[key]==entry[key] for key in ('inode','type','mode','uid','gid')) and
             (entry['bytes'] is None or pre['bytes']==entry['bytes']),'batch-listing-stat')
        if depth<len(PARTS)-1:
            need(pre['type']=='directory','batch-ancestor-type');selected=walk(pre['inode'],inode,depth+1,pre)
        else:
            need(pre['type']=='file' and pre['nlink']==1 and pre['bytes']<=BATCH['selected_file_bytes'],'batch-regular-cap')
            need(all(pre[key]==expected[key] for key in ('mode','uid','gid','bytes')),'batch-expected-metadata')
            content=call('cat',pre['inode'],pre['bytes'])
            need(type(content['bytes']) is int and content['bytes']==expected['bytes'] and content['sha256']==expected['sha256'],'batch-content-mismatch')
            selected=dict(path=SELECTED_PATH,inode=pre['inode'],mode=pre['mode'],uid=pre['uid'],gid=pre['gid'],
                          bytes=content['bytes'],sha256=content['sha256'],nlink=pre['nlink'])
        need(read(pre['inode'])==pre,'batch-child-drift')
        need(call('ls',inode)['data']==raw and read(inode)==before,'batch-directory-drift')
        return selected
    selected=walk(2,2,0)
    need(calls==31 and cat_calls==1 and nodes==5 and ledger.calls==initial_calls+31,'batch-closed-schedule')
    ledger.check(tool)
    return dict(selected=selected,calls=calls,CAT_calls=cat_calls,selected_image_nodes=nodes)


def run_batch(selection,reader,ledger,deadline):
    """One archive lease then one image lease, never reset shared work or cutoff."""
    need(ledger.end==deadline and ledger.calls==0 and ledger.budget.decoded==0 and
         ledger.budget.tree_bytes==0 and ledger.budget.nodes==0,'batch-fresh-ledger')
    ledger.check();nodes=ledger.archive_nodes(selection['archive']['reference'],PACKAGE);ledger.check()
    need(type(nodes) is dict and SELECTED_PATH in nodes,'selected-archive-path')
    expected=nodes[SELECTED_PATH];ledger.core.node_shape(expected)
    need(expected['type']=='file' and expected['bytes']<=BATCH['selected_file_bytes'],'selected-archive-regular-cap')
    archive_decoded,archive_nodes=ledger.budget.decoded,ledger.budget.nodes
    need(archive_decoded<=1024**3 and archive_nodes<=100000,'batch-archive-bound')
    with reader.open_selected(selection['core']['path'],selection['tool_contract'],selection['image'],deadline,
                              execution_selected=True,ledger=ledger) as tool:
        observed=batch_walk(tool,expected,reader,ledger)
    ledger.check();check_deadline(deadline)
    need(ledger.budget.decoded==archive_decoded and ledger.budget.nodes==archive_nodes+5 and
         ledger.calls==31,'batch-final-ledger')
    return dict(schema_version=1,status='SINGLE_FILE_BATCH_MATCH_ONLY',scope=SCOPE,selected_package=PACKAGE,
                selected=observed['selected'],expected={key:expected[key] for key in ('type','mode','uid','gid','bytes','sha256')},
                requests=dict(image_calls=31,CAT_calls=1,archive_parse_count=1,directory_frames=5,child_stat_reuse=False),
                final_image_tool_rehash_completed=True,archive_actor_run=True,whole_package_correspondence_accepted=False,full341_accepted=False,
                required_tuples=261,baseline_available_archives=259,selected_archives=1,missing_tuples=selection['missing_tuples'],signer_joins_unresolved=26,
                raw_hash_accounting=dict(outside_returned_decoded_report_ledger=True,image_full_hash_bytes=2*IMAGE_SIZE,
                                         archive_hash_bytes=14864,tool_hashes='initial/final pinned9 physical files; not charged content',physical_IO_measurement=False),
                ledger=dict(decoded_archive_bytes=ledger.budget.decoded,returned_stdout_bytes_before_report=ledger.budget.tree_bytes,
                            calls=ledger.calls,nodes=ledger.budget.nodes),**ACCEPTANCE)


@contextmanager
def job_envelope():
    start = time.monotonic(); deadline = start + POLICY['absolute_seconds']
    need(signal.getitimer(signal.ITIMER_REAL) == (0.0,0.0), 'existing-wall-timer')
    resource.setrlimit(resource.RLIMIT_AS,(POLICY['addressspace_bytes'],)*2)
    resource.setrlimit(resource.RLIMIT_CPU,(POLICY['cpu_seconds'],)*2)
    resource.setrlimit(resource.RLIMIT_FSIZE,(POLICY['report_bytes'],)*2)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    previous = signal.getsignal(signal.SIGALRM)
    def expired(*_):
        raise TimeoutError('absolute-job-deadline')
    signal.signal(signal.SIGALRM,expired)
    signal.setitimer(signal.ITIMER_REAL,max(0.001,deadline-time.monotonic()))
    old_pyc = sys.dont_write_bytecode; sys.dont_write_bytecode = True
    try:
        yield start,deadline
        check_deadline(deadline)
    finally:
        sys.dont_write_bytecode = old_pyc
        signal.setitimer(signal.ITIMER_REAL,0)
        signal.signal(signal.SIGALRM,previous)


def execute(selection, selection_sha, grant, start, deadline, custody):
    validate_selection(selection); check_deadline(deadline)
    need(type(start) in (int,float) and math.isfinite(start) and deadline-start == POLICY['absolute_seconds'] and
         start <= time.monotonic(), 'job-envelope-binding')
    own = Path(__file__).absolute(); info = own.lstat()
    need(type(grant) is dict and grant.get('approved') is True, 'root-grant-not-selected')
    raw = captured(dict(path=str(own),size=info.st_size,sha256=grant.get('harness_sha256'),identity=identity(own)),MIB,deadline)
    grant_checked(grant,selection_sha,hashlib.sha256(raw).hexdigest(),selection)
    metadata_guard(selection,deadline)
    reader = load_reader(selection,deadline)
    ledger = reader.WorkLedger(selection['core']['path'],deadline)
    need(reader.TOTAL == POLICY['shared_work_bytes'] and ledger.end == deadline, 'ledger-policy')
    metadata = metadata_inputs(selection,reader,ledger,deadline)
    result = run_batch(selection,reader,ledger,deadline)
    result['ownership_metadata'] = metadata
    result['selection_sha256'] = selection_sha
    result['absolute_seconds_used_before_report'] = time.monotonic()-start
    try:
        persist_report(ledger,selection['output_path'],result,custody)
        ledger.check(); check_deadline(deadline)
        return result
    except BaseException:
        revoke_after_failure(custody)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection',required=True); parser.add_argument('--selection-sha256',required=True)
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--grant'); parser.add_argument('--grant-sha256')
    args = parser.parse_args()
    custody = {}
    try:
        if args.execute:
            need(args.grant is not None and args.grant_sha256 is not None, 'root-grant-required')
            with job_envelope() as (start,deadline):
                selection = validate_selection(json_file(args.selection,args.selection_sha256,deadline))
                grant = json_file(args.grant,args.grant_sha256,deadline)
                result = execute(selection,args.selection_sha256,grant,start,deadline,custody)
                finish_report(custody, close_parent=True)
                check_deadline(deadline)
            # The retained report holds detailed counters; stdout is one bounded status.
            print(json.dumps(dict(status=result['status'],report_path=custody['path'],**ACCEPTANCE),sort_keys=True))
        else:
            selection = validate_selection(json_file(args.selection,args.selection_sha256))
            result = dict(status='UNSELECTED_LICENSE_BATCH_SOURCE',batch=BATCH,policy=POLICY,
                          actual_reader=False,archive_actor_run=False,whole_package_correspondence_accepted=False,full341_accepted=False,
                          baseline_available_archives=259,required_tuples=261,
                          signer_joins_unresolved=26,**ACCEPTANCE)
            print(json.dumps(result,sort_keys=True))
    except BaseException:
        revoke_after_failure(custody)
        raise
    finally:
        finish_report(custody, close_parent=True)



if __name__ == '__main__':
    main()
