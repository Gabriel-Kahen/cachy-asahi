#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline joins of twelve Rust submodule identities; no payload/build admission."""
import argparse
import configparser
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import stat

HERE=Path(__file__).resolve().parent
COMMIT='b940084d7eb6a299eb4bfeb8e34901bc051e7ac4'
SHA=re.compile(r'[0-9a-f]{40}')
TREES={'root':'','src':'src','doc':'src/doc','tools':'src/tools','library':'library'}


def need(value,why):
    if not value:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def oid(kind,raw):return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()


def read(path,expected=None):
    path=Path(path);cap=4*1024**2
    need(path==path.resolve() and not any(p.is_symlink()for p in(path,*path.parents)),'canonical metadata path')
    state=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=cap,'bounded ordinary metadata file')
        with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(cap+1)
        need(len(raw)==before.st_size and state(before)==state(os.fstat(fd))==state(path.lstat()),'stable whole metadata')
    finally:os.close(fd)
    if expected is not None:need(pin(raw)=={k:expected[k]for k in('bytes','sha256')},'metadata whole pin '+path.name)
    return raw


def decode(raw):
    def pairs(items):
        value={}
        for k,v in items:need(k not in value,'duplicate JSON key');value[k]=v
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))


def tree(value):
    need(type(value)is dict and type(value.get('oid'))is str and SHA.fullmatch(value['oid']) and
         type(value.get('entries'))is list and len(value['entries'])<=1000,'bounded complete Git tree metadata')
    rows={};encoded=[]
    for e in value['entries']:
        name=e.get('name');mode=e.get('mode');kind=e.get('type');sha=e.get('oid')
        need(type(name)is str and name not in('','.','..') and '/'not in name and '\0'not in name and name not in rows,'distinct single Git tree name')
        need(type(mode)is int and (mode,kind)in((0o40000,'tree'),(0o100644,'blob'),(0o100755,'blob'),(0o120000,'blob'),(0o160000,'commit')) and
             type(sha)is str and SHA.fullmatch(sha),'typed tree mode/kind/OID')
        rows[name]=e;encoded.append((name.encode()+(b'/'if kind=='tree'else b''),format(mode,'o').encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha)))
    raw=b''.join(b for _,b in sorted(encoded))
    need(oid('tree',raw)==value['oid'],'complete reconstructed Git tree SHA')
    return rows


def declarations(text):
    need(type(text)is str and len(text.encode())<=65536,'bounded gitmodules text')
    c=configparser.ConfigParser(interpolation=None,strict=True);c.read_string(text)
    need(not c.defaults(),'no inherited submodule fields');result=[];paths=set()
    for section in c.sections():
        need(re.fullmatch(r'submodule "[^"\n]+"',section)is not None,'submodule section')
        row=dict(c[section]);path=row.get('path');url=row.get('url')
        need(type(path)is str and PurePosixPath(path).as_posix()==path and not path.startswith('/') and
             '..'not in PurePosixPath(path).parts and path not in paths,'canonical distinct submodule path')
        need(type(url)is str and re.fullmatch(r'https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git',url)is not None,'literal declared GitHub repository')
        need(set(row)<=set(('path','url','branch','shallow','update','ignore')),'known pinned gitmodules fields')
        paths.add(path);result.append({k:row[k]for k in('path','url','branch')if k in row})
    need(len(result)==12,'exact twelve declared submodules')
    return result


def graphql(record):
    need(type(record)is dict and not record.get('errors') and type(record.get('data'))is dict,'complete successful primary GraphQL response')
    return record['data']


def reconcile(records,inventory,source_inputs,authentication):
    rust=graphql(records['rust-tree.json'])['rust'];upstreams=graphql(records['upstreams.json']);roots=graphql(records['upstream-root-trees.json'])
    need(rust['nameWithOwner']=='rust-lang/rust' and rust['databaseId']==724712 and rust['url']=='https://github.com/rust-lang/rust' and
         rust['owner']['login']=='rust-lang' and rust['commit']['oid']==COMMIT,'exact official Rust repository/commit')
    archive=source_inputs['archives']['rustc-1.99.0-src.tar.xz'];signed=authentication['source_signatures']['rust']
    need(archive['expected_upstream_commit']==COMMIT and signed['signature_mathematics']=='PASS' and signed['gpgv_exit']==0 and
         signed['archive']['bytes']==archive['bytes'] and signed['archive']['sha256']==archive['checksums']['sha256'],'prior authenticated compressed archive identity (signature not rerun)')
    need(inventory['status']=='COMPLETE_BOUNDED_SCAN' and inventory['authenticated_source_pin_verified']is True and
         inventory['compressed_bytes_read']==archive['bytes'] and inventory['compressed_sha256_observed']==archive['checksums']['sha256'],'complete retained archive scan of exact authenticated bytes')
    maps={k:tree(rust[k])for k in TREES}
    need(rust['commit']['tree']['oid']==rust['root']['oid'],'Rust commit root tree')
    for parent,name,child in [('root','src','src'),('root','library','library'),('src','doc','doc'),('src','tools','tools')]:
        need(maps[parent][name]['type']=='tree' and maps[parent][name]['oid']==rust[child]['oid'],'connected exact Rust path trees')
    modules=rust['modules'];raw=modules['text'].encode();declared=declarations(modules['text'])
    selected=[r for r in inventory['selected_metadata']if r['path']=='.gitmodules']
    need(len(selected)==1 and pin(raw)=={k:selected[0][k]for k in('bytes','sha256')} and len(raw)==modules['byteSize'] and
         oid('blob',raw)==modules['oid']==maps['root']['.gitmodules']['oid'] and maps['root']['.gitmodules']['mode']==0o100644,'authenticated archive gitmodules equals official Git blob')
    need(declared==selected[0]['declarations']['submodules'],'archive/raw parsed declarations agree')
    occupancy=inventory['submodule_declarations'];need(len(occupancy)==12 and len({r['path']for r in occupancy})==12,'complete distinct archive submodule observations')
    observed={r['path']:r for r in occupancy};need(set(observed)=={r['path']for r in declared},'all declared archive paths reconciled')
    available_links={str(PurePosixPath(prefix)/n):e['oid']for label,prefix in TREES.items()for n,e in maps[label].items()if e['type']=='commit'}
    need(set(available_links)==set(observed),'declared gitlinks in all selected connected path trees')
    need(set(upstreams)==set(roots)=={'r'+str(i)for i in range(12)},'all twelve repository responses, no missing alias')
    rows=[];repo_ids=set()
    for i,d in enumerate(declared):
        path=d['path'];seen=observed[path];repo=upstreams['r'+str(i)];root=roots['r'+str(i)];name=d['url'][19:-4];sha=available_links[path]
        need(all(seen.get(k)==v for k,v in d.items()) and type(seen['regular_members_under_path'])is int and seen['regular_members_under_path']>=0,'exact archive path/url/count observation')
        need(repo['nameWithOwner']==root['nameWithOwner']==name and repo['url']=='https://github.com/'+name and
             repo['owner']['login']==name.split('/')[0] and type(repo['databaseId'])is int and repo['databaseId']>0 and
             root['databaseId']==repo['databaseId'] and repo['databaseId']not in repo_ids,'exact declared canonical repository identity/owner')
        repo_ids.add(repo['databaseId'])
        need(repo['object']is not None and root['object']is not None and repo['object']['oid']==root['object']['oid']==sha and
             repo['object']['tree']['oid']==root['object']['tree']['oid'],'exact gitlink commit exists in declared repository')
        entries=tree(root['object']['tree']);regular=[e for e in entries.values()if e['mode']in(0o100644,0o100755)]
        rows.append(dict(path=path,declared_url=d['url'],declared_branch=d.get('branch'),gitlink_mode='160000',gitlink_commit=sha,
                         declared_repository=name,repository_id=repo['databaseId'],repository_owner=repo['owner']['login'],
                         is_fork=repo['isFork'],fork_parent=repo['parent'],upstream_root_tree=root['object']['tree']['oid'],
                         upstream_root_regular_files=len(regular),archive_regular_members_under_path=seen['regular_members_under_path'],
                         root_gitmodules_present='.gitmodules'in entries,recursive_content_verification='NOT_PERFORMED',
                         payload_identity_at_gitlink_commit='NOT_VERIFIED',exact_missing_payload_names_and_total_bytes='NOT_ESTABLISHED',
                         copyright_holders_and_notice_obligations='NOT_AUDITED; repository owner is not a license finding'))
    gcc=graphql(records['gcc-root-sizes.json'])['gcc'];expected=upstreams['r11'];t=gcc['object']['tree'];entries=tree(t)
    need(gcc['nameWithOwner']==expected['nameWithOwner']=='rust-lang/gcc' and gcc['databaseId']==expected['databaseId'] and
         gcc['object']['oid']==expected['object']['oid'] and t['oid']==expected['object']['tree']['oid'],'exact GCC root byte-size metadata')
    regular=[e for e in entries.values()if e['mode']in(0o100644,0o100755)];sizes=[]
    for e in regular:
        size=e['object']['byteSize'];need(type(size)is int and 0<=size<=32*1024**2,'bounded GCC root blob size');sizes.append(size)
    gcc_row=next(r for r in rows if r['path']=='src/gcc');count=gcc_row['archive_regular_members_under_path'];sizes.sort(reverse=True)
    gcc_row['minimum_absent_upstream_root_regular_files']=max(0,len(sizes)-count)
    gcc_row['minimum_absent_upstream_root_payload_bytes']=sum(sizes[count:])
    gcc_row['upstream_root_regular_payload_bytes']=sum(sizes)
    gcc_row['missing_lower_bound_scope']='At most the archive count can cover distinct upstream root regular files at their correct paths; no filenames/content equality assumed. Excludes all deeper files.'
    ledger=records['requests.json'];requests=ledger['requests']
    pairs=[('root','rust-tree.json'),('upstream','upstreams.json'),('upstream-trees','upstream-root-trees.json'),('gcc-sizes','gcc-root-sizes.json')]
    need(len(requests)==len(pairs)<=20 and sum(r['bytes']for r in requests)<=8*1024**2,'bounded complete new metadata acquisition')
    for i,(query,response)in enumerate(pairs):
        row=requests[i];need(row['number']==i+1 and row['url']=='https://api.github.com/graphql' and row['method']=='POST_READ_ONLY_QUERY' and
             row['status']=='RECEIVED' and row['http_status']==200 and row['query_sha256']==hashlib.sha256(records[query+'-query.graphql']).hexdigest() and
             {k:row[k]for k in('bytes','sha256')}==pin(records[response+'_raw']),'exact primary query/response receipt')
    return dict(schema=1,status='TWELVE_DECLARED_SUBMODULE_IDENTITIES_RECONCILED_CONTENT_AND_LICENSE_COMPLETENESS_HELD',rust_commit=COMMIT,
                gitmodules=pin(raw),rust_root_tree=rust['root']['oid'],submodules=rows,metadata_requests=len(requests),metadata_response_bytes=sum(r['bytes']for r in requests),
                archive_scans_in_this_task=0,payload_downloads=0,retrieved_code_execution=0,checkout_or_builds=0,
                prior_signature_record_rejoined_not_rerun=True,recursive_source_completeness='HELD',license_completeness='HELD',binary_correspondence='HELD',
                native_ARM_M2_performance_and_release='NOT_TESTED_OR_ADMITTED',
                limitations=['GitHub repository identities are observations at acquisition time; Git object OIDs and declared paths are exact pinned facts.',
                             'Archive path occupancy is not payload equality to a gitlink commit. Only the GCC count-based lower bound establishes missing regular root files.',
                             'No recursive tree/payload fetch, nested submodule closure, full notice/grant audit, bootstrap acquisition or build consumption was performed.',
                             'Rust LLVM fork gitlink is a separate identity from the separately retained llvm/llvm-project release archive.',
                             'Only five connected Rust trees needed for the twelve declared paths were inspected; no global absence of other nested gitlinks is asserted.'])


def verify(inventory_report):
    inputs=decode(read(HERE/'inputs.json'));need(inputs['schema']==1 and inputs['rust_commit']==COMMIT,'fixed verifier inputs')
    records={}
    for name,expected in inputs['records'].items():
        need(PurePosixPath(name).parts[0]=='records' and '..'not in PurePosixPath(name).parts,'local pinned record path')
        raw=read(HERE/name,expected);key=Path(name).name
        records[key]=raw if key.endswith('.graphql')else decode(raw)
        if key.endswith('.json'):records[key+'_raw']=raw
    parents={name:decode(read(HERE.parent/name,p))for name,p in inputs['parents'].items()}
    inventory=decode(read(Path(inventory_report).resolve(),inputs['inventory_report']))
    retained=records['archive-declarations.json']
    need(retained['gitmodules']==next(x for x in inventory['selected_metadata']if x['path']=='.gitmodules') and
         retained['submodule_declarations']==inventory['submodule_declarations'],'retained declaration projection rejoins original full scan')
    return reconcile(records,inventory,parents['source-inputs.json'],parents['authentication/successor-evidence.json'])


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(128*1024**2,128*1024**2))
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--inventory-report',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    report=verify(a.inventory_report)
    with a.output.open('x')as f:f.write(json.dumps(report,indent=2,sort_keys=True)+'\n')
    hwm=next(line for line in Path('/proc/self/status').read_text().splitlines()if line.startswith('VmHWM:'))
    print(json.dumps(dict(status=report['status'],submodules=len(report['submodules']),new_requests=report['metadata_requests'],new_bytes=report['metadata_response_bytes'],process_VmHWM_bytes=int(hwm.split()[1])*1024)))
