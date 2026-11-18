# SPDX-License-Identifier: MIT
"""Exact allowlisted hosted export and passive immutable artifact readback."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import zipfile

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import lane as L
import preflight as P

OUTER_CAP=8<<20
ARTIFACT_CAP=L.BYTE_CAP+OUTER_CAP
MANIFEST='artifact-manifest.json'
INNER_MANIFEST='evidence/inner-public-manifest.json'
UPLOADER='cf430e030ddbb5b0abf93d22962f4752f3646cd9'
FIXED=('owner-report.json','actual-domains.json','host-policy.json','host-tools.json')


def load(path,name):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s)
    s.loader.exec_module(m);return m


def read(path,cap):
    P.need(path.is_absolute() and path==path.resolve(),'ordinary artifact source path')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb') as stream:
        first=os.fstat(stream.fileno())
        P.need(stat.S_ISREG(first.st_mode) and first.st_nlink==1 and first.st_size<=cap,
               'ordinary bounded artifact leaf')
        raw=stream.read(cap+1)
        identity=lambda st:(st.st_dev,st.st_ino,st.st_mode,st.st_nlink,st.st_size,st.st_ctime_ns,st.st_mtime_ns)
        P.need(len(raw)==first.st_size and identity(first)==identity(os.fstat(stream.fileno()))==identity(path.lstat()),
               'whole same original artifact leaf')
    return raw


def exact_names(rows, inner, public):
    P.need(isinstance(rows,dict) and set(rows)<=set(public.PUBLIC_LEAVES)
           and 0<len(rows)<=len(public.PUBLIC_LEAVES) and sum(row['bytes'] for row in rows.values())<=L.BYTE_CAP,
           'literal sealed owner evidence namespace and total budget')
    P.need(inner['private_trees_read'] is False and inner['truncation'] is False,
           'complete untruncated evidence-only projection')
    for name,value in rows.items():
        cap=L.ARCHIVE_CAP if name.endswith('.pkg.tar.xz') else 8<<20
        P.need(set(value)=={'bytes','sha256'} and type(value['bytes']) is int and 0<=value['bytes']<=cap
               and re.fullmatch('[0-9a-f]{64}',value['sha256']),
               'exact finite owner evidence member')


def empty_controller(group):
    path=Path('/sys/fs/cgroup'+group)
    for _ in range(2):
        P.need(not path.exists() or 'populated 0' in (path/'cgroup.events').read_text().splitlines(),
               'same owned controller scope empty on both observations')
        time.sleep(.05)


def join_inner(selected, public, identity):
    report=json.loads(selected['owner-report.json'])
    P.need(all(report[key]==value for key,value in identity.items()),'same external owner receipt')
    inner_raw=selected.get(INNER_MANIFEST)
    if inner_raw is None:
        P.need(report['status']=='HOLD','missing public evidence is HOLD only')
        return
    inner=json.loads(inner_raw)
    rows=inner['files'];exact_names(rows,inner,public)
    P.need(inner['source']==identity['source'] and inner['source_map_sha256']==identity['source_map_sha256']
           and report['inner_public_evidence']['manifest']==P.pin(inner_raw)
           and set(rows)=={name.removeprefix('evidence/') for name in selected
                           if name.startswith('evidence/') and name!=INNER_MANIFEST}
           and all(P.pin(selected['evidence/'+name])==pin for name,pin in rows.items()),
           'complete same owner-selected evidence manifest')
    if report['status']=='PASS_CURRENT_PYTHON3148_FULL_PROFILE_EXTERNAL_DOMAINS_ONLY':
        P.need(inner['status']=='EXPORTED' and not inner['missing_required']
               and set(public.SUCCESS_REQUIRED)<=set(rows) and report['cleanup']['owned_storage_absent'] is True
               and report['cleanup']['errors']==[],'complete clean owner export on success')
        result=json.loads(selected['evidence/build-result.json'])
        name='build-1/artifacts/'+P.ARCHIVE
        check='build-1/artifacts/'+L.CHECK_LOG
        lock='build-1/artifacts/packages.lock'
        P.need(result['status']=='PYTHON3148_SINGLE_NATIVE_BUILD_DATA'
               and result['Root_acceptance'] is None and result['archive']==rows[name]
               and result['check']==rows[check] and result['builder']==rows[lock]
               and rows[lock]['sha256']==L.LOCK_SHA and result['pagesize']==4096,
               'same Python package, check and exact 345-payload lock')


def snapshot(root,owned,target,map_sha,env,observe=empty_controller):
    overlay=load(root/'scripts/ci/python3148-native-full-profile/overlay.py','python_artifact_source')
    overlay.verify(root,map_sha,overlay.RUNTIME_KIND)
    public=load(root/overlay.FULL/'public_evidence.py','accepted_literal_owner_export')
    P.need(env['GITHUB_RUN_ATTEMPT']=='1' and env['GITHUB_JOB']=='pair'
           and env['GITHUB_REF']==L.REF and re.fullmatch('[1-9][0-9]{1,19}',env['GITHUB_RUN_ID']),
           'exact first-attempt Python hosted role')
    body=P.read(owned/'owner-report.json',2<<20)
    report=json.loads(body);run=env['GITHUB_RUN_ID']
    identity=dict(source=env['GITHUB_SHA'],ref=L.REF,source_map_sha256=map_sha,run=run,attempt=1,job='pair')
    P.need(all(report[k]==value for k,value in identity.items()),'same hosted owner identity')
    group='/system.slice/cachy-python3148-controller-'+run+'-1.scope'
    P.need(report['controller']['cgroup']==group,'exact controller scope')
    observe(group)
    selected={'owner-report.json':body}
    for name in FIXED[1:]:
        path=owned/name
        if path.exists():
            selected[name]=read(path,2<<20)
    selected['controller-retirement.json']=P.encode(dict(cgroup=group,empty_twice=True,run=run,attempt=1))
    path=owned/INNER_MANIFEST
    if path.exists():
        raw=P.read(path,2<<20)
        inner=json.loads(raw);rows=inner['files'];exact_names(rows,inner,public)
        P.need(inner['source']==identity['source'] and inner['source_map_sha256']==map_sha
               and report['inner_public_evidence']['manifest']==P.pin(raw),'exact owner-selected evidence manifest')
        selected[INNER_MANIFEST]=raw
        for name,pin in rows.items():
            data=read(owned/'evidence'/name,pin['bytes'])
            P.need(P.pin(data)==pin,'exact retained leaf '+name)
            selected['evidence/'+name]=data
    join_inner(selected,public,identity)
    total=sum(map(len,selected.values()))
    P.need(total<=ARTIFACT_CAP,'bounded raw upload data bytes')
    manifest=P.encode(dict(kind='PYTHON3148_IMMUTABLE_HOSTED_ARTIFACT_DATA_ONLY',**identity,
                files={name:P.pin(raw) for name,raw in selected.items()},raw_bytes=total,Root_acceptance=None))
    P.need(target.is_absolute() and target.resolve()==target and not target.exists()
           and not target.is_relative_to(owned),'fresh disjoint immutable export')
    target.mkdir(mode=0o700)
    for name,raw in {**selected,MANIFEST:manifest}.items():
        P.put(target/name,raw,0o400)
    return P.pin(manifest)


def inspect_original(archive, archive_sha, binding, public):
    raw=P.read(archive,ARTIFACT_CAP+(2<<20))
    P.need(P.pin(raw)['sha256']==archive_sha,'explicit independent whole original ZIP pin')
    import io
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
            files=[row for row in bundle.infolist() if not row.is_dir()]
            P.need(0<len(files)<4096 and len({row.filename for row in files})==len(files)
                   and sum(row.file_size for row in files)<=ARTIFACT_CAP+(2<<20)
                   and all(not name.startswith('/') and all(x not in ('','.','..') for x in name.split('/'))
                           for name in (row.filename for row in files))
                   and all(not row.flag_bits&1 and stat.S_IFMT(row.external_attr>>16) in (0,stat.S_IFREG)
                           for row in files),'strict finite original ZIP members')
            index={row.filename:row for row in files}
            P.need(MANIFEST in index and index[MANIFEST].file_size<=2<<20,'bounded artifact manifest')
            manifest=json.loads(bundle.read(MANIFEST))
            fixed=set(FIXED)|{'controller-retirement.json'}
            P.need(set(index)==set(manifest['files'])|{MANIFEST}
                   and all(name in fixed or name==INNER_MANIFEST or name.removeprefix('evidence/') in public.PUBLIC_LEAVES
                           and name.startswith('evidence/') for name in manifest['files'])
                   and manifest['kind']=='PYTHON3148_IMMUTABLE_HOSTED_ARTIFACT_DATA_ONLY'
                   and manifest['Root_acceptance'] is None and all(manifest[k]==v for k,v in binding.items()),
                   'exact sealed scope, Source, run, attempt and output allowlist')
            P.need(set(binding)=={'source','ref','source_map_sha256','run','attempt','job'}
                   and binding['attempt']==1 and binding['ref']==L.REF and binding['job']=='pair',
                   'external whole Source, ref, run, attempt, job role binding')
            selected={name:bundle.read(name) for name in manifest['files']}
            for name,want in manifest['files'].items():
                P.need(P.pin(selected[name])==want,'all original immutable selected bytes')
            join_inner(selected,public,binding)
            P.need(manifest['raw_bytes']==sum(index[name].file_size for name in manifest['files'])<=ARTIFACT_CAP,
                   'whole artifact output cap')
            return manifest
    except (OSError,zipfile.BadZipFile,RuntimeError) as error:
        raise ValueError('complete valid original ZIP') from error


if __name__=='__main__':
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--root',type=Path,required=True)
    cli.add_argument('--owner-output',type=Path,required=True)
    cli.add_argument('--target',type=Path,required=True)
    cli.add_argument('--runtime-sha256',required=True)
    a=cli.parse_args()
    print(json.dumps(snapshot(a.root,a.owner_output,a.target,a.runtime_sha256,os.environ),sort_keys=True))
