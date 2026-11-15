#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Construct a fresh unquiet diagnostic Source as DATA; never run its code."""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
PARENT='6b5b5a8f20ad2698c2d7f14a8f59c9b0ad5da165'
PARENT_TREE='a825d475d248f2254070d256d23780c4ef2d0f4b'
PARENT_MAP='7474683e198759876dcee6b31a036473f2129da351fce3bcc8e37770b4a70f79'
OPERATION='native-build-namespace-preflight-v1'
VISIBILITY='UNQUIET_TOOLS_IIDFILE_V1'
FACTORY_MANIFEST_SHA='3d588010e92b058c06bac0d5b2f0229a097ed0d7e0ac2b99eb2743577e8823c2'
MAP='native/source-map.json'
READER='native/build_tools_reader_v2.py'
CHANGED=frozenset(('native/owner.py','native/image_lifecycle.py',READER,MAP))
TRANSFORMS={
 'native/owner.py':[(b"command = [*DOCKER, 'build', '--quiet', '--network=none'",b"command = [*DOCKER, 'build', '--network=none'")],
 'native/image_lifecycle.py':[
  (b"len(argv) == (16 if role == 'base' else 17) and",b'len(argv) == 16 and'),
  (b"DOCKER+['build','--quiet','--network=none'",b"DOCKER+['build','--network=none'")],
 READER:[
  (b"len(argv) == (16 if role == 'base' else 17),",b'len(argv) == 16,'),
  (b"docker + ['build', '--quiet', '--network=none'",b"docker + ['build', '--network=none'"),
  (b"tools[0]['actor']['argv'] == ['/usr/bin/docker','--host=unix:///var/run/docker.sock','build','--quiet',",b"tools[0]['actor']['argv'] == ['/usr/bin/docker','--host=unix:///var/run/docker.sock','build',"),
  (b'exact normal quiet build argv without privilege/sysctl/seccomp bypass',b'exact normal unquiet build argv without privilege/sysctl/seccomp bypass'),
  (b"    image_build_policy = build_tools_build_policy_data(view, files, receipt, binding, expected['map_sha256'])",b"    image_build_policy = build_tools_build_policy_data(view, files, receipt, binding, expected['map_sha256'])\n    build_log_visibility = retained_namespace_build_log(view, files, receipt, cleanup, binding, expected['map_sha256'])"),
  (b'consumer_diagnostic=consumer_diagnostic, build_summary=build_summary, image_build_policy=image_build_policy,',b'consumer_diagnostic=consumer_diagnostic, build_summary=build_summary, image_build_policy=image_build_policy, build_log_visibility=build_log_visibility,'),
  (b'build_tools=component, image_build_policy=image_build_policy, native=',b'build_tools=component, image_build_policy=image_build_policy, build_log_visibility=build_log_visibility, native='),
  (b'    return manifest\n',b"    need(manifest.get('namespace_build_log_visibility') == 'UNQUIET_TOOLS_IIDFILE_V1', 'exact unquiet diagnostic Source family')\n    return manifest\n")]
}


def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def read(path,cap=4*1024**2):
    path=Path(path)
    need(path.is_absolute() and path==path.resolve() and not any(p.is_symlink() for p in (path,*path.parents)),'canonical constructor DATA operand')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    state=lambda s:tuple(getattr(s,n)for n in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=cap,'bounded ordinary constructor DATA')
        with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(cap+1)
        need(len(raw)==before.st_size and state(before)==state(os.fstat(fd))==state(path.lstat()),'stable whole constructor DATA')
        return raw
    finally:os.close(fd)


def factory():
    raw=read(HERE/'factory-inputs.json');need(pin(raw)['sha256']==FACTORY_MANIFEST_SHA,'fixed whole held factory manifest before code import')
    manifest=json.loads(raw);root=HERE.parent/'native-build-namespace-preflight'
    need(manifest['schema']==1 and manifest['root']=='../native-build-namespace-preflight','fixed existing diagnostic factory')
    for name,row in manifest['files'].items():need(pin(read(root/name))==row,'exact held factory operand '+name)
    path=root/'prepare.py';spec=importlib.util.spec_from_file_location('_held_namespace_source_DATA_factory',path)
    P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
    return P,manifest


def baseline(P,manifest):
    """Reconstruct complete published6b metadata from the pinned original factory."""
    raw,_=P.read(P.HERE/'profile.json');old=P.profile(raw,manifest['files']['profile.json']['sha256'])
    rows=dict(old['parent_files']);rows.update(old['overlay']);blobs=dict(old['parent_blobs'])
    for name in old['overlay']:
        body,mode=P.read(P.HERE/'payload'/name)
        need(dict(**pin(body),mode=mode)==old['overlay'][name],'original factory overlay body/mode')
        blobs[name]=P.oid(b'blob',body).hex()
    mapping=P.decode(P.read(P.HERE/'parent-map.json')[0]);mapping['namespace_preflight_operation']=OPERATION
    mapping['files']={n:r for n,r in rows.items() if n!=MAP};body=P.encoded(mapping)
    need(pin(body)['sha256']==PARENT_MAP,'original factory reconstructs published6b map exactly')
    rows[MAP]=dict(**pin(body),mode=420);blobs[MAP]=P.oid(b'blob',body).hex()
    raw=read(HERE/'parent.raw',4096)
    need(P.oid(b'commit',raw).hex()==PARENT and raw.splitlines()[:2]==[('tree '+PARENT_TREE).encode(),('parent '+P.PARENT).encode()], 'exact published6b raw parent and its genuine97 parent')
    return rows,blobs


def once(raw,old,new):
    need(raw.count(old)==1,'one finite reviewed source seam')
    return raw.replace(old,new,1)


def transform(before,P,manifest):
    rows,blobs=baseline(P,manifest)
    need(P.descriptors(before)==rows and {n:P.oid(b'blob',b).hex()for n,(b,m)in before.items()}==blobs
         and P.tree(before)==PARENT_TREE,'complete genuine published6b Source200 body/mode/blob/tree')
    after=dict(before);helper=read(HERE/'reader_visibility.py.in')
    need(helper.startswith(b'\n\ndef retained_namespace_build_log('),'one explicit pure Reader visibility helper')
    for name,replacements in TRANSFORMS.items():
        body,mode=before[name]
        for old,new in replacements:body=once(body,old,new)
        if name==READER:body=once(body,b"\n\nif __name__ == '__main__':",helper+b"\n\nif __name__ == '__main__':")
        inverse=body
        if name==READER:inverse=once(inverse,helper,b'')
        for old,new in reversed(replacements):inverse=once(inverse,new,old)
        need(inverse==before[name][0],'exact inverse restores every original guard byte')
        ast.parse(body,filename=name);after[name]=(body,mode)
    mapping=P.decode(before[MAP][0]);need(mapping.get('namespace_preflight_operation')==OPERATION and 'namespace_build_log_visibility' not in mapping,'only old6b diagnostic source family')
    mapping['namespace_build_log_visibility']=VISIBILITY
    mapping['files']={n:r for n,r in P.descriptors(after).items()if n!=MAP}
    after[MAP]=(P.encoded(mapping),before[MAP][1])
    need(len(after)==200 and len(mapping['files'])==199 and mapping['actual']==dict(source=None,ref=None,run=None)
         and {n for n in before if before[n]!=after[n]}==CHANGED,'only finite three source leaves plus regenerated map')
    inverse=dict(after)
    for name in CHANGED:inverse[name]=before[name]
    need(inverse==before and P.tree(inverse)==PARENT_TREE,'complete Source200 byte/mode/tree inverse')
    return after


def facts(before,after,P,manifest):
    def row(value):
        body,mode=value;return dict(**pin(body),mode=mode,oid=P.oid(b'blob',body).hex())
    return dict(schema=1,purpose='native-build-namespace-observable-source-v1',operation=OPERATION,
        parent=PARENT,parent_tree=PARENT_TREE,parent_map_sha256=PARENT_MAP,parent_raw=pin(read(HERE/'parent.raw')),
        factory_inputs=pin(read(HERE/'factory-inputs.json')),reader_helper=pin(read(HERE/'reader_visibility.py.in')),
        source_files=200,map_rows=199,unchanged_files=196,prospective_tree=P.tree(after),map_sha256=pin(after[MAP][0])['sha256'],
        changes={n:dict(before=row(before[n]),after=row(after[n]))for n in sorted(CHANGED)},
        actual=dict(source=None,ref=None,run=None,job=None,artifact=None),visibility=VISIBILITY,
        native='NOT_RUN',Reader='NOT_RUN',namespace_policy_cause='UNKNOWN',physical_M2='NOT_RUN',release='NOT_ADMITTED',acceptance=False)


def compose(before,checksum):
    P,manifest=factory();raw=read(HERE/'profile.json');need(pin(raw)['sha256']==checksum,'external Root reviewed whole observable profile pin')
    expected=P.decode(raw);after=transform(before,P,manifest)
    need(facts(before,after,P,manifest)==expected,'entire exact observable Source family facts')
    return after,P


def prepare(parent_source,checksum,output=None):
    P,manifest=factory();parent_source=P.absolute(parent_source);before=P.snapshot(parent_source)
    after,P=compose(before,checksum)
    if output is not None:
        output=P.absolute(output)
        need(output!=parent_source and parent_source not in output.parents and output not in parent_source.parents
             and output!=HERE and HERE not in output.parents and output not in HERE.parents,'fresh disjoint observable Source output')
        P.publish(after,output)
    return dict(status='OBSERVABLE_SOURCE_DATA_ONLY',prospective_tree=P.tree(after),map_sha256=pin(after[MAP][0])['sha256'],
                source_written=output is not None,actual=dict(source=None,ref=None,run=None,job=None,artifact=None),
                Native_POSTs=0,Original_GETs=0,Reader_calls=0,native='NOT_RUN',physical_M2='NOT_RUN',release='NOT_ADMITTED',acceptance=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--parent-source',type=Path,required=True)
    parser.add_argument('--profile-sha256',required=True);parser.add_argument('--output',type=Path)
    args=parser.parse_args();print(json.dumps(prepare(args.parent_source,args.profile_sha256,args.output),sort_keys=True))
