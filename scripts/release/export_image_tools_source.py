#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Export one externally pinned finite image-tools source profile as data only."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

MAX_FILE = 8*1024**2
MAX_TOTAL = 16*1024**2
FIELDS = ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(rows):
        result = {}
        for key,value in rows:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False,'nonfinite-json'))


def read(path, maximum):
    path=Path(path).absolute()
    need(path==path.resolve(), 'source-path-symlink')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=maximum,
             'bounded-single-link-source')
        with os.fdopen(os.dup(fd),'rb') as stream:
            raw=stream.read(maximum+1)
        need(len(raw)==before.st_size and all(
            getattr(before,key)==getattr(os.fstat(fd),key)==getattr(path.lstat(),key) for key in FIELDS), 'source-drift')
        return raw
    finally:
        os.close(fd)


def relative(name):
    need(type(name) is str and 0<len(name)<=4096 and not name.startswith('/')
         and all(part not in ('','.','..') for part in name.split('/'))
         and re.fullmatch(r'[A-Za-z0-9._+/-]+',name), 'source-relative-path')
    return name


def export(root, profile_path, profile_sha256, output, overlay=None):
    need(type(profile_sha256) is str and re.fullmatch('[0-9a-f]{64}',profile_sha256), 'profile-sha256-required')
    profile_raw=read(profile_path,1024**2)
    need(sha(profile_raw)==profile_sha256, 'profile-pin')
    profile=decode(profile_raw)
    need(type(profile) is dict and set(profile)=={'schema_version','kind','epoch','original_source_revision','files'}
         and type(profile['schema_version']) is int and profile['schema_version']==1
         and profile['kind']=='cachy-asahi-image-tools-finite-source-v1'
         and type(profile['epoch']) is int and 0<=profile['epoch']<=2147483647
         and re.fullmatch('[0-9a-f]{40}',profile['original_source_revision']), 'finite-profile-schema')
    rows=profile['files']
    need(type(rows) is dict and 1<=len(rows)<=128, 'finite-file-bound')
    root=Path(root).absolute();overlay=Path(overlay).absolute() if overlay is not None else None
    need(root==root.resolve() and (overlay is None or overlay==overlay.resolve()), 'source-root-symlink')
    bodies={};total=0
    for name,row in sorted(rows.items()):
        relative(name)
        need(name != 'IMAGE_TOOLS_SOURCE_PROFILE.json', 'reserved-profile-member')
        need(type(row) is dict and set(row)=={'bytes','sha256','mode'}
             and type(row['bytes']) is int and 0<row['bytes']<=MAX_FILE
             and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256'])
             and type(row['mode']) is int and row['mode'] in (0o644,0o755), 'finite-row-schema')
        source=(overlay/name) if overlay is not None and os.path.lexists(overlay/name) else root/name
        raw=read(source,row['bytes'])
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'], 'finite-source-pin:'+name)
        total+=len(raw);need(total<=MAX_TOTAL,'finite-total-bound')
        bodies[name]=raw
    archive_raw=io.BytesIO()
    with gzip.GzipFile(filename='',mode='wb',fileobj=archive_raw,mtime=profile['epoch']) as zipped:
        with tarfile.open(fileobj=zipped,mode='w',format=tarfile.USTAR_FORMAT) as archive:
            for name,raw in sorted(dict(bodies,**{'IMAGE_TOOLS_SOURCE_PROFILE.json':profile_raw}).items()):
                info=tarfile.TarInfo(name);info.size=len(raw);info.mtime=profile['epoch']
                info.mode=rows[name]['mode'] if name in rows else 0o644
                archive.addfile(info,io.BytesIO(raw))
    raw=archive_raw.getvalue()
    output=Path(output).absolute()
    need(output.parent==output.parent.resolve(),'output-parent-symlink')
    fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    return dict(status='EXPORTED_EXACT_SOURCE_DATA_ONLY',files=len(bodies)+1,source_bytes=total,
                archive=dict(bytes=len(raw),sha256=sha(raw)),profile_sha256=profile_sha256,
                source_execution='NOT_RUN',native_ARM='NOT_RUN',installation='NOT_RUN',M2='NOT_RUN',release='NOT_ACCEPTED')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--profile',type=Path,required=True)
    parser.add_argument('--profile-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--overlay',type=Path)
    args=parser.parse_args()
    print(json.dumps(export(args.root,args.profile,args.profile_sha256,args.output,args.overlay),sort_keys=True))


if __name__=='__main__':main()
