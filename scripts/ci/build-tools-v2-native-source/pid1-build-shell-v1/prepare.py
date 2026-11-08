#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit BuildTools02 PID1-shell Source200 DATA variant. No emitted code import."""
import argparse
import hashlib
import json
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
PARENT='52a425ef08c5dc84ba1a7c5b53be8d21dc42f9dd'
MAP='native/source-map.json'
CHANGED=frozenset('native/'+name for name in (
    'build_tools_alpm_v2.py','build_tools_projection_v2.py','build_tools_reader_v2.py'))
BASE_SHA='444b673fc9f2643522009a8cec0ac8c599e922011d0a9968a98728a4b6f0707e'

def need(ok,why):
    if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def oid(kind,raw):return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def read(path):
    path=Path(path)
    need(path==path.resolve() and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary DATA path')
    before=path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=1024**2,'bounded single-link DATA file')
    raw=path.read_bytes();after=path.stat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(len(raw)==before.st_size and identity(before)==identity(after),'unchanged DATA input')
    return raw

def construct(parent_source,output,profile_sha256):
    raw=read(HERE/'profile.json');need(pin(raw)['sha256']==profile_sha256,'externally reviewed variant profile')
    profile=json.loads(raw)
    need(profile['schema']==1 and profile['variant']=='build-tools02-pid1-build-shell-v1'
         and profile['parent_source']==PARENT and profile['actual']==dict(source=None,ref=None,run=None)
         and (profile['source_files'],profile['changed'],profile['held'])==(200,4,196),'explicit Source200 variant')
    # Reuse maintained descriptor-relative snapshot and no-replace DATA publisher, never Source code.
    base=HERE.parent/'prepare.py';base_raw=read(base)
    need(pin(base_raw)==profile['base_factory'] and pin(base_raw)['sha256']==BASE_SHA,'pinned maintained DATA helpers')
    B={'__file__':str(base),'__name__':'_build_tools_pinned_data_helpers'}
    exec(compile(base_raw,str(base),'exec'),B)
    rows_raw=read(HERE/'parent-files.json');parent_raw=read(HERE/'parent.raw-commit')
    need(pin(rows_raw)==profile['parent_files'] and pin(parent_raw)==profile['parent_raw']
         and oid('commit',parent_raw)==PARENT and parent_raw.startswith(('tree '+profile['parent_tree']+'\n').encode()),'actual Source52 parent raw commit/map')
    rows=json.loads(rows_raw);files=B['snapshot'](parent_source)
    actual={name:dict(pin(body),mode=oct(mode|0o100000)[2:],oid=oid('blob',body)) for name,(body,mode) in files.items()}
    need(len(rows)==200 and actual==rows and B['tree'](files)==profile['parent_tree'],'complete physical Source52 namespace/body/mode/tree')
    manifest=json.loads(files[MAP][0]);map_raw=read(HERE/'parent-source-map.json')
    need(pin(map_raw)==profile['parent_source_map'] and files[MAP][0]==map_raw
         and manifest['actual']==dict(source=None,ref=None,run=None)
         and manifest['files']==B['descriptors']({n:v for n,v in files.items() if n!=MAP}), 'complete parent map199')
    need(set(profile['payload'])==CHANGED,'exact three code replacements')
    for name,row in profile['payload'].items():
        body=read(HERE/'payload'/name)
        need(pin(body)==row and files[name][1]==0o644,'exact replacement payload/mode')
        files[name]=(body,0o644);manifest['files'][name]=dict(pin(body),mode=0o644)
    need(profile['matching_reader']==dict(target='native/build_tools_reader_v2.py',**pin(files['native/build_tools_reader_v2.py'][0])),'matching successor reader')
    manifest['build_tools_pid1_shell_parent']=PARENT
    files[MAP]=((json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode(),0o644)
    after={name:dict(pin(body),mode=oct(mode|0o100000)[2:],oid=oid('blob',body)) for name,(body,mode) in files.items()}
    need(set(rows)==set(after) and {n for n in rows if rows[n]!=after[n]}==CHANGED|{MAP}
         and B['tree'](files)==profile['source_tree'] and pin(files[MAP][0])==profile['source_map'],'exact four replacements/196held inverse')
    parent=Path(parent_source).absolute();output=Path(output).absolute()
    need(not output.is_relative_to(parent) and not parent.is_relative_to(output)
         and not output.is_relative_to(HERE),'fresh disjoint DATA output')
    B['publish'](files,output)
    return dict(status='PREPARED_CLOSED_SOURCE200_DATA_ONLY',parent=PARENT,tree=profile['source_tree'],map_sha256=profile['source_map']['sha256'],
                files=200,changed=4,held=196,actual=dict(source=None,ref=None,run=None),native='NOT_RUN',reader_executed=False)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--parent-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--profile-sha256',required=True);a=p.parse_args()
    print(json.dumps(construct(a.parent_source,a.output,a.profile_sha256),sort_keys=True))
if __name__=='__main__':main()
