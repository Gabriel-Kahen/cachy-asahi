#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare one fixed developer-tools Source200 as inert DATA; Root owns actors."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat

HERE=Path(__file__).resolve().parent
PARENT='97a44c4c7cb206704bf76e9fd1f1afb2266278c2'
PARENT_TREE='81d61d9e1f33c1638e9f67fbd7e39b158c603451'
MAP='native/source-map.json'
OPERATION='developer-tools-alpm-v1'

def need(ok,why):
    if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path,cap=1024**2):
    path=Path(path)
    need(path.is_absolute()and path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'absolute ordinary DATA operand')
    before=path.lstat();need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=cap,'bounded single-link DATA operand')
    body=path.read_bytes();after=path.lstat();identity=lambda q:(q.st_dev,q.st_ino,q.st_mode,q.st_nlink,q.st_size,q.st_mtime_ns,q.st_ctime_ns)
    need(len(body)==before.st_size and identity(before)==identity(after),'stable whole DATA operand');return body

def policy(raw,checksum):
    need(type(checksum)is str and re.fullmatch('[0-9a-f]{64}',checksum)and pin(raw)['sha256']==checksum,'externally bound profile checksum required')
    value=json.loads(raw)
    need(type(value)is dict and value.get('schema')==1 and value.get('variant')=='developer-tools-native-source-v1'and value.get('parent_source')==PARENT and value.get('parent_tree')==PARENT_TREE and value.get('operation')==OPERATION and value.get('source_files')==200 and value.get('actual')==dict(source=None,ref=None,run=None)and value.get('native')=='NOT_RUN'and value.get('reader_executed')is False,'exact unexecuted developer-tools Source200 profile')
    need(type(value.get('removed'))is list and len(value['removed'])==10 and len(set(value['removed']))==10 and type(value.get('overlay'))is dict and len(value['overlay'])==19,'finite10 replaced operands and19 source overlay leaves')
    return value

def plan(parent,overlay,parent_rows,raw_commit,value,B):
    """Virtual Git/map/inverse algebra only, callable by actor-denied DATA controls."""
    need(hashlib.sha1(b'commit '+str(len(raw_commit)).encode()+b'\0'+raw_commit).hexdigest()==PARENT and raw_commit.startswith(('tree '+PARENT_TREE+'\n').encode()),'actual immutable parent commit DATA')
    need(B['descriptors'](parent)==parent_rows and len(parent)==200 and B['tree'](parent)==PARENT_TREE,'all200 physical parent bytes/modes/tree required')
    original=json.loads(parent[MAP][0]);need(original.get('actual')==dict(source=None,ref=None,run=None)and original.get('files')==B['descriptors']({n:v for n,v in parent.items()if n!=MAP}),'complete exact parent map199')
    need(B['descriptors'](overlay)==value['overlay'],'exact maintained overlay bytes/modes/namespace')
    removed=set(value['removed']);need(removed<=parent.keys()and not removed&overlay.keys(),'exact retired parent operand set')
    files={n:v for n,v in parent.items()if n not in removed};files.update(overlay)
    manifest=json.loads(files[MAP][0]);need(len(files)==200 and manifest.get('actual')==dict(source=None,ref=None,run=None)and manifest.get('developer_tools_parent')==PARENT and manifest.get('files')==B['descriptors']({n:v for n,v in files.items()if n!=MAP})and pin(files[MAP][0])==value['source_map']and B['tree'](files)==value['source_tree'],'exact final closed200 namespace/map/tree')
    restored=dict(files)
    for n in set(overlay)-parent.keys():restored.pop(n)
    for n in set(overlay)&parent.keys()|removed:restored[n]=parent[n]
    need(restored==parent,'complete bytes/modes inverse restores actual parent')
    contract=json.loads(files['native/developer-tools-contract-v1.json'][0]);need(contract['operation']==OPERATION and contract['actual']==dict(source=None,ref=None,run=None,job=None,artifact=None)and contract['recipe']['expected_test_count']==13 and len(contract['recipe']['payload_files'])==34 and contract['invocation']['inventory_counts']==[354,355,354],'exact package13/payload34/inventory354 lifecycle')
    need(files['.github/workflows/native-arm-build.yml']==files['.github/workflows/native-arm-developer-workflows.yml']and b'group: native-arm-build\n  cancel-in-progress: false\n  queue: max\n' in files['.github/workflows/native-arm-build.yml'][0],'Root-serialized heavy lane and equal manual Source workflows')
    return files

def construct(parent_source,output,profile_sha256):
    raw=read(HERE/'profile.json');value=policy(raw,profile_sha256)
    helper_raw=read(HERE/'data_helpers.py');need(pin(helper_raw)==value['data_helpers'],'exact maintained non-Source DATA helper bytes')
    B={'__file__':str(HERE/'data_helpers.py'),'__name__':'_developer_tools_data_helpers'};exec(compile(helper_raw,B['__file__'],'exec'),B)
    rows_raw=read(HERE/'parent-files.json');commit=read(HERE/'parent.raw-commit')
    need(pin(rows_raw)==value['parent_files']and pin(commit)==value['parent_raw'],'exact retained parent descriptors/raw-commit')
    files=plan(B['snapshot'](parent_source),B['snapshot'](HERE/'payload'),json.loads(rows_raw),commit,value,B)
    parent,output=Path(parent_source).absolute(),Path(output).absolute()
    need(parent==parent.resolve()and output==output.resolve()and not output.is_relative_to(parent)and not parent.is_relative_to(output)and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh disjoint private DATA output')
    B['publish'](files,output)
    return dict(status='PREPARED_DEVELOPER_TOOLS_CLOSED_SOURCE200_DATA_ONLY',parent=PARENT,tree=value['source_tree'],source_map=value['source_map'],files=200,operation=OPERATION,actual=value['actual'],native='NOT_RUN',reader_executed=False)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--profile-sha256',required=True)
    args=parser.parse_args();print(json.dumps(construct(args.parent_source,args.output,args.profile_sha256),sort_keys=True))
