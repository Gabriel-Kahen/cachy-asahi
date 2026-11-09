#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite first-build-failure successor of actual developer Sourcedc36; DATA only."""
import argparse
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
PARENT='dc36f6dda0bab4a72604aad3782c2f6b5e933a38'
TREE='72daab4c387cfba649b10f08ef919072ebeda2eb'
MAP='native/source-map.json'
CHANGED=frozenset(('native/developer_tools_alpm_v1.py','native/developer_tools_projection_v1.py','native/developer_tools_reader_v1.py',MAP))

def need(ok,why):
    if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def construct(parent_source,output,profile_sha256):
    # The maintained helper is constructor code, never an operand from Source/artifacts.
    base=HERE.parent;helper_raw=(base/'data_helpers.py').read_bytes();B={'__file__':str(base/'data_helpers.py')}
    need(pin(helper_raw)==dict(bytes=9522,sha256='a85f92dcaaad0a7f8621b882fdf46fe26f579bb740354b1e4aa1f005aea48a76'),'held maintained DATA helper')
    exec(compile(helper_raw,B['__file__'],'exec'),B)
    raw,_=B['read'](HERE/'profile.json');need(pin(raw)['sha256']==profile_sha256,'external Root profile checksum')
    profile=B['decode'](raw)
    need(profile['schema']==1 and profile['variant']=='developer-build-pair-first-failure-v1'and profile['parent_source']==PARENT
        and profile['parent_tree']==TREE and profile['helpers']==pin(helper_raw) and profile['actual']==dict(source=None,ref=None,run=None)
        and (profile['source_files'],profile['changed'],profile['held'])==(200,4,196)and profile['native']=='NOT_RUN','exact unexecuted diagnostic Source200 variant')
    commit,_=B['read'](HERE/'parent.raw-commit');old_map,_=B['read'](base/'safe-failure-v1/payload/native/source-map.json')
    need(pin(commit)==profile['parent_raw']and pin(old_map)==profile['parent_map']and B['oid'](b'commit',commit).hex()==PARENT
        and commit.startswith(('tree '+TREE+'\n').encode()),'exact actual parent raw commit/map')
    files=B['snapshot'](parent_source);before=dict(files);rows=B['decode'](old_map)['files']
    need(len(files)==200 and files[MAP]==(old_map,0o644)and B['descriptors']({n:v for n,v in files.items()if n!=MAP})==rows
        and B['tree'](files)==TREE,'complete physical Sourcedc36 bytes/modes/tree')
    overlay=B['snapshot'](HERE/'payload');need(set(overlay)==CHANGED and B['descriptors'](overlay)==profile['overlay'],'exact four-leaf diagnostic overlay')
    files.update(overlay);manifest=B['decode'](files[MAP][0])
    need(set(files)==set(before)and manifest['actual']==dict(source=None,ref=None,run=None)
        and manifest['files']==B['descriptors']({n:v for n,v in files.items()if n!=MAP})and manifest['developer_build_pair_first_failure_parent']==PARENT
        and pin(files[MAP][0])==profile['source_map']and B['tree'](files)==profile['source_tree'],'closed200 map/tree and fixed namespace')
    need({n for n in files if files[n]!=before[n]}==CHANGED,'four changed leaves and196 held')
    restored=dict(files);restored.update({n:before[n]for n in CHANGED});need(restored==before,'complete original inverse')
    parent,output=B['absolute'](parent_source),B['absolute'](output)
    need(not output.is_relative_to(parent)and not parent.is_relative_to(output)and not output.is_relative_to(base)and not base.is_relative_to(output),'fresh disjoint private output')
    B['publish'](files,output)
    return dict(status='PREPARED_DEVELOPER_BUILD_PAIR_FIRST_FAILURE_SOURCE200_DATA_ONLY',parent=PARENT,tree=profile['source_tree'],source_map=profile['source_map'],actual=profile['actual'],native='NOT_RUN')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--parent-source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--profile-sha256',required=True)
    args=parser.parse_args();print(json.dumps(construct(args.parent_source,args.output,args.profile_sha256),sort_keys=True))
