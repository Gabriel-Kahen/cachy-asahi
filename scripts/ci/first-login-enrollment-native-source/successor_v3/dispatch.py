#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Strict current registry; invokes only the committed Root-selected owned callback."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import time

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('current_v3_dispatch_common',HERE/'common.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)


def registry(root,source_sha,grant,inputs,output,stage):
    _,program=C.source(root,source_sha)
    table=C.decode(C.read(root/C.PREFIX/'operation-registry.json',cap=1024**2)[0])
    expected=dict(api=C.API,callback='open_current_session',lifecycle_callback='launch_lifecycle',owner=program['owner'],route=program['route'],entry=program['registry'])
    C.need(table['schema']==3 and table['operations']=={C.OPERATION:expected} and table['actual_Root_admission']is None,
           'one exact new current operation; no generic or v1 registration')
    C.need(stage in C.STAGES and grant['operation']==C.OPERATION and grant['stage']==stage,'explicit current stage')
    owner=program['owner'];reference=dict(path=str(root/owner['path']),bytes=owner['bytes'],sha256=owner['sha256'])
    C.need(type(grant['owner'])is dict and grant['owner']['api']==C.API and grant['owner']['code']==reference,'actual grant must select the exact emitted committed owner')
    C.need(grant['source_root']==str(root) and grant['output']==str(output) and not output.exists()
           and output.is_absolute() and output==output.resolve() and root not in output.parents and output not in root.parents
           and root!=output,'exact fresh disjoint Root stage operands')
    C.need(grant['binding']['source_lock']==C.pin(C.read(root/'source.lock.json',cap=1024**2)[0]),'same complete Source map/lock binding')
    return program


def load(root,row,name):
    path=root/row['path'];raw,_=C.read(path,row,cap=128*1024)
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def lifecycle_entry(provider,grant,inputs,root,output,admission_path,admission_sha,inputs_path):
    C.need(callable(getattr(provider,'launch_lifecycle',None)) and isinstance(admission_path,Path) and isinstance(inputs_path,Path),
           'committed outer lifecycle launcher and literal Root operands required')
    admission_raw,_=C.read(admission_path,cap=4*1024**2);inputs_raw,_=C.read(inputs_path,cap=4*1024**2)
    C.need(C.pin(admission_raw)['sha256']==admission_sha and C.decode(admission_raw)==grant and C.decode(inputs_raw)==inputs
           and grant['owner']['admission_path']==str(admission_path)
           and grant['owner']['inputs']==dict(path=str(inputs_path),**C.pin(inputs_raw)),
           'same exact Root admission/input bytes and paths for outer lifecycle entry')
    return provider.launch_lifecycle(admission_path,admission_sha,inputs_path,root,output)


def execute(root,source_sha,grant,inputs,output,stage,*,admission_path=None,admission_sha=None,inputs_path=None):
    program=registry(root,source_sha,grant,inputs,output,stage)
    profile=C.decode(C.read(root/(C.FAMILY+'/successor_v2/profile.json'))[0])
    # Maintained route checks actual Source/run/job/images/current signatures,
    # capacity and independent runtime admission BEFORE provider code is loaded.
    route=load(root,program['route'],'root_committed_current_route_v3')
    C.need(route.OPERATION==C.OPERATION and callable(getattr(route,'admission',None))
           and callable(getattr(route,'run_registered',None)),'exact committed current route API')
    route.admission(grant,inputs,root,profile,stage,time.time())
    C.source(root,source_sha)
    provider=load(root,program['owner'],'root_committed_current_owner_v3')
    C.need(callable(getattr(provider,'open_current_session',None)),'committed actual current owner callback')
    if stage=='lifecycle':
        return lifecycle_entry(provider,grant,inputs,root,output,admission_path,admission_sha,inputs_path)
    return route.run_registered(stage=stage,source=root,profile=profile,inputs=inputs,grant=grant,output=output,
                                open_session=provider.open_current_session)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','admission','inputs','output'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('source-map-sha256','admission-sha256','inputs-sha256'):p.add_argument('--'+name,required=True)
    p.add_argument('--stage',choices=tuple(C.STAGES),required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
    C.need(a.execute and sys.flags.isolated and sys.dont_write_bytecode and __debug__,'explicit isolated Root stage entry')
    read=lambda path,sha:C.read(path,dict(bytes=path.stat().st_size,sha256=sha),cap=4*1024**2)[0]
    grant=C.decode(read(a.admission,a.admission_sha256));inputs=C.decode(read(a.inputs,a.inputs_sha256))
    result=execute(a.source,a.source_map_sha256,grant,inputs,a.output,a.stage,
                   admission_path=a.admission,admission_sha=a.admission_sha256,inputs_path=a.inputs)
    print(json.dumps(dict(status=result['status'],operation=C.OPERATION,stage=a.stage,Root_acceptance=None)))


if __name__=='__main__':main()
