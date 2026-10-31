#!/usr/bin/env python3
"""Exclusive once-only GET transport, preserving original failures and unknown outcomes."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import resource
import subprocess

import replay as R


def save(path,value):
    with path.open('x') as stream:
        json.dump(value,stream,sort_keys=True,indent=2)
        stream.write('\n');stream.flush();os.fsync(stream.fileno())


def original_get(path,suffix,cap,seconds):
    def limit():
        resource.setrlimit(resource.RLIMIT_FSIZE,(cap,cap))
    argv=['gh','api','--method','GET','repos/Gabriel-Kahen/cachy-asahi/'+suffix]
    with path.open('xb') as out,path.with_suffix(path.suffix+'.stderr').open('xb') as err:
        row=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=seconds,preexec_fn=limit)
    save(path.with_suffix(path.suffix+'.request.json'),dict(argv=argv,exit=row.returncode,cap=cap,timeout=seconds))
    R.need(row.returncode==0 and path.stat().st_size<=cap,'original GET failed; retained once, no retry')


def artifact_row(value,binding):
    rows=value['artifacts']
    R.need(type(value['total_count']) is int and value['total_count']==len(rows)<=100,'complete single artifact page')
    expected='gnu-verity-kernel-build-only-'+binding['run_id']+'-'+binding['run_attempt']
    found=[a for a in rows if a['name']==expected and a['expired'] is False]
    R.need(len(found)==1,'unique unexpired original GNU verity kernel build artifact required')
    item=found[0]
    R.need(type(item['id']) is int and item['id']>0 and type(item['size_in_bytes']) is int and
           0<item['size_in_bytes']<=R.MAX_ZIP,'bounded exact original artifact identity')
    run=item['workflow_run']
    R.need(str(run['id'])==binding['run_id'] and run['head_sha']==R.SOURCE and run['head_branch']==R.REF,'artifact original workflow join')
    return item


def collect(binding,selection,metadata,output,get=original_get):
    R.selected(binding,selection,archive=False)
    raw=R.ordinary(metadata,1024**2);run=R.decode(raw)
    R.run_identity(run,binding,success=False)
    R.preflight(R.HERE/'source')
    R.need(output.is_absolute() and output.parent.is_dir() and not any(p.is_symlink() for p in output.parents),'fresh ordinary collection location')
    # Exclusive mkdir reserves the entire operation, including unknown/partial outcomes.
    output.mkdir(mode=0o700)
    save(output/'collection-intent.json',dict(source=R.SOURCE,run=R.RUN,attempt='1',pid=os.getpid(),
         utc=datetime.now(timezone.utc).isoformat(),once=True,retry=False,dispatch=False))
    (output/'run.json').write_bytes(raw)
    result=dict(source=R.SOURCE,run=R.RUN,workflow_conclusion=run['conclusion'],
                status='COLLECTION_UNKNOWN',retry=False,acceptance_authority=False,cleanup_authority=False)
    try:
        get(output/'artifacts.json','actions/runs/'+R.RUN+'/artifacts?per_page=100',2*1024**2,40)
        get(output/'logs.zip','actions/runs/'+R.RUN+'/logs',64*1024**2,120)
        artifact=artifact_row(R.decode(R.ordinary(output/'artifacts.json',2*1024**2)),binding)
        get(output/'artifact.zip','actions/artifacts/'+str(artifact['id'])+'/zip',R.MAX_ZIP,120)
        package=R.ordinary(output/'artifact.zip',R.MAX_ZIP);identity=R.pin(package)
        R.need(identity['bytes']==artifact['size_in_bytes'],'original complete ZIP size')
        if artifact.get('digest') is not None:
            R.need(artifact['digest']=='sha256:'+identity['sha256'],'original API archive digest')
        save(output/'bound-original.json',dict(binding,artifact_sha256=identity['sha256']))
        result.update(status='ORIGINALS_COLLECTED_ONCE_NOT_ACCEPTED',artifact_id=artifact['id'],
                      artifact=identity,logs=R.pin(R.ordinary(output/'logs.zip',64*1024**2)),
                      metadata=R.pin(raw),artifact_metadata=R.pin(R.ordinary(output/'artifacts.json',2*1024**2)))
    except BaseException as error:
        result.update(error_type=type(error).__name__,error=str(error)[:512])
        save(output/'collection-outcome.json',result)
        raise
    save(output/'collection-outcome.json',result)
    return result


if __name__=='__main__':
    cli=argparse.ArgumentParser(description=__doc__)
    for name in ('binding','selection','metadata','output'):cli.add_argument('--'+name,type=Path,required=True)
    args=cli.parse_args()
    result=collect(R.decode(args.binding.read_bytes()),R.decode(args.selection.read_bytes()),args.metadata.absolute(),args.output.absolute())
    print(json.dumps(result,sort_keys=True))
