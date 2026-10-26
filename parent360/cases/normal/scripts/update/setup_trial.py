#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy/initialize/update glue; signed input construction remains with the driver."""
from pathlib import Path

import aux_checkpoint as aux
import aux_copy
import aux_initialize
import linked_runtime
import scale_update as scale


def run(args,source,*,comparator_path):
    """Return separate preparation/transaction/cleanup truth, with no retries."""
    phase='configuration'
    result=dict(status='FAIL',phase=phase,transaction={'status':'NOT RUN','commit_started':False,
        'packages_committed':False,'checkpoint_changed':False},full587_composition='NOT ESTABLISHED',
        apple_acceptance='NOT ESTABLISHED',hardware='NOT RUN')
    try:
        workspace=Path(args.workspace)
        aux.need(Path(args.root)==workspace/'root','trial-root-workspace')
        config=scale.configuration(args.scale,args.scale_sha256)
        limits=aux_initialize.limits_from(config)
        phase='copy'
        with aux_copy.copied_root(source,workspace,limits=limits) as (root,copy_report):
            result['copy']=copy_report
            aux.need(root==Path(args.root),'trial-copied-root')
            phase='cache-initialization'
            result['initialization']=aux_initialize.initialize(args,source,comparator_path=comparator_path)
            initialized=result['initialization']
            if initialized['status']=='PASS' and initialized['root_initialized'] is True and initialized['source_preserved'] is True:
                phase='signed-update'
                result['transaction']=linked_runtime.apply(args,comparator_path=comparator_path)
            phase='cleanup'
        if result['transaction']['status']=='PASS' and result['copy']['cleanup']=='PASS-owned-workspace-removed':
            result.update(status='PASS',phase='completed')
        else: result['phase']='signed-update' if result['transaction']['status']!='NOT RUN' else 'cache-initialization'
    except BaseException as error:
        result.update(status='FAIL',phase=phase,error_type=type(error).__name__,error=str(error)[:256])
    return result
