#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One declared copied-root cache initialization, before any update baseline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import aux_checkpoint as aux
import full_root as roots
import measure_copy as copy
import scale_update as scale
import supervision

CACHES = {aux.MAIN_CACHE, aux.AUX_CACHE}


def observe(root, limits):
    value = roots.observe(root, limits=limits, hardlinks='generic-development-internal')
    aux.need(value['complete'] is True and set(value['unsupported_counts']) <= {'absolute-symlink','auxiliary-present'}, 'initialization-root-shape')
    return value


def limits_from(config):
    value = config['limits']
    return roots.Limits(deadline=time.monotonic()+value['seconds'],max_nodes=value['root_nodes'],
        max_bytes=value['root_bytes'],max_file_bytes=value['file_bytes'],max_package_files=value['package_files'])


def exec_helper(root, workspace):
    """Worker only: pin static ELF, chroot through retained FD, then exec by FD."""
    scale.bound.guard(root, workspace)
    aux.need(os.execve in os.supports_fd, 'fd-exec-unavailable')
    limits = roots.Limits(deadline=time.monotonic()+150)
    observation = observe(root, limits)
    aux.checkpoint(root, observation, limits)  # Includes exact helper/config/scan closure.
    rootfd = roots._open_root(root)
    helper = None
    try:
        root_id, mount = roots._identity(os.fstat(rootfd)), roots._mount_id(rootfd, limits)
        with copy._parent(rootfd, aux.HELPER_NODE, mount, {}, limits, observation['nodes']) as (parent, base):
            helper = os.open(base, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            info = os.fstat(helper)
            aux.need(info.st_nlink == 1 and info.st_size == aux.HELPER[1]
                     and roots._file_hash(helper,info,limits) == aux.HELPER[0], 'initialization-helper-pin')
            copy._metadata_equal(info, observation['nodes'][aux.HELPER_NODE])
            aux.need(roots._mount_id(helper,limits) == mount, 'initialization-helper-mount')
        copy._root_check(root,rootfd,root_id,mount,limits)
        # No -r fallback: failure to chroot is terminal. No source-root FD is open.
        os.fchdir(rootfd); os.chroot('.'); os.chdir('/')
        os.close(rootfd); rootfd = None
        os.execve(helper, ['/usr/bin/ldconfig'], {'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','HOME':'/','TMPDIR':'/tmp'})
    finally:
        if helper is not None: os.close(helper)
        if rootfd is not None: os.close(rootfd)


def initialize(args, source, *, comparator_path):
    """Source is the complete supplied pre-copy tree, never a command target."""
    result = dict(status='FAIL',phase='configuration',initialization_started=False,root_initialized=False,
        source_preserved='NOT CHECKED',copy_byte_identical_after_initialization=False,
        transaction_acceptance='NOT ESTABLISHED',hardware='NOT RUN')
    original = None
    try:
        root,workspace,source = Path(args.root),Path(args.workspace),Path(source)
        scale.bound.guard(root,workspace)
        aux.need(source.is_absolute() and not root.is_relative_to(source) and not source.is_relative_to(workspace), 'disjoint-initialization-source')
        config = scale.configuration(args.scale,args.scale_sha256); limits = limits_from(config)
        comparator = aux.load_comparator(comparator_path,limits)
        original = observe(source,limits)
        result['phase'] = 'before-initialization'
        before = observe(root,limits); old = aux.checkpoint(root,before,limits)
        # One exclusive marker prevents a failed/unknown attempt from being retried.
        with copy._descriptors() as held:
            fd = roots._open_root(workspace); held.append(fd)
            marker = os.open('aux-initialization-started',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd); held.append(marker)
        result.update(phase='initialization-worker',initialization_started=True,root_initialized='UNKNOWN')
        remaining = limits.deadline-time.monotonic(); aux.need(remaining > 0,'initialization-deadline')
        row = supervision.run([sys.executable,'-B',str(Path(__file__).absolute()),'--worker','--root',str(root),'--workspace',str(workspace)],
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','HOME':str(workspace),'TMPDIR':str(workspace),
                 'PYTHONDONTWRITEBYTECODE':'1','CACHY_ASAHI_BOUND_UPDATE':os.environ.get('CACHY_ASAHI_BOUND_UPDATE','')},
            cwd=str(workspace),timeout=min(180,remaining),output_limit=65536)
        result['helper_exit_status'] = 0 if row['termination'] is None and row['returncode'] == 0 else 'NOT OBSERVED'
        result['worker'] = {key:row[key] for key in ('returncode','termination','direct_child_reaped','group_kill_sent')}
        aux.need(row['termination'] is None and row['returncode'] == 0 and row['direct_child_reaped'] is True,'initialization-worker-failed')
        result['phase'] = 'after-initialization'
        after = observe(root,limits); new = aux.checkpoint(root,after,limits)
        aux.need({k:v for k,v in before['nodes'].items() if k not in CACHES}
                 == {k:v for k,v in after['nodes'].items() if k not in CACHES}
                 and before['hardlink_groups'] == after['hardlink_groups'],'initialization-unrelated-root-change')
        # Only generated cache bytes/size/inodes may differ in this preparation.
        for name,mode in ((aux.MAIN_CACHE,0o644),(aux.AUX_CACHE,0o600)):
            node = new['caches'][name]['node']
            aux.need(node['type']=='file' and (node['uid'],node['gid'],node['mode'])==(0,0,mode),'initialized-cache-metadata')
        for field in ('helper','configs','aliases','scan','targets','closure','scan_directories'):
            aux.need(old[field] == new[field],'initialization-'+field+'-changed')
        # Cache parent inode/metadata and both temporary absences stay fixed.
        for name in set(old['caches'])-CACHES:
            aux.need(old['caches'][name] == new['caches'][name],'initialization-cache-parent-or-temp')
        result.update(status='PASS',phase='completed',root_initialized=True,helper_exit_status=0,
            scope='one-copied-root-cache-initialization-before-update-baseline',
            cache_hashes={name:dict(before=old['caches'][name]['node']['sha256'],after=new['caches'][name]['node']['sha256']) for name in sorted(CACHES)},
            live_cache_keys=aux.live_keys(new,comparator))
    except BaseException as error:
        result.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:256])
    finally:
        if original is not None:
            try:
                current = observe(source,limits)
                result['source_preserved'] = (original['nodes']==current['nodes'] and original['hardlink_groups']==current['hardlink_groups'])
                aux.need(result['source_preserved'],'initialization-source-changed')
            except BaseException as error:
                if result['source_preserved'] == 'NOT CHECKED': result['source_preserved'] = 'UNKNOWN'
                result.update(status='FAIL',source_check_error=type(error).__name__)
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker',action='store_true',required=True)
    parser.add_argument('--root',type=Path,required=True); parser.add_argument('--workspace',type=Path,required=True)
    args=parser.parse_args(); exec_helper(args.root,args.workspace)
