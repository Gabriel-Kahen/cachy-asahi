#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Isolated opt-in binding of the exact safe copier/lifetime to selected data."""
from pathlib import Path
import hashlib
import os
import stat
import types

import aux_checkpoint as aux
import full_root as roots
import measure_copy
import disposable_copy
import root_link_selection as links

COPY_SHA256='e582245bd114b0b9d83f2de4fdc81a35d2f48493ba6147879871af794476813b'
LIFETIME_SHA256='fb05d12a0d67a598cc940e0bc7edb5aa9ffc8cf87ce7b9f695ba5fbd26747667'


def _isolated(source,expected):
    """Read/pin once, compile in a private namespace; no shared-global patch."""
    path=Path(source)
    with measure_copy._descriptors() as held:
        parent=roots._open_root(path.parent); held.append(parent)
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent); held.append(fd)
        info=os.fstat(fd)
        aux.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=512*1024,'copier-source-shape')
        data=bytearray()
        while len(data)<=info.st_size:
            block=os.read(fd,min(65536,info.st_size-len(data)+1))
            if not block: break
            data.extend(block)
        aux.need(len(data)==info.st_size and roots._identity(info)==roots._identity(os.fstat(fd))
                 ==roots._identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False))
                 and hashlib.sha256(data).hexdigest()==expected,'copier-source-pin-or-drift')
    module=types.ModuleType('_selected_'+path.stem); module.__file__=str(path)
    exec(compile(bytes(data),str(path),'exec'),module.__dict__)
    return module


def _copy_binding(limits):
    module=_isolated(measure_copy.__file__,COPY_SHA256)
    facade=types.SimpleNamespace(**vars(roots))
    def observe(root,**kwargs):
        observation=roots.observe(root,**kwargs)
        links.check(observation,kwargs['limits'])
        aux.checkpoint(root,observation,kwargs['limits'])
        return observation
    def eligible(observation):
        return links.check(observation,limits)
    def groups(before,after,*,protected_paths,limits):
        return roots.check_hardlink_preservation(links.view(before,limits),links.view(after,limits),
                                                protected_paths=protected_paths,limits=limits)
    facade.observe,facade.require_eligible,facade.check_hardlink_preservation=observe,eligible,groups
    module.roots=facade
    return module


def copy_data(source,target,*,limits,hardlinks='generic-development-internal'):
    aux.need(hardlinks=='generic-development-internal' and not limits.allow_cross_device,'complete-selected-copy-scope')
    report=_copy_binding(limits).copy_data(source,target,limits=limits,hardlinks=hardlinks)
    report.update(scope='complete-supplied-source-with-selected-links-and-held-auxiliary',
        copy_byte_identical_before_initialization=True,transaction_acceptance='NOT ESTABLISHED')
    # Existing observation report remains ineligible; a data copy grants no update.
    return report


def copied_root(source,workspace,*,limits,cleanup_seconds=60,cleanup_extra_nodes=10000):
    module=_isolated(disposable_copy.__file__,LIFETIME_SHA256)
    module.measure_copy=types.SimpleNamespace(copy_data=copy_data)
    return module.copied_root(source,workspace,limits=limits,cleanup_seconds=cleanup_seconds,
                              cleanup_extra_nodes=cleanup_extra_nodes)
