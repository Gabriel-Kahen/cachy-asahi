#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check future byte/inode demand, combining allocations on shared filesystems."""
import os
from pathlib import Path


def check(requirements, *, statvfs=None):
    statvfs = statvfs or os.statvfs
    filesystems = {}
    for row in requirements:
        path = Path(row['path'])
        size, inodes = row['bytes'], row['inodes']
        if type(size) is not int or type(inodes) is not int or min(size,inodes) < 0:
            raise ValueError('nonnegative finite capacity demand required')
        info, space = path.stat(), statvfs(path)
        value = filesystems.setdefault(info.st_dev, {'paths':[], 'bytes':0, 'inodes':0,
            'available_bytes':space.f_bavail*space.f_frsize, 'available_inodes':space.f_favail})
        value['paths'].append(str(path))
        value['bytes'] += size; value['inodes'] += inodes
        value['available_bytes'] = min(value['available_bytes'],space.f_bavail*space.f_frsize)
        value['available_inodes'] = min(value['available_inodes'],space.f_favail)
    for row in filesystems.values():
        if row['available_inodes'] <= 0 and row['inodes'] > 0:
            raise ValueError('insufficient or unknown filesystem free inode count')
        if row['bytes'] > row['available_bytes'] or row['inodes'] > row['available_inodes']:
            raise ValueError('insufficient future transaction bytes/inodes')
    return list(filesystems.values())
