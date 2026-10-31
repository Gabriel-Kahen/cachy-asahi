# SPDX-License-Identifier: MIT
"""Exact accepted kernel DATA and separate runtime facts; no acquisition/actors."""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

IMAGE = {'bytes': 9019400, 'sha256': 'cd8053ebdb83302015efbad97ab1cc53fcd5a2353bf3f37ba208f4e6360946ec'}
CONFIG = {'bytes': 68789, 'sha256': 'e97d54d4852eceb6cba28c38f78d4a00aacbfdb0c1523cb96366590f7eaa915b'}
HEADER = {'bytes': 64, 'sha256': '621f2a525f58d3eeca54a8cd049939a0382e8bad48b07b7533850ff310162fcc'}
RELEASE = '7.1.13-generic16k-managed-gui'
FILES = {'Image', 'config', 'kernel-input.json'}
BUILTINS = ('CONFIG_ARM64_16K_PAGES', 'CONFIG_USER_NS', 'CONFIG_PID_NS', 'CONFIG_NET_NS',
            'CONFIG_SECCOMP', 'CONFIG_SECCOMP_FILTER', 'CONFIG_EXT4_FS',
            'CONFIG_EXT4_FS_POSIX_ACL', 'CONFIG_EXT4_FS_SECURITY', 'CONFIG_VIRTIO_PCI',
            'CONFIG_VIRTIO_BLK', 'CONFIG_DEVTMPFS', 'CONFIG_PROC_FS', 'CONFIG_SYSFS',
            'CONFIG_CGROUPS', 'CONFIG_TMPFS_POSIX_ACL', 'CONFIG_TMPFS_XATTR')


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def expected_descriptor():
    """Independent copy of 0db93415's complete source-owned BUILD_ONLY descriptor."""
    return dict(purpose='FRESH607_GENERIC16K_BUILD_ONLY_KERNEL_INPUT',
                source='4056e2505ed7081674e949e0460258672cce14ff',
                ref='codex/gnu-verity-kernel-config-domain-v1', run='39156901928',
                artifact=dict(bytes=9348486, id=12147995917,
                              name='gnu-verity-kernel-build-only-39156901928-1',
                              digest='sha256:b07124fb219e4af315094f97f201490433fc120a45cd3b55f39f9588e65d3057',
                              sha256='b07124fb219e4af315094f97f201490433fc120a45cd3b55f39f9588e65d3057'),
                Image=dict(IMAGE), config=dict(CONFIG), header=dict(HEADER),
                build_decision=dict(bytes=6667, sha256='f615551a21aa60195ca62884bc0359f4630da9cb12f8e10ad949b41798a4764a'),
                page_size=16384, kernel=RELEASE, modules='DISABLED',
                boot='NOT_RUN', fresh607='NOT_RUN', hardware='NOT_RUN')


def profile(value):
    need(type(value) is dict and encoded(value) == encoded(expected_descriptor()),
         'complete fixed source-owned kernel descriptor required')
    return expected_descriptor()


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate kernel descriptor JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite kernel JSON'))


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def ordinary(root):
    root = Path(root).absolute()
    need('..' not in root.parts and root == root.resolve(strict=True) and
         not any(path.is_symlink() for path in (root, *root.parents)),
         'canonical ordinary kernel DATA directory required')
    return root


def read_at(directory, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=directory)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 <= before.st_size <= maximum, 'bounded singlelink regular kernel DATA required')
        need(identity(before) == identity(os.stat(name, dir_fd=directory, follow_symlinks=False)),
             'kernel DATA descriptor/path differs before read')
        data = bytearray()
        while chunk := os.read(fd, min(1024**2, before.st_size - len(data) + 1)):
            data.extend(chunk)
            need(len(data) <= before.st_size, 'kernel DATA grew during read')
        need(len(data) == before.st_size and identity(before) == identity(os.fstat(fd)) ==
             identity(os.stat(name, dir_fd=directory, follow_symlinks=False)),
             'kernel DATA changed during read')
        return bytes(data)
    finally:
        os.close(fd)


def pin(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def configuration(raw):
    rows = {}
    for line in raw.decode('ascii').splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1)
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            key, value = line[2:-11], 'n'
        else:
            continue
        need(key not in rows, 'duplicate kernel configuration')
        rows[key] = value
    wanted = dict.fromkeys(BUILTINS, 'y')
    wanted.update(CONFIG_MODULES='n', CONFIG_ARM64_4K_PAGES='n', CONFIG_ARM64_64K_PAGES='n',
                  CONFIG_LOCALVERSION='"-generic16k-managed-gui"')
    need(all(rows.get(key) == value for key, value in wanted.items()),
         'complete fixed kernel facilities required; modules disabled')


def verify(root, descriptor):
    """Return (profile, Image bytes, config bytes); DATA grants no boot authority."""
    selected = profile(descriptor)
    root = ordinary(root)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(identity(before) == identity(root.lstat()) and set(os.listdir(fd)) == FILES,
             'closed exact three-file kernel DATA directory required')
        members = {name: identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) for name in FILES}
        metadata = read_at(fd, 'kernel-input.json', len(encoded(selected)))
        need(profile(decode(metadata)) == selected and metadata == encoded(selected),
             'exact canonical source-owned kernel descriptor bytes required')
        image = read_at(fd, 'Image', IMAGE['bytes'])
        config = read_at(fd, 'config', CONFIG['bytes'])
        need(pin(image) == IMAGE and pin(config) == CONFIG, 'exact fixed Image/config bytes required')
        need(pin(image[:64]) == HEADER and image[56:60] == b'ARMd' and
             (struct.unpack_from('<Q', image, 24)[0] >> 1) & 3 == 2,
             'exact AArch64 header and 16K geometry required')
        configuration(config)
        need(ordinary(root) == root and set(os.listdir(fd)) == FILES and
             identity(before) == identity(os.fstat(fd)) == identity(root.lstat()) and
             members == {name: identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) for name in FILES},
             'kernel DATA namespace changed during verification')
        return selected, image, config
    finally:
        os.close(fd)


def actual(facts, selected):
    """Validate caller-supplied runtime facts separately from BUILD_ONLY DATA."""
    profile(selected)
    expected = dict(sysname='Linux', architecture='aarch64', page_size=16384, kernel=RELEASE)
    need(type(facts) is dict and encoded(facts) == encoded(expected),
         'closed exact current generic16K runtime facts required')
    return dict(expected)
