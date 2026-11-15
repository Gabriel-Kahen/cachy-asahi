# SPDX-License-Identifier: MIT
"""Opt-in Docker28 nested namespace policy; no action or observation on import."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

HERE = Path(__file__).resolve().parent
BASE = dict(bytes=12828, sha256='9c1025c88ccaa517b648da571961838744ea2137f176bfe6a48b21294cae9c76')
PROFILE = dict(bytes=17303, sha256='471a0bfd86586464226ac69cedf7104ab573d37c3be83771a3fb5f33e95f1e29')
SERVER = dict(Version='28.0.4', Os='linux', Arch='arm64')
KIND = 'MOBY28_NESTED_USER_MOUNT_NET_V1'
COMMAND = ['docker', 'version', '--format', '{{json .Server}}']


def need(ok, why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def read(path):
    path = Path(path)
    need(path.is_absolute() and path.anchor == '/' and '..' not in path.parts and
         not any(c in str(path) for c in '\n\r\0') and
         not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute nonaliased policy path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid in (0, os.getuid()) and
             not before.st_mode & 0o022 and 0 < before.st_size <= 256 * 1024, 'safe bounded ordinary policy file required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:raw = stream.read(256 * 1024 + 1)
        identity = lambda v:tuple(getattr(v, 'st_' + n) for n in ('dev','ino','mode','uid','gid','nlink','size','mtime_ns','ctime_ns'))
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'policy changed during read')
        return raw
    finally:os.close(fd)


def eq(index, value):return dict(index=index, value=value, op='SCMP_CMP_EQ')


def rule(name, *args):return dict(names=[name], action='SCMP_ACT_ALLOW', **({'args':list(args)} if args else {}))


def additions():
    return [rule('clone', eq(0, 0x50020011)), rule('unshare', eq(0, 0x10000000)),
            rule('mount'), rule('pivot_root'), rule('umount2', eq(1, 2)),
            rule('mount_setattr', eq(2, 4096), eq(4, 32)),
            rule('mount_setattr', eq(2, 36864), eq(4, 32))]


def validate(raw, expected):
    need(expected == PROFILE['sha256'] and pin(raw) == PROFILE, 'independently reviewed exact nested policy SHA-256 required')
    baseline = read(HERE / 'default.json')
    need(pin(baseline) == BASE, 'whole pinned Moby28.0.4 default profile required')
    before = json.loads(baseline);after = json.loads(raw)
    need(after == dict(before, syscalls=before['syscalls'] + additions()), 'only seven explicit namespace rules may differ')
    return raw


def request(path, expected, network, mode):
    need((path is None) == (expected is None), 'profile path and reviewed SHA-256 must be supplied together')
    if path is None:return None
    need(network == 'none' and mode == 'native', 'nested profile requires offline native ARM mode')
    need(os.getuid() == os.geteuid() > 0, 'ordinary non-root nested builder caller required')
    return validate(read(path), expected)


def engine():
    result = subprocess.run(COMMAND, stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
    need(len(result.stdout) + len(result.stderr) <= 1024**2 and result.returncode == 0 and not result.stderr,
         'fresh bounded successful Docker server version query required')
    return server(json.loads(result.stdout))


def server(value):
    need(type(value) is dict and all(type(value.get(k)) is str and value[k] == v for k,v in SERVER.items()),
         'nested profile covers only observed Docker server28.0.4/linux/arm64')
    return dict(SERVER)


def descriptor(observed):
    return dict(kind=KIND, profile=dict(PROFILE), baseline=dict(BASE), server=server(observed),
                namespace_qualification='NOT_RUN', kernel_LSM='NOT_QUALIFIED')


def retain(raw, observed, output):
    validate(raw, PROFILE['sha256']);value = descriptor(observed);output = Path(output)
    need(output.stat().st_uid == os.getuid() and not output.stat().st_mode & 0o022, 'safe owned new policy output required')
    with (output / 'nested-seccomp.json').open('xb') as stream:
        stream.write(raw);os.fchmod(stream.fileno(), 0o444)
    verify(output, value)
    return value


def verify(output, value):
    if value is None:return
    need(type(value) is dict and value == descriptor(value.get('server')), 'closed exact default/custom policy binding required')
    validate(read(Path(output) / 'nested-seccomp.json'), PROFILE['sha256'])


def arguments(output, value):
    if value is None:return []
    verify(output, value)
    return ['--security-opt', 'seccomp=' + str(Path(output) / 'nested-seccomp.json')]
