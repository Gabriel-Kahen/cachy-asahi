# SPDX-License-Identifier: MIT
"""Private mount-root entry and passive namespace evidence for Overlay583."""

from base64 import b64decode
import json
import os
from pathlib import Path
import re
import stat
import sys

SUPPLEMENT = Path('/trial-code/first-login')
TARGET_WORK = Path('/run/caa-platform-tools-v2-overlay583')
ACCOUNT = 'caa-platform-v2-guest'

# BEGIN GUEST SOURCE
JOURNEY = 'first-login-installed-journey'
JOURNEY_ROOT_FLAG = '--private-mount-root-journey'
STOCK_PYTHON = '/trial-media/runtime/usr/bin/python3.14'
TARGET = Path('/trial-work/target')
ROOT_MARKER = b'PLATFORM_TOOLS_JOURNEY_MOUNT_ROOT_DATA '
API_MOUNTS = {'proc':'proc','sys':'sysfs','run':'tmpfs','dev':'tmpfs'}


def ordinary_journey(nonce):
    return ['/usr/bin/runuser','-u',ACCOUNT,'--','/usr/bin/env','-i',
            'PATH=/usr/bin:/bin','LC_ALL=C','TZ=UTC','HOME='+str(TARGET_WORK/'home'),
            '/usr/bin/python3','-I','-B',str(TARGET_WORK/'target.py'),nonce]


def mount_rows(text):
    rows = {}
    for line in text.splitlines():
        left, sep, right = line.partition(' - ')
        fields = left.split()
        if not sep or len(fields)<6 or len(right.split())!=3:
            raise ValueError('exact guest mountinfo required')
        id_, parent = map(int,fields[:2])
        if id_ in rows:
            raise ValueError('duplicate guest mount id')
        rows[id_] = (parent,fields[4],set(fields[5].split(',')),fields[6:],right.split()[0])
    return rows


def one_mount(rows, path, kind, options):
    found = [id_ for id_, row in rows.items() if row[1]==str(path)]
    if len(found)!=1 or not options<=rows[found[0]][2] or rows[found[0]][4]!=kind:
        raise ValueError('exact guest mount geometry required')
    return found[0]


def root_snapshot(rows, target):
    root = one_mount(rows,'/','ext4',{'ro'} if target==TARGET else {'rw','nosuid','nodev'})
    if rows[root][0] in rows and rows[root][0]!=root:
        raise ValueError('visible root must be the root of this mount namespace')
    for name, kind in API_MOUNTS.items():
        one_mount(rows,target/name,kind,{'nosuid','noexec'})
    return root


def mount_namespace(raw):
    return type(raw) is str and re.fullmatch(r'mnt:\[[1-9][0-9]*\]',raw) is not None


def enter_private_root(nonce):
    """Preserve the installed target and its four API mounts under a new guest mount root."""
    if not (sys.flags.isolated and sys.dont_write_bytecode
            and Path(__file__)==SUPPLEMENT/'guest.py' and sys.executable==STOCK_PYTHON
            and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'
            and os.sysconf('SC_PAGE_SIZE')==16384 and re.fullmatch('[0-9a-f]{32}',nonce)
            and Path('/proc/cmdline').read_text().split().count('cachy_overlay583_nonce='+nonce)==1
            and {entry.name for entry in Path('/sys/class/net').iterdir()}=={'lo'}
            and TARGET.resolve(strict=True)==TARGET and TARGET.is_dir()
            and TARGET.stat().st_dev==TARGET.parent.stat().st_dev!=Path('/').stat().st_dev):
        raise ValueError('exact owned offline ARM16K guest target required')
    parent = os.readlink('/proc/1/ns/mnt')
    if not mount_namespace(parent) or os.readlink('/proc/self/ns/mnt')!=parent:
        raise ValueError('exact inherited guest mount namespace required')
    mountinfo = Path('/proc/self/mountinfo')
    rows = mount_rows(mountinfo.read_text())
    root_snapshot(rows,TARGET)
    one_mount(rows,TARGET.parent,'ext4',{'rw','nosuid','nodev'})
    one_mount(rows,SUPPLEMENT.parent,'ext4',{'ro','nosuid','nodev','noexec'})
    from ctypes import CDLL, c_int, c_char_p, c_long, c_ulong, get_errno
    libc = CDLL('libc.so.6',use_errno=True)
    libc.unshare.argtypes = [c_int]
    libc.mount.argtypes = [c_char_p,c_char_p,c_char_p,c_ulong,c_char_p]
    libc.syscall.restype = c_long
    libc.umount2.argtypes = [c_char_p,c_int]

    def checked(label, fn, *args):
        if fn(*args)!=0:
            raise OSError(get_errno(),label)

    ns_newns, ms_rec, ms_private, ms_bind = 0x20000, 0x4000, 0x40000, 0x1000
    checked('private guest mount namespace',libc.unshare,ns_newns)
    child = os.readlink('/proc/self/ns/mnt')
    if child==parent or not mount_namespace(child):
        raise ValueError('distinct private guest mount namespace required')
    checked('private guest mount propagation',libc.mount,None,b'/',None,ms_rec|ms_private,None)
    before = mount_rows(mountinfo.read_text())
    old_root = root_snapshot(before,TARGET)
    if any(row[3] for row in before.values()):
        raise ValueError('guest mount propagation must be private')
    identities = {name: identity(TARGET/name) for name in ('',*API_MOUNTS)}
    target = os.fsencode(TARGET)
    checked('bound installed target and API mounts',libc.mount,target,target,None,ms_rec|ms_bind,None)
    os.chdir(TARGET)
    # AArch64 __NR_pivot_root. Stacking the old root here avoids a target directory.
    checked('installed mount root',libc.syscall,c_long(41),b'.',b'.')
    checked('detached boot root',libc.umount2,b'.',2)
    os.chdir('/')
    after = mount_rows(mountinfo.read_text())
    root_snapshot(after,Path('/'))
    if old_root in after or any(row[3] for row in after.values()) or any(
            identity(Path('/')/name)!=held for name,held in identities.items()):
        raise ValueError('detached boot root and same installed target required')
    if os.readlink('/proc/self/ns/mnt')!=child or os.readlink('/proc/1/ns/mnt')!=parent:
        raise ValueError('private guest mount namespace identity differs')
    evidence = dict(nonce=nonce,parent=parent,owner=child,root='SAME_INSTALLED_TARGET',
                    api='SAME_FOUR_API_MOUNTS',old_root='DETACHED')
    print(ROOT_MARKER.decode('ascii')+json.dumps(evidence,sort_keys=True,separators=(',',':')),
          file=sys.stderr,flush=True)
    argv = ordinary_journey(nonce)
    os.execve(argv[0],argv,{'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'})


def identity(path):
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError('ordinary target/API mountpoint required')
    return info.st_dev,info.st_ino


def journey_root_evidence(stderr, nonce, *, required):
    lines = [line for line in stderr.splitlines() if line.startswith(ROOT_MARKER)]
    if not lines and not required:
        return None
    if len(lines)!=1 or len(lines[0])>512:
        raise ValueError('one bounded owned journey mount-root witness required')
    body = lines[0][len(ROOT_MARKER):]
    observed = json.loads(body)
    if not (type(observed) is dict and set(observed)=={'nonce','parent','owner','root','api','old_root'}
            and body==json.dumps(observed,sort_keys=True,separators=(',',':')).encode('ascii')
            and observed['nonce']==nonce and mount_namespace(observed['parent'])
            and mount_namespace(observed['owner']) and observed['parent']!=observed['owner']
            and observed['root']=='SAME_INSTALLED_TARGET' and observed['api']=='SAME_FOUR_API_MOUNTS'
            and observed['old_root']=='DETACHED'):
        raise ValueError('exact owned journey mount-root witness required')
    return observed


NAMESPACE_HOLD_MARKER = b'PLATFORM_TOOLS_ORDINARY_NAMESPACE_HOLD_DATA '
NAMESPACE_REASONS = {'BWRAP_USER_NAMESPACE_PERMISSION','BWRAP_MOUNT_PERMISSION','UNCLASSIFIED'}


def journey_observations(stdout, stderr, nonce, exit_code):
    root = journey_root_evidence(stderr,nonce,required=exit_code==0)
    failures = [line[len(NAMESPACE_HOLD_MARKER):] for line in stderr.splitlines()
                if line.startswith(NAMESPACE_HOLD_MARKER)]
    if exit_code==0:
        ordinary = json.loads(stdout)['commands']['ordinary']['output']
        facts = json.loads(b64decode(ordinary,validate=True))
        if failures or facts['ns']['mnt']!=root['owner']:
            raise ValueError('ordinary journey must begin in the exact owned mount root')
    diagnostic = None
    if failures:
        if len(failures)!=1 or root is None or exit_code!=1 or len(failures[0])>512:
            raise ValueError('one bounded owned namespace failure witness required')
        diagnostic = json.loads(failures[0])
        if not (type(diagnostic) is dict and set(diagnostic)=={'exit','bytes','sha256','reason'}
                and failures[0]==json.dumps(diagnostic,sort_keys=True,separators=(',',':')).encode('ascii')
                and type(diagnostic['exit']) is int and diagnostic['exit']>0
                and type(diagnostic['bytes']) is int and 0<=diagnostic['bytes']<=128<<10
                and re.fullmatch('[0-9a-f]{64}',diagnostic['sha256'])
                and diagnostic['reason'] in NAMESPACE_REASONS):
            raise ValueError('exact naturally reaped namespace failure witness required')
    return dict(root=root,namespace_hold=diagnostic)
