# SPDX-License-Identifier: MIT
"""Project only the Fish entry's shared bootstrap and retirement seams."""

from hashlib import sha256
from pathlib import Path
import re
from types import ModuleType


SHARED_SHA256 = 'd340603c22b5747be7499de994ddf3bd1e2cb507d95f02be49f66ed7b5e04074'

EDITS = (
    (b'scopes=[];tag=None;report=dict(', b'scopes=[];tag=None;rootfs_bootstrap=None;report=dict('),
    (b"native.audit(inputs,output/'cache',output/'bootstrap');image=native.build",
     b"native.audit(inputs,output/'cache',output/'bootstrap')\n"
     b"        cache_handoff=PINNED_CARRIER.install_context_handoff(native,inputs,output/'cache',output/'bootstrap')\n"
     b"        rootfs_bootstrap=FISH_ROOTFS.install(native,runner,output/'bootstrap',nonce)\n"
     b"        image=native.build"),
    (b"        C.need((output/'bootstrap/packages.lock').read_bytes()==C.read(HERE/'expected349.lock'),'genuine exact freshly provisioned349 inventory')",
     b"        C.need((output/'bootstrap/packages.lock').read_bytes()==C.read(HERE/'expected349.lock'),'genuine exact freshly provisioned349 inventory')\n"
     b"        cache_handoff.retire_context()"),
    (b"        clean=not cleanup['errors']and all(",
     b"        FISH_ROOTFS.retire(rootfs_bootstrap,cleanup)\n"
     b"        clean=not cleanup['errors']and all("),
)


def project_entry(raw):
    """Preserve the prior held entry by an exact, independently checked inverse."""
    result = raw
    for before, after in EDITS:
        if result.count(before) != 1 or after in result:
            raise ValueError('one exact Fish rootfs entry seam required')
        result = result.replace(before, after, 1)
    restored = result
    for before, after in reversed(EDITS):
        restored = restored.replace(after, before, 1)
    if restored != raw:
        raise ValueError('whole Fish rootfs entry projection inverse failed')
    return result


def install(native, runner, out, nonce):
    """Bind the exact shared implementation after the original audit succeeds."""
    path = Path(__file__).resolve().with_name('signed_rootfs_bootstrap.py')
    body = path.read_bytes()
    if sha256(body).hexdigest() != SHARED_SHA256:
        raise ValueError('exact reviewed shared signed-rootfs bootstrap required')
    shared = ModuleType('fish_shared_signed_rootfs_bootstrap')
    shared.__file__ = str(path)
    exec(compile(body, str(path), 'exec'), shared.__dict__)
    state = shared.SignedRootfsBootstrap(native, runner, out, nonce, operation='fish02')
    bind_pacman_config_mode(native, out)
    return state


def retire(state, cleanup):
    """Join bounded base retirement to Fish's existing retained cleanup gate."""
    if state is None:
        return
    try:
        result = state.cleanup()
        if (type(result) is not dict or
                (result != {'submitted': False} and
                 (set(result) != {'submitted', 'image_id', 'owned_image_absence_verified'} or
                  result['submitted'] is not True or result['owned_image_absence_verified'] is not True or
                  (result['image_id'] is not None and
                   not re.fullmatch(r'sha256:[0-9a-f]{64}', result['image_id']))))):
            raise ValueError('exact owned Fish rootfs retirement summary required')
        cleanup['signed_rootfs_base'] = result
    except BaseException as error:
        cleanup['errors'].append(dict(step='owned-signed-rootfs', type=type(error).__name__))


# Fish r11 generated pacman.conf mode correction.
def normalize_pacman_config(path):
    """Expose only the reviewed generated config to the ordinary OCI builder."""
    import os
    import stat

    parent = path.parent
    info = parent.lstat()
    if (path.name != 'pacman.conf' or parent.name != 'context' or parent != parent.resolve()
            or info.st_mode != (stat.S_IFDIR | 0o700) or info.st_uid != os.getuid()):
        raise ValueError('exact private Fish build context required')

    def identity(s):
        return s.st_dev, s.st_ino, s.st_nlink, s.st_uid, s.st_gid, s.st_size, s.st_mtime_ns

    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as file:
        before = os.fstat(file.fileno())
        linked = path.lstat()
        if (before.st_mode != (stat.S_IFREG | 0o600) or before.st_nlink != 1 or before.st_uid != os.getuid()
                or before.st_mode != linked.st_mode or identity(before) != identity(linked)):
            raise ValueError('exact generated private pacman.conf required')
        raw = file.read(117)
        if (len(raw) != before.st_size or len(raw) != 116
                or sha256(raw).hexdigest() != '14d304eeb83baf1379279356c232580fd095c2d508b41c74677347801a0bafe7'):
            raise ValueError('exact reviewed pacman.conf bytes required')
        os.fchmod(file.fileno(), 0o644)
        after = os.fstat(file.fileno())
        linked = path.lstat()
        file.seek(0)
        if (after.st_mode != (stat.S_IFREG | 0o644) or after.st_mode != linked.st_mode
                or identity(after) != identity(before) or identity(after) != identity(linked)
                or file.read(117) != raw):
            raise ValueError('pacman.conf mode correction changed the selected file')


def bind_pacman_config_mode(native, out):
    existing = native.run
    build = ['docker', 'build', '--network=none', '--pull=false', '--platform=linux/arm64',
             '--iidfile', str(out/'image-id'), str(out/'context')]

    def run(argv, log=None, timeout=1800):
        if argv == build:
            normalize_pacman_config(out/'context/pacman.conf')
        return existing(argv, log, timeout)

    native.run = run
