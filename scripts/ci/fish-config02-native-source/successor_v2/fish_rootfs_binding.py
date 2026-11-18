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
    return shared.SignedRootfsBootstrap(native, runner, out, nonce, operation='fish02')


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
