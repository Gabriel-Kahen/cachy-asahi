# SPDX-License-Identifier: MIT
"""Finite diagnostics from the already reaped ordinary bubblewrap probe."""

from hashlib import sha256

MAX_OUTPUT = 128 << 10


def pin(body):
    return dict(bytes=len(body), sha256=sha256(body).hexdigest())


# BEGIN TARGET SOURCE
NAMESPACE_HOLD_MARKER = 'PLATFORM_TOOLS_ORDINARY_NAMESPACE_HOLD_DATA '


def clean_retirement(result):
    return (result['reaped'] is result['output_complete'] is True
            and result['ownership']=='REAPED' and result['group_census']=='EMPTY_TWICE'
            and result['timeout'] is False and result['signals']==[] and result['error'] is None)


def namespace_hold(body, receipt):
    if not clean_retirement(receipt) or type(receipt['exit']) is not int or receipt['exit']<=0:
        return None
    if len(body)>MAX_OUTPUT:
        raise ValueError('bounded complete namespace child output required')
    reason = 'UNCLASSIFIED'
    lines = body.splitlines()
    if len(lines)==1 and lines[0].startswith(b'bwrap: '):
        if (lines[0]==b'bwrap: No permissions to create a new namespace'
                or lines[0].startswith(b'bwrap: No permissions to create a new namespace, ')):
            reason = 'BWRAP_USER_NAMESPACE_PERMISSION'
        elif lines[0].endswith(b': Operation not permitted') and any(lines[0].startswith(message) for message in (
                b"bwrap: Can't mount ",b'bwrap: Failed to mount ',b'bwrap: Unable to mount ')):
            reason = 'BWRAP_MOUNT_PERMISSION'
    return dict(exit=receipt['exit'],reason=reason,**pin(body))
