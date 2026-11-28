# SPDX-License-Identifier: MIT
"""Read the frozen release dependency used by the historical full-root tests."""

import hashlib
import os
from pathlib import Path
import stat
import subprocess

RELEASE = 'scripts/release/release.py'
COMMIT = '598a3dd77184f74935f71cb07c48c4411b6c44e4'
SHA256 = 'afd2bed6775d435e0a9a4dca62d162b5b32800d9d07dbb2cfc9642ddbcf14e6f'
MAX_BYTES = 1 << 20


def frozen_release(root):
    selected = os.environ.get('FROZEN_FULL_ROOT_RELEASE_HELPER')
    if not selected:
        body = subprocess.check_output(
            ['git', '--no-replace-objects', '-C', str(root), 'cat-file', 'blob', f'{COMMIT}:{RELEASE}'],
            timeout=10,
        )
    else:
        path = Path(selected)
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError('Expected an ordinary absolute frozen full-root release fixture')
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError('Expected a regular frozen full-root release fixture')
            body = stream.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES or hashlib.sha256(body).hexdigest() != SHA256:
        raise ValueError('Frozen full-root release fixture differs from its pinned digest')
    return body
