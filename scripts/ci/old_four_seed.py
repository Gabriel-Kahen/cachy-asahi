# SPDX-License-Identifier: MIT
"""Reviewed four-blob transport seed; normal signed native audit remains mandatory."""
import base64
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import sys
import time


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def finite(value):
    try:return type(value) in (int,float) and math.isfinite(value)
    except (OverflowError,TypeError,ValueError):return False


def within(deadline):
    require(finite(deadline) and time.monotonic() < deadline,
            'development-deadline-exceeded')


OLD_FOUR_PRIVATE_PREFIX = 'CACHY_OLD_FOUR_'


OLD_FOUR_PRIVATE_ROWS = (
    ('jbigkit-2.1-8-aarch64.pkg.tar.xz', 48816,
     'ecaddb099f4a1f1bcbc1497fd0f3dc98581552b9eacaa17c5568211c38bec1db', 'JBIGKIT', 2),
    ('jbigkit-2.1-8-aarch64.pkg.tar.xz.sig', 566,
     'f00be593f9ab5855f9e450d054e6cacd319ec834ef7fc97c51bcf3be3ebfdb1f', 'JBIGKIT_SIG', 1),
    ('libtiff-4.7.2-1-aarch64.pkg.tar.xz', 354480,
     '02a5d2d74019b39befd6cf63d9bde95a2d16f91b4d0d56939498375e0e491ffd', 'LIBTIFF', 15),
    ('libtiff-4.7.2-1-aarch64.pkg.tar.xz.sig', 566,
     '8dae1efda531e3ac7db09512cfe0c619eaae6787cc16fdea1315588b4fc340fa', 'LIBTIFF_SIG', 1),
)


def seed_old_four_private_cache(cache, source_packet, deadline):
    """Exact old transport only; inherit J and erase chunks before native work."""
    within(deadline)
    header = {OLD_FOUR_PRIVATE_PREFIX + 'SCHEMA', OLD_FOUR_PRIVATE_PREFIX + 'SOURCE_EPOCH'}
    names = {OLD_FOUR_PRIVATE_PREFIX + f'{tag}_{i:02d}'
             for _, _, _, tag, count in OLD_FOUR_PRIVATE_ROWS for i in range(1, count + 1)}
    # All matching names are removed even if a surplus chunk causes refusal.
    captured = {name: os.environ.pop(name) for name in tuple(os.environ)
                if name.startswith(OLD_FOUR_PRIVATE_PREFIX)}
    within(deadline)
    require(len(captured) <= 21 and set(captured) <= names | header, 'private-cache-schema-refused')
    supplied = any(captured.get(name, '') for name in names)
    if not supplied:
        require(not captured or captured.get(OLD_FOUR_PRIVATE_PREFIX + 'SCHEMA') == '1' and
                captured.get(OLD_FOUR_PRIVATE_PREFIX + 'SOURCE_EPOCH') == '1791748800',
                'private-cache-schema-refused')
        return
    require(set(captured) == names | header and
            captured[OLD_FOUR_PRIVATE_PREFIX + 'SCHEMA'] == '1' and
            captured[OLD_FOUR_PRIVATE_PREFIX + 'SOURCE_EPOCH'] == '1791748800' and
            source_packet['metadata_pins']['scripts/ci/inputs.lock.json'] ==
            'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f',
            'private-cache-input-binding-refused')
    decoded = []
    for filename, size, pin, tag, count in OLD_FOUR_PRIVATE_ROWS:
        within(deadline)
        length = 4 * ((size + 2) // 3)
        require(count == (length + 32767) // 32768, 'private-cache-schema-refused')
        parts = []
        for i in range(1, count + 1):
            within(deadline)
            part = captured.pop(OLD_FOUR_PRIVATE_PREFIX + f'{tag}_{i:02d}')
            expected = min(32768, length - (i - 1) * 32768)
            require(type(part) is str and len(part) == expected and
                    re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', part) is not None,
                    'private-cache-chunk-refused')
            parts.append(part)
        text = ''.join(parts)
        within(deadline)
        try:
            body = base64.b64decode(text.encode('ascii'), validate=True)
        except (ValueError, UnicodeError):
            raise ValueError('private-cache-base64-refused') from None
        within(deadline)
        require(base64.b64encode(body).decode('ascii') == text and len(body) == size and
                hashlib.sha256(body).hexdigest() == pin, 'private-cache-bytes-refused')
        decoded.append((filename, body))
    captured.clear()
    require(sum(len(body) for _, body in decoded) == 404428, 'private-cache-bound-refused')
    parent = cache.lstat()
    require(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700 and
            parent.st_uid == os.geteuid(), 'private-cache-owner-refused')
    directory = os.open(cache, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    owned = []
    identity = lambda node: (node.st_dev, node.st_ino, node.st_mode, node.st_uid, node.st_gid)
    try:
        require(identity(os.fstat(directory)) == identity(parent), 'private-cache-owner-refused')
        for filename, body in decoded:
            within(deadline)
            fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                         os.O_CLOEXEC, 0o600, dir_fd=directory)
            node = None
            try:
                try:
                    node = os.fstat(fd)
                except BaseException as first:
                    first.add_note('private-cache-unbound-creation-cleanup-uncertain')
                    raise
                owned.append((filename, identity(node)))
                require(stat.S_ISREG(node.st_mode) and stat.S_IMODE(node.st_mode) == 0o600 and
                        node.st_uid == os.geteuid() and node.st_nlink == 1, 'private-cache-owner-refused')
                offset = 0
                while offset < len(body):
                    within(deadline)
                    written = os.write(fd, body[offset:offset + 65536])
                    within(deadline)
                    require(type(written) is int and written > 0, 'private-cache-write-refused')
                    offset += written
                final = os.fstat(fd)
                require(identity(final) == identity(node) and final.st_nlink == 1 and
                        final.st_size == len(body), 'private-cache-owner-refused')
            finally:
                first = sys.exception()
                try:
                    os.close(fd)
                except BaseException:
                    if first is None:
                        raise
                    first.add_note('private-cache-close-uncertain')
            require(identity(os.stat(filename, dir_fd=directory, follow_symlinks=False)) == identity(node),
                    'private-cache-owner-refused')
        within(deadline)
        require(identity(cache.lstat()) == identity(parent), 'private-cache-owner-refused')
    except BaseException as first:
        # Remove only these exact owned creations; never foreign/replaced files.
        for filename, wanted in reversed(owned):
            try:
                within(deadline)
                node = os.stat(filename, dir_fd=directory, follow_symlinks=False)
                if identity(node) != wanted:
                    raise ValueError('private-cache-owner-refused')
                os.unlink(filename, dir_fd=directory)
            except BaseException:
                first.add_note('private-cache-cleanup-uncertain')
        raise
    finally:
        first = sys.exception()
        try:
            os.close(directory)
        except BaseException:
            if first is None:
                raise
            first.add_note('private-cache-close-uncertain')


def seed_current_build_cache(cache, inputs_sha256):
    """Use the fixed current lock and a 60-second seed-only cap within the job timeout."""
    require(inputs_sha256 == 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f',
            'private-cache-input-binding-refused')
    deadline = time.monotonic() + 60
    cache = Path(cache)
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    source_packet = {'metadata_pins': {'scripts/ci/inputs.lock.json': inputs_sha256}}
    seed_old_four_private_cache(cache, source_packet, deadline)
