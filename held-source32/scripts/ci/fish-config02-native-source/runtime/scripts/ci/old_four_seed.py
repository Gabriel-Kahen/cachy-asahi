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


def _seed_owned_old_four_private_cache(cache, source_packet, deadline, *, ownership=None):
    """Exact old transport only; inherit J and erase chunks before native work."""
    require(ownership is None or type(ownership) is dict and type(ownership['owned']) is list and
            not ownership['owned'], 'private-cache-ownership-refused')
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
        return ()
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
    owned = [] if ownership is None else ownership['owned']
    identity = lambda node: (node.st_dev, node.st_ino, node.st_mode, node.st_uid, node.st_gid)
    try:
        require(identity(os.fstat(directory)) == identity(parent), 'private-cache-owner-refused')
        for filename, body in decoded:
            within(deadline)
            fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                         os.O_CLOEXEC, 0o600, dir_fd=directory)
            owned.append((filename, None))
            node = None
            try:
                try:
                    node = os.fstat(fd)
                except BaseException as first:
                    if ownership is not None:ownership['errors'].append(first)
                    first.add_note('private-cache-unbound-creation-cleanup-uncertain')
                    raise
                owned[-1] = (filename, identity(node))
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
                except BaseException as error:
                    if ownership is not None:ownership['errors'].append(error)
                    if first is None:
                        raise
                    if ownership is not None and not isinstance(error, Exception) and isinstance(first, Exception):
                        raise error from first
                    first.add_note('private-cache-close-uncertain')
            require(identity(os.stat(filename, dir_fd=directory, follow_symlinks=False)) == identity(node),
                    'private-cache-owner-refused')
        within(deadline)
        require(identity(cache.lstat()) == identity(parent), 'private-cache-owner-refused')
    except BaseException as first:
        # Remove only these exact owned creations; never foreign/replaced files.
        cleanup_control = None
        for filename, wanted in reversed(owned):
            try:
                within(deadline)
                node = os.stat(filename, dir_fd=directory, follow_symlinks=False)
                if ownership is not None:
                    require(identity(os.fstat(directory)) == identity(parent) and
                            identity(cache.lstat()) == identity(parent) and node.st_nlink == 1,
                            'private-cache-owner-refused')
                if identity(node) != wanted:
                    raise ValueError('private-cache-owner-refused')
                os.unlink(filename, dir_fd=directory)
                if ownership is not None:owned.remove((filename, wanted))
            except BaseException as error:
                if ownership is not None:
                    ownership['errors'].append(error)
                    if not isinstance(error, Exception) and isinstance(first, Exception):cleanup_control = error
                first.add_note('private-cache-cleanup-uncertain')
        if cleanup_control is not None:raise cleanup_control from first
        raise
    finally:
        first = sys.exception()
        try:
            os.close(directory)
        except BaseException as error:
            if ownership is not None:ownership['errors'].append(error)
            if first is None:
                raise
            if ownership is not None and not isinstance(error, Exception) and isinstance(first, Exception):
                raise error from first
            first.add_note('private-cache-close-uncertain')

    return tuple(owned)


RETAINED_BUBBLEWRAP_PRIVATE_PREFIX = 'CACHY_RETAINED_BUBBLEWRAP_V1_'


RETAINED_BUBBLEWRAP_INPUT_SHA256 = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'


RETAINED_BUBBLEWRAP_PRIVATE_ROWS = (
    ('bubblewrap-0.13.0-1-aarch64.pkg.tar.xz', 40428,
     '4866e25c5a7c33c3ded9f221058b5f4136cdbd991f3dc77a2f7a740368c95a61', 'PACKAGE', (32768, 21136)),
    ('bubblewrap-0.13.0-1-aarch64.pkg.tar.xz.sig', 566,
     'dc7ad4f478d7b196b5189e670e2d80f3e68ad28aa869b0bee697d2c5309064fa', 'SIGNATURE', (756,)),
)


def capture_retained_private_environment():
    """Remove every matching variable before Source preload/seed failure paths."""
    return {name: os.environ.pop(name) for name in tuple(os.environ)
            if name.startswith(RETAINED_BUBBLEWRAP_PRIVATE_PREFIX)}


def retained_cache_identity(node):
    return (node.st_dev, node.st_ino, node.st_mode, node.st_uid, node.st_gid)


def rollback_retained_private_cache(receipt, deadline, first):
    """Only creation-journal identities; expiry/sticky Guard means UNCERTAIN."""
    receipt['uncertain'] = True
    if 'directory' not in receipt:
        return
    control = None
    for filename, wanted in reversed(receipt['owned']):
        try:
            within(deadline)
            require(retained_cache_identity(os.fstat(receipt['directory'])) == receipt['parent'] and
                    retained_cache_identity(receipt['cache'].lstat()) == receipt['parent'],
                    'retained-cache-directory-refused')
            node = os.stat(filename, dir_fd=receipt['directory'], follow_symlinks=False)
            require(retained_cache_identity(node) == wanted and stat.S_ISREG(node.st_mode) and
                    stat.S_IMODE(node.st_mode) == 0o600 and node.st_nlink == 1,
                    'retained-cache-cleanup-owner-refused')
            os.unlink(filename, dir_fd=receipt['directory'])
        except BaseException as error:
            receipt['errors'].append(error)
            if not isinstance(error, Exception) and isinstance(first, Exception):
                control = error
    try:
        within(deadline)
        os.lseek(receipt['directory'], 0, os.SEEK_SET)
        require(not os.listdir(receipt['directory']), 'retained-cache-cleanup-uncertain')
    except BaseException as error:
        receipt['errors'].append(error)
        if not isinstance(error, Exception) and isinstance(first, Exception):
            control = error
    try:
        within(deadline)
        os.close(receipt['directory'])
        receipt['directory'] = None
    except BaseException as error:
        receipt['errors'].append(error)
        if not isinstance(error, Exception) and isinstance(first, Exception):
            control = error
    if not receipt['errors']:
        receipt['uncertain'] = False
        receipt['state'] = 'ROLLED_BACK'
    else:
        try:
            BaseException.add_note(first, 'retained-cache-cleanup-uncertain')
        except BaseException as error:
            receipt['errors'].append(error)
            if not isinstance(error, Exception) and isinstance(first, Exception):
                control = error
    if control is not None:
        raise control from first


def finish_retained_private_cache(receipt, deadline):
    """Release the retained seed dirfd only after caller custody/handoff checks."""
    within(deadline)
    require(receipt['state'] == 'SEEDED' and len(receipt['owned']) == 6,
            'retained-cache-finish-state-refused')
    require(retained_cache_identity(os.fstat(receipt['directory'])) == receipt['parent'] and
            retained_cache_identity(receipt['cache'].lstat()) == receipt['parent'],
            'retained-cache-directory-refused')
    os.close(receipt['directory'])
    receipt['directory'] = None
    receipt['state'] = 'HANDED_OFF'
    receipt['uncertain'] = False


def seed_retained_private_cache(cache, source_packet, deadline, receipt, captured):
    """Fixed two-object transport plus old four, same endpoint and ownership."""
    require(type(receipt) is dict and not receipt, 'retained-cache-receipt-refused')
    receipt.update(state='VALIDATING', uncertain=True, owned=[], errors=[])
    # Caller captured early; refuse any new matching environment values as well.
    late = capture_retained_private_environment()
    within(deadline)
    names = {RETAINED_BUBBLEWRAP_PRIVATE_PREFIX + f'{tag}_{i:02d}'
             for _, _, _, tag, sizes in RETAINED_BUBBLEWRAP_PRIVATE_ROWS
             for i in range(1, len(sizes) + 1)}
    require(type(captured) is dict and len(captured) == 3 and
            all(type(name) is str for name in captured) and
            set(captured) == names and len(names) == 3 and not late,
            'retained-cache-schema-refused')
    require(source_packet['metadata_pins']['scripts/ci/inputs.lock.json'] ==
            RETAINED_BUBBLEWRAP_INPUT_SHA256, 'retained-cache-input-binding-refused')
    decoded = []
    for filename, size, pin, tag, sizes in RETAINED_BUBBLEWRAP_PRIVATE_ROWS:
        parts = []
        for i, length in enumerate(sizes, 1):
            within(deadline)
            part = captured[RETAINED_BUBBLEWRAP_PRIVATE_PREFIX + f'{tag}_{i:02d}']
            require(type(part) is str and len(part) == length and
                    re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', part) is not None,
                    'retained-cache-chunk-refused')
            parts.append(part)
        text = ''.join(parts)
        within(deadline)
        try:
            body = base64.b64decode(text.encode('ascii'), validate=True)
        except (ValueError, UnicodeError):
            raise ValueError('retained-cache-base64-refused') from None
        within(deadline)
        require(len(text) == 4*((size+2)//3) and len(body) == size and
                base64.b64encode(body).decode('ascii') == text and
                hashlib.sha256(body).hexdigest() == pin, 'retained-cache-bytes-refused')
        decoded.append((filename, body))
    captured.clear()
    require(sum(len(body) for _, body in decoded) == 40994, 'retained-cache-bound-refused')
    within(deadline)
    parent = cache.lstat()
    require(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700 and
            parent.st_uid == os.geteuid() and parent.st_gid == os.getegid(),
            'retained-cache-directory-refused')
    receipt.update(cache=cache, parent=retained_cache_identity(parent))
    receipt['directory'] = os.open(cache, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    require(retained_cache_identity(os.fstat(receipt['directory'])) == receipt['parent'] and
            not os.listdir(receipt['directory']), 'retained-cache-fresh-directory-refused')
    _seed_owned_old_four_private_cache(cache, source_packet, deadline, ownership=receipt)
    require(len(receipt['owned']) == 4, 'retained-cache-old-four-refused')
    for filename, body in decoded:
        within(deadline)
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     os.O_CLOEXEC, 0o600, dir_fd=receipt['directory'])
        receipt['owned'].append((filename, None))
        try:
            node = os.fstat(fd)
            receipt['owned'][-1] = (filename, retained_cache_identity(node))
            require(stat.S_ISREG(node.st_mode) and stat.S_IMODE(node.st_mode) == 0o600 and
                    node.st_uid == os.geteuid() and node.st_gid == os.getegid() and node.st_nlink == 1,
                    'retained-cache-owner-refused')
            offset = 0
            while offset < len(body):
                within(deadline)
                written = os.write(fd, body[offset:offset+65536])
                within(deadline)
                require(type(written) is int and 0 < written <= len(body)-offset,
                        'retained-cache-write-refused')
                offset += written
            final = os.fstat(fd)
            require(retained_cache_identity(final) == retained_cache_identity(node) and
                    final.st_nlink == 1 and final.st_size == len(body), 'retained-cache-owner-refused')
        finally:
            first = sys.exception()
            try:
                os.close(fd)
            except BaseException as error:
                receipt['errors'].append(error)
                if first is None:
                    raise
                if not isinstance(error, Exception) and isinstance(first, Exception):
                    raise error from first
                BaseException.add_note(first, 'retained-cache-close-uncertain')
    expected = {r[0] for r in OLD_FOUR_PRIVATE_ROWS} | {r[0] for r in RETAINED_BUBBLEWRAP_PRIVATE_ROWS}
    within(deadline)
    os.lseek(receipt['directory'], 0, os.SEEK_SET)
    require(len(receipt['owned']) == 6 and len(expected) == 6 and
            set(os.listdir(receipt['directory'])) == expected and
            retained_cache_identity(cache.lstat()) == receipt['parent'],
            'retained-cache-membership-refused')
    for filename, wanted in receipt['owned']:
        within(deadline)
        node = os.stat(filename, dir_fd=receipt['directory'], follow_symlinks=False)
        require(retained_cache_identity(node) == wanted and node.st_nlink == 1 and
                stat.S_ISREG(node.st_mode) and stat.S_IMODE(node.st_mode) == 0o600,
                'retained-cache-owner-refused')
    receipt['state'] = 'SEEDED'


def _verify_retained_private_cache(receipt, deadline):
    """Read only six named owned files, within their fixed sizes and seed endpoint."""
    require(receipt['state'] == 'SEEDED' and len(receipt['owned']) == 6 and
            not receipt['errors'], 'retained-cache-readback-state-refused')
    expected = {name: (size, pin) for name, size, pin, *_ in
                OLD_FOUR_PRIVATE_ROWS + RETAINED_BUBBLEWRAP_PRIVATE_ROWS}
    wanted = dict(receipt['owned'])
    require(set(wanted) == set(expected), 'retained-cache-membership-refused')
    for name, (size, pin) in expected.items():
        within(deadline)
        require(retained_cache_identity(os.fstat(receipt['directory'])) == receipt['parent'] and
                retained_cache_identity(receipt['cache'].lstat()) == receipt['parent'],
                'retained-cache-directory-refused')
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=receipt['directory'])
        try:
            node = os.fstat(fd)
            require(retained_cache_identity(node) == wanted[name] and stat.S_ISREG(node.st_mode) and
                    stat.S_IMODE(node.st_mode) == 0o600 and node.st_uid == os.geteuid() and
                    node.st_gid == os.getegid() and node.st_nlink == 1 and node.st_size == size,
                    'retained-cache-readback-owner-refused')
            digest, total = hashlib.sha256(), 0
            while total <= size:
                within(deadline)
                block = os.read(fd, min(65536, size + 1 - total))
                within(deadline)
                if not block:
                    break
                total += len(block)
                digest.update(block)
            require(total == size and digest.hexdigest() == pin,
                    'retained-cache-readback-bytes-refused')
            final = os.fstat(fd)
            require(retained_cache_identity(final) == wanted[name] and final.st_size == size and
                    final.st_nlink == 1 and
                    retained_cache_identity(os.stat(name, dir_fd=receipt['directory'],
                                                   follow_symlinks=False)) == wanted[name],
                    'retained-cache-readback-owner-refused')
        finally:
            first = sys.exception()
            try:
                os.close(fd)
            except BaseException as error:
                receipt['errors'].append(error)
                if first is None:
                    raise
                if not isinstance(error, Exception) and isinstance(first, Exception):
                    raise error from first
                BaseException.add_note(first, 'retained-cache-close-uncertain')
    within(deadline)
    os.lseek(receipt['directory'], 0, os.SEEK_SET)
    require(set(os.listdir(receipt['directory'])) == set(expected) and
            retained_cache_identity(os.fstat(receipt['directory'])) == receipt['parent'] and
            retained_cache_identity(receipt['cache'].lstat()) == receipt['parent'],
            'retained-cache-membership-refused')


def seed_current_build_cache(cache, inputs_sha256):
    """Mandatory retained six; one seed-only deadline, before ordinary native audit."""
    captured = capture_retained_private_environment()
    receipt = {}
    deadline = None
    finishing = False
    try:
        require(inputs_sha256 == RETAINED_BUBBLEWRAP_INPUT_SHA256,
                'private-cache-input-binding-refused')
        deadline = time.monotonic() + 60
        within(deadline)
        cache = Path(cache)
        cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        packet = {'metadata_pins': {'scripts/ci/inputs.lock.json': inputs_sha256}}
        seed_retained_private_cache(cache, packet, deadline, receipt, captured)
        _verify_retained_private_cache(receipt, deadline)
        finishing = True
        finish_retained_private_cache(receipt, deadline)
    except BaseException as first:
        BaseException.__setattr__(first, '_retained_cache_receipt', receipt)
        if finishing:
            receipt['uncertain'] = True
            receipt['state'] = 'FINISH_UNCERTAIN'
            receipt['errors'].append(first)
            BaseException.add_note(first, 'retained-cache-finish-uncertain')
        elif deadline is not None and receipt:
            try:
                rollback_retained_private_cache(receipt, deadline, first)
            except BaseException as error:
                receipt['uncertain'] = True
                receipt.setdefault('errors', []).append(error)
                if not isinstance(error, Exception) and isinstance(first, Exception):
                    raise error from first
                BaseException.add_note(first, 'retained-cache-cleanup-uncertain')
        raise
    finally:
        captured.clear()
        for name in tuple(os.environ):
            if name.startswith((OLD_FOUR_PRIVATE_PREFIX, RETAINED_BUBBLEWRAP_PRIVATE_PREFIX)):
                os.environ.pop(name, None)
