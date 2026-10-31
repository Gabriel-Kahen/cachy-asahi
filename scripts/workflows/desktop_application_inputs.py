#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit, bounded local-file/URI expansion for an audited desktop Exec."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
from urllib.parse import unquote_to_bytes, urlsplit

import desktop_applications as desktop

MAX_INPUTS = 64
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
SCHEMES = frozenset(('file', 'http', 'https'))


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


class InputAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        items = list(getattr(namespace, self.dest, None) or ())
        items.append({'kind': 'file' if option_string == '--file' else 'uri', 'value': value})
        setattr(namespace, self.dest, items)


def local_path(value):
    require(type(value) is str and 0 < len(value.encode('utf-8')) <= 4096 and '\0' not in value,
            'bounded UTF-8 local input path required')
    require(value.startswith('/') and not value.startswith('//') and os.path.normpath(value) == value,
            'local input must be an absolute normalized path')
    return value


def metadata(info):
    return {key: getattr(info, 'st_' + key) for key in
            ('dev', 'ino', 'mode', 'uid', 'gid', 'size', 'mtime_ns', 'ctime_ns')}


def open_input(value):
    parts = value.split('/')[1:]
    require(len(parts) <= 128 and parts[-1], 'local input path component cap')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, name in enumerate(parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if index != len(parts) - 1:
                flags |= os.O_DIRECTORY
            new = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = new
        return fd
    except BaseException:
        os.close(fd)
        raise


class Budget:
    def __init__(self):
        self.remaining = MAX_TOTAL


def bind_file(value, budget=None):
    """No symlink component or FIFO/device read; retain hashes, not file bytes."""
    value = local_path(value)
    budget = Budget() if budget is None else budget
    fd = open_input(value)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), 'local input must be a regular file')
        require(before.st_size <= min(MAX_FILE, budget.remaining), 'local input byte budget exceeded')
        digest, count = hashlib.sha256(), 0
        while count < before.st_size:
            block = os.read(fd, min(65536, before.st_size - count))
            if not block:
                break
            budget.remaining -= len(block)  # Charge even if later identity checks fail.
            count += len(block)
            digest.update(block)
        require(budget.remaining > 0, 'local input byte budget exhausted before EOF proof')
        extra = os.read(fd, 1)
        budget.remaining -= len(extra)
        require(not extra, 'local input size differs from metadata')
        after = os.fstat(fd)
        require(metadata(before) == metadata(after) and count == after.st_size,
                'local input changed while reading')
        current = open_input(value)
        try:
            require(metadata(os.fstat(current)) == metadata(after), 'local input pathname changed while reading')
        finally:
            os.close(current)
        return dict(path=value, bytes=count, sha256=digest.hexdigest(), metadata=metadata(after))
    finally:
        os.close(fd)


def uri(value, allowed):
    require(type(value) is str and 0 < len(value.encode('ascii')) <= 8192 and
            all(32 < ord(char) < 127 for char in value) and '\\' not in value,
            'bounded ASCII URI without controls, spaces or backslashes required')
    require(re.search(r'[<>"`^{}|]', value) is None, 'URI punctuation must be percent-encoded')
    require(re.search(r'%(?![0-9A-Fa-f]{2})', value) is None, 'malformed URI percent escape')
    parsed = urlsplit(value)
    require(parsed.scheme in allowed, 'URI scheme not explicitly allowed')
    if parsed.scheme == 'file':
        require(not parsed.netloc and not parsed.query and not parsed.fragment, 'only local plain file URIs supported')
        path = local_path(unquote_to_bytes(parsed.path).decode('utf-8'))
        require(Path(path).as_uri() == value, 'canonical local file URI required')
        return path
    require(parsed.scheme in ('http', 'https') and parsed.netloc and '%' not in parsed.netloc and parsed.hostname and
            parsed.username is None and parsed.password is None, 'absolute credential-free HTTP(S) URI required')
    require(re.fullmatch(r'(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+)(?::[0-9]+)?', parsed.netloc) is not None,
            'unsupported or malformed HTTP(S) authority')
    port = parsed.port
    require(port is None or 1 <= port <= 65535, 'URI port out of range')
    return None


def prepare(items=(), allowed=()):
    require(type(items) in (list, tuple) and len(items) <= MAX_INPUTS, 'input count cap exceeded')
    require(type(allowed) in (list, tuple) and all(type(x) is str and x in SCHEMES for x in allowed),
            'allowed URI schemes are only file, http, https')
    records, budget = [], Budget()
    for item in items:
        require(type(item) is dict and set(item) == {'kind', 'value'} and item['kind'] in ('file', 'uri'),
                'explicit file/URI input record required')
        value = item['value']
        path = local_path(value) if item['kind'] == 'file' else uri(value, allowed)
        row = dict(item, local_path=path, uri=Path(path).as_uri() if path else value)
        if path:
            row['before'] = bind_file(path, budget)
        records.append(row)
    return records


def expand(raw, name='', icon='', location='', records=()):
    """Validate original syntax first, then expand only inert parsed placeholders.

    The existing parser remains byte-held. No input text is inserted into Exec
    source or re-parsed as fields, quotes, shell syntax or multiple arguments.
    """
    parsed = desktop.exec_argv(raw, name, icon, location)
    fields = [code for code in parsed['field_codes'] if code in ('%f', '%F', '%u', '%U')]
    require(not records or fields, 'explicit inputs supplied but Exec has no file/URI field')
    if not records:
        return parsed['argv_without_file_inputs']
    field = fields[0]
    require(field in ('%F', '%U') or len(records) == 1, 'single-item Exec field accepts at most one input; use separate invocations')
    if field in ('%f', '%F'):
        require(all(row['local_path'] is not None for row in records), 'file Exec fields require local files; remote download unsupported')
        values = [row['local_path'] for row in records]
    else:
        values = [row['uri'] for row in records]
    token = None
    for _ in range(8):
        candidate = 'CAA_INPUT_' + secrets.token_hex(16)
        if all(candidate not in value for value in (raw, name, icon, location, *values)):
            token = candidate
            break
    require(token is not None, 'input placeholder collision budget exceeded')
    source, i = '', 0
    while i < len(raw):
        if raw[i] == '%' and i + 1 < len(raw):
            pair = raw[i:i + 2]
            source += token if pair == field else pair
            i += 2
        else:
            source += raw[i]
            i += 1
    argv = desktop.exec_argv(source, name, icon, location)['argv_without_file_inputs']
    result, seen = [], 0
    for word in argv:
        if token not in word:
            result.append(word)
            continue
        seen += word.count(token)
        if field in ('%F', '%U'):
            require(word == token, 'multi-item field must stand alone')
            result.extend(values)
        else:
            result.append(word.replace(token, values[0]))
    require(seen == 1, 'input field expansion lost or duplicated')
    return result


def verify(records):
    """After launch retain process result even if an input changed/disappeared."""
    rows, budget = [], Budget()
    for original in records:
        row = dict(original)
        if original['local_path'] is None:
            row['state'] = 'URI_PASSED_WITHOUT_FETCH'
        else:
            try:
                after = bind_file(original['local_path'], budget)
                row.update(after=after, state='UNCHANGED' if after == original['before'] else 'CHANGED')
            except (ValueError, OSError, UnicodeError) as exc:
                row.update(state='UNVERIFIED', error=type(exc).__name__ + ': ' + str(exc))
        rows.append(row)
    return rows
