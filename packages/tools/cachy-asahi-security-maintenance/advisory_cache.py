#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Explicit official Arch advisory DATA acquisition and pinned offline verification."""
import argparse
import ctypes
from datetime import datetime, timezone
import math
import os
from pathlib import Path
import resource
import secrets
import ssl
import stat
import sys
import urllib.request

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / 'scripts/maintenance/security_advisories.py').is_file())
sys.path.extend(str(ROOT / 'scripts' / p) for p in ('maintenance', 'release', 'virtual'))
import security_advisories as a
import source_cache as sc
import owned_process as op

sd, need = sc.sd, a.need
MAX_SECONDS, MAX_META = 120, 65536
FILES = ('advisories.json', 'provenance.json', 'snapshot.json')
SOURCES = ('scripts/maintenance/advisory_cache.py', 'scripts/maintenance/security_advisories.py',
           'scripts/maintenance/source_cache.py', 'scripts/release/source_delivery.py',
           'scripts/virtual/owned_process.py')


def timestamp():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def settings(url, seconds, maximum):
    need(url == a.URL, 'only the exact official tracker URL is supported')
    sc.https(url)
    need(type(seconds) in (int, float) and math.isfinite(seconds) and 1 <= seconds <= MAX_SECONDS,
         'timeout must be finite, between 1 and 120 seconds including retirement')
    need(type(maximum) is int and 1 <= maximum <= a.CAP, 'body limit must be within 8 MiB')


def header(response, name):
    values = response.headers.get_all(name, [])
    need(len(values) <= 1, 'duplicate HTTP ' + name)
    if not values:
        return None
    value = values[0]
    need(type(value) is str and len(value) <= 1024 and
         all(32 <= ord(c) < 127 for c in value), 'unsafe HTTP header')
    return value


def download(fd, seconds, maximum):
    """One direct GET; no proxy, authentication, cookies, retries or redirects."""
    # Explicit compiled-in CA file avoids SSL_CERT_FILE/SSL_CERT_DIR overrides.
    ca = ssl.get_default_verify_paths().openssl_cafile
    need(ca is not None, 'system OpenSSL CA file unavailable')
    context = ssl.create_default_context(cafile=ca)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), sc.NoRedirect(),
                                        urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(a.URL, headers={
        'Accept': 'application/json', 'Accept-Encoding': 'identity',
        'User-Agent': 'cachy-asahi-advisory-cache/1'})
    started = timestamp()
    with opener.open(request, timeout=min(30, seconds)) as response:
        need(response.status == 200 and response.url == a.URL, 'unexpected HTTP status or URL')
        length = header(response, 'Content-Length')
        transfer = header(response, 'Transfer-Encoding')
        need(length is None or (length.isascii() and length.isdecimal() and
                               0 < int(length) <= maximum), 'HTTP body length exceeds budget')
        need(transfer in (None, 'chunked') and not (transfer and length), 'ambiguous HTTP framing')
        need(header(response, 'Content-Encoding') in (None, 'identity'), 'encoded body refused')
        content_type = header(response, 'Content-Type')
        need(content_type is not None and content_type.split(';')[0].strip().lower() ==
             'application/json', 'JSON HTTP content type required')
        remote = {k: header(response, k) for k in ('Date', 'Last-Modified', 'ETag')}
        count = 0
        while True:
            block = response.read(min(sc.CHUNK, maximum - count + 1))
            if not block:
                break
            count += len(block)
            need(count <= maximum, 'HTTP body exceeds budget')
            sc.write_all(fd, block)
        need(count > 0 and (length is None or count == int(length)), 'empty or truncated HTTP body')
    os.fsync(fd)
    return dict(request_started_at=started, retrieved_at=timestamp(), status=200,
                final_url=a.URL, content_type=content_type, content_length=length,
                response_headers=remote, request_count=1, redirects=0,
                proxy='DISABLED', authentication='NONE', content_encoding='identity',
                tls='SYSTEM_OPENSSL_COMPILED_CA_FILE_HOSTNAME_VERIFIED_ENV_OVERRIDES_IGNORED')


def transport(fd, seconds, maximum):
    """Reuse exclusive WNOWAIT supervisor; never signal/probe after custody ends."""
    op.prepare()
    receive, send = os.pipe2(os.O_CLOEXEC)
    try:
        pid = os.fork()
    except BaseException:
        os.close(receive); os.close(send)
        raise
    if pid == 0:
        os.close(receive)
        code = 1
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
            result = download(fd, seconds, maximum)
            raw = a.encoded(result)
            need(len(raw) <= MAX_META, 'transport metadata bound')
            sc.write_all(send, raw)
            code = 0
        except BaseException:
            # Remote exception strings and environment values are never copied.
            pass
        finally:
            os.close(send)
            os._exit(code)
    os.close(send)
    stream = os.fdopen(receive, 'rb')
    retirement = min(.5, seconds / 4)
    outcome = op.supervise(pid, cap=seconds, retirement=retirement,
                           grace=retirement / 4, group=False,
                           streams=(stream,), max_output=MAX_META)
    need(outcome['passed'], 'HTTPS transfer failed, exceeded limits, or lost child custody')
    raw = outcome.pop('output')
    outcome['elapsed_milliseconds'] = int(outcome.pop('seconds') * 1000)
    return dict(a.decode(raw), supervision=outcome)


def write(parent, name, raw):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=parent)
    try:
        sc.write_all(fd, raw); os.fsync(fd)
    finally:
        os.close(fd)


def read_at(parent, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
    try:
        before = sc.private(fd)
        need(0 < before.st_size <= limit, 'snapshot entry byte bound')
        blocks, size = [], 0
        while True:
            block = os.read(fd, min(sc.CHUNK, limit - size + 1))
            if not block:
                break
            size += len(block)
            need(size <= limit, 'snapshot entry byte bound')
            blocks.append(block)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                              s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(size == before.st_size and identity(before) == identity(os.fstat(fd)) ==
             identity(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'snapshot entry changed')
        return b''.join(blocks)
    finally:
        os.close(fd)


def publish(parent, temporary, output, inspected_inode):
    # Same Linux RENAME_NOREPLACE primitive as release/offline_kit.py; no fallback.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    need(rename is not None, 'Linux renameat2 is required for atomic fresh output')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    before = os.stat(temporary, dir_fd=parent, follow_symlinks=False)
    need(stat.S_ISDIR(before.st_mode) and (before.st_dev, before.st_ino) == inspected_inode,
         'staging directory identity changed')
    if rename(parent, os.fsencode(temporary), parent, os.fsencode(output), 1):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    after = os.stat(output, dir_fd=parent, follow_symlinks=False)
    need((after.st_dev, after.st_ino) == inspected_inode, 'published directory identity changed')


def implementation():
    paths = (Path(__file__), Path(a.__file__), Path(sc.__file__), Path(sd.__file__), Path(op.__file__))
    return {name: a.pin(sd.read_file(path, a.CAP)) for name, path in zip(SOURCES, paths)}


def acquire(output, url, seconds=60, maximum=a.CAP):
    settings(url, seconds, maximum)
    output = Path(output)
    need(output.is_absolute() and output.name not in ('', '.', '..') and
         '..' not in output.parts and not str(output).startswith('//'), 'absolute fresh output required')
    sources = implementation()
    parent = sd.directory(output.parent)
    stage, root = None, None
    try:
        # Refuse preexisting files/directories/dangling symlinks before any GET.
        try:
            os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise a.Error('fresh output required; prior snapshot retained')
        stage = '.advisory-' + secrets.token_hex(16)
        os.mkdir(stage, 0o700, dir_fd=parent)
        root = sc.open_dir(stage, parent)
        fd = os.open('advisories.json', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=root)
        try:
            info = transport(fd, seconds, maximum)
        finally:
            os.close(fd)
        raw = read_at(root, 'advisories.json', maximum)
        groups = a.decode(raw)
        a.advisories(groups)
        need(implementation() == sources, 'acquisition implementation changed')
        provenance = dict(url=a.URL, retrieved_at=info['retrieved_at'], **a.pin(raw),
                          schema_version=1, purpose='official-advisory-snapshot-provenance',
                          transport=info, implementation=sources,
                          arm_applicability='UNKNOWN', arm_security_status='UNKNOWN',
                          tracker_completeness='UNKNOWN', tracker_update_time='UNKNOWN_NOT_IN_THIS_FEED',
                          origin_verification='HTTPS_SYSTEM_CA_NOT_SIGNED_ADVISORY_ATTESTATION')
        a.provenance(provenance, raw, datetime.now(timezone.utc), 24)
        meta = a.encoded(provenance)
        write(root, 'provenance.json', meta)
        snapshot = dict(schema_version=1, purpose='official-advisory-snapshot',
                        files={'advisories.json': a.pin(raw), 'provenance.json': a.pin(meta)},
                        tracker_groups=len(groups), arm_security_status='UNKNOWN')
        receipt = a.encoded(snapshot)
        write(root, 'snapshot.json', receipt)
        os.fsync(root)
        visible = sd.directory(output.parent)
        try:
            left, right = os.fstat(visible), os.fstat(parent)
            need((left.st_dev, left.st_ino) == (right.st_dev, right.st_ino), 'output parent identity changed')
        finally:
            os.close(visible)
        held = os.fstat(root)
        publish(parent, stage, output.name, (held.st_dev, held.st_ino))
        stage = None
        os.fsync(parent)
        visible = sd.directory(output)
        try:
            current = os.fstat(visible)
            need((current.st_dev, current.st_ino) == (held.st_dev, held.st_ino), 'published path identity changed')
        finally:
            os.close(visible)
        return dict(output=str(output), snapshot_sha256=a.pin(receipt)['sha256'],
                    advisories=a.pin(raw), tracker_groups=len(groups), arm_security_status='UNKNOWN')
    finally:
        if root is not None:
            if stage is not None:
                # Rename may have succeeded before interruption. Never empty a
                # published directory or remove a substituted staging name.
                try: current = os.stat(stage, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError: stage = None
                else:
                    held = os.fstat(root)
                    if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
                        stage = None
                if stage is not None:
                    for name in FILES:
                        try: os.unlink(name, dir_fd=root)
                        except FileNotFoundError: pass
            os.close(root)
        if stage is not None:
            os.rmdir(stage, dir_fd=parent)
        os.close(parent)


def verify(snapshot, checksum, as_of=None, max_age_hours=24):
    sd.sha(checksum)
    need(type(max_age_hours) is int and 1 <= max_age_hours <= 8760, 'bounded cache age setting')
    root = sd.directory(snapshot)
    try:
        sc.private(root, True)
        need(set(os.listdir(root)) == set(FILES), 'unexpected or missing snapshot entries')
        receipt = read_at(root, 'snapshot.json', a.CAP)
        need(a.pin(receipt)['sha256'] == checksum, 'snapshot checksum mismatch')
        value = a.decode(receipt)
        sd.fields(value, ('schema_version', 'purpose', 'files', 'tracker_groups', 'arm_security_status'))
        need(type(value['schema_version']) is int and value['schema_version'] == 1 and
             value['purpose'] == 'official-advisory-snapshot' and value['arm_security_status'] == 'UNKNOWN',
             'unsupported advisory snapshot schema')
        sd.fields(value['files'], FILES[:2])
        originals = {}
        for name, descriptor in value['files'].items():
            sd.fields(descriptor, ('bytes', 'sha256'))
            need(type(descriptor['bytes']) is int and 0 < descriptor['bytes'] <= a.CAP, 'snapshot byte bound')
            sd.sha(descriptor['sha256'])
            originals[name] = read_at(root, name, a.CAP)
            need(a.pin(originals[name]) == descriptor, 'snapshot input checksum mismatch: ' + name)
        groups = a.decode(originals['advisories.json'])
        a.advisories(groups)
        need(type(value['tracker_groups']) is int and value['tracker_groups'] == len(groups), 'tracker group count mismatch')
        now = datetime.now(timezone.utc) if as_of is None else a.utc(as_of)
        cache = a.provenance(a.decode(originals['provenance.json']), originals['advisories.json'], now, max_age_hours)
        visible = sd.directory(snapshot)
        try:
            left, right = os.fstat(visible), os.fstat(root)
            need((left.st_dev, left.st_ino) == (right.st_dev, right.st_ino) and
                 set(os.listdir(root)) == set(FILES), 'snapshot directory changed')
        finally:
            os.close(visible)
        return dict(snapshot=str(snapshot), snapshot_sha256=checksum, status='VERIFIED_RETAINED_DATA_OFFLINE',
                    tracker_groups=len(groups), cache=cache, arm_security_status='UNKNOWN')
    finally:
        os.close(root)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    fetch = commands.add_parser('acquire', help='one explicit official HTTPS GET into fresh output')
    fetch.add_argument('--url', required=True, help='exact official URL: ' + a.URL)
    fetch.add_argument('--output', type=Path, required=True)
    fetch.add_argument('--timeout', type=float, default=60)
    fetch.add_argument('--max-bytes', type=int, default=a.CAP)
    check = commands.add_parser('verify', help='read-only offline check of externally pinned snapshot')
    check.add_argument('--snapshot', type=Path, required=True)
    check.add_argument('--snapshot-sha256', required=True)
    check.add_argument('--as-of')
    check.add_argument('--max-age-hours', type=int, default=24)
    args = parser.parse_args(argv)
    try:
        if args.command == 'acquire':
            value = acquire(args.output, args.url, args.timeout, args.max_bytes)
        else:
            value = verify(args.snapshot, args.snapshot_sha256, args.as_of, args.max_age_hours)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print('advisory cache: acquisition or offline verification refused; prior snapshots retained', file=sys.stderr)
        return 2
    print(a.encoded(value).decode(), end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
