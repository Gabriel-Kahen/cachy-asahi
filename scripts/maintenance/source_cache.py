#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Acquire explicitly selected pinned HTTPS source data; verify/reuse offline."""
import argparse
import hashlib
import json
import math
import multiprocessing
import os
from pathlib import Path
import secrets
import stat
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'release'))
import source_delivery as sd

MAX_SECONDS = 600
MARKER = b'cachy-asahi-source-cache-v1\n'
CHUNK = 65536
need = sd.need


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def https(value):
    need(type(value) is str and 0 < len(value) <= 4096 and
         all(32 < ord(c) < 127 for c in value) and '\\' not in value, 'unsafe HTTPS URL')
    parsed = urllib.parse.urlsplit(value)
    need(parsed.scheme == 'https' and parsed.hostname and not parsed.username and
         not parsed.password and not parsed.query and not parsed.fragment and
         parsed.port in (None, 443) and '%' not in parsed.netloc and
         '?' not in value and '#' not in value and '@' not in parsed.netloc,
         'credential-free HTTPS URL without query/fragment required')
    return value


def text(value):
    need(type(value) is str and 0 < len(value) <= 4096 and
         not any(ord(c) < 32 or ord(c) == 127 for c in value), 'bounded provenance text required')


def inputs(path, checksum, selected, maximum):
    sd.sha(checksum)
    raw = sd.read_file(path, sd.MAX_JSON)
    need(sd.digest(raw) == checksum, 'source input descriptor checksum mismatch')
    data = sd.decode(raw)
    sd.fields(data, ('schema_version', 'purpose', 'sources'))
    need(type(data['schema_version']) is int and data['schema_version'] == 1 and
         data['purpose'] == 'source-cache-inputs', 'source cache input version/purpose')
    rows = data['sources']
    need(type(rows) is list and 0 < len(rows) <= 128, 'bounded sources required')
    ids = set()
    for row in rows:
        sd.fields(row, ('material', 'url', 'revision', 'license', 'license_evidence'))
        sd.descriptor(row['material'], True)
        https(row['url']); text(row['revision']); text(row['license'])
        need(row['material']['id'] not in ids, 'duplicate source ID')
        ids.add(row['material']['id'])
        notices = row['license_evidence']
        need(type(notices) is list and 0 < len(notices) <= 16, 'license evidence descriptors required')
        for notice in notices:
            sd.descriptor(notice, True)
            need(notice['bytes'] <= sd.MAX_JSON, 'license evidence byte bound')
    need(selected and len(selected) == len(set(selected)) and set(selected) <= ids,
         'explicit unique known source IDs required')
    chosen = [next(row for row in rows if row['material']['id'] == key) for key in selected]
    need(sum(row['material']['bytes'] for row in chosen) <= maximum, 'selected source byte budget exceeded')
    for row in chosen:
        for notice in row['license_evidence']:
            content = sd.local_read(Path(path).absolute().parent, notice['path'], sd.MAX_JSON)
            need(len(content) == notice['bytes'] and sd.digest(content) == notice['sha256'],
                 'license evidence size/checksum mismatch')
    return chosen


def private(fd, directory=False):
    info = os.fstat(fd)
    need((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) and
         info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
         and (directory or info.st_nlink == 1), 'private owned cache entry required')
    return info


def open_dir(name, parent):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        private(fd, True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_entry(parent, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = private(fd)
        need(before.st_size <= limit, 'cache file byte bound')
        hashed = hashlib.sha256(); count = 0
        while True:
            block = os.read(fd, min(CHUNK, limit - count + 1))
            if not block:
                break
            count += len(block); need(count <= limit, 'cache file byte bound'); hashed.update(block)
        after = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
             'cache file changed while reading')
        return count, hashed.hexdigest()
    finally:
        os.close(fd)


def write_all(fd, raw):
    while raw:
        size = os.write(fd, raw); need(size > 0, 'cache short write'); raw = raw[size:]


def initialize(path):
    path = Path(path)
    need(path.is_absolute() and path.name not in ('', '.', '..') and not str(path).startswith('//') and
         '..' not in path.parts, 'absolute fresh cache path required')
    parent = sd.directory(path.parent)
    try:
        os.mkdir(path.name, 0o700, dir_fd=parent)
        root = open_dir(path.name, parent)
        try:
            for name in ('objects', 'receipts', '.partial'):
                os.mkdir(name, 0o700, dir_fd=root)
            fd = os.open('FORMAT', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root)
            try:
                write_all(fd, MARKER); os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(root)
        finally:
            os.close(root)
    finally:
        os.close(parent)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise sd.Error('redirect refused; pin the final HTTPS URL explicitly')


def download(row, fd, seconds, send):
    """Only transport runs in a disposable child; parent enforces wall time."""
    try:
        deadline = time.monotonic() + seconds
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request(row['url'], headers={'Accept-Encoding': 'identity',
                                                             'User-Agent': 'cachy-asahi-source-cache/1'})
        expected = row['material']['bytes']
        with opener.open(request, timeout=min(30, seconds)) as response:
            need(response.status == 200 and response.url == row['url'], 'unexpected HTTP response')
            length = response.headers.get('Content-Length')
            need(length is None or (length.isdecimal() and int(length) == expected), 'HTTP length mismatch')
            need(response.headers.get('Content-Encoding', 'identity') == 'identity', 'HTTP encoding refused')
            count = 0; hashed = hashlib.sha256()
            while True:
                need(time.monotonic() < deadline, 'download deadline exceeded')
                block = response.read(min(CHUNK, expected - count + 1))
                if not block:
                    break
                count += len(block); need(count <= expected, 'download exceeds pinned size')
                hashed.update(block); write_all(fd, block)
            need(count == expected and hashed.hexdigest() == row['material']['sha256'], 'download size/checksum mismatch')
        os.fsync(fd); send.send(True)
    except BaseException:
        # Do not echo remote errors, URLs, or environment data into receipts.
        send.send(False)
    finally:
        send.close()


def transport(row, fd, seconds):
    context = multiprocessing.get_context('fork')
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=download, args=(row, fd, seconds, send))
    started = False
    try:
        process.start(); started = True; send.close()
        process.join(seconds)
        need(not process.is_alive(), 'download wall-clock deadline exceeded')
        need(process.exitcode == 0 and receive.poll() and receive.recv() is True,
             'HTTPS transfer failed or source pin differs')
    finally:
        if started:
            if process.is_alive():
                process.terminate(); process.join(0.2)
            if process.is_alive():
                process.kill(); process.join(1)
            need(not process.is_alive(), 'download child cleanup failed')
        process.close(); receive.close(); send.close()


def publish(partials, name, target, key):
    # link is atomic and fails if *any* destination already exists.
    os.link(name, key, src_dir_fd=partials, dst_dir_fd=target, follow_symlinks=False)
    os.unlink(name, dir_fd=partials)
    os.fsync(target); os.fsync(partials)


def temporary(partials):
    name = secrets.token_hex(16) + '.part'
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=partials)
    private(fd)
    return name, fd


def run(cache, input_path, checksum, selected, offline=True, seconds=120, maximum=sd.MAX_TOTAL):
    need(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= MAX_SECONDS,
         'finite timeout within 600 seconds required')
    need(type(maximum) is int and 0 < maximum <= sd.MAX_TOTAL, 'finite byte budget required')
    need(not str(cache).startswith('//'), 'cache path alias refused')
    rows = inputs(input_path, checksum, selected, maximum)
    root = sd.directory(cache); held = [root]
    try:
        private(root, True)
        need(read_entry(root, 'FORMAT', len(MARKER)) == (len(MARKER), sd.digest(MARKER)), 'cache format mismatch')
        for name in ('objects', 'receipts', '.partial'):
            held.append(open_dir(name, root))
        objects, receipts, partials = held[1:]
        result = []; deadline = time.monotonic() + seconds
        for row in rows:
            material = row['material']; key = material['sha256']; fetched = False
            expected = (material['bytes'], key)
            try:
                need(read_entry(objects, key, material['bytes']) == expected, 'existing cache object mismatch; retained')
            except FileNotFoundError:
                need(not offline, 'offline source object missing: ' + material['id'])
                remaining = deadline - time.monotonic(); need(remaining > 0, 'acquisition deadline exceeded')
                name, fd = temporary(partials)
                try:
                    transport(row, fd, remaining)
                    need(read_entry(partials, name, material['bytes']) == expected, 'partial source pin mismatch')
                    try:
                        publish(partials, name, objects, key)
                    except FileExistsError:
                        need(read_entry(objects, key, material['bytes']) == expected, 'concurrent cache object mismatch; retained')
                    fetched = True
                finally:
                    os.close(fd)
                    try: os.unlink(name, dir_fd=partials)
                    except FileNotFoundError: pass
            receipt = dict(schema_version=1, purpose='source-cache-receipt', inputs_sha256=checksum,
                           source=row, object_path='objects/' + key, legal_acceptance=False,
                           source_completeness_accepted=False)
            raw = encoded(receipt); need(len(raw) <= sd.MAX_JSON, 'provenance receipt byte bound')
            receipt_key = checksum + '-' + material['id'] + '.json'
            try:
                need(read_entry(receipts, receipt_key, sd.MAX_JSON) == (len(raw), sd.digest(raw)),
                     'existing provenance receipt mismatch; retained')
            except FileNotFoundError:
                need(not offline, 'offline provenance receipt missing: ' + material['id'])
                name, fd = temporary(partials)
                try:
                    write_all(fd, raw); os.fsync(fd)
                    try:
                        publish(partials, name, receipts, receipt_key)
                    except FileExistsError:
                        need(read_entry(receipts, receipt_key, sd.MAX_JSON) == (len(raw), sd.digest(raw)),
                             'concurrent provenance receipt mismatch; retained')
                finally:
                    os.close(fd)
                    try: os.unlink(name, dir_fd=partials)
                    except FileNotFoundError: pass
            result.append(dict(id=material['id'], sha256=key, bytes=material['bytes'],
                               path=str(Path(cache) / 'objects' / key), status='acquired' if fetched else 'verified'))
        return dict(schema_version=1, purpose='source-cache-result', inputs_sha256=checksum, sources=result,
                    legal_acceptance=False, source_completeness_accepted=False)
    finally:
        for fd in reversed(held): os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init'); init.add_argument('--cache', required=True, type=Path)
    for command in ('acquire', 'verify'):
        child = sub.add_parser(command)
        child.add_argument('--cache', required=True, type=Path)
        child.add_argument('--inputs', required=True, type=Path)
        child.add_argument('--inputs-sha256', required=True)
        child.add_argument('--id', action='append', required=True)
        child.add_argument('--timeout', type=float, default=120)
        child.add_argument('--max-bytes', type=int, default=sd.MAX_TOTAL)
    args = parser.parse_args(argv)
    try:
        if args.command == 'init':
            initialize(args.cache); result = dict(status='initialized', cache=str(args.cache))
        else:
            result = run(args.cache, args.inputs, args.inputs_sha256, args.id,
                         args.command == 'verify', args.timeout, args.max_bytes)
        print(encoded(result).decode(), end=''); return 0
    except (sd.Error, OSError, ValueError, EOFError):
        print('source-cache: refused; check pins, private paths, cached bytes and transport', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
