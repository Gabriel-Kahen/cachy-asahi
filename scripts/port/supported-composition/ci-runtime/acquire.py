#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Acquire verified, cached composition test inputs; never run package/image tools."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
import time
from urllib.parse import urlsplit

LOCK = Path(__file__).with_name('inputs.lock')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def load_lock(path=LOCK, *, raw=None):
    raw = path.read_bytes() if raw is None else raw
    need(len(raw) <= 16384, 'bounded input lock')
    rows = {}
    for line in raw.decode().splitlines():
        size, digest, name, source = line.split()
        need(re.fullmatch(r'[A-Za-z0-9_.+-]+', name) and name not in ('.', '..') and name not in rows, 'unsafe or duplicate input name')
        need(size.isdecimal() and 0 < int(size) <= 32 * 1024**2 and re.fullmatch('[0-9a-f]{64}', digest), 'invalid input pin')
        if source.startswith('db:'):
            need(name.endswith('.sig') and re.fullmatch(r'db:[A-Za-z0-9_.+-]+/desc', source), 'invalid signature provenance')
        else:
            url = urlsplit(source)
            need(url.scheme == 'https' and url.netloc == 'archive.archlinux.org' and not url.query and not url.fragment
                 and url.path.endswith('/' + name), 'only exact official HTTPS input URLs')
        rows[name] = dict(bytes=int(size), sha256=digest, source=source)
    need(len(rows) == 5 and 'core.db' in rows and sum(r['source'].startswith('db:') for r in rows.values()) == 2,
         'exact DB, two packages and two signatures required')
    need(sum(r['bytes'] for r in rows.values()) <= 64 * 1024**2, 'finite total input size')
    return rows


def verified(path, row):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ValueError('unsafe input operand') from error
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'ordinary single-link input required')
        if before.st_size != row['bytes']:
            return None
        raw = stream.read(row['bytes'] + 1)
        after = os.fstat(stream.fileno())
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(identity(before) == identity(after) == identity(path.lstat()), 'input changed while read')
    return raw if len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'] else None


def database(rows, raw):
    need(len(raw) == rows['core.db']['bytes'] and hashlib.sha256(raw).hexdigest() == rows['core.db']['sha256'], 'whole DB pin')
    signatures = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        for name, row in rows.items():
            if not row['source'].startswith('db:'):
                continue
            member = archive.getmember(row['source'][3:])
            need(member.isfile() and 0 < member.size <= 65536, 'bounded DB package descriptor')
            fields = {}
            key = None
            for line in archive.extractfile(member).read().decode().splitlines():
                if line.startswith('%'):
                    need(line.endswith('%') and line not in fields, 'duplicate DB field')
                    key = line
                    fields[key] = []
                elif line:
                    need(key is not None, 'unframed DB field')
                    fields[key].append(line)
            package = name.removesuffix('.sig')
            need(package in rows and fields['%FILENAME%'] == [package] and fields['%CSIZE%'] == [str(rows[package]['bytes'])]
                 and fields['%SHA256SUM%'] == [rows[package]['sha256']], 'package pins must match exact DB')
            need(len(fields['%PGPSIG%']) == 1, 'one embedded package signature')
            signature = base64.b64decode(fields['%PGPSIG%'][0], validate=True)
            need(len(signature) == row['bytes'] and hashlib.sha256(signature).hexdigest() == row['sha256'], 'whole DB signature pin')
            signatures[name] = signature
    return signatures


class TransferError(ValueError):
    def __init__(self, message='public input transfer failed', *, retryable=False):
        super().__init__(message)
        self.retryable = retryable


def fetch(row, path, remaining):
    seconds = min(60, remaining)
    argv = ['curl', '--disable', '--fail', '--location', '--max-redirs', '2', '--silent', '--show-error',
            '--proto', '=https', '--proto-redir', '=https', '--connect-timeout', str(min(10, seconds)),
            '--max-time', str(seconds), '--max-filesize', str(row['bytes']), '--output', str(path),
            '--write-out', '%{http_code}', row['source']]
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=seconds + 1, check=False)
    except subprocess.TimeoutExpired as error:
        raise TransferError('bounded curl process deadline', retryable=True) from error
    status = result.stdout.decode('ascii', errors='replace')
    retry = result.returncode in (5, 6, 7, 18, 28, 35, 52, 55, 56, 92) or (result.returncode == 22 and status in ('408', '429', '500', '502', '503', '504'))
    if result.returncode or status != '200':
        raise TransferError('curl code ' + str(result.returncode) + ', HTTP ' + status[:3], retryable=retry)
    return dict(http_status=200)


def acquire(cache, context, *, lock_path=LOCK, transfer=fetch, clock=time.monotonic, sleep=time.sleep, total_seconds=180):
    lock_raw = lock_path.read_bytes()
    rows = load_lock(lock_path, raw=lock_raw)
    cache, context = Path(cache), Path(context)
    for path in (cache, context):
        need(path.is_absolute() and path == path.resolve() and '..' not in path.parts, 'ordinary absolute output paths')
    need(not context.is_relative_to(cache) and not cache.is_relative_to(context), 'disjoint cache/context')
    need(not context.exists() and not context.is_symlink(), 'fresh absent build context required')
    cache.mkdir(mode=0o700, parents=False, exist_ok=True)
    need(cache.is_dir() and cache.stat().st_uid == os.getuid() and not cache.stat().st_mode & 0o022, 'owned private cache directory')
    with os.scandir(cache) as entries:
        for index, entry in enumerate(entries):
            need(index < len(rows) and entry.name in rows, 'unexpected cache entries')
    deadline = clock() + total_seconds
    bodies, requests, hits = {}, [], []

    def remaining():
        value = deadline - clock()
        need(value > 0, 'total acquisition deadline exhausted')
        return value

    with tempfile.TemporaryDirectory(prefix='composition-inputs-', dir=cache.parent) as temporary:
        temporary = Path(temporary)

        def store(name, raw):
            path = temporary / name
            path.write_bytes(raw)
            path.chmod(0o644)
            os.replace(path, cache / name)

        for name, row in rows.items():
            remaining()
            if row['source'].startswith('db:'):
                continue
            raw = verified(cache / name, row)
            if raw is not None:
                hits.append(name)
            else:
                for attempt in range(3):
                    path = temporary / name
                    path.unlink(missing_ok=True)
                    try:
                        observation = transfer(row, path, remaining())
                        requests.append(dict(file=name, source=row['source'], attempt=attempt + 1, status='COMPLETE', observation=observation))
                    except TransferError as error:
                        requests.append(dict(file=name, source=row['source'], attempt=attempt + 1, status='FAILED', reason=str(error)))
                        if not error.retryable or attempt == 2:
                            raise
                        sleep(min(2**attempt, remaining()))
                        continue
                    raw = verified(path, row)
                    need(raw is not None, 'download byte/SHA256 pin mismatch: ' + name)
                    remaining()
                    store(name, raw)
                    break
            bodies[name] = raw
        for name, raw in database(rows, bodies['core.db']).items():
            cached = verified(cache / name, rows[name])
            if cached is not None:
                hits.append(name)
            else:
                store(name, raw)
            bodies[name] = raw
        remaining()
        need(set(bodies) == set(rows), 'complete input set required')
        need(lock_path.read_bytes() == lock_raw, 'input lock changed during acquisition')
        context.mkdir(mode=0o700)
        inputs = context / 'inputs'
        inputs.mkdir(mode=0o755)
        for name, raw in bodies.items():
            path = inputs / name
            path.write_bytes(raw)
            path.chmod(0o644)
        (context / 'inputs.lock').write_bytes(lock_raw)
        (context / 'inputs.lock').chmod(0o644)
        remaining()
    return dict(schema=1, status='PASS_COMPLETE_PINNED_COMPOSITION_INPUTS', lock_sha256=hashlib.sha256(lock_raw).hexdigest(),
                cache_hits=hits, requests=requests, verified_files=list(rows), verified_bytes=sum(r['bytes'] for r in rows.values()),
                signatures='EXACT_PACKETS_FROM_PINNED_DB; PACKAGE_SIGNATURE_VERIFICATION_REMAINS_REQUIRED_IN_IMAGE',
                network_budget_seconds=total_seconds, maximum_attempts_per_input=3, package_or_image_execution=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--context', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(acquire(args.cache, args.context), sort_keys=True, indent=2))
