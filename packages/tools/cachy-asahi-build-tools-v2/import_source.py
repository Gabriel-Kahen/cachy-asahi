#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Import one reviewed local archive into an existing private offline source cache."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import stat
import time

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MAX = 64 * 1024**2


def library(root):
    # A private module instance keeps this invocation's local transport adapter
    # separate from source_materials and all normal HTTPS cache callers.
    path = Path(root) / 'scripts/maintenance/source_cache.py'
    spec = importlib.util.spec_from_file_location('_source_cache_local_v1', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_uid', 'st_gid',
                 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def import_source(cache_path, inputs, checksum, selected, archive, *, seconds=120,
                  maximum=DEFAULT_MAX, repo_root=None, clock=time.monotonic):
    c = library(ROOT if repo_root is None else repo_root)
    c.need(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= 600,
           'finite local import timeout required')
    c.need(type(maximum) is int and 0 < maximum <= c.sd.MAX_FILE, 'bounded local import size required')
    deadline = clock() + seconds

    def live():
        left = deadline - clock()
        c.need(left > 0, 'local import deadline exceeded')
        return left

    rows = c.inputs(inputs, checksum, [selected], maximum)
    row = rows[0]; material = row['material']; live()
    path = Path(os.path.abspath(archive))
    c.need(path == path.resolve() and not any(p.is_symlink() for p in (path, *path.parents)),
           'ordinary nonsymlink local archive required')
    before = path.lstat()
    c.need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
           and stat.S_IMODE(before.st_mode) in (0o600, 0o644)
           and before.st_size == material['bytes'], 'owned exact-size local archive required')
    source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        def stable():
            live()
            c.need(identity(before) == identity(os.fstat(source)) == identity(path.lstat())
                   and path == path.resolve() and not any(p.is_symlink() for p in (path, *path.parents)),
                   'local archive changed during import')

        def stream(destination=None):
            stable(); os.lseek(source, 0, os.SEEK_SET)
            digest = hashlib.sha256(); count = 0
            while True:
                live(); block = os.read(source, min(c.CHUNK, material['bytes'] - count + 1))
                if not block:
                    break
                count += len(block)
                c.need(count <= material['bytes'], 'local archive exceeds reviewed bytes')
                digest.update(block)
                if destination is not None:
                    c.write_all(destination, block)
            stable()
            c.need((count, digest.hexdigest()) == (material['bytes'], material['sha256']),
                   'local archive size/checksum mismatch')
            if destination is not None:
                os.fsync(destination)

        # Always validate the caller's actual local file, even on a cache hit.
        stream()
        transports = []

        def local_transport(actual, destination, remaining):
            c.need(actual == row and type(remaining) in (int, float) and remaining > 0
                   and not transports, 'one exact local archive transport only')
            transports.append(True); c.private(destination); stream(destination)

        c.transport = local_transport
        result = c.run(cache_path, inputs, checksum, [selected], offline=False,
                       seconds=live(), maximum=maximum)
        stable()
        # The existing generic receipt binds catalog/material/notice identity; it
        # never claims an HTTP transaction. Preserve that schema for build_v2.
        # Retain separate, deterministic local-origin provenance in the cache.
        receipt = dict(schema_version=1, purpose='local-source-cache-import',
                       inputs_sha256=checksum, id=selected, source_kind='local_archive',
                       bytes=material['bytes'], sha256=material['sha256'],
                       network_fetches=0, extraction=False, source_execution=False,
                       legal_acceptance=False, source_completeness_accepted=False)
        raw = c.encoded(receipt)
        root = c.sd.directory(cache_path); receipts = partials = None
        try:
            c.private(root, True)
            receipts = c.open_dir('receipts', root); partials = c.open_dir('.partial', root)
            key = 'local-import-' + checksum + '-' + selected + '.json'
            try:
                c.need(c.read_entry(receipts, key, c.sd.MAX_JSON) == (len(raw), c.sd.digest(raw)),
                       'existing local import provenance mismatch; retained')
            except FileNotFoundError:
                name, fd = c.temporary(partials)
                try:
                    live(); c.write_all(fd, raw); os.fsync(fd)
                    try:
                        c.publish(partials, name, receipts, key)
                    except FileExistsError:
                        c.need(c.read_entry(receipts, key, c.sd.MAX_JSON) == (len(raw), c.sd.digest(raw)),
                               'concurrent local import provenance mismatch; retained')
                finally:
                    os.close(fd)
                    try: os.unlink(name, dir_fd=partials)
                    except FileNotFoundError: pass
            live()
        finally:
            for fd in (partials, receipts, root):
                if fd is not None: os.close(fd)
        return dict(status='IMPORTED_VERIFIED_LOCAL_SOURCE', source_kind='local_archive',
                    inputs_sha256=checksum, cache=result,
                    import_receipt=dict(path='receipts/' + key, bytes=len(raw), sha256=c.sd.digest(raw)),
                    network_fetches=0, extraction=False, source_execution=False,
                    legal_acceptance=False, source_completeness_accepted=False)
    finally:
        os.close(source)


def main(argv=None, *, repo_root=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cache', 'inputs', 'local-archive'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--id', required=True)
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--max-bytes', type=int, default=DEFAULT_MAX)
    args = parser.parse_args(argv)
    # CLI hard wall-clock cutoff supplements the streamed per-read checks.
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 600:
        parser.error('timeout must be finite and within600seconds')
    previous = signal.getsignal(signal.SIGALRM)
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        parser.error('an existing real-time alarm must not be replaced')
    def expired(signum, frame):
        raise ValueError('local import deadline exceeded')
    signal.signal(signal.SIGALRM, expired); signal.setitimer(signal.ITIMER_REAL, args.timeout)
    try:
        result = import_source(args.cache, args.inputs, args.inputs_sha256, args.id,
                               args.local_archive, seconds=args.timeout,
                               maximum=args.max_bytes, repo_root=repo_root)
    except (OSError, ValueError, EOFError):
        print(json.dumps(dict(status='REFUSED_LOCAL_SOURCE_IMPORT', network_fetches=0,
                              source_execution=False, legal_acceptance=False)))
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0); signal.signal(signal.SIGALRM, previous)
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == '__main__':
    raise SystemExit(main())
