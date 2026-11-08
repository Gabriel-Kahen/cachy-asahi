#!/usr/bin/env python3
"""Stage fixed zlib bytes locally or from two official endpoints; no extraction or build."""
import argparse
import hashlib
from http.client import HTTPException
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

URL = 'https://zlib.net/fossils/zlib-1.3.2.tar.gz'
FALLBACK_URL = 'https://github.com/madler/zlib/releases/download/v1.3.2/zlib-1.3.2.tar.gz'
FILENAME = 'zlib-1.3.2.tar.gz'
SHA256 = 'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'
MAX_BYTES = 2_000_000
MAX_REDIRECTS = 3
SECONDS = 55
SOCKET_SECONDS = 10
CONTENT_TYPES = {'application/gzip', 'application/x-gzip', 'application/octet-stream'}


class Refused(Exception):
    """A fixed safe reason, never a transport exception or signed URL."""
    def __init__(self, reason, **facts):
        super().__init__(reason)
        self.facts = facts


class Unavailable(Refused):
    """Only endpoint availability permits the other fixed official endpoint."""


def unavailable(error, phase):
    # Do not serialize exception strings: they may contain signed asset URLs.
    reason = getattr(error, 'reason', error)
    facts = dict(phase=phase, exception=type(error).__name__, cause=type(reason).__name__)
    if type(getattr(reason, 'errno', None)) is int:
        facts['errno'] = reason.errno
    return Unavailable('transport', **facts)


def need(condition, reason):
    if not condition:
        raise Refused(reason)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        return None


def redirect_target(current, location):
    need(type(location) is str and location and not any(c.isspace() or ord(c) < 32 for c in location), 'redirect-url')
    target = urljoin(current, location)
    parsed = urlsplit(target)
    need(parsed.scheme == 'https' and parsed.netloc == 'release-assets.githubusercontent.com'
         and parsed.hostname == 'release-assets.githubusercontent.com' and not parsed.fragment
         and parsed.username is None and parsed.password is None, 'redirect-origin')
    return target


def header(response, name):
    values = response.headers.get_all(name, [])
    need(len(values) <= 1, 'duplicate-header')
    return values[0].strip() if values else None


def parent_descriptor(output):
    output = Path(os.path.abspath(output))
    need(output.name == FILENAME, 'fixed-filename')
    parent = output.parent
    need(parent == parent.resolve() and not any(p.is_symlink() for p in (parent, *parent.parents)), 'parent-symlink')
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        need(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == (parent.stat().st_dev, parent.stat().st_ino), 'parent-identity')
        try:
            os.stat(FILENAME, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return descriptor
        raise Refused('destination-exists')
    except BaseException:
        os.close(descriptor)
        raise


def _stage(output, parent, response, *, expected_sha256, deadline, budget, clock,
           declared=None, before_publish=None, local=False):
    """One bounded byte validator and exclusive publisher for both input routes."""
    temporary = None
    size = 0
    try:
        candidate = '.' + FILENAME + '.' + secrets.token_hex(12) + '.part'
        descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        temporary = candidate
        size = 0
        digest = hashlib.sha256()
        prefix = bytearray()
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            while True:
                need(clock() < deadline, 'deadline')
                try:
                    block = response.read(min(65536, MAX_BYTES + 1 - budget[0]))
                except (OSError, URLError, HTTPException) as error:
                    if local:
                        raise Refused('local-read') from None
                    raise unavailable(error, 'read') from None
                need(clock() < deadline, 'deadline')
                if not block:
                    break
                size += len(block)
                budget[0] += len(block)
                need(budget[0] <= MAX_BYTES, 'stream-size')
                prefix.extend(block[:max(0, 2 - len(prefix))])
                digest.update(block)
                need(stream.write(block) == len(block), 'short-write')
            need(size > 0 and (declared is None or size == declared), 'body-size')
            need(bytes(prefix) == b'\x1f\x8b', 'gzip-magic')
            need(digest.hexdigest() == expected_sha256, 'sha256')
            stream.flush()
            os.fsync(stream.fileno())
            need(clock() < deadline, 'deadline')
            if before_publish is not None:
                before_publish()
            parent_path = Path(os.path.abspath(output)).parent
            info = os.fstat(parent)
            need(parent_path == parent_path.resolve() and not any(p.is_symlink() for p in (parent_path, *parent_path.parents))
                 and (info.st_dev, info.st_ino) == (parent_path.stat().st_dev, parent_path.stat().st_ino), 'parent-identity')
            # Hard-link publication is atomic and refuses an existing entry.
            # The fully validated temporary body is never renamed over a path.
            try:
                os.link(temporary, FILENAME, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            except FileExistsError:
                raise Refused('destination-exists') from None
            os.unlink(temporary, dir_fd=parent)
            temporary = None
            os.fsync(parent)
        return dict(bytes=size, sha256=digest.hexdigest())
    except Refused as error:
        error.facts.setdefault('bytes', size)
        raise
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass


def _fetch(output, *, expected_sha256, transport, clock=time.monotonic,
           source_url=FALLBACK_URL, deadline=None, budget=None):
    """Internal fixture seam; the public entry point always supplies SHA256."""
    deadline = clock() + SECONDS if deadline is None else deadline
    budget = [0] if budget is None else budget
    parent = parent_descriptor(output)
    response = None
    current = source_url
    size = 0
    status = None
    redirects = 0
    try:
        while True:
            remaining = deadline - clock()
            need(remaining > 0, 'deadline')
            request = Request(current, headers={'Accept': 'application/octet-stream', 'Accept-Encoding': 'identity'})
            try:
                response = transport.open(request, timeout=min(SOCKET_SECONDS, remaining))
            except HTTPError as error:
                response = error
            except (OSError, URLError, HTTPException) as error:
                raise unavailable(error, 'open') from None
            status = response.code
            if status in (301, 302, 303, 307, 308):
                need(source_url == FALLBACK_URL, 'primary-redirect')
                need(redirects < MAX_REDIRECTS, 'redirect-cap')
                target = redirect_target(current, header(response, 'Location'))
                response.close()
                response = None
                current = target
                redirects += 1
                continue
            # A bodyless fixed GET can still be rejected by an endpoint with 415.
            # No response bytes are trusted; only the other fixed endpoint is tried.
            if status in (404, 408, 410, 415, 429) or type(status) is int and 500 <= status <= 599:
                raise Unavailable('http-status')
            need(status == 200, 'http-status')
            content_type = (header(response, 'Content-Type') or '').split(';', 1)[0].strip().lower()
            need(content_type in CONTENT_TYPES, 'content-type')
            need((header(response, 'Content-Encoding') or 'identity').lower() == 'identity', 'content-encoding')
            declared = header(response, 'Content-Length')
            if declared is not None:
                need(declared.isascii() and declared.isdecimal() and 0 < int(declared) <= MAX_BYTES, 'advertised-size')
                declared = int(declared)
            staged = _stage(output, parent, response, expected_sha256=expected_sha256,
                            deadline=deadline, budget=budget, clock=clock, declared=declared)
            size = staged['bytes']
            return dict(status='VALIDATED_FIXED_ZLIB_SOURCE', source_url=source_url,
                        final_origin='https://' + urlsplit(current).netloc,
                        filename=FILENAME, bytes=size, sha256=staged['sha256'],
                        content_type=content_type, http_status=200, redirects=redirects)
    except Refused as error:
        error.facts.setdefault('bytes', size)
        error.facts.update(source_url=source_url, final_origin='https://' + urlsplit(current).netloc,
                           http_status=status, redirects=redirects)
        raise
    except (OSError, URLError, ValueError, HTTPException):
        raise Refused('filesystem', source_url=source_url, bytes=size) from None
    finally:
        if response is not None:
            response.close()
        os.close(parent)


def _fetch_sources(output, *, expected_sha256, transport, clock=time.monotonic):
    deadline = clock() + SECONDS
    budget = [0]
    attempts = []
    for source_url in (URL, FALLBACK_URL):
        try:
            result = _fetch(output, expected_sha256=expected_sha256, transport=transport,
                            clock=clock, source_url=source_url, deadline=deadline, budget=budget)
        except Refused as error:
            attempts.append(dict(status='REFUSED', reason=str(error), **error.facts))
            if isinstance(error, Unavailable) and source_url == URL:
                continue
            error.facts = dict(attempts=attempts, total_received_bytes=budget[0])
            raise
        result.update(attempts=attempts + [dict(result)], total_received_bytes=budget[0])
        return result


def _local_source(output, archive, *, expected_sha256, clock=time.monotonic):
    """Stage caller-supplied bytes without headers, URL interpretation or network."""
    deadline = clock() + SECONDS
    budget = [0]
    descriptor = None
    parent = None
    try:
        path = Path(os.path.abspath(archive))
        need(not any(p.is_symlink() for p in (path, *path.parents)) and path == path.resolve(), 'local-symlink')
        identity = lambda s: tuple(getattr(s, k) for k in (
            'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
            'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        initial = path.lstat()
        need(stat.S_ISREG(initial.st_mode) and initial.st_uid == os.getuid()
             and initial.st_nlink == 1 and stat.S_IMODE(initial.st_mode) in (0o600, 0o644), 'local-file')
        need(0 < initial.st_size <= MAX_BYTES, 'local-size')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        need(identity(initial) == identity(os.fstat(descriptor)), 'local-identity')
        def stable():
            need(not any(p.is_symlink() for p in (path, *path.parents)) and path == path.resolve()
                 and identity(initial) == identity(os.fstat(stream.fileno())) == identity(path.lstat()), 'local-changed')
        with os.fdopen(descriptor, 'rb') as stream:
            descriptor = None
            parent = parent_descriptor(output)
            result = _stage(output, parent, stream, expected_sha256=expected_sha256,
                            deadline=deadline, budget=budget, clock=clock,
                            declared=initial.st_size, before_publish=stable, local=True)
        result.update(status='VALIDATED_FIXED_ZLIB_SOURCE', source_kind='local_archive',
                      source_url=None, final_origin=None, filename=FILENAME,
                      content_type=None, http_status=None, redirects=0,
                      total_received_bytes=budget[0])
        return result
    except Refused as error:
        error.facts.update(source_kind='local_archive', total_received_bytes=budget[0])
        raise
    except (OSError, ValueError, RuntimeError):
        raise Refused('local-filesystem', source_kind='local_archive', total_received_bytes=budget[0]) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


def fetch_source(output, *, local_archive=None):
    if local_archive is not None:
        return _local_source(output, local_archive, expected_sha256=SHA256)
    # Ignore proxy environment and install no cookie, password or auth handler.
    # Two different fixed official endpoints; no retry, one shared deadline/cap.
    return _fetch_sources(output, expected_sha256=SHA256,
                          transport=build_opener(ProxyHandler({}), NoRedirect()))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='New zlib-1.3.2.tar.gz in an existing ordinary directory')
    parser.add_argument('--local-archive', help='Optional existing fixed archive; validate and stage without network')
    parser.add_argument('--receipt', help='New zlib-source-retrieval.json beside the archive')
    args = parser.parse_args(argv)
    def expired(signum, frame):
        raise Refused('deadline')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, SECONDS)
    receipt_fd = None
    try:
        try:
            if args.receipt:
                receipt = Path(os.path.abspath(args.receipt))
                need(receipt.name == 'zlib-source-retrieval.json'
                     and receipt.parent == Path(os.path.abspath(args.output)).parent, 'receipt-path')
                parent = parent_descriptor(args.output)
                try:
                    receipt_fd = os.open(receipt.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                    os.fchmod(receipt_fd, 0o600)
                finally:
                    os.close(parent)
            result = fetch_source(args.output, local_archive=args.local_archive)
        except (Refused, OSError) as error:
            result = dict(status='REFUSED', reason=str(error) if isinstance(error, Refused) else 'filesystem',
                          source_url=None if args.local_archive is not None else URL, filename=FILENAME,
                          **(error.facts if isinstance(error, Refused) else {}))
            if args.local_archive is not None:
                result['source_kind'] = 'local_archive'
            code = 1
        else:
            code = 0
        encoded = (json.dumps(result, sort_keys=True) + '\n').encode()
        if receipt_fd is not None:
            try:
                with os.fdopen(receipt_fd, 'wb') as stream:
                    receipt_fd = None
                    need(stream.write(encoded) == len(encoded), 'receipt-short-write')
                    stream.flush()
                    os.fsync(stream.fileno())
            except (OSError, Refused):
                result = dict(status='REFUSED', reason='receipt-write',
                              source_url=None if args.local_archive is not None else URL, filename=FILENAME)
                if args.local_archive is not None:
                    result['source_kind'] = 'local_archive'
                code = 1
        print(json.dumps(result, sort_keys=True))
        return code
    finally:
        if receipt_fd is not None:
            os.close(receipt_fd)
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


if __name__ == '__main__':
    raise SystemExit(main())
