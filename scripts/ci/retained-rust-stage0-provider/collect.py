#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Trusted-Main opaque stage0 DATA provider; never extracts or executes inputs."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import ssl
import stat
import sys
import tempfile
import time

HOST = 'static.rust-lang.org'
BASE = 'https://' + HOST + '/dist/2026-08-20/'
FILES = {
    'cargo-1.98.0-aarch64-unknown-linux-gnu.tar.xz': dict(bytes=11116188, sha256='5784379d73ac881d15a9e67eed2882cd58c747c276221c23cdf9aff37e015ff6'),
    'rust-std-1.98.0-aarch64-unknown-linux-gnu.tar.xz': dict(bytes=30768752, sha256='a36f7ac98af20ef0ba6368aace0345efabbebaef7962eba99f47190fd256162d'),
    'rustc-1.98.0-aarch64-unknown-linux-gnu.tar.xz': dict(bytes=66413136, sha256='00590657f2356d7163ca5ef295283523974c340fa21bb94b420ce794f29b358c'),
}
for _name, _row in FILES.items():
    _row['url'] = BASE + _name
SECONDS, FILE_SECONDS, SOCKET_SECONDS = 300, 120, 15
CHUNK = 1024 ** 2
MIN_DISK = 512 * 1024 ** 2
ZIP_LIMIT = 128 * 1024 ** 2
REPOSITORY = 'Gabriel-Kahen/cachy-asahi'
WORKFLOW = REPOSITORY + '/.github/workflows/retained-rust-stage0-provider.yml@refs/heads/main'
SCOPE = 'RETAINED_RUST198_AARCH64_STAGE0_OPAQUE_DATA_ONLY'


def need(value, reason):
    if not value:
        raise ValueError(reason)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def members():
    return [dict(member=name, name=name, role='stage0:' + name, container='ZIP', outer_member=None,
                 bytes=row['bytes'], sha256=row['sha256']) for name, row in FILES.items()]


def profile():
    return dict(schema=1, scope=SCOPE, files=FILES, total_bytes=sum(r['bytes'] for r in FILES.values()),
                host=HOST, port=443, redirects=0, retries=0, requests=3,
                seconds=SECONDS, per_file_seconds=FILE_SECONDS, socket_seconds=SOCKET_SECONDS,
                minimum_disk_bytes=MIN_DISK, zip_bytes_max=ZIP_LIMIT,
                detached_signature_authentication=False, runtime_qualification=False)


def provider_binding(env):
    need(env.get('GITHUB_REPOSITORY') == REPOSITORY and env.get('GITHUB_REF') == 'refs/heads/main'
         and env.get('GITHUB_WORKFLOW_REF') == WORKFLOW and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
         and env.get('GITHUB_RUN_ATTEMPT') == '1' and env.get('GITHUB_JOB') == 'stage0',
         'only first-attempt trusted-Main manual provider job')
    source, run = env.get('GITHUB_SHA'), env.get('GITHUB_RUN_ID')
    need(type(source) is str and re.fullmatch('[0-9a-f]{40}', source)
         and source == env.get('GITHUB_WORKFLOW_SHA') and type(run) is str
         and re.fullmatch('[1-9][0-9]{0,19}', run), 'actual Main workflow source/run required')
    return dict(source=source, ref='refs/heads/main', run=run, attempt=1, job_key='stage0',
                job=None, artifact=None, Root_acceptance=None, runtime_qualification=None)


def ordinary_parent(parent):
    need(parent.is_absolute() and '..' not in parent.parts
         and not any(p.is_symlink() for p in (parent, *parent.parents)), 'ordinary absolute RunnerTemp')
    info = parent.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022,
         'owned RunnerTemp without group/world writes')


def default_https(host, timeout):
    need(host == HOST, 'fixed official host only')
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    need(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname, 'verified TLS required')
    return http.client.HTTPSConnection(host, 443, timeout=timeout, context=context)


def validate_namespace(directory):
    need(not directory.is_symlink() and set(p.name for p in directory.iterdir()) == set(FILES),
         'closed three-file archive namespace')
    for name, expected in FILES.items():
        path = directory / name
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o644
             and info.st_size == expected['bytes'], 'ordinary exact-sized 0644 archive')
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            after = os.fstat(stream.fileno())
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(identity(info) == identity(after) == identity(path.lstat())
             and digest == expected['sha256'], 'whole immutable archive byte pin')


def collect(parent, profile_sha, provider, *, connect=default_https, clock=time.monotonic):
    need(type(profile_sha) is str and profile_sha == pin(encode(profile()))['sha256'],
         'external whole fixed-profile SHA256 mismatch')
    parent = Path(parent)
    ordinary_parent(parent)
    need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'dedicated provider wall timer required')
    # Compression-level0 ZIP overhead/deflate expansion stays below the consumer cap.
    bound = 1024 + sum(r['bytes'] + (r['bytes'] // 16383 + 1) * 5 + 1024 + 2 * len(n)
                       for n, r in FILES.items())
    need(bound <= ZIP_LIMIT, 'stage0 ZIP conservative bound exceeds consumer cap')
    root = Path(tempfile.mkdtemp(prefix='rust-stage0-provider-', dir=parent))
    directory = root / 'archives'
    directory.mkdir(mode=0o755)
    report_path = root / 'provider.DATA.json'
    report = dict(schema=1, scope=SCOPE, status='FETCHING_DATA', provider=provider, profile_sha256=profile_sha,
                  requests=[], body_bytes=0, zip_upper_bound=bound, Root_acceptance=None,
                  native_build=False, runtime_qualification=False, signature_authentication=False)
    started = clock()
    deadline = started + SECONDS
    total = sum(r['bytes'] for r in FILES.values())
    def save():
        report_path.write_bytes(encode(report))
    def tick(file_deadline):
        remaining = min(deadline, file_deadline) - clock()
        need(remaining > 0, 'provider deadline expired')
        need(shutil.disk_usage(parent).free >= MIN_DISK, 'minimum disk reserve')
        need(report['body_bytes'] <= total, 'aggregate response body cap')
        return min(SOCKET_SECONDS, remaining)
    def expired(_signal, _frame):
        raise TimeoutError('provider file/overall wall deadline')
    previous_handler = signal.signal(signal.SIGALRM, expired)
    try:
        save()
        for name, expected in FILES.items():
            file_deadline = min(deadline, clock() + FILE_SECONDS)
            timeout = tick(file_deadline)
            signal.setitimer(signal.ITIMER_REAL, min(deadline, file_deadline) - clock())
            need(expected['url'] == BASE + name and len(report['requests']) < 3, 'fixed URL/request budget')
            attempt = dict(url=expected['url'], status='ATTEMPTED', bytes=0)
            report['requests'].append(attempt)
            save()  # Intent persists before each connection; no retry path exists.
            connection = connect(HOST, timeout)
            response = None
            try:
                connection.request('GET', '/dist/2026-08-20/' + name,
                                   headers={'Accept-Encoding': 'identity', 'User-Agent': 'Cachy-Asahi-stage0-DATA/1'})
                response_socket = connection.sock
                response = connection.getresponse()
                tick(file_deadline)
                attempt['http_status'] = response.status
                need(response.status == 200, 'HTTP200 required; redirects/errors are not retried')
                headers = response.getheaders()
                need(sum(len(k) + len(v) for k, v in headers) <= 16384, 'HTTP header cap')
                values = lambda key: [v for k, v in headers if k.lower() == key]
                lengths = values('content-length')
                need(len(lengths) == 1 and lengths[0] == str(expected['bytes'])
                     and not values('transfer-encoding') and values('content-encoding') in ([], ['identity']),
                     'one exact Content-Length and identity body framing required')
                digest = hashlib.sha256()
                partial = directory / (name + '.partial')
                with partial.open('xb') as stream:
                    while attempt['bytes'] < expected['bytes']:
                        timeout = tick(file_deadline)
                        if response_socket is not None:
                            response_socket.settimeout(timeout)
                        count = min(CHUNK, expected['bytes'] - attempt['bytes'], total - report['body_bytes'])
                        need(count > 0, 'remaining body cap')
                        block = response.read1(count)
                        need(type(block) is bytes and 0 < len(block) <= count, 'short or excessive response body')
                        tick(file_deadline)
                        attempt['bytes'] += len(block)
                        report['body_bytes'] += len(block)
                        stream.write(block)
                        digest.update(block)
                    need(response.length == 0 and digest.hexdigest() == expected['sha256'],
                         'whole response framing/SHA256 mismatch')
                    stream.flush()
                    os.fsync(stream.fileno())
                    os.fchmod(stream.fileno(), 0o644)
                # No-replace publication inside this fresh private directory.
                os.link(partial, directory / name, follow_symlinks=False)
                partial.unlink()
                attempt.update(status='PIN_MATCH', sha256=digest.hexdigest())
                save()
            finally:
                try:
                    if response is not None:
                        response.close()
                finally:
                    connection.close()
        signal.setitimer(signal.ITIMER_REAL, max(0.001, deadline - clock()))
        tick(deadline)
        need(report['body_bytes'] == total and len(report['requests']) == 3, 'exact aggregate transfer')
        validate_namespace(directory)
        tick(deadline)
        report['status'] = 'THREE_PINNED_STAGE0_ARCHIVES_DATA_ONLY'
        save()
        return dict(directory=str(directory), report=report, report_path=str(report_path))
    except BaseException as error:
        report.update(status='STOPPED_NO_RETRY', error=type(error).__name__)
        save()
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile-sha256')
    parser.add_argument('--describe', action='store_true')
    args = parser.parse_args()
    if args.describe:
        print(encode(dict(profile=profile(), profile_sha256=pin(encode(profile()))['sha256'])).decode(), end='')
        return
    need(sys.flags.isolated and not sys.flags.optimize, 'isolated unoptimized trusted collector required')
    provider = provider_binding(os.environ)
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 ** 2,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (60,) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (max(r['bytes'] for r in FILES.values()),) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    result = collect(Path(os.environ['RUNNER_TEMP']), args.profile_sha256, provider)
    print(encode(dict(scope=SCOPE, status=result['report']['status'], files=3,
                      bytes=result['report']['body_bytes'], zip_upper_bound=result['report']['zip_upper_bound'])).decode(), end='')
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
        stream.write('archive_directory=' + result['directory'] + '\n')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, TimeoutError, http.client.HTTPException, MemoryError) as error:
        print('REFUSED: ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(2)
