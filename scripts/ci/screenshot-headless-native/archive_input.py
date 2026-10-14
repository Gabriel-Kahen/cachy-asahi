"""Admit one fixed native-build helper from original GitHub workflow logs."""
import base64
import gzip
import hashlib
import http.client
import io
import ipaddress
import json
import lzma
import math
import os
from pathlib import Path, PurePosixPath
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse
import zipfile

REPOSITORY = 'Gabriel-Kahen/cachy-asahi'
RUN = 38571648129
ATTEMPT = 1
JOB = 115917195186
SOURCE = '92a3f0612c558b91accc15cd6495d98d6463b943'
WORKFLOW = 381664314
API = 'https://api.github.com/repos/' + REPOSITORY
TGZ = {'frame': 'native-evidence', 'bytes': 1275070,
       'sha256': 'dea293276f1e465012fa17fab39e8a7c28ee6003e53a0c0d5a54db4061e55a4d'}
PACKAGE = {'member': 'native-evidence/cachy-asahi-hyprland-settings-1/artifacts/cachy-asahi-hyprland-settings-0.1.0-2-any.pkg.tar.xz',
           'bytes': 12740, 'sha256': '0b22b778ec83d8b98d98d06fa4f016bd4e3f581b69efa83d6526c5265c2adf5e'}
HELPER = {'member': 'usr/bin/cachy-asahi-screenshot', 'bytes': 8523,
          'sha256': '5a920a5dd7a40463417a9b15e64a6620acfe7b2328960bf7014c9f587c4b69a8', 'mode': '0755'}
LIMITS = {'json_bytes': 262144, 'zip_bytes': 8388608, 'zip_members': 32,
          'zip_total_bytes': 16777216, 'log_bytes': 6291456, 'log_line_bytes': 16384,
          'outer_tar_bytes': 9574400, 'outer_members': 512,
          'package_tar_bytes': 262144, 'package_members': 32, 'seconds': 120}
CONTRACT = {'schema_version': 1, 'repository': REPOSITORY, 'run_id': RUN,
            'run_attempt': ATTEMPT, 'source_commit': SOURCE, 'workflow_id': WORKFLOW,
            'job_id': JOB, 'tgz': TGZ, 'package': PACKAGE, 'helper': HELPER,
            'log_member': '0_native.txt', 'limits': LIMITS}


class Refusal(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise Refusal('archive-input-' + code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked(data, spec, code):
    need(len(data) == spec['bytes'] and sha(data) == spec['sha256'], code)
    return data


def origin_refusal(ok, request_role, hop, check, parsed):
    """Retain only bounded origin context; never export URL components."""
    if not ok:
        error = Refusal('archive-input-download-origin')
        error.archive_origin = {
            'request_role': request_role if type(request_role) is str and request_role in ('run_attempt', 'job', 'attempt_logs') else 'unknown',
            'hop': hop if type(hop) is int and 0 <= hop <= 2 else None,
            'check': check if type(check) is str and check in ('shape', 'route') else 'unknown',
            'scheme': None, 'hostname': None, 'port': None, 'userinfo_present': False,
        }
        try:
            error.archive_origin['userinfo_present'] = parsed.username is not None or parsed.password is not None
            scheme = parsed.scheme
            if type(scheme) is str and re.fullmatch(r'[a-z][a-z0-9+.-]{0,15}', scheme):
                error.archive_origin['scheme'] = scheme
            hostname = parsed.hostname
            if type(hostname) is str and len(hostname) <= 253 and re.fullmatch(r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}', hostname) and hostname.rsplit('.', 1)[-1].lower() not in ('localhost', 'localdomain', 'local', 'internal', 'home', 'lan', 'corp', 'private', 'intranet', 'invalid', 'test', 'example', 'onion', 'arpa'):
                error.archive_origin['hostname'] = hostname
            try:
                port = parsed.port
            except ValueError:
                port = None
            if type(port) is int and 0 <= port <= 65535:
                error.archive_origin['port'] = port
        except Exception:
            pass  # Telemetry must not replace the already established refusal.
        raise error


class AlarmExpired(BaseException):
    pass


def unresolved_cleanup(error):
    try:
        error.archive_cleanup = 'UNRESOLVED'
    except Exception:
        pass


class Deadline:
    """Linux/main-thread only; no existing alarm ownership may be displaced."""
    def __init__(self, end):
        need(type(end) in (int, float) and math.isfinite(end), 'deadline')
        self.end = end

    def remaining(self):
        remaining = self.end - time.monotonic()
        need(remaining > 0, 'deadline')
        return remaining

    def expire(self, *_):
        raise AlarmExpired()

    def tighten(self, end):
        self.end = min(self.end, end)
        signal.setitimer(signal.ITIMER_REAL, self.remaining())

    def cancel(self):
        signal.setitimer(signal.ITIMER_REAL, 0)

    def __enter__(self):
        need(sys.platform == 'linux' and threading.current_thread() is threading.main_thread(), 'deadline-owner')
        need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0) and
             signal.SIGALRM not in signal.sigpending() and
             signal.SIGALRM not in signal.pthread_sigmask(signal.SIG_BLOCK, []), 'deadline-owner')
        self.previous = signal.getsignal(signal.SIGALRM)
        need(self.previous in (signal.SIG_DFL, signal.SIG_IGN) or callable(self.previous), 'deadline-handler')
        signal.signal(signal.SIGALRM, self.expire)
        try:
            signal.setitimer(signal.ITIMER_REAL, self.remaining())
        except BaseException as error:
            for cleanup in (lambda: self.cancel(), lambda: signal.signal(signal.SIGALRM, self.previous)):
                try:
                    cleanup()
                except BaseException:
                    unresolved_cleanup(error)
            if isinstance(error, AlarmExpired):
                primary = Refusal('archive-input-deadline')
                if getattr(error, 'archive_cleanup', None) == 'UNRESOLVED':
                    unresolved_cleanup(primary)
                raise primary from None
            raise
        return self

    def __exit__(self, kind, value, traceback):
        failed = False
        for cleanup in (lambda: self.cancel(), lambda: signal.signal(signal.SIGALRM, self.previous)):
            try:
                cleanup()
            except BaseException:
                failed = True
        if failed and value is not None:
            unresolved_cleanup(value)
        if kind is AlarmExpired:
            primary = Refusal('archive-input-deadline')
            if getattr(value, 'archive_cleanup', None) == 'UNRESOLVED':
                unresolved_cleanup(primary)
            raise primary from None
        if failed and kind is None:
            primary = Refusal('archive-input-deadline-cleanup')
            unresolved_cleanup(primary)
            raise primary


def delegated_url(url, request_role, hop):
    """Location is opaque, but only a bounded absolute HTTPS DNS URL is usable."""
    empty = urllib.parse.urlsplit('')
    shape = type(url) is str and 0 < len(url) <= 8192 and all(33 <= ord(c) < 127 for c in url) and '\\' not in url and '#' not in url
    origin_refusal(shape, request_role, hop, 'shape', empty)
    try:
        parsed = urllib.parse.urlsplit(url)
        valid = (parsed.scheme == 'https' and parsed.username is None and parsed.password is None and
                 parsed.port in (None, 443) and type(parsed.hostname) is str and len(parsed.hostname) <= 253 and
                 re.fullmatch(r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}', parsed.hostname) is not None and
                 parsed.netloc.lower() in (parsed.hostname, parsed.hostname + ':443'))
    except (ValueError, UnicodeError):
        origin_refusal(False, request_role, hop, 'shape', empty)
    origin_refusal(valid, request_role, hop, 'shape', parsed)
    return parsed


def public_address(value):
    address = ipaddress.ip_address(value)
    if not address.is_global or any((address.is_private, address.is_loopback, address.is_link_local,
                                    address.is_multicast, address.is_reserved, address.is_unspecified)):
        return False
    if address.version == 4:
        return address not in ipaddress.ip_network('192.0.0.0/24')
    return (address in ipaddress.ip_network('2000::/3') and not address.is_site_local and address.ipv4_mapped is None and address.sixtofour is None and
            address.teredo is None and not any(address in ipaddress.ip_network(prefix) for prefix in
            ('64:ff9b::/96', '64:ff9b:1::/48', '2001::/23', '2002::/16', '2001:db8::/32', '3fff::/20')))


RESOLVER_CODE = """import json,socket,sys
try:
 rows=socket.getaddrinfo(sys.argv[1],443,type=socket.SOCK_STREAM,proto=socket.IPPROTO_TCP)
 if not 0<len(rows)<=32:sys.exit(2)
 data=json.dumps([[f,k,p,list(a)] for f,k,p,_,a in rows],separators=(',',':')).encode('ascii')
 if len(data)>16384:sys.exit(2)
 sys.stdout.buffer.write(data)
except Exception:sys.exit(2)
"""


def public_addresses(hostname, deadline):
    """One isolated resolution; never leave libc DNS blocking the parent."""
    process = None
    primary = None
    previous_mask = None
    try:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGALRM])
        spawn_primary = None
        try:
            process = subprocess.Popen([sys.executable, '-I', '-S', '-c', RESOLVER_CODE, hostname],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       env={}, close_fds=True)
        except BaseException as error:
            spawn_primary = error
            raise
        finally:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            except BaseException:
                if spawn_primary is None:
                    raise
                unresolved_cleanup(spawn_primary)
        output, _ = process.communicate(timeout=min(15, deadline.remaining()))
        need(process.returncode == 0 and len(output) <= 16384, 'dns-result')
        rows = json.loads(output)
    except subprocess.TimeoutExpired:
        primary = Refusal('archive-input-dns-timeout')
        raise primary from None
    except BaseException as error:
        primary = error
        raise
    finally:
        # Bound cleanup separately; expired alarm must not interrupt kill/reap.
        cleanup_failed = False
        try:
            deadline.cancel()
        except BaseException:
            cleanup_failed = True
        if previous_mask is not None:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            except BaseException:
                cleanup_failed = True
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
            except BaseException:
                cleanup_failed = True
            try:
                process.wait(timeout=2)
            except BaseException:
                cleanup_failed = True
            try:
                if process.stdout is not None:
                    process.stdout.close()
            except BaseException:
                cleanup_failed = True
        if primary is None:
            if cleanup_failed:
                error = Refusal('archive-input-dns-cleanup')
                unresolved_cleanup(error)
                raise error
            deadline.tighten(deadline.end)
        elif cleanup_failed:
            unresolved_cleanup(primary)
    need(type(rows) is list and 0 < len(rows) <= 32, 'dns-answers')
    addresses = []
    for row in rows:
        need(type(row) is list and len(row) == 4, 'dns-answer-shape')
        family, kind, protocol, address = row
        need(all(type(v) is int for v in (family, kind, protocol)) and type(address) is list and
             family in (socket.AF_INET, socket.AF_INET6) and kind == socket.SOCK_STREAM and
             protocol == socket.IPPROTO_TCP and len(address) == (2 if family == socket.AF_INET else 4) and
             type(address[0]) is str and type(address[1]) is int and address[1] == 443 and '%' not in address[0] and
             (family == socket.AF_INET or (all(type(v) is int for v in address[2:]) and address[2:] == [0, 0])), 'dns-answer-shape')
        parsed = ipaddress.ip_address(address[0])
        need(parsed.version == (4 if family == socket.AF_INET else 6) and public_address(address[0]), 'dns-public')
        item = (family, tuple(address))
        if item not in addresses:
            addresses.append(item)
    return addresses


class PublicHTTPSConnection(http.client.HTTPSConnection):
    """Numeric dial only; HTTP cannot auto-open/re-resolve after socket loss."""
    def __init__(self, hostname, addresses, deadline):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)
        need(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED, 'tls-verification')
        super().__init__(hostname, 443, timeout=deadline.remaining(), context=context)
        self.addresses, self.deadline = addresses, deadline
        self.auto_open = 0

    def checked_peer(self, stream):
        peer = stream.getpeername()
        need(len(peer) in (2, 4) and peer[1] == 443 and
             (len(peer) == 2 or peer[2:] == (0, 0)), 'connected-peer')
        value = ipaddress.ip_address(peer[0])
        need(public_address(peer[0]) and any(value == ipaddress.ip_address(row[1][0]) for row in self.addresses), 'connected-peer')

    def connect(self):
        for family, address in self.addresses:
            raw = None
            try:
                raw = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                raw.settimeout(min(5, self.deadline.remaining()))
                raw.connect(address)
            except OSError:
                if raw is not None:
                    try:
                        raw.close()
                    except BaseException:
                        error = Refusal('archive-input-connect-cleanup')
                        unresolved_cleanup(error)
                        raise error from None
                self.deadline.remaining()
                continue  # TCP only: no TLS attempt, HTTP resend or new DNS query.
            except BaseException as error:
                if raw is not None:
                    try:
                        raw.close()
                    except BaseException:
                        unresolved_cleanup(error)
                raise
            held = raw
            try:
                self.checked_peer(raw)
                raw.settimeout(self.deadline.remaining())
                held = self._context.wrap_socket(raw, server_hostname=self.host)
                self.checked_peer(held)
                held.settimeout(self.deadline.remaining())
                self.sock = held
                return
            except BaseException as error:
                try:
                    held.close()
                except BaseException:
                    unresolved_cleanup(error)
                raise  # Peer/certificate/TLS failures never select another address.
        raise Refusal('archive-input-connect-failed')


def download(url, limit, token, deadline, request_role):
    """Fixed API metadata or fresh API-delegated logs; never persist Location."""
    fixed = {'run_attempt': API + f'/actions/runs/{RUN}/attempts/{ATTEMPT}',
             'job': API + f'/actions/jobs/{JOB}',
             'attempt_logs': API + f'/actions/runs/{RUN}/attempts/{ATTEMPT}/logs'}
    need(request_role in fixed and url == fixed[request_role], 'request-role')
    try:
        with Deadline(deadline) as clock:
            for hop in range(3):
                parsed = delegated_url(url, request_role, hop)
                addresses = public_addresses(parsed.hostname, clock)
                clock.remaining()
                connection = PublicHTTPSConnection(parsed.hostname, addresses, clock)
                response = None
                primary = None
                try:
                    connection.connect()
                    # Slice the original value: preserve empty query delimiters and escape case.
                    target = url[url.index('://') + 3 + len(parsed.netloc):]
                    if not target or target.startswith('?'):
                        target = '/' + target
                    headers = {'Host': parsed.netloc, 'User-Agent': 'cachy-asahi-native-custody'}
                    if hop == 0:
                        headers.update({'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2026-03-10'})
                        if token is not None:
                            headers['Authorization'] = 'Bearer ' + token
                    connection.request('GET', target, headers=headers)
                    response = connection.getresponse()
                    received_at = time.monotonic()
                    clock.remaining()
                    if request_role == 'attempt_logs' and (hop == 0 or response.status in (301, 302, 303, 307, 308)):
                        need(response.status == 302 if hop == 0 else hop < 2, 'redirect-status-or-limit')
                        locations = response.headers.get_all('Location', [])
                        need(len(locations) == 1, 'redirect-location')
                        if hop == 0:
                            clock.tighten(received_at + 45)
                        url = locations[0]
                        # Validate before any following request; no urljoin or reconstruction.
                        delegated_url(url, request_role, hop + 1)
                        continue
                    need(response.status == 200, 'http-status')
                    declared = response.headers.get_all('Content-Length', [])
                    need(len(declared) <= 1 and (not declared or
                         (declared[0].isdecimal() and len(declared[0]) <= 12 and int(declared[0]) <= limit)), 'download-size')
                    data = bytearray()
                    while True:
                        clock.remaining()
                        chunk = response.read(min(65536, limit + 1 - len(data)))
                        if not chunk:
                            break
                        data.extend(chunk)
                        need(len(data) <= limit, 'download-size')
                    clock.remaining()
                    need(not declared or len(data) == int(declared[0]), 'download-size')
                    return bytes(data)
                except BaseException as error:
                    primary = error
                    raise
                finally:
                    for resource in (response, connection):
                        if resource is not None:
                            try:
                                resource.close()
                            except BaseException as error:
                                if primary is None:
                                    primary = error if isinstance(error, AlarmExpired) else Refusal('archive-input-response-close')
                                unresolved_cleanup(primary)
                    if primary is not None and not sys.exc_info()[0]:
                        raise primary
    except Refusal:
        raise
    except Exception as error:
        # HTTP/TLS/DNS exception strings may contain credentials or signed URLs.
        primary = Refusal('archive-input-download-failed')
        if getattr(error, 'archive_cleanup', None) == 'UNRESOLVED':
            unresolved_cleanup(primary)
        raise primary from None
    raise Refusal('archive-input-redirect-limit')


def document(data):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            need(key not in out, 'json-duplicate')
            out[key] = value
        return out
    try:
        result = json.loads(data, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError('archive-input-json') from None
    need(type(result) is dict, 'json-object')
    return result


def identities(run, job):
    need(all(type(run.get(k)) is int for k in ('id', 'run_attempt', 'workflow_id')) and
         type(run.get('repository')) is dict, 'run-shape')
    need(all(type(job.get(k)) is int for k in ('id', 'run_id', 'run_attempt')) and
         type(job.get('steps')) is list and all(type(s) is dict for s in job['steps']), 'job-shape')
    need(run.get('id') == RUN and run.get('run_attempt') == ATTEMPT and
         run.get('head_sha') == SOURCE and run.get('workflow_id') == WORKFLOW and
         run.get('event') == 'workflow_dispatch' and run.get('status') == 'completed' and
         run.get('conclusion') == 'success' and run.get('path') == '.github/workflows/native-arm-build.yml' and
         run.get('repository', {}).get('full_name') == REPOSITORY, 'run-identity')
    need(job.get('id') == JOB and job.get('run_id') == RUN and job.get('run_attempt') == ATTEMPT and
         job.get('head_sha') == SOURCE and job.get('name') == 'native' and
         job.get('status') == 'completed' and job.get('conclusion') == 'success' and
         job.get('labels') == ['ubuntu-24.04-arm'], 'job-identity')
    exports = [s for s in job.get('steps', []) if s.get('name') ==
               'Retain bounded evidence and package artifacts in free workflow logs']
    need(len(exports) == 1 and exports[0].get('conclusion') == 'success', 'export-step')


def safe_name(name):
    need(type(name) is str and 0 < len(name) <= 240 and all(32 <= ord(c) < 127 for c in name) and '\\' not in name and
         '\0' not in name and not name.startswith('/') and
         all(p not in ('', '.', '..') for p in name.rstrip('/').split('/')), 'member-name')
    need(str(PurePosixPath(name)) == name.rstrip('/'), 'member-name')


def log_from_zip(data):
    need(len(data) <= LIMITS['zip_bytes'], 'zip-size')
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            need(0 < len(members) <= LIMITS['zip_members'], 'zip-members')
            need(sum(m.file_size for m in members) <= LIMITS['zip_total_bytes'], 'zip-total')
            seen = set()
            selected = None
            for member in members:
                safe_name(member.filename)
                need(member.filename not in seen, 'zip-duplicate')
                seen.add(member.filename)
                mode = member.external_attr >> 16
                need(not member.flag_bits & 1 and not mode & 0o7000 and
                     stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR) and
                     member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), 'zip-type')
                need(member.file_size <= LIMITS['log_bytes'], 'log-size')
                if member.is_dir():
                    need(member.file_size == 0, 'zip-directory')
                    continue
                need(stat.S_IFMT(mode) != stat.S_IFDIR, 'zip-type')
                with archive.open(member) as stream:
                    body = stream.read(member.file_size + 1)
                need(len(body) == member.file_size, 'zip-member-size')
                if member.filename == CONTRACT['log_member']:
                    selected = body
            need(selected is not None, 'log-member')
            return selected
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError):
        raise ValueError('archive-input-zip-invalid') from None


def framed_tgz(log):
    need(len(log) <= LIMITS['log_bytes'], 'log-size')
    try:
        lines = log.decode('utf-8-sig').splitlines()
    except UnicodeError:
        raise ValueError('archive-input-log-encoding') from None
    payload = []
    prefix = r'(?:native\tRetain bounded evidence and package artifacts in free workflow logs\t)?'
    stamp = r'\ufeff?\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z '
    for line in lines:
        need(len(line.encode()) <= LIMITS['log_line_bytes'], 'log-line')
        match = re.fullmatch(prefix + stamp + r'(.*)', line)
        if match:
            payload.append(match[1])
        else:
            need('CACHY_ASAHI_EVIDENCE_' not in line, 'log-prefix')
    begin = 'CACHY_ASAHI_EVIDENCE_BEGIN native-evidence'
    end = 'CACHY_ASAHI_EVIDENCE_END native-evidence'
    starts = [i for i, p in enumerate(payload) if p.startswith(begin)]
    ends = [i for i, p in enumerate(payload) if p.startswith(end)]
    need(len(starts) == len(ends) == 1 and starts[0] < ends[0], 'frame-unique')
    need(payload[starts[0]] == begin + ' sha256=' + TGZ['sha256'] + ' bytes=' + str(TGZ['bytes'])
         and payload[ends[0]] == end, 'frame-header')
    chunks = payload[starts[0] + 1:ends[0]]
    encoded_length = 4 * ((TGZ['bytes'] + 2) // 3)
    need(len(chunks) == (encoded_length + 75) // 76 and all(
        re.fullmatch(r'[A-Za-z0-9+/]{1,76}={0,2}', chunk) and
        (i == len(chunks) - 1 or len(chunk) == 76) for i, chunk in enumerate(chunks)), 'frame-base64')
    encoded = ''.join(chunks)
    need(len(encoded) == encoded_length, 'frame-size')
    try:
        data = base64.b64decode(encoded, validate=True)
    except ValueError:
        raise ValueError('archive-input-frame-base64') from None
    need(base64.b64encode(data).decode() == encoded, 'frame-base64-canonical')
    return checked(data, TGZ, 'tgz-identity')


def tar_member(data, target, maximum_members, expected_regular=None):
    seen = set()
    selected = None
    regular = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
            for member in archive:
                name = member.name.removeprefix('./')
                safe_name(name)
                need(name not in seen and len(seen) < maximum_members, 'tar-members')
                seen.add(name)
                need(member.isfile() or member.isdir(), 'tar-type')
                need(not member.mode & 0o7000 and member.size >= 0 and member.size <= len(data), 'tar-size-mode')
                if member.isfile():
                    regular += 1
                if name == target:
                    need(member.isfile(), 'target-type')
                    selected = (archive.extractfile(member).read(member.size + 1), stat.S_IMODE(member.mode))
                    need(len(selected[0]) == member.size, 'target-size')
        need(selected is not None and (expected_regular is None or regular == expected_regular), 'target-member')
        return selected
    except (tarfile.TarError, EOFError):
        raise ValueError('archive-input-tar-invalid') from None


def helper_from_tgz(tgz):
    checked(tgz, TGZ, 'tgz-identity')
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(tgz)) as stream:
            outer = stream.read(LIMITS['outer_tar_bytes'] + 1)
        need(len(outer) == LIMITS['outer_tar_bytes'], 'outer-size')
        package, _ = tar_member(outer, PACKAGE['member'], LIMITS['outer_members'], 262)
        checked(package, PACKAGE, 'package-identity')
        decoder = lzma.LZMADecompressor(memlimit=128 * 1024 * 1024)
        inner = decoder.decompress(package, max_length=LIMITS['package_tar_bytes'] + 1)
        need(len(inner) <= LIMITS['package_tar_bytes'] and decoder.eof and not decoder.unused_data, 'package-size')
        helper, mode = tar_member(inner, HELPER['member'], LIMITS['package_members'], 11)
        need(mode == 0o755, 'helper-mode')
        return checked(helper, HELPER, 'helper-identity')
    except (OSError, EOFError, lzma.LZMAError):
        raise ValueError('archive-input-compression') from None


def store_new(destination, data):
    parent = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    fd = None
    primary = None
    try:
        info = os.fstat(parent)
        need(info.st_uid == os.getuid() and not info.st_mode & 0o022, 'destination-parent')
        fd = os.open(destination.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o755, dir_fd=parent)
        remaining = memoryview(data)
        while remaining:
            written = os.write(fd, remaining)
            need(written > 0, 'destination-write')
            remaining = remaining[written:]
        os.fchmod(fd, 0o755)
        os.lseek(fd, 0, os.SEEK_SET)
        checked(os.read(fd, HELPER['bytes'] + 1), HELPER, 'destination-identity')
        held = os.fstat(fd)
        named = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(held.st_mode) and held.st_uid == os.getuid() and held.st_nlink == 1 and
             stat.S_IMODE(held.st_mode) == 0o755 and (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino), 'destination-identity')
    except BaseException as exc:
        primary = exc
        raise
    finally:
        for handle in (fd, parent):
            if handle is not None:
                try:
                    os.close(handle)
                except OSError:
                    if primary is None:
                        primary = ValueError('archive-input-destination-close')
        if primary is not None and not sys.exc_info()[0]:
            raise primary


def acquire_helper(destination: Path, *, token: str | None = None) -> dict:
    """No fallback: authenticate original remote logs and create one new staged file."""
    need(token is None or (type(token) is str and 0 < len(token) <= 8192 and '\n' not in token and '\r' not in token), 'token-type')
    destination = Path(destination)
    need(destination.name not in ('', '.', '..'), 'destination-name')
    deadline = time.monotonic() + LIMITS['seconds']
    run = document(download(API + f'/actions/runs/{RUN}/attempts/{ATTEMPT}', LIMITS['json_bytes'], token, deadline, 'run_attempt'))
    job = document(download(API + f'/actions/jobs/{JOB}', LIMITS['json_bytes'], token, deadline, 'job'))
    identities(run, job)
    logs = download(API + f'/actions/runs/{RUN}/attempts/{ATTEMPT}/logs', LIMITS['zip_bytes'], token, deadline, 'attempt_logs')
    log = log_from_zip(logs)
    helper = helper_from_tgz(framed_tgz(log))
    need(time.monotonic() < deadline, 'deadline')
    store_new(destination, helper)
    need(time.monotonic() < deadline, 'deadline')
    return {'schema_version': 1, 'status': 'AUTHENTICATED_NATIVE_ARCHIVE_HELPER',
            'repository': REPOSITORY, 'run_id': RUN, 'run_attempt': ATTEMPT,
            'source_commit': SOURCE, 'workflow_id': WORKFLOW, 'job_id': JOB,
            'tgz': dict(TGZ), 'package': dict(PACKAGE), 'helper': dict(HELPER),
            'log_archive': {'bytes': len(logs), 'sha256': sha(logs), 'selected_member': CONTRACT['log_member'],
                            'selected_log_bytes': len(log), 'selected_log_sha256': sha(log)}}
