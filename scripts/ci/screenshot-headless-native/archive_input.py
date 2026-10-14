"""Admit one fixed native-build helper from original GitHub workflow logs."""
import base64
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def download(url, limit, token, deadline):
    """Fixed API origin; credentials never follow the signed storage redirect."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    for hop in range(3):
        parsed = urllib.parse.urlsplit(url)
        need(parsed.scheme == 'https' and not parsed.username and not parsed.password
             and parsed.port in (None, 443), 'download-origin')
        api = parsed.hostname == 'api.github.com'
        storage = re.fullmatch(r'productionresultssa[0-9]+\.blob\.core\.windows\.net', parsed.hostname or '')
        need((hop == 0 and api and url.startswith(API + '/actions/')) or
             (hop > 0 and storage), 'download-origin')
        headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'cachy-asahi-native-custody',
                   'X-GitHub-Api-Version': '2026-03-10'}
        if api and token is not None:
            headers['Authorization'] = 'Bearer ' + token
        need(time.monotonic() < deadline, 'deadline')
        try:
            response = opener.open(urllib.request.Request(url, headers=headers),
                                   timeout=min(15, deadline - time.monotonic()))
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                location = exc.headers.get('Location', '')
                exc.close()
                need(bool(location), 'redirect-location')
                url = urllib.parse.urljoin(url, location)
                continue
            code = exc.code
            exc.close()
            raise ValueError('archive-input-http-' + str(code)) from None
        except Exception:
            raise ValueError('archive-input-download-failed') from None
        primary = None
        try:
            need(response.status == 200, 'http-status')
            declared = response.headers.get('Content-Length')
            need(declared is None or (declared.isdecimal() and int(declared) <= limit), 'download-size')
            data = bytearray()
            while True:
                need(time.monotonic() < deadline, 'deadline')
                chunk = response.read(min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                need(len(data) <= limit, 'download-size')
            need(time.monotonic() < deadline, 'deadline')
            return bytes(data)
        except Refusal as exc:
            primary = exc
            raise
        except Exception:
            primary = ValueError('archive-input-download-failed')
            raise primary from None
        except BaseException as exc:
            primary = exc
            raise
        finally:
            try:
                response.close()
            except Exception:
                if primary is None:
                    raise ValueError('archive-input-response-close') from None
    raise ValueError('archive-input-redirect-limit')


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
    run = document(download(API + f'/actions/runs/{RUN}/attempts/{ATTEMPT}', LIMITS['json_bytes'], token, deadline))
    job = document(download(API + f'/actions/jobs/{JOB}', LIMITS['json_bytes'], token, deadline))
    identities(run, job)
    logs = download(API + f'/actions/runs/{RUN}/attempts/{ATTEMPT}/logs', LIMITS['zip_bytes'], token, deadline)
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
