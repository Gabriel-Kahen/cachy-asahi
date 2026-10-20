#!/usr/bin/env python3
"""Retrieve five fixed public CI outputs and one official LSP object privately."""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent
POLICY = '5dae018a1357708e85393048728a6fb44cd9c9eb02a78ab19e60435d370ffdf2'
REPO = 'Gabriel-Kahen/cachy-asahi'
MIB = 1024**2
RUNS = (
    ('38789569155', 'native/6_Retain ordinary data build diagnostics and original archives.txt',
     {'summary', 'native', 'build-asahi-audio-1', 'build-asahi-audio-2', 'build-alsa-ucm-conf-asahi-1', 'build-alsa-ucm-conf-asahi-2'}, {
         'build-asahi-audio-1': ('asahi-audio', 4005256, 'ea9b2f979386f71f4d4075201fc2f6a492ac9066ff7b7d95c68c7cc780ff9b95'),
         'build-alsa-ucm-conf-asahi-1': ('alsa-ucm-conf-asahi', 33679, '5c5a64d0afbda303f355a8ae4a0c6fe7ffbfb70ebbcae55f273c3570362e12b7')}),
    ('38801968699', 'native/6_Retain public diagnostics, source snapshots and package pairs.txt',
     {'summary', 'native', 'speakersafetyd-build-1', 'speakersafetyd-build-2', 'bankstown-build-1', 'bankstown-build-2', 'triforce-lv2-build-1', 'triforce-lv2-build-2'}, {
         'speakersafetyd-build-1': ('speakersafetyd', 6205695, 'ee0f33561afdcf291c1c1882fe6ed6599b24e23ff3c3a986dc686aa57a420b72'),
         'bankstown-build-1': ('bankstown', 5953806, '1cafc946a2fb30aa2cd0bf8b9ca7a27c03cabb99b42cd8f2e6a8080c4712e6ca'),
         'triforce-lv2-build-1': ('triforce-lv2', 6157978, '72414a23ae3e5d888a4148f60ffb52c55b85693387ef7879218b62535d76f5a3')}),
)
LSP = 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/lsp-plugins-lv2-1.2.35-1-aarch64.pkg.tar.xz'


class Refused(ValueError): pass


def need(ok, message):
    if not ok: raise Refused(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


def url_allowed(url, github):
    p = urllib.parse.urlsplit(url)
    host = p.hostname or ''
    return (p.scheme == 'https' and p.username is None and p.password is None and p.port in (None, 443) and not p.fragment
            and (host == 'api.github.com' or host.endswith('.blob.core.windows.net') or host.endswith('.actions.githubusercontent.com')
                 if github else host == 'ca.us.mirror.archlinuxarm.org'))


def fetch(url, target, limit, deadline, *, token=None):
    """One initial GET; follow at most4 HTTPS redirects without forwarding auth."""
    github = token is not None
    opener = urllib.request.build_opener(NoRedirect())
    for hop in range(5):
        need(url_allowed(url, github), 'redirect-host-refused')
        need(time.monotonic() < deadline, 'retrieval-deadline')
        headers = {'Accept-Encoding': 'identity', 'User-Agent': 'cachy-asahi-fixed-audio-inputs'}
        if hop == 0 and github:
            need(urllib.parse.urlsplit(url).hostname == 'api.github.com', 'token-host-refused')
            headers.update(Authorization='Bearer ' + token, Accept='application/vnd.github+json', **{'X-GitHub-Api-Version': '2022-11-28'})
        try:
            response = opener.open(urllib.request.Request(url, headers=headers), timeout=30)
        except urllib.error.HTTPError as error:
            if error.code in (301, 302, 303, 307, 308):
                location = error.headers.get('Location'); error.close()
                need(location and hop < 4, 'redirect-limit-or-location')
                url = urllib.parse.urljoin(url, location); continue
            code = error.code; error.close()
            raise Refused('fixed-input-unavailable-http-' + str(code)) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise Refused('fixed-input-unavailable-network') from None
        with response, target.open('xb') as out:
            os.chmod(target, 0o600)
            need(response.status == 200, 'non200-input')
            declared = response.headers.get('Content-Length')
            need(declared is None or declared.isdecimal() and 0 < int(declared) <= limit, 'declared-input-size-refused')
            total = 0
            while True:
                need(time.monotonic() < deadline, 'retrieval-deadline')
                chunk = response.read1(min(1024**2, limit - total + 1))
                if not chunk: break
                total += len(chunk); need(total <= limit, 'download-size-refused'); out.write(chunk)
            need(total > 0, 'empty-input')
            return
    raise Refused('redirect-limit')


def ordinary(name):
    p = PurePosixPath(name)
    return bool(name and len(name) <= 240 and not p.is_absolute() and '..' not in p.parts and '\\' not in name
                and str(p) == name and not any(ord(c) < 32 for c in name))


def extract_package(data, frame, row, output):
    # Bound gzip expansion before tarfile sees PAX/long-name header sizes.
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        expanded = compressed.read(18 * MIB + 1)
    need(len(expanded) <= 18 * MIB, 'frame-expansion-refused')
    wanted = frame + '/artifacts/' + row['filename']
    selected, names, total = None, set(), 0
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        for member in archive:
            need(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and ordinary(member.name) and member.name.startswith(frame + '/') and member.name not in names,
                 'frame-member-type-or-path-refused')
            names.add(member.name); total += member.size
            need(len(names) <= 128 and 0 <= member.size <= 8 * MIB and total <= 16 * MIB, 'frame-member-size-refused')
            if member.name == wanted:
                need(member.size == row['size'] and selected is None, 'package-member-size-or-duplicate')
                selected = archive.extractfile(member).read(row['size'] + 1)
    need(selected is not None and len(selected) == row['size'] and hashlib.sha256(selected).hexdigest() == row['sha256'], 'package-byte-pin-refused')
    destination = output / row['filename']
    with destination.open('xb') as stream: stream.write(selected)
    os.chmod(destination, 0o600)


def zip_budget(path):
    size = path.stat().st_size
    need(22 <= size <= 100 * MIB, 'zip-byte-budget-refused')
    with path.open('rb') as stream:
        start = max(0, size - 65557); stream.seek(start); tail = stream.read(65557)
    offset = tail.rfind(b'PK\x05\x06')
    need(offset >= 0 and len(tail) >= offset + 22, 'zip-end-record-refused')
    _, disk, cd_disk, disk_count, count, cd_size, cd_offset, comment = struct.unpack('<4s4H2LH', tail[offset:offset + 22])
    need(disk == cd_disk == 0 and 0 < disk_count == count <= 64 and cd_size <= 65536
         and cd_offset + cd_size == start + offset and offset + 22 + comment == len(tail), 'zip-directory-budget-refused')


def decode(zip_path, log_name, expected_frames, wanted, policy, output):
    zip_budget(zip_path)  # Bound central-directory allocation before ZipFile parses it.
    with zipfile.ZipFile(zip_path) as archive:
        members = archive.infolist()
        need(0 < len(members) <= 64 and sum(m.file_size for m in members) <= 256 * MIB, 'zip-member-budget-refused')
        names = set()
        for member in members:
            kind = stat.S_IFMT(member.external_attr >> 16)
            need(ordinary(member.filename) and member.filename not in names and not member.flag_bits & 1
                 and kind in (0, stat.S_IFREG) and 0 <= member.file_size <= 96 * MIB
                 and member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), 'zip-entry-refused')
            names.add(member.filename)
        if log_name not in names:
            # Fixed run-log API aggregate shape only; no fuzzy member selection.
            if any(r[1] == log_name for r in RUNS) and names == {'0_native.txt', 'native/system.txt'}:
                log_name = '0_native.txt'
            else:
                # Only bounded public Actions step labels, never log contents or URLs.
                labels = sorted(n for n in names if len(n) <= 200 and re.fullmatch(
                    r'(?:[0-9]{1,3}_[A-Za-z0-9 _.,@()+=~-]+|[A-Za-z0-9 _().-]{1,64}/(?:system|[0-9]{1,3}_[A-Za-z0-9 _.,@()+=~-]+))\.txt', n))
                with zip_path.open('rb') as stream: digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                error = Refused('fixed-retention-step-missing')
                error.lookup = dict(run_id=next((r[0] for r in RUNS if r[1] == log_name), 'UNRECOGNIZED'),
                    expected_step=log_name if any(r[1] == log_name for r in RUNS) else 'UNRECOGNIZED',
                    zip_bytes=zip_path.stat().st_size, zip_sha256=digest, member_count=len(names),
                    public_step_labels=labels[:16], other_members=len(names)-len(labels),
                    labels_truncated=len(labels)>16)
                raise error
        seen, decoded, active, chunks, encoded_size = set(), set(), None, [], 0
        with archive.open(log_name) as stream:
            while True:
                raw = stream.readline(16385)
                if not raw: break
                need(len(raw) <= 16384, 'log-line-budget-refused')
                line = re.sub(rb'^\d{4}-\d\d-\d\dT[^ ]+Z ', b'', raw.removeprefix(b'\xef\xbb\xbf').rstrip(b'\r\n'))
                begin = re.fullmatch(rb'CACHY_ASAHI_EVIDENCE_BEGIN ([A-Za-z0-9-]+) sha256=([0-9a-f]{64}) bytes=(\d+)', line)
                end = re.fullmatch(rb'CACHY_ASAHI_EVIDENCE_END ([A-Za-z0-9-]+)', line)
                if begin:
                    frame, digest, size = begin[1].decode(), begin[2].decode(), int(begin[3])
                    need(active is None and frame in expected_frames and frame not in seen and 0 < size <= 8 * MIB, 'unexpected-frame')
                    seen.add(frame); active = frame; chunks = []; encoded_size = 0
                    if frame in wanted:
                        need((size, digest) == wanted[frame][1:], 'frame-header-pin-refused')
                elif end:
                    need(active == end[1].decode(), 'frame-end-refused')
                    if active in wanted:
                        data = base64.b64decode(b''.join(chunks), validate=True)
                        package, size, digest = wanted[active]
                        need(len(data) == size and hashlib.sha256(data).hexdigest() == digest, 'frame-compressed-pin-refused')
                        extract_package(data, active, policy[package], output); decoded.add(active)
                    active = None
                elif active:
                    encoded_size += len(line)
                    need(encoded_size <= 12 * MIB, 'frame-encoding-budget-refused')
                    if active in wanted: chunks.append(line)
        need(active is None and seen == expected_frames and decoded == set(wanted), 'incomplete-fixed-run-frames')


def retrieve(output):
    temporary = Path(os.environ['RUNNER_TEMP'])
    need(os.getuid() == os.geteuid() > 0 and '..' not in temporary.parts and temporary.is_absolute() and all(not p.is_symlink() for p in (temporary, *temporary.parents))
         and temporary.is_dir() and temporary.stat().st_uid == os.getuid() and not temporary.stat().st_mode & 0o022, 'owned-runner-temp-required')
    need(output.is_absolute() and output.parent == temporary and output.name == 'audio-archives' and not output.exists()
         and not output.is_symlink(), 'new-private-audio-archives-required')
    token = os.environ.pop('GH_TOKEN', '')
    need(token and not any(c in token for c in '\r\n'), 'workflow-actions-read-token-required')
    raw = (HERE / 'audio-inputs.json').read_bytes()
    need(hashlib.sha256(raw).hexdigest() == POLICY, 'audio-policy-pin-refused')
    policy = {r['name']: r for r in json.loads(raw)}
    output.mkdir(mode=0o700)
    try:
        deadline = time.monotonic() + 600
        with tempfile.TemporaryDirectory(prefix='audio-input-retrieval-', dir=temporary) as directory:
            work = Path(directory)
            for run, log, frames, wanted in RUNS:
                path = work / (run + '.zip')
                fetch(f'https://api.github.com/repos/{REPO}/actions/runs/{run}/logs', path, 100 * MIB, deadline, token=token)
                decode(path, log, frames, wanted, policy, output); path.unlink()
            row = policy['lsp-plugins-lv2']
            for suffix, size, digest in (('', row['size'], row['sha256']), ('.sig', row['signature_size'], row['signature_sha256'])):
                path = output / (row['filename'] + suffix)
                fetch(LSP + suffix, path, size, deadline)
                need(path.stat().st_size == size and hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'official-LSP-pin-refused')
        need(len(list(output.iterdir())) == 7, 'seven-fixed-output-files-required')
    except BaseException:
        shutil.rmtree(output); raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try: retrieve(args.output)
    except Exception as error:
        # Do not expose signed redirect URLs, tokens, logs, source or binary data.
        if isinstance(error, Refused) and hasattr(error, 'lookup'):
            print('AUDIO_INPUT_RETRIEVAL_LOOKUP=' + json.dumps(error.lookup, sort_keys=True))
        print('AUDIO_INPUT_RETRIEVAL=FAIL ' + (str(error) if isinstance(error, Refused) else type(error).__name__))
        return 1
    print('AUDIO_INPUT_RETRIEVAL=PASS five-retained-outputs one-official-archive-and-signature private-only')
    return 0


if __name__ == '__main__': raise SystemExit(main())
