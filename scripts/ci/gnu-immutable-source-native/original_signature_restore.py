# SPDX-License-Identifier: MIT
"""Required original ALARM signature restore; unsigned candidate policy stays separate.

No import-time actors. Runtime callers supply the existing bounded runner and a
PID1-established current clock. This helper never adjusts time or edits a DB.
"""
import base64
import contextlib
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
import types

PACKAGE = 'glibc-2.43+r22+g8362e8ce10b2-2-aarch64.pkg.tar.xz'
PACKAGE_PIN = dict(bytes=9676568, sha256='8fac217e98c6e4342326726b2640ac254e8c82032f06f30bfa13ebbcc4fcb25b')
SIGNATURE_PIN = dict(bytes=566, sha256='82501115482ffeb93cce58cbc36372d917159f9dd60e3b98fd465e94e16c2103')
FINGERPRINT = '68B3537F39A313B3E574D06777193F152BDBE6A6'
SIGNATURE_CREATED = 1779031879
KEYRING_COMMIT = '29432c01130efc4ad297dfe8f487d5b79cbaf8e9'
PUBLIC_KEY_BASE64 = 'LS0tLS1CRUdJTiBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tCgptUUlOQkZMYkJQTUJFQUROQjJYQ2hKUXBsUXdiQWNsOHdraHNQWk9vekdoeFVZTytCVkVGNXZLanhjTnplUjU3CmNqajF2ZVN3NGFNbUV2MDNNa0JIaTlLeXlrMndLVWtGSHVUeDREQTVaeG5UdCsyU2NFZXpFRmNtRW9Mc1JZaWQKZVEzNXRZV2FGanBqWkRMYlI0YnAwRXVtQ2k4enZ4d1FoWGwxeTRtUlp0QkNYOHo0b3RkZ1hrOGRCVVNKSnNIZwpKc21Sb2J6TnJCREdFcjU1bk5iVDg4QnhWY0czOWlkRWIvVk9PcVMyNHJvZ05KdmtRVWRSd211OEJHYlNXSS9JCmFMQjBXYzNjTUVNWUNmNVRqRXdTOUhzU3ZVT21kV0U2UldpYnBuYVFwOS9DQzJQSGpQMVFuWGJ5M2IxdEE0bk4KbTNJa1A4SHF3cGVJclNMM2hYU0dLTW4zcjhEL1NpbDFrZlUxVTVubGwweWsxaEZvQWZWSzRBV0V2Y1hIcXkzQgp3RFlhMWl5aWlxR3htTlJ5aUs2OEVabGMyMHVHakcvR3NOSngrL3RBcVdUT1c4c0pKcnArWUdULzA3dUgyaVJQCml2aldBZXRnaWg2eGxtYmJrc2tLbTRoUUkrc296V0ZPYlF6UGU5UjFsTkxmbmNHWHh4T1dra3ZHbGJkWlZYWW4KUFNLZjZkRitIK2xaTGpTdmhSem5UbHorak0vT3UvOWJtemYwa3ZKdDZmT0k0YVI4WmVzZVhFSmZ4cEEwQmRieAphcmpQVXJQajlYVkx1NzViRlhNemVSSUVXM3pMZDlPaUhBbnhmTGxtL1dEd2MwellqSkl5VTBWL0tWaFl4N0txCm1ObEQ1enBnNGdJaCtuNTNPcFNaUHNMQ1d4d2EvNXk4dzhITE9FcFpSQi9ONm9jbXpJU1NpcVdVbHdBUkFRQUIKdERaQmNtTm9JRXhwYm5WNElFRlNUU0JDZFdsc1pDQlRlWE4wWlcwZ1BHSjFhV3hrWlhKQVlYSmphR3hwYm5WNApZWEp0TG05eVp6NkpBamNFRXdFS0FDRUZBbExiQlBNQ0d3TUZDd2tJQndNRkZRb0pDQXNGRmdJREFRQUNIZ0VDCkY0QUFDZ2tRZHhrL0ZTdmI1cWFKYkEvL1F2L3JUNStIRlFJT3pETHdNclgrQTd2OC9vanEvMjFHejNUeTgrRVIKeXZadnRnME9hWDVDWWRqN3JWTmdzcHdTTlVnZ1lQVEt5dUM3b29FWG8yU3dMT0JNR2t1OWs2d3lkem9pcFhubgpRWkNZcVZQaSttK2FqYlJ2ZzhBZTdUREF0cmF1U3hqZW92SHBDb3ZnYVdWbkJrN0ZlNjJBblNlNm5VR0xZWGdCCkw3Tk9ZVGI5eUg4VG1LQXM3dmFVTEFWM1dMdFFja2lWYWQrMVJ3UmxFcU5vdmV5ZXBqR0V0KzFGT2Z0UlBlemQKRUgzTkNaYjB0Wk9HalB4ajFPUVdZL1RFNGdmcHB2ajhsclNZMWhFUDZVM29nbjR2Njk5eXhBZ1ZWMzFJbnR0ZwpDWWNjSkpQSUtwWGdFYS81SWt0eHFwN0NpU3VCeEJxYmpzUmdqU2t6Mk5CNWZjTFdrN2RhQ3hkV1MzaktnR09RCnNoYnd0OWxOQWVPRjBUSHFtM2NJZTNKQVA3NkEvY08wZk9oMHZMMHpoMXdIbERxSVBZRzRKWHVCejlxTDlTb1UKcnVlVnh1bzJvcXk3aU5xRXAybnVQbDRRdzRYRzRYR0Y5VzByUFBHUy9pRGNDS0pOeVRvNU9QR1VYU1B1TEJRUgpDcTZKYUt6ZTlpTEJkSEhYTkZTQ2FkWmlNRFNpVlhOblRXRnROYWFnRFRFZ1V2RGJMTGd0cWx4Wm5EY0VSUkg1CjFoV01XUmFLcmdGcC9PRWEyTVJSd1AvWEJnN2haaUhqQkVVU0VWd1lUMlp6bXN5N1QwdVhYdTlMRHR1NHFuSHAKK2pOSmFZUG9SSWhubFFQbzZsQm92QTRyZ3o3a09kTVVQUVpSTVBDZ2o2QVc4Z25kemk1Mi9pMk5NUnc3NUJpTQpObEM1QWcwRVV0c0U4d0VRQU5OUWs4Y1pGWUVhcm5XaTBET05jRnBGNnJ2Nk1WM0kxc3J0SlFOaUZXbG1sblVXCjl3V2dDZGNsQUFaT29saFUwanFjTmlXUUtxbWVUL1BJRXhrNjlMMWJTcFIxdDVUaXNITGhjU25rOGFqVUVuZ0gKaUdNeXd3SVF3SmI4a0NSZ3l0VXd4UTVsN0Eya2llaDJ2RnU1ZmZudmt3bXhoUHgvdldLSFlNdnRiUGZLQy9KVQpQQUNzZUxhY1RQaERSQ2cvSFZJYnYzSkljRTZlSHRuSGxsaVRZd1BaMXdpS3FWTk01MWQ0TjdBTjJLOHpVTU9kCldCRHBubk1YODl4N25DTWdFMEY0b0Q2cHEvaHM5Vi9jVFJ3TUx0ZWhlY0xISHhhc1k1ZXV1OFlPUWpOamlNZm4KSFZ3ZGV1bEFDUE9mQXlISUZtTWY0NHM0d2JicjdtWmRHWElmNlhMZU82SXdUQ3dJSkdhMkpsNzZzL0orNWRYUApDQkgzTTFWdzlGWW1qVlB4UzN0VmVNa3lYS2NXT1RXSU5ZMkQzbXk2L2RFSTZObXJLZGMzSVVqay9LZ3BtbmVWCk1Kcmk5Z3Q3dFV5LzBVSGxOTmJyeVJqeVFMOVJubHFBVWlHcWVWSU5RZ2hwWFphdnEwWkl5YnFTTEtDazIwdG8KQjhtcWlUWE83UTRnRWVBa29RanpaY0ZxWHNtV0RVRTZiTXJqcWxudWE4SG9UYUt0YVhtcnh5S1pmcGc4dTlzMwowSkVES0EybW51ZFZ1N0hmM21TM3BWUXpIOG9NYlNkSENBdmlkVHMySjRxakVaVnlNbGIxRHlaOXVaV04yUzFJCjR2NmdSczlHY3RUTzdsc0tNZ1R4ckl3UGloYWgrd1JURlQ0Z1lCMnRhU0d1M2JGZWxiak0zOXVLRkV3L0FCRUIKQUFHSkFoOEVHQUVLQUFrRkFsTGJCUE1DR3d3QUNna1FkeGsvRlN2YjVxWlgvZy8vZXBxcnR1ZnNTK2FVY0R0YQo3NjdTTWYrUDdLQW5aaXRSQ2t4YlV2OTlqd2srRXBZbEJjandZbXB4S0hJWmZyN1l0U2VtY3RLQzhEQzNNN0xrCk9heWZuVUFLK0dKZHdRRmFXN3pZM1k2aTc5Qmo5Zk92Y21HeVVuZlFyem5EYU4xSXMxdXJqaDJCTW9DSEttbSsKYUxqVTU4ZFBhMTYyNEdweittazJ0MWVjQVlSMVA2OHdHT0JjQnhUcTVuMkdDSmJta21kd1ZEa3RCd2FuT0RKMQo3SEY1cVZ4QitEOHV4cCtTMjdoY1N2TVpLOTFNOXpUNmUyOFdjRVIwa1lqaGxOemI2aGg5MVZzRllNemJ0R1Y4CnN1OHNYdjhSM21lS1JDRHBVKzNKMzJCNk9QNEJPNHpvamdwaUZnU1JlNGtrU0l4eTUvWnF5R3VjTGpaNlEyMkMKTlBOTXVxK3hWamdmTHZVNDlWVk1HOWRwYTcyMTZNeHZWNEJBd3VWMUd4Qyt4TEo1U0pqZEVFRTloSEdPdXRnQQpuWEVxQWFyVy82RXBObTBwRjNnY3lrRFpyUFQzL05RZ0lUNjdjek42TmU2QWpQYlRsSmxhNmgzTHhLSUVrRWFBCnkvYnlhWkxvUHVSNDJCZjBrMDBJbWZ4VDRiNWFhN1UvMXdGWjlTQ1RodWI0MXRpK1JYU0x1TXVSQW00VG1ndDcKWitHT1JEQ0ppQTRobnJZVlliclZXZGNRZzRVREkrajdURVdoelB1M3JBby9rbGVKRVYzdUl2aXM2UE9mVnRBNgpPMjhaVkRYeGd3RXplc29xY20zanBVb2Ezc0lrdkxXUkRseCttNHRGcVhiL2pSSGowbEQyaVR2Y0lBQ2pBTURuCmZ4Nnk4K0Ewa0JpYUFtY1kwMVUvdXBZWGVIcz0KPUFJZ0QKLS0tLS1FTkQgUEdQIFBVQkxJQyBLRVkgQkxPQ0stLS0tLQo='
TRUST_DATA = {
    'archlinuxarm.gpg': base64.b64decode(PUBLIC_KEY_BASE64, validate=True),
    'archlinuxarm-trusted': b'68B3537F39A313B3E574D06777193F152BDBE6A6:4:\n',
    'archlinuxarm-revoked': b'',
}
TRUST_PINS = {
    'archlinuxarm.gpg': dict(bytes=3098, sha256='6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f'),
    'archlinuxarm-trusted': dict(bytes=44, sha256='f2a7250f2a2b77542f82f4219b2bae7895f27b3dcfdf350b497e2be306af776d'),
    'archlinuxarm-revoked': dict(bytes=0, sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
}
GPG_CONF = ("no-default-keyring\nkeyring pubring.gpg\ntrust-model pgp\ntrusted-key " + FINGERPRINT +
            "\nno-auto-key-retrieve\nno-auto-key-import\nauto-key-locate clear\ndisable-dirmngr\nno-autostart\n").encode()
STATUS_CAP = 65536


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve() and
         not any(p.is_symlink() for p in (path, *path.parents)), 'canonical ordinary original input')
    return path


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextlib.contextmanager
def exact_file(path, expected):
    path = ordinary(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_uid in (0, os.geteuid()) and not before.st_mode & 0o022 and
             before.st_size == expected['bytes'], 'exact ordinary held input extent/owner/mode')
        digest = hashlib.sha256(); size = 0
        while True:
            raw = os.read(fd, 1024**2)
            if not raw:
                break
            size += len(raw); need(size <= expected['bytes'], 'bounded original input')
            digest.update(raw)
        need(dict(bytes=size, sha256=digest.hexdigest()) == expected and
             identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'whole original input FD/path/hash')
        yield path
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'original input held through verification/load')
    finally:
        os.close(fd)


def fresh_file(path, raw):
    path = ordinary(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        need(stream.write(raw) == len(raw), 'whole private trust file')
        stream.flush(); os.fsync(stream.fileno())


def public_keyring():
    # The locked .gpg input is armored; GPG's legacy keyring uses binary packets.
    raw = TRUST_DATA['archlinuxarm.gpg']
    need(pin(raw) == TRUST_PINS['archlinuxarm.gpg'], 'exact upstream armored public key')
    lines = raw.decode('ascii').splitlines()
    need(lines[0] == '-----BEGIN PGP PUBLIC KEY BLOCK-----' and lines[1] == '' and
         lines[-1] == '-----END PGP PUBLIC KEY BLOCK-----' and
         lines[-2].startswith('=') and len(lines[-2]) == 5, 'complete canonical upstream public armor')
    text = ''.join(lines[2:-2]); body = base64.b64decode(text, validate=True)
    need(base64.b64encode(body).decode('ascii') == text, 'canonical upstream public key packets')
    crc = 0xB704CE
    for octet in body:
        crc ^= octet << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000: crc ^= 0x1864CFB
    need(base64.b64decode(lines[-2][1:], validate=True) == (crc & 0xFFFFFF).to_bytes(3, 'big'), 'upstream public armor CRC')
    return body


def public_packets(raw):
    # Only GnuPG's local tag12 trust/cache packets may vary; cryptographic
    # packets stay byteexact to the original source-pinned upstream public key.
    need(type(raw) is bytes and 0 < len(raw) <= 65536, 'bounded private public keyring')
    offset = 0; packets = []; local = 0
    while offset < len(raw):
        start = offset; header = raw[offset]; offset += 1
        need(header & 0x80, 'complete OpenPGP public packet header')
        if header & 0x40:
            tag = header & 0x3F; need(offset < len(raw), 'public packet length')
            length = raw[offset]; offset += 1
            if 192 <= length <= 223:
                need(offset < len(raw), 'two-octet public packet length'); length = ((length - 192) << 8) + raw[offset] + 192; offset += 1
            elif length == 255:
                need(offset + 4 <= len(raw), 'four-octet public packet length'); length = int.from_bytes(raw[offset:offset+4], 'big'); offset += 4
            else: need(length < 224, 'no partial public keyring packets')
        else:
            tag = (header >> 2) & 15; kind = header & 3
            need(kind != 3, 'no indeterminate public keyring packets'); size = (1, 2, 4)[kind]
            need(offset + size <= len(raw), 'old-format public packet length'); length = int.from_bytes(raw[offset:offset+size], 'big'); offset += size
        need(offset + length <= len(raw), 'complete bounded public keyring packet'); offset += length
        if tag == 12:
            local += 1; need(local <= 16 and length <= 4096, 'bounded GnuPG local trust/cache packets')
        else: packets.append(raw[start:offset])
    return b''.join(packets)


def trust_files():
    need(set(TRUST_DATA) == set(TRUST_PINS) and all(pin(raw) == TRUST_PINS[name]
         for name, raw in TRUST_DATA.items()), 'embedded exact original upstream public trust data')
    policy = dict(status='SOURCE_EXPLICIT_ORIGINAL_UPSTREAM_PUBLIC_TRUST_ONLY', fingerprint=FINGERPRINT,
                  upstream_keyring_commit=KEYRING_COMMIT, original_files=TRUST_PINS,
                  trust_model='pgp', trusted_key_source='EXPLICIT_UPSTREAM_MASTER_NOT_DYNAMIC_SIGNATURE_ISSUER',
                  secret_keys=False, candidate_TEST_keys=False, acceptance=False)
    return {'pubring.gpg': public_keyring(),
            'archlinuxarm.gpg': TRUST_DATA['archlinuxarm.gpg'],
            'archlinuxarm-trusted': TRUST_DATA['archlinuxarm-trusted'],
            'archlinuxarm-revoked': TRUST_DATA['archlinuxarm-revoked'],
            'gpg.conf': GPG_CONF, 'source-trust.json': encoded(policy)}


def private_dir(path):
    path = ordinary(path); info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
         stat.S_IMODE(info.st_mode) == 0o700, 'owned private0700 trust directory')
    return path


def prepare_home(work):
    work = private_dir(work); home = work / 'original-upstream-gnupg'
    need(not os.path.lexists(home), 'fresh original upstream trust home; no overwrite/retry')
    home.mkdir(mode=0o700); home.chmod(0o700)
    for name, raw in trust_files().items():
        fresh_file(home / name, raw)
    check_home(home)
    return home


def check_home(home):
    home = private_dir(home); expected = trust_files(); allowed = set(expected) | {'trustdb.gpg', 'pubring.gpg~', 'random_seed'}
    need({p.name for p in home.iterdir()} <= allowed, 'public trust cache only; no secret keys/agents/keyboxd')
    for path in home.iterdir():
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_nlink == 1 and
             info.st_uid == os.geteuid() and not info.st_mode & 0o077 and 0 <= info.st_size <= 1024**2,
             'ordinary bounded private public-trust cache only')
    for name, raw in expected.items():
        if name == 'pubring.gpg':
            path = home / name; fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                before = os.fstat(fd); need(0 < before.st_size <= 65536, 'bounded actual public keyring')
                value = os.read(fd, before.st_size + 1)
                need(len(value) == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'stable entire public keyring FD/path')
                need(public_packets(value) == public_keyring(), 'all original public cryptographic key packets byteexact')
            finally: os.close(fd)
        else:
            with exact_file(home / name, pin(raw)): pass
    return home


def current_time(now=None):
    value = time.time() if now is None else now
    need(type(value) in (int, float) and math.isfinite(value) and
         SIGNATURE_CREATED <= value <= 2**53, 'current clock must follow original signature; PID1 trusted-current handoff required')
    return value


def guest_clock(selection):
    clock = selection.get('trusted_clock')
    fields = {'schema', 'status', 'source_sha', 'ref', 'run_id', 'nonce', 'native_epoch_ns',
              'native_monotonic_ns', 'guest_before_ns', 'guest_after_ns', 'guest_monotonic_ns', 'clock_set'}
    need(type(clock) is dict and set(clock) == fields and type(clock['schema']) is int and
         clock['schema'] == 1 and clock['status'] == 'PASS_GUEST_REALTIME_HANDOFF' and
         clock['source_sha'] == selection.get('source_sha') and clock['nonce'] == selection.get('nonce') and
         type(clock['ref']) is str and re.fullmatch('codex/[a-z0-9-]+', clock['ref']) and type(clock['run_id']) is int and
         0 < clock['run_id'] < 2**63 and type(clock['clock_set']) is bool,
         'exact PID1-established original-source current-time receipt')
    for name in ('native_epoch_ns', 'native_monotonic_ns', 'guest_before_ns', 'guest_after_ns', 'guest_monotonic_ns'):
        need(type(clock[name]) is int and 0 <= clock[name] < 2**64, 'typed bounded trusted-clock nanoseconds')
    now = time.time_ns()
    need(clock['native_epoch_ns'] >= SIGNATURE_CREATED * 10**9 and
         clock['native_epoch_ns'] <= clock['guest_after_ns'] <= now and
         now - clock['guest_after_ns'] <= 10801 * 10**9 and
         clock['guest_after_ns'] - clock['native_epoch_ns'] <= 10801 * 10**9,
         'fresh inherited real current guest clock; never signature-time substitution')
    return clock


def parse_status(stdout, returncode=0, now=None):
    now = current_time(now)
    need(type(returncode) is int and returncode == 0 and type(stdout) is bytes and
         0 < len(stdout) <= STATUS_CAP, 'bounded successful original signature status')
    text = stdout.decode('utf-8', 'strict'); rows = []
    allowed = {'NEWSIG', 'KEY_CONSIDERED', 'SIG_ID', 'GOODSIG', 'VALIDSIG',
               'TRUST_FULLY', 'TRUST_ULTIMATE', 'VERIFICATION_COMPLIANCE_MODE'}
    for line in text.splitlines():
        need(line.startswith('[GNUPG:] ') and len(line.encode()) <= 4096, 'closed GPG status-fd records')
        fields = line[9:].split(); need(fields and fields[0] in allowed, 'unknown/bad/expired/revoked/time-invalid signature status')
        rows.append(fields)
    need(0 < len(rows) <= 32, 'bounded GPG status count')
    good = [row for row in rows if row[0] == 'GOODSIG']; valid = [row for row in rows if row[0] == 'VALIDSIG']
    trusted = [row for row in rows if row[0] in ('TRUST_FULLY', 'TRUST_ULTIMATE')]
    need(len(good) == len(valid) == len(trusted) == 1 and len(good[0]) >= 3 and
         good[0][1] == FINGERPRINT[-16:], 'one exact original signer and full trust')
    row = valid[0]
    need(len(row) == 11 and row[1] == row[-1] == FINGERPRINT and row[2] == '2026-05-17' and
         row[3:] == [str(SIGNATURE_CREATED), '0', '4', '0', '1', '8', '00', FINGERPRINT],
         'one exact pinned original signature creation/expiry/algorithm/fingerprint')
    need(SIGNATURE_CREATED <= now and trusted[0][1:] in (['0', 'pgp'], ['0', 'classic']), 'ordinary current-time PGP full/ultimate trust')
    for row in rows:
        if row[0] == 'KEY_CONSIDERED':
            need(len(row) == 3 and row[1] == FINGERPRINT and row[2] in ('0', '1'), 'only original upstream considered key')
        elif row[0] == 'SIG_ID':
            need(len(row) == 4 and row[2:] == ['2026-05-17', str(SIGNATURE_CREATED)], 'same original signature timestamp')
    return dict(status='PASS_REQUIRED_ORIGINAL_UPSTREAM_SIGNATURE', signer=FINGERPRINT,
                signature_created=SIGNATURE_CREATED, signature_expires=0,
                trust=trusted[0][0], status_pin=pin(stdout), acceptance=False)


def call(run, argv):
    need(callable(run), 'existing bounded source-owned runner required')
    result = run(argv, seconds=30, cap=STATUS_CAP)
    need(type(result) in (tuple, list) and len(result) == 3, 'bounded runner returns exit/stdout/stderr')
    code, out, err = result
    need(type(code) is int and type(out) is type(err) is bytes and len(out) + len(err) <= STATUS_CAP,
         'bounded complete GPG streams')
    return code, out, err


def verify_original(archive, signature, home, run=None, now=None):
    archive, signature = ordinary(archive), ordinary(signature); home = check_home(home)
    need(archive.name == PACKAGE and signature == archive.with_name(PACKAGE + '.sig'), 'exact adjacent original detached signature')
    current_time(now)
    with exact_file(archive, PACKAGE_PIN), exact_file(signature, SIGNATURE_PIN):
        argv = ['/usr/bin/gpg', '--batch', '--no-autostart', '--homedir', str(home),
                '--no-auto-key-retrieve', '--auto-key-locate', 'clear', '--disable-dirmngr',
                '--status-fd', '1', '--verify', str(signature), str(archive)]
        code, stdout, stderr = call(run, argv)
        checked = parse_status(stdout, code, now)
        check_home(home)
    return dict(checked, archive=PACKAGE_PIN, signature=SIGNATURE_PIN, stderr_pin=pin(stderr))


def bind_validation(alpm):
    function = getattr(alpm, 'alpm_pkg_get_validation', None)
    if function is None:
        function = alpm.lib.alpm_pkg_get_validation
        function.restype = ctypes.c_int; function.argtypes = (ctypes.c_void_p,)
        alpm.alpm_pkg_get_validation = function
    return function


def load_signed_original(alpm, archive, signature, home, run=None, now=None):
    archive, signature = ordinary(archive), ordinary(signature); home = check_home(home)
    with exact_file(archive, PACKAGE_PIN), exact_file(signature, SIGNATURE_PIN):
        verify_original(archive, signature, home, run=run, now=now)
        alpm.ok(alpm.alpm_option_set_gpgdir(alpm.handle, os.fsencode(home)), 'set exact private upstream gpgdir')
        loaded = ctypes.c_void_p()
        try:
            alpm.ok(alpm.alpm_pkg_load(alpm.handle, os.fsencode(archive), 1, 1, ctypes.byref(loaded)), 'required original upstream signed package load')
            need(loaded.value is not None and bind_validation(alpm)(loaded) == 8, 'actual loaded original package PGP validation bit only')
            check_home(home)
        except BaseException:
            if loaded.value is not None:
                free = alpm.lib.alpm_pkg_free
                free.restype = ctypes.c_int; free.argtypes = (ctypes.c_void_p,)
                free(loaded)
            raise
    return loaded


def wrap_alpm(api, index, selection, work, run=None, diagnostic_root=None):
    """Return an API view; only exact original-glibc loads become required-signed."""
    need(type(api) is dict and type(index) is dict and type(selection) is dict, 'explicit lifecycle input and actual selection')
    work = private_dir(work); held = index.get('held')
    need(type(held) is dict and set(held) == {'path', 'bytes', 'sha256'} and
         {k: held[k] for k in ('bytes', 'sha256')} == PACKAGE_PIN and type(held['path']) is str and
         not held['path'].startswith('/') and all(p not in ('', '.', '..') for p in held['path'].split('/')) and
         Path(held['path']).name == PACKAGE, 'exact source-bound held original input')
    archive = ordinary(Path('/inputs') / held['path']); signature = archive.with_name(PACKAGE + '.sig')
    need(type(selection.get('source_sha')) is str and re.fullmatch('[a-f0-9]{40}', selection['source_sha']) and
         type(selection.get('nonce')) is str and re.fullmatch('[a-f0-9]{32}', selection['nonce']), 'actual original source/nonce selection')
    candidates = index.get('archives')
    need(type(candidates) is dict and set(candidates) == {'a', 'b'}, 'separate source-bound unsigned candidate TEST archives')
    candidate_paths = {}
    for row in candidates.values():
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'} and
             type(row['bytes']) is int and 0 < row['bytes'] <= 256 * 1024**2 and
             type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}', row['sha256']) and
             type(row.get('path')) is str and not row['path'].startswith('/') and
             all(p not in ('', '.', '..') for p in row['path'].split('/')), 'ordinary separate candidate TEST path')
        path = ordinary(Path('/inputs') / row['path'])
        need(path != archive and path.name != PACKAGE, 'original upstream archive is never an unsigned candidate')
        candidate_paths[path] = {k: row[k] for k in ('bytes', 'sha256')}
    need(candidates['a']['bytes'] == candidates['b']['bytes'] and
         candidates['a']['sha256'] == candidates['b']['sha256'], 'held byte-identical candidate TEST pair')
    guest_clock(selection); current_time()
    existing = work / 'original-upstream-gnupg'
    home = check_home(existing) if os.path.lexists(existing) else prepare_home(work)
    original = api['roots'].Alpm
    diagnostic = dict(case=None, events=[])
    def record(event):
        case = diagnostic['case']
        if diagnostic_root is None or case not in ('pristine', 'modified'): return
        root = private_dir(Path(diagnostic_root)); path = root / (case + '-original-signature.log')
        diagnostic['events'].append(event)
        need(len(diagnostic['events']) <= 12, 'bounded original signature diagnostic event count')
        value = dict(schema=1,status='ORIGINAL_SIGNATURE_DIAGNOSTIC_DATA_ONLY',case=case,
                     source_sha=selection['source_sha'],nonce=selection['nonce'],clock=selection['trusted_clock'],
                     events=diagnostic['events'],acceptance=False,Root_acceptance=None)
        raw = encoded(value); need(len(raw) <= 65536, 'bounded original signature diagnostics')
        flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        flags |= os.O_EXCL | os.O_CREAT if not os.path.lexists(path) else 0
        fd = os.open(path, flags, 0o600)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid() and
                 stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 65536, 'owned fixed signature diagnostic file')
            os.ftruncate(fd, 0); need(os.write(fd, raw) == len(raw), 'whole signature diagnostic write'); os.fsync(fd)
        finally: os.close(fd)
    if run is None:
        def run(argv, seconds=30, cap=STATUS_CAP):
            row, out, err, error = api['runtime'].run_command(argv, work,
                dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', HOME=str(home), TMPDIR=str(work), PYTHONDONTWRITEBYTECODE='1'), seconds, cap)
            need(error is None and type(row) is dict and row.get('group_absence_verified') is True and
                 type(row.get('exit_code')) is int and type(row.get('seconds')) in (int, float) and
                 0 <= row['seconds'] < seconds, 'original supervised GPG exit/retirement/time bounds')
            def stream(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),prefix_base64=base64.b64encode(raw[:4096]).decode('ascii'),truncated=len(raw)>4096)
            record(dict(phase='BOUNDED_OFFLINE_GPG_VERIFY',exit=row['exit_code'],group_absence_verified=True,stdout=stream(out),stderr=stream(err)))
            return row['exit_code'], out, err

    class SignedOriginal:
        def __init__(self, instance):
            object.__setattr__(self, '_instance', instance)
        def __getattr__(self, name):
            return getattr(self._instance, name)
        def __setattr__(self, name, value):
            setattr(self._instance, name, value)
        def alpm_pkg_load(self, handle, path, full, level, pointer):
            name = Path(os.fsdecode(path))
            if name != archive:
                need(name in candidate_paths and handle == self._instance.handle and type(full) is int and full == 1 and type(level) is int and level == 0,
                     'only exact separate unsigned candidate TEST policy remains unchanged')
                with exact_file(name, candidate_paths[name]):
                    return self._instance.alpm_pkg_load(handle, path, full, level, pointer)
            need(handle == self._instance.handle and type(full) is int and full == 1 and type(level) is int and level == 0, 'exact existing original load call before signed specialization')
            guest_clock(selection)
            try: loaded = load_signed_original(self._instance, archive, signature, home, run=run)
            except BaseException as error:
                record(dict(phase='SIGNED_ORIGINAL_LOAD_REFUSED',error_type=type(error).__name__,error=str(error)[:512]));raise
            record(dict(phase='SIGNED_ORIGINAL_LOAD_PGP_VALIDATION',required_siglevel=1,actual_validation=8))
            ctypes.cast(pointer, ctypes.POINTER(ctypes.c_void_p))[0] = loaded
            return 0

    def factory(*args, **kwargs):
        root = Path(args[0]) if args else Path(kwargs.get('root', '/'))
        if root in (Path('/work/pristine/root'), Path('/work/modified/root')):
            case = root.parent.name
            if diagnostic['case'] != case: diagnostic.update(case=case,events=[])
        return SignedOriginal(original(*args, **kwargs))

    roots = types.SimpleNamespace(**dict(vars(api['roots']), Alpm=factory))
    return dict(api, roots=roots)
