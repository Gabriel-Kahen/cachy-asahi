#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage the pinned installed-Check dependencies and public ALARM keyring."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

BASE_URL = 'https://raw.githubusercontent.com/Gabriel-Kahen/cachy-asahi/'
RUNTIME_CARRIER = '405761af52cdfa92b97bbf5b0519f32230d9a254'
XDG_CARRIER = '4659076d3a1d3e5cf87c185a3ff383fbc38e734d'
KEYRING = 'archlinuxarm.gpg'
KEYRING_PIN = (3098, '6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f')
# Exact pins from the historical installed Check lock at 480053c0.
PACKAGES = (
    ('archlinux-contrib-20261009-1-any.pkg.tar.xz', 24792,
     '0cda9e6618956615a9065265300af78d1c4b5693bbfe3f6aab7f58b8aa0eeca3',
     '747683dd22f7264d672919be36e1fa3bc433d8e980d2202927c8b1ec5ad51ff8'),
    ('htmlq-0.4.0-3-aarch64.pkg.tar.xz', 609268,
     '325ab19a2414dc47d118a48dfce4dee082c65f058afb994ffac2cbc1498055f8',
     '0d0832b6f1b97de38aa5ae79b15bcffd0d7ece81fb4dd11d245965a4408a1c19'),
    ('pacman-contrib-1.13.1-1-aarch64.pkg.tar.xz', 49604,
     '7f89d02bae727950f543ec969145212b93abea947675de27280c6978cfe9b946',
     '7437894b8dedcd8b3bc1fdeee787cf6b49273292c4dbd2fd17f8f51cc1444789'),
    ('pyalpm-0.12.0-1-aarch64.pkg.tar.xz', 53640,
     '1fba3d5b99aba62d4e7b85481e19a993863995f44b20a6a5bf2e30b37be845f5',
     'c7ca01f7524cbc4e08d81d0f69bcb523379bd367c4548486b62a0a65cf53aa6e'),
    ('xdg-utils-1.2.1-2-any.pkg.tar.xz', 60512,
     'afd760ce97e18f354c5893038327c70b72053c23b41e609c5351c5c22fc84cd8',
     'f91b68e6c87f340bb7429ed581c5cad541bcbf9000789bbeeb73f7782cf96990'),
)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def runtime_files():
    for name, size, digest, signature in PACKAGES:
        xdg = name.startswith('xdg-utils-')
        carrier = XDG_CARRIER if xdg else RUNTIME_CARRIER
        base = BASE_URL + carrier + '/'
        yield name, base + 'packages/' + name, (size, digest)
        folder = 'packages/' if xdg else 'upstream-signatures/'
        yield name + '.sig', base + folder + name + '.sig', (566, signature)


def checked_body(stream, pin):
    size, digest = pin
    body = stream.read(size + 1)
    need(len(body) == size and hashlib.sha256(body).hexdigest() == digest, 'runtime-input-pin')
    return body


def public_keyring(path):
    need(path.name == KEYRING and path.is_absolute() and path.resolve(strict=True) == path,
         'runtime-keyring-path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
             and before.st_size == KEYRING_PIN[0], 'runtime-keyring-file')
        body = checked_body(stream, KEYRING_PIN)
        after = os.fstat(stream.fileno())
        identity = lambda info: (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
        need(identity(before) == identity(after) == identity(path.lstat()), 'runtime-keyring-stability')
    return body


def download(opener, url, pin, deadline):
    remaining = deadline - time.monotonic()
    need(remaining > 0, 'runtime-input-deadline')
    try:
        with opener.open(url, timeout=min(8, remaining)) as response:
            need(response.geturl() == url and response.status == 200, 'runtime-input-transport')
            body = checked_body(response, pin)
    except HTTPError as error:
        error.close()
        raise
    need(time.monotonic() < deadline, 'runtime-input-deadline')
    return body


def stage(output, keyring):
    parent = output.parent
    info = parent.lstat()
    uid = os.getuid()
    need(output.is_absolute() and parent.resolve(strict=True) == parent
         and stat.S_ISDIR(info.st_mode) and info.st_uid == uid == os.geteuid() > 0
         and stat.S_IMODE(info.st_mode) == 0o700 and not os.path.lexists(output),
         'runtime-output-path')
    files = {KEYRING: public_keyring(keyring)}
    # Fixed public URLs, without a proxy, credentials, or redirects.
    opener = build_opener(ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + 40
    for name, url, pin in runtime_files():
        files[name] = download(opener, url, pin, deadline)
    with tempfile.TemporaryDirectory(prefix='.runtime-intake-', dir=parent) as scratch:
        staging = Path(scratch) / 'inputs'
        staging.mkdir(mode=0o700)
        for name, body in files.items():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            with os.fdopen(os.open(staging / name, flags, 0o600), 'wb') as stream:
                stream.write(body)
        need(not os.path.lexists(output), 'runtime-output-path')
        staging.rename(output)
    return len(files), sum(map(len, files.values()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--alarm-keyring', type=Path, required=True)
    args = parser.parse_args()
    try:
        count, size = stage(args.output, args.alarm_keyring)
    except (OSError, ValueError):
        print(json.dumps({'runtime_inputs': 'FAIL'}))
        return 1
    print(json.dumps({'runtime_inputs': 'PASS', 'files': count, 'bytes': size}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
