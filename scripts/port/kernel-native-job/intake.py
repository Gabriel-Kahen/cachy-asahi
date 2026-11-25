# SPDX-License-Identifier: MIT
"""Verify the pinned retained-input packet for the native kernel job."""
import hashlib
import http.client
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from urllib.parse import urlsplit

OPT_IN = 'KERNEL_RETAINED_INPUTS'
URL_ENV = 'KERNEL_NATIVE_RETAINED_INPUTS_URL'
MAX_SECONDS = 180
CHUNK = 1024 * 1024
ARCHIVE_BYTES = 152391680
ARCHIVE_SHA256 = '0a3e3661754e2c194895e5ada5e075866c99b3702b9361bb3b3395ae665c81fa'

# Exact original sizes and SHA-256 pins, including detached signatures.
MEMBERS = {
    'bubblewrap-0.13.0-1-aarch64.pkg.tar.xz': ('alarm-cache', 40428,
        '4866e25c5a7c33c3ded9f221058b5f4136cdbd991f3dc77a2f7a740368c95a61'),
    'bubblewrap-0.13.0-1-aarch64.pkg.tar.xz.sig': ('alarm-cache', 566,
        'dc7ad4f478d7b196b5189e670e2d80f3e68ad28aa869b0bee697d2c5309064fa'),
    'clang-23.1.1-1-aarch64.pkg.tar.xz': ('extension', 56314652,
        'b2a2be3f213d5ef06d55eb4cecce2c3ff969b4b3dd08f4ad7be7d2c21c40b809'),
    'clang-23.1.1-1-aarch64.pkg.tar.xz.sig': ('extension', 566,
        'c7272946077b4b06aa0bbd9ef304f4065ef8a03878bc67e72af45852b7c02571'),
    'compiler-rt-23.1.1-1-aarch64.pkg.tar.xz': ('extension', 2906236,
        '7bb647047b1c7cc3e6f7f15626b03e748b177b8ea5fcab117e6641b5b6ea4093'),
    'compiler-rt-23.1.1-1-aarch64.pkg.tar.xz.sig': ('extension', 566,
        '1a92715f8a987c82c90949be0bcf60ca7a29b37d1d5b02439ae167883fc2775a'),
    'jbigkit-2.1-8-aarch64.pkg.tar.xz': ('alarm-cache', 48816,
        'ecaddb099f4a1f1bcbc1497fd0f3dc98581552b9eacaa17c5568211c38bec1db'),
    'jbigkit-2.1-8-aarch64.pkg.tar.xz.sig': ('alarm-cache', 566,
        'f00be593f9ab5855f9e450d054e6cacd319ec834ef7fc97c51bcf3be3ebfdb1f'),
    'libgit2-1:1.9.7-1-aarch64.pkg.tar.xz': ('extension', 768812,
        'cacbf38f50e09c1fa4a8a94bb5dae5d7719dc4b7a4262a8a8e94f9d001bc0842'),
    'libgit2-1:1.9.7-1-aarch64.pkg.tar.xz.sig': ('extension', 566,
        '2d4e15982858794428446596475c285c54aa1d3fc7cccb27b57d5e310153729b'),
    'libtiff-4.7.2-1-aarch64.pkg.tar.xz': ('alarm-cache', 354480,
        '02a5d2d74019b39befd6cf63d9bde95a2d16f91b4d0d56939498375e0e491ffd'),
    'libtiff-4.7.2-1-aarch64.pkg.tar.xz.sig': ('alarm-cache', 566,
        '8dae1efda531e3ac7db09512cfe0c619eaae6787cc16fdea1315588b4fc340fa'),
    'libxslt-1.1.45-2-aarch64.pkg.tar.xz': ('extension', 189964,
        'dd508d0060063ed5d833001a125d6b427c8a623d669758c44ac10cc84a92392f'),
    'libxslt-1.1.45-2-aarch64.pkg.tar.xz.sig': ('extension', 566,
        '5068bb5aa19b0b7da70cdd26619c8ee52b4ec706c059149b3a2c96b68cce9b9e'),
    'lld-23.1.1-1-aarch64.pkg.tar.xz': ('extension', 1923368,
        '8caa2b84af777a4e719b59696d181dd63e7d953b8bd17b7b2b6b56d93ea4f8bf'),
    'lld-23.1.1-1-aarch64.pkg.tar.xz.sig': ('extension', 566,
        'e92fc9f8173beef5666385d40ed15cf37345fb0147bfd92c8f6c87f31551e302'),
    'llvm-23.1.1-1-aarch64.pkg.tar.xz': ('extension', 23652748,
        '335a739a6a09c1fbb052a64c4f8d529d0809c0ad9fb7b8cfdf77dff13ee6b516'),
    'llvm-23.1.1-1-aarch64.pkg.tar.xz.sig': ('extension', 566,
        'a996c62740f07dfbfeddf257d1ebcbd8427df6cd0a8b1eec17d7da54c2b3868d'),
    'rust-1:1.99.0-1-aarch64.pkg.tar.xz': ('extension', 59807260,
        '337e715182a8f81bfd6df844793c5d1cb2697ff9e94ddb496dd850ba901c31d4'),
    'rust-1:1.99.0-1-aarch64.pkg.tar.xz.sig': ('extension', 566,
        'd7dcf2f24bca366570446a6c7228048524e1632122fa36200685a0fbe638735e'),
    'rust-src-1:1.99.0-1-aarch64.pkg.tar.xz': ('extension', 6358040,
        '0e5ebd0df1a17e71473e1f16d161bd31a3fa7e5cd8d7e0aef800d8ee51bcdd65'),
    'rust-src-1:1.99.0-1-aarch64.pkg.tar.xz.sig': ('extension', 566,
        'cdfa02ab7321560ca4736464117ece6f0a1ceafbce6172a0901b97363b85fd58'),
}


def require(condition):
    if not condition:
        raise ValueError('retained-inputs-refused')


def endpoint(value):
    require(value.startswith('https://') and 0 < len(value) <= 4096 and
            all(32 < ord(char) < 127 for char in value) and '#' not in value and '\\' not in value)
    url = urlsplit(value)
    require(url.hostname and url.username is None and
            (url.port is None or 1 <= url.port <= 65535))
    target = url.path or '/'
    if '?' in value:
        target += '?' + url.query
    return url.hostname, url.port, target


def copy_pinned(source, destination, size, digest):
    remaining = size
    hashed = hashlib.sha256()
    while remaining:
        block = source.read(min(CHUNK, remaining))
        require(block)
        hashed.update(block)
        destination.write(block)
        remaining -= len(block)
    require(hashed.hexdigest() == digest)


def download(value, destination):
    host, port, target = endpoint(value)
    connection = http.client.HTTPSConnection(host, port, timeout=20)
    try:
        # Direct, TLS-verified GET with no proxy, credentials in argv, or redirects.
        connection.request('GET', target)
        with connection.getresponse() as response:
            require(response.status == 200)
            length = response.headers.get_all('Content-Length', [])
            encoding = response.headers.get_all('Content-Encoding', [])
            framing = response.headers.get_all('Transfer-Encoding', [])
            require(length in ([], [str(ARCHIVE_BYTES)]) and encoding in ([], ['identity']) and
                    (not framing or (framing == ['chunked'] and not length)))
            copy_pinned(response, destination, ARCHIVE_BYTES, ARCHIVE_SHA256)
            require(not response.read(1))
    finally:
        connection.close()


def stage(archive, output):
    for lane in ('alarm-cache', 'extension'):
        (output / lane).mkdir(mode=0o700)
    # Compare the raw headers. Only flat, sorted, canonical regular USTAR
    # members are admitted. Extension headers and links are never interpreted.
    for name, (lane, size, digest) in sorted(MEMBERS.items()):
        expected = tarfile.TarInfo(name)
        expected.type = tarfile.REGTYPE
        expected.mode = 0o600
        expected.size = size
        require(archive.read(tarfile.BLOCKSIZE) == expected.tobuf(tarfile.USTAR_FORMAT))
        fd = os.open(output / lane / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as member:
            copy_pinned(archive, member, size, digest)
        padding = -size % tarfile.BLOCKSIZE
        require(archive.read(padding) == bytes(padding))
    end_markers = 2 * tarfile.BLOCKSIZE
    offset = archive.tell()
    footer = end_markers + (-(offset + end_markers) % tarfile.RECORDSIZE)
    require(offset + footer == ARCHIVE_BYTES)
    require(archive.read(footer) == bytes(footer) and not archive.read(1))


def main():
    try:
        value = os.environ.pop(URL_ENV, '')
        output = Path(sys.argv[1])
        # The caller owns this new mode-0700 directory and supervises our total time.
        with tempfile.TemporaryFile(dir=output) as archive:
            download(value, archive)
            archive.seek(0)
            stage(archive, output)
        return 0
    except Exception:
        # HTTP/TLS and URL parsing exceptions may carry the protected endpoint.
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
