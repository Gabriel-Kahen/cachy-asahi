# SPDX-License-Identifier: MIT
"""Verify the pinned retained-input packet for the native kernel job."""
import hashlib
import http.client
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import tarfile
import tempfile
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import packet
import runtime

OPT_IN = 'KERNEL_RETAINED_INPUTS'
TRANSPORT_ENV = 'KERNEL_RETAINED_TRANSPORT'
OUTCOME_ENV = 'KERNEL_RETAINED_INPUTS_OUTCOME'
URL_ENV = 'KERNEL_NATIVE_RETAINED_INPUTS_URL'
SSH_ENV = 'CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY'
SSH_REMOTE = 'git@github.com:Gabriel-Kahen/cachy-asahi-ci-inputs.git'
SSH_REF = 'refs/heads/native623-r1'
SSH_COMMIT = 'b429266444c82238783044301ceb0f8d08bbf3f6'
SSH_TREE = 'a8f1cd41e3aadeee9a25bc3b96e14c823de870aa'
BASE_REF = 'refs/heads/native623-base-r1'
BASE_COMMIT = '3ac0b845b13b9a8f1da4fc9ec90ac627a6f0da0c'
BASE_TREE = 'e3f619a2bb8a287cd0aaa7d1975d8d392cb8786e'
NATIVE349_REF = 'refs/heads/native349-r1'
NATIVE349_COMMIT = '9d9e1ab7ce694e33238ec1152bef72270d4bf91f'
NATIVE349_TREE = 'cc6298d8dbbb5b0dd522de76b7140306d83bfe7a'
NATIVE349_MANIFEST = (99724, 'd831cf894377deb4a90f6b8fd69eca08263318273a58061936f00b7ad82ba18e')
BASE_NAMES = {'at-spi2-core', 'dav1d', 'fontconfig', 'gdb', 'gdb-common', 'gnutls', 'gpgme',
              'libffi', 'libfontenc', 'libjxl', 'libxfont2'}
HOST_KEY = 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n'
DEPLOY_KEY = b'256 SHA256:6gnCZBWA+I9mccJV/YzywHoefkGrpuKBHU0dVcgqn7k'
SSH_SECONDS = 210
GIT = ['/usr/bin/git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null',
       '-c', 'core.autocrlf=false', '-c', 'core.attributesFile=/dev/null', '-c', 'maintenance.auto=false',
       '-c', 'gc.auto=0', '-c', 'pack.threads=1', '-c', 'protocol.allow=never',
       '-c', 'protocol.ssh.allow=always', '-c', 'fetch.fsckObjects=true']
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


def runner_output(env):
    temporary = Path(env['RUNNER_TEMP'])
    run, attempt = env['GITHUB_RUN_ID'], env['GITHUB_RUN_ATTEMPT']
    require(temporary.is_absolute() and temporary == temporary.resolve() and temporary.is_dir() and
            re.fullmatch('[0-9]{1,20}', run) and re.fullmatch('[0-9]{1,10}', attempt))
    return temporary / ('kernel623-retained-' + run + '-' + attempt)


def kernel_files():
    return {f'{lane}/{name}': (size, digest) for name, (lane, size, digest) in MEMBERS.items()}


def carrier_profiles():
    root = Path(__file__).resolve().parents[3]
    original = packet.load(root / 'scripts/ci/inputs.lock.json', packet.INPUTS_SHA)
    selected = packet.load(root / packet.NATIVE349_FILES, packet.HELPERS[packet.NATIVE349_FILES][0])
    require(selected['input_lock_sha256'] == packet.INPUTS_SHA and len(selected['files']) == 182)
    producer = {}
    supplemental = {}
    for row in original['packages']:
        for suffix, field in (('', ''), ('.sig', 'signature_')):
            name = row['filename'] + suffix
            pin = (row[field + 'size'], row[field + 'sha256'])
            path = 'packages/' + name
            if path in selected['files']:
                require(selected['files'][path] == dict(bytes=pin[0], sha256=pin[1], mode=0o644))
                producer[path] = pin
            if row['name'] in BASE_NAMES:
                supplemental['alarm-cache/' + name] = pin
    require(len(producer) == 182 and len(supplemental) == 22)
    return ((SSH_REF, SSH_COMMIT, SSH_TREE, kernel_files()),
            (BASE_REF, BASE_COMMIT, BASE_TREE, supplemental),
            (NATIVE349_REF, NATIVE349_COMMIT, NATIVE349_TREE, producer | {'manifest.json': NATIVE349_MANIFEST}))


def cache_path(path):
    if path == 'manifest.json':
        return None
    return 'alarm-cache/' + path.removeprefix('packages/') if path.startswith('packages/') else path


def retained_files(transport):
    require(transport in ('https', 'ssh'))
    if transport == 'https':
        return kernel_files()
    files = {}
    for _, _, _, rows in carrier_profiles():
        for path, pin in rows.items():
            target = cache_path(path)
            if target is not None:
                require(target not in files)
                files[target] = pin
    return files


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
        if destination is not None:
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


def copy_files(source, output, files, destination):
    """Verify every requested byte, copying only destinations admitted by the caller."""
    for path, (size, digest) in files.items():
        fd = os.open(source / path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as member:
            info = os.fstat(member.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == size)
            if (name := destination(path)) is None:
                copy_pinned(member, None, size, digest)
            else:
                target = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(target, 'wb') as copy:
                    copy_pinned(member, copy, size, digest)
            require(not member.read(1))


def materialize(source, output, files):
    """Copy the exact body/signature closure from an owned private tree."""
    require(source == source.resolve() and stat.S_ISDIR(source.lstat().st_mode))
    lanes = ('alarm-cache', 'extension')
    require({p.name for p in source.iterdir()} == set(lanes))
    for lane in lanes:
        directory = source / lane
        require(stat.S_ISDIR(directory.lstat().st_mode))
        require({p.relative_to(source).as_posix() for p in directory.iterdir()} ==
                {path for path in files if path.startswith(lane + '/')})
        (output / lane).mkdir(mode=0o700)
    copy_files(source, output, files, lambda path: path)


def verify_tree(raw, files):
    require(raw.endswith(b'\0'))
    expected = {path.encode(): size for path, (size, _) in files.items()}
    for row in raw[:-1].split(b'\0'):
        header, path = row.split(b'\t')
        mode, kind, oid, size = header.split()
        require(mode == b'100644' and kind == b'blob' and re.fullmatch(b'[0-9a-f]{40}', oid) and
                size == str(expected.pop(path, None)).encode())
    require(not expected)


def fetch_ssh(secret, scratch, output):
    require(64 <= len(secret) <= 32768 and secret.startswith('-----BEGIN OPENSSH PRIVATE KEY-----\n') and
            secret.rstrip().endswith('-----END OPENSSH PRIVATE KEY-----'))
    clean = {'PATH': '/usr/bin:/bin', 'HOME': str(scratch), 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
             'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0', 'GIT_SSH_VARIANT': 'ssh'}
    profiles = carrier_profiles()
    runner = runtime.Runner(SSH_SECONDS, clean, scratch)
    store = scratch / 'store.git'

    def run(argv, timeout=15):
        result = runner.run(argv, timeout=timeout, limit=65536)
        require(result.returncode == 0)
        return result.stdout

    run(GIT + ['init', '--quiet', '--bare', '--template=', '--object-format=sha1', str(store)])
    git = GIT + ['--git-dir=' + str(store)]
    with tempfile.TemporaryDirectory(prefix='credential-', dir=scratch) as location:
        key, known = Path(location) / 'identity', Path(location) / 'known_hosts'
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(secret.rstrip() + '\n')
        del secret
        known.write_text(HOST_KEY, encoding='ascii')
        fingerprint = run(['/usr/bin/ssh-keygen', '-lf', str(key), '-E', 'sha256']).split()
        require(fingerprint[:2] == DEPLOY_KEY.split())
        ssh = ['/usr/bin/ssh', '-q', '-F', '/dev/null', '-i', str(key), '-o', 'BatchMode=yes',
               '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'UserKnownHostsFile=' + str(known), '-o', 'GlobalKnownHostsFile=/dev/null',
               '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'ClearAllForwardings=yes',
               '-o', 'ConnectionAttempts=1', '-o', 'ConnectTimeout=15']
        runner.env['GIT_SSH_COMMAND'] = shlex.join(ssh)
        try:
            refs = [ref + ':' + ref for ref, _, _, _ in profiles]
            run(git + ['fetch', '--quiet', '--depth=1', '--no-tags', SSH_REMOTE, *refs], timeout=185)
        finally:
            del runner.env['GIT_SSH_COMMAND']
    for lane in ('alarm-cache', 'extension'):
        (output / lane).mkdir(mode=0o700)
    for index, (ref, commit, tree, files) in enumerate(profiles):
        require(run(git + ['rev-parse', '--verify', ref + '^{commit}']) == (commit + '\n').encode())
        head = run(git + ['cat-file', 'commit', commit]).split(b'\n\n', 1)[0].splitlines()
        require(head[0] == ('tree ' + tree).encode() and not any(line.startswith(b'parent ') for line in head))
        verify_tree(run(git + ['ls-tree', '-r', '-l', '-z', '--full-tree', tree]), files)
        checkout = scratch / ('checkout-' + str(index))
        checkout.mkdir(mode=0o700)
        # Populate only the admitted tree, with no working-tree Git config or hooks.
        worktree = git + ['--work-tree=' + str(checkout)]
        run(worktree + ['read-tree', tree])
        run(worktree + ['checkout-index', '--all', '--prefix=' + str(checkout) + '/'], timeout=35)
        copy_files(checkout, output, files, cache_path)


def main():
    try:
        key = os.environ.pop(SSH_ENV, '')
        url = os.environ.pop(URL_ENV, '')
        transport = os.environ.pop(TRANSPORT_ENV, '')
        output = runner_output(os.environ)
        require(not output.exists() and not output.is_symlink())
        os.umask(0o077)
        with runtime.cancellation_handlers(), tempfile.TemporaryDirectory(prefix='kernel623-fetch-', dir=output.parent) as location:
            scratch = Path(location)
            staged = scratch / 'inputs'
            staged.mkdir(mode=0o700)
            if transport == 'ssh' and not url:
                fetch_ssh(key, scratch, staged)
            elif transport == 'https' and not key:
                with tempfile.TemporaryFile(dir=scratch) as archive:
                    download(url, archive)
                    archive.seek(0)
                    stage(archive, staged)
            else:
                require(False)
            staged.rename(output)
        return 0
    except (Exception, runtime.Cancelled, KeyboardInterrupt):
        # Transport failures may contain protected data.
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
