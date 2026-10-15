#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private authenticated DEVELOPMENT inputs; no package or checkpoint mutation."""
import argparse
from contextlib import contextmanager
import copy
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def inventory(c, path):
    """Descriptor-relative complete inventory, including directory identities."""
    root = c.directory(path)
    found, total = {}, 0

    def visit(fd, prefix):
        nonlocal total
        for name in sorted(os.listdir(fd)):
            relative = prefix + name
            c.relative(relative)
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            c.need(len(found) < c.MAX_FILES * 4, 'snapshot member bound exceeded')
            identity = (*c.identity(info), info.st_mode, info.st_uid, info.st_nlink)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    c.need(c.identity(os.fstat(child)) == c.identity(info), 'directory changed during inventory')
                    found[relative] = ('directory', identity)
                    visit(child, relative + '/')
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                digest, size = c.hash_member(root, relative)
                total += size
                c.need(total <= c.MAX_TOTAL, 'snapshot total byte bound exceeded')
                found[relative] = ('file', identity, digest)
            elif stat.S_ISLNK(info.st_mode):
                found[relative] = ('symlink', identity, os.readlink(name, dir_fd=fd))
            else:
                c.need(False, 'special snapshot member refused')
            c.need(c.identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == c.identity(info),
                   'member changed during inventory')

    try:
        identity = c.identity(os.fstat(root))
        visit(root, '')
        c.need(c.identity(os.fstat(root)) == identity, 'snapshot root changed during inventory')
        return identity, found
    finally:
        os.close(root)


def public_home(c, home, keyring, signer):
    home.mkdir(mode=0o700)
    (home / 'pubring.gpg').write_bytes(keyring)
    (home / 'pubring.gpg').chmod(0o400)
    (home / 'gpg.conf').write_text('no-auto-key-retrieve\nno-auto-key-import\nauto-key-locate clear\n'
                                   'disable-dirmngr\nno-autostart\nno-auto-check-trustdb\n')
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'GNUPGHOME': str(home), 'LC_ALL': 'C'}
    common = ['gpg', '--batch', '--no-tty', '--no-options', '--homedir', str(home),
              '--no-default-keyring', '--keyring', str(home / 'pubring.gpg'),
              '--no-auto-key-retrieve', '--no-auto-key-import', '--auto-key-locate', 'clear',
              '--disable-dirmngr', '--no-autostart', '--no-auto-check-trustdb']

    def run(options):
        result = subprocess.run(common + options, env=env, capture_output=True, timeout=30)
        c.need(result.returncode == 0 and len(result.stdout) + len(result.stderr) <= c.MAX_JSON,
               'public certificate inspection failed')
        return result.stdout

    packets = run(['--list-packets', str(home / 'pubring.gpg')])
    c.need(b':secret key packet:' not in packets and b':secret sub key packet:' not in packets,
           'public certificate must not contain secret key packets')
    listing = run(['--with-colons', '--list-keys']).decode().splitlines()
    primaries, primary = [], False
    for line in listing:
        fields = line.split(':')
        if fields[0] == 'pub':
            primary = True
        elif fields[0] == 'sub':
            primary = False
        elif fields[0] == 'fpr' and primary:
            primaries.append(fields[9])
            primary = False
    c.need(primaries == [signer], 'one exact public primary certificate required')
    return env


@contextmanager
def authenticated(args, workspace, settings):
    """Yield verified snapshots until exit; caller owns checkpoint/ALPM locks.

    settings is the coordinator-validated enrollment/transaction selection.
    This function requires its exact identities but authorizes no installation.
    """
    c = module('update_snapshot_client', ROOT / 'scripts/client/client.py')
    r = module('update_snapshot_release', ROOT / 'scripts/release/release.py')
    settings = copy.deepcopy(settings)
    signer = c.fingerprint(settings['signer'])
    for name in ('metadata_sha256', 'release_sha256', 'public_keyring_sha256'):
        c.need(type(settings[name]) is str and c.HEX.fullmatch(settings[name]), 'exact input digest required')
    c.need(signer == settings['signer'] and c.NAMESPACE.fullmatch(settings['namespace'])
           and c.NAME.fullmatch(settings['release_id']) and c.NAME.fullmatch(settings['repo_name']),
           'exact repository selection required')
    c.sequence(settings['minimum_sequence'])
    workspace = c.absolute(workspace)
    fd = c.directory(workspace)
    try:
        info = os.fstat(fd)
        c.need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
               'owned private workspace required')
    finally:
        os.close(fd)
    source = c.absolute(args.bundle)
    child = workspace / 'authenticated'
    child.mkdir(mode=0o700)  # Fresh ownership; never reuse a previous snapshot.
    child_identity = child.stat().st_dev, child.stat().st_ino
    try:
        bundle = child / 'bundle'
        bundle.mkdir(mode=0o700)
        original_external = {}
        for name, supplied, limit, expected in (
                ('metadata.json', args.metadata, c.MAX_JSON, settings['metadata_sha256']),
                ('metadata.json.sig', args.signature, c.MAX_SIGNATURE, None),
                ('public.gpg', args.public_keyring, c.MAX_KEYRING, settings['public_keyring_sha256'])):
            path = c.absolute(supplied)
            data = c.read_path(path, limit)
            c.need(expected is None or c.digest(data) == expected, 'externally pinned input differs')
            parent = c.directory(path.parent)
            try:
                with c.member(parent, path.name) as entry:
                    identity = c.identity(os.fstat(entry))
                c.need(c.read_member(parent, path.name, limit) == data, 'external input changed')
            finally:
                os.close(parent)
            original_external[name] = (path, limit, identity, c.digest(data))
            (child / name).write_bytes(data)
            (child / name).chmod(0o400)
        metadata = c.decode((child / 'metadata.json').read_bytes())
        c.need(metadata.get('synthetic') is True and metadata.get('release_id') == settings['release_id']
               and metadata.get('repo_name') == settings['repo_name'], 'synthetic selected release required')
        root = c.directory(source)
        try:
            raw = c.read_member(root, 'release.json')
            c.need(c.digest(raw) == settings['release_sha256'], 'selected release digest differs')
            release = c.decode(raw)
            c.need(set(release) == {'schema_version', 'release_id', 'signer', 'created_utc',
                                    'packages', 'files', 'symlinks'}, 'exact release record required')
            files = dict(release['files'])
            c.need(not {'release.json', 'release.json.sig'} & files.keys(), 'self-referential release refused')
            files.update({'release.json': settings['release_sha256'],
                          'release.json.sig': c.digest(c.read_member(root, 'release.json.sig', c.MAX_SIGNATURE))})
            links = release['symlinks']
            c.need(type(links) is dict and len(files) + len(links) <= c.MAX_FILES,
                   'bounded declared release required')
            directories = set()
            for name, digest in files.items():
                c.reference(name, digest)
                directories.update(str(p) for p in Path(name).parents if str(p) != '.')
            for name, target in links.items():
                c.relative(name)
                c.need(type(target) is str and target not in {'', '.', '..'} and '/' not in target
                       and (Path(name).parent / target).as_posix() in files and name not in files,
                       'contained declared repository alias required')
                directories.update(str(p) for p in Path(name).parents if str(p) != '.')
            original_bundle = inventory(c, source)
            members = original_bundle[1]
            c.need(set(members) == files.keys() | links.keys() | directories,
                   'bundle has missing or undeclared members')
            for name, item in members.items():
                if name in files:
                    c.need(item[0] == 'file' and item[2] == files[name], 'declared release file differs')
                elif name in links:
                    c.need(item[0] == 'symlink' and item[2] == links[name], 'declared repository alias differs')
                else:
                    c.need(item[0] == 'directory', 'declared parent is not a directory')
            for name in sorted(directories, key=lambda value: len(Path(value).parts)):
                (bundle / name).mkdir(mode=0o700)
            for name, digest in files.items():
                actual, _ = c.hash_member(root, name, snapshot=bundle / name)
                c.need(actual == digest, 'release changed during snapshot')
                (bundle / name).chmod(0o400)
            for name, target in links.items():
                (bundle / name).symlink_to(target)
        finally:
            os.close(root)
        check = argparse.Namespace(bundle=str(bundle), metadata=str(child / 'metadata.json'),
            signature=str(child / 'metadata.json.sig'), public_keyring=str(child / 'public.gpg'),
            state_dir=args.state_dir, namespace=settings['namespace'], signer=signer,
            minimum_sequence=settings['minimum_sequence'], apply=False)
        verified = c.verify(check)
        c.need(verified['metadata_sha256'] == settings['metadata_sha256']
               and verified['release_sha256'] == settings['release_sha256'], 'verified selection differs')
        home = child / 'verifier-home'
        env = public_home(c, home, (child / 'public.gpg').read_bytes(), signer)
        semantic_release, spec = r.verify_release(bundle, signer, env)
        c.need(semantic_release == release and spec.get('synthetic') is True
               and spec['repo_name'] == settings['repo_name'] and spec['release_id'] == settings['release_id'],
               'semantic release selection differs')
        expected_snapshot = inventory(c, child)
        result = dict(bundle=bundle, metadata=metadata, release=release, spec=spec,
                      keyring=child / 'public.gpg', verifier_home=home,
                      metadata_sha256=settings['metadata_sha256'], release_sha256=settings['release_sha256'])
        expected_result = copy.deepcopy(result)

        def recheck():
            c.need(inventory(c, source) == original_bundle, 'original bundle drifted')
            for path, limit, identity, digest in original_external.values():
                parent = c.directory(path.parent)
                try:
                    with c.member(parent, path.name) as entry:
                        c.need(c.identity(os.fstat(entry)) == identity, 'original input identity drifted')
                    c.need(c.digest(c.read_member(parent, path.name, limit)) == digest, 'original input bytes drifted')
                finally:
                    os.close(parent)
            c.need(inventory(c, child) == expected_snapshot, 'authenticated snapshot drifted')
            c.need({key: value for key, value in result.items() if key != 'recheck'} == expected_result,
                   'authenticated result changed')
            return True

        result['recheck'] = recheck
        recheck()
        yield result
    finally:
        # Never remove a replacement directory after ownership is lost.
        if child.exists() and not child.is_symlink():
            info = child.stat()
            if (info.st_dev, info.st_ino) == child_identity:
                shutil.rmtree(child)
