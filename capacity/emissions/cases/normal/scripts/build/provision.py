#!/usr/bin/env python3
"""Prepare (or explicitly execute) an offline, isolated builder image provisioning.

Supply a locally present pinned ARM base image and a complete signed package cache.
No downloads, host package operations, privileged containers, or host keyring changes.
"""
import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from build import image_pin, capture
from package_checks import digest


PACKAGE_SUFFIXES = ('.pkg.tar.zst', '.pkg.tar.xz', '.pkg.tar.gz')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-image', type=image_pin, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--checksums', type=Path, required=True, help='reviewed JSON basename -> SHA-256 map, including .sig files')
    parser.add_argument('--output', type=Path, required=True, help='new context/evidence directory')
    parser.add_argument('--execute', action='store_true', help='explicitly build isolated image; default only writes context')
    args = parser.parse_args()
    out = args.output.resolve()
    record = {'schema_version': 1, 'status': 'context-only', 'base_image': args.base_image,
              'hardware_status': 'NOT RUN'}
    created = False
    try:
        if '@sha256:' not in args.base_image:
            raise ValueError('Dockerfile base requires a repository digest, not a local image ID')
        cache = args.cache.resolve()
        expected = json.loads(args.checksums.read_text())
        if not expected or not isinstance(expected, dict):
            raise ValueError('empty/invalid checksum map')
        for name, checksum in expected.items():
            archive_name = name.removesuffix('.sig')
            if (Path(name).name != name or not re.fullmatch(r'[A-Za-z0-9@][A-Za-z0-9@._+:-]*', name)
                    or not archive_name.endswith(PACKAGE_SUFFIXES)):
                raise ValueError(f'unsafe package cache name: {name}')
            item = cache / name
            if item.is_symlink() or not item.is_file() or digest(item) != checksum:
                raise ValueError(f'cache checksum mismatch: {name}')
        packages = sorted(name for name in expected if name.endswith(PACKAGE_SUFFIXES))
        if not packages or any(name + '.sig' not in expected for name in packages):
            raise ValueError('every package requires a recorded detached signature')
        if any(name.endswith('.sig') and name.removesuffix('.sig') not in packages for name in expected):
            raise ValueError('detached signature has no matching original archive')
        if out.is_relative_to(cache):
            raise ValueError('output must be outside package cache')
        out.mkdir(parents=True, exist_ok=False)
        created = True
        deps = out / 'deps'
        deps.mkdir()
        for name in expected:
            shutil.copyfile(cache / name, deps / name)
        # A separate strict config removes dependence on a lax base-image SigLevel.
        (out / 'offline-pacman.conf').write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\n')
        package_arguments = ' '.join(shlex.quote('/tmp/deps/' + name) for name in packages)
        dockerfile = (f'FROM {args.base_image}\nUSER 0\nCOPY deps/ /tmp/deps/\n'
                      'COPY offline-pacman.conf /tmp/offline-pacman.conf\n'
                      f'RUN pacman --config /tmp/offline-pacman.conf -U --noconfirm {package_arguments} '
                      '&& rm -rf /tmp/deps /tmp/offline-pacman.conf '
                      '&& pacman -Q | LC_ALL=C sort > /builder-packages.lock\n'
                      'USER 1000:1000\nWORKDIR /tmp\n')
        (out / 'Dockerfile').write_text(dockerfile)
        record['cache_sha256'] = expected
        if {name: digest(deps / name) for name in expected} != expected:
            raise ValueError('package cache changed during snapshot')
        record['dockerfile_sha256'] = digest(out / 'Dockerfile')
        if args.execute:
            image = json.loads(capture(['docker', 'image', 'inspect', args.base_image]))[0]
            if image['Architecture'] != 'arm64' or image['Os'] != 'linux':
                raise ValueError('base image is not linux/arm64')
            record['base_image_id'] = image['Id']
            command = ['docker', 'build', '--network=none', '--pull=false', '--platform=linux/arm64',
                       '--iidfile', str(out / 'image-id'), str(out)]
            record['command'] = command
            with (out / 'provision.log').open('wb') as log:
                completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
            record['exit_code'] = completed.returncode
            if completed.returncode:
                raise ValueError('isolated provisioning failed; see provision.log')
            image_id = (out / 'image-id').read_text().strip()
            lock = capture(['docker', 'run', '--rm', '--pull=never', '--network=none',
                            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
                            '--entrypoint=/bin/cat', image_id, '/builder-packages.lock'])
            (out / 'packages.lock').write_text(lock + '\n')
            record.update({'status': 'image-provisioned', 'image_id': image_id,
                           'packages_lock_sha256': digest(out / 'packages.lock')})
        print(json.dumps(record, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        record.update({'status': 'failed', 'error': str(error)})
        print(str(error), file=sys.stderr)
        return 1
    finally:
        if created:
            (out / 'provision.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    sys.exit(main())
