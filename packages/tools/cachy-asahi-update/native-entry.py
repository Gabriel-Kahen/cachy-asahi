#!/usr/bin/env python3
"""Readonly entry for the updater's isolated native worker; never run on host."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import sys


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    worker = module('updater_worker_entry', Path('/inputs/recipe/worker-metadata.py'))
    facts = worker.observe()
    worker.guard(facts)
    controller = worker.verify_controller(Path('/inputs/controller-input.json'),
                                          os.environ.get('CACHY_ASAHI_CONTROLLER_SHA256'), facts)
    out = Path('/out')
    work = Path('/tmp/work')
    shutil.copytree('/inputs/recipe', work)
    home = Path('/tmp/build-home')
    home.mkdir(mode=0o700)
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'HOME': str(home),
           'SOURCE_DATE_EPOCH': '1789753605', 'CARCH': 'aarch64',
           'CACHY_ASAHI_CONTAINER': '1', 'CACHY_ASAHI_IMAGE_ID': facts['image_id'],
           'CACHY_ASAHI_UPDATE_BUILD_NONCE': facts['nonce'],
           'CACHY_ASAHI_CONTROLLER_SHA256': os.environ['CACHY_ASAHI_CONTROLLER_SHA256']}
    expected = Path('/expected-packages.lock').read_bytes()
    inventory = worker.run(['/usr/bin/pacman', '-Q'], work, env, out, 'inventory-entry')
    inventory = b''.join(sorted(inventory.splitlines(keepends=True)))
    if inventory != expected:
        raise ValueError('installed worker package inventory differs')
    (out / 'packages.lock').write_bytes(inventory)
    for name in ('makepkg.conf', 'pacman.conf'):
        shutil.copyfile('/etc/' + name, out / name)
    generated = worker.run(['/usr/bin/makepkg', '--printsrcinfo'], work, env, out, 'srcinfo')
    (out / 'generated.SRCINFO').write_bytes(generated)
    def normalized(data):
        return [x for x in data.decode().splitlines() if x.strip() and not x.lstrip().startswith('#')]
    if normalized(generated) != normalized((work / '.SRCINFO').read_bytes()):
        raise ValueError('generated recipe metadata differs')
    # Compile-only trial: runtime transaction remains unresolved. The authenticated
    # image fixes all build/check roots; --nodeps never authorizes target installation.
    try:
        worker.run(['/usr/bin/makepkg', '--verifysource', '--nodeps', '--noconfirm'], work, env, out, 'source-verification', timeout=120)
        worker.run(['/usr/bin/makepkg', '--cleanbuild', '--clean', '--force', '--log', '--nodeps', '--noconfirm'],
                   work, env, out, 'makepkg', timeout=1500)
        packages = sorted(work.glob('*.pkg.tar.*'))
        if len(packages) != 1:
            raise ValueError('one complete native package required')
        shutil.copyfile(packages[0], out / packages[0].name)
    finally:
        for log in work.glob('*.log'):
            if log.is_file() and not log.is_symlink():
                shutil.copyfile(log, out / log.name)
    (out / 'entry-result.json').write_text(json.dumps({'scope': 'private native package trial',
        'controller_sha256': os.environ['CACHY_ASAHI_CONTROLLER_SHA256'], 'image_id': controller['image_id'],
        'publication': 'NOT ACCEPTED', 'hardware': 'NOT RUN'}) + '\n')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    main()
