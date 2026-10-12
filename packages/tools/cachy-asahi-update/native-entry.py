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
    helper = module('updater_entry_diagnostic', Path('/inputs/recipe/worker-diagnostic.py'))
    diagnostic = helper.Recorder(bindings=helper.binding_values(Path(__file__)))
    success = False
    try:
        with diagnostic.step('entry-worker-import'):
            worker = module('updater_worker_entry', Path('/inputs/recipe/worker-metadata.py'))
            worker.set_diagnostic(diagnostic)
        with diagnostic.step('entry-observe'):
            facts = worker.observe()
        with diagnostic.step('entry-guard'):
            worker.guard(facts)
        with diagnostic.step('entry-controller'):
            controller = worker.verify_controller(Path('/inputs/controller-input.json'),
                                                  os.environ.get('CACHY_ASAHI_CONTROLLER_SHA256'), facts)
            diagnostic.controller_validated()
        out = Path('/out')
        work = Path('/tmp/work')
        with diagnostic.step('entry-recipe-copy'):
            shutil.copytree('/inputs/recipe', work)
        home = Path('/tmp/build-home')
        with diagnostic.step('entry-home'):
            home.mkdir(mode=0o700)
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'HOME': str(home),
               'SOURCE_DATE_EPOCH': '1789753605', 'CARCH': 'aarch64',
               'CACHY_ASAHI_CONTAINER': '1', 'CACHY_ASAHI_IMAGE_ID': facts['image_id'],
               'CACHY_ASAHI_UPDATE_BUILD_NONCE': facts['nonce'],
               'CACHY_ASAHI_CONTROLLER_SHA256': os.environ['CACHY_ASAHI_CONTROLLER_SHA256']}
        with diagnostic.step('entry-builder-lock'):
            expected = Path('/expected-packages.lock').read_bytes()
        with diagnostic.step('entry-inventory'):
            inventory = worker.run(['/usr/bin/pacman', '-Q'], work, env, out, 'inventory-entry')
            inventory = b''.join(sorted(inventory.splitlines(keepends=True)))
            if inventory != expected:
                error = ValueError('installed worker package inventory differs')
                diagnostic.fail('entry-inventory', error); raise error
            (out / 'packages.lock').write_bytes(inventory)
        with diagnostic.step('entry-config-copy'):
            for name in ('makepkg.conf', 'pacman.conf'):
                shutil.copyfile('/etc/' + name, out / name)
        with diagnostic.step('entry-srcinfo'):
            generated = worker.run(['/usr/bin/makepkg', '--printsrcinfo'], work, env, out, 'srcinfo')
            (out / 'generated.SRCINFO').write_bytes(generated)
            def normalized(data):
                return [x for x in data.decode().splitlines() if x.strip() and not x.lstrip().startswith('#')]
            if normalized(generated) != normalized((work / '.SRCINFO').read_bytes()):
                error = ValueError('generated recipe metadata differs')
                diagnostic.fail('entry-srcinfo', error); raise error
        # Original source verification/build commands and success gates remain.
        try:
            with diagnostic.step('entry-verifysource'):
                worker.run(['/usr/bin/makepkg', '--verifysource', '--nodeps', '--noconfirm'], work, env, out, 'source-verification', timeout=120)
            with diagnostic.step('entry-makepkg'):
                worker.run(['/usr/bin/makepkg', '--cleanbuild', '--clean', '--force', '--log', '--nodeps', '--noconfirm'],
                           work, env, out, 'makepkg', timeout=1500)
            with diagnostic.step('entry-package'):
                packages = sorted(work.glob('*.pkg.tar.*'))
                if len(packages) != 1:
                    error = ValueError('one complete native package required')
                    diagnostic.fail('entry-package-count', error); raise error
                shutil.copyfile(packages[0], out / packages[0].name)
        finally:
            with diagnostic.step('entry-log-copy'):
                for log in work.glob('*.log'):
                    if log.is_file() and not log.is_symlink():
                        shutil.copyfile(log, out / log.name)
        with diagnostic.step('entry-receipt'):
            (out / 'entry-result.json').write_text(json.dumps({'scope': 'private native package trial',
                'controller_sha256': os.environ['CACHY_ASAHI_CONTROLLER_SHA256'], 'image_id': controller['image_id'],
                'publication': 'NOT ACCEPTED', 'hardware': 'NOT RUN'}) + '\n')
        success = True
    except BaseException as error:
        diagnostic.fail('UNKNOWN', error)
        raise
    finally:
        try:
            diagnostic.finish(success)
        except BaseException as error:
            diagnostic.fail('UNKNOWN', error)
            raise


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    main()
