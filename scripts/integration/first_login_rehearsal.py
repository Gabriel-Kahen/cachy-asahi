#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit host assembly and actual-shell rehearsal from four local recipes.

No dependency installation, source downloads, check() execution or native/M2
qualification. Build and user state are private temporary directories; diagnostic
reports survive both success and failure in the new selected output directory.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('first_login_journey', Path(__file__).with_name('first_login.py'))
journey = importlib.util.module_from_spec(spec)
spec.loader.exec_module(journey)
RECIPES = {
    'first_login': ('packages/tools/cachy-asahi-first-login', '0.1.0-2'),
    'setup': ('packages/tools/cachy-asahi-setup8', '0.3.0-1'),
    'fish': ('packages/shells/cachy-asahi-fish-config', '0.1.0-1'),
    'zsh': ('packages/shells/cachy-asahi-zsh-config', '0.1.0-1'),
}
SOURCE_DATE_EPOCH = 1794614400  # 2026-11-14 00:00 UTC, fixed for this finite recipe set.


def fields(text):
    result = {}
    for line in text.splitlines():
        key, separator, value = line.strip().partition(' = ')
        if separator:
            result.setdefault(key, []).append(value)
    return result


def prepare_sources(root, workspace, runner):
    receipts = {}
    for name, (relative, version) in RECIPES.items():
        source = root / relative
        recipe = source / 'PKGBUILD'
        journey.require(recipe.is_file() and not recipe.is_symlink(), 'Regular selected recipe required: ' + name)
        target = workspace / name
        target.mkdir(mode=0o700)
        recipe_sha256 = journey.sha(recipe)
        shutil.copyfile(recipe, target / 'PKGBUILD')
        journey.require(journey.sha(target / 'PKGBUILD') == recipe_sha256, 'Recipe changed during private copy')
        runner.cwd = target
        srcinfo = runner.run(name + '-srcinfo', ['/usr/bin/makepkg', '--printsrcinfo'])
        (target / '.SRCINFO').write_text(srcinfo)
        metadata = fields(srcinfo)
        journey.require(metadata.get('pkgname') == [journey.PACKAGE_NAMES[name]]
                        and metadata.get('arch') == ['any']
                        and metadata.get('pkgver', []) == [version.rsplit('-', 1)[0]]
                        and metadata.get('pkgrel', []) == [version.rsplit('-', 1)[1]],
                        'Selected finite recipe identity/version differs: ' + name)
        sources, pins = metadata.get('source', []), metadata.get('sha256sums', [])
        journey.require(0 < len(sources) == len(pins) <= 32, 'Complete local SHA-256 source pins required')
        receipt = {'recipe': relative + '/PKGBUILD', 'recipe_sha256': recipe_sha256,
                   'version': version, 'sources': {}, 'check_function': 'NOT RUN (--nocheck)'}
        for filename, expected in zip(sources, pins):
            journey.require(re.fullmatch(r'[A-Za-z0-9_.-]+', filename) is not None
                            and filename not in ('.', '..') and filename not in receipt['sources'],
                            'Only unique local source basenames allowed; downloads refused')
            path = source / filename
            journey.require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024 * 1024,
                            'Missing, unsafe or oversized local source: ' + name + '/' + filename)
            journey.require(re.fullmatch('[0-9a-f]{64}', expected) and journey.sha(path) == expected,
                            'Local source checksum differs: ' + name + '/' + filename)
            shutil.copyfile(path, target / filename)
            journey.require(journey.sha(target / filename) == expected, 'Source changed during private copy')
            receipt['sources'][filename] = expected
        receipts[name] = receipt
    # These existing checkers verify canonical implementation/doc/test copies in
    # addition to the recipe's retained local input pins. They do not run check().
    for name in ('first_login', 'setup'):
        checker = workspace / name / 'check-sync.py'
        runner.run(name + '-canonical-source', ['/usr/bin/python3', '-I', '-B', checker, '--root', root])
    return receipts


def configuration(scratch):
    config = scratch / 'makepkg.conf'
    values = {'SRCDEST': scratch / 'sources', 'PKGDEST': scratch / 'packages',
              'SRCPKGDEST': scratch / 'source-packages', 'LOGDEST': scratch / 'logs',
              'BUILDDIR': scratch / 'build'}
    lines = ['source /etc/makepkg.conf']
    for key, value in values.items():
        value.mkdir(mode=0o700)
        lines.append(key + '=' + shlex.quote(str(value)))
    lines += ["PKGEXT='.pkg.tar.zst'", "PACKAGER='cachy-asahi unsigned host rehearsal'",
              'BUILDENV=(!distcc !color !ccache !check !sign)',
              'COMPRESSZST=(zstd -c -T1 -q -)']
    config.write_text('\n'.join(lines) + '\n')
    config.chmod(0o600)
    return config, values['PKGDEST']


def execute(root, output):
    journey.require(os.geteuid() != 0, 'Run as the intended ordinary user without sudo')
    journey.require(root.is_absolute() and output.is_absolute(), 'Absolute checkout and new output paths required')
    for name in ('makepkg', 'fakeroot', 'bsdtar', 'fish', 'zsh', 'python3', 'git', 'zstd'):
        program = Path('/usr/bin') / name
        journey.require(program.is_file() and os.access(program, os.X_OK), 'Required actual host program unavailable: ' + str(program))
    output.mkdir(mode=0o700, exist_ok=False)
    report = {'status': 'FAIL', 'scope': 'unsigned host assembly and extracted-package shell software only',
              'source_date_epoch': SOURCE_DATE_EPOCH, 'entry_sha256': journey.sha(__file__),
              'dependency_resolution': 'NOT RUN (--nodeps)', 'recipe_check_functions': 'NOT RUN (--nocheck)',
              'package_installation': 'NOT RUN', 'native_arm': 'NOT RUN', 'hardware': 'NOT RUN',
              'graphical_login': 'NOT RUN', 'builds': {}}
    try:
        with tempfile.TemporaryDirectory(prefix='private-build-', dir=output) as temporary:
            scratch = Path(temporary)
            home, workspace = scratch / 'home', scratch / 'recipes'
            home.mkdir(mode=0o700)
            workspace.mkdir(mode=0o700)
            env = {'HOME': str(home), 'XDG_CONFIG_HOME': str(home / '.config'),
                   'XDG_CACHE_HOME': str(home / '.cache'), 'XDG_STATE_HOME': str(home / '.local/state'),
                   'GNUPGHOME': str(home / '.gnupg'), 'PATH': '/usr/bin:/bin',
                   'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'SOURCE_DATE_EPOCH': str(SOURCE_DATE_EPOCH)}
            runner = journey.Runner(output, env, scratch, timeout=60, phase='host-build')
            report['checkout_commit'] = runner.run('checkout-commit', ['/usr/bin/git', '-C', root, 'rev-parse', 'HEAD']).strip()
            runner.run('makepkg-version', ['/usr/bin/makepkg', '--version'])
            report['builds'] = prepare_sources(root, workspace, runner)
            config, packages = configuration(scratch)
            inputs = {}
            for name, receipt in report['builds'].items():
                runner.cwd = workspace / name
                runner.run(name + '-verify-local-source', ['/usr/bin/makepkg', '--config', config, '--verifysource', '--noconfirm'])
                runner.run(name + '-assemble', ['/usr/bin/makepkg', '--config', config, '--nodeps', '--nocheck', '--noconfirm', '--nosign'])
                archive = packages / (journey.PACKAGE_NAMES[name] + '-' + receipt['version'] + '-any.pkg.tar.zst')
                journey.require(archive.is_file(), 'Expected host archive missing: ' + name)
                inputs[name] = {'path': str(archive), 'sha256': journey.sha(archive)}
                receipt.update(archive_sha256=inputs[name]['sha256'], archive_bytes=archive.stat().st_size)
            selection_path = output / 'derived-inputs.json'
            journey.commands.save(selection_path, inputs)
            pinned = journey.selection(selection_path, journey.sha(selection_path))
            report['derived_inputs_sha256'] = journey.sha(selection_path)
            report['journey'] = journey.execute(pinned, output / 'journey')
        report.update(status='PASS', temporary_build_state_removed=True)
    except Exception as error:
        report['error'] = str(error) if isinstance(error, journey.Failure) else type(error).__name__
        raise
    finally:
        report['temporary_build_state_removed'] = not any(output.glob('private-build-*'))
        journey.commands.save(output / 'result.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--build-and-rehearse', action='store_true', help='explicitly assemble four local recipes and execute their temporary shell journey')
    args = parser.parse_args()
    try:
        journey.require(args.build_and_rehearse, 'Execution requires --build-and-rehearse')
        report = execute(args.root, args.output)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (journey.Failure, OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
