#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real package staging, moved-prefix execution and exact removal inverse."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def run(recipe, srcdir, hide):
    with tempfile.TemporaryDirectory(prefix='source-tools-package-') as tmp:
        root = Path(tmp)
        stage, moved = root / 'stage', root / 'moved'
        subprocess.run(['bash', '--noprofile', '--norc', '-c',
            'set -eu; umask 022; source "$1/PKGBUILD"; srcdir=$2; pkgdir=$3; package',
            'source-tools-stage', str(recipe), str(srcdir), str(stage)], check=True, timeout=30)
        subprocess.run([sys.executable, '-I', '-B', str(srcdir / 'check_package.py'),
            '--recipe-root', str(recipe), '--stage', str(stage)], check=True, timeout=15)
        stage.rename(moved)
        cli = moved / 'usr/bin/cachy-asahi-source-tools'
        prefix = ['bwrap', '--unshare-net', '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev',
                  '--tmpfs', str(hide), '--bind', str(root), str(root), '--chdir', str(root)]
        hidden = subprocess.run(prefix + ['/usr/bin/python3', '-I', '-B', '-c',
            'import pathlib,socket,sys; assert not (pathlib.Path(sys.argv[1])/"scripts").exists(); '
            'assert [name for _, name in socket.if_nameindex()] == ["lo"]', str(hide)],
            capture_output=True, text=True, timeout=15)
        assert hidden.returncode == 0, hidden.stdout + hidden.stderr
        shutil.copytree(srcdir / 'fixtures', root / 'fixtures')
        qa = root / 'roundtrip.py'
        shutil.copyfile(srcdir / 'multi_package_roundtrip.py', qa)
        result = subprocess.run([sys.executable, '-I', '-B', str(qa), 'run', '--cli', str(cli),
            '--fixtures', str(root / 'fixtures'), '--work', str(root / 'workflow'),
            '--command-prefix', json.dumps(prefix)], capture_output=True, text=True, timeout=180)
        assert result.returncode == 0, result.stdout + result.stderr
        report = json.loads(result.stdout)
        assert not list(moved.rglob('__pycache__'))
        inventory = [path for path in moved.rglob('*') if path.is_file()]
        foreign = moved / 'usr/share/user-owned-keep'
        foreign.write_text('preserve user content\n')
        for path in inventory:
            path.unlink()
        assert foreign.read_text() == 'preserve user content\n'
        assert [path for path in moved.rglob('*') if path.is_file()] == [foreign]
        assert (root / 'workflow/first/mirror.tar').is_file()
        return dict(status='PASS', staged_payload_files=len(inventory), checkout_hidden=True,
            network_namespace='loopback-only', moved_prefix=True, workflow=report,
            removal='EXACT_FILE_INVERSE_USER_CONTENT_PRESERVED', alpm_installation='NOT_RUN', native_build='NOT_RUN')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, required=True)
    parser.add_argument('--srcdir', type=Path, required=True)
    parser.add_argument('--hide-checkout', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.recipe_root, args.srcdir, args.hide_checkout), sort_keys=True))
