#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Fetch explicit public DATA operands before the separate actor-fenced runner."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
URL = 'https://github.com/Gabriel-Kahen/cachy-asahi.git'


def acquire(output):
    if not output.is_absolute() or output != output.resolve() or output.exists():
        raise ValueError('fresh canonical input directory required')
    info = output.parent.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError('owned input parent without foreign writes required')
    output.mkdir(mode=0o700)
    native = json.loads((HERE / 'native-fish-inputs.lock.json').read_bytes())
    lib = json.loads((HERE / 'libgit2-inputs.lock.json').read_bytes())
    selected = dict(native['sources'], recipes=lib['recipe_checkout'])
    env = dict(PATH=os.environ.get('PATH', '/usr/bin:/bin'), LC_ALL='C', GIT_CONFIG_NOSYSTEM='1',
               GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1')
    repo = output / 'repository'
    git = ['git', '-c', 'credential.helper=', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
           '-c', 'protocol.https.allow=always', '-C', str(repo)]
    subprocess.run(['git', 'init', '--bare', str(repo)], env=env, check=True, timeout=30)
    subprocess.run(git + ['fetch', '--depth=1', '--no-tags', URL, *[v['commit'] for v in selected.values()]],
                   env=env, check=True, timeout=180)
    deny = json.loads((ROOT / 'scripts/port/arm-rust-toolchain-inputs/source-closure/history-search/licenses/redaction-plan.json').read_bytes())
    forbidden = {v['git_blob_sha1'] for v in deny['files']}
    objects = subprocess.check_output(git + ['--no-replace-objects', 'rev-list', '--objects', *[v['commit'] for v in selected.values()]], env=env, timeout=60)
    if len(forbidden) != 4 or forbidden & {row.split(b' ', 1)[0].decode() for row in objects.splitlines()}:
        raise ValueError('forbidden object in reachable input metadata; no archive may be read')
    for name, spec in selected.items():
        raw = subprocess.check_output(git + ['cat-file', 'commit', spec['commit']], env=env, timeout=30)
        (output / (name + '.commit')).write_bytes(raw)
        args = git + ['-c', 'tar.umask=0022', 'archive', '--format=tar', spec['commit']]
        if name == 'recipes': args += [v['path'] for v in spec['recipes'].values()]
        with (output / (name + '.tar')).open('xb') as stream:
            subprocess.run(args, env=env, stdout=stream, check=True, timeout=60)
    shutil.rmtree(repo)  # Only this invocation's exclusively created DATA repository.
    for spec in lib['upstream_archives'].values():
        dest = output / spec['filename']
        subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error', '--proto', '=https',
                        '--proto-redir', '=https', '--tlsv1.2', '--max-time', '90', '--max-filesize', str(8 * 1024**2),
                        '--output', str(dest), spec['url']], env=env, check=True, timeout=100)
        raw = dest.read_bytes()
        if dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) != {k: spec[k] for k in ('bytes', 'sha256')}:
            raise ValueError('whole upstream archive DATA pin differs')
    for p in output.iterdir(): p.chmod(0o644)
    print(json.dumps(dict(status='EXPLICIT_PUBLIC_DATA_ACQUIRED_NOT_EXECUTED',
                         commits={k:v['commit'] for k,v in selected.items()}, forbidden_reachable_hits=[], Root_authority=None)))


if __name__ == '__main__':
    if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
        raise ValueError('use Python -I -B')
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--output', type=Path, required=True)
    acquire(parser.parse_args().output)
