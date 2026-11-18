#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Build the unissued Perl serial and journal successor from exact Source339."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
LOCK = 'source.lock.json'
SOURCE339 = dict(bytes=3512147, files=339, lock=dict(
    bytes=60210, sha256='7beb4deb63cbd03b34738b41463380b388e67c2a8015b81f7124866e80b17b13'))
CHANGED = {'actor.py', 'protocol.py', 'test_controls.py'}


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


codec = load(HERE.parent / 'arm16k_perl_observed_hold_successor_vm' / 'constructor.py')


def fresh(path):
    path = codec.ordinary(path)
    codec.need(path.parent.is_dir() and not path.exists(), 'fresh output with an existing parent')
    return path


def local_git(*args):
    output = subprocess.check_output(
        ['/usr/bin/git', '-c', 'core.packedGitWindowSize=16m', '-c', 'core.packedGitLimit=64m',
         '-C', str(ROOT), *args], stdin=subprocess.DEVNULL, timeout=10,
        env=dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL=''))
    codec.need(len(output) <= codec.CAP, 'bounded local Git DATA')
    return output


def tracked_predecessor(work):
    """Rebuild the exact public Source339 using the tracked reconstruction."""
    check = load(ROOT / 'scripts' / 'ci' / 'perl-observed-hold-source339' / 'check.py')
    codec.need(check.DEPENDENCIES['sources']['339'] == SOURCE339, 'exact tracked Source339 tuple')
    check.git = local_git
    work = fresh(work)
    work.mkdir(mode=0o700)
    return check.build(work, check.original_families(work))[-1]


def replace(raw, change):
    codec.need(codec.pin(raw) == change['before'], 'exact changed leaf preimage')
    for edit in change['replace']:
        before, after = (''.join(edit[key]).encode() for key in ('before', 'after'))
        codec.need(before and raw.count(before) == 1, 'unique exact delta preimage')
        raw = raw.replace(before, after, 1)
    codec.need(codec.pin(raw) == change['after'], 'exact changed leaf output')
    return raw


def construct(predecessor, output):
    predecessor, output = codec.ordinary(predecessor), fresh(output)
    codec.need(not output.is_relative_to(predecessor), 'output outside the predecessor')
    codec.need(codec.pin(codec.read(predecessor / LOCK)[0]) == SOURCE339['lock'],
               'exact public Source339 lock')
    files = codec.snapshot(predecessor)
    lock = codec.closed(files, SOURCE339['lock'])
    codec.need(len(files) == SOURCE339['files'] and
               sum(len(raw) for raw, _ in files.values()) == SOURCE339['bytes'],
               'exact physical Source339 tuple')
    delta = codec.decode(codec.read(HERE / 'source-delta.json')[0])
    codec.need(delta['kind'] == 'PERL_ARM16K_SERIAL_JOURNAL_SOURCE_DELTA_V1' and
               delta['changes'].keys() == CHANGED, 'exact serial and journal delta scope')
    del files[LOCK]
    for name, change in delta['changes'].items():
        before, mode = files[name]
        body = replace(before, change)
        compile(body, name, 'exec')
        files[name] = body, mode
    lock['files'] = codec.rows(files)
    files[LOCK] = codec.canonical(lock), 0o644
    expected = delta['successor_lock']
    codec.closed(files, expected)
    codec.need(sum(len(raw) for raw, _ in files.values()) <= codec.CAP,
               'successor fits the existing Source cap')

    output.mkdir(mode=0o700)
    for name, (body, mode) in files.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(body)
        target.chmod(mode)
    codec.need(codec.snapshot(output) == files, 'exact generated Source bytes and modes')
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--predecessor', type=Path, help='reuse an already reconstructed exact Source339')
    args = parser.parse_args()
    try:
        output = fresh(args.output.absolute())
        if args.predecessor is None:
            with tempfile.TemporaryDirectory(prefix='perl-serial-journal-') as temporary:
                result = construct(tracked_predecessor(Path(temporary) / 'tracked'), output)
        else:
            result = construct(args.predecessor.absolute(), output)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(2, f'Perl source construction refused: {error}\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
