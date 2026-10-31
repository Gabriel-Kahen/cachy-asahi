#!/usr/bin/env python3
"""Retrieve twelve fixed project-source objects; no build/install/target execution."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import signal
import stat

HERE = Path(__file__).resolve().parent
SOURCE = 'b83c0f539034f10112a2d1e9743810344f13bb9d'
INPUTS_SHA256 = '049c8a2f2146c9eb12666879947b42b902a51978df867d08459f2c120fe55ec2'
NATIVE_SHA256 = '8e71ba83e7d5037c6f7772401ec3b872684ccfa8472d855d8d6d3052cb1f41ba'
CHECKS_SHA256 = 'e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8'
README = f'''Fixed local project-source handoff; consult report.json for this invocation.
Project Source: https://github.com/Gabriel-Kahen/cachy-asahi/tree/{SOURCE}
Build entry: https://github.com/Gabriel-Kahen/cachy-asahi/blob/{SOURCE}/scripts/build/container-entry.sh
Audio caller: https://github.com/Gabriel-Kahen/cachy-asahi/blob/{SOURCE}/scripts/ci/asahi-audio-rust/run.py
Actual: https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38801968699
Filename/path aliases and object pins are in the local source-inputs.json.
No build/install/extraction/target execution or public hosting is performed.
Compiler recipe/source correspondence and complete runtime/source scope remain unresolved.
wmidi3.1.0 uses separately added2023 license text; explicit retrospective association remains limited.
nalgebra-macros0.2.2 retains a published-manifest dev-dependency difference and absent VCS metadata.
Local verified retrieval does not establish durable public availability, legal sufficiency or release acceptance.
'''


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inputs():
    path = HERE / 'source-inputs.json'
    need(path.is_file() and not path.is_symlink() and path.stat().st_size < 16384,
         'regular bounded policy required')
    need(sha(path) == INPUTS_SHA256, 'source policy differs')
    policy = json.loads(path.read_bytes()); rows = policy['objects']
    need(policy['source'] == SOURCE and policy['actual_run'] == '38801968699'
         and len(rows) == 12 and policy['total_bytes'] == 6193014, 'fixed source set differs')
    names = [row['filename'] for row in rows]
    need(len(set(names)) == 12 and sum(row['size'] for row in rows) == 6193014,
         'duplicate or oversized source set')
    prefix = 'https://raw.githubusercontent.com/Gabriel-Kahen/cachy-asahi/' + SOURCE + '/'
    for row in rows:
        path = PurePosixPath(row['repository_path'])
        need(not path.is_absolute() and '..' not in path.parts and str(path) == row['repository_path']
             and row['url'] == prefix + str(path), 'immutable source URL differs')
    return policy


def native():
    path = HERE.parent / 'native_arm.py'
    checks = HERE.parents[1] / 'checks/package_checks.py'
    need(sha(path) == NATIVE_SHA256 and sha(checks) == CHECKS_SHA256, 'source downloader API differs')
    spec = importlib.util.spec_from_file_location('fixed_audio_source_native', path)
    api = importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
    return api  # Only api.fetch is called; none of its runner/build/probe modes.


def private(path):
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink destination forbidden')
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
         and stat.S_IMODE(info.st_mode) == 0o700, 'owned0700 directory required')


def save(output, report):
    path = output / 'report.json'; partial = output / '.report.partial'
    with partial.open('x') as stream:
        json.dump(report, stream, sort_keys=True, indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())
    partial.replace(path)


def retrieve(api, policy, output):
    output = output.absolute()
    need(not any(p.is_symlink() for p in (output, *output.parents)), 'symlink destination forbidden')
    if not output.exists():
        output.mkdir(mode=0o700)
    private(output)
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        need({p.name for p in output.iterdir()} <= {'cache', 'report.json', 'README.txt', 'source-inputs.json'},
             'unexpected handoff entry preserved')
        for name in ('report.json', 'README.txt', 'source-inputs.json'):
            path = output / name
            if path.exists() or path.is_symlink():
                info = path.lstat()
                need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                     and info.st_nlink == 1 and not info.st_mode & 0o077, 'unsafe handoff file preserved')
        cache = output / 'cache'
        if not cache.exists() and not cache.is_symlink():
            cache.mkdir(mode=0o700)
        private(cache)
        names = {api.input_name(row['filename']) for row in policy['objects']}
        need(len(names) == len(policy['objects']), 'unique filenames required')
        need({p.name for p in cache.iterdir()} <= names, 'unexpected cache entry preserved')
        report = dict(status='FAIL', scope='FIXED_LOCAL_PROJECT_SOURCES', source=policy['source'],
                      actual_run=policy['actual_run'], policy_sha256=INPUTS_SHA256,
                      downloader_sha256=NATIVE_SHA256, checks_sha256=CHECKS_SHA256,
                      caller_sha256=sha(Path(__file__)), expected_objects=len(policy['objects']),
                      expected_bytes=policy['total_bytes'], build_install_execution='NOT_RUN',
                      public_hosting='NOT_RUN', compiler_correspondence='NOT_ESTABLISHED',
                      complete_source_scope='NOT_ESTABLISHED', objects=[])
        save(output, report)
        (output / 'README.txt').write_text(README)
        (output / 'source-inputs.json').write_text(json.dumps(policy, sort_keys=True, indent=2) + '\n')
        try:
            for row in policy['objects']:
                target = cache / row['filename']
                record = dict(filename=row['filename'], status='FAIL', expected_bytes=row['size'],
                              expected_sha256=row['sha256'])
                report['objects'].append(record); save(output, report)
                if target.exists() or target.is_symlink():
                    info = target.lstat()
                    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                         and info.st_nlink == 1 and not info.st_mode & 0o077, 'unsafe cached file preserved')
                origin = 'verified_cache' if target.exists() else 'download'
                api.fetch(row, cache)
                record.update(status='VERIFIED', origin=origin); save(output, report)
            # Verify the complete set again before reporting this handoff complete.
            need(all((cache / row['filename']).stat().st_size == row['size']
                     and sha(cache / row['filename']) == row['sha256'] for row in policy['objects']),
                 'final source set differs')
            report['status'] = 'PASS_LOCAL_SOURCE_HANDOFF'
        except (OSError, ValueError, KeyError, TypeError, KeyboardInterrupt) as error:
            report['error_kind'] = type(error).__name__
        finally:
            save(output, report)
        return report
    finally:
        os.close(fd)


def deadline(signum, frame):
    raise TimeoutError('source handoff budget expired')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); os.umask(0o077)
    previous = signal.signal(signal.SIGALRM, deadline); signal.alarm(900)
    try:
        report = retrieve(native(), inputs(), args.output)
        print(json.dumps(dict(status=report['status'], verified=sum(
            row['status'] == 'VERIFIED' for row in report['objects'])), sort_keys=True))
        return int(report['status'] != 'PASS_LOCAL_SOURCE_HANDOFF')
    except (OSError, ValueError, KeyError, TypeError, KeyboardInterrupt) as error:
        print(json.dumps(dict(status='FAIL', error_kind=type(error).__name__), sort_keys=True))
        return 1
    finally:
        signal.alarm(0); signal.signal(signal.SIGALRM, previous)


if __name__ == '__main__':
    raise SystemExit(main())
