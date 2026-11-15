#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Assemble exact signed inputs as DATA; never starts Docker, GPG or ALPM."""
import argparse
import importlib.util
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('perl_installed_common', HERE / 'common.py')
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)


def prepare(args):
    lock_raw = C.read(args.baseline_lock, 8 * 1024**2)
    expected = C.read(args.expected349)
    C.need(C.pin(lock_raw)['sha256'] == C.LOCK_SHA and C.pin(expected)['sha256'] == C.EXPECTED_SHA,
           'exact Frozen272 genuine349 signed bootstrap DATA required')
    C.inventory(expected)
    lock = C.decode(lock_raw)
    # The package is selected from authenticated frozen DATA, never a moving mirror.
    packages = lock.get('packages', [])
    if type(packages) is dict:
        packages = list(packages.values())
    old = [p for p in packages if p.get('name') == 'perl']
    C.need(len(old) == 1 and old[0]['filename'] == C.BASELINE and old[0]['version'] == '5.42.3-1'
           and old[0]['sha256'] == C.OLD['sha256'] and old[0]['signature_sha256'] == C.OLD_SIG['sha256'],
           'frozen baseline Perl archive/signature identity')
    originals = {C.CANDIDATE: args.candidate, C.CANDIDATE + '.sig': args.candidate_signature,
                 C.BASELINE: args.baseline, C.BASELINE + '.sig': args.baseline_signature,
                 'expected349.lock': args.expected349, 'baseline-inputs.lock.json': args.baseline_lock,
                 'trust/pubring.gpg': args.public_keyring, 'trust/trustdb.gpg': args.public_trustdb,
                 'test-public.asc': args.test_public}
    bodies = {name: C.read(path) for name, path in originals.items()}
    for name, expected_pin in ((C.CANDIDATE, C.ARCHIVE), (C.BASELINE, C.OLD), (C.BASELINE + '.sig', C.OLD_SIG)):
        C.need(C.pin(bodies[name]) == expected_pin, 'qualified exact package/signature: ' + name)
    C.need(100 < len(bodies[C.CANDIDATE + '.sig']) < 2048, 'fresh external Root TEST signature required')
    C.need(b'-----BEGIN PGP PUBLIC KEY BLOCK-----' in bodies['test-public.asc']
           and b'PRIVATE' not in bodies['test-public.asc'], 'public TEST certificate only')
    archive = C.load('archive.py')
    for label, path in [('candidate', args.candidate), ('baseline', args.baseline)]:
        rows = archive.read_rows(Path(path))
        if label == 'candidate':
            C.need(len(rows) == 3262 and sum('ELF_machine' in row for row in rows.values()) == 54,
                   'Root-qualified candidate 3262 nodes/54 ELF identity')
        C.need(all(not name.startswith('.') or name in ('.PKGINFO', '.BUILDINFO', '.MTREE', '.INSTALL', '.CHANGELOG')
                   for name in rows), 'ordinary known ALPM metadata only')
        if label == 'candidate':
            C.need(all(not name.startswith('.') or name in ('.PKGINFO', '.BUILDINFO', '.MTREE')
                       for name in rows), 'reviewed candidate metadata only; no install script')
            C.need(all(name.startswith('.') or name == 'usr' or name.startswith('usr/') for name in rows),
                   'reviewed candidate usr payload only')
            C.need(all(not name.startswith(('usr/local/', 'usr/share/libalpm/', 'usr/lib/systemd/'))
                       and (row['type'] == 'symlink' or not row['mode'] & 0o7022)
                       and row.get('ELF_machine', 183) == 183 for name, row in rows.items()),
                   'safe reviewed ARM candidate payload; no hook/service/operator paths')
        else:
            # Restore the authenticated old package as-is; do not guess away its interface/configs/hooks.
            review = {name: row for name, row in rows.items() if name.startswith(('.', 'etc/', 'usr/share/libalpm/'))}
            bodies['baseline-review.json'] = C.encode(dict(status='ROOT_ARCHIVE_REVIEW_REQUIRED_BEFORE_ADMISSION',
                archive=C.OLD, signature=C.OLD_SIG, metadata_config_hook_paths=review,
                note='Root reviews exact original ALPM metadata/hooks/configuration before normal trusted rollback'))
        C.need(rows['usr/bin/perl']['ELF_machine'] == 183
               and rows['usr/lib/perl5/5.42/core_perl/CORE/libperl.so']['ELF_machine'] == 183,
               'actual ARM64 interpreter/libperl DATA required')
        bodies[label + '-payload.json'] = C.encode(rows)
    for name in ('common.py', 'actor.py', 'probe.pl', 'domain.json', 'producer.py', 'read_result.py',
                 'helpers/owned_child.py'):
        bodies[name] = C.read(HERE / name)
    # Private input parents prevent other users from swapping the future bind.
    out = Path(args.output)
    C.need(out.is_absolute() and not out.exists() and str(out) == str(out.resolve())
           and not out.is_relative_to(HERE) and not HERE.is_relative_to(out), 'fresh disjoint absolute output')
    C.need(out.parent.stat().st_uid == __import__('os').getuid()
           and out.parent.stat().st_mode & 0o022 == 0, 'caller-owned private output parent')
    out.mkdir(mode=0o700)
    for name, raw in bodies.items():
        dest = out / name; dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        dest.write_bytes(raw); dest.chmod(0o444)
    manifest = dict(schema=1, operation=C.OPERATION, files={name: C.pin(raw) for name, raw in bodies.items()},
                    build_source=C.SOURCE, native_build_run='43692477455',
                    trust='ROOT_EXTERNAL_TEST_AND_BASELINE_PUBLIC_ONLY', installation='NOT_RUN')
    raw = C.encode(manifest); (out / 'source-map.json').write_bytes(raw)
    return dict(status='PREPARED_SOURCE_DATA_ONLY', source_map=C.pin(raw), output=str(out),
                selectors='UNSET_UNTIL_EXTERNAL_ROOT_ADMISSION', installation='NOT_RUN')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline-lock', 'expected349', 'candidate', 'candidate-signature', 'baseline',
                 'baseline-signature', 'public-keyring', 'public-trustdb', 'test-public', 'output'):
        p.add_argument('--' + name, required=True)
    args = p.parse_args()
    print(C.encode(prepare(args)).decode(), end='')


if __name__ == '__main__':
    main()
