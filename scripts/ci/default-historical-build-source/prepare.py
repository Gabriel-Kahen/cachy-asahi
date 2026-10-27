#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit one fixed historical default-native source view; no actors or authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys

sys.dont_write_bytecode = True
# Independent pins of ORIGINAL whole manifests, never caller-selected authority.
PROFILES = {
    'apps7-client-native': (14637, '8728d396ba5485ec506cee6e2378cd0ba67c00e68e0c7824a98fdf3c8a314846'),
    'dns-sysctl-native': (10278, 'f0385a479e85d8511c18e03a19a3bcc94c0962cb9d96758bd952b98a49de22f9'),
    'sysctl2-upgrade-native': (10067, '46ecd5f79260953d4c21db859c27d913e3ea503cd4eefbc4dcf4574ce0225284'),
    'dns2-native-upgrade': (10463, 'e492984ae1f5d7f69201f2d2e6d66bd306f7ab3fb4e40ed2f3bcbb0047913d63'),
    'ksm2-upgrade-native': (12263, 'e77e3e9d61ba0d64d0e84f987bfb1e9aee5b895b97afbfce12cfd0e3986c92af'),
    'welcome5-native-upgrade': (16113, '98a311fa4d2c7318619b397e8408cf1ec6993d83c3572af373ed909f3f15355b'),
    'desktop-file-manager-workflow': (3457, '04047b75f5932570ae135a4f1957fd7f98ace463d522959249805ae9520dec26'),
    'desktop-user-session': (3242, 'b5e4df112c8a9ade746b6a60cafa68e5a58226a1f13280d0725b9e5175a7686d'),
    'full-root-failed-update': (7738, '8f80761c299c1fb81c9ba47e6e30044037365d9119ae651a1cf5f69d2eca1012'),
    'full-root-postcommit-failure': (7778, 'bb18da3fc23ac82d5a6ab04902e3753491de88c1ed2f686d0ba3454d06617c54'),
    'full-root-upgrade-caller': (6850, 'b90fc82f0755a408e94d87ed5e1b07a3ede3fe862477cb3ee02495ba3b675ee1'),
}
CONFIGS = {'full-root-failed-update': 'lane-config.json', 'full-root-postcommit-failure': 'lane-config.json', 'full-root-upgrade-caller': 'upgrade-config.json'}
DESKTOP = frozenset(('desktop-user-session', 'desktop-file-manager-workflow'))
# This unchanged test also reads its registered workflow, excluded from its own manifest.
EXTRA = {'apps7-client-native': {'.github/workflows/native-arm-apps7-client.yml':
    (7321, 'f6f4f474c1db44a6a3eb8768afb3daa7d7ba80bff276c97e25bdd83d934722ff')}}
# Fixed supplemental original test/runtime bytes omitted from the desktop SHA maps.
EXTRA.update({'desktop-file-manager-workflow': {'scripts/ci/desktop-file-manager-workflow/contract.py': (2866,
                                                                                            'e08c88b821b20ba6eb9c8c544bc03f49a153473c914a4c8eee1dc92b863a6a23'),
                                   'scripts/ci/desktop-file-manager-workflow/file_manager.py': (5170,
                                                                                                'ce310e06cf836dbe597154367766030a1608737fe3c0ea92da09a211483f9300'),
                                   'scripts/ci/desktop-file-manager-workflow/open_probe.py': (1186,
                                                                                              '4c223e4c6eed4e7a48a5ee93142c6443692621a4cb2e2409d7f0dd77268de810'),
                                   'scripts/ci/desktop-file-manager-workflow/package-inputs.json': (236345,
                                                                                                    'd8bcff6a5e84ea1241e216b5abd52dbc33054ac5d66ec88bece5634ff760240d'),
                                   'scripts/ci/desktop-file-manager-workflow/session.py': (10716,
                                                                                           '6c5e411ef481a7a690a5b102ab8bc2ad03d7b523f603798b9782888d88178712'),
                                   'scripts/ci/desktop-file-manager-workflow/test_workflow.py': (9843,
                                                                                                 '775b7fb6e74e6c78b5f3e250d05276ba8280fb87ac5d6d5cc82827d8aa11a35f')},
 'desktop-user-session': {'scripts/ci/desktop-user-session/managed_contract.py': (3790,
                                                                                  '0f6c7566afd2ffb4e283b7f2edd36433e13cca873c60e5d68a46afbd3c2d4218'),
                          'scripts/ci/desktop-user-session/managed_guest.py': (676,
                                                                               '647c73b08a332aae31fd397b64f5cb13d4690617c12bed79d4f8311db3d31e8c'),
                          'scripts/ci/desktop-user-session/managed_session.py': (11255,
                                                                                 '2187c47b3f5877d8585c66c806b0c5dd17efc38cee414c46bc746157f3c4d991'),
                          'scripts/ci/desktop-user-session/prepare.py': (6300,
                                                                         'a70885622a36fe1ba764ea7d0846933b639ef04dc3c532598fb92ceb73ffe00b'),
                          'scripts/ci/desktop-user-session/test_managed.py': (22349,
                                                                              '92ea44d99ac75588b37a4429cba2583ae28f3dd58b5e155580feb27119788dbd')}})
EXTRA['full-root-upgrade-caller'] = {'scripts/ci/full-root-upgrade-caller/run.py': (27803, 'b9840c79ffc6c45070ac12b80d469fb46c26059df63e121801d6ab223035e303')}
SHARED = 'scripts/ci/historical-inventory-source/shared-build-v1'
BUILD = {
    'scripts/build/build.py': (11299, 'e520b37e5dfc285914203cfab99daecc80543505fef7ded6704b3fb06f001d45'),
    'scripts/build/compare.py': (5820, '4198864c264642b196a090a67b36185e5c194e38edc4cb928d08eb65b9f710cd'),
    'scripts/build/container-entry.sh': (1787, '89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24'),
}
MAX_FILE, MAX_TOTAL = 8 * 1024**2, 32 * 1024**2


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def row(value):
    return dict(zip(('bytes', 'sha256'), value))


def matches(actual, expected):
    return actual == expected if type(expected) is dict else actual['sha256'] == expected


def ordinary(path, directory=False):
    path = Path(path).absolute()
    need(path.anchor == '/' and '..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)),
         'ordinary single-root unaliased path required')
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
         'ordinary directory or single-link file required')
    return path, info


def identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                                              'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(path):
    path, before = ordinary(path)
    need(0 < before.st_size <= MAX_FILE and not before.st_mode & 0o022, 'bounded non-writable source required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        need(identity(os.fstat(fd)) == identity(before), 'source changed before read')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(before.st_size + 1)
        need(len(raw) == before.st_size and identity(os.fstat(fd)) == identity(before) == identity(path.lstat()),
             'source changed during read')
        return raw, stat.S_IMODE(before.st_mode)
    finally:
        os.close(fd)


def relative(name):
    need(type(name) is str and name and '\\' not in name and '\0' not in name, 'relative source path required')
    path = PurePosixPath(name)
    need(not path.is_absolute() and name == path.as_posix() and all(p not in ('.', '..') for p in path.parts),
         'canonical contained source path required')
    return path


def profile_path(profile):
    leaf = CONFIGS.get(profile, 'source-pins.json' if profile in DESKTOP else 'source-manifest.json')
    return 'scripts/ci/' + profile + '/' + leaf


def source_map(profile, value):
    return value['code_pins'] if profile in CONFIGS else value if profile in DESKTOP else value['files']


def prepare(source, output, profile):
    need(not sys.flags.optimize, 'optimized Python would disable original assertion guards')
    need(type(profile) is str and profile in PROFILES, 'unknown fixed default-native profile')
    source, _ = ordinary(source, True)
    output = Path(output).absolute()
    parent, info = ordinary(output.parent, True)
    need('..' not in output.parts and not os.path.lexists(output) and info.st_uid == os.getuid()
         and not info.st_mode & 0o022 and not output.is_relative_to(source) and not source.is_relative_to(output),
         'fresh disjoint source view in caller-owned parent required')
    manifest_path = profile_path(profile)
    raw_manifest, manifest_mode = read(source / manifest_path)
    need(pin(raw_manifest) == row(PROFILES[profile]), 'fixed original whole manifest differs')
    manifest = json.loads(raw_manifest)
    files = source_map(profile, manifest)
    need(type(files) is dict and 0 < len(files) <= 128 and manifest_path not in files,
         'finite original non-self-referential source map required')
    if profile not in DESKTOP:
        need(type(manifest['schema_version']) is int and manifest['schema_version'] == 1,
             'original manifest schema differs')
    roles = (set(BUILD) - {'scripts/build/container-entry.sh'} if profile in CONFIGS else
             set(BUILD) - {'scripts/build/compare.py'} if profile in DESKTOP else set(BUILD))
    need(files.keys() & BUILD.keys() == roles and all(matches(row(BUILD[name]), files[name]) for name in roles),
         'original declared helper roles differ')
    extras = {name: row(want) for name, want in EXTRA.get(profile, {}).items()}
    need(not files.keys() & extras.keys(), 'supplemental test role collision')
    files = {**files, **extras}
    contents, modes, current = {manifest_path: raw_manifest}, {manifest_path: manifest_mode}, {}
    for name, expected in files.items():
        relative(name)
        live, mode = read(source / name)
        if name in roles:
            current[name] = pin(live)
            raw, mode = read(source / SHARED / Path(name).name)
            need(pin(raw) == row(BUILD[name]), 'fixed shared build snapshot differs: ' + name)
        else:
            raw = live
        need(matches(pin(raw), expected), 'historical source drift outside selected helpers: ' + name)
        contents[name], modes[name] = raw, mode
    need(sum(map(len, contents.values())) <= MAX_TOTAL, 'finite source view byte bound exceeded')
    # Capture and validate every source byte before creating the first output.
    output.mkdir(mode=0o700)
    for name, raw in contents.items():
        path = output / name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, modes[name])
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
    expected = {**files, manifest_path: row(PROFILES[profile])}
    actual = {p.relative_to(output).as_posix(): pin(read(p)[0]) for p in output.rglob('*') if p.is_file()}
    need(actual.keys() == expected.keys() and all(matches(actual[name], expected[name]) for name in expected),
         'emitted fixed source closure differs')
    return dict(status='SOURCE_ONLY_FIXED_EXPORT_CONSUMER_BUILD_VIEW' if profile in CONFIGS else
                       'SOURCE_ONLY_FIXED_DESKTOP_BUILD_VIEW' if profile in DESKTOP else 'SOURCE_ONLY_FIXED_DEFAULT_NATIVE_BUILD_VIEW', profile=profile, files=len(actual),
                original_manifest=row(PROFILES[profile]), supplemental_test_inputs=extras, substituted={name: row(BUILD[name]) for name in sorted(roles)},
                current_build_helpers=current, current_helpers_used=False, run_id=None,
                native='NOT_RUN', hardware='NOT_RUN', acceptance=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=tuple(PROFILES), required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.source, args.output, args.profile), sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, 'default historical build source refused: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
