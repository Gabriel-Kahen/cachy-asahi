#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded GCC profile adapter for the pinned zlib ARM-C03 experiment.

Only public repeated.txt and the pinned upstream example's fixed literals train.
Two independent training attempts are retained; only attempt one supplies both
final builds. Raw profile regeneration equality is an observation, not a gate.
"""
import hashlib
import io
from pathlib import Path
import re
import shlex
import shutil
import tarfile
import time
import zlib

PROFILE = Path('/tmp/profile')
WORK = Path('/tmp/build')
OBJECTS = tuple(sorted(('adler32 crc32 deflate infback inffast inflate inftrees trees zutil '
                        'compress uncompr gzclose gzlib gzread gzwrite example minigzip').split()))
PROFILE_NAMES = tuple('#tmp#build#' + name + '.gcda' for name in OBJECTS)
SOURCES = {
    'test/example.c': 'be1b050aad808cdb016c01f42568d3a62ee37dd7b2b56bef0ade21be8d9fee0d',
    'test/minigzip.c': '203b1a4623a11021f4b64c5f6b6a4addc1bcefac694cd48cac71ccce35d82c1d',
    'examples/gun.c': 'e203716e306e79f31f73ffe594e4214801f72ae768db7a8f115ac425132ad52f'}
SOURCE_FILES = {name: name.replace('/', '-') for name in SOURCES}
BUILD_FILES = ('libz.a', 'example', 'minigzip', 'gun', 'gun.o')
TRAIN_FILES = ('train.gz', 'train.decoded', 'gun.decoded', 'example.gz')
TRAIN_SECONDS = 120


def generation_flags(core):
    suffix = ' -fno-lto -fprofile-generate=/tmp/profile -fprofile-reproducible=serial'
    return core.BASE_FLAGS + suffix, core.LINK_FLAGS + suffix


def apply_use_flags(core, work):
    """Switch only Makefile compile/link assignments after unprofiled probes.

    GCC's missing-profile error must govern real source compilation, while
    configure's temporary feature-probe translation units have no profiles.
    """
    makefile, log = work / 'Makefile', work / 'configure.log'
    core.regular(makefile); core.regular(log)
    original = makefile.read_bytes()
    baseline = core.configured_flags(original, log.read_bytes(), 'baseline')
    base_c, _ = core.build_flags('baseline')
    suffix = shlex.split(baseline['CFLAGS'])[len(shlex.split(base_c)):]
    cflags, ldflags = core.build_flags('pgo')
    replacements = {'CFLAGS': cflags + ' ' + ' '.join(suffix), 'LDFLAGS': ldflags}
    updated = original.decode('utf-8')
    for key, value in replacements.items():
        updated, count = re.subn(r'(?m)^(' + key + r'[ \t]*=[ \t]*)[^\n]*$',
                                 lambda match: match[1] + value, updated)
        core.need(count == 1, 'one profile-use Makefile assignment required')
    makefile.write_bytes(updated.encode('utf-8'))


def _gun_compile(core):
    flags = core.BASE_FLAGS + ' -fno-lto'
    return ['gcc', *shlex.split(flags.replace('$@', 'gun.o')), '-I/tmp/build',
            '-c', '/tmp/build/examples/gun.c', '-o', '/tmp/build/gun.o']


def command_plan(core, manifest):
    """Insert after the five common tool commands, before the four final builds."""
    _training(core, manifest)
    rows, env = [], core.trial_env()
    flags, ldflags = generation_flags(core)
    build_env = {**env, 'CFLAGS': flags, 'LDFLAGS': ldflags}
    def add(name, argv, cwd=None, environment=None, source=None, target=None):
        rows.append({'name': name, 'argv': argv, 'cwd': cwd,
                     'environment': env if environment is None else environment,
                     'source': source, 'target': target, 'reject': False,
                     'sample': False, 'observe': False})
    for attempt in (1, 2):
        prefix = f'pgo-training-{attempt}'
        dest = '/out/' + prefix
        add(prefix + '-configure', ['./configure', '--static'], '/tmp/build', build_env)
        add(prefix + '-build', ['make', '-j2', 'static'], '/tmp/build', build_env)
        add(prefix + '-gun-compile', _gun_compile(core), '/tmp/build')
        add(prefix + '-gun-link', ['gcc', '/tmp/build/gun.o', '/tmp/build/libz.a',
                                 '-o', '/tmp/build/gun', *shlex.split(ldflags)], '/tmp/build')
        add(prefix + '-train-encode', ['/tmp/build/minigzip', '-6'],
            source='/tmp/corpus/repeated.txt', target=dest + '/train.gz')
        add(prefix + '-train-decode', ['/tmp/build/minigzip', '-d'],
            source=dest + '/train.gz', target=dest + '/train.decoded')
        add(prefix + '-train-example', ['/tmp/build/example', dest + '/example.gz'], '/tmp/build')
        add(prefix + '-train-gun', ['/tmp/build/gun'],
            source=dest + '/train.gz', target=dest + '/gun.decoded')
        # This separate diagnostic copy doubles counters; final builds always
        # restore untouched raw attempt-one profiles, never this decoder output.
        add(prefix + '-profile-check', ['gcov-tool', 'merge', '-v', '-w', '1,1',
                                       '-o', dest + '/decoded-profiles', dest + '/profiles', dest + '/profiles'])
    return rows


def _training(core, manifest):
    selected = [row for row in manifest['files'] if row['role'] == 'train']
    expected = {'path': 'repeated.txt', 'sha256': hashlib.sha256(core.corpus.TRAIN).hexdigest(),
                'bytes': len(core.corpus.TRAIN), 'kind': 'input', 'role': 'train'}
    core.need(selected == [expected], 'one exact public training corpus required')
    return expected


def _binding(core, path):
    core.regular(path, 8 * 1024**2)
    return {'bytes': path.stat().st_size, 'sha256': core.sha(path)}


def profile_map(core, directory):
    """Exact bounded regular GCDA objects at the fixed GCC object paths."""
    core.need(directory.is_dir() and not directory.is_symlink(), 'real profile directory required')
    core.need({p.name for p in directory.iterdir()} == set(PROFILE_NAMES), 'all seventeen exact profiles required')
    rows, total, versions = [], 0, set()
    for name in PROFILE_NAMES:
        path = directory / name
        binding = _binding(core, path)
        data = path.read_bytes()
        core.need(16 <= len(data) <= core.LIMIT and data[:4] in (b'adcg', b'gcda'), 'bounded GCC gcda profile required')
        versions.add(data[4:8]); total += len(data)
        rows.append({'name': name, **binding})
    core.need(total <= 16 * 1024**2 and len(versions) == 1, 'profile aggregate/version differs')
    return rows


def check_profile_output(core, data):
    """Require both decoder reads; the weighted copy is checked separately."""
    text = data.decode('utf-8')
    core.need(not re.search(r'not a gcov|corrupt|malformed|\b(?:warning|error)\b|cannot open|'
                            r'cannot access directory|is not a directory|incorrect gcov version|'
                            r'mismatch|skipping|counter overflow|read error', text, re.IGNORECASE),
              'gcov-tool profile decoding diagnostic refused')
    # stdout progress can lack a newline before stderr's reader record when
    # both streams share the retained log. Keep the exact filename/end boundary.
    names = re.findall(r'reading file:[ \t]+(?:\./)?([^\r\n]*?)[ \t]*$', text, re.MULTILINE)
    core.need(len(names) == 2 * len(PROFILE_NAMES) and set(names) == set(PROFILE_NAMES)
              and all(names.count(name) == 2 for name in PROFILE_NAMES),
              'complete exact gcov-tool profile reader coverage required')


def decoded_profile_map(core, dest):
    """Check decoded copy closure/version without requiring identical encoding."""
    result = profile_map(core, dest / 'decoded-profiles')
    for name in PROFILE_NAMES:
        core.need((dest / 'profiles' / name).read_bytes()[:8]
                  == (dest / 'decoded-profiles' / name).read_bytes()[:8],
                  'decoded gcov-tool profile magic/version differs')
    return result


def _configured(core, makefile, log):
    expected_c, expected_l = generation_flags(core)
    parsed = []
    for data in (makefile, log):
        values = {}
        for key in ('CC', 'AR', 'RANLIB', 'CFLAGS', 'LDFLAGS'):
            found = re.findall(r'^' + key + r'[ \t]*=[ \t]*([^\n]*)$', data.decode(), re.MULTILINE)
            core.need(len(found) == 1, 'one training configured assignment required')
            values[key] = ' '.join(shlex.split(found[0]))
        parsed.append(values)
    core.need(parsed[0] == parsed[1], 'training Makefile/configure flags differ')
    values = parsed[0]
    core.need(all(values[key] == value for key, value in (('CC', 'gcc'), ('AR', 'gcc-ar'), ('RANLIB', 'gcc-ranlib'))),
              'training configured tool override refused')
    expected, actual = shlex.split(expected_c), shlex.split(values['CFLAGS'])
    suffix = actual[len(expected):]
    core.need(actual[:len(expected)] == expected and suffix and suffix[0] == '-fPIC'
              and len(suffix) == len(set(suffix)) and all(flag in core.FEATURE_FLAGS for flag in suffix)
              and values['LDFLAGS'] == expected_l, 'training effective flags differ')
    return values


def _reset_profile():
    if PROFILE.exists():
        shutil.rmtree(PROFILE)
    PROFILE.mkdir(mode=0o700)


def prepare(core, runner, inputs, out, env, corpus_root, manifest):
    """Run fresh generate/train twice, retaining bytes before replacing work."""
    train = _training(core, manifest)
    training_path = corpus_root / train['path']
    core.need(training_path.read_bytes() == core.corpus.TRAIN, 'public training bytes changed')
    plans = command_plan(core, manifest)
    report = {'source_training_sha256': SOURCES.copy(), 'training_input': train,
              'profile_path': str(PROFILE), 'build_path': str(WORK), 'attempts': [], 'restores': [],
              'unchanged_after_build': [], 'training_seconds_limit': TRAIN_SECONDS,
              'profile_regeneration_acceptance': 'NOT REQUIRED'}
    for attempt in (1, 2):
        prefix = f'pgo-training-{attempt}'
        dest = out / prefix; dest.mkdir(mode=0o700)
        core.need(not WORK.exists(), 'fresh training build path required')
        WORK.mkdir(mode=0o700)
        core.extract(inputs / 'zlib.tar.gz', WORK)
        _reset_profile()
        for name, pin in SOURCES.items():
            path = WORK / name
            core.need(core.sha(path) == pin, 'pinned public training source changed')
            shutil.copyfile(path, dest / SOURCE_FILES[name])
        selected = [p for p in plans if p['name'].startswith(prefix + '-')]
        training_started = None
        for index, plan in enumerate(selected):
            if index == 4:
                # configure executes feature probes; they must never enter training.
                _reset_profile()
                training_started = time.monotonic()
            if index == 8:
                training_elapsed = time.monotonic() - training_started
                core.need(training_elapsed <= TRAIN_SECONDS, 'aggregate training timeout')
                shutil.copytree(PROFILE, dest / 'profiles')
                profiles = profile_map(core, dest / 'profiles')
            is_training = '-train-' in plan['name']
            timeout = TRAIN_SECONDS - (time.monotonic() - training_started) if is_training else 180
            core.need(timeout > 0, 'aggregate training timeout')
            output = runner.run(plan['name'], plan['argv'], cwd=plan['cwd'], env=plan['environment'],
                                source=Path(plan['source']) if plan['source'] else None,
                                target=Path(plan['target']) if plan['target'] else None, timeout=timeout)
            if index == 8:
                check_profile_output(core, output)
                core.need(profile_map(core, dest / 'profiles') == profiles, 'gcov-tool mutated retained profiles')
                decoded_profiles = decoded_profile_map(core, dest)
        for filename in ('train.decoded', 'gun.decoded'):
            core.need((dest / filename).read_bytes() == core.corpus.TRAIN, 'training roundtrip bytes differ')
        for name in BUILD_FILES:
            shutil.copyfile(WORK / name, dest / name)
        for name in core.CONFIG_FILES:
            shutil.copyfile(WORK / name, dest / (name + '.txt'))
        effective = _configured(core, (dest / 'Makefile.txt').read_bytes(), (dest / 'configure.log.txt').read_bytes())
        files = {p.name: _binding(core, p) for p in sorted(dest.iterdir()) if p.is_file()}
        report['attempts'].append({'attempt': attempt, 'files': files, 'profiles': profiles, 'decoded_profiles': decoded_profiles,
                                   'configured_flags': effective, 'training_elapsed_seconds': training_elapsed})
        shutil.rmtree(WORK)
    report['profile_regeneration'] = ('identical' if report['attempts'][0]['profiles'] == report['attempts'][1]['profiles'] else 'different')
    return report


def restore(core, raw_or_out, attempt):
    core.need(attempt in (1, 2), 'two final profile-use attempts required')
    first = Path(raw_or_out) / 'pgo-training-1' / 'profiles'
    expected = profile_map(core, first)
    _reset_profile()
    for name in PROFILE_NAMES:
        shutil.copyfile(first / name, PROFILE / name)
    core.need(profile_map(core, PROFILE) == expected, 'restored profile bytes differ')
    return {'attempt': attempt, 'profiles': expected}


def assert_unchanged(core, raw_or_out, attempt):
    expected = profile_map(core, Path(raw_or_out) / 'pgo-training-1' / 'profiles')
    core.need(profile_map(core, PROFILE) == expected, 'profile-use build mutated retained profiles')
    return {'attempt': attempt, 'profiles': expected}


def _source_bytes(core, data):
    core.need(hashlib.sha256(data).hexdigest() == core.SOURCE_SHA, 'training source archive pin differs')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        found = {name: archive.extractfile('zlib-1.3.2/' + name).read() for name in SOURCES}
    core.need({name: hashlib.sha256(value).hexdigest() for name, value in found.items()} == SOURCES,
              'public training sources differ')
    return found


def verify(core, raw, report, manifest, source_bytes, commands):
    """Check source-derived inputs and retained records without executing binaries."""
    raw = Path(raw)
    training = _training(core, manifest)
    material = _source_bytes(core, source_bytes)
    license_bytes = core.source_material(source_bytes)['LICENSE']
    core.need(report.get('source_training_sha256') == SOURCES and report.get('training_input') == training
              and report.get('profile_path') == str(PROFILE) and report.get('build_path') == str(WORK)
              and report.get('training_seconds_limit') == TRAIN_SECONDS
              and report.get('profile_regeneration_acceptance') == 'NOT REQUIRED', 'training controls differ')
    attempts = report.get('attempts', [])
    core.need([a['attempt'] for a in attempts] == [1, 2], 'two independent training attempts required')
    by_name = {r['name']: r for r in commands}
    expected_files = set(BUILD_FILES) | set(TRAIN_FILES) | set(SOURCE_FILES.values()) | {n + '.txt' for n in core.CONFIG_FILES}
    for record in attempts:
        prefix = f"pgo-training-{record['attempt']}"
        dest = raw / prefix
        core.need(dest.is_dir() and not dest.is_symlink()
                  and {p.name for p in dest.iterdir()} == expected_files | {'profiles', 'decoded-profiles'}
                  and set(record['files']) == expected_files, 'complete exact training artifacts required')
        for name, binding in record['files'].items():
            core.need(_binding(core, dest / name) == binding, 'retained training artifact differs')
        for name, data in material.items():
            core.need((dest / SOURCE_FILES[name]).read_bytes() == data, 'retained training source differs')
        core.need((dest / 'LICENSE.txt').read_bytes() == license_bytes, 'training license differs from pinned source')
        effective = _configured(core, (dest / 'Makefile.txt').read_bytes(), (dest / 'configure.log.txt').read_bytes())
        core.need(record['configured_flags'] == effective, 'training effective flags receipt differs')
        core.need(profile_map(core, dest / 'profiles') == record['profiles'], 'retained profile map differs')
        core.need(decoded_profile_map(core, dest) == record.get('decoded_profiles'), 'retained decoded profile map differs')
        elapsed = record['training_elapsed_seconds']
        core.need(isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool) and 0 <= elapsed <= TRAIN_SECONDS,
                  'bounded training elapsed required')
        train_rows = [by_name[prefix + '-train-' + suffix] for suffix in ('encode', 'decode', 'example', 'gun')]
        core.need(sum(r['elapsed_seconds'] for r in train_rows) <= elapsed + 0.01
                  and all(0 < r['timeout_seconds'] <= TRAIN_SECONDS for r in train_rows), 'aggregate training budget differs')
        for suffix, filename in (('encode', 'train.gz'), ('decode', 'train.decoded'), ('gun', 'gun.decoded')):
            binding = by_name[prefix + '-train-' + suffix]['stdout']
            core.need(binding == {'path': '/out/' + prefix + '/' + filename, **_binding(core, dest / filename)},
                      'retained training stdout binding differs')
        for name in ('train.decoded', 'gun.decoded'):
            core.need((dest / name).read_bytes() == core.corpus.TRAIN, 'retained training roundtrip differs')
        for name, expected in (('train.gz', core.corpus.TRAIN), ('example.gz', b'hello, hello!\0')):
            data = (dest / name).read_bytes()
            decoder = zlib.decompressobj(31)
            decoded = decoder.decompress(data, len(expected) + 1)
            core.need(decoded == expected and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
                      'retained training gzip payload differs')
        row = by_name[prefix + '-profile-check']
        directory = '/out/' + prefix + '/profiles'
        core.need(row['argv'] == ['gcov-tool', 'merge', '-v', '-w', '1,1', '-o',
                                 '/out/' + prefix + '/decoded-profiles', directory, directory]
                  and row['status'] == row['cleanup'] == 'PASS' and row['exit_code'] == 0,
                  'successful retained gcov-tool profile check required')
        check_profile_output(core, (raw / row['log']).read_bytes())
    equality = 'identical' if attempts[0]['profiles'] == attempts[1]['profiles'] else 'different'
    core.need(report.get('profile_regeneration') == equality, 'profile regeneration observation differs')
    wanted = [{'attempt': n, 'profiles': attempts[0]['profiles']} for n in (1, 2)]
    core.need(report.get('restores') == wanted and report.get('unchanged_after_build') == wanted,
              'both final builds require unchanged first-attempt profiles')
    return report


def artifact_files(core, raw, verified):
    """Finite additional export selection; no directory-wide unbounded capture."""
    result = {}
    for record in verified['attempts']:
        prefix = f"pgo-training-{record['attempt']}"
        for name in record['files']:
            path = Path(raw) / prefix / name
            result[prefix + '/' + name] = core.sha(path)
        for profile in record['profiles']:
            relative = prefix + '/profiles/' + profile['name']
            result[relative] = core.sha(Path(raw) / relative)
        for profile in record['decoded_profiles']:
            relative = prefix + '/decoded-profiles/' + profile['name']
            result[relative] = core.sha(Path(raw) / relative)
    return result
