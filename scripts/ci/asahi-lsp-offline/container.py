#!/usr/bin/env python3
"""Prospective container-only offline trial; importing this file executes no actors."""
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import resource
import shlex
import signal
import subprocess
import time

SOURCE = Path('/source')
OUT = Path('/out')
BUNDLE = Path('/candidate')
LIBRARY = BUNDLE / 'lsp-plugins-lv2.so'
HOST = Path('/tmp/offline/host')
LIBRARY_SHA256 = 'b11bb9851ac3153ffe8b423d591133d4f48bd12cb9508c8c7080f93b6a906a84'
HEADERS = {
    'lilv': ('/usr/include/lilv-0/lilv/lilv.h', '68c53a8023206291dafb22d6e099d554fa8b1b047f3f4ab601fd90f0b26990af'),
    'lv2_core': ('/usr/include/lv2/core/lv2.h', '802568ed0e3882a27172e4503cfee74936bc3f8252467b26d32a7d2dbb372689'),
    'lv2_urid': ('/usr/include/lv2/urid/urid.h', '62f7424bc0a4dc2716291ec9d305771bce2ce26edf765d57de9eedba48db2f78'),
}
URIS = ['http://lsp-plug.in/plugins/lv2/' + x for x in
        ('loud_comp_mono', 'mb_compressor_stereo', 'compressor_stereo')]
FLAGS = ['-std=c11', '-O2', '-march=armv8-a', '-mtune=generic', '-Wall', '-Wextra', '-Werror']
LOG_LIMIT = 2 * 1024 * 1024
FILE_LIMIT = 128 * 1024 * 1024
NAME = re.compile(r'[A-Za-z0-9_+.-]{1,160}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
HOST_FAILURES = frozenset(['allocation-failed', 'audio-input-changed', 'audio-output-nonfinite',
 'audio-output-runaway', 'audio-symbol-invalid', 'binding-metadata-invalid',
 'buffer-guard-changed', 'bundle-path-invalid', 'bypass-identity-failed', 'cli-invalid',
 'control-default-invalid', 'control-guard-changed', 'control-input-changed',
 'control-value-invalid', 'descriptor-origin-differs', 'descriptor-set-invalid',
 'descriptor-symbol-missing', 'descriptor-uri-duplicate', 'descriptor-uri-invalid',
 'dlclose-failed', 'dlopen-failed', 'duplicate-port-symbol',
 'enabled-or-latency-invalid', 'enum-count-invalid', 'enum-value-invalid',
 'instantiation-or-urid-failed', 'latency-invalid', 'latency-unstable',
 'library-outside-bundle', 'library-path-invalid', 'link-map-limit',
 'link-map-name-invalid', 'link-map-path-invalid', 'link-map-unavailable',
 'metadata-file-count-invalid', 'metadata-outside-bundle', 'metadata-size-invalid',
 'metadata-write-failed', 'node-allocation-failed', 'port-count-invalid',
 'port-direction-invalid', 'port-index-invalid', 'port-shape-invalid',
 'port-symbol-invalid', 'profile-control-missing', 'reference-generator-not-off',
 'repeat-latency-differs', 'repeat-output-differs', 'required-feature-unsupported',
 'selected-plugin-invalid', 'silence-or-energy-gate-failed', 'unsupported-atom-port',
 'unsupported-port-type', 'urid-overflow', 'world-allocation-failed'])
FAILURE_CODES = frozenset(['file_bounds', 'isolation', 'deadline', 'timeout', 'log_limit', 'signal', 'child_exit', 'inventory', 'pkg_config', 'elf', 'elf_metadata', 'elf_structure', 'elf_search_path', 'host_schema', 'loader_schema', 'loader_identity', 'loader_failure', 'host_controls', 'processing_failure', 'case_grid', 'case_metrics', 'header_hash', 'candidate_hash', 'internal_error', 'inventory_changed']) | {'host_' + code for code in HOST_FAILURES}
STAGES = frozenset(('isolation', 'inventory_before', 'headers', 'candidate', 'compile', 'elf', 'loader', 'processing', 'complete', 'inventory_after'))


class Failure(Exception):
    def __init__(self, code):
        self.code = code


def require(condition, code):
    if not condition:
        raise Failure(code)


def bounded_bytes(path, limit=FILE_LIMIT):
    path = Path(path)
    require(path.is_file() and path.stat().st_size <= limit, 'file_bounds')
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, 'file_bounds')
    return data


def digest(path):
    return hashlib.sha256(bounded_bytes(path)).hexdigest()


def runtime_environment():
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
            'HOME': '/tmp/offline/home', 'XDG_RUNTIME_DIR': '/tmp/offline/runtime',
            'LV2_PATH': '/tmp/offline/lv2'}


def mount_readonly(path, mountinfo):
    matches = []
    for line in mountinfo.splitlines():
        fields = line.split()
        require(len(fields) >= 10 and ' - ' in line, 'isolation')
        mount = fields[4]
        if str(path) == mount or str(path).startswith(mount.rstrip('/') + '/'):
            matches.append((len(mount), fields[5].split(',')))
    return bool(matches) and 'ro' in max(matches)[1]


def assert_isolation():
    require(os.environ.get('CACHY_ASAHI_OFFLINE') == '1' and os.getuid() != 0,
            'isolation')
    require(platform.machine() == 'aarch64' and not Path('/dev/snd').exists(), 'isolation')
    require(not any(k.startswith('LD_') for k in os.environ), 'isolation')
    status = Path('/proc/self/status').read_text()
    require(re.search(r'^CapEff:\s*0+$', status, re.M) is not None and
            re.search(r'^NoNewPrivs:\s*1$', status, re.M) is not None, 'isolation')
    mounts = Path('/proc/self/mountinfo').read_text()
    require(all(mount_readonly(p, mounts) for p in
                ('/', '/source', '/candidate', '/expected.lock', '/checks.py', '/var/lib/pacman')),
            'isolation')
    interfaces = [x.name for x in Path('/sys/class/net').iterdir()]
    require(set(interfaces) <= {'lo'}, 'isolation')
    require(OUT.is_dir() and not OUT.is_symlink(), 'isolation')
    Path('/tmp/offline').mkdir(mode=0o700, exist_ok=False)
    for name in ('home', 'runtime', 'lv2'):
        (Path('/tmp/offline') / name).mkdir(mode=0o700)


def command(args, name, timeout, allowed=(0,)):
    """Bound logs and time, always kill the newly owned process group."""
    require(timeout > 0, 'deadline')
    stdout, stderr = OUT / (name + '.stdout'), OUT / (name + '.stderr')
    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (LOG_LIMIT, LOG_LIMIT))
    process = None
    code = None
    started = time.monotonic()
    with stdout.open('xb') as out, stderr.open('xb') as err:
        try:
            process = subprocess.Popen(args, stdout=out, stderr=err, cwd='/tmp/offline',
                                       env=runtime_environment(), start_new_session=True,
                                       preexec_fn=limits)
            while process.poll() is None:
                if time.monotonic() - started >= timeout:
                    raise Failure('timeout')
                require(max(out.tell(), err.tell(), stdout.stat().st_size,
                            stderr.stat().st_size) < LOG_LIMIT, 'log_limit')
                time.sleep(0.02)
            code = process.returncode
        finally:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
    require(stdout.stat().st_size < LOG_LIMIT and stderr.stat().st_size < LOG_LIMIT, 'log_limit')
    require(code in allowed, 'signal' if code is not None and code < 0 else 'child_exit')
    return bounded_bytes(stdout, LOG_LIMIT)


def inventory(name):
    raw = command(['/usr/bin/pacman', '-Q'], name, 15)
    lines = raw.decode('ascii').splitlines()
    require(len(lines) == 574 and len(set(lines)) == 574 and
            all(re.fullmatch(r'[a-z0-9@_+.-]+ [A-Za-z0-9:._+~=-]+', x) for x in lines),
            'inventory')
    normalized = ('\n'.join(sorted(lines)) + '\n').encode()
    require(normalized == bounded_bytes('/expected.lock', 256 * 1024), 'inventory')
    return hashlib.sha256(normalized).hexdigest()


def pkg_flags(raw):
    flags = shlex.split(raw.decode('ascii'))
    require(0 < len(flags) <= 32, 'pkg_config')
    require(all(re.fullmatch(r'-I/usr/include(?:/[A-Za-z0-9_.+-]+)*|-L/usr/lib|-l[A-Za-z0-9_.+-]+',
                             flag) for flag in flags), 'pkg_config')
    require('-llilv-0' in flags, 'pkg_config')
    return flags


def parse_readelf(raw):
    text = raw.decode('ascii')
    require(re.search(r'Class:\s+ELF64\s', text) is not None and
            re.search(r'Machine:\s+AArch64\s', text) is not None, 'elf')
    needed, paths, versions = [], [], []
    version_needs = False
    for line in text.splitlines():
        if line.startswith('Version '):
            version_needs = line.startswith('Version needs section')
        if '(NEEDED)' in line:
            found = re.search(r'\[([^\]]+)\]', line)
            require(found is not None and NAME.fullmatch(found[1]), 'elf_metadata')
            needed.append(found[1])
        if '(RPATH)' in line or '(RUNPATH)' in line:
            # Do not export any path, even for the rejection report.
            paths.append('RPATH' if '(RPATH)' in line else 'RUNPATH')
        if version_needs and 'Name:' in line:
            found = re.search(r'Name:\s+(\S+)', line)
            require(found is not None and NAME.fullmatch(found[1]), 'elf_metadata')
            versions.append(found[1])
    require(len(needed) <= 128 and len(versions) <= 128 and len(paths) <= 2, 'elf_metadata')
    return {'class': 'ELF64', 'machine': 'AArch64', 'needed': sorted(set(needed)),
            'path_tags': sorted(paths), 'version_requirements': sorted(set(versions))}


def elf_observation(path, name, checker):
    data = bounded_bytes(path)
    structure = checker(data)
    require(isinstance(structure, dict) and not structure.get('errors') and
            structure.get('machine') == 183 and 0 < structure.get('load_segments', 0) <= 128,
            'elf_structure')
    parsed = parse_readelf(command(['/usr/bin/readelf', '-W', '-h', '-l', '-d',
                                   '--version-info', str(path)], name + '-readelf', 15))
    require(not parsed['path_tags'], 'elf_search_path')
    parsed.update({'sha256': hashlib.sha256(data).hexdigest(),
                   'load_segments': structure['load_segments'],
                   'structural_16k': 'PASS', 'hardware_status': 'NOT RUN'})
    return parsed


def json_document(raw):
    def pairs(items):
        value = {}
        for key, entry in items:
            require(key not in value, 'host_schema')
            value[key] = entry
        return value
    def nonfinite(_):
        raise Failure('host_schema')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=nonfinite)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Failure('host_schema') from error


def exact_keys(value, keys):
    require(type(value) is dict and set(value) == set(keys), 'host_schema')


def finite(value, minimum=0, maximum=1e12):
    require(type(value) in (int, float) and math.isfinite(value) and
            minimum <= value <= maximum, 'host_schema')
    return value


def loaded_libraries(names, paths):
    require(type(names) is list and 0 < len(names) <= 128 and
            all(type(x) is str and NAME.fullmatch(x) for x in names) and
            len(names) == len(set(names)) and type(paths) is list and len(paths) == len(names),
            'loader_schema')
    libraries = []
    for name, actual in zip(names, paths):
        if name == 'linux-vdso.so.1':
            require(actual is None, 'loader_identity')
            identity, sha = 'virtual/linux-vdso.so.1', None
        else:
            require(type(actual) is str and len(actual) <= 4096 and actual.startswith('/'),
                    'loader_identity')
            path = Path(actual)
            require(path.resolve(strict=True) == path and path.is_file(), 'loader_identity')
            # Resolve the observed loader path, never guess a file from its basename.
            if path == LIBRARY:
                require(name == LIBRARY.name, 'loader_identity')
                identity = 'candidate/' + LIBRARY.name
            elif path == HOST:
                require(name == HOST.name, 'loader_identity')
                identity = 'host/host'
            else:
                require(path.is_relative_to(Path('/usr/lib')) and
                        all(NAME.fullmatch(part) for part in path.relative_to('/usr/lib').parts),
                        'loader_identity')
                identity = 'system/' + path.relative_to('/usr/lib').as_posix()
            sha = digest(path)
        require(identity not in {x['identity'] for x in libraries}, 'loader_identity')
        libraries.append({'identity': identity, 'sha256': sha})
    return sorted(libraries, key=lambda x: x['identity'])


def host_failure(value, mode):
    """Export only a closed failure identifier; discard partial plugin metadata."""
    if type(value) is dict and value.get('status') == 'FAIL':
        require(type(value.get('schema_version')) is int and value['schema_version'] == 1 and
                value.get('mode') == mode and value.get('failure_class') in HOST_FAILURES and
                value.get('audio_devices') == 'NOT USED' and value.get('hardware') == 'NOT RUN' and
                value.get('optimization_acceptance') == 'NOT RUN', 'host_schema')
        raise Failure('host_' + value['failure_class'])


def project_loader(raw):
    value = json_document(raw)
    host_failure(value, 'loader')
    require(type(value) is dict and value.get('status') == 'PASS', 'loader_failure')
    exact_keys(value, ('schema_version', 'mode', 'status', 'selected_uris', 'descriptor_count',
                       'loaded_basenames', 'loaded_paths', 'failure_class', 'audio_devices',
                       'hardware', 'optimization_acceptance'))
    require(type(value['schema_version']) is int and value['schema_version'] == 1 and
            value['mode'] == 'loader' and value['status'] == 'PASS' and
            value['failure_class'] is None and value['audio_devices'] == 'NOT USED' and
            value['hardware'] == 'NOT RUN' and value['optimization_acceptance'] == 'NOT RUN',
            'loader_failure')
    require(value['selected_uris'] == URIS and type(value['descriptor_count']) is int and
            3 <= value['descriptor_count'] <= 512, 'loader_schema')
    libraries = loaded_libraries(value['loaded_basenames'], value['loaded_paths'])
    require('candidate/' + LIBRARY.name in {x['identity'] for x in libraries}, 'loader_identity')
    return {'status': 'PASS', 'selected_uris': URIS,
            'descriptor_count': value['descriptor_count'], 'loaded_libraries': libraries}


PROFILE_VALUES = {
    URIS[0]: {'volume-0': {'enabled': 1, 'input': 1, 'fft': 2, 'volume': 0},
              'volume-minus47_5': {'enabled': 1, 'input': 1, 'fft': 2, 'volume': -47.5}},
    URIS[1]: {'asahi-woofer-band': {
        'mode': 0, 'ce_0': 1, 'sla_0': 5, 'cr_0': 1.75, 'al_0': .725,
        'at_0': 1, 'rt_0': 100, 'kn_0': .125, 'cbe_1': 1, 'sf_1': 200,
        'ce_1': 0, 'cbe_2': 0, 'ce_2': 0, 'cbe_3': 0, 'ce_3': 0,
        'cbe_4': 0, 'ce_4': 0, 'cbe_5': 0, 'ce_5': 0, 'cbe_6': 0, 'ce_6': 0}},
    URIS[2]: {'asahi-woofer-limiter': {'sla': 5, 'al': 1, 'at': 1, 'rt': 100,
                                      'cr': 15, 'kn': .5}},
}
RATES = (44100, 48000, 88200, 96000)
FIXTURES = ('zero', 'bypass', 'synthetic')


def project_plugins(plugins):
    require(type(plugins) is list and len(plugins) == 3, 'host_schema')
    for plugin, uri in zip(plugins, URIS):
        exact_keys(plugin, ('uri', 'port_count', 'required_features', 'audio_inputs',
                            'audio_outputs', 'optional_null_atoms', 'controls'))
        channels = 1 if uri == URIS[0] else 2
        require(plugin['uri'] == uri and type(plugin['port_count']) is int and
                0 < plugin['port_count'] <= 512 and
                plugin['required_features'] == ['http://lv2plug.in/ns/ext/urid#map'] and
                plugin['audio_inputs'] == (['in'] if channels == 1 else ['in_l', 'in_r']) and
                plugin['audio_outputs'] == (['out'] if channels == 1 else ['out_l', 'out_r']) and
                plugin['optional_null_atoms'] == ['in_ui', 'out_ui'], 'host_schema')
        profiles = list(PROFILE_VALUES[uri].values())
        expected = set(profiles[0])
        controls = plugin['controls']
        require(type(controls) is list and len(controls) == len(expected), 'host_schema')
        seen, indices = set(), set()
        for row in controls:
            exact_keys(row, ('symbol', 'index', 'default', 'minimum', 'maximum',
                             'integer', 'toggled', 'enum_values'))
            symbol, index = row['symbol'], row['index']
            require(type(symbol) is str and symbol in expected and symbol not in seen and
                    type(index) is int and 0 <= index < plugin['port_count'] and index not in indices,
                    'host_schema')
            seen.add(symbol)
            indices.add(index)
            minimum = finite(row['minimum'], -1e12)
            maximum = finite(row['maximum'], minimum)
            finite(row['default'], minimum, maximum)
            require(type(row['integer']) is bool and type(row['toggled']) is bool and
                    type(row['enum_values']) is list and len(row['enum_values']) <= 512,
                    'host_schema')
            enums = [finite(x, minimum, maximum) for x in row['enum_values']]
            require(len(enums) == len(set(enums)), 'host_schema')
            for profile in profiles:
                value = profile[symbol]
                require(minimum <= value <= maximum and
                        (not enums or value in enums) and
                        (not row['integer'] or value == int(value)) and
                        (not row['toggled'] or value in (0, 1)), 'host_controls')
    return plugins


def project_processing(raw):
    value = json_document(raw)
    host_failure(value, 'processing')
    require(type(value) is dict and value.get('status') == 'PASS', 'processing_failure')
    exact_keys(value, ('schema_version', 'mode', 'status', 'failure_class', 'plugins',
                       'control_binding_count', 'case_count', 'instance_count', 'cases',
                       'audio_devices', 'hardware', 'optimization_acceptance'))
    require(type(value['schema_version']) is int and value['schema_version'] == 1 and
            value['mode'] == 'processing' and
            value['failure_class'] is None and value['control_binding_count'] == 31 and
            value['case_count'] == 48 and value['instance_count'] == 96 and
            value['audio_devices'] == 'NOT USED' and value['hardware'] == 'NOT RUN' and
            value['optimization_acceptance'] == 'NOT RUN', 'host_schema')
    project_plugins(value['plugins'])
    grid = {(uri, profile, rate, fixture) for uri, profiles in PROFILE_VALUES.items()
            for profile in profiles for rate in RATES for fixture in FIXTURES}
    require(type(value['cases']) is list and len(value['cases']) == 48, 'host_schema')
    for case in value['cases']:
        exact_keys(case, ('profile', 'uri', 'rate_hz', 'fixture', 'status', 'latency_frames',
                          'peak', 'rms', 'max_bypass_error', 'max_repeat_error',
                          'sample_count_per_channel', 'sample_fnv1a64'))
        require(type(case['rate_hz']) is int and type(case['uri']) is str and
                type(case['profile']) is str and type(case['fixture']) is str, 'host_schema')
        key = (case['uri'], case['profile'], case['rate_hz'], case['fixture'])
        require(key in grid and case['status'] == 'PASS', 'case_grid')
        grid.remove(key)
        latency = finite(case['latency_frames'], 0, 8192)
        require(abs(latency - round(latency)) <= 1e-3, 'case_metrics')
        peak = finite(case['peak'], 0, 16)
        rms = finite(case['rms'], 0, peak)
        bypass = finite(case['max_bypass_error'])
        finite(case['max_repeat_error'])
        require(type(case['sample_count_per_channel']) is int and
                case['sample_count_per_channel'] == 24576, 'case_metrics')
        hashes = case['sample_fnv1a64']
        require(type(hashes) is list and len(hashes) == 2 and
                all(type(x) is str and re.fullmatch('[0-9a-f]{16}', x) for x in hashes),
                'case_metrics')
        if case['fixture'] == 'zero':
            require(peak <= 1e-7, 'case_metrics')
        if case['fixture'] == 'bypass':
            require(bypass <= 1e-7 + 1e-5 * .001, 'case_metrics')
        if case['fixture'] == 'synthetic':
            channels = 1 if case['uri'] == URIS[0] else 2
            require(rms * rms * 16384 * channels > 1e-20, 'case_metrics')
    require(not grid, 'case_grid')
    return value


def main():
    os.umask(0o077)
    report = {'schema_version': 1, 'status': 'FAIL', 'failure_class': None,
              'stage': 'isolation'}
    before = None
    try:
        assert_isolation()
        report['stage'] = 'inventory_before'
        before = inventory('inventory-before')
        report['inventory'] = {'count': 574, 'before_sha256': before,
                               'after_sha256': None, 'unchanged': False}
        report['stage'] = 'headers'
        report['headers'] = {}
        for key, (path, expected) in HEADERS.items():
            actual = digest(path)
            require(actual == expected, 'header_hash')
            report['headers'][key] = actual
        report['stage'] = 'candidate'
        require(LIBRARY.resolve(strict=True) == LIBRARY and digest(LIBRARY) == LIBRARY_SHA256,
                'candidate_hash')
        report['candidate_sha256'] = LIBRARY_SHA256
        report['stage'] = 'compile'
        started = time.monotonic()
        flags = pkg_flags(command(['/usr/bin/pkg-config', '--cflags', '--libs', 'lilv-0'],
                                  'pkg-config', 10))
        args = ['/usr/bin/gcc', *FLAGS, str(SOURCE / 'host.c'), '-o', str(HOST),
                *flags, '-ldl', '-lm']
        (OUT / 'compile-command.json').write_text(json.dumps(args) + '\n')
        command(args, 'compile', 60 - (time.monotonic() - started))
        report['host'] = {'sha256': digest(HOST), 'source_sha256': digest(SOURCE / 'host.c'),
                          'compile_flags': FLAGS + flags + ['-ldl', '-lm'],
                          'compiler_sha256': digest('/usr/bin/gcc'),
                          'pkg_config_sha256': digest('/usr/bin/pkg-config'),
                          'readelf_sha256': digest('/usr/bin/readelf'),
                          'lilv_pc_sha256': digest('/usr/lib/pkgconfig/lilv-0.pc')}
        report['stage'] = 'elf'
        spec = importlib.util.spec_from_file_location('frozen_package_checks', '/checks.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report['elf'] = {name: elf_observation(path, name, module.elf_check)
                         for name, path in (('host', HOST), ('candidate', LIBRARY))}
        report['stage'] = 'loader'
        report['loader'] = project_loader(command([str(HOST), '--loader', str(LIBRARY)],
                                                 'loader', 30, allowed=(0, 1)))
        report['stage'] = 'processing'
        report['processing'] = project_processing(command([str(HOST), '--bundle', str(BUNDLE)],
                                                          'processing', 120, allowed=(0, 1)))
        report['status'] = 'PASS'
        report['stage'] = 'complete'
    except Failure as error:
        report['failure_class'] = error.code
    except Exception:
        # Raw errors/paths remain private; no unrestricted exception interpolation.
        report['failure_class'] = 'internal_error'
    finally:
        if before is not None:
            try:
                after = inventory('inventory-after')
                report['inventory'].update(after_sha256=after, unchanged=after == before)
                require(after == before, 'inventory_changed')
            except Exception:
                report.update(status='FAIL', failure_class='inventory_changed', stage='inventory_after')
    try:
        (OUT / 'observations.json').write_text(json.dumps(report, sort_keys=True,
                                                        allow_nan=False) + '\n')
    except OSError:
        return 1
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
