#!/usr/bin/env python3
"""Rust-only projection/entrypoint using the byte-held offline container primitives."""
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import time

spec = importlib.util.spec_from_file_location('rust_support', Path(__file__).with_name('support.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
SOURCE, OUT, BUNDLE = Path('/source'), Path('/out'), Path('/candidate')
HOST = Path('/tmp/offline/host')
HOST_FAILURES = frozenset(['allocation-failed', 'audio-input-changed', 'audio-output-nonfinite',
 'audio-output-runaway', 'bundle-parent-invalid', 'bundle-path-invalid',
 'channel-exchange-failed', 'channel-isolation-failed', 'cli-invalid',
 'control-input-changed', 'control-metadata-invalid', 'control-value-invalid',
 'descriptor-origin-differs', 'descriptor-set-invalid', 'descriptor-symbol-missing',
 'descriptor-uri-invalid', 'direct-oracle-failed', 'dlclose-failed', 'dlopen-failed',
 'instantiation-failed', 'library-or-port-count-invalid', 'library-path-invalid',
 'link-map-limit', 'link-map-name-invalid', 'link-map-path-invalid',
 'link-map-unavailable', 'loader-uri-invalid', 'metadata-file-count-invalid',
 'metadata-outside-bundle', 'metadata-size-invalid', 'metadata-write-failed',
 'node-allocation-failed', 'nonzero-energy-gate-failed', 'plugin-set-invalid',
 'port-count-invalid', 'port-guard-changed', 'port-index-invalid', 'port-shape-invalid',
 'port-symbol-invalid', 'repeat-output-differs', 'required-feature-unsupported',
 'selected-plugin-invalid', 'sign-reversal-failed', 'silence-gate-failed',
 'wet-amount-scaling-failed', 'wet-rms-gate-failed', 'world-allocation-failed'])
STAGES = frozenset(('isolation', 'inventory_before', 'headers', 'candidates', 'compile',
                    'elf', 'loader', 'processing', 'complete', 'inventory_after'))
EXTRA_FAILURES = frozenset(('candidate_hash', 'host_schema', 'host_controls', 'case_grid',
                            'case_metrics', 'loader_schema', 'loader_identity', 'internal_error',
                            'inventory_changed', 'header_hash'))


def common():
    return s.held('container', Path('/held'))


def require(condition, code):
    common().require(condition, code)


def candidate_rows():
    return [(row, BUNDLE / Path(row['elf_paths'][0]).parts[-2] /
             Path(row['elf_paths'][0]).name) for row in s.inputs()['packages']]


def failure_codes():
    return common().FAILURE_CODES | EXTRA_FAILURES | {'host_' + x for x in HOST_FAILURES}


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys), 'host_schema')


def number(value, minimum=0, maximum=1e12):
    require(type(value) in (int, float) and math.isfinite(value) and minimum <= value <= maximum,
            'host_schema')
    return value


def document(raw, mode):
    value = common().json_document(raw)
    require(type(value) is dict and type(value.get('schema_version')) is int and value['schema_version'] == 1 and value.get('mode') == mode,
            'host_schema')
    if value.get('status') == 'FAIL':
        require(value.get('failure_class') in HOST_FAILURES and value.get('audio_devices') == 'NOT USED' and
                value.get('hardware') == value.get('optimization_acceptance') == 'NOT RUN', 'host_schema')
        raise common().Failure('host_' + value['failure_class'])
    require(value.get('status') == 'PASS' and value.get('failure_class') is None, 'host_schema')
    return value


def project_plugins(plugins):
    require(type(plugins) is list and len(plugins) == 2, 'host_schema')
    for plugin, uri in zip(plugins, s.URIS):
        exact(plugin, ('uri', 'port_count', 'required_features', 'audio_inputs', 'audio_outputs', 'controls'))
        require(plugin['uri'] == uri and type(plugin['port_count']) is int and plugin['port_count'] == 12 and
                plugin['required_features'] == [s.FEATURE] and
                plugin['audio_inputs'] == (['in_l', 'in_r'] if uri == s.BANK else ['in_1', 'in_2', 'in_3']) and
                plugin['audio_outputs'] == (['out_l', 'out_r'] if uri == s.BANK else ['out']), 'host_schema')
        expected = set().union(*(set(p) for p in s.PROFILES[uri].values()))
        controls = plugin['controls']
        require(type(controls) is list and len(controls) == len(expected) == 8, 'host_schema')
        seen, indices = set(), set()
        for control in controls:
            exact(control, ('symbol', 'index', 'default', 'minimum', 'maximum', 'integer', 'toggled', 'enum_values'))
            symbol, index = control['symbol'], control['index']
            require(type(symbol) is str and symbol in expected and symbol not in seen and
                    type(index) is int and 4 <= index < 12 and index not in indices, 'host_schema')
            seen.add(symbol); indices.add(index)
            low = number(control['minimum'], -1e12)
            high = number(control['maximum'], low)
            default = number(control['default'], low, high)
            require(type(control['integer']) is bool and type(control['toggled']) is bool and
                    type(control['enum_values']) is list and len(control['enum_values']) <= 512, 'host_schema')
            enums = [number(x, low, high) for x in control['enum_values']]
            require(len(enums) == len(set(enums)), 'host_schema')
            if uri == s.BANK and symbol == 'final_hp':
                require(default == 200, 'host_controls')
            values = [profile.get(symbol, default) for profile in s.PROFILES[uri].values()]
            if symbol == 'amt': values += [2 * value for value in values] + [0]
            if symbol == 'bypass': values += [1]
            for value in values:
                require(low <= value <= high and (not enums or value in enums) and
                        (not control['integer'] or value == int(value)) and
                        (not control['toggled'] or value in (0, 1)), 'host_controls')
    return plugins


def project_processing(raw):
    value = document(raw, 'processing')
    exact(value, ('schema_version', 'mode', 'status', 'failure_class', 'plugins', 'control_binding_count',
                  'case_count', 'instance_count', 'cases', 'audio_devices', 'hardware', 'optimization_acceptance'))
    require(value['control_binding_count'] == 16 and value['case_count'] == 60 and value['instance_count'] == 120 and
            value['audio_devices'] == 'NOT USED' and value['hardware'] == value['optimization_acceptance'] == 'NOT RUN',
            'host_schema')
    project_plugins(value['plugins'])
    require(type(value['cases']) is list and len(value['cases']) == 60, 'host_schema')
    grid = s.grid()
    for case in value['cases']:
        exact(case, ('profile', 'uri', 'rate_hz', 'fixture', 'pair_role', 'frames_per_instance', 'latency_frames',
                     'peak', 'rms', 'max_oracle_error', 'max_repeat_error', 'wet_energy', 'wet_rms',
                     'sample_fnv1a64', 'status'))
        require(all(type(case[k]) is str for k in ('profile', 'uri', 'fixture', 'pair_role')) and
                type(case['rate_hz']) is int, 'host_schema')
        key = (case['uri'], case['profile'], case['rate_hz'], case['fixture'])
        require(key in grid and case['status'] == 'PASS', 'case_grid'); grid.remove(key)
        bank = case['uri'] == s.BANK
        fixture = case['fixture']
        role = fixture if bank and fixture in ('channel-exchange', 'sign-reversal', 'wet-amount-scaling') else 'repeat'
        require(case['pair_role'] == role and case['latency_frames'] is None and
                type(case['frames_per_instance']) is int and case['frames_per_instance'] == (24576 if bank else 32768),
                'case_metrics')
        peak = number(case['peak'], 0, 16 if bank else 10)
        rms = number(case['rms'], 0, peak)
        error = number(case['max_oracle_error'])
        if role == 'repeat':
            require(number(case['max_repeat_error']) <= 1e-6 + 1e-5 * peak, 'case_metrics')
        else: require(case['max_repeat_error'] is None, 'case_metrics')
        wet_energy = number(case['wet_energy'])
        require(type(case['wet_rms']) is list and len(case['wet_rms']) == 2, 'case_metrics')
        wet_rms = [number(x) for x in case['wet_rms']]
        hashes = case['sample_fnv1a64']
        require(type(hashes) is list and len(hashes) == 2 and
                all(type(x) is str and re.fullmatch('[0-9a-f]{16}', x) for x in hashes), 'case_metrics')
        if fixture == 'zero': require(peak <= 1e-7, 'case_metrics')
        if fixture in ('bypass', 'amount-zero'): require(error <= 1e-7 + 1e-5 / 16, 'case_metrics')
        if fixture.startswith('common-mode-'): require(error <= 1e-4 + 1e-3 / 16, 'case_metrics')
        if fixture in ('channel-exchange', 'sign-reversal'):
            require(error <= 1e-6 + 1e-5 * peak, 'case_metrics')
        if fixture == 'wet-amount-scaling':
            require(error <= 1e-6 + 1e-5 * (2 * peak + 1 / 16) and
                    all(x >= 1e-4 for x in wet_rms), 'case_metrics')
            stimulus_energy = 8192 * sum(x * x for x in wet_rms)
            # Nonnegative whole-run energy contains the stimulus subset. Allow
            # only conservative binary64 accumulation/RMS reconstruction roundoff:
            # 4*N*epsilon, N bounded by two channels' full sample count plus8 ops.
            operations = 2 * case['frames_per_instance'] + 8
            roundoff = 4 * operations * math.ulp(1.0) * max(wet_energy, stimulus_energy)
            require(wet_energy + roundoff >= stimulus_energy, 'case_metrics')
        else:
            require(wet_energy == 0 and wet_rms == [0, 0], 'case_metrics')
        if fixture in ('zero', 'configured', 'unequal'):
            require(error == 0, 'case_metrics')
        # Maxima/energy consistency are necessary metadata gates, not a replay
        # of the host's per-sample comparisons against each expected sample.
        if fixture in ('configured', 'unequal'):
            require(rms * rms * (16384 * 2 if bank else 32768) > 1e-20, 'case_metrics')
    require(not grid, 'case_grid')
    return value


def project_loader(raw, uri, library):
    c = common(); value = document(raw, 'loader')
    exact(value, ('schema_version', 'mode', 'status', 'selected_uris', 'descriptor_count', 'loaded_basenames',
                  'loaded_paths', 'failure_class', 'audio_devices', 'hardware', 'optimization_acceptance'))
    require(value['selected_uris'] == [uri] and type(value['descriptor_count']) is int and
            value['descriptor_count'] == 1 and value['audio_devices'] == 'NOT USED' and
            value['hardware'] == value['optimization_acceptance'] == 'NOT RUN', 'loader_schema')
    names, paths = value['loaded_basenames'], value['loaded_paths']
    require(type(names) is list and type(paths) is list and 0 < len(names) == len(paths) <= 128 and
            all(type(name) is str and c.NAME.fullmatch(name) for name in names) and
            len(names) == len(set(names)), 'loader_schema')
    libraries = []
    for name, actual in zip(names, paths):
        if name == 'linux-vdso.so.1':
            require(actual is None, 'loader_identity'); identity, digest = 'virtual/' + name, None
        else:
            require(type(actual) is str and len(actual) <= 4096 and actual.startswith('/'), 'loader_identity')
            path = Path(actual)
            require(path.resolve(strict=True) == path and path.is_file(), 'loader_identity')
            if path == library:
                require(name == library.name, 'loader_identity')
                identity = 'candidate/' + library.parent.name + '/' + library.name
            elif path == HOST: identity = 'host/host'
            else:
                require(path.is_relative_to('/usr/lib') and
                        all(c.NAME.fullmatch(part) for part in path.relative_to('/usr/lib').parts), 'loader_identity')
                identity = 'system/' + path.relative_to('/usr/lib').as_posix()
            digest = c.digest(path)
        require(identity not in {row['identity'] for row in libraries}, 'loader_identity')
        libraries.append({'identity': identity, 'sha256': digest})
    require('candidate/' + library.parent.name + '/' + library.name in {x['identity'] for x in libraries},
            'loader_identity')
    return {'status': 'PASS', 'selected_uris': [uri], 'descriptor_count': 1,
            'loaded_libraries': sorted(libraries, key=lambda row: row['identity'])}


def main():
    os.umask(0o077); c = common()
    report = {'schema_version': 1, 'status': 'FAIL', 'failure_class': None, 'stage': 'isolation'}
    before = None
    try:
        c.assert_isolation()
        require(c.mount_readonly('/held', Path('/proc/self/mountinfo').read_text()), 'isolation')
        report['stage'] = 'inventory_before'; before = c.inventory('inventory-before')
        report['inventory'] = {'count': 574, 'before_sha256': before, 'after_sha256': None, 'unchanged': False}
        report['stage'] = 'headers'; report['headers'] = {}
        for key, (path, expected) in c.HEADERS.items():
            actual = c.digest(path); require(actual == expected, 'header_hash'); report['headers'][key] = actual
        report['stage'] = 'candidates'; candidates = candidate_rows(); report['candidates'] = {}
        for row, library in candidates:
            expected = next(x['sha256'] for x in row['payload'] if x['path'] == '/' + row['elf_paths'][0])
            require(library.resolve(strict=True) == library and c.digest(library) == expected, 'candidate_hash')
            report['candidates'][row['name']] = expected
        report['stage'] = 'compile'; start = time.monotonic()
        flags = c.pkg_flags(c.command(['/usr/bin/pkg-config', '--cflags', '--libs', 'lilv-0'], 'pkg-config', 10))
        c.command(['/usr/bin/gcc', *c.FLAGS, str(SOURCE / 'host.c'), '-o', str(HOST), *flags, '-ldl', '-lm'],
                  'compile', 60 - (time.monotonic() - start))
        report['host'] = {'sha256': c.digest(HOST), 'source_sha256': c.digest(SOURCE / 'host.c'),
                          'compile_flags': c.FLAGS + flags + ['-ldl', '-lm'],
                          'compiler_sha256': c.digest('/usr/bin/gcc'), 'pkg_config_sha256': c.digest('/usr/bin/pkg-config'),
                          'readelf_sha256': c.digest('/usr/bin/readelf'), 'lilv_pc_sha256': c.digest('/usr/lib/pkgconfig/lilv-0.pc')}
        report['stage'] = 'elf'; checker = s.load('rust_checks', '/checks.py').elf_check
        report['elf'] = {'host': c.elf_observation(HOST, 'host', checker)}
        for row, library in candidates: report['elf'][row['name']] = c.elf_observation(library, row['name'], checker)
        report['stage'] = 'loader'; report['loader'] = {}
        for (row, library), uri in zip(candidates, s.URIS):
            report['loader'][row['name']] = project_loader(c.command(
                [str(HOST), '--loader', str(library), '--uri', uri], row['name'] + '-loader', 30, allowed=(0, 1)), uri, library)
        report['stage'] = 'processing'
        report['processing'] = project_processing(c.command([str(HOST), '--bundle', str(BUNDLE)],
                                                             'processing', 120, allowed=(0, 1)))
        report.update(status='PASS', stage='complete')
    except c.Failure as error: report['failure_class'] = error.code
    except Exception: report['failure_class'] = 'internal_error'
    finally:
        if before is not None:
            try:
                after = c.inventory('inventory-after')
                report['inventory'].update(after_sha256=after, unchanged=before == after)
                require(after == before, 'inventory_changed')
            except Exception: report.update(status='FAIL', stage='inventory_after', failure_class='inventory_changed')
    OUT.joinpath('observations.json').write_text(json.dumps(report, sort_keys=True, allow_nan=False) + '\n')
    return int(report['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
