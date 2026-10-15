#!/usr/bin/env python3
"""Fixed graph load/activation trial; importing starts no actors."""
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import time

spec = importlib.util.spec_from_file_location('graph_support', Path(__file__).with_name('support.py'))
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)
SOURCE, OUT, CANDIDATE = Path('/source'), Path('/out'), Path('/candidate')
DATA, WORK, HOST = Path('/usr/share/asahi-audio'), Path('/tmp/offline'), Path('/tmp/offline/host')
ENGINE_PATHS = {'graph': '/usr/lib/spa-0.2/filter-graph/libspa-filter-graph.so',
                'builtin': '/usr/lib/spa-0.2/filter-graph/libspa-filter-graph-plugin-builtin.so',
                'lv2': '/usr/lib/spa-0.2/filter-graph/libspa-filter-graph-plugin-lv2.so'}
GRAPH_HEADERS = {
    'spa_graph': ('/usr/include/spa-0.2/spa/filter-graph/filter-graph.h', '01fddeb053e24b725d16974dee3ccc8207b7ca303ec3de3f398396007d5c4816'),
    'spa_json': ('/usr/include/spa-0.2/spa/utils/json.h', 'd33bbe7697b0b82efebe18e18853ad1c7cdfbd5eaba35ddd3ffb10b3fcdcd267'),
    'spa_json_core': ('/usr/include/spa-0.2/spa/utils/json-core.h', '7d3159cfad392742900f7d8e8a14130a589300fb73b835d706c34e9efb2ddbee'),
}
HOST_FAILURES = frozenset(('input', 'syntax', 'duplicate', 'trailing', 'metadata', 'missing_uri',
                          'port', 'control', 'fir_unavailable', 'fir_selection', 'load', 'activate',
                          'observe', 'library', 'readback', 'cleanup'))
NEGATIVES = {'malformed': 'syntax', 'duplicate': 'duplicate', 'trailing': 'trailing',
             'missingURI': 'missing_uri', 'invalidport': 'port', 'allFIRabsent': 'fir_unavailable',
             '48konlyabsent': 'fir_selection', 'unknowncontrol': 'control'}
GATES = ('full_input', 'unique_keys', 'metadata', 'ports', 'controls', 'volumes', 'activation',
         'stages', 'fir_selection', 'libraries', 'readback', 'retired')
COUNTS = ('nodes', 'lv2', 'builtin', 'convolvers', 'links', 'controls', 'readbacks')
CLEANUP = ('deactivated', 'graph_unloaded', 'children_unloaded', 'loop_destroyed')
STAGES = frozenset(('isolation', 'inventory_before', 'inputs', 'headers', 'compile', 'elf',
                    'parsing', 'host', 'complete', 'inventory_after'))
EXTRA_FAILURES = frozenset(('graph_schema', 'graph_equality', 'host_schema', 'host_expected',
                          'host_counts', 'host_gates', 'library_identity', 'fir_identity',
                          'fixture', 'inventory_changed', 'candidate_hash', 'header_hash',
                          'runtime_schema', 'case_grid', 'deadline', 'internal_error'))
SAFETY = {'audio_devices': 'NOT USED', 'hardware': 'NOT RUN', 'speakersafetyd': 'NOT RUN',
          'wireplumber': 'NOT RUN', 'processing': 'NOT RUN', 'ui_libraries': 'NOT OPENED',
          'new_package_builds': 0}


def common(): return s.held('container', Path('/held'))
def require(ok, code): common().require(ok, code)
def failure_codes(): return common().FAILURE_CODES | EXTRA_FAILURES | {'host_' + x for x in HOST_FAILURES}
def exact(value, keys, code='host_schema'):
    require(type(value) is dict and set(value) == set(keys), code)


def integer(value, low=0, high=4096):
    require(type(value) is int and low <= value <= high, 'host_schema')
    return value


def strict_json(raw):
    value = common().json_document(raw)
    def walk(item, depth=0):
        require(depth <= 64, 'graph_schema')
        if type(item) is dict:
            require(len(item) <= 1024 and all(type(k) is str and len(k) < 1024 for k in item), 'graph_schema')
            for entry in item.values(): walk(entry, depth + 1)
        elif type(item) is list:
            require(len(item) <= 1024, 'graph_schema')
            for entry in item: walk(entry, depth + 1)
        elif type(item) is int: require(abs(item) <= 2 ** 53, 'graph_schema')
        elif type(item) is float: require(math.isfinite(item), 'graph_schema')
        else: require(item is None or type(item) in (str, bool), 'graph_schema')
    walk(value)
    return value


def parse_graph(raw, case):
    value = strict_json(raw)
    # Python numeric equality equates bool/int and float/int. The typed encoding
    # check deliberately preserves JSON primitive types in this fixed projection.
    require(json.dumps(value, sort_keys=True, allow_nan=False) ==
            json.dumps(case['expected'], sort_keys=True, allow_nan=False), 'graph_equality')
    return {'id': case['id'], 'raw_sha256': case['raw_sha256'], 'status': 'PASS',
            'full_equality': True, 'converter': 'spa-json-dump'}


class Budget:
    def __init__(self, seconds, clock=time.monotonic):
        self.clock, self.end = clock, clock() + seconds

    def take(self, cap, reserve=0):
        available = self.end - self.clock() - reserve
        require(available > 0, 'deadline')
        return min(cap, available)


def command(args, name, cap, budget, allowed=(0,), group=None):
    limit = budget.take(cap, 20)  # Inventory-after/retirement remains possible.
    if group is not None: limit = min(limit, group.take(cap))
    return common().command(args, name, limit, allowed=allowed)


def regular(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.resolve(strict=True) == path, 'candidate_hash')
    return path


def payload_files():
    files, libraries = {}, {}
    for row in s.inputs()['packages']:
        if row['name'] == 'asahi-audio': continue
        for item in row['payload']:
            if item['type'] == 'file' and item['path'].startswith('/usr/lib/lv2/'):
                relative = item['path'][len('/usr/lib/lv2/'):]
                path = CANDIDATE / 'lv2' / relative
                files[path] = item['sha256']
                if path.name.endswith('.so') and 'ui' not in path.name.lower():
                    libraries[row['name']] = path
    for row in s.graphs()['cases']:
        relative = row['graph_path'][len('usr/share/asahi-audio/'):]
        files[CANDIDATE / 'data' / relative] = row['raw_sha256']
        files[DATA / relative] = row['raw_sha256']
    for row in s.graphs()['firs']:
        relative = row['path'].lstrip('/')[len('usr/share/asahi-audio/'):]
        files[CANDIDATE / 'data' / relative] = row['sha256']
        files[DATA / relative] = row['sha256']
    return files, libraries


def check_inputs():
    c = common(); files, libraries = payload_files()
    require(set(libraries) == {'bankstown', 'triforce-lv2', 'lsp-plugins-lv2'}, 'candidate_hash')
    for root in (CANDIDATE / 'lv2', CANDIDATE / 'data', DATA):
        require(root.is_dir() and not root.is_symlink(), 'candidate_hash')
        actual = set()
        for path in root.rglob('*'):
            require(not path.is_symlink() and (path.is_dir() or path.is_file()), 'candidate_hash')
            if path.is_file(): actual.add(path)
        require(actual == {p for p in files if p.is_relative_to(root)}, 'candidate_hash')
    for path, digest in files.items(): require(c.digest(regular(path)) == digest, 'candidate_hash')
    return files, libraries


def fixture(control, original, case):
    """Only a private copy changes; accepted graph/FIR trees stay read-only."""
    directory = WORK / control; directory.mkdir(mode=0o700)
    raw = original.read_bytes(); text = raw.decode('utf-8')
    if control == 'malformed':
        require(text.rstrip().endswith('}'), 'fixture'); text = text.rstrip()[:-1]
    elif control == 'duplicate':
        text = text.replace('{', '{"node.description":"duplicate",', 1)
    elif control == 'trailing': text += '\nTRAILING_TOKEN \n'
    elif control in ('missingURI', 'invalidport', 'unknowncontrol'):
        old, new = {'missingURI': ('https://chadmed.au/bankstown', 'urn:missing:offline-graph'),
                    'invalidport': ('ell:in', 'ell:nonexistent_port'),
                    'unknowncontrol': ('"bypass"', '"nonexistent_control"')}[control]
        require(text.count(old) == 1, 'fixture'); text = text.replace(old, new, 1)
    elif control in ('allFIRabsent', '48konlyabsent'):
        # Alter one convolver's exact candidate array, preserving other arrays.
        paths = case['expected']['filter.graph']['nodes'][3]['config']['filename']
        require(len(paths) == 4 and all('/j413/tweeters-' in p for p in paths), 'fixture')
        private = directory / 'data'; private.mkdir(mode=0o700)
        for old in paths:
            new = private / Path(old).name
            if control == '48konlyabsent' and not old.endswith('-48.wav'):
                shutil.copyfile(DATA / Path(old).relative_to('/usr/share/asahi-audio'), new)
                require(common().digest(new) == common().digest(old), 'fixture')
            require(text.count(old) >= 1, 'fixture')
            text = text.replace(old, str(new), 1)
    else: require(False, 'fixture')
    path = directory / 'graph.json'; path.write_text(text)
    return path


def public_library(path):
    path = Path(path); regular(path)
    if path.is_relative_to(CANDIDATE / 'lv2'):
        require('ui' not in path.name.lower(), 'library_identity')
        identity = 'candidate/' + path.relative_to(CANDIDATE / 'lv2').as_posix()
    else:
        require(path.is_relative_to('/usr/lib') and all(common().NAME.fullmatch(p) for p in
                path.relative_to('/usr/lib').parts), 'library_identity')
        identity = 'system/' + path.relative_to('/usr/lib').as_posix()
    return {'identity': identity, 'sha256': common().digest(path)}


def candidate_hashes():
    result = {}
    for row in s.inputs()['packages']:
        if row['name'] == 'asahi-audio': continue
        matches = [x for x in row['payload'] if x['type'] == 'file' and
                   x['path'].startswith('/usr/lib/lv2/') and x['path'].endswith('.so') and
                   'ui' not in Path(x['path']).name.lower()]
        require(len(matches) == 1, 'candidate_hash')
        result[row['name']] = {'identity': 'candidate/' + matches[0]['path'][len('/usr/lib/lv2/'):],
                               'sha256': matches[0]['sha256']}
    return result


def validate_flags(flags):
    prefix = ['-std=gnu11', *common().FLAGS[1:]]
    require(type(flags) is list and len(prefix) + 2 < len(flags) <= 64 and
            flags[:len(prefix)] == prefix and flags[-2:] == ['-ldl', '-lm'], 'runtime_schema')
    package_flags = flags[len(prefix):-2]
    require(all(type(v) is str and re.fullmatch(
            r'-I/usr/include(?:/[A-Za-z0-9_.+-]+)*|-L/usr/lib|-l[A-Za-z0-9_.+-]+|-D_REENTRANT', v)
            for v in package_flags) and all(v in package_flags for v in
            ('-lpipewire-0.3', '-llilv-0', '-lserd-0')), 'runtime_schema')


def validate_projected_host(row, case, expect):
    exact(row, ('schema', 'status', 'failure_class', 'case', 'expect', 'rate', 'process_calls',
                'counts', 'gates', 'stage_names', 'fir_selections', 'libraries', 'cleanup', 'raw_sha256'))
    require(row['schema'] == 'asahi-audio-offline-graph-host-v1' and row['case'] == case['id'] and
            row['expect'] == expect and type(row['rate']) is int and row['rate'] == 48000 and
            type(row['process_calls']) is int and row['process_calls'] == 0 and
            type(row['raw_sha256']) is str and common().SHA.fullmatch(row['raw_sha256']), 'host_schema')
    exact(row['gates'], GATES); exact(row['cleanup'], CLEANUP); exact(row['counts'], COUNTS)
    for value in row['counts'].values(): integer(value)
    require(all(type(x) is bool for x in [*row['gates'].values(), *row['cleanup'].values()]) and
            all(row['cleanup'].values()) and row['gates']['retired'], 'host_gates')
    require(type(row['stage_names']) is list and len(row['stage_names']) <= 32 and
            all(type(x) is str and common().NAME.fullmatch(x) for x in row['stage_names']) and
            len(set(row['stage_names'])) == len(row['stage_names']), 'host_schema')
    if expect == 'positive':
        controls = 326 if case['kind'] == 'graph' else 57
        require(row['raw_sha256'] == case['raw_sha256'] and row['status'] == 'PASS' and
                row['failure_class'] is None and all(row['gates'].values()), 'host_gates')
        require(row['counts'] == {'nodes': case['nodes'], 'lv2': case['lv2_instances'],
                'builtin': case['builtin_instances'], 'convolvers': case['convolvers'],
                'links': case['links'], 'controls': controls, 'readbacks': controls} and
                set(row['stage_names']) == {x['name'] for x in case['expected']['filter.graph']['nodes']}, 'host_counts')
    else:
        require(expect in NEGATIVES and row['status'] == 'FAIL' and row['failure_class'] == NEGATIVES[expect] and
                not all(row['gates'].values()) and row['raw_sha256'] != case['raw_sha256'], 'host_expected')
    require(type(row['libraries']) is list and len(row['libraries']) <= 128, 'library_identity')
    candidates = candidate_hashes(); identities = set()
    for library in row['libraries']:
        exact(library, ('identity', 'sha256'))
        identity = library['identity']
        require(type(identity) is str and len(identity) <= 512 and identity not in identities and
                type(library['sha256']) is str and common().SHA.fullmatch(library['sha256']), 'library_identity')
        identities.add(identity)
        if identity.startswith('candidate/'):
            require(library in candidates.values(), 'library_identity')
        else:
            require(identity.startswith('system/') and all(common().NAME.fullmatch(p) and p not in ('.', '..')
                    for p in identity[len('system/'):].split('/')), 'library_identity')
    if expect == 'positive':
        names = ('bankstown', 'lsp-plugins-lv2') if case['kind'] == 'graph' else ('triforce-lv2',)
        require({x for x in identities if x.startswith('candidate/')} ==
                {candidates[name]['identity'] for name in names} and
                {'system/' + str(Path(p).relative_to('/usr/lib')) for p in ENGINE_PATHS.values()} <= identities,
                'library_identity')
    require(type(row['fir_selections']) is list and len(row['fir_selections']) <= 4, 'fir_identity')
    firs = {x['path'].lstrip('/'): x for x in s.graphs()['firs']}; nodes = set()
    for selection in row['fir_selections']:
        exact(selection, ('node', 'identity', 'rate', 'sha256'))
        identity = selection['identity']
        require(type(selection['node']) is str and selection['node'] not in nodes and
                type(identity) is str and identity in firs and selection['sha256'] == firs[identity]['sha256'] and
                type(selection['rate']) is int and selection['rate'] == firs[identity]['sample_rate'], 'fir_identity')
        nodes.add(selection['node'])
    if expect == 'positive':
        expected = {x['name']: next(p.lstrip('/') for p in x['config']['filename'] if p.endswith('-48.wav'))
                    for x in case['expected']['filter.graph']['nodes'] if x.get('label') == 'convolver'}
        require({x['node']: x['identity'] for x in row['fir_selections']} == expected and
                all(x['rate'] == 48000 for x in row['fir_selections']), 'fir_identity')
    return row


def project_host(raw, case, expect, graph, libraries):
    value = strict_json(raw)
    exact(value, ('schema', 'status', 'failure_class', 'case', 'expect', 'rate', 'process_calls',
                  'counts', 'gates', 'stage_names', 'fir_selections', 'libraries', 'cleanup'))
    require(value['schema'] == 'asahi-audio-offline-graph-host-v1' and value['case'] == case['id'] and
            value['expect'] == expect and type(value['rate']) is int and value['rate'] == 48000 and
            type(value['process_calls']) is int and value['process_calls'] == 0, 'host_schema')
    exact(value['counts'], COUNTS); exact(value['gates'], GATES); exact(value['cleanup'], CLEANUP)
    for number in value['counts'].values(): integer(number)
    require(all(type(v) is bool for v in list(value['gates'].values()) + list(value['cleanup'].values())) and
            all(value['cleanup'].values()) and value['gates']['retired'], 'host_gates')
    require(type(value['stage_names']) is list and len(value['stage_names']) <= 32 and
            all(type(x) is str and common().NAME.fullmatch(x) for x in value['stage_names']) and
            len(set(value['stage_names'])) == len(value['stage_names']), 'host_schema')
    if expect == 'positive':
        require(value['status'] == 'PASS' and value['failure_class'] is None and
                all(value['gates'].values()), 'host_gates')
        controls = 326 if case['kind'] == 'graph' else 57
        require(value['counts'] == {'nodes': case['nodes'], 'lv2': case['lv2_instances'],
                'builtin': case['builtin_instances'], 'convolvers': case['convolvers'],
                'links': case['links'], 'controls': controls, 'readbacks': controls}, 'host_counts')
        require(set(value['stage_names']) == {x['name'] for x in case['expected']['filter.graph']['nodes']},
                'host_counts')
    else:
        require(expect in NEGATIVES and value['status'] == 'FAIL' and
                value['failure_class'] == NEGATIVES[expect] and not all(value['gates'].values()), 'host_expected')
    require(type(value['libraries']) is list and len(value['libraries']) <= 128 and
            all(type(x) is str for x in value['libraries']) and
            len(set(value['libraries'])) == len(value['libraries']), 'library_identity')
    observed = [public_library(path) for path in value['libraries']]
    require(len({x['identity'] for x in observed}) == len(observed), 'library_identity')
    allowed = {path: common().digest(path) for path in libraries.values()}
    for path in value['libraries']:
        if Path(path).is_relative_to(CANDIDATE):
            require(Path(path) in allowed and common().digest(path) == allowed[Path(path)], 'library_identity')
    if expect == 'positive':
        chosen = {libraries['bankstown'], libraries['lsp-plugins-lv2']} if case['kind'] == 'graph' else {libraries['triforce-lv2']}
        require({Path(p) for p in value['libraries'] if Path(p).is_relative_to(CANDIDATE)} == chosen and
                set(ENGINE_PATHS.values()) <= set(value['libraries']), 'library_identity')
    require(type(value['fir_selections']) is list and len(value['fir_selections']) <= 4, 'fir_identity')
    selections = []
    fir_map = {row['path'].lstrip('/'): row['sha256'] for row in s.graphs()['firs']}
    for row in value['fir_selections']:
        exact(row, ('node', 'path', 'rate')); integer(row['rate'], 1, 384000)
        require(type(row['node']) is str and type(row['path']) is str, 'fir_identity')
        path = Path(row['path']); regular(path)
        if path.is_relative_to(DATA): identity = path.relative_to('/').as_posix()
        else:
            require(expect in ('allFIRabsent', '48konlyabsent') and
                    path.is_relative_to(WORK / expect / 'data'), 'fir_identity')
            identity = 'usr/share/asahi-audio/' + case['model'] + '/' + path.name
        require(identity in fir_map and common().digest(path) == fir_map[identity], 'fir_identity')
        selections.append({'node': row['node'], 'identity': identity, 'rate': row['rate'], 'sha256': fir_map[identity]})
    require(len({x['node'] for x in selections}) == len(selections), 'fir_identity')
    if expect == 'positive':
        expected = {x['name']: next(p.lstrip('/') for p in x['config']['filename'] if p.endswith('-48.wav'))
                    for x in case['expected']['filter.graph']['nodes'] if x.get('label') == 'convolver'}
        require({x['node']: x['identity'] for x in selections} == expected and
                all(x['rate'] == 48000 for x in selections), 'fir_identity')
    value['libraries'] = sorted(observed, key=lambda x: x['identity']); value['fir_selections'] = selections
    value['raw_sha256'] = common().digest(graph)
    return validate_projected_host(value, case, expect)


def validate_public(value):
    """Pure closed projection, also reused by the outer caller; no runtime actors."""
    exact(value, ('schema_version', 'status', 'failure_class', 'stage', 'inventory', 'headers', 'tools',
                  'engines', 'candidates', 'host', 'elf', 'parsing', 'positive_cases', 'negative_controls',
                  'host_children', 'converter_children', 'safety'), 'runtime_schema')
    require(type(value['schema_version']) is int and value['schema_version'] == 1 and
            type(value['stage']) is str and value['stage'] in STAGES and value['status'] in ('PASS', 'FAIL') and
            json.dumps(value['safety'], sort_keys=True) == json.dumps(SAFETY, sort_keys=True),
            'runtime_schema')
    require(value['failure_class'] is None if value['status'] == 'PASS' else
            type(value['failure_class']) is str and value['failure_class'] in failure_codes(), 'runtime_schema')
    integer(value['host_children'], 0, 12); integer(value['converter_children'], 0, 4)
    for key in ('parsing', 'positive_cases', 'negative_controls'):
        require(type(value[key]) is list and len(value[key]) <= (8 if key == 'negative_controls' else 4), 'runtime_schema')
    require(value['inventory'] is None or type(value['inventory']) is dict, 'runtime_schema')
    if value['inventory'] is not None:
        exact(value['inventory'], ('count', 'before_sha256', 'after_sha256', 'unchanged'), 'runtime_schema')
        require(type(value['inventory']['count']) is int and value['inventory']['count'] == 574 and
                type(value['inventory']['unchanged']) is bool and
                value['inventory']['before_sha256'] == s.LOCK and
                (value['inventory']['after_sha256'] is None or
                 type(value['inventory']['after_sha256']) is str and common().SHA.fullmatch(value['inventory']['after_sha256'])),
                'runtime_schema')
    for key in ('headers', 'tools', 'engines', 'candidates', 'elf'):
        require(type(value[key]) is dict, 'runtime_schema')
    expected_headers = {k: digest for k, (_, digest) in {**common().HEADERS, **GRAPH_HEADERS}.items()}
    expected_candidates = {k: v['sha256'] for k, v in candidate_hashes().items()}
    for key, expected in (('headers', expected_headers), ('candidates', expected_candidates)):
        require(set(value[key]) <= set(expected) and all(v == expected[k] for k, v in value[key].items()), 'runtime_schema')
    for key, keys in (('tools', {'gcc', 'pkg-config', 'readelf', 'spa-json-dump'}), ('engines', set(ENGINE_PATHS))):
        require(set(value[key]) <= keys and all(type(v) is str and common().SHA.fullmatch(v) for v in value[key].values()),
                'runtime_schema')
    require(value['host'] is None or type(value['host']) is dict, 'runtime_schema')
    if value['host'] is not None:
        exact(value['host'], ('sha256', 'source_sha256', 'compile_flags'), 'runtime_schema')
        require(all(type(value['host'][k]) is str and common().SHA.fullmatch(value['host'][k])
                    for k in ('sha256', 'source_sha256')) and
                value['host']['source_sha256'] == s.sha(s.HERE / 'host.c'),
                'runtime_schema')
        validate_flags(value['host']['compile_flags'])
    require(set(value['elf']) <= {'host', *ENGINE_PATHS, *expected_candidates}, 'runtime_schema')
    for key, row in value['elf'].items():
        exact(row, ('class', 'machine', 'needed', 'path_tags', 'version_requirements', 'sha256',
                    'load_segments', 'structural_16k', 'hardware_status'), 'runtime_schema')
        require(row['class'] == 'ELF64' and row['machine'] == 'AArch64' and row['path_tags'] == [] and
                row['structural_16k'] == 'PASS' and row['hardware_status'] == 'NOT RUN' and
                type(row['sha256']) is str and common().SHA.fullmatch(row['sha256']), 'runtime_schema')
        integer(row['load_segments'], 1, 128)
        for field in ('needed', 'version_requirements'):
            require(type(row[field]) is list and len(row[field]) <= 128 and
                    all(type(v) is str and common().NAME.fullmatch(v) for v in row[field]) and
                    len(set(row[field])) == len(row[field]), 'runtime_schema')
        if key in expected_candidates: require(row['sha256'] == expected_candidates[key], 'candidate_hash')
        if key in ENGINE_PATHS: require(row['sha256'] == value['engines'].get(key), 'library_identity')
        if key == 'host': require(value['host'] is not None and row['sha256'] == value['host']['sha256'], 'runtime_schema')
    for row in value['parsing']:
        exact(row, ('id', 'raw_sha256', 'status', 'full_equality', 'converter'), 'runtime_schema')
        require(type(row['id']) is str and row['id'] in s.cases() and row['raw_sha256'] == s.cases()[row['id']]['raw_sha256'] and
                row['status'] == 'PASS' and row['full_equality'] is True and row['converter'] == 'spa-json-dump', 'graph_equality')
    for row in value['positive_cases']:
        require(type(row) is dict and type(row.get('case')) is str and row['case'] in s.cases(), 'case_grid')
        validate_projected_host(row, s.cases()[row['case']], 'positive')
        by_identity = {x['identity']: x['sha256'] for x in row['libraries']}
        for key, path in ENGINE_PATHS.items():
            require(by_identity['system/' + str(Path(path).relative_to('/usr/lib'))] == value['engines'].get(key),
                    'library_identity')
    for row in value['negative_controls']:
        require(type(row) is dict and type(row.get('expect')) is str and row['expect'] in NEGATIVES, 'case_grid')
        validate_projected_host(row, s.cases()['j413-speakers'], row['expect'])
    if value['status'] == 'PASS':
        require(value['stage'] == 'complete' and value['host_children'] == 12 and value['converter_children'] == 4,
                'case_grid')
        require(value['headers'] == expected_headers and value['candidates'] == expected_candidates and
                set(value['engines']) == set(ENGINE_PATHS) and set(value['tools']) ==
                {'gcc', 'pkg-config', 'readelf', 'spa-json-dump'} and value['host'] is not None and
                set(value['elf']) == {'host', *ENGINE_PATHS, *expected_candidates}, 'runtime_schema')
        exact(value['inventory'], ('count', 'before_sha256', 'after_sha256', 'unchanged'), 'runtime_schema')
        require(type(value['inventory']['count']) is int and value['inventory']['count'] == 574 and
                value['inventory']['before_sha256'] == value['inventory']['after_sha256'] == s.LOCK and
                value['inventory']['unchanged'] is True, 'inventory_changed')
        require({x.get('id') for x in value['parsing']} == set(s.cases()) and
                len(value['parsing']) == 4 and {x.get('case') for x in value['positive_cases']} == set(s.cases()) and
                len(value['positive_cases']) == 4 and {x.get('expect') for x in value['negative_controls']} == set(NEGATIVES) and
                len(value['negative_controls']) == 8, 'case_grid')
    return value


def main():
    os.umask(0o077); c = common(); budget = Budget(420)
    report = dict(schema_version=1, status='FAIL', failure_class=None, stage='isolation', inventory=None,
                  headers={}, tools={}, engines={}, candidates={}, host=None, elf={}, parsing=[],
                  positive_cases=[], negative_controls=[], host_children=0, converter_children=0, safety=SAFETY)
    before = None
    try:
        c.assert_isolation()
        mounts = Path('/proc/self/mountinfo').read_text()
        require(c.mount_readonly('/held', mounts) and c.mount_readonly(str(DATA), mounts), 'isolation')
        report['stage'] = 'inventory_before'; before = c.inventory('inventory-before')
        report['inventory'] = dict(count=574, before_sha256=before, after_sha256=None, unchanged=False)
        report['stage'] = 'inputs'; files, libraries = check_inputs()
        report['candidates'] = {name: c.digest(path) for name, path in libraries.items()}
        for key, path in ENGINE_PATHS.items(): report['engines'][key] = c.digest(regular(path))
        report['stage'] = 'headers'
        for key, (path, expected) in {**c.HEADERS, **GRAPH_HEADERS}.items():
            report['headers'][key] = c.digest(path); require(report['headers'][key] == expected, 'header_hash')
        for name in ('gcc', 'pkg-config', 'readelf', 'spa-json-dump'):
            report['tools'][name] = c.digest('/usr/bin/' + name)
        report['stage'] = 'compile'; compile_budget = Budget(60)
        raw = command(['/usr/bin/pkg-config', '--cflags', '--libs', 'libpipewire-0.3', 'lilv-0', 'serd-0'],
                      'pkg-config', 10, budget, group=compile_budget)
        import shlex
        flags = shlex.split(raw.decode('ascii'))
        require(0 < len(flags) <= 40 and all(re.fullmatch(
                r'-I/usr/include(?:/[A-Za-z0-9_.+-]+)*|-L/usr/lib|-l[A-Za-z0-9_.+-]+|-D_REENTRANT', flag)
                for flag in flags) and all(flag in flags for flag in ('-lpipewire-0.3', '-llilv-0', '-lserd-0')), 'pkg_config')
        compile_flags = ['-std=gnu11', *c.FLAGS[1:]]
        command(['/usr/bin/gcc', *compile_flags, str(SOURCE / 'host.c'), '-o', str(HOST), *flags, '-ldl', '-lm'],
                'compile', 60, budget, group=compile_budget)
        report['host'] = {'sha256': c.digest(HOST), 'source_sha256': c.digest(SOURCE / 'host.c'),
                          'compile_flags': compile_flags + flags + ['-ldl', '-lm']}
        report['stage'] = 'elf'; checker = s.load('graph_checks', '/checks.py').elf_check
        # The held ELF primitive caps its own child at15s. Debit the full7-call
        # maximum before entering it; later guarded actors use the real clock.
        budget.take(1, 20 + 15 * 7)
        for name, path in [('host', HOST), *libraries.items(), *ENGINE_PATHS.items()]:
            report['elf'][name] = c.elf_observation(path, 'graph-' + name, checker)
        report['stage'] = 'parsing'
        for case in s.cases().values():
            path = CANDIDATE / 'data' / Path(case['graph_path']).relative_to('usr/share/asahi-audio')
            raw = command(['/usr/bin/spa-json-dump', str(path)], 'parse-' + case['id'], 5, budget)
            report['converter_children'] += 1; report['parsing'].append(parse_graph(raw, case))
        report['stage'] = 'host'; children = Budget(360)
        invocations = [(case, 'positive', CANDIDATE / 'data' / Path(case['graph_path']).relative_to('usr/share/asahi-audio'))
                       for case in s.cases().values()]
        case = s.cases()['j413-speakers']
        original = CANDIDATE / 'data' / Path(case['graph_path']).relative_to('usr/share/asahi-audio')
        for name in s.CONTROLS: invocations.append((case, name, fixture(name, original, case)))
        for case, expect, path in invocations:
            raw = command([str(HOST), '--graph', str(path), '--case', case['id'], '--expect', expect],
                          'host-' + (case['id'] if expect == 'positive' else expect), 30, budget,
                          allowed=(0, 1), group=children)
            report['host_children'] += 1
            row = project_host(raw, case, expect, path, libraries)
            report['positive_cases' if expect == 'positive' else 'negative_controls'].append(row)
        require(all(c.digest(path) == digest for path, digest in files.items()), 'candidate_hash')
        report.update(status='PASS', stage='complete')
    except c.Failure as error: report['failure_class'] = error.code
    except Exception: report['failure_class'] = 'internal_error'
    finally:
        if before is not None:
            try:
                after = c.inventory('inventory-after')
                report['inventory'].update(after_sha256=after, unchanged=after == before)
                require(after == before, 'inventory_changed')
            except Exception: report.update(status='FAIL', stage='inventory_after', failure_class='inventory_changed')
    try: validate_public(report)
    except c.Failure as error: report.update(status='FAIL', failure_class=error.code)
    OUT.joinpath('observations.json').write_text(json.dumps(report, sort_keys=True, allow_nan=False) + '\n')
    return int(report['status'] != 'PASS')


if __name__ == '__main__': raise SystemExit(main())
