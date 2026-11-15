# SPDX-License-Identifier: MIT
"""Narrow passive v2 outer/v1 executor joins; frozen prior readers stay unchanged."""
import importlib.util
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
PINS = {'bootstrap.py': '3bd3b507b4fd2148db679116c9a4eeb9f54cb780c5662608d059e223d2f6552d',
        'consumer.py': 'd1dff4ae3dde90e52ce702b19a781ec717b2446de5a8b03e44b4eea2f3a93a93'}
OUTER = 'perl5423-native-xs-v2'
INNER = 'perl5423-native-xs-v1'
MODE_PIN = dict(bytes=349767, sha256='7004309f83344b49f0f8ca598d8cefcffbc078450944824849ab9c575f1c0cd2')


def passive(name, scope, io):
    raw = io.read(BASE, name, 128*1024)
    io.need(io.pin(raw)['sha256'] == PINS[name], 'whole frozen passive classifier differs')
    spec = importlib.util.spec_from_file_location('xs_v2_' + scope, BASE / name)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(BASE / name), 'exec'), module.__dict__)
    return module


def mode_map(get, source_root, io):
    raw = io.read(source_root, 'accepted/runtime-files.json', 1024**2)
    io.need(io.pin(raw) == MODE_PIN, 'exact reviewed v2 runtime map')
    manifest = io.decode(raw)
    inputs = io.decode(get('bundle/xs-inputs.json'))
    preparation = io.decode(get('bundle/preparation.json'))
    io.need(manifest['schema'] == 1 and manifest['archive']['sha256'] == inputs['archive_sha256'] and
            manifest['files'] == inputs['files'] == preparation['files'] and
            preparation['runtime_manifest'] == MODE_PIN, 'actual complete prefix byte/mode map and preparation join')
    rows = manifest['files']
    modes = {mode: 0 for mode in (0o444, 0o555, 0o644, 0o755)}
    for name, row in rows.items():
        io.tick()
        io.need(type(row['mode']) is int and row['mode'] in modes, 'ordinary exact runtime file mode')
        modes[row['mode']] += 1
    io.need(len(rows) == 1870 and sum(row['bytes'] for row in rows.values()) == 74426813 and
            modes == {0o444: 1587, 0o555: 53, 0o644: 229, 0o755: 1}, 'exact reviewed namespace/bytes/mode distribution')
    return dict(manifest=MODE_PIN, files=1870, bytes=74426813, mode_policy='EXACT_PER_PATH_NO_NORMALIZATION')


def bootstrap(get, source_root, binding, source_map, io):
    io.need(binding['operation'] == OUTER, 'external binding must name the new outer v2 operation')
    outer = passive('bootstrap.py', 'outer_bootstrap', io)
    inner = passive('bootstrap.py', 'inner_producer', io)
    # Separate module globals retain every prior predicate. Only the outer
    # job/preparation names change; native producer argv and admission stay v1.
    outer.OPERATION = OUTER
    outer.producer = inner.producer
    context = outer.validate(get, source_root, binding, source_map, io)
    io.need(context['operation']['operation'] == INNER, 'outer v2 must delegate the frozen v1 executor')
    mode_map(get, source_root, io)
    return context


def inner_binding(binding, operation, io):
    io.need(binding['operation'] == OUTER and operation['operation'] == INNER,
            'only the explicit v2 outer/v1 inner operation projection is permitted')
    return dict(binding, operation=INNER)


def consumer(get, source_root, binding, context, io):
    projected = inner_binding(binding, context['operation'], io)
    original = passive('consumer.py', 'consumer', io)
    result = original.validate(get, source_root, projected, context, io)
    result['outer_operation'] = OUTER
    result['frozen_inner_operation'] = INNER
    result['reviewed_runtime_modes'] = mode_map(get, source_root, io)
    return result
