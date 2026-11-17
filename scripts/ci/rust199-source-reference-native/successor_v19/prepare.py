#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Separate project TEST Source constructor; no native actor or authority role."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import resource
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def module(name, path, digest=None):
    raw = path.read_bytes()
    if digest is not None and hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('immutable constructor dependency differs')
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


fs = module('v19_source_filesystem', HERE.parent / 'filesystem.py',
            '7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7')
fs.MAX_FILES = 512
D = module('v19_operational_delta', HERE / 'delta.py')
A = module('v19_project_admission', HERE.parent / 'project_test_provider_v1/admission.py',
           '5fa246f5b23152aeb2833ebb1f33e30d94149ee71796c1b85366c037a1e1b9f9')
PARENT = dict(files=367, bytes=43757093, tree='f846369139e03239d500cb737092b5eeb358c260',
              map_sha256='189430cae42422e8f50d8de38a41976d87a8b4a0fcec527a3949d6031eccc2f6')
ACTUAL = dict.fromkeys(('source', 'ref', 'run', 'job', 'approval', 'artifact', 'image'))
SCOPE = 'RUST199_PROJECT_TEST_PROVIDER_SUCCESSOR_V19'
MARKER = 'project-test-providers-v19.json'
ARCHIVE = 'previous-project-test-v19/'
REPLACED = {'hosted/bootstrap.py', 'hosted/qualification.py', 'actor/qualify.py'}
CONFIG = 'hosted/project-test-provider.json'
BRIDGE = 'hosted/project_provider.py'
SELECTION_PATHS = {'policy': 'project-test/provider-policy.json',
                   'decision': 'project-test/Root-provider-decision.json'}
PREDECESSOR_PIN = '2748685ec2b6b1cf966681b0c875e6ef591a7953a63296512c5329903ad20d0a'
encode = A.encode


def identity(files):
    return dict(files=len(files), bytes=sum(len(raw) for raw, mode in files.values()),
                tree=fs.tree(files), map_sha256=fs.pin(files['source-map.json'][0])['sha256'])


def census(files):
    fs.need(len(files) <= fs.MAX_FILES and sum(len(raw) for raw, mode in files.values()) <= fs.MAX_TOTAL,
            'unchanged finite Source file/byte caps')
    for name, (raw, mode) in files.items():
        fs.relative(name)
        fs.need(type(raw) is bytes and 0 < len(raw) <= fs.MAX_FILE and type(mode) is int
                and mode in (0o644, 0o755), 'bounded whole Source bytes/modes')
    fs.tree(files)  # Also rejects file/directory namespace collisions.


def capture(root):
    files = fs.snapshot(root)
    fs.need(identity(files) == PARENT, 'whole genuine367 parent bytes/modes/tree/map')
    mapping = fs.decode(files['source-map.json'][0])
    fs.need(mapping['actual'] == ACTUAL and mapping['files'] == fs.descriptors(
        {n: row for n, row in files.items() if n != 'source-map.json'}), 'complete367 parent census')
    return files


def embedded():
    raw, mode = fs.read(HERE / 'predecessors.DATA.json')
    fs.need(mode == 0o644 and fs.pin(raw)['sha256'] == PREDECESSOR_PIN,
            'immutable14dd interface and passive8128 dependency pins')
    pins = fs.decode(raw); files = {}
    for name, wanted in pins.items():
        fs.relative(name); files[name] = fs.read(ROOT / name)
    fs.need(fs.descriptors(files) == pins, 'all exact immutable embedded helper bytes/modes')
    return files


def config(selection):
    fs.need(type(selection) is dict and set(selection) == set(SELECTION_PATHS),
            'explicit independently profiled policy and Root decision operands')
    for key, path in SELECTION_PATHS.items():
        A.reference(selection[key], A.D.MIB)
        fs.need(selection[key]['path'] == path, 'fixed separate project TEST selection namespace')
    return dict(schema=19, kind='RUST19_PROJECT_TEST_PROVIDER_BINDING_V1', **selection)


def required_inputs(files, selection):
    """Enumerate every original receipt operand; no status-only native shortcut."""
    config(selection); census(files); required = {}

    def put(name, wanted=None):
        fs.relative(name)
        fs.need(name in files and files[name][1] == 0o644, 'complete ordinary provider input: ' + name)
        raw = files[name][0]
        if wanted is not None:
            fs.need(fs.pin(raw) == wanted, 'whole provider operand pin: ' + name)
        required[name] = files[name]
        return raw

    def reference(row):
        A.reference(row)
        return put(row['path'], {k: row[k] for k in ('bytes', 'sha256')})

    put('expected349.lock')
    policy_raw = reference(selection['policy']); decision_raw = reference(selection['decision'])
    p = A.validate_policy(A.decode(policy_raw))
    fs.need(policy_raw == encode(p), 'canonical project provider policy')
    decision = A.decode(decision_raw)
    fs.need(decision_raw == encode(decision), 'canonical external Root decision')
    reference(p['trust']['public_key'])
    for row in p['packages']:
        for name, wanted in ((row['filename'], row['archive']), (row['filename'] + '.sig', row['signature'])):
            put('build-dependencies/' + name, wanted)
        q = row['license_provenance']; reference(q['pkgbuild'])
        for field in ('recipe_files', 'license_files', 'sources'):
            for name, wanted in q[field].items():
                put(name, {k: wanted[k] for k in ('bytes', 'sha256')})
        native = row['native']
        fs.need(type(native) is dict and set(native) == {'builds', 'comparison'}
                and type(native['builds']) is list and len(native['builds']) == 2, 'both complete native build references')
        reference(native['comparison'])
        for build in native['builds']:
            fs.need(type(build) is dict and set(build) == {'provenance', 'validation'}, 'whole native build pair')
            record = A.decode(reference(build['provenance'])); reference(build['validation'])
            folder = PurePosixPath(build['provenance']['path']).parent
            fs.need(type(record.get('files')) is dict and 1 <= len(record['files']) <= 1024,
                    'complete original native evidence census')
            for name, digest in record['files'].items():
                fs.relative(name); raw = put(str(folder / name))
                fs.need(A.D.sha(digest) and fs.pin(raw)['sha256'] == digest, 'whole native retained evidence hash')
            prefix = PurePosixPath(q['pkgbuild']['path']).parent
            for name, wanted in q['recipe_files'].items():
                relative = PurePosixPath(name).relative_to(prefix)
                put(str(folder / 'inputs' / relative), wanted)
    fs.need(set(files) == set(required), 'closed complete provider input census; no missing or unlisted operands')
    return p


def bridge(config_raw):
    files = fs.snapshot(HERE / 'payload')
    fs.need(set(files) == {BRIDGE} and files[BRIDGE][1] == 0o644, 'one exact separate project bridge template')
    raw = files[BRIDGE][0]
    fs.need(raw.count(b'CONFIG_PIN=None') == 1, 'unique explicit unbound bridge config sentinel')
    return raw.replace(b'CONFIG_PIN=None', b'CONFIG_PIN=' + repr(fs.pin(config_raw)).encode()), 0o644


def payload(input_root, selection, *, now=None):
    files = fs.snapshot(input_root); required_inputs(files, selection)
    state = A.admit(input_root, files[selection['policy']['path']][0], selection['policy']['sha256'],
                    files[selection['decision']['path']][0], selection['decision']['sha256'], now=now)
    fs.need(state['signature_mathematics_verified'] is False and state['native_acceptance'] is False
            and state['Root_acceptance'] is None, 'DATA admission grants no runtime/native/signature credit')
    cfg = encode(config(selection)); result = D.payload_leaves()
    additions = {n: row for n, row in files.items() if n != 'expected349.lock'}
    for rows in (embedded(), {CONFIG: (cfg, 0o644), BRIDGE: bridge(cfg)}, additions):
        fs.need(not set(rows) & set(result), 'unique separate project provider namespace'); result.update(rows)
    census(result)
    return result


def inspect_payload(before, new, provider_inputs, selection):
    fs.need({n: new[n] for n in REPLACED} == D.render_leaves(before), 'exact finite project operational delta')
    cfg = encode(config(selection)); helpers = embedded()
    fs.need(new[CONFIG] == (cfg, 0o644) and new[BRIDGE] == bridge(cfg)
            and all(new[n] == row for n, row in helpers.items()), 'whole exact scoped runtime/helper projection')
    files = {n: before[n] if n == 'expected349.lock' else new[n] for n in provider_inputs}
    fs.need(fs.descriptors(files) == provider_inputs, 'complete selected provider Source lock')
    required_inputs(files, selection)
    fs.need(set(new) == REPLACED | {CONFIG, BRIDGE} | set(helpers) | (set(files) - {'expected349.lock'}),
            'only complete explicit operational/provider additions')
    fs.need(all(mode == 0o644 for raw, mode in new.values()), 'ordinary project provider Source modes')


def marker(before, new, provider_inputs, selection):
    return dict(schema=19, scope=SCOPE, parent=PARENT, actual=ACTUAL, selection=selection,
                provider_inputs=provider_inputs, changes={n: dict(before=fs.descriptors({n: before[n]})[n]
                if n in before else None, after=fs.descriptors({n: row})[n]) for n, row in sorted(new.items())},
                added=sorted(set(new) - REPLACED), archives=sorted(ARCHIVE + n for n in REPLACED | {'source-map.json'}),
                project_TEST_only=True, ALARM_authentication=False, makepkg_dependency_checks_preserved=True,
                resources_changed=False, authority_changed=False, workflows_changed=False, HTTP_changed=False,
                signed349_changed=False, recipe_changed=False, kernel_preentry_required=True, holds_preserved=True,
                unadmitted=True, Root_grants=None, dispatch=None, native_acceptance=False, Root_acceptance=None)


def render(before, new):
    fs.need(identity(before) == PARENT, 'exact367 parent only')
    cfg = A.decode(new[CONFIG][0]); selection = {k: cfg[k] for k in SELECTION_PATHS}
    additions = set(new) - REPLACED
    fs.need(not additions & set(before) and MARKER not in before
            and not any(n.startswith(ARCHIVE) for n in before), 'fresh separate project TEST namespace')
    helper_names = set(embedded()) | {CONFIG, BRIDGE} | REPLACED
    inputs = {n: row for n, row in new.items() if n not in helper_names}
    inputs['expected349.lock'] = before['expected349.lock']; provider_inputs = fs.descriptors(inputs)
    inspect_payload(before, new, provider_inputs, selection)
    files = dict(before)
    for name in REPLACED | {'source-map.json'}: files[ARCHIVE + name] = before[name]
    files.update(new); files[MARKER] = (encode(marker(before, new, provider_inputs, selection)), 0o644)
    mapping = fs.decode(before['source-map.json'][0])
    mapping['files'] = fs.descriptors({n: row for n, row in files.items() if n != 'source-map.json'})
    files['source-map.json'] = (encode(mapping), 0o644); census(files)
    fs.need(undo(files) == before, 'whole exact byte/mode inverse to367')
    return files


def undo(files):
    census(files); m = fs.decode(files[MARKER][0]); old_map = files[ARCHIVE + 'source-map.json']
    old = fs.decode(old_map[0]); expected = set(old['files']) | {'source-map.json'}
    new = {n: files[n] for n in m['changes']}
    extras = (set(new) - REPLACED) | {MARKER} | {ARCHIVE + n for n in REPLACED | {'source-map.json'}}
    fs.need(set(files) == expected | extras, 'whole closed successor Source namespace')
    restored = {n: row for n, row in files.items() if n in expected}
    for name in REPLACED | {'source-map.json'}: restored[name] = files[ARCHIVE + name]
    fs.need(identity(restored) == PARENT and old['files'] == fs.descriptors(
        {n: row for n, row in restored.items() if n != 'source-map.json'}), 'all367 prior bytes/modes restored')
    inspect_payload(restored, new, m['provider_inputs'], m['selection'])
    fs.need(files[MARKER] == (encode(marker(restored, new, m['provider_inputs'], m['selection'])), 0o644),
            'canonical whole unissued project provider inverse marker')
    mapping = fs.decode(files['source-map.json'][0]); want = dict(old)
    want['files'] = fs.descriptors({n: row for n, row in files.items() if n != 'source-map.json'})
    fs.need(files['source-map.json'] == (encode(want), 0o644) and mapping['actual'] == ACTUAL,
            'complete canonical current Source census and unchanged metadata')
    return restored


def inputs():
    return fs.descriptors({n: row for n, row in fs.snapshot(HERE).items()
                           if n not in ('constructor-profile.json', 'development-seal.DATA.json')})


def construct(parent, input_root, output, profile, expected_sha256, *, now=None):
    parent, input_root, output, profile = map(fs.absolute, (parent, input_root, output, profile))
    fs.need(not any(output.is_relative_to(p) or p.is_relative_to(output) for p in (parent, input_root, HERE))
            and not profile.is_relative_to(output), 'fresh disjoint Source DATA output')
    raw, mode = fs.read(profile, A.D.MIB)
    fs.need(mode == 0o644 and A.D.sha(expected_sha256) and fs.pin(raw)['sha256'] == expected_sha256,
            'external whole constructor profile SHA')
    p = fs.decode(raw)
    fs.need(raw == encode(p) and set(p) == {'schema', 'scope', 'parent', 'actual', 'Root_review', 'accepted',
        'unadmitted', 'constructor_files', 'provider_inputs', 'selection', 'files', 'bytes', 'tree', 'map_sha256'}
        and type(p['schema']) is int and p['schema'] == 19 and p['scope'] == SCOPE and p['parent'] == PARENT
        and p['actual'] == ACTUAL and p['Root_review'] is p['accepted'] is None and p['unadmitted'] is True
        and p['constructor_files'] == inputs(), 'complete exact unissued constructor closure')
    provided = fs.snapshot(input_root)
    fs.need(fs.descriptors(provided) == p['provider_inputs'], 'whole externally profiled provider input census')
    before = capture(parent)
    fs.need(provided['expected349.lock'] == before['expected349.lock'], 'unchanged exact349 baseline input')
    files = render(before, payload(input_root, p['selection'], now=now)); result = identity(files)
    fs.need(all(p[k] == value for k, value in result.items()), 'whole profiled successor Source identity')
    fs.need(fs.snapshot(input_root) == provided, 'provider inputs stable through Source rendering')
    fs.need(inputs() == p['constructor_files'], 'constructor closure stable through Source rendering')
    policy_raw = provided[p['selection']['policy']['path']][0]
    A.root_decision(provided[p['selection']['decision']['path']][0], p['selection']['decision']['sha256'],
                    A.decode(policy_raw), fs.pin(policy_raw), int(time.time()) if now is None else now)
    fs.publish(files, output)
    return dict(schema=19, status=SCOPE, unadmitted=True, actual=ACTUAL, native='NOT RUN',
                Root_grants=None, dispatch=None, Root_acceptance=None, **result)


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2,) * 2)
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('parent', 'input-root', 'output', 'profile'):
        parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--profile-sha256', required=True); args = parser.parse_args()
    print(json.dumps(construct(args.parent, args.input_root, args.output, args.profile, args.profile_sha256), sort_keys=True))
