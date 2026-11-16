#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Construct the exact unadmitted notice-preservation successor; execute no roles."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource

HERE = Path(__file__).resolve().parent
FS_SHA = '7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'
path = HERE.parent / 'filesystem.py'
if hashlib.sha256(path.read_bytes()).hexdigest() != FS_SHA:
    raise ValueError('held filesystem DATA helper differs')
spec = importlib.util.spec_from_file_location('rust_v7_source_fs', path)
fs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fs)
fs.MAX_FILES = 512
PARENT = dict(files=314, bytes=41639049, tree='109005278b7a1404310ffb06e5f57933a6c1ba20',
              map_sha256='2786d1d393888699faf320b416e1570f40060e2428907c09855d4c7103aa33f8',
              factory_commit='d9f66d8bb10c9af91a7169cfa5f6b6fcb453910b')
SCOPE = 'RUST199_NOTICE_PRESERVATION_UNADMITTED_SOURCE_V7'
ACTUAL = dict.fromkeys(('source', 'ref', 'run', 'job', 'approval', 'artifact', 'image'))
REVISION = 'notice-preservation.json'
PREFIX = 'packages/port/rust199-source-reference/'
LEAVES = {PREFIX + name for name in ('reference.py', 'notice_preservation.py', 'notice-catalogue.DATA.json', 'PKGBUILD', '.SRCINFO')} | {
    'candidate-map.json', 'contract.json', 'notice_binding.py', 'recipe/PKGBUILD', 'admission.py',
    'actor/entry.py', 'actor/phase.py', 'actor/qualify.py', 'hosted/entry.py', 'hosted/producer.py',
    '.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-rust199-source-reference-v1.yml'}

SEAL = 'd66d49a2734e79c6f9d1f5a57fda98ab519d39016483da0f4f88a0f626576fd9'


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def capture(directory):
    files = fs.snapshot(directory)
    fs.need(len(files) == PARENT['files'] and sum(len(raw) for raw, _ in files.values()) == PARENT['bytes']
            and fs.tree(files) == PARENT['tree'] and fs.pin(files['source-map.json'][0])['sha256'] == PARENT['map_sha256'],
            'whole exact frozen Source314 bytes/modes/map required')
    fs.need(fs.descriptors({name: row for name, row in files.items() if name != 'source-map.json'}) ==
            json.loads(files['source-map.json'][0])['files'], 'complete parent map membership')
    return files


def render(before):
    fs.need(len(before) == PARENT['files'] and fs.tree(before) == PARENT['tree'], 'exact frozen Source314 required')
    payload = fs.snapshot(HERE / 'payload')
    fs.need(set(payload) == LEAVES and all(mode == 0o644 for raw, mode in payload.values()), 'exact notice successor payload leaves')
    catalogue = json.loads(payload[PREFIX + 'notice-catalogue.DATA.json'][0])
    fs.need(catalogue['catalogue_basis']['seal_sha256'] == SEAL and catalogue['holds_preserved'] is True
            and catalogue['Root_review'] is None and catalogue['accepted'] is None, 'sealed factual catalogue without invented authority')
    files = {name: row for name, row in before.items() if name != 'source-map.json'}
    files.update(payload)
    changes = {name: dict(before=fs.descriptors({name: before[name]})[name] if name in before else None,
                          after=fs.descriptors({name: files[name]})[name]) for name in sorted(payload)}
    candidate = json.loads(files['candidate-map.json'][0])
    contract = json.loads(files['contract.json'][0])
    candidate_rows = {name.removeprefix(PREFIX): row for name, row in files.items() if name.startswith(PREFIX)}
    binding = candidate['notice_binding']
    fs.need(candidate['files'] == fs.descriptors(candidate_rows) and len(candidate_rows) == binding['files'] == 11
            and binding['files_pin'] == fs.pin(encode(candidate['files'])) and binding['tree'] == fs.tree(candidate_rows)
            and candidate['commit'] == binding['base_commit'] == json.loads(before['candidate-map.json'][0])['commit']
            and binding['base_candidate_map_pin'] == fs.pin(before['candidate-map.json'][0])
            and contract['actual'] == ACTUAL
            and contract['candidate'] == {key: candidate[key] for key in ('commit', 'files', 'notice_binding')},
            'whole effective eleven-file candidate and unchanged base provenance')
    native_recipe = files[PREFIX + 'PKGBUILD'][0]
    hooks = []
    for action in ('prepare', 'build', 'package'):
        suffix = ' --destination "$pkgdir"' if action == 'package' else ''
        old = f'  python -I "$srcdir/reference.py" {action} --work "$srcdir"{suffix} || return'.encode()
        new = f'  /usr/bin/python -I -B /source/actor/entry.py {action} || return'.encode()
        fs.need(native_recipe.count(old) == 1, 'exact original recipe hook')
        native_recipe = native_recipe.replace(old, new)
        hooks.append(dict(before=old.decode(), after=new.decode(), count=1))
    fs.need(files['recipe/PKGBUILD'][0] == native_recipe, 'same three-hook native recipe projection')
    marker = dict(schema=7, scope=SCOPE, parent=PARENT, changes=changes, holds_preserved=True,
                  catalogue_seal_sha256=SEAL, candidate_binding=binding,
                  candidate_map_pin=fs.pin(files['candidate-map.json'][0]), contract_pin=fs.pin(files['contract.json'][0]),
                  recipe_derivation=dict(candidate=fs.pin(files[PREFIX + 'PKGBUILD'][0]), effective=fs.pin(native_recipe), hooks=hooks),
                  unadmitted=True, Root_grants=None, dispatch=None, pending=None, actual=ACTUAL)
    files[REVISION] = (encode(marker), 0o644)
    original_map = json.loads(before['source-map.json'][0])
    files['source-map.json'] = (encode(dict(schema=1, operation=original_map['operation'], actual=ACTUAL,
                                          files=fs.descriptors(files))), 0o644)
    fs.need(undo(files, before, marker) == before, 'whole exact Source314 inverse')
    fs.need(all(files[name] == row for name, row in before.items() if name not in LEAVES | {'source-map.json'}),
            'all Source314 leaves outside the exact successor binding delta unchanged')
    return files


def undo(files, before, marker):
    fs.need(marker['schema'] == 7 and marker['scope'] == SCOPE and marker['parent'] == PARENT
            and marker['actual'] == ACTUAL and marker['unadmitted'] is True
            and marker['pending'] is None and marker['Root_grants'] is None and marker['dispatch'] is None
            and files[REVISION] == (encode(marker), 0o644), 'exact notice proposal inverse metadata')
    expected_map = json.loads(before['source-map.json'][0])
    expected_map.update(actual=ACTUAL, files=fs.descriptors({name: row for name, row in files.items() if name != 'source-map.json'}))
    fs.need(files['source-map.json'] == (encode(expected_map), 0o644), 'whole successor map differs')
    restored = {name: row for name, row in files.items() if name not in ('source-map.json', REVISION)}
    for name, change in marker['changes'].items():
        fs.need(fs.descriptors({name: restored[name]})[name] == change['after'], 'whole successor inverse operand differs')
        if change['before'] is None:
            restored.pop(name)
        else:
            fs.need(fs.descriptors({name: before[name]})[name] == change['before'], 'whole parent inverse operand differs')
            restored[name] = before[name]
    restored['source-map.json'] = before['source-map.json']
    fs.need(restored == before, 'complete Source314 inverse including protected leaves')
    return restored


def inputs():
    return fs.descriptors({name: row for name, row in fs.snapshot(HERE).items()
                           if name not in ('constructor-profile.json', 'prospective.DATA.json')})


def construct(parent, output, expected):
    parent, output = map(fs.absolute, (parent, output))
    raw = fs.read(HERE / 'constructor-profile.json')[0]
    fs.need(fs.pin(raw)['sha256'] == expected, 'external whole constructor profile pin required')
    profile = json.loads(raw)
    fs.need(profile['schema'] == 7 and profile['unadmitted'] is True and profile['actual'] == ACTUAL
            and profile['parent'] == PARENT and profile['scope'] == SCOPE and profile['constructor_files'] == inputs(),
            'whole reviewed constructor closure')
    fs.need(not any(output.is_relative_to(path) or path.is_relative_to(output) for path in (parent, HERE)),
            'fresh disjoint Source DATA proposal output')
    files = render(capture(parent))
    result = dict(files=len(files), bytes=sum(len(raw) for raw, _ in files.values()), tree=fs.tree(files),
                  map_sha256=fs.pin(files['source-map.json'][0])['sha256'])
    fs.need(all(profile[key] == value for key, value in result.items()), 'whole profiled prospective Source identity')
    fs.publish(files, output)
    return dict(status=SCOPE, unadmitted=True, actual=ACTUAL, native='NOT RUN', **result)


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2,) * 2)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--profile-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(construct(args.parent, args.output, args.profile_sha256), sort_keys=True))
