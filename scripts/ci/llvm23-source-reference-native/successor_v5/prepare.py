#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Exact stage-receipt Source DATA successor; no actor, acquisition or replay."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource

HERE = Path(__file__).resolve().parent
FS_SHA = '7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'
TRUSTED = {
    'successor_v4/prepare.py': 'e96e938ef606299e6cb809a0e1c6a9df3a02a3bb6677fca1229f6eb0abdf007a',
    'successor_v3/prepare.py': '7ab44efb107f77052ae1c35f3170f3db841eec5fd81b2b474b6fda297a9f58b6',
    'successor_v2/prepare.py': 'ba41cc4e3ec0dc285be5909fa32331c7ce1eb5dc33ebb1d2538ae5240aa75784',
}


def trusted(name, relative, expected):
    path = HERE.parent / relative
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError('maintained DATA constructor/helper pin changed: ' + relative)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fs = trusted('llvm_stage_filesystem', 'filesystem.py', FS_SHA)
fs.MAX_FILES, fs.MAX_TOTAL = 320, 96 * 1024**2
P4, P3, P2 = (trusted('llvm_stage_inverse_' + name.split('/')[0], name, pin)
              for name, pin in TRUSTED.items())
PARENT = dict(source='365a763bc515a1b3550cc804536ddbf66353aac8',
              ref='refs/heads/codex/llvm23-source-reference-native-v2-20261115-r2',
              files=256, bytes=40919517,
              map_sha256='22f6f8a9d3eabf4de16c853cf67183b67beca4e702e26c5b492066e94194735c',
              tree='f251f3b7c7e152943ce85bc012f97305934e8fd8')
OP, INNER = 'llvm23-source-reference-native-v2', 'llvm23-source-reference-native-v1'
ACTUAL = dict.fromkeys(('source', 'ref', 'run', 'job', 'reader', 'authority', 'approval', 'artifact', 'image'))
ACTOR, CONTRACT = 'actor/container_mode.py', 'contract.json'
SAVED_ACTOR, SAVED_CONTRACT = 'previous-v4/actor-container_mode.py', 'previous-v4/contract.json'
SAVED_MAP, META = 'previous-v4/source-map.json', 'successor-v5.json'
OLD = "    need(re.fullmatch('[a-z0-9-]+', name), 'fixed command log name')\n"
NEW = OLD + "    if name in STAGES: name = 'stage-'+name\n"
OLD_ACTOR = dict(bytes=13147, sha256='b5f8c08db799335f0b6ccbd0873060a429cd0bc31c826af3b929494a83394637', mode=0o644)
OLD_CONTRACT = dict(bytes=3148, sha256='40e01661102dee517c5f535696c4625b6c57aa68c3985a89014f9475643da469', mode=0o644)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def descriptor(row):
    return dict(**fs.pin(row[0]), mode=row[1])


def closed(rows):
    raw, mode = rows['source-map.json']
    m = fs.decode(raw)
    fs.need(mode == 0o644 and set(m) == {'schema', 'scope', 'actual', 'files'} and
            type(m['schema']) is int and m['schema'] == 1 and m['actual'] == ACTUAL and
            m['files'] == fs.descriptors({n: v for n, v in rows.items() if n != 'source-map.json'}),
            'closed complete byte/mode map with NULL operational selectors')


def historical(rows):
    """Verify self-contained256→253→251 and its exact recorded248 parent."""
    old253 = P4.undo(rows)
    old251 = P3.undo(old253)
    inverse = fs.decode(old251['successor-v2.json'][0])
    # v2 requires the separately retained exact248 DATA. Complete that inverse
    # with historical_with_ancestor; never invent missing old workflow bytes.
    fs.need(len(old253) == 253 and len(old251) == 251 and inverse['parent'] == P2.PARENT,
            'complete recorded historical lineage to exact248 parent')
    return old253, old251


def historical_with_ancestor(rows, ancestor):
    old253, old251 = historical(rows)
    fs.need(len(ancestor) == P2.PARENT['files'] and fs.tree(ancestor) == P2.PARENT['tree'] and
            sum(len(b) for b, _ in ancestor.values()) == P2.PARENT['bytes'] and
            fs.pin(ancestor['source-map.json'][0])['sha256'] == P2.PARENT['map_sha256'],
            'exact complete248 ancestor DATA')
    old248 = P2.undo(old251, ancestor, fs.decode(old251['successor-v2.json'][0]))
    fs.need(old248 == ancestor, 'full256→253→251→248 inverse')
    return old248


def validate_parent(rows):
    closed(rows)
    fs.need(len(rows) == PARENT['files'] and sum(len(b) for b, _ in rows.values()) == PARENT['bytes'] and
            fs.tree(rows) == PARENT['tree'] and fs.pin(rows['source-map.json'][0])['sha256'] == PARENT['map_sha256'],
            'complete exact published256 parent DATA')
    fs.need(descriptor(rows[ACTOR]) == OLD_ACTOR and descriptor(rows[CONTRACT]) == OLD_CONTRACT,
            'exact old actor/contract bodies and modes')
    historical(rows)
    return rows


def parent(directory):
    return validate_parent(fs.snapshot(directory))


def corrected(raw):
    fs.need(raw.count(OLD.encode()) == 1 and NEW.encode() not in raw, 'one exact stage command-name seam')
    fixed = raw.replace(OLD.encode(), NEW.encode())
    fs.need(fixed.replace(NEW.encode(), OLD.encode()) == raw, 'whole actor literal inverse')
    return fixed


def contract(raw, actor):
    value = fs.decode(raw)
    fs.need(value['actor_files']['container_mode.py'] == OLD_ACTOR and
            value['outer_delegation']['frozen_python_actor'] is True, 'old exact actor binding/claim')
    value['actor_files']['container_mode.py'] = descriptor(actor)
    value['outer_delegation']['frozen_python_actor'] = False
    return encode(value)


def metadata(before, after):
    return dict(schema=1, scope='STAGE_RECEIPT_NAMESPACE_SOURCE_ONLY_NOT_REPLAY', parent=PARENT,
        outer_operation=OP, inner_operation=INNER,
        changed={ACTOR: dict(before=descriptor(before[ACTOR]), after=descriptor(after[ACTOR]),
                            inverse=dict(old=OLD, new=NEW, count=1)),
                 CONTRACT: dict(before=descriptor(before[CONTRACT]), after=descriptor(after[CONTRACT]),
                    derivation=dict(actor_file='container_mode.py', frozen_python_actor=dict(before=True, after=False),
                                    all_other_contract_fields_unchanged=True))},
        saved_parent_map=SAVED_MAP, saved_parent_actor=SAVED_ACTOR, saved_parent_contract=SAVED_CONTRACT,
        all_other_parent_leaves_unchanged=True, actual=ACTUAL)


def render(previous):
    before = validate_parent(previous)
    files = dict(before)
    files.pop('source-map.json')
    fs.need(not {SAVED_ACTOR, SAVED_CONTRACT, SAVED_MAP, META} & set(files), 'fresh v5 namespace')
    files[ACTOR] = (corrected(before[ACTOR][0]), before[ACTOR][1])
    files[CONTRACT] = (contract(before[CONTRACT][0], files[ACTOR]), before[CONTRACT][1])
    files[SAVED_ACTOR], files[SAVED_CONTRACT], files[SAVED_MAP] = before[ACTOR], before[CONTRACT], before['source-map.json']
    files[META] = (encode(metadata(before, files)), 0o644)
    files['source-map.json'] = (encode(dict(schema=1, scope='LLVM23_NATIVE_V2_STAGE_RECEIPT_SOURCE_PACKET_ONLY',
                                          actual=ACTUAL, files=fs.descriptors(files))), 0o644)
    fs.need(undo(files) == before and len(files) == 260, 'whole260→256 byte/mode inverse')
    fs.need(all(files[n] == row for n, row in before.items() if n not in (ACTOR, CONTRACT, 'source-map.json')),
            'all other parent leaves frozen')
    return files


def undo(files):
    closed(files)
    fs.need(files['source-map.json'][0] == encode(dict(schema=1,
        scope='LLVM23_NATIVE_V2_STAGE_RECEIPT_SOURCE_PACKET_ONLY', actual=ACTUAL,
        files=fs.descriptors({n: v for n, v in files.items() if n != 'source-map.json'}))),
        'exact canonical v5 map scope and body')
    result = dict(files)
    result.pop('source-map.json')
    raw, mode = result.pop(META)
    meta = fs.decode(raw)
    saved_actor, saved_contract, saved_map = result.pop(SAVED_ACTOR), result.pop(SAVED_CONTRACT), result.pop(SAVED_MAP)
    fs.need(descriptor(saved_actor) == OLD_ACTOR and descriptor(saved_contract) == OLD_CONTRACT and
            saved_map[1] == 0o644 and fs.pin(saved_map[0])['sha256'] == PARENT['map_sha256'], 'whole retained256 bodies/map')
    before = dict(result)
    before[ACTOR], before[CONTRACT], before['source-map.json'] = saved_actor, saved_contract, saved_map
    fs.need(mode == 0o644 and type(meta.get('schema')) is int and raw == encode(metadata(before, result)),
            'exact typed v5 inverse metadata')
    fs.need(result[ACTOR] == (corrected(saved_actor[0]), saved_actor[1]) and
            result[CONTRACT] == (contract(saved_contract[0], result[ACTOR]), saved_contract[1]),
            'only stage receipt literal and derived contract bindings changed')
    return validate_parent(before)


def constructor_files():
    return fs.descriptors({name: fs.read(HERE / name) for name in
                          ('prepare.py', 'README.md', 'test_constructor.py', 'test_stage_receipts.py', 'observed-failure.json')})


def verify_profile(expected):
    raw = fs.read(HERE / 'constructor-profile.json')[0]
    fs.need(fs.pin(raw)['sha256'] == expected, 'external exact v5 constructor profile required')
    p = fs.decode(raw)
    fs.need(p['parent'] == PARENT and p['actual'] == ACTUAL and p['outer_operation'] == OP and
            p['inner_operation'] == INNER and p['constructor_files'] == constructor_files(),
            'whole v5 constructor/profile DATA join')
    return p


def construct(source, output, profile_sha):
    source, output = fs.absolute(source), fs.absolute(output)
    fs.need(not source.is_relative_to(output) and not output.is_relative_to(source) and
            not output.is_relative_to(HERE) and not HERE.is_relative_to(output), 'fresh disjoint v5 output')
    p = verify_profile(profile_sha)
    files = render(parent(source))
    fs.need(len(files) == p['expected_files'] and sum(len(b) for b, _ in files.values()) == p['expected_bytes'] and
            fs.pin(files['source-map.json'][0]) == p['expected_map'] and fs.tree(files) == p['expected_tree'],
            'exact count/bytes/map/tree v5 profile')
    fs.publish(files, output)
    return dict(status='CONSTRUCTED_STAGE_RECEIPT_DATA_ONLY', files=len(files), bytes=p['expected_bytes'],
                map=p['expected_map'], tree=p['expected_tree'], parent=PARENT, outer_operation=OP,
                inner_operation=INNER, actual=ACTUAL, native_acceptance=False, publication='NOT_PERFORMED_BY_CONSTRUCTOR')


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2,) * 2)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(construct(args.parent_source, args.output, args.profile_sha256), sort_keys=True))
