#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Compose XS v2 DATA from the exact closed v1 Source; execute no input code."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[4]
HELPER = REPO / 'scripts/ci/native-build-namespace-preflight/prepare.py'
if hashlib.sha256(HELPER.read_bytes()).hexdigest() != '7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7':
    raise ValueError('held atomic filesystem DATA helper differs')
spec = importlib.util.spec_from_file_location('xs_v2_atomic', HELPER)
atomic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(atomic)
atomic.MAX_FILES = 384
atomic.MAX_TOTAL = 96 * 1024**2
ACTUAL = dict.fromkeys(('source', 'ref', 'run', 'job', 'reader', 'authority', 'approval', 'artifact', 'image'))
PARENT = '0885f89ab7a4301bbdf9c4b180620fb447d9a41a'
PARENT_MAP = '674cc3d18e954dd1f3f351b357f746e3b9ab1b7580370666061fcb9deeb15efc'
PARENT_TREE = '6a1c29b7aa1655943b54de71a89f3900ff1671c9'
MODE_PIN = dict(bytes=349767, sha256='7004309f83344b49f0f8ca598d8cefcffbc078450944824849ab9c575f1c0cd2')
OPERATION = 'perl5423-native-xs-v2'
OLD_ALIAS = '.github/workflows/native-arm-perl5423-xs-v1.yml'
NEW_ALIAS = '.github/workflows/native-arm-perl5423-xs-v2.yml'


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def previous(path):
    files = atomic.snapshot(path)
    atomic.need(len(files) == 297 and sum(len(b) for b, _ in files.values()) == 87006934 and
                atomic.pin(files['source-map.json'][0])['sha256'] == PARENT_MAP and
                atomic.tree(files) == PARENT_TREE, 'exact closed published v1 Source required')
    rows = atomic.decode(files['source-map.json'][0])
    atomic.need(rows['actual'] == ACTUAL and rows['files'] == atomic.descriptors(
                {n: row for n, row in files.items() if n != 'source-map.json'}), 'complete v1 Source leaf/mode pins')
    atomic.need(files[OLD_ALIAS] == files['.github/workflows/native-arm-build.yml'], 'exact old aliases')
    return files


def workflow(before, old_entry_sha, new_entry_sha):
    text = before.decode()
    for old, new in (('native-arm-perl5423-xs-v1', 'native-arm-perl5423-xs-v2'),
                     ('perl5423-native-xs-v1', OPERATION), (old_entry_sha, new_entry_sha)):
        atomic.need(old in text, 'exact v1 workflow seam missing')
        text = text.replace(old, new)
    atomic.need('group: native-arm-build\n  cancel-in-progress: false\n  queue: max' in text and
                'native-arm-perl5423-xs-v1' not in text, 'new dedicated serialized workflow required')
    return text.encode()


def render(parent, profile_sha):
    raw, _ = atomic.read(HERE / 'profile.json', 1024**2)
    atomic.need(atomic.pin(raw)['sha256'] == profile_sha, 'whole Root-reviewed v2 profile pin required')
    profile = atomic.decode(raw)
    atomic.need(profile['schema'] == 1 and profile['actual'] == ACTUAL and profile['operation'] == OPERATION and
                profile['delegated_consumer_operation'] == 'perl5423-native-xs-v1', 'new authority/lineage; frozen consumer engine')
    before = previous(parent)
    files = dict(before)
    mode_raw, mode = atomic.read(HERE / 'runtime-files.json', 1024**2)
    atomic.need(atomic.pin(mode_raw) == MODE_PIN == profile['runtime_manifest'] and mode == 0o644,
                'complete reviewed archive-derived byte/mode map')
    runtime = atomic.decode(mode_raw)
    atomic.need(runtime['schema'] == 1 and runtime['archive'] == profile['accepted_archive'] and
                len(runtime['files']) == 1870 and sum(r['bytes'] for r in runtime['files'].values()) == 74426813,
                'exact selected archive namespace and bytes')
    for name, row in profile['payload'].items():
        body, permissions = atomic.read(HERE / 'payload' / name)
        atomic.need(dict(**atomic.pin(body), mode=permissions) == row, 'whole corrected payload pin differs: ' + name)
        atomic.need(name in ('xs/entry.py', 'xs/prepare_inputs.py'), 'only bounded v2 payload replacements')
        files[name] = (body, permissions)
    files['accepted/runtime-files.json'] = (mode_raw, mode)
    text = workflow(before[OLD_ALIAS][0], atomic.pin(before['xs/entry.py'][0])['sha256'],
                    atomic.pin(files['xs/entry.py'][0])['sha256'])
    del files[OLD_ALIAS]
    files[NEW_ALIAS] = (text, 0o644)
    files['.github/workflows/native-arm-build.yml'] = (text, 0o644)
    files['xs-provenance.json'] = (encode(dict(schema=1, actual=ACTUAL, operation=OPERATION,
        delegated_consumer_operation='perl5423-native-xs-v1', parent_source=PARENT,
        parent_map_sha256=PARENT_MAP, parent_tree=PARENT_TREE,
        closed_failed_run='43705018149', closed_failed_job='132784130584',
        closed_failure='PREPARATION_MODE_GUARD_BEFORE_XS_PRODUCER',
        runtime_manifest=MODE_PIN, accepted_archive=profile['accepted_archive'],
        correction='PRESERVE_EXACT_0444_0555_0644_0755_ARCHIVED_BYTES_AND_MODES_WITH_FULL_MAP',
        constructor_profile_sha256=profile_sha, native_acceptance=False, XS_acceptance=False)), 0o644)
    preserved = {n: row for n, row in before.items() if n.startswith(('held/', 'consumer/', 'accepted/')) or n == 'LICENSE'}
    atomic.need(all(files[n] == row for n, row in preserved.items()), 'held/bootstrap/consumer/accepted bytes and modes preserved')
    files['source-map.json'] = (encode(dict(schema=1, actual=ACTUAL,
        scope='PROPOSED_SEPARATE_NATIVE_XS_V2_EXACT_RUNTIME_MODES',
        files=atomic.descriptors({n: row for n, row in files.items() if n != 'source-map.json'}))), 0o644)
    atomic.need(len(files) == 298 and sum(len(b) for b, _ in files.values()) <= 96*1024**2,
                'finite corrected Source membership/byte budget')
    return files


def construct(parent, profile_sha, output):
    parent, output = map(atomic.absolute, (parent, output))
    atomic.need(not any(output.is_relative_to(p) or p.is_relative_to(output) for p in (REPO, parent)),
                'fresh disjoint DATA output; previous published Source immutable')
    files = render(parent, profile_sha)
    atomic.publish(files, output)
    return dict(status='CONSTRUCTED_XS_V2_SOURCE_DATA_ONLY', actual=ACTUAL, files=len(files),
                bytes=sum(len(b) for b, _ in files.values()), map=atomic.pin(files['source-map.json'][0]),
                prospective_tree=atomic.tree(files), parent_source=PARENT, runtime_manifest=MODE_PIN,
                native_acceptance=False, XS_acceptance=False)


if __name__ == '__main__':
    atomic.need(sys.flags.isolated and not sys.flags.optimize, 'isolated unoptimized DATA constructor')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('previous-xs-source', 'profile-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    print(json.dumps(construct(Path(args.previous_xs_source), args.profile_sha256, Path(args.output)), sort_keys=True))
