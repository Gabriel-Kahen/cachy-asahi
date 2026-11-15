#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Compose separate hosted XS Source from held Source and accepted opaque DATA."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[4]
CONSUMER = HERE.parents[1]
HELPER = REPO / 'scripts/ci/native-build-namespace-preflight/prepare.py'
if hashlib.sha256(HELPER.read_bytes()).hexdigest() != '7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7':
    raise ValueError('held atomic filesystem DATA helper differs')
spec = importlib.util.spec_from_file_location('xs_source_atomic', HELPER)
atomic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(atomic)
atomic.MAX_FILES = 384
atomic.MAX_TOTAL = 96 * 1024**2
ACTUAL = dict(source=None, ref=None, run=None, job=None, reader=None, authority=None, approval=None, artifact=None, image=None)
HELD_MAP = '4b1de3aade5116206318570d1d44ee1063342faeab54935748b1b7c179a99e96'
HELD_TREE = '43dfa9d6370abd1424bd5586c5524a6f4b4e1556'
PACKAGE = 'perl-5.42.3-1.3-aarch64.pkg.tar.zst'


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def snapshot_held(path):
    files = atomic.snapshot(path)
    atomic.need(len(files) == 272 and atomic.pin(files['source-map.json'][0])['sha256'] == HELD_MAP
                and atomic.tree(files) == HELD_TREE, 'complete exact held272 Source required')
    manifest = atomic.decode(files['source-map.json'][0])
    atomic.need(manifest['actual'] == ACTUAL and manifest['files'] ==
                atomic.descriptors({name: row for name, row in files.items() if name != 'source-map.json'}),
                'whole held map/leaf/mode namespace differs')
    return files


def workflow(held, entry_sha):
    raw = held['.github/workflows/native-arm-perl5423-v2.yml'][0]
    old_entry = atomic.pin(held['hosted/entry.py'][0])['sha256']
    text = raw.decode()
    replacements = {
        'native-arm-perl5423-v2': 'native-arm-perl5423-xs-v1',
        'perl5423-native-pair-v2': 'perl5423-native-xs-v1',
        'perl5423-native-v2': 'perl5423-native-xs-v1',
        'hosted/entry.py': 'xs/entry.py',
        'hosted/common.py': 'held/hosted/common.py',
        'original/bootstrap/': 'held/original/bootstrap/',
        old_entry: entry_sha,
        'Signed349 bootstrap and full ordinary native Perl pair': 'Signed349 bootstrap and separate native XS consumer',
        'Retain only public audit and pair DATA': 'Retain public bootstrap and XS DATA',
        '${{ runner.temp }}/perl-hosted/hosted.json': '${{ runner.temp }}/perl-hosted/hosted-xs.json',
        '${{ runner.temp }}/perl-hosted/pair/**': '${{ runner.temp }}/perl-hosted/xs/**\n'
            '            ${{ runner.temp }}/perl-hosted/preparation/**\n'
            '            ${{ runner.temp }}/perl-hosted/preparation*.json\n'
            '            ${{ runner.temp }}/perl-hosted/bundle/preparation.json\n'
            '            ${{ runner.temp }}/perl-hosted/bundle/operation.json\n'
            '            ${{ runner.temp }}/perl-hosted/bundle/bundle-map.json\n'
            '            ${{ runner.temp }}/perl-hosted/bundle/xs-admission.json\n'
            '            ${{ runner.temp }}/perl-hosted/bundle/xs-inputs.json\n'
            '            ${{ runner.temp }}/perl-hosted/bundle/xs-plan.json',
    }
    for before, after in replacements.items():
        atomic.need(before in text, 'held workflow seam missing: ' + before)
        text = text.replace(before, after)
    atomic.need('perl/producer.py' not in text and 'native-arm-perl5423-v2' not in text and
                'group: native-arm-build\n  cancel-in-progress: false\n  queue: max' in text,
                'separate XS workflow and existing serialization contract required')
    return text.encode()


def render(held_source, package_evidence, decision, profile_sha):
    profile_raw, _ = atomic.read(HERE / 'profile.json', 1024**2)
    atomic.need(atomic.pin(profile_raw)['sha256'] == profile_sha, 'whole Root-reviewed XS constructor profile required')
    profile = atomic.decode(profile_raw)
    atomic.need(profile['actual'] == ACTUAL and profile['operation'] == 'perl5423-native-xs-v1',
                'new XS Source selectors must remain NULL')
    held = snapshot_held(held_source)
    files = {'held/' + name: row for name, row in held.items()}
    for name, expected in profile['consumer'].items():
        raw, mode = atomic.read(CONSUMER / name)
        atomic.need(dict(**atomic.pin(raw), mode=mode) == expected, 'frozen consumer dependency differs: ' + name)
        files['consumer/' + name] = (raw, mode)
    for name, expected in profile['payload'].items():
        raw, mode = atomic.read(HERE / 'payload' / name)
        atomic.need(dict(**atomic.pin(raw), mode=mode) == expected, 'whole XS hosted payload differs: ' + name)
        files[name] = (raw, mode)
    for name, expected in profile['accepted'].items():
        raw, mode = atomic.read(decision if name == 'Root-decision.json' else package_evidence / name)
        atomic.need(atomic.pin(raw) == expected, 'exact Root-accepted opaque DATA differs: ' + name)
        files['accepted/' + name] = (raw, 0o644)
    # The externally pinned actual decision includes observed fractional timings.
    d = json.loads(files['accepted/Root-decision.json'][0])
    atomic.need(d['accepted'] is True and d['status'] == 'ACCEPTED_EXACT_PERL5423_NATIVE_ARM4K_BUILD_PAIR_ONLY'
                and d['archive'] == profile['accepted'][PACKAGE] and d['page_bytes'] == 4096,
                'Root accepted exact ARM4K archive decision required')
    license_body, mode = atomic.read(REPO / 'LICENSE')
    atomic.need(dict(**atomic.pin(license_body), mode=mode) == profile['license'], 'project MIT license differs')
    files['LICENSE'] = (license_body, mode)
    text = workflow(held, atomic.pin(files['xs/entry.py'][0])['sha256'])
    files['.github/workflows/native-arm-build.yml'] = (text, 0o644)
    files['.github/workflows/native-arm-perl5423-xs-v1.yml'] = (text, 0o644)
    files['xs-provenance.json'] = (encode(dict(schema=1, actual=ACTUAL,
        operation='perl5423-native-xs-v1', held_source='25dc3e65bdb6137c87a9409067fe9b2cf6e9763f',
        held_map_sha256=HELD_MAP, held_tree=HELD_TREE, root_decision=profile['accepted']['Root-decision.json'],
        accepted_package=profile['accepted'][PACKAGE], constructor_profile_sha256=profile_sha,
        scope='SOURCE_DATA_ONLY_NO_BOOTSTRAP_EXTRACTION_CONSUMER_READER_OR_PUBLICATION_ROLE',
        native_acceptance=False, XS_acceptance=False)), 0o644)
    files['source-map.json'] = (encode(dict(schema=1, actual=ACTUAL,
        scope='PROPOSED_SEPARATE_NATIVE_XS_HOSTED_SOURCE', files=atomic.descriptors(files))), 0o644)
    atomic.need(len(files) <= 384 and sum(len(raw) for raw, _ in files.values()) <= 96 * 1024**2,
                'finite complete XS hosted Source budget')
    atomic.need({name.removeprefix('held/'): row for name, row in files.items() if name.startswith('held/')} == held,
                'held272 Source bytes and modes preserved exactly')
    return files


def construct(held_source, package_evidence, decision, profile_sha, output):
    held_source, package_evidence, decision, output = map(atomic.absolute,
        (held_source, package_evidence, decision, output))
    frozen = (REPO, held_source, package_evidence, decision.parent)
    atomic.need(not any(output.is_relative_to(path) or path.is_relative_to(output) for path in frozen),
                'fresh disjoint DATA output; no held Source or evidence mutation')
    files = render(held_source, package_evidence, decision, profile_sha)
    atomic.publish(files, output)
    return dict(status='CONSTRUCTED_XS_HOSTED_SOURCE_DATA_ONLY', actual=ACTUAL,
                files=len(files), bytes=sum(len(raw) for raw, _ in files.values()),
                map=atomic.pin(files['source-map.json'][0]), prospective_tree=atomic.tree(files),
                native_acceptance=False, XS_acceptance=False)


if __name__ == '__main__':
    atomic.need(sys.flags.isolated and not sys.flags.optimize, 'isolated unoptimized Source DATA constructor')
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('held-source', 'package-evidence', 'root-decision', 'profile-sha256', 'output'):
        parser.add_argument('--' + key, required=True)
    args = parser.parse_args()
    print(json.dumps(construct(Path(args.held_source), Path(args.package_evidence), Path(args.root_decision),
                               args.profile_sha256, Path(args.output)), sort_keys=True))
