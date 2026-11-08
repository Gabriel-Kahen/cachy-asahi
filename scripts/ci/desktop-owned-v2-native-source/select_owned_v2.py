#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Describe an explicit pinned opt-in delta; never construct/emit/run a Source."""
import argparse
import hashlib
import json
from pathlib import Path

SELECTION = 'desktop-owned-retirement-v2'
PROFILE_SHA256 = '2b34ce484406cfeedfc990bc0bb3698ba01bec71d36e4f9b35d18c50e6edc9c5'
PARENT = '72bc639de295704b94901c03ac8acf7667ff6f9c'
RUNTIME = dict(bytes=38256, sha256='9388d270d06e28fee50160b7c04dd69593e383647d791f8aaff69380032165d5', mode=0o755)


def need(ok, why):
    if not ok:
        raise ValueError(why)


def select(value, *, selection):
    need(selection == SELECTION, 'explicit owned-v2 selection required; no default route')
    need(type(value) is dict and value.get('kind') == 'desktop-owned-v2-source-proposal-v1'
         and value.get('parent_source') == PARENT, 'exact actual Desktop parent profile required')
    runtime=value.get('runtime')
    need(type(runtime) is dict and type(runtime.get('bytes')) is int and type(runtime.get('mode')) is int
         and runtime == RUNTIME and value.get('runtime_source') == 'd9708daa75083f85f1a182cb3aa97a728d04d695', 'exact native runtime body/mode/source required')
    need(all(type(value.get(key)) is int for key in ('source_files','source_map_rows','common_mapped_cap','factory_full_file_cap'))
         and value.get('source_files') == 200 and value.get('source_map_rows') == 199
         and value.get('common_mapped_cap') == value.get('factory_full_file_cap') == 200, 'unchanged closed Source caps required')
    need(value.get('actual') == dict(source=None, ref=None, run=None, job=None, artifact=None), 'preparation actuals must stay NULL')
    need(value.get('admission') == dict(native_control='ROOT_ACCEPTED_FINITE_NATIVE_ARM4K_ADOPTED_ZERO_EXIT_CHILD_PROCESS_CONTROL', matching_reader='HELD_V2_COMPONENT_SCHEMA_PENDING_ROOT',
         producer_pins='EXACT_SOURCE_PRODUCER_PINS_ONLY', publication='ROOT_ONLY_NOT_AUTHORIZED_HERE'), 'held native/reader/publication boundaries required')
    need(type(value.get('delta')) is list and len(value['delta']) == 9, 'exact finite opt-in Source delta required')
    return dict(status='EXPLICIT_SOURCE_DELTA_SELECTED_PREPARATION_ONLY', selection=SELECTION, parent_source=PARENT,
                source_files=200, source_map_rows=199, runtime=dict(RUNTIME),
                workflow_inputs=dict(operation='desktop-alpm-v1', owned_retirement_v2=True),
                invocation_operation='desktop-alpm-owned-v2', source_delta=value['delta'],
                constructor_invoked=False, emitted=False, executed=False, dispatchable=False,
                migration='HOLD', native='NOT_RUN', release='NOT_ADMITTED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', required=True, choices=(SELECTION,))
    parser.add_argument('--profile', type=Path, default=Path(__file__).with_name('profile.json'))
    args = parser.parse_args()
    with args.profile.open('rb') as stream:
        raw = stream.read(1024**2+1)
    need(len(raw) <= 1024**2 and hashlib.sha256(raw).hexdigest() == PROFILE_SHA256, 'whole fixed opt-in profile differs')
    print(json.dumps(select(json.loads(raw), selection=args.selection), sort_keys=True))


if __name__ == '__main__':
    main()
