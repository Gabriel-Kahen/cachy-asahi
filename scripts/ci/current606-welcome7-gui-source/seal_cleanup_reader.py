#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Derive an unopened Current606 Reader for the source-owned cleanup receipts."""

import argparse
import ast
import inspect
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fresh606 import decode, encoded, need, pin, read
from seal_fresh606 import replace


ACTOR = 'factory/failure_cleanup.py'
ACTOR_PIN = {'bytes': 3973, 'sha256': '130f6d21e4bcd03a187124631208457d422a0a4472b6f8cce2e3431e0673446a'}
OLD_METHOD = {'bytes': 651, 'sha256': 'a57abb595b981ebeec95029c2f42b95b064f4332cf536a2042ee5f5ad99a3703'}
CASES = {profile+'-'+mode for profile in ('minimal', 'overlay') for mode in ('generic4k', 'generic16k')}


def cleanup_order(gui, root, H):
    actor = H.load('_current606_cleanup_receipt_schema', root/'factory/failure_cleanup.py')
    plan = gui['resource_acquisition']
    rows = gui['cleanup']
    H.need(plan == actor.plan(plan['containers'], plan['images'], plan['base_image'],
                             plan['base_reference'], plan['fixture'])
           and plan['images'] == [gui['runtime_image'], gui['controller_image']]
           and (plan['base_image'], plan['base_reference']) == (gui['base_image'], gui['base_reference']),
           'exact original cleanup acquisitions')
    H.need(type(rows) is list and len(rows) == 15 and rows[10] == {'guest_disk_removed': True}
           and rows[10]['guest_disk_removed'] is True, 'all original 15 cleanup rows')
    plain, output = [], {}
    for i, row in enumerate(rows):
        if i == 10:
            plain.append(dict(row))
            continue
        H.need(type(row) is dict and set(row) == {'action', 'exit', 'stdout', 'stdout_base64'}
               and type(row['stdout_base64']) is str and len(row['stdout_base64']) <= 87384
               and type(row['stdout']) is dict and type(row['stdout'].get('bytes')) is int,
               'exact bounded cleanup command receipt schema')
        output[i] = actor.raw(row)
        plain.append(dict(action=row['action'], exit=row['exit']))
    actions = [action+name for name in reversed(plan['containers'])
               for action in ('remove-container:', 'check-container:')]
    H.need([row['action'] for row in plain[:6]] == actions
           and plain[7] == dict(action='remove-image:'+gui['controller_image'], exit=0),
           'exact acquired container order and controller image seam')
    H.need(all(output[i] == b'' for i in (1, 3, 5, 13))
           and output[11].splitlines() == [plan['base_image'].encode()],
           'actual container and alias absence and prior borrowed image identity')
    listed = output[14].decode().splitlines()
    H.need(all(actor.image(v) for v in listed) and plan['base_image'] in listed
           and not set(plan['images']) & set(listed), 'borrowed base present and both owned images absent')
    baseline = H.load('_current606_original_cleanup_semantics', H.HERE/'baseline/verify.py')
    baseline.cleanup_order(dict(gui, cleanup=plain[:7]+plain[8:]))


def patch_verify(raw, source_files):
    need(source_files.get(ACTOR) == ACTOR_PIN, 'exact source-owned stdout receipt producer required')
    text = raw.decode()
    methods = [node for node in ast.parse(text).body
               if isinstance(node, ast.FunctionDef) and node.name == 'cleanup_order']
    need(len(methods) == 1, 'one historical cleanup method required')
    previous = ast.get_source_segment(text, methods[0]).encode()
    need(pin(previous) == OLD_METHOD, 'exact historical cleanup method required')
    result = replace(raw, previous, inspect.getsource(cleanup_order).rstrip().encode())
    result = replace(result, b';cleanup_order(gui)', b';cleanup_order(gui,root,H)')
    compile(result, 'verify.py', 'exec')
    return result


def emit(reader, reader_map_sha256, output):
    from seal_fresh606_reader import files_at

    need(reader == reader.resolve(strict=True) and reader.is_dir()
         and output == output.resolve() and output.parent.is_dir() and not output.exists(),
         'ordinary input and fresh canonical output required')
    rows = files_at(reader)
    before = pin(encoded(rows))
    need(before['sha256'] == reader_map_sha256, 'whole original Reader map differs')
    raw = {name: read(reader/name, 32*1024**2, leaf) for name, leaf in rows.items()}
    profile = decode(raw['reader-profile.json'])
    known = decode(raw['known-source.json'])
    need(profile['actual'] is None and known['workflow_id'] is None
         and type(known['runs']) is dict and set(known['runs']) == CASES
         and all(run is None for run in known['runs'].values())
         and known == decode(raw['binding-template.json']), 'derive only an unopened Reader')
    protected = (reader, Path(profile['source_path']), Path(profile['original_assets']))
    need(all(not output.is_relative_to(path) and not path.is_relative_to(output) for path in protected),
         'fresh Reader must be disjoint from original Reader, Source and assets')
    raw['verify.py'] = patch_verify(raw['verify.py'], profile['source_files'])
    need(files_at(reader) == rows, 'whole prior Reader rejoined before writes')
    output.mkdir(mode=0o700)
    for name, body in sorted(raw.items()):
        target = output/name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(body)
        target.chmod((reader/name).stat().st_mode & 0o777)
    after = {name: pin(body) for name, body in raw.items()}
    need(files_at(output) == after, 'complete derived Reader readback')
    return dict(status='EMITTED_CURRENT606_CLEANUP_RECEIPT_READER_UNOPENED', files=len(after),
                before=before, after=pin(encoded(after)), changed={'verify.py': after['verify.py']},
                actual=None, authority=None)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--reader', required=True, type=Path)
    parser.add_argument('--reader-map-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(encoded(emit(args.reader, args.reader_map_sha256, args.output)).decode(), end='')
