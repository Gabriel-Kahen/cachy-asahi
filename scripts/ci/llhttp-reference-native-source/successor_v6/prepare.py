#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure Source93 successor; strict public retention before storage cleanup."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
raw = (HERE.parent/'successor_v5/prepare.py').read_bytes()
if dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) != dict(bytes=9474, sha256='f51ad9ead66d2e87148d1eb19ca9ce8df1a28ff14937a04f26600bc1bc3fe491'):
    raise ValueError('whole immutable Source93 constructor')
spec = importlib.util.spec_from_file_location('llhttp_v6_previous', HERE.parent/'successor_v5/prepare.py')
P5 = importlib.util.module_from_spec(spec); spec.loader.exec_module(P5)
P = P5.P
PREFIX = P.PREFIX
PARENT_MAP = dict(bytes=19821, sha256='4abcbcd541e3bf3ad652ff09cd2a813ce5a276bc58fade63cc2801a248c349c7')
PARENT_TREE = '424259eb3868b802b9aa2ae4dbeceff169fce7fd'
CHANGED = (PREFIX+'hosted_owner.py', PREFIX+'policy.json', PREFIX+'owner-program.json', 'source-map.json')
HELPER = PREFIX+'public_evidence.py'
MARKER = 'inner-public-retention-v6.json'
HELPER_PIN = {'bytes': 10144, 'sha256': '9b3c103dc6b309568ff5215f2b282b27bb349b4a44f55b777dcf55bda3157a42'}


def validate_parent(bodies):
    P.need(P.pin(bodies['source-map.json']) == PARENT_MAP, 'whole retained Source93 map')
    rows = json.loads(bodies['source-map.json'])
    P.need(set(bodies) == set(rows['files']) | {'source-map.json'} and len(bodies) == 93
           and sum(map(len, bodies.values())) == 1204391 and P.tree(bodies) == PARENT_TREE,
           'complete93 bytes/namespace/tree')
    P.need(all(dict(P.pin(bodies[n]), mode=0o644) == row for n, row in rows['files'].items())
           and all(v is None for v in rows['actual'].values()), 'whole93 bodies/modes and NULL actuals')
    previous85 = P5.inverse(bodies)
    P.need(len(previous85) == 85, 'complete93/85/76/68/62 source inverse')


def parent_bodies(parent):
    parent = P.ordinary(parent)
    found = {str(n.relative_to(parent)) for n in parent.rglob('*') if n.is_file() or n.is_symlink()}
    bodies = {n: P.read(parent/n) for n in sorted(found)}
    P.need(all((parent/n).stat().st_mode & 0o777 == 0o644 for n in found), 'whole93 physical modes')
    validate_parent(bodies)
    return bodies


def projection(old):
    text = old[PREFIX+'hosted_owner.py'].decode()
    seams = []
    def replace(before, after):
        nonlocal text
        P.need(text.count(before) == 1 and after not in text, 'one exact public-retention seam')
        text = text.replace(before, after)
        seams.append(dict(before=before, after=after))
    anchor = "s=importlib.util.spec_from_file_location('llhttp_source_readonly_v5',HERE/'source_readonly.py');Q=importlib.util.module_from_spec(s);s.loader.exec_module(Q)"
    replace(anchor, anchor+"\ns=importlib.util.spec_from_file_location('llhttp_public_evidence_v6',HERE/'public_evidence.py');E=importlib.util.module_from_spec(s);s.loader.exec_module(E)")
    start = text.index('        # Copy only original finite public evidence, never cache/keyring/config or Docker data.')
    stop = text.index("        report.update(status='PAIR_PASSED_PENDING_EXTERNAL_CLEANUP'", start)
    replace(text[start:stop], '        # Strict finite public outputs are exported in finally before storage cleanup.\n')
    anchor = "    finally:\n        report['host_preflight']=owner.host_facts"
    replace(anchor, "    finally:\n        E.preserve(report,a.output/'volume/work/llhttp-reference-native',a.output/'evidence',\n"
            "                   dict(source=actual['source'],ref=actual['ref'],source_map_sha256=a.source_map_sha256,\n"
            "                        run=os.environ['GITHUB_RUN_ID'],attempt=1,job=os.environ['GITHUB_JOB'],nonce=actual['nonce']),a.runner_uid)\n"
            "        report['host_preflight']=owner.host_facts")
    restored = text
    for seam in reversed(seams):
        P.need(restored.count(seam['after']) == 1, 'one exact inverse seam')
        restored = restored.replace(seam['after'], seam['before'])
    P.need(restored.encode() == old[PREFIX+'hosted_owner.py'], 'whole unchanged controller inverse')
    return text.encode(), seams


def assemble(old):
    validate_parent(old)
    helper = P.read(HERE/'public_evidence.py')
    P.need(P.pin(helper) == HELPER_PIN, 'whole pinned strict public exporter')
    spec = importlib.util.spec_from_file_location('llhttp_public_retention_policy', HERE/'public_evidence.py')
    E = importlib.util.module_from_spec(spec); spec.loader.exec_module(E)
    controller, seams = projection(old)
    bodies = dict(old)
    bodies[PREFIX+'hosted_owner.py'] = controller
    bodies[HELPER] = helper
    policy = json.loads(old[PREFIX+'policy.json'])
    P.need('inner_public_retention' not in policy, 'no prior inner retention declaration')
    policy['inner_public_retention'] = E.DECLARATION
    bodies[PREFIX+'policy.json'] = P.encode(policy)
    bodies[MARKER] = P.encode(dict(kind='LLHTTP_INNER_STRICT_PUBLIC_RETENTION_V6',
        parent_source='8f6370a35215496c0e6c10922929028f5146644b', parent_map=PARENT_MAP,
        parent_tree=PARENT_TREE, parent_files=93, parent_bytes=1204391,
        before={n: dict(pin=P.pin(old[n]), mode=0o644, body_base64=base64.b64encode(old[n]).decode()) for n in CHANGED},
        helper=P.pin(helper), seams=seams, actual=None, native_pair='NOT RUN', Root_acceptance=None,
        actual95='HOLD; Source RO observed; inner cause UNPROVEN; original evidence unchanged',
        preservation='all failed payload and cleanup predicates, held Source, resources, custody, zeroAPT and GoVA unchanged'))
    bodies.pop('source-map.json'); bodies.pop(PREFIX+'owner-program.json')
    bodies[PREFIX+'owner-program.json'] = P.encode(dict(schema=1,
        base_source_map_sha256=json.loads(old[PREFIX+'owner-program.json'])['base_source_map_sha256'],
        files={n: dict(P.pin(raw), mode=0o644) for n, raw in sorted(bodies.items()) if not n.startswith('held-source/')}))
    bodies['source-map.json'] = P.encode(dict(json.loads(old['source-map.json']),
        files={n: dict(P.pin(raw), mode=0o644) for n, raw in sorted(bodies.items())}))
    return bodies


def inverse(bodies):
    marker = json.loads(bodies[MARKER])
    P.need(set(marker['before']) == set(CHANGED) and marker['parent_map'] == PARENT_MAP, 'complete compact93 inverse ledger')
    old = {n: raw for n, raw in bodies.items() if n not in (HELPER, MARKER)}
    for name, row in marker['before'].items():
        raw = base64.b64decode(row['body_base64'], validate=True)
        P.need(P.pin(raw) == row['pin'] and row['mode'] == 0o644, 'whole compact original body/mode')
        old[name] = raw
    validate_parent(old)
    P.need(bodies == assemble(old), 'whole canonical successor and compact inverse')
    P.need(all(bodies[n] == raw for n, raw in old.items() if n not in CHANGED), 'all other93 bytes unchanged')
    return old


def construct(parent, output):
    parent, output = map(P.ordinary, (parent, output))
    P.need(not output.exists() and not output.is_relative_to(parent) and not parent.is_relative_to(output), 'fresh disjoint Source output')
    old = parent_bodies(parent)
    bodies = assemble(old)
    inverse(bodies)
    P.need(len(bodies) == 95 and len(bodies) < 96 and sum(map(len, bodies.values())) < 2*1024**2, 'unchanged strict96/2MiB Source limits')
    output.mkdir(mode=0o700)
    for name, raw in bodies.items():
        target = output/name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(raw)
        target.chmod(0o644)
    D = P5.P4.P3.load(output/PREFIX/'data.py', 'llhttp_v6_closed_source_data')
    D.source(output, P.pin(bodies['source-map.json'])['sha256'])
    return dict(status='SOURCE_DATA_ONLY', files=len(bodies), bytes=sum(map(len, bodies.values())), tree=P.tree(bodies),
                source_map=P.pin(bodies['source-map.json']), policy=P.pin(bodies[PREFIX+'policy.json']),
                program=P.pin(bodies[PREFIX+'owner-program.json']), actual=json.loads(bodies['source-map.json'])['actual'],
                inner_cause='UNPROVEN', public_retention_effect='NOT RUN', native_pair='NOT RUN', Root_acceptance=None)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('parent', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(construct(args.parent, args.output), indent=2, sort_keys=True))
