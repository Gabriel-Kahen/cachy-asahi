#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure DATA filesystem-observation successor to exact public Source76."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE_PINS = {
    'successor_v2/prepare.py': dict(bytes=8931, sha256='9da8a325c0ca13dd1325e5e5903652f046d31678294c826c83276d1a84b2c39f'),
    'successor_v3/prepare.py': dict(bytes=10724, sha256='0d6ac04a67aaa750ff6d696c30a729433b8398c64bb7c130d4f1ef49f46c418c'),
}
for name, expected in MODULE_PINS.items():
    raw = (HERE.parent/name).read_bytes()
    if dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) != expected:
        raise ValueError('whole pinned predecessor constructor: '+name)
spec = importlib.util.spec_from_file_location('llhttp_v4_previous_data', HERE.parent/'successor_v3/prepare.py')
P3 = importlib.util.module_from_spec(spec); spec.loader.exec_module(P3)
P = P3.P
PREFIX = P.PREFIX
PARENT_MAP = dict(bytes=16377, sha256='8e6290fb7c916ba52d094d2a324b7ba77e8813c910a6e454a8f78f0aeda92d57')
PARENT_TREE = 'ff131da635fc160b557c58ce0f716a997a918551'
PARENT_SOURCE = '28dae2796f6f50f42da19be89618c5fda0549d2c'
CHANGED = tuple(PREFIX+n for n in ('payload.py', 'data.py', 'policy.json', 'owner-program.json'))
MARKER = 'mount-class-diagnostics-v4.json'
HELPER = 'mount_accounting.py'
HELPER_PIN = dict(bytes=7940, sha256='439cf67e561692e7987a9092d2fed8e5d825bdc28a822ab8e54a63bf331bfada')
EVIDENCE_PIN = dict(bytes=7710, sha256='e16370da6417ea8236ae6b26075059abc0b27caff64dcd723b8628c9fa31803a')
README_PIN = dict(bytes=4531, sha256='ee6f4467307f1325c0b593f56d9951b80623cdac3cf474d04a997eb562459a20')
REVIEW_INPUTS = ('README.md', 'evidence.DATA.json')
GUARD = "    D.need(not os.access('/tmp',os.W_OK) and not os.access('/var/tmp',os.W_OK) and not os.access(root,os.W_OK),'actual owner writable filesystem restricted to quota work domain')"
CAPACITY = "32 < len(rows) < 80"


def parent_bodies(parent):
    parent = P.ordinary(parent)
    raw = P.read(parent/'source-map.json')
    P.need(P.pin(raw) == PARENT_MAP, 'whole exact public Source76 map')
    P.need((parent/'source-map.json').stat().st_mode & 0o777 == 0o644, 'exact public Source76 map mode')
    value = json.loads(raw)
    found = {str(n.relative_to(parent)) for n in parent.rglob('*') if n.is_file() or n.is_symlink()}
    P.need(found == set(value['files']) | {'source-map.json'} and len(found) == 76
           and all(v is None for v in value['actual'].values()), 'complete ordinary Source76 namespace and NULL selectors')
    bodies = {n: P.read(parent/n) for n in sorted(found)}
    P.need(all(dict(P.pin(bodies[n]), mode=(parent/n).stat().st_mode & 0o777) == row
               and row['mode'] == 0o644 for n, row in value['files'].items()), 'whole Source76 pinned bytes and modes')
    validate_parent(bodies)
    return bodies, value


def validate_parent(bodies):
    P.need(P.pin(bodies['source-map.json']) == PARENT_MAP, 'complete retained Source76 map')
    value = json.loads(bodies['source-map.json'])
    P.need(set(bodies) == set(value['files']) | {'source-map.json'} and len(bodies) == 76
           and sum(map(len, bodies.values())) == 1053728 and P.tree(bodies) == PARENT_TREE,
           'complete Source76 inverse namespace, bytes and physical Git tree')
    P.need(all(dict(P.pin(bodies[n]), mode=0o644) == row for n, row in value['files'].items())
           and all(v is None for v in value['actual'].values()), 'whole Source76 inverse modes and NULL selectors')
    previous68 = P3.inverse(bodies)
    P.need(len(previous68) == 68 and len(P.inverse(previous68)) == 62, 'whole predecessor76/68/62 inverse chain')


def projections(old):
    code, seams = {}, {}
    def replace(name, before, after):
        text = code.get(name, old[name]).decode()
        P.need(text.count(before) == 1 and after not in text, 'one exact observation seam: '+name)
        code[name] = text.replace(before, after).encode()
        seams.setdefault(name, []).append(dict(before=before, after=after))
    payload = PREFIX+'payload.py'
    anchor = "s = importlib.util.spec_from_file_location('llhttp_payload_diagnostic_v3',HERE/'payload_diagnostic.py');X=importlib.util.module_from_spec(s);s.loader.exec_module(X)"
    replace(payload, anchor, anchor+"\ns = importlib.util.spec_from_file_location('llhttp_mount_accounting_v4',HERE/'mount_accounting.py');M=importlib.util.module_from_spec(s);s.loader.exec_module(M)")
    replace(payload, GUARD, "    print(M.record(M.observe(root,Path(config['output']).parent)),file=sys.stderr)\n"+GUARD)
    replace(PREFIX+'data.py', CAPACITY, '32 < len(rows) < 96')
    for name, changes in seams.items():
        text = code[name].decode()
        for seam in reversed(changes):
            P.need(text.count(seam['after']) == 1, 'one exact observation inverse seam')
            text = text.replace(seam['after'], seam['before'])
        P.need(text.encode() == old[name], 'whole projection inverse')
    P.need(code[payload].decode().count(GUARD) == 1, 'byte-identical aggregate confinement guard')
    return code, seams


def assemble(old):
    code, seams = projections(old)
    helper = P.read(HERE/HELPER)
    P.need(P.pin(helper) == HELPER_PIN, 'whole pinned observation helper custody')
    M = P3.load(HERE/HELPER, 'llhttp_v4_mount_policy_data')
    bodies = dict(old); bodies.update(code)
    policy = json.loads(old[PREFIX+'policy.json'])
    P.need('mount_class_diagnostics' not in policy, 'no previous mount declaration')
    policy['mount_class_diagnostics'] = M.DECLARATION
    bodies[PREFIX+'policy.json'] = P.encode(policy)
    bodies[PREFIX+HELPER] = helper
    for name in REVIEW_INPUTS:
        bodies[PREFIX+'successor-v4-'+name] = P.read(HERE/name)
    P.need(P.pin(bodies[PREFIX+'successor-v4-evidence.DATA.json']) == EVIDENCE_PIN,
           'whole pinned retained public evidence DATA')
    P.need(P.pin(bodies[PREFIX+'successor-v4-README.md']) == README_PIN,
           'whole pinned source-review notes')
    for name in (*CHANGED, 'source-map.json'):
        bodies['previous-v3/'+name] = old[name]
    bodies[MARKER] = P.encode(dict(
        kind='LLHTTP_MOUNT_CLASS_DIAGNOSTICS_V4', parent_source=PARENT_SOURCE,
        parent_map=PARENT_MAP, parent_tree=PARENT_TREE, parent_files=76,
        parent_bytes=1053728, actual=None, native_pair='NOT RUN',
        Root_closure_review='PENDING', actual87_status='HOLD',
        actual87_cleanup_verified=True, actual87_payload_success=False,
        retroactive_acceptance=False, seams=seams, helper=HELPER_PIN,
        review_inputs={n: P.pin(bodies[PREFIX+'successor-v4-'+n]) for n in REVIEW_INPUTS}))
    bodies.pop('source-map.json'); bodies.pop(PREFIX+'owner-program.json')
    program = P.encode(dict(schema=1,
        base_source_map_sha256=json.loads(old[PREFIX+'owner-program.json'])['base_source_map_sha256'],
        files={n: dict(P.pin(raw), mode=0o644) for n, raw in sorted(bodies.items()) if not n.startswith('held-source/')}))
    bodies[PREFIX+'owner-program.json'] = program
    bodies['source-map.json'] = P.encode(dict(json.loads(old['source-map.json']),
        files={n: dict(P.pin(raw), mode=0o644) for n, raw in sorted(bodies.items())}))
    return bodies


def inverse(bodies):
    additions = {MARKER, PREFIX+HELPER, *(PREFIX+'successor-v4-'+n for n in REVIEW_INPUTS)}
    old = {n: raw for n, raw in bodies.items() if n not in additions and n != 'source-map.json' and not n.startswith('previous-v3/')}
    for name in (*CHANGED, 'source-map.json'):
        old[name] = bodies['previous-v3/'+name]
    validate_parent(old)
    P.need(bodies == assemble(old), 'whole canonical successor namespace, projections, policy, helper, program and source-map')
    P.need(bodies[PREFIX+'hosted_owner.py'] == old[PREFIX+'hosted_owner.py'], 'whole unchanged controller and systemd service arguments')
    P.need(all(bodies[n] == raw for n, raw in old.items() if n.startswith('held-source/')), 'whole unchanged held-source and base')
    return old


def construct(parent, output):
    parent, output = map(P.ordinary, (parent, output))
    P.need(not output.exists() and not output.is_relative_to(parent), 'fresh disjoint successor output')
    old, prior = parent_bodies(parent)
    bodies = assemble(old)
    inverse(bodies)
    P.need(len(bodies) == 85 and len(bodies) < 96 and sum(map(len, bodies.values())) < 2*1024**2,
           'finite metadata-only namespace expansion; unchanged 2MiB byte cap')
    output.mkdir(mode=0o700)
    for name, raw in bodies.items():
        path = output/name; path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
        path.chmod(0o644)
    D = P3.load(output/PREFIX/'data.py', 'llhttp_v4_closed_source_data')
    D.source(output, P.pin(bodies['source-map.json'])['sha256'])
    return dict(status='SOURCE_DATA_ONLY', files=len(bodies), bytes=sum(map(len, bodies.values())),
        tree=P.tree(bodies), source_map=P.pin(bodies['source-map.json']),
        policy=P.pin(bodies[PREFIX+'policy.json']), program=P.pin(bodies[PREFIX+'owner-program.json']),
        actual=prior['actual'], native_pair='NOT RUN', Root_closure_review='PENDING')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('parent', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(construct(args.parent, args.output), indent=2, sort_keys=True))
