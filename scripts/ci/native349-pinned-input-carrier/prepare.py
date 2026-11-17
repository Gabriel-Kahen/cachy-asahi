#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Lossless fixed95-leaf Source95 successor with an unissued carrier case."""
import argparse
import ast
import base64
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAMILY = HERE.parent/'llhttp-reference-native-source/successor_v6/prepare.py'
spec = importlib.util.spec_from_file_location('frozen_source95', FAMILY)
Q = importlib.util.module_from_spec(spec); spec.loader.exec_module(Q)
P = Q.P
PREFIX = P.PREFIX
MAP = dict(bytes=20200, sha256='ab743415f602ba8c5f81a063fc7cc5d25587be0d535601396f2ee617fb4149ce')
TREE = 'b73f92b1ed4e6f6ab8c4210fdaa19617b1a5721f'
OLD_WF = '.github/workflows/native-arm-llhttp-reference-source.yml'
NEW_WF = '.github/workflows/native-arm-llhttp-pinned-input-source.yml'
REPACK = PREFIX+'successor-v5-README.md'
HELPER = PREFIX+'native349_carrier.py'
MARKER = 'inner-public-retention-v6.json'
CHANGED = (PREFIX+'hosted_owner.py', PREFIX+'payload.py', PREFIX+'policy.json', PREFIX+'owner-program.json',
           'source-map.json', MARKER, OLD_WF, REPACK)


def parent_bodies(root):
    root = P.ordinary(root)
    names = {str(n.relative_to(root)) for n in root.rglob('*') if n.is_file() or n.is_symlink()}
    bodies = {n: P.read(root/n) for n in sorted(names)}
    P.need(all((root/n).stat().st_mode & 0o777 == 0o644 for n in names), 'whole frozen95 modes')
    validate_parent(bodies)
    return bodies


def validate_parent(bodies):
    P.need(P.pin(bodies['source-map.json']) == MAP and len(bodies) == 95 and sum(map(len, bodies.values())) == 1318237
           and P.tree(bodies) == TREE, 'whole immutable95 source')
    rows = json.loads(bodies['source-map.json'])
    P.need(set(bodies) == set(rows['files']) | {'source-map.json'} and all(dict(P.pin(bodies[n]), mode=0o644) == r for n, r in rows['files'].items())
           and all(v is None for v in rows['actual'].values()), 'all95 bytes/modes/NULL selectors')
    P.need(len(Q.inverse(bodies)) == 93, 'complete95/93/85/76/68/62 inverse')


def runtime():
    raw = P.read(HERE/'carrier.py').decode()
    for name, file in (('EXPECTED', 'expected-files.json'), ('BINDING', 'binding.TEMPLATE.json'), ('HOST_REFERENCE', 'github-host-reference.json')):
        before = name+" = json.loads((HERE/'"+file+"').read_text())"
        P.need(raw.count(before) == 1, 'one literal Source data binding')
        raw = raw.replace(before, name+' = '+repr(json.loads(P.read(HERE/file))))
    ast.parse(raw)
    return raw.encode()


def project(old):
    changes = {}; seams = {}
    def replace(name, before, after):
        text = changes.get(name, old[name]).decode()
        P.need(text.count(before) == 1 and after not in text, 'one exact carrier seam')
        changes[name] = text.replace(before, after).encode()
        seams.setdefault(name, []).append(dict(before=before, after=after))
    host = PREFIX+'hosted_owner.py'; payload = PREFIX+'payload.py'
    anchor = "s=importlib.util.spec_from_file_location('llhttp_public_evidence_v6',HERE/'public_evidence.py');E=importlib.util.module_from_spec(s);s.loader.exec_module(E)"
    replace(host, anchor, anchor+"\ns=importlib.util.spec_from_file_location('native349_public_carrier',HERE/'native349_carrier.py');N=importlib.util.module_from_spec(s);s.loader.exec_module(N)")
    replace(host, "    for name in ('root','output'):parser.add_argument('--'+name,type=Path,required=True)",
                  "    for name in ('root','output','carrier-root'):parser.add_argument('--'+name,type=Path,required=True)")
    anchor = "        daemon,available,disk=owner.setup();volume=a.output/'volume';work=volume/'work';marker=work/'actual-owner.json'"
    replace(host, anchor, anchor+"\n        report['pinned_input_carrier']=N.stage(a.carrier_root,work/'native349-pinned-inputs',a.runner_uid,a.runner_gid)")
    replace(host, "                    marker=str(marker),output=str(work/'llhttp-reference-native'))",
                  "                    marker=str(marker),output=str(work/'llhttp-reference-native'),pinned_inputs=str(work/'native349-pinned-inputs'))")
    anchor = "s = importlib.util.spec_from_file_location('llhttp_mount_accounting_v4',HERE/'mount_accounting.py');M=importlib.util.module_from_spec(s);s.loader.exec_module(M)"
    replace(payload, anchor, anchor+"\ns = importlib.util.spec_from_file_location('native349_public_carrier',HERE/'native349_carrier.py');N=importlib.util.module_from_spec(s);s.loader.exec_module(N)")
    replace(payload, "    namespace = dict(__name__='llhttp-reference_v2_held_entry',__file__=str(entry_path))",
                     "    namespace = dict(__name__='llhttp-reference_v2_held_entry',__file__=str(entry_path),PINNED_CARRIER=N,PINNED_INPUTS=Path(config['pinned_inputs']))")
    replace(payload, "    exec(compile(D.projected_entry(D.read(entry_path)),str(entry_path),'exec'),namespace)",
                     "    exec(compile(N.project_entry(D.projected_entry(D.read(entry_path))),str(entry_path),'exec'),namespace)")
    for name, parts in seams.items():
        reverse = changes[name].decode()
        for part in reversed(parts): reverse = reverse.replace(part['after'], part['before'])
        P.need(reverse.encode() == old[name], 'whole original controller/payload inverse')
    return changes, seams


def assemble(old):
    validate_parent(old)
    changes, seams = project(old)
    new = dict(old); new.update(changes)
    new[HELPER] = runtime(); new[NEW_WF] = P.read(HERE/'workflow.yml.in')
    del new[OLD_WF]; del new[REPACK]
    expected = json.loads(P.read(HERE/'expected-files.json')); binding = json.loads(P.read(HERE/'binding.TEMPLATE.json'))
    policy = json.loads(old[PREFIX+'policy.json'])
    policy['private_pinned_input_carrier'] = dict(kind='ONLY_EXACT_MISSING182_BEFORE_UNCHANGED_ALL501', input_lock_sha256=expected['input_lock_sha256'],
        files=182, bytes=544634853, largest=104330276, namespace='manifest.json + packages/<exact filename>', binding=binding,
        fetch_tools=['git', 'ssh', 'ssh-keygen'], host_package_mutations=0, SSH_agent=False, private_key_scope='fetch step only;0600;delete before controller',
        fetch_seconds=180, fetch_process_AS_bytes=2*1024**3, fetch_CPU_seconds=45, fetch_staging_bytes=2*544634853+64*1024**2,
        added_preflight_disk_reserve_bytes=2*544634853+64*1024**2, existing_controller_resources_changed=False,
        seed_destination='owned quota volume/work/llhttp-reference-native/cache', all501_required=True, canonical_GPG_required=True,
        URL_overrides=False, new_workflow=NEW_WF, Root_registration=None)
    new[PREFIX+'policy.json'] = P.encode(policy)
    # One existing marker holds every changed/deleted95 before-body. No leaf cap expansion.
    new[MARKER] = P.encode(dict(kind='NATIVE349_PINNED_INPUT_CARRIER_SOURCE_V1', parent_tree=TREE, parent_map=MAP, parent_files=95, parent_bytes=1318237,
        before={n: dict(pin=P.pin(old[n]), mode=0o644, body_base64=base64.b64encode(old[n]).decode()) for n in CHANGED}, seams=seams,
        helper=P.pin(new[HELPER]), workflow=P.pin(new[NEW_WF]), binding=binding, actual=None, Root_acceptance=None, native_pair='NOT RUN'))
    new.pop('source-map.json'); new.pop(PREFIX+'owner-program.json')
    new[PREFIX+'owner-program.json'] = P.encode(dict(schema=1, base_source_map_sha256=json.loads(old[PREFIX+'owner-program.json'])['base_source_map_sha256'],
        files={n: dict(P.pin(raw), mode=0o644) for n, raw in sorted(new.items()) if not n.startswith('held-source/')}))
    new['source-map.json'] = P.encode(dict(json.loads(old['source-map.json']), files={n: dict(P.pin(raw), mode=0o644) for n, raw in sorted(new.items())}))
    return new


def inverse(bodies):
    value = json.loads(bodies[MARKER]); P.need(set(value['before']) == set(CHANGED), 'whole compact95 inverse')
    old = {n: raw for n, raw in bodies.items() if n not in (HELPER, NEW_WF)}
    for name, row in value['before'].items():
        raw = base64.b64decode(row['body_base64'], validate=True)
        P.need(P.pin(raw) == row['pin'] and row['mode'] == 0o644, 'whole original95 body/mode'); old[name] = raw
    validate_parent(old)
    P.need(bodies == assemble(old), 'whole literal carrier successor')
    return old


def construct(parent, output):
    parent, output = map(P.ordinary, (parent, output))
    P.need(not output.exists() and not output.is_relative_to(parent) and not parent.is_relative_to(output), 'fresh disjoint Source output')
    new = assemble(parent_bodies(parent)); inverse(new)
    P.need(len(new) == 95 and len(new) < 96 and sum(map(len, new.values())) < 2*1024**2, 'unchanged strict95/96/2MiB Source bounds')
    output.mkdir(mode=0o700)
    for name, raw in new.items():
        target = output/name; target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream: stream.write(raw)
        target.chmod(0o644)
    D = Q.P5.P4.P3.load(output/PREFIX/'data.py', 'unissued_native349_closed_source'); D.source(output, P.pin(new['source-map.json'])['sha256'])
    return dict(status='UNISSUED_PRIVATE_CARRIER_SOURCE_PROPOSAL', files=len(new), bytes=sum(map(len, new.values())), tree=P.tree(new),
        source_map=P.pin(new['source-map.json']), policy=P.pin(new[PREFIX+'policy.json']), program=P.pin(new[PREFIX+'owner-program.json']),
        helper=P.pin(new[HELPER]), workflow_path=NEW_WF, workflow=P.pin(new[NEW_WF]), Root_registration=None,
        carrier_binding=json.loads(P.read(HERE/'binding.TEMPLATE.json')), actual=json.loads(new['source-map.json'])['actual'], native_pair='NOT RUN')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('parent', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args(); print(json.dumps(construct(args.parent, args.output), sort_keys=True, indent=2))
