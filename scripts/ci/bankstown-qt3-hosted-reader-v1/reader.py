#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Passive composition of maintained audio predicates; never an authority issuer."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
AUDIO = 'scripts/ci/bankstown-qt3-native-source/'
HOSTED = 'scripts/ci/bankstown-qt3-hosted-v1/'
PROFILE = 'scripts/ci/bankstown-qt3-native-profile-v1/'
WORKFLOW = '.github/workflows/native-arm-bankstown-qt3-hosted-v1.yml'
SOURCE78 = dict(bytes=15363, sha256='dc3197203a91bdcd98cdd98f4f672d05abbc6865e26f2b744c3646c1b4d761eb')
RESULT_PIN = dict(bytes=25600, sha256='52446cb3b534fe041be3656f8d1f2cf3cd75a87a2878fd53457e54fd433a7355')
FINAL = dict(Root_acceptance=None, native_acceptance=False, hardware_acceptance=False,
             release_acceptance=False, source='HELD', legal='HELD', key_freshness='HELD',
             exact_Qt_recipe_correspondence='HELD', original_Qt_minus2='UNCHANGED',
             platform='NOT_RUN', M2='NOT_RUN')


def load(name, member):
    spec = importlib.util.spec_from_file_location('audio_reader_' + name, ROOT / member)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load('handoff', AUDIO + 'handoff.py')
P = load('prepare', HOSTED + 'prepare.py')
L = load('hosted', HOSTED + 'hosted.py')
N = load('inputs', HOSTED + 'inputs.py')
I = load('audio_inputs', AUDIO + 'inputs.py')
C = load('context', AUDIO + 'context.py')
E = load('controller', AUDIO + 'controller.py').E
J = load('inventory', PROFILE + 'inventory.py')
need, pin, encoded = H.need, H.pin, H.encoded


def reference(path, digest):
    path = N.ordinary(str(path))
    return dict(path=str(path), bytes=path.lstat().st_size, sha256=digest)


def selected(row, cap=4 * 1024**2):
    raw = N.read_reference(row, cap)
    value = H.decoded(raw)
    need(raw == encoded(value), 'CANONICAL_EXTERNALLY_SELECTED_DATA')
    return value


def source_readiness(source_root):
    """Check files-only Source78 as DATA. No publication/runtime IDs are inferred."""
    root = N.ordinary(str(source_root))
    raw = H.verify_reference(dict(path=str(root / 'source-map.json'), **SOURCE78),
                             cap=128 * 1024, body=True)
    value = H.decoded(raw)
    need(set(value) == {'schema', 'kind', 'operation', 'actual', 'files'}
         and type(value['schema']) is int and value['schema'] == 1
         and value['kind'] == C.SOURCE_KIND and value['operation'] == C.OPERATION
         and type(value['files']) is dict and len(value['files']) == 76
         and value['actual'] and all(v is None for v in value['actual'].values()),
         'EXACT_UNISSUED_SOURCE78')
    P.namespace(root, set(value['files']) | {'source-map.json', 'source.lock.json'})
    total = 0
    for name, row in dict(value['files'], **{'source-map.json': dict(SOURCE78, mode=0o644),
                                          'source.lock.json': dict(SOURCE78, mode=0o644)}).items():
        path = root / name
        need(stat.S_IMODE(path.lstat().st_mode) == row['mode'], 'EXACT_SOURCE78_MODE')
        H.verify_reference(dict(path=str(path), bytes=row['bytes'], sha256=row['sha256']),
                           cap=64 * 1024**2)
        total += row['bytes']
    need(total == 35742081, 'EXACT_SOURCE78_TOTAL')
    L.source72_parent(root)
    # Every selected runtime also equals this trusted Main dependency, before
    # any maintained pure definition is composed. Source remains opaque DATA.
    for name in P.RUNTIME:
        member = HOSTED + name
        need(N.read_reference(dict(path=str(ROOT / member),
             **{k: value['files'][member][k] for k in ('bytes', 'sha256')}), 128 * 1024)
             == (root / member).read_bytes(), 'SAME_REVIEWED_HOSTED_DEPENDENCY')
    joins = J.check((root / 'inputs/prospective477.expected.DATA.lock').read_bytes(),
                    (ROOT / (PROFILE + 'expected349.lock')).read_bytes(),
                    (root / 'inputs/catalog333.DATA.json').read_bytes())
    return dict(status='PASS_SOURCE78_DATA_ONLY', files=78, bytes=total, source_map=SOURCE78,
                preserved_Source72_members=70, prospective_inventory_joins=joins,
                hosted_dispatch='HELD_SOURCE78_OMITS_WORKFLOW', dispatch_ready=False,
                hosted_workflow_member=WORKFLOW,
                actual=dict(source=None, ref=None, run=None, job=None, image=None,
                            executor=None, Main=None, grants=None), **FINAL)


def workflow_binding(root, d, workflow, registration):
    """Join separately selected Main registration and the actual dispatch leaf."""
    need(type(registration) is dict and set(registration) == {'id', 'ref', 'sha'}
         and type(registration['id']) is int and registration['id'] > 0
         and registration['ref'] == d['hosted']['workflow_ref']
         and registration['sha'] == d['hosted']['workflow_sha']
         and d['hosted']['repository'] == 'Gabriel-Kahen/cachy-asahi'
         and d['hosted']['job_key'] == 'audio'
         and d['hosted']['job_name'] == 'bankstown-qt3-hosted-v1'
         and registration['ref'] == d['hosted']['repository'] + '/' + WORKFLOW + '@' + d['binding']['ref'],
         'SEPARATE_EXACT_WORKFLOW_REGISTRATION')
    workflow_body = N.read_reference(workflow, 128 * 1024)
    need(workflow_body == (ROOT / WORKFLOW).read_bytes(), 'EXACT_TOKEN_FREE_READ_ONLY_WORKFLOW')
    # GitHub dispatch selects the workflow at the requested Source ref. A Main
    # registration is a separate role and cannot supply an absent Source leaf.
    need((root / WORKFLOW).is_file() and (root / WORKFLOW).read_bytes() == workflow_body,
         'HELD_SOURCE78_OMITS_WORKFLOW_AT_DISPATCH_REF')


def admit_inputs(*, source_root, request_path, request_sha256, provider, context,
                 workflow, registration, now=None):
    """Rejoin independently selected DATA and stream all773 operands, no actors.

    provider/context/workflow are whole references. registration is the caller's
    separate actual workflow {id,ref,sha}; this function does not authenticate it.
    No kernel/host/runtime probe or native role is selected.
    """
    proof = source_readiness(source_root)
    root = N.ordinary(str(source_root))
    r = L.request(request_path, request_sha256)
    now = int(time.time()) if now is None else now
    d = C.validate_delegation(r['delegation_json'].encode(), r['delegation_pin']['sha256'], now)
    C.source(d, root)
    need(d['binding']['source_lock'] == SOURCE78, 'SELECTED_SOURCE78_MAP')
    c = selected(context)
    C.validate_context(d, c, now=now)
    C.context_contract(d, c)
    need(c['source_root'] == str(root), 'EXACT_READER_SOURCE_ROOT')
    workflow_binding(root, d, workflow, registration)
    p = C.decode(C.read(root / d['policy']['member'])[0])
    E.validate_policy(p, d)
    need(d['context_limits'] == p['context'] and p['context']['max_delegation_seconds'] == 4320
         and d['expires_epoch'] - d['issued_epoch'] >= 4140
         and p['hosted_transport_v1']['whole_launcher_seconds'] == L.LIMITS['launcher_seconds'] == 4170
         and p['executor_current_v3']['controller_seconds'] == 3960,
         'FULL_UNEXTENDED_HOSTED_WINDOW')
    envelope, intake = complete_inputs(source_root=root, request=r, delegation=d, provider=provider)
    return dict(root=root, request=r, delegation=d, context=c, inputs=envelope, policy=p,
                Source=proof, intake=intake, workflow_registration=registration)


def complete_inputs(*, source_root, request, delegation, provider):
    """Finite complete773 DATA check; grants no hosted/runtime readiness.

    Caller must validate Source and delegation separately before any actual use.
    This pure seam also exposes the mandatory provider/body composition when the
    fixed Source78's absent workflow prevents an actual hosted admission.
    """
    root, r, d = Path(source_root), request, delegation
    envelope = selected(r['staged_inputs'])
    metadata = N.validate_hosted_inputs_v3(inputs=envelope, delegation=d, source_root=root)
    fields = I.provider_fields(selected(provider), source_root=root)
    owner = envelope['owner_inputs']
    need(all(owner[k] == v for k, v in fields.items()), 'SAME_COMPLETE517_PROVIDER_FIELDS')
    plan = I.plan_inputs(source_root=root, source_rows=C.source_rows(d, root),
                         request=owner, verify_archives=True)
    refs = metadata['required_refs']
    need(len(refs) == 779 and len(plan['base_rows']) == 257 and len(plan['additions']) == 128,
         'MANDATORY_COMPLETE773_PLUS_SIX_METADATA')
    # The real maintained preprivilege intake enforces root confinement, all
    # exact refs, whole bodies, private-key refusal and its180-second deadline.
    checked, intake = L.H.checked_inputs(r, d, root, C, time.monotonic() + 180)
    need(checked == owner and intake['files'] == 779, 'WHOLE_COMPLETE773_INTAKE')
    return envelope, intake


def qualify_result(state, records, *, reader_pin, now_monotonic=None):
    need(reader_pin == pin(Path(__file__).read_bytes()), 'EXTERNALLY_SELECTED_EXECUTING_READER')
    H.verify_reference(dict(path=str(HERE / 'result.py'), **RESULT_PIN), cap=128 * 1024)
    result = load('result', 'scripts/ci/bankstown-qt3-hosted-reader-v1/result.py')
    return result.qualify(state, records, reader_pin=reader_pin,
                          now_monotonic=time.monotonic() if now_monotonic is None else now_monotonic)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('source', 'inputs', 'result'))
    parser.add_argument('--source-root', type=Path, required=True)
    for role in ('request', 'provider', 'context', 'workflow', 'registration', 'records'):
        parser.add_argument('--' + role, type=Path)
        parser.add_argument('--' + role + '-sha256')
    parser.add_argument('--reader-sha256')
    args = parser.parse_args()
    if args.operation == 'source':
        report = source_readiness(args.source_root)
    else:
        for role in ('request', 'provider', 'context', 'workflow', 'registration'):
            need(getattr(args, role) is not None and getattr(args, role + '_sha256') is not None,
                 'EXPLICIT_WHOLE_' + role.upper())
        state = admit_inputs(source_root=args.source_root, request_path=args.request,
            request_sha256=args.request_sha256,
            **{role: reference(getattr(args, role), getattr(args, role + '_sha256'))
               for role in ('provider', 'context', 'workflow')},
            registration=selected(reference(args.registration, args.registration_sha256)))
        report = dict(status='PASS_COMPLETE773_INPUT_DATA_ONLY', intake=state['intake'], **FINAL)
        if args.operation == 'result':
            need(args.records is not None and args.records_sha256 is not None
                 and args.reader_sha256 is not None, 'EXPLICIT_RESULT_AND_READER_SELECTION')
            report = qualify_result(state, selected(reference(args.records, args.records_sha256)),
                reader_pin=dict(bytes=Path(__file__).stat().st_size, sha256=args.reader_sha256))
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('HOLD_BANKSTOWN_QT3_READER: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(2)
