# SPDX-License-Identifier: MIT
"""Exact retained-two authority bridge; no CLI, GPG or generalized admission."""
import ast
import copy
import hashlib
import os
from pathlib import Path
import sys
import types

INTAKE_SHA = '345fb5b49bccfc611234196eee65159d7b8372a6de49d05b1572166acd8ad7e2'
CONSUMER_SHA = '25385b498845920575a12068f58af05159aed9482119227b43859489a4eb453f'
PROOF_PINS = {
    'proof/actual-receipt.json': '53747d29b02c11517d3c330530f9a6de57afcd9575e0c75c8f23f2dbd7fb6b3c',
    'proof/retained-2.json': '9407330375b60db80180abdbfffdd50bdd811c3269a9e665f8696efb8cbe223e',
    'proof/retained-3.json': '0c4c8e7755195c6f33f83df9de746c4406520806e0e4856315444d0e23f68205',
    'proof/process-observations.json': '8d19c8f6b70218007b1ce06766913c48b4fdeabe5fe6796fb44b6d09f59ef02e',
}


def _source(core, module, expected):
    raw = getattr(module, '__source_bytes__', None)
    core.need(type(raw) is bytes and 0 < len(raw) <= 262144
              and hashlib.sha256(raw).hexdigest() == expected
              and getattr(module, '__source_sha256__', None) == expected,
              'real-admission-module-pin')
    return raw


def _close_snapshot(held):
    """Attempt every private registered close once; failed FD state is unproved."""
    original = failure = sys.exc_info()[1]
    had_close_failure = False
    for _, fd, _ in reversed(held):
        try:
            os.close(fd)
        except BaseException as later:
            had_close_failure = True
            if failure is None or (isinstance(failure, Exception) and not isinstance(later, Exception)):
                later.__cause__ = failure
                failure = later
            else:
                failure.add_note('real-admission-snapshot-close-failure: ' + type(later).__name__)
    if had_close_failure:
        raise failure


def _custody_bridge(core, fresh, raw):
    functions = [n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef)
                 and n.name == 'snapshot']
    core.need(len(functions) == 1, 'real-admission-snapshot-source')
    function = copy.deepcopy(functions[0])
    old = ast.parse('for _, fd, _ in reversed(held):\n    os.close(fd)').body
    selected = [n for n in ast.walk(function) if isinstance(n, ast.Try)
                and ast.dump(ast.Module(body=n.finalbody, type_ignores=[]))
                == ast.dump(ast.Module(body=old, type_ignores=[]))]
    core.need(len(selected) == 1, 'real-admission-snapshot-close-bridge')
    selected[0].finalbody = ast.parse('_adapter_close_snapshot(held)').body
    ast.fix_missing_locations(function)
    fresh.__dict__['_adapter_close_snapshot'] = _close_snapshot
    exec(compile(ast.Module(body=[function], type_ignores=[]),
                 'pinned-consumer-custody-bridge', 'exec'), fresh.__dict__)


def _fresh(core, module, expected):
    raw = _source(core, module, expected)
    path = getattr(module, '__file__', None)
    core.need(type(path) is str and Path(path).is_absolute()
              and str(Path(path)) == path and '..' not in Path(path).parts,
              'real-admission-module-location')
    fresh = types.ModuleType('_real_retained_' + Path(path).stem)
    fresh.__file__ = path
    fresh.__source_bytes__, fresh.__source_sha256__ = raw, expected
    exec(compile(raw, path, 'exec'), fresh.__dict__)
    if expected == CONSUMER_SHA:
        _custody_bridge(core, fresh, raw)
    return fresh


def _bridge(core, intake):
    """Change exactly the modeled authority call; preserve the parser AST."""
    tree = ast.parse(_source(core, intake, INTAKE_SHA))
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                 and n.name == 'inspect_archive']
    core.need(len(functions) == 1, 'real-admission-parser-source')
    function = copy.deepcopy(functions[0])
    selected = [n for n in function.body if isinstance(n, ast.Assign)
                and ast.dump(n) == ast.dump(ast.parse(
                    'expected = _bindings(core, row, budget)').body[0])]
    core.need(len(selected) == 1, 'real-admission-authority-bridge')
    selected[0].value = ast.Name(id='_retained_expected', ctx=ast.Load())
    ast.fix_missing_locations(function)
    namespace = dict(intake.__dict__)
    code = compile(ast.Module(body=[function], type_ignores=[]),
                   'pinned-retained-two-payload-bridge', 'exec')
    # Expected metadata is attached to a private namespace per invocation.
    def payload(row, metadata, store, budget):
        local = dict(namespace, _retained_expected=copy.deepcopy(metadata))
        exec(code, local)
        return local['inspect_archive'](core, row, store, budget)
    return payload


def _proof_ref(core, consumer, raws, name):
    rows = [r for r in consumer.FILE_ROWS if r[0] == name]
    core.need(len(rows) == 1, 'real-admission-proof-reference')
    _, size, mode, digest = rows[0]
    core.need(hashlib.sha256(raws[name]).hexdigest() == digest,
              'real-admission-proof-reference')
    path = Path(consumer.BASE) / name
    info = path.lstat()
    core.need(info.st_size == size and info.st_uid == os.getuid()
              and info.st_mode & 0o7777 == mode, 'real-admission-proof-state')
    result = dict(path=str(path), size=size, sha256=digest, identity=core.identity(info))
    core.reference(result, 1048576)
    return result


def _metadata(core, intake, consumer, raws, association):
    leaf = 'proof/metadata-' + association['identity']['name'] + '.json'
    document = consumer.decode(raws[leaf])
    core.need(document['identity'] == association['identity']
              and document['payload_extracted_executed'] is False,
              'real-admission-metadata-source')
    fields = document['metadata']['.PKGINFO']['fields']
    expected = dict(association['identity'])
    for key, field in [('depends', 'depend'), ('provides', 'provides'),
                       ('conflicts', 'conflict'), ('replaces', 'replaces'),
                       ('license', 'license')]:
        expected[key] = fields.get(field, [])
    return intake.normalized_metadata(core, expected), leaf


def _discard(core, intake, store, result, failure):
    """Revoke parser-owned spools when later custody checks reject its result."""
    if result is None:
        return failure
    refs = list(result['bodies'].values()) + [r['ref'] for r in result['metadata'].values()]
    seen = set()
    for ref in reversed(refs):
        try:
            intake._spool_ref(core, ref, core.FILE)
            core.need(ref['name'] not in seen, 'real-admission-spool-alias')
            seen.add(ref['name'])
            store.discard(ref)
        except BaseException as later:
            failure = intake._priority(failure, later)
            failure.add_note('real-admission-discard-failure: ' + type(later).__name__)
    return failure


def inspect_selected(core, intake, consumer, identity, archive_ref, signature_ref, store, budget):
    """Explicit caller selection of one exact retained tuple; no discovery."""
    budget.check()
    intake = _fresh(core, intake, INTAKE_SHA)
    consumer = _fresh(core, consumer, CONSUMER_SHA)
    identity, archive_ref, signature_ref = copy.deepcopy((identity, archive_ref, signature_ref))
    core.package_identity(identity)
    core.reference(archive_ref, core.ARCHIVE)
    core.reference(signature_ref, 65536)
    result = None
    try:
        with consumer.snapshot() as (raws, check):
            budget.check()
            for name, digest in PROOF_PINS.items():
                core.need(hashlib.sha256(raws[name]).hexdigest() == digest,
                          'real-admission-retained-proof-pin')
            plan = consumer.decode(raws['inputs/assembly-plan.json'])
            index = consumer.decode(raws['inputs/package-reference-index.json'])
            verified = consumer.associations(raws, plan, index)
            core.need(verified == 'EXACT_TWO_RETAINED_SIGNED_DATA_ASSOCIATIONS',
                      'real-admission-association-result')
            side = consumer.decode(raws['two-associations.json'])
            matches = [r for r in side['associations'] if r['identity'] == identity]
            core.need(len(matches) == 1, 'real-admission-selected-identity')
            association = matches[0]
            for ref, key in ((archive_ref, 'archive'), (signature_ref, 'signature')):
                core.need({k: ref[k] for k in ('path', 'size', 'sha256')} == association[key],
                          'real-admission-selected-reference')
            expected, leaf = _metadata(core, intake, consumer, raws, association)
            row = dict(identity=identity, archive=archive_ref, signature=signature_ref,
                       authentication=_proof_ref(core, consumer, raws, 'proof/actual-receipt.json'),
                       source_admission=_proof_ref(core, consumer, raws, leaf))
            check()
            budget.check()
            # The trusted primitive hashes/binds current signature bytes before any
            # archive read. The unchanged parser hashes the archive before decoding.
            core.read_reference(signature_ref, 65536, budget)
            check()
            failure = None
            try:
                with budget.job():
                    result = _bridge(core, intake)(row, expected, store, budget)
                budget.check()
            except BaseException as error:
                failure = error
            finally:
                try:
                    check()
                except BaseException as later:
                    failure = intake._priority(failure, later)
            if failure is not None:
                raise failure
            # This envelope adds retained proof authority, not a new crypto actor or
            # a relabeling of the old parser's conservative compatibility fields.
            answer = {
                'status': 'PASS_RETAINED_TWO_BOUND_INERT_PAYLOAD',
                'authority': {'scope': 'EXACT_RETAINED_TWO_HISTORICAL_SIGNATURE_AND_METADATA',
                              'identity': identity, 'archive_sha256': archive_ref['sha256'],
                              'signature_sha256': signature_ref['sha256'],
                              'primary_fingerprint': consumer.FP,
                              'consumer_source_sha256': CONSUMER_SHA,
                              'source_metadata_sha256': row['source_admission']['sha256'],
                              'process_witness_sha256': PROOF_PINS['proof/process-observations.json'],
                              'retained_proof_sha256': dict(PROOF_PINS),
                              'signature_status': 'cryptographic-signature-valid',
                              'new_gpg_verification_executed': False,
                              'independent_owner_trust_accepted': False,
                              'signed_database_association': False},
                'payload': result,
                'payload_fields_role': 'INHERITED_PARSER_COMPATIBILITY_LABELS_UNCHANGED; EFFECTIVE_DATA_AUTHORITY_IS_SEPARATE',
                'source_build_license_hooks_ownertrust_all261_accepted': False,
                'image_assembly_installation_hardware_accepted': False,
            }
    except BaseException as failure:
        raise _discard(core, intake, store, result, failure)
    return answer


if __name__ == '__main__':
    raise SystemExit('real retained-two admission requires explicit pinned caller selection')
