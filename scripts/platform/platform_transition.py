#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Plan an offline coordinated Asahi platform transition; never prepare or apply it.

Exit 0: data plan complete, 2: concrete blockers, 1: malformed/unbound input.
Neither exit 0 nor an explicit policy establishes compatibility or recovery.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / 'scripts/platform/tuple_audit.py').is_file())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


transaction = module('transition_transaction', ROOT / 'scripts/platform/transaction.py')
preflight = module('transition_preflight', ROOT / 'scripts/platform/recovery_preflight.py')
comparison = module('transition_comparison', ROOT / 'scripts/release/compare_releases.py')
audit, recovery, need = preflight.audit, preflight.recovery, preflight.need
MAX_ROWS, MAX_SECONDS, MAX_ARCHIVE_BYTES = 4096, 120, 512 * 1024**2


def document(ref):
    return audit.load_json(transaction.bound(ref))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def identity(row):
    return tuple(row[key][0] for key in ('NAME', 'VERSION', 'ARCH'))


def inventory(state):
    need(set(state) == {'id', 'inventory', 'archive_index'} and isinstance(state['id'], str)
         and 0 < len(state['id']) <= 128, 'release state fields/id refused')
    doc = document(state['inventory'])
    fields = set(doc) & {'packages', 'proposed_final_inventory'}
    need(len(fields) == 1, 'one explicit inventory collection required')
    return preflight.metadata(doc[fields.pop()])


def as_release(rows, archives):
    return [{'name': name, 'version': row['VERSION'][0], 'arch': row['ARCH'][0],
             'depend': row.get('DEPENDS', []), 'provides': row.get('PROVIDES', []),
             'conflicts': row.get('CONFLICTS', []), 'replaces': row.get('REPLACES', []),
             'filename': Path(archives[name]['archive']['path']).name if name in archives else None,
             'sha256': archives[name]['archive']['sha256'] if name in archives else None}
            for name, row in sorted(rows.items())]


def inspect(ref, metadata, remaining):
    need(remaining > 0, 'transition deadline exceeded')
    request = json.dumps({'archive': ref, 'metadata': metadata}).encode()
    try:
        child = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--inspect'],
                               input=request, capture_output=True, timeout=min(20, remaining), check=False)
    except subprocess.TimeoutExpired:
        raise ValueError('archive metadata inspection deadline exceeded') from None
    need(child.returncode == 0 and child.stdout == b'OK\n' and not child.stderr,
         'archive metadata inspection refused: ' + metadata['NAME'][0])


def consumer_impact(before, after, remaining):
    need(remaining > 0, 'transition deadline exceeded')
    request = json.dumps({'before': before, 'after': after}).encode()
    need(len(request) <= 8 * recovery.MIB, 'dependency impact request bound exceeded')
    try:
        child = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--impact'],
                               input=request, capture_output=True, timeout=min(30, remaining), check=False)
    except subprocess.TimeoutExpired:
        raise ValueError('dependency impact deadline exceeded') from None
    need(child.returncode == 0 and len(child.stdout) <= 8 * recovery.MIB and not child.stderr,
         'bounded dependency impact refused')
    return audit.load_json(child.stdout)


def archive_index(state, rows, cache, started, documents):
    doc = document(state['archive_index'])
    need(set(doc) == {'schema_version', 'kind', 'packages'} and type(doc['schema_version']) is int
         and doc['schema_version'] == 1 and doc['kind'] == 'platform-archive-reference-index',
         'archive reference index schema refused')
    entries = doc['packages']
    need(isinstance(entries, list) and len(entries) <= MAX_ROWS, 'finite archive index required')
    found = {}
    for entry in entries:
        need(time.monotonic() - started <= MAX_SECONDS, 'transition deadline exceeded')
        need(set(entry) == {'name', 'archive', 'signature', 'provenance'}, 'archive binding fields refused')
        name = entry['name']
        need(name in rows and name not in found, 'archive package absent or duplicate')
        provenance = entry['provenance']
        need(set(provenance) == {'document', 'row'} and type(provenance['row']) is int,
             'provenance reference/row refused')
        pin = digest(provenance['document'])
        if pin not in documents:
            need(sum(value[0] for value in documents.values()) + provenance['document']['size'] <= 64 * recovery.MIB,
                 'aggregate provenance document bound exceeded')
            documents[pin] = (provenance['document']['size'], document(provenance['document']))
        source = documents[pin][1]
        need(isinstance(source.get('packages'), list) and 0 <= provenance['row'] < len(source['packages']),
             'provenance row refused')
        original = source['packages'][provenance['row']]
        metadata = original.get('metadata', original.get('observed_image_metadata'))
        need(metadata is not None and preflight.semantic(metadata) == preflight.semantic(rows[name]),
             'archive provenance metadata mismatch: ' + name)
        need(identity(metadata) == identity(rows[name]), 'archive provenance identity mismatch')
        if source.get('kind') == 'exact-superseded-recovery-archive-data':
            need(source.get('inputs', {}).get('image_inventory') == state['inventory'],
                 'recovery provenance/baseline binding refused')
        for field, limit in (('archive', 300_000_000), ('signature', 65536)):
            ref, old = entry[field], original[field]
            need(ref['size'] == old.get('size', old.get('bytes')) and ref['sha256'] == old['sha256'],
                 'archive/signature provenance digest mismatch: ' + name)
            key = digest(ref)
            if key not in cache:
                cache[key] = ref['size']
                need(sum(cache.values()) <= MAX_ARCHIVE_BYTES, 'aggregate archive byte bound exceeded')
                recovery.auth.bound_bytes(ref, limit)
        key = digest({'archive': entry['archive'], 'metadata': preflight.semantic(rows[name])})
        if key not in cache:
            inspect(entry['archive'], rows[name], MAX_SECONDS - (time.monotonic() - started))
            cache[key] = 0
        claim = original.get('signature_verification', original.get('verification', {}))
        observation = original.get('signature_observation')
        if observation is not None:
            need(observation.get('exit') == 0, 'retained signature exit refused')
            recovery.auth.signature_status(observation['gpg_status'].encode('ascii'), claim['primary_fingerprint'])
        found[name] = dict(entry, retained_signature_claim=claim,
                           metadata_reinspected=True, fresh_signature_verification=False)
    return found


def policy_sets(policy, before_state, candidate_state, before, after):
    need(set(policy) == {'schema_version', 'kind', 'before_release', 'candidate_release', 'coordinated_sets'}
         and type(policy['schema_version']) is int and policy['schema_version'] == 1
         and policy['kind'] == 'coordinated-platform-version-policy'
         and policy['before_release'] == before_state and policy['candidate_release'] == candidate_state,
         'policy/release binding refused')
    groups = policy['coordinated_sets']
    need(isinstance(groups, list) and len(groups) <= MAX_ROWS, 'finite coordinated policy required')
    covered, group_names = {}, set()
    for group in groups:
        need(set(group) == {'name', 'before', 'candidate', 'allow_changes', 'allow_downgrades', 'allow_removals'}
             and isinstance(group['name'], str) and 0 < len(group['name']) <= 128
             and group['name'] not in group_names, 'coordinated set fields/name refused')
        group_names.add(group['name'])
        left, right = group['before'], group['candidate']
        need(isinstance(left, dict) and isinstance(right, dict) and left and set(left) == set(right),
             'whole coordinated before/candidate maps required')
        for name in left:
            need(name not in covered and name in set(before) | set(after), 'overlapping or unknown policy member')
            need(left[name] == before.get(name, {}).get('VERSION', [None])[0]
                 and right[name] == after.get(name, {}).get('VERSION', [None])[0],
                 'coordinated exact version mismatch: ' + name)
            covered[name] = group
        for field in ('allow_changes', 'allow_downgrades', 'allow_removals'):
            names = group[field]
            need(isinstance(names, list) and len(names) == len(set(names)) and set(names) <= set(left),
                 'policy allowances must name unique set members')
    return covered


def run(contract):
    need(set(contract) == {'schema_version', 'before_release', 'candidate_release', 'protected_tuple',
                           'coordinated_policy', 'retained_recovery_assets'}
         and type(contract['schema_version']) is int and contract['schema_version'] == 1,
         'transition contract fields/version refused')
    started, cache, documents = time.monotonic(), {}, {}
    left, right = contract['before_release'], contract['candidate_release']
    before, after = inventory(left), inventory(right)
    for rows in (before, after):
        counts = {field: sum(len(row.get(field, [])) for row in rows.values())
                  for field in ('DEPENDS', 'PROVIDES', 'CONFLICTS')}
        need((counts['DEPENDS'] + counts['CONFLICTS']) * (len(rows) + counts['PROVIDES']) <= 8_000_000,
             'dependency assessment work bound exceeded')
    tuple_doc = document(contract['protected_tuple'])
    need(tuple_doc.get('input_sha256', {}).get('image') == left['inventory']['sha256'],
         'protected tuple/before inventory binding refused')
    graph = tuple_doc['proposed_installed_dependency_graph']
    need(isinstance(graph, list) and 0 < len(graph) <= MAX_ROWS, 'finite protected tuple required')
    protected = {row['name']: row['version'] for row in graph}
    need(len(protected) == len(graph) and all(before.get(name, {}).get('VERSION') == [version]
                                            for name, version in protected.items()), 'protected tuple identity refused')
    old_archives = archive_index(left, before, cache, started, documents)
    new_archives = archive_index(right, after, cache, started, documents)
    covered = policy_sets(document(contract['coordinated_policy']), left, right, before, after)
    versions, conditions = audit.Versions(), []

    def blocked(code, action, **details):
        conditions.append(dict(code=code, next_action=action, **details))

    def state(name, rows, archives):
        if name not in rows:
            return None
        return {'version': rows[name]['VERSION'][0], 'arch': rows[name]['ARCH'][0],
                'metadata_sha256': digest(preflight.semantic(rows[name])),
                'archive_sha256': archives.get(name, {}).get('archive', {}).get('sha256')}

    changes = []
    for name in sorted(set(before) | set(after)):
        old, new = state(name, before, old_archives), state(name, after, new_archives)
        same_metadata = old and new and all(old[key] == new[key] for key in ('version', 'arch', 'metadata_sha256'))
        same_bytes = old and new and (not old['archive_sha256'] or not new['archive_sha256']
                                     or old['archive_sha256'] == new['archive_sha256'])
        if same_metadata and same_bytes:
            continue
        kind = 'added' if old is None else 'removed' if new is None else 'metadata-or-archive-changed'
        if old and new and old['version'] != new['version']:
            order = versions.compare(new['version'].encode(), old['version'].encode())
            kind = 'upgraded' if order > 0 else 'downgraded' if order < 0 else 'equivalent-version'
        changes.append({'name': name, 'change': kind, 'before': old, 'candidate': new,
                        'protected': name in protected or name in preflight.PLATFORM})
        group = covered.get(name)
        if not group or name not in group['allow_changes']:
            blocked('change-not-coordinated', 'Review and bind this exact change in a coordinated version set.', package=name)
        if kind == 'downgraded' and (not group or name not in group['allow_downgrades']):
            blocked('downgrade-not-explicit', 'Review the exact downgrade and recovery consequences.', package=name)
        if kind == 'removed' and (not group or name not in group['allow_removals']):
            blocked('removal-not-explicit', 'Review the exact removal and its dependent packages.', package=name)
    for name in sorted(preflight.PLATFORM):
        for side, rows in (('before', before), ('candidate', after)):
            if name not in rows:
                blocked('required-platform-package-missing', 'Supply the complete boot/kernel/firmware/Mesa/audio/protection tuple.',
                        package=name, side=side)
    required_old = set(protected) | (preflight.PLATFORM & set(before)) | {r['name'] for r in changes if r['before']}
    required_new = (preflight.PLATFORM & set(after)) | {r['name'] for r in changes if r['candidate']}
    for side, needed, archives in (('before', required_old, old_archives), ('candidate', required_new, new_archives)):
        for name in sorted(needed - set(archives)):
            blocked('exact-archive-missing', 'Retain the exact package archive, detached signature and metadata provenance; do not substitute a current version.',
                    package=name, side=side, version=(before if side == 'before' else after)[name]['VERSION'][0])
    for side, needed, archives in (('before', required_old, old_archives), ('candidate', required_new, new_archives)):
        for name in sorted(needed & set(archives)):
            claim = archives[name]['retained_signature_claim']
            if claim.get('status') != 'cryptographic-signature-valid' or claim.get('primary_fingerprint') not in {
                    key[0] for key in recovery.auth.KEYS.values()}:
                blocked('retained-signature-evidence-missing', 'Supply retained signature evidence for this exact archive.',
                        package=name, side=side)
    dependencies = {}
    for side, rows in (('before', before), ('candidate', after)):
        edges = audit.requirements(rows, rows, versions)
        missing = [row for row in edges if not row['witnesses']]
        dependencies[side] = {'missing': missing, 'relation_count': len(edges)}
        for row in missing:
            blocked('dependency-unsatisfied', 'Supply a compatible provider in this exact inventory and replan.', side=side,
                    package=row['package'], requires=row['requires'])
    for name, row in sorted(after.items()):
        need(time.monotonic() - started <= MAX_SECONDS, 'transition deadline exceeded')
        for relation in row.get('CONFLICTS', []):
            for witness in audit.witnesses(relation, after, versions):
                if witness['package'] != name:
                    blocked('candidate-package-conflict', 'Resolve the conflicting final package set.',
                            package=name, conflicts=relation, provider=witness['package'])
    assets = document(contract['retained_recovery_assets'])
    need(set(assets) == {'schema_version', 'for_inventory', 'assets'} and type(assets['schema_version']) is int
         and assets['schema_version'] == 1 and assets['for_inventory'] == left['inventory']
         and isinstance(assets['assets'], list) and len(assets['assets']) <= 64, 'recovery asset/baseline binding refused')
    roles, required_roles = set(), preflight.BOOT_ROLES | preflight.CONFIG_ROLES
    for asset in assets['assets']:
        need(set(asset) == {'role', 'artifact'} and asset['role'] in required_roles and asset['role'] not in roles,
             'duplicate/unknown recovery asset role')
        roles.add(asset['role'])
        recovery.auth.bound_bytes(asset['artifact'], 32 * recovery.MIB)
    for role in sorted(required_roles - roles):
        blocked('retained-recovery-asset-missing', 'Retain the exact baseline artifact and exercise its restoration.', role=role)
    # Missing evidence is unknown, not proof that a package's bytes changed.
    comparable = set(old_archives) & set(new_archives)
    impact = consumer_impact(as_release(before, {n: old_archives[n] for n in comparable}),
                             as_release(after, {n: new_archives[n] for n in comparable}),
                             MAX_SECONDS - (time.monotonic() - started))
    need(time.monotonic() - started <= MAX_SECONDS, 'transition deadline exceeded')
    return {'schema_version': 1, 'kind': 'offline-coordinated-platform-transition-plan',
            'status': 'BLOCKED-data-gaps' if conditions else 'PASS-offline-data-plan',
            'input_references': contract, 'conditions': conditions, 'changes': changes,
            'source_sha256': {str(path.relative_to(ROOT)): recovery.auth.hash_file(path) for path in
                              (Path(__file__).resolve(), Path(transaction.__file__), Path(preflight.__file__),
                               Path(audit.__file__), Path(recovery.__file__), Path(comparison.__file__))},
            'dependency_assessment': dependencies, 'dependency_impact': impact,
            'added_package_dependencies': [row for row in audit.requirements(after, after, versions)
                                           if row['package'] not in before],
            'protected_package_count': len(protected),
            'archive_provenance_joins': {'before': old_archives, 'candidate': new_archives},
            'retained_recovery_assets': assets['assets'], 'archive_bytes_rehashed': sum(cache.values()),
            'software_data_bound': not conditions, 'system_mutation': False,
            'transaction_prepared': False, 'dependency_transaction_accepted': False,
            'fresh_signature_verification': False, 'independent_owner_trust_accepted': False,
            'installation_accepted': False, 'hardware_accepted': False, 'recovery_accepted': False,
            'physical_checks': [{'model': model, 'air_size_inches': size, 'result': 'NOT RUN',
                                 'checks': ['cold-boot', 'graphics-input-network', 'audio-speaker-protection',
                                            'lock-session-preserving-suspend', 'interrupted-update-boot-session-recovery']}
                                for model, size in sorted(preflight.MODELS.items())],
            'limitations': ['Checksums and retained signature claims bind supplied observations; no fresh crypto or owner authentication.',
                           'All-provider runtime impacts are review candidates, not rebuild requirements or an ALPM transaction.',
                           'Archive PKGINFO is inspected; installed files, hooks, boot assets completeness and runtime ABI are not qualified.',
                           'An explicit coordinated policy is an exact data proposal, not tested platform compatibility.',
                           'No native ARM, installed-system, M2, performance, release or recovery acceptance follows.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract', type=Path, required=True)
    parser.add_argument('--contract-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        contract = audit.load_json(audit.read_bound(args.contract, args.contract_sha256))
        report = run(contract)
        report['contract_sha256'] = args.contract_sha256
        audit.write_private(args.output, report)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, UnicodeError, EOFError) as error:
        parser.exit(1, 'platform transition refused: ' + str(error) + '\n')
    print(json.dumps({'report': str(args.output.absolute()), 'status': report['status'], 'hardware_accepted': False}))
    return 0 if report['software_data_bound'] else 2


if __name__ == '__main__':
    if sys.argv[1:] in (['--inspect'], ['--impact']):
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (512 * recovery.MIB, 512 * recovery.MIB))
        resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
        try:
            raw = sys.stdin.buffer.read(8 * recovery.MIB + 1)
            need(len(raw) <= 8 * recovery.MIB, 'worker request bound exceeded')
            request = audit.load_json(raw)
            if sys.argv[1:] == ['--impact']:
                result = comparison.dependency_impact(request['before'], request['after'], [], [])
                data = json.dumps(result).encode()
                need(len(data) <= 8 * recovery.MIB, 'impact output bound exceeded')
                sys.stdout.buffer.write(data)
                raise SystemExit(0)
            ref, metadata = request['archive'], request['metadata']
            recovery.auth.bound_bytes(ref, 300_000_000)
            selected = recovery.auth.pkginfo(Path(ref['path']))
            audit.verify_pkginfo({metadata['NAME'][0]: {'metadata': metadata, 'archive': ref}},
                                 [{'name': metadata['NAME'][0], 'archive_sha256': ref['sha256'],
                                   'selected_data': {'.PKGINFO': selected}}])
            fields = {}
            for line in selected['text'].splitlines():
                key, sep, value = line.partition(' = ')
                if sep:
                    fields.setdefault(key, []).append(value)
            need(fields.get('license', []) == metadata.get('LICENSE', []), 'archive license metadata mismatch')
            print('OK')
        except Exception:
            raise SystemExit(1)
        raise SystemExit(0)
    raise SystemExit(main())
