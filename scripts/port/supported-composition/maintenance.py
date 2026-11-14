#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite, unapproved three-package DATA proposal over an unchanged original run."""
import json
from pathlib import Path
import tempfile

# This version supports only the exact retained route reviewed in this task.
EXACT = {
    'python': ('3.14.7-1', '3.14.8-1', 'core'),
    'networkmanager': ('1.58.1-1', '1.58.1-2', 'extra'),
    'perl': ('5.42.2-2', '5.42.3-1', 'core'),
}


def evaluate(proposal_ref, contract_ref, contract, reader, output, *, image, protected,
             catalogs, targets, provenance, tx, prepare, platform):
    need = tx.preview.need
    proposal = reader.document(proposal_ref)
    need(contract_ref is not None and reader.document(contract_ref) == contract, 'exact original composition reference required')
    need(set(proposal) == {'schema_version', 'kind', 'approval_status', 'composition_contract', 'image_inventory',
                          'protected_tuple', 'catalogs', 'changes'}
         and proposal['schema_version'] == 1 and proposal['kind'] == 'unapproved-Asahi-three-package-maintenance-v1'
         and proposal['approval_status'] == 'UNAPPROVED' and contract['workflow'] == 'full-desktop', 'finite unapproved full-desktop maintenance proposal required')
    need(proposal['composition_contract'] == contract_ref
         and all(proposal[key] == contract[key] for key in ('image_inventory', 'protected_tuple', 'catalogs')),
         'proposal original image/protected/catalog/composition binding differs')
    changes = proposal['changes']
    need(isinstance(changes, list) and len(changes) == len(EXACT)
         and {row.get('name') for row in changes} == set(EXACT), 'exactly Python/NetworkManager/Perl changes required; no extra policy')
    by_name = {row['name']: row for row in targets}
    approved_shape = {}
    for row in changes:
        need(set(row) == {'name', 'before', 'after', 'repo', 'reason'}, 'exact maintenance identity/reason fields required')
        name = row['name']; before, after, repo = EXACT[name]
        need((row['before'], row['after'], row['repo']) == (before, after, repo), 'wrong finite maintenance before/after/repository identity')
        need(image.get(name, {}).get('VERSION') == [before], 'exact retained before identity is missing')
        need(by_name.get(name) == {'name': name, 'version': after, 'repo': repo}, 'maintenance may not add or retarget original roots')
        need(isinstance(row['reason'], str) and 0 < len(row['reason'].strip()) <= 1024
             and not any(ord(char) < 32 for char in row['reason']), 'explicit bounded maintenance reason required')
        need(catalogs.get(repo, {}).get(name, {}).get('VERSION') == [after], 'exact proposed after is absent from the bound catalog')
        approved_shape[name] = {key: row[key] for key in ('name', 'before', 'after', 'repo')}
    need('python' in protected and protected['python'] == EXACT['python'][0]
         and not {'networkmanager', 'perl'} & protected.keys(), 'finite proposal requires the original retained protection roles')
    need(not any(row['name'] in protected and row['version'] != protected[row['name']]
                 and row['name'] != 'python' for row in targets), 'extra original protected/boot/kernel/Mesa/audio target change refused')
    proposed_protected = dict(protected); proposed_protected['python'] = EXACT['python'][1]
    selected_catalogs = {repo: {name: metadata for name, metadata in rows.items()
        if name != 'mesa-dummy' and (name not in proposed_protected or metadata['VERSION'] == [proposed_protected[name]])}
        for repo, rows in catalogs.items()}
    directory = output / 'proposed-maintenance'; directory.mkdir(mode=0o700)
    result = {'schema_version': 1, 'approval_status': 'UNAPPROVED', 'status': 'HOLD',
              'metadata_prepare_status': 'FAIL', 'proposal_reference': proposal_ref, 'changes': changes,
              'blockers': [], 'holds': [], 'transaction_accepted': False, 'selection_changed': False,
              'original_root_provider_policy_changed': False, 'platform_policy_changed': False,
              'original_protected_policy_adopted_changes': False, 'native_build': 'NOT RUN',
              'signature_authentication': 'NOT RUN', 'hardware': 'NOT RUN', 'installation': 'NOT RUN'}
    def block(code, **details): result['blockers'].append({'code': code, **details})
    for row in targets:
        metadata = image.get(row['name']) if row['repo'] == 'observed-Asahi-base' else selected_catalogs.get(row['repo'], {}).get(row['name'])
        if not metadata or metadata['VERSION'] != [row['version']]: block('exact-target-pin-unavailable', target=row)
    with tempfile.TemporaryDirectory(prefix='private-supported-composition-', dir=directory) as temporary:
        work = Path(temporary)
        for name in ('root', 'db/sync', 'cache', 'gpg', 'hooks'): (work / name).mkdir(parents=True, mode=0o700)
        engine = prepare(work, image, proposed_protected, selected_catalogs, targets, directory)
    prepared = engine['prepare']; result['prepare'] = prepared
    if prepared['prepare_exit'] or prepared['errors'] or prepared['callback_errors']:
        block('libalpm-preparation-incomplete', errors=prepared['errors'], errno=prepared['prepare_errno'])
    for row in prepared['questions']:
        if row.get('type') == 32 and row.get('policy') != 'explicit-root-provider': block('unapproved-provider-choice', question=row)
    final, origins = dict(image), {name: 'observed-Asahi-base' for name in image}
    for row in prepared['remove']: final.pop(row['name'], None); origins.pop(row['name'], None)
    for row in prepared['add']:
        metadata = selected_catalogs[row['repo']][row['name']]
        need(metadata['VERSION'] == [row['version']], 'maintenance addition/catalog identity differs')
        final[row['name']], origins[row['name']] = metadata, row['repo']
    result['base_changes'] = []
    for name in sorted(image):
        before, after = image[name]['VERSION'][0], final.get(name, {}).get('VERSION', [None])[0]
        if before != after:
            change = {'name': name, 'before': before, 'after': after, 'repo': origins.get(name)}
            matches = approved_shape.get(name) == change
            result['base_changes'].append({**change, 'exact_proposal_matches': matches})
            if not matches: block('unlisted-or-wrong-base-change', change=change)
    for name, row in approved_shape.items():
        if final.get(name, {}).get('VERSION') != [row['after']] or origins.get(name) != row['repo']:
            block('proposed-after-not-realized', change=row)
    result['roots'] = [{**row, 'satisfied': final.get(row['name'], {}).get('VERSION') == [row['version']]} for row in targets]
    for row in result['roots']:
        if not row['satisfied']: block('explicit-root-unsatisfied', root=row)
    result['protected'] = [{'name': name, 'before': protected[name], 'proposed': version,
        'final': final.get(name, {}).get('VERSION', [None])[0],
        'preserved_under_proposal': final.get(name, {}).get('VERSION') == [version],
        'original_version_unchanged': final.get(name, {}).get('VERSION') == [protected[name]]}
        for name, version in sorted(proposed_protected.items())]
    for row in result['protected']:
        if not row['preserved_under_proposal']: block('proposed-protected-anchor-changed', decision=row)
    for row in engine['dependencies']:
        if row['provider'] is None: block('final-dependency-unresolved', dependency=row)
    for row in engine['conflicts']: block('final-declared-conflict', conflict=row)
    for name in sorted(platform - final.keys()): block('required-platform-member-missing', package=name)
    versions = tx.tuple_audit.Versions()
    result['provider_bindings'] = []
    for row in contract['providers']:
        metadata = final.get(row['name'])
        matches = bool(metadata and metadata['VERSION'] == [row['version']]
                       and tx.tuple_audit.witnesses(row['requirement'], {row['name']: metadata}, versions))
        result['provider_bindings'].append({**row, 'final_witness_matches': matches})
        if not matches: block('final-explicit-provider-unsatisfied', provider=row)
    packages = []
    for name, metadata in sorted(final.items()):
        origin = origins[name]
        proof = provenance.get((origin, name), {'kind': 'observed-image-local-metadata', 'reference': contract['image_inventory']})
        packages.append({'name': name, 'version': metadata['VERSION'][0], 'repo': origin, 'metadata': metadata, 'provenance': proof})
        result['holds'].append({'package': name, 'facts': ['UNAPPROVED-maintenance-DATA', 'archive-custody-unverified',
            'signature-authentication-NOT-RUN', 'source-license-grant-maintainer-review-incomplete',
            'installed-payload-ownership-hooks-ABI-recovery-unverified', 'native-hardware-NOT-RUN']})
    inventory = {'schema_version': 1, 'kind': 'UNAPPROVED-maintenance-metadata-inventory',
                 'dependency_transaction_accepted': False, 'proposed_final_inventory': packages}
    raw = (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode()
    path = directory / 'inventory.json'; tx.write_bytes(path, raw)
    result.update(metadata_prepare_status='FAIL' if result['blockers'] else 'PASS', final_package_count=len(final),
        original_protected_unchanged=sum(row['original_version_unchanged'] for row in result['protected']),
        original_protected_count=len(protected), proposed_protected_preserved=sum(row['preserved_under_proposal'] for row in result['protected']),
        dependencies=engine['dependencies'], final_inventory={'path': str(path), 'size': len(raw), 'sha256': tx.tuple_audit.digest(raw)},
        private_database_removed=not any(directory.glob('private-supported-composition-*')))
    return result
