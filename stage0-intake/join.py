#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Join retained archive DATA into a candidate prefix model, never an installed image."""
import hashlib
import json
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent


def model_join(groups):
    nodes, collisions = {}, []
    for root, component, records in groups:
        base = root + '/' + component + '/'
        for record in records:
            if not record['path'].startswith(base):
                continue
            relative = record['path'][len(base):]
            if relative == 'manifest.in':
                continue
            node = {'kind': record['kind'], 'mode': record['mode'], 'content': record.get('sha256', record.get('link_target', ''))}
            if node['kind'] not in ['file', 'dir']:
                raise ValueError('model supports this observed link-free corpus only')
            if relative in nodes and nodes[relative] != node:
                collisions.append(relative)
            nodes[relative] = node
    if collisions:
        raise ValueError('nonidentical component collision: ' + ','.join(collisions))
    h = hashlib.sha256()
    def visit(parent):
        children = sorted(name for name in nodes if PurePosixPath(name).parent.as_posix() == (parent or '.'))
        for name in children:
            node = nodes[name]
            h.update((json.dumps([name, node['kind'], node['mode'], node['content']], separators=(',', ':')) + '\n').encode())
        for name in children:
            if nodes[name]['kind'] == 'dir':
                visit(name)
    visit('')
    for name in nodes:
        parent = PurePosixPath(name).parent.as_posix()
        if parent != '.' and (parent not in nodes or nodes[parent]['kind'] != 'dir'):
            raise ValueError('missing modeled directory parent')
    return nodes, h.hexdigest()


def main():
    facts = json.loads((HERE / 'data-admission.json').read_bytes())
    pins = json.loads((HERE.parent / 'inputs.json').read_bytes())
    groups = []
    elfs = {}
    for name, report in facts['archives'].items():
        groups.append((report['archive_root'], report['install_manifest']['component'], json.loads((HERE / 'records' / (name + '.inventory.json')).read_bytes())))
        elfs.update(json.loads((HERE / 'records' / (name + '.elf.json')).read_bytes()))
    nodes, model = model_join(groups)
    bundled = {e['soname'] for e in elfs.values() if e['soname']}
    needed = {n for e in elfs.values() for n in e['needed']}
    facts['component_join_DATA_model'] = {'status': 'DERIVED_ARCHIVE_MODEL_ONLY_NOT_FILESYSTEM_ASSEMBLED_OR_RUNTIME_QUALIFIED', 'mode_assumption': 'Recorded tar modes; all observed directories0755 and files0644/0755. Candidate extraction umask/metadata must still be checked on actual assembly.', 'modeled_tree_sha256': model, 'modeled_entries': len(nodes), 'modeled_regular_files': sum(v['kind'] == 'file' for v in nodes.values()), 'nonidentical_collisions': [], 'bundled_sonames': sorted(bundled), 'external_needed_sonames_by_name_only': sorted(needed - bundled), 'interpreter_paths_required_in_environment': sorted({e['interpreter'] for e in elfs.values() if e['interpreter']})}
    facts['archive_release_metadata_DATA'] = {name: {key: (HERE / 'records/metadata' / report['archive_root'] / key).read_text().strip() for key in ['version', 'git-commit-hash', 'rust-installer-version']} for name, report in facts['archives'].items()}
    facts['candidate_conditions_satisfied_as_DATA_only'] = ['three exact local archive byte identities', 'all three declared component layouts actually observed', 'installer manifest entries and payload namespaces joined', 'root notices retained', 'top-level AArch64 ELF program/dynamic metadata observed']
    facts['candidate_conditions_remaining'] = ['independent source/authentication and dependency-notice qualification', 'actual assembled stage0 tree digest', 'native runtime/loader/library and bootstrap compatibility qualification', 'complete pinned external LLVM23.1.1 dependency image', 'source/vendor closure and private build resource budget']
    facts['existing_candidate_selector_and_admission_example_changed'] = False
    (HERE / 'data-admission.json').write_text(json.dumps(facts, indent=2, sort_keys=True) + '\n')
    (HERE / 'records/component-prefix-model.json').write_text(json.dumps(nodes, indent=2, sort_keys=True) + '\n')
    print(json.dumps(facts['component_join_DATA_model'], sort_keys=True))


if __name__ == '__main__':
    main()
