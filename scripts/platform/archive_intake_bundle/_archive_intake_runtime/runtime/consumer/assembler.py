#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Project fresh-payload staging assembler proposal; CLI performs readiness only.

The pure assembler emits a normalized staging tar to a supplied stream. It never
extracts to host paths, installs packages, runs hooks or builds an ext4 image.
"""
import argparse
import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import sys
import tarfile
import types

BASE = Path(__file__).resolve().parent
ASSEMBLER_SOURCE_SHA = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
CORE_SHA = '3a71ba896700f72130e35a56845516bd9c42de0b1b0fd782b79829b37ac262a7'
VALIDATOR_SHA = 'c2ba2c6bd183ce4f300aec16757707017d273a7119b45072b1d2667d07ae0776'
PLAN_SHA = 'c1f3379385d210b8464d28b9e876141bec9dd45768c58ab5157c8580fabf92fe'
INDEX_SHA = '498078ecae47dc3cfa53a0c5580b2d4b1d4d4fd4dbaaa88772372f3240b00a68'
INVENTORY_SHA = '5c1630b5cdf07898118979895682c3a3b705e416c9840ada4e1a5193dccd6941'
TRANSFORMS_SHA = 'e261df266f2fff41f25a6900e1ab07a4bffbf5fb7399eb1d4f44c6efd1ab10f3'
FSTAB = (b'UUID=725346d2-f127-47bc-b464-9dd46155e8d6 / ext4 rw,relatime,x-systemd.growfs 0 1\n'
         b'UUID=2ABF-9F91 /boot/efi vfat rw,relatime,fmask=0022,dmask=0022,codepage=437,'
         b'iocharset=iso8859-1,shortname=mixed,errors=remount-ro    0 2\n')
LIMITS = dict(packages=261, nodes=500000, total_bytes=8*1024**3, file_bytes=512*1024**2, recipes=3)


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                       allow_nan=False) + '\n').encode()


def source_module(relative, expected):
    path = BASE / relative
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 1024**2, 'source-file')
    raw = path.read_bytes()
    need(sha(raw) == expected, 'source-pin')
    module = types.ModuleType('_private_assembly_source')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def json_input(relative, expected, maximum):
    path = BASE / relative
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= maximum, 'input-file')
    raw = path.read_bytes()
    need(sha(raw) == expected, 'input-pin')
    validator = source_module('inputs/validate_plan.py', VALIDATOR_SHA)
    return validator.decode(raw)


def readiness():
    """The real frozen 261 gate; never dispatch an assembler or follow archives."""
    validator = source_module('inputs/validate_plan.py', VALIDATOR_SHA)
    plan = json_input('inputs/assembly-plan.json', PLAN_SHA, 2*1024**2)
    inventory = json_input('inputs/image-inventory.json', INVENTORY_SHA, 1024**2)
    index = json_input('inputs/package-reference-index.json', INDEX_SHA, 2*1024**2)
    result = validator.validate(plan, inventory, FSTAB, index)
    need(result['status'] == 'PLAN_VALID_BLOCKED_MISSING_INPUTS', 'frozen-plan-state')
    return dict(status='ASSEMBLER_SOURCE_PROPOSED_ACTUAL_BUILD_BLOCKED', contract=result,
                pristine_staging='IMPLEMENTED_PURE_PAYLOAD_MAPS', config='FINITE_PINNED_DATA_RECIPES',
                deterministic_output='PAX_STAGING_BUNDLE_ONLY', native_ext4_esp_build='NOT_RUN',
                package_intake='PREPARED_BYTE_MAPS_ONLY_NO_ARCHIVE_DISPATCH',
                actual_build_executed=False, assembly_authorized=False)


def file_node(raw, mode=0o644, uid=0, gid=0):
    need(type(raw) is bytes, 'file-body')
    return dict(type='file', mode=mode, uid=uid, gid=gid, bytes=len(raw), sha256=sha(raw))


def fstab_recipe():
    """Closed proposed config policy; no historical-image attribution."""
    return dict(id='fstab-ext4-v1', path='etc/fstab', package='filesystem',
                before=dict(type='file', mode=0o644, uid=0, gid=0, bytes=126,
                            sha256='e54626e74ed8fee4173b62a545ab1c3a3a069e4217a0ee8fc398d9933e9c1696'),
                after=file_node(FSTAB), body=FSTAB,
                source=dict(commit='58cc158c7fda3ef6aeae36606f84a63b4b0867e7',
                            path='scripts/base/20-fstab.sh',
                            sha256='3d0f0b6ffaee802b0cf41efe57ca96c9e85387e72773b2566eadc12693a1131f'),
                metadata_policy='PRESERVE_PRISTINE_PACKAGE_METADATA', preserve_existing_user_files=True,
                required_parents={'etc': dict(type='directory', mode=0o755, uid=0, gid=0)},
                new_directories={},
                preserved_nodes={'usr/share/factory/etc/fstab': dict(type='file', mode=0o644, uid=0, gid=0,
                    bytes=126, sha256='e54626e74ed8fee4173b62a545ab1c3a3a069e4217a0ee8fc398d9933e9c1696')})


def reviewed_recipes():
    """Three closed literal-data policies; unresolved service decisions stay open."""
    catalog = json_input('transforms/transforms.json', TRANSFORMS_SHA, 1024**2)
    result = {'fstab-ext4-v1': fstab_recipe()}
    for identity in ('asahi-repository-mirrorlist', 'systemd-firstboot-no-prompt'):
        row = next(item for item in catalog['transforms'] if item['id'] == identity)
        need(row['status'] == 'CONTENT_EXACT' and len(row['outputs']) == 1, 'literal-source-recipe')
        ref = row['after']['content']
        path = BASE / 'transforms' / ref['path']
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == ref['bytes'] <= 65536,
             'recipe-content-file')
        body = path.read_bytes()
        need(sha(body) == ref['sha256'], 'recipe-content-pin')
        parents, additions = {}, {}
        for parent in row['recipe_data']['parent_directories']:
            node = {key: parent[key] for key in ('type', 'mode', 'uid', 'gid')}
            target = additions if parent['creation_permitted_as_future_candidate'] else parents
            target[parent['path']] = node
        source = row['source_refs'][-1]
        result[identity] = dict(id=identity, path=row['outputs'][0], package=None, before=None,
                               after=file_node(body), body=body,
                               source={key: source[key] for key in ('commit', 'path', 'sha256')},
                               metadata_policy='PROJECT_NEW_FILE_METADATA_POLICY_NOT_UPSTREAM_MODE_PROOF',
                               preserve_existing_user_files=True, required_parents=parents,
                               new_directories=additions, preserved_nodes={},
                               remaining_policy_inputs=row['missing_inputs'])
    return result


def bounded_link_tail(core, name, target, nodes):
    """Check expanded targets past the comparator's first-missing checkpoint.

    A parent traversal after an unknown component has no closed meaning here.
    This conservative proposal rejects it, rather than following host state.
    """
    parts = [] if target.startswith('/') else name.split('/')[:-1]
    pending, hops, steps = target.split('/'), 0, 0
    while pending:
        steps += 1
        need(steps <= 4096, 'virtual-link-step-cap')
        part = pending.pop(0)
        if part in ('', '.'):
            continue
        if part == '..':
            need(bool(parts), 'virtual-link-root-escape')
            parts.pop()
            continue
        parts.append(part)
        node = nodes.get('/'.join(parts))
        if node is not None and node['type'] == 'symlink':
            hops += 1
            need(hops <= 40, 'virtual-link-hop-cap')
            link = node['target']
            pending = link.split('/') + pending
            parts = [] if link.startswith('/') else parts[:-1]
        elif pending and node is None:
            need('..' not in pending, 'unresolved-parent-tail')
            return
        elif pending:
            need(node['type'] == 'directory', 'virtual-link-file-parent')


def validate_tree(core, nodes):
    """Validate only this virtual namespace. No host path is followed."""
    need(type(nodes) is dict and len(nodes) <= LIMITS['nodes'], 'tree-bound')
    links = {}
    for name, node in nodes.items():
        core.path(name)
        core.node_shape(node)
        parts = name.split('/')
        for length in range(1, len(parts)):
            parent = '/'.join(parts[:length])
            need(parent in nodes and nodes[parent]['type'] == 'directory', 'explicit-directory-parent')
        if node['type'] == 'hardlink':
            target = node['target']
            core.path(target)
            need(target in nodes and nodes[target]['type'] == 'file', 'direct-hardlink-target')
            need(all(node[key] == nodes[target][key] for key in ('mode', 'uid', 'gid')), 'hardlink-metadata')
        elif node['type'] == 'symlink':
            bounded_link_tail(core, name, node['target'], nodes)
            target, state = core.resolve_link(name, node['target'], nodes)
            need(state not in ('ESCAPE', 'CYCLE', 'HOP_LIMIT', 'NON_DIRECTORY'), 'unsafe-virtual-link')
            links[name] = dict(target=target, state=state)
    return links


def prepare(core, payloads, expected):
    """Assemble the complete declared pristine tree; no partial package subset."""
    need(type(expected) is list and 0 < len(expected) <= LIMITS['packages'], 'selection-bound')
    selected = {}
    for identity in expected:
        core.package_identity(identity)
        need(identity['name'] not in selected, 'duplicate-selection')
        selected[identity['name']] = identity
    need(type(payloads) is list and len(payloads) == len(selected), 'payload-closure')
    nodes, bodies, owners, sources, package_nodes = {}, {}, {}, {}, {}
    total = entries = 0
    for payload in payloads:
        need(type(payload) is dict and set(payload) == {'identity', 'archive_sha256', 'source_sha256',
                                                       'nodes', 'bodies'}, 'prepared-payload-schema')
        identity = core.package_identity(payload['identity'])
        name = identity['name']
        need(name in selected and identity == selected[name] and name not in sources, 'exact-payload-tuple')
        need(all(type(payload[key]) is str and core.HEX.fullmatch(payload[key])
                 for key in ('archive_sha256', 'source_sha256')), 'declared-input-digests')
        tree = payload['nodes']
        need(type(tree) is dict and type(payload['bodies']) is dict, 'prepared-byte-maps')
        for node in tree.values():
            core.node_shape(node)
        need(set(payload['bodies']) == {path for path, node in tree.items() if node.get('type') == 'file'},
             'regular-body-set')
        for path, node in tree.items():
            entries += 1
            need(entries <= LIMITS['nodes'], 'aggregate-node-bound')
            core.path(path)
            need(path not in core.CONTROL, 'package-control-not-payload')
            core.node_shape(node)
            if node['type'] == 'hardlink':
                need(node['target'] in tree and tree[node['target']]['type'] == 'file', 'same-package-hardlink')
            if node['type'] == 'file':
                raw = payload['bodies'][path]
                need(type(raw) is bytes and len(raw) <= LIMITS['file_bytes'] and
                     len(raw) == node['bytes'] and sha(raw) == node['sha256'], 'pristine-content')
                total += len(raw)
                need(total <= LIMITS['total_bytes'], 'aggregate-payload-bytes')
                bodies[path] = raw
            if path in nodes:
                need(node['type'] == 'directory' and node == nodes[path], 'pristine-path-conflict')
            nodes[path] = copy.deepcopy(node)
            owners.setdefault(path, []).append(name)
        package_nodes[name] = copy.deepcopy(tree)
        sources[name] = dict(identity=copy.deepcopy(identity), archive_sha256=payload['archive_sha256'],
                             source_sha256=payload['source_sha256'],
                             evidence='DECLARED_PREPARED_INPUTS_NOT_FRESH_AUTHENTICATION')
    need(set(sources) == set(selected), 'complete-selection')
    links = validate_tree(core, nodes)
    pristine = dict(nodes=copy.deepcopy(nodes), owners={p: sorted(v) for p, v in owners.items()},
                    packages={p: sources[p] for p in sorted(sources)}, link_states=links)
    return nodes, bodies, pristine, package_nodes


def configure(core, nodes, bodies, pristine, recipes):
    need(type(recipes) is list and len(recipes) <= LIMITS['recipes'], 'recipe-bound')
    known_recipes = reviewed_recipes()
    need(all(type(row) is dict and type(row.get('id')) is str for row in recipes), 'recipe-identity')
    configured, content = copy.deepcopy(nodes), dict(bodies)
    deltas, seen = [], set()
    for recipe in sorted(recipes, key=lambda row: row['id']):
        need(type(recipe) is dict and recipe.get('id') in known_recipes and
             recipe == known_recipes[recipe['id']], 'exact-reviewed-recipe')
        path = core.path(recipe['path'])
        need(path not in seen, 'single-config-writer')
        seen.add(path)
        need(recipe['preserve_existing_user_files'] is True, 'user-config-preservation')
        for parent, expected in recipe['required_parents'].items():
            need(configured.get(parent) == expected and parent in pristine['owners'], 'config-package-parent')
        for preserved, expected in recipe['preserved_nodes'].items():
            need(configured.get(preserved) == expected and pristine['owners'].get(preserved) == [recipe['package']],
                 'preserved-factory-preimage')
        created = []
        for parent, after in sorted(recipe['new_directories'].items(), key=lambda item: (item[0].count('/'), item[0])):
            core.path(parent)
            core.node_shape(after)
            need(parent not in configured and parent not in seen and after['type'] == 'directory', 'new-config-directory-absence')
            seen.add(parent)
            configured[parent] = copy.deepcopy(after)
            created.append(dict(path=parent, before=None, after=copy.deepcopy(after)))
        need(configured.get(path) == recipe['before'], 'config-pristine-precondition')
        if recipe['before'] is not None:
            need(pristine['owners'].get(path) == [recipe['package']], 'config-package-owner')
            need(not any(node['type'] == 'hardlink' and node['target'] == path
                         for node in configured.values()), 'config-hardlink-group')
        else:
            need(recipe['package'] is None, 'project-config-ownership')
        after = recipe['after']
        core.node_shape(after)
        need(after['type'] == 'file' and file_node(recipe['body'], after['mode'], after['uid'], after['gid']) == after,
             'config-exact-output')
        configured[path] = copy.deepcopy(after)
        content[path] = recipe['body']
        delta = {key: copy.deepcopy(value) for key, value in recipe.items() if key != 'body'}
        delta['created_directories'] = created
        deltas.append(delta)
    links = validate_tree(core, configured)
    return configured, content, deltas, links


class DigestWriter:
    def __init__(self, destination):
        self.destination = destination
        self.digest = hashlib.sha256()
        self.bytes = 0
        self.failure = None

    def write(self, raw):
        if self.failure is not None:
            raise self.failure
        try:
            need(type(raw) is bytes, 'bundle-write-type')
            need(self.bytes + len(raw) <= LIMITS['total_bytes'] + LIMITS['nodes']*4096, 'bundle-byte-cap')
            count = self.destination.write(raw)
            need(type(count) is int and count == len(raw), 'bundle-short-write')
            self.digest.update(raw)
            self.bytes += len(raw)
            return count
        except BaseException as error:
            self.failure = error
            raise


def emit_bundle(core, nodes, bodies, manifest, epoch, destination):
    need(type(epoch) is int and 0 <= epoch <= 2**31-1, 'fixed-source-epoch')
    validate_tree(core, nodes)
    writer = DigestWriter(destination)
    # Explicit metadata, ordering and PAX format; no host inode metadata imported.
    ordering = {'directory': 0, 'file': 1, 'symlink': 2, 'hardlink': 3}
    with tarfile.open(fileobj=writer, mode='w|', format=tarfile.PAX_FORMAT) as output:
        for name in ('rootfs', 'metadata'):
            item = tarfile.TarInfo(name)
            item.type, item.mode, item.uid, item.gid, item.mtime = tarfile.DIRTYPE, 0o755, 0, 0, epoch
            item.uname = item.gname = ''
            output.addfile(item)
        for path in sorted(nodes, key=lambda p: (ordering[nodes[p]['type']], p.count('/'), p)):
            node = nodes[path]
            item = tarfile.TarInfo('rootfs/' + path)
            item.mode, item.uid, item.gid, item.mtime = node['mode'], node['uid'], node['gid'], epoch
            item.uname = item.gname = ''
            if node['type'] == 'file':
                raw = bodies[path]
                need(type(raw) is bytes and file_node(raw, node['mode'], node['uid'], node['gid']) == node,
                     'bundle-content-binding')
                item.size = len(raw)
                output.addfile(item, io.BytesIO(raw))
            else:
                item.type = {'directory': tarfile.DIRTYPE, 'symlink': tarfile.SYMTYPE,
                             'hardlink': tarfile.LNKTYPE}[node['type']]
                if node['type'] in ('symlink', 'hardlink'):
                    item.linkname = ('rootfs/' if node['type'] == 'hardlink' else '') + node['target']
                output.addfile(item)
        raw = encoded(manifest)
        item = tarfile.TarInfo('metadata/assembly.json')
        item.mode, item.uid, item.gid, item.mtime, item.size = 0o644, 0, 0, epoch, len(raw)
        item.uname = item.gname = ''
        output.addfile(item, io.BytesIO(raw))
    return dict(bytes=writer.bytes, sha256=writer.digest.hexdigest(), format='PAX_FIXED_METADATA_STAGING_ONLY')


def assemble(core, payloads, expected, recipes, epoch, destination):
    """Concrete fresh staging pipeline. Input map references convey no authority."""
    nodes, bodies, pristine, package_nodes = prepare(core, payloads, expected)
    nodes, bodies, deltas, links = configure(core, nodes, bodies, pristine, recipes)
    ownership = {path: dict(package_owners=pristine['owners'].get(path, []),
                            configured_by=next((row['id'] for row in deltas if row['path'] == path or
                                                path in row['new_directories']), None))
                 for path in sorted(nodes)}
    manifest = dict(schema_version=1, kind='PROJECT_STAGING_SOURCE_PROPOSAL_NOT_AUTHENTICATED',
                    base='FRESH_PRISTINE_PREPARED_PACKAGE_TREE', source_date_epoch=epoch,
                    source_inputs=dict(assembler_sha256=ASSEMBLER_SOURCE_SHA, primitive_sha256=CORE_SHA,
                                       literal_recipe_catalog_sha256=TRANSFORMS_SHA),
                    model_environment=dict(python_implementation=sys.implementation.name,
                                           python_version=list(sys.version_info[:3]),
                                           native_environment_accepted=False,
                                           acl_xattr_capability_encoding='UNIMPLEMENTED_NATIVE_PHASE'),
                    bundle_layout=dict(payload_prefix='rootfs/', project_metadata='metadata/assembly.json',
                                       metadata_installed_into_rootfs=False),
                    platform=dict(root_uuid='725346d2-f127-47bc-b464-9dd46155e8d6',
                                  efi_fat_uuid='2ABF-9F91', kernel='linux-asahi',
                                  boot='ASAHI_STUB_INTERNAL_ESP_STAGE2_ARM64_EFI'),
                    pristine=pristine, config_deltas=deltas, output_nodes=nodes,
                    output_ownership=ownership, output_link_states=links,
                    unresolved_runtime_links=sorted(path for path, row in links.items() if row['state'] != 'RESOLVED'),
                    existing_install_modified=False, hooks_executed=False, package_database_created=False,
                    archive_signatures_authenticated=False, image_assembled=False,
                    reproducible_image_accepted=False, installation_accepted=False, hardware_accepted=False)
    bundle = emit_bundle(core, nodes, bodies, manifest, epoch, destination)
    return dict(manifest=manifest, manifest_sha256=sha(encoded(manifest)), bundle=bundle,
                status='PRISTINE_AND_CONFIG_STAGING_BUNDLE_PROPOSED', assembly_authorized=False,
                actual_image_build=False)


def compare_builds(first, second):
    """Exact source/payload/config/metadata/bundle comparison; no image claim."""
    need(first['status'] == second['status'] == 'PRISTINE_AND_CONFIG_STAGING_BUNDLE_PROPOSED', 'build-scope')
    fields = ['manifest', 'manifest_sha256', 'bundle']
    differing = [field for field in fields if first[field] != second[field]]
    return dict(status='MATCH_STAGING_BUNDLE_ONLY' if not differing else 'FAIL_STAGING_COMPARISON',
                differences=differing, image_reproducibility_accepted=False, hardware_accepted=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--readiness', action='store_true', required=True)
    parser.parse_args()
    print(json.dumps(readiness(), sort_keys=True))


if __name__ == '__main__':
    main()
