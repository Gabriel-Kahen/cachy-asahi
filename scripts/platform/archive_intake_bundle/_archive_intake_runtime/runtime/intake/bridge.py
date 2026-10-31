#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pinned assembler manifest/config policy with regular bodies streamed from spool."""
import ast
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import types

BASE = Path(__file__).resolve().parent
CORE_SHA = '3a71ba896700f72130e35a56845516bd9c42de0b1b0fd782b79829b37ac262a7'
ASSEMBLER_SHA = '170b60eb8b314f99f883dfd155b918131fb23f7d6b6c6b299d19621c5a60f1d4'
BRIDGE_SHA = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def need(value, reason):
    if not value:
        raise ValueError(reason)


def module(relative, expected):
    path = BASE/relative
    raw = path.read_bytes()
    need(len(raw) <= 1024**2 and hashlib.sha256(raw).hexdigest() == expected, 'source-pin')
    result = types.ModuleType('_owned_source')
    result.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    return result


def sources():
    return module('source/core.py', CORE_SHA), module('source/assembler.py', ASSEMBLER_SHA)


def manifest_builder(assembler):
    """Reuse exactly the two pinned pure assignments from assembler.assemble."""
    raw = (BASE/'source/assembler.py').read_bytes()
    need(hashlib.sha256(raw).hexdigest() == ASSEMBLER_SHA, 'manifest-source-pin')
    function = next(item for item in ast.parse(raw).body if isinstance(item, ast.FunctionDef) and item.name == 'assemble')
    assignments = [item for item in function.body if isinstance(item, ast.Assign) and
                   len(item.targets) == 1 and isinstance(item.targets[0], ast.Name) and
                   item.targets[0].id in ('ownership', 'manifest')]
    need([item.targets[0].id for item in assignments] == ['ownership', 'manifest'], 'manifest-source-shape')
    wrapper = ast.parse('def create(nodes, pristine, deltas, links, epoch):\n    return None\n').body[0]
    wrapper.body = assignments + [ast.Return(value=ast.Name(id='manifest', ctx=ast.Load()))]
    tree = ast.fix_missing_locations(ast.Module(body=[wrapper], type_ignores=[]))
    namespace = dict(assembler.__dict__)
    exec(compile(tree, '<pinned-assembler-manifest>', 'exec'), namespace)
    return namespace['create']


def prepare(core, assembler, packages, expected, store):
    need(type(expected) is list and 0 < len(expected) <= 261 and type(packages) is list and
         len(packages) == len(expected), 'complete-spooled-selection')
    selection = {}
    for identity in expected:
        core.package_identity(identity)
        need(identity['name'] not in selection, 'duplicate-selection')
        selection[identity['name']] = identity
    nodes, bodies, owners, provenance = {}, {}, {}, {}
    entries = total = metadata_bytes = 0
    for package in packages:
        need(type(package) is dict and set(package) == {'identity', 'archive_sha256', 'source_sha256',
               'nodes', 'bodies', 'metadata', 'intake'}, 'spooled-package-schema')
        identity = core.package_identity(package['identity'])
        name = identity['name']
        need(name in selection and identity == selection[name] and name not in provenance, 'exact-package-tuple')
        need(all(type(package[key]) is str and core.HEX.fullmatch(package[key]) for key in
                 ('archive_sha256', 'source_sha256')), 'package-source-digests')
        need(type(package['metadata']) is dict and set(package['metadata']) <= core.CONTROL and
             type(package['intake']) is dict, 'control-metadata-schema')
        for control in package['metadata'].values():
            need(type(control) is dict and set(control) == {'ref', 'parsed'} and
                 type(control['parsed']) is dict, 'control-record')
            store.reference_check(control['ref'])
            need(control['ref']['size'] <= 1024**2, 'control-metadata-bound')
        tree = package['nodes']
        need(type(tree) is dict and type(package['bodies']) is dict, 'spooled-node-maps')
        entries += len(tree)
        need(entries <= assembler.LIMITS['nodes'], 'node-map-cap')
        for node in tree.values():
            core.node_shape(node)
        need(set(package['bodies']) == {path for path, node in tree.items() if node['type'] == 'file'}, 'body-reference-set')
        semantic_controls = {name: row['parsed'] for name, row in package['metadata'].items()}
        metadata_bytes += len(assembler.encoded(semantic_controls)) + len(assembler.encoded(package['intake']))
        need(metadata_bytes <= 32*1024**2, 'semantic-metadata-cap')
        for path, node in tree.items():
            core.path(path)
            metadata_bytes += len(path.encode()) + len(assembler.encoded(node))
            need(metadata_bytes <= 32*1024**2, 'semantic-metadata-cap')
            need(path not in core.CONTROL, 'control-not-payload')
            if node['type'] == 'hardlink':
                need(node['target'] in tree and tree[node['target']]['type'] == 'file', 'same-package-hardlink')
            if node['type'] == 'file':
                ref = package['bodies'][path]
                store.reference_check(ref)
                need(ref['size'] == node['bytes'] and ref['sha256'] == node['sha256'], 'spool-payload-binding')
                total += ref['size']
                need(total <= assembler.LIMITS['total_bytes'], 'payload-byte-cap')
                bodies[path] = copy.deepcopy(ref)
            if path in nodes:
                need(node['type'] == 'directory' and node == nodes[path], 'pristine-path-conflict')
            nodes[path] = copy.deepcopy(node)
            owners.setdefault(path, []).append(name)
        provenance[name] = dict(identity=copy.deepcopy(identity), archive_sha256=package['archive_sha256'],
                               source_sha256=package['source_sha256'],
                               evidence='DECLARED_PREPARED_INPUTS_NOT_FRESH_AUTHENTICATION')
    need(set(provenance) == set(selection), 'package-selection-closure')
    links = assembler.validate_tree(core, nodes)
    pristine = dict(nodes=copy.deepcopy(nodes), owners={path: sorted(names) for path, names in owners.items()},
                    packages={name: provenance[name] for name in sorted(provenance)}, link_states=links)
    return nodes, bodies, pristine


class ChargedWriter:
    def __init__(self, destination, budget, limit):
        self.destination, self.budget, self.limit = destination, budget, limit
        self.bytes = 0
        self.max_chunk = 0

    def write(self, raw):
        self.budget.check()
        need(type(raw) is bytes and len(raw) <= 65536 and self.bytes + len(raw) <= self.limit, 'output-byte-cap')
        count = self.destination.write(raw)
        need(type(count) is int and count == len(raw), 'output-write')
        self.bytes += count
        self.max_chunk = max(self.max_chunk, count)
        self.budget.check()
        return count


def emit(core, assembler, nodes, bodies, manifest, epoch, destination, store, budget):
    need(type(epoch) is int and 0 <= epoch <= 2**31-1, 'fixed-source-epoch')
    assembler.validate_tree(core, nodes)
    charged = ChargedWriter(destination, budget, assembler.LIMITS['total_bytes']+assembler.LIMITS['nodes']*4096)
    writer = assembler.DigestWriter(charged)
    ordering = {'directory': 0, 'file': 1, 'symlink': 2, 'hardlink': 3}
    output = tarfile.open(fileobj=writer, mode='w|', format=tarfile.PAX_FORMAT)
    try:
        for name in ('rootfs', 'metadata'):
            item = tarfile.TarInfo(name)
            item.type, item.mode, item.uid, item.gid, item.mtime = tarfile.DIRTYPE, 0o755, 0, 0, epoch
            item.uname = item.gname = ''
            output.addfile(item)
        for path in sorted(nodes, key=lambda name: (ordering[nodes[name]['type']], name.count('/'), name)):
            budget.check()
            node = nodes[path]
            item = tarfile.TarInfo('rootfs/'+path)
            item.mode, item.uid, item.gid, item.mtime = node['mode'], node['uid'], node['gid'], epoch
            item.uname = item.gname = ''
            if node['type'] == 'file':
                body = bodies[path]
                item.size = node['bytes']
                if type(body) is bytes:
                    need(len(body) <= 65536 and assembler.file_node(body, node['mode'], node['uid'], node['gid']) == node,
                         'literal-config-body')
                    output.addfile(item, io.BytesIO(body))
                else:
                    need(body['size'] == node['bytes'] and body['sha256'] == node['sha256'], 'stream-body-binding')
                    with store.lookup(body) as stream:
                        output.addfile(item, stream)
            else:
                item.type = {'directory': tarfile.DIRTYPE, 'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE}[node['type']]
                if node['type'] in ('symlink', 'hardlink'):
                    item.linkname = ('rootfs/' if node['type'] == 'hardlink' else '')+node['target']
                output.addfile(item)
        raw = assembler.encoded(manifest)
        need(len(raw) <= 256*1024**2, 'manifest-byte-cap')
        item = tarfile.TarInfo('metadata/assembly.json')
        item.mode, item.uid, item.gid, item.mtime, item.size = 0o644, 0, 0, epoch, len(raw)
        item.uname = item.gname = ''
        output.addfile(item, io.BytesIO(raw))
        output.close()
    except BaseException as original:
        # Preserve body-reader/cancellation failures as well as writer failures.
        if writer.failure is None:
            writer.failure = original
        try:
            output.close()
        except BaseException:
            pass
        raise
    return dict(bytes=writer.bytes, sha256=writer.digest.hexdigest(), format='PAX_FIXED_METADATA_STAGING_ONLY'), charged


def assemble_streamed(core, assembler, packages, expected, recipes, epoch, destination, store, budget):
    nodes, bodies, pristine = prepare(core, assembler, packages, expected, store)
    nodes, bodies, deltas, links = assembler.configure(core, nodes, bodies, pristine, recipes)
    manifest = manifest_builder(assembler)(nodes, pristine, deltas, links, epoch)
    manifest['source_inputs']['stream_bridge_sha256'] = BRIDGE_SHA
    manifest['source_inputs']['spool_source_sha256'] = hashlib.sha256((BASE/'spool.py').read_bytes()).hexdigest()
    manifest['body_storage'] = dict(kind='CLOSED_OWNED_REGULAR_SPOOL_REFERENCES', chunk_bytes=65536,
                                    physical_spool_identities_in_reproducible_manifest=False)
    manifest['intake_metadata'] = {package['identity']['name']: dict(
        controls={name: dict(bytes=row['ref']['size'], sha256=row['ref']['sha256'], parsed=row['parsed'])
                  for name, row in sorted(package['metadata'].items())},
        facts=package['intake']) for package in sorted(packages, key=lambda row: row['identity']['name'])}
    bundle, charged = emit(core, assembler, nodes, bodies, manifest, epoch, destination, store, budget)
    return dict(manifest=manifest, manifest_sha256=assembler.sha(assembler.encoded(manifest)), bundle=bundle,
                status='PRISTINE_AND_CONFIG_STAGING_BUNDLE_PROPOSED', assembly_authorized=False,
                actual_image_build=False,
                io=dict(compressed_reserved_work_bytes=getattr(budget, 'intake_compressed', 0), decoded_bytes=budget.decoded,
                        spool=copy.deepcopy(store.stats), output_bytes=charged.bytes, max_output_chunk=charged.max_chunk))


def main():
    need(sys.argv[1:] == ['--readiness'], 'readiness-only-cli')
    _, assembler = sources()
    result = assembler.readiness()
    result.update(archive_intake_dispatch=False, source_increment='BOUNDED_ARCHIVE_AND_SPOOL_FIXTURE_PROPOSAL')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
