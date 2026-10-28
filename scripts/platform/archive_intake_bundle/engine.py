#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline exact-archive intake into fresh staging; never install or execute packages.

The supported authentication profile reuses pinned historical signature proofs
for exactly two retained archives. Hash agreement alone cannot select that profile.
Prepared maps hold bounded spool references, not aggregate package bytes.
"""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import types

BASE = Path(__file__).resolve().parent
RUNTIME = BASE / '_archive_intake_runtime'
POLICY_SHA = '42ff1974180d00acfb211839ece6c55addcc7254f1a54f2450bf5ac91ab58521'
ADMISSION_SHA = '98bf4430ae7bef56ed61aa9bf314613a86c73c54592a12564c108c2761aedcf5'
PROFILE = 'retained-two-historical-signatures-v1'
PROOFS = {
    'proof/actual-receipt.json': '53747d29b02c11517d3c330530f9a6de57afcd9575e0c75c8f23f2dbd7fb6b3c',
    'proof/retained-2.json': '9407330375b60db80180abdbfffdd50bdd811c3269a9e665f8696efb8cbe223e',
    'proof/retained-3.json': '0c4c8e7755195c6f33f83df9de746c4406520806e0e4856315444d0e23f68205',
    'proof/process-observations.json': '8d19c8f6b70218007b1ce06766913c48b4fdeabe5fe6796fb44b6d09f59ef02e',
}
AUTHENTICATION = dict(schema_version=1, profile=PROFILE, adapter_sha256=ADMISSION_SHA,
                      proof_sha256=PROOFS)


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False, ensure_ascii=True) + '\n').encode()


def pinned_file(path, digest, maximum=1024**2):
    """Read one no-follow, single-link source/input with a stable descriptor."""
    path = Path(path).absolute()
    need(path == path.resolve(), 'input-symlink-or-noncanonical-path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 < before.st_size <= maximum, 'input-ordinary-file-bound')
        raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(all(getattr(before, k) == getattr(os.fstat(fd), k) ==
                 getattr(path.lstat(), k) for k in fields), 'input-drift')
        need(len(raw) == before.st_size and sha(raw) == digest, 'input-pin')
        return bytes(raw)
    finally:
        os.close(fd)


def load(path, digest):
    raw = pinned_file(path, digest)
    module = types.ModuleType('_archive_adapter_' + path.stem)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite-json'))


def validate_selection(core, selection, authentication):
    need(type(authentication) is dict and authentication == AUTHENTICATION and
         type(authentication.get('schema_version')) is int, 'authentication-profile-required')
    need(type(selection) is dict and set(selection) == {'schema_version', 'scope', 'packages'} and
         type(selection['schema_version']) is int and selection['schema_version'] == 1 and
         selection['scope'] == 'EXACT_SELECTED_ARCHIVE_STAGING_ONLY', 'selection-schema')
    rows = selection['packages']
    need(type(rows) is list and 0 < len(rows) <= 261, 'selection-bound')
    seen = set()
    for row in rows:
        need(type(row) is dict and set(row) == {'identity', 'archive', 'signature'}, 'selection-row')
        identity = core.package_identity(row['identity'])
        name = identity['name']
        need(name not in seen, 'duplicate-selection')
        seen.add(name)
        need(identity in [dict(name='networkmanager', version='1.58.1-1', arch='aarch64'),
                          dict(name='perl', version='5.42.2-2', arch='aarch64')],
             'authentication-profile-has-no-proof-for-tuple')
        core.reference(row['archive'], core.ARCHIVE)
        core.reference(row['signature'], 65536)
    return copy.deepcopy(rows)


def separation(core, package):
    """Controls stay out of rootfs; hooks/config stay pristine and separately listed."""
    tree = package['nodes']
    need(not any(path.startswith('.') for path in tree), 'unsupported-root-dot-control')
    fields = package['metadata']['.PKGINFO']['parsed']['fields']
    backups = fields.get('backup', [])
    need(len(set(backups)) == len(backups), 'duplicate-backup-path')
    for path in backups:
        core.path(path)
        need(path in tree and tree[path]['type'] == 'file', 'backup-not-package-file')
    hooks = sorted(path for path, node in tree.items() if node['type'] != 'directory' and
                   (path.startswith(('usr/share/libalpm/hooks/', 'etc/pacman.d/hooks/')) or
                    path.startswith(('usr/lib/sysusers.d/', 'usr/lib/tmpfiles.d/'))))
    return dict(controls={name: dict(bytes=row['ref']['size'], sha256=row['ref']['sha256'])
                          for name, row in sorted(package['metadata'].items())},
                scriptlets=['.INSTALL'] if '.INSTALL' in package['metadata'] else [],
                hook_and_generated_state_inputs=hooks, backup_paths=sorted(backups),
                etc_payload_paths=sorted(path for path in tree if path.startswith('etc/')),
                hooks_executed=False, generated_state_created=False,
                config_policy='PRISTINE_ARCHIVE_BYTES_NO_LIBALPM_TRANSACTION')


@contextmanager
def prepared(selection, authentication, spool_parent, seconds=1200):
    """Yield complete selected spooled payload/node maps; valid only inside context.

    Expected tuples, authentication-profile selection and current file identities
    are explicit inputs. The retained admission reader independently authenticates
    the proof graph and matches signed PKGINFO metadata before returning maps.
    """
    need(sys.exc_info() == (None, None, None), 'normal-entry-required')
    need(type(seconds) is int and 0 < seconds <= 1200, 'wall-bound')
    policy = load(RUNTIME / 'policy.py', POLICY_SHA)
    admission = load(RUNTIME / 'real_admission.py', ADMISSION_SHA)
    with policy.snapshot() as (raws, check):
        modules = policy.sources(raws)
        core = modules['core']
        rows = validate_selection(core, selection, authentication)
        budget = core.Budget(time.monotonic() + seconds)
        # Conservative full-profile ceiling; this does not reserve disk blocks.
        space = policy.space_check(core, Path(spool_parent), budget)
        with modules['spool'].Store(Path(spool_parent) / 'spool', core, budget) as store:
            packages, authority, separated = [], {}, {}
            for row in rows:
                answer = admission.inspect_selected(core, modules['intake'], modules['consumer'],
                    row['identity'], row['archive'], row['signature'], store, budget)
                package = answer['payload']
                name = package['identity']['name']
                packages.append(package)
                authority[name] = answer['authority']
                separated[name] = separation(core, package)
                check()
            expected = [row['identity'] for row in rows]
            # Validate ownership, body closure, directory parents and virtual links
            # before exposing maps; do not synthesize nodes absent from archives.
            modules['bridge'].prepare(core, modules['assembler'], packages, expected, store)
            yield dict(modules=modules, packages=packages, expected=expected, store=store,
                       budget=budget, authentication=authority, separation=separated,
                       space_preflight=space)
            check()
        need(not os.path.lexists(Path(spool_parent) / 'spool') and not store.cleanup_errors,
             'spool-cleanup-incomplete')
        check()


def assemble(session, destination, epoch=0):
    """Stream the selected pristine tree through pinned assembler policy."""
    m, store, budget = session['modules'], session['store'], session['budget']
    core, assembler, bridge = m['core'], m['assembler'], m['bridge']
    nodes, bodies, pristine = bridge.prepare(core, assembler, session['packages'], session['expected'], store)
    nodes, bodies, deltas, links = assembler.configure(core, nodes, bodies, pristine, [])
    manifest = bridge.manifest_builder(assembler)(nodes, pristine, deltas, links, epoch)
    manifest['source_inputs'].update(archive_intake_sha256=sha(Path(__file__).read_bytes()),
                                    stream_bridge_sha256=bridge.BRIDGE_SHA,
                                    retained_authentication_adapter_sha256=ADMISSION_SHA,
                                    spool_source_sha256=m['spool'].__source_sha256__,
                                    source_policy_sha256=POLICY_SHA)
    manifest['archive_authentication'] = copy.deepcopy(session['authentication'])
    manifest['inert_separation'] = copy.deepcopy(session['separation'])
    manifest['body_storage'] = dict(kind='CLOSED_OWNED_REGULAR_SPOOL_REFERENCES', chunk_bytes=65536,
                                   physical_spool_identities_in_reproducible_manifest=False)
    manifest['intake_metadata'] = {p['identity']['name']: dict(
        controls={name: dict(bytes=row['ref']['size'], sha256=row['ref']['sha256'], parsed=row['parsed'])
                  for name, row in sorted(p['metadata'].items())}, facts=p['intake'])
                                  for p in sorted(session['packages'], key=lambda p: p['identity']['name'])}
    bundle, charged = bridge.emit(core, assembler, nodes, bodies, manifest, epoch, destination, store, budget)
    return dict(status='PRISTINE_AND_CONFIG_STAGING_BUNDLE_PROPOSED', manifest=manifest,
                manifest_sha256=sha(assembler.encoded(manifest)), bundle=bundle,
                assembly_authorized=False, actual_image_build=False,
                io=dict(compressed_reserved_work_bytes=getattr(budget, 'intake_compressed', 0),
                        decoded_bytes=budget.decoded, spool=copy.deepcopy(store.stats),
                        output_bytes=charged.bytes, max_output_chunk=charged.max_chunk))


def run(selection, authentication, output, epoch=0, seconds=1200):
    """Create a new private staging directory. Failed runs never get a PASS receipt."""
    output = Path(output).absolute()
    need(output.parent == output.parent.resolve() and output.name not in ('', '.', '..'), 'output-parent')
    os.mkdir(output, 0o700)
    (output / 'INCOMPLETE.json').write_bytes(encoded(dict(status='INCOMPLETE_NOT_ACCEPTED')))
    with prepared(selection, authentication, output, seconds) as session:
        with (output / 'staging.tar').open('xb') as destination:
            result = assemble(session, destination, epoch)
            destination.flush()
            os.fsync(destination.fileno())
        counts = {p['identity']['name']: dict(nodes=len(p['nodes']), files=len(p['bodies']))
                  for p in session['packages']}
    # The result becomes durable only after spool and pinned source cleanup.
    receipt = dict(status='PASS_EXACT_SELECTED_ARCHIVES_TO_STAGING_ONLY',
                   selection_sha256=sha(encoded(selection)), authentication_input_sha256=sha(encoded(authentication)),
                   bundle=result['bundle'], manifest_sha256=result['manifest_sha256'], packages=counts,
                   archive_authentication=result['manifest']['archive_authentication'],
                   separation=result['manifest']['inert_separation'], io=result['io'],
                   spool_cleanup='PASS', full261_accepted=False, license_redistribution_accepted=False,
                   independent_owner_trust_accepted=False, native_image_build=False,
                   boot_installation_hardware_release_accepted=False)
    (output / 'assembly.json').write_bytes(encoded(result['manifest']))
    with (output / 'receipt.pending.json').open('xb') as pending:
        pending.write(encoded(receipt))
        pending.flush()
        os.fsync(pending.fileno())
    (output / 'INCOMPLETE.json').unlink()
    # Commit last: failed cleanup or writes cannot leave an accepted filename.
    os.rename(output / 'receipt.pending.json', output / 'receipt.json')
    return receipt


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('selection', 'selection-sha256', 'authentication', 'authentication-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--epoch', type=int, default=0)
    parser.add_argument('--seconds', type=int, default=1200)
    args = parser.parse_args()
    selection = decode(pinned_file(args.selection, args.selection_sha256))
    authentication = decode(pinned_file(args.authentication, args.authentication_sha256))
    print(json.dumps(run(selection, authentication, args.output, args.epoch, args.seconds), sort_keys=True))


if __name__ == '__main__':
    main()
