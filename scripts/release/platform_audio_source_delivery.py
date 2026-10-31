#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Finite offline platform/audio recipe-input bundles; never build or install.

Exact retained source/vendor/patch/notice bytes are authoritative, not a checkout
label or a package's self-reported BUILDINFO. Publication blockers stay visible.
"""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
MAX_FILE, MAX_TOTAL, MAX_MEMBERS = 16 * 1024**2, 32 * 1024**2, 64
PROFILE_SHA256 = 'bea1e7ee2a5f5db78ca721348a8ae44e68bb5a0bdf495616c42eb08ca3f435da'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


s = module('platform_audio_source_transport', HERE / 'source_delivery.py')


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def profiles():
    raw = s.local_read(HERE, 'platform_audio_source_profiles.json', s.MAX_JSON)
    s.need(s.digest(raw) == PROFILE_SHA256, 'reviewed platform/audio profiles changed')
    return s.decode(raw)['profiles']


def profile(name):
    rows = profiles()
    s.need(name in rows, 'package outside finite platform/audio set')
    return rows[name]


def flat(key):
    s.need(len(s.relative(key)) == 1, 'flat bundle filename required')
    return key


def archive_member(raw, key):
    """Read a named license only; preserve original source archives opaque."""
    s.relative(key)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:*') as archive:
        matches = [m for m in archive if m.name == key]
        s.need(len(matches) == 1 and matches[0].isfile() and
               0 < matches[0].size <= MAX_FILE, 'missing/duplicate/nonregular license: ' + key)
        return archive.extractfile(matches[0]).read()


def instructions(name, p, epoch):
    note = '''This bundle preserves the exact reviewed PKGBUILD and every declared local
source, including source archives, full vendor archive, patches and notices.
The original archives are opaque inputs; do not flatten their trees or rewrite
Cargo.lock. LICENSE.upstream and copied third-party texts are convenience copies
of exact retained archive members. PACKAGING.LICENSE applies to project packaging,
not to every upstream component. Consult source-map.json and bundle.json.

Rebuild only in a separately provisioned disposable native aarch64 environment as
an ordinary user, never on the working host or a live Asahi system. Provision the
PKGBUILD makedepends and an appropriate pacman/makepkg/base-devel toolchain first.
BUILD.inputs.lock.json identifies the historical environment binary inputs; it
is not a toolchain source bundle or proof those URLs remain available. Where
present, BUILD.expected-packages.lock is the exact historical package inventory.
No provisioning, dependency install, service start or audio execution is automated.

From this unpacked directory, review PKGBUILD, then run:
  makepkg --verifysource --noconfirm
  makepkg --cleanbuild --clean --force --log --noconfirm --nodeps
The --nodeps switch reproduces the historical build-only exception: runtime
requirements remain declared but unresolved in that builder. It is not a license
to install a partial platform stack. Do not add --syncdeps or --install here.
Record uname -a, getconf PAGESIZE, pacman -Q, makepkg --version, configuration,
SOURCE_DATE_EPOCH, flags, logs and output hashes for both clean build attempts.
Byte reproducibility and historical compiler correspondence need separate checks.
'''
    s.need(type(epoch) in (int, str) and re.fullmatch('[0-9]{10}', str(epoch)), 'historical source epoch')
    note = note.replace('From this unpacked directory, review PKGBUILD, then run:',
                        'From this unpacked directory, review PKGBUILD, then run:\n  export SOURCE_DATE_EPOCH=' + str(epoch))
    if 'components' in p:
        note += '''\nPKGBUILD prepares a private CARGO_HOME and points Cargo at the extracted vendor/
tree with offline=true. Its build uses --release --frozen --offline and checks
the preserved Cargo.lock hash. Keep the entire 117-crate vendor archive: selecting
only an apparent host-specific dependency subset can omit target/build inputs.
COMPONENTS.json records the audited registry package checksum joins for this lock.
Speakersafetyd's original source includes legitimate relative configuration links;
the exporter neither follows nor extracts these links. makepkg handles them in the
isolated source worktree. No relinking obligation is declared satisfied here.
'''
    note += '\nPackage: ' + name + ' ' + p['version'] + '\n'
    note += 'Publication blockers: ' + json.dumps(p['publication_blockers'], sort_keys=True) + '\n'
    note += 'Native rebuild, ALPM install, VM execution, physical M2 and publication: NOT_RUN.\n'
    return note.encode()


def source_set(name, read):
    p = profile(name)
    bodies = {}
    for key, row in p['inputs'].items():
        flat(key)
        raw = read(key, row)
        s.need(type(raw) is bytes and len(raw) == row['bytes'] <= MAX_FILE and
               s.digest(raw) == row['sha256'], 'missing/changed pinned input: ' + row['path'])
        bodies[key] = raw
    info = p['metadata']
    s.need(len(info['source']) == len(info['sha256sums']) and
           all(s.digest(bodies[key]) == pin for key, pin in zip(info['source'], info['sha256sums'])),
           'recipe source checksum/order mismatch')
    for key, row in p['extracts'].items():
        flat(key)
        s.need(key not in bodies, 'license filename collision')
        bodies[key] = archive_member(bodies[row['archive']], row['member'])
    if 'components' in p:
        bodies['COMPONENTS.json'] = encoded(p['components'])
    bodies['UPSTREAM.json'] = encoded(p['upstream_acquisition_receipt'])
    bodies['REBUILD.txt'] = instructions(name, p, s.decode(bodies['BUILD.inputs.lock.json'])['source_date_epoch'])
    s.need(len(bodies) < MAX_MEMBERS and sum(map(len, bodies.values())) <= MAX_TOTAL,
           'source material bounds')
    return bodies


def binding_check(binding, p):
    if binding is None:
        return
    s.fields(binding, ('status', 'archive_sha256', 'archive_bytes', 'pkgbuild_sha256',
                       'metadata_sha256', 'payload_sha256', 'compiled_source_correspondence',
                       'native_execution', 'generic_guard_errors', 'installation_review'))
    s.need(binding['status'] == 'METADATA_FIXED_DATA_AND_ELF_STRUCTURE_BOUND' and
           binding['compiled_source_correspondence'] == 'NOT_ESTABLISHED' and
           binding['native_execution'] == 'NOT_ESTABLISHED', 'archive binding status')
    for key in ('archive_sha256', 'metadata_sha256', 'payload_sha256', 'pkgbuild_sha256'):
        s.sha(binding[key])
    s.need(binding['pkgbuild_sha256'] == p['inputs']['PKGBUILD']['sha256'] and
           type(binding['archive_bytes']) is int and 0 < binding['archive_bytes'] <= MAX_TOTAL,
           'binding recipe/size mismatch')
    for key in ('generic_guard_errors', 'installation_review'):
        s.need(type(binding[key]) is list and len(binding[key]) <= 1024 and
               all(type(x) is str and len(x) <= 4096 for x in binding[key]), 'binding review list')


def bind_archive(path, name):
    """Static metadata/payload join, preserving generic protected-stack refusals."""
    p = profile(name)
    c = module('platform_audio_package_checks', HERE.parent / 'checks/package_checks.py')
    raw = s.read_file(path, MAX_TOTAL)
    with tempfile.TemporaryDirectory(prefix='platform-audio-archive-') as folder:
        snapshot = Path(folder) / ('archive.pkg.tar.zst' if str(path).endswith('.zst') else 'archive.pkg.tar')
        snapshot.write_bytes(raw)
        report = c.package(snapshot)
    info, build = report['metadata']['.PKGINFO'], report['metadata']['.BUILDINFO']
    expected = dict(pkgname=[name], pkgbase=[name], pkgver=[p['version']], arch=[p['arch']],
                    license=p['metadata']['license'])
    for src, dest in (('depends', 'depend'), ('makedepends', 'makedepend'), ('checkdepends', 'checkdepend'),
                      ('optdepends', 'optdepend'), ('provides', 'provides'), ('conflicts', 'conflict'),
                      ('replaces', 'replaces'), ('backup', 'backup')):
        expected[dest] = p['metadata'].get(src, [])
    s.need(all(sorted(info.get(k, [])) == sorted(v) for k, v in expected.items()), 'package identity/dependency mismatch')
    s.need(build.get('pkgbuild_sha256sum') == [p['inputs']['PKGBUILD']['sha256']] and
           build.get('format') == ['2'] and build.get('pkgname') == [name] and
           build.get('pkgver') == [p['version']] and build.get('pkgarch') == [p['arch']],
           'BUILDINFO recipe/identity mismatch')
    members, wanted = report['members'], p['payload']
    metadata = {'.PKGINFO', '.BUILDINFO', '.MTREE'}
    files = {k for k, row in members.items() if row['type'] != '5'}
    s.need(files == set(wanted) | metadata, 'package payload coverage mismatch')
    directories = {str(parent) for key in wanted for parent in Path(key).parents if str(parent) != '.'}
    for key, row in members.items():
        s.need(row['uid'] == row['gid'] == 0, 'package member ownership mismatch')
        if row['type'] == '5':
            s.need(key in directories and row['mode'] == 0o755, 'foreign directory/mode')
        elif key in metadata:
            s.need(row['type'] == '0' and row['mode'] == 0o644, 'metadata type/mode')
        else:
            expected_row = wanted[key]
            s.need(row['type'] == '0' and row['mode'] == expected_row['mode'], 'payload type/mode: ' + key)
            if expected_row['ELF']:
                s.need(key in report['elf'] and not report['elf'][key]['errors'], 'AArch64 ELF structure: ' + key)
            else:
                s.need(row['sha256'] == expected_row['sha256'] and key not in report['elf'], 'payload bytes: ' + key)
    # Preserve the generic checker result. This narrower join does not admit
    # protected paths, installation, speaker safety, or compiler provenance.
    return dict(status='METADATA_FIXED_DATA_AND_ELF_STRUCTURE_BOUND', archive_sha256=s.digest(raw),
                archive_bytes=len(raw), pkgbuild_sha256=p['inputs']['PKGBUILD']['sha256'],
                metadata_sha256=s.digest(encoded(report['metadata'])),
                payload_sha256=s.digest(encoded({k: members[k] for k in sorted(files - metadata)})),
                compiled_source_correspondence='NOT_ESTABLISHED', native_execution='NOT_ESTABLISHED',
                generic_guard_errors=report['errors'], installation_review=report['review'])


def manifest(name, bodies, revision, binding):
    s.need(type(revision) is str and re.fullmatch('[0-9a-f]{40}', revision), 'full observed checkout revision required')
    p = profile(name)
    binding_check(binding, p)
    return dict(schema_version=1, purpose='finite-platform-audio-source-inputs', profile_sha256=PROFILE_SHA256,
                package=dict(name=name, version=p['version'], arch=p['arch']),
                upstream_revision=p['upstream_revision'], observed_checkout_revision=revision,
                revision_is_not_source_authority=True, recipe_sha256=p['inputs']['PKGBUILD']['sha256'],
                source_order=p['metadata']['source'], declared_licenses=p['metadata']['license'],
                dependencies={k: p['metadata'].get(k, []) for k in ('depends', 'makedepends', 'checkdepends', 'optdepends')},
                source_scope=p['source_scope'], finite_recipe_inputs_complete=True,
                complete_corresponding_source_accepted=False, legal_acceptance=False,
                relinking_obligations='NOT_ADJUDICATED', publication_blockers=p['publication_blockers'],
                source_input_status='EXPORTED_WITH_PUBLICATION_BLOCKERS' if p['publication_blockers'] else 'EXPORTED_FINITE_DATA_INPUTS',
                archive_binding=binding, archive_status='BOUND_STATIC_ONLY' if binding else 'UNBOUND_NO_ARCHIVE_SUPPLIED',
                archive_binding_is_not_authenticated_build_provenance=True,
                files={k: dict(sha256=s.digest(v), bytes=len(v), mode='0644') for k, v in sorted(bodies.items())},
                native_build='NOT_RUN', alpm_installation='NOT_RUN', vm_execution='NOT_RUN',
                physical_m2='NOT_RUN', publication='NOT_RUN', release='NOT_ADMITTED')


def tar_bytes(bodies):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for key, raw in sorted(bodies.items()):
            flat(key)
            member = tarfile.TarInfo(key)
            member.size, member.mode = len(raw), 0o644
            member.uid, member.gid, member.mtime = 0, 0, 0
            archive.addfile(member, io.BytesIO(raw))
    return output.getvalue()


def verified(raw, checksum, archive_path=None):
    s.sha(checksum)
    s.need(type(raw) is bytes and 0 < len(raw) <= MAX_TOTAL and s.digest(raw) == checksum, 'bundle checksum/bound mismatch')
    bodies = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            key = flat(member.name)
            s.need(key not in bodies and member.isfile() and 0 < member.size <= MAX_FILE and
                   len(bodies) < MAX_MEMBERS, 'duplicate/nonregular/oversized bundle member')
            bodies[key] = archive.extractfile(member).read()
            s.need(sum(map(len, bodies.values())) <= MAX_TOTAL, 'expanded bundle bound')
    saved = s.decode(bodies.pop('bundle.json'))
    s.need(type(saved.get('package')) is dict, 'bundle package object')
    name = saved['package'].get('name')
    exact = source_set(name, lambda key, row: bodies[key])
    s.need(exact == bodies, 'source bundle coverage/derived material mismatch')
    expected = manifest(name, exact, saved.get('observed_checkout_revision'), saved.get('archive_binding'))
    s.need(saved == expected, 'bundle manifest mismatch')
    s.need(tar_bytes(dict(bodies, **{'bundle.json': encoded(expected)})) == raw, 'noncanonical source bundle')
    if archive_path is not None:
        s.need(saved['archive_binding'] is not None and
               saved['archive_binding'] == bind_archive(archive_path, name), 'supplied archive does not match saved binding')
    return saved, bodies


def write_fresh(output, bodies):
    """Descriptor-relative fresh private directory; failed partials stay reviewable."""
    output = Path(output).absolute()
    flat(output.name)
    parent = s.directory(output.parent)
    fd = None
    try:
        os.mkdir(output.name, 0o700, dir_fd=parent)
        created = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        opened = os.fstat(fd)
        s.need((created.st_dev, created.st_ino) == (opened.st_dev, opened.st_ino), 'output directory replaced')
        for key, raw in sorted(bodies.items()):
            flat(key)
            leaf = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(leaf, 'wb') as stream:
                stream.write(raw)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def pack(root, name, revision, output, archive=None):
    bodies = source_set(name, lambda key, row: s.local_read(root, row['path'], MAX_FILE))
    bound = bind_archive(archive, name) if archive else None
    saved = manifest(name, bodies, revision, bound)
    source_map = encoded({key: s.digest(raw) for key, raw in sorted(bodies.items())})
    raw = tar_bytes(dict(bodies, **{'bundle.json': encoded(saved)}))
    verified(raw, s.digest(raw))
    # Use bundle.json itself for embedded instructions/source map authority; the
    # external map has the exact opaque transport format source_delivery expects.
    write_fresh(output, {'source.tar': raw, 'bundle.json': encoded(saved), 'source-map.json': source_map,
                         'PKGBUILD': bodies['PKGBUILD'], 'LICENSE.upstream': bodies['LICENSE.upstream'],
                         'PACKAGING.LICENSE': bodies['PACKAGING.LICENSE'], 'REBUILD.txt': bodies['REBUILD.txt']})
    return dict(package=saved['package'], status=saved['source_input_status'], bundle_sha256=s.digest(raw),
                bundle_bytes=len(raw), archive_status=saved['archive_status'], publication_blockers=saved['publication_blockers'])


def pack_all(root, revision, output):
    output = Path(output).absolute()
    write_fresh(output, {})
    rows = []
    for name in profiles():
        try:
            rows.append(pack(root, name, revision, output / name))
        except (s.Error, OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
            rows.append(dict(package=dict(name=name), status='INPUT_REFUSED', error=str(error)))
    result = dict(status='EXPORTED_ALL_FINITE_INPUTS' if all(r['status'] != 'INPUT_REFUSED' for r in rows)
                  else 'PARTIAL_INPUT_EXPORT', packages=rows, legal_acceptance=False,
                  complete_corresponding_source_accepted=False, publication='NOT_RUN')
    # An owned fresh directory; never replace an existing report or package.
    fd = s.directory(output)
    try:
        leaf = os.open('report.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(leaf, 'wb') as stream:
            stream.write(encoded(result))
    finally:
        os.close(fd)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for operation in ('pack', 'pack-all'):
        build = commands.add_parser(operation)
        build.add_argument('--root', type=Path, required=True)
        build.add_argument('--source-revision', required=True)
        build.add_argument('--output', type=Path, required=True)
        if operation == 'pack':
            build.add_argument('--package', choices=profiles(), required=True)
            build.add_argument('--archive', type=Path)
    for operation in ('verify', 'unpack'):
        check = commands.add_parser(operation)
        check.add_argument('--bundle', type=Path, required=True)
        check.add_argument('--sha256', required=True)
        check.add_argument('--archive', type=Path, help='recheck saved static binding against this actual archive')
        if operation == 'unpack':
            check.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'pack':
        result = pack(args.root, args.package, args.source_revision, args.output, args.archive)
    elif args.command == 'pack-all':
        result = pack_all(args.root, args.source_revision, args.output)
    else:
        saved, bodies = verified(s.read_file(args.bundle, MAX_TOTAL), args.sha256, args.archive)
        if args.command == 'unpack':
            write_fresh(args.output, dict(bodies, **{'bundle.json': encoded(saved),
                'source-map.json': encoded({k: s.digest(v) for k, v in sorted(bodies.items())})}))
        result = dict(status='VERIFIED_FINITE_INPUTS', package=saved['package'],
                      publication_blockers=saved['publication_blockers'], code_executed=False,
                      archive_binding_rechecked=args.archive is not None,
                      legal_acceptance=False, complete_corresponding_source_accepted=False)
    print(json.dumps(result, sort_keys=True))
    return int(result['status'] == 'PARTIAL_INPUT_EXPORT')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (s.Error, OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print('platform/audio source delivery refused: ' + str(error), file=sys.stderr)
        sys.exit(2)
