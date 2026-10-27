#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Offline source bundles for two reviewed original recipes; never execute/install.

The existing source_delivery transport remains authoritative for release joins.
An observed revision labels a checkout, while reviewed file hashes bind inputs.
Archive metadata correspondence does not establish native execution or acceptance.
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

sys.dont_write_bytecode = True


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


HERE = Path(__file__).absolute().parent
s = module('recipe_source_transport', HERE / 'source_delivery.py')
MAX_FILE, MAX_TOTAL, MAX_FILES = 1024**2, 8 * 1024**2, 64
PROFILES = {
    'cachy-asahi-maintenance': {
        'version': '0.1.0-1',
        'recipe': '2d4b50ac1bc3c4c934d9b53ee0a386e4c9553470e4b36b3eb7a11abbd7f48296',
        'srcinfo': '4b162f9f54baf9c804f11a8591bd75a8f4a445f2b557805415e077f39a97d9c4',
        'checker': 'check_source.py',
        'tests': ['test_package.py'],
        'docs': ['README.md', 'health-inputs.md', 'source-provenance.json', 'payload-pins.json'],
    },
    'cachy-asahi-session-diagnostics': {
        'version': '0.1.0-2',
        'recipe': '13e4f092bec2ea7ff525319e3462db1e1e0fc42591dae307e900d7c5486f14d5',
        'srcinfo': 'f716264b09b28fef7a7fb3dee3c30aa1f9dc5e425809e8492b8d99796fd6e2ce',
        'checker': 'check_package.py',
        'tests': ['test_session_probe.py', 'test_package.py'],
        'docs': ['README.md', 'session-probe.md', 'source-provenance.json'],
    },
}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def profile(name):
    s.need(name in PROFILES, 'recipe is outside the reviewed original-project set')
    return PROFILES[name]


def metadata(raw):
    result = {}
    for line in raw.decode('utf-8').splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            match = re.fullmatch(r'\s*([A-Za-z0-9_]+) = (.+)', line)
            s.need(match is not None, 'literal SRCINFO required')
            key, value = match.groups()
            result.setdefault(key, []).append(value)
    return result


def source_set(name, read):
    p = profile(name)
    bodies = {key: read(key) for key in ('PKGBUILD', '.SRCINFO')}
    s.need(s.digest(bodies['PKGBUILD']) == p['recipe'] and
           s.digest(bodies['.SRCINFO']) == p['srcinfo'], 'reviewed recipe/SRCINFO changed')
    info = metadata(bodies['.SRCINFO'])
    sources, pins = info['source'], info['sha256sums']
    s.need(len(sources) == len(pins) == len(set(sources)) <= MAX_FILES - 2, 'source count/duplicates')
    for name, pin in zip(sources, pins):
        s.need(len(s.relative(name)) == 1 and name not in bodies and name != 'bundle.json',
               'flat local recipe inputs required')
        s.sha(pin)
        raw = read(name)
        s.need(0 < len(raw) <= MAX_FILE and s.digest(raw) == pin, 'recipe source checksum mismatch: ' + name)
        bodies[name] = raw
    s.need(sum(map(len, bodies.values())) <= MAX_TOTAL, 'source total bound')
    s.need({'NOTICE', 'LICENSE', 'source-provenance.json'} <= bodies.keys(), 'original notices/provenance required')
    return bodies, info


def payload(name):
    result = {'usr/bin/' + name: (name, 0o755)}
    if name == 'cachy-asahi-maintenance':
        for folder, names in {
            'maintenance': ('health', 'update_plan', 'rebuild_plan', 'signing_expiry', 'security_advisories'),
            'release': ('check_source_pins', 'compare_releases', 'release', 'source_delivery'),
        }.items():
            for leaf in names:
                result[f'usr/lib/cachy-asahi/maintenance/scripts/{folder}/{leaf}.py'] = (leaf + '.py', 0o644)
    else:
        result['usr/lib/' + name + '/session_probe.py'] = ('session_probe.py', 0o644)
    result.update({'usr/share/doc/' + name + '/' + leaf: (leaf, 0o644) for leaf in profile(name)['docs']})
    result.update({'usr/share/licenses/' + name + '/' + leaf: (leaf, 0o644) for leaf in ('NOTICE', 'LICENSE')})
    return result


def binding_check(binding):
    if binding is None:
        return
    s.fields(binding, ('status', 'archive_sha256', 'archive_bytes', 'pkgbuild_sha256', 'metadata_sha256', 'native_execution'))
    s.need(binding['status'] == 'ARCHIVE_METADATA_AND_PAYLOAD_BOUND' and binding['native_execution'] == 'NOT_ESTABLISHED',
           'archive binding status')
    for key in ('archive_sha256', 'pkgbuild_sha256', 'metadata_sha256'):
        s.sha(binding[key])
    s.need(type(binding['archive_bytes']) is int and 0 < binding['archive_bytes'] <= MAX_TOTAL, 'archive size bound')


def bind_archive(path, name, bodies, info):
    # Reuse the existing read-only package inspector, operating on a private
    # byte snapshot so metadata and the hash cannot name different archives.
    import tempfile
    c = module('recipe_source_package_checks', HERE.parent / 'checks/package_checks.py')
    raw = s.read_file(path, MAX_TOTAL)
    with tempfile.TemporaryDirectory(prefix='recipe-source-archive-') as directory:
        snapshot = Path(directory) / ('archive.pkg.tar.zst' if str(path).endswith('.zst') else 'archive.pkg.tar')
        snapshot.write_bytes(raw)
        report = c.package(snapshot)
    s.need(not report['errors'] and not report['review'], 'package archive inspection refused')
    pkg, build = report['metadata']['.PKGINFO'], report['metadata']['.BUILDINFO']
    expected = {'pkgname': [name], 'pkgbase': [name], 'pkgver': [profile(name)['version']],
                'arch': ['any'], 'license': ['MIT']}
    for src, dest in (('depends', 'depend'), ('optdepends', 'optdepend'), ('makedepends', 'makedepend'),
                      ('checkdepends', 'checkdepend'), ('provides', 'provides'), ('conflicts', 'conflict'),
                      ('replaces', 'replaces'), ('backup', 'backup')):
        expected[dest] = info.get(src, [])
    s.need(all(sorted(pkg.get(k, [])) == sorted(v) for k, v in expected.items()), 'package archive identity/dependencies mismatch')
    s.need(build.get('pkgbuild_sha256sum') == [profile(name)['recipe']], 'archive BUILDINFO PKGBUILD mismatch')
    members = report['members']
    wanted = payload(name)
    files = {k for k, v in members.items() if v['type'] != '5'}
    s.need(files == set(wanted) | {'.PKGINFO', '.BUILDINFO', '.MTREE'}, 'archive payload set mismatch')
    s.need(all(members[key]['type'] == '0' and members[key]['mode'] == 0o644
               for key in ('.PKGINFO', '.BUILDINFO', '.MTREE')), 'archive metadata type/mode mismatch')
    dirs = {str(parent) for key in wanted for parent in Path(key).parents if str(parent) != '.'}
    s.need(all(k in dirs and v['mode'] == 0o755 for k, v in members.items() if v['type'] == '5'),
           'archive foreign directory/mode')
    for key, (source, mode) in wanted.items():
        row = members[key]
        s.need(row['type'] == '0' and row['mode'] == mode and row['size'] == len(bodies[source]) and
               row['sha256'] == s.digest(bodies[source]), 'archive payload bytes/mode mismatch: ' + key)
    return dict(status='ARCHIVE_METADATA_AND_PAYLOAD_BOUND', archive_sha256=s.digest(raw), archive_bytes=len(raw),
                pkgbuild_sha256=profile(name)['recipe'], metadata_sha256=s.digest(encoded(report['metadata'])),
                native_execution='NOT_ESTABLISHED')


def manifest(name, bodies, info, revision, binding):
    s.need(type(revision) is str and re.fullmatch('[0-9a-f]{40}', revision), 'full observed source revision required')
    binding_check(binding)
    if binding:
        s.need(binding['pkgbuild_sha256'] == profile(name)['recipe'], 'binding recipe mismatch')
    p = profile(name)
    return dict(schema_version=1, purpose='reviewed-original-recipe-source',
                package=dict(name=name, version=p['version'], arch='any'), license='MIT',
                observed_source_revision=revision, revision_is_not_source_authority=True,
                recipe_sha256=p['recipe'], recipe_key='PKGBUILD', source_order=info['source'],
                files={k: dict(sha256=s.digest(v), bytes=len(v), mode='0644') for k, v in sorted(bodies.items())},
                dependencies={k: info.get(k, []) for k in ('depends', 'makedepends', 'checkdepends', 'optdepends')},
                archive_binding=binding, archive_status='BOUND' if binding else 'UNBOUND_NO_ARCHIVE_SUPPLIED',
                rebuild_commands=['makepkg --verifysource', 'makepkg --cleanbuild --force'],
                rebuild_environment='Separately provisioned native aarch64 build environment with declared dependencies; no automatic dependency installation.',
                host_check_commands=[['python', '-I', '-B', p['checker'], '--recipe-root', '.']] +
                                    [['python', '-I', '-B', '-Werror::ResourceWarning', test] for test in p['tests']],
                stage_command='umask 022; source "$1/PKGBUILD"; srcdir=$1; pkgdir=$2; package',
                stage_is_not_installation=True, native_build='NOT_RUN', alpm_installation='NOT_RUN',
                physical_m2='NOT_RUN', release='NOT_ADMITTED', legal_acceptance=False)


def tar_bytes(bodies):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for key, raw in sorted(bodies.items()):
            member = tarfile.TarInfo(key)
            member.size, member.mode = len(raw), 0o644
            member.mtime, member.uid, member.gid = 0, 0, 0
            archive.addfile(member, io.BytesIO(raw))
    return output.getvalue()


def unpacked(raw, checksum):
    s.sha(checksum)
    s.need(len(raw) <= MAX_TOTAL and s.digest(raw) == checksum, 'bundle checksum/bound mismatch')
    bodies = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            key = member.name
            s.need(len(s.relative(key)) == 1 and key not in bodies and member.isfile() and
                   0 < member.size <= MAX_FILE and len(bodies) < MAX_FILES, 'unsafe/duplicate bundle member')
            bodies[key] = archive.extractfile(member).read()
            s.need(sum(map(len, bodies.values())) <= MAX_TOTAL, 'bundle expanded bound')
    s.need('bundle.json' in bodies, 'bundle manifest missing')
    saved = s.decode(bodies.pop('bundle.json'))
    s.need(type(saved.get('package')) is dict, 'bundle package object required')
    name = saved['package'].get('name')
    exact, info = source_set(name, lambda key: bodies[key])
    s.need(exact == bodies, 'bundle source coverage mismatch')
    expected = manifest(name, exact, info, saved.get('observed_source_revision'), saved.get('archive_binding'))
    s.need(saved == expected, 'bundle manifest mismatch')
    s.need(tar_bytes(dict(bodies, **{'bundle.json': encoded(expected)})) == raw, 'noncanonical/tampered source tar')
    return saved, bodies


def write_fresh(output, bodies):
    output = Path(output).absolute()
    parent = s.directory(output.parent)
    fd = None
    try:
        os.mkdir(output.name, 0o700, dir_fd=parent)
        created = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        opened = os.fstat(fd)
        s.need((created.st_dev, created.st_ino) == (opened.st_dev, opened.st_ino), 'output directory replaced')
        for key, raw in sorted(bodies.items()):
            s.need(len(s.relative(key)) == 1, 'flat output required')
            leaf = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(leaf, 'wb') as stream:
                stream.write(raw)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def pack(recipe, name, revision, output, archive=None, review=None, review_status=None, synthetic=False):
    s.need(type(synthetic) is bool, 'synthetic label required')
    recipe = Path(recipe).absolute()
    bodies, info = source_set(name, lambda key: s.local_read(recipe, key, MAX_FILE))
    bound = bind_archive(archive, name, bodies, info) if archive else None
    saved = manifest(name, bodies, info, revision, bound)
    material = dict(bodies, **{'bundle.json': encoded(saved)})
    raw = tar_bytes(material)
    unpacked(raw, s.digest(raw))
    output_bodies = {'source.tar': raw, 'bundle.json': encoded(saved),
                     'source-map.json': encoded({k: s.digest(v) for k, v in sorted(bodies.items())}),
                     **{k: bodies[k] for k in ('PKGBUILD', 'NOTICE', 'LICENSE')}}
    if review is not None or review_status is not None:
        s.need(bound is not None and review is not None and review_status is not None,
               'release association requires actual matching archive and existing review/status')
        output_bodies['existing-review'] = s.read_file(review, MAX_FILE)
        def descriptor(key):
            return dict(id=name + '-' + key, path=key, sha256=s.digest(output_bodies[key]), bytes=len(output_bodies[key]))
        record = dict(package=dict(saved['package'], sha256=bound['archive_sha256']),
                      bundle=descriptor('source.tar'), source_map=descriptor('source-map.json'),
                      recipe=descriptor('PKGBUILD'), recipe_key='PKGBUILD',
                      notices=[descriptor(k) for k in ('NOTICE', 'LICENSE')],
                      authorization=descriptor('existing-review'), review_status=review_status)
        s.record_check(record, lambda eid, limit: output_bodies[eid[len(name) + 1:]],
                       {'recipe_sha256': saved['recipe_sha256']})
        output_bodies['source-delivery.json'] = encoded(dict(schema_version=1, purpose='release-source-delivery',
                                                            synthetic=synthetic, packages=[record]))
    write_fresh(output, output_bodies)
    return dict(status='PACKED_SOURCE_ONLY', package=saved['package'], bundle_sha256=s.digest(raw),
                bundle_bytes=len(raw), archive_status=saved['archive_status'],
                release_index='source-delivery.json' if 'source-delivery.json' in output_bodies else None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('pack')
    build.add_argument('--recipe', type=Path, required=True)
    build.add_argument('--package', choices=PROFILES, required=True)
    build.add_argument('--source-revision', required=True)
    build.add_argument('--output', type=Path, required=True)
    build.add_argument('--archive', type=Path)
    build.add_argument('--review', type=Path)
    build.add_argument('--review-status')
    build.add_argument('--synthetic', action='store_true', help='label a synthetic archive/release association explicitly')
    verify = commands.add_parser('unpack')
    verify.add_argument('--bundle', type=Path, required=True)
    verify.add_argument('--sha256', required=True)
    verify.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'pack':
        result = pack(args.recipe, args.package, args.source_revision, args.output,
                      args.archive, args.review, args.review_status, args.synthetic)
    else:
        saved, bodies = unpacked(s.read_file(args.bundle, MAX_TOTAL), args.sha256)
        write_fresh(args.output, bodies)
        result = dict(status='UNPACKED_REVIEWED_SOURCE', package=saved['package'],
                      archive_status=saved['archive_status'], code_executed=False)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (s.Error, OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print('recipe source delivery refused: ' + str(error), file=sys.stderr)
        sys.exit(2)
