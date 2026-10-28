#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Materialize authenticated retained mirror inputs for build_v2; never build.

Only trusted installed helpers are imported. Every mirrored recipe, package and
Python source remains inert data. Actual native selectors are deliberately NULL.
"""
import argparse
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent


def file_mode(path):
    return 0o600 if path.startswith('retained/cache/') else 0o400


def dependencies(directory=HERE):
    directory = Path(directory)
    import importlib.util
    def module(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
        return result
    sbom = module('consumer_sbom', directory.parent / 'release/release_sbom.py')
    shared = sbom.dependencies(directory.parent / 'release')
    return dict(mirror=module('consumer_mirror', directory.parent / 'release/release_source_mirror.py'),
        recipe=shared[1], sbom=sbom, shared=shared,
        materials=module('consumer_materials', directory / 'source_materials.py'),
        build=module('consumer_build', directory / 'build_v2.py'))


def write_tree(output, bodies, directories, s):
    """Exclusive private fd-relative writes; source bytes never executable."""
    output = Path(output).absolute()
    s.need(output.anchor == '/' and '..' not in output.parts, 'output path alias refused')
    dirs = set(directories)
    dirs.update(str(p) for key in list(dirs) for p in Path(key).parents if str(p) != '.')
    for key in bodies:
        s.relative(key)
        dirs.update(str(p) for p in Path(key).parents if str(p) != '.')
    for key in dirs:
        s.relative(key)
    s.need(len(dirs) <= 16384, 'context directory count bound')
    s.need(not dirs.intersection(bodies), 'context file/directory collision')
    s.need(len(bodies) <= 16384 and sum(map(len, bodies.values())) <= 512 * 1024**2, 'context aggregate bound')
    parent = s.directory(output.parent); root = None
    try:
        parent_info = os.fstat(parent)
        s.need(parent_info.st_uid == os.getuid() and not stat.S_IMODE(parent_info.st_mode) & 0o022,
               'owned non-writable-by-others output parent required')
        os.mkdir(output.name, 0o700, dir_fd=parent)
        created = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        root = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        identity = os.fstat(root)
        s.need(identity.st_uid == os.getuid() and stat.S_IMODE(identity.st_mode) == 0o700 and
            (identity.st_dev, identity.st_ino) == (created.st_dev, created.st_ino), 'private owned output root required')
        def held(parts):
            fd = os.dup(root)
            try:
                for part in parts:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd); fd = child
                return fd
            except BaseException:
                os.close(fd); raise
        for key in sorted(dirs, key=lambda p: (len(Path(p).parts), p)):
            parts = s.relative(key); fd = held(parts[:-1])
            try:
                os.mkdir(parts[-1], 0o700, dir_fd=fd)
            finally:
                os.close(fd)
        for key, raw in sorted(bodies.items()):
            parts = s.relative(key); fd = held(parts[:-1])
            try:
                leaf = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                with os.fdopen(leaf, 'wb') as stream:
                    stream.write(raw); os.fchmod(stream.fileno(), file_mode(key))
            finally:
                os.close(fd)
        current = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        s.need((current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino), 'context directory replaced')
    finally:
        if root is not None:
            os.close(root)
        os.close(parent)


def validate(bodies, directories, package, recipe_hash, deps):
    """Static checks and source_materials staging in an owned temporary tree."""
    s = deps['shared'][0]; m = deps['mirror']; b = deps['build']; sm = deps['materials']
    with tempfile.TemporaryDirectory(prefix='mirror-consumer-') as tmp:
        root = Path(tmp) / 'context'; write_tree(root, bodies, directories, s)
        report = b.recipe(root / 'recipe/PKGBUILD')
        s.need(not report['errors'], 'static recipe refused: ' + '; '.join(report['errors']))
        info = report['metadata']
        s.need(info.get('pkgname') == [package['name']] and info.get('arch') == [package['arch']] and
            len(info.get('pkgver', [])) == len(info.get('pkgrel', [])) == 1 and
            info['pkgver'][0] + '-' + info['pkgrel'][0] == package['version'] and
            info.get('epoch', ['0']) == ['0'], 'static recipe package identity mismatch')
        expected = s.decode(bodies['reviewed-inputs.json'])
        s.need(report['input_sha256'] == expected and expected.get('PKGBUILD') == recipe_hash,
               'reviewed recipe input map mismatch')
        archive = deps['sbom'].tar_entries(bodies['evidence/retained-package.pkg.tar'], s, deps['shared'][2])
        raw = archive['.BUILDINFO']['raw']; buildinfo = deps['sbom'].metadata(raw, s)
        pkginfo = deps['sbom'].metadata(archive['.PKGINFO']['raw'], s)
        s.need(all(pkginfo.get(key) == [package[field]] for key, field in
            (('pkgname', 'name'), ('pkgver', 'version'), ('arch', 'arch'))), 'retained PKGINFO identity mismatch')
        provenance = s.decode(bodies['evidence/provenance.json'])
        notices = {m.digest(body) for key, body in bodies.items() if key.startswith('evidence/notices/')}
        s.need(m.digest(bodies['evidence/retained-package.pkg.tar']) == package['sha256'] and
            provenance.get('artifact_sha256') == package['sha256'] and provenance.get('recipe_sha256') == recipe_hash and
            provenance.get('package') == {key: package[key] for key in ('name', 'version', 'arch')} and
            any(node.get('sha256') in notices for key, node in archive.items() if key.startswith('usr/share/licenses/')),
            'retained archive/provenance/license mismatch')
        s.need(raw == bodies['evidence/BUILDINFO'] and buildinfo.get('format') == ['2'] and
            buildinfo.get('pkgbuild_sha256sum') == [recipe_hash] and buildinfo.get('installed') and
            all(buildinfo.get(key) == [package[field]] for key, field in
                (('pkgname', 'name'), ('pkgver', 'version'), ('pkgarch', 'arch'))), 'retained BUILDINFO identity mismatch')
        extras = {}
        if 'retained/source-plan.json' in bodies:
            prepared = sm.prepare(report, root / 'retained/source-plan.json', m.digest(bodies['retained/source-plan.json']),
                root / 'retained/catalog/source-catalog.json', root / 'retained/cache')
            sm.stage(prepared, root / 'source-material')
            for path in sorted((root / 'source-material').rglob('*')):
                if path.is_file():
                    key = str(path.relative_to(root)); extras[key] = s.local_read(root, key, m.MAX_OBJECT)
        else:
            s.need(not any('://' in source for source in info.get('source', []) + info.get('source_aarch64', [])),
                   'remote recipe requires retained source plan')
        return report, extras


def native_argv(bodies, m):
    argv = ['python3', '-I', '-B', '${TRUSTED_REPO}/scripts/build/build_v2.py', 'recipe', '--image', None,
        '--mode', 'native', '--network', 'none', '--source-date-epoch', None, '--expected-packages', None,
        '--reviewed-inputs', 'reviewed-inputs.json', '--output', None]
    if 'retained/source-plan.json' in bodies:
        argv += ['--source-plan', 'retained/source-plan.json', '--source-plan-sha256', m.digest(bodies['retained/source-plan.json']),
            '--source-catalog', 'retained/catalog/source-catalog.json', '--source-cache', 'retained/cache']
    return argv


def prepare(raw, mirror_sha256, release_sha256, package, version, arch, package_sha256,
            recipe_sha256, srcinfo_sha256, deps):
    m = deps['mirror']; s = deps['shared'][0]
    for pin in (mirror_sha256, release_sha256, package_sha256, recipe_sha256, srcinfo_sha256):
        s.sha(pin)
    s.name(package)
    getattr(m, 'verify_any', m.verify)(raw, mirror_sha256, release_sha256)
    # Only after verifier proof: parse inert members; never load archived Python.
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        files = {node.name: archive.extractfile(node).read() for node in archive}
    def get(ref):
        body = files['objects/' + ref['sha256']]
        s.need((len(body), m.digest(body)) == (ref['bytes'], ref['sha256']), 'selected object mismatch')
        return body
    if 'mirror.json' in files:
        manifest = s.decode(files['mirror.json'])
    else:
        rows = [row for row in s.decode(files['history.json'])['releases'] if row['release_sha256'] == release_sha256]
        s.need(len(rows) == 1, 'exact retained release required')
        manifest = s.decode(get(rows[0]['manifest']))
    identity = dict(name=package, version=version, arch=arch, sha256=package_sha256)
    s.identity(identity)
    rows = [row for row in manifest['packages'] if row['package'] == identity]
    s.need(len(rows) == 1 and manifest['release_sha256'] == release_sha256, 'exact retained package required')
    row = rows[0]; record = row['source_delivery']
    source = {key: get(ref) for key, ref in row['source_files'].items()}
    s.need(m.digest(source['PKGBUILD']) == recipe_sha256 == row['recipe_sha256'] and
        m.digest(source['.SRCINFO']) == srcinfo_sha256, 'exact PKGBUILD/SRCINFO pair required')
    if row['profile'] == 'REVIEWED_ORIGINAL_RECIPE_PROFILE':
        bundle = get(manifest['files']['evidence/' + record['bundle']['id']])
        saved, exact = deps['recipe'].unpacked(bundle, m.digest(bundle))
        s.need(saved['package'] == {key: identity[key] for key in ('name', 'version', 'arch')}, 'reviewed profile identity mismatch')
        source = exact
    bodies = {'recipe/' + key: body for key, body in source.items()}
    bodies['reviewed-inputs.json'] = m.encoded({key: m.digest(body) for key, body in sorted(source.items())})
    bodies['evidence/retained-package.pkg.tar'] = get(manifest['files'][row['archive']['path']])
    bodies['evidence/provenance.json'] = get(manifest['files'][row['provenance']['path']])
    bodies['evidence/source-map.json'] = get(manifest['files']['evidence/' + record['source_map']['id']])
    nodes = deps['sbom'].tar_entries(bodies['evidence/retained-package.pkg.tar'], s, deps['shared'][2])
    bodies['evidence/BUILDINFO'] = nodes['.BUILDINFO']['raw']
    for notice in record['notices']:
        body = get(manifest['files']['evidence/' + notice['id']])
        s.need(body in source.values(), 'source notice missing from recipe inputs')
        bodies['evidence/notices/' + s.name(notice['id'])] = body
    directories = {'recipe'}
    if row['remote_sources']:
        sm = deps['materials']; cache = sm.cache
        bodies['retained/source-plan.json'] = get(row['plan'])
        bodies['retained/catalog/source-catalog.json'] = get(row['catalog'])
        bodies['retained/cache/FORMAT'] = cache.MARKER
        directories.update(('retained/cache/objects', 'retained/cache/receipts', 'retained/cache/.partial'))
        for remote in row['remote_sources']:
            material = remote['record']['material']
            bodies['retained/cache/objects/' + material['sha256']] = get(remote['object'])
            key = row['catalog']['sha256'] + '-' + material['id'] + '.json'
            bodies['retained/cache/receipts/' + key] = get(remote['receipt'])
            for notice in remote['record']['license_evidence']:
                path = 'retained/catalog/' + notice['path']; body = get(row['remote_notices'][notice['sha256']])
                s.need(path not in bodies or bodies[path] == body, 'retained notice path collision')
                bodies[path] = body
    report, staged = validate(bodies, directories, identity, recipe_sha256, deps)
    bodies.update(staged)
    if not row['remote_sources']:
        directories.add('source-material/srcdest')
    actual = dict(builder_image=None, expected_packages_lock=None, expected_packages_sha256=None,
        source_date_epoch=None, output=None, native_host_binding=None, native_build_record=None)
    request = dict(schema_version=1, purpose='mirror-native-build-request', status='HELD_ACTUAL_SELECTORS_NULL',
        argv_template=native_argv(bodies, m), working_directory='materialized-context', actual_selectors=actual,
        input_identity=identity, recipe_sha256=recipe_sha256, srcinfo_sha256=srcinfo_sha256,
        container_makepkg_commands=['makepkg --printsrcinfo', 'makepkg --verifysource --noconfirm',
            'LOGDEST=/out makepkg --cleanbuild --clean --force --log --noconfirm'],
        build_tool_sha256=m.digest(s.read_file(Path(deps['build'].__file__))),
        entry_script_sha256=m.digest(s.read_file(Path(deps['build'].__file__).with_name('container-entry-v2.sh'))),
        actual_archive_sha256=None, actual_archive_bytes=None, actual_buildinfo_sha256=None,
        native_build='NOT_RUN', installation='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')
    bodies['builder-request.json'] = m.encoded(request)
    selection = dict(schema_version=1, purpose='mirror-builder-context', mirror_sha256=mirror_sha256,
        release_sha256=release_sha256, package=identity, profile=row['profile'], recipe_sha256=recipe_sha256,
        srcinfo_sha256=srcinfo_sha256, buildinfo_sha256=m.digest(bodies['evidence/BUILDINFO']),
        recipe_inputs=report['input_sha256'], source_map_sha256=m.digest(bodies['evidence/source-map.json']),
        notice_paths=sorted(key for key in bodies if key.startswith('evidence/notices/')),
        remote_sources=bool(row['remote_sources']), static_review=report['review'],
        legal_acceptance=False, corresponding_source_completeness='NOT_ASSERTED', native_build='NOT_RUN',
        installation='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')
    return dict(bodies=bodies, directories=sorted(directories), selection=selection, native_request=request)


def materialize(prepared, output, deps):
    m = deps['mirror']; s = deps['shared'][0]
    bodies = dict(prepared['bodies']); selection = dict(prepared['selection'])
    selection['files'] = {key: dict(sha256=m.digest(raw), bytes=len(raw), mode=f'{file_mode(key):04o}') for key, raw in sorted(bodies.items())}
    dirs = set(prepared['directories'])
    dirs.update(str(p) for key in list(dirs) for p in Path(key).parents if str(p) != '.')
    dirs.update(str(p) for key in bodies for p in Path(key).parents if str(p) != '.')
    selection['directories'] = sorted(dirs)
    raw = m.encoded(selection); bodies['selection.json'] = raw
    s.need(len(raw) <= s.MAX_JSON and all(len(body) <= m.MAX_OBJECT for body in bodies.values()), 'context metadata/object byte bound')
    write_tree(output, bodies, dirs, s)
    return dict(status='MATERIALIZED_MIRROR_BUILDER_CONTEXT', selection_sha256=m.digest(raw),
        mirror_sha256=selection['mirror_sha256'], release_sha256=selection['release_sha256'], package=selection['package'],
        native_build='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')


def verify_context(context, selection_sha256, deps):
    m = deps['mirror']; s = deps['shared'][0]; context = Path(context).absolute()
    s.need(context.anchor == '/' and '..' not in context.parts, 'context path alias refused')
    raw = s.local_read(context, 'selection.json', s.MAX_JSON)
    s.need(m.digest(raw) == s.sha(selection_sha256), 'context selection checksum mismatch')
    selection = s.decode(raw)
    s.need(selection.get('purpose') == 'mirror-builder-context' and selection.get('schema_version') == 1,
           'context selection schema')
    s.need(selection['legal_acceptance'] is False and selection['corresponding_source_completeness'] == 'NOT_ASSERTED' and
        all(selection[key] == 'NOT_RUN' for key in ('native_build', 'installation', 'hardware')) and
        selection['release'] == 'NOT_ADMITTED', 'context evidence boundary changed')
    bodies = {}
    for key, ref in selection['files'].items():
        s.need(ref['mode'] == f'{file_mode(key):04o}', 'context file mode declaration mismatch')
        body = s.local_read(context, key, m.MAX_OBJECT)
        s.need((len(body), m.digest(body)) == (ref['bytes'], ref['sha256']), 'context file checksum mismatch: ' + key)
        bodies[key] = body
    # Walk by directory descriptors; never follow live context symlinks.
    found_files, found_dirs = set(), set()
    def walk(fd, prefix=''):
        info = os.fstat(fd)
        s.need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'private owned context directory required')
        for leaf in os.listdir(fd):
            key = prefix + leaf; info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                found_dirs.add(key)
                child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    walk(child, key + '/')
                finally:
                    os.close(child)
            else:
                s.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and
                    stat.S_IMODE(info.st_mode) == file_mode(key), 'unsafe context file')
                found_files.add(key)
            s.need(len(found_files) <= 16385 and len(found_dirs) <= 16384, 'context inventory count bound')
    fd = s.directory(context)
    try:
        walk(fd)
    finally:
        os.close(fd)
    s.need(found_files == set(bodies) | {'selection.json'} and found_dirs == set(selection['directories']), 'context inventory differs')
    s.need(m.digest(bodies['recipe/PKGBUILD']) == selection['recipe_sha256'] and
        m.digest(bodies['recipe/.SRCINFO']) == selection['srcinfo_sha256'] and
        m.digest(bodies['evidence/retained-package.pkg.tar']) == selection['package']['sha256'] and
        m.digest(bodies['evidence/BUILDINFO']) == selection['buildinfo_sha256'], 'context identity mismatch')
    source_map = s.decode(bodies['evidence/source-map.json'])
    s.need(m.digest(bodies['evidence/source-map.json']) == selection['source_map_sha256'] and
        s.decode(bodies['reviewed-inputs.json']) == selection['recipe_inputs'], 'context source metadata mismatch')
    s.need(all(m.digest(bodies['recipe/' + key]) == value for key, value in source_map.items()), 'context source map mismatch')
    recipe_bodies = {key[7:]: body for key, body in bodies.items() if key.startswith('recipe/')}
    s.need(set(recipe_bodies) == set(source_map) | ({'bundle.json'} if 'bundle.json' in recipe_bodies else set()),
           'context source map coverage mismatch')
    if selection['profile'] == 'REVIEWED_ORIGINAL_RECIPE_PROFILE':
        exact, _ = deps['recipe'].source_set(selection['package']['name'], lambda key: recipe_bodies[key])
        s.need(exact == recipe_bodies, 'context reviewed profile inputs differ')
    s.need(all(bodies[key] in recipe_bodies.values() for key in selection['notice_paths']), 'context source notices differ')
    base = {key: body for key, body in bodies.items() if not key.startswith('source-material/')}
    dirs = [key for key in selection['directories'] if not key.startswith('source-material')]
    _, staged = validate(base, dirs, selection['package'], selection['recipe_sha256'], deps)
    s.need(staged == {key: body for key, body in bodies.items() if key.startswith('source-material/')}, 'context SRCDEST differs')
    request = s.decode(bodies['builder-request.json'])
    s.need(request['input_identity'] == selection['package'] and request['recipe_sha256'] == selection['recipe_sha256'] and
        request['srcinfo_sha256'] == selection['srcinfo_sha256'], 'native request input identity differs')
    s.need(set(request['actual_selectors']) == {'builder_image', 'expected_packages_lock', 'expected_packages_sha256',
        'source_date_epoch', 'output', 'native_host_binding', 'native_build_record'} and
        all(value is None for value in request['actual_selectors'].values()) and
        request['status'] == 'HELD_ACTUAL_SELECTORS_NULL' and
        request['argv_template'] == native_argv(bodies, m) and
        request['actual_archive_sha256'] is request['actual_archive_bytes'] is request['actual_buildinfo_sha256'] is None,
        'actual native selectors must remain NULL')
    s.need(request['build_tool_sha256'] == m.digest(s.read_file(Path(deps['build'].__file__))) and
        request['entry_script_sha256'] == m.digest(s.read_file(Path(deps['build'].__file__).with_name('container-entry-v2.sh'))),
        'trusted builder helper bytes differ')
    return dict(status='VERIFIED_MIRROR_BUILDER_CONTEXT', selection_sha256=selection_sha256,
        package=selection['package'], native_build='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('materialize')
    create.add_argument('--bundle', type=Path, required=True)
    create.add_argument('--mirror-sha256', required=True)
    create.add_argument('--release-sha256', required=True)
    create.add_argument('--package', required=True); create.add_argument('--version', required=True)
    create.add_argument('--arch', choices=('any', 'aarch64'), required=True)
    create.add_argument('--package-sha256', required=True); create.add_argument('--recipe-sha256', required=True)
    create.add_argument('--srcinfo-sha256', required=True); create.add_argument('--output', type=Path, required=True)
    check = commands.add_parser('verify-context')
    check.add_argument('--context', type=Path, required=True); check.add_argument('--selection-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        deps = dependencies()
        if args.command == 'verify-context':
            result = verify_context(args.context, args.selection_sha256, deps)
        else:
            prepared = prepare(deps['mirror'].read_file(args.bundle), args.mirror_sha256, args.release_sha256,
                args.package, args.version, args.arch, args.package_sha256, args.recipe_sha256, args.srcinfo_sha256, deps)
            result = materialize(prepared, args.output, deps)
        print(json.dumps(result, sort_keys=True)); return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, tarfile.TarError, EOFError, RecursionError) as error:
        print(json.dumps(dict(status='REFUSED', reason=str(error)), sort_keys=True)); return 1


if __name__ == '__main__':
    raise SystemExit(main())
