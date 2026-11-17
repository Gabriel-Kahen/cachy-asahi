# SPDX-License-Identifier: MIT
"""Closed protected349 + Qt3 selection DATA; no acquisition or authority."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
NATIVE = 'scripts/ci/first-login-enrollment-native-source/payload/native/'
HELD = {
    'base_inputs_current_v3.py': (18820, '9e35c3ae6c3e1e9596f54806279d05cc77ae6a2cb5fb284d469df549e1d3abc6'),
    'inputs_current_v3.py': (45247, 'ddc4f0da13c4e9d7ab58f2c3fe318343082f320dae105e069336ecb24c4c49cb'),
    'image_current_v3.py': (55783, 'f4e590532d7f6115f830215810f9dee5f2a1eb714351a9a7e572d22c5a255f90'),
}
LOCKS = {
    'scripts/port/arm-rust-toolchain-inputs/inputs.lock.json': (334371, 'a69001b6e4b2426ed12fd17a548a1a3f7a07e491b48c5c62ea48f8832355b5f9'),
    'scripts/port/arm-rust-toolchain-inputs/qtbase-successor/candidate.lock.json': (88821, 'b9053079a1c2f6dab8cee3b782d8ebbedae5865c6f9fad74de85357fec2d07a7'),
}
REQUEST_KEYS = {'base_lock', 'bootstrap_profile', 'baseline_inventory', 'base_materials',
                'supplemental_materials', 'keyring_materials', 'candidate_materials',
                'catalog', 'official_trust'}


def need(value, code):
    if not value:
        raise ValueError(code)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def read_code(path, expected):
    path = Path(path)
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'HELD_HELPER_ALIAS')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size == expected['bytes'] <= 128 * 1024, 'HELD_HELPER_FILE_BOUND')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            body = stream.read(expected['bytes'] + 1)
        attrs = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        identity = lambda s: tuple(getattr(s, n) for n in attrs)
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
             and pin(body) == expected, 'HELD_HELPER_PIN')
        return body
    finally:
        os.close(fd)


def held(source_root, filename):
    """Only whole-reviewed passive module definitions are imported."""
    path = Path(source_root) / NATIVE / filename
    size, sha = HELD[filename]
    body = read_code(path, dict(bytes=size, sha256=sha))
    spec = importlib.util.spec_from_file_location('bankstown_qt3_held_' + filename[:-3], path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(body, str(path), 'exec'), module.__dict__)
    return module


def provider_fields(complete_reference_result, *, source_root=ROOT):
    """Use the maintained complete517 provider result, without credit or rebinding."""
    return held(source_root, 'base_inputs_current_v3.py').assembler_fields(complete_reference_result)


def selected_packages(source_root, provider):
    values = []
    for member, (size, sha) in LOCKS.items():
        raw = provider.stream(dict(path=str(Path(source_root) / member), bytes=size, sha256=sha), {}, body=True, cap=1024**2)
        values.append(provider.decode(raw))
    baseline, successor = values
    need(len(baseline['packages']) == 276 and len(successor['new_packages']) == 58,
         'EXACT_HELD_CANDIDATE_SELECTION')
    selected = {n: row for n, row in baseline['packages'].items() if n != 'qt6-base'} | successor['new_packages']
    need(len(selected) == 333 and selected['qt6-base']['version'] == '6.12.0-3'
         and selected['rust']['version'] == '1:1.99.0-1', 'EXACT333_QT3_RUST199')
    return selected


def plan_inputs(*, source_root, source_rows, request, verify_archives=True):
    """Check the actual base APIs and all explicit128 archive/signature references.

    Source authenticity and the external Root request selection belong to the
    caller's admission gate. verify_archives=False is finite metadata MODEL only.
    """
    need(type(request) is dict and set(request) == REQUEST_KEYS, 'CLOSED_QT3_INPUT_REQUEST')
    need(type(verify_archives) is bool, 'TYPED_ARCHIVE_VERIFICATION')
    provider = held(source_root, 'base_inputs_current_v3.py')
    assembler = held(source_root, 'inputs_current_v3.py')
    image = held(source_root, 'image_current_v3.py')
    base_fields, base, baseline = assembler.base349_inputs(source_root=source_root,
        source_rows=source_rows, request=request, verify_archives=verify_archives)
    checked_base, base_rows, checked_baseline = image.base_inputs(base_fields, Path(source_root))
    need(base == checked_base and baseline == checked_baseline, 'INDEPENDENT_BASE349_JOIN')
    selected = selected_packages(source_root, provider)
    rootfs = {row['name'][0]: row['arch'][0] for row in base['rootfs_packages']}
    rootfs.update({row['name']: row['arch'] for row in base['packages']})
    profile = provider.decode(provider.stream(base_fields['bootstrap_profile'], {}, body=True, cap=1024**2))
    rootfs.update({row['name']: row['arch'] for row in profile['additions']['rows']})
    shared = set(baseline) & set(selected)
    need(len(shared) == 205 and all(baseline[n] == selected[n]['version']
         and rootfs[n] == selected[n]['arch'] for n in shared), 'PROTECTED349_IDENTITY_CONFLICT')
    signed = {row['name']: row for row in base['packages'] + profile['additions']['rows']}
    for name in set(signed) & set(selected):
        old, new = signed[name], selected[name]
        need(old['filename'] == new['filename']
             and new['archive'] == dict(bytes=old['size'], sha256=old['sha256'])
             and new['signature'] == dict(bytes=old['signature_size'], sha256=old['signature_sha256']),
             'SHARED_SELECTED_ARCHIVE_PIN_CONFLICT')
    names = sorted(set(selected) - set(baseline))
    need(len(names) == 128, 'EXACT128_ADDITIONS')
    refs = request['candidate_materials']
    filenames = {selected[n]['filename'] + suffix for n in names for suffix in ('', '.sig')}
    need(type(refs) is dict and set(refs) == filenames and len(filenames) == 256, 'EXACT256_CANDIDATE_REFS')
    observed, additions = {}, []
    for name in names:
        row = selected[name]
        archive, signature = refs[row['filename']], refs[row['filename'] + '.sig']
        for value, expected in ((archive, row['archive']), (signature, row['signature'])):
            need(type(value) is dict and set(value) == {'path', 'bytes', 'sha256'}
                 and {k: value[k] for k in ('bytes', 'sha256')} == expected, 'EXACT_CANDIDATE_WHOLE_PIN')
            if verify_archives:
                provider.stream(value, observed)
            else:
                provider.ordinary(value['path'])
        additions.append(dict(name=name, version=row['version'], arch=row['arch'], filename=row['filename'],
            archive=archive, signature=signature, trust='official', source_group='qt3_candidate128',
            metadata_pin=pin(encoded(row))))
    paths = [v['path'] for key in ('base_materials', 'supplemental_materials', 'keyring_materials')
             for v in base_fields[key].values()] + [v['path'] for v in refs.values()]
    need(len(paths) == len(set(paths)) == 773, 'DISTINCT_COMPLETE773_MATERIAL_ROLES')
    catalog_ref = request['catalog']
    catalog = provider.decode(provider.stream(catalog_ref, observed, body=True, cap=64 * 1024**2))
    need('schema' not in catalog and catalog.get('purpose') == 'bankstown-optional-qtbase6.12.0-3-input-candidate'
         and catalog.get('candidate') == 'EXPLICIT_OPTIONAL_QT_BASE_6.12.0-3'
         and catalog.get('complete') is True and catalog.get('original_minus2_hold') == 'UNCHANGED'
         and catalog.get('native_tools_profile') == 'NOT_PRODUCED'
         and catalog.get('source_legal_freshness_acceptance') == 'HELD'
         and set(catalog['packages']) == set(selected), 'EXACT_ACTUAL_QT3_CATALOG')
    for field in ('missing_inputs', 'unresolved_package_dependencies', 'unresolved_elf_dependencies', 'unresolved_GNU_versions'):
        need(catalog.get(field) == [], 'CATALOG_CLOSURE_HOLD')
    for name, row in selected.items():
        md = catalog['packages'][name]['metadata']['/.PKGINFO']
        need(md.get('pkgname') == [name] and md.get('pkgver') == [row['version']]
             and md.get('arch') == [row['arch']], 'CATALOG_SELECTED_IDENTITY')
    need(catalog.get('candidate_lock') == dict(bytes=88821, sha256=LOCKS[next(reversed(LOCKS))][1]), 'CATALOG_LOCK_BINDING')
    provider.unchanged(observed)
    expected = baseline | {n: selected[n]['version'] for n in names}
    need(len(expected) == 477 and all(expected[n] == v for n, v in baseline.items()), 'PROTECTED349_IN477')
    return dict(kind='BANKSTOWN_QT3_INPUT_PLAN_DATA_V1', base=base, base_fields=base_fields,
        base_rows=base_rows, additions=additions, baseline=baseline, expected=expected,
        catalog=catalog_ref, official_trust=request['official_trust'], request_pin=pin(encoded(request)),
        verified_archives=verify_archives, prospective_inventory_pin=pin(image.lock(expected)),
        Root_acceptance=None, native_component_acceptance=False, hardware_acceptance=False, release_acceptance=False)
