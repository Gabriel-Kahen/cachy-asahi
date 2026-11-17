# SPDX-License-Identifier: MIT
"""Closed name/version/architecture BUILDINFO DATA checks; no artifact execution."""
import hashlib
import re

ARCHES = ('aarch64', 'any')
NAME = r'[a-z0-9@._+][a-z0-9@._+-]{0,254}'
VERSION = r'(?:[0-9]+:)?[A-Za-z0-9.+_~]+-[A-Za-z0-9.+_]+'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def identity(name, version, arch):
    need(type(name) is str and re.fullmatch(NAME, name) and
         type(version) is str and len(version) <= 255 and re.fullmatch(VERSION, version),
         'literal baseline package name/version')
    need(type(arch) is str and arch in ARCHES, 'explicit baseline architecture must be aarch64 or any')
    return name, version, arch


def lock_rows(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 65536 and raw.endswith(b'\n'), 'bounded complete349 lock bytes')
    lines = raw.decode('ascii').split('\n')[:-1]
    need(len(lines) == 349, 'exact349 lock rows')
    result = {}
    for line in lines:
        parts = line.split(' ')
        need(len(parts) == 2, 'exact lock name/version encoding')
        name, version, _ = identity(*parts, 'any')
        need(name not in result, 'duplicate baseline lock name')
        result[name] = version
    return result


def architecture_rows(original, additions, expected):
    """Use pinned input metadata, never output BUILDINFO, as the authority."""
    rootfs, packages = original['rootfs_packages'], original['packages']
    need(type(rootfs) is list and len(rootfs) == 165 and type(packages) is list and len(packages) == 248 and
         type(additions) is list and len(additions) == 8, 'exact165 rootfs/248 original/8 added input metadata')
    result = {}
    for row in rootfs:
        need(type(row) is dict and all(type(row.get(k)) is list and len(row[k]) == 1 for k in ('name','version','arch')),
             'singleton rootfs name/version/architecture metadata required')
        name, version, arch = identity(*(row[k][0] for k in ('name','version','arch')))
        need(name not in result, 'duplicate rootfs package name')
        result[name] = dict(version=version, arch=arch)
    selected, replacements = set(), 0
    for row in packages + additions:
        need(type(row) is dict, 'ordinary selected package metadata')
        name, version, arch = identity(*(row[k] for k in ('name','version','arch')))
        need(name not in selected, 'duplicate selected/addition package name')
        selected.add(name)
        # This closed ALARM input family includes epoch in its pinned filenames.
        filename = name+'-'+version+'-'+arch+'.pkg.tar.xz'
        need(row.get('filename') == filename, 'selected package name/version/arch filename binding')
        need(type(row.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'selected whole signed payload pin')
        if name in result:
            need(result[name]['arch'] == arch, 'conflicting rootfs/selected architecture')
            replacements += result[name]['version'] != version
        result[name] = dict(version=version, arch=arch)
    need(len(selected) == 256 and len(result) == 349 and
         {name: row['version'] for name, row in result.items()} == expected,
         'complete349 Source input name/version join; missing architecture input cannot be invented')
    return result, replacements


def validate(raw, lock, original, additions):
    expected = lock_rows(lock)
    architectures, replacements = architecture_rows(original, additions, expected)
    need(type(raw) is bytes and 0 < len(raw) <= 4*1024**2, 'bounded package BUILDINFO')
    lines = raw.decode('ascii').split('\n')
    installed = []
    for line in lines:
        if re.match(r'^\s*installed(?:\s|=|$)', line):
            need(line.startswith('installed = '), 'exact installed BUILDINFO key encoding')
            installed.append(line[len('installed = '):])
    need(len(installed) == 349 and len(set(installed)) == 349, 'exact349 distinct installed BUILDINFO rows')
    labels = {name+'-'+row['version']: (name,row['arch']) for name,row in architectures.items()}
    need(len(labels) == 349, 'unambiguous baseline name/version labels')
    seen = set()
    for literal in installed:
        name_version, separator, arch = literal.rpartition('-')
        need(separator and arch in ARCHES, 'one explicit terminal aarch64/any architecture required')
        need(name_version in labels, 'installed name/version differs from complete349 baseline')
        name, expected_arch = labels[name_version]
        need(name not in seen and arch == expected_arch, 'duplicate installed name or independently bound architecture mismatch')
        seen.add(name)
    need(seen == set(architectures), 'complete349 installed membership')
    return dict(rows=349, architectures={a:sum(r['arch'] == a for r in architectures.values()) for a in ARCHES},
                selected_packages=256, rootfs_only_packages=93, selected_version_replacements=replacements,
                basis='SOURCE_PINNED_SIGNED_BOOTSTRAP_INPUT_METADATA_NOT_OUTPUT_BUILDINFO',
                required_external_architecture_input=None, fresh_signature_verification=False,
                rootfs_body_reread=False, output_BUILDINFO_used_as_architecture_authority=False)


def check(raw, source, evidence, reader, profile):
    """Called only by the new replay after inherited Source/signature predicates."""
    bodies = {}
    for name, pin in profile['files'].items():
        body = reader.read(source/name, 4*1024**2)
        reader.need(dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest()) == pin,
                    'whole Source architecture metadata pin')
        bodies[name] = body
    original = reader.decode(bodies['original/bootstrap/scripts/ci/inputs.lock.json'])
    additions = reader.decode(bodies['original/native/input-profile.json'])['additions']['rows']
    # Retained independent bootstrap metadata must agree with the pinned Source.
    reader.need(reader.load(evidence/'bootstrap/inputs.lock.json') ==
                dict(original,packages=original['packages']+additions), 'same closed signed input derivation')
    reader.need(reader.load(evidence/'bootstrap/rootfs-inventory.json') == original['rootfs_packages'],
                'retained rootfs ALPM architecture metadata/Source join')
    verdict = validate(raw,bodies['expected349.lock'],original,additions)
    reader.buildinfo_architecture_verdict = verdict
    return verdict
