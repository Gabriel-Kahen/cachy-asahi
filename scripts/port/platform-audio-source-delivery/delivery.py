#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Finite portable audio source DATA export and offline recipient verification."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
JOIN_SHA = '5eb6279bf5ad495d53e46771471aba0d345c7839f4354e0d2366a145ec0812eb'
INPUTS_SHA = 'fc8d9e9bb5c2696dce29bdddfc58e39d8cb568a5434dac47eb8ace3afc9adc94'
HANDOFF_SHA = '70a94f1df45b982abd78644e2bc9182bf0b761f8a11549a993bc2f73e22e777c'
WMIDI_COMMIT = '3bd91df0dc6af1d081b2ac6b43730a116bb2e198'
WMIDI_TREE = '350c51ae2311147baccb4c2ebda62320e24518d8'
MAX_FILE, MAX_TOTAL, MAX_NODES = 32 * 1024**2, 128 * 1024**2, 512
HOLDS = {
    'complete_corresponding_source_accepted': False, 'legal_acceptance': False,
    'compiler_original_flags_binary_correspondence': 'NOT_ESTABLISHED',
    'signature_authentication': 'NOT_PERFORMED', 'security_freshness_accepted': False,
    'relinking': 'NOT_ADJUDICATED', 'code_execution': False, 'network': False,
    'native_build': False, 'installation': False, 'audio_speaker_safety': 'NOT_RUN',
    'physical_m2': 'NOT_RUN', 'performance': 'NOT_RUN',
    'publication': 'NOT_RUN', 'release': 'NOT_ADMITTED',
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def desc(raw):
    return dict(size=len(raw), sha256=sha(raw))


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def load(checkout):
    path = checkout / 'scripts/port/platform-audio-registry-sources/join.py'
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ALIASED_TRUSTED_CHECKOUT')
    with path.open('rb') as stream:
        raw = stream.read(65537)
    need(len(raw) <= 65536 and sha(raw) == JOIN_SHA, 'TRUSTED_JOIN_PIN')
    spec = importlib.util.spec_from_file_location('delivery_registry_join', path)
    j = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), j.__dict__)
    a = j.trusted_auditor(checkout)
    intake = a.intake_module()
    raw = intake.ordinary(checkout / 'scripts/port/platform-audio-registry-sources/registry-inputs.json', 1024**2)
    need(sha(raw) == INPUTS_SHA, 'ORIGINAL_REGISTRY_INPUTS_PIN')
    inputs = j.decode(raw)
    need(inputs['handoff_index_sha256'] == HANDOFF_SHA, 'ORIGINAL_HANDOFF_PIN')
    # This profile is part of the trusted checkout, never loaded as packet code.
    profile = j.decode(intake.ordinary(HERE / 'delivery-profile.json', 65536))
    return j, a, intake, inputs, profile


def reference(path, raw):
    return dict(path=path, **desc(raw))


def public_receipt(inputs):
    """Reconstruct only receipt fields used by the existing join, from public pins."""
    objects, reuse = {}, []
    for row in inputs['sources']:
        name, version = row['name'], row['version']
        objects['index-' + name.lower()] = dict(id='index-' + name.lower(),
            material=row['index'], status=200, url=row['index_url'])
        if row['origin'] == 'existing-Cargo-cache':
            reuse.append(dict(name=name, version=version, material=row['archive']))
        else:
            key = 'crate-' + name + '-' + version
            objects[key] = dict(id=key, material=row['archive'], status=200, url=row['archive_url'])
    return dict(objects=[objects[k] for k in sorted(objects)], cache_reuse=reuse,
        downloaded_body_bytes=sum(r['material']['size'] for r in objects.values()))


def public_metadata(j, original):
    """Only registry identities needed to label the new host-metadata subset."""
    packages = {}
    for name, record in sorted(original['packages'].items()):
        need(name in ('speakersafetyd', 'bankstown', 'triforce-lv2'), 'METADATA_PACKAGE')
        identities = []
        for row in record['graph']['packages']:
            ident = row['identity']
            if ident[2] == 'registry+https://github.com/rust-lang/crates.io-index':
                j.identity(ident[0], ident[1])
                need(len(ident) == 3, 'METADATA_IDENTITY')
                identities.append(ident)
        packages[name] = dict(graph=dict(packages=[dict(identity=i) for i in sorted(identities)]))
    need(len(packages) == 3, 'METADATA_THREE_PACKAGES')
    return dict(source_handoff_index_sha256=HANDOFF_SHA, native_profile_sha256=j.PROFILE,
        scope='DERIVED_REGISTRY_IDENTITIES_ONLY_NEW_HOST_DEFAULT_FEATURE_METADATA_NOT_ORIGINAL_NATIVE_GRAPH',
        packages=packages)


def derived_inputs(inputs, metadata, receipt):
    result = dict(inputs)
    result['metadata'] = reference('metadata-replay.json', metadata)
    result['acquisition_receipt'] = reference('acquisition.json', receipt)
    return result


def join(j, checkout, handoff, inputs, materials):
    # Existing API writes one data report; no downloaded/source code is imported.
    with tempfile.TemporaryDirectory(prefix='audio-source-data-join-') as temp:
        path = Path(temp) / 'inputs.json'
        path.write_bytes(encoded(inputs)); path.chmod(0o600)
        report = j.run(checkout, handoff, path, sha(encoded(inputs)), materials, Path(temp) / 'report')
    need(not report['errors'] and report['exact_crates'] == 117 and report['exact_member_files'] == 4292,
         'REGISTRY_JOIN_NOT_EXACT')
    return report


def git_tree(files):
    """Reconstruct this small regular-file upstream tree, without invoking Git."""
    def object_id(kind, body):
        return hashlib.sha1(kind + b' ' + str(len(body)).encode() + b'\0' + body).digest()
    tree = {}
    for path, raw in files.items():
        node = tree
        for part in PurePosixPath(path).parts[:-1]:
            node = node.setdefault(part, {})
        node[PurePosixPath(path).name] = raw
    def build(node):
        body = b''
        for name in sorted(node, key=lambda n: (n + '/' if isinstance(node[n], dict) else n).encode()):
            value = node[name]
            mode, ident = (b'40000', build(value)) if isinstance(value, dict) else (b'100644', object_id(b'blob', value))
            body += mode + b' ' + name.encode() + b'\0' + ident
        return object_id(b'tree', body)
    return build(tree).hex()


def wmidi_report(j, a, raw_crate, source, commit):
    files = j.raw_members(a, raw_crate, 'wmidi', '3.1.0')
    vcs = j.decode(files['.cargo_vcs_info.json'])
    need(vcs == {'git': {'sha1': WMIDI_COMMIT}}, 'WMIDI_PUBLISHED_VCS_IDENTITY')
    manifest = a.toml(files['Cargo.toml.orig'])
    need(a.identity(manifest) == ('wmidi', '3.1.0') and manifest['package']['license'] == 'MIT'
         and manifest['package']['repository'] == 'https://github.com/wmedrano/wmidi', 'WMIDI_PUBLISHED_MANIFEST')
    prefix = 'wmidi-' + WMIDI_COMMIT + '/'
    upstream = a.tar_data(source)
    need(all(p.startswith(prefix) for p in upstream), 'WMIDI_FOREIGN_UPSTREAM_ROOT')
    upstream = {p[len(prefix):]: b for p, b in upstream.items()}
    need(git_tree(upstream) == WMIDI_TREE, 'WMIDI_UPSTREAM_GIT_TREE_DIFFERS')
    info = j.decode(commit)
    need(info['sha'] == WMIDI_COMMIT and info['tree']['sha'] == WMIDI_TREE, 'WMIDI_COMMIT_TREE_IDENTITY')
    # Cargo publishes generated normalized/VCS files, replacing original Cargo.toml.
    expected = {p: b for p, b in files.items() if p not in ('Cargo.toml', 'Cargo.toml.orig', '.cargo_vcs_info.json')}
    expected['Cargo.toml'] = files['Cargo.toml.orig']
    need(upstream == expected, 'WMIDI_UPSTREAM_PUBLISHED_MEMBER_DIFFERENCE')
    observation = a.license_material(a.toml(upstream['Cargo.toml']),
        {prefix + p: b for p, b in upstream.items()}, prefix.rstrip('/'))
    need(not observation['text_presence'], 'WMIDI_LICENSE_OBSERVATION_CHANGED')
    return dict(status='HOLD_NO_LICENSE_TEXT_IN_PUBLISHED_CRATE_OR_EXACT_VCS_TREE',
        published_crate=desc(raw_crate), published_vcs_commit=WMIDI_COMMIT,
        published_repository='https://github.com/wmedrano/wmidi',
        observed_repository='https://github.com/RustAudio/wmidi',
        source_url='https://codeload.github.com/RustAudio/wmidi/tar.gz/' + WMIDI_COMMIT,
        commit_url='https://api.github.com/repos/RustAudio/wmidi/git/commits/' + WMIDI_COMMIT,
        upstream_source=desc(source), upstream_commit_response=desc(commit),
        reconstructed_git_tree=WMIDI_TREE, exact_upstream_regular_files=len(upstream),
        comparison='ALL_UPSTREAM_FILES_EXACT_AFTER_EXPLICIT_CARGO_PUBLICATION_TRANSFORM',
        transformation=dict(normalized_manifest='Cargo.toml', original_manifest='Cargo.toml.orig',
                            cargo_generated_vcs='.cargo_vcs_info.json'),
        exact_tree_license_observation=observation,
        later_2023_notice_association='ORIGINAL_LIMITED_ASSOCIATION_UNCHANGED_NOT_RETROACTIVELY_ACCEPTED',
        grant_or_legal_acceptance=False)


def packet_files(intake, root):
    root = Path(root).absolute()
    need(root.is_dir() and not any(p.is_symlink() for p in (root, *root.parents)), 'ALIASED_OR_MISSING_PACKET')
    found, directories, total = {}, set(), 0
    # Bounded walk before reading any file, no recursion through symlinks.
    pending = [root]
    while pending:
        path = pending.pop(); info = path.lstat()
        need(info.st_uid == os.getuid(), 'PACKET_FOREIGN_OWNER')
        if stat.S_ISDIR(info.st_mode):
            need(stat.S_IMODE(info.st_mode) == 0o700, 'PACKET_DIRECTORY_MODE')
            if path != root:
                directories.add(path.relative_to(root).as_posix())
            with os.scandir(path) as children:
                for child in children:
                    pending.append(Path(child.path))
                    need(len(pending) + len(found) + len(directories) <= MAX_NODES, 'PACKET_NODE_LIMIT')
        else:
            need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600, 'PACKET_FILE_TYPE_OR_MODE')
            total += info.st_size
            need(total <= MAX_TOTAL, 'PACKET_TOTAL_LIMIT')
            name = intake.relative(path.relative_to(root).as_posix())
            found[name] = intake.ordinary(path, MAX_FILE)
    parents = {str(p) for name in found for p in PurePosixPath(name).parents if str(p) != '.'}
    need(directories == parents, 'PACKET_EMPTY_OR_EXTRA_DIRECTORY')
    return found


def manifest(inputs, profile, material, report, wmidi):
    return dict(schema=1, purpose='finite-public-safe-audio-source-delivery-v1',
        original_handoff_index_sha256=HANDOFF_SHA, original_registry_inputs_sha256=INPUTS_SHA,
        delivery_profile=desc(encoded(profile)),
        native_profile_sha256=inputs['native_profile_sha256'], trusted_join_sha256=JOIN_SHA,
        derivations=dict(
            registry_inputs='UNCHANGED_ORIGINAL_REFERENCES_EXCEPT_TWO_EXPLICIT_PUBLIC_PROJECTIONS',
            acquisition=dict(original=inputs['acquisition_receipt'],
                projection='PUBLIC_DESCRIPTOR_OBJECTS_AND_CACHE_IDENTITIES_ONLY_NO_OPERATOR_RECEIPT',
                removed='ALL_PRIVATE_CACHE_PATHS_AND_UNSELECTED_OPERATOR_FIELDS'),
            metadata=dict(original=inputs['metadata'], projection=profile['metadata_projection'],
                scope='THREE_REGISTRY_IDENTITY_LISTS_ONLY_NO_TOOL_PROBES_ENVIRONMENT_OR_OPERATOR_FIELDS'),
            original_private_receipts='NOT_EXPORTED_OR_MODIFIED; OFFLINE_RECIPIENT_CANNOT_RECONSTRUCT_THEM'),
        registry=dict(exact_crates=report['exact_crates'], exact_member_files=report['exact_member_files'],
            metadata_reachable_registry_identities=report['metadata_reachable_registry_identities']),
        wmidi_status=wmidi['status'],
        files={p: desc(b) for p, b in sorted(material.items())}, holds=HOLDS)


def checks(checkout, root, j, a, intake, inputs, profile, material):
    receipt = encoded(public_receipt(inputs))
    metadata = material['registry/metadata-replay.json']
    need(desc(metadata) == profile['metadata_projection'], 'PUBLIC_METADATA_PROJECTION_PIN')
    need(material['registry/acquisition.json'] == receipt, 'PUBLIC_RECEIPT_PROJECTION_DIFFERS')
    derived = derived_inputs(inputs, metadata, receipt)
    need(material['registry/registry-inputs.json'] == encoded(derived), 'DERIVED_REGISTRY_INPUTS_DIFFER')
    need(material['registry/original-inputs.json'] == encoded(inputs), 'ORIGINAL_INPUTS_COPY_DIFFERS')
    expected = {'registry/' + r[k]['path'] for r in inputs['sources'] for k in ('archive', 'index')}
    expected.update('handoff/' + p for p in intake.files(root / 'handoff'))
    expected.update('wmidi/' + name for name in profile['wmidi_materials'])
    expected.update('registry/' + p for p in ('metadata-replay.json', 'acquisition.json', 'registry-inputs.json', 'original-inputs.json'))
    expected.update(('registry-source-join.json', 'wmidi-source-observation.json'))
    need(set(material) == expected, 'PACKET_NAMESPACE_DIFFERS')
    for name, pin in profile['wmidi_materials'].items():
        need(desc(material['wmidi/' + name]) == pin, 'WMIDI_EXACT_MATERIAL_PIN')
    report = join(j, checkout, root / 'handoff', derived, root / 'registry')
    wmidi = wmidi_report(j, a, material['registry/crates/wmidi-3.1.0.crate'],
                         material['wmidi/source.tar.gz'], material['wmidi/commit.json'])
    need(material['registry-source-join.json'] == encoded(report), 'RECOMPUTED_JOIN_REPORT_DIFFERS')
    need(material['wmidi-source-observation.json'] == encoded(wmidi), 'RECOMPUTED_WMIDI_REPORT_DIFFERS')
    return manifest(inputs, profile, material, report, wmidi)


def verify(checkout, root, checksum):
    j, a, intake, inputs, profile = load(checkout)
    material = packet_files(intake, root)
    raw = material.pop('delivery.json')
    need(sha(raw) == checksum, 'DELIVERY_INDEX_PIN')
    saved = j.decode(raw)
    need(saved['files'] == {p: desc(b) for p, b in sorted(material.items())}, 'PACKET_FILE_BYTES_DIFFER')
    expected = checks(checkout, root, j, a, intake, inputs, profile, material)
    need(saved == expected, 'DELIVERY_MANIFEST_DIFFERS')
    return dict(status='VERIFIED_FIVE_PACKAGE_117_REGISTRY_DELIVERY_WITH_HOLDS',
        delivery_sha256=checksum, files=len(material), registry=saved['registry'], holds=HOLDS)


def write_tree(api, output, material):
    # Only fixed verified relative paths reach the writer; existing outputs refuse.
    api.write_fresh(output, {})
    directories = sorted({str(p) for name in material for p in PurePosixPath(name).parents if str(p) != '.'},
                         key=lambda p: (len(PurePosixPath(p).parts), p))
    for directory in directories:
        api.write_fresh(output / directory, {})
    for name, raw in sorted(material.items()):
        fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)


def export(checkout, handoff, materials, wmidi, output):
    j, a, intake, inputs, profile = load(checkout)
    output = output.absolute()
    need('..' not in output.parts and not any(p.is_symlink() for p in (output, *output.parents)), 'ALIASED_OUTPUT')
    need(not any(output.is_relative_to(p.absolute()) for p in (handoff, materials, wmidi)), 'OUTPUT_OVERLAPS_ORIGINAL_INPUT')
    need(not output.exists() and not output.is_symlink(), 'OUTPUT_ALREADY_EXISTS')
    # Validate originals and acquisition associations before deriving any public data.
    original_report = join(j, checkout, handoff, inputs, materials)
    handoff_files = intake.files(handoff)
    metadata_raw = intake.ordinary(materials / inputs['metadata']['path'])
    need(desc(metadata_raw) == {k: inputs['metadata'][k] for k in ('size', 'sha256')}, 'ORIGINAL_METADATA_PIN')
    metadata = encoded(public_metadata(j, j.decode(metadata_raw)))
    need(desc(metadata) == profile['metadata_projection'], 'PUBLIC_METADATA_PROJECTION_PIN')
    receipt = encoded(public_receipt(inputs))
    need(original_report['acquisition']['downloaded_body_bytes'] == j.decode(receipt)['downloaded_body_bytes'], 'PROJECTED_RECEIPT_TOTAL_DIFFERS')
    derived = derived_inputs(inputs, metadata, receipt)
    material = {'handoff/' + p: b for p, b in handoff_files.items()}
    for row in inputs['sources']:
        for key in ('archive', 'index'):
            ref = row[key]; raw = intake.ordinary(materials / ref['path'], j.MAX_OBJECT)
            need(desc(raw) == {k: ref[k] for k in ('size', 'sha256')}, 'ORIGINAL_REGISTRY_MATERIAL_CHANGED')
            material['registry/' + ref['path']] = raw
    material.update({'registry/metadata-replay.json': metadata, 'registry/acquisition.json': receipt,
                     'registry/registry-inputs.json': encoded(derived), 'registry/original-inputs.json': encoded(inputs)})
    for name, pin in profile['wmidi_materials'].items():
        raw = intake.ordinary(wmidi / name)
        need(desc(raw) == pin, 'WMIDI_EXACT_MATERIAL_PIN')
        material['wmidi/' + name] = raw
    observation = wmidi_report(j, a, material['registry/crates/wmidi-3.1.0.crate'],
                              material['wmidi/source.tar.gz'], material['wmidi/commit.json'])
    # Export only after every original input verifies. Any failed output stays unaccepted.
    api = intake.load_api(intake.profile(handoff_files['native-inputs.json'], j.PROFILE))
    write_tree(api, output, material)
    report = join(j, checkout, output / 'handoff', derived, output / 'registry')
    material.update({'registry-source-join.json': encoded(report), 'wmidi-source-observation.json': encoded(observation)})
    saved = manifest(inputs, profile, material, report, observation)
    for name in ('registry-source-join.json', 'wmidi-source-observation.json', 'delivery.json'):
        raw = encoded(saved) if name == 'delivery.json' else material[name]
        fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
    return verify(checkout, output, sha(encoded(saved)))


def main():
    need(sys.flags.isolated, 'Python isolated mode (-I) required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted-checkout', type=Path, default=ROOT)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('export')
    for name in ('handoff', 'materials', 'wmidi', 'output'):
        build.add_argument('--' + name, type=Path, required=True)
    check = commands.add_parser('verify')
    check.add_argument('--packet', type=Path, required=True)
    check.add_argument('--sha256', required=True)
    args = parser.parse_args()
    try:
        result = export(args.trusted_checkout, args.handoff, args.materials, args.wmidi, args.output) if args.command == 'export' else verify(args.trusted_checkout, args.packet, args.sha256)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        # Exception messages can include operator paths; emit only the category.
        print(json.dumps(dict(status='REFUSED_AUDIO_SOURCE_DELIVERY', category=type(error).__name__, holds=HOLDS)))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
