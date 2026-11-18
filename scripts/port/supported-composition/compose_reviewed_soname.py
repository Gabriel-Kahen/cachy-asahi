#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preview one whole-pinned AArch64 makepkg SONAME dependency in development DATA.

The separate relation operand pins the exact v1 contract, original candidate
row, recipe, selected executable member, and observed Asahi provider metadata.
Only a temporary SRCINFO projection enters the original composer.
"""

import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MIB = 1024**2
ARCHIVE_LIMIT = 32 * MIB
ELF_LIMIT = 16 * MIB
KIND = 'supported-Asahi-reviewed-aarch64-Soname-DATA'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


C = module('legacy_supported_composition', HERE / 'compose.py')
A = module('reviewed_soname_archive_reader', HERE / 'assemble_signed_additions.py')
E = module('reviewed_soname_elf', ROOT / 'scripts/platform/elf_audit.py')
L = module('reviewed_soname_literal_metadata', ROOT / 'scripts/checks/recipe_metadata_consistency.py')
S = module('reviewed_soname_sbom', ROOT / 'scripts/release/release_sbom.py')
source, _, stream = S.dependencies()
need = C.need


def fields(value, names):
    need(type(value) is dict and set(value) == set(names.split()), 'exact SONAME review fields required')


def pin(raw):
    return dict(size=len(raw), sha256=C.sha(raw))


class Reader(C.Reader):
    """One explicitly reviewed archive may exceed the legacy per-file DATA limit."""

    def __init__(self, reference):
        super().__init__()
        self.archive = reference

    def read_archive(self):
        need(time.monotonic() - self.started <= 120, 'composition DATA deadline exceeded')
        path = A.reference(self.archive, ARCHIVE_LIMIT)
        with A.pinned_open(path, ARCHIVE_LIMIT) as (source_file, info):
            need(not info.st_mode & 0o022, 'ordinary non-writable DATA required')
            raw = source_file.read(self.archive['size'] + 1)
        need(pin(raw) == {k: self.archive[k] for k in ('size', 'sha256')}, 'whole reviewed archive differs')
        return raw

    def read(self, ref):
        if ref != self.archive:
            return super().read(ref)
        name = ref['path']
        if name in self.refs:
            need(self.refs[name] == ref, 'contradictory DATA references')
            return self.raw[name]
        raw = self.read_archive()
        self.refs[name], self.raw[name] = dict(ref), raw
        need(sum(map(len, self.raw.values())) <= 64 * MIB, 'aggregate DATA input bound')
        return raw

    def recheck(self):
        for name, ref in self.refs.items():
            raw = self.read_archive() if ref == self.archive else C.t.bound(ref)
            need(raw == self.raw[name], 'DATA drift before result publication')


def project_source(raw, recipe, declared, generated):
    need(0 < len(raw) <= L.MAX_BYTES and 0 < len(recipe) <= L.MAX_BYTES,
         'bounded SRCINFO and PKGBUILD required')
    lines = raw.decode().splitlines(keepends=True)
    architectures = [line.strip().removeprefix('arch = ') for line in lines if line.strip().startswith('arch = ')]
    need(sorted(architectures) in (['aarch64'], ['aarch64', 'x86_64']), 'explicit AArch64 source architecture required')
    target = [line for line in lines if line.strip() != 'arch = x86_64']
    candidates = (f'depends = {declared}', f'depends_aarch64 = {declared}')
    hits = [i for i, line in enumerate(target) if line.strip() in candidates]
    need(len(hits) == 1, 'one exact unversioned SRCINFO dependency required')
    before, _ = C.srcinfo(''.join(target).encode())
    declarations, source_dependencies = set(), []
    recipe = recipe.decode()
    for match in re.finditer(r'(?m)^(depends|depends_aarch64)([+]?=)', recipe):
        key = match[1]
        need(match[2] == '=' and recipe[match.end():match.end() + 1] == '(',
             'literal PKGBUILD dependency array required')
        tail = recipe[match.end() + 1:]
        end, _ = L.array_end(tail)
        need(key not in declarations and end is not None, 'unique literal PKGBUILD dependency arrays required')
        following = tail[end + 1:].split('\n', 1)[0].strip()
        need(not following or following.startswith('#'), 'literal PKGBUILD dependency array required')
        declarations.add(key)
        source_dependencies.extend(L.words(tail[:end]))
    need(sorted(source_dependencies) == sorted(before['DEPENDS']), 'literal PKGBUILD and SRCINFO dependencies differ')
    need(before['DEPENDS'].count(declared) == 1 and generated not in before['DEPENDS'],
         'generated SONAME dependency must be a single reviewed replacement')
    index = hits[0]
    key, value = target[index].rsplit(' = ', 1)
    target[index] = key + ' = ' + generated + value[len(declared):]
    projected = ''.join(target).encode()
    after, _ = C.srcinfo(projected)
    need(after == dict(before, DEPENDS=[generated if row == declared else row for row in before['DEPENDS']]),
         'unrelated source metadata changed in projection')
    return projected, after


def checked_layout(raw, operand, recipe_raw, expected):
    """Check the full bounded archive namespace and read the selected member as bytes."""
    layout = S.tar_entries(raw, source, stream)
    row = operand['member']
    fields(row, 'path size sha256')
    name = row['path']
    need(E.normalized(name) == name and name.startswith('usr/') and type(row['size']) is int
         and 0 < row['size'] <= ELF_LIMIT, 'ordinary bounded package ELF member required')
    record = layout.get(name, {})
    need(record.get('type') == 'file' and record['mode'] & 0o100
         and (record['bytes'], record['sha256']) == (row['size'], row['sha256']),
         'reviewed ELF member differs from checked archive layout')
    for control in ('.PKGINFO', '.BUILDINFO'):
        need(layout.get(control, {}).get('type') == 'file' and layout[control]['bytes'] <= MIB,
             'ordinary bounded package metadata member required')
    pkg_raw, build_raw = (layout[key]['raw'] for key in ('.PKGINFO', '.BUILDINFO'))
    pkg, build = (S.metadata(body, source) for body in (pkg_raw, build_raw))
    identity = dict(pkgname=expected['NAME'], pkgbase=expected['BASE'], pkgver=expected['VERSION'])
    need(all(pkg.get(key) == build.get(key) == value for key, value in identity.items())
         and pkg.get('arch') == build.get('pkgarch') == ['aarch64']
         and build.get('buildtool') == ['makepkg'] and build.get('pkgbuild_sha256sum') == [C.sha(recipe_raw)],
         'archive package identity or BUILDINFO recipe binding differs')
    need(sorted(pkg.get('depend', [])) == sorted(expected['DEPENDS']),
         'archive runtime dependencies differ beyond the reviewed mapping')

    limits = stream.Limits(ARCHIVE_LIMIT, ARCHIVE_LIMIT, S.MAX_TAR, S.MAX_MEMBERS,
                           ELF_LIMIT, 64 * MIB, time.monotonic() + 20)
    decoder = stream.Decoded(io.BytesIO(raw), limits, 0)
    with tarfile.open(fileobj=decoder, mode='r|', bufsize=stream.CHUNK) as tar:
        for member in tar:
            if member.name.removeprefix('./') == name:
                need(member.isfile() and member.uid == member.gid == 0 and member.size == row['size'],
                     'ordinary root-owned package ELF member required')
                body = tar.extractfile(member).read(row['size'] + 1)
                break
        else:
            raise ValueError('reviewed ELF member missing')
    need(pin(body) == {key: row[key] for key in ('size', 'sha256')}, 'reviewed ELF member bytes differ')
    obj = E.parse_elf(body)
    declared = operand['declared']
    version = operand['generated'].removeprefix(declared + '=').removesuffix('-64')
    needed = f'{declared}.{version}'
    need(obj and obj['classification'] == 'aarch64-loadable-elf'
         and [value for value in obj['needed'] if value.startswith(declared + '.')] == [needed],
         'actual AArch64 ELF SONAME dependency differs')
    return dict(package=pin(pkg_raw), buildinfo=pin(build_raw), member=row, needed=needed)


def provider_lock(reader, contract, operand):
    locked = operand['provider']
    fields(locked, 'name version repo inventory metadata_sha256')
    identity = C.pin({key: locked[key] for key in ('name', 'version', 'repo')})
    need(identity['repo'] == 'observed-Asahi-base' and locked['inventory'] == contract['image_inventory'],
         'review requires the exact frozen Asahi provider inventory')
    image, _, _ = C.base_policy(reader, contract)
    row = image.get(identity['name'], {})
    requirement = operand['generated']
    need(row.get('VERSION') == [identity['version']] and row.get('ARCH') == ['aarch64']
         and C.sha(S.encoded(row)) == locked['metadata_sha256'] and row.get('PROVIDES', []).count(requirement) == 1,
         'exact frozen AArch64 SONAME provider differs')
    witnesses = C.t.tuple_audit.witnesses(requirement, {identity['name']: row}, C.t.tuple_audit.Versions())
    need(len(witnesses) == 1 and witnesses[0]['via'] == requirement, 'exact frozen SONAME provider witness required')
    return locked


def checked_operand(contract_ref, review_ref):
    held = C.Reader()
    operand = held.document(review_ref)
    fields(operand, 'kind schema_version approval_status composition_contract candidate recipe member declared generated provider')
    need(operand['kind'] == KIND and type(operand['schema_version']) is int and operand['schema_version'] == 1
         and operand['approval_status'] == 'UNAPPROVED' and operand['composition_contract'] == contract_ref,
         'unapproved SONAME review must bind the whole composition contract')
    declared, generated = operand['declared'], operand['generated']
    need(type(declared) is str and re.fullmatch(r'[A-Za-z0-9_+-]+\.so', declared)
         and type(generated) is str and re.fullmatch(re.escape(declared) + r'=[0-9]+(?:\.[0-9]+)*-64', generated),
         'one explicit source-to-generated ELF64 SONAME relation required')
    item = operand['candidate']
    fields(item, 'srcinfo archive archive_scope')
    need(item['archive_scope'] in ('retained-native-development-unqualified', 'synthetic-test-only'),
         'retained development archive required')
    reader = Reader(item['archive'])
    need(reader.document(review_ref) == operand, 'reviewed operand changed')
    contract = reader.document(contract_ref)
    need(contract['candidate_srcinfo'].count(item) == 1, 'exact reviewed candidate must appear once in composition')
    recipe = reader.read(operand['recipe'])
    projected, expected = project_source(reader.read(item['srcinfo']), recipe, declared, generated)
    package = expected['NAME'][0]
    need(all(row['name'] != package for key in ('roots', 'providers', 'allowed_base_changes') for row in contract[key]),
         'reviewed project candidate must remain unselected')
    layout = checked_layout(reader.read(item['archive']), operand, recipe, expected)
    return reader, operand, contract, projected, expected, layout, provider_lock(reader, contract, operand)


def run(contract_ref, review_ref, output):
    reader, operand, contract, projected, expected, layout, provider = checked_operand(contract_ref, review_ref)
    need(output.is_absolute() and output.resolve() == output and not output.exists(), 'fresh absolute output required')
    output.mkdir(mode=0o700)
    package = expected['NAME'][0]
    with tempfile.TemporaryDirectory(prefix='private-soname-composition-', dir=output) as scratch:
        path = Path(scratch) / 'projected.SRCINFO'
        C.t.write_bytes(path, projected)
        item = operand['candidate']
        old_rows = contract['candidate_srcinfo']
        projected_ref = dict(path=str(path), **pin(projected))
        projected_item = dict(item, srcinfo=projected_ref)
        inputs = dict(contract, candidate_srcinfo=[projected_item if row == item else row for row in old_rows])
        out = Path(scratch) / 'engine'
        report = C.compose(inputs, out, reader=reader)
        worker_raw = (out / 'preparation-inputs.json').read_bytes()
        worker = C.t.tuple_audit.load_json(worker_raw)
        admitted = worker['catalogs']['project'][package]
        need(admitted['DEPENDS'] == expected['DEPENDS'] and admitted['ARCH'] == ['aarch64']
             and admitted['SHA256SUM'] == [item['archive']['sha256']],
             'legacy libALPM input did not retain the exact reviewed candidate')
        final = {row['name']: row for row in report['proposed_final_inventory']}
        selected = final.get(package, {})
        need(selected.get('repo') != 'project'
             and not any(row['name'] == package for op in ('add', 'remove') for row in report['prepare'][op]),
             'reviewed candidate entered a proposed transaction')
        provider_row = final.get(provider['name'], {})
        need(provider_row.get('repo') == provider['repo'] and provider_row.get('version') == provider['version']
             and C.sha(S.encoded(provider_row['metadata'])) == provider['metadata_sha256'],
             'frozen SONAME provider changed in legacy preparation')
        reader.recheck()
        code = (Path(__file__).resolve(), Path(C.__file__), Path(A.__file__), Path(E.__file__), Path(L.__file__),
                Path(S.__file__), Path(source.__file__), Path(stream.__file__))
        result = dict(kind=KIND + '-result', schema_version=1, status='HOLD', approval_status='UNAPPROVED',
                      relation_status='VERIFIED_ONE_AARCH64_SONAME_RELATION_DATA_ONLY',
                      contract=contract_ref, review=review_ref, source_sha256={str(path.relative_to(ROOT)): C.t.preview.digest(path) for path in code},
                      candidate=operand['candidate'], recipe=operand['recipe'], provider=provider,
                      relation=dict(declared=operand['declared'], generated=operand['generated'], **layout),
                      projected_srcinfo=pin(projected), legacy_worker_input=pin(worker_raw),
                      legacy_composition=pin((out / 'composition.json').read_bytes()),
                      metadata_prepare_status=report['metadata_prepare_status'], blockers=report['blockers'],
                      image_package_count=report['image_package_count'], final_package_count=report['final_package_count'],
                      prepared_add=report['prepare']['add'], prepared_remove=report['prepare']['remove'],
                      project_candidate_selected=False, transaction_accepted=False, abi_qualified=False)
    C.t.write_bytes(output / 'reviewed-composition.DATA.json', S.encoded(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ('contract', 'reviewed-relation'):
        parser.add_argument('--' + label, type=Path, required=True)
        parser.add_argument('--' + label + '-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        def selected(path, digest):
            return dict(path=str(path.absolute()), size=path.stat().st_size, sha256=digest)
        result = run(selected(args.contract, args.contract_sha256),
                     selected(args.reviewed_relation, args.reviewed_relation_sha256), args.output)
        print(json.dumps({key: result[key] for key in ('status', 'approval_status', 'relation_status',
                                                       'metadata_prepare_status', 'project_candidate_selected')}, sort_keys=True))
        return 2
    except (ValueError, OSError, KeyError, TypeError, AttributeError, C.r.Error,
            subprocess.SubprocessError, *stream.DECODER_ERRORS) as error:
        print('reviewed SONAME DATA refused: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
