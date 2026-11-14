#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Join retained Asahi base/catalog DATA and current SRCINFO in private libalpm.

No recipe/payload execution, network, installation, image assembly or acceptance.
SRCINFO supplies proposed relations, never an archive identity or native evidence.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('supported_existing_transaction', ROOT / 'scripts/platform/transaction.py')
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
spec = importlib.util.spec_from_file_location('supported_existing_archive_metadata', ROOT / 'scripts/release/release.py')
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
need = t.preview.need
PLATFORM = set(t.tuple_audit.BOOT + t.tuple_audit.AUDIO +
               ('mesa', 'vulkan-asahi', 'linux-firmware', 'alsa-ucm-conf-asahi', 'pipewire', 'wireplumber', 'bankstown', 'triforce-lv2'))
SEMANTIC = ('NAME', 'VERSION', 'ARCH', 'DEPENDS', 'PROVIDES', 'CONFLICTS', 'REPLACES', 'LICENSE')


def inspection(argv, *, env=None):
    need(argv[0] == 'bsdtar' and argv[1] in ('-tf', '-xOf'), 'only existing inert archive metadata inspection permitted')
    process = subprocess.run(['/usr/bin/bsdtar', *map(str, argv[1:])], capture_output=True, timeout=20,
                             env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
    need(process.returncode == 0 and len(process.stdout) + len(process.stderr) <= 1024**2, 'archive metadata inspection failed/output bound')
    return process.stdout


# A private imported reader object; the existing source is unchanged. Its parser
# runs only the two bounded read-only bsdtar operations above, never payloads.
r.run = inspection
spec = importlib.util.spec_from_file_location('supported_maintenance_proposal', Path(__file__).with_name('maintenance.py'))
maintenance = importlib.util.module_from_spec(spec); spec.loader.exec_module(maintenance)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Reader:
    def __init__(self):
        self.refs, self.raw = {}, {}
        self.started = time.monotonic()

    def read(self, ref):
        need(set(ref) == {'path', 'size', 'sha256'}, 'exact path/size/SHA256 reference required')
        path = Path(ref['path'])
        need(path.is_absolute() and not any(item.is_symlink() for item in (path, *path.parents)), 'unaliased absolute DATA reference required')
        need(type(ref['size']) is int and 0 < ref['size'] <= t.LIMIT and re.fullmatch('[0-9a-f]{64}', ref['sha256']), 'bounded DATA pin required')
        need(time.monotonic() - self.started <= 120, 'composition DATA deadline exceeded')
        if str(path) in self.refs:
            need(self.refs[str(path)] == ref, 'contradictory DATA references')
            return self.raw[str(path)]
        row = path.lstat()
        need(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and not row.st_mode & 0o022, 'ordinary non-writable DATA required')
        raw = t.bound(ref)
        need(path.lstat() == row, 'DATA changed during read')
        self.refs[str(path)], self.raw[str(path)] = dict(ref), raw
        need(sum(map(len, self.raw.values())) <= 64 * 1024**2, 'aggregate DATA input bound')
        return raw

    def document(self, ref):
        return t.tuple_audit.load_json(self.read(ref))

    def recheck(self):
        for name, ref in self.refs.items():
            need(t.bound(ref) == self.raw[name], 'DATA drift before result publication')


def srcinfo(raw):
    """Single-package SRCINFO only; no shell evaluation or guessed split inheritance."""
    need(len(raw) <= 1024**2, 'SRCINFO size bound')
    fields = {}
    for line in raw.decode('utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition(' = ')
        need(sep and re.fullmatch('[a-z0-9_]+', key) and value and len(value) <= 16384
             and not re.search('[\x00-\x1f]', value), 'invalid SRCINFO data line')
        fields.setdefault(key, []).append(value)
    single = lambda key: fields[key][0] if len(fields.get(key, [])) == 1 else None
    name, version, release, base = (single(key) for key in ('pkgname', 'pkgver', 'pkgrel', 'pkgbase'))
    need(all((name, version, release, base)), 'single-package complete SRCINFO identity required')
    arch = fields.get('arch', [])
    need(arch in (['aarch64'], ['any']), 'one explicit aarch64/any SRCINFO architecture required')
    epochs = fields.get('epoch', ['0'])
    need(len(epochs) == 1 and re.fullmatch('[0-9]+', epochs[0]), 'invalid SRCINFO epoch')
    metadata = {'NAME': [name], 'BASE': [base], 'VERSION': [((epochs[0] + ':') if int(epochs[0]) else '') + version + '-' + release], 'ARCH': arch}
    for source, destination in (('depends', 'DEPENDS'), ('provides', 'PROVIDES'), ('conflicts', 'CONFLICTS'), ('replaces', 'REPLACES')):
        metadata[destination] = fields.get(source, []) + fields.get(source + '_aarch64', [])
    for source, destination in (('license', 'LICENSE'), ('pkgdesc', 'DESC'), ('url', 'URL')):
        if source in fields:
            metadata[destination] = fields[source]
    t.clean(metadata)
    return metadata, {'representation': 'SRCINFO-declared metadata-only DB row; not an archive',
                      'declared_source_entries': len(fields.get('source', [])) + len(fields.get('source_aarch64', [])),
                      'ignored_fields': sorted(set(fields) - {'pkgbase', 'pkgname', 'pkgver', 'pkgrel', 'epoch', 'arch', 'license', 'pkgdesc', 'url',
                          'depends', 'provides', 'conflicts', 'replaces', 'depends_aarch64', 'provides_aarch64', 'conflicts_aarch64', 'replaces_aarch64'})}


def pin(row):
    need(isinstance(row, dict) and set(row) == {'name', 'version', 'repo'}, 'exact name/version/repository pin required')
    need(all(isinstance(row[key], str) and row[key] for key in row), 'invalid identity pin')
    t.preview.check({'NAME': [row['name']], 'VERSION': [row['version']], 'ARCH': ['aarch64']})
    return dict(row)


def clean_metadata(row):
    row = {key: value for key, value in row.items() if key != 'repo'}
    t.clean(row)
    return row


def worker_diagnostic(stderr):
    """Expose bounded escaped errors without printing the private input DATA."""
    prefix = b'SUPPORTED_COMPOSITION_ERROR '
    for line in reversed(stderr[-8192:].splitlines()):
        if line.startswith(prefix):
            try:
                value = json.loads(line[len(prefix):])
                if (set(value) == {'category', 'message'}
                        and isinstance(value['category'], str)
                        and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}', value['category'])
                        and isinstance(value['message'], str) and len(value['message']) <= 512):
                    return json.dumps(value, ensure_ascii=True, separators=(',', ':'))
            except (ValueError, TypeError):
                pass
    # Import failures and C-library diagnostics may precede the structured
    # handler. Escape all control/non-ASCII bytes and retain only the final tail.
    return json.dumps({'stderr_tail': stderr[-512:].decode('utf-8', errors='backslashreplace')},
                      ensure_ascii=True, separators=(',', ':'))


def prepare_isolated(work, image, protected, catalogs, targets, output):
    """Contain trusted C metadata preparation; no new general process supervisor."""
    fields = set(SEMANTIC) | {'FILENAME', 'CSIZE', 'ISIZE', 'SHA256SUM'}
    compact = lambda row: {key: value for key, value in row.items() if key in fields}
    value = {'image': {name: compact(row) for name, row in image.items()}, 'protected': protected,
             'catalogs': {repo: {name: compact(row) for name, row in rows.items()} for repo, rows in catalogs.items()},
             'targets': targets}
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    need(len(raw) <= 64 * 1024**2, 'private engine DATA size bound')
    source = work / 'prepare-data.json'
    t.write_bytes(source, raw)
    t.write_bytes(output / 'preparation-inputs.json', raw)
    try:
        process = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).with_name('prepare_worker.py')), str(source)],
            capture_output=True, timeout=90, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'})
    except subprocess.TimeoutExpired as error:
        t.write_bytes(output / 'prepare.stdout', error.stdout or b'')
        t.write_bytes(output / 'prepare.stderr', error.stderr or b'')
        raise ValueError('private libalpm worker timed out; DATA and diagnostics retained') from None
    t.write_bytes(output / 'prepare.stdout', process.stdout)
    t.write_bytes(output / 'prepare.stderr', process.stderr)
    need(process.returncode == 0 and len(process.stdout) + len(process.stderr) <= 16 * 1024**2,
         'private libalpm worker failed (exit ' + str(process.returncode) + '): '
         + worker_diagnostic(process.stderr) + '; DATA and diagnostics retained')
    result = t.tuple_audit.load_json(process.stdout)
    need(set(result) == {'prepare', 'dependencies', 'conflicts'}, 'private worker result fields refused')
    return result


def compose(contract, output, reader=None, maintenance_ref=None, contract_ref=None):
    need(set(contract) == {'schema_version', 'kind', 'workflow', 'image_inventory', 'protected_tuple', 'catalogs',
                          'candidate_srcinfo', 'roots', 'providers', 'allowed_base_changes'}
         and contract['schema_version'] == 1 and contract['kind'] == 'supported-Asahi-composition-inputs-v1'
         and contract['workflow'] in ('project-extension', 'full-desktop'), 'composition contract refused')
    need(output.is_absolute() and not any(path.is_symlink() for path in (output, *output.parents)), 'new absolute output directory required')
    output.mkdir(mode=0o700, exist_ok=False)
    reader = reader or Reader()
    report = {'schema_version': 1, 'kind': 'supported-Asahi-composition-DATA-proposal', 'status': 'FAIL',
              'metadata_prepare_status': 'FAIL', 'workflow': contract['workflow'], 'blockers': [], 'holds': [],
              'transaction_accepted': False, 'full_supported_system_accepted': False,
              'system_mutation': False, 'payload_execution': False, 'network_used': False,
              'native_build': 'NOT RUN', 'installation': 'NOT RUN', 'hardware': 'NOT RUN',
              'source_sha256': {str(Path(path).relative_to(ROOT)): t.preview.digest(path)
                  for path in (__file__, maintenance.__file__, Path(__file__).with_name('prepare_worker.py'), t.__file__, t.preview.__file__, t.tuple_audit.__file__, r.__file__)}}
    def block(code, **details):
        report['blockers'].append({'code': code, **details})
    try:
        image_doc = reader.document(contract['image_inventory'])
        tuple_doc = reader.document(contract['protected_tuple'])
        need(image_doc.get('kind') == 'observed-image-local-package-metadata'
             and tuple_doc.get('kind') == 'offline-platform-metadata-witnesses'
             and tuple_doc['input_sha256']['image'] == contract['image_inventory']['sha256'], 'actual image/protected tuple binding refused')
        image = t.tuple_audit.packages([clean_metadata(row['metadata']) for row in image_doc['packages']])
        original = tuple_doc['proposed_installed_dependency_graph']
        need(isinstance(original, list) and 0 < len(original) <= 4096, 'finite original protected tuple required')
        protected = {}
        for row in original:
            need(set(row) == {'name', 'version'} and row['name'] not in protected
                 and image.get(row['name'], {}).get('VERSION') == [row['version']], 'protected tuple/image identity differs')
            protected[row['name']] = row['version']
        for name in PLATFORM & image.keys():
            protected[name] = image[name]['VERSION'][0]
        report.update(image_package_count=len(image), original_protected_count=len(original), protected_package_count=len(protected))
        for name in set(t.tuple_audit.BOOT) - image.keys():
            block('missing-Asahi-boot-anchor', package=name)
        catalogs, pristine_catalogs, provenance, diagnostics = {}, {}, {}, []
        refs = contract['catalogs']
        need(isinstance(refs, list) and [row.get('name') for row in refs] == ['asahi-alarm', 'core', 'extra'], 'explicit ordered Asahi/core/extra catalogs required')
        for ref in refs:
            need(set(ref) == {'name', 'path', 'size', 'sha256'}, 'catalog reference fields refused')
            name = ref['name']
            source = {key: value for key, value in ref.items() if key != 'name'}
            grouped = t.repository_records(reader.read(source), diagnostics, name)
            catalogs[name] = {}
            pristine_catalogs[name] = {}
            need(len(grouped) <= 32768, 'catalog package count bound')
            for entry, raw in grouped.items():
                try:
                    metadata = clean_metadata(raw)
                except ValueError as error:
                    diagnostics.append({'repo': name, 'entry': entry, 'reason': str(error), 'selectable': False})
                    continue
                package = metadata['NAME'][0]
                need(package not in catalogs[name], 'duplicate catalog package identity')
                filename = metadata.get('FILENAME', [])
                if len(filename) != 1 or not filename[0] or Path(filename[0]).name != filename[0]:
                    diagnostics.append({'repo': name, 'entry': entry, 'reason': 'missing/unsafe real catalog archive filename; unavailable', 'selectable': False})
                    continue
                pristine_catalogs[name][package] = metadata
                provenance[(name, package)] = {'kind': 'retained-catalog-declaration', 'reference': source, 'entry': entry}
                if package == 'mesa-dummy' or package in protected and metadata['VERSION'] != [protected[package]]:
                    diagnostics.append({'repo': name, 'entry': entry, 'reason': 'protected-version/mesa-dummy excluded', 'selectable': False})
                    continue
                catalogs[name][package] = metadata
                provenance[(name, package)] = {'kind': 'retained-catalog-declaration', 'reference': source, 'entry': entry}
        report['catalog_diagnostics'] = diagnostics
        report['holds'].extend({'origin': 'excluded-catalog-entry', 'repo': row.get('repo'), 'entry': row.get('entry'),
                                'selectable': False, 'facts': [row['reason']]} for row in diagnostics)
        catalogs['project'] = {}
        candidates = contract['candidate_srcinfo']
        need(isinstance(candidates, list) and 0 < len(candidates) <= 64, 'finite current candidate SRCINFO set required')
        report['current_candidates'] = []
        for item in candidates:
            if set(item) == {'path', 'size', 'sha256'}:
                ref, archive, scope = item, None, 'MISSING'
            else:
                need(set(item) == {'srcinfo', 'archive', 'archive_scope'} and item['archive_scope'] in
                     ('host-assembled-unqualified', 'retained-native-development-unqualified', 'synthetic-test-only'), 'candidate DATA source/archive fields refused')
                ref, archive, scope = item['srcinfo'], item['archive'], item['archive_scope']
            metadata, notes = srcinfo(reader.read(ref))
            name = metadata['NAME'][0]
            need(all(row['name'] != name for row in report['current_candidates']), 'duplicate project SRCINFO identity')
            candidate = {'name': name, 'version': metadata['VERSION'][0], 'srcinfo': ref,
                         'archive_scope': scope, 'archive_reference': archive, 'signature_reference': None,
                         'representation': 'source-declared metadata; archive/source correspondence requires actual matching PKGINFO'}
            report['current_candidates'].append(candidate)
            if archive is None:
                candidate['status'] = 'HOLD-missing-exact-candidate-archive'
                report['holds'].append({'package': name, 'facts': ['exact-candidate-archive-missing; no DB row fabricated']})
                continue
            raw = reader.read(archive)
            filename = Path(archive['path']).name
            need(re.fullmatch('[A-Za-z0-9][A-Za-z0-9+_.:@-]*', filename)
                 and filename.endswith(('.pkg.tar.xz', '.pkg.tar.zst', '.pkg.tar.gz')), 'real safe candidate archive filename required')
            with tempfile.TemporaryDirectory(prefix='private-candidate-metadata-', dir=output) as temporary:
                captured = Path(temporary) / filename
                captured.write_bytes(raw)
                actual = r.pkginfo(captured)
            for key, source in (('NAME', 'name'), ('VERSION', 'version'), ('ARCH', 'arch')):
                need(metadata[key] == [actual[source]], 'SRCINFO/archive identity differs: ' + name + '/' + key)
            for key, source in (('DEPENDS', 'depend'), ('PROVIDES', 'provides'), ('CONFLICTS', 'conflict'), ('REPLACES', 'replaces'), ('LICENSE', 'license')):
                need(sorted(metadata.get(key, [])) == sorted(actual.get(source, [])), 'SRCINFO/archive relations differ: ' + name + '/' + key)
            metadata.update(FILENAME=[filename], CSIZE=[str(len(raw))], SHA256SUM=[archive['sha256']])
            candidate['status'] = 'PKGINFO-correspondence-only; custody/signature/native/source-review HOLD'
            catalogs['project'][name] = metadata
            provenance[('project', name)] = {'kind': 'source-declared-candidate-with-real-archive-PKGINFO', 'reference': ref,
                'archive_reference': archive, 'archive_scope': scope, 'signature_reference': None, **notes}
        pristine_catalogs['project'] = dict(catalogs['project'])
        targets, by_name = [], {}
        def target(row):
            identity = pin(row)
            old = by_name.get(identity['name'])
            need(old is None or old == identity, 'contradictory explicit target/provider pins')
            if old is None:
                targets.append(identity); by_name[identity['name']] = identity
        need(isinstance(contract['roots'], list) and 0 < len(contract['roots']) <= 128, 'explicit finite roots required')
        for row in contract['roots']:
            target(row)
        versions = t.tuple_audit.Versions()
        need(isinstance(contract['providers'], list) and len(contract['providers']) <= 64, 'finite explicit provider bindings required')
        provider_checks, provider_requirements = [], set()
        for row in contract['providers']:
            need(set(row) == {'requirement', 'name', 'version', 'repo'}, 'provider requirement/exact identity required')
            need(row['requirement'] not in provider_requirements, 'duplicate/contradictory provider requirement binding')
            provider_requirements.add(row['requirement'])
            identity = {key: row[key] for key in ('name', 'version', 'repo')}
            target(identity)
            metadata = image.get(row['name']) if row['repo'] == 'observed-Asahi-base' else catalogs.get(row['repo'], {}).get(row['name'])
            witness = bool(metadata and metadata['VERSION'] == [row['version']]
                           and t.tuple_audit.witnesses(row['requirement'], {row['name']: metadata}, versions))
            provider_checks.append({**row, 'declared_witness_matches': witness})
            if not witness:
                block('explicit-provider-unavailable-or-incompatible', provider=row)
        allowed = {}
        need(isinstance(contract['allowed_base_changes'], list) and len(contract['allowed_base_changes']) <= 256, 'finite exact base-change policy required')
        for row in contract['allowed_base_changes']:
            need(set(row) == {'name', 'before', 'after', 'repo'} and row['name'] not in allowed
                 and image.get(row['name'], {}).get('VERSION') == [row['before']], 'exact baseline-bound change policy required')
            allowed[row['name']] = row
            if row['name'] in protected:
                block('protected-base-policy-cannot-relax-original-tuple', policy=row)
        for row in targets:
            metadata = image.get(row['name']) if row['repo'] == 'observed-Asahi-base' else catalogs.get(row['repo'], {}).get(row['name'])
            if not metadata or metadata['VERSION'] != [row['version']]:
                block('exact-target-pin-unavailable', target=row)
            if row['repo'] == 'project' and image.get(row['name'], {}).get('VERSION') == [row['version']]:
                block('same-version-project-root-needs-explicit-reinstall-plan', target=row)
        with tempfile.TemporaryDirectory(prefix='private-supported-composition-', dir=output) as temporary:
            work = Path(temporary)
            for name in ('root', 'db/sync', 'cache', 'gpg', 'hooks'):
                (work / name).mkdir(parents=True, mode=0o700)
            engine = prepare_isolated(work, image, protected, catalogs, targets, output)
            prepared = engine['prepare']
            report['prepare'] = prepared
            final, origins = dict(image), {name: 'observed-Asahi-base' for name in image}
            for row in prepared['remove']:
                final.pop(row['name'], None); origins.pop(row['name'], None)
            for row in prepared['add']:
                metadata = catalogs[row['repo']][row['name']]
                need(metadata['VERSION'] == [row['version']], 'prepared addition/catalog identity differs')
                final[row['name']], origins[row['name']] = metadata, row['repo']
            relations, conflicts = engine['dependencies'], engine['conflicts']
        if prepared['prepare_exit'] or prepared['errors'] or prepared['callback_errors']:
            block('libalpm-preparation-incomplete', errors=prepared['errors'], errno=prepared['prepare_errno'])
        for row in prepared['questions']:
            if row.get('type') == 32 and row.get('policy') != 'explicit-root-provider':
                block('unapproved-provider-choice', question=row)
        report['roots'] = [{**row, 'final_version': final.get(row['name'], {}).get('VERSION', [None])[0],
                            'satisfied': final.get(row['name'], {}).get('VERSION') == [row['version']]} for row in targets]
        for row in report['roots']:
            if not row['satisfied']:
                block('explicit-root-unsatisfied', root=row)
        report['base_changes'] = []
        for name in sorted(image):
            before, after = image[name]['VERSION'][0], final.get(name, {}).get('VERSION', [None])[0]
            if before != after:
                proposed = {'name': name, 'before': before, 'after': after, 'repo': origins.get(name)}
                accepted = name not in protected and after is not None and allowed.get(name) == proposed
                report['base_changes'].append({**proposed, 'explicit_policy_matches': accepted})
                if not accepted:
                    block('unapproved-base-change', **proposed)
        report['protected'] = [{'name': name, 'expected': version, 'final': final.get(name, {}).get('VERSION', [None])[0],
                                'preserved': final.get(name, {}).get('VERSION') == [version]} for name, version in sorted(protected.items())]
        for row in report['protected']:
            if not row['preserved']:
                block('protected-anchor-changed', decision=row)
        for row in relations:
            if row['provider'] is None:
                block('final-dependency-unresolved', dependency=row)
        for row in conflicts:
            block('final-declared-conflict', conflict=row)
        for row in provider_checks:
            present = final.get(row['name'])
            row['final_witness_matches'] = bool(present and present['VERSION'] == [row['version']]
                and t.tuple_audit.witnesses(row['requirement'], {row['name']: present}, versions))
            if not row['final_witness_matches']:
                block('final-explicit-provider-unsatisfied', provider=row)
        if contract['workflow'] == 'full-desktop':
            for name in sorted(PLATFORM - final.keys()):
                block('required-platform-member-missing', package=name)
        report.update(provider_bindings=provider_checks, dependencies=relations, catalog_diagnostics=diagnostics,
                      final_package_count=len(final), added_package_count=len(set(final) - set(image)))
        packages = []
        for name, metadata in sorted(final.items()):
            origin = origins[name]
            proof = provenance.get((origin, name), {'kind': 'observed-image-local-metadata', 'reference': contract['image_inventory']})
            packages.append({'name': name, 'version': metadata['VERSION'][0], 'repo': origin,
                             'metadata': metadata, 'provenance': proof})
            report['holds'].append({'package': name, 'origin': proof['kind'],
                'facts': ['archive-custody-unverified', 'signature-authentication-NOT-RUN', 'installed-payload-correspondence-unverified',
                          'source-license-grant-maintainer-review-incomplete', 'file-ownership-hook-effects-unverified']
                         + (['SRCINFO-recipe-archive-correspondence-unverified', 'native-build-NOT-RUN'] if origin == 'project' else [])})
        report['proposed_final_inventory'] = packages
        report['metadata_prepare_status'] = 'FAIL' if report['blockers'] else 'PASS'
        report['status'] = 'FAIL' if report['blockers'] else 'HOLD'
        report['input_references'] = list(reader.refs.values())
        report['policy_scope'] = 'caller-supplied exact unprotected base changes only; original protected list never relaxed; compatibility NOT accepted'
        if maintenance_ref is not None:
            report['original_policy'] = {key: report[key] for key in
                ('status', 'metadata_prepare_status', 'blockers', 'base_changes', 'protected_package_count', 'final_package_count')}
            report['proposed_maintenance'] = maintenance.evaluate(maintenance_ref, contract_ref, contract, reader, output,
                image=image, protected=protected, catalogs=pristine_catalogs, targets=targets, provenance=provenance,
                tx=t, prepare=prepare_isolated, platform=PLATFORM)
            report.update(status='HOLD', approval_status='UNAPPROVED', original_policy_failure_retained=bool(report['blockers']))
        reader.recheck()
    except BaseException as error:
        report.update(status='FAIL', metadata_prepare_status='FAIL', error=str(error) or type(error).__name__)
        raise
    finally:
        report['input_references'] = list(reader.refs.values())
        report['elapsed_seconds'] = time.monotonic() - reader.started
        report['private_database_removed'] = not any(output.rglob('private-supported-composition-*'))
        raw = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
        need(len(raw) <= 16 * 1024**2, 'composition report size bound')
        t.write_bytes(output / 'composition.json', raw)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract', type=Path, required=True)
    parser.add_argument('--contract-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--maintenance-proposal', type=Path)
    parser.add_argument('--maintenance-proposal-sha256')
    args = parser.parse_args()
    try:
        reader = Reader()
        ref = {'path': str(args.contract.absolute()), 'size': args.contract.stat().st_size, 'sha256': args.contract_sha256}
        need(bool(args.maintenance_proposal) == bool(args.maintenance_proposal_sha256), 'both maintenance proposal path and SHA256 required')
        proposal = None if args.maintenance_proposal is None else {'path': str(args.maintenance_proposal.absolute()),
            'size': args.maintenance_proposal.stat().st_size, 'sha256': args.maintenance_proposal_sha256}
        report = compose(reader.document(ref), args.output, reader=reader, maintenance_ref=proposal, contract_ref=ref)
        summary = {key: report[key] for key in ('status', 'metadata_prepare_status', 'image_package_count', 'final_package_count', 'added_package_count')}
        proposed = report.get('proposed_maintenance')
        if proposed: summary.update(approval_status='UNAPPROVED', proposed_metadata_prepare_status=proposed['metadata_prepare_status'])
        print(json.dumps(summary, sort_keys=True))
        return 2 if (proposed or report)['metadata_prepare_status'] == 'PASS' else 1
    except (ValueError, OSError, KeyError, TypeError, r.Error, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
