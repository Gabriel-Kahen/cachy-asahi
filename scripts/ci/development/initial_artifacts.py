#!/usr/bin/env python3
"""Receive three exact initial producers' receipt-bound development artifacts.

No extraction, GPG import, signature execution or repository acceptance occurs.
Public OpenPGP syntax and original receipt bindings are independently checked.
"""
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat

from common import digest, read_json, read_regular, require

KINDS = {'fixture-archives', 'signer-public-artifacts', 'repository-public-artifacts'}
RECIPES = {'cachy-asahi-hyprland-settings': 'packages/desktop/cachy-asahi-hyprland-settings',
           'cachy-asahi-fish-config': 'packages/shells/cachy-asahi-fish-config',
           'cachy-asahi-zsh-config': 'packages/shells/cachy-asahi-zsh-config',
           'cachy-asahi-setup': 'packages/settings/cachy-asahi-setup'}
ORIGINALS = set(RECIPES)
LABELS = {'baseline-A', 'updated-B', 'tampered-package-B', 'tampered-database-B',
          'missing-database-signature-B', 'missing-package-signature-B'}
CERTS = {'TEST-signer-A-public.asc', 'TEST-signer-B-public.asc', 'TEST-verifier-public.asc', 'TEST-signer-A-revoked-public.asc'}
# repo-add signs these gzip databases; its normalized signature symlinks are
# exported as receipt-bound regular copies. The negative case removes both DB
# signatures. Packages and the alias record retain the SHA256-only policy.
DATABASE_SIGNATURES = frozenset('TEST-repositories/' + label + '/' + name
    for label in LABELS for name in ('integration.db.tar.gz.sig', 'integration.db.sig',
                                     'integration.files.tar.gz.sig', 'integration.files.sig')
    if label != 'missing-database-signature-B' or name.startswith('integration.files'))
PUBLIC_SOURCE_AUDITS = {'runtime-dependency-observation.json', 'arm-dependency-audit.json', 'dependency-observation.json'}
PIN = re.compile(r'[0-9a-f]{64}\Z')
FILE_LIMIT, TOTAL_LIMIT = 8 * 1024**2, 12 * 1024**2


def public_policy(root):
    # Load only declarative regex/suffix constants; importing the integration
    # controller or its bare common dependencies is unnecessary.
    scope = {'re': re}
    wanted = {'PRIVATE_CONTENT', 'SENSITIVE_PATH', 'SUFFIXES'}
    for node in ast.parse(read_regular(root / 'scripts/ci/integration_export.py').decode()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in wanted:
            exec(compile(ast.Module(body=[node], type_ignores=[]), '<public-policy>', 'exec'), scope)
    require(wanted <= scope.keys(), 'public-policy-unavailable')
    return scope


def certificate(root, data):
    # Execute the unchanged pure parser with only its declared dependencies.
    tree = ast.parse(read_regular(root / 'scripts/ci/sign_fixture.py').decode())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'public_certificate')
    import base64
    scope = {'base64': base64, 'LIMIT': 4 * 1024**2, 'need': require}
    exec(compile(ast.Module(body=[node], type_ignores=[]), '<public-certificate>', 'exec'), scope)
    scope['public_certificate'](data)


def relative(name, policy, sensitive=True):
    require(isinstance(name, str) and name and len(name) <= 256 and '\\' not in name and
            all(32 <= ord(c) < 127 for c in name), 'unsafe-artifact-path')
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name and all(p not in ('', '.', '..') for p in name.split('/')) and
            (not sensitive or not any(policy['SENSITIVE_PATH'].search(p) for p in path.parts)), 'sensitive-artifact-path')
    return path


def signature(data, policy, *, kind=None, name=None):
    require(0 < len(data) <= 8192 and not policy['PRIVATE_CONTENT'].search(data.decode('latin-1')), 'private-or-unbounded-signature')
    header, offset = data[0], 1
    require(header & 128 and (header & 63 if header & 64 else (header >> 2) & 15) == 2, 'signature-packet-required')
    if header & 64:
        require(offset < len(data), 'truncated-signature')
        length = data[offset]; offset += 1
        if length < 192:
            size = length
        elif length < 224:
            require(offset < len(data), 'truncated-signature')
            size = ((length - 192) << 8) + data[offset] + 192; offset += 1
        elif length == 255:
            require(offset + 4 <= len(data), 'truncated-signature')
            size = int.from_bytes(data[offset:offset + 4], 'big'); offset += 4
        else:
            raise ValueError('partial-signature-refused')
    else:
        width = (1, 2, 4, 0)[header & 3]
        require(width and offset + width <= len(data), 'indeterminate-signature-refused')
        size = int.from_bytes(data[offset:offset + width], 'big'); offset += width
    hashes = (8, 10) if kind == 'repository-public-artifacts' and name in DATABASE_SIGNATURES else (8,)
    require(size >= 13 and offset + size == len(data) and data[offset:offset + 2] == bytes((4, 0)) and data[offset + 2] in (1, 22) and data[offset + 3] in hashes,
            'one-binary-reviewed-path-digest-signature-required')
    body = data[offset:]; position = 4
    for _ in range(2):
        require(position + 2 <= len(body), 'truncated-signature-subpackets')
        length = int.from_bytes(body[position:position + 2], 'big'); position += 2 + length
        require(position <= len(body), 'truncated-signature-subpackets')
    position += 2  # First two bytes of the signed hash.
    for _ in range(1 if body[2] == 1 else 2):
        require(position + 2 <= len(body), 'truncated-signature-mpi')
        bits = int.from_bytes(body[position:position + 2], 'big'); position += 2
        length = (bits + 7) // 8; mpi = body[position:position + length]; position += length
        # Legacy Ed25519 R/S are opaque octet strings inside MPI framing;
        # their significant-bit count need not be canonical integer encoding.
        require(0 < bits <= (8192 if body[2] == 1 else 264) and len(mpi) == length and
                (body[2] == 22 or int.from_bytes(mpi, 'big').bit_length() == bits), 'signature-mpi-refused')
    require(position == len(body), 'extra-signature-packet-or-bytes-refused')


def fixture_rows(root, evidence, commit, policy):
    rows = read_json(evidence / 'work/fixtures-raw/archives.json')
    manifest_path = evidence / 'work/fixtures/fixture-manifest.json'
    generated = read_json(manifest_path)
    # The accepted source packet authenticates ROOT's frozen initial lock. Its
    # recipe-origin commit deliberately differs from the workflow source commit.
    lock = read_json(root / 'scripts/ci/integration.lock.json')
    recipes = read_json(root / 'scripts/ci/recipes.lock.json')
    generator = digest(root / 'scripts/integration/fixtures.py')
    frozen_manifest = lock.get('generated_fixture_files', {}).get('fixture-manifest.json', {})
    frozen_generator = lock.get('source_files', {}).get('scripts/integration/fixtures.py', {})
    require(frozen_manifest.get('mode') == stat.S_IMODE(manifest_path.lstat().st_mode) == 0o644 and
            frozen_generator.get('mode') == stat.S_IMODE((root / 'scripts/integration/fixtures.py').lstat().st_mode),
            'fixture-authority-mode-refused')
    require(type(lock.get('schema_version')) is int and lock['schema_version'] == 1 and
            lock.get('purpose') == 'frozen-development-only-native-integration' and
            lock.get('development_only') is True and lock.get('selected_for_release') is False and
            re.fullmatch('[0-9a-f]{40}', lock.get('recipe_source_commit', '')) and
            lock.get('recipes_sha256') == digest(root / 'scripts/ci/recipes.lock.json') and
            lock.get('source_files', {}).get('scripts/integration/fixtures.py', {}).get('sha256') == generator and
            lock.get('generated_fixture_files', {}).get('fixture-manifest.json', {}).get('sha256') == digest(manifest_path),
            'frozen-fixture-authority-refused')
    require(generated.get('schema_version') == 1 and generated.get('source_commit') == lock['recipe_source_commit'] and
            generated.get('frozen_lock_sha256') == lock['recipes_sha256'] and generated.get('generator_sha256') == generator and
            generated.get('source_date_epoch') == lock.get('source_date_epoch') and
            generated.get('development_only') is True and generated.get('selected_for_release') is False and
            set(generated.get('packages', {})) == ORIGINALS and set(rows) == {'baseline', 'upgrade'}, 'fixture-source-binding-refused')
    for stage in ('baseline', 'upgrade'):
        require(isinstance(rows[stage], list) and len(rows[stage]) == 4 and all(isinstance(r, dict) for r in rows[stage]) and
                {r.get('name') for r in rows[stage]} == ORIGINALS, 'exact-fixture-roles-required')
        for row in rows[stage]:
            require(set(row) == {'name', 'version', 'sha256', 'payload_sha256', 'archive'}, 'fixture-row-fields-refused')
            metadata = generated['packages'][row['name']]
            require(metadata.get('recipe') == RECIPES[row['name']] and
                    metadata.get('base_inputs_sha256') == recipes[RECIPES[row['name']]], 'fixture-recipe-map-refused')
            for name, pin in recipes[RECIPES[row['name']]].items():
                relative(name, policy, sensitive=name not in PUBLIC_SOURCE_AUDITS)
                require(isinstance(pin, str) and PIN.fullmatch(pin) and
                        digest(root / RECIPES[row['name']] / name) == pin, 'fixture-recipe-source-drift')
            version = metadata['base_version' if stage == 'baseline' else 'upgrade_version']
            require(row.get('version') == version and re.fullmatch(r'[A-Za-z0-9._+:~\-]+', version) and
                    isinstance(row.get('sha256'), str) and PIN.fullmatch(row['sha256']), 'fixture-version-or-hash-refused')
            path = relative(row['archive'], policy)
            require(len(path.parts) == 2 and path.parts[0] == stage and re.fullmatch(
                re.escape(row['name'] + '-' + version.split(':')[-1] + '-any.pkg.tar.') + '(?:xz|zst|gz)', path.name), 'fixture-archive-role-refused')
            require(isinstance(row.get('payload_sha256'), dict) and row['payload_sha256'] and
                    all(str(relative(n, policy)).startswith('usr/') and isinstance(p, str) and PIN.fullmatch(p)
                        for n, p in row['payload_sha256'].items()), 'fixture-payload-refused')
    return rows


def repository_allowed(name):
    if name in CERTS or name in ('TEST-repository-aliases.json', 'TEST-repository-aliases.json.sig', 'TEST-pacman.conf'):
        return True
    path = PurePosixPath(name)
    if len(path.parts) != 3 or path.parts[0] != 'TEST-repositories' or path.parts[1] not in LABELS:
        return False
    return bool(re.fullmatch(r'integration\.(?:db|files)(?:\.tar\.(?:gz|xz|zst))?(?:\.sig)?', path.name) or
        re.fullmatch('(?:' + '|'.join(map(re.escape, sorted(ORIGINALS | {'cachy-asahi-repository-test-fixture'}))) +
                     r')-[A-Za-z0-9._+:-]+\.pkg\.tar\.(?:gz|xz|zst)(?:\.sig)?', path.name))


def signer_authority(evidence, rows, initial, policy):
    receipt = read_json(evidence / 'work/signer-raw/test-signature-receipt.json')
    manifest_path = evidence / 'work/archive-inputs/archive-manifest.json'
    manifest = read_json(manifest_path)
    expected = [{k: row[k] for k in ('name', 'version', 'sha256')} |
                {'path': row['archive'], 'role': 'original' if stage == 'baseline' else 'upgrade-fixture'}
                for stage in ('baseline', 'upgrade') for row in rows[stage]]
    require(manifest == {'schema_version': 1, 'purpose': 'TEST-ONLY-integration-signatures',
                        'source_commit': initial['source_commit'], 'archives': expected}, 'signer-manifest-binding-refused')
    contract = receipt.get('contract', {})
    require(receipt.get('status') == 'TEST-SIGNATURES PASS' and receipt.get('purpose') == 'TEST-ONLY-integration-signatures' and
            receipt.get('production_credentials_used') is False and receipt.get('hardware_status') == 'NOT RUN' and
            contract.get('manifest_sha256') == digest(manifest_path) and contract.get('image_id') == initial['base_image'] and
            re.fullmatch(r'[0-9A-F]{40}', receipt.get('fingerprint', '')) and type(receipt.get('expiry')) is int and receipt['expiry'] > 0 and
            set(receipt.get('signatures', {})) == {r['path'] for r in expected}, 'signer-receipt-binding-refused')
    approved = {'public-key.asc': receipt['public_certificate_sha256']}
    for row in expected:
        record = receipt['signatures'][row['path']]
        require(set(record) == {'archive_sha256', 'signature_sha256', 'status'} and record['archive_sha256'] == row['sha256'],
                'signer-archive-binding-refused')
        records = [line.split()[1:] for line in record['status'].splitlines() if line.startswith('[GNUPG:] ')]
        valid = [r for r in records if r and r[0] == 'VALIDSIG']
        require(not any(r and r[0] in ('EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG', 'NO_PUBKEY') for r in records) and
                len(valid) == 1 and len(valid[0]) == 11 and valid[0][1] == valid[0][-1] == receipt['fingerprint'], 'signer-validsig-binding-refused')
        approved['signatures/' + row['path'] + '.sig'] = record['signature_sha256']
    return approved, receipt, {r['path']: r['sha256'] for r in expected}


def repository_rows(root, evidence, rows, initial, policy):
    require(initial.get('stages', {}).get('signer', {}).get('status') == 'PASS', 'successful-initial-signer-required')
    approved, _, _ = signer_authority(evidence, rows, initial, policy)
    public = evidence / 'work/test-signatures/public'
    for name, pin in approved.items():
        relative(name, policy)
        require(isinstance(pin, str) and PIN.fullmatch(pin), 'original-signer-pin-required')
        path = public / name
        data = read_regular(path, 4 * 1024**2 if name == 'public-key.asc' else 8192)
        require(stat.S_IMODE(path.lstat().st_mode) == 0o644 and hashlib.sha256(data).hexdigest() == pin,
                'original-signer-byte-or-mode-binding-refused')
        if name == 'public-key.asc':
            certificate(root, data)
        else:
            # Bind the original signer bytes, never the repository's independently
            # regenerated signatures. These package signatures remain SHA256.
            signature(data, policy)
    return {stage: [row | {'signature_sha256': approved['signatures/' + row['archive'] + '.sig']}
                    for row in rows[stage]] for stage in ('baseline', 'upgrade')}


def receive(root, evidence, directory):
    root, evidence, directory = map(lambda p: Path(p).absolute(), (root, evidence, directory))
    require(directory.name in KINDS and directory == evidence / 'public' / directory.name, 'unknown-initial-artifact-directory')
    require('..' not in evidence.parts and all(stat.S_ISDIR(p.lstat().st_mode) for p in (directory, *directory.parents)), 'real-artifact-directories-required')
    policy = public_policy(root)
    initial = read_json(evidence / 'result.json')
    require(type(initial.get('schema_version')) is int and initial['schema_version'] == 1 and
            initial.get('purpose') == 'frozen-development-only-native-integration' and
            initial.get('hardware_validation') == initial.get('production_trust') == 'NOT RUN' and
            initial.get('development_only') is True and initial.get('selected_for_release') is False and
            re.fullmatch('[0-9a-f]{40}', initial.get('source_commit', '')) and re.fullmatch('sha256:[0-9a-f]{64}', initial.get('base_image', '')),
            'initial-source-identity-required')
    commit = initial['source_commit']; rows = fixture_rows(root, evidence, commit, policy)
    kind = directory.name
    stage = {'fixture-archives': 'fixtures', 'signer-public-artifacts': 'signer', 'repository-public-artifacts': 'repository'}[kind]
    require(initial.get('stages', {}).get(stage, {}).get('status') == 'PASS', 'successful-initial-producer-required')
    if kind == 'fixture-archives':
        manifest_name = 'archive-manifest.json'; manifest = read_json(directory / manifest_name)
        approved = {PurePosixPath(r['archive']).name: r['sha256'] for r in rows['upgrade']}
        require(manifest == {'development_only': True, 'selected_for_release': False, 'source_commit': commit,
                            'archives': approved, 'production_signing': 'NOT RUN'}, 'fixture-export-manifest-refused')
        sources = {PurePosixPath(r['archive']).name: evidence / 'work/archive-inputs' / r['archive'] for r in rows['upgrade']}
    else:
        manifest_name = 'public-artifact-manifest.json'; manifest = read_json(directory / manifest_name)
        require(manifest.get('development_only') is True and manifest.get('selected_for_release') is False and
                manifest.get('production_credentials_used') is False and manifest.get('source_commit') == commit,
                'TEST-export-envelope-required')
        if kind == 'signer-public-artifacts':
            approved, signer, archives = signer_authority(evidence, rows, initial, policy)
            require(set(manifest) == {'development_only', 'selected_for_release', 'production_credentials_used', 'files',
                    'source_commit', 'purpose', 'fingerprint', 'expiry', 'archives'} and
                    manifest.get('purpose') == 'TEST-ONLY-offline-signature-verification' and manifest.get('fingerprint') == signer['fingerprint'] and
                    manifest.get('expiry') == signer['expiry'] and manifest.get('archives') == archives, 'TEST-signer-export-binding-refused')
            sources = {name: evidence / 'work/test-signatures/public' / name for name in approved}
        else:
            raw = evidence / 'work/repository-raw'; receipt = read_json(raw / 'result.json')
            contract = read_json(evidence / 'work/repository-inputs/manifest.json')
            signed_rows = repository_rows(root, evidence, rows, initial, policy)
            fields = ('nonce', 'image_id', 'daemon_arch', 'script_sha256', 'upgrade_kind')
            require(receipt.get('schema_version') == 1 and receipt.get('status') == 'PASS' and receipt.get('purpose') == 'disposable-generic-repository-test' and
                    receipt.get('source_commit') == contract.get('source_commit') == commit and
                    type(contract.get('schema_version')) is int and contract['schema_version'] == 1 and
                    contract.get('purpose') == 'disposable-generic-repository-test' and contract.get('execution') == 'native-aarch64-disposable-docker' and
                    contract.get('allow_system_mutation') is True and contract.get('image_id') == initial['base_image'] and
                    contract.get('baseline') == signed_rows['baseline'] and contract.get('upgrade') == signed_rows['upgrade'] and
                    contract.get('script_sha256') == digest(root / 'scripts/integration/repository.py') and contract.get('daemon_arch') == 'aarch64' and
                    contract.get('upgrade_kind') == 'synthetic-changed-package-fixtures' and re.fullmatch('[0-9a-f]{32}', contract.get('nonce', '')) and
                    receipt.get('input_contract') == {k: contract[k] for k in fields} and receipt.get('test_private_state_removed') is True and
                    receipt.get('hardware_validation') == receipt.get('stable_promotion') == 'NOT RUN' and receipt.get('published') is False,
                    'accepted-repository-contract-required')
            evidence_map = receipt.get('evidence_sha256', {})
            require(isinstance(evidence_map, dict), 'repository-evidence-map-required')
            approved = {name: pin for name, pin in evidence_map.items() if repository_allowed(name)}
            require(CERTS <= approved.keys() and 'TEST-repository-aliases.json' in approved and
                    all(any(n.startswith('TEST-repositories/' + stage + '/') for n in approved) for stage in ('baseline-A', 'updated-B')),
                    'repository-required-public-files-missing')
            require(set(manifest) == {'development_only', 'selected_for_release', 'production_credentials_used', 'files',
                    'source_commit', 'purpose', 'cases', 'expected_negative_cases_retained'} and
                    manifest.get('purpose') == 'TEST-ONLY-offline-repository-case-verification' and manifest.get('cases') == receipt.get('cases') and
                    manifest.get('expected_negative_cases_retained') is True, 'TEST-repository-export-binding-refused')
            sources = {name: raw / name for name in approved}
        require(set(manifest.get('files', {})) == set(approved), 'exact-export-files-required')
    require(0 < len(approved) <= 512, 'finite-artifact-set-required')
    total, opaque, text, expected = 0, {}, {}, {manifest_name}
    for name, pin in approved.items():
        relative(name, policy); require(isinstance(pin, str) and PIN.fullmatch(pin), 'artifact-pin-required')
        data = read_regular(directory / name, FILE_LIMIT)
        source = read_regular(sources[name], FILE_LIMIT)
        total += len(data); require(total <= TOTAL_LIMIT and data == source and hashlib.sha256(data).hexdigest() == pin, 'artifact-hash-or-byte-binding-refused')
        record = {'sha256': pin, 'bytes': len(data)}
        if kind != 'fixture-archives':
            require(manifest['files'][name] == record, 'artifact-manifest-byte-binding-refused')
        if name.endswith('.asc'):
            require(b'PRIVATE KEY' not in data and not policy['PRIVATE_CONTENT'].search(data.decode('ascii')), 'private-certificate-refused')
            certificate(root, data); opaque[name] = record
        elif name.endswith('.sig'):
            signature(data, policy, kind=kind, name=name); opaque[name] = record
        elif name.endswith(('.json', '.conf')):
            content = data.decode('utf-8')
            require(not policy['PRIVATE_CONTENT'].search(content) and not any(ord(c) < 32 and c not in '\n\r\t' for c in content), 'private-or-control-text-refused')
            if name.endswith('.json'):
                read_json(directory / name)
            text[name] = record
        else:
            require(not policy['PRIVATE_CONTENT'].search(data.decode('latin-1')), 'private-binary-marker-refused')
            opaque[name] = record
        expected.add(name)
    allowed_dirs = {p.as_posix() for n in expected for p in PurePosixPath(n).parents if p.as_posix() != '.'}
    actual = set()
    for path in directory.rglob('*'):
        name = path.relative_to(directory).as_posix(); relative(name, policy)
        info = path.lstat()
        require(not path.is_symlink(), 'artifact-symlink-refused')
        if stat.S_ISDIR(info.st_mode):
            require(name in allowed_dirs, 'extra-artifact-directory-refused')
        else:
            read_regular(path, FILE_LIMIT); actual.add(name)
    require(actual == expected, 'extra-or-missing-artifact-files')
    manifest_bytes = read_regular(directory / manifest_name)
    require(total + len(manifest_bytes) <= 16 * 1024**2 and not policy['PRIVATE_CONTENT'].search(manifest_bytes.decode()), 'artifact-wrapper-refused')
    return {'manifest': manifest, 'opaque_approved': opaque, 'text_approved': text,
            'approved_paths': [str(directory / n) for n in sorted(expected)]}
