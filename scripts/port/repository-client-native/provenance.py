#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Consume actual immutable-builder observations and four build evidence pairs."""
import io
from pathlib import Path
import re
import tarfile
import unicodedata

from common import bounded_tar_payload, digest, encoded, decode, need, pinned, mapped, relative

ORIGINALS = frozenset(('cachy-asahi-hyprland-settings', 'cachy-asahi-fish-config',
                      'cachy-asahi-zsh-config', 'cachy-asahi-setup'))
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
REQUIRED = {'build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock',
            'artifacts/generated.SRCINFO', 'artifacts/environment.txt', 'artifacts/config.sha256',
            'artifacts/makepkg.conf', 'artifacts/pacman.conf'}


def package_url(data, parsed):
    """Only a single exact empty optional URL is equivalent to omission."""
    values = parsed.get('url', [])
    need(len(values) <= 1, 'duplicate-url-field')
    physical = []
    for line in data.decode().split('\n'):
        name, separator, value = line.partition(' = ')
        if name.strip() == 'url':
            need(name == 'url' and separator, 'malformed-package-url')
            physical.append(value)
    need(physical == values, 'malformed-package-url')
    if values == ['']:
        parsed.pop('url')
    else:
        need(all(value and not any(char.isspace() or unicodedata.category(char) in ('Cc', 'Cf') for char in value)
                 for value in values), 'malformed-url-value')


def package_bytes(raw):
    """Bounded in-memory inspection; archive data is never extracted or executed."""
    need(0 < len(raw) <= 16 * 1024**2, 'archive byte bound')
    members, total = {}, 0
    try:
        payload = bounded_tar_payload(raw)
        offset, headers = 0, 0
        while offset + 512 <= len(payload):
            header = payload[offset:offset + 512]
            if header == b'\0' * 512:
                need(not any(payload[offset:]), 'archive nonzero trailing bytes')
                break
            item = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
            need(item.type not in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE), 'archive PAX header refused')
            need(0 <= item.size <= 16 * 1024**2 and headers < 2048, 'archive header bound')
            offset += 512 + ((item.size + 511) // 512) * 512
            headers += 1
            need(offset <= len(payload), 'archive body truncated')
        else:
            raise ValueError('archive end marker required')
        with tarfile.open(fileobj=io.BytesIO(payload), mode='r:') as archive:
            need(not archive.pax_headers, 'archive global metadata refused')
            for member in archive:
                name = member.name.removeprefix('./').rstrip('/')
                if not name and member.isdir():
                    continue
                relative(name)
                need(name not in members and len(members) < 2048, 'archive duplicate/count bound')
                need(member.isdir() or member.isfile(), 'archive links/devices refused')
                need(not member.pax_headers, 'archive extended metadata refused')
                need(0 <= member.size <= 16 * 1024**2, 'member byte bound')
                total += member.size
                need(total <= 64 * 1024**2, 'expanded archive bound')
                stream = archive.extractfile(member) if member.isfile() else None
                data = stream.read(member.size + 1) if stream else None
                need(data is None or len(data) == member.size, 'archive truncated member')
                members[name] = data
    except (tarfile.TarError, EOFError):
        raise ValueError('unsupported or invalid bounded archive') from None
    need('.PKGINFO' in members and members['.PKGINFO'], 'package metadata missing')
    info = {}
    for line in members['.PKGINFO'].decode().splitlines():
        if not line or line.startswith('#'):
            continue
        need(' = ' in line, 'malformed package metadata')
        key, value = line.split(' = ', 1)
        need((value or key == 'url') and re.fullmatch(r'[a-z][a-z0-9_]*', key), 'invalid package field')
        info.setdefault(key, []).append(value)
    package_url(members['.PKGINFO'], info)
    for key in ('pkgname', 'pkgver', 'arch'):
        need(len(info.get(key, [])) == 1, 'package identity missing/duplicate')
    need(info['pkgname'][0] in ORIGINALS and info['arch'][0] in ('any', 'aarch64') and
         info.get('license') == ['MIT'] and '.INSTALL' not in members, 'original package scope/license/hook differs')
    return {'name': info['pkgname'][0], 'version': info['pkgver'][0], 'arch': info['arch'][0],
            'license': info['license'], 'depend': info.get('depend', []), 'provides': info.get('provides', []),
            'conflict': info.get('conflict', []), 'replaces': info.get('replaces', []),
            'files': sorted(name for name, data in members.items() if data is not None and not name.startswith('.'))}, members


def srcinfo(raw):
    fields = {}
    for line in raw.decode().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'\s*([a-z0-9_]+)\s*=\s*(.+)', line)
        need(match is not None, 'malformed generated SRCINFO')
        fields.setdefault(match[1], []).append(match[2])
    return fields


def build_record(data, prefix, request, package, lock_raw):
    relative(prefix)
    record = decode(data[prefix + '/provenance.json'])
    need(record.get('schema_version') == 1 and type(record['schema_version']) is int and
         record.get('status') == 'built-package-static-pass' and record.get('mode') == 'native'
         and record.get('network') == 'none' and record.get('image') == record.get('image_id') == request['image_id']
         and record.get('builder_host_arch') in ('aarch64', 'arm64') and record.get('exit_code') == 0
         and type(record['exit_code']) is int and type(record.get('source_date_epoch')) is int
         and record['source_date_epoch'] >= 0 and record.get('hardware_status') == 'NOT RUN', 'native build receipt differs')
    need(record.get('entry_script_sha256') == digest(data[request['entry_script']]), 'actual build entry source differs')
    files, recipes, artifacts = record.get('files'), record.get('recipe_inputs'), record.get('artifacts')
    need(isinstance(files, dict) and REQUIRED <= set(files) and isinstance(recipes, dict) and recipes
         and {'PKGBUILD', '.SRCINFO', 'LICENSE'} <= set(recipes) and isinstance(artifacts, dict)
         and len(artifacts) == 1, 'complete build evidence required')
    for name, pin in files.items():
        relative(name)
        need(digest(data[prefix + '/' + name]) == pin, 'build evidence binding differs')
    for name, pin in recipes.items():
        relative(name)
        need(digest(data[prefix + '/inputs/' + name]) == pin, 'build recipe snapshot binding differs')
    need(data[prefix + '/expected-packages.lock'] == data[prefix + '/artifacts/packages.lock'] == lock_raw
         and record.get('expected_packages_sha256') == digest(lock_raw), 'build inventory differs')
    filename, pin = next(iter(artifacts.items()))
    need(Path(filename).name == filename and digest(data[prefix + '/artifacts/' + filename]) == pin,
         'build artifact differs')
    info, members = package_bytes(data[prefix + '/artifacts/' + filename])
    need(info == package and filename.startswith(package['name'] + '-'), 'artifact package identity differs')
    need(members.get('.BUILDINFO') and members.get('.MTREE'), 'actual build metadata required')
    buildinfo = {}
    for line in members['.BUILDINFO'].decode().splitlines():
        if line and not line.startswith('#'):
            need(' = ' in line, 'malformed BUILDINFO')
            key, value = line.split(' = ', 1)
            buildinfo.setdefault(key, []).append(value)
    need(buildinfo.get('format') == ['2'] and buildinfo.get('pkgname') == [package['name']]
         and buildinfo.get('pkgver') == [package['version']] and buildinfo.get('pkgarch') == [package['arch']]
         and buildinfo.get('pkgbuild_sha256sum') == [recipes['PKGBUILD']], 'archive recipe BUILDINFO binding differs')
    generated = srcinfo(data[prefix + '/artifacts/generated.SRCINFO'])
    checked = srcinfo(data[prefix + '/inputs/.SRCINFO'])
    need(generated == checked and generated.get('pkgname') == [package['name']] and
         generated.get('arch') == [package['arch']] and generated.get('license') == ['MIT'], 'generated source metadata differs')
    version = generated.get('pkgver', [''])[0] + '-' + generated.get('pkgrel', [''])[0]
    if generated.get('epoch'):
        version = generated['epoch'][0] + ':' + version
    need(version == package['version'] and generated.get('depends', []) == package['depend']
         and generated.get('provides', []) == package['provides'] and generated.get('conflicts', []) == package['conflict']
         and generated.get('replaces', []) == package['replaces'], 'package/source relation mismatch')
    validation = decode(data[prefix + '/validation.json'])
    need(validation.get('errors') == [] and isinstance(validation.get('artifacts'), list)
         and len(validation['artifacts']) == 1 and validation['artifacts'][0].get('sha256') == pin,
         'actual artifact validation required')
    command = record.get('command', [])
    need(isinstance(command, list) and command[:3] == ['docker', 'run', '--rm']
         and '--read-only' in command and '--cap-drop=ALL' in command and '--security-opt=no-new-privileges' in command
         and '--network' in command and command[command.index('--network') + 1] == 'none'
         and request['image_id'] in command and '/builder-entry.sh' == command[-1]
         and re.fullmatch(r'cachy-asahi-[0-9a-f]{16}', record.get('clean_environment_id', '')),
         'bounded native build launch observation required')
    license_raw = data[prefix + '/inputs/LICENSE']
    need(license_raw and members.get('usr/share/licenses/' + package['name'] + '/LICENSE') == license_raw,
         'packaged license differs from reviewed source')
    return record, filename, pin, license_raw


def consume(input_root, request_raw, request_sha256, base_raw, base_sha256):
    """Produce metadata components from externally authenticated actual records."""
    request, base = pinned(request_raw, request_sha256), pinned(base_raw, base_sha256)
    need(set(request) == {'schema_version', 'purpose', 'source_commit', 'recipe_source_commit', 'repository_url',
                         'image_id', 'archive_role', 'snapshot_id', 'packages_lock', 'files', 'packages', 'fixture_manifest',
                         'entry_script', 'generator_source'},
         'exact provenance request fields required')
    need(request['schema_version'] == 1 and type(request['schema_version']) is int and
         request['purpose'] == 'native-artifact-provenance-inputs' and request['archive_role'] in ('baseline', 'updated')
         and COMMIT.fullmatch(request['source_commit']) and COMMIT.fullmatch(request['recipe_source_commit'])
         and re.fullmatch(r'https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', request['repository_url'])
         and re.fullmatch(r'sha256:[0-9a-f]{64}', request['image_id']), 'provenance identity required')
    data = mapped(input_root, request['files'])
    need(base.get('schema_version') == 1 and base.get('target_arch') == 'aarch64'
         and base.get('kind') == 'complete-target-transaction' and base.get('snapshot_id') == request['snapshot_id']
         and isinstance(base.get('packages'), list) and len(base['packages']) == 341, 'complete observed generic base required')
    lock_raw = data[request['packages_lock']]
    expected = ''.join(f"{p['name']} {p['version']}\n" for p in sorted(base['packages'], key=lambda p: p['name'])).encode()
    need(lock_raw == expected and len({p['name'] for p in base['packages']}) == 341, 'base lock metadata differs')
    rows = request['packages']
    need(isinstance(rows, list) and len(rows) == 4 and {row.get('name') for row in rows} == ORIGINALS,
         'exact four original packages required')
    fixture = decode(data[request['fixture_manifest']])
    need(fixture.get('schema_version') == 1 and fixture.get('source_commit') == request['recipe_source_commit']
         and fixture.get('development_only') is True and fixture.get('selected_for_release') is False
         and set(fixture.get('packages', {})) == ORIGINALS, 'actual frozen fixture identity required')
    need(fixture.get('generator_sha256') == digest(data[request['generator_source']]), 'actual fixture generator bytes differ')
    provenance, overlay = {}, []
    for row in rows:
        need(set(row) == {'name', 'archive', 'first', 'second', 'compare', 'diff'}, 'exact artifact references required')
        package, _ = package_bytes(data[row['archive']])
        need(package['name'] == row['name'] and row['first'] != row['second'], 'distinct artifact/build identities required')
        left, filename, pin, license_raw = build_record(data, row['first'], request, package, lock_raw)
        right, second, other, _ = build_record(data, row['second'], request, package, lock_raw)
        need(filename == second and pin == other == digest(data[row['archive']])
             and data[row['first'] + '/artifacts/' + filename] == data[row['second'] + '/artifacts/' + filename]
             and left['clean_environment_id'] != right['clean_environment_id'], 'actual clean build bytes/identities differ')
        for key in ('image', 'image_id', 'mode', 'source_date_epoch', 'recipe_inputs', 'recipe_metadata',
                    'expected_packages_sha256', 'entry_script_sha256'):
            need(key in left and left[key] == right.get(key), 'paired build input drift')
        comparison = decode(data[row['compare']])
        need(comparison.get('status') == 'contents-reproduced' and comparison.get('errors') == []
             and set(comparison.get('packages', {})) == {filename}
             and all(comparison['packages'][filename].get(key) is True for key in
                     ('installed_contents_equal', 'pkginfo_equal', 'bytes_equal')), 'actual comparison receipt differs')
        origin = fixture['packages'][row['name']]
        phase = 'base' if request['archive_role'] == 'baseline' else 'fixture'
        need(left['recipe_inputs'] == origin[phase + '_inputs_sha256']
             and left['recipe_inputs']['PKGBUILD'] == origin[phase + '_recipe_sha256']
             and left['source_date_epoch'] == fixture.get('source_date_epoch'), 'fixture recipe ancestry/epoch differs')
        need(package['version'] == origin['base_version' if phase == 'base' else 'upgrade_version'], 'fixture version ancestry differs')
        need(digest(data[row['diff']]) == origin['diff_sha256'], 'actual generated diff differs')
        sources = [{'url': request['repository_url'] + '/blob/' + request['recipe_source_commit'] + '/' +
                    origin['recipe'] + '/' + name, 'sha256': source_pin, 'commit': request['recipe_source_commit'],
                    'generated': phase == 'fixture'} for name, source_pin in sorted(left['recipe_inputs'].items())]
        if phase == 'fixture':
            # A generated byte string has a hash and real ancestry, not a fabricated Git version.
            for (name, _), source in zip(sorted(left['recipe_inputs'].items()), sources):
                source.pop('commit')
                source['origin'] = {'url': source['url'], 'commit': request['recipe_source_commit'],
                                    'sha256': origin['base_inputs_sha256'][name]}
                source['url'] = 'evidence:sha256:' + request_sha256 + '/' + row['first'] + '/inputs/' + name
            sources.append({'url': request['repository_url'] + '/blob/' + request['source_commit'] + '/scripts/integration/fixtures.py',
                            'commit': request['source_commit'], 'sha256': fixture['generator_sha256'], 'role': 'generator'})
        record = {'schema_version': 1, 'artifact_sha256': pin,
                  'package': {key: package[key] for key in ('name', 'version', 'arch')},
                  'source_commit': request['recipe_source_commit'], 'recipe_sha256': left['recipe_inputs']['PKGBUILD'],
                  'licenses': [{'spdx': 'MIT', 'sha256': digest(license_raw), 'text': license_raw.decode()}],
                  'sources': sources, 'build': {'execution': 'native' if phase == 'base' else 'synthetic',
                  'actual_compilation': 'native', 'architecture': 'aarch64', 'environment': request['image_id'],
                  'snapshot_id': request['snapshot_id'], 'source_date_epoch': left['source_date_epoch'],
                  'execution_source_commit': request['source_commit'], 'command': left['command'],
                  'clean_environment_ids': [left['clean_environment_id'], right['clean_environment_id']],
                  'receipt_sha256': [digest(data[row['first'] + '/provenance.json']), digest(data[row['second'] + '/provenance.json'])],
                  'comparison_sha256': digest(data[row['compare']])},
                  'ancestry': {'fixture_manifest_sha256': digest(data[request['fixture_manifest']]),
                               'generator_sha256': fixture['generator_sha256'], 'diff_sha256': origin['diff_sha256'],
                               'original_recipe_sha256': origin['base_recipe_sha256'], 'archive_role': request['archive_role']}}
        provenance[row['name']] = record
        overlay.append({**package, 'sha256': pin})
    # Re-read every mapped file before returning a reviewable observation packet.
    need(mapped(input_root, request['files']) == data, 'provenance observations changed')
    return {'schema_version': 1, 'purpose': 'consumed-native-artifact-provenance', 'status': 'PASS',
            'development_only': True, 'platform_scope': 'generic-builder-only',
            'source_commit': request['recipe_source_commit'], 'execution_source_commit': request['source_commit'],
            'image_id': request['image_id'], 'archive_role': request['archive_role'], 'base': base,
            'provenance': provenance, 'packages': overlay, 'input_request_sha256': request_sha256,
            'base_observation_sha256': base_sha256, 'hardware_validation': 'NOT RUN', 'installation': 'NOT RUN'}


def bind_metadata(components_raw, components_pin, authority_raw, authority_pin, policy_raw, policy_pin, license_raw, license_pin):
    components, authority, policy = (pinned(raw, pin) for raw, pin in
                                    ((components_raw, components_pin), (authority_raw, authority_pin), (policy_raw, policy_pin)))
    need(digest(license_raw) == license_pin and license_raw.strip(), 'external project license bytes required')
    need(components.get('status') == 'PASS' and authority.get('status') == 'PASS'
         and components['source_commit'] == authority['recipe_source_commit']
         and components['execution_source_commit'] == authority['source_commit']
         and components['image_id'] == authority['image_id'] and components['archive_role'] == authority['archive_role'],
         'metadata authority identity differs')
    need(policy.get('purpose') == 'reviewed-generic-restage-policy' and policy.get('platform_scope') == 'generic-builder-only'
         and policy.get('supported_models') == [] and set(policy.get('selected_packages', [])) == ORIGINALS
         and policy.get('protected_packages') and policy.get('coordinated_sets'), 'explicit reviewed generic policy required')
    archives = authority.get('archives', [])
    need(len(archives) == 4 and {row['name']: (row['version'], row['sha256']) for row in archives} ==
         {p['name']: (p['version'], p['sha256']) for p in components['packages']}, 'metadata artifacts differ from accepted archive role')
    return encoded({'schema_version': 1, 'purpose': 'reviewed-generic-restage-metadata',
                    'development_only': True, 'platform_scope': 'generic-builder-only', 'acceptance_sha256': authority_pin,
                    'source_commit': components['source_commit'], 'base': components['base'], 'policy': policy,
                    'provenance': components['provenance'], 'project_license': {'spdx': 'MIT', 'text': license_raw.decode(),
                    'sha256': license_pin}, 'observation_components_sha256': components_pin, 'policy_sha256': policy_pin})
