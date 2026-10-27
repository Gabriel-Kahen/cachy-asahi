#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite native candidate DEVELOPMENT contract; no actors or library loading."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import argparse
import types

PROFILE_SHA = '92342499a72bfde278975c12d33e97165d51ddeb0fd8094ad8bd4d3f0eb6c741'
PROFILE_SIZE = 47723
BASELINE_SHA = 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
RUNTIME_SHA = 'd889340eef78ba3755ea8751ff4e97dc35889c1604567ce24e0d8effc323ed9a'
LIBALPM_SHA = '94c013b9026772ffe4f227f508a2cdf0c61323dc1f7b7836fe629b49bfbc3902'
SCOPE = 'native-aarch64-real-candidate-development'
PURPOSE = 'native-arm-real-candidate-development'
SEED_SCOPE = 'ALPM_DATABASE_ONLY_NOT_BOOTABLE_SYSTEM'
HEX = re.compile(r'[0-9a-f]{64}\Z')
FPR = re.compile(r'[0-9A-F]{40}\Z')
PACKAGES = {
    'cachy-asahi-session-diagnostics': ('0.1.0-3', 'session',
        'ef55f7a91dab46dbf5355a5d02c0ccd4113bf45db2578cf59412662dca734662'),
    'cachy-asahi-maintenance': ('0.1.0-2', 'maintenance',
        '984509e7f468086f02e23704748a58a3fc13b5c2babfbc27a2d27ac7258b3857'),
}
CORRECTED_RECIPE_SOURCE = 'ab57e41b60d08e564bc0fe7e9a0c9a9c0706c283'
SRCINFO_SHA = {
    'cachy-asahi-session-diagnostics': 'c4dc2ceebed4250bceebd00204c29c2c9ddfd67f4b25cfde78bd2001349b44fd',
    'cachy-asahi-maintenance': '6614557aa31b48a3b3a82af1d7bd311daedb4f771c0e8737d1f6297716962ac6',
}
# Exact accepted archive/source identities remain DATA pins, not execution claims.
# Producer must verify original TEST signatures before re-signing exact archives.
ACCEPTED = {
    'cachy-asahi-maintenance': dict(
        archive_size=53104, archive_sha256='028340024c32ff02109679d6a5dfc56122c769830b94014a5373199c26e195d1',
        source_size=245760, source_sha256='bf687e3d29fae3f85d1c79acd508a7cc0571eebacaa6fe663d8a0356cc434d0a',
        source_commit='50c6280fa3b2871bb663c0910d95e35f2a488b01', source_files=20),
    'cachy-asahi-session-diagnostics': dict(
        archive_size=20924, archive_sha256='8e69184b33395d80ba921385d0ed071cc35178ae64f18549a9bf34e5c185c70d',
        source_size=102400, source_sha256='154057c2bfad0928c4a6cfb376628bb87d61c70ccc7149ec21936349672c7913',
        source_commit='e20eb9a2095f3e9a2dd0073ce68f9208bec0d87d', source_files=12),
}
PHASES = ('install', 'reinstall', 'remove', 'reinstall-after-remove', 'final-remove')
SOURCE_NAMES = {'candidate-worker.py', 'candidate_profile.py', 'runtime.py', 'candidate_lifecycle.py',
    'receiver/LICENSE', 'receiver/scripts/release/offline_kit.py', 'receiver/scripts/client/client.py',
    'receiver/scripts/release/source_delivery.py', 'receiver/scripts/release/recipe_source_delivery.py',
    'receiver/scripts/checks/package_checks.py'}


def require(ok, label):
    if not ok:
        raise ValueError('candidate profile: ' + label)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fields(value, names, label):
    require(type(value) is dict and set(value) == set(names), label)


def pin(value, length=64):
    require(type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value), 'exact hash required')
    return value


def baseline():
    require(digest(BASELINE_BYTES) == BASELINE_SHA, 'embedded original574 inventory hash')
    rows = [line.split(' ') for line in BASELINE_BYTES.decode().splitlines()]
    require(len(rows) == 574 and all(len(row) == 2 for row in rows), 'embedded original574 inventory')
    value = dict(rows)
    require(len(value) == 574 and BASELINE_BYTES == ''.join(n + ' ' + v + '\n' for n, v in sorted(value.items())).encode(),
            'canonical original574 inventory')
    return value


def actual_inventory(value):
    require(type(value) is dict and value == baseline(), 'actual original574 local ALPM inventory absent or changed')
    return value


def reference(value):
    fields(value, ('path', 'size', 'sha256'), 'file reference shape')
    path = Path(value['path']) if type(value['path']) is str else Path('.')
    require(path.is_absolute() and '..' not in path.parts and str(path) == os.path.normpath(str(path)) and
            type(value['size']) is int and 0 < value['size'] <= 8 * 1024**2, 'bounded canonical reference')
    pin(value['sha256'])
    return value


def reviewed_source_hashes(name, recipe_sha, srcinfo_sha):
    require(name in PACKAGES and recipe_sha == PACKAGES[name][2] and srcinfo_sha == SRCINFO_SHA[name],
            'exact corrected recipe/SRCINFO pair required')


def validate_selection(value):
    fields(value, ('schema_version', 'purpose', 'seed_scope', 'source_commit', 'feature_code_sha',
        'image_id', 'nonce', 'profile_sha256', 'baseline_packages_sha256', 'runtime_sha256',
        'worker_sha256', 'sources', 'candidate', 'kit'), 'selection closed fields')
    require(type(value['schema_version']) is int and value['schema_version'] == 1 and
            value['purpose'] == PURPOSE and value['seed_scope'] == SEED_SCOPE, 'selection scope')
    pin(value['source_commit'], 40); pin(value['feature_code_sha'], 40); pin(value['nonce'], 32)
    require(type(value['image_id']) is str and value['image_id'].startswith('sha256:'), 'immutable image')
    pin(value['image_id'][7:]); pin(value['worker_sha256'])
    require(value['profile_sha256'] == PROFILE_SHA and value['baseline_packages_sha256'] == BASELINE_SHA and
            value['runtime_sha256'] == RUNTIME_SHA, 'native tool/runtime/original574 profile')
    sources = value['sources']
    require(type(sources) is dict and set(sources) == SOURCE_NAMES,
            'exact selected source closure')
    for name, row in sources.items():
        fields(row, ('size', 'sha256'), 'selected source row')
        require(type(row['size']) is int and 0 < row['size'] <= 128 * 1024, 'selected source bound')
        pin(row['sha256'])
    require(sources['candidate-worker.py']['sha256'] == value['worker_sha256'] and
            sources['runtime.py'] == dict(size=16869, sha256=RUNTIME_SHA), 'selected worker/runtime hash')
    row = value['candidate']
    fields(row, ('package', 'archive', 'signature', 'keyring', 'recipe_sha256', 'source_bundle_sha256'),
           'single selected candidate')
    package = row['package']
    fields(package, ('name', 'version', 'arch', 'sha256'), 'candidate identity')
    require(type(package['name']) is str and package['name'] in PACKAGES and
            package['version'] == PACKAGES[package['name']][0] and package['arch'] == 'any', 'candidate allowlist')
    accepted = ACCEPTED[package['name']]
    require(package['sha256'] == accepted['archive_sha256'] and
            row['source_bundle_sha256'] == accepted['source_sha256'],
            'exact accepted native archive and complete original source bundle required')
    require(row['recipe_sha256'] == PACKAGES[package['name']][2], 'reviewed original recipe hash')
    for key in ('archive', 'signature', 'keyring'):
        reference(row[key])
    require(row['archive']['size'] == accepted['archive_size'] and
            row['archive']['sha256'] == package['sha256'] and
            row['signature']['path'] == row['archive']['path'] + '.sig', 'archive/signature identity')
    kit = value['kit']
    fields(kit, ('path', 'state_dir', 'kit_sha256', 'envelope_sha256', 'signer', 'namespace', 'minimum_sequence'),
           'external kit trust fields')
    require(kit['path'] == '/media/good' and kit['state_dir'] == '/out/client-state', 'fixed relocated kit and preserved state')
    pin(kit['kit_sha256']); pin(kit['envelope_sha256'])
    require(type(kit['signer']) is str and FPR.fullmatch(kit['signer']) and
            type(kit['namespace']) is str and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,127}', kit['namespace']) and
            type(kit['minimum_sequence']) is int and kit['minimum_sequence'] >= 1, 'external kit trust pins')
    return value


def read_pinned(path, checksum, maximum, engine):
    path = Path(path)
    return engine.capture(dict(path=str(path), size=path.lstat().st_size, sha256=checksum), maximum)


def read_selection(checksum, engine):
    pin(checksum)
    raw = read_pinned('/inputs/candidate-selection.json', checksum, 1024**2, engine)
    return validate_selection(engine.decode(raw))


def contract_reference(actual, expected, contract, selection, engine, leaf):
    reference(actual)
    require(actual['size'] == expected['size'] and actual['sha256'] == expected['sha256'],
            'selected signed input size/hash mismatch')
    if actual['path'] == expected['path']:
        return
    # Only the original authenticated sealed child spec can rewrite inputs.
    raw = getattr(engine, 'ENGINE_SPEC_BYTES', None)
    require(type(raw) is bytes and getattr(engine, 'EXECUTED_WORKER_SHA', None) == selection['worker_sha256'],
            'only captured sealed child can use copied input paths')
    spec = engine.decode(raw)
    require(spec['worker_source_sha256'] == selection['worker_sha256'] and
            spec['runtime_source_sha256'] == RUNTIME_SHA and spec['contract'] == contract,
            'sealed copied contract execution binding')
    path = Path(actual['path']); parent = path.parent
    require(path.name == leaf and parent.name == 'inputs' and
            parent.parent.parent == Path(contract['workspace']).parent and
            re.fullmatch(r'\.local-transaction-[a-z0-9_]{6,16}', parent.parent.name),
            'exact phase-owned private snapshot path')


def validate_contract(contract, selection_sha256, engine):
    fields(contract, ('schema_version', 'scope', 'workspace', 'architecture', 'before', 'after', 'protected',
        'add', 'remove', 'keyring', 'timeout_seconds', 'libalpm_sha256', 'profile_sha256',
        'input_selection_sha256', 'candidate_binding'), 'schema4 closed contract')
    require(type(contract['schema_version']) is int and contract['schema_version'] == 4 and
            contract['scope'] == SCOPE and contract['architecture'] == 'aarch64', 'schema4 candidate scope')
    require(contract['input_selection_sha256'] == selection_sha256 and
            contract['profile_sha256'] == PROFILE_SHA and contract['libalpm_sha256'] == LIBALPM_SHA,
            'selected contract/profile/library hashes')
    selection = read_selection(selection_sha256, engine)
    candidate, kit = selection['candidate'], selection['kit']
    package = candidate['package']; name, version = package['name'], package['version']
    binding = contract['candidate_binding']
    fields(binding, ('package', 'phase', 'kit_sha256', 'envelope_sha256', 'source_bundle_sha256',
        'recipe_sha256', 'signer'), 'candidate binding shape')
    require(binding['package'] == package and binding['kit_sha256'] == kit['kit_sha256'] and
            binding['envelope_sha256'] == kit['envelope_sha256'] and binding['signer'] == kit['signer'] and
            binding['source_bundle_sha256'] == candidate['source_bundle_sha256'] and
            binding['recipe_sha256'] == candidate['recipe_sha256'], 'candidate external identity/pin mismatch')
    prefix = PACKAGES[name][1] + '-'
    require(type(binding['phase']) is str and binding['phase'].startswith(prefix) and
            binding['phase'][len(prefix):] in PHASES, 'finite candidate phase')
    phase = binding['phase'][len(prefix):]
    require(contract['workspace'] == '/out/phase-' + binding['phase'] + '/workspace', 'fixed fresh phase workspace')
    require(type(contract['timeout_seconds']) is int and 1 <= contract['timeout_seconds'] <= 600,
            'finite candidate timeout')
    require(contract['protected'] == {} and type(contract['protected']) is dict, 'DB-only seed has no accepted base payload')
    contract_reference(contract['keyring'], candidate['keyring'], contract, selection, engine, 'public-keyring')
    original = baseline(); installed = dict(original, **{name: version})
    before = installed if phase in ('reinstall', 'remove', 'final-remove') else original
    after = original if phase in ('remove', 'final-remove') else installed
    require(type(contract['before']) is dict and type(contract['after']) is dict and
            contract['before'] == before and contract['after'] == after,
            'exact original574/575 before/after inventory; base delta or missing inventory')
    if phase in ('remove', 'final-remove'):
        require(contract['add'] == [] and contract['remove'] == {name: version}, 'finite selected candidate removal')
    else:
        require(type(contract['add']) is list and len(contract['add']) == 1 and contract['remove'] == {},
                'finite selected signed candidate add')
        added = contract['add'][0]
        fields(added, ('name', 'version', 'archive', 'signature', 'signer'), 'single closed add row')
        require(added['name'] == name and added['version'] == version and added['signer'] == kit['signer'],
                'selected candidate add identity/signer')
        suffix = '.pkg.tar.xz' if candidate['archive']['path'].endswith('.xz') else '.pkg.tar.gz'
        contract_reference(added['archive'], candidate['archive'], contract, selection, engine, '0' + suffix)
        contract_reference(added['signature'], candidate['signature'], contract, selection, engine, '0' + suffix + '.sig')
    return contract


def environment_authority(selection_sha, worker_sha, engine):
    selection = read_selection(selection_sha, engine)
    require(selection['worker_sha256'] == worker_sha, 'executing sealed candidate worker differs')
    require(os.uname().sysname == 'Linux' and os.uname().machine == 'aarch64' and
            os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() != 0, 'ordinary native ARM parent')
    require(os.environ.get('CACHY_ASAHI_INSTALL_NONCE') == selection['nonce'] and
            os.environ.get('CACHY_ASAHI_INSTALL_IMAGE') == selection['image_id'], 'external isolated image handoff')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    require(status.get('NoNewPrivs', '').strip() == '1' and
            all(int(status[key].strip(), 16) == 0 for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd')),
            'outer native actor capability/no-new-privileges boundary')
    interfaces = [line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    require(interfaces == ['lo'], 'private network-none namespace')
    lock = read_pinned('/builder-packages.lock', BASELINE_SHA, 65536, engine)
    require(lock == BASELINE_BYTES, 'actual original574 installed inventory lock')
    actual, _ = engine.candidate_database_records(Path('/'))
    actual_inventory(actual)
    raw = read_pinned('/source/profile.json', PROFILE_SHA, 65536, engine)
    require(len(raw) == PROFILE_SIZE, 'full coherent native574 tool profile bytes')
    profile = engine.decode(raw)
    require(profile['architecture'] == 'aarch64' and profile['libalpm_expected_abi'] == '16.0.1' and
            len(profile['files']) == 136 and sum(row['size'] for row in profile['files']) == 85444968,
            'full native136 tool role')
    for alias, target in profile['aliases'].items():
        require(str(Path(alias).resolve(strict=True)) == target, 'native tool alias changed')
    for row in profile['files']:
        body = read_pinned(row['path'], row['sha256'], 64 * 1024**2, engine)
        require(len(body) == row['size'], 'native tool bytes changed')
    for relative, row in selection['sources'].items():
        body = read_pinned(Path('/source') / relative, row['sha256'], 128 * 1024, engine)
        require(len(body) == row['size'], 'selected exact source bytes changed')
    # All selected source bytes and native tools are pinned before a receiver
    # import can launch GPG. /source and /media are admitted read-only mounts.
    path = Path('/source/receiver/scripts/release/offline_kit.py')
    kit_module = types.ModuleType('candidate_selected_kit'); kit_module.__file__ = str(path)
    code = read_pinned(path, selection['sources']['receiver/scripts/release/offline_kit.py']['sha256'], 128 * 1024, engine)
    exec(compile(code, str(path), 'exec'), kit_module.__dict__)
    trust = selection['kit']
    args = argparse.Namespace(kit=trust['path'], kit_sha256=trust['kit_sha256'],
        namespace=trust['namespace'], signer=trust['signer'], minimum_sequence=trust['minimum_sequence'],
        state_dir=trust['state_dir'])
    verified = kit_module.inspect(args)
    require(verified['metadata_sha256'] == trust['envelope_sha256'] and
            verified['source_delivery'] == 'CHECKED_DECLARED_ASSOCIATIONS' and
            not verified['packages_installed'] and not verified['state_changed'], 'real external kit authentication')
    c = kit_module.c; descriptor = c.directory(Path(trust['path']) / 'release')
    try:
        _, release, raw = c.describe(descriptor)
        require(c.digest(raw) == verified['release_sha256'], 'release changed after authentication')
        spec_raw = c.read_member(descriptor, 'spec.json')
        require(c.digest(spec_raw) == release['files']['spec.json'], 'signed spec changed after authentication')
        spec = c.decode(spec_raw)
        require(spec.get('synthetic') is False, 'real candidate profile refuses synthetic release')
        associations = c.source_associations(descriptor, spec, release)
        selected = selection['candidate']; package = selected['package']
        records = [row for row in associations['packages'] if row['package'] == package]
        require(len(records) == 1, 'selected real package source association')
        record = records[0]
        require(record['recipe']['sha256'] == selected['recipe_sha256'] and
                record['bundle']['sha256'] == selected['source_bundle_sha256'], 'selected source/recipe hashes')
        source_raw = c.read_member(descriptor, 'evidence/' + record['bundle']['id'], 8 * 1024**2)
        adapter_path = Path('/source/receiver/scripts/release/recipe_source_delivery.py')
        adapter = types.ModuleType('candidate_selected_source_adapter'); adapter.__file__ = str(adapter_path)
        code = read_pinned(adapter_path, selection['sources']['receiver/scripts/release/recipe_source_delivery.py']['sha256'],
                           128 * 1024, engine)
        exec(compile(code, str(adapter_path), 'exec'), adapter.__dict__)
        accepted = ACCEPTED[package['name']]
        require(len(source_raw) == accepted['source_size'] and digest(source_raw) == accepted['source_sha256'],
                'complete original accepted source tar bytes')
        saved, bodies = adapter.unpacked(source_raw, selected['source_bundle_sha256'])
        require(saved['observed_source_revision'] == accepted['source_commit'] and
                len(bodies) == accepted['source_files'], 'exact original accepted source closure')
        reviewed_source_hashes(package['name'], digest(bodies['PKGBUILD']), digest(bodies['.SRCINFO']))
        require(saved['package'] == {key: package[key] for key in ('name', 'version', 'arch')} and
                saved['recipe_sha256'] == selected['recipe_sha256'] and
                saved['archive_binding'] is not None and
                saved['archive_binding']['archive_sha256'] == package['sha256'] and
                digest(bodies['PKGBUILD']) == selected['recipe_sha256'], 'real archive/source bundle correspondence')
        actual_binding = adapter.bind_archive(Path(selected['archive']['path']), package['name'], bodies,
                                              adapter.metadata(bodies['.SRCINFO']))
        require(actual_binding == saved['archive_binding'], 'actual archive metadata/payload differs from source bundle')
        matches = [row for row in release['packages'] if all(row.get(key) == val for key, val in package.items())]
        require(len(matches) == 1 and selected['archive']['path'] == trust['path'] + '/release/repo/' + matches[0]['filename'] and
                selected['keyring']['path'] == trust['path'] + '/public.gpg' and
                selected['signature']['sha256'] == release['files']['repo/' + matches[0]['filename'] + '.sig'],
                'actual relocated signed archive paths')
        for key in ('archive', 'signature', 'keyring'):
            body = engine.capture(selected[key], 8 * 1024**2)
            require(len(body) == selected[key]['size'], 'selected signed input changed')
    finally:
        os.close(descriptor)
    require(kit_module.inspect(args)['metadata_sha256'] == trust['envelope_sha256'], 'kit changed during source validation')
    return selection

BASELINE_BYTES = b'abseil-cpp 20260817.0-2\nacl 2.4.0-1\nadwaita-cursors 51.0-1\nadwaita-fonts 51.0-2\nadwaita-icon-theme 51.0-1\nadwaita-icon-theme-legacy 46.2-3\nalacritty 0.17.0-1\nalsa-card-profiles 1:1.6.9-1\nalsa-lib 1.2.16.1-1\nalsa-topology-conf 1.2.5.1-4\nalsa-ucm-conf 1.2.16.1-1\naquamarine 0.15.1-1\narchlinux-keyring 20260909-1\narchlinuxarm-keyring 20240419-2\nat-spi2-core 2.62.1-1\natkmm 2.28.5-2\nattr 2.6.0-1\naudit 4.2.1-1\nautoconf 2.73-1\nautomake 1.19-1\navahi 1:0.9rc5-1\nbase 3-3\nbase-devel 1-2\nbash 5.3.20-1\nbenchmark 1.9.5-2\nbinutils 2.46+r70+g155188ea10a7-1\nbison 3.8.2-8\nbluez 5.87-2\nbluez-libs 5.87-2\nbluez-utils 5.87-2\nboost-libs 1.92.0-1\nbrightnessctl 0.5.1-3\nbrotli 1.2.0-1\nbubblewrap 0.13.0-1\nbzip2 1.0.8-6\nca-certificates 20240618-1\nca-certificates-mozilla 3.131-1\nca-certificates-utils 20240618-1\ncairo 1.18.6-1\ncairomm 1.14.6-1\ncairomm-1.16 1.18.1-1\ncmake 4.4.4-1\ncoreutils 9.12-2\ncpio 2.15-3\ncppdap 1.58.0-3\ncryptsetup 2.8.8-1\ncurl 8.22.0-1\ndav1d 1.5.4-1\ndb5.3 5.3.28-7\ndbus 1.16.2-1\ndbus-broker 37-3\ndbus-broker-units 37-3\ndbus-units 37-3\ndconf 51.0-1\ndebugedit 5.3-2\ndefault-cursors 3-1\ndesktop-file-utils 0.28-1\ndevice-mapper 2.03.43-2\ndhcpcd 10.5.2-1\ndiffutils 3.12-2\ndouble-conversion 3.4.0-1\nduktape 2.7.0-7\ne2fsprogs 1.47.4-1\nelfutils 0.196-1\nex-vi-compat 3-1\nexo 4.20.0-2\nexpat 2.9.0-1\nfakeroot 1:1.37.2-3\nffmpeg 2:9.0.2-2\nfftw 3.3.11-1\nfile 5.48-1\nfilesystem 2025.10.12-1\nfindutils 4.11.0-1\nfirefox 157.0.1-1\nfish 4.9.3-1\nflac 1.5.0-1\nflex 2.6.4-6\nfmt 12.2.0-1\nfontconfig 2:2.18.3-2\nfreetype2 2.14.3-1\nfribidi 1.0.17-1\nfuse-common 3.18.3-1\nfuse3 3.18.3-1\ngawk 5.4.1-1\ngc 8.2.12-1\ngcc 16.1.1+r12+g301eb08fa2c5-1\ngcc-libs 16.1.1+r12+g301eb08fa2c5-1\ngcr 3.41.2-2\ngcr-4 4.4.1-1\ngdb 18.1-1\ngdb-common 18.1-1\ngdbm 1.26-2\ngdk-pixbuf2 2.44.8-1\ngettext 1.0-2\ngiflib 6.1.3-2\ngit 2.56.0-1\nglib-networking 1:2.90.0-1\nglib2 2.90.1-1\nglibc 2.43+r22+g8362e8ce10b2-2\nglibmm 2.66.10-1\nglibmm-2.68 2.90.0-1\nglslang 1:1.4.363.0-1\nglycin 2.2.2-1\ngmp 6.3.0-3\ngnome-keyring 1:51.1-1\ngnulib-l10n 20241231-1\ngnupg 2.4.9-3\ngnutls 3.8.13-3\ngperftools 2.18.1-1\ngpgme 2.2.0-1\ngpm 1.20.7.r38.ge82d1a6-7\ngpsd 3.27.5-1\ngraphene 1.10.8-2.1\ngraphite 1:1.3.15-1\ngrep 3.12-2\ngrim 1.5.0-2\ngroff 1.24.2-1\ngsettings-desktop-schemas 51.0-1\ngsettings-system-schemas 51.0-1\ngsm 1.0.24-1\ngssdp 1.6.6-1\ngst-plugins-bad-libs 1.28.8-1\ngst-plugins-base-libs 1.28.8-1\ngstreamer 1.28.8-1\ngtest 1.18.0-1\ngtk-layer-shell 0.10.1-1\ngtk-update-icon-cache 1:4.24.1-1\ngtk3 1:3.24.52-2\ngtk4 1:4.24.1-1\ngtkmm-4.0 4.24.0-1\ngtkmm3 3.24.11-1\nguile 3.0.11-1\ngupnp 1:1.6.10-1\ngupnp-igd 1.6.0-2\ngvfs 1.62.0-3\ngzip 1.15-1\nharfbuzz 14.6.0-1\nhicolor-icon-theme 0.18-1\nhidapi 0.15.0-1\nhighway 1.4.0-1\nhwdata 0.412-1\nhyprcursor 0.1.13-7\nhyprgraphics 0.5.1-4\nhyprland 0.56.2-4\nhyprland-guiutils 0.2.2-4\nhyprland-qt-support 0.1.0-14\nhyprlang 0.6.8-5\nhyprpolkitagent 0.2.0-1\nhyprtoolkit 0.6.0-1\nhyprutils 0.14.2-1\nhyprwire 0.3.1-3\niana-etc 20260617-1\nicu 78.3-1\niniparser 4.3.2-1\niproute2 7.2.0-1\niptables 1:1.8.13-1\niputils 20250605-1\niso-codes 4.20.1-1\njansson 2.15.1-1\njbigkit 2.1-8\njson-c 0.19-1\njson-glib 1.10.8-1\njsoncpp 1.9.8-1\nkbd 2.10.0-1\nkeyutils 1.6.3-4\nkmod 34.2-1\nkrb5 1.22.2-1\nl-smash 2.14.5-4\nlame 4.0-1\nlcms2 2.19.1-1\nleancrypto 1.9.1-1\nless 1:710-1\nlibappindicator 12.10.1-2\nlibarchive 3.8.9-1\nlibasan 16.1.1+r12+g301eb08fa2c5-1\nlibass 0.17.5-1\nlibassuan 3.0.0-1\nlibasyncns 1:0.8+r3+g68cd5af-3\nlibatasmart 0.19-8\nlibatomic 16.1.1+r12+g301eb08fa2c5-1\nlibavc1394 0.5.4-7\nlibb2 0.98.1-3\nlibblockdev 3.5.0-2\nlibblockdev-crypto 3.5.0-2\nlibblockdev-fs 3.5.0-2\nlibblockdev-loop 3.5.0-2\nlibblockdev-mdraid 3.5.0-2\nlibblockdev-nvme 3.5.0-2\nlibblockdev-part 3.5.0-2\nlibblockdev-smart 3.5.0-2\nlibblockdev-swap 3.5.0-2\nlibbluray 1.5.1-1\nlibbpf 1.7.0-1\nlibbs2b 3.1.0-10\nlibbsd 0.12.2-2\nlibbytesize 2.12-3\nlibcanberra 1:0.30+r2+gc0620e4-6\nlibcap 2.78-1\nlibcap-ng 0.9.6-1\nlibcdio 2.4.0-1\nlibcdio-paranoia 10.2+2.0.2-3\nlibcloudproviders 0.4.1-1\nlibcolord 1.4.8-1\nlibcups 2:2.4.20-1\nlibdaemon 0.14-6\nlibdatrie 0.2.14-1\nlibdbusmenu-glib 18.10.20180917-2\nlibdbusmenu-gtk3 18.10.20180917-2\nlibdecor 0.2.5-1\nlibdeflate 1.26-1\nlibdisplay-info 0.3.0-1\nlibdovi 3.4.0-1\nlibdrm 2.4.134-1\nlibdvdnav 7.0.0-1\nlibdvdread 7.1.1-1\nlibebur128 1.2.6-2\nlibedit 20260512_3.1-1\nlibei 1.6.0-1\nlibelf 0.196-1\nlibepoxy 1.5.10-3\nlibevdev 1.14.0-1\nlibevent 2.1.13-2\nlibexif 0.6.26-1\nlibfdk-aac 3.0.0-1\nlibffi 3.8.0-1\nlibfontenc 1.1.9-1\nlibfreeaptx 0.2.2-1\nlibgcc 16.1.1+r12+g301eb08fa2c5-1\nlibgcrypt 1.12.4-1\nlibgfortran 16.1.1+r12+g301eb08fa2c5-1\nlibglvnd 1.7.0-3\nlibgomp 16.1.1+r12+g301eb08fa2c5-1\nlibgpg-error 1.61-1\nlibgtop 2.41.3-2\nlibgudev 238-3\nlibice 1.1.2-1\nlibidn2 2.3.8-1\nlibiec61883 1.2.0-9\nlibimobiledevice 1.4.0-2\nlibimobiledevice-glue 1.3.2-1\nlibinih 62-2\nlibinput 1.32.0-1\nlibisl 0.28-1\nlibjpeg-turbo 3.2.0-2\nlibjxl 0.12.0-1\nlibksba 1.8.1-1\nliblc3 1.1.3-2\nlibldac 2.0.2.6-1\nlibldap 2.7.1-1\nliblsan 16.1.1+r12+g301eb08fa2c5-1\nlibmakepkg-dropins 20-2\nlibmd 1.3.0-1\nlibmm-glib 1.24.2-1\nlibmnl 1.0.5-2\nlibmodplug 0.8.9.0-7\nlibmpc 1.4.1-1\nlibmpdclient 2.27-1\nlibmysofa 1.3.5-1\nlibndp 1.9-1\nlibnetfilter_conntrack 1.1.1-1\nlibnewt 0.52.25-2\nlibnfnetlink 1.0.2-2\nlibnftnl 1.3.2-1\nlibnghttp2 1.70.0-1\nlibnghttp3 1.18.0-1\nlibngtcp2 1.25.0-1\nlibnice 0.1.24-1\nlibnl 3.12.0-1\nlibnm 1.58.1-2\nlibnma 1.10.6-3\nlibnma-common 1.10.6-3\nlibnotify 0.8.8-1\nlibnsl 2.0.1-2\nlibnvme 1.16.2-2\nlibobjc 16.1.1+r12+g301eb08fa2c5-1\nlibogg 1.3.6-1\nlibopenmpt 0.8.9-1\nlibp11-kit 0.26.5-1\nlibpcap 1.11.0-1\nlibpciaccess 0.19-1\nlibpgm 5.3.128-4\nlibpipeline 1.5.8-1\nlibpipewire 1:1.6.9-1\nlibplacebo 7.360.1-7\nlibplist 2.7.0-3\nlibpng 1.6.59-1\nlibproxy 0.5.12-1\nlibpsl 0.21.5-2\nlibpulse 17.0+r98+gb096704c0-1\nlibquadmath 16.1.1+r12+g301eb08fa2c5-1\nlibraw1394 2.1.2-4\nlibrsvg 2:2.63.2-1\nlibsamplerate 0.2.2-3\nlibsasl 2.1.28-5\nlibseccomp 2.6.0-1\nlibsecret 0.21.8.2-1\nlibsigc++ 2.12.2-1\nlibsigc++-3.0 3.8.1-1\nlibsm 1.2.6-1\nlibsndfile 1.2.2-4\nlibsodium 1.0.22-1\nlibsoup3 3.8.0-1\nlibsoxr 0.1.3-5\nlibssh 0.12.2-1\nlibssh2 1.11.1-7\nlibstdc++ 16.1.1+r12+g301eb08fa2c5-1\nlibstemmer 3.1.1-1\nlibsysprof-capture 51.0-1\nlibtasn1 4.21.0-1\nlibtatsu 1.0.5-1\nlibteam 1.32-3\nlibthai 0.1.30-1\nlibtheora 1.2.0-1\nlibtiff 4.7.2-1\nlibtirpc 1.3.8-1\nlibtool 2.6.0+r23+gb08cb0a0-1\nlibtsan 16.1.1+r12+g301eb08fa2c5-1\nlibubsan 16.1.1+r12+g301eb08fa2c5-1\nlibunibreak 7.0-1\nlibunistring 1.4.2-1\nlibunwind 1.8.3-1\nliburing 2.15-1\nlibusb 1.0.30-1\nlibusbmuxd 2.1.1-2\nlibuv 1.52.1-2\nlibva 2.24.1-1\nlibvdpau 1.5-4\nlibverto 0.3.2-6\nlibvorbis 1.3.7-4\nlibvpx 1.17.0-1\nlibwacom 2.20.0-1\nlibwebp 1.6.0-2\nlibwireplumber 0.5.18-1\nlibx11 1.8.13-2\nlibxau 1.0.12-1\nlibxcb 1.17.0-1\nlibxcomposite 0.4.7-1\nlibxcrypt 4.5.2-1\nlibxcursor 1.2.3-1\nlibxcvt 0.1.3-1\nlibxdamage 1.1.7-1\nlibxdmcp 1.1.5-2\nlibxext 1.3.7-1\nlibxfce4ui 4.20.2-1\nlibxfce4util 4.20.1-1\nlibxfixes 6.0.2-1\nlibxfont2 2.0.9-1\nlibxft 2.3.9-1\nlibxi 1.8.3-1\nlibxinerama 1.1.6-1\nlibxkbcommon 1.13.2-1\nlibxkbcommon-x11 1.13.2-1\nlibxkbfile 1.2.0-1\nlibxml2 2.15.4-1\nlibxrandr 1.5.5-1\nlibxrender 0.9.12-1\nlibxshmfence 1.3.3-1\nlibxss 1.2.5-1\nlibxt 1.3.1-1\nlibxtst 1.2.5-1\nlibxv 1.0.13-1\nlibxxf86vm 1.1.7-1\nlibzip 1.11.4-1\nlicenses 20240728-1\nlilv 0.28.0-1\nlinux-aarch64 7.2.10-1\nlinux-api-headers 7.2-1\nlinux-firmware 20260916-1\nlinux-firmware-amd 20260916-1\nlinux-firmware-amdgpu 20260916-1\nlinux-firmware-atheros 20260916-1\nlinux-firmware-broadcom 20260916-1\nlinux-firmware-cirrus 20260916-1\nlinux-firmware-intel 20260916-1\nlinux-firmware-mediatek 20260916-1\nlinux-firmware-nvidia 20260916-1\nlinux-firmware-other 20260916-1\nlinux-firmware-radeon 20260916-1\nlinux-firmware-realtek 20260916-1\nlinux-firmware-ti 20260916-1\nlinux-firmware-whence 20260916-1\nllvm-libs 23.1.1-1\nlm_sensors 1:3.6.2-1\nlmdb 0.9.35-1\nlua 5.5.1-1\nlua54 5.4.9-1\nlv2 1.18.10-2\nlz4 1:1.10.0-2\nlzo 2.10-5\nm4 1.4.21-2\nmailcap 2.1.54-3\nmake 4.4.1-3\nmako 1.11.0-1\nman-db 2.13.1-2\nmd4c 0.6.0-2\nmdadm 4.6-2\nmesa 1:26.2.4-1\nmeson 1.12.1-2\nmkinitcpio 42.2-1\nmkinitcpio-busybox 1.36.1-1\nmobile-broadband-provider-info 20251101-1\nmpdecimal 4.0.1-3\nmpfr 4.2.2-1\nmpg123 1.33.7-1\nmtdev 1.1.7-1\nmuparser 2.3.5-2\nnano 9.2-1\nncurses 6.6-2\nnet-tools 2.10-3\nnetctl 1.29-2\nnettle 4.0-1\nnetwork-manager-applet 1.36.0-2\nnetworkmanager 1.58.1-2\nnftables 1:1.1.7-3\nninja 1.13.2-3\nnm-connection-editor 1.36.0-2\nnoto-fonts 1:2026.10.01-1\nnoto-fonts-emoji 1:2.051-1\nnpth 1.8-1\nnspr 4.40-1\nnss 3.131-1\nnumactl 2.0.19-1\nocl-icd 2.3.5-1\nopencore-amr 0.1.6-2\nopenjpeg2 2.5.4-1\nopenssh 10.6p1-1\nopenssl 3.6.5-1\nopus 1.6.1-1\norc 0.4.44-1\np11-kit 0.26.5-1\npacman 7.1.0.r9.g54d9411-2\npacman-mirrorlist 20260411-2\npam 1.7.3-1\npambase 20260616-1\npango 1:1.58.2-1\npangomm 2.46.5-1\npangomm-2.48 2.58.0-1\nparted 3.8-1\npatch 2.8-1\npavucontrol 1:6.2-1\npciutils 3.15.0-1\npcre 8.45-5\npcre2 10.49-1\npcsclite 2.5.2-1\nperl 5.42.3-1\nperl-error 0.17030-3\nperl-mailtools 2.22-3\nperl-timedate 2.35-1\npinentry 1.3.3-1\npipewire 1:1.6.9-1\npipewire-audio 1:1.6.9-1\npipewire-jack 1:1.6.9-1\npipewire-pulse 1:1.6.9-1\npixman 0.46.4-1.1\npkgconf 3.0.7-1\nplayerctl 2.4.1-5\npolkit 127-3\npolkit-qt6 0.201.1-1\npopt 1.19-2\nportaudio 1:19.7.0-4\npps-tools 1.0.3-2\nprocps-ng 4.0.7-1\npsmisc 23.7-2\npugixml 1.16-1\npython 3.14.8-1\npython-dbus 1.5.0-1\npython-pyxdg 0.28-8\npython-tqdm 4.70.1-1\nqt6-base 6.12.0-3\nqt6-declarative 6.12.0-1\nqt6-translations 6.12.0-1\nre2 2:2025.11.05-6\nreadline 8.3.6-1\nrhash 1.4.6-1\nrubberband 4.0.0-2\nsbc 2.2-1\nsdbus-cpp 2.3.1-1\nsdl2-compat 2.32.74-1\nsdl3 3.4.18-1\nseatd 0.9.3-1\nsed 4.10-2\nserd 0.32.10-1\nshaderc 2026.4-1\nshadow 4.20.0.arch1-1\nshared-mime-info 2.5.1-2\nslang 2.3.3-4\nslurp 1.5.0-2\nsnappy 1.3.1-1\nsndio 1.10.0-1\nsord 0.16.22-1\nsound-theme-freedesktop 0.8-6\nsource-highlight 3.1.9-19\nspandsp 0.0.6-7\nspdlog 1.17.0-2\nspeex 1.2.1-2\nspeexdsp 1.2.1-2\nspirv-tools 1:1.4.363.0-1\nsqlite 3.54.0-1\nsratom 0.6.22-1\nsrt 1.5.7-2\nstartup-notification 0.12-9\nsudo 1.9.17.p2-6\nswayidle 1.9.0-1\nswaylock 1.8.6-1\nsystemd 262-1\nsystemd-libs 262-1\nsystemd-resolvconf 262-1\nsystemd-sysvcompat 262-1\ntar 1.35-5\ntdb 1.4.15-2\ntexinfo 7.3-1\nthunar 4.20.10-1\ntinysparql 3.12.0-1\ntomlplusplus 3.4.0-1\ntpm2-tss 4.2.0-2\ntslib 1.24-1\nttf-dejavu 2.37+18+g9b5d1b2f-8\ntzdata 2026e-1\nudisks2 2.11.2-1\nupower 1.91.5-1\nutil-linux 2.42.4-1\nutil-linux-libs 2.42.4-1\nuwsm 0.27.0-1\nv4l-utils 1.32.0-2\nvapoursynth 80-1\nvid.stab 1.1.2-1\nvim 9.2.1178-1\nvim-runtime 9.2.1178-1\nvmaf 3.2.1-1\nvolume_key 0.3.12-12\nvulkan-icd-loader 1.4.363.0-1\nwaybar 0.15.0-3\nwayland 1.26.0-1\nwayland-protocols 1.49-1\nwebrtc-audio-processing-1 1.3-5\nwhich 2.25-1\nwireplumber 0.5.18-1\nwl-clipboard 1:2.3.0-1\nwofi 1.5.3-1\nwpa_supplicant 2:2.12-1\nx264 3:0.165.r3222.b35605a-2\nx265 4.3-1\nxcb-proto 1.17.0-4\nxcb-util 0.4.1-2\nxcb-util-cursor 0.1.6-1\nxcb-util-errors 1.0.1-2\nxcb-util-image 0.4.1-3\nxcb-util-keysyms 0.4.1-5\nxcb-util-renderutil 0.3.10-2\nxcb-util-wm 0.4.2-2\nxdg-desktop-portal 1.22.1-2\nxdg-desktop-portal-gtk 1.15.3-1\nxdg-desktop-portal-hyprland 1.4.1-2\nxdg-user-dirs 0.20-1\nxdg-utils 1.2.1-2\nxfconf 4.20.0-2\nxkeyboard-config 2.48-1\nxorg-fonts-encodings 1.1.0-2\nxorg-server-common 21.1.25-1\nxorg-setxkbmap 1.3.5-1\nxorg-xkbcomp 1.5.0-1\nxorg-xprop 1.2.8-1\nxorg-xwayland 24.1.14-1\nxorgproto 2026.1-1\nxvidcore 1.3.7-4\nxxhash 0.8.4-1\nxz 5.8.4-1\nzeromq 4.3.5-3\nzimg 3.0.6-2\nzix 0.8.2-1\nzlib 1:1.3.2-3\nzlib-ng 2.3.3-1\nzsh 5.9.2-1\nzstd 1.5.7-3\n'
