#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded passive native DATA reader; no retained imports or actor authority."""
import argparse
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile

MAX_CAPSULE, MAX_MEMBER, MAX_MEMBERS = 32 * 1024**2, 8 * 1024**2, 512
LOCK_SHA = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
LABEL = 'org.cachy-asahi.support-native'
CAPS = {'CHOWN', 'FOWNER', 'DAC_OVERRIDE', 'SETUID', 'SETGID'}
CLOSURE_SHA = 'f87609bff1a5e29f97ec49babd45ee382b13169a201509a8b5f1acd168cae378'
RECIPE_ROOT = 'packages/tools/cachy-asahi-support2'
CHECK_METHODS = ('test_collector_tamper_refused_before_launch', 'test_exact_payload_metadata_and_new_command',
    'test_installed_collect_explicit_health_selection', 'test_new_source_pin_and_payload_refusal',
    'test_real_headless_collect_verify_relocation_without_checkout',
    'test_unchanged_create_verify_preserves_fixture_failures_and_unknowns')

def need(ok, message):
    if not ok:
        raise ValueError(message)

def fields(value, names):
    need(type(value) is dict and set(value) == set(names.split()), 'unexpected data fields')

def hexadecimal(value, length=64):
    need(type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value), 'explicit lowercase hex identity required')
    return value

def relative(name):
    need(type(name) is str and 0 < len(name) <= 255 and '\\' not in name, 'bounded POSIX member path')
    path = PurePosixPath(name)
    need(not path.is_absolute() and '..' not in path.parts and path.as_posix() == name and name != '.', 'unsafe member path')
    need(all(part not in ('private-keys-v1.d', 'openpgp-revocs.d') and not part.startswith('S.gpg-agent') for part in path.parts), 'private signing material forbidden')
    return path

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def check_pin(value, maximum=MAX_MEMBER):
    fields(value, 'bytes sha256')
    need(type(value['bytes']) is int and 0 <= value['bytes'] <= maximum, 'bounded byte count')
    hexadecimal(value['sha256'])

def decode(raw):
    def pairs(rows):
        value = {}
        for name, item in rows:
            need(name not in value, 'duplicate JSON key')
            value[name] = item
        return value
    def invalid(_):
        raise ValueError('nonfinite JSON number')
    def floating(value):
        result = float(value)
        need(math.isfinite(result), 'nonfinite JSON number')
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_float=floating, parse_constant=invalid)

def read(path, maximum=MAX_CAPSULE):
    path = Path(os.path.abspath(path))
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum, 'bounded ordinary single-link file required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        stable = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
        need(stable(before) == stable(after) and len(raw) == before.st_size, 'input changed during read')
        return raw
    finally:
        os.close(fd)

def canonical_tar(members):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(members.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(raw), 0o644, 0
            archive.addfile(info, io.BytesIO(raw))
    return stream.getvalue()

def unpack_capsule(raw, expected):
    need(0 < len(raw) <= MAX_CAPSULE and pin(raw)['sha256'] == expected['capsule_sha256'], 'capsule wire size/hash mismatch')
    members, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for row in archive:
            relative(row.name)
            need(row.name not in members and row.isfile() and row.type == tarfile.REGTYPE
                 and not row.pax_headers and not row.linkname and row.mode == 0o644
                 and row.uid == row.gid == row.mtime == 0 and not row.uname and not row.gname,
                 'noncanonical/link/duplicate capsule member')
            need(0 <= row.size <= MAX_MEMBER and len(members) < MAX_MEMBERS, 'capsule member bound')
            total += row.size
            need(total <= MAX_CAPSULE, 'capsule expansion bound')
            members[row.name] = archive.extractfile(row).read(MAX_MEMBER + 1)
    need(canonical_tar(members) == raw and 'capsule.json' in members, 'exact canonical capsule required')
    manifest = decode(members.pop('capsule.json'))
    fields(manifest, 'schema binding source_map_sha256 files')
    need(type(manifest['schema']) is int and manifest['schema'] == 1
         and manifest['binding'] == {k: expected[k] for k in ('source_sha', 'ref', 'run_id', 'attempt')}
         and manifest['source_map_sha256'] == expected['source_map_sha256'], 'capsule actual/source map binding differs')
    need(type(manifest['files']) is dict and set(manifest['files']) == set(members), 'closed capsule inventory')
    for name, row in manifest['files'].items():
        check_pin(row)
        need(pin(members[name]) == row, 'capsule member checksum mismatch')
    return members

def admission(expected, policy):
    # This guard deliberately precedes all capsule/file reads and output handling.
    fields(expected, 'source_sha ref run_id attempt source_map_sha256 capsule_sha256')
    hexadecimal(expected['source_sha'], 40)
    hexadecimal(expected['source_map_sha256'])
    hexadecimal(expected['capsule_sha256'])
    need(type(expected['ref']) is str and re.fullmatch(r'refs/heads/codex/[A-Za-z0-9][A-Za-z0-9._/-]{0,160}', expected['ref'])
         and '..' not in expected['ref'] and not expected['ref'].endswith('/'), 'actual Root-selected ref required')
    need(type(expected['run_id']) is str and re.fullmatch('[1-9][0-9]{0,19}', expected['run_id'])
         and type(expected['attempt']) is int and expected['attempt'] == 1, 'first actual run required')
    need(type(policy) is dict and type(policy.get('schema')) is int and policy['schema'] == 1, 'reader policy required')
    selected = policy.get('selected_package')
    need(type(selected) is dict and type(selected.get('schema')) is int and selected['schema'] == 1
         and selected.get('selection_status') == 'ROOT_AUTHORIZED_SEALED_V2_PACKET', 'NULL/unsealed package selection refused before originals')
    fields(selected['package'], 'name version arch depends license')
    need(selected['package'] == dict(name='cachy-asahi-support', version='0.2.0-1', arch='any',
         depends=['python>=3.11'], license=['MIT']), 'exact final support v2 identity required')
    need(selected.get('candidate_source') is None and selected.get('closure_sha256') == selected.get('seal_sha256') == CLOSURE_SHA
         and selected.get('recipe_root') == RECIPE_ROOT, 'exact Root-authorized sealed packet identity required')
    hexadecimal(selected.get('recipe_sha256'))
    base = policy.get('base_input_admission')
    fields(base, 'status receipt_sha256')
    need(base['status'] == 'ROOT_RESOLVED_BASE_INPUT_ACQUISITIONS', 'unresolved base acquisition refused before originals')
    hexadecimal(base['receipt_sha256'])
    need(policy.get('original341_sha256') == LOCK_SHA, 'exact original341 binding required')
    need(policy.get('input_counts') == dict(base=5, package_signature=496, total=501, extras=0)
         and all(type(v) is int for v in policy['input_counts'].values()), 'exact original501 input scope required')
    installed = policy.get('installed341')
    need(type(installed) is list and all(type(s) is str for s in installed)
         and len(installed) == len(set(installed)) == 341
         and all(re.fullmatch('[A-Za-z0-9@._+~:-]+-(aarch64|any)', s) for s in installed), 'complete BUILDINFO installed inventory required')
    policy_tables(selected, policy)
    return selected

def policy_tables(selected, policy):
    for table, minimum, maximum in ((selected.get('files'), 19, 19), (selected.get('payload'), 12, 12),
                                     (policy.get('source_files'), 1, 200)):
        need(type(table) is dict and minimum <= len(table) <= maximum, 'finite source/payload closure required')
        for name, row in table.items():
            relative(name)
            need(type(row) is dict and set(row) in ({'bytes', 'sha256', 'mode'}, {'bytes', 'sha256', 'mode', 'blob'}), 'source/payload pin fields')
            check_pin({k: row[k] for k in ('bytes', 'sha256')})
            need(type(row['mode']) is int and row['mode'] in (0o644, 0o755), 'source/payload mode')
            if 'blob' in row:
                hexadecimal(row['blob'], 40)
    runtime = {'collect_support.py': '2116e931e91ceed87627eeeb1acec2da1158a523c7c2f71fc2f4b4b41936159e',
               'support_bundle.py': '2fff76ad4df036f383927381b0b56c89904c3087f7ca151902ba80fb8c82bdc8',
               'doctor.py': 'ddd8c3cedc5ba1291dcdd2d1d7a188e5b4d4a4ac7323ffe6f7ee554f6687d41e',
               'session_probe.py': '9c5c41899cd991b0de4bf8d30bad6f5452b4592ea9440df0f0b4a7b54bc66984'}
    prefix = RECIPE_ROOT + '/'
    for name, checksum in runtime.items():
        need(selected['files'][prefix + name]['sha256'] == checksum, 'held runtime bytes changed')
    need(selected['files'][prefix + 'PKGBUILD']['sha256'] == selected['recipe_sha256'], 'recipe selection mismatch')
    need(all(name.startswith(('usr/bin/cachy-asahi-support', 'usr/lib/cachy-asahi/support/',
         'usr/share/doc/cachy-asahi-support/', 'usr/share/licenses/cachy-asahi-support/')) for name in selected['payload']), 'private support payload namespace')
    contract = selected.get('cli_contract')
    need(type(contract) is dict and set(contract) in ({'collect', 'create', 'verify'}, {'collect', 'create', 'verify', 'session_relative'}), 'sealed CLI contract')
    for name in ('collect', 'create', 'verify'):
        argv = contract[name]
        need(type(argv) is list and 1 <= len(argv) <= 48 and argv[0] == name
             and all(type(s) is str and 0 < len(s) <= 512 and s.isprintable() for s in argv), 'finite support argv')
    if 'session_relative' in contract:
        relative(contract['session_relative'])
    need(type(selected.get('metadata')) is dict, 'complete selected SRCINFO metadata required')

def metadata(raw):
    value = {}
    need(0 < len(raw) <= 128 * 1024, 'bounded package metadata')
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([a-z][a-z0-9_]*) = ([^\r\n]{1,4096})', line)
        need(match is not None, 'malformed package metadata')
        value.setdefault(match[1], []).append(match[2])
    return value

def package_archive(raw, selected, policy):
    need(0 < len(raw) <= MAX_MEMBER, 'finite actual raw package archive')
    payload, data, directories = selected['payload'], {}, set()
    allowed_dirs = {str(p) for name in payload for p in PurePosixPath(name).parents if str(p) != '.'}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for row in archive:
            name = row.name.removeprefix('./').rstrip('/')
            if name in ('', '.'):
                need(row.isdir(), 'package root must be directory')
                continue
            relative(name)
            need(name not in data and name not in directories and row.uid == row.gid == 0
                 and not row.issym() and not row.islnk() and not row.linkname, 'unsafe/duplicate package member')
            if row.isdir():
                need(name in allowed_dirs and row.mode == 0o755, 'unexpected package directory')
                directories.add(name)
                continue
            need(row.isfile() and name in set(payload) | {'.PKGINFO', '.BUILDINFO', '.MTREE'}
                 and 0 < row.size <= MAX_MEMBER, 'unexpected package file')
            body = archive.extractfile(row).read(MAX_MEMBER + 1)
            need(row.mode == (payload[name]['mode'] if name in payload else 0o644), 'package file mode')
            data[name] = body
            if name in payload:
                need(pin(body) == {k: payload[name][k] for k in ('bytes', 'sha256')}, 'actual package payload differs')
    need(set(data) == set(payload) | {'.PKGINFO', '.BUILDINFO', '.MTREE'}, 'complete actual package payload required')
    validate_metadata(data, selected, policy)
    return data

def validate_metadata(data, selected, policy):
    pkg, build = metadata(data['.PKGINFO']), metadata(data['.BUILDINFO'])
    info = selected['metadata']
    expected = selected['package']
    for key, want in dict(pkgname=[expected['name']], pkgbase=[expected['name']], pkgver=[expected['version']],
                          arch=[expected['arch']], license=expected['license']).items():
        need(pkg.get(key) == want, 'actual PKGINFO identity mismatch')
    relations = {'depends': 'depend', 'makedepends': 'makedepend', 'checkdepends': 'checkdepend', 'groups': 'group',
                 'optdepends': 'optdepend', 'provides': 'provides', 'conflicts': 'conflict',
                 'replaces': 'replaces', 'backup': 'backup'}
    for source, key in relations.items():
        want = info.get(source, []) + info.get(source + '_aarch64', [])
        need(sorted(pkg.get(key, [])) == sorted(want), 'full actual PKGINFO relationships mismatch')
    need(not set(pkg) - {'pkgname', 'pkgbase', 'pkgver', 'pkgdesc', 'url', 'builddate', 'packager', 'size',
                         'arch', 'license', 'xdata', *relations.values()}, 'unexpected PKGINFO fields')
    need(pkg.get('xdata') == ['pkgtype=pkg'] + info.get('xdata', []), 'exact selected package xdata')
    for key in ('pkgdesc', 'url', 'builddate', 'packager', 'size'):
        need(len(pkg.get(key, [])) == 1, 'complete single-valued PKGINFO')
    need(pkg['pkgdesc'] == info.get('pkgdesc') and pkg['url'] == info.get('url'), 'selected description/URL mismatch')
    for key, want in dict(format=['2'], pkgname=[expected['name']], pkgbase=[expected['name']], pkgver=[expected['version']],
                          pkgarch=[expected['arch']], pkgbuild_sha256sum=[selected['recipe_sha256']]).items():
        need(build.get(key) == want, 'actual BUILDINFO recipe/identity mismatch')
    need(not set(build) - {'format', 'pkgname', 'pkgbase', 'pkgver', 'pkgarch', 'pkgbuild_sha256sum',
             'packager', 'builddate', 'builddir', 'startdir', 'buildenv', 'options', 'installed', 'buildtool', 'buildtoolver'}, 'unexpected BUILDINFO fields')
    need(build.get('buildtool') == [policy['expected_buildtool']] == ['makepkg']
         and build.get('buildtoolver') == [policy['expected_buildtoolver']], 'exact selected build writer identity')
    need(sorted(build.get('installed', [])) == sorted(policy['installed341']), 'exact341 BUILDINFO inventory required')
    for key in ('packager', 'builddate', 'builddir', 'startdir'):
        need(len(build.get(key, [])) == 1, 'single-valued BUILDINFO field')

def consumer(row, role, report, binding, token):
    host, config = row['HostConfig'], row['Config']
    need(row['Name'] == '/support-' + role + '-' + token and row['Image'] == report['image']
         and config['Labels'].get(LABEL) == token and config['Labels'].get(LABEL + '.source') == binding['source_sha']
         and config['Labels'].get(LABEL + '.run') == binding['run_id']
         and config['User'] == ('0:0' if role == 'lifecycle' else str(report['uid']) + ':' + str(report['gid'])), 'exact role/image/user')
    need(host['NetworkMode'] == 'none' and host['Privileged'] is False and host['ReadonlyRootfs'] is (role != 'lifecycle')
         and type(host['Memory']) is int and host['Memory'] == 2*1024**3 and type(host['NanoCpus']) is int
         and host['NanoCpus'] == 2_000_000_000 and type(host['PidsLimit']) is int and host['PidsLimit'] == 128
         and set(host['CapDrop']) == {'ALL'} and set(host.get('CapAdd') or []) == (CAPS if role == 'lifecycle' else set())
         and host['SecurityOpt'] == ['no-new-privileges'] and not host.get('Devices') and not host.get('DeviceRequests')
         and not host.get('VolumesFrom') and not host.get('PortBindings'), 'actual role isolation/resources')
    wanted = {('/source', report['source_root'], False), ('/out', report['output_root'] + '/' + role, True)}
    if role == 'lifecycle':
        wanted.add(('/packages', report['output_root'] + '/build1', False))
    binds = {(m['Destination'], m['Source'], m['RW']) for m in row['Mounts'] if m['Type'] == 'bind'}
    need(binds == wanted and all(m['Type'] == 'bind' or (m['Type'] == 'tmpfs' and m['Destination'] == '/tmp') for m in row['Mounts'])
         and set(host['Tmpfs']) == {'/tmp'} and set(host['Tmpfs']['/tmp'].split(',')) == {'rw', 'nosuid', 'nodev', 'exec', 'size=1g'}, 'exact finite role mounts')

def retirement(state):
    need(type(state) is dict and state.get('natural_exit') is True and state.get('group_absent') is True
         and state.get('leader_held_until_group_inspection') is True and state.get('exit_observed_via_waitpid') is True
         and state.get('ownership_lost') is False and state.get('forced_cleanup') is False
         and state.get('retirement') == 'REAPED', 'direct natural owned retirement required')

def exact_check_log(raw):
    text = raw.decode('utf-8')
    results = re.findall(r'^([A-Za-z0-9_]+) \([^\n]+\) \.\.\. ([^\n]+)$', text, re.M)
    need(results == [(name, 'ok') for name in CHECK_METHODS]
         and len(re.findall(r'^Ran 6 tests in [0-9.]+s$', text, re.M)) == 1
         and len(re.findall(r'^OK$', text, re.M)) == 1
         and not re.search(r'\b(skipped|FAILED|FAIL|ERROR|expected failure|unexpected success)\b', text),
         'exact six frozen methods must actually pass without skips in raw check log')

def actor_rows(rows, members):
    need(type(rows) is list and 0 < len(rows) <= 256, 'finite actual actor records')
    for row in rows:
        relative(row['public_log'])
        need(row['status'] == 'PASS' and type(row['exit']) is int and row['exit'] == 0
             and row['public_log'] in members and pin(members[row['public_log']]) == row['log_pin'], 'actor log/exit mismatch')
        retirement(row)

def command_rows(rows, prefix, members):
    need(type(rows) is list and 0 < len(rows) <= 128, 'finite actual guest commands')
    for row in rows:
        relative(row['log'])
        name = prefix + '/' + row['log']
        need(row['status'] == 'PASS' and type(row['expected_exit']) is int and row['expected_exit'] in (0, 2)
             and row['supervision']['exit'] == row['expected_exit'] and name in members
             and pin(members[name]) == row['log_pin'], 'guest command exit/log mismatch')
        retirement(row['supervision'])

def private_check_result(members, report, selected, policy, expected):
    needed = {'private-check/proof-result.json', 'private-check/export.json',
              'private-check/check.log', 'private-check/outer.log'}
    need(needed <= members.keys(), 'external exact check proof is mandatory')
    receipt = decode(members['private-check/proof-result.json'])
    exported = decode(members['private-check/export.json'])
    binding = {k: expected[k] for k in ('source_sha', 'ref', 'run_id', 'attempt')}
    proof = report['private_check']
    fields(proof, 'status receipt export exact_check in_makepkg')
    need(proof['status'] == 'PASS_EXTERNAL_EXACT_CHECK_FUNCTION' and proof['exact_check'] is True
         and proof['in_makepkg'] is False and proof['receipt'] == pin(members['private-check/proof-result.json'])
         and proof['export'] == pin(members['private-check/export.json']), 'owner external proof byte binding')
    source_files = {name: row for name, row in selected['files'].items()
                    if PurePosixPath(name).parent.as_posix() == RECIPE_ROOT}
    need(len(source_files) == 17, 'seventeen exact sealed check sources')
    need(type(receipt['schema']) is int and receipt['schema'] == 1
         and receipt['status'] == 'PASS_EXTERNAL_EXACT_CHECK_FUNCTION' and receipt['binding'] == binding
         and receipt['source_map_sha256'] == expected['source_map_sha256'] and receipt['image'] == report['image']
         and receipt['recipe_sha256'] == selected['recipe_sha256'] and receipt['source_files'] == source_files
         and receipt['architecture'] == 'aarch64' and type(receipt['page_size']) is int and receipt['page_size'] > 0
         and type(receipt['uid']) is int and receipt['uid'] == report['uid'] > 0
         and receipt['inventory'] == pin(members['bootstrap/packages.lock']), 'actual source-bound native341 check environment')
    checks = receipt['checks']
    fields(checks, 'count skips methods exit log log_pin')
    need(type(checks['count']) is int and checks['count'] == 6 and type(checks['skips']) is int and checks['skips'] == 0
         and type(checks['exit']) is int and checks['exit'] == 0 and checks['log'] == 'check.log'
         and type(checks['methods']) is list and sorted(checks['methods']) == list(CHECK_METHODS)
         and checks['log_pin'] == pin(members['private-check/check.log']), 'exact six check outcomes bound to raw log')
    exact_check_log(members['private-check/check.log'])
    command_rows(receipt['commands'], 'private-check', members)
    shell = 'set -euo pipefail\nsrcdir=$1\nstartdir=$1\nsource "$1/PKGBUILD"\ncheck\n'
    need(len(receipt['commands']) == 2 and receipt['commands'][0]['argv'] == ['/usr/bin/pacman', '-Q']
         and receipt['commands'][1]['argv'] == ['/usr/bin/bash', '--noprofile', '--norc', '-c', shell,
             'support-external-exact-check', '/source/' + RECIPE_ROOT]
         and receipt['commands'][1]['log'] == 'check.log'
         and all(row['expected_exit'] == 0 for row in receipt['commands']), 'exact unchanged check function invocation')
    inventory_raw = members['private-check/' + receipt['commands'][0]['log']]
    need(b''.join(sorted(inventory_raw.splitlines(keepends=True))) == members['bootstrap/packages.lock'], 'observed exact341 proof inventory')
    need(decode(members['private-check/outer.log']) == receipt, 'actual outer actor output matches inner check receipt')
    private_export(exported, report, expected, source_files, members)
    return receipt

def private_export(exported, report, expected, source_files, members):
    binding = {k: expected[k] for k in ('source_sha', 'ref', 'run_id', 'attempt')}
    need(type(exported['schema']) is int and exported['schema'] == 1 and exported['binding'] == binding
         and exported['source_map_sha256'] == expected['source_map_sha256'] and exported['image'] == report['image']
         and exported['rootfs_export_public'] is False and exported['source_files'] == source_files, 'private exported exact image/source binding')
    hexadecimal(exported['container'])
    need(exported['container'] not in report['containers'].values(), 'independent private proof export container')
    token = hashlib.sha256((binding['source_sha'] + ':' + binding['ref'] + ':' + binding['run_id']).encode()).hexdigest()[:24]
    row = exported['inspect']; host = row['HostConfig']; labels = row['Config']['Labels']
    need(row['Id'] == exported['container'] and row['Image'] == report['image']
         and row['Name'] == '/support-proof-export-' + token and row['State']['Running'] is False
         and row['State']['Status'] == 'created' and labels.get(LABEL) == token
         and labels.get(LABEL + '.source') == binding['source_sha'] and labels.get(LABEL + '.run') == binding['run_id']
         and host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True and host['Privileged'] is False
         and set(host['CapDrop']) == {'ALL'} and not host.get('CapAdd') and host['SecurityOpt'] == ['no-new-privileges']
         and not row.get('Mounts') and not host.get('Devices') and not host.get('DeviceRequests')
         and not host.get('VolumesFrom') and not host.get('PortBindings'), 'unstarted owned readonly isolated proof export')
    material = exported['materialized']
    need(type(material['schema']) is int and material['schema'] == 1
         and material['status'] == 'PASS_PRIVATE_ROOTFS_MATERIALIZATION_ONLY' and material['private_root_mode'] == '0700'
         and material['chown'] is False and material['executed'] is False and material['keys'] == 'PRIVATE_ROOT_ONLY_NOT_PUBLIC_DATA', 'confined private root materialization data')
    check_pin(material['export'], 8 * 1024**3)
    for name in ('members', 'expanded_bytes', 'regular_files', 'hardlinks_copied', 'symlinks_delayed', 'omitted_dev_proc_sys', 'suid_sgid_stripped'):
        need(type(material[name]) is int and 0 <= material[name] <= (8 * 1024**3 if name == 'expanded_bytes' else 150000), 'finite private export derivation')
    need(material['export']['bytes'] > 0 and material['members'] > 0
         and material['expanded_bytes'] > 0 and material['regular_files'] > 0, 'nonempty actual original341 materialization')
    need(material['generated_mountpoints'] == ['dev', 'proc', 'sys', 'run', 'home', 'root', 'tmp', 'source', 'work', 'etc/pacman.d/gnupg'], 'private export generated mountpoints')
    owned = str(PurePosixPath(report['output_root']).parent)
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
        '--ro-bind', owned + '/private-original341-root', '/', '--proc', '/proc', '--dev', '/dev',
        '--tmpfs', '/tmp', '--tmpfs', '/home', '--tmpfs', '/run', '--tmpfs', '/sys', '--tmpfs', '/root', '--tmpfs', '/etc/pacman.d/gnupg',
        '--ro-bind', report['source_root'], '/source', '--bind', owned + '/private-check-work', '/work', '--chdir', '/work',
        '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LC_ALL', 'C', '--setenv', 'HOME', '/tmp/proof-home',
        '--setenv', 'TMPDIR', '/tmp/proof-tmp', '--', '/usr/bin/python3', '-I', '-B', '/source/native/private_check.py', '--inner', '--recipe-root', RECIPE_ROOT]
    need(exported['command'] == command, 'exact nonprivileged original341 outer namespace command')
    actors = [actor for actor in report['actors'] if actor.get('argv') == command]
    need(len(actors) == 1 and actors[0]['log_pin'] == pin(members['private-check/outer.log']), 'actual owned outer proof command and raw log')

def build_result(role, members, selected, policy, expected):
    result = decode(members[role + '/result.json'])
    need(result['schema'] == 1 and type(result['schema']) is int and result['status'] == 'PASS_NATIVE_PACKAGE_BUILD'
         and result['source_map_sha256'] == expected['source_map_sha256'] and result['architecture'] == 'aarch64'
         and type(result['page_size']) is int and result['page_size'] > 0 and type(result['uid']) is int and result['uid'] != 0
         and result['inventory'] == pin(members['bootstrap/packages.lock']) and result['package_identity'] == selected['package']
         and result['recipe_sha256'] == selected['recipe_sha256'] and result['makepkg_check'] == 'EXTERNALIZED_EXACT_CHECK_FUNCTION_REQUIRED'
         and result['makepkg_nocheck'] is True
         and result['SOURCE_DATE_EPOCH'] == 1793065600 and result['native_16K'] == 'NOT_QUALIFIED'
         and result['physical_M2'] == 'NOT_RUN' and result['release'] == 'NOT_ADMITTED', 'actual build result identity/scope')
    data = package_archive(members[role + '/package.pkg.tar'], selected, policy)
    package = result['package']
    need(package['archive'] == pin(members[role + '/package.pkg.tar']) and package['payload'] == selected['payload']
         and package['PKGINFO'] == pin(data['.PKGINFO']) and package['BUILDINFO'] == pin(data['.BUILDINFO'])
         and members[role + '/PKGINFO'] == data['.PKGINFO'] and members[role + '/BUILDINFO'] == data['.BUILDINFO']
         and package['metadata'] == metadata(data['.PKGINFO']) and package['buildinfo'] == metadata(data['.BUILDINFO']), 'actual build raw archive/metadata/payload correspondence')
    need(decode(members[role + '/commands.json']) == result['commands'], 'guest command inventory mismatch')
    command_rows(result['commands'], role, members)
    return result

def host_evidence(members, expected, policy):
    binding = {k: expected[k] for k in ('source_sha', 'ref', 'run_id', 'attempt')}
    report, cleanup = decode(members['report.json']), decode(members['cleanup.json'])
    need(type(report['schema']) is int and report['schema'] == 1 and report['binding'] == binding
         and report['source_map_sha256'] == expected['source_map_sha256']
         and report['status'] == 'PASS_FINITE_NATIVE_PAIR_AND_SIGNED_ALPM_LIFECYCLE'
         and report['native_16K'] == 'NOT_QUALIFIED' and report['physical_M2'] == 'NOT_RUN'
         and report['release'] == 'NOT_ADMITTED' and report['pair'] == dict(archive_equal=True, independent_containers=True)
         and report['makepkg_check'] == 'EXTERNALIZED_EXACT_CHECK_FUNCTION_REQUIRED', 'actual owner completion/scope')
    need(type(report['uid']) is int and report['uid'] > 0 and type(report['gid']) is int and report['gid'] >= 0,
         'ordinary actual owner credentials')
    for name in ('source_root', 'output_root'):
        need(type(report[name]) is str and report[name].startswith('/') and report[name] == str(PurePosixPath(report[name]))
             and '..' not in PurePosixPath(report[name]).parts, 'absolute bounded owner path')
    need(cleanup['status'] == 'PASS_EXACT_OWNED_RESOURCES_RETIRED' and cleanup['containers_absent'] is True
         and cleanup['images_absent'] is True and cleanup['daemon_build_complete'] is True, 'actual ordered owned cleanup')
    actor_rows(report['actors'], members)
    actor_rows(cleanup['actors'], members)
    runner = decode(members['bootstrap/runner.json'])
    need(runner['kernel']['machine'] in ('aarch64', 'arm64') and runner['kernel']['system'] == 'Linux'
         and runner['docker_server_arch'] in ('aarch64', 'arm64') and runner['runner_arch'] == 'ARM64'
         and runner['runner_os'] == 'Linux' and runner['repository'] == 'Gabriel-Kahen/cachy-asahi'
         and runner['commit'] == binding['source_sha'] and runner['run_id'] == binding['run_id']
         and runner['uid'] == report['uid'] and runner['gid'] == report['gid']
         and type(runner['page_size']) is int and runner['page_size'] > 0
         and runner['docker_endpoint'] in ('unix:///var/run/docker.sock', 'unix:///run/docker.sock'), 'actual native local-daemon provenance')
    need(pin(members['bootstrap/packages.lock'])['sha256'] == policy['original341_sha256'], 'original341 bootstrap bytes')
    image = decode(members['bootstrap/image-inspect.json'])
    token = hashlib.sha256((binding['source_sha'] + ':' + binding['ref'] + ':' + binding['run_id']).encode()).hexdigest()[:24]
    labels = image['Config']['Labels']
    need(image['Id'] == report['image'] and image['Architecture'] == 'arm64' and image['Os'] == 'linux'
         and labels.get(LABEL) == token and labels.get(LABEL + '.source') == binding['source_sha']
         and labels.get(LABEL + '.run') == binding['run_id'], 'actual immutable native image binding')
    hexadecimal(report['image'].removeprefix('sha256:'))
    need(type(report['containers']) is dict and set(report['containers']) == {'build1', 'build2', 'lifecycle'}
         and len(set(report['containers'].values())) == 3, 'three independent containers required')
    for role, identity in report['containers'].items():
        hexadecimal(identity)
        for phase in ('before', 'after'):
            row = decode(members[role + '/inspect-' + phase + '.json'])
            need(row['Id'] == identity, 'actual role container ID')
            consumer(row, role, report, binding, token)
            if phase == 'after':
                need(row['State']['Running'] is False and row['State']['ExitCode'] == 0
                     and type(row['State']['ExitCode']) is int and row['State']['Status'] == 'exited', 'actual exited role completion')
    proof = decode(members['source-proof.json'])
    need(proof['binding'] == binding and set(proof['files']) == set(policy['source_files']), 'whole actual published source namespace')
    for name, row in proof['files'].items():
        fields(row, 'mode blob bytes sha256')
        selected = policy['source_files'][name]
        need(row['mode'] == ('100755' if selected['mode'] == 0o755 else '100644')
             and {k: row[k] for k in ('bytes', 'sha256')} == {k: selected[k] for k in ('bytes', 'sha256')}
             and row['blob'] == selected['blob'], 'source Git blob/mode/body pin mismatch')
    return report

def public_fingerprint(raw):
    """Parse public v4 key packet identity only; never verify cryptography."""
    need(0 < len(raw) <= 128 * 1024, 'bounded binary public certificate')
    offset, primary = 0, []
    while offset < len(raw):
        header = raw[offset]
        offset += 1
        need(header & 0x80, 'OpenPGP packet header')
        if header & 0x40:
            tag = header & 0x3f
            need(offset < len(raw), 'OpenPGP length')
            first = raw[offset]
            offset += 1
            if first < 192:
                size = first
            elif first < 224:
                need(offset < len(raw), 'OpenPGP two-byte length')
                size = ((first - 192) << 8) + raw[offset] + 192
                offset += 1
            elif first == 255:
                need(offset + 4 <= len(raw), 'OpenPGP long length')
                size = int.from_bytes(raw[offset:offset+4], 'big')
                offset += 4
            else:
                raise ValueError('partial OpenPGP lengths refused')
        else:
            tag, kind = (header >> 2) & 15, header & 3
            need(kind != 3, 'indeterminate OpenPGP length refused')
            width = (1, 2, 4)[kind]
            need(offset + width <= len(raw), 'OpenPGP old length')
            size = int.from_bytes(raw[offset:offset+width], 'big')
            offset += width
        need(tag not in (5, 7) and 0 < size <= 65535 and offset + size <= len(raw), 'secret/truncated/oversized OpenPGP packet')
        body = raw[offset:offset+size]
        offset += size
        if tag == 6:
            need(body[0] == 4, 'public v4 primary packet required')
            primary.append(hashlib.sha1(b'\x99' + len(body).to_bytes(2, 'big') + body).hexdigest().upper())
    need(len(primary) == 1, 'one public primary identity required')
    return primary[0]

def signature_status(raw, fingerprint):
    rows = [line.split()[1:] for line in raw.decode('utf-8').splitlines() if line.startswith('[GNUPG:] ')]
    forbidden = {'BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'KEYEXPIRED', 'SIGEXPIRED',
                 'KEYREVOKED', 'NO_PUBKEY', 'NODATA', 'FAILURE', 'ERROR'}
    need(rows and not any(row[0] in forbidden for row in rows), 'GPG failure/expiry/revocation status refused')
    valid = [row for row in rows if row[0] == 'VALIDSIG']
    need(len(valid) == 1 and len(valid[0]) in (10, 11) and valid[0][1] == fingerprint
         and (len(valid[0]) == 10 or valid[0][-1] == fingerprint), 'one matching primary VALIDSIG record required')

def lifecycle_result(members, selected, policy, expected, package):
    result = decode(members['lifecycle/result.json'])
    need(type(result['schema']) is int and result['schema'] == 1 and result['status'] == 'PASS_SIGNED_DISPOSABLE_ALPM_LIFECYCLE'
         and result['source_map_sha256'] == expected['source_map_sha256'] and result['architecture'] == 'aarch64'
         and type(result['page_size']) is int and result['page_size'] > 0 and result['package_identity'] == selected['package']
         and result['recipe_sha256'] == selected['recipe_sha256'] and result['package'] == package
         and result['inventory'] == result['final_inventory'] == pin(members['bootstrap/packages.lock'])
         and result['config_preserved'] is True and result['user_outputs_preserved'] is True
         and result['native_16K'] == 'NOT_QUALIFIED' and result['physical_M2'] == 'NOT_RUN'
         and result['release'] == 'NOT_ADMITTED', 'actual installed lifecycle result/scope')
    need(decode(members['lifecycle/commands.json']) == result['commands'], 'lifecycle command inventory')
    command_rows(result['commands'], 'lifecycle', members)
    signing = result['signing']
    need(signing['private_key_removed'] is True and signing['fake_signature_time_used'] is False
         and signing['production_trust'] == 'UNTOUCHED' and signing['signature_verified_at_actual_time'] is True
         and signing['alpm_local_signature_policy'] == 'Required TrustedOnly'
         and type(signing['key_created_epoch']) is int and type(signing['verified_epoch']) is int
         and 0 < signing['key_created_epoch'] <= signing['verified_epoch'], 'isolated TEST signing scope/retirement')
    need(signing['archive'] == package['archive'] and signing['signature'] == pin(members['lifecycle/package.pkg.tar.sig'])
         and signing['certificate'] == pin(members['lifecycle/TEST-public.gpg']), 'actual signature/certificate bytes')
    fingerprint = public_fingerprint(members['lifecycle/TEST-public.gpg'])
    need(signing['fingerprint'] == fingerprint, 'binary TEST certificate primary identity')
    relative(signing['verification_log'])
    signature_status(members['lifecycle/' + signing['verification_log']], fingerprint)
    need(type(result['public_files']) is dict and len(result['public_files']) <= 32, 'finite retained lifecycle public data')
    for name, row in result['public_files'].items():
        relative(name)
        need('lifecycle/' + name in members and pin(members['lifecycle/' + name]) == row, 'retained lifecycle public bytes')
    phases = result['phases']
    need(type(phases) is list and [p['phase'] for p in phases] == ['install', 'same-version', 'remove', 'reinstall', 'final-remove'], 'complete ordered ALPM transitions')
    baseline = members['bootstrap/packages.lock']
    installed = b''.join(sorted((baseline + (selected['package']['name'] + ' ' + selected['package']['version'] + '\n').encode()).splitlines(keepends=True)))
    for phase in phases:
        need(phase['status'] == 'PASS' and phase['prior_outputs_preserved'] is True, 'lifecycle transition preservation')
        if phase['phase'] in ('remove', 'final-remove'):
            need(phase['inventory_count'] == 341 and phase['inventory'] == pin(baseline)
                 and phase['removed_payload_absent'] is True, 'actual restored base and removed owned files')
            continue
        need(phase['inventory_count'] == 342 and phase['inventory'] == pin(installed)
             and phase['payload'] == selected['payload'] and phase['ownership_exact'] is True
             and type(phase['observations']) is list and {o['profile'] for o in phase['observations']} == {'fresh', 'existing'}
             and len(phase['observations']) == 2, 'actual installed payload and two ordinary profile observations')
        for observed in phase['observations']:
            validate_observation(observed, phase['phase'], result, members)
    return result

def validate_observation(observed, phase, result, members):
    need(observed['collect_create_verify'] == 'PASS' and observed['negative_refusals'] == 'PASS_EXPECTED_EXIT2', 'actual collector/create/verify plus negative controls')
    for name in ('session', 'archive'):
        row = observed[name]
        relative(row['path'])
        need(row['path'].startswith('observations/' + phase + '/' + observed['profile'] + '/')
             and pin(members['lifecycle/' + row['path']]) == {k: row[k] for k in ('bytes', 'sha256')}, 'actual collected/session bundle data')
    verbs = [('collect_command', 'collect', 0), ('create_command', 'create', 0), ('verify_command', 'verify', 0),
             ('relocation_command', 'verify', 0), ('malformed_command', 'create', 2), ('tamper_command', 'verify', 2)]
    indices = []
    for key, verb, exit_code in verbs:
        number = observed[key]
        need(type(number) is int and 0 <= number < len(result['commands']), 'actual CLI command index')
        command = result['commands'][number]
        argv = command['argv']
        cli = '/usr/bin/cachy-asahi-support'
        need(command['expected_exit'] == exit_code and type(argv) is list and argv[:7] == ['/usr/bin/runuser', '-u', 'alarm', '--', '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin']
             and cli in argv and argv[argv.index(cli) + 1] == verb, 'actual ordinary installed CLI command/expected exit')
        indices.append(number)
    need(indices == list(range(indices[0], indices[0] + 6)), 'complete ordered per-profile CLI observations')

def validate(capsule_path, expected_binding, policy):
    selected = admission(expected_binding, policy)
    members = unpack_capsule(read(capsule_path), expected_binding)
    report = host_evidence(members, expected_binding, policy)
    checked = private_check_result(members, report, selected, policy, expected_binding)
    first = build_result('build1', members, selected, policy, expected_binding)
    second = build_result('build2', members, selected, policy, expected_binding)
    need(members['build1/package.pkg.tar'] == members['build2/package.pkg.tar']
         and members['build1/PKGINFO'] == members['build2/PKGINFO']
         and members['build1/BUILDINFO'] == members['build2/BUILDINFO']
         and first['package'] == second['package'] and first['uid'] == second['uid'] == report['uid'], 'independent full native pair equality')
    lifecycle = lifecycle_result(members, selected, policy, expected_binding, first['package'])
    need(first['page_size'] == second['page_size'] == checked['page_size'] == lifecycle['page_size']
         == decode(members['bootstrap/runner.json'])['page_size'], 'same native host page-size observations')
    return dict(status='MATCHED_PASSIVE_SUPPORT_NATIVE_DATA_PENDING_ROOT', acceptance=False,
                binding={k: expected_binding[k] for k in ('source_sha', 'ref', 'run_id', 'attempt')},
                package=selected['package'], signature_authentication='NOT_REEXECUTED',
                makepkg_check='MATCHED_EXTERNAL_PROOF_NOT_EXECUTED_BY_READER',
                native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN', performance='NOT_MEASURED', release='NOT_ADMITTED')

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capsule', required=True, type=Path)
    parser.add_argument('--binding', required=True, type=Path)
    parser.add_argument('--policy', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        expected, policy = decode(read(args.binding, 1024**2)), decode(read(args.policy, 8*1024**2))
        print(json.dumps(validate(args.capsule, expected, policy), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError, RecursionError, tarfile.TarError):
        print('support native reader: refused unbound, malformed or mismatching DATA', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
