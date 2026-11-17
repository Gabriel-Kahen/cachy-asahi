#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Finite Root-selected native build adapter. Importing this module does no work.

The externally owned executor is responsible for real process custody and live
resource enforcement. No default executor, Docker endpoint or trial is supplied.
"""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
PREFIX = 'scripts/port/bankstown-qt3-native-v1/'
RECIPE = 'packages/port/bankstown-source-candidate/'
RECIPE_FILES = {'PKGBUILD', '.SRCINFO', 'build_guard.py', 'native-rust-inputs.json',
                'native-toolchain-requirements.json', 'COMPONENTS.json', 'SOURCE-CANDIDATE.md',
                'PACKAGING.LICENSE', 'bankstown-1.1.0.tar.gz', 'cargo-vendor-117.tar.xz',
                'audio-rust-notices-v1.tar.xz'}
HELD = {
    'scripts/checks/package_checks.py': '314e8b4a0920b3f6d93619fc74ad1d63a6210d1b17b925618451b493d2610a1a',
    'scripts/build/build.py': 'e520b37e5dfc285914203cfab99daecc80543505fef7ded6704b3fb06f001d45',
    'scripts/build/container-entry.sh': '89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24',
    RECIPE + 'build_guard.py': '778c22cb52a4ffe4103a0e7a2c907def00bd9cd2411d0fdbca339a4cc010e21a',
}
FINAL = {'Root_acceptance': None, 'native_component_acceptance': False,
         'hardware_acceptance': False, 'release_acceptance': False}


def need(value, code):
    if not value:
        raise ValueError(code)


def pin(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and not any(c in str(path) for c in ',\n\r\x00')
         and '..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)),
         'UNALIASED_ABSOLUTE_PATH_REQUIRED')
    return path


def identity(s):
    return tuple(getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_nlink',
                 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(path, cap, expected=None):
    path = ordinary(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= cap, 'BOUNDED_ORDINARY_FILE_REQUIRED')
        chunks = []
        remaining = before.st_size + 1
        while remaining:
            part = os.read(fd, min(1024**2, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        body = b''.join(chunks)
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
             and len(body) == before.st_size, 'FILE_CHANGED')
        need(expected is None or pin(body) == expected, 'FILE_PIN_DIFFERS')
        return body
    finally:
        os.close(fd)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def natural(row, expected):
    s = row.get('supervision', {})
    need(row.get('exit') == expected and row.get('passed', True) is True
         and s.get('exit') == expected and s.get('reaped') is True
         and s.get('ownership') == 'REAPED' and s.get('group_census') == 'EMPTY_TWICE'
         and s.get('output_complete') is True and s.get('timeout') is False
         and s.get('signals') == [] and s.get('error') is None
         and not s.get('forced_cleanup') and not s.get('ownership_lost')
         and not s.get('emergency_retirement'), 'NATURAL_COMMAND_REQUIRED')


class Commands:
    def __init__(self, executor, output, resources, endpoint, end=None, work_deadline=None):
        self.executor, self.output, self.resources = executor, output, resources
        self.endpoint = endpoint
        self.end = end if end is not None else time.monotonic() + resources['wall_seconds']
        self.work_end = self.end - min(30, resources['wall_seconds'] / 4)
        if work_deadline is not None:
            self.work_end = min(self.work_end, work_deadline)
        self.rows = []
        output.mkdir()

    def run(self, step, args, *, cleanup=False, expected=0):
        need(re.fullmatch('[a-z0-9-]{1,100}', step) and all(r['step'] != step for r in self.rows), 'UNIQUE_COMMAND_STEP')
        remaining = (self.end if cleanup else self.work_end) - time.monotonic()
        need(remaining > 0, 'SHARED_DEADLINE_EXHAUSTED')
        timeout = min(self.resources['command_seconds'], remaining)
        argv = ['/usr/bin/docker', '--host', self.endpoint] + args
        result = self.executor.run(step, argv, timeout, expected=expected)
        need(type(result) is dict and type(result.get('stdout')) is bytes
             and type(result.get('stderr')) is bytes, 'OWNED_EXECUTOR_BYTES_REQUIRED')
        stdout, stderr, row = result['stdout'], result['stderr'], result['receipt']
        need(len(stdout) + len(stderr) <= self.resources['max_output_bytes'], 'COMMAND_OUTPUT_BOUND')
        need(type(row) is dict, 'ACTUAL_RECEIPT_REQUIRED')
        self.rows.append(row)
        (self.output / (step + '.stdout')).write_bytes(stdout)
        (self.output / (step + '.stderr')).write_bytes(stderr)
        (self.output / 'commands.json').write_bytes(encode(self.rows))
        need(row.get('step') == step and row.get('argv') == argv
             and row.get('expected') == expected and row.get('output_pin') == pin(stdout)
             and row.get('stderr_pin') == pin(stderr), 'ACTUAL_RECEIPT_JOIN')
        need(type(row.get('timeout_seconds')) in (int, float)
             and 0 < row['timeout_seconds'] <= timeout
             and type(row.get('supervision_cap_seconds')) in (int, float)
             and 0 < row['supervision_cap_seconds'] <= remaining
             and row['timeout_seconds'] == timeout
             and type(row.get('supervision', {}).get('seconds')) in (int, float)
             and 0 <= row['supervision']['seconds'] < row['supervision_cap_seconds']
             and row['supervision_cap_seconds'] <= timeout, 'ACTUAL_COMMAND_BOUNDS_REQUIRED')
        natural(row, expected)
        need(time.monotonic() < (self.end if cleanup else self.work_end), 'COMMAND_OVERRAN_SHARED_DEADLINE')
        return stdout


def mounts(source, inputs, artifacts, control, inventory):
    return [(source, '/bankstown-qt3-source', True), (inputs, '/inputs', True),
            (artifacts, '/out', False), (control, '/bankstown-qt3-control', True),
            (inventory, '/expected-packages.lock', True)]


def inspect_container(row, intent):
    c, h = row['Config'], row['HostConfig']
    need(row['Id'] == intent['cid'] and row['Name'] == '/' + intent['name']
         and row['Image'] == intent['image'] and c['User'] == intent['user']
         and c['Entrypoint'] == ['/bin/bash'] and c['Cmd'] == [intent['entry']]
         and c['Labels'] == intent['labels'], 'EXACT_CONTAINER_IDENTITY')
    need(h['ReadonlyRootfs'] is True and h['NetworkMode'] == 'none'
         and h['Privileged'] is False and not h.get('Devices')
         and not h.get('DeviceRequests') and not h.get('Binds') and not h.get('VolumesFrom')
         and h['CapDrop'] == ['ALL'] and not h.get('CapAdd')
         and h['SecurityOpt'] == ['no-new-privileges'] and h.get('Init') in (None, False)
         and h['Memory'] == h['MemorySwap'] == intent['memory']
         and h['NanoCpus'] == intent['cpus'] * 10**9 and h['PidsLimit'] == intent['pids']
         and h['Tmpfs'] == {'/tmp': 'rw,nosuid,nodev,exec,size=4g'}, 'EXACT_CONTAINER_LIMITS')
    binds = [m for m in row['Mounts'] if m['Type'] == 'bind']
    tmpfs = [m for m in row['Mounts'] if m['Type'] == 'tmpfs']
    actual = {(m['Source'], m['Destination'], not m['RW']) for m in binds}
    need(len(binds) == len(intent['mounts']) and actual == set(intent['mounts'])
         and len(tmpfs) <= 1 and len(binds) + len(tmpfs) == len(row['Mounts'])
         and all(m['Destination'] == '/tmp' and m['RW'] is True for m in tmpfs), 'EXACT_CONTAINER_MOUNTS')
    env = dict(v.split('=', 1) for v in c['Env'])
    need(len(env) == len(c['Env']), 'DUPLICATE_CONTAINER_ENV')
    need(all(env.get(k) == v for k, v in intent['env'].items())
         and set(k for k in env if k.startswith('BANKSTOWN_')) == {
             'BANKSTOWN_NATIVE_TOOLS_PROFILE', 'BANKSTOWN_NATIVE_TOOLS_SHA256'}, 'EXACT_PROFILE_FORWARDING')


def static_helpers(source, d):
    for path, sha in HELD.items():
        need(path in d['materials'] and d['materials'][path]['sha256'] == sha, 'HELD_HELPER_PIN_REQUIRED')
    checks = load(source / 'scripts/checks/package_checks.py', 'bankstown_held_checks_v1')
    tree = ast.parse((source / 'scripts/build/build.py').read_bytes())
    selected = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                and n.name in ('normalize_metadata', 'bind_generated', 'bind_artifact')]
    need(len(selected) == 3, 'HELD_STATIC_FUNCTIONS_REQUIRED')
    namespace = {'FIELDS': checks.FIELDS, 'ARCH_FIELDS': checks.ARCH_FIELDS}
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<held-static-build>', 'exec'), namespace)
    guard = load(source / RECIPE / 'build_guard.py', 'bankstown_held_guard_v1')
    return checks, namespace, guard


def source_payload(inputs, checks, deadline):
    """Read only the six declared source/notice bodies; never extract an archive."""
    expected = {}
    for filename, prefix, names, destination in (
        ('bankstown-1.1.0.tar.gz', 'bankstown-1.1.0/', ('LICENSE', 'bankstown.ttl', 'manifest.ttl'), ''),
        ('audio-rust-notices-v1.tar.xz', 'audio-rust-notices/bankstown/',
         ('THIRD-PARTY.md', 'THIRD-PARTY-LICENSES.txt', 'SOURCE.md'), 'usr/share/licenses/bankstown/')):
        wanted = {prefix + n: n for n in names}
        seen, total = set(), 0
        with tarfile.open(inputs / filename, 'r|*') as archive:
            for count, member in enumerate(archive, 1):
                need(time.monotonic() < deadline, 'SOURCE_PAYLOAD_DEADLINE')
                name = checks.clean_name(member.name)
                need(count <= 50000 and name not in seen and 0 <= member.size <= 128 * 1024**2,
                     'SOURCE_ARCHIVE_MEMBER_BOUND')
                seen.add(name)
                total += member.size
                need(total <= 512 * 1024**2, 'SOURCE_ARCHIVE_LOGICAL_BOUND')
                if name in wanted:
                    need(member.isfile() and member.size <= 2 * 1024**2, 'ORDINARY_SOURCE_NOTICE_REQUIRED')
                    with archive.extractfile(member) as stream:
                        body = stream.read(member.size + 1)
                    need(len(body) == member.size, 'TRUNCATED_SOURCE_NOTICE')
                    n = wanted[name]
                    dest = destination or ('usr/share/licenses/bankstown/' if n == 'LICENSE' else 'usr/lib/lv2/bankstown.lv2/')
                    expected[dest + n] = pin(body)
        need(set(wanted) <= seen, 'DECLARED_SOURCE_NOTICES_MISSING')
    for name, destination in (('PACKAGING.LICENSE', 'usr/share/licenses/bankstown/'),
                               ('SOURCE-CANDIDATE.md', 'usr/share/doc/bankstown/')):
        expected[destination + name] = pin(read(inputs / name, 2 * 1024**2))
    return expected


def validate_outputs(artifacts, inventory, reviewed, checks, helpers, guard, profile_sha256, deadline):
    files = list(artifacts.iterdir())
    need(len(files) <= 128, 'ARTIFACT_NAMESPACE_BOUND')
    total = 0
    for item in files:
        ordinary(item)
        s = item.lstat()
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and 0 <= s.st_size <= 64 * 1024**2,
             'ORDINARY_ARTIFACT_REQUIRED')
        total += s.st_size
    need(total <= 128 * 1024**2, 'ARTIFACT_AGGREGATE_BOUND')
    need(read(artifacts / 'packages.lock', 2 * 1024**2) == inventory, 'ACTUAL_IMAGE_INVENTORY_DIFFERS')
    for name in ('environment.txt', 'config.sha256', 'makepkg.conf', 'pacman.conf'):
        read(artifacts / name, 4 * 1024**2)
    generated = checks.metadata(read(artifacts / 'generated.SRCINFO', 2 * 1024**2).decode())
    helpers['bind_generated'](reviewed['metadata'], generated)
    packages = [p for p in artifacts.iterdir() if '.pkg.tar.' in p.name and not p.name.endswith('.sig')]
    need(len(packages) == 1, 'EXACTLY_ONE_PACKAGE_REQUIRED')
    path = ordinary(packages[0])
    read(path, 64 * 1024**2)
    temporary = artifacts.parent / 'validation.tar'
    try:
        if path.name.endswith('.zst'):
            try:
                from compression import zstd
            except ImportError:
                raise ValueError('ZSTD_DATA_REQUIRES_PYTHON314') from None
            total = 0
            with zstd.open(path, 'rb') as src, temporary.open('xb') as dst:
                while part := src.read(1024**2):
                    need(time.monotonic() < deadline, 'STATIC_DATA_DEADLINE')
                    total += len(part)
                    need(total <= 512 * 1024**2, 'EXPANDED_PACKAGE_BOUND')
                    dst.write(part)
            report = checks.package(temporary)
            report.update(artifact=path.name, sha256=checks.digest(path))
        else:
            report = checks.package(path)
        errors = report['errors'] + helpers['bind_artifact'](
            reviewed['metadata'], report, reviewed['input_sha256']['PKGBUILD'])
        need(not errors, 'STATIC_ARTIFACT_REFUSED: ' + '; '.join(errors))
        payload = {'usr/lib/lv2/bankstown.lv2/' + n for n in ('bankstown.so', 'bankstown.ttl', 'manifest.ttl')}
        payload |= {'usr/share/licenses/bankstown/' + n for n in (
            'LICENSE', 'THIRD-PARTY.md', 'THIRD-PARTY-LICENSES.txt', 'SOURCE.md', 'PACKAGING.LICENSE')}
        payload |= {'usr/share/doc/bankstown/' + n for n in ('SOURCE-CANDIDATE.md', 'BUILD-INPUTS.json')}
        regular = {n for n, row in report['members'].items() if row['type'] == '0'}
        need(regular == payload | {'.PKGINFO', '.BUILDINFO', '.MTREE'}
             and all(row['type'] in ('0', '5') for row in report['members'].values()), 'EXACT_TEN_BANKSTOWN_PAYLOAD_FILES')
        need(all(report['members'][name]['mode'] == (0o755 if name.endswith('.so') else 0o644)
                 for name in payload), 'EXACT_BANKSTOWN_PAYLOAD_MODES')
        bodies = {}
        with tarfile.open(temporary if path.name.endswith('.zst') else path, 'r:*') as archive:
            for member in archive:
                name = checks.clean_name(member.name)
                if name in payload:
                    need(member.isfile() and 0 <= member.size <= (64 * 1024**2 if name.endswith('.so') else 2 * 1024**2), 'PAYLOAD_BODY_BOUND')
                    with archive.extractfile(member) as stream:
                        bodies[name] = stream.read(member.size + 1)
                    need(pin(bodies[name]) == {'bytes': report['members'][name]['size'],
                         'sha256': report['members'][name]['sha256']}, 'PAYLOAD_REREAD_DIFFERS')
        receipt = json.loads(bodies['usr/share/doc/bankstown/BUILD-INPUTS.json'])
        need(receipt.get('tool_catalog_sha256') == profile_sha256, 'PAYLOAD_ROOT_PROFILE_ASSOCIATION')
        guard.check_receipt(bodies['usr/lib/lv2/bankstown.lv2/bankstown.so'], 'aarch64-unknown-linux-gnu', receipt)
        for name, expected in source_payload(artifacts.parent / 'inputs', checks, deadline).items():
            need(pin(bodies[name]) == expected, 'SOURCE_OR_NOTICE_PAYLOAD_DIFFERS')
        need(time.monotonic() < deadline, 'STATIC_DATA_DEADLINE')
        return report
    finally:
        if temporary.exists():
            temporary.unlink()


def build_private_test(*, admission_raw, admission_sha256, profile_path,
                       profile_sha256, executor, source_root, output):
    """Build only a fresh Root-admitted private TEST; failures raise after cleanup.

    executor.facts must contain Root-bound code_pin/docker_endpoint/engine_id,
    plus actual non-root uid/gid. Every CLI uses executor.run; no host tools run.
    """
    started = time.monotonic()
    A = load(HERE / 'admission.py', 'bankstown_trial_admission_v1')
    d = A.validate_trial(admission_raw, admission_sha256, now=time.time())
    facts = executor.facts
    need(all(facts.get(k) == v for k, v in d['owned_executor'].items()), 'ACTUAL_EXECUTOR_BINDING_DIFFERS')
    uid, gid = facts.get('uid'), facts.get('gid')
    need(type(uid) is int and uid > 0 and type(gid) is int and gid >= 0, 'NONROOT_EXECUTOR_IDS_REQUIRED')
    kernel = os.uname()
    need(kernel.sysname == 'Linux' and kernel.machine in ('aarch64', 'arm64')
         and os.getuid() == os.geteuid() == uid and os.getgid() == os.getegid() == gid
         and ('native_architecture' not in facts or facts['native_architecture'] == kernel.machine),
         'NATIVE_LINUX_EXECUTOR_REQUIRED')
    root, out = ordinary(source_root), ordinary(output)
    need(not out.exists() and not out.is_relative_to(root) and not root.is_relative_to(out), 'FRESH_EXTERNAL_OUTPUT_REQUIRED')
    deadline = started + d['resources']['wall_seconds']
    need(sum(r['bytes'] for r in d['materials'].values()) <= 128 * 1024**2, 'MATERIAL_AGGREGATE_BOUND')
    profile = read(profile_path, 2 * 1024**2)
    need(pin(profile)['sha256'] == profile_sha256, 'ROOT_PROFILE_PIN_DIFFERS')
    p = A.decoded(profile)
    expected_profile = dict(schema=1, purpose='bankstown-1.1.0-5-native-toolchain',
        compiler_version='1.99.0', target='aarch64-unknown-linux-gnu', tools=d['tool_paths'],
        files=d['selected_files'], admission_pin=A.pin(admission_raw), catalog_pin=d['catalog'],
        image=d['image'], legal='HELD', key_freshness='HELD', **FINAL)
    need(p == expected_profile, 'PROFILE_TRIAL_JOIN')
    out.mkdir(mode=0o700)
    control = out / 'control'
    control.mkdir()
    snapshot = control / 'source'
    snapshot.mkdir()
    for relative, expected in sorted(d['materials'].items()):
        need(time.monotonic() < deadline, 'MATERIAL_DEADLINE')
        need(not set(Path(relative).parts) & {'.git', 'work', '__pycache__'}, 'CONTROL_SOURCE_ONLY')
        target = snapshot / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(read(root / relative, 64 * 1024**2, expected))
    for name in ('admission.py', 'builder.py', 'entry.sh'):
        need(read(HERE / name, 2 * 1024**2) == read(snapshot / PREFIX / name, 2 * 1024**2), 'ACTUAL_ADAPTER_SOURCE_DIFFERS')
    checks, helpers, guard = static_helpers(snapshot, d)
    catalog = next(k for k, v in d['materials'].items() if v == d['catalog'])
    inventory_name = next(k for k, v in d['materials'].items() if v == d['image']['inventory'])
    inventory_path = snapshot / inventory_name
    inventory = read(inventory_path, 2 * 1024**2)
    lines = inventory.decode().splitlines(keepends=True)
    need(lines and inventory.endswith(b'\n') and lines == sorted(set(lines))
         and all(re.fullmatch(r'[A-Za-z0-9@._+:-]+ [^\s]+\n', l) for l in lines), 'SORTED_COMPLETE_IMAGE_INVENTORY_REQUIRED')
    catalog_body = A.decoded(read(snapshot / catalog, 64 * 1024**2), 64 * 1024**2)
    installed = dict(line.strip().split(' ', 1) for line in lines)
    need(all(installed.get(name) == row['metadata']['/.PKGINFO']['pkgver'][0]
             for name, row in catalog_body['packages'].items()), 'SELECTED_CATALOG_NOT_IN_IMAGE')
    need({'make', 'pacman', 'fakeroot', 'gcc', 'binutils', 'python', 'rust', 'bash', 'coreutils'} <= set(installed), 'PACKAGING_PREREQUISITES_REQUIRED')
    inputs, artifacts = out / 'inputs', out / 'artifacts'
    inputs.mkdir()
    artifacts.mkdir()
    need({p.name for p in (snapshot / RECIPE).iterdir()} == RECIPE_FILES, 'EXACT_RECIPE_NAMESPACE_REQUIRED')
    for path in (snapshot / RECIPE).iterdir():
        need(path.is_file() and not path.is_symlink(), 'FLAT_CLOSED_RECIPE_REQUIRED')
        (inputs / path.name).write_bytes(read(path, 64 * 1024**2))
    reviewed = checks.recipe(inputs / 'PKGBUILD')
    need(not reviewed['errors'], 'REVIEWED_RECIPE_REFUSED')
    (control / 'admission.json').write_bytes(admission_raw)
    (control / 'admission.sha256').write_text(admission_sha256 + '\n')
    (control / 'profile.json').write_bytes(profile)
    (control / 'catalog.path').write_text('/bankstown-qt3-source/' + catalog + '\n')
    work_deadline = time.monotonic() + (d['expires_at'] - time.time())
    C = Commands(executor, out / 'commands', d['resources'], d['owned_executor']['docker_endpoint'], deadline, work_deadline)
    name = 'bankstown-qt3-' + admission_sha256[:24]
    labels = {'org.cachy-asahi.operation': 'bankstown-qt3-private-test-v1',
              'org.cachy-asahi.admission': admission_sha256, 'org.cachy-asahi.source': d['source']['commit']}
    env = {'CACHY_ASAHI_CONTAINER': '1', 'SOURCE_DATE_EPOCH': '1791748800',
           'PATH': '/usr/bin:/bin', 'BASH_ENV': '/dev/null', 'ENV': '/dev/null',
           'PYTHONPATH': '', 'PYTHONHOME': '', 'LD_PRELOAD': '', 'LD_LIBRARY_PATH': '',
           'PYTHONDONTWRITEBYTECODE': '1',
           'BANKSTOWN_NATIVE_TOOLS_PROFILE': '/bankstown-qt3-control/profile.json',
           'BANKSTOWN_NATIVE_TOOLS_SHA256': profile_sha256}
    r = d['resources']
    intent = {'name': name, 'image': d['image']['id'], 'user': f'{uid}:{gid}',
              'entry': '/bankstown-qt3-source/' + PREFIX + 'entry.sh', 'labels': labels,
              'mounts': [(str(a), b, c) for a, b, c in mounts(snapshot, inputs, artifacts, control, inventory_path)],
              'env': env, 'memory': r['memory_bytes'], 'cpus': r['cpus'], 'pids': r['pids']}
    cid = None
    created = False
    absence = False
    try:
        image = json.loads(C.run('image', ['image', 'inspect', intent['image']]))
        need(len(image) == 1 and image[0]['Id'] == intent['image'] and image[0]['Architecture'] == 'arm64'
             and image[0]['Os'] == 'linux', 'EXACT_ARM64_IMAGE_REQUIRED')
        daemon = json.loads(C.run('daemon', ['info', '--format', '{{json .}}']))
        need(daemon['ID'] == d['owned_executor']['engine_id'] and daemon['OSType'] == 'linux'
             and daemon['Architecture'] in ('arm64', 'aarch64') and daemon['NCPU'] >= r['cpus']
             and daemon['MemTotal'] >= r['memory_bytes'] and daemon.get('MemoryLimit') is True
             and daemon.get('SwapLimit') is True and daemon.get('PidsLimit') is True
             and daemon.get('CgroupVersion') == '2', 'NATIVE_BOUNDED_ENGINE_REQUIRED')
        need(not C.run('fresh-name', ['ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$']).strip(), 'NAME_COLLISION')
        args = ['create', '--name', name, '--pull=never', '--platform', 'linux/arm64', '--user', intent['user'],
                '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only', '--pids-limit', str(r['pids']),
                '--memory', str(r['memory_bytes']), '--memory-swap', str(r['memory_bytes']), '--cpus', str(r['cpus']),
                '--network', 'none', '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g']
        for k, v in labels.items():
            args += ['--label', k + '=' + v]
        for k, v in env.items():
            args += ['--env', k + '=' + v]
        for src, dst, ro in intent['mounts']:
            args += ['--mount', f'type=bind,src={src},dst={dst}' + (',readonly' if ro else '')]
        args += ['--entrypoint', '/bin/bash', intent['image'], intent['entry']]
        # Creation can succeed before its receipt is returned; finally queries only this exact name.
        created = True
        cid = C.run('create', args).decode().strip()
        need(re.fullmatch('[0-9a-f]{64}', cid), 'FULL_CREATED_CID_REQUIRED')
        intent['cid'] = cid
        inspect_container(json.loads(C.run('inspect-created', ['inspect', cid]))[0], intent)
        C.run('attach', ['start', '--attach', cid])
        terminal = json.loads(C.run('inspect-terminal', ['inspect', cid]))[0]
        inspect_container(terminal, intent)
        need(terminal['State']['Running'] is False and terminal['State']['ExitCode'] == 0
             and terminal['State']['OOMKilled'] is False, 'NATURAL_CONTAINER_EXIT_REQUIRED')
    finally:
        original = sys.exc_info()[1]
        if created:
            try:
                ids = C.run('retire-query', ['ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$'], cleanup=True).decode().split()
                need(len(ids) == 1 and re.fullmatch('[0-9a-f]{64}', ids[0]) and (cid is None or ids == [cid]), 'OWNED_CONTAINER_RECOVERY_ID_REQUIRED')
                cid = ids[0]
                intent['cid'] = cid
                row = json.loads(C.run('retire-inspect', ['inspect', cid], cleanup=True))[0]
                inspect_container(row, intent)
                forced = row['State']['Running']
                C.run('retire-remove', ['rm'] + (['--force'] if forced else []) + [cid], cleanup=True)
                need(not C.run('retire-after-name', ['ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$'], cleanup=True).strip()
                     and not C.run('retire-after-cid', ['ps', '-aq', '--no-trunc', '--filter', 'id=' + cid], cleanup=True).strip(), 'OWNED_ABSENCE_REQUIRED')
                absence = True
                need(not forced, 'FORCED_RETIREMENT_IS_HOLD')
            except BaseException as cleanup_error:
                (out / "cleanup-HOLD.json").write_bytes(encode({"status": "HOLD",
                    "original_error": None if original is None else str(original),
                    "cleanup_error": str(cleanup_error), "owned_container_absence_verified": False}))
                if original is None:
                    raise
                original.add_note("Owned cleanup also held: " + str(cleanup_error))
    report = validate_outputs(artifacts, inventory, reviewed, checks, helpers, guard, profile_sha256, C.end)
    result = {'schema': 1, 'status': 'PASS_PRIVATE_TEST_BUILD_DATA_ONLY', 'admission_pin': pin(admission_raw),
              'profile_pin': pin(profile), 'source': d['source'], 'image': d['image'], 'intent': intent,
              'commands': C.rows, 'artifact': report, 'owned_container_absence_verified': absence,
              'legal': 'HELD', 'key_freshness': 'HELD', 'hardware_status': 'NOT RUN', **FINAL}
    (out / 'result.json').write_bytes(encode(result))
    return result
