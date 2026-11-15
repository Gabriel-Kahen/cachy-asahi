#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Future Root-admitted signed349 bootstrap and four-command native XS smoke."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
HELD = ROOT / 'held'
HELD_MAP = '4b1de3aade5116206318570d1d44ee1063342faeab54935748b1b7c179a99e96'
PINS = {'common.py': '776122710442ba1541cd4d7a7d8472ad01c295d523b28282a04e7c8298286b79',
        'entry.py': '1c58f8d1226cf1a88149509b183fb61135d0f38ff75c02c729a00ed004a55cd0',
        'bootstrap.py': '34b3b0742587af63b1762aa2dcaf9e2e3446be9b6851b865784654c4cd6d26cd'}
NATIVE_SHA = '40c048fbbb6599bdb61ed8b105708b2d21db8ea2b2732258e1225a48c635d146'
ARCHIVE = 'perl-5.42.3-1.3-aarch64.pkg.tar.zst'
ARCHIVE_PIN = {'bytes': 22071176, 'sha256': '647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22'}
DECISION_PIN = {'bytes': 5804, 'sha256': '27803c99064198f8688abe2e4d91910eef93df5ad337ebfc7f2d8798afbf41e1'}
PAIR = {'source': '25dc3e65bdb6137c87a9409067fe9b2cf6e9763f', 'run': '43692477455', 'job': '132745843566'}
ACTUAL = dict.fromkeys(('source', 'ref', 'run', 'job', 'reader', 'authority', 'approval', 'artifact', 'image'))
ALIASES = ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-perl5423-xs-v1.yml')
OPERATION = 'perl5423-native-xs-v1'
DOCKER = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock']
PREP_TMPFS = {'/run': 'rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001',
              '/tmp': 'rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001',
              '/xs-work': 'rw,exec,nosuid,nodev,size=256m,uid=1001,gid=1001,mode=0700'}


def need(value, why):
    if not value:
        raise ValueError(why)


def raw(path, cap=1024**2):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute DATA path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap,
             'bounded single-link DATA')
        body = bytearray()
        while block := os.read(fd, min(65536, cap + 1 - len(body))):
            body.extend(block)
            need(len(body) <= cap, 'DATA byte bound')
        key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(body) == before.st_size and key(before) == key(os.fstat(fd)) == key(path.lstat()),
             'DATA changed during read')
        return bytes(body)
    finally:
        os.close(fd)


def pin(body):
    return dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())


def load(name, path, sha):
    body = raw(path)
    need(pin(body)['sha256'] == sha, 'whole pinned executable source differs: ' + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(body, str(path), 'exec'), module.__dict__)
    return module


def helpers():
    common = load('xs_held_hosted_common', HELD / 'hosted/common.py', PINS['common.py'])
    common.verify_source(HELD, HELD_MAP)
    entry = load('xs_held_hosted_entry', HELD / 'hosted/entry.py', PINS['entry.py'])
    return common, entry


def source(common, expected):
    body = raw(ROOT / 'source-map.json')
    need(re.fullmatch('[0-9a-f]{64}', expected or '') and pin(body)['sha256'] == expected,
         'Root whole XS Source map required')
    manifest = common.decode(body)
    need(manifest['schema'] == 1 and manifest['actual'] == ACTUAL and
         type(manifest['files']) is dict and 1 <= len(manifest['files']) <= 384,
         'finite closed Source with NULL operational selectors')
    rows = manifest['files']
    found, directories, count = set(), set(), 0
    for directory, dirs, files in os.walk(ROOT, followlinks=False):
        base = Path(directory)
        if base == ROOT and '.git' in dirs:
            need(not (base / '.git').is_symlink(), 'Git directory alias')
            dirs.remove('.git')
        for name in dirs + files:
            leaf = base / name
            count += 1
            need(count <= 1800 and not leaf.is_symlink(), 'finite ordinary Source nodes')
            relative = str(leaf.relative_to(ROOT))
            if leaf.is_dir():
                directories.add(relative)
            else:
                need(leaf.is_file(), 'Source special file')
                found.add(relative)
    need(found == set(rows) | {'source-map.json'}, 'complete Source membership differs')
    expected_dirs = {str(d) for n in found for d in Path(n).parents if str(d) != '.'}
    need(directories == expected_dirs, 'complete Source directories differ')
    total = 0
    for name, row in rows.items():
        need(type(name) is str and re.fullmatch('[A-Za-z0-9._+/-]{1,240}', name) and
             all(p not in ('', '.', '..') for p in name.split('/')), 'ordinary Source leaf')
        data = raw(ROOT / name, 64 * 1024**2)
        total += len(data)
        need(dict(**pin(data), mode=stat.S_IMODE((ROOT / name).stat().st_mode)) == row,
             'Source byte/mode differs: ' + name)
    need(total <= 96 * 1024**2 and raw(ROOT / ALIASES[0]) == raw(ROOT / ALIASES[1]),
         'finite Source and identical dedicated aliases')
    need(pin(raw(HELD / 'source-map.json'))['sha256'] == HELD_MAP and
         pin(raw(ROOT / 'consumer/native_adapter/native.py'))['sha256'] == NATIVE_SHA,
         'unchanged held Source and frozen native adapter')
    common.verify_source(HELD, HELD_MAP)
    return manifest


def binding(args, common):
    manifest = source(common, args.map_sha256)
    e = os.environ
    ref, run = e.get('GITHUB_REF', ''), e.get('GITHUB_RUN_ID', '')
    need(re.fullmatch('[0-9a-f]{40}', args.source_sha or '') and
         re.fullmatch('[0-9a-f]{64}', args.approval_sha256 or '') and
         e.get('GITHUB_SHA') == e.get('GITHUB_WORKFLOW_SHA') == args.source_sha and
         re.fullmatch('refs/heads/codex/[A-Za-z0-9._/-]+', ref) and re.fullmatch('[1-9][0-9]{0,19}', run),
         'actual same Source/ref/run and Root approval operand')
    need(e.get('GITHUB_RUN_ATTEMPT') == '1' and e.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and
         e.get('GITHUB_REPOSITORY') == 'Gabriel-Kahen/cachy-asahi' and
         e.get('GITHUB_WORKFLOW_REF') in {'Gabriel-Kahen/cachy-asahi/' + n + '@' + ref for n in ALIASES},
         'first dedicated manual XS workflow only')
    need(e.get('GITHUB_ACTIONS') == 'true' and e.get('RUNNER_ARCH') == 'ARM64' and
         e.get('RUNNER_OS') == 'Linux' and platform.system() == 'Linux' and platform.machine() == 'aarch64' and
         os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 1001 and
         e.get('PERL_OPERATION') == OPERATION, 'actual alarm1001 native XS coordinator')
    need(not any(k.startswith(('LD_', 'DOCKER_', 'GIT_', 'CACHY_OLD_FOUR_', 'CACHY_RETAINED_')) for k in e),
         'ambient policy/loader/cache overrides refused')
    return dict(source=args.source_sha, ref=ref, run=run, approval=args.approval_sha256,
                source_map_sha256=args.map_sha256, operation=OPERATION), manifest


def checked(command, argv, seconds=30):
    result = command(argv, timeout=seconds)
    need(result.returncode == 0, 'command failed: ' + str(argv))
    return result


def proof(args, work, common, held):
    b, manifest = binding(args, common)
    need(not os.path.lexists(work), 'fresh one-shot XS Source proof workspace')
    work.mkdir(mode=0o700)
    (work / 'home').mkdir(mode=0o700)
    command = held.Commands(work, time.monotonic() + 150, scope='proof')
    git = ['/usr/bin/git', '--no-replace-objects', '--git-dir=' + str(ROOT / '.git'),
           '--work-tree=' + str(ROOT), '-c', 'protocol.allow=never', '-c', 'core.fsmonitor=false']
    head = checked(command, git + ['rev-parse', '--verify', 'HEAD'])
    need(head.stdout.decode().strip() == b['source'], 'actual published Source HEAD differs')
    tree = checked(command, git + ['ls-tree', '-rz', '--full-tree', b['source']], 60)
    found = {}
    for item in tree.stdout.split(b'\0'):
        if not item:
            continue
        header, name = item.split(b'\t', 1)
        mode, kind, oid = header.decode().split()
        name = name.decode()
        need(name not in found and name in set(manifest['files']) | {'source-map.json'}, 'actual unique Source Git leaf')
        data = raw(ROOT / name, 64 * 1024**2)
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        need(kind == 'blob' and oid == blob and mode == ('100755' if (ROOT / name).stat().st_mode & 0o111 else '100644'),
             'actual Source Git blob/mode differs')
        found[name] = dict(**pin(data), mode=int(mode[-3:], 8), blob=oid)
    need(set(found) == set(manifest['files']) | {'source-map.json'}, 'actual whole published Source membership')
    (work / 'source-readback.json').write_bytes(common.encode(dict(schema=1,
        status='PASS_EXACT_HOSTED_XS_SOURCE_READBACK', binding=b, files=found, actors=command.rows)))


def metadata(args, work, common):
    import urllib.request
    b, _ = binding(args, common)
    need(common.decode(raw(work / 'source-readback.json'))['binding'] == b, 'Source proof before token use')
    token = os.environ.get('GH_TOKEN', '')
    need(token, 'existing Actions metadata token required')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    url = 'https://api.github.com/repos/Gabriel-Kahen/cachy-asahi/actions/runs/' + b['run'] + '/jobs?filter=latest&per_page=10'
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json'})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        body = response.read(1024**2 + 1)
    value = common.decode(body)
    jobs = value['jobs']
    need(value['total_count'] == len(jobs) == 1 and jobs[0]['name'] == OPERATION and
         jobs[0]['run_id'] == int(b['run']) and jobs[0]['head_sha'] == b['source'], 'actual unique XS run/job/Source')
    b['job'] = str(jobs[0]['id'])
    need(re.fullmatch('[1-9][0-9]{0,19}', b['job']), 'actual numeric XS job ID')
    (work / 'binding.json').write_bytes(common.encode(b))
    (work / 'job-metadata.json').write_bytes(body)


def inputs(args, work, common, held):
    b, _ = binding(args, common)
    need(common.decode(raw(work / 'source-readback.json'))['binding'] == b, 'Source proof before retained DATA transport')
    # Only the immutable held transport leaf is reused, with its held Git supervision.
    original = HELD / 'original'
    old_path, old_modules, old_run = sys.path.copy(), sys.modules.copy(), subprocess.run
    try:
        sys.modules.pop('common', None)
        sys.path[:0] = [str(original / 'native')]
        transport = common.load('xs_held_retained_transport', original / 'native/retained_transport.py')
        owner = common.load('xs_held_transport_ownership', original / 'bootstrap/scripts/ci/zlib-pgo-native-hosted/owner.py')
        subprocess.run = owner.owned_subprocess_run
        profile = raw(original / 'bootstrap/scripts/ci/setup6-retained-helpers/carrier-profile.json', 2 * 1024**2)
        result = transport.deliver(original, Path(os.environ['RUNNER_TEMP']) / 'pgo-hosted-retained',
            work / 'retained-transport', profile, '4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c')
        need(result['status'] == 'PASS_EXACT_RETAINED_GIT_DATA_ONLY', 'exact retained Git DATA transport')
        (work / 'input-transport.json').write_bytes(common.encode(result))
    finally:
        subprocess.run = old_run
        sys.path[:] = old_path
        for name, module in list(sys.modules.items()):
            file = getattr(module, '__file__', None)
            if name.startswith('xs_held_') or file and Path(file).is_relative_to(original):
                if name in old_modules:
                    sys.modules[name] = old_modules[name]
                else:
                    sys.modules.pop(name, None)
        if 'common' in old_modules:
            sys.modules['common'] = old_modules['common']
        else:
            sys.modules.pop('common', None)


def accepted(common):
    decision = raw(ROOT / 'accepted/Root-decision.json')
    need(pin(decision) == DECISION_PIN and pin(raw(ROOT / 'accepted' / ARCHIVE, 64 * 1024**2)) == ARCHIVE_PIN,
         'exact Root-accepted native archive and decision')
    value = common.decode(decision)
    need(value['schema'] == 1 and value['issuer'] == 'Root' and value['accepted'] is True and
         value['status'] == 'ACCEPTED_EXACT_PERL5423_NATIVE_ARM4K_BUILD_PAIR_ONLY' and value['page_bytes'] == 4096 and
         {k: value['archive'][k] for k in ARCHIVE_PIN} == ARCHIVE_PIN and
         all(value['binding'][k] == v for k, v in PAIR.items()),
         'Root acceptance is only the fixed native ARM4K pair')
    return decision


def make_bundle(common, manifest, work, daemon):
    bundle = work / 'bundle'
    need(not os.path.lexists(bundle), 'fresh XS input bundle')
    bundle.mkdir(mode=0o700)
    names = [n for n in manifest['files'] if n.startswith('consumer/')]
    need(len(names) == 13 and all('/hosted_source/' not in n for n in names), 'exact frozen13-file consumer only')
    for name in names:
        target = bundle / name
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        target.write_bytes(raw(ROOT / name))
        target.chmod(manifest['files'][name]['mode'])
    for name in (ARCHIVE, 'PKGINFO', 'BUILDINFO', 'packages.txt'):
        (bundle / name).write_bytes(raw(ROOT / 'accepted' / name, 64 * 1024**2))
    (bundle / 'accepted-reader.json').write_bytes(accepted(common))
    (bundle / 'daemon.json').write_bytes(common.encode(daemon))
    return bundle


def prepare_argv(name, image, bundle, delegation_sha, source_sha):
    return DOCKER + ['create', '--name', name, '--label', 'cachy-asahi.operation=' + OPERATION,
        '--label', 'cachy-asahi.admission=' + delegation_sha,
        '--label', 'cachy-asahi.hosted-perl.source=' + source_sha,
        '--cpus=2', '--memory=4g', '--memory-swap=4g',
        '--pids-limit=256', '--init', '--read-only', '--network=none', '--cgroupns=private',
        '--hostname=perl5423-native', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--user=1001:1001',
        '--ulimit=nofile=1024:1024', '--ulimit=core=0:0',
        *['--tmpfs=' + key + ':' + value for key, value in PREP_TMPFS.items()],
        '--mount', 'type=bind,src=' + str(ROOT) + ',dst=/source,readonly',
        '--mount', 'type=bind,src=' + str(bundle) + ',dst=/inputs', '--workdir=/inputs',
        '--entrypoint=/usr/bin/python3', image, '-I', '-B', '/source/xs/prepare_inputs.py']


def inspect_preparation(row, image, name, bundle, delegation_sha, source_sha):
    h, x = row['HostConfig'], row['Config']
    need(row['Name'] == '/' + name and row['Image'] == image and not row['State']['Running'] and
         x['User'] == '1001:1001' and x['Hostname'] == 'perl5423-native' and
         x['Labels'].get('cachy-asahi.operation') == OPERATION and
         x['Labels'].get('cachy-asahi.admission') == delegation_sha and
         x['Labels'].get('cachy-asahi.hosted-perl.source') == source_sha,
         'actual stopped delegated preparation identity')
    need(h['NanoCpus'] == 2000000000 and h['Memory'] == h['MemorySwap'] == 4294967296 and
         h['PidsLimit'] == 256 and h['Init'] is True and h['ReadonlyRootfs'] is True and
         h['NetworkMode'] == 'none' and h['CgroupnsMode'] == 'private' and h['CapDrop'] == ['ALL'] and
         not h.get('CapAdd') and h['SecurityOpt'] == ['no-new-privileges'] and not h['Privileged'] and
         not h.get('Devices') and not h.get('DeviceRequests') and h['Tmpfs'] == PREP_TMPFS,
         'actual preparation CPU/memory/swap/PID/isolation policy')
    mounts = {m['Destination']: m for m in row['Mounts']}
    need(len(row['Mounts']) == 2 and set(mounts) == {'/source', '/inputs'} and
         all(m['Type'] == 'bind' for m in mounts.values()) and mounts['/source']['Source'] == str(ROOT) and
         not mounts['/source']['RW'] and mounts['/inputs']['Source'] == str(bundle) and mounts['/inputs']['RW'],
         'preparation touches only readonly Source and owned bundle')
    need(x['Entrypoint'] == ['/usr/bin/python3'] and x['WorkingDir'] == '/inputs' and
         x['Cmd'] == ['-I', '-B', '/source/xs/prepare_inputs.py'], 'actual fixed DATA-only preparation argv')


def operation(common, bundle, b, image, source_sha, daemon_sha, signatures_sha):
    a = common.decode(raw(ROOT / 'consumer/native_adapter/operation.TEMPLATE.json'))
    a.update(authorization='ROOT_ACCEPTED_PAIR_AND_ADMITTED_NATIVE_XS',
        source=dict(sha=b['source'], ref=b['ref'].removeprefix('refs/heads/')), run=b['run'], job=b['job'],
        pair=PAIR, image=image, approval=b['approval'], source_readback_sha256=source_sha,
        native_daemon_identity_sha256=daemon_sha, input_signature_audit_sha256=signatures_sha,
        runtime_identity_generator_sha256=NATIVE_SHA, authorize_runtime_observation_only=True,
        xs_admission_sha256=pin(raw(bundle / 'xs-admission.json'))['sha256'],
        inputs_sha256=pin(raw(bundle / 'xs-inputs.json'))['sha256'],
        plan_sha256=pin(raw(bundle / 'xs-plan.json'))['sha256'],
        accepted_reader_receipt=dict(path='/inputs/accepted-reader.json', **DECISION_PIN))
    rows, total = {}, 0
    for directory, dirs, files in os.walk(bundle, followlinks=False):
        need(all(not (Path(directory) / n).is_symlink() for n in dirs + files), 'ordinary prepared bundle')
        for name in files:
            leaf = Path(directory) / name
            relative = str(leaf.relative_to(bundle))
            need(relative not in ('operation.json', 'bundle-map.json') and len(rows) < 6000, 'fresh finite prepared bundle')
            body = raw(leaf, 64 * 1024**2)
            total += len(body)
            need(total <= 224 * 1024**2, 'prepared bundle byte bound')
            rows[relative] = pin(body)
    body = common.encode(dict(schema=1, files=rows))
    (bundle / 'bundle-map.json').write_bytes(body)
    a['bundle_map_sha256'] = pin(body)['sha256']
    body = common.encode(a)
    (bundle / 'operation.json').write_bytes(body)
    return pin(body)['sha256']


def native(args, work, common, held):
    b, manifest = binding(args, common)
    full = common.decode(raw(work / 'binding.json'))
    need(all(full[k] == v for k, v in b.items()) and re.fullmatch('[1-9][0-9]{0,19}', full['job']), 'actual same-Source XS job binding')
    proof_record = common.decode(raw(work / 'source-readback.json'))
    need(proof_record['binding'] == b and proof_record['status'] == 'PASS_EXACT_HOSTED_XS_SOURCE_READBACK',
         'current complete XS Source readback before native roles')
    need(args.execute, 'Root actual-role authorization required')
    accepted(common)
    command = held.Commands(work, time.monotonic() + 4500)
    record = dict(schema=1, status='FAIL', binding=full, native_acceptance=False, XS_acceptance=False,
        qualification='NOT_GRANTED', source_readback_sha256=pin(raw(work / 'source-readback.json'))['sha256'],
        daemon_identity_sha256=None, bootstrap={}, preparation={}, producer_exit=None, cleanup={})
    image, prep_name, delegation_sha = None, None, None
    old_env = dict(os.environ)
    handlers = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    def requested(number, frame):
        command.cancelled[0] = True
    try:
        for s in handlers:
            signal.signal(s, requested)
        daemon = held.daemon(command)
        (work / 'daemon.json').write_bytes(common.encode(daemon))
        record['daemon_identity_sha256'] = pin(raw(work / 'daemon.json'))['sha256']
        boot = load('xs_held_signed349_bootstrap', HELD / 'hosted/bootstrap.py', PINS['bootstrap.py'])
        boot_binding = dict(full, source_map_sha256=HELD_MAP, outer_source_map_sha256=b['source_map_sha256'])
        record['bootstrap_binding'] = boot_binding
        record['bootstrap'] = boot.run(HELD, work, boot_binding, command.deadline, command)
        image = record['bootstrap']['image']
        lock = raw(work / 'bootstrap/packages.lock')
        need(lock == raw(HELD / 'original/native/expected349.lock'), 'actual complete signed349 image inventory')
        bundle = make_bundle(common, manifest, work, daemon)
        command.deadline = time.monotonic() + 600
        prep_name = 'perl-xs-prep-' + full['run'] + '-' + uuid.uuid4().hex[:12]
        delegation = dict(schema=1, authorization='ROOT_ADMITTED_NATIVE_XS_DATA_PREPARATION', binding=full,
            image=image, accepted_pair=PAIR, accepted_reader_receipt=DECISION_PIN,
            generator_sha256=manifest['files']['xs/prepare_inputs.py']['sha256'],
            allowed_outputs=['prefix', 'xs-admission.json', 'xs-inputs.json', 'xs-plan.json', 'preparation.json'],
            roles=dict(Perl=0, make=0, compiler=0, XS=0), native_acceptance=False, XS_acceptance=False)
        delegation_body = common.encode(delegation)
        delegation_sha = pin(delegation_body)['sha256']
        (work / 'preparation-delegation.json').write_bytes(delegation_body)
        listed = checked(command, DOCKER + ['container', 'ls', '--all', '--format', '{{.Names}}'])
        need(prep_name not in listed.stdout.decode().splitlines(), 'preparation container already exists')
        inspected = checked(command, DOCKER + ['image', 'inspect', image])
        image_row = common.decode(inspected.stdout)[0]
        need(image_row['Id'] == image and image_row['Architecture'] == 'arm64' and image_row['Os'] == 'linux' and
             not image_row.get('Config', {}).get('Volumes'), 'native image without inherited anonymous volumes')
        checked(command, prepare_argv(prep_name, image, bundle, delegation_sha, full['source']))
        inspected = checked(command, DOCKER + ['inspect', prep_name])
        inspect_preparation(common.decode(inspected.stdout)[0], image, prep_name, bundle, delegation_sha, full['source'])
        (work / 'preparation-before.json').write_bytes(inspected.stdout)
        checked(command, DOCKER + ['start', '--attach', prep_name], 180)
        inspected = checked(command, DOCKER + ['inspect', prep_name])
        final = common.decode(inspected.stdout)[0]
        need(final['State']['Running'] is False and final['State']['Pid'] == 0 and
             final['State']['ExitCode'] == 0 and not final['State']['OOMKilled'], 'natural DATA preparation completion')
        (work / 'preparation-after.json').write_bytes(inspected.stdout)
        preparation_body = raw(bundle / 'preparation.json', 2 * 1024**2)
        preparation = common.decode(preparation_body)
        need(preparation['schema'] == 1 and preparation['status'] == 'PREPARED_NATIVE_XS_DATA_ONLY' and
             preparation['native_acceptance'] is False and preparation['XS_acceptance'] is False and
             preparation['planning_stage_removed'] is True and
             all(type(preparation[k]) is int and preparation[k] == 0 for k in
                 ('Perl_invocations', 'compiler_invocations', 'XS_loads')) and
             preparation['inputs'] == pin(raw(bundle / 'xs-inputs.json')) and
             preparation['admission'] == pin(raw(bundle / 'xs-admission.json')) and
             preparation['plan'] == pin(raw(bundle / 'xs-plan.json')),
             'actual DATA-only preparation receipt required')
        (work / 'preparation.json').write_bytes(preparation_body)
        record['preparation'] = dict(name=prep_name, delegation_sha256=delegation_sha, **pin(preparation_body))
        checked(command, DOCKER + ['rm', prep_name])
        listed = checked(command, DOCKER + ['container', 'ls', '--all', '--format', '{{.Names}}'])
        need(prep_name not in listed.stdout.decode().splitlines(), 'preparation retirement before XS actor')
        signature_sha = pin(raw(work / 'bootstrap/signatures.json'))['sha256']
        op_sha = operation(common, bundle, full, image, record['source_readback_sha256'],
                           record['daemon_identity_sha256'], signature_sha)
        record['operation_sha256'] = op_sha
        adapter = load('xs_frozen_native_adapter', ROOT / 'consumer/native_adapter/native.py', NATIVE_SHA)
        need(not command.cancelled[0], 'Root cancellation before XS operation')
        record['producer_exit'] = adapter.producer(str(bundle), op_sha, str(work / 'xs'))
        need(record['producer_exit'] == 0 and not command.cancelled[0], 'native XS producer did not complete')
        record['status'] = 'XS_SMOKE_EXPORTED_PENDING_ROOT_READER'
    except BaseException as error:
        record['error'] = type(error).__name__ + ': ' + str(error)[:2048]
    finally:
        command.deadline = time.monotonic() + 240
        command.cleaning = True
        errors = []
        token = hashlib.sha256((full['source'] + ':' + full['ref'] + ':' + full['run']).encode()).hexdigest()[:24]
        try:
            home = work / 'bootstrap/gpg'
            if home.is_dir():
                checked(command, ['gpgconf', '--homedir', str(home), '--kill', 'gpg-agent'])
                need(all(not p.exists() and not p.is_symlink() for p in
                     [home / ('S.gpg-agent' + s) for s in ('', '.browser', '.extra', '.ssh')]), 'bootstrap GPG socket absence')
            record['cleanup']['gpg_agent_absent'] = True
        except BaseException as error:
            errors.append('GPG: ' + str(error)[:1024])
        try:
            if not image:
                try:
                    candidate = raw(work / 'bootstrap/image-id').decode().strip()
                    if re.fullmatch('sha256:[0-9a-f]{64}', candidate):
                        image = candidate
                except (OSError, ValueError):
                    pass
                if not image:
                    found = checked(command, DOCKER + ['image', 'ls', '--no-trunc', '-q', '--filter',
                        'label=cachy-asahi.hosted-perl=' + token])
                    ids = found.stdout.decode().splitlines()
                    need(len(ids) <= 1, 'unambiguous owned bootstrap image recovery')
                    image = ids[0] if ids else None
            if image:
                need(re.fullmatch('sha256:[0-9a-f]{64}', image), 'exact immutable owned image ID')
        except BaseException as error:
            errors.append('image recovery: ' + str(error)[:1024])
            image = None
        for name, labels in [(prep_name, {'cachy-asahi.operation': OPERATION, 'cachy-asahi.admission': delegation_sha,
                                        'cachy-asahi.hosted-perl.source': full['source']}),
                             ('perl-bootstrap-inventory-' + token, {'cachy-asahi.hosted-perl': token,
                              'cachy-asahi.hosted-perl.source': full['source']})]:
            if name is None:
                continue
            try:
                query = DOCKER + ['container', 'ls', '--all', '--format', '{{.Names}}', '--filter', 'name=^' + name + '$']
                result = checked(command, query)
                if result.stdout.strip():
                    record['status'] = 'FAIL'
                    errors.append('unexpected owned container remained: ' + name)
                    need(result.stdout.decode().strip() == name, 'only exact owned container may retire')
                    result = checked(command, DOCKER + ['container', 'inspect', name])
                    row = common.decode(result.stdout)[0]
                    need(image and row['Image'] == image and all(row['Config']['Labels'].get(k) == v
                         for k, v in labels.items()), 'owned container image/labels before retirement')
                    if row['State']['Running']:
                        checked(command, DOCKER + ['stop', '--time=1', name], 10)
                        record['status'] = 'FAIL'
                        errors.append('forced retirement: ' + name)
                    checked(command, DOCKER + ['rm', name])
                    result = checked(command, query)
                    need(not result.stdout.strip(), 'owned container still present')
                record['cleanup'][name] = 'ABSENT'
            except BaseException as error:
                errors.append(name + ': ' + str(error)[:1024])
        try:
            if image:
                inspected = checked(command, DOCKER + ['image', 'inspect', image])
                row = common.decode(inspected.stdout)[0]
                need(row['Id'] == image and row['Config']['Labels'].get('cachy-asahi.hosted-perl') == token and
                     row['Config']['Labels'].get('cachy-asahi.hosted-perl.source') == full['source'] and
                     row.get('RepoTags') == ['perl-native-base:' + token], 'only exact owned bootstrap image may retire')
                checked(command, DOCKER + ['image', 'rm', image])
                absent = command(DOCKER + ['image', 'inspect', image], timeout=30)
                need(absent.returncode == 1 and absent.stderr.decode().strip() ==
                     'Error response from daemon: No such image: ' + image,
                     'actual owned image ID absence after removal')
            for selector in ('reference=perl-native-base:' + token, 'label=cachy-asahi.hosted-perl=' + token):
                result = checked(command, DOCKER + ['image', 'ls', '--no-trunc', '-q', '--filter', selector])
                need(not result.stdout.strip(), 'owned bootstrap image alias still present')
            record['cleanup']['image_absent'] = True
            record['cleanup']['image'] = image
        except BaseException as error:
            errors.append('image: ' + str(error)[:1024])
        if errors or command.cancelled[0]:
            record['status'] = 'FAIL'
            record['cleanup']['errors'] = errors
        if record['status'] != 'XS_SMOKE_EXPORTED_PENDING_ROOT_READER':
            record['daemon_build_retirement'] = 'UNPROVEN_ON_FAILED_OR_FORCED_BUILD;_ROOT_HOLD_REQUIRED'
        try:
            operations = work / 'bootstrap/operations.json'
            record['bootstrap_operations_sha256'] = pin(raw(operations, 2 * 1024**2))['sha256'] if operations.is_file() else None
            (work / 'hosted-xs.json').write_bytes(common.encode(record))
        finally:
            for s, handler in handlers.items():
                signal.signal(s, handler)
            os.environ.clear()
            os.environ.update(old_env)
    return 0 if record['status'] == 'XS_SMOKE_EXPORTED_PENDING_ROOT_READER' else 2


def main():
    need(sys.flags.isolated and not sys.flags.optimize, 'isolated unoptimized hosted XS entry')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('proof', 'metadata', 'inputs', 'native'))
    for name in ('source-sha', 'map-sha256', 'approval-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    common, held = helpers()
    work = common.path(Path(os.environ['RUNNER_TEMP']) / 'perl-hosted')
    if args.phase == 'proof':
        proof(args, work, common, held)
    elif args.phase == 'metadata':
        metadata(args, work, common)
    elif args.phase == 'inputs':
        inputs(args, work, common, held)
    else:
        return native(args, work, common, held)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
