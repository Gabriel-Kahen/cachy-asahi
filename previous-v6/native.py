#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""One separately admitted native XS container; no install or nested namespace role."""
import sys
if __name__ == '__main__' and (not sys.flags.isolated or sys.flags.optimize):
    raise SystemExit('isolated unoptimized Python required')

import argparse
import importlib.util
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import subprocess
import time
import uuid

HERE = Path(__file__).resolve().parent
CONSUMER = HERE.parent
RUNNER_SHA = 'bf2903fd1f72fe5c33a71bd00a15f71e7a4ae153d13522682af4f71d660e580e'
spec = importlib.util.spec_from_file_location('native_xs_runner', CONSUMER / 'runner/run.py')
runner = importlib.util.module_from_spec(spec)
raw = (CONSUMER / 'runner/run.py').read_bytes()
import hashlib
if hashlib.sha256(raw).hexdigest() != RUNNER_SHA:
    raise ValueError('frozen four-command runner changed')
exec(compile(raw, str(CONSUMER / 'runner/run.py'), 'exec'), runner.__dict__)
c = runner.load_module('native_xs_common', HERE / 'support/common.py', '97cf794d9f08bae3144c50d8b48258e37296cdcb11ba8db8dbed05ac6f7fc725')
p = runner.load_module('native_xs_preflight', CONSUMER / 'preflight.py', runner.PREFLIGHT_SHA)
DOCKER = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock']
INVENTORY = '579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
TMPFS = {'/run': 'rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001',
         '/tmp': 'rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001',
         '/xs-work': 'rw,exec,nosuid,nodev,size=256m,uid=1001,gid=1001,mode=0700'}
OPERATION = 'perl5423-native-xs-v1'


def operation(a):
    c.need(a['schema'] == 1 and a['operation'] == OPERATION and
           a['authorization'] == 'ROOT_ACCEPTED_PAIR_AND_ADMITTED_NATIVE_XS',
           'external Root pair acceptance and native XS authorization required')
    c.need(c.sha(a['source']['sha'], 40) and re.fullmatch(r'codex/[A-Za-z0-9._/-]+', a['source']['ref'])
           and all(type(a[k]) is str and re.fullmatch('[1-9][0-9]{0,19}', a[k]) for k in ('run', 'job')),
           'actual XS Source/run/job required')
    c.need(c.sha(a['pair']['source'], 40) and all(type(a['pair'][k]) is str and
           re.fullmatch('[1-9][0-9]{0,19}', a['pair'][k]) for k in ('run', 'job')),
           'actual accepted native pair selectors required')
    c.need(type(a['image']) is str and re.fullmatch('sha256:[0-9a-f]{64}', a['image']),
           'Root immutable native image required')
    for key in ('approval', 'source_readback_sha256', 'native_daemon_identity_sha256',
                'input_signature_audit_sha256', 'bundle_map_sha256', 'xs_admission_sha256',
                'inputs_sha256', 'plan_sha256', 'runtime_identity_generator_sha256'):
        c.need(c.sha(a[key]), 'external Root pin required: ' + key)
    c.need(a['runtime_identity_generator_sha256'] == c.pin(c.read(HERE / 'native.py'))['sha256']
           and a['authorize_runtime_observation_only'] is True and a['runner_sha256'] == RUNNER_SHA,
           'Root must explicitly authorize this exact runtime identity generator and runner')
    c.need(a['expected349_sha256'] == INVENTORY and a['nested_invocation'] == 'NOT_INVOKED'
           and a['nested_qualification'] == 'NOT_QUALIFIED', 'fixed image inventory; nested feature unqualified')
    row = a['accepted_reader_receipt']
    c.need(row['path'] == '/inputs/accepted-reader.json' and type(row['bytes']) is int
           and 0 < row['bytes'] <= 2 * 1024**2 and c.sha(row['sha256']),
           'actual Root-accepted Original Reader whole-file descriptor required')


def inputs(bundle, a):
    """Read-only, host/container path join. No archive extraction or actor launch."""
    bundle = c.path(bundle)
    def read_inside(path, cap=2 * 1024**2):
        c.need(type(path) is str and path.startswith('/inputs/'), 'fixed readonly input path required')
        relative = path[len('/inputs/'):]
        c.need(re.fullmatch('[A-Za-z0-9._+/-]+', relative) and
               all(part not in ('', '.', '..') for part in relative.split('/')), 'ordinary input-relative path')
        return c.read(bundle / relative, cap)
    ar, ir, plan_raw = (read_inside('/inputs/' + name) for name in
                         ('xs-admission.json', 'xs-inputs.json', 'xs-plan.json'))
    c.need([c.pin(body)['sha256'] for body in (ar, ir, plan_raw)] ==
           [a['xs_admission_sha256'], a['inputs_sha256'], a['plan_sha256']], 'Root XS operand whole pins differ')
    xs, imap, plan = p.decode(ar), p.decode(ir), p.decode(plan_raw)
    daemon_raw = read_inside('/inputs/daemon.json')
    c.need(c.pin(daemon_raw)['sha256'] == a['native_daemon_identity_sha256'], 'external actual daemon proof pin differs')
    c.need(xs['schema'] == 1 and xs['candidate'] == p.CANDIDATE and xs['target_arch'] == 'aarch64'
           and xs['artifact'] == dict(kind='native', **a['pair']), 'exact native candidate/accepted pair join')
    c.need(xs['root']['path'] == '/inputs/prefix' and xs['root']['kind'] in ('extracted', 'installed')
           and xs['root']['owner_uid'] == 1001 and all(type(xs['root'][k]) is int for k in ('device', 'inode')),
           'already Root-prepared alarm1001 prefix required')
    root_info = (bundle / 'prefix').stat()
    c.need((root_info.st_dev, root_info.st_ino, root_info.st_uid) ==
           tuple(xs['root'][k] for k in ('device', 'inode', 'owner_uid')), 'prefix identity differs')
    arc = xs['archive']
    c.need(arc['name'] == 'perl-5.42.3-1.3-aarch64.pkg.tar.zst'
           and arc['path'] == '/inputs/' + arc['name'], 'actual new candidate package archive required')
    for row, cap in [(arc, 64 * 1024**2), (xs['metadata']['pkginfo'], 1024**2),
                     (xs['metadata']['buildinfo'], 1024**2), (xs['inventory'], 1024**2),
                     (a['accepted_reader_receipt'], 2 * 1024**2)]:
        body = read_inside(row['path'], cap)
        c.need(c.pin(body) == {key: row[key] for key in ('bytes', 'sha256')}, 'external actual input pin differs')
    c.need(xs['inputs_sha256'] == a['inputs_sha256'] and imap['schema'] == 1 and
           imap['archive_sha256'] == arc['sha256'] and
           imap['candidate_recipe_sha256'] == p.CANDIDATE['recipe_sha256'], 'archive/runtime map join differs')
    required = {'usr/bin/perl', p.CORE + '/libperl.so', p.CORE + '/perl.h', p.CORE + '/config.h',
                p.CORE + '/EXTERN.h', p.CORE + '/XSUB.h', p.CORE + '/patchlevel.h',
                p.ARCH + '/Config.pm', p.ARCH + '/Config_heavy.pl', p.PURE + '/ExtUtils/MakeMaker.pm'}
    c.need(type(imap['files']) is dict and required <= set(imap['files']) and
           len(imap['files']) <= 5000, 'complete actual candidate runtime/header/Config/libperl inputs required')
    prefix = bundle / 'prefix'
    c.need(not root_info.st_mode & 0o022, 'prefix must already be protected from group/other writes')
    found = {'usr/bin/perl'}
    for relative in (p.ARCH, p.PURE):
        nodes = list((prefix / relative).rglob('*'))
        c.need(len(nodes) <= 10000 and all(not leaf.is_symlink() and
               (leaf.is_file() or leaf.is_dir()) for leaf in nodes), 'ordinary finite candidate runtime namespace')
        found.update(str(leaf.relative_to(prefix)) for leaf in nodes if leaf.is_file())
    c.need(found == set(imap['files']), 'complete actual prefix/runtime map differs')
    runtime_bytes = 0
    for relative, row in imap['files'].items():
        c.need(re.fullmatch('[A-Za-z0-9._+/-]+', relative) and
               all(part not in ('', '.', '..') for part in relative.split('/')), 'ordinary relative runtime input')
        body = c.read(prefix / relative, 32 * 1024**2)
        runtime_bytes += len(body)
        c.need(dict(**c.pin(body), mode=stat.S_IMODE((prefix / relative).stat().st_mode)) == row
               and runtime_bytes <= 128 * 1024**2, 'actual runtime/header whole pin or byte bound differs')
        if relative in ('usr/bin/perl', p.CORE + '/libperl.so'):
            c.need(len(body) >= 64 and body[:7] == b'\x7fELF\x02\x01\x01'
                   and int.from_bytes(body[18:20], 'little') == 183, 'actual AArch64 ELF executable/libperl required')
    pkg = p.metadata(read_inside(xs['metadata']['pkginfo']['path'], 1024**2))
    build = p.metadata(read_inside(xs['metadata']['buildinfo']['path'], 1024**2))
    c.need(all(pkg.get(k) == [v] for k, v in [('pkgname', 'perl'), ('pkgver', '5.42.3-1.3'), ('arch', 'aarch64')])
           and all(build.get(k) == [v] for k, v in [('pkgver', '5.42.3-1.3'), ('pkgarch', 'aarch64'),
               ('pkgbuild_sha256sum', p.CANDIDATE['recipe_sha256'])]), 'actual1.3 package/build metadata required')
    c.need(set(xs['toolchain']) == {'cc', 'ld', 'make'}, 'explicit toolchain inputs required')
    for row in xs['toolchain'].values():
        c.need(type(row['path']) is str and re.fullmatch('/usr/bin/[A-Za-z0-9._+-]+', row['path']) and
               type(row['bytes']) is int and 0 < row['bytes'] <= 16 * 1024**2 and c.sha(row['sha256']),
               'actual immutable-image tool binary pins required')
    # Check the complete expected command/env plan now, before even a Docker query.
    arch, pure = '/inputs/prefix/' + p.ARCH, '/inputs/prefix/' + p.PURE
    argv = ['/inputs/prefix/usr/bin/perl', '-I' + arch, '-I' + pure]
    tools = xs['toolchain']
    environment = dict(PATH='/usr/bin', HOME='/xs-work/xs-stage', LC_ALL='C', TZ='UTC',
                       LD_LIBRARY_PATH='/inputs/prefix/' + p.CORE, PERL_DL_NONLAZY='1',
                       CACHY_XS_ROOT='/inputs/prefix', CACHY_XS_PERL=argv[0],
                       CACHY_XS_CORE='/inputs/prefix/' + p.CORE,
                       CACHY_XS_ADMISSION='/inputs/xs-admission.json',
                       CACHY_XS_ADMISSION_SHA256=a['xs_admission_sha256'],
                       CACHY_XS_INPUTS='/inputs/xs-inputs.json', CACHY_XS_INPUTS_SHA256=a['inputs_sha256'])
    environment.update({'CACHY_XS_' + key.upper(): tools[key]['path'] for key in ('cc', 'ld', 'make')})
    expected = dict(status='PREFLIGHT_DATA_ONLY_XS_NOT_RUN', native_acceptance=False,
                    cwd='/xs-work/xs-stage', environment_policy='REPLACE_ENTIRE_ENVIRONMENT_WITH_THIS_EXACT_MAP',
                    environment=environment, commands=[argv + ['Makefile.PL'], [tools['make']['path'], '-j2'],
                    [tools['make']['path'], 'test'], argv + ['provenance.pl']],
                    archive=arc, root=xs['root'], artifact=xs['artifact'])
    runner.identical(p.encode(expected), plan_raw)
    return xs, plan


def bundle_check(bundle, a):
    raw = c.read(bundle / 'bundle-map.json', 2 * 1024**2)
    c.need(c.pin(raw)['sha256'] == a['bundle_map_sha256'], 'Root complete bundle map pin differs')
    rows = p.decode(raw)['files']
    c.need(type(rows) is dict and 1 <= len(rows) <= 6000, 'finite complete readonly bundle map')
    found = set()
    total = 0
    count = 0
    for directory, dirs, files in os.walk(bundle, followlinks=False):
        for name in dirs + files:
            count += 1
            c.need(count <= 14000, 'finite bundle node count')
            leaf = Path(directory) / name
            c.need(not leaf.is_symlink(), 'bundle aliases refused')
        for name in files:
            leaf = Path(directory) / name
            relative = str(leaf.relative_to(bundle))
            if relative in ('operation.json', 'bundle-map.json'):
                continue
            c.need(relative in rows, 'unmapped bundle leaf')
            body = c.read(leaf, 64 * 1024**2)
            c.need(c.pin(body) == {k: rows[relative][k] for k in ('bytes', 'sha256')}, 'bundle leaf pin differs')
            total += len(body)
            c.need(total <= 224 * 1024**2, 'bundle aggregate byte bound')
            found.add(relative)
    c.need(found == set(rows), 'missing bundle leaf')


def create_argv(name, volume, image, bundle, admission_sha):
    return DOCKER + ['create', '--name', name, '--label', 'cachy-asahi.operation=' + OPERATION,
        '--label', 'cachy-asahi.admission=' + admission_sha,
        '--cpus=2', '--memory=4g', '--memory-swap=4g', '--pids-limit=256', '--init', '--read-only',
        '--network=none', '--cgroupns=private', '--hostname=perl5423-native', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--user=1001:1001', '--ulimit=nofile=1024:1024',
        '--ulimit=core=0:0', *['--tmpfs=' + key + ':' + value for key, value in TMPFS.items()],
        '--mount', 'type=bind,src=' + str(bundle) + ',dst=/inputs,readonly',
        '--mount', 'type=volume,src=' + volume + ',dst=/work,volume-nocopy', '--workdir=/work',
        '--entrypoint=/usr/bin/python3', image, '-I', '-B',
        '/inputs/consumer/native_adapter/native.py', 'actor', '--admission-sha256', admission_sha]


def inspect_actor(row, a, name, volume, bundle, admission_sha):
    h, x = row['HostConfig'], row['Config']
    c.need(row['Name'] == '/' + name and row['Image'] == a['image'] and not row['State']['Running']
           and x['User'] == '1001:1001' and x['Hostname'] == 'perl5423-native', 'actual stopped native actor identity')
    c.need(h['NanoCpus'] == 2000000000 and h['Memory'] == h['MemorySwap'] == 4294967296
           and h['PidsLimit'] == 256 and h['ReadonlyRootfs'] is True and h['Init'] is True
           and h['NetworkMode'] == 'none' and h['CgroupnsMode'] == 'private' and h['CapDrop'] == ['ALL']
           and not h.get('CapAdd') and h['SecurityOpt'] == ['no-new-privileges'] and not h['Privileged']
           and not h.get('Devices') and not h.get('DeviceRequests') and h['Tmpfs'] == TMPFS,
           'actual finite native Docker policy differs')
    mounts = {m['Destination']: m for m in row['Mounts']}
    c.need(len(row['Mounts']) == 2 and set(mounts) == {'/inputs', '/work'} and
           mounts['/inputs']['Type'] == 'bind' and not mounts['/inputs']['RW'] and
           mounts['/inputs']['Source'] == str(bundle) and mounts['/work']['Type'] == 'volume'
           and mounts['/work']['Name'] == volume and mounts['/work']['RW'], 'actual exact input/work mounts')
    declared = [m for m in h['Mounts'] if m['Target'] == '/work']
    c.need(len(declared) == 1 and declared[0]['Type'] == 'volume' and declared[0]['Source'] == volume
           and declared[0]['VolumeOptions']['NoCopy'] is True, 'explicit owned consumer volume-nocopy')
    c.need(x['Entrypoint'] == ['/usr/bin/python3'] and x['WorkingDir'] == '/work' and
           x['Cmd'] == ['-I', '-B', '/inputs/consumer/native_adapter/native.py', 'actor',
                        '--admission-sha256', admission_sha], 'actual fixed actor argv')


def inspect_init(row, a, name, volume):
    h, x = row['HostConfig'], row['Config']
    c.need(row['Name'] == '/' + name and row['Image'] == a['image'] and not row['State']['Running']
           and x['User'] == '0:0' and x['Entrypoint'] == ['/usr/bin/chown'] and
           x['Cmd'] == ['1001:1001', '/work'] and h['CapDrop'] == ['ALL'] and h['CapAdd'] in (['CHOWN'], ['CAP_CHOWN'])
           and h['SecurityOpt'] == ['no-new-privileges'] and h['ReadonlyRootfs'] is True
           and h['NetworkMode'] == 'none' and not h['Privileged'] and not h.get('Devices')
           and not h.get('DeviceRequests') and h['NanoCpus'] == 2000000000
           and h['Memory'] == h['MemorySwap'] == 4294967296 and h['PidsLimit'] == 256,
           'actual bounded volume-owner initializer differs')
    declared = h['Mounts']
    c.need(len(declared) == 1 and declared[0]['Type'] == 'volume' and declared[0]['Source'] == volume
           and declared[0]['Target'] == '/work' and declared[0]['VolumeOptions']['NoCopy'] is True,
           'explicit owned initializer volume-nocopy')
    c.need(len(row['Mounts']) == 1 and row['Mounts'][0]['Destination'] == '/work'
           and row['Mounts'][0]['Type'] == 'volume' and row['Mounts'][0]['Name'] == volume
           and row['Mounts'][0]['RW'], 'initializer touches only the owned work volume')


def daemon_join(proof, info, version, before, after):
    c.need(proof['schema'] == 1 and proof['status'] == 'OBSERVED_ROOTFUL_NATIVE_LOCAL_DAEMON_PRECONDITIONS'
           and proof['native_acceptance'] is False, 'held Root actual daemon observation required')
    c.need(proof['socket'] == dict(path='/var/run/docker.sock', uid=0, socket=True, stable=True)
           and before == after and before[3] == 0 and stat.S_ISSOCK(before[2]),
           'actual stable root-owned local daemon socket differs')
    for key in ('ID', 'OSType', 'Architecture', 'SecurityOptions', 'CgroupVersion',
                'CpuCfsQuota', 'MemoryLimit', 'SwapLimit', 'PidsLimit', 'DockerRootDir'):
        c.need(info[key] == proof['info'][key], 'current daemon differs from Root proof: ' + key)
    c.need(info['ID'] and info['OSType'] == 'linux' and info['Architecture'] in ('aarch64', 'arm64')
           and info['CgroupVersion'] == '2' and all(info[key] is True for key in
               ('CpuCfsQuota', 'MemoryLimit', 'SwapLimit', 'PidsLimit')) and
           type(info['SecurityOptions']) is list and all(type(value) is str and
               'rootless' not in value and 'userns' not in value for value in info['SecurityOptions']),
           'Rootful unremapped native cgroup daemon required')
    c.need(version['Server'] == proof['version']['Server'] and version['Server']['Os'] == 'linux'
           and version['Server']['Arch'] in ('arm64', 'aarch64'), 'actual daemon version identity differs')
    c.need(proof['host']['machine'] == 'aarch64' and proof['host']['system'] == 'Linux'
           and proof['host']['uid'] == proof['host']['gid'] == 1001 and
           os.uname().machine == 'aarch64' and os.getuid() == os.getgid() == 1001,
           'actual native alarm1001 coordinator differs')


def export_join(exported):
    rows = c.decode(exported['evidence-map.json'][0])
    c.need(type(rows) is dict and 1 <= len(rows) <= 50, 'nonempty bounded complete evidence map required')
    found = {'evidence-map.json', 'actor-result.json', 'runtime-observation.json',
             'actual-packages.txt', 'operation.json', 'accepted-reader.json', 'work-preentry-v5.json'}
    for relative, row in rows.items():
        c.need(re.fullmatch('[A-Za-z0-9._+/-]+', relative) and all(part not in ('', '.', '..') for part in relative.split('/'))
               and re.fullmatch(r'evidence-[0-9]{3}\.data', row['file']) and row['file'] not in found,
               'unique relative original evidence path and flat export filename required')
        c.need(c.pin(exported[row['file']][0]) == {key: row[key] for key in ('bytes', 'sha256')},
               'exported evidence leaf differs from actual map')
        found.add(row['file'])
    c.need(found == set(exported), 'complete mapped export namespace differs')
    c.need(len(exported['work-preentry-v5.json'][0]) <= 16384, 'bounded versioned preentry channel')
    receipt = c.decode(exported['work-preentry-v5.json'][0])
    operation_body = c.decode(exported['operation.json'][0])
    runtime_body = c.decode(exported['runtime-observation.json'][0])
    c.need(all(receipt[k] == operation_body[k] for k in ('source', 'run', 'job', 'image'))
           and receipt['native_adapter_sha256'] == operation_body['runtime_identity_generator_sha256']
           == runtime_body['generator_sha256'], 'preentry actual tuple and generator joins')
    c.need(receipt['schema'] == 1 and receipt['kind'] == 'XS_WORK_VOLUME_PREENTRY_V5'
           and receipt['phase'] == 'OBSERVED_BEFORE_ANY_WORK_WRITE'
           and receipt['operation_sha256'] == c.pin(exported['operation.json'][0])['sha256']
           and receipt['runtime_observation'] == c.pin(exported['runtime-observation.json'][0])
           and receipt['actor_result'] == c.pin(exported['actor-result.json'][0])
           and receipt['work_root']['empty'] is receipt['work_root']['writable'] is True
           and receipt['work_root']['uid'] == receipt['work_root']['gid'] == 1001
           and receipt['work_root']['mode'] in (0o700, 0o755)
           and receipt['native_acceptance'] is receipt['XS_acceptance'] is False,
           'versioned preentry and unchanged actor-output byte joins')


def alpm_inventory(raw):
    c.need(type(raw) is bytes and len(raw) <= 1024**2 and c.pin(raw)['sha256'] == INVENTORY,
           'exact admitted signed349 inventory before local DB reads')
    rows = raw.decode().splitlines()
    c.need(len(rows) == 349 and rows == sorted(rows) and len(set(rows)) == 349,
           'complete canonical349 inventory')
    admitted = {}
    for row in rows:
        parts = row.split(' ')
        c.need(len(parts) == 2 and re.fullmatch('[a-z0-9][a-z0-9@._+-]{0,127}', parts[0])
               and re.fullmatch('(?:[0-9]+:)?[A-Za-z0-9._+~-]{1,160}', parts[1]),
               'finite admitted package name/version including optional numeric epoch')
        name, version = parts
        key = name + '-' + version
        c.need(key not in admitted and len(key) <= 240, 'unique admitted local DB directory')
        admitted[key] = (name, version)
    return admitted


def read_alpm_desc(value, admitted):
    """Only one inventory-bound fixed-root ALPM desc; never a Docker path operand."""
    path = Path(value)
    c.need(path.parts[:5] == ('/', 'var', 'lib', 'pacman', 'local') and len(path.parts) == 7
           and path.name == 'desc' and path.parent.name in admitted,
           'only admitted /var/lib/pacman/local/name-version/desc')
    expected = admitted[path.parent.name]
    c.need(path.parent.name == expected[0] + '-' + expected[1], 'inventory-bound directory identity')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fds = [os.open('/', flags)]
    links = []
    leaf = None
    key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid,
                     s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    try:
        for part in path.parts[1:-1]:
            before = os.stat(part, dir_fd=fds[-1], follow_symlinks=False)
            c.need(stat.S_ISDIR(before.st_mode), 'ordinary nonsymlink ALPM ancestry')
            child = os.open(part, flags, dir_fd=fds[-1])
            fds.append(child)
            c.need(key(before) == key(os.fstat(child)), 'stable ALPM directory link/open')
            links.append((fds[-2], part, child, before))
        before = os.stat('desc', dir_fd=fds[-1], follow_symlinks=False)
        leaf = os.open('desc', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                       dir_fd=fds[-1])
        c.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
               and 0 < before.st_size <= 1024**2 and key(before) == key(os.fstat(leaf)),
               'bounded ordinary single-link ALPM descriptor')
        body = bytearray()
        while block := os.read(leaf, min(65536, 1024**2 + 1 - len(body))):
            body.extend(block)
            c.need(len(body) <= 1024**2, 'ALPM descriptor byte cap')
        c.need(len(body) == before.st_size and key(before) == key(os.fstat(leaf))
               == key(os.stat('desc', dir_fd=fds[-1], follow_symlinks=False)),
               'stable complete ALPM descriptor identity')
        for parent, name, child, previous in links:
            c.need(key(previous) == key(os.fstat(child))
                   == key(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                   'unchanged nonsymlink ALPM ancestry')
        c.need(b'\0' not in body, 'ordinary ALPM text bytes')
        rows = bytes(body).decode().splitlines()
        for field, text in zip(('%NAME%', '%VERSION%'), expected):
            c.need(rows.count(field) == 1, 'one ALPM name/version field')
            index = rows.index(field)
            c.need(index + 2 < len(rows) and rows[index + 1] == text and rows[index + 2] == '',
                   'descriptor name/version exactly match admitted directory')
        return expected[0] + ' ' + expected[1]
    finally:
        if leaf is not None:
            os.close(leaf)
        for fd in reversed(fds):
            os.close(fd)


def actor(admission_sha):
    ar = c.read('/inputs/operation.json')
    c.need(c.pin(ar)['sha256'] == admission_sha, 'external Root operation whole pin differs')
    a = c.decode(ar)
    operation(a)
    bundle_check(Path('/inputs'), a)
    xs, _ = inputs(Path('/inputs'), a)
    runtime = runner.load_module('native_xs_runtime', HERE / 'support/runtime.py', '01e84abc7bce05df42262d8ab7f279be406aa2b63671f2e6f1cb02d08681ba0b')
    entry, parent = runtime.context(), runtime.context(1)
    for value in (entry, parent):
        c.need(all(value[k] == 1001 for k in ('uid', 'euid', 'gid', 'egid')) and
               value['architecture'] == 'aarch64' and value['page_bytes'] in (4096, 16384)
               and value['limits'] == runner.CONTROLLERS and value['interfaces'] == ['lo'] and
               value['hostname'] == 'perl5423-native', 'actual native actor runtime differs')
        c.need(all(int(value['status'][k], 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'))
               and value['status']['NoNewPrivs'] == '1', 'actual cap0/NNP runtime')
        runtime.mounts(value['mountinfo'])
    c.need(entry['ppid'] == parent['pid'] == 1 and entry['pid'] > 1 and
           entry['cmdline'] == ['/usr/bin/python3', '-I', '-B', '/inputs/consumer/native_adapter/native.py',
                                'actor', '--admission-sha256', admission_sha] and
           Path(parent['exe']).name in ('docker-init', 'tini') and
           parent['cmdline'][-len(entry['cmdline']) - 1:] == ['--'] + entry['cmdline'] and
           entry['cwd'] == '/work' and
           all(entry[key] == parent[key] for key in ('namespaces', 'uid_map', 'gid_map', 'groups', 'cgroup')),
           'actual direct init/entry domain continuity')
    c.need(all(entry[key] == [[0, 0, 4294967295]] for key in ('uid_map', 'gid_map')),
           'actual unremapped initial user namespace required')
    # Derive the actual installed-image inventory without launching a fifth command.
    admitted_raw = p.pinned(xs['inventory'], 1024**2)
    admitted = alpm_inventory(admitted_raw)
    packages = []
    for desc in Path('/var/lib/pacman/local').glob('*/desc'):
        c.need(len(packages) < 400, 'finite installed image inventory')
        packages.append(read_alpm_desc(desc, admitted))
    inventory = ('\n'.join(sorted(packages)) + '\n').encode()
    c.need(c.pin(inventory)['sha256'] == INVENTORY and inventory == admitted_raw,
           'actual signed349 image inventory differs')
    workspace = Path('/xs-work')
    mounts = [line.split() for line in entry['mountinfo'].splitlines()]
    work_mounts = [row for row in mounts if row[4] == '/xs-work']
    c.need(len(work_mounts) == 1 and {'rw', 'nosuid', 'nodev'} <= set(work_mounts[0][5].split(','))
           and 'noexec' not in work_mounts[0][5].split(',') and workspace.stat().st_gid == 1001
           and os.statvfs(workspace).f_blocks * os.statvfs(workspace).f_frsize == 256 * 1024**2,
           'actual exact executable private XS tmpfs required')
    membership = Path('/proc/self/cgroup').read_text()
    c.need(membership == '0::/\n', 'private unified cgroup namespace required')
    cg = Path('/sys/fs/cgroup').stat()
    sandbox = dict(schema=1, authorization='ROOT_ADMITTED_FOUR_COMMAND_XS_SMOKE', exclusive_scope=True,
                   plan_sha256=a['plan_sha256'], runner_sha256=RUNNER_SHA, target_arch='aarch64', uid=1001, gid=1001,
                   workspace=str(workspace), workspace_identity=runner.identity(workspace),
                   namespaces={key: os.readlink('/proc/self/ns/' + key) for key in runner.NS},
                   cgroup_membership=membership, cgroup_directory='/sys/fs/cgroup',
                   cgroup_identity=[cg.st_dev, cg.st_ino], accepted_reader_receipt=a['accepted_reader_receipt'])
    runner.sandbox_check(p, sandbox)
    # Runtime identities are observations under explicit Root delegation, never a new approval.
    observation = dict(schema=1, operation_sha256=admission_sha,
                       generator_sha256=a['runtime_identity_generator_sha256'],
                       entry=entry, parent=parent, sandbox=sandbox, native_acceptance=False, XS_acceptance=False)
    sandbox_path = Path('/tmp/xs-sandbox.json')
    with sandbox_path.open('xb') as stream:
        stream.write(p.encode(sandbox))
    output = Path('/work/output')
    output.mkdir(mode=0o700)
    (output / 'runtime-observation.json').write_bytes(c.encode(observation))
    (output / 'actual-packages.txt').write_bytes(inventory)
    (output / 'operation.json').write_bytes(ar)
    (output / 'accepted-reader.json').write_bytes(p.pinned(a['accepted_reader_receipt'], 2 * 1024**2))
    failure = None
    report = None
    try:
        report = runner.execute('/inputs/xs-plan.json', a['plan_sha256'], sandbox_path,
                                c.pin(p.encode(sandbox))['sha256'])
    except BaseException as error:
        failure = type(error).__name__ + ': ' + str(error)
    evidence = workspace / 'xs-evidence'
    exported = {}
    total = 0
    if evidence.exists():
        for directory, dirs, files in os.walk(evidence, followlinks=False):
            c.need(all(not (Path(directory) / name).is_symlink() for name in dirs + files), 'evidence alias')
            for name in sorted(files):
                leaf = Path(directory) / name
                body = c.read(leaf, 16 * 1024**2)
                total += len(body)
                c.need(len(exported) < 50 and total <= 128 * 1024**2, 'complete finite evidence export bound')
                flat = f'evidence-{len(exported):03d}.data'
                with (output / flat).open('xb') as stream:
                    stream.write(body)
                exported[str(leaf.relative_to(evidence))] = dict(file=flat, **c.pin(body))
    (output / 'evidence-map.json').write_bytes(c.encode(exported))
    result = dict(schema=1, status='RUNNER_COMPLETED' if report and report['status'] == 'FOUR_SMOKE_COMMANDS_COMPLETED' else 'FAIL',
                  runner_status=report['status'] if report else None, failure=failure,
                  operation_sha256=admission_sha, native_acceptance=False, XS_acceptance=False,
                  qualification='NOT_GRANTED', nested_invocation='NOT_INVOKED', nested_qualification='NOT_QUALIFIED')
    (output / 'actor-result.json').write_bytes(c.encode(result))
    return 0 if result['status'] == 'RUNNER_COMPLETED' else 2


def work_preentry(admission_sha):
    """Capture before ANY work write. No stdout, file creation or policy mutation."""
    raw = c.read('/inputs/operation.json')
    c.need(c.pin(raw)['sha256'] == admission_sha, 'exact preentry operation pin')
    a = c.decode(raw)
    operation(a)
    c.need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 1001,
           'ordinary1001 preentry credentials')
    work = Path('/work')
    fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        c.need(stat.S_ISDIR(s.st_mode) and s.st_uid == s.st_gid == 1001
               and stat.S_IMODE(s.st_mode) in (0o700, 0o755), 'owned safe work-root mode')
        with os.scandir(fd) as entries:
            c.need(next(entries, None) is None, 'fresh empty work root before writes')
        c.need(Path.cwd() == work and os.access(work, os.W_OK | os.X_OK, effective_ids=True)
               and not os.statvfs(work).f_flag & os.ST_RDONLY, 'actual writable work-root access')
        current = work.lstat()
        c.need((s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode) ==
               (current.st_dev, current.st_ino, current.st_uid, current.st_gid, current.st_mode),
               'same ordinary work-root identity')
        result = dict(schema=1, kind='XS_WORK_VOLUME_PREENTRY_V5',
                      phase='OBSERVED_BEFORE_ANY_WORK_WRITE', operation_sha256=admission_sha,
                      source=a['source'], run=a['run'], job=a['job'], image=a['image'],
                      native_adapter_sha256=a['runtime_identity_generator_sha256'],
                      work_root=dict(device=s.st_dev, inode=s.st_ino, uid=s.st_uid, gid=s.st_gid,
                                     mode=stat.S_IMODE(s.st_mode), empty=True, writable=True),
                      native_acceptance=False, XS_acceptance=False)
        return result, fd
    except BaseException:
        os.close(fd)
        raise


def record_work_preentry(value, fd):
    """Write only into the already-created original private actor output domain."""
    s = os.fstat(fd)
    old = value['work_root']
    c.need((s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) ==
           tuple(old[k] for k in ('device', 'inode', 'uid', 'gid', 'mode')),
           'held work-root identity unchanged after actor')
    out = os.open('output', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    try:
        info = os.fstat(out)
        c.need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 1001
               and stat.S_IMODE(info.st_mode) == 0o700 and info.st_dev == s.st_dev,
               'existing private actor output, never an alternate receipt path')
        result = dict(value)
        for field, name in [('runtime_observation', 'runtime-observation.json'), ('actor_result', 'actor-result.json')]:
            leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=out)
            try:
                before = os.fstat(leaf)
                c.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= 2 * 1024**2,
                       'bounded original actor receipt')
                with os.fdopen(os.dup(leaf), 'rb') as stream:
                    body = stream.read(2 * 1024**2 + 1)
                after = os.fstat(leaf)
                c.need(len(body) == before.st_size and
                       (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                       (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                       'original actor receipt stable while joined')
                result[field] = c.pin(body)
            finally:
                os.close(leaf)
        body = c.encode(result)
        c.need(len(body) <= 16384, 'finite versioned preentry receipt')
        receipt = os.open('work-preentry-v5.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o600, dir_fd=out)
        with os.fdopen(receipt, 'wb') as stream:
            stream.write(body)
    finally:
        os.close(out)


def actor_dispatch(admission_sha):
    observed, fd = work_preentry(admission_sha)
    failure = None
    code = None
    try:
        try:
            code = actor(admission_sha)  # Explicit v6 ALPM-read seam; other runtime probes/JSON are unchanged.
        except BaseException as error:
            failure = error
        try:
            record_work_preentry(observed, fd)
        except BaseException as error:
            if failure is not None:
                failure.add_note('XS v6 preentry receipt unavailable: ' + type(error).__name__ + ': ' + str(error)[:512])
                raise failure from None
            raise
        if failure is not None:
            raise failure
        return code
    finally:
        os.close(fd)


def producer(bundle, admission_sha, output):
    bundle, output = c.path(bundle), c.path(output)
    ar = c.read(bundle / 'operation.json')
    c.need(c.pin(ar)['sha256'] == admission_sha, 'external Root operation whole pin differs')
    a = c.decode(ar)
    operation(a)
    bundle_check(bundle, a)
    inputs(bundle, a)  # All externally supplied DATA must exist before a single Docker call.
    c.need(os.uname().sysname == 'Linux' and os.uname().machine == 'aarch64'
           and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 1001,
           'native alarm1001 coordinator required before Docker calls')
    c.need(not output.exists() and not output.is_relative_to(bundle) and not bundle.is_relative_to(output),
           'fresh disjoint output required')
    c.need(output.parent.stat().st_uid == os.getuid() and not output.parent.stat().st_mode & 0o022,
           'private caller-owned output parent')
    c.need(shutil.disk_usage(output.parent).free >= 1024**3, 'one GiB evidence reserve required')
    output.mkdir(mode=0o700)
    owned = runner.load_module('native_xs_owned', CONSUMER / 'runner/helpers/owned_child.py', runner.HELPER_SHA)
    parser = runner.load_module('native_xs_export', HERE / 'support/data_export.py', 'ac59342608cc8279ccb0aa218da792e72d903960769ab2f4553ee8ea9b5d334e')
    token = 'perl-xs-' + a['run'] + '-' + uuid.uuid4().hex[:12]
    volume, init = token + '-work', token + '-init'
    report = dict(schema=1, status='FAIL', operation_sha256=admission_sha, operations=[], cleanup=[],
                  planned=dict(actor=token, init=init, volume=volume), native_acceptance=False,
                  XS_acceptance=False, qualification='NOT_GRANTED', owned_resources_absent=False)
    (output / 'operation.json').write_bytes(ar)
    deadline = time.monotonic() + 600
    cancelled = runner.Cancellation()
    handlers = {sig: runner.signal.signal(sig, cancelled.signal) for sig in (runner.signal.SIGINT, runner.signal.SIGTERM)}
    cleanup = False
    recovery = False
    volume_attempted = False
    actor_ok = False

    def save():
        (output / 'producer-receipt.json').write_bytes(c.encode(report))

    def command(argv, seconds=30, check=True, tar=False):
        if not cleanup and not recovery:
            cancelled.check()
        remaining = deadline - time.monotonic() - (0 if cleanup else 90)
        c.need(remaining > 2, 'finite operation/cleanup deadline exhausted')
        number = len(report['operations'])
        log = output / f'command-{number:03d}.log'
        row = dict(argv=argv, lifecycle={}, log=log.name)
        old = resource.getrlimit(resource.RLIMIT_FSIZE)
        limit = 256 * 1024**2 if tar else 8 * 1024**2
        soft = min([limit] + [value for value in old if value != resource.RLIM_INFINITY])
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (soft, old[1]))
            with log.open('xb') as stream:
                if tar:
                    destination = output / 'output.tar'
                    row['stdout'] = destination.name
                    with destination.open('xb') as data:
                        result = owned.run(argv, timeout=min(seconds, remaining), cwd=output,
                            env=dict(PATH='/usr/bin', HOME=str(output), LC_ALL='C', TZ='UTC'),
                            stdout=data, stderr=stream, lifecycle=row['lifecycle'],
                            stdout_limit=limit, stderr_limit=8 * 1024**2,
                            on_tick=None if cleanup or recovery else cancelled.check)
                else:
                    result = owned.run(argv, timeout=min(seconds, remaining), cwd=output,
                        env=dict(PATH='/usr/bin', HOME=str(output), LC_ALL='C', TZ='UTC'),
                        stdout=stream, stderr=subprocess.STDOUT, lifecycle=row['lifecycle'],
                        stdout_limit=limit, on_tick=None if cleanup or recovery else cancelled.check)
            c.need(c.natural(row['lifecycle'], zero=check), 'CLI failure or uncertain/forced retirement')
            row['returncode'] = result.returncode
            return c.read(log, 8 * 1024**2), result.returncode
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE, old)
            row['launched'] = type(row['lifecycle'].get('pid')) is int
            report['operations'].append(row)
            save()

    try:
        raw, _ = command(DOCKER + ['image', 'inspect', a['image']])
        image = c.decode(raw)[0]
        c.need(image['Id'] == a['image'] and image['Architecture'] == 'arm64' and image['Os'] == 'linux'
               and not image.get('Config', {}).get('Volumes'), 'actual immutable ARM image without inherited volumes')
        (output / 'image-inspect.json').write_bytes(raw)
        socket_path = Path('/var/run/docker.sock')
        socket_identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)
        before = socket_identity(socket_path.stat())
        info_raw, _ = command(DOCKER + ['info', '--format', '{{json .}}'])
        version_raw, _ = command(DOCKER + ['version', '--format', '{{json .}}'])
        after = socket_identity(socket_path.stat())
        info, version = c.decode(info_raw), c.decode(version_raw)
        proof_raw = c.read(bundle / 'daemon.json')
        daemon_join(c.decode(proof_raw), info, version, before, after)
        (output / 'root-daemon-proof.json').write_bytes(proof_raw)
        (output / 'actual-daemon.json').write_bytes(c.encode(dict(info=info, version=version,
                                                               socket_before=before, socket_after=after)))
        docker_root = c.path(info['DockerRootDir'])
        memory = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                          if line.startswith('MemAvailable:'))) * 1024
        c.need(memory >= 8 * 1024**3 and shutil.disk_usage(docker_root).free >= 2 * 1024**3,
               'actual native host memory/disk reserve required')
        raw, _ = command(DOCKER + ['container', 'ls', '--all', '--format', '{{.Names}}'])
        c.need(not {token, init} & set(raw.decode().splitlines()), 'planned container already exists')
        raw, _ = command(DOCKER + ['volume', 'ls', '--quiet'])
        c.need(volume not in raw.decode().splitlines(), 'planned volume already exists')
        volume_attempted = True
        label = 'cachy-asahi.admission=' + admission_sha
        command(DOCKER + ['volume', 'create', '--label', label, volume])
        command(DOCKER + ['create', '--name', init, '--label', label, '--cpus=2', '--memory=4g',
            '--memory-swap=4g', '--pids-limit=256', '--network=none', '--read-only', '--user=0:0',
            '--cap-drop=ALL', '--cap-add=CHOWN', '--security-opt=no-new-privileges',
            '--mount', 'type=volume,src=' + volume + ',dst=/work,volume-nocopy', '--entrypoint=/usr/bin/chown',
            a['image'], '1001:1001', '/work'])
        raw, _ = command(DOCKER + ['inspect', init])
        inspect_init(c.decode(raw)[0], a, init, volume)
        (output / 'init-before.json').write_bytes(raw)
        argv = create_argv(token, volume, a['image'], bundle, admission_sha)
        command(argv)
        raw, _ = command(DOCKER + ['inspect', token])
        inspect_actor(c.decode(raw)[0], a, token, volume, bundle, admission_sha)
        (output / 'actor-before.json').write_bytes(raw)
        command(DOCKER + ['start', '--attach', init])
        raw, _ = command(DOCKER + ['inspect', init])
        final_init = c.decode(raw)[0]
        inspect_init(final_init, a, init, volume)
        c.need(final_init['State']['Status'] == 'exited' and final_init['State']['Pid'] == 0
               and final_init['State']['ExitCode'] == 0 and not final_init['State']['OOMKilled'],
               'natural initializer completion before consumer start')
        (output / 'init-after.json').write_bytes(raw)
        try:
            command(DOCKER + ['start', '--attach', token], seconds=300)
            actor_ok = True
        except BaseException as error:
            report['actor_error'] = type(error).__name__ + ': ' + str(error)
        recovery = True  # Export stopped failure evidence despite cancellation; reserve cleanup time.
        # A disconnected/expired CLI is never evidence that its daemon-owned actor stopped.
        if not actor_ok:
            command(DOCKER + ['stop', '--time=1', token], seconds=10, check=False)
        raw, _ = command(DOCKER + ['inspect', token])
        final = c.decode(raw)[0]
        (output / 'actor-after.json').write_bytes(raw)
        c.need(final['State']['Running'] is False and final['State']['Pid'] == 0, 'container stop unproven')
        command(DOCKER + ['cp', token + ':/work/output', '-'], seconds=120, tar=True)
        exported = parser.parse(c.read(output / 'output.tar', 256 * 1024**2))
        export_join(exported)
        destination = output / 'exported'
        destination.mkdir(mode=0o700)
        for name, (body, mode) in exported.items():
            with (destination / name).open('xb') as stream:
                stream.write(body)
            (destination / name).chmod(mode)
        result = c.decode(c.read(destination / 'actor-result.json'))
        c.need(actor_ok and final['State']['ExitCode'] == 0 and not final['State']['OOMKilled']
               and result['status'] == 'RUNNER_COMPLETED' and result['operation_sha256'] == admission_sha
               and result['native_acceptance'] is False and result['XS_acceptance'] is False,
               'actual actor/runner did not complete smoke')
        report['status'] = 'SMOKE_EVIDENCE_EXPORTED_PENDING_INDEPENDENT_READER'
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        cleanup = True
        if volume_attempted:
            # Unique names were absent before creation. Require the exact admission label
            # again before any removal, including an uncertain create/start outcome.
            for kind, name in (('container', token), ('container', init), ('volume', volume)):
                try:
                    raw, code = command(DOCKER + [kind, 'inspect', name], check=False)
                    if code:
                        expected = ('Error response from daemon: get ' + name + ': no such volume') if kind == 'volume' else ('Error: No such container: ' + name)
                        c.need(code == 1 and raw.decode().strip() == expected, 'unexpected owned-resource inspection refusal')
                        report['cleanup'].append(dict(kind=kind, name=name, absent=True))
                        continue
                    row = c.decode(raw)[0]
                    labels = row.get('Labels') if kind == 'volume' else row['Config'].get('Labels')
                    c.need(labels and labels.get('cachy-asahi.admission') == admission_sha,
                           'resource ownership label differs; no removal')
                    selector = name if kind == 'volume' else row['Id']
                    command(DOCKER + [kind, 'rm', *([] if kind == 'volume' else ['--force']), selector])
                    report['cleanup'].append(dict(kind=kind, name=name, removed=True))
                except BaseException as error:
                    report['cleanup'].append(dict(kind=kind, name=name, error=str(error)))
            try:
                raw, _ = command(DOCKER + ['container', 'ls', '--all', '--format', '{{.Names}}'])
                rawv, _ = command(DOCKER + ['volume', 'ls', '--quiet'])
                c.need(not {token, init} & set(raw.decode().splitlines()) and volume not in rawv.decode().splitlines(),
                       'owned resources remain')
                report['owned_resources_absent'] = True
            except BaseException as error:
                report['cleanup_error'] = str(error)
        if not report['owned_resources_absent'] or any('error' in row for row in report['cleanup']) or cancelled.signum:
            report['status'] = 'FAIL'
        for sig, handler in handlers.items():
            runner.signal.signal(sig, handler)
        save()
    return 0 if report['status'] == 'SMOKE_EVIDENCE_EXPORTED_PENDING_INDEPENDENT_READER' else 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=('producer', 'actor'))
    parser.add_argument('--admission-sha256', required=True)
    parser.add_argument('--bundle')
    parser.add_argument('--output')
    args = parser.parse_args()
    if args.role == 'producer':
        c.need(args.bundle is not None and args.output is not None, 'external Root bundle and output required')
        raise SystemExit(producer(args.bundle, args.admission_sha256, args.output))
    c.need(args.bundle is None and args.output is None, 'fixed actor operands')
    raise SystemExit(actor_dispatch(args.admission_sha256))
