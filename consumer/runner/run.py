#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Four-command XS smoke executor INSIDE an already Root-admitted sandbox."""
import sys

if __name__ == '__main__' and (not sys.flags.isolated or sys.flags.optimize):
    raise SystemExit('isolated unoptimized Python required: python3 -I -B run.py')

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import stat
import time

HERE = Path(__file__).resolve().parent
FIXTURE = HERE.parent
PREFLIGHT_SHA = '9e881d5144c49cfa6b4a9abe5bc5172f0d4f00038d94e52426dc88b05473bc0d'
HELPER_SHA = 'eaf9a46630e4fe4ca0a8f94a6dc2de4a881a6ad7e8b4dd0810b3347c0d7038d5'
FILES = {
    'Makefile.PL': (1892, '5706dab03e22e73ad8d91a7e75430263603a2a6560bc01559c2d56121addac0e'),
    'Consumer.xs': (1406, 'bcf502b93bb8b6e8196b977a328c5242c56b1c8adb02062e1037c396b8cee5ee'),
    'lib/CachyAsahi/Perl5423/Consumer.pm': (181, '9b422015bde54964a1b73f35691192f2a036466ed3904c639dbd7952780df64f'),
    't/roundtrip.t': (1908, 'fad9c6668f28f0a584e8b9c56d583d5d763869b8b9dbebbe3e1829435f0fc1ab'),
    'provenance.pl': (9357, 'ae9b547198fdb2313defa89a83589d98f7228c3418b5031c3f9c6fd5088b87eb'),
}
CONTROLLERS = {'cpu.max': '200000 100000', 'memory.max': '4294967296',
               'memory.swap.max': '0', 'pids.max': '256'}
ARTIFACTS = ('Makefile', 'consumer.d', 'Consumer.c', 'Consumer.o',
             'blib/arch/auto/CachyAsahi/Perl5423/Consumer/Consumer.so',
             'xs-configure-provenance.json', 'xs-runtime-provenance.json')
NS = ('user', 'mnt', 'net', 'pid', 'cgroup')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_module(name, path, expected):
    raw = path.read_bytes()
    need(digest(raw) == expected, 'frozen helper/preflight whole-file pin differs')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Execute the checked bytes, avoiding a second source read or cached bytecode.
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def identical(actual, expected):
    need(actual == expected, 'complete preflight plan changed or substituted')


def retired(row):
    return (row.get('retirement') == 'REAPED' and row.get('group_absent') is True
            and row.get('leader_held_until_group_inspection') is True
            and row.get('exit_observed_via_waitpid') is True
            and row.get('ownership_lost') is False and 'cleanup_error' not in row)


def natural_zero(row):
    return (retired(row) and row.get('natural_exit') is True
            and row.get('forced_cleanup') is False and type(row.get('exit')) is int
            and row['exit'] == 0)


class Cancellation:
    def __init__(self):
        self.signum = None

    def signal(self, signum, frame):
        self.signum = signum

    def check(self):
        need(self.signum is None, 'cancelled by signal ' + str(self.signum))


def identity(path):
    s = path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid()
         and stat.S_IMODE(s.st_mode) == 0o700, 'caller-owned private directory required')
    return {'device': s.st_dev, 'inode': s.st_ino, 'owner_uid': s.st_uid}


def sandbox_check(p, sandbox):
    need(platform.system() == 'Linux' and os.getuid() == os.geteuid() != 0
         and os.getgid() == os.getegid(), 'nonroot Linux actor required')
    need((os.getuid(), os.getgid(), platform.machine()) ==
         (sandbox['uid'], sandbox['gid'], sandbox['target_arch']), 'actual actor/architecture differs')
    need({name: os.readlink('/proc/self/ns/' + name) for name in NS} == sandbox['namespaces'],
         'admitted namespace identity changed')
    membership = Path('/proc/self/cgroup').read_text()
    need(membership == sandbox['cgroup_membership'] and membership.startswith('0::/')
         and len(membership.splitlines()) == 1, 'admitted unified cgroup membership changed')
    cg = p.path(sandbox['cgroup_directory'])
    need(cg.is_relative_to(Path('/sys/fs/cgroup')), 'actual cgroup controller directory required')
    need(os.statvfs(cg).f_flag & os.ST_RDONLY, 'read-only cgroup mount required against actor escape')
    info = cg.stat()
    need([info.st_dev, info.st_ino] == sandbox['cgroup_identity'], 'cgroup identity changed')
    # The directory must be the caller's unified membership, not another constrained group.
    need(cg == Path('/sys/fs/cgroup') / membership.strip()[3:].lstrip('/'),
         'controller path differs from actual membership')
    need({name: (cg / name).read_text().strip() for name in CONTROLLERS} == CONTROLLERS,
         'existing CPU/memory/swap/PID bounds differ; runner never creates them')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
    need(all(int(status[key].strip(), 16) == 0 for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb'))
         and status['NoNewPrivs'].strip() == '1',
         'capability-free no-new-privileges actor required')
    need(identity(p.path(sandbox['workspace'])) == sandbox['workspace_identity'],
         'workspace identity changed')
    workspace = p.path(sandbox['workspace'])
    mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    need(any(row[4] == str(workspace) and row[row.index('-') + 1] == 'tmpfs' for row in mounts),
         'workspace must already be its own bounded tmpfs mount')
    fs = os.statvfs(workspace)
    need(fs.f_blocks * fs.f_frsize <= 256 * 1024**2, 'workspace hard filesystem capacity exceeds 256 MiB')
    facts = {name: (cg / name).read_text().strip()
             for name in ('cpu.stat', 'memory.current', 'memory.events', 'pids.current', 'pids.events',
                          'cgroup.procs', 'cgroup.threads')}
    for name in ('cgroup.procs', 'cgroup.threads'):
        facts[name] = sorted(map(int, facts[name].split()))
    return facts


def tree_check(stage, deadline):
    total = count = 0
    for directory, dirs, files in os.walk(stage, followlinks=False):
        need(time.monotonic() < deadline, 'whole-job deadline')
        for name in dirs + files:
            s = (Path(directory) / name).lstat()
            count += 1
            need(count <= 512 and s.st_uid == os.getuid() and
                 (stat.S_ISDIR(s.st_mode) or (stat.S_ISREG(s.st_mode) and s.st_nlink == 1)),
                 'bounded ordinary owned stage required')
            total += s.st_size if stat.S_ISREG(s.st_mode) else 0
            need(total <= 64 * 1024**2, 'stage byte bound')
    return {'entries': count, 'regular_bytes': total}


def execute(plan_path, plan_sha, sandbox_path, sandbox_sha):
    need(sys.flags.isolated and not sys.flags.optimize, 'isolated unoptimized executor required')
    p = load_module('xs_frozen_preflight', FIXTURE / 'preflight.py', PREFLIGHT_SHA)
    owned = load_module('xs_owned_child', HERE / 'helpers/owned_child.py', HELPER_SHA)
    plan_raw, sandbox_raw = p.read(plan_path), p.read(sandbox_path)
    need(p.sha(plan_sha) and p.sha(sandbox_sha) and digest(plan_raw) == plan_sha
         and digest(sandbox_raw) == sandbox_sha, 'external whole-file plan/sandbox pins required')
    plan, sandbox = p.decode(plan_raw), p.decode(sandbox_raw)
    need(sandbox['schema'] == 1 and sandbox['plan_sha256'] == plan_sha
         and sandbox['runner_sha256'] == digest(p.read(HERE / 'run.py'))
         and sandbox['authorization'] == 'ROOT_ADMITTED_FOUR_COMMAND_XS_SMOKE'
         and sandbox['exclusive_scope'] is True, 'external Root sandbox/runner/plan admission required')
    workspace = p.path(sandbox['workspace'])
    stage, evidence = workspace / 'xs-stage', workspace / 'xs-evidence'
    need(plan['cwd'] == str(stage), 'fixed fresh stage in admitted workspace required')
    env = plan['environment']
    admission_raw = p.read(env['CACHY_XS_ADMISSION'])
    need(digest(admission_raw) == env['CACHY_XS_ADMISSION_SHA256'], 'admission pin differs')
    admission = p.decode(admission_raw)
    need(admission['target_arch'] == sandbox['target_arch'] and
         plan['artifact'] == admission['artifact'], 'target/artifact admission differs')
    if admission['artifact']['kind'] == 'native':
        p.pinned(sandbox['accepted_reader_receipt'], 2 * 1024**2)
    else:
        need(sandbox['accepted_reader_receipt'] is None, 'host scope cannot claim native Reader acceptance')
    # Admission operands and the immutable source must survive stage removal.
    external = [FIXTURE, p.path(admission['root']['path']), p.path(plan_path), p.path(sandbox_path),
                p.path(env['CACHY_XS_ADMISSION']), p.path(env['CACHY_XS_INPUTS'])]
    external += [p.path(admission['archive']['path']), p.path(admission['inventory']['path'])]
    external += [p.path(row['path']) for row in admission['metadata'].values()]
    external += [p.path(row['path']) for row in admission['toolchain'].values()]
    if sandbox['accepted_reader_receipt'] is not None:
        external.append(p.path(sandbox['accepted_reader_receipt']['path']))
    need(all(not path.is_relative_to(workspace) and not workspace.is_relative_to(path)
             for path in external), 'all operands/source/prefix/tools must be disjoint from workspace')
    initial = sandbox_check(p, sandbox)
    need(not stage.exists() and not evidence.exists(), 'stage and evidence must both be absent')
    need(shutil.disk_usage(workspace).free >= 192 * 1024**2, '192 MiB free workspace budget required')
    bodies = {name: p.read(FIXTURE / name) for name in FILES}
    need(all((len(raw), digest(raw)) == FILES[name] for name, raw in bodies.items()),
         'exact five-file fixture whole pins required')
    evidence.mkdir(mode=0o700)
    for name, raw in (('plan.json', plan_raw), ('sandbox.json', sandbox_raw),
                      ('admission.json', admission_raw), ('inputs.json', p.read(env['CACHY_XS_INPUTS']))):
        with (evidence / name).open('xb') as stream:
            stream.write(raw)
    report = dict(schema=1, status='FAIL', native_acceptance=False, XS_acceptance=False,
                  qualification='NOT_GRANTED', plan_sha256=plan_sha, sandbox_sha256=sandbox_sha,
                  commands=[], artifacts={}, resource_initial=initial, cleanup={'removed': False})
    started = time.monotonic()
    deadline = started + 240
    command_deadline = deadline - 30
    cancel = Cancellation()
    handlers = {sig: signal.signal(sig, cancel.signal) for sig in (signal.SIGINT, signal.SIGTERM)}
    stage_id = None
    old_fsize = resource.getrlimit(resource.RLIMIT_FSIZE)
    cap = 16 * 1024**2
    soft = cap if old_fsize[0] == resource.RLIM_INFINITY else min(cap, old_fsize[0])
    last_scan = 0.0

    def tick():
        nonlocal last_scan
        cancel.check()
        need(time.monotonic() < command_deadline, 'whole command budget exhausted')
        sandbox_check(p, sandbox)
        need(identity(stage) == stage_id, 'stage identity changed')
        if time.monotonic() - last_scan >= .1:
            tree_check(stage, command_deadline)
            last_scan = time.monotonic()

    try:
        stage.mkdir(mode=0o700)
        stage_id = identity(stage)
        for name, raw in bodies.items():
            target = stage / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(raw)
            target.chmod(0o600)
        actual = p.plan(env['CACHY_XS_ADMISSION'], env['CACHY_XS_ADMISSION_SHA256'],
                        env['CACHY_XS_INPUTS'], env['CACHY_XS_INPUTS_SHA256'], stage)
        identical(p.encode(actual), plan_raw)
        # A soft file bound is inherited; never relax an existing tighter bound or hard limit.
        resource.setrlimit(resource.RLIMIT_FSIZE, (soft, old_fsize[1]))
        for number, (argv, timeout) in enumerate(zip(actual['commands'], (30, 90, 30, 30)), 1):
            tick()
            row = {'number': number, 'argv': argv, 'environment_sha256': digest(p.encode(actual['environment'])),
                   'lifecycle': {}}
            report['commands'].append(row)
            outpath, errpath = evidence / f'{number}.stdout', evidence / f'{number}.stderr'
            try:
                with outpath.open('xb') as stdout, errpath.open('xb') as stderr:
                    owned.run(argv, timeout=min(timeout, command_deadline - time.monotonic()),
                              cwd=stage, env=actual['environment'], stdout=stdout, stderr=stderr,
                              stdout_limit=4 * 1024**2, stderr_limit=4 * 1024**2,
                              lifecycle=row['lifecycle'], on_tick=tick, allowed_uids={os.getuid()})
            finally:
                row['launched'] = type(row['lifecycle'].get('pid')) is int
                for label, path in (('stdout', outpath), ('stderr', errpath)):
                    if path.exists():
                        row[label] = dict(path=path.name, **p.pin(p.read(path, 16 * 1024**2)))
            need(natural_zero(row['lifecycle']), 'command did not naturally exit zero with owned retirement')
            after = sandbox_check(p, sandbox)
            need(all(after[key] == initial[key] for key in ('cgroup.procs', 'cgroup.threads')),
                 'exclusive cgroup still contains additional or substituted actors')
        tick()
        need(all((stage / name).exists() for name in ARTIFACTS), 'actual generated outputs missing')
        report['status'] = 'FOUR_SMOKE_COMMANDS_COMPLETED'
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        resource.setrlimit(resource.RLIMIT_FSIZE, old_fsize)
        try:
            report['resource_final'] = sandbox_check(p, sandbox)
            need(all(report['resource_final'][key] == initial[key]
                     for key in ('memory.events', 'pids.events')), 'memory/PID resource event changed')
            # No filesystem cleanup while any launched child's fate is uncertain.
            need(all('pid' not in row['lifecycle'] or retired(row['lifecycle'])
                     for row in report['commands']), 'uncertain child retirement; stage retained')
            need(all(report['resource_final'][key] == initial[key]
                     for key in ('cgroup.procs', 'cgroup.threads')),
                 'additional or substituted cgroup actors; stage retained')
            if stage_id is not None:
                need(identity(stage) == stage_id, 'stage identity changed; stage retained')
                report['stage_final'] = tree_check(stage, deadline)
                # Preserve existing generated outputs even after a failed command. Never synthesize them.
                for name in ARTIFACTS:
                    need(time.monotonic() < deadline, 'artifact export deadline')
                    if not (stage / name).exists():
                        continue
                    raw = p.read(stage / name, 16 * 1024**2)
                    target = evidence / 'generated' / name
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with target.open('xb') as stream:
                        stream.write(raw)
                    report['artifacts'][name] = dict(path=str(target.relative_to(evidence)), **p.pin(raw))
                # Retain raw provenance verbatim above; also expose actual loaded paths and Config.
                report['provenance'] = {}
                for label, path in (('configure', stage / 'xs-configure-provenance.json'),
                                    ('runtime', stage / 'xs-runtime-provenance.json'),
                                    ('standalone', evidence / '4.stdout')):
                    if path.exists() and path.stat().st_size:
                        report['provenance'][label] = p.decode(p.read(path))
                need(shutil.rmtree.avoids_symlink_attacks, 'descriptor-anchored rmtree required')
                shutil.rmtree(stage)
                need(not stage.exists(), 'owned stage removal failed')
                report['cleanup'] = {'removed': True, 'stage_identity': stage_id}
        except BaseException as error:
            report['status'] = 'FAIL'
            report['cleanup']['error'] = type(error).__name__ + ': ' + str(error)
        report['elapsed_seconds'] = time.monotonic() - started
        if cancel.signum is not None or report['elapsed_seconds'] >= 240:
            report['status'] = 'FAIL'
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        with (evidence / 'receipt.json').open('xb') as stream:
            stream.write(p.encode(report))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    for key in ('plan', 'plan-sha256', 'sandbox', 'sandbox-sha256'):
        parser.add_argument('--' + key, required=True)
    args = parser.parse_args()
    try:
        result = execute(args.plan, args.plan_sha256, args.sandbox, args.sandbox_sha256)
        print(json.dumps({'status': result['status'], 'native_acceptance': False, 'XS_acceptance': False}))
        sys.exit(0 if result['status'] == 'FOUR_SMOKE_COMMANDS_COMPLETED' else 1)
    except (ValueError, KeyError, OSError, TypeError) as error:
        print('RUNNER_ERROR (inspect any xs-evidence receipt): ' + str(error), file=sys.stderr)
        sys.exit(2)
