# SPDX-License-Identifier: MIT
"""Authenticate and own one separately admitted Q3 updater guest."""

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import resource
import runpy
import signal
import stat
import subprocess
import sys
from tempfile import TemporaryFile
import time
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
Q3 = HERE.parents[2] / 'scripts/integration/qt612_md4c_compile/prepare.py'
P = SimpleNamespace(**runpy.run_path(str(Q3)))
IMAGE = 'sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a'
DOCKER = Path('/home/gabe/bin/docker')
DOCKER_PIN = {'bytes': 44217952, 'sha256': 'e966e0e6ea215b74fdbee17fbe7ed8bff15b65930bfc8e131652ceae4ed0210e'}
INPUTS = {'Image': 9019400, 'boot.raw': 1611661312, 'scratch.raw': 17179869184, 'media.raw': 134217728}
SERIAL_CAP = 1 << 20
OVERLAY_CAP = 1 << 30
ATTACH_SECONDS = 1300
HEXSHA = re.compile('[0-9a-f]{64}')
CLAIM_LABEL = 'org.cachy-asahi.updater-q3'
SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
ACTOR = r'''umask 077
ulimit -c 0
ulimit -f 1048576
printf '%s  %s\n' 2139b2c8d5a9f28dbef2c5cdb663ce842648105fa76720ec691f8f5cddc8b002 /usr/bin/qemu-img \
   6f16cea44da813a65a1076886f63687350a0173e188873ba227dcc06f5c16b27 /usr/bin/qemu-system-aarch64 |
   sha256sum --check --strict --quiet
[[ ! -e /out/overlay.qcow2 ]]
/usr/bin/qemu-img create -q -f qcow2 -F raw -b /inputs/scratch.raw /out/overlay.qcow2
inspect() { /usr/bin/qemu-img info -f qcow2 --backing-chain --output=json /out/overlay.qcow2; }
inspect > /out/overlay-before.json
stat -c %s /out/overlay.qcow2 > /out/overlay-before.size
stamp=$(date -u +%s)
printf '%s\n' "$stamp" > /out/host-utc
argv=()
for word in "$@"; do argv+=("${word//\{HOST_UTC\}/$stamp}"); done
set +e
timeout --signal=TERM --kill-after=10s 1270s "${argv[@]}"
status=$?
set -e
inspect > /out/overlay-after.json
exit "$status"
'''


def need(value, reason):
    if not value:
        raise ValueError(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def save(path, value):
    P.new(path, encoded(value))


def load(path, digest):
    need(type(digest) is str and HEXSHA.fullmatch(digest), 'external digest required')
    return P.strict_json(P.read(path, digest))


def directory(path):
    need(path.is_absolute() and path.resolve(strict=True) == path
         and re.fullmatch(r'/[A-Za-z0-9._/-]+', str(path)), 'ordinary literal directory required')
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() > 0 and not info.st_mode & 0o022,
         'private ordinary owner directory required')


def verify_pin(pin, size):
    need(type(pin) is dict and set(pin) == {'bytes', 'sha256'} and pin['bytes'] == size
         and type(pin['bytes']) is int and type(pin['sha256']) is str and HEXSHA.fullmatch(pin['sha256']),
         'exact input pin required')


def argv_template(nonce, case):
    append = P.boot_cmdline(nonce, '/updater-q3-v2/guest-init.sh')
    append += (f' cachy_updater16k_nonce={nonce} cachy_updater16k_case={case}'
               ' cachy_updater16k={PLAN_SHA256} arm16k_rtc_host_epoch={HOST_UTC}')
    return P.vm_argv('/inputs/Image', append, 'updater-q3-' + nonce,
                     (('boot', 'file=/inputs/boot.raw,format=raw,readonly=on'),
                      ('scratch', 'file=/out/overlay.qcow2,format=qcow2,readonly=off,discard=ignore'),
                      ('input', 'file=/inputs/media.raw,format=raw,readonly=on')))


def preflight(args, *, rehash=True):
    for path in (args.packet, args.media):
        directory(path)
    need(not args.packet.is_relative_to(args.media) and not args.media.is_relative_to(args.packet),
         'media and preparation must be disjoint')
    prep = load(args.packet / 'PLAN.UNISSUED.json', args.preparation_sha256)
    need(prep['kind'] == 'UPDATER_Q3_PREPARATION_UNISSUED' and prep['authority'] is None
         and prep['base_inventory'] == 356 and prep['target_inventory'] == 362, 'exact unissued preparation')
    nonce, case = prep['nonce'], prep['case']
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce) and nonce[:8] != '00000000'
         and case in ('update', 'signature-refusal') and prep['qemu_argv_template'] == argv_template(nonce, case),
         'exact finite case and guest argv required')
    need(prep['input_ext4'] == {'bytes': INPUTS['media.raw'], 'label': 'UPDATER16K', 'uuid': P.result_uuid(nonce)},
         'wrong media device identity')
    media = load(args.media / 'media.json', args.media_manifest_sha256)
    need(media['kind'] == 'UPDATER_Q3_MEDIA_V1' and media['preparation_sha256'] == args.preparation_sha256
         and media['case'] == case, 'media preparation or case differs')
    verify_pin(media['media'], INPUTS['media.raw'])
    files = {name: (args.packet / 'inputs' / name, prep['inputs'][name]) for name in INPUTS if name != 'media.raw'}
    scratch, scratch_pin = files['scratch.raw']
    if not os.path.lexists(scratch):
        original = prep['originals']['scratch.raw']
        need(set(original) == {'path', 'bytes', 'sha256'} and
             {key: original[key] for key in scratch_pin} == scratch_pin, 'shared backing pin differs')
        scratch = Path(original['path'])
        directory(scratch.parent)
        need(scratch.name == 'scratch.raw', 'shared backing leaf differs')
        files['scratch.raw'] = scratch, scratch_pin
    files['media.raw'] = args.media / 'media.raw', media['media']
    for name, (path, pin) in files.items():
        verify_pin(pin, INPUTS[name])
        info = path.lstat()
        need(info.st_uid == os.getuid() and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o444 and info.st_size == pin['bytes'], 'exact sealed input required')
        if rehash:
            P.match(path, pin)
    verify_pin(media['plan'], media['plan']['bytes'])
    need(0 < media['plan']['bytes'] <= 16384, 'guest plan exceeds cap')
    guest_plan = load(args.media / 'plan.json', media['plan']['sha256'])
    need((args.media / 'plan.json').stat().st_size == media['plan']['bytes'] and guest_plan['case'] == case
         and type(guest_plan['valid_from']) is int and type(guest_plan['expires']) is int
         and 0 < guest_plan['expires'] - guest_plan['valid_from'] <= 86400, 'exact finite guest plan required')
    return prep, media, guest_plan, files


def binding(args, prep, media):
    return {'kind': 'UPDATER_Q3_ADMISSION_V1', 'nonce': prep['nonce'], 'case': prep['case'],
            'preparation_sha256': args.preparation_sha256, 'media_manifest_sha256': args.media_manifest_sha256,
            'media_sha256': media['media']['sha256'], 'guest_plan_sha256': media['plan']['sha256'],
            'owner_sha256': P.observe(Path(__file__).resolve(), 128 << 10)[1]['sha256'],
            'output': str(args.output), 'runner_image': IMAGE, 'attach_seconds': ATTACH_SECONDS,
            'serial_cap': SERIAL_CAP, 'overlay_cap': OVERLAY_CAP}


def admit(args, prep, media, guest_plan, now):
    expected = binding(args, prep, media)
    row = load(args.admission, args.admission_sha256)
    start, expires = row.pop('valid_from'), row.pop('expires')
    need(row == expected and type(start) is int and type(expires) is int
         and guest_plan['valid_from'] <= start <= now and now + ATTACH_SECONDS + 30 < expires <= guest_plan['expires']
         and expires - start <= 7200, 'exact current owner admission required')
    return expires


def output_path(args):
    out = args.output
    directory(out.parent)
    need(out.is_absolute() and out.resolve() == out and not os.path.lexists(out)
         and re.fullmatch(r'/[A-Za-z0-9._/-]+', str(out)), 'fresh owned attempt path required')
    for source in (args.packet, args.media):
        need(not out.is_relative_to(source) and not source.is_relative_to(out), 'disjoint attempt required')


def capacity(directory):
    vfs = os.statvfs(directory)
    mem = next(int(row.split()[1]) for row in Path('/proc/meminfo').read_text().splitlines()
               if row.startswith('MemAvailable:'))
    need(vfs.f_bavail * vfs.f_frsize >= 4 << 30 and mem >= 8 * 1024**2
         and len(os.sched_getaffinity(0)) >= 4, 'insufficient isolated guest capacity')


def resource_limit():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (SERIAL_CAP, SERIAL_CAP))


class Docker:
    def __init__(self, attempt):
        self.socket = Path(f'/run/user/{os.getuid()}/docker.sock')
        self.identity = self.endpoint_identity()
        self.cli_identity = P.identity(DOCKER.lstat())
        P.match(DOCKER, DOCKER_PIN)
        self.env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC', 'HOME': str(attempt),
                    'DOCKER_CONFIG': str(attempt / 'docker-config')}
        (attempt / 'docker-config').mkdir(mode=0o700)
        self.check()

    def endpoint_identity(self):
        info = self.socket.lstat()
        need(self.socket.resolve(strict=True) == self.socket and stat.S_ISSOCK(info.st_mode)
             and info.st_uid == os.getuid(), 'exact ordinary rootless daemon socket required')
        return info.st_dev, info.st_ino, info.st_uid, info.st_mode

    def check(self):
        need(self.endpoint_identity() == self.identity and P.identity(DOCKER.lstat()) == self.cli_identity,
             'runner endpoint or client changed')

    def invoke(self, args, out, err, seconds):
        self.check()
        proc = subprocess.run([str(DOCKER), '--host', 'unix://' + str(self.socket), *args],
                              env=self.env, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                              timeout=seconds, preexec_fn=resource_limit)
        self.check()
        return proc.returncode

    def command(self, *args, seconds=30):
        with TemporaryFile() as out, TemporaryFile() as err:
            rc = self.invoke(args, out, err, seconds)
            out.seek(0)
            body = out.read(SERIAL_CAP + 1)
            need(rc == 0 and len(body) <= SERIAL_CAP, 'bounded owned Docker command failed')
            return body

    def runtime(self):
        options = P.strict_json(self.command('info', '--format', '{{json .SecurityOptions}}'))
        need(type(options) is list and 'name=rootless' in options, 'selected daemon is not rootless')
        actual = self.command('image', 'inspect', IMAGE, '--format', '{{.Id}} {{.Architecture}}').decode().strip()
        need(actual == IMAGE + ' amd64', 'exact local runner image required')

    def attach(self, attempt, cid):
        with (attempt / 'serial.log').open('xb') as out, (attempt / 'runner.stderr').open('xb') as err:
            return self.invoke(('container', 'start', '--attach', cid), out, err, ATTACH_SECONDS)


def container_argv(out, name, nonce, argv):
    role = ['-euc', ACTOR, 'updater-q3', *argv]
    mounts = ((out / 'inputs', '/inputs', False), (out / 'work', '/out', True))
    args = ['container', 'create', '--name', name, '--cidfile', str(out / 'run.cid'),
            '--pull=never', '--init=false', '--read-only', '--network=none', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--cpus=4', '--memory=6g', '--memory-swap=6g',
            '--pids-limit=64', '--log-driver=none', '--label', CLAIM_LABEL + '=' + nonce]
    for source, target, writable in mounts:
        args += ['--mount', f'type=bind,source={source},target={target}' + ('' if writable else ',readonly')]
    return [*args, '--entrypoint', '/usr/bin/bash', IMAGE, *role]


def inspect_scope(raw, cid, name, out, nonce, argv):
    rows = P.strict_json(raw)
    need(type(rows) is list and len(rows) == 1, 'one exact container inspect required')
    row, = rows
    config, host, mounts = (row[k] for k in ('Config', 'HostConfig', 'Mounts'))
    need(row['Id'] == cid and row['Name'] == '/' + name and row['Image'] == IMAGE
         and row['Path'] == '/usr/bin/bash' and row['Args'] == ['-euc', ACTOR, 'updater-q3', *argv]
         and config['Labels'][CLAIM_LABEL] == nonce, 'owned container identity differs')
    need(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True and host['Privileged'] is False
         and host['AutoRemove'] is False and host['Init'] is False and host['CapDrop'] == ['ALL']
         and host['SecurityOpt'] in (['no-new-privileges'], ['no-new-privileges=true'])
         and host['Memory'] == host['MemorySwap'] == 6 << 30 and host['NanoCpus'] == 4_000_000_000
         and host['PidsLimit'] == 64 and host['LogConfig']['Type'] == 'none'
         and not any(host.get(key) for key in ('CapAdd', 'Devices', 'DeviceRequests', 'DeviceCgroupRules',
                                               'PortBindings', 'VolumesFrom', 'Tmpfs')),
         'owned container limits differ')
    need(len(mounts) == 2 and all(m['Type'] == 'bind' and m['Propagation'] == 'rprivate'
                                for m in mounts) and
         {(m['Source'], m['Destination'], m['RW']) for m in mounts}
         == {(str(out / 'inputs'), '/inputs', False), (str(out / 'work'), '/out', True)},
         'owned readonly inputs and isolated output mounts required')
    return row['State']


def overlay_pin(work):
    initial = P.observe(work / 'overlay-before.size', 16, collect=True)[0].decode().strip()
    need(re.fullmatch('[1-9][0-9]{0,6}', initial), 'bounded initial overlay size required')
    P.validate_empty_overlay(P.observe(work / 'overlay-before.json', 16 << 10, collect=True)[0], int(initial))
    raw = P.observe(work / 'overlay-after.json', 16 << 10, collect=True)[0]
    records = P.strict_json(raw)
    need(type(records) is list and len(records) == 2, 'exact two-node final backing chain required')
    child, raw_base = records
    need(child['filename'] == '/out/overlay.qcow2' and child['format'] == 'qcow2'
         and child['backing-filename-format'] == 'raw' and child['full-backing-filename'] == '/inputs/scratch.raw'
         and raw_base['filename'] == '/inputs/scratch.raw' and raw_base['format'] == 'raw'
         and all(x['virtual-size'] == INPUTS['scratch.raw'] and x['dirty-flag'] is False for x in records)
         and child['format-specific']['data']['corrupt'] is False, 'dirty or drifted overlay backing')
    overlay = work / 'overlay.qcow2'
    info = overlay.lstat()
    need(info.st_uid == os.getuid() and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
         'overlay must be exact private output')
    pin = P.observe(overlay, OVERLAY_CAP)[1]
    need(pin['bytes'] >= int(initial), 'owned overlay shrank')
    return pin, P.identity(info)


def execute(args, prep, media, guest_plan, files, *, docker_factory=Docker):
    output_path(args)
    admit(args, prep, media, guest_plan, int(time.time()))
    out, nonce = args.output, prep['nonce']
    capacity(out.parent)
    out.mkdir(mode=0o700)
    for leaf in ('inputs', 'work'):
        (out / leaf).mkdir(mode=0o700)
    for name, (source, pin) in files.items():
        target = out / 'inputs' / name
        P.clone(source, target)
        target.chmod(0o444)
        P.match(target, pin)
    P.new(out / 'admission.checked.json', P.read(args.admission, args.admission_sha256))
    docker = docker_factory(out)
    docker.runtime()
    capacity(out.parent)
    admit(args, prep, media, guest_plan, int(time.time()))
    name = 'caa-updater-q3-' + nonce
    argv = [word.replace('{PLAN_SHA256}', media['plan']['sha256']) for word in prep['qemu_argv_template']]
    def inspect(cid):
        body = docker.command('container', 'inspect', cid)
        return body, inspect_scope(body, cid, name, out, nonce, argv)

    def named():
        return docker.command('container', 'ls', '-a', '--no-trunc', '--filter', f'name=^/{name}$',
                              '--format', '{{.ID}}')

    need(named() == b'', 'claimed actor name already exists')
    def interrupted(_number, _frame):
        raise InterruptedError('owned guest interrupted')

    previous = {sig: signal.signal(sig, interrupted) for sig in SIGNALS}
    cid_path = out / 'run.cid'
    clean = natural = False
    launched = time.monotonic()
    try:
        created = docker.command(*container_argv(out, name, nonce, argv)).decode().strip()
        cid = P.observe(cid_path, 66, collect=True)[0].decode().strip()
        need(HEXSHA.fullmatch(cid) and created == cid, 'created container id differs')
        raw, state = inspect(cid)
        need(state['Status'] == 'created' and state['Pid'] == 0 and state['Running'] is False,
             'fresh created state required')
        P.new(out / 'created.inspect.json', raw)
        rc = docker.attach(out, cid)
        raw, state = inspect(cid)
        P.new(out / 'exited.inspect.json', raw)
        natural = (rc == state['ExitCode'] == 0 and state['Status'] == 'exited' and state['Pid'] == 0
                   and state['Running'] is state['OOMKilled'] is False and state['Error'] == '')
        need(natural, 'natural guest exit required; owned evidence retained')
    finally:
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        try:
            if not os.path.lexists(cid_path):
                discovered = named()
                if discovered:
                    discovered_cid = discovered.decode().strip()
                    need(HEXSHA.fullmatch(discovered_cid), 'unrecorded actor identity ambiguous')
                    inspect(discovered_cid)
                    P.new(cid_path, (discovered_cid + '\n').encode())
            if os.path.lexists(cid_path):
                cid = P.observe(cid_path, 66, collect=True)[0].decode().strip()
                need(HEXSHA.fullmatch(cid), 'owned cleanup id malformed')
                listing = lambda: docker.command('container', 'ls', '-a', '--no-trunc',
                                                  '--filter', 'id=' + cid, '--format', '{{.ID}}')
                observed = listing()
                need(observed in (b'', (cid + '\n').encode()), 'ambiguous owned container census')
                if observed:
                    _, state = inspect(cid)
                    if state['Running']:
                        docker.command('container', 'stop', '--time', '10', cid)
                    docker.command('container', 'rm', cid)
                for index in (1, 2):
                    need(listing() == b'', 'owned container retirement unproved')
                    P.new(out / f'absence-{index}', b'')
                clean = True
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    need(clean and natural, 'owned guest retirement unproved')
    child_seconds = max(1, round(time.monotonic() - launched))
    need(child_seconds <= ATTACH_SECONDS, 'owned run exceeded time bound')
    serial = P.observe(out / 'serial.log', SERIAL_CAP)[1]
    work = out / 'work'
    overlay, identity = overlay_pin(work)
    start = P.observe(work / 'host-utc', 16, collect=True)[0].decode().strip()
    need(re.fullmatch('[1-9][0-9]{9}', start), 'missing launch UTC')
    host_utc = int(start)
    time_from = lambda key: datetime.fromisoformat(state[key].replace('Z', '+00:00')).timestamp()
    need(int(time_from('StartedAt')) <= host_utc <= int(time_from('FinishedAt'))
         and guest_plan['valid_from'] <= host_utc < guest_plan['expires'], 'actual launch UTC outside owner bounds')
    for name, (source, pin) in files.items():
        copied = out / 'inputs' / name
        observed = P.identity(copied.lstat())
        P.match(copied, pin)
        P.match(source, pin)
        need(P.identity(copied.lstat()) == observed, 'input clone identity changed')
        copied.unlink()
    (out / 'inputs').rmdir()
    path = work / 'overlay.qcow2'
    need(P.identity(path.lstat()) == identity, 'retirement target changed')
    path.unlink()
    need(not os.path.lexists(path), 'owned overlay retirement unproved')
    evidence = {}
    for leaf in ('admission.checked.json', 'created.inspect.json', 'exited.inspect.json', 'run.cid',
                 'absence-1', 'absence-2', 'work/host-utc', 'work/overlay-before.json',
                 'work/overlay-before.size', 'work/overlay-after.json', 'runner.stderr'):
        path = out / leaf
        evidence[leaf] = (P.observe(path, SERIAL_CAP)[1] if path.lstat().st_size
                          else {'bytes': 0, 'sha256': P.sha(b'')})
    row = {'kind': 'UPDATER_Q3_OWNER_V1', 'nonce': nonce, 'case': prep['case'],
           'preparation_sha256': args.preparation_sha256, 'media_sha256': media['media']['sha256'],
           'admission_sha256': args.admission_sha256, 'guest_plan_sha256': media['plan']['sha256'],
           'container_id': cid, 'boot': files['boot.raw'][1], 'kernel': files['Image'][1],
           'scratch': files['scratch.raw'][1], 'serial': serial, 'overlay': overlay,
           'qemu_argv': [word.replace('{HOST_UTC}', start) for word in argv],
           'host_utc': host_utc, 'elapsed_seconds': child_seconds, 'natural_exit': True,
           'container_absent_twice': True, 'overlay_retired': True, 'retirement': 'PASS', 'evidence': evidence}
    save(out / 'owner.json', row)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('preflight', 'run'))
    for name in ('packet', 'media', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('preparation-sha256', 'media-manifest-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--admission', type=Path)
    parser.add_argument('--admission-sha256')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        ready = args.admission is not None and args.admission_sha256 is not None
        if args.mode == 'run':
            need(ready, 'separately issued one-shot admission required')
        else:
            need(args.admission is None and args.admission_sha256 is None, 'passive preflight cannot take admission')
        output_path(args)
        prep, media, guest_plan, files = preflight(args)
        if args.mode == 'run':
            result = execute(args, prep, media, guest_plan, files)
        else:
            result = {'status': 'UNISSUED', 'binding': binding(args, prep, media),
                      'valid_from': None, 'expires': None}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'HOLD', 'reason': str(error)[:300]}), file=sys.stderr)
        return 1
    print(encoded(result).decode(), end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
