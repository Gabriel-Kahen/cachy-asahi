#!/usr/bin/python3 -IB
# SPDX-License-Identifier: MIT
"""Actual TEST-signed pacman journey in a guarded copied root, never on the host."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('audio_candidate_common', HERE / 'common.py')
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
spec = importlib.util.spec_from_file_location('audio_candidate_host_contract', HERE / 'host_contract.py')
H = importlib.util.module_from_spec(spec); spec.loader.exec_module(H)
NAME = 'cachy-asahi-audio-sources'
STANDARD_DEVICE_MOUNTS = {'/dev/null': (1, 3), '/dev/zero': (1, 5), '/dev/full': (1, 7),
                          '/dev/random': (1, 8), '/dev/urandom': (1, 9), '/dev/tty': (5, 0)}


def mappings(raw, outside):
    rows = [tuple(map(int, row.split())) for row in raw.splitlines()]
    C.need(1 <= len(rows) <= 16 and all(len(row) == 3 and min(row) >= 0 and row[2] > 0 for row in rows), 'ROOTLESS_ID_MAP_FORMAT')
    C.need(rows[0] == (0, outside, 1) and outside > 0, 'ROOTLESS_ID_MAP_REQUIRED')
    return rows


def observe(repository, lifecycle):
    """Bounded passive failure context; does not accept or alter a guard fact."""
    def proc(name, maximum):
        with (Path('/proc/self') / name).open('rb') as stream:
            raw = stream.read(maximum + 1)
        C.need(len(raw) <= maximum, 'PASSIVE_PROC_BYTE_LIMIT')
        return raw.decode('ascii')
    table = repository.mounts(proc('mountinfo', 256 * 1024))
    selected = {}
    for path in ('/', '/inputs', '/runner', '/out', '/scratch', '/test-home', '/alpm', *STANDARD_DEVICE_MOUNTS,
                 *sorted(repository.MASKED_NULL)):
        if path in table:
            row = table[path]
            selected[path] = dict(fs=row['fs'], options=sorted(row['options']),
                                 root_kind='ROOT' if row['root'] == '/' else 'DEVICE_LEAF' if row['root'] in
                                 {path, '/' + Path(path).name} else 'NULL_DEVICE_LEAF' if row['root'] == '/null'
                                 else 'OTHER_ROOT_REDACTED')
    info = Path('/dev/zero').lstat()
    status = proc('status', 65536)
    status_rows = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
    masks = {}
    for path in sorted(repository.MASKED_NULL):
        if path in table:
            node = Path(path).lstat()
            masks[path] = dict(is_character=stat.S_ISCHR(node.st_mode), is_symlink=stat.S_ISLNK(node.st_mode),
                              major=os.major(node.st_rdev), minor=os.minor(node.st_rdev))
    return dict(architecture=platform.machine(), uid=os.geteuid(),
        privileges=lifecycle.privilege_status(status),
        seccomp={key: status_rows.get(key, '').strip() for key in ('Seccomp', 'Seccomp_filters')},
        selected_mounts=selected,
        protected_mask_nodes=masks,
        dev_zero=dict(is_character=stat.S_ISCHR(info.st_mode), major=os.major(info.st_rdev), minor=os.minor(info.st_rdev)),
        uid_map=proc('uid_map', 4096), gid_map=proc('gid_map', 4096))


def guard(r, contract, initial=False):
    C.need(platform.machine() == 'x86_64' and os.geteuid() == 0, 'EXPLICIT_HOST_X86_CONTAINER_ONLY')
    marker = Path('/.dockerenv')
    C.need(marker.is_file() and not marker.is_symlink() and marker.stat().st_uid == 0, 'REAL_DOCKER_MARKER_REQUIRED')
    C.need(os.environ.get('CACHY_ASAHI_AUDIO_CANDIDATE') == contract['nonce']
           and os.environ.get('CACHY_ASAHI_IMAGE_ID') == contract['image_id'], 'CONTAINER_CONTRACT_IDENTITY')
    C.need(os.environ.get('TMPDIR') == '/scratch', 'PARENT_PRIVATE_DATA_TMP_REQUIRED')
    observed = r.mounts(Path('/proc/self/mountinfo').read_text())
    host = C.host_contract(HERE)
    admitted_roles = H.mounts(r, observed, contract['engine_host_config'], host)
    H.volumes(host, contract['nonce'], initial=initial)
    H.runtime_metadata(r)
    status = Path('/proc/self/status').read_text()
    privileges = r.privileges(status)
    rows = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
    C.need(rows.get('Seccomp', '').strip() == '2' and rows.get('Seccomp_filters', '').strip().isdigit()
           and int(rows['Seccomp_filters']) > 0, 'ACTIVE_SECCOMP_FILTER_REQUIRED')
    C.need(sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo'], 'NETWORK_NAMESPACE_REQUIRED')
    C.need(not any(Path(p).exists() for p in ('/run/docker.sock', '/var/run/docker.sock')), 'DOCKER_SOCKET_REFUSED')
    uid = mappings(Path('/proc/self/uid_map').read_text(), contract['host_uid'])
    gid = mappings(Path('/proc/self/gid_map').read_text(), contract['host_gid'])
    C.need(not Path(contract['producer_checkout']).exists() and not Path('/work/scripts').exists(), 'PRODUCER_CHECKOUT_EXPOSED')
    if initial:
        r.validate_exposure(r.exposed_nodes())
        C.need(all(not any(Path(p).iterdir()) for p in ('/scratch', '/test-home', '/out')), 'FRESH_PRIVATE_MOUNTS_REQUIRED')
    return dict(architecture='x86_64', uid_map=uid, gid_map=gid, privileges=privileges,
                mounts={p: dict(fs=v['fs'], options=sorted(v['options'])) for p, v in observed.items()},
                network_interfaces=['lo'], producer_checkout_hidden=True, host_admitted_roles=admitted_roles)


class Journey:
    def __init__(self, profile, contract, lifecycle, repository):
        self.profile, self.contract, self.l, self.r = profile, contract, lifecycle, repository
        self.report = dict(schema=1, scope='host-x86_64-rootless-docker-copied-ALPM-root', status='FAIL',
            commands=[], checks=[], package_installation='NOT_RUN', reinstallation='NOT_RUN', removal='NOT_RUN',
            native_arm='NOT_RUN', physical_m2='NOT_RUN', complete_corresponding_source_accepted=False,
            legal_acceptance=False, release='NOT_ADMITTED', publication='NOT_RUN')
        self.base = Path('/alpm/system')
        self.keydirs = []

    def command(self, label, argv, allowed=(0,), data=None, clean=False):
        guard(self.r, self.contract)
        C.need(re.fullmatch('[a-z0-9-]{1,64}', label), 'COMMAND_LABEL')
        env = dict(PATH='/usr/bin:/bin', HOME='/test-home', TMPDIR='/scratch', LC_ALL='C.UTF-8',
                   TZ='UTC', PYTHONDONTWRITEBYTECODE='1')
        result = self.l.bounded_process(argv, timeout=60, stdout_limit=2 * 1024**2,
                                        stderr_limit=256 * 1024, stdin=data, env=env)
        number = len(self.report['commands']); name = f'{number:03d}-{label}'
        for stream in ('stdout', 'stderr'):
            path = Path('/out') / (name + '-' + stream + '.log'); path.write_bytes(result[stream]); path.chmod(0o600)
        row = {k: v for k, v in result.items() if k not in ('stdout', 'stderr')}
        row.update(label=label, argv=list(map(str, argv)), expected=list(allowed),
                   stdout_sha256=C.digest(result['stdout']), stderr_sha256=C.digest(result['stderr']))
        self.report['commands'].append(row)
        C.need(result['reason'] == 'exit' and result['returncode'] in allowed and result['cleanup']['reaped'], 'BOUNDED_COMMAND_REFUSED:' + label)
        if clean:
            C.need(not re.search(rb'^(?:error\s*:|could not change (?:the root directory|directory)\b)',
                                result['stdout'] + result['stderr'], re.I | re.M), 'ANCILLARY_TRANSACTION_ERROR:' + label)
        return result['stdout'], result['stderr'], result['returncode']

    def check(self, name, ok):
        C.need(ok, name); self.report['checks'].append(name)

    def pacman(self, label, options, allowed=(0,)):
        C.need(C.digest(C.read(Path('/scratch/pacman.conf'))) == self.report['actual_pacman_config']['sha256'],
               'ACTUAL_LOCAL_PACMAN_CONFIG_CHANGED')
        return self.command(label, ['pacman', '--config', '/scratch/pacman.conf', '--root', str(self.base),
            '--dbpath', str(self.base / 'var/lib/pacman'), '--cachedir', '/scratch/cache',
            '--gpgdir', '/test-home/verifier', '--hookdir', '/scratch/masked-hooks',
            '--logfile', '/out/pacman.log', '--noconfirm', '--color', 'never', *options],
            allowed, clean=allowed == (0,))

    def inventory(self, label):
        stdout, stderr, _ = self.pacman(label, ['-Q'])
        C.need(not stderr, 'INVENTORY_DIAGNOSTIC')
        return self.r.package_inventory(stdout.decode())

    def installed(self, phase, baseline):
        self.check(phase + '-exact-inventory', self.inventory(phase + '-inventory') == {**baseline, NAME: '0.1.0-1'})
        self.pacman(phase + '-file-check', ['-Qkk', NAME]); self.pacman(phase + '-database-check', ['-Dk'])
        for name, pin in self.profile['payload'].items():
            path = self.base / name; info = path.lstat(); raw = C.read(path)
            self.check(phase + '-payload-' + str(len(self.report['checks'])),
                stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == pin['mode']
                and len(raw) == pin['bytes'] and C.digest(raw) == pin['sha256'])
        listed, _, _ = self.pacman(phase + '-ownership', ['-Qql', NAME])
        actual = set()
        for value in listed.decode().splitlines():
            path = Path(value)
            C.need(path.is_relative_to(self.base), 'OWNERSHIP_PATH_ESCAPES_ROOT')
            if path.is_file():
                actual.add(path.relative_to(self.base).as_posix())
        self.check(phase + '-exact-file-ownership', actual == set(self.profile['payload']))
        stdout, _, _ = self.command(phase + '-tool-check', [str(self.base / 'usr/bin' / NAME), 'check'])
        self.check(phase + '-frozen-runtime-check', C.decode(stdout)['files'] == 10)
        stdout, _, _ = self.command(phase + '-real-packet-verify', [str(self.base / 'usr/bin' / NAME), 'verify',
            '--packet', '/scratch/caller/packet', '--sha256', self.profile['packet_index_sha256']])
        report = C.decode(stdout)
        self.check(phase + '-genuine-packet', report['registry']['exact_crates'] == 117
            and report['registry']['exact_member_files'] == 4292 and not report['holds']['legal_acceptance']
            and report['holds']['release'] == 'NOT_ADMITTED')
        self.report.setdefault('installed_verification', {})[phase] = report

    def run(self):
        self.report['passive_context'] = observe(self.r, self.l)
        self.report['environment'] = guard(self.r, self.contract, initial=True)
        host = C.host_contract(HERE)
        H.claim(host, self.contract['nonce'])
        self.report['host_contract_sha256'] = C.HOST_CONTRACT_SHA
        C.need(Path(__file__).resolve() == Path('/runner/journey.py'), 'FIXED_RUNNER_PATH_REQUIRED')
        for name, pin in self.contract['runner_files'].items():
            C.need(C.digest(C.read(HERE / name, 128 * 1024)) == pin, 'RUNNER_FILE_PIN')
        for program in ('pacman', 'gpg', 'gpgconf', 'python3'):
            C.need(shutil.which(program), 'PREINSTALLED_PROGRAM_REQUIRED:' + program)
        C.need(sys.version_info >= (3, 14), 'IMAGE_PYTHON_ZSTD_SUPPORT_REQUIRED')
        package = Path('/inputs') / self.profile['package']['filename']
        raw = C.read(package)
        self.check('exact-package-archive', len(raw) == self.profile['package']['bytes'] and C.digest(raw) == self.profile['package']['sha256'])
        initial_packet = C.packet(Path('/inputs/packet'))
        self.check('genuine-input-packet-index', C.digest(C.read(Path('/inputs/packet/delivery.json'))) == self.profile['packet_index_sha256'])
        original_conf = C.digest(C.read(Path('/etc/pacman.conf')))
        for name, target in host['root_symlinks'].items():
            path = Path('/') / name
            C.need(path.is_symlink() and os.readlink(path) == target, 'EXACT_IMAGE_ROOT_SYMLINK')
        # Reuse the unchanged copied-root mechanism and its capacity/hook masking.
        copier = self.r.Integration({'source_commit': self.profile['package']['source_commit']})
        copier.scratch = Path('/alpm'); copier.target = self.base
        copier.config = Path('/scratch/pacman.conf'); copier.query_config = Path('/scratch/query-pacman.conf')
        copier.copy_base()
        for directory in ('cache', 'masked-hooks'):
            shutil.move(str(Path('/alpm') / directory), str(Path('/scratch') / directory))
        for name, target in host['root_symlinks'].items():
            (self.base / name).symlink_to(target)
        self.report['copy_capacity'] = copier.result['copy_capacity']
        for leaf in ('TEST-pacman.conf', 'TEST-query-pacman.conf'):
            (Path('/out') / leaf).rename(Path('/out') / ('UNUSED-HELD-TEMPLATE-' + leaf))
        config = b'[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n'
        Path('/scratch/pacman.conf').write_bytes(config)
        evidence = Path('/out/ACTUAL-host-pacman.conf'); evidence.write_bytes(config); evidence.chmod(0o600)
        self.report['actual_pacman_config'] = dict(evidence='ACTUAL-host-pacman.conf', sha256=C.digest(config),
            unused_helper_templates=['UNUSED-HELD-TEMPLATE-TEST-pacman.conf', 'UNUSED-HELD-TEMPLATE-TEST-query-pacman.conf'])
        for name in ('signing', 'verifier'):
            path = Path('/test-home') / name; path.mkdir(mode=0o700); self.keydirs.append(path)
        signer = ['gpg', '--no-options', '--batch', '--homedir', '/test-home/signing', '--no-auto-key-retrieve']
        verifier = ['gpg', '--no-options', '--batch', '--homedir', '/test-home/verifier', '--no-auto-key-retrieve']
        self.command('generate-test-only-key', signer + ['--pinentry-mode', 'loopback', '--passphrase', '',
            '--quick-generate-key', 'TEST ONLY audio sources candidate <audio-source@test.invalid>', 'ed25519', 'sign', '1d'])
        listing, _, _ = self.command('test-fingerprint', signer + ['--with-colons', '--fingerprint', '--list-keys'])
        keys = [line.split(':')[9] for line in listing.decode().splitlines() if line.startswith('fpr:')]
        C.need(len(keys) == 1 and re.fullmatch('[0-9A-F]{40}', keys[0]), 'ONE_TEST_SIGNING_KEY_REQUIRED')
        fingerprint = keys[0]; self.report['test_only_fingerprint'] = fingerprint
        public = Path('/scratch/TEST-public.asc')
        self.command('export-test-public', signer + ['--armor', '--output', str(public), '--export', fingerprint])
        self.command('import-private-verifier', verifier + ['--import', str(public)])
        self.command('trust-only-ephemeral-test-key', verifier + ['--import-ownertrust'], data=fingerprint + ':6:\n')
        incoming = Path('/scratch') / package.name; shutil.copyfile(package, incoming)
        Path('/scratch/caller').mkdir(mode=0o700)
        shutil.copytree('/inputs/packet', '/scratch/caller/packet')
        sentinel = Path('/scratch/caller/caller-sentinel'); sentinel.write_bytes(b'caller-owned audio source packet\n'); sentinel.chmod(0o600)
        caller = C.packet(Path('/scratch/caller'))
        baseline = self.inventory('copied-base-inventory')
        C.need(NAME not in baseline and 'python' in baseline and 'xz' in baseline, 'BASE_DEPENDENCIES_OR_PACKAGE_STATE')
        self.report['base_inventory_sha256'] = C.digest(C.encoded(baseline)); self.report['base_package_count'] = len(baseline)
        stdout, stderr, _ = self.pacman('unsigned-package-refused', ['-U', '--noscriptlet', str(incoming)], (1,))
        self.check('required-signature-actually-refused', bool(re.search(rb'signature', stdout + stderr, re.I))
                   and self.inventory('unsigned-refusal-inventory') == baseline)
        self.command('sign-exact-test-archive', signer + ['--local-user', fingerprint, '--digest-algo', 'SHA256',
                     '--detach-sign', '--output', str(incoming) + '.sig', str(incoming)])
        status, _, _ = self.command('verify-full-test-signature', verifier + ['--status-fd', '1', '--verify', str(incoming) + '.sig', str(incoming)])
        self.r.signature_status(status.decode(), fingerprint)
        self.check('signed-archive-stays-exact', C.digest(C.read(incoming)) == self.profile['package']['sha256'])
        self.pacman('actual-test-signed-install', ['-U', '--noscriptlet', str(incoming)])
        self.report['package_installation'] = 'PACMAN_COMMIT_COMPLETED'
        self.installed('installed', baseline)
        self.check('install-preserves-caller', C.packet(Path('/scratch/caller')) == caller)
        self.pacman('actual-test-signed-reinstall', ['-U', '--noscriptlet', str(incoming)])
        self.report['reinstallation'] = 'PACMAN_COMMIT_COMPLETED'
        self.installed('reinstalled', baseline)
        self.check('reinstall-preserves-caller', C.packet(Path('/scratch/caller')) == caller)
        self.pacman('actual-package-removal', ['-R', '--noscriptlet', NAME])
        self.report['removal'] = 'PACMAN_COMMIT_COMPLETED'
        self.check('removed-restores-exact-base-inventory', self.inventory('removed-base-inventory') == baseline)
        self.check('all-package-files-removed', all(not (self.base / name).exists() and not (self.base / name).is_symlink() for name in self.profile['payload']))
        self.check('removal-preserves-caller-packet', C.packet(Path('/scratch/caller')) == caller)
        self.check('original-input-packet-preserved', C.packet(Path('/inputs/packet')) == initial_packet)
        self.check('base-configuration-preserved', C.digest(C.read(Path('/etc/pacman.conf'))) == original_conf)
        self.report['status'] = 'PASS_HOST_PRIVATE_TEST_SIGNED_ALPM_JOURNEY'

    def cleanup(self):
        for home in self.keydirs:
            self.command('retire-' + home.name + '-agent', ['gpgconf', '--homedir', str(home), '--kill', 'all'])
            shutil.rmtree(home)
        self.report['private_test_key_homes_absent'] = all(not p.exists() for p in self.keydirs)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--contract-sha256', required=True)
    args = parser.parse_args()
    raw = C.read(Path('/inputs/contract.json'), 65536)
    C.need(C.digest(raw) == args.contract_sha256, 'PRIVATE_CONTRACT_PIN')
    contract = C.decode(raw); profile = C.profile(HERE)
    C.need(contract['image_id'] == profile['image_id'] and re.fullmatch('[0-9a-f]{32}', contract['nonce']), 'CLOSED_CANDIDATE_CONTRACT')
    l = C.held(HERE / 'held/lifecycle.py', profile['held_apis']['scripts/integration/lifecycle.py'], 'audio_held_lifecycle')
    r = C.held(HERE / 'held/repository.py', profile['held_apis']['scripts/integration/repository.py'], 'audio_held_repository')
    journey = Journey(profile, contract, l, r)
    try:
        journey.run()
    except BaseException as error:
        journey.report.update(status='REFUSED_OR_FAILED_HOST_AUDIO_CANDIDATE', error_type=type(error).__name__, error=str(error)[:512])
    finally:
        try:
            journey.cleanup()
        except BaseException as error:
            journey.report.update(status='REFUSED_OR_FAILED_HOST_AUDIO_CANDIDATE', cleanup_error=type(error).__name__)
        path = Path('/out/result.json'); path.write_bytes(C.encoded(journey.report)); path.chmod(0o600)
    print(json.dumps({k: journey.report[k] for k in ('status', 'package_installation', 'reinstallation', 'removal')}))
    return int(journey.report['status'] != 'PASS_HOST_PRIVATE_TEST_SIGNED_ALPM_JOURNEY')


if __name__ == '__main__':
    sys.exit(main())
