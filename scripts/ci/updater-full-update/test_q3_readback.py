# SPDX-License-Identifier: MIT
"""Exercise the independent reader with finite host and serial fixtures."""

from datetime import datetime, timezone
import ast
import hashlib
import json
from pathlib import Path
from runpy import run_path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from uuid import UUID


SCRIPT = Path(__file__).with_name('q3-readback.py')
R = SimpleNamespace(**run_path(str(SCRIPT)))
NONCE = '7587bd83cc18382ba49989cc1d51d791'
HOST_UTC = 1795656000
BOOT_PIN = {'bytes': R.BOOT_BYTES, 'sha256': '1' * 64}
MEDIA_SHA = '2' * 64


def wire(data):
    return json.dumps(data, sort_keys=True)


def pin(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}


class Fixture:
    def __init__(self, root, case='update'):
        self.root = root
        self.out = root / 'owned-run'
        (self.out / 'work').mkdir(mode=0o700, parents=True, exist_ok=True)
        self.out.chmod(0o700)
        self.prep = self.preparation(case)
        self.guest = self.guest_plan(case)
        self.args = SimpleNamespace(plan=root / 'prep.json', guest_plan=root / 'guest.json',
                                    owner=self.out / 'owner.json', serial=self.out / 'serial.log',
                                    media_sha256=MEDIA_SHA, admission=root / 'admission.json',
                                    media_manifest=root / 'media.json')
        self.write_plans()
        argv, cmdline = R.qemu_arguments(self.prep, NONCE, case, self.args.guest_plan_sha256, HOST_UTC)
        stamp = datetime.fromtimestamp(HOST_UTC, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
        refusal = case == 'signature-refusal'
        self.report = {'status': 'PASS', 'case': case, 'case_exits': {'signature-refusal': 5} if refusal else {
            'unconfigured': 21, 'protected': 22, 'update': 0},
            'pages': 16384, 'private_state_removed': True, 'fixture_db_versions': ['0.1.0-1' if refusal else '0.1.1-1'],
            'command_timed_out': False, 'guest_disposal': 'REQUIRES_OWNER_RECEIPT',
            'sudo_upgrade_calls': 1, 'alpm_upgrades': 0 if refusal else 1, 'refusal_checkpoint_preserved': True}
        if refusal:
            self.report['signature_rejected'] = True
        self.serial = [
            '[    0.000000] Booting Linux on physical CPU 0x0000000000 [0x00000000]',
            f'[    0.000000] Kernel command line: {cmdline}',
            '[    0.353313] rtc-pl031 9010000.pl031: registered as rtc0',
            f'[    0.355601] rtc-pl031 9010000.pl031: setting system clock to {stamp} UTC ({HOST_UTC})',
            f'UPDATER_Q3_CLOCK {NONCE}',
            'RTC_PRESENT=yes', 'RTC_DRIVER=pl031', 'RTC_HCTOSYS=1', f'HOST_BOOT_UTC={HOST_UTC}',
            f'GUEST_BEFORE_CRYPTO_UTC={HOST_UTC + 10}', f'RTC_BEFORE_CRYPTO_UTC={HOST_UTC + 9}',
            'RTC_CLOCK_ADVANCED=yes', 'CLOCK_SETTING=none',
            f'UPDATER_Q3_BOOTSTRAP {NONCE} ' + wire({'before_packages': 362, 'q3_bootstrap': 'PASS'}),
            f'UPDATER_Q3_MOUNTS {NONCE} ' + wire(R.MOUNTS),
            f'UPDATER_Q3_REPORT {NONCE} ' + wire(self.report),
            f'UPDATER_Q3_TERMINAL {NONCE} PASS complete',
            'Powering off.', '[  684.887776] reboot: Power down',
        ]
        self.owner = {'kind': 'UPDATER_Q3_OWNER_V1', 'nonce': NONCE, 'case': case, 'host_utc': HOST_UTC,
                      'media_sha256': MEDIA_SHA, 'container_id': 'c' * 64,
                      'qemu_argv': argv, 'boot': BOOT_PIN, 'kernel': R.KERNEL, 'scratch': R.SCRATCH,
                      'elapsed_seconds': 685.0, 'natural_exit': True, 'container_absent_twice': True,
                      'overlay_retired': True, 'retirement': 'PASS',
                      'overlay': {'bytes': 300001, 'sha256': 'd' * 64}}
        self.write_leaves()
        self.write_receipts()

    def preparation(self, case):
        append = R.BOOT['boot_cmdline'](NONCE, '/updater-q3-v2/guest-init.sh')
        append += (f' cachy_updater16k_nonce={NONCE} cachy_updater16k_case={case}'
                   ' cachy_updater16k={PLAN_SHA256} arm16k_rtc_host_epoch={HOST_UTC}')
        template = R.BOOT['vm_argv']('/inputs/Image', append, 'updater-q3-' + NONCE,
                                     (('boot', 'file=/inputs/boot.raw,format=raw,readonly=on'),
                                      ('scratch', 'file=/out/overlay.qcow2,format=qcow2,readonly=off,discard=ignore'),
                                      ('input', 'file=/inputs/media.raw,format=raw,readonly=on')))
        leaves = {'q3.lock': {'bytes': 6925, 'sha256': R.Q3_SHA},
                  'before.lock': {'bytes': 7069, 'sha256': R.BEFORE_SHA},
                  'hooks.list': {'bytes': 1001, 'sha256': R.HOOKS_SHA},
                  R.OLD: pin(b'old fixture'), R.NEW: pin(b'new fixture')}
        return {'kind': 'UPDATER_Q3_PREPARATION_UNISSUED', 'authority': None, 'case': case, 'nonce': NONCE,
                'base_inventory': 356, 'target_inventory': 362,
                'input_ext4': {'bytes': 128 << 20, 'label': 'UPDATER16K', 'uuid': str(UUID(hex=NONCE, version=4))},
                'inputs': {'boot.raw': BOOT_PIN, 'Image': R.KERNEL, 'scratch.raw': R.SCRATCH},
                'unsigned_media': leaves, 'qemu_argv_template': template}

    def guest_plan(self, case):
        sealed = {name: self.prep['unsigned_media'].get(name, pin(name.encode()))['sha256'] for name in R.PLAN_LEAVES}
        sealed['updater.pkg'] = R.UPDATER_SHA
        if case == 'signature-refusal':
            sealed[R.NEW + '.sig'] = sealed[R.OLD + '.sig']
        return {'kind': 'cachy-asahi-updater16k-disposable-v1', 'case': case, 'valid_from': HOST_UTC - 60,
                'expires': HOST_UTC + 1800, 'signer': 'A' * 40, 'files': sealed}

    def write_plans(self):
        for name, value in (('plan', self.prep), ('guest_plan', self.guest)):
            path = getattr(self.args, name)
            body = wire(value).encode()
            path.write_bytes(body)
            setattr(self.args, name + '_sha256', pin(body)['sha256'])
        self.media = {'kind': 'UPDATER_Q3_MEDIA_V1', 'preparation_sha256': self.args.plan_sha256,
                      'case': self.prep['case'], 'plan': pin(self.args.guest_plan.read_bytes()),
                      'media': {'bytes': R.MEDIA_BYTES, 'sha256': MEDIA_SHA}}
        self.args.media_manifest.write_text(wire(self.media))
        self.args.media_manifest_sha256 = pin(self.args.media_manifest.read_bytes())['sha256']
        self.owner_source = SCRIPT.with_name('q3-owner.py').read_bytes()
        self.admission = {'kind': 'UPDATER_Q3_ADMISSION_V1', 'nonce': NONCE, 'case': self.prep['case'],
                          'preparation_sha256': self.args.plan_sha256, 'guest_plan_sha256': self.args.guest_plan_sha256,
                          'media_manifest_sha256': self.args.media_manifest_sha256, 'media_sha256': MEDIA_SHA,
                          'output': str(self.out), 'owner_sha256': pin(self.owner_source)['sha256'], 'runner_image': R.IMAGE,
                          'attach_seconds': R.MAX_SECONDS, 'serial_cap': R.MAX_SERIAL, 'overlay_cap': R.MAX_OVERLAY,
                          'valid_from': HOST_UTC - 30, 'expires': HOST_UTC + 1500}
        self.args.admission.write_text(wire(self.admission))
        self.args.admission_sha256 = pin(self.args.admission.read_bytes())['sha256']

    def inspect(self, exited=False):
        actor = next(row.value.value for row in ast.parse(self.owner_source).body if isinstance(row, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == 'ACTOR' for target in row.targets))
        argv = [word.replace('{PLAN_SHA256}', self.args.guest_plan_sha256) for word in self.prep['qemu_argv_template']]
        stamp = lambda value: datetime.fromtimestamp(value, timezone.utc).isoformat().replace('+00:00', 'Z')
        cid = self.owner['container_id']
        return {'Id': cid, 'Name': '/caa-updater-q3-' + NONCE, 'Image': R.IMAGE, 'Path': '/usr/bin/bash',
                'Args': ['-euc', actor, 'updater-q3', *argv],
                'Config': {'Labels': {'org.cachy-asahi.updater-q3': NONCE}},
                'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False,
                    'AutoRemove': False, 'Init': False, 'CapDrop': ['ALL'], 'Memory': 6 << 30, 'MemorySwap': 6 << 30,
                    'NanoCpus': 4000000000, 'PidsLimit': 64, 'LogConfig': {'Type': 'none'},
                    'SecurityOpt': ['no-new-privileges']},
                'Mounts': [{'Type': 'bind', 'Propagation': 'rprivate', 'Source': str(self.out / source),
                            'Destination': '/' + destination, 'RW': rw}
                           for source, destination, rw in (('inputs', 'inputs', False), ('work', 'out', True))],
                'State': {'Status': 'exited' if exited else 'created', 'Pid': 0, 'Running': False,
                          'OOMKilled': False, 'ExitCode': 0, 'Error': '', 'StartedAt': stamp(HOST_UTC - 2),
                          'FinishedAt': stamp(HOST_UTC + 683)}}

    def chain(self, size, allocated):
        def node(kind, name, length, allocated_bytes):
            info = {'filename': name, 'format': 'file', 'actual-size': allocated_bytes,
                    'virtual-size': (length + 511) // 512 * 512, 'children': [], 'dirty-flag': False,
                    'format-specific': {'type': 'file', 'data': {}}}
            return {'filename': name, 'format': kind, 'actual-size': allocated_bytes, 'virtual-size': R.SCRATCH['bytes'],
                    'children': [{'name': 'file', 'info': info}], 'dirty-flag': False}

        raw = '/inputs/scratch.raw'
        qcow = node('qcow2', '/out/overlay.qcow2', size, allocated) | {
            'backing-filename': raw, 'full-backing-filename': raw, 'backing-filename-format': 'raw',
            'cluster-size': 65536, 'format-specific': {'type': 'qcow2', 'data': {
                'compat': '1.1', 'compression-type': 'zlib', 'lazy-refcounts': False, 'refcount-bits': 16,
                'corrupt': False, 'extended-l2': False}}}
        return [qcow, node('raw', raw, R.SCRATCH['bytes'], 1048576)]

    def write_leaves(self):
        leaves = {'admission.checked.json': self.args.admission.read_bytes(),
                  'created.inspect.json': wire([self.inspect()]).encode(),
                  'exited.inspect.json': wire([self.inspect(exited=True)]).encode(),
                  'run.cid': self.owner['container_id'].encode(), 'absence-1': b'', 'absence-2': b'',
                  'work/host-utc': f'{HOST_UTC}\n'.encode(),
                  'work/overlay-before.json': wire(self.chain(196616, 196608)).encode(),
                  'work/overlay-before.size': b'196616\n',
                  'work/overlay-after.json': wire(self.chain(300001, 262144)).encode(), 'runner.stderr': b''}
        self.owner['evidence'] = {}
        for name, body in leaves.items():
            self.set_leaf(name, body)

    def set_leaf(self, name, body):
        (self.out / name).write_bytes(body)
        self.owner['evidence'][name] = pin(body)

    def write_receipts(self):
        body = ('\r\n'.join(self.serial) + '\r\n').encode()
        self.args.serial.write_bytes(body)
        self.owner['serial'] = pin(body)
        self.owner['preparation_sha256'] = self.args.plan_sha256
        self.owner['guest_plan_sha256'] = self.args.guest_plan_sha256
        self.owner.setdefault('admission_sha256', self.args.admission_sha256)
        self.write_owner()

    def write_owner(self):
        owner_raw = wire(self.owner).encode()
        self.args.owner.write_bytes(owner_raw)
        self.args.owner_sha256 = pin(owner_raw)['sha256']

    def cli(self):
        flags = [part for key, value in vars(self.args).items() for part in ('--' + key.replace('_', '-'), str(value))]
        return subprocess.run([sys.executable, '-I', '-B', str(SCRIPT), *flags],
                              capture_output=True, text=True, check=False, timeout=10)


class ReadbackTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_normal_entry_accepts_golden_update_and_refusal(self):
        for case, upgrades in (('update', 1), ('signature-refusal', 0)):
            with self.subTest(case=case):
                fixture = Fixture(self.root, case)
                result = fixture.cli()
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                row = json.loads(result.stdout)
                self.assertEqual((row['status'], row['case'], row['worker']['alpm_upgrades']), ('PASS', case, upgrades))
                self.assertEqual(row['guest_disposal'], 'PASS')

    def test_shell_entry_refuses_changed_serial_bytes_or_noncanonical_file(self):
        fixture = Fixture(self.root)
        fixture.args.serial.write_bytes(fixture.args.serial.read_bytes() + b'extra\n')
        result = fixture.cli()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['status'], 'HOLD')
        other = self.root / 'other.log'
        fixture.args.serial.rename(other)
        fixture.args.serial.symlink_to(other)
        self.assertIn('Canonical read-only path', fixture.cli().stdout)

    def test_repinned_missing_or_extra_frame_and_wrong_nonce_refuse(self):
        for action in ('duplicate', 'missing_powerdown', 'foreign_nonce', 'hold'):
            with self.subTest(action=action):
                fixture = Fixture(self.root)
                if action == 'duplicate':
                    fixture.serial.insert(-2, fixture.serial[-3])
                elif action == 'missing_powerdown':
                    fixture.serial.pop()
                elif action == 'foreign_nonce':
                    fixture.serial[-3] = fixture.serial[-3].replace(NONCE, 'e' * 32)
                else:
                    fixture.serial[-3] = fixture.serial[-3].replace('PASS complete', 'HOLD cleanup')
                fixture.write_receipts()
                with self.assertRaises(ValueError):
                    R.readback(fixture.args)

    def test_natural_hold_reports_the_attested_boot_stage(self):
        fixture = Fixture(self.root)
        report = next(i for i, line in enumerate(fixture.serial) if line.startswith('UPDATER_Q3_CLOCK'))
        fixture.serial[report:] = [f'UPDATER_Q3_TERMINAL {NONCE} HOLD clock', '[   15.000000] reboot: Power down']
        fixture.owner['overlay']['bytes'] = 196616
        fixture.set_leaf('work/overlay-after.json', (fixture.out / 'work/overlay-before.json').read_bytes())
        fixture.write_receipts()
        result = fixture.cli()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['reason'], 'Guest terminal HOLD at clock')

    def test_repinned_rtc_mount_and_transaction_claims_refuse(self):
        for target, wrong in (('HOST_BOOT_UTC=', f'HOST_BOOT_UTC={HOST_UTC + 1}'),
                              ('CLOCK_SETTING=', 'CLOCK_SETTING=manual'),
                              ('UPDATER_Q3_BOOTSTRAP', f'UPDATER_Q3_BOOTSTRAP {NONCE} {wire({"before_packages": 361, "q3_bootstrap": "PASS"})}'),
                              ('UPDATER_Q3_MOUNTS', f'UPDATER_Q3_MOUNTS {NONCE} {wire(R.MOUNTS | {"media_ro": 1})}'),
                              ('UPDATER_Q3_REPORT', None)):
            with self.subTest(target=target):
                fixture = Fixture(self.root, 'signature-refusal')
                index = next(i for i, row in enumerate(fixture.serial) if row.startswith(target))
                fixture.serial[index] = wrong or f'UPDATER_Q3_REPORT {NONCE} ' + wire(fixture.report | {'alpm_upgrades': 1})
                fixture.write_receipts()
                with self.assertRaises(ValueError):
                    R.readback(fixture.args)

    def test_wrong_owner_media_admission_network_and_cleanup_claims_refuse(self):
        for field, wrong in (('retirement', 'HOLD'), ('container_absent_twice', 1), ('overlay_retired', False),
                             ('media_sha256', 'f' * 64), ('admission_sha256', 'e' * 64),
                             ('elapsed_seconds', 1500), ('natural_exit', False)):
            with self.subTest(field=field):
                fixture = Fixture(self.root)
                fixture.owner[field] = wrong
                fixture.write_receipts()
                with self.assertRaises(ValueError):
                    R.readback(fixture.args)
        fixture = Fixture(self.root)
        nic = fixture.prep['qemu_argv_template'].index('-nic') + 1
        fixture.prep['qemu_argv_template'][nic] = 'user'
        fixture.owner['qemu_argv'][nic] = 'user'
        fixture.write_plans()
        fixture.owner['admission_sha256'] = fixture.args.admission_sha256
        fixture.write_receipts()
        with self.assertRaisesRegex(ValueError, 'offline scope'):
            R.readback(fixture.args)

    def test_media_signature_case_cannot_be_relabelled(self):
        fixture = Fixture(self.root, 'signature-refusal')
        fixture.guest['files'][R.NEW + '.sig'] = '0' * 64
        fixture.write_plans()
        fixture.owner['admission_sha256'] = fixture.args.admission_sha256
        fixture.write_receipts()
        with self.assertRaisesRegex(ValueError, 'signature case'):
            R.readback(fixture.args)

    def test_admitted_readback_rejects_changed_unretired_and_relabelled_owner_evidence(self):
        fixture = Fixture(self.root)
        leaf = fixture.out / 'exited.inspect.json'
        original = leaf.read_bytes()
        leaf.write_bytes(original + b'\n')
        with self.assertRaisesRegex(ValueError, 'Exact original file pin'):
            R.readback(fixture.args)
        leaf.write_bytes(original)
        remaining = fixture.out / 'work/overlay.qcow2'
        remaining.touch()
        with self.assertRaisesRegex(ValueError, 'retirement'):
            R.readback(fixture.args)
        remaining.unlink()
        corrupt = fixture.inspect(exited=True)
        corrupt['HostConfig']['NetworkMode'] = 'bridge'
        fixture.set_leaf('exited.inspect.json', wire([corrupt]).encode())
        fixture.write_owner()
        with self.assertRaisesRegex(ValueError, 'isolation bounds'):
            R.readback(fixture.args)

    def test_issued_scope_mismatch_refuses_despite_repinned_admission(self):
        fixture = Fixture(self.root)
        fixture.admission['output'] = str(self.root / 'unrelated')
        body = wire(fixture.admission).encode()
        fixture.args.admission.write_bytes(body)
        fixture.args.admission_sha256 = pin(body)['sha256']
        fixture.owner['admission_sha256'] = fixture.args.admission_sha256
        fixture.set_leaf('admission.checked.json', body)
        fixture.write_owner()
        with self.assertRaisesRegex(ValueError, 'Issued admission differs'):
            R.readback(fixture.args)


if __name__ == '__main__':
    unittest.main()
