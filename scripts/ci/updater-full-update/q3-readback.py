# SPDX-License-Identifier: MIT
"""Read the admitted Q3 guest and owner evidence using only retained files."""

import argparse
import ast
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from runpy import run_path
import stat
import sys
from uuid import UUID


HERE = Path(__file__).resolve().parent
INTEGRATION = HERE.parents[1] / 'integration'
Q3 = run_path(str(INTEGRATION / 'qt612_base_16k_link_preflight/readback.py'))
BOOT = run_path(str(INTEGRATION / 'qt612_md4c_compile/prepare.py'))
need, read, external, json_body, check_pin = (Q3[key] for key in
    ('need', 'read', 'external', 'json_body', 'check_pin'))
SHA = re.compile(r'[0-9a-f]{64}')
NONCE = re.compile(r'[0-9a-f]{32}')
FINGERPRINT = re.compile(r'[0-9A-F]{40}')
CASES = {'update', 'signature-refusal'}
KERNEL = {'bytes': 9019400, 'sha256': '36066ded2f5721fd9bb257cebb2e4cb32084f45c3717f4d7a45430fe3cdcc494'}
SCRATCH = {'bytes': 16 << 30, 'sha256': '70ca6c345fcf5e5d29d0bb90993d54c17a54164f23b2a6fe839e061b51edca45'}
BOOT_BYTES = 1611661312
MEDIA_BYTES = 128 << 20
IMAGE = 'sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a'
OLD = 'cachy-asahi-check-fixture-0.1.0-1-any.pkg.tar.gz'
NEW = 'repo/cachy-asahi-check-fixture-0.1.1-1-any.pkg.tar.gz'
UPDATER_SHA = '44b89959b768c80e82d1e32b29348bdd4b58bfb1fabfba393b14794178d086dc'
Q3_SHA = 'e2a4da7903e6de26b0ee37758ad424439f83196fa6a3b0bdffa501f35a02d0b9'
BEFORE_SHA = '7a5779caafed704a109debcf207b040e32565b5102c889809eb33d9bbbe8680b'
HOOKS_SHA = 'd31e16267b226b46367696f662825642762d34699724525abeaeaa57bad8fe2e'
PLAN_LEAVES = {'q3.lock', 'before.lock', 'hooks.list', 'updater.pkg', 'updater.pkg.sig',
               OLD, OLD + '.sig', NEW, NEW + '.sig', 'repo/fixture.db', 'repo/fixture.db.sig',
               'policy.json', 'pre.json', 'post.json', 'protected-policy.json', 'protected-pre.json'}
MAX_SERIAL = 1 << 20
MAX_OVERLAY = 1 << 30
MAX_SECONDS = 1300
EVIDENCE_CAPS = {
    'admission.checked.json': 32 << 10, 'created.inspect.json': MAX_SERIAL, 'exited.inspect.json': MAX_SERIAL,
    'run.cid': 66, 'absence-1': 0, 'absence-2': 0, 'work/host-utc': 16,
    'work/overlay-before.json': 16 << 10, 'work/overlay-before.size': 16, 'work/overlay-after.json': 16 << 10,
    'runner.stderr': MAX_SERIAL,
}
OWNER_FIELDS = set((
    'kind nonce case preparation_sha256 media_sha256 guest_plan_sha256 serial overlay '
    'boot kernel scratch qemu_argv host_utc natural_exit container_absent_twice retirement '
    'admission_sha256 container_id elapsed_seconds overlay_retired evidence'
).split())
MOUNTS = {'boot_ro': True, 'media_ro': True, 'scratch_nosuid': True, 'sudo_single_file': True}
CLOCK_KEYS = (b'RTC_PRESENT', b'RTC_DRIVER', b'RTC_HCTOSYS', b'HOST_BOOT_UTC',
              b'GUEST_BEFORE_CRYPTO_UTC', b'RTC_BEFORE_CRYPTO_UTC', b'RTC_CLOCK_ADVANCED', b'CLOCK_SETTING')


def epoch(value):
    return type(value) is int and 1000000000 <= value < 4102444800


def exact_object(observed, expected, message):
    need(observed.keys() == expected.keys() and
         all(type(observed[k]) is type(v) and observed[k] == v for k, v in expected.items()), message)


def read_plan(path, digest, cap):
    raw, observed = external(path, cap, digest)
    return json_body(raw), observed


def verify_preparation(prep):
    nonce, case = prep['nonce'], prep['case']
    need(prep['kind'] == 'UPDATER_Q3_PREPARATION_UNISSUED' and prep['authority'] is None
         and type(nonce) is str and NONCE.fullmatch(nonce) and nonce[:8] != '00000000'
         and type(case) is str and case in CASES
         and prep['base_inventory'] == 356 and prep['target_inventory'] == 362,
         'Exact unissued Q3 preparation and case required')
    need(prep['input_ext4'] == {'bytes': MEDIA_BYTES, 'label': 'UPDATER16K', 'uuid': str(UUID(hex=nonce, version=4))},
         'Q3 media geometry differs')
    inputs = prep['inputs']
    need(inputs.keys() == {'Image', 'scratch.raw', 'boot.raw'} and inputs['Image'] == KERNEL
         and inputs['scratch.raw'] == SCRATCH and check_pin(inputs['boot.raw'], BOOT_BYTES)
         and inputs['boot.raw']['bytes'] == BOOT_BYTES, 'Q3 input pins differ')
    leaves = prep['unsigned_media']
    fixed = {'q3.lock': Q3_SHA, 'before.lock': BEFORE_SHA, 'hooks.list': HOOKS_SHA}
    need(all(check_pin(leaves[name], 1 << 20) and leaves[name]['bytes'] > 0 for name in (*fixed, OLD, NEW))
         and all(leaves[name]['sha256'] == digest for name, digest in fixed.items()), 'Q3 inventory or fixture pins differ')
    return nonce, case


def verify_guest_plan(plan, prep, case):
    need(plan.keys() == {'kind', 'case', 'valid_from', 'expires', 'signer', 'files'}
         and plan['kind'] == 'cachy-asahi-updater16k-disposable-v1' and plan['case'] == case,
         'Guest plan case or schema differs')
    need(epoch(plan['valid_from']) and epoch(plan['expires'])
         and 0 < plan['expires'] - plan['valid_from'] <= 86400
         and type(plan['signer']) is str and FINGERPRINT.fullmatch(plan['signer']),
         'Guest plan TEST signer or validity differs')
    files = plan['files']
    need(type(files) is dict and files.keys() == PLAN_LEAVES and
         all(type(value) is str and SHA.fullmatch(value) for value in files.values()) and
         all(files[name] == prep['unsigned_media'][name]['sha256']
             for name in ('q3.lock', 'before.lock', 'hooks.list', OLD, NEW)) and files['updater.pkg'] == UPDATER_SHA,
         'Exact guest package, signature and inventory pins required')
    need((files[OLD + '.sig'] == files[NEW + '.sig']) == (case == 'signature-refusal'),
         'Guest plan does not isolate the selected signature case')


def qemu_arguments(prep, nonce, case, guest_plan, host_utc):
    template = prep['qemu_argv_template']
    need(type(template) is list and len(template) <= 64 and template.count('-append') == 1
         and all(type(word) is str and 0 < len(word) <= 4096 for word in template), 'Invalid QEMU template')
    append_index = template.index('-append') + 1
    need(append_index < len(template), 'Missing QEMU kernel arguments')
    append = template[append_index]
    base = BOOT['boot_cmdline'](nonce, '/updater-q3-v2/guest-init.sh')
    suffix = {
        f'cachy_updater16k_nonce={nonce}', f'cachy_updater16k_case={case}',
        'cachy_updater16k={PLAN_SHA256}', 'arm16k_rtc_host_epoch={HOST_UTC}',
    }
    extras = append[len(base) + 1:].split(' ')
    need(append.startswith(base + ' ') and len(extras) == len(suffix) and set(extras) == suffix,
         'QEMU template boot identity or case differs')
    expected = BOOT['vm_argv']('/inputs/Image', append, 'updater-q3-' + nonce,
                             (('boot', 'file=/inputs/boot.raw,format=raw,readonly=on'),
                              ('scratch', 'file=/out/overlay.qcow2,format=qcow2,readonly=off,discard=ignore'),
                              ('input', 'file=/inputs/media.raw,format=raw,readonly=on')))
    need(template == expected, 'QEMU template differs from the exact offline scope')
    expected[append_index] = append.replace('{PLAN_SHA256}', guest_plan).replace('{HOST_UTC}', str(host_utc))
    return expected, expected[append_index]


def verify_owner(owner, prep, nonce, case, preparation_sha, guest_sha, media_sha, admission_sha):
    need(owner.keys() == OWNER_FIELDS and owner['kind'] == 'UPDATER_Q3_OWNER_V1'
         and owner['nonce'] == nonce and owner['case'] == case
         and owner['preparation_sha256'] == preparation_sha and owner['guest_plan_sha256'] == guest_sha
         and owner['media_sha256'] == media_sha and owner['admission_sha256'] == admission_sha, 'Owner binding differs')
    need(type(owner['container_id']) is str and SHA.fullmatch(owner['container_id'])
         and epoch(owner['host_utc']) and type(owner['elapsed_seconds']) in (int, float)
         and 0 < owner['elapsed_seconds'] <= MAX_SECONDS, 'Owner runtime identity or limit differs')
    need(owner['natural_exit'] is owner['container_absent_twice'] is owner['overlay_retired'] is True
         and owner['retirement'] == 'PASS', 'Complete natural owner retirement required')
    need(owner['boot'] == prep['inputs']['boot.raw'] and owner['kernel'] == KERNEL and owner['scratch'] == SCRATCH,
         'Owner boot, kernel or backing pins differ')
    need(check_pin(owner['serial'], MAX_SERIAL) and owner['serial']['bytes'] > 0
         and check_pin(owner['overlay'], MAX_OVERLAY) and owner['overlay']['bytes'] > 0,
         'Owner output exceeds its finite scope')
    expected, cmdline = qemu_arguments(prep, nonce, case, guest_sha, owner['host_utc'])
    need(owner['qemu_argv'] == expected, 'Observed owner QEMU arguments differ')
    return cmdline


def verify_admission(admission, args, guest_plan, owner):
    bindings = {'kind': 'UPDATER_Q3_ADMISSION_V1', 'nonce': owner['nonce'], 'case': owner['case'],
                'preparation_sha256': args.plan_sha256, 'guest_plan_sha256': args.guest_plan_sha256,
                'media_manifest_sha256': args.media_manifest_sha256, 'media_sha256': args.media_sha256,
                'output': str(args.owner.parent), 'runner_image': IMAGE,
                'serial_cap': MAX_SERIAL, 'overlay_cap': MAX_OVERLAY, 'attach_seconds': MAX_SECONDS}
    need(admission.keys() == bindings.keys() | {'valid_from', 'expires', 'owner_sha256'},
         'Wrong issued admission fields')
    exact_object({name: admission[name] for name in bindings}, bindings, 'Issued admission differs')
    start, expires = admission['valid_from'], admission['expires']
    need(epoch(start) and epoch(expires) and guest_plan['valid_from'] <= start <= owner['host_utc'] < expires
         <= guest_plan['expires'] and 0 < expires - start <= 7200, 'Owner launch UTC is outside issued admission')
    source, _ = external(HERE / 'q3-owner.py', 128 << 10, admission['owner_sha256'])
    definitions = [row for row in ast.parse(source).body if isinstance(row, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'ACTOR' for target in row.targets)]
    need(len(definitions) == 1 and isinstance(definitions[0].value, ast.Constant)
         and type(definitions[0].value.value) is str, 'Exact admitted runner script is unavailable')
    return definitions[0].value.value


def verify_container(body, out, owner, actor, template_args):
    rows = BOOT['strict_json'](body)
    need(type(rows) is list and len(rows) == 1, 'One original container inspection required')
    row, = rows
    cid, nonce = owner['container_id'], owner['nonce']
    need(row['Id'] == cid and row['Name'] == '/caa-updater-q3-' + nonce and row['Image'] == IMAGE
         and row['Path'] == '/usr/bin/bash' and row['Args'] == ['-euc', actor, 'updater-q3', *template_args]
         and row['Config']['Labels']['org.cachy-asahi.updater-q3'] == nonce, 'Inspected container identity differs')
    host = row['HostConfig']
    expected = {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False, 'AutoRemove': False,
                'Init': False, 'CapDrop': ['ALL'], 'Memory': 6 << 30, 'MemorySwap': 6 << 30,
                'NanoCpus': 4000000000, 'PidsLimit': 64}
    exact_object({k: host[k] for k in expected}, expected, 'Inspected container resource or isolation bounds differ')
    need(host['SecurityOpt'] in (['no-new-privileges'], ['no-new-privileges=true'])
         and host['LogConfig']['Type'] == 'none'
         and not any(host.get(key) for key in ('CapAdd', 'Devices', 'DeviceRequests', 'DeviceCgroupRules',
                                               'PortBindings', 'VolumesFrom', 'Tmpfs')),
         'Inspected container has unexpected access')
    mounts = row['Mounts']
    need(len(mounts) == 2 and all(m['Type'] == 'bind' and m['Propagation'] == 'rprivate'
                                 and type(m['RW']) is bool for m in mounts)
         and {(m['Source'], m['Destination'], m['RW']) for m in mounts}
         == {(str(out / 'inputs'), '/inputs', False), (str(out / 'work'), '/out', True)},
         'Inspected container mounts are outside the owned scope')
    return row['State']


def verify_overlay(evidence, owner):
    initial_size = evidence['work/overlay-before.size']
    need(re.fullmatch(rb'[1-9][0-9]{0,6}\n', initial_size), 'Invalid original overlay size')
    before = evidence['work/overlay-before.json']
    BOOT['validate_empty_overlay'](before, int(initial_size))
    after = BOOT['strict_json'](evidence['work/overlay-after.json'])
    need(type(after) is list and len(after) == 2 and after[1] == BOOT['strict_json'](before)[1],
         'Original read-only backing differs after guest exit')
    child, backing = after
    need(child['filename'] == '/out/overlay.qcow2' and child['format'] == 'qcow2'
         and child['backing-filename'] == child['full-backing-filename'] == backing['filename']
         and child['backing-filename-format'] == 'raw' and child['virtual-size'] == SCRATCH['bytes']
         and child['dirty-flag'] is False and child['format-specific']['data']['corrupt'] is False,
         'Final owned overlay was not clean and on the exact backing')
    nodes = child['children']
    size = owner['overlay']['bytes']
    need(len(nodes) == 1 and nodes[0]['name'] == 'file' and size >= int(initial_size)
         and nodes[0]['info']['format'] == 'file' and nodes[0]['info']['filename'] == child['filename']
         and nodes[0]['info']['virtual-size'] == (size + 511) // 512 * 512
         and nodes[0]['info']['dirty-flag'] is False and nodes[0]['info']['children'] == [],
         'Final owned overlay size or local file node differs')
    return int(initial_size)


def read_owner_evidence(args, prep, owner, admission, admission_pin, actor):
    out = args.owner.parent
    info = out.lstat()
    need(args.owner == out / 'owner.json' and args.serial == out / 'serial.log'
         and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
         'Exact private owner attempt path required')
    pins = owner['evidence']
    need(type(pins) is dict and pins.keys() == EVIDENCE_CAPS.keys()
         and pins['admission.checked.json'] == admission_pin, 'Owner evidence set or original admission differs')
    evidence = {name: read(out / name, cap, pins[name])[0] for name, cap in EVIDENCE_CAPS.items()}
    need(evidence['run.cid'] in (owner['container_id'].encode(), (owner['container_id'] + '\n').encode())
         and evidence['work/host-utc'] == f'{owner["host_utc"]}\n'.encode()
         and evidence['absence-1'] == evidence['absence-2'] == b''
         and not any(os.path.lexists(out / name) for name in ('inputs', 'work/overlay.qcow2')),
         'Owned CID, start UTC, two absences or writable media retirement differ')
    template_args = [word.replace('{PLAN_SHA256}', args.guest_plan_sha256) for word in prep['qemu_argv_template']]
    created, exited = (verify_container(evidence[key], out, owner, actor, template_args)
                       for key in ('created.inspect.json', 'exited.inspect.json'))
    for row, status in ((created, 'created'), (exited, 'exited')):
        expected = {'Status': status, 'Pid': 0, 'Running': False}
        exact_object({key: row[key] for key in expected}, expected, 'Exact original container state required')
    expected = {'OOMKilled': False, 'ExitCode': 0, 'Error': ''}
    exact_object({key: exited[key] for key in expected}, expected, 'Natural guest exit was not observed')
    def utc_stamp(value):
        need(type(value) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}(?:\.[0-9]{1,9})?Z', value),
             'Exact inspected container UTC timestamp required')
        return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()

    started, finished = map(utc_stamp, (exited['StartedAt'], exited['FinishedAt']))
    need(admission['valid_from'] <= int(started) <= owner['host_utc'] <= int(finished) < admission['expires']
         and 0 < finished - started <= min(MAX_SECONDS, owner['elapsed_seconds'] + 2),
         'Original launch or exit timestamps are outside admission')
    return verify_overlay(evidence, owner)


def unique_serial(lines, prefix, pattern):
    matches = [(index, line) for index, line in enumerate(lines) if prefix(line)]
    need(len(matches) == 1, 'Expected exactly one admitted serial frame')
    index, line = matches[0]
    result = re.fullmatch(pattern, line)
    need(result is not None, 'Serial frame is malformed or belongs to another guest')
    return index, result


def observed_clock(lines, index, bootstrap, host_utc, kernel_rtc, plan):
    clock_rows = [(pos, line.partition(b'=')) for pos, line in enumerate(lines)
                  if line.partition(b'=')[0] in CLOCK_KEYS]
    need(tuple(parts[0] for _, parts in clock_rows) == CLOCK_KEYS
         and all(index < pos < bootstrap and parts[1] == b'=' for pos, parts in clock_rows),
         'Clock evidence missing, duplicated or out of order')
    values = dict((parts[0], parts[2]) for _, parts in clock_rows)
    need(tuple(values[key] for key in CLOCK_KEYS[:3] + CLOCK_KEYS[6:]) ==
         (b'yes', b'pl031', b'1', b'yes', b'none'), 'PL031 live UTC evidence differs')
    epochs = tuple(values[key] for key in CLOCK_KEYS[3:6])
    need(all(re.fullmatch(rb'[1-9][0-9]{9}', value) for value in epochs), 'Invalid RTC observation timestamp')
    host, guest, rtc = map(int, epochs)
    need(host == host_utc and host - 5 <= kernel_rtc <= guest and host - 5 <= guest <= host + 490
         and abs(guest - rtc) <= 2 and plan['valid_from'] <= guest < plan['expires'],
         'RTC observation does not bind launch UTC and the TEST validity window')
    return {'host_boot_utc': host, 'guest_before_crypto_utc': guest, 'rtc_before_crypto_utc': rtc,
            'kernel_rtc_epoch': kernel_rtc}


def verify_worker(row, case):
    refusal = case == 'signature-refusal'
    cases = {'signature-refusal': 5} if refusal else {'unconfigured': 21, 'protected': 22, 'update': 0}
    exact_object(row['case_exits'], cases, 'Installed updater exit codes differ')
    expected = {'status': 'PASS', 'case': case, 'case_exits': cases, 'pages': 16384,
                'private_state_removed': True, 'fixture_db_versions': ['0.1.0-1' if refusal else '0.1.1-1'],
                'command_timed_out': False, 'guest_disposal': 'REQUIRES_OWNER_RECEIPT',
                'sudo_upgrade_calls': 1, 'alpm_upgrades': 0 if refusal else 1, 'refusal_checkpoint_preserved': True}
    if refusal:
        expected['signature_rejected'] = True
    exact_object(row, expected, 'Guest transaction evidence differs')


def verify_serial(body, nonce, case, cmdline, plan, owner):
    need(body.endswith(b'\n'), 'Incomplete serial stream')
    lines = body.splitlines()
    timestamp = rb'\[ *[0-9]{1,6}\.[0-9]{6}\] '
    idx_cmdline, _ = unique_serial(lines, lambda row: b'Kernel command line:' in row,
                                   timestamp + rb'Kernel command line: ' + re.escape(cmdline.encode('ascii')))
    idx_power, _ = unique_serial(lines, lambda row: b'reboot: Power down' in row,
                                 timestamp + rb'reboot: Power down')

    def frame(label, suffix=b''):
        prefix = ('UPDATER_Q3_' + label).encode()
        return unique_serial(lines, lambda row: row.startswith(prefix), prefix + b' ' + nonce.encode() + suffix)

    idx_terminal, terminal = frame('TERMINAL', rb' (PASS|HOLD) (boot|clock|storage|bootstrap|sudo|worker|complete|cleanup)')
    need(idx_cmdline < idx_terminal < idx_power, 'Guest terminal is outside its observed boot')
    if terminal[1] == b'HOLD':
        raise ValueError('Guest terminal HOLD at ' + terminal[2].decode('ascii'))
    need(terminal[2] == b'complete', 'Guest PASS requires completed transaction and shutdown')
    idx_rtc, rtc = unique_serial(lines, lambda row: b'rtc-pl031 9010000.pl031: setting system clock' in row,
                               timestamp + rb'rtc-pl031 9010000\.pl031: setting system clock to '
                               rb'([0-9T:\-]{19}) UTC \(([1-9][0-9]{9})\)')
    kernel_epoch = int(rtc[2])
    need(datetime.fromtimestamp(kernel_epoch, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S').encode() == rtc[1],
         'PL031 kernel calendar does not match its epoch')
    idx_clock, _ = frame('CLOCK')
    idx_bootstrap, bootstrap = frame('BOOTSTRAP', rb' (\{.{0,8190}\})')
    idx_mounts, mounts = frame('MOUNTS', rb' (\{.{0,8190}\})')
    idx_report, report = frame('REPORT', rb' (\{.{0,16382}\})')
    need(idx_cmdline < idx_rtc < idx_clock < idx_bootstrap < idx_mounts < idx_report < idx_terminal < idx_power,
         'Clock, bootstrap, transaction, terminal and powerdown evidence is out of order')
    clock = observed_clock(lines, idx_clock, idx_bootstrap, owner['host_utc'], kernel_epoch, plan)
    exact_object(json_body(bootstrap[1]), {'before_packages': 362, 'q3_bootstrap': 'PASS'},
                 'Exact Q3 successor bootstrap required')
    exact_object(json_body(mounts[1]), MOUNTS, 'Q3 mount and single-file sudo evidence differs')
    row = json_body(report[1])
    verify_worker(row, case)
    return clock, row


def readback(args):
    digests = [args.plan_sha256, args.guest_plan_sha256, args.owner_sha256, args.media_sha256,
               args.admission_sha256, args.media_manifest_sha256]
    need(all(type(value) is str and SHA.fullmatch(value) for value in digests), 'Exact independent SHA-256 pins required')
    prep, preparation_pin = read_plan(args.plan, args.plan_sha256, 64 << 10)
    nonce, case = verify_preparation(prep)
    guest_plan, guest_pin = read_plan(args.guest_plan, args.guest_plan_sha256, 16 << 10)
    verify_guest_plan(guest_plan, prep, case)
    media, media_pin = read_plan(args.media_manifest, args.media_manifest_sha256, 16 << 10)
    exact_object(media, {'kind': 'UPDATER_Q3_MEDIA_V1', 'preparation_sha256': args.plan_sha256,
                         'case': case, 'plan': guest_pin, 'media': {'bytes': MEDIA_BYTES, 'sha256': args.media_sha256}},
                 'Exact sealed-media receipt required')
    admission, admission_pin = read_plan(args.admission, args.admission_sha256, 32 << 10)
    owner, owner_pin = read_plan(args.owner, args.owner_sha256, 32 << 10)
    cmdline = verify_owner(owner, prep, nonce, case, args.plan_sha256, args.guest_plan_sha256,
                           args.media_sha256, args.admission_sha256)
    actor = verify_admission(admission, args, guest_plan, owner)
    initial_overlay_size = read_owner_evidence(args, prep, owner, admission, admission_pin, actor)
    body, serial_pin = read(args.serial, MAX_SERIAL, owner['serial'])
    clock, worker = verify_serial(body, nonce, case, cmdline, guest_plan, owner)
    need(owner['overlay']['bytes'] > initial_overlay_size, 'Guest PASS requires an observed changed overlay')
    return {'kind': 'UPDATER_Q3_INDEPENDENT_READBACK_V1', 'status': 'PASS', 'case': case, 'nonce': nonce,
            'admission_sha256': args.admission_sha256, 'media_sha256': args.media_sha256,
            'preparation': preparation_pin, 'guest_plan': guest_pin, 'media_manifest': media_pin,
            'owner': owner_pin, 'serial': serial_pin,
            'owner_observed_overlay': owner['overlay'], 'guest_disposal': owner['retirement'], 'clock': clock,
            'worker': worker}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'guest-plan', 'owner', 'serial', 'admission', 'media-manifest'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('plan', 'guest-plan', 'owner', 'media', 'admission', 'media-manifest'):
        parser.add_argument('--' + name + '-sha256', required=True)
    args = parser.parse_args()
    sys.addaudithook(Q3['audit_fence'])
    try:
        result = readback(args)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError) as error:
        message = str(error) if type(error) is ValueError else 'Invalid or unavailable Q3 evidence'
        print(json.dumps({'kind': 'UPDATER_Q3_INDEPENDENT_READBACK_V1', 'status': 'HOLD', 'reason': message}))
        return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
