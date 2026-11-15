#!/usr/bin/python3 -IB
# SPDX-License-Identifier: MIT
"""Prepare exact private operands and run one owned offline Docker candidate."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import shutil
import sys

HERE = Path(__file__).resolve().parent
CHECKOUT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('audio_candidate_common', HERE / 'common.py')
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
spec = importlib.util.spec_from_file_location('audio_driver_host_contract', HERE / 'host_contract.py')
H = importlib.util.module_from_spec(spec); spec.loader.exec_module(H)


def copy_packet(source, output, snapshot):
    output.mkdir(mode=0o700)
    for name, row in sorted(snapshot.items(), key=lambda item: (len(Path(item[0]).parts), item[0])):
        if name == '.':
            continue
        target = output / name
        if row['kind'] == 'directory':
            target.mkdir(mode=0o700)
        else:
            raw = C.read(source / name)
            C.need(len(raw) == row['bytes'] and C.digest(raw) == row['sha256'], 'ORIGINAL_PACKET_CHANGED')
            target.write_bytes(raw); target.chmod(0o600)
    C.need(C.packet(output) == snapshot, 'COPIED_PACKET_DIFFERS')


def retire(report, command, attempted, name, label, nonce, acknowledged=False):
    report['owned_container_retired'] = False
    try:
        names = []
        if attempted:
            names = command('cleanup-census', ['docker', 'container', 'ls', '--all', '--filter', 'label=' + label,
                '--format', '{{.Names}}']).decode().splitlines()
            C.need(set(names) <= {name}, 'CLEANUP_LABEL_COLLISION')
        report['owned_container_found_at_cleanup'] = name in names
        if name in names:
            identity = command('cleanup-owner', ['docker', 'inspect', name, '--format',
                '{{index .Config.Labels "cachy-asahi.audio-candidate"}}']).decode().strip()
            C.need(identity == nonce, 'CLEANUP_OWNERSHIP_REFUSAL')
            command('remove-owned-container', ['docker', 'rm', '--force', name])
            names = command('confirm-container-absent', ['docker', 'container', 'ls', '--all', '--filter', 'label=' + label,
                '--format', '{{.Names}}']).decode().splitlines()
            C.need(not names, 'OWNED_CONTAINER_REMAINS')
        if attempted and not acknowledged:
            report['cleanup_state'] = 'CREATE_OUTCOME_UNKNOWN'
            raise ValueError('UNACKNOWLEDGED_CREATE_OUTCOME')
        report['owned_container_retired'] = True
        report['cleanup_state'] = 'CONFIRMED_ABSENT' if attempted else 'NOT_CREATED'
    except BaseException as error:
        report.update(status='REFUSED_OR_FAILED_HOST_AUDIO_CANDIDATE', cleanup_error=type(error).__name__)


def execute(args):
    C.need(os.geteuid() != 0, 'HOST_ORDINARY_USER_REQUIRED')
    profile = C.profile(HERE)
    host = C.host_contract(HERE)
    lifecycle = C.held(CHECKOUT / 'scripts/integration/lifecycle.py',
        profile['held_apis']['scripts/integration/lifecycle.py'], 'audio_host_bounded_lifecycle')
    output = args.output.absolute()
    for operand in (output, args.packet.absolute(), args.archive.absolute()):
        C.need('..' not in operand.parts and not any(p.is_symlink() for p in (operand, *operand.parents)), 'ALIASED_OPERAND')
    C.need(',' not in str(output), 'AMBIGUOUS_DOCKER_BIND_PATH')
    C.need(output.parent.is_dir() and output.parent.resolve() == output.parent, 'EXISTING_CANONICAL_OUTPUT_PARENT_REQUIRED')
    C.need(not output.exists() and not any(p.is_symlink() for p in (output, *output.parents)), 'FRESH_UNALIASED_OUTPUT_REQUIRED')
    C.need(not output.is_relative_to(args.packet.absolute()), 'OUTPUT_OVERLAPS_PACKET')
    output.mkdir(mode=0o700)
    report = dict(status='REFUSED_OR_FAILED_HOST_AUDIO_CANDIDATE', scope=profile['purpose'],
                  commands=[], host_installation=False, native_arm='NOT_RUN', physical_m2='NOT_RUN',
                  release='NOT_ADMITTED', publication='NOT_RUN', owned_container_retired=False,
                  profile_sha256=C.PROFILE_SHA)
    report['host_contract_sha256'] = C.HOST_CONTRACT_SHA
    name = 'cachy-asahi-audio-candidate-' + secrets.token_hex(8)
    nonce = secrets.token_hex(16)
    label = 'cachy-asahi.audio-candidate=' + nonce
    created = False
    creation_attempted = False

    def command(step, argv, allowed=(0,), timeout=30):
        result = lifecycle.bounded_process(argv, timeout=timeout, stdout_limit=256 * 1024,
            stderr_limit=256 * 1024, env=dict(os.environ, LC_ALL='C'))
        index = len(report['commands'])
        for stream in ('stdout', 'stderr'):
            path = output / f'{index:02d}-{step}-{stream}.log'; path.write_bytes(result[stream]); path.chmod(0o600)
        row = {k: v for k, v in result.items() if k not in ('stdout', 'stderr')}
        row.update(step=step, argv=list(map(str, argv)), expected=list(allowed))
        report['commands'].append(row)
        C.need(result['reason'] == 'exit' and result['returncode'] in allowed and result['cleanup']['reaped'], 'HOST_BOUNDED_COMMAND_REFUSED:' + step)
        return result['stdout']

    try:
        info = C.decode(command('daemon', ['docker', 'info', '--format',
            '{"architecture":{{json .Architecture}},"security":{{json .SecurityOptions}}}']))
        C.need(info['architecture'] == 'x86_64' and 'name=rootless' in info['security'], 'ACTUAL_ROOTLESS_X86_DAEMON_REQUIRED')
        image = C.decode(command('image', ['docker', 'image', 'inspect', profile['image_id'], '--format',
            '{"id":{{json .Id}},"architecture":{{json .Architecture}}}']))
        C.need(image == dict(id=profile['image_id'], architecture='amd64'), 'EXACT_EXISTING_IMAGE_REQUIRED')
        report.update(daemon=info, image=image)
        raw = C.read(args.archive)
        C.need(len(raw) == profile['package']['bytes'] and C.digest(raw) == profile['package']['sha256'], 'EXACT_TOOL_ARCHIVE_REQUIRED')
        checker_path = CHECKOUT / profile['package_checker']['path']
        checker_raw = C.read(checker_path)
        C.need(C.digest(checker_raw) == profile['package_checker']['sha256'], 'PACKAGE_CHECKER_PIN')
        checker = C.held(checker_path, dict(bytes=len(checker_raw), sha256=C.digest(checker_raw)), 'audio_original_package_checker')
        checker.archive(checker_path.parent, args.archive.absolute(), output / 'validated-archive-data')
        C.need(checker.payload(checker_path.parent) == profile['payload'], 'PROFILE_PAYLOAD_DIFFERS')
        snapshot = C.packet(args.packet)
        index = C.read(args.packet / 'delivery.json')
        C.need(C.digest(index) == profile['packet_index_sha256'], 'GENUINE_PACKET_INDEX_REQUIRED')
        actual = {n: dict(size=r['bytes'], sha256=r['sha256']) for n, r in snapshot.items() if r['kind'] == 'file' and n != 'delivery.json'}
        C.need(actual == C.decode(index)['files'], 'GENUINE_PACKET_FILE_SET_OR_BYTES_DIFFER')
        runner, inputs, guest = (output / n for n in ('runner', 'inputs', 'guest'))
        for path in (runner, inputs, guest):
            path.mkdir(mode=0o700)
        (runner / 'held').mkdir(mode=0o700)
        for operand in ('common.py', 'journey.py', 'profile.json', 'host_contract.py', 'host-contract-v2.json'):
            (runner / operand).write_bytes(C.read(HERE / operand))
        for path, pin in profile['held_apis'].items():
            raw_api = C.read(CHECKOUT / path, 128 * 1024)
            C.need(len(raw_api) == pin['bytes'] and C.digest(raw_api) == pin['sha256'], 'HELD_API_CHANGED')
            (runner / 'held' / Path(path).name).write_bytes(raw_api)
        (inputs / profile['package']['filename']).write_bytes(raw)
        (inputs / profile['package']['filename']).chmod(0o600)
        copy_packet(args.packet, inputs / 'packet', snapshot)
        runner_files = {p.relative_to(runner).as_posix(): C.digest(C.read(p, 128 * 1024))
                        for p in runner.rglob('*') if p.is_file()}
        contract = dict(nonce=nonce, image_id=profile['image_id'], producer_checkout=str(CHECKOUT),
                        host_uid=os.getuid(), host_gid=os.getgid(), runner_files=runner_files,
                        engine_host_config=dict(host['engine_host_config'], MaskedPaths=host['engine_masked_paths'],
                                                ReadonlyPaths=host['engine_readonly_paths']))
        raw_contract = C.encoded(contract); (inputs / 'contract.json').write_bytes(raw_contract)
        report.update(runner_files=runner_files, contract_sha256=C.digest(raw_contract))
        argv = ['docker', 'create', '--name', name, '--label', label, '--pull=never',
            '--platform=linux/amd64', '--user=0:0', '--read-only', '--network=none', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--pids-limit=128', '--memory=2g', '--cpus=2']
        # Exactly repository.py's unchanged six-cap mask, including copied-root ldconfig.
        for cap in ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETGID', 'SETUID', 'SYS_CHROOT'):
            argv += ['--cap-add=' + cap]
        for path, options in host['engine_host_config']['Tmpfs'].items():
            argv += ['--tmpfs', path + ':' + options]
        argv += [
            '--mount', f'type=bind,src={inputs},dst=/inputs,readonly',
            '--mount', f'type=bind,src={runner},dst=/runner,readonly',
            '--mount', f'type=bind,src={guest},dst=/out',
            '--env', 'CACHY_ASAHI_AUDIO_CANDIDATE=' + nonce,
            '--env', 'CACHY_ASAHI_IMAGE_ID=' + profile['image_id'],
            '--entrypoint=/usr/bin/python3', profile['image_id'], '-I', '-B', '/runner/journey.py',
            '--contract-sha256', C.digest(raw_contract)]
        creation_attempted = True
        command('create', argv); created = True
        observed = C.decode(command('created-identity', ['docker', 'inspect', name, '--format',
            '{"image":{{json .Image}},"label":{{json (index .Config.Labels "cachy-asahi.audio-candidate")}}}']))
        C.need(observed == dict(image=profile['image_id'], label=nonce), 'OWNED_CONTAINER_IDENTITY')
        engine = C.decode(command('engine-mount-resource-contract', ['docker', 'inspect', name, '--format', '{{json .HostConfig}}']))
        report['engine_host_config'] = H.engine(engine, host)
        H.binds(engine, {'/inputs': (str(inputs), True), '/runner': (str(runner), True), '/out': (str(guest), False)})
        report['exact_private_bind_sources_verified'] = True
        command('journey', ['docker', 'start', '--attach', name], allowed=(0, 1), timeout=180)
        state = C.decode(command('terminal-state', ['docker', 'inspect', name, '--format', '{{json .State}}']))
        C.need(not state['Running'] and not state['OOMKilled'] and state['ExitCode'] in (0, 1), 'TERMINAL_CONTAINER_STATE')
        report['terminal_state'] = {k: state[k] for k in ('Status', 'Running', 'OOMKilled', 'ExitCode')}
        result = C.decode(C.read(guest / 'result.json', 1024**2)); report['guest_result'] = result
        if state['ExitCode'] == 0 and result['status'] == 'PASS_HOST_PRIVATE_TEST_SIGNED_ALPM_JOURNEY':
            report['status'] = result['status']
        C.need(C.packet(args.packet) == snapshot, 'PRODUCER_PACKET_CHANGED')
        report['producer_packet_preserved'] = True
    except BaseException as error:
        report.update(status='REFUSED_OR_FAILED_HOST_AUDIO_CANDIDATE', error_type=type(error).__name__, error=str(error)[:512])
    finally:
        retire(report, command, creation_attempted, name, label, nonce, acknowledged=created)
        report['container_creation'] = 'ACKNOWLEDGED' if created else 'UNACKNOWLEDGED' if creation_attempted else 'NOT_ATTEMPTED'
        path = output / 'result.json'; path.write_bytes(C.encoded(report)); path.chmod(0o600)
    return report


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise KeyboardInterrupt('candidate interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('archive', 'packet', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    try:
        result = execute(parser.parse_args())
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(json.dumps(dict(status='REFUSED_AUDIO_CANDIDATE_INPUT', error_type=type(error).__name__)))
        sys.exit(2)
    print(json.dumps({k: result[k] for k in ('status', 'owned_container_retired', 'host_installation', 'native_arm')}))
    sys.exit(result['status'] != 'PASS_HOST_PRIVATE_TEST_SIGNED_ALPM_JOURNEY')
