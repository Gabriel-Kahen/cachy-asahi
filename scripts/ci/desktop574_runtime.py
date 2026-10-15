#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Same-job native574 configuration and generic QEMU software session exercise."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time

ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
PREFIX = 'DESKTOP574_EVENT '


def require(ok, message):
    if not ok:
        raise ValueError(message)


def inventory(text):
    rows = [line.split() for line in text.splitlines()]
    require(rows and all(len(row) == 2 for row in rows), 'invalid inventory')
    result = dict(rows)
    require(len(result) == len(rows), 'duplicate inventory names')
    return result


def additions(base, tooling):
    rows = tooling['packages']
    require(len({row['name'] for row in rows}) == len(rows), 'duplicate tooling')
    # Existing newer packages are preserved, never downgraded to old tooling pins.
    return [row for row in rows if row['name'] not in base]


def ppm(path):
    data = path.read_bytes()
    header = re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\s', data)
    require(header is not None, 'invalid QMP PPM')
    width, height = map(int, header.groups())
    pixels = data[header.end():]
    require((width, height) == (1024, 768) and len(pixels) == width * height * 3,
            'unexpected/truncated QMP frame')
    require(any(pixels[i:i + 3] != pixels[:3] for i in range(0, len(pixels), 3)), 'uniform QMP frame')
    return {'width': width, 'height': height,
            'sha256': hashlib.sha256(data).hexdigest()}


def log_complete(collector, path, offset):
    """Join the final output drain before treating a child exit as log EOF."""
    if collector.process.poll() is None:
        return False
    collector.finish()
    return path.stat().st_size == offset


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def docker_args(image, name, out, source, runner, *, root=False):
    args = ['docker', 'run', '--name', name, '--pull=never', '--network=none',
            '--platform=linux/arm64', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--read-only', '--pids-limit=512', '--memory=6g', '--cpus=4',
            '--user', '0:0' if root else f'{os.getuid()}:{os.getgid()}',
            '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=1g',
            '--mount', f'type=bind,src={out},dst=/out',
            '--mount', f'type=bind,src={source},dst=/source,readonly',
            '--mount', f'type=bind,src={runner},dst=/runner,readonly']
    if root:
        args += ['--cap-add=CHOWN', '--cap-add=DAC_OVERRIDE', '--cap-add=FOWNER', '--cap-add=FSETID']
    return args + ['--entrypoint=/bin/bash', image]


def qemu_command(image, name, out, source, runner):
    """Keep QEMU snapshot files on the container's existing private tmpfs."""
    cmd = docker_args(image, name, out, source, runner)
    cmd[-2:-2] = ['--env=TMPDIR=/tmp']
    cmd += ['-c', 'exec qemu-system-aarch64 -nodefaults -machine virt-11.1 -accel tcg -cpu max -smp 2 -m 4096 -kernel /out/Image -append "console=ttyAMA0 root=/dev/vda rw systemd.unit=desktop574.target cachy_asahi_desktop574=1 cachy_asahi_virtual_proof=1" -drive if=none,id=root,file=/out/guest.raw,format=raw,snapshot=on -device virtio-blk-pci,drive=root -device virtio-gpu-pci,id=gpu,xres=1024,yres=768 -nic none -display none -audiodev none,id=noaudio -monitor none -serial stdio -qmp unix:/out/qmp.sock,server=on,wait=off']
    return cmd


def bind_local_base(image, reference, execute, inspect):
    """BuildKit FROM needs a named local image; bind it to the checked ID."""
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', image), 'immutable base ID required')
    require(re.fullmatch(r'cachy-asahi-desktop574-base:[0-9a-f]{32}', reference), 'owned base reference required')
    execute(['docker', 'image', 'tag', image, reference], 'base-reference', 30)
    require(inspect(['docker', 'image', 'inspect', '--format', '{{.Id}}', reference]) == image,
            'local base reference differs from selected image')
    return reference


def release_local_base(image, reference, cleanup):
    """Remove only the owned tag after all base consumers; never force-remove IDs."""
    found = cleanup(['docker', 'image', 'ls', '--no-trunc', '-q', '--filter',
                     'reference=' + reference], 'check-base-alias')
    if found is None:
        return {'ok': False, 'base_image_present': None}
    if found.strip():
        if set(found.decode().splitlines()) != {image}:
            return {'ok': False, 'base_image_present': None, 'error': 'base alias changed; not removed'}
        if cleanup(['docker', 'image', 'rm', '--no-prune', reference], 'remove-base-alias') is None:
            return {'ok': False, 'base_image_present': None}
    remaining = cleanup(['docker', 'image', 'ls', '--no-trunc', '-q', '--filter',
                         'reference=' + reference], 'check-base-alias-absent')
    images = cleanup(['docker', 'image', 'ls', '--no-trunc', '-q'], 'check-base-image-after-alias')
    return {'ok': remaining is not None and not remaining.strip() and images is not None,
            'base_image_present': image in images.decode().splitlines() if images is not None else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--base-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, base_dir, out = (p.resolve() for p in (args.source, args.base_dir, args.output))
    require(not out.exists() and os.getuid() != 0, 'fresh output and nonroot controller required')
    require(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64'), 'native ARM required')
    out.mkdir(mode=0o700)
    (out / 'home').mkdir(mode=0o700)
    os.environ.clear()
    os.environ.update(ENV, HOME=str(out / 'home'))
    sys.path.insert(0, str(source / 'scripts/virtual'))
    common = load('desktop574_common', source / 'scripts/virtual/common.py')
    virtual = load('desktop574_qmp', source / 'scripts/virtual/run.py')
    hosted = load('desktop574_inputs', source / 'scripts/ci/maintained_desktop574.py')
    report = {'status': 'FAIL', 'hardware_validation': 'NOT_RUN', 'graphics_acceleration': 'NOT_RUN',
              'commands': [], 'frames': {}, 'events': [], 'cleanup': []}
    containers, images, active = [], [], None
    base_reference = None
    def execute(argv, label, seconds=300):
        nonlocal active
        report['commands'].append({'argv': argv, 'log': label + '.log'})
        active = common.LoggedProcess(argv, out / (label + '.log'), env=dict(os.environ), limit=16 * 1024**2)
        try:
            code = active.process.wait(timeout=seconds)
            active.finish()
            require(code == 0 and active.error is None, 'command failed: ' + label)
        finally:
            if active is not None:
                if active.process.poll() is None:
                    os.killpg(active.process.pid, signal.SIGKILL)
                    active.process.wait(timeout=5)
                active.finish()
                active = None
    def text_command(argv):
        return subprocess.check_output(argv, text=True, env=dict(os.environ), timeout=30).strip()
    def interrupted(*_):
        raise TimeoutError('runtime cancelled/deadline')
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM)}
    # Reserve at least five minutes inside the outer 2050s limit for cleanup.
    signal.setitimer(signal.ITIMER_REAL, 1750)
    qmp = None
    try:
        require(text_command(['docker', 'info', '--format', '{{.Architecture}}']) in ('aarch64', 'arm64'), 'ARM daemon required')
        original = json.loads((base_dir / 'report.json').read_text())
        require(original.get('status') == 'PASS_NATIVE_OFFLINE_574_TRANSACTION', 'successful574 transaction required')
        image = (base_dir / 'image-id').read_text().strip()
        require(re.fullmatch('sha256:[0-9a-f]{64}', image) and original.get('image') == image, 'base image differs')
        require(text_command(['docker', 'image', 'inspect', '--format', '{{.Os}}/{{.Architecture}}', image]) == 'linux/arm64', 'base image architecture differs')
        base_lock = base_dir / 'installed-packages.lock'
        base = inventory(base_lock.read_text())
        selected = json.loads((source / 'scripts/ci/maintained-desktop574-inputs.json').read_text())
        require(len(base) == 574 and base == {r['name']: r['version'] for r in selected['packages']}, '574 inventory differs')
        observed = inventory(text_command(['docker', 'run', '--rm', '--pull=never', '--network=none',
            '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--entrypoint=/usr/bin/pacman', image, '-Q']))
        require(observed == base, 'actual base inventory differs')
        recipe_dir = source / 'packages/desktop/cachy-asahi-hyprland-settings'
        checks = load('desktop574_package_checks', source / 'scripts/checks/package_checks.py')
        recipe = checks.recipe(recipe_dir / 'PKGBUILD')
        require(not recipe['errors'], 'invalid desktop recipe')
        review = out / 'recipe-inputs.json'
        review.write_text(json.dumps(recipe['input_sha256']) + '\n')
        execute([sys.executable, str(source / 'scripts/build/build.py'), str(recipe_dir), '--image', image,
            '--mode', 'native', '--source-date-epoch', str(selected['source_date_epoch']),
            '--expected-packages', str(base_lock), '--reviewed-inputs', str(review),
            '--output', str(out / 'package'), '--timeout', '300'], 'package-build', 330)
        archives = list((out / 'package/artifacts').glob('*.pkg.tar.*'))
        require(len(archives) == 1, 'one desktop archive required')
        context = out / 'context'; context.mkdir()
        packages = context / 'tooling'; packages.mkdir()
        tooling = json.loads((source / 'scripts/virtual/tooling.lock.json').read_text())
        extra = additions(base, tooling)
        require(len(extra) == 16, 'review the changed tooling extension')
        for row in extra:
            for sig in (False, True):
                name = row['filename'] + ('.sig' if sig else '')
                hosted.fetch({'filename': name, 'target': packages / name,
                    'url': row['url'] + ('.sig' if sig else ''),
                    'size': row['signature_size' if sig else 'size'],
                    'sha256': row['signature_sha256' if sig else 'sha256']})
        shutil.copyfile(archives[0], context / 'desktop.pkg.tar.zst')
        project_version = recipe['metadata']['pkgver'][0] + '-' + recipe['metadata']['pkgrel'][0]
        expected = base | {r['name']: r['version'] for r in extra} | {'cachy-asahi-hyprland-settings': project_version}
        (context / 'expected.lock').write_text(''.join(f'{n} {v}\n' for n, v in sorted(expected.items())))
        # Only this exact locally built project archive uses the local unsigned policy.
        (context / 'project.conf').write_text(hosted.PACMAN.replace('LocalFileSigLevel = Required', 'LocalFileSigLevel = Optional'))
        base_reference = 'cachy-asahi-desktop574-base:' + os.urandom(16).hex()
        bind_local_base(image, base_reference, execute, text_command)
        report['base_reference'] = base_reference
        (context / 'Dockerfile').write_text(f'FROM {base_reference}\nCOPY tooling/ /tmp/tooling/\nCOPY desktop.pkg.tar.zst /tmp/project/desktop.pkg.tar.zst\nCOPY project.conf /tmp/project.conf\nCOPY expected.lock /expected-runtime.lock\nRUN pacman -U --noconfirm --noscriptlet /tmp/tooling/*.pkg.tar.xz && pacman -U --noconfirm --noscriptlet --config /tmp/project.conf /tmp/project/desktop.pkg.tar.zst && ldconfig && pacman -Q | LC_ALL=C sort > /runtime-packages.lock && cmp /expected-runtime.lock /runtime-packages.lock && rm -rf /tmp/tooling /tmp/project /tmp/project.conf\n')
        iid = out / 'runtime-image-id'
        execute(['docker', 'build', '--network=none', '--pull=false', '--iidfile', str(iid), str(context)], 'runtime-image', 300)
        derived = iid.read_text().strip()
        require(re.fullmatch('sha256:[0-9a-f]{64}', derived) and derived != image, 'invalid derivative image')
        images.append(derived)
        report.update(base_image=image, runtime_image=derived, runtime_package_count=len(expected))
        inputs = out / 'inputs'; inputs.mkdir()
        shutil.copyfile(archives[0], inputs / archives[0].name)
        (inputs / 'base.lock').write_text(''.join(f'{n} {v}\n' for n, v in sorted(expected.items()) if n != 'cachy-asahi-hyprland-settings'))
        verifier = out / 'verifier'; verifier.mkdir()
        shutil.copyfile(source / 'scripts/integration/desktop.py', verifier / 'desktop.py')
        result = out / 'config'; result.mkdir()
        nonce = os.urandom(16).hex(); name = 'desktop574-config-' + nonce; containers.append(name)
        cmd = docker_args(derived, name, result, source, verifier)
        cmd[-2:-2] = ['--mount', f'type=bind,src={inputs},dst=/inputs,readonly',
             '--env=CACHY_ASAHI_INTEGRATION_CONTAINER=1', '--env=CACHY_ASAHI_DISPOSABLE_DESKTOP=' + nonce,
             '--env=CACHY_ASAHI_IMAGE_ID=' + derived]
        # Verifier requires its runner at /runner/desktop.py and fresh /out/desktop.
        execute(cmd + ['-c', 'exec python3 -B /runner/desktop.py --package /inputs/' + archives[0].name +
            ' --package-sha256 ' + hosted.digest(archives[0]) +
            ' --runtime-lock /inputs/base.lock --output /out/desktop'], 'configuration', 300)
        report['configuration'] = json.loads((result / 'desktop/desktop.json').read_text())['status']
        runner = Path(__file__).resolve().parent
        fixture = out / 'fixture'; fixture.mkdir()
        name = 'desktop574-fixture-' + os.urandom(8).hex(); containers.append(name)
        cmd = docker_args(derived, name, fixture, source, runner, root=True)
        cmd[-2:-2] = ['--env=CACHY_DESKTOP574_FIXTURE=1']
        execute(cmd + ['/runner/desktop574_fixture.sh'], 'fixture', 600)
        name = 'desktop574-vm-' + os.urandom(8).hex(); containers.append(name)
        cmd = qemu_command(derived, name, fixture, source, runner)
        frames = out / 'frames'; frames.mkdir()
        active = common.LoggedProcess(cmd, out / 'guest.log', env=dict(os.environ), limit=8 * 1024**2)
        pending = b''; offset = 0; complete = False; phases = set(); deadline = time.monotonic() + 700
        while time.monotonic() < deadline:
            if qmp is None and (fixture / 'qmp.sock').exists():
                qmp = virtual.QMP(fixture / 'qmp.sock')
            with (out / 'guest.log').open('rb') as stream:
                stream.seek(offset); data = stream.read(); offset += len(data)
            pending += data
            while b'\n' in pending:
                raw, pending = pending.split(b'\n', 1)
                line = raw.decode(errors='replace').strip()
                if not line.startswith(PREFIX):
                    continue
                event = json.loads(line[len(PREFIX):]); report['events'].append(event)
                if event.get('event') == 'frame_ready':
                    stage = event.get('stage')
                    require(stage in ('minimal', 'overlay') and stage not in report['frames'] and qmp is not None, 'invalid frame stage')
                    qmp.execute('screendump', {'filename': '/out/' + stage + '.ppm'})
                    report['frames'][stage] = ppm(fixture / (stage + '.ppm'))
                    shutil.copyfile(fixture / (stage + '.ppm'), frames / (stage + '.ppm'))
                if event.get('event') == 'phase_pass': phases.add(event.get('stage'))
                if event.get('event') == 'complete': complete = event.get('status') == 'PASS'
                require(event.get('event') not in ('failed', 'failure'), 'guest failed; inspect guest.log')
            require(active.error is None, 'guest log capture failed')
            if log_complete(active, out / 'guest.log', offset):
                break
            time.sleep(.1)
        require(active.process.poll() == 0 and complete and phases == {'minimal', 'overlay'} and
                set(report['frames']) == phases, 'guest session incomplete; inspect guest.log')
        active.finish(); active = None
        report['status'] = 'PASS_NATIVE_CONFIGURATION_AND_GENERIC_SOFTWARE_SESSION'
    except Exception as error:
        report.update(error_type=type(error).__name__, error=str(error))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for sig in previous: signal.signal(sig, signal.SIG_IGN)
        if qmp is not None:
            try: qmp.close()
            except Exception: report['status'] = 'FAIL_CLEANUP'
        def cleanup(argv, label):
            try:
                done = subprocess.run(argv, env=dict(os.environ), stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, timeout=30)
                row = {'action': label, 'exit': done.returncode}
                require(done.returncode == 0, 'cleanup command failed')
                return done.stdout
            except Exception as error:
                row = {'action': label, 'error': type(error).__name__}
                report['status'] = 'FAIL_CLEANUP'
                return None
            finally:
                report['cleanup'].append(row)
        for name in reversed(containers):
            cleanup(['docker', 'rm', '-f', name], 'remove-container:' + name)
            found = cleanup(['docker', 'container', 'ls', '-aq', '--filter', 'name=^/' + name + '$'], 'check-container:' + name)
            if found is not None and found.strip(): report['status'] = 'FAIL_CLEANUP'
        if active is not None:
            try:
                try: os.killpg(active.process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                active.process.wait(timeout=5); active.finish()
            except Exception as error:
                report['cleanup'].append({'active_process': type(error).__name__})
                report['status'] = 'FAIL_CLEANUP'
        for owned_image in images:
            cleanup(['docker', 'image', 'rm', owned_image], 'remove-image:' + owned_image)
        fixture = out / 'fixture'
        if fixture.exists():
            try:
                # Files were created by fixture root. Use its image for owned deletion;
                # no general host sudo and no delete outside the one mounted directory.
                if any(fixture.iterdir()) and images:
                    cleaner = 'desktop574-clean-' + os.urandom(8).hex()
                    cleanup(['docker', 'run', '--name', cleaner, '--pull=never', '--network=none',
                        '--cap-drop=ALL', '--cap-add=DAC_OVERRIDE', '--cap-add=FOWNER', '--security-opt=no-new-privileges',
                        '--read-only', '--user=0:0', '--mount', f'type=bind,src={fixture},dst=/owned',
                        '--entrypoint=/bin/sh', original['image'], '-c', 'find /owned -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +'], 'remove-fixture')
                    cleanup(['docker', 'rm', '-f', cleaner], 'remove-cleaner')
                fixture.rmdir()
                report['cleanup'].append({'guest_disk_removed': True})
            except Exception as error:
                report['cleanup'].append({'guest_disk_removed': False, 'error': type(error).__name__})
                report['status'] = 'FAIL_CLEANUP'
        if base_reference is not None:
            released = release_local_base(image, base_reference, cleanup)
            report['base_reference_cleanup'] = released
            if not released['ok']: report['status'] = 'FAIL_CLEANUP'
        (out / 'runtime.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2), flush=True)
        for sig, handler in previous.items(): signal.signal(sig, handler)
    return 0 if report['status'] == 'PASS_NATIVE_CONFIGURATION_AND_GENERIC_SOFTWARE_SESSION' else 1


if __name__ == '__main__':
    raise SystemExit(main())
