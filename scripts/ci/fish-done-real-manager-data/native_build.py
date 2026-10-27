#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run only inside Root's offline ordinary-user immutable native574 consumer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from construct import archive, encoded, need, read, sha
import reserved_process as R

HERE = Path(__file__).resolve().parent
MODULES = ['wayland-server', 'wayland-client', 'wayland-cursor', 'wayland-scanner',
           'wayland-protocols', 'libdrm', 'xkbcommon', 'pixman-1', 'json-c',
           'libpcre2-8', 'cairo', 'pango', 'pangocairo', 'libevdev', 'libsystemd']


def guard():
    need(platform.system() == 'Linux' and platform.machine() == 'aarch64' and
         os.geteuid() != 0, 'actual ordinary native Linux aarch64 required')
    need(os.environ.get('CACHY_ASAHI_NATIVE_HEADLESS_BUILD') == '1' and
         Path('/.dockerenv').is_file(), 'explicit owned native consumer marker required')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(int(status['CapEff'].strip(), 16) == 0 and status['NoNewPrivs'].strip() == '1',
         'capability-free no-new-privileges consumer required')
    need(os.statvfs('/').f_flag & os.ST_RDONLY and os.statvfs('/usr').f_flag & os.ST_RDONLY,
         'readonly native base required')
    interfaces = [line.split(':')[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    need(interfaces == ['lo'], 'offline loopback-only native consumer required')
    need(not Path('/dev/dri').exists() and not Path('/dev/input').exists() and
         not Path('/run/user').exists(), 'GPU/input/live desktop mounts refused')
    need(not any(os.environ.get(key) for key in ('DISPLAY', 'WAYLAND_DISPLAY',
         'DBUS_SESSION_BUS_ADDRESS', 'LD_PRELOAD', 'WAYLAND_DEBUG', 'G_DBUS_DEBUG')),
         'inherited desktop or injection environment refused')


def elf(raw, *, aligned=False):
    need(len(raw) >= 64 and raw[:6] == b'\x7fELF\x02\x01' and
         struct.unpack_from('<H', raw, 18)[0] == 183, 'native AArch64 ELF64 required')
    if aligned:
        offset = struct.unpack_from('<Q', raw, 32)[0]
        size, count = struct.unpack_from('<HH', raw, 54)
        need(size == 56 and 0 < count <= 128 and offset+size*count <= len(raw), 'bounded ELF program headers required')
        loads = 0
        for i in range(count):
            fields = struct.unpack_from('<IIQQQQQQ', raw, offset+i*size)
            if fields[0] == 1:
                loads += 1
                need(fields[7] >= 16384 and fields[2] % 16384 == fields[3] % 16384 and
                     fields[2]+fields[5] <= len(raw), '16KiB aligned PT_LOAD required')
        need(loads > 0, 'ELF load segments required')


def plan(output, lock, context=HERE):
    output, context = Path(output), Path(context)
    common = ['--prefix='+str(output/'prefix'), '--libdir=lib', '--native-file='+str(context/'no-git.native')]
    result = []
    for name in ('wlroots', 'sway'):
        result.append(['/usr/bin/meson', 'setup', str(output/'build'/name), str(output/'sources'/name)] +
                      common+lock['build_options'][name])
        result.append(['/usr/bin/ninja', '-C', str(output/'build'/name), '-j2'])
        if name == 'wlroots':
            # Private headers/pkgconfig are needed to compile Sway against this build.
            result.append(['/usr/bin/meson', 'install', '-C', str(output/'build'/name), '--no-rebuild'])
    return result


def environment(output, epoch):
    return dict(PATH='/usr/bin', HOME=str(output/'home'), TMPDIR=str(output/'tmp'),
        LANG='C.UTF-8', LC_ALL='C.UTF-8', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1',
        CC='/usr/bin/gcc', AR='/usr/bin/ar',
        PKG_CONFIG_PATH=str(output/'prefix/lib/pkgconfig'),
        PKG_CONFIG_LIBDIR='/usr/lib/pkgconfig:/usr/share/pkgconfig',
        LD_LIBRARY_PATH=str(output/'prefix/lib'),
        CFLAGS='-O2 -ffile-prefix-map='+str(output)+'=/build/native-headless',
        LDFLAGS='-Wl,-z,max-page-size=0x4000', SOURCE_DATE_EPOCH=str(epoch),
        MESON_FORCE_BACKTRACE='1')


class Commands:
    def __init__(self, output, env):
        self.output, self.env, self.rows = output, env, []
        self.deadline = time.monotonic()+1200

    def __call__(self, argv, seconds=300):
        seconds = min(seconds, self.deadline-time.monotonic())
        need(seconds > 0, 'overall native build command budget expired')
        number = len(self.rows)+1
        log = self.output/f'command-{number}.log'
        row = dict(argv=argv, log=log.name)
        self.rows.append(row)
        started = time.monotonic()
        with log.open('xb') as stream:
            receipt = R.run(argv, seconds, cwd=self.output, env=self.env,
                            stdout=stream, stderr=subprocess.STDOUT,
                            term_seconds=3, kill_seconds=2)
        row.update(pid=receipt['pid'], exit=receipt['exit'],
                   group_absent=receipt['group_absent'], supervision=receipt,
                   seconds=time.monotonic()-started)
        (self.output/'commands.json').write_bytes(encoded(self.rows))
        need(log.stat().st_size <= 256*1024, 'bounded build command log required')
        raw = log.read_bytes()
        row.update(bytes=len(raw), sha256=sha(raw))
        (self.output/'commands.json').write_bytes(encoded(self.rows))
        need(receipt['completed'] is True and not receipt['timed_out'] and
             receipt['retirement'] == 'VERIFIED_ABSENT' and
             row['exit'] == 0 and row['group_absent'] is True,
             'native command failed or retirement unknown: '+receipt['retirement'])
        R.assert_verified(receipt)
        return raw.decode('utf-8')


def closure(paths, command, prefix):
    """Read ELF metadata only; never use ldd or execute the new binaries."""
    queue, result = list(paths), {}
    while queue:
        path = queue.pop(0).resolve()
        if str(path) in result:
            continue
        need(len(result) < 256 and (path.is_relative_to(prefix) or path.is_relative_to('/usr/lib') or
                                   path.is_relative_to(prefix.parent/'tools') or
                                   path.is_relative_to(prefix.parent/'libs')), 'bounded native library closure required')
        raw = path.read_bytes()
        elf(raw)
        text = command(['/usr/bin/readelf', '--dynamic', str(path)], 10)
        needed = re.findall(r'\(NEEDED\).*?Shared library: \[([^\]]+)\]', text)
        result[str(path)] = dict(bytes=len(raw), sha256=sha(raw), needed=needed)
        for name in needed:
            need(re.fullmatch(r'[A-Za-z0-9_.+-]+', name), 'ordinary library SONAME required')
            choices = [p for p in (prefix/'lib'/name, Path('/usr/lib')/name) if p.is_file()]
            need(choices, 'unavailable actual DT_NEEDED library: '+name)
            queue.append(choices[0])
    return result


def trial_inputs(output, lock, command):
    tools = {name: str(output/'tools'/name) for name in ('sway', 'swaymsg')}
    tools.update(mako='/usr/bin/mako', makoctl='/usr/bin/makoctl', fish='/usr/bin/fish',
        busctl='/usr/bin/busctl', dbus_daemon='/usr/bin/dbus-daemon', notify_send='/usr/bin/notify-send',
        timeout='/usr/bin/timeout', bwrap='/usr/bin/bwrap', sleep='/usr/bin/sleep', shell='/usr/bin/bash',
        python=str(Path(sys.executable).resolve()), pacman='/usr/bin/pacman')
    for name, path in tools.items():
        raw = Path(path).read_bytes()
        elf(raw)
        if path in lock['native_mako_payload']:
            need(sha(raw) == lock['native_mako_payload'][path], 'selected retained native Mako payload differs')
    value = dict(schema_version=1, tools={name: dict(path=path, sha256=sha(Path(path).read_bytes()))
                                         for name, path in tools.items()},
        libraries=[dict(path=str(output/'libs/libwlroots-0.19.so'),
                        sha256=sha((output/'libs/libwlroots-0.19.so').read_bytes()))],
        mako_config=dict(path=str(HERE/'mako.conf'), sha256=sha((HERE/'mako.conf').read_bytes())),
        done_archive=dict(path=str(HERE/'done.pkg.tar.xz'), sha256=sha((HERE/'done.pkg.tar.xz').read_bytes())),
        source_metadata=dict(mako=dict(version='1.11.0', revision='91c6b799855762ad1eb8b4498967c270a339be0c'),
            sway=lock['sources']['sway'], wlroots=lock['sources']['wlroots'],
            qualification='NATIVE_BUILD_RECORDED_SEPARATELY_FROM_ALPM_INSTALLED_DELIVERY'))
    (output/'trial-inputs.json').write_bytes(encoded(value))
    return dict(inputs_sha256=sha((output/'trial-inputs.json').read_bytes()),
        command=['/usr/bin/python', '-I', '-B', str(HERE/'delivery/run.py'),
                 '--inputs', str(output/'trial-inputs.json'), '--inputs-sha256', sha(encoded(value)),
                 '--work-dir', str(output/'installed-delivery'), '--package-context', 'alpm-installed'],
        prerequisite='Root installs exact retained Done package into a separate derived disposable image; never this constructor',
        delivery='NOT_RUN')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    guard()  # Must precede all commands, extraction and output creation.
    output = args.output
    need(output.is_absolute() and not output.exists() and output.parent.is_dir() and
         output.parent.stat().st_uid == os.getuid() and
         not any(p.is_symlink() for p in (output, *output.parents)), 'fresh private native output required')
    context = json.loads((HERE/'context.json').read_bytes())
    for name, row in context['files'].items():
        read(HERE/name, row['sha256'], 8*1024**2)
    lock = json.loads((HERE/'build.lock.json').read_bytes())
    output.mkdir(mode=0o700)
    for name in ('home', 'tmp', 'sources', 'build', 'tools', 'libs', 'licenses'):
        (output/name).mkdir(mode=0o700)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64*1024**2, 64*1024**2))
    command = Commands(output, environment(output, lock['base']['source_date_epoch']))
    report = dict(status='FAIL_NATIVE_HEADLESS_DEPENDENCY_BUILD', hardware='NOT_RUN',
        installed_delivery='NOT_RUN', page_size=os.sysconf('SC_PAGE_SIZE'), native_arch=platform.machine(), errors=[],
        context_sha256=sha((HERE/'context.json').read_bytes()), sources=lock['sources'], base=lock['base'])
    try:
        inventory = command(['/usr/bin/pacman', '-Q'], 10)
        need(inventory == (HERE/'inventory574.lock').read_text(), 'exact installed574 inventory required')
        report['build_tools'] = {}
        for name in ('gcc', 'as', 'ld', 'ninja', 'readelf', 'pkgconf', 'python', 'meson'):
            path = (Path('/usr/bin')/name).resolve()
            raw = path.read_bytes()
            if name != 'meson':
                elf(raw)
            else:
                need(raw.startswith(b'#!/usr/bin/python'), 'known system Meson Python entrypoint required')
            report['build_tools'][name] = dict(path=str(path), bytes=len(raw), sha256=sha(raw))
        for name, row in lock['sources'].items():
            raw = read(HERE/row['filename'], row['sha256'], 8*1024**2)
            actual = archive(raw, row, output/'sources'/name)
            need(actual == context['source_trees'][name], 'original source tree differs')
        report['dependency_versions'] = command(['/usr/bin/pkgconf', '--modversion', *MODULES], 15)
        report['commands_planned'] = plan(output, lock)
        for argv in report['commands_planned']:
            command(argv, 300)
        origins = {'tools/sway': output/'build/sway/sway/sway',
                   'tools/swaymsg': output/'build/sway/swaymsg/swaymsg',
                   'libs/libwlroots-0.19.so': output/'prefix/lib/libwlroots-0.19.so'}
        report['outputs'] = {}
        for name, origin in origins.items():
            raw = origin.read_bytes()
            elf(raw, aligned=True)
            dest = output/name
            dest.write_bytes(raw)
            dest.chmod(0o555 if name.startswith('tools/') else 0o444)
            report['outputs'][name] = dict(bytes=len(raw), sha256=sha(raw), elf_machine=183,
                                           load_alignment='AT_LEAST_16384')
        for name in ('wlroots', 'sway'):
            shutil.copyfile(output/'sources'/name/'LICENSE', output/'licenses'/(name+'.MIT'))
        report['elf_closure'] = closure([output/name for name in origins], command, output/'prefix')
        need(command(['/usr/bin/pacman', '-Q'], 10) == inventory, 'build changed installed inventory')
        report['next_installed_trial'] = trial_inputs(output, lock, command)
        report['status'] = 'PASS_NATIVE_AARCH64_HEADLESS_DEPENDENCY_BUILD_ONLY'
    except BaseException as error:
        report['errors'].append(type(error).__name__+': '+str(error))
    finally:
        report['commands'] = command.rows
        (output/'native-build-result.json').write_bytes(encoded(report))
    print(json.dumps(dict(status=report['status'], errors=report['errors'])))
    return 0 if report['status'].startswith('PASS_') else 1


if __name__ == '__main__':
    raise SystemExit(main())
