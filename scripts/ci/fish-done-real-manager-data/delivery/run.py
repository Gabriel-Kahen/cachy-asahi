#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Construct a private CPU-only Mako/Fish trial from explicit retained native inputs."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
SYSTEM = {'fish': '/usr/bin/fish', 'busctl': '/usr/bin/busctl',
          'dbus_daemon': '/usr/bin/dbus-daemon', 'notify_send': '/usr/bin/notify-send',
          'timeout': '/usr/bin/timeout', 'bwrap': '/usr/bin/bwrap',
          'sleep': '/usr/bin/sleep', 'shell': '/usr/bin/bash',
          'python': str(Path(sys.executable).resolve()), 'pacman': '/usr/bin/pacman'}
TOOLS = set(SYSTEM) | {'sway', 'swaymsg', 'mako', 'makoctl'}
SHIPPED_STYLE = 'c6ab55ae475611bf2df2b7120b97a924eed5d65c149561d4da4f12b5b8c25504'
BASE_SHA256 = '9254d986922719ab694eb077428f9247f5caf23f4e419bcafc6be1e9aad4c1dc'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def inherited():
    """Reuse the retained native architecture, file and archive validators verbatim."""
    path = HERE/'native_inputs.py'
    need(not path.is_symlink() and sha(path.read_bytes()) == BASE_SHA256,
         'retained native input validator drift')
    spec = importlib.util.spec_from_file_location('done_native_inputs', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mapped_root(kind, mapping=None, overflow=None):
    need(kind in ('uid', 'gid'), 'exact namespace identity type required')
    text = Path('/proc/self/'+kind+'_map').read_text() if mapping is None else mapping
    rows = [tuple(map(int, line.split())) for line in text.splitlines()]
    need(0 < len(rows) <= 340 and all(len(row) == 3 and min(row) >= 0 and row[2] > 0
                                    for row in rows), 'finite namespace ID mapping required')
    for inside, outside, count in rows:
        if outside == 0:
            return inside
    return int(Path('/proc/sys/kernel/overflow'+kind).read_text()) if overflow is None else overflow


def installed(command, lock, root=Path('/'), owners=(0, 0)):
    need(command(['/usr/bin/pacman', '-Q', lock['name']]).strip() ==
         lock['name']+' '+lock['version'], 'exact ALPM installed version required')
    owned = set()
    for line in command(['/usr/bin/pacman', '-Ql', lock['name']]).splitlines():
        owner, path = line.split(' ', 1)
        need(owner == lock['name'], 'foreign ALPM owner')
        if not path.endswith('/'):
            owned.add(path.lstrip('/'))
    need(owned == set(lock['payload']), 'complete installed eight-file ownership required')
    result = {}
    for name, row in lock['payload'].items():
        p = root/name
        info = p.lstat()
        need(not any(q.is_symlink() for q in (p, *p.parents)) and
             stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid) == owners and
             stat.S_IMODE(info.st_mode) == row['mode'] and info.st_size == row['size'] and
             sha(p.read_bytes()) == row['sha256'], 'installed payload drift: '+name)
        result[name] = row['sha256']
    return dict(package=lock['name'], version=lock['version'], files=result,
                status='VERIFIED_ALPM_INSTALLED_PAYLOAD')


def preflight(inputs, expected, work, package_context):
    need(package_context in ('archive-staged', 'alpm-installed'), 'exact package context required')
    base = inherited()
    arch = base.native_architecture()
    need(os.getuid() != 0, 'ordinary native user required')
    pins = base.decode((HERE/'source-pins.json').read_bytes())
    need(set(pins) == {'run.py', 'controller.py', 'fish_terminal.py', 'monitor.py',
                      'observation.py', 'done-lock.json', 'native_inputs.py'}, 'complete fixed runtime source set required')
    sources = {name: base.ordinary(str(HERE/name), digest, 131072)[1]
               for name, digest in pins.items()}
    _, raw, _ = base.ordinary(inputs, expected, 32768)
    value = base.decode(raw)
    need(set(value) == {'schema_version', 'tools', 'libraries', 'mako_config',
                        'done_archive', 'source_metadata'} and
         type(value['schema_version']) is int and value['schema_version'] == 1,
         'exact CPU-only input schema required')
    need(type(value['tools']) is dict and set(value['tools']) == TOOLS and
         type(value['libraries']) is list and len(value['libraries']) <= 16 and
         type(value['source_metadata']) is dict and len(encoded(value['source_metadata'])) <= 8192,
         'finite tools/libraries/metadata required')
    need(value['source_metadata'].get('mako', {}).get('revision') ==
         '91c6b799855762ad1eb8b4498967c270a339be0c' and
         value['source_metadata']['mako'].get('version') == '1.11.0',
         'selected retained Mako source identity required')
    target = base.path(work)
    need(not target.exists() and not target.is_symlink() and target.parent.is_dir() and
         target.parent.stat().st_uid == os.getuid() and not target.parent.stat().st_mode & 0o022,
         'fresh work in owned non-public parent required')
    identities, total, imported = set(), 0, []

    def take(row, executable=False, aliases=(), limit=32*1024**2):
        nonlocal total
        need(type(row) is dict and set(row) == {'path', 'sha256'}, 'exact path/hash required')
        p, data, ident = base.ordinary(row['path'], row['sha256'], limit, executable, aliases, arch)
        need(ident not in identities and target not in p.parents and p not in target.parents,
             'alias or input/output overlap refused')
        identities.add(ident)
        total += len(data)
        need(total <= 128*1024**2, '128MiB explicit inputs cap')
        imported.append(p)
        return p, data

    tools, libraries = {}, {}
    for name, row in value['tools'].items():
        p, data = take(row, True, ('/usr/bin/fish', '/usr/bin/fish_indent',
                                  '/usr/bin/fish_key_reader') if name == 'fish' else ())
        if name in SYSTEM:
            need(str(p) == SYSTEM[name], 'fixed system tool required: '+name)
        tools[name] = (p, data)
    for row in value['libraries']:
        p, data = take(row)
        import re
        need(re.fullmatch(r'lib[A-Za-z0-9_.+-]+\.so(?:\.[0-9]+)*', p.name) and
             p.name not in libraries, 'unique ordinary native library required')
        base.native_elf(data, arch)
        libraries[p.name] = (p, data)
    _, style = take(value['mako_config'], limit=4096)
    need(sha(style) == SHIPPED_STYLE, 'unchanged shipped Mako style required')
    lock = base.decode(sources['done-lock.json'])
    _, archive = take(value['done_archive'], limit=65536)
    need(len(archive) == lock['bytes'] and sha(archive) == lock['sha256'],
         'exact retained Done pkgrel2 archive required')
    payload = base.archive(archive, lock)
    base.system_aliases()
    need(Path(SYSTEM['python']).is_relative_to('/usr'), 'read-only system Python required')
    installed_proof = None
    if package_context == 'alpm-installed':
        # These are read-only ALPM queries after all explicit inputs have passed.
        def query(argv):
            result = subprocess.run(argv, env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'},
                                    capture_output=True, timeout=5, check=True)
            need(len(result.stdout)+len(result.stderr) <= 65536, 'ALPM query output cap')
            return result.stdout.decode()
        installed_proof = installed(query, lock)
    return dict(arch=arch, inputs=value, inputs_sha256=expected, work=target,
                tools=tools, libraries=libraries, style=style, payload=payload,
                sources=sources, context=package_context, installed=installed_proof)


def stage(plan):
    work = plan['work']
    work.mkdir(mode=0o700)
    for name in ('home', 'runtime', 'tools', 'libs', 'diagnostic'):
        (work/name).mkdir(mode=0o700)
    inside = {}
    for name, (p, raw) in plan['tools'].items():
        dest = Path(SYSTEM[name]) if name in SYSTEM else Path('/work/tools')/name
        if name not in SYSTEM:
            (work/'tools'/name).write_bytes(raw)
            (work/'tools'/name).chmod(0o555)
        inside[name] = dict(path=str(dest), sha256=sha(raw))
    for name, (_, raw) in plan['libraries'].items():
        (work/'libs'/name).write_bytes(raw)
        (work/'libs'/name).chmod(0o444)
    for name, raw in plan['sources'].items():
        (work/'diagnostic'/name).write_bytes(raw)
        (work/'diagnostic'/name).chmod(0o444)
    for name, raw in plan['payload'].items():
        dest = work/'done'/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        dest.chmod(0o444)
    (work/'mako.conf').write_bytes(plan['style'])
    (work/'sway.conf').write_text('swaybg_command -\noutput * resolution 1024x768 position 0 0\n'
                                 'seat seat0 fallback true\nfocus_follows_mouse no\n')
    # Deliberately NO standard_session_servicedirs: cannot activate host services.
    (work/'bus.conf').write_text('<busconfig><type>session</type>'
        '<listen>unix:path=/work/runtime/bus</listen><auth>EXTERNAL</auth>'
        '<policy context="default"><allow own="*"/><allow send_destination="*"/>'
        '<allow receive_sender="*"/><allow eavesdrop="true"/></policy></busconfig>\n')
    bindings = dict(schema_version=1, native_arch=plan['arch'], inputs=plan['inputs'],
        source_metadata_qualification='CALLER_DECLARED_NOT_INDEPENDENT_BINARY_ATTESTATION',
        inputs_sha256=plan['inputs_sha256'], inside_tools=inside,
        libraries={name: sha(raw) for name, (_, raw) in plan['libraries'].items()},
        package_context=plan['context'], installed=plan['installed'],
        diagnostic_sources={name: sha(raw) for name, raw in plan['sources'].items()},
        renderer='CPU_PIXMAN_NO_DRM_OR_INPUT_DEVICES',
        scope='PRIVATE_REAL_MAKO_DELIVERY_ONLY_NO_HYPRLAND_M2_RELEASE_OR_PERFORMANCE')
    (work/'bindings.json').write_bytes(encoded(bindings))
    return bindings


def argv(plan):
    work = plan['work']
    command = [str(plan['tools']['bwrap'][0]), '--unshare-all', '--die-with-parent',
        '--new-session', '--clearenv', '--ro-bind', '/usr', '/usr', '--ro-bind', '/etc', '/etc',
        '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib', '/lib64', '--proc', '/proc', '--dev', '/dev',
        '--tmpfs', '/tmp', '--tmpfs', '/run', '--bind', str(work), '/work',
        '--ro-bind', str(work/'diagnostic'), '/inputs', '--chdir', '/work']
    if plan['context'] == 'alpm-installed':
        command += ['--ro-bind', '/var/lib/pacman', '/var/lib/pacman']
    env = dict(PATH='/usr/bin', HOME='/work/home', XDG_RUNTIME_DIR='/work/runtime',
        XDG_CONFIG_HOME='/work/home/config', XDG_CACHE_HOME='/work/home/cache',
        LANG='C.UTF-8', PYTHONDONTWRITEBYTECODE='1', CACHY_NATIVE_UID=str(os.getuid()))
    for key, value in env.items():
        command += ['--setenv', key, value]
    return command+['--', SYSTEM['python'], '-I', '-B', '/inputs/controller.py']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--work-dir', required=True)
    parser.add_argument('--package-context', choices=('archive-staged', 'alpm-installed'),
                        default='alpm-installed')
    parser.add_argument('--validate-only', action='store_true')
    args = parser.parse_args()
    plan = preflight(args.inputs, args.inputs_sha256, args.work_dir, args.package_context)
    if args.validate_only:
        print('VALIDATED_NO_SESSION_ACTORS_OR_WORK_CREATED')
        return 0
    stage(plan)
    command = argv(plan)
    started = time.monotonic()
    process = subprocess.Popen(command, env={'PATH': '/usr/bin'}, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    out, err = b'', b''
    try:
        out, err = process.communicate(timeout=180)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = process.communicate(timeout=5)
        raise
    finally:
        (plan['work']/'outer.stdout').write_bytes(out)
        (plan['work']/'outer.stderr').write_bytes(err)
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            absent = True
        else:
            absent = False
        (plan['work']/'outer.json').write_bytes(encoded(dict(argv=command, pid=process.pid,
            exit=process.returncode, process_group_absent=absent,
            elapsed_seconds=time.monotonic()-started)))
    need(process.returncode == 0 and absent, 'isolated trial failed; retained outer evidence')
    result = json.loads((plan['work']/'result.json').read_bytes())
    need(result['status'] == 'PASS_PRIVATE_REAL_MAKO_TRIAL', 'trial refused; see result.json')
    print(json.dumps(dict(status=result['status'], cases=len(result['cases']),
                         package_context=result['package_context'])))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
