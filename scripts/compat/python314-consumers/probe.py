#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline, ordinary-user CPython candidate consumers; writes only a fresh output."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import tomllib

HERE = Path(__file__).resolve().parent
REPORT_SHA = 'e83a377b23fb602c8e076b3a16eae81c356af9b209359f7089f1f7769529e1ef'
FULL_ARCHIVE_SHA = '8474bf623e6efe46f02ef5dd65b7707b2f526a7a612661b33819920e451b016e'
FULL_REPORT_SHA = 'd3f75b5f6217d55859db5e59818379a999e8e2454ea1f3f21ee23b7095073c67'
SOURCE_SHA = 'c2215904f02b175596dc49351585104f4bc20341e1c47378b26a2c274360ce73'


class Refusal(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise Refusal(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inventory(root):
    """Seal regular bytes/modes and relative internal links; no sockets/devices."""
    result, size = {}, 0
    paths = sorted(root.rglob('*'))
    require(len(paths) <= 5000, 'stage path bound exceeded')
    for path in paths:
        rel = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode & 0o7777
        require(not mode & 0o6000, 'privileged stage file')
        if path.is_symlink():
            target = path.readlink()
            require(not target.is_absolute() and path.resolve(strict=True).is_relative_to(root),
                    'external stage symlink')
            result[rel] = {'link': str(target), 'mode': mode}
        elif path.is_file():
            size += path.stat().st_size
            require(size <= 256 * 1024**2, 'stage size bound exceeded')
            result[rel] = {'sha256': sha(path), 'mode': mode}
        else:
            require(path.is_dir(), 'special stage file')
            result[rel] = {'directory': True, 'mode': mode}
    return result


def gate(prefix, seal, interpreter):
    require(interpreter == prefix / 'bin/python3.14', 'wrong selected interpreter')
    require((prefix / 'lib/libpython3.14.so.1.0').is_file(), 'missing candidate library')
    require(inventory(prefix) == seal, 'candidate bytes/modes/links changed')


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024**2, 4 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def child_terminal(pid):
    return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is not None


def wait_terminal(pid, deadline):
    while (remaining := deadline - time.monotonic()) > 0:
        if child_terminal(pid):
            return True
        time.sleep(min(0.01, remaining))
    return False


def group_has_peers(pid, deadline):
    # The wait-owned terminal leader itself would keep killpg(0) successful.
    with os.scandir('/proc') as entries:
        for count, entry in enumerate(entries, 1):
            require(count <= 32768 and time.monotonic() < deadline, 'owned process group census bound exceeded')
            if entry.name.isascii() and entry.name.isdecimal() and int(entry.name) != pid:
                try:
                    if os.getpgid(int(entry.name)) == pid:
                        return True
                except ProcessLookupError:
                    continue
    return False


def retire_group(child, abort):
    """Retain wait ownership through the last signal, then prove group absence."""
    pid, deadline = child.pid, time.monotonic() + 2
    peers, failure = False, None
    if not abort:
        try:
            peers = group_has_peers(pid, deadline)
        except (Refusal, OSError) as error:
            failure = error
    if abort or peers or failure is not None:
        child_terminal(pid)  # ECHILD prevents signaling a reused numeric identity.
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as error:
            failure = failure or error
    require(wait_terminal(pid, deadline) or child_terminal(pid), 'owned process group leader did not retire')
    reaped, status = os.waitpid(pid, os.WNOHANG)
    require(reaped == pid, 'owned process group leader reap unverified')
    child.returncode = os.waitstatus_to_exitcode(status)
    # After reaping, only a read-only group probe is safe. Presence can mean reuse.
    while (remaining := deadline - time.monotonic()) > 0:
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            break
        except OSError as error:
            raise Refusal('owned process group absence unverified') from error
        time.sleep(min(0.01, remaining))
    else:
        raise Refusal('owned process group absence unverified')
    if failure is not None:
        raise Refusal('owned process group cleanup unverified') from failure
    require(not peers, 'command left descendants in its owned process group')
    return child.returncode


class Runner:
    def __init__(self, output):
        self.output, self.commands = output, []
        self.deadline = time.monotonic() + 300
        for name in ('home', 'tmp', 'config', 'cache', 'data', 'logs'):
            (output / name).mkdir(mode=0o700)
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(output / 'home'),
                    'TMPDIR': str(output / 'tmp'), 'LC_ALL': 'C', 'TZ': 'UTC',
                    'XDG_CONFIG_HOME': str(output / 'config'),
                    'XDG_CACHE_HOME': str(output / 'cache'),
                    'XDG_DATA_HOME': str(output / 'data'), 'PYTHONDONTWRITEBYTECODE': '1'}

    def run(self, argv, prefix=None, allowed=(0,)):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'probe deadline exceeded')
        require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'exclusive child wait ownership required')
        env = dict(self.env)
        if prefix:
            env['LD_LIBRARY_PATH'] = str(prefix / 'lib')
        argv = list(map(str, argv))
        log = self.output / 'logs' / f'{len(self.commands):02d}.txt'
        timeout = min(60, remaining)
        deadline = time.monotonic() + timeout
        delayed = {signal.SIGINT, signal.SIGTERM, signal.SIGALRM}
        with log.open('wb') as stream:
            child, complete = None, False
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, delayed)

            def child_setup():
                limits()
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)

            try:
                try:
                    child = subprocess.Popen(argv, cwd=self.output, env=env, stdin=subprocess.DEVNULL,
                                             stdout=stream, stderr=subprocess.STDOUT,
                                             start_new_session=True, preexec_fn=child_setup)
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous)
                if not wait_terminal(child.pid, deadline):
                    raise subprocess.TimeoutExpired(argv, timeout)
                complete = True
            finally:
                if child is not None:
                    previous = signal.pthread_sigmask(signal.SIG_BLOCK, delayed)
                    try:
                        code = retire_group(child, abort=not complete)
                    finally:
                        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        require(time.monotonic() < self.deadline, 'probe deadline exceeded')
        record = {'argv': argv, 'exit': code, 'log': str(log), 'sha256': sha(log)}
        self.commands.append(record)
        require(log.stat().st_size <= 1024**2, 'command output bound exceeded')
        output = log.read_text(errors='replace')
        require(code in allowed, f'command {len(self.commands)-1} exited {code}: {output[-1500:]}')
        return code, output


QUERY = '''import json, sys, sysconfig
from pathlib import Path
p = Path(sys.argv[1])
if (sys.version_info[:3] != (3,14,8) or Path(sys.executable) != p/'bin/python3.14'
    or Path(sys.prefix) != p or not Path(sysconfig.__file__).is_relative_to(p)):
    raise RuntimeError('candidate interpreter identity refused')
maps=sorted({x.split()[-1] for x in Path('/proc/self/maps').read_text().splitlines() if 'libpython' in x})
if maps != [str(p/'lib/libpython3.14.so.1.0')]:
    raise RuntimeError('candidate library identity refused')
keys=('SOABI','EXT_SUFFIX','INCLUDEPY','LIBDIR','LDLIBRARY','LIBS','SYSLIBS','CC','CFLAGS','CONFIG_ARGS')
print(json.dumps(dict(version=sys.version, executable=sys.executable, prefix=sys.prefix,
                     mapped_libpython=maps, config={k:sysconfig.get_config_var(k) for k in keys})))
'''


def extract_full(evidence, output):
    archive = evidence / 'export/python-3.14.8-1.1-x86_64.pkg.tar.zst'
    require(sha(archive) == FULL_ARCHIVE_SHA, 'unrecognized full-profile archive')
    require(archive.stat().st_size == 17308438, 'wrong full-profile archive size')
    require(sha(evidence / 'report.json') == FULL_REPORT_SHA, 'unrecognized full-profile report')
    full_report = json.loads((evidence / 'report.json').read_text())
    require(full_report['build_returncode'] == 0, 'full-profile builder failed')
    for name, entry in full_report['inputs']['files'].items():
        require(sha(HERE.parents[2] / 'packages/port/python3148-source-candidate' / name)
                == entry['sha256'], 'full-profile candidate source drift')
    destination = output / 'archive-stage'
    destination.mkdir()
    with tarfile.open(archive, 'r:zst') as stream:
        members = stream.getmembers()
        require(len(members) <= 5000 and sum(m.size for m in members) <= 128 * 1024**2,
                'archive bounds exceeded')
        seen = set()
        for member in members:
            path = Path(member.name)
            require(not path.is_absolute() and '..' not in path.parts and member.name not in seen,
                    'unsafe/duplicate archive path')
            seen.add(member.name)
            require(path.parts and (path.parts[0] == 'usr' or
                    member.name in ('.PKGINFO', '.BUILDINFO', '.MTREE')), 'unexpected archive material')
            require(member.isfile() or member.isdir() or member.issym(), 'special/hardlinked archive member')
            require(not member.mode & 0o6000, 'privileged archive member')
            if member.issym():
                target = Path(member.linkname)
                require(not target.is_absolute() and
                        (destination / path.parent / target).resolve().is_relative_to(destination / 'usr'),
                        'external archive link')
        stream.extractall(destination, filter='data')
    return destination / 'usr', {'archive': str(archive), 'sha256': FULL_ARCHIVE_SHA,
                                 'builder_report': str(evidence / 'report.json'),
                                 'builder_report_sha256': FULL_REPORT_SHA,
                                 'run': 'separate full-Tk second run; not a future cleanup-version run'}


def probe(origin, output, full_evidence=None):
    require(sha(origin / 'host-probe-report.json') == REPORT_SHA, 'unrecognized original report')
    report = json.loads((origin / 'host-probe-report.json').read_text())
    require(report['package'] == 'python 3.14.8-1.1' and report['build']['missing_module'] == '_tkinter',
            'original candidate profile changed')
    for entry in report['candidate_files']:
        require(sha(Path(entry['path'])) == entry['sha256'], 'original candidate source drift')
        local = HERE.parents[2] / 'packages/port/python3148-source-candidate' / Path(entry['path']).name
        require(sha(local) == entry['sha256'], 'checkout candidate source drift')
    stage = origin / 'stage/usr'
    source = origin / 'source/Python-3.14.8'
    seal = inventory(stage)
    for staged, built in [('bin/python3.14', 'python'),
                          ('lib/libpython3.14.so.1.0', 'libpython3.14.so.1.0'),
                          ('include/python3.14/Python.h', 'Include/Python.h'),
                          ('include/python3.14/patchlevel.h', 'Include/patchlevel.h'),
                          ('include/python3.14/pyconfig.h', 'pyconfig.h')]:
        require(sha(stage / staged) == sha(source / built), 'staged/build identity mismatch')
    runner = Runner(output)
    original_seal = seal
    full_input = None
    if full_evidence:
        stage, full_input = extract_full(full_evidence, output)
        seal = inventory(stage)
    before = output / 'initial-prefix'
    shutil.copytree(stage, before, symlinks=True)
    require(inventory(before) == seal, 'copy changed candidate')
    # Genuine move: initial executable/headers/libraries no longer exist here.
    prefix = output / 'relocated-prefix'
    before.rename(prefix)
    interpreter = prefix / 'bin/python3.14'
    gate(prefix, seal, interpreter)
    _, data = runner.run([interpreter, '-I', '-S', '-B', '-c', QUERY, prefix], prefix)
    identity = json.loads(data)
    cfg = identity['config']
    require(re.fullmatch(r'cpython-314-[A-Za-z0-9_-]+', cfg['SOABI']) is not None, 'wrong SOABI')
    require(cfg['EXT_SUFFIX'] == '.' + cfg['SOABI'] + '.so', 'wrong extension suffix')
    require(cfg['LDLIBRARY'] == 'libpython3.14.so', 'unexpected library configuration')
    config_script = prefix / 'bin/python3.14-config'
    _, includes = runner.run([config_script, '--includes'], prefix)
    _, ldflags = runner.run([config_script, '--ldflags', '--embed'], prefix)
    include_flags, link_flags = shlex.split(includes), shlex.split(ldflags)
    require(include_flags == [f'-I{prefix}/include/python3.14'] * 2, 'foreign include flags')
    expected_links = [f'-L{prefix}/lib', '-lpython3.14'] + shlex.split(cfg['LIBS'] + ' ' + cfg['SYSLIBS'])
    require(link_flags == expected_links and
            all(re.fullmatch(r'-l[A-Za-z0-9_.]+', x) for x in link_flags[1:]), 'foreign link flags')
    compiler = Path(shutil.which('cc', path='/usr/bin:/bin')).resolve(strict=True)
    runner.run([compiler, '--version'])
    modules = output / 'modules'
    modules.mkdir()
    common = [compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', *include_flags]
    full = modules / ('consumer_full' + cfg['EXT_SUFFIX'])
    stable = modules / 'consumer_stable.abi3.so'
    for name, target in [('full.c', full), ('stable.c', stable)]:
        gate(prefix, seal, interpreter)
        runner.run([*common, '-fPIC', '-shared', HERE / name, '-o', target], prefix)
    executable = output / 'embed'
    runner.run([*common, HERE / 'embed.c', '-o', executable, *link_flags], prefix)
    # Bind the ABI inventory back to the exact candidate source archive.
    abi_file = source / 'Misc/stable_abi.toml'
    source_archive = origin / 'recipe/Python-3.14.8.tar.xz'
    require(sha(source_archive) == SOURCE_SHA, 'candidate source archive changed')
    with tarfile.open(source_archive, 'r:xz') as stream:
        member = stream.getmember('Python-3.14.8/Misc/stable_abi.toml')
        require(member.isfile() and member.size <= 1024**2, 'unexpected ABI inventory member')
        with stream.extractfile(member) as extracted:
            require(extracted.read() == abi_file.read_bytes(), 'ABI source inventory drift')
    with abi_file.open('rb') as stream:
        abi = tomllib.load(stream)
    _, symbols = runner.run(['/usr/bin/readelf', '--dyn-syms', '--wide', stable])
    imports = sorted({line.split()[-1] for line in symbols.splitlines()
                      if ' UND ' in line and line.split()[-1].startswith(('Py', '_Py'))})
    require(imports, 'no stable Python symbols found')
    for symbol in imports:
        entry = abi.get('function', {}).get(symbol) or abi.get('data', {}).get(symbol)
        require(entry and tuple(map(int, entry['added'].split('.'))) <= (3, 11),
                f'non-stable/newer symbol: {symbol}')
    _, dynamic = runner.run(['/usr/bin/readelf', '-d', executable])
    require('Shared library: [libpython3.14.so.1.0]' in dynamic and
            '(RPATH)' not in dynamic and '(RUNPATH)' not in dynamic, 'embedding linkage mismatch')
    gate(prefix, seal, interpreter)
    _, imported = runner.run([interpreter, '-I', '-S', '-B', HERE / 'consume.py', prefix, modules], prefix)
    embed_args = [executable, HERE / 'consume.py', prefix, modules, prefix / 'lib/libpython3.14.so.1.0']
    _, embedded = runner.run(embed_args, prefix)
    controls = []

    def refused(name, action, expected):
        try:
            action()
        except Refusal as exc:
            require(expected in str(exc), f'unexpected refusal: {exc}')
            controls.append({'name': name, 'result': 'PASS', 'reason': str(exc)})
        else:
            raise Refusal(f'{name} was not refused')

    refused('wrong selected interpreter', lambda: gate(prefix, seal, Path('/usr/bin/python3')),
            'wrong selected interpreter')
    _, wrong = runner.run(['/usr/bin/python3', '-I', '-S', '-B', '-c', QUERY, prefix], allowed=(1,))
    require('candidate interpreter identity refused' in wrong, 'wrong runtime refusal missing')
    controls.append({'name': 'actual system interpreter execution', 'result': 'PASS', 'exit': 1})
    # Real changed header: guard refuses and the compiler's version pin also fails.
    header = prefix / 'include/python3.14/patchlevel.h'
    original_header = header.read_bytes()
    try:
        changed = re.sub(rb'(#define PY_MICRO_VERSION\s+)8\b', rb'\g<1>9', original_header)
        require(changed != original_header, 'header control pattern absent')
        header.write_bytes(changed)
        refused('tampered header', lambda: gate(prefix, seal, interpreter), 'changed')
        _, bad_compile = runner.run([*common, '-fPIC', '-shared', HERE / 'full.c',
                                     '-o', output / 'refused.so'], prefix, allowed=(1,))
        require('requires the selected Python 3.14.8 headers' in bad_compile,
                'wrong header compiler refusal missing')
        controls.append({'name': 'actual wrong-version header compilation', 'result': 'PASS', 'exit': 1})
    finally:
        header.write_bytes(original_header)
    library = prefix / 'lib/libpython3.14.so.1.0'
    hidden = output / 'withheld-libpython'
    library.rename(hidden)
    try:
        refused('missing library', lambda: gate(prefix, seal, interpreter), 'missing candidate library')
        code, fallback = runner.run(embed_args, prefix, allowed=(41, 127))
        require(code == 41 and 'consumer-library-identity-refused' in fallback or
                code == 127 and 'libpython3.14.so.1.0' in fallback,
                'unexpected missing-library execution failure')
        controls.append({'name': 'actual embedding missing-library/system-fallback refusal',
                         'result': 'PASS', 'exit': code})
    finally:
        hidden.rename(library)
    # Corrupt a private library byte, then prove refusal without loading it.
    with library.open('r+b') as stream:
        original_byte = stream.read(1)
        stream.seek(0)
        stream.write(bytes([original_byte[0] ^ 1]))
    try:
        refused('tampered library', lambda: gate(prefix, seal, interpreter), 'changed')
    finally:
        with library.open('r+b') as stream:
            stream.write(original_byte)
    gate(prefix, seal, interpreter)
    runner.run([interpreter, '-I', '-S', '-B', HERE / 'consume.py', prefix, modules], prefix)
    runner.run(embed_args, prefix)
    require(inventory(stage) == seal and inventory(origin / 'stage/usr') == original_seal,
            'original stage changed during probe')
    (output / 'stage-seal.json').write_text(json.dumps(seal, sort_keys=True, indent=2) + '\n')
    result = {
        'schema_version': 1, 'status': 'PASS bounded host consumer slice',
        'scope': 'x86_64 staged source-built 3.14.8-1.1 C consumers only',
        'origin_report': {'path': str(origin / 'host-probe-report.json'), 'sha256': REPORT_SHA},
        'origin_stage': str(stage), 'relocated_prefix': str(prefix),
        'full_profile_input': full_input,
        'stage_seal_sha256': sha(output / 'stage-seal.json'), 'identity': identity,
        'compiler': {'path': str(compiler), 'sha256': sha(compiler)},
        'imports': json.loads(imported), 'embedding': json.loads(embedded), 'controls': controls,
        'stable_ABI': {'limited_API_floor': '3.11', 'imported_symbols': imports,
                       'source_inventory': str(abi_file), 'source_inventory_sha256': sha(abi_file),
                       'source_archive_sha256': SOURCE_SHA,
                       'cross_version_execution': 'NOT RUN; candidate 3.14.8 only'},
        'artifacts': {str(p): sha(p) for p in (full, stable, executable)},
        'consumer_sources': {p.name: sha(p) for p in sorted(HERE.iterdir()) if p.is_file()},
        'commands': runner.commands,
        'limits': {'wall_seconds': 300, 'command_seconds': 60, 'child_cpu_seconds': 45,
                   'child_address_space_bytes': 1024**3, 'child_file_bytes': 4 * 1024**2,
                   'fresh_HOME_XDG_TMPDIR': True, 'network_or_install_commands': False},
        'full_candidate': ('separate full-Tk host package built; consumer scope only' if full_input else
                           'HOLD missing Tk; unchanged original core profile'),
        'original_core_profile': 'HOLD missing Tk; original report and stage preserved',
        'native_ARM': 'NOT RUN', 'native_16K': 'NOT RUN', 'M2': 'NOT RUN',
        'system_install': 'NOT RUN', 'legal_source_acceptance': 'HOLD original gates unchanged',
        'full_system_acceptance': 'NOT RUN', 'release': 'NOT ADMITTED'
    }
    (output / 'report.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin', type=Path, required=True, help='original host-core evidence directory')
    parser.add_argument('--output', type=Path, required=True, help='fresh absolute private directory')
    parser.add_argument('--full-evidence', type=Path,
                        help='optional pinned second-run full-Tk builder evidence directory')
    args = parser.parse_args()
    require(os.geteuid() != 0, 'ordinary user required')
    require(args.output.is_absolute() and not any(c.isspace() for c in str(args.output)),
            'absolute output path without whitespace required by python-config output')
    output = args.output.parent.resolve(strict=True) / args.output.name
    origin = args.origin.resolve(strict=True)
    full_evidence = args.full_evidence.resolve(strict=True) if args.full_evidence else None
    require(not output.is_relative_to(origin) and
            (not full_evidence or not output.is_relative_to(full_evidence)),
            'output must be outside input evidence')
    require(not output.exists() and not output.is_symlink(), 'fresh output required')
    output.mkdir(mode=0o700)
    def deadline(signum, frame):
        raise Refusal('overall 300-second probe deadline exceeded')
    previous_handler = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(300)
    try:
        result = probe(origin, output, full_evidence)
    except BaseException as exc:
        (output / 'failure.json').write_text(json.dumps({'status': 'FAIL', 'error': str(exc)}) + '\n')
        raise
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)
    print(json.dumps({'status': result['status'], 'report': str(output / 'report.json'),
                      'controls': len(result['controls']), 'full_candidate': result['full_candidate']}))


if __name__ == '__main__':
    main()
